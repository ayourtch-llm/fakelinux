//! X18 branch-to-trampoline: replaces SIGILL traps with inline branches
//! for ~100x speedup on x18-touching instructions.
//!
//! Each x18 instruction is replaced with `B <trampoline>`. The trampoline
//! loads the guest x18 value into x17, runs the original instruction with
//! its x18 fields rewritten to x17, stores x17 back, and branches to the
//! next instruction.
//!
//! The guest value is carried in x17 (NOT hardware x18) because the macOS
//! kernel zeroes x18 on interrupts/context switches — a value held in hw
//! x18 across even a couple of instructions can silently become 0.
//!
//! Guest x18 is stored per-thread using macOS's thread-specific data (TSD)
//! accessed via `MRS TPIDRRO_EL0` + a fixed offset. This is correct for
//! multi-threaded guests where each thread has its own x18 value.
//! The TSD slot is allocated via `pthread_key_create` at startup, and the
//! trampoline reads/writes `[TPIDRRO_EL0 + key*8]` directly.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

/// The guest's x18 value (global fallback, used before TSD is initialized).
/// Kept for backward compatibility with the SIGILL fallback path.
#[no_mangle]
pub static GUEST_X18_GLOBAL: AtomicU64 = AtomicU64::new(0);

/// TSD byte offset: key * 8, set once at startup by init_x18_key().
/// Used by trampolines to access per-thread guest x18 via TPIDRRO_EL0.
static TSD_BYTE_OFFSET: AtomicU32 = AtomicU32::new(0);

/// Set the TSD byte offset for x18 trampolines. Called once from init_x18_key().
pub fn set_tsd_offset(byte_offset: u32) {
    assert!(byte_offset % 8 == 0 && byte_offset / 8 < 4096,
            "TSD offset {} doesn't fit in LDR/STR unsigned imm12", byte_offset);
    TSD_BYTE_OFFSET.store(byte_offset, Ordering::SeqCst);
}

// ─── ARM64 instruction encoding ─────────────────────────────────────────────

/// Encode `B <target>` from `pc`. Returns None if out of ±128 MB range.
fn encode_b(pc: u64, target: u64) -> Option<u32> {
    let offset = (target as i64) - (pc as i64);
    if offset % 4 != 0 { return None; }
    let imm26 = offset / 4;
    if imm26 < -0x200_0000 || imm26 >= 0x200_0000 { return None; }
    Some(0x1400_0000 | ((imm26 as u32) & 0x03FF_FFFF))
}

/// Encode `LDR Xt, [Xn, #imm]` unsigned offset (8-byte scaled).
fn encode_ldr_unsigned(rt: u32, rn: u32, byte_offset: u32) -> u32 {
    debug_assert!(byte_offset % 8 == 0 && byte_offset / 8 < 4096);
    0xF940_0000 | ((byte_offset / 8) << 10) | (rn << 5) | rt
}

/// Encode `STR Xt, [Xn, #imm]` unsigned offset (8-byte scaled).
fn encode_str_unsigned(rt: u32, rn: u32, byte_offset: u32) -> u32 {
    debug_assert!(byte_offset % 8 == 0 && byte_offset / 8 < 4096);
    0xF900_0000 | ((byte_offset / 8) << 10) | (rn << 5) | rt
}

/// Encode `ADRP Xd, <page>` from `pc`. Returns None if out of ±4 GB range.
fn encode_adrp(rd: u32, pc: u64, target_page: u64) -> Option<u32> {
    let pc_page = pc & !0xFFF;
    let delta = (target_page as i64) - (pc_page as i64);
    let imm = delta >> 12;
    if imm < -0x10_0000 || imm >= 0x10_0000 { return None; } // ±4 GB
    let imm21 = imm as u32 & 0x1F_FFFF;
    let immlo = imm21 & 0x3;
    let immhi = (imm21 >> 2) & 0x7_FFFF;
    Some(0x9000_0000 | (immlo << 29) | (immhi << 5) | rd)
}

// ─── Code island ────────────────────────────────────────────────────────────

const PAGE_SIZE: usize = 16384;

/// Number of instructions per trampoline (fixed-size slots in the island).
const TRAMP_INSTRS: usize = 10;

struct CodeIsland {
    base: u64,
    capacity: usize,
    used: usize,
}

impl CodeIsland {
    /// Allocate a code island. Uses MAP_JIT for macOS ARM64 W^X support.
    fn alloc(size: usize) -> Option<Self> {
        let sz = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                sz,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON | 0x800, // 0x800 = MAP_JIT
                -1, 0,
            )
        };
        if ptr == libc::MAP_FAILED { return None; }
        Some(CodeIsland { base: ptr as u64, capacity: sz, used: 0 })
    }

    fn flush_icache(&self) {
        if self.used > 0 {
            unsafe {
                extern "C" { fn sys_icache_invalidate(start: *mut libc::c_void, size: usize); }
                sys_icache_invalidate(self.base as *mut _, self.used);
            }
        }
    }

    /// Emit one trampoline. Returns trampoline address or None if full/out-of-range.
    ///
    /// CRITICAL: the guest x18 value must NEVER be held in the hardware x18
    /// register. The macOS kernel zeroes/clobbers x18 on any interrupt or
    /// context switch, so a value placed in hw x18 can silently become 0
    /// between two instructions (this caused the apt-get install SIGSEGV in
    /// liblzma's match finder: `str w3, [x18]` faulted with x18=0 while the
    /// TSD slot still held the correct pointer). Instead, the original
    /// instruction is rewritten to use x17 in place of x18.
    fn emit(&mut self, orig_pc: u64, orig_instr: u32) -> Option<u64> {
        // Rewrite all x18 register fields to x17. Instructions that already
        // use x16/x17 are rejected by the caller, so x17 is free here.
        let subst_instr = crate::decoder::substitute_gpr(orig_instr, 18, 17)?;

        // TRAMP_INSTRS instructions x 4 bytes per trampoline
        //
        // Saves/restores x16 and x17 via the stack so hand-written assembly
        // (like libgcrypt's crypto routines) that uses x16/x17 as temporaries
        // is not corrupted. SP is restored before the rewritten instruction
        // executes, in case it references SP.
        //
        // Per-thread x18 is accessed via MRS TPIDRRO_EL0 + TSD offset:
        //  0: stp x16, x17, [sp, #-32]! ; push frame: [sp]=x16, [sp+8]=x17
        //  1: mrs x16, tpidrro_el0       ; get thread-local base
        //  2: ldr x17, [x16, #(key*8)]   ; x17 = per-thread guest x18
        //  3: add sp, sp, #32            ; restore SP for the instruction
        //  4: <instr with x18→x17>        ; x17 = guest x18, SP correct
        //  5: sub sp, sp, #32            ; re-lower SP to access our frame
        //  6: mrs x16, tpidrro_el0       ; get thread-local base again
        //  7: str x17, [x16, #(key*8)]   ; save per-thread guest x18
        //  8: ldp x16, x17, [sp], #32    ; restore x16/x17; sp += 32
        //  9: b <return_pc>
        let size = TRAMP_INSTRS * 4;
        if self.used + size > self.capacity { return None; }

        let tramp_pc = self.base + self.used as u64;
        let return_pc = orig_pc + 4;
        let tsd_off = TSD_BYTE_OFFSET.load(Ordering::Relaxed);
        assert!(tsd_off != 0, "TSD_BYTE_OFFSET not initialized before emitting trampoline");

        let b_back = encode_b(tramp_pc + (TRAMP_INSTRS as u64 - 1)*4, return_pc)?;

        // MRS x16, TPIDRRO_EL0 = 0xD53BD060 | Rt, Rt=16 → 0xD53BD070
        const MRS_X16_TPIDRRO: u32 = 0xD53BD070;

        let instrs: [u32; TRAMP_INSTRS] = [
            0xA9BE_47F0,                               // stp x16, x17, [sp, #-32]!
            MRS_X16_TPIDRRO,                           // mrs x16, tpidrro_el0
            encode_ldr_unsigned(17, 16, tsd_off),       // ldr x17, [x16, #(key*8)]
            0x9100_83FF,                               // add sp, sp, #32
            subst_instr,                                // original instr, x18→x17
            0xD100_83FF,                               // sub sp, sp, #32
            MRS_X16_TPIDRRO,                           // mrs x16, tpidrro_el0
            encode_str_unsigned(17, 16, tsd_off),       // str x17, [x16, #(key*8)]
            0xA8C2_47F0,                               // ldp x16, x17, [sp], #32
            b_back,                                     // b <return>
        ];

        // MAP_JIT requires pthread_jit_write_protect_np to toggle W^X
        unsafe {
            pthread_jit_write_protect_np(0); // writable
            let p = tramp_pc as *mut u32;
            for (i, &ins) in instrs.iter().enumerate() {
                p.add(i).write(ins);
            }
            // Flush icache for this trampoline before making executable
            extern "C" { fn sys_icache_invalidate(start: *mut libc::c_void, size: usize); }
            sys_icache_invalidate(tramp_pc as *mut _, size);
            pthread_jit_write_protect_np(1); // executable
        }

        self.used += size;
        Some(tramp_pc)
    }
}

extern "C" {
    fn pthread_jit_write_protect_np(enabled: i32);
}

// ─── Global island list ─────────────────────────────────────────────────────

static ISLANDS: Mutex<Vec<CodeIsland>> = Mutex::new(Vec::new());

/// Patch an x18 instruction with a B-to-trampoline.
/// Returns true on success, false to fall back to UDF.
pub fn patch_x18_with_trampoline(pc_addr: u64, instr: u32) -> bool {
    // Environment override to disable trampolines for debugging
    static DISABLED: std::sync::atomic::AtomicI8 = std::sync::atomic::AtomicI8::new(-1);
    let d = DISABLED.load(Ordering::Relaxed);
    if d < 0 {
        let v = if std::env::var_os("FAKELINUX_NO_X18_TRAMP").is_some() { 1 } else { 0 };
        DISABLED.store(v, Ordering::Relaxed);
        if v == 1 { return false; }
    } else if d == 1 { return false; }

    // AdvSIMD structure ld/st (e.g. clang's `ld2 {v0.2d, v1.2d}, [x18]`):
    // EmulClass::Other, but perfectly trampolinable — only Rn/Rm are GPRs
    // (Rt is a vector register, so the generic x16/x17 field check would
    // misfire on v16/v17 operands).
    let simd_struct = crate::decoder::is_simd_ldst_struct(instr);

    // Skip if instruction also references x16 or x17 (our scratch regs)
    if simd_struct {
        let rn = (instr >> 5) & 0x1F;
        let rm = (instr >> 16) & 0x1F; // only a GPR in the post-index form
        let post_index = instr & 0x00800000 != 0;
        if rn == 16 || rn == 17 || (post_index && (rm == 16 || rm == 17)) {
            FALLBACK_COUNT.fetch_add(1, Ordering::Relaxed);
            return false;
        }
    } else if uses_x16_or_x17(instr) {
        FALLBACK_COUNT.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    // Skip instruction classes that cannot execute at a different PC or
    // whose control flow would escape the trampoline:
    //  - PcRelAddr (ADR/ADRP), LoadLiteral: PC-relative, wrong result in island
    //  - CompareBranch/TestBranch (CBZ/TBZ): branch target relative to island
    //  - LoadStoreExclusive: trampoline memory accesses clear the monitor → livelock
    //  - Other: includes BR/BLR/RET x18 (control flow escapes the island)
    use crate::decoder::EmulClass;
    match crate::decoder::decode_emul_class(instr) {
        EmulClass::Other if simd_struct => {} // safe in an island, see above
        EmulClass::PcRelAddr
        | EmulClass::LoadLiteral
        | EmulClass::CompareBranch
        | EmulClass::TestBranch
        | EmulClass::LoadStoreExclusive
        | EmulClass::Other => {
            FALLBACK_COUNT.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        _ => {}
    }

    // Verify the instruction's encoding is known so x18→x17 substitution will
    // succeed in emit(); unknown encodings fall back to UDF emulation.
    if crate::decoder::substitute_gpr(instr, 18, 17).is_none() {
        FALLBACK_COUNT.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    let mut islands = ISLANDS.lock().unwrap();

    // Try existing islands
    for island in islands.iter_mut() {
        if let Some(tramp) = island.emit(pc_addr, instr) {
            if let Some(b) = encode_b(pc_addr, tramp) {
                unsafe { (pc_addr as *mut u32).write(b); }
                TRAMP_COUNT.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
    }

    // Need new island (256 KB = ~8000 trampolines)
    if let Some(mut island) = CodeIsland::alloc(256 * 1024) {
        if let Some(tramp) = island.emit(pc_addr, instr) {
            if let Some(b) = encode_b(pc_addr, tramp) {
                unsafe { (pc_addr as *mut u32).write(b); }
                TRAMP_COUNT.fetch_add(1, Ordering::Relaxed);
                islands.push(island);
                return true;
            }
        }
    }

    false
}

static TRAMP_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static FALLBACK_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Flush instruction caches for all islands and log stats.
pub fn flush_all_islands() {
    if let Ok(islands) = ISLANDS.lock() {
        for island in islands.iter() {
            island.flush_icache();
        }
    }
    let t = TRAMP_COUNT.load(Ordering::Relaxed);
    let f = FALLBACK_COUNT.load(Ordering::Relaxed);
    if t > 0 || f > 0 {
        eprintln!("fakelinux: x18 trampolines: {} ok, {} fallback to UDF", t, f);
    }
}

/// If `pc` lies inside a trampoline island, return
/// (island_base, tramp_index, offset_within_trampoline, guest_orig_pc).
/// guest_orig_pc is recovered from the trailing `B <return_pc>` of the
/// trampoline: orig_pc = return_pc - 4.
///
/// Async-signal-safe-ish: uses try_lock so it can be called from a crash
/// handler without deadlocking if the lock is held.
pub fn find_trampoline_for_pc(pc: u64) -> Option<(u64, u64, u64, u64)> {
    const TRAMP_SIZE: u64 = TRAMP_INSTRS as u64 * 4;
    const B_SLOT_OFF: u64 = (TRAMP_INSTRS as u64 - 1) * 4;
    let islands = ISLANDS.try_lock().ok()?;
    for island in islands.iter() {
        if pc >= island.base && pc < island.base + island.used as u64 {
            let delta = pc - island.base;
            let idx = delta / TRAMP_SIZE;
            let off = delta % TRAMP_SIZE;
            let tramp_base = island.base + idx * TRAMP_SIZE;
            // Trailing B is the last instruction slot
            let b_instr = unsafe { ((tramp_base + B_SLOT_OFF) as *const u32).read() };
            let orig_pc = if b_instr & 0xFC00_0000 == 0x1400_0000 {
                let imm26 = (b_instr & 0x03FF_FFFF) as i64;
                let imm = (imm26 << 38) >> 38; // sign-extend 26 bits
                let return_pc = (tramp_base + B_SLOT_OFF).wrapping_add((imm * 4) as u64);
                return_pc.wrapping_sub(4)
            } else {
                0
            };
            return Some((island.base, idx, off, orig_pc));
        }
    }
    None
}

/// Check if instruction references x16 or x17 in any GPR field.
fn uses_x16_or_x17(instr: u32) -> bool {
    // Check common 5-bit GPR fields: Rd(0), Rn(5), Rm(16), Ra(10)
    for shift in [0u32, 5, 16, 10] {
        let reg = (instr >> shift) & 0x1F;
        if reg == 16 || reg == 17 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Allocate a writable page with guest-like code, mirroring how fakelinux
    /// maps guest text: anonymous RW (patched while writable), then RX.
    fn alloc_code_page(instrs: &[u32]) -> u64 {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1, 0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED, "mmap failed");
        unsafe {
            let p = ptr as *mut u32;
            for (i, &ins) in instrs.iter().enumerate() {
                p.add(i).write(ins);
            }
        }
        ptr as u64
    }

    /// Flip a code page to RX and flush icache, like the loader does after patching.
    fn make_executable(addr: u64) {
        unsafe {
            libc::mprotect(addr as *mut _, PAGE_SIZE, libc::PROT_READ | libc::PROT_EXEC);
            extern "C" { fn sys_icache_invalidate(start: *mut libc::c_void, size: usize); }
            sys_icache_invalidate(addr as *mut _, PAGE_SIZE);
        }
    }

    /// The emitted trampoline must NEVER reference hardware x18: the macOS
    /// kernel zeroes x18 on interrupts/context switches, so any guest value
    /// held in hw x18 can silently become 0 mid-trampoline. This is the
    /// regression test for the apt-get install SIGSEGV in liblzma.
    #[test]
    fn test_trampoline_never_holds_guest_value_in_x18() {
        crate::trap::init_x18_key();
        // STR W3, [X18] — the exact crashing instruction
        let code = alloc_code_page(&[0xb9000243, 0xD65F03C0 /* ret */]);
        assert!(patch_x18_with_trampoline(code, 0xb9000243), "patch should succeed");

        // Follow the B to the trampoline and inspect every instruction.
        let b = unsafe { (code as *const u32).read() };
        assert_eq!(b & 0xFC00_0000, 0x1400_0000, "patched site must be a B");
        let imm = (((b & 0x03FF_FFFF) as i64) << 38) >> 38;
        let tramp = code.wrapping_add((imm * 4) as u64);
        for i in 0..TRAMP_INSTRS {
            let ins = unsafe { ((tramp + i as u64 * 4) as *const u32).read() };
            // No instruction in the trampoline may use x18 as a GPR operand
            // (the trailing B has no GPR fields; MRS targets x16).
            assert!(!crate::decoder::references_x18(ins),
                "trampoline slot {} references x18: {:#010x}", i, ins);
        }
    }

    /// End-to-end: execute a trampolined `STR W3, [X18]` and verify it stores
    /// through the guest x18 (TSD) pointer.
    #[test]
    fn test_trampoline_str_through_guest_x18() {
        crate::trap::init_x18_key();
        let code = alloc_code_page(&[0xb9000243, 0xD65F03C0 /* ret */]);
        assert!(patch_x18_with_trampoline(code, 0xb9000243));
        make_executable(code);
        flush_all_islands();

        let mut target: u32 = 0;
        crate::trap::set_thread_x18(&mut target as *mut u32 as u64);
        let f: extern "C" fn(u64, u64, u64, u64) =
            unsafe { std::mem::transmute(code) };
        f(0, 0, 0, 0xCAFE_F00D); // x3 = value to store
        assert_eq!(target, 0xCAFE_F00D, "STR W3,[X18] must store via guest x18");
        assert_eq!(crate::trap::get_thread_x18(), &mut target as *mut u32 as u64,
            "guest x18 unchanged by a store");
    }

    /// End-to-end: AdvSIMD structure load through guest x18. clang's
    /// `ld2 {v0.2d, v1.2d}, [x18]` used to fall back to UDF (EmulClass::
    /// Other) and PANIC trap_handler during the rdma-core build.
    #[test]
    fn test_trampoline_simd_ld2_through_guest_x18() {
        crate::trap::init_x18_key();
        // ld2 {v0.2d, v1.2d}, [x18] ; st1 {v0.2d, v1.2d}, [x0] ; ret
        let code = alloc_code_page(&[0x4C408E40, 0x4C00AC00, 0xD65F03C0]);
        assert!(patch_x18_with_trampoline(code, 0x4C408E40),
            "AdvSIMD structure loads must be trampolinable");
        make_executable(code);
        flush_all_islands();

        let src: [u64; 4] = [0x1111, 0x2222, 0x3333, 0x4444];
        let mut dst: [u64; 4] = [0; 4];
        crate::trap::set_thread_x18(src.as_ptr() as u64);
        let f: extern "C" fn(u64, u64, u64, u64) =
            unsafe { std::mem::transmute(code) };
        f(dst.as_mut_ptr() as u64, 0, 0, 0);
        // LD2 de-interleaves: v0 = {m0, m2}, v1 = {m1, m3};
        // ST1 stores v0 then v1 contiguously.
        assert_eq!(dst, [0x1111, 0x3333, 0x2222, 0x4444],
            "LD2 must de-interleave through guest x18");
    }

    /// End-to-end: a trampolined instruction that WRITES x18 must update TSD.
    #[test]
    fn test_trampoline_writes_back_guest_x18() {
        crate::trap::init_x18_key();
        // ADD x18, x18, #4 ; RET
        let code = alloc_code_page(&[0x91001252, 0xD65F03C0]);
        assert!(patch_x18_with_trampoline(code, 0x91001252));
        make_executable(code);
        flush_all_islands();

        crate::trap::set_thread_x18(100);
        let f: extern "C" fn() = unsafe { std::mem::transmute(code) };
        f();
        assert_eq!(crate::trap::get_thread_x18(), 104,
            "ADD x18, x18, #4 must propagate to TSD");
    }

    /// PC-relative and branch instructions must NOT be trampolined — they
    /// cannot execute at the island's different PC.
    #[test]
    fn test_unsafe_classes_fall_back_to_udf() {
        crate::trap::init_x18_key();
        let cases: &[(u32, &str)] = &[
            (0xb4000012, "CBZ x18"),
            (0x34005372, "CBZ w18 (liblzma-style)"),
            (0x90001cf2, "ADRP x18"),
            (0xd61f0240, "BR x18"),
        ];
        for &(instr, name) in cases {
            let code = alloc_code_page(&[instr, 0xD65F03C0]);
            assert!(!patch_x18_with_trampoline(code, instr),
                "{} must fall back to UDF emulation", name);
        }
    }
}
