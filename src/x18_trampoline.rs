//! X18 branch-to-trampoline: replaces SIGILL traps with inline branches
//! for ~100x speedup on x18-touching instructions.
//!
//! Each x18 instruction is replaced with `B <trampoline>`. The trampoline
//! swaps the guest x18 value in, runs the original instruction natively,
//! swaps back, and branches to the next instruction.
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
    fn emit(&mut self, orig_pc: u64, orig_instr: u32) -> Option<u64> {
        // 13 instructions x 4 bytes = 52 bytes per trampoline
        //
        // Saves/restores x16 and x17 via the stack so hand-written assembly
        // (like libgcrypt's crypto routines) that uses x16/x17 as temporaries
        // is not corrupted. SP is restored before the original instruction.
        //
        // Per-thread x18 is accessed via MRS TPIDRRO_EL0 + TSD offset:
        //  0: stp x16, x17, [sp, #-32]! ; push frame: [sp]=x16, [sp+8]=x17
        //  1: str x18, [sp, #16]         ; [sp+16] = macOS x18
        //  2: mrs x16, tpidrro_el0       ; get thread-local base
        //  3: ldr x18, [x16, #(key*8)]   ; x18 = per-thread guest x18
        //  4: ldp x16, x17, [sp]         ; restore x16/x17
        //  5: add sp, sp, #32            ; restore SP for the original instruction
        //  6: <original instruction>      ; x16/x17/SP all correct, x18 = guest
        //  7: sub sp, sp, #32            ; re-lower SP to access our frame
        //  8: mrs x16, tpidrro_el0       ; get thread-local base again
        //  9: str x18, [x16, #(key*8)]   ; save per-thread guest x18
        // 10: ldr x18, [sp, #16]         ; restore macOS x18
        // 11: ldp x16, x17, [sp], #32    ; restore x16/x17; sp += 32
        // 12: b <return_pc>
        let size = 13 * 4;
        if self.used + size > self.capacity { return None; }

        let tramp_pc = self.base + self.used as u64;
        let return_pc = orig_pc + 4;
        let tsd_off = TSD_BYTE_OFFSET.load(Ordering::Relaxed);
        assert!(tsd_off != 0, "TSD_BYTE_OFFSET not initialized before emitting trampoline");

        let b_back = encode_b(tramp_pc + 12*4, return_pc)?;

        // MRS x16, TPIDRRO_EL0 = 0xD53BD060 | Rt, Rt=16 → 0xD53BD070
        const MRS_X16_TPIDRRO: u32 = 0xD53BD070;

        let instrs: [u32; 13] = [
            0xA9BE_47F0,                               // stp x16, x17, [sp, #-32]!
            0xF900_0BF2,                               // str x18, [sp, #16]
            MRS_X16_TPIDRRO,                           // mrs x16, tpidrro_el0
            encode_ldr_unsigned(18, 16, tsd_off),       // ldr x18, [x16, #(key*8)]
            0xA940_47F0,                               // ldp x16, x17, [sp]
            0x9100_83FF,                               // add sp, sp, #32
            orig_instr,                                 // original instruction
            0xD100_83FF,                               // sub sp, sp, #32
            MRS_X16_TPIDRRO,                           // mrs x16, tpidrro_el0
            encode_str_unsigned(18, 16, tsd_off),       // str x18, [x16, #(key*8)]
            0xF940_0BF2,                               // ldr x18, [sp, #16]
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

    // Skip if instruction also references x16 or x17 (our scratch regs)
    if uses_x16_or_x17(instr) {
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
