//! X18 branch-to-trampoline: replaces SIGILL traps with inline branches
//! for ~100× speedup on x18-touching instructions.
//!
//! Each x18 instruction is replaced with `B <trampoline>`. The trampoline
//! swaps the guest x18 value in, runs the original instruction natively,
//! swaps back, and branches to the next instruction.
//!
//! Guest x18 is stored in a global AtomicU64. Multi-threaded guests use
//! the existing pthread_key via get/set_thread_x18 for the SIGILL fallback,
//! but the trampoline uses this global for speed. Single-process guests
//! (the common case for dpkg-deb, apt, etc.) only have one thread executing
//! x18 code at a time, so a global is correct.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// The guest's x18 value. Accessed by trampoline code via absolute address.
/// Must be pub so the linker keeps it and we can take its address.
#[no_mangle]
pub static GUEST_X18_GLOBAL: AtomicU64 = AtomicU64::new(0);

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
        // 12 instructions × 4 bytes = 48 bytes per trampoline
        //
        // Saves/restores x16 and x17 via the stack so hand-written assembly
        // (like libgcrypt's crypto routines) that uses x16/x17 as temporaries
        // is not corrupted. SP is offset by -16 during the original instruction
        // but x18-touching instructions almost never reference SP.
        let size = 12 * 4;
        if self.used + size > self.capacity { return None; }

        let tramp_pc = self.base + self.used as u64;
        let return_pc = orig_pc + 4;
        let x18_addr = &GUEST_X18_GLOBAL as *const AtomicU64 as u64;
        let x18_page = x18_addr & !0xFFF;
        let x18_page_off = (x18_addr & 0xFFF) as u32;

        //  0: stp x16, x17, [sp, #-16]! ; save scratch regs
        //  1: mov x16, x18              ; save macOS x18 in x16
        //  2: adrp x17, <x18_page>
        //  3: ldr x18, [x17, #off]      ; x18 = guest x18
        //  4: ldp x16, x17, [sp], #16   ; restore scratch regs
        //  5: <original instruction>     ; x16/x17 correct, x18 = guest
        //  6: stp x16, x17, [sp, #-16]! ; save scratch regs again
        //  7: adrp x17, <x18_page>
        //  8: str x18, [x17, #off]      ; save guest x18
        //  9: ldr x18, [sp, #-16]       ; restore macOS x18 (saved at step 0's [sp])
        //                                 ; step 0 pushed to [sp-16], step 6 re-pushed to current [sp-16]
        //                                 ; actually we saved macOS x18 in x16 at step 1, then restored x16 at step 4.
        //                                 ; We need to save macOS x18 somewhere persistent.
        //
        // Revised approach: save macOS x18 in the stack frame alongside x16/x17:
        //  0: stp x16, x17, [sp, #-32]! ; push frame: [sp]=x16, [sp+8]=x17
        //  1: str x18, [sp, #16]         ; [sp+16] = macOS x18
        //  2: adrp x16, <x18_page>
        //  3: ldr x18, [x16, #off]       ; x18 = guest x18
        //  4: ldp x16, x17, [sp]         ; restore x16/x17
        //  5: add sp, sp, #32            ; restore SP for the original instruction
        //  6: <original instruction>      ; x16/x17/SP all correct, x18 = guest
        //  7: sub sp, sp, #32            ; re-lower SP to access our frame
        //  8: adrp x16, <x18_page>
        //  9: str x18, [x16, #off]       ; save guest x18
        // 10: ldr x18, [sp, #16]         ; restore macOS x18
        // 11: ldp x16, x17, [sp], #32    ; restore x16/x17; sp += 32
        // 12: b <return_pc>
        let size = 13 * 4;
        if self.used + size > self.capacity { return None; }

        let adrp_0 = encode_adrp(16, tramp_pc + 2*4, x18_page)?;
        let adrp_1 = encode_adrp(16, tramp_pc + 8*4, x18_page)?;
        let b_back = encode_b(tramp_pc + 12*4, return_pc)?;

        let instrs: [u32; 13] = [
            0xA9BE_47F0,                               // stp x16, x17, [sp, #-32]!
            0xF900_0BF2,                               // str x18, [sp, #16]
            adrp_0,                                     // adrp x16, <page>
            encode_ldr_unsigned(18, 16, x18_page_off),  // ldr x18, [x16, #off]
            0xA940_47F0,                               // ldp x16, x17, [sp]
            0x9100_83FF,                               // add sp, sp, #32
            orig_instr,                                 // original instruction
            0xD100_83FF,                               // sub sp, sp, #32
            adrp_1,                                     // adrp x16, <page>
            encode_str_unsigned(18, 16, x18_page_off),  // str x18, [x16, #off]
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
