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

/// `STP Xt1, Xt2, [SP, #-32]!` (64-bit pre-index push).
fn encode_stp_pre32(rt1: u32, rt2: u32) -> u32 {
    // imm7 = -32/8 = -4 → 0x7C
    0xA980_0000 | (0x7C << 15) | (rt2 << 10) | (31 << 5) | rt1
}

/// `LDP Xt1, Xt2, [SP], #32` (64-bit post-index pop).
fn encode_ldp_post32(rt1: u32, rt2: u32) -> u32 {
    // imm7 = 32/8 = 4
    0xA8C0_0000 | (4 << 15) | (rt2 << 10) | (31 << 5) | rt1
}

/// `MRS Xt, TPIDRRO_EL0`.
fn encode_mrs_tpidrro(rt: u32) -> u32 {
    0xD53B_D060 | rt
}

/// `STR Xt, [SP, #-16]!` (pre-index push of one register).
fn encode_str_pre16(rt: u32) -> u32 {
    // imm9 = -16 → 0x1F0
    0xF800_0C00 | (0x1F0 << 12) | (31 << 5) | rt
}

/// `LDR Xt, [SP], #16` (post-index pop of one register).
fn encode_ldr_post16(rt: u32) -> u32 {
    // imm9 = 16
    0xF840_0400 | (16 << 12) | (31 << 5) | rt
}

const NOP: u32 = 0xD503_201F;

/// Pick two scratch GPRs the instruction does not reference (prefer x16/x17 —
/// the intra-procedure-call regs — then low caller-saved regs). None if the
/// encoding is unknown.
fn pick_scratch_pair(instr: u32) -> Option<(u32, u32)> {
    let used = crate::decoder::referenced_gprs(instr)?;
    const CANDIDATES: [u32; 26] = [
        16, 17, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        19, 20, 21, 22, 23, 24, 25, 26,
    ];
    let mut found = [0u32; 2];
    let mut n = 0;
    for &r in &CANDIDATES {
        if used & (1 << r) == 0 {
            found[n] = r;
            n += 1;
            if n == 2 {
                return Some((found[0], found[1]));
            }
        }
    }
    None
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
    /// Per-slot (guest_orig_pc, orig_instr) — lets the SIGBUS recovery path
    /// fall back to emulating the original instruction if a trampoline
    /// becomes unexecutable (e.g. PROT_EXEC stripped by an overlapping
    /// guest mprotect, or per-thread JIT write-mode anomalies).
    meta: Vec<(u64, u32)>,
}

impl CodeIsland {
    /// Allocate a code island. Uses MAP_JIT for macOS ARM64 W^X support.
    fn alloc(size: usize) -> Option<Self> {
        Self::alloc_at_hint(size, 0)
    }

    /// Allocate near `near_pc` so that `B` (±128 MB) can reach the island
    /// from the patch site. A NULL-hint mmap lands wherever the kernel
    /// likes — for big libraries (libLLVM text is ~120 MB) that's usually
    /// out of branch range, and every rejected site costs a SIGILL per
    /// execution forever after. Try hints at growing distances on both
    /// sides; verify reachability of the WHOLE island before accepting.
    fn alloc_near(size: usize, near_pc: u64) -> Option<Self> {
        const MB: i64 = 1 << 20;
        const DELTAS: [i64; 12] = [
            16 * MB, -16 * MB, 32 * MB, -32 * MB, 48 * MB, -48 * MB,
            64 * MB, -64 * MB, 96 * MB, -96 * MB, 112 * MB, -112 * MB,
        ];
        // Guest-fixed territory: addresses there are computed by the
        // loader/guest and written with MAP_FIXED — an island placed in a
        // temporary hole gets silently clobbered (zeroed) later:
        //  - 0x500000000+: PIE main binary, and brk grows up from image end
        //    (clobbered binutils-ld islands → permanent emulation storm);
        //  - 0x600000000+: interpreter (ld-linux) zone;
        //  - 0x700000000+: relocated ET_EXEC images + their brk
        //    (cc1's data PT_LOAD zeroed a live island → gcc SIGBUS).
        // For pcs in any such zone, only use the arena BELOW the zone base,
        // which the guest never fixed-maps.
        let sz = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let zone_base = [0x7_0000_0000u64, 0x6_0000_0000, 0x5_0000_0000]
            .iter().copied().find(|&z| near_pc >= z);
        if let Some(ceiling) = zone_base {
            for &d in &DELTAS {
                if d <= 0 { continue; }
                let hint = (ceiling - d as u64) & !(PAGE_SIZE as u64 - 1);
                if let Some(island) = Self::alloc_at_hint(sz, hint) {
                    if island.base + (sz as u64) <= ceiling
                        && encode_b(near_pc, island.base).is_some()
                        && encode_b(near_pc, island.base + sz as u64 - 4).is_some() {
                        return Some(island);
                    }
                    unsafe {
                        libc::munmap((island.base - PAGE_SIZE as u64) as *mut _,
                            island.capacity + 2 * PAGE_SIZE);
                    }
                }
            }
            // Out of B range of the arena — never place an island in
            // MAP_FIXED territory; UDF emulation is slow but correct.
            return None;
        }
        for &d in &DELTAS {
            let hint = (near_pc as i64).saturating_add(d);
            if hint <= 0 { continue; }
            let hint = (hint as u64) & !(PAGE_SIZE as u64 - 1);
            if let Some(island) = Self::alloc_at_hint(sz, hint) {
                // both ends of the island must be B-reachable from near_pc
                if encode_b(near_pc, island.base).is_some()
                    && encode_b(near_pc, island.base + sz as u64 - 4).is_some() {
                    return Some(island);
                }
                // unmap the whole region including the guard pages
                unsafe {
                    libc::munmap((island.base - PAGE_SIZE as u64) as *mut _,
                        island.capacity + 2 * PAGE_SIZE);
                }
            }
        }
        // Out-of-range island is still useful for OTHER (closer) call sites.
        Self::alloc_at_hint(sz, 0)
    }

    /// Islands get a PROT_NONE guard page on each side: islands now live
    /// NEAR guest mappings (alloc_near), and do_mprotect/do_mmap round
    /// write-granting ranges OUTWARD to 16KB pages — without guards, a
    /// guest mprotect on an adjacent region with an unaligned end bled one
    /// page into the island, stripping PROT_EXEC → SIGBUS fetching a
    /// trampoline (intact bytes, unexecutable page; hit ~1/1600 VPP
    /// compiles). The rounding bleeds at most one page each side, so the
    /// guards absorb it.
    fn alloc_at_hint(size: usize, hint: u64) -> Option<Self> {
        let sz = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let total = sz + 2 * PAGE_SIZE;
        let hint = if hint == 0 { 0 } else { hint.saturating_sub(PAGE_SIZE as u64) };
        let ptr = unsafe {
            libc::mmap(
                hint as *mut _,
                total,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON | 0x800, // 0x800 = MAP_JIT
                -1, 0,
            )
        };
        if ptr == libc::MAP_FAILED { return None; }
        unsafe {
            libc::mprotect(ptr, PAGE_SIZE, libc::PROT_NONE);
            libc::mprotect((ptr as u64 + PAGE_SIZE as u64 + sz as u64) as *mut _,
                PAGE_SIZE, libc::PROT_NONE);
        }
        Some(CodeIsland { base: ptr as u64 + PAGE_SIZE as u64, capacity: sz, used: 0, meta: Vec::new() })
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
        // Pick two scratch registers the instruction does not reference
        // (s1 = TSD base pointer, s2 = substituted guest x18). Historically
        // these were hardcoded x16/x17 and any instruction touching either
        // fell back to UDF — ~40% of all x18 SIGILL traps in a clang run
        // (e.g. `ccmp w17, w18`, `ldr x16, [x20, x18]`).
        let (s1, s2) = pick_scratch_pair(orig_instr)?;
        let subst_instr = crate::decoder::substitute_gpr(orig_instr, 18, s2)?;

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

        let instrs: [u32; TRAMP_INSTRS] = [
            encode_stp_pre32(s1, s2),                  // stp s1, s2, [sp, #-32]!
            encode_mrs_tpidrro(s1),                    // mrs s1, tpidrro_el0
            encode_ldr_unsigned(s2, s1, tsd_off),      // ldr s2, [s1, #(key*8)]
            0x9100_83FF,                               // add sp, sp, #32
            subst_instr,                               // original instr, x18→s2
            0xD100_83FF,                               // sub sp, sp, #32
            encode_mrs_tpidrro(s1),                    // mrs s1, tpidrro_el0
            encode_str_unsigned(s2, s1, tsd_off),      // str s2, [s1, #(key*8)]
            encode_ldp_post32(s1, s2),                 // ldp s1, s2, [sp], #32
            b_back,                                    // b <return>
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

        self.meta.push((orig_pc, orig_instr));
        self.used += size;
        EMIT_GPR_COUNT.fetch_add(1, Ordering::Relaxed);
        Some(tramp_pc)
    }

    /// Emit a TPIDR_EL0 access trampoline. Guest tpidr lives in a TSD slot
    /// (same scheme as guest x18, different pthread key):
    ///   MRS Xt, tpidr_el0 →  mrs Xt, tpidrro_el0 ; ldr Xt, [Xt, #off] ; b
    ///   MSR tpidr_el0, Xt →  str Xs, [sp,#-16]! ; mrs Xs, tpidrro_el0 ;
    ///                        str Xt, [Xs, #off] ; ldr Xs, [sp], #16 ; b
    /// Uses the same fixed-size slots as x18 trampolines (NOP padded).
    fn emit_tpidr(&mut self, orig_pc: u64, orig_instr: u32) -> Option<u64> {
        let tpidr_off = TPIDR_TSD_BYTE_OFFSET.load(Ordering::Relaxed);
        if tpidr_off == 0 { return None; }
        let rt = orig_instr & 0x1F;
        if rt == 31 { return None; } // MRS/MSR to xzr — pointless, keep UDF

        let size = TRAMP_INSTRS * 4;
        if self.used + size > self.capacity { return None; }
        let tramp_pc = self.base + self.used as u64;
        let return_pc = orig_pc + 4;

        let is_mrs = orig_instr & crate::trap::MRS_TPIDR_MASK == crate::trap::MRS_TPIDR_BASE;
        let mut instrs: [u32; TRAMP_INSTRS] = [NOP; TRAMP_INSTRS];
        if is_mrs {
            instrs[0] = encode_mrs_tpidrro(rt);
            instrs[1] = encode_ldr_unsigned(rt, rt, tpidr_off);
            instrs[2] = encode_b(tramp_pc + 2 * 4, return_pc)?;
        } else {
            let s = if rt == 0 { 1 } else { 0 };
            instrs[0] = encode_str_pre16(s);
            instrs[1] = encode_mrs_tpidrro(s);
            instrs[2] = encode_str_unsigned(rt, s, tpidr_off);
            instrs[3] = encode_ldr_post16(s);
            instrs[4] = encode_b(tramp_pc + 4 * 4, return_pc)?;
        }

        unsafe {
            pthread_jit_write_protect_np(0);
            let p = tramp_pc as *mut u32;
            for (i, &ins) in instrs.iter().enumerate() {
                p.add(i).write(ins);
            }
            extern "C" { fn sys_icache_invalidate(start: *mut libc::c_void, size: usize); }
            sys_icache_invalidate(tramp_pc as *mut _, size);
            pthread_jit_write_protect_np(1);
        }

        self.meta.push((orig_pc, orig_instr));
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
    // Environment override to disable trampolines for debugging.
    // Read once in init_trampoline_flags() (NOT here lazily — with the
    // patch-site cache the first call can happen inside the trap handler,
    // where std::env takes the env lock → self-deadlock, see bf94855).
    if TRAMP_DISABLED.load(Ordering::Relaxed) {
        return false;
    }

    // AdvSIMD structure ld/st (e.g. clang's `ld2 {v0.2d, v1.2d}, [x18]`):
    // EmulClass::Other, but perfectly trampolinable — only Rn/Rm are GPRs.
    // Scratch-register conflicts are handled by pick_scratch_pair() in
    // emit(), which chooses two GPRs the instruction does not reference.
    let simd_struct = crate::decoder::is_simd_ldst_struct(instr);

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

    // Verify scratch selection + substitution will succeed in emit();
    // unknown encodings fall back to UDF emulation.
    if pick_scratch_pair(instr)
        .and_then(|(_, s2)| crate::decoder::substitute_gpr(instr, 18, s2))
        .is_none()
    {
        FALLBACK_COUNT.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    let mut islands = ISLANDS.lock().unwrap();

    // Try existing islands. Pre-check B range to the island's NEXT free slot:
    // emit() consumes the slot, so letting it succeed and then failing
    // encode_b would leak trampoline space.
    for island in islands.iter_mut() {
        let next_slot = island.base + island.used as u64;
        if encode_b(pc_addr, next_slot).is_none() {
            continue;
        }
        if let Some(tramp) = island.emit(pc_addr, instr) {
            if let Some(b) = encode_b(pc_addr, tramp) {
                unsafe { (pc_addr as *mut u32).write(b); }
                TRAMP_COUNT.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
    }

    // Need a new island (256 KB = ~6500 trampolines), B-reachable from the
    // patch site — a NULL-hint mmap usually lands out of ±128 MB range for
    // big libraries, dooming every site there to a SIGILL per execution.
    if let Some(mut island) = CodeIsland::alloc_near(256 * 1024, pc_addr) {
        if let Some(tramp) = island.emit(pc_addr, instr) {
            if let Some(b) = encode_b(pc_addr, tramp) {
                unsafe { (pc_addr as *mut u32).write(b); }
                TRAMP_COUNT.fetch_add(1, Ordering::Relaxed);
                islands.push(island);
                return true;
            }
        }
        // keep the island anyway — it may serve other call sites
        islands.push(island);
    }

    FALLBACK_COUNT.fetch_add(1, Ordering::Relaxed);
    false
}

/// TSD byte offset of the guest TPIDR_EL0 slot (tpidr pthread key * 8).
/// 0 = not yet initialized → TPIDR sites fall back to UDF.
static TPIDR_TSD_BYTE_OFFSET: AtomicU32 = AtomicU32::new(0);

pub fn set_tpidr_tsd_offset(byte_offset: u32) {
    TPIDR_TSD_BYTE_OFFSET.store(byte_offset, Ordering::SeqCst);
}

/// Patch an MRS/MSR tpidr_el0 instruction with a B-to-trampoline so TLS
/// accesses execute natively instead of costing one SIGILL each (422k traps
/// in a single VPP clang compile — the dominant trap source once x18 is
/// trampolined). Returns false to fall back to UDF + side-table emulation.
///
/// SAFETY: every thread's TSD tpidr slot is populated before guest code can
/// run on it (main.rs guest entry, thread.rs clone_entry CLONE_SETTLS, fork
/// child re-set, signal trampoline restore), so reading the slot directly
/// from asm matches get_thread_tpidr() exactly. The only semantic loss is a
/// guest writing tpidr_el0 = 0 (the asm slot would read back 0, while the
/// emulated path falls back to the stale global) — no real guest does that.
pub fn patch_tpidr_with_trampoline(pc_addr: u64, instr: u32) -> bool {
    if TRAMP_DISABLED.load(Ordering::Relaxed) {
        return false;
    }
    if TPIDR_TSD_BYTE_OFFSET.load(Ordering::Relaxed) == 0 {
        return false;
    }
    let mut islands = ISLANDS.lock().unwrap();
    for island in islands.iter_mut() {
        let next_slot = island.base + island.used as u64;
        if encode_b(pc_addr, next_slot).is_none() {
            continue;
        }
        if let Some(tramp) = island.emit_tpidr(pc_addr, instr) {
            if let Some(b) = encode_b(pc_addr, tramp) {
                unsafe { (pc_addr as *mut u32).write(b); }
                TRAMP_COUNT.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
    }
    if let Some(mut island) = CodeIsland::alloc_near(256 * 1024, pc_addr) {
        if let Some(tramp) = island.emit_tpidr(pc_addr, instr) {
            if let Some(b) = encode_b(pc_addr, tramp) {
                unsafe { (pc_addr as *mut u32).write(b); }
                TRAMP_COUNT.fetch_add(1, Ordering::Relaxed);
                islands.push(island);
                return true;
            }
        }
        islands.push(island);
    }
    false
}

/// Read trampoline env knobs once, outside signal context (from
/// trap::init_trace_flags via install_handler).
static TRAMP_DISABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn init_trampoline_flags() {
    TRAMP_DISABLED.store(
        std::env::var_os("FAKELINUX_NO_X18_TRAMP").is_some(),
        Ordering::Relaxed,
    );
}

static TRAMP_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static FALLBACK_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// DIAGNOSTIC: count of GPR-x18 trampolines built (emit()), which have the
/// below-sp scratch window — distinct from tpidr/SIMD trampolines.
pub static EMIT_GPR_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// (trampolined_ok, fallback_to_udf) counts — for trap-stats diagnostics.
pub fn tramp_fallback_counts() -> (u64, u64) {
    (TRAMP_COUNT.load(Ordering::Relaxed), FALLBACK_COUNT.load(Ordering::Relaxed))
}

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
        crate::vlog!("fakelinux: x18 trampolines: {} ok, {} fallback to UDF", t, f);
    }
}

/// SIGBUS recovery: if `pc` is the FIRST instruction of a trampoline slot
/// (off==0 → no trampoline side effects have executed yet), return the
/// slot's (guest_orig_pc, orig_instr) so the fault handler can emulate the
/// original instruction directly and continue at orig_pc+4. try_lock —
/// safe from a crash handler.
pub fn island_fault_recovery_info(pc: u64) -> Option<(u64, u32)> {
    const TRAMP_SIZE: u64 = TRAMP_INSTRS as u64 * 4;
    let islands = ISLANDS.try_lock().ok()?;
    for island in islands.iter() {
        if pc >= island.base && pc < island.base + island.used as u64 {
            let delta = pc - island.base;
            if delta % TRAMP_SIZE != 0 {
                return None; // mid-trampoline — partial state, can't recover
            }
            let idx = (delta / TRAMP_SIZE) as usize;
            return island.meta.get(idx).copied();
        }
    }
    None
}

/// DIAGNOSTIC: if `pc` is inside a trampoline island, return its offset within
/// the trampoline slot (0,4,8,... = which instruction). None if not in an island.
pub fn pc_island_slot_offset(pc: u64) -> Option<u64> {
    const TRAMP_SIZE: u64 = TRAMP_INSTRS as u64 * 4;
    let islands = ISLANDS.try_lock().ok()?;
    for island in islands.iter() {
        if pc >= island.base && pc < island.base + island.used as u64 {
            return Some((pc - island.base) % TRAMP_SIZE);
        }
    }
    None
}

/// Diagnostic: does [addr, addr+len) intersect any island (incl. guards)?
/// Returns (island_base, island_capacity). try_lock — safe anywhere.
pub fn range_hits_island(addr: u64, len: u64) -> Option<(u64, u64)> {
    let islands = ISLANDS.try_lock().ok()?;
    let pg = PAGE_SIZE as u64;
    for island in islands.iter() {
        let lo = island.base - pg; // include guard pages
        let hi = island.base + island.capacity as u64 + pg;
        if addr < hi && addr + len > lo {
            return Some((island.base, island.capacity as u64));
        }
    }
    None
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

    // ── Dynamic scratch selection (x16/x17 conflicts used to fall back) ──

    /// T1 — end-to-end: the openssl AES_encrypt "smoking gun" candidate
    /// `LDP W18, W17, [X6, #8]` (instruction word 0x294144d2 — actual byte
    /// found in libcrypto's AES_encrypt at offset +0xfc). The hypothesis
    /// under test is: the trampoline epilogue's `ldp s1, s2, [sp], #32`
    /// unconditionally restores the picked scratch pair regardless of
    /// whether the wrapped instruction also writes to one of them. For
    /// this LDP, Rt2=17 is a destination — if pick_scratch_pair picks
    /// (s1, s2) such that s2==17, the epilogue would clobber the loaded
    /// w17. pick_scratch_pair is supposed to avoid x17 here (it is in
    /// referenced_gprs), but this test verifies the END-TO-END behavior
    /// by actually executing the emitted trampoline and reading back w17.
    #[test]
    fn t1_trampoline_ldp_w18_w17_preserves_w17() {
        crate::trap::init_x18_key();
        //   [0] LDP W18, W17, [X6, #8]   = 0x294144d2
        //   [1] MOV W0, W17 (ORR W0,WZR,W17) = 0x2A1103E0
        //   [2] RET                       = 0xD65F03C0
        let code = alloc_code_page(&[0x294144d2, 0x2A1103E0, 0xD65F03C0]);
        assert!(patch_x18_with_trampoline(code, 0x294144d2),
            "LDP W18, W17 must be trampolinable");
        make_executable(code);
        flush_all_islands();

        // src layout: pass X6=src.as_ptr(). LDP W18, W17, [X6, #8]
        // reads w18 from [X6+8] = src[2], w17 from [X6+12] = src[3].
        let src: [u32; 8] = [0, 0, 0xAAAA_1111, 0xBBBB_2222, 0, 0, 0, 0];
        crate::trap::set_thread_x18(0xDEAD_BEEF);
        let f: extern "C" fn(u64, u64, u64, u64, u64, u64, u64) -> u64 =
            unsafe { std::mem::transmute(code) };
        let result_w0 = f(0, 0, 0, 0, 0, 0, src.as_ptr() as u64) as u32;

        // w17 should hold the value loaded from [X6+12] = 0xBBBB_2222.
        // If the trampoline epilogue clobbered w17, this fails.
        assert_eq!(result_w0, 0xBBBB_2222,
            "trampoline epilogue clobbered w17 — got {:#x}, expected 0xBBBB_2222 (the value LDP loaded into w17)",
            result_w0);
        // TSD x18 should hold the 32-bit zero-extended w18 load.
        assert_eq!(crate::trap::get_thread_x18(), 0xAAAA_1111u64,
            "trampoline must write zero-extended w18 to TSD");
    }

    #[test]
    fn scratch_pair_avoids_referenced_regs() {
        // ldr x16, [x18] references {16, 18} → scratch must avoid both
        let (s1, s2) = pick_scratch_pair(0xF9400250).unwrap();
        assert!(s1 != 16 && s1 != 18 && s2 != 16 && s2 != 18 && s1 != s2);
        // ccmp w17, w18, #0, al references {17, 18}
        let (s1, s2) = pick_scratch_pair(0x7A52E220).unwrap();
        assert!(s1 != 17 && s1 != 18 && s2 != 17 && s2 != 18 && s1 != s2);
        // no conflicts → prefers x16/x17 (historical encoding)
        assert_eq!(pick_scratch_pair(0xb9000243), Some((16, 17))); // str w3, [x18]
    }

    #[test]
    fn push_pop_encoders_match_historical_x16_x17_encoding() {
        assert_eq!(encode_stp_pre32(16, 17), 0xA9BE_47F0);
        assert_eq!(encode_ldp_post32(16, 17), 0xA8C2_47F0);
        assert_eq!(encode_mrs_tpidrro(16), 0xD53B_D070);
    }

    /// End-to-end: `LDR X16, [X18]` (uses scratch reg x16) was rejected by
    /// the hardcoded-x16/x17 check and cost a SIGILL per execution — 54k
    /// traps in a single VPP clang compile. Must now trampoline.
    #[test]
    fn test_trampoline_conflict_ldr_x16_through_guest_x18() {
        crate::trap::init_x18_key();
        // ldr x16, [x18] ; mov x0, x16 ; ret
        let code = alloc_code_page(&[0xF9400250, 0xAA1003E0, 0xD65F03C0]);
        assert!(patch_x18_with_trampoline(code, 0xF9400250),
            "x16-conflicting instruction must be trampolinable");
        make_executable(code);
        flush_all_islands();

        let value: u64 = 0xDEAD_BEEF_1234;
        crate::trap::set_thread_x18(&value as *const u64 as u64);
        let f: extern "C" fn() -> u64 = unsafe { std::mem::transmute(code) };
        assert_eq!(f(), 0xDEAD_BEEF_1234);
    }

    /// End-to-end: `CCMP W17, W18, #0, AL` (uses scratch reg x17) — the
    /// single hottest fallback instruction in a VPP clang compile (66k traps).
    #[test]
    fn test_trampoline_conflict_ccmp_w17_w18() {
        crate::trap::init_x18_key();
        // mov w17, #5 ; ccmp w17, w18, #0, al ; cset w0, eq ; ret
        let code = alloc_code_page(&[0x528000B1, 0x7A52E220, 0x1A9F17E0, 0xD65F03C0]);
        assert!(patch_x18_with_trampoline(code + 4, 0x7A52E220),
            "x17-conflicting CCMP must be trampolinable");
        make_executable(code);
        flush_all_islands();

        let f: extern "C" fn() -> u64 = unsafe { std::mem::transmute(code) };
        crate::trap::set_thread_x18(5);
        assert_eq!(f(), 1, "w17(5) == w18(5) → eq");
        crate::trap::set_thread_x18(7);
        assert_eq!(f(), 0, "w17(5) != w18(7) → ne");
    }

    /// Slot metadata must map an island pc back to (orig_pc, orig_instr)
    /// at slot boundaries (SIGBUS recovery), and refuse mid-slot pcs.
    #[test]
    fn island_recovery_info_maps_slots() {
        crate::trap::init_x18_key();
        let instr = 0xb9000243; // str w3, [x18]
        let code = alloc_code_page(&[instr, 0xD65F03C0]);
        assert!(patch_x18_with_trampoline(code, instr));
        let b = unsafe { (code as *const u32).read() };
        let imm = (((b & 0x03FF_FFFF) as i64) << 38) >> 38;
        let tramp = code.wrapping_add((imm * 4) as u64);
        assert_eq!(island_fault_recovery_info(tramp), Some((code, instr)));
        assert_eq!(island_fault_recovery_info(tramp + 4), None, "mid-slot");
    }

    // ── TPIDR (TLS) trampolines ──────────────────────────────────────────

    /// End-to-end: `MRS X0, TPIDR_EL0` must read the guest tpidr from TSD
    /// natively (422k SIGILL traps per VPP clang compile before this).
    #[test]
    fn test_tpidr_mrs_trampoline_reads_guest_tls() {
        crate::trap::init_tpidr_key();
        // mrs x0, tpidr_el0 ; ret
        let code = alloc_code_page(&[0xD53BD040, 0xD65F03C0]);
        assert!(patch_tpidr_with_trampoline(code, 0xD53BD040),
            "MRS tpidr_el0 must be trampolinable");
        make_executable(code);
        flush_all_islands();

        crate::trap::set_thread_tpidr(0x1234_5678_9ABC);
        let f: extern "C" fn() -> u64 = unsafe { std::mem::transmute(code) };
        assert_eq!(f(), 0x1234_5678_9ABC);
        crate::trap::set_thread_tpidr(0x42);
        assert_eq!(f(), 0x42, "must track per-thread value, not a snapshot");
    }

    /// End-to-end: `MSR TPIDR_EL0, X0` must write the guest tpidr TSD slot
    /// so a subsequent get_thread_tpidr() (and MRS trampoline) sees it.
    #[test]
    fn test_tpidr_msr_trampoline_writes_guest_tls() {
        crate::trap::init_tpidr_key();
        // msr tpidr_el0, x0 ; ret
        let code = alloc_code_page(&[0xD51BD040, 0xD65F03C0]);
        assert!(patch_tpidr_with_trampoline(code, 0xD51BD040),
            "MSR tpidr_el0 must be trampolinable");
        make_executable(code);
        flush_all_islands();

        let f: extern "C" fn(u64) = unsafe { std::mem::transmute(code) };
        f(0xCAFE_0042);
        assert_eq!(crate::trap::get_thread_tpidr(), 0xCAFE_0042);
    }

    /// MRS/MSR with Rt=31 (xzr) must fall back to UDF, not emit nonsense.
    #[test]
    fn test_tpidr_xzr_falls_back() {
        crate::trap::init_tpidr_key();
        let code = alloc_code_page(&[0xD53BD05F, 0xD65F03C0]); // mrs xzr, tpidr_el0
        assert!(!patch_tpidr_with_trampoline(code, 0xD53BD05F));
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
