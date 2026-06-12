use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicI8, AtomicU64, Ordering};

use crate::syscall;

extern "C" {
    pub fn mach_task_self() -> u32;
    pub fn mach_vm_read_overwrite(
        target_task: u32,
        address: u64,
        size: u64,
        data: u64,
        outsize: *mut libc::vm_size_t,
    ) -> i32;
}

/// Flag indicating we're inside our trap handler. When set, other signal
/// handlers (signal_forwarder) must defer delivery by queuing to pending,
/// because the ucontext contains trap handler registers, not guest registers.
pub static IN_TRAP: AtomicBool = AtomicBool::new(false);

// ─── Lazy relocation for relocated ET_EXEC ──────────────────────────────────
// When a non-PIE ET_EXEC is relocated (macOS 4GB PAGEZERO), some absolute
// pointers lack RELA entries and remain unrelocated. When the guest accesses
// one, we get SIGSEGV at the original (pre-relocation) address. The fixup
// handler detects this and adjusts the faulting register or PC on the fly.

/// ET_EXEC relocation delta (0 if not relocated or PIE).
pub static EXEC_BASE_OFFSET: AtomicU64 = AtomicU64::new(0);
/// Original ET_EXEC address range (lowest PT_LOAD vaddr).
pub static EXEC_ORIG_LO: AtomicU64 = AtomicU64::new(0);
/// Original ET_EXEC address range (highest PT_LOAD vaddr + memsz).
pub static EXEC_ORIG_HI: AtomicU64 = AtomicU64::new(0);

/// Debug counter: trace first N SVC syscalls in a fork child.
pub static FORK_SVC_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Debug counter: trace first N UDF traps (SVC+MRS/MSR) in a fork child.
/// Gives a complete picture of every intercepted instruction.
pub static FORK_TRAP_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Debug: canary address and saved value from fork trampoline.
/// Used to check if the stack canary gets corrupted during __libc_fork's child path.
pub static FORK_CANARY_ADDR: AtomicU64 = AtomicU64::new(0);
pub static FORK_CANARY_SAVED: AtomicU64 = AtomicU64::new(0);

/// Debug: address of __libc_fork's `mov w0, w19` instruction (offset c1d28 in libc).
/// When set, we patch it to UDF to intercept __libc_fork's return and log w19.
pub static FORK_RETURN_PROBE: AtomicU64 = AtomicU64::new(0);
/// The original instruction at FORK_RETURN_PROBE (to restore after intercepting).
pub static FORK_RETURN_PROBE_ORIG: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Debug: address of __libc_fork's saved LR on the stack ([sp+0xE0]).
/// Monitored at each FORK_TRAP to detect when it gets corrupted.
pub static FORK_LR_WATCH_ADDR: AtomicU64 = AtomicU64::new(0);
pub static FORK_LR_WATCH_EXPECTED: AtomicU64 = AtomicU64::new(0);

/// Debug: address of __libc_fork's first instruction (sub sp, sp, #0x140 at c1b50).
/// Patched to UDF to intercept every call to __libc_fork and log x30 (caller's LR).
pub static FORK_ENTRY_PROBE: AtomicU64 = AtomicU64::new(0);
pub static FORK_ENTRY_PROBE_ORIG: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
/// Remaining count for FORK_ENTRY_PROBE re-arming.
pub static FORK_ENTRY_PROBE_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Track x30 across traps for FORK_ENTRY_PROBE LR recovery.
static X30_LAST: AtomicU64 = AtomicU64::new(0);
/// Last x30 value that looked like ExecFork's return address (code addr ending in 0x77DC).
static X30_LAST_GOOD_EXEC_FORK: AtomicU64 = AtomicU64::new(0);

/// Address of libapt-pkg's B instruction at offset 0xB7EE4. Set by patch_new_code
/// when it detects libapt-pkg. Used to detect corruption.
pub static LIBAPT_B_WATCH: AtomicU64 = AtomicU64::new(0);
pub static LIBAPT_B_REPORTED: AtomicBool = AtomicBool::new(false);

/// Diagnostic: the x18 instruction currently being emulated (for crash dumps).
static mut CURRENT_X18_INSTR: u32 = 0;
static mut CURRENT_X18_PC: u64 = 0;

/// Last guest PC that issued a SVC — used by futex deadlock diagnostics.
pub static LAST_SVC_PC: AtomicU64 = AtomicU64::new(0);
pub static LAST_SVC_FP: AtomicU64 = AtomicU64::new(0);
pub static LAST_SVC_LR: AtomicU64 = AtomicU64::new(0);

/// Fault-safe read of a u64 from possibly-unmapped memory (Mach read,
/// no recursive SIGSEGV).
pub fn safe_read_u64(addr: u64) -> Option<u64> {
    let mut val: u64 = 0;
    let mut out_size: libc::vm_size_t = 0;
    let kr = unsafe {
        mach_vm_read_overwrite(mach_task_self(), addr, 8, &mut val as *mut u64 as u64, &mut out_size)
    };
    if kr == 0 && out_size == 8 { Some(val) } else { None }
}

/// Format into a stack buffer using raw write — no Mutex, safe after fork.
pub fn raw_fmt(buf: &mut [u8], args: std::fmt::Arguments) -> usize {
    use std::io::Write;
    let mut cursor = std::io::Cursor::new(&mut buf[..]);
    let _ = cursor.write_fmt(args);
    cursor.position() as usize
}

/// The UDF instruction we patch in place of SVC #0 and MSR/MRS tpidr_el0.
/// UDF #imm16 encoding on aarch64: 0x0000XXXX. We use UDF #0xF000 = 0x0000F000.
/// UDF triggers SIGILL (not SIGTRAP), and macOS preserves x18 in the mcontext
/// for SIGILL — unlike BRK/SIGTRAP which zeroes x18.
pub const UDF_MARKER: u32 = 0x0000_F000;

/// The original SVC #0 encoding.
pub const SVC_0: u32 = 0xD400_0001;

/// MSR tpidr_el0, Xn — mask and base for detection
pub const MSR_TPIDR_MASK: u32 = 0xFFFF_FFE0;
pub const MSR_TPIDR_BASE: u32 = 0xD51B_D040;

/// MRS Xn, tpidr_el0 — mask and base for detection
pub const MRS_TPIDR_MASK: u32 = 0xFFFF_FFE0;
pub const MRS_TPIDR_BASE: u32 = 0xD53B_D040;

/// Guest's TPIDR_EL0 value. macOS clobbers TPIDR_EL0 on every signal
/// entry/return (restoring it to ~0x1004), so we must track the guest's
/// value ourselves and intercept all MSR/MRS tpidr_el0 instructions.
/// This global is used as fallback and for the main thread's initial value.
pub static GUEST_TPIDR: AtomicU64 = AtomicU64::new(0);

// ─── Per-thread TPIDR via pthread keys ──────────────────────────────────────

/// pthread_key_t for per-thread guest TPIDR storage.
static TPIDR_KEY: AtomicU64 = AtomicU64::new(0);
/// Whether init_tpidr_key() has been called.
static TPIDR_KEY_INIT: AtomicBool = AtomicBool::new(false);

/// Initialize the pthread key for per-thread TPIDR. Idempotent; called once
/// before loading the ELF (and freely from tests).
pub fn init_tpidr_key() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let mut key: libc::pthread_key_t = 0;
        let ret = unsafe { libc::pthread_key_create(&mut key, None) };
        if ret != 0 {
            panic!("pthread_key_create for TPIDR failed: {}", ret);
        }
        TPIDR_KEY.store(key as u64, Ordering::SeqCst);
        // Tell the trampoline system the TSD byte offset BEFORE marking
        // initialized (same ordering rule as init_x18_key).
        crate::x18_trampoline::set_tpidr_tsd_offset(key as u32 * 8);
        TPIDR_KEY_INIT.store(true, Ordering::SeqCst);
    });
}

/// Set the per-thread guest TPIDR value.
pub fn set_thread_tpidr(val: u64) {
    // Log TPIDR changes for debugging TLS/stack overlap issues
    if crate::syscall::trace_enabled() {
        let pid = unsafe { libc::getpid() };
        let sp: u64;
        unsafe { core::arch::asm!("mov {}, sp", out(reg) sp); }
        let mut buf = [0u8; 120];
        let n = raw_fmt(&mut buf, format_args!(
            "fakelinux: [{}] SET_TPIDR={:#x} sp={:#x} delta={:#x}\n",
            pid, val, sp, val.wrapping_sub(sp)
        ));
        unsafe { libc::write(2, buf.as_ptr() as *const _, n); }
    }
    if !TPIDR_KEY_INIT.load(Ordering::SeqCst) {
        // Fallback to global before key is initialized
        GUEST_TPIDR.store(val, Ordering::SeqCst);
        return;
    }
    let key = TPIDR_KEY.load(Ordering::SeqCst) as libc::pthread_key_t;
    unsafe { libc::pthread_setspecific(key, val as *const libc::c_void); }
    // Also update global for compatibility
    GUEST_TPIDR.store(val, Ordering::SeqCst);
}

/// Get the per-thread guest TPIDR value.
pub fn get_thread_tpidr() -> u64 {
    if !TPIDR_KEY_INIT.load(Ordering::SeqCst) {
        return GUEST_TPIDR.load(Ordering::SeqCst);
    }
    let key = TPIDR_KEY.load(Ordering::SeqCst) as libc::pthread_key_t;
    let val = unsafe { libc::pthread_getspecific(key) } as u64;
    // If this thread never called set_thread_tpidr, val will be 0 (NULL).
    // Fall back to the global in that case.
    if val == 0 {
        GUEST_TPIDR.load(Ordering::SeqCst)
    } else {
        val
    }
}

pub fn get_guest_tpidr() -> u64 {
    get_thread_tpidr()
}

// ─── Per-thread x18 via pthread keys ─────────────────────────────────────────

/// pthread_key_t for per-thread guest x18 storage.
static X18_KEY: AtomicU64 = AtomicU64::new(0);
/// Whether init_x18_key() has been called.
static X18_KEY_INIT: AtomicBool = AtomicBool::new(false);

/// Initialize the pthread key for per-thread x18. Idempotent; called once at
/// startup (and freely from tests).
pub fn init_x18_key() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let mut key: libc::pthread_key_t = 0;
        let ret = unsafe { libc::pthread_key_create(&mut key, None) };
        if ret != 0 {
            panic!("pthread_key_create for x18 failed: {}", ret);
        }
        X18_KEY.store(key as u64, Ordering::SeqCst);
        // Tell the trampoline system the TSD byte offset BEFORE marking
        // initialized, so concurrent readers never see a half-initialized state.
        crate::x18_trampoline::set_tsd_offset(key as u32 * 8);
        X18_KEY_INIT.store(true, Ordering::SeqCst);
    });
}

/// Set the per-thread guest x18 value.
pub fn set_thread_x18(val: u64) {
    if !X18_KEY_INIT.load(Ordering::SeqCst) {
        crate::x18_trampoline::GUEST_X18_GLOBAL.store(val, Ordering::Relaxed);
        return;
    }
    let key = X18_KEY.load(Ordering::SeqCst) as libc::pthread_key_t;
    unsafe { libc::pthread_setspecific(key, val as *const libc::c_void); }
}

/// Get the per-thread guest x18 value.
pub fn get_thread_x18() -> u64 {
    if !X18_KEY_INIT.load(Ordering::SeqCst) {
        return crate::x18_trampoline::GUEST_X18_GLOBAL.load(Ordering::Relaxed);
    }
    let key = X18_KEY.load(Ordering::SeqCst) as libc::pthread_key_t;
    unsafe { libc::pthread_getspecific(key) as u64 }
}

// macOS aarch64 mcontext structures

#[repr(C)]
pub struct ExceptionState64 {
    pub far: u64,
    pub esr: u32,
    pub exception: u32,
}

#[repr(C)]
pub struct ThreadState64 {
    pub x: [u64; 29],
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u32,
    pub _pad: u32,
}

#[repr(C)]
pub struct NeonState64 {
    pub v: [u128; 32],  // q0-q31, each 128 bits
    pub fpsr: u32,
    pub fpcr: u32,
}

#[repr(C)]
pub struct MContext64 {
    pub es: ExceptionState64,
    pub ss: ThreadState64,
    pub ns: NeonState64,
}

#[repr(C)]
pub struct UContext {
    pub uc_onstack: i32,
    pub uc_sigmask: u32,
    pub uc_stack: libc::stack_t,
    pub uc_link: *mut UContext,
    pub uc_mcsize: usize,
    pub uc_mcontext: *mut MContext64,
}

/// Read a register value from the saved thread state by register number (0-30).
fn read_reg(regs: &ThreadState64, n: usize) -> u64 {
    match n {
        0..=28 => regs.x[n],
        29 => regs.fp,
        30 => regs.lr,
        _ => 0,
    }
}

/// Write a register value in the saved thread state by register number.
fn write_reg(regs: &mut ThreadState64, n: usize, val: u64) {
    match n {
        0..=28 => regs.x[n] = val,
        29 => regs.fp = val,
        30 => regs.lr = val,
        _ => {}
    }
}

/// Read a GPR value, substituting x18 with the per-thread saved value.
/// Register 31 returns 0 (XZR) — use read_gpr_sp for load/store base registers.
fn read_gpr(regs: &ThreadState64, n: usize) -> u64 {
    if n == 18 {
        get_thread_x18()
    } else {
        read_reg(regs, n)
    }
}

/// Read a GPR value, but register 31 returns SP instead of XZR.
/// Use this for Rn (base register) in load/store instructions.
fn read_gpr_sp(regs: &ThreadState64, n: usize) -> u64 {
    if n == 31 { regs.sp }
    else if n == 18 { get_thread_x18() }
    else { read_reg(regs, n) }
}

/// Write a GPR value, but register 31 writes to SP instead of being ignored.
fn write_gpr_sp(regs: &mut ThreadState64, n: usize, val: u64) {
    if n == 30 && crate::syscall::trace_enabled() {
        let pc = regs.pc;
        let pid = unsafe { libc::getpid() };
        let mut buf = [0u8; 160];
        let sz = raw_fmt(&mut buf, format_args!(
            "fakelinux: [{}] WRITE_X30_SP val={:#x} pc={:#x}\n", pid, val, pc));
        unsafe { libc::write(2, buf.as_ptr() as *const _, sz); }
    }
    if n == 31 { regs.sp = val; }
    else if n == 18 { set_thread_x18(val); }
    else { write_reg(regs, n, val); }
}

/// Write a GPR value, storing x18 to per-thread storage instead of mcontext.
fn write_gpr(regs: &mut ThreadState64, n: usize, val: u64) {
    // DEBUG: log any write to x30 (LR) — this catches corruption of the return address
    if n == 30 && crate::syscall::trace_enabled() {
        let pc = regs.pc;
        let pid = unsafe { libc::getpid() };
        let mut buf = [0u8; 160];
        let sz = raw_fmt(&mut buf, format_args!(
            "fakelinux: [{}] WRITE_X30 val={:#x} pc={:#x}\n", pid, val, pc));
        unsafe { libc::write(2, buf.as_ptr() as *const _, sz); }
    }
    if n == 18 {
        set_thread_x18(val);
    } else {
        write_reg(regs, n, val);
    }
}

pub fn references_x18(instr: u32) -> bool {
    // Use the unified decoder::references_x18 as the single source of truth
    crate::decoder::references_x18(instr)
}

/// Emulate an instruction that references x18, substituting per-thread x18 storage.
/// Returns true if emulation succeeded.
///
/// Uses the XML-generated decode table (via `decode_emul_class()`) to classify
/// the instruction, then dispatches to the appropriate handler.
fn emulate_x18_instruction(orig_instr: u32, mctx: &mut MContext64) -> bool {
    use crate::decoder::EmulClass;
    let instr_pc = mctx.ss.pc;

    match crate::decoder::decode_emul_class(orig_instr) {
        EmulClass::AddSubImm => emul_addsub_imm(orig_instr, mctx),
        EmulClass::MoveWide => emul_move_wide(orig_instr, mctx),
        EmulClass::LogicalImm => emul_logical_imm(orig_instr, mctx),
        EmulClass::LogicalShiftedReg => emul_logical_shifted_reg(orig_instr, mctx),
        EmulClass::AddSubShiftedReg => emul_addsub_shifted_reg(orig_instr, mctx),
        EmulClass::AddSubExtReg => emul_addsub_ext_reg(orig_instr, mctx),
        EmulClass::AddSubCarry => emul_addsub_carry(orig_instr, mctx),
        EmulClass::CondSelect => emul_cond_select(orig_instr, mctx),
        EmulClass::DataProc2Src => emul_dp2_src(orig_instr, mctx),
        EmulClass::DataProc3Src => emul_dp3_src(orig_instr, mctx),
        EmulClass::LdrStrUnsignedImm => emul_ldr_str_unsigned_imm(orig_instr, mctx),
        EmulClass::LdrStrUnscaled => emul_ldr_str_unscaled(orig_instr, mctx),
        EmulClass::LdrStrPrePost => emul_ldr_str_prepost(orig_instr, mctx),
        EmulClass::LdrStrRegOffset => emul_ldr_str_reg_offset(orig_instr, mctx),
        EmulClass::LdpStp => emul_ldp_stp(orig_instr, mctx),
        EmulClass::Bitfield => emul_bitfield(orig_instr, mctx),
        EmulClass::PcRelAddr => emul_adr_adrp(orig_instr, instr_pc, mctx),
        EmulClass::CompareBranch => emul_cbz_cbnz(orig_instr, instr_pc, mctx),
        EmulClass::TestBranch => emul_tbz_tbnz(orig_instr, instr_pc, mctx),
        EmulClass::CondCompareReg => emul_ccmp_reg(orig_instr, mctx),
        EmulClass::CondCompareImm => emul_ccmp_imm(orig_instr, mctx),
        EmulClass::FloatGprConvert => emul_fmov(orig_instr, mctx),
        EmulClass::Extract => emul_extract(orig_instr, mctx),
        EmulClass::DataProc1Src => emul_dp1_src(orig_instr, mctx),
        other => {
            // AdvSIMD copy (DUP/INS/SMOV/UMOV) — not in the XML GPR table but
            // can reference x18 as GPR operand (or v18, which the patcher
            // also matches). Pattern: 0_Q_op_01110000_imm5_0_imm4_1_Rn_Rd.
            if orig_instr & 0x9FE0_8400 == 0x0E00_0400 {
                return emul_simd_copy(orig_instr, mctx);
            }
            let pc = mctx.ss.pc;
            panic!(
                "fakelinux: UNHANDLED EmulClass::{:?} for instr={:#010x} at pc={:#x}",
                other, orig_instr, pc
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Emulation handler functions (one per EmulClass)
// ═══════════════════════════════════════════════════════════════════════════

fn emul_addsub_imm(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    // ADD/SUB immediate: sf_op_S_100010_sh_imm12_Rn_Rd
    if orig_instr & 0x1F00_0000 == 0x1100_0000 {
        let sf = (orig_instr >> 31) & 1;
        let op = (orig_instr >> 30) & 1; // 0=ADD, 1=SUB
        let s = (orig_instr >> 29) & 1;
        let sh = ((orig_instr >> 22) & 1) as u32;
        let imm12 = ((orig_instr >> 10) & 0xFFF) as u64;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rd = (orig_instr & 0x1F) as usize;
        let imm = if sh == 1 { imm12 << 12 } else { imm12 };
        let a = read_gpr_sp(regs, rn);
        let result = if op == 0 { a.wrapping_add(imm) } else { a.wrapping_sub(imm) };
        let result = if sf == 0 { result & 0xFFFF_FFFF } else { result };
        if s == 1 {
            // ADDS/SUBS — update flags; Rd=31 means XZR (CMP), not SP
            update_nzcv(regs, a, imm, result, op == 1, sf == 1);
            if rd != 31 { write_gpr(regs, rd, result); }
        } else {
            // ADD/SUB without flags: Rd=31 means SP
            write_gpr_sp(regs, rd, result);
        }
        return true;
    }
    false
}

fn emul_move_wide(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    {
        let sf = (orig_instr >> 31) & 1;
        let opc = (orig_instr >> 29) & 0x3;
        let hw = ((orig_instr >> 21) & 0x3) as u32;
        let imm16 = ((orig_instr >> 5) & 0xFFFF) as u64;
        let rd = (orig_instr & 0x1F) as usize;
        let shift = hw * 16;
        let val = match opc {
            0 => { // MOVN
                let wide = imm16 << shift;
                if sf == 1 { !wide } else { (!wide) & 0xFFFF_FFFF }
            }
            2 => { // MOVZ
                imm16 << shift
            }
            3 => { // MOVK
                let old = read_gpr(regs, rd);
                let mask = !(0xFFFFu64 << shift);
                (old & mask) | (imm16 << shift)
            }
            _ => return false,
        };
        if rd != 31 { write_gpr(regs, rd, val); }
        return true;
    }
    false
}

fn emul_logical_imm(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    {
        let sf = (orig_instr >> 31) & 1;
        let opc = (orig_instr >> 29) & 0x3;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rd = (orig_instr & 0x1F) as usize;
        if let Some(imm) = decode_bitmask_imm(orig_instr, sf == 1) {
            let a = read_gpr(regs, rn);
            let result = match opc {
                0 => a & imm,   // AND
                1 => a | imm,   // ORR
                2 => a ^ imm,   // EOR
                3 => a & imm,   // ANDS
                _ => unreachable!(),
            };
            let result = if sf == 0 { result & 0xFFFF_FFFF } else { result };
            if opc == 3 {
                // ANDS — update NZ, clear CV; Rd=31 is XZR
                let bits = if sf == 1 { 64 } else { 32 };
                let n = (result >> (bits - 1)) & 1;
                let z = if result == 0 { 1 } else { 0 };
                regs.cpsr = (regs.cpsr & 0x0FFF_FFFF) | ((n as u32) << 31) | ((z as u32) << 30);
                if rd != 31 { write_gpr(regs, rd, result); }
            } else {
                // AND/ORR/EOR — Rd=31 is SP
                write_gpr_sp(regs, rd, result);
            }
            return true;
        }
        return false; // bad bitmask encoding
    }
    false
}

fn emul_logical_shifted_reg(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    {
        let sf = (orig_instr >> 31) & 1;
        let opc = (orig_instr >> 29) & 0x3;
        let n_bit = (orig_instr >> 21) & 1; // NOT flag
        let shift_type = (orig_instr >> 22) & 0x3;
        let rm = ((orig_instr >> 16) & 0x1F) as usize;
        let imm6 = ((orig_instr >> 10) & 0x3F) as u32;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rd = (orig_instr & 0x1F) as usize;
        let bits = if sf == 1 { 64u32 } else { 32 };
        let mut b = read_gpr(regs, rm);
        if sf == 0 { b &= 0xFFFF_FFFF; }
        b = apply_shift(b, shift_type, imm6, bits);
        if n_bit == 1 { b = !b; if sf == 0 { b &= 0xFFFF_FFFF; } }
        let a = read_gpr(regs, rn);
        let result = match opc {
            0 => a & b,   // AND / BIC
            1 => a | b,   // ORR / ORN
            2 => a ^ b,   // EOR / EON
            3 => a & b,   // ANDS / BICS
            _ => unreachable!(),
        };
        let result = if sf == 0 { result & 0xFFFF_FFFF } else { result };
        if opc == 3 {
            let n = (result >> (bits - 1)) & 1;
            let z = if result == 0 { 1 } else { 0 };
            regs.cpsr = (regs.cpsr & 0x0FFF_FFFF) | ((n as u32) << 31) | ((z as u32) << 30);
        }
        if rd != 31 { write_gpr(regs, rd, result); }
        return true;
    }
    false
}

fn emul_addsub_shifted_reg(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    {
        let sf = (orig_instr >> 31) & 1;
        let op = (orig_instr >> 30) & 1;
        let s = (orig_instr >> 29) & 1;
        let shift_type = (orig_instr >> 22) & 0x3;
        let rm = ((orig_instr >> 16) & 0x1F) as usize;
        let imm6 = ((orig_instr >> 10) & 0x3F) as u32;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rd = (orig_instr & 0x1F) as usize;
        let bits = if sf == 1 { 64u32 } else { 32 };
        let mut b = read_gpr(regs, rm);
        if sf == 0 { b &= 0xFFFF_FFFF; }
        b = apply_shift(b, shift_type, imm6, bits);
        let a = read_gpr(regs, rn);
        let result = if op == 0 { a.wrapping_add(b) } else { a.wrapping_sub(b) };
        let result = if sf == 0 { result & 0xFFFF_FFFF } else { result };
        if s == 1 { update_nzcv(regs, a, b, result, op == 1, sf == 1); }
        if rd != 31 { write_gpr(regs, rd, result); }
        return true;
    }
    false
}

fn emul_addsub_ext_reg(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    {
        let sf = (orig_instr >> 31) & 1;
        let op = (orig_instr >> 30) & 1;
        let s = (orig_instr >> 29) & 1;
        let rm = ((orig_instr >> 16) & 0x1F) as usize;
        let option = (orig_instr >> 13) & 0x7;
        let imm3 = ((orig_instr >> 10) & 0x7) as u32;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rd = (orig_instr & 0x1F) as usize;
        let b_raw = read_gpr(regs, rm);
        let b_ext = extend_reg(b_raw, option, imm3);
        let a = read_gpr_sp(regs, rn);
        let result = if op == 0 { a.wrapping_add(b_ext) } else { a.wrapping_sub(b_ext) };
        let result = if sf == 0 { result & 0xFFFF_FFFF } else { result };
        if s == 1 {
            update_nzcv(regs, a, b_ext, result, op == 1, sf == 1);
            if rd != 31 { write_gpr(regs, rd, result); }
        } else {
            write_gpr_sp(regs, rd, result);
        }
        return true;
    }
    false
}

fn emul_addsub_carry(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    {
        let sf = (orig_instr >> 31) & 1;
        let op = (orig_instr >> 30) & 1;
        let s = (orig_instr >> 29) & 1;
        let rm = ((orig_instr >> 16) & 0x1F) as usize;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rd = (orig_instr & 0x1F) as usize;
        let a = read_gpr(regs, rn);
        let b = read_gpr(regs, rm);
        let carry = (regs.cpsr >> 29) & 1; // C flag
        let result = if op == 0 {
            // ADC: Rd = Rn + Rm + C
            a.wrapping_add(b).wrapping_add(carry as u64)
        } else {
            // SBC: Rd = Rn - Rm - !C = Rn + ~Rm + C
            a.wrapping_add(!b).wrapping_add(carry as u64)
        };
        let result = if sf == 0 { result & 0xFFFF_FFFF } else { result };
        if s == 1 {
            // ADC/SBC needs its own carry/overflow computation (3-operand)
            let bits = if sf == 1 { 64u32 } else { 32 };
            let mask = if bits == 64 { u64::MAX } else { 0xFFFF_FFFF };
            let a_m = a & mask;
            let b_eff = if op == 0 { b & mask } else { (!b) & mask };
            // Carry: use 128-bit to detect overflow
            let wide = (a_m as u128) + (b_eff as u128) + (carry as u128);
            let c_out = (wide >> bits) & 1;
            // N, Z from result
            let n = (result >> (bits - 1)) & 1;
            let z = if (result & mask) == 0 { 1u32 } else { 0 };
            // Overflow: sign of a_m and b_eff agree, but differ from result
            let sa = (a_m >> (bits - 1)) & 1;
            let sb = (b_eff >> (bits - 1)) & 1;
            let sr = (result >> (bits - 1)) & 1;
            let v = if sa == sb && sa != sr { 1u32 } else { 0 };
            regs.cpsr = (regs.cpsr & 0x0FFF_FFFF)
                | ((n as u32) << 31) | (z << 30) | ((c_out as u32) << 29) | (v << 28);
        }
        if rd != 31 { write_gpr(regs, rd, result); }
        return true;
    }
    false
}

fn emul_cond_select(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    {
        let sf = (orig_instr >> 31) & 1;
        let op = (orig_instr >> 30) & 1;
        let rm = ((orig_instr >> 16) & 0x1F) as usize;
        let cond = ((orig_instr >> 12) & 0xF) as u32;
        let op2 = (orig_instr >> 10) & 1;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rd = (orig_instr & 0x1F) as usize;
        let cond_true = eval_condition(cond, regs.cpsr);
        let result = if cond_true {
            read_gpr(regs, rn)
        } else {
            let val = read_gpr(regs, rm);
            match (op, op2) {
                (0, 0) => val,                   // CSEL
                (0, 1) => val.wrapping_add(1),   // CSINC
                (1, 0) => !val,                   // CSINV
                (1, 1) => (!val).wrapping_add(1), // CSNEG
                _ => val,
            }
        };
        let result = if sf == 0 { result & 0xFFFF_FFFF } else { result };
        if rd != 31 { write_gpr(regs, rd, result); }
        return true;
    }
    false
}

fn emul_dp2_src(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    {
        let sf = (orig_instr >> 31) & 1;
        let rm = ((orig_instr >> 16) & 0x1F) as usize;
        let opcode = (orig_instr >> 10) & 0x3F;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rd = (orig_instr & 0x1F) as usize;
        let bits = if sf == 1 { 64u32 } else { 32 };
        let a = read_gpr(regs, rn);
        let b = read_gpr(regs, rm);
        let (a, b) = if sf == 0 { (a & 0xFFFF_FFFF, b & 0xFFFF_FFFF) } else { (a, b) };
        let result = match opcode {
            2 => if b == 0 { 0 } else { a / b },               // UDIV
            3 => if b == 0 { 0 } else {                         // SDIV
                if sf == 1 { (a as i64).wrapping_div(b as i64) as u64 }
                else { ((a as i32).wrapping_div(b as i32) as u32) as u64 }
            },
            8 => a << (b % bits as u64),    // LSLV
            9 => a >> (b % bits as u64),    // LSRV
            10 => {                          // ASRV
                if sf == 1 { ((a as i64) >> (b % 64)) as u64 }
                else { (((a as i32) >> (b % 32)) as u32) as u64 }
            },
            11 => {                          // RORV
                let shift = (b % bits as u64) as u32;
                if sf == 1 { a.rotate_right(shift) }
                else { (a as u32).rotate_right(shift) as u64 }
            }
            _ => return false,
        };
        let result = if sf == 0 { result & 0xFFFF_FFFF } else { result };
        if rd != 31 { write_gpr(regs, rd, result); }
        return true;
    }
    false
}

fn emul_dp3_src(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    {
        let sf = (orig_instr >> 31) & 1;
        let op31 = (orig_instr >> 21) & 0x7;
        let rm = ((orig_instr >> 16) & 0x1F) as usize;
        let o0 = (orig_instr >> 15) & 1;
        let ra = ((orig_instr >> 10) & 0x1F) as usize;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rd = (orig_instr & 0x1F) as usize;
        let a = read_gpr(regs, rn);
        let b = read_gpr(regs, rm);
        let result = match (sf, op31, o0) {
            // MADD (64/32): Rd = Ra + Rn*Rm
            (_, 0b000, 0) => {
                let c = if ra == 31 { 0 } else { read_gpr(regs, ra) };
                c.wrapping_add(a.wrapping_mul(b))
            }
            // MSUB (64/32): Rd = Ra - Rn*Rm
            (_, 0b000, 1) => {
                let c = if ra == 31 { 0 } else { read_gpr(regs, ra) };
                c.wrapping_sub(a.wrapping_mul(b))
            }
            // SMADDL: Xd = Xa + Wn*Wm (signed 32×32→64)
            (1, 0b001, 0) => {
                let c = if ra == 31 { 0 } else { read_gpr(regs, ra) };
                let prod = (a as i32 as i64).wrapping_mul(b as i32 as i64) as u64;
                c.wrapping_add(prod)
            }
            // SMSUBL: Xd = Xa - Wn*Wm (signed 32×32→64)
            (1, 0b001, 1) => {
                let c = if ra == 31 { 0 } else { read_gpr(regs, ra) };
                let prod = (a as i32 as i64).wrapping_mul(b as i32 as i64) as u64;
                c.wrapping_sub(prod)
            }
            // SMULH: Xd = (Xn * Xm) >> 64 (signed high multiply)
            (1, 0b010, 0) => {
                ((a as i64 as i128).wrapping_mul(b as i64 as i128) >> 64) as u64
            }
            // UMADDL: Xd = Xa + Wn*Wm (unsigned 32×32→64)
            (1, 0b101, 0) => {
                let c = if ra == 31 { 0 } else { read_gpr(regs, ra) };
                let prod = (a as u32 as u64).wrapping_mul(b as u32 as u64);
                c.wrapping_add(prod)
            }
            // UMSUBL: Xd = Xa - Wn*Wm (unsigned 32×32→64)
            (1, 0b101, 1) => {
                let c = if ra == 31 { 0 } else { read_gpr(regs, ra) };
                let prod = (a as u32 as u64).wrapping_mul(b as u32 as u64);
                c.wrapping_sub(prod)
            }
            // UMULH: Xd = (Xn * Xm) >> 64 (unsigned high multiply)
            (1, 0b110, 0) => {
                ((a as u128).wrapping_mul(b as u128) >> 64) as u64
            }
            _ => {
                // Fallback: MADD-like (for any unrecognized subtype)
                let c = if ra == 31 { 0 } else { read_gpr(regs, ra) };
                c.wrapping_add(a.wrapping_mul(b))
            }
        };
        let result = if sf == 0 { result & 0xFFFF_FFFF } else { result };
        if rd != 31 { write_gpr(regs, rd, result); }
        return true;
    }
    false
}

// ─── X18-relative store tracer (FAKELINUX_TRACE_X18_STORES) ──────────────────
//
// Diagnostic helper for the libc6 zstd "Data corruption detected" blocker
// (see project_libc6_zstd_corruption.md). Every emulated x18-aware STR/STP
// path reports its destination so we can cross-reference stores against the
// decompressor's heap layout — a stray store landing inside libzstd's DCtx
// would explain why decompression sees corrupt state with intact input bytes.
//
// Cached so the env-var lookup is O(1) per store after the first call.
// -1 = uninitialised, 0 = disabled, 1 = enabled.

static X18_STORE_TRACE: AtomicI8 = AtomicI8::new(-1);
/// pid for which we've already snapshotted /proc/self/maps. 0 = none yet.
static X18_STORE_MAPS_DUMPED_PID: AtomicU64 = AtomicU64::new(0);

// Trace flags read in trap_handler context. std::env::var takes the Rust env
// lock — if a signal lands while the interrupted code holds it (e.g. setenv in
// pidns::set_child_env after fork), the handler self-deadlocks on
// env_read_lock (semaphore_wait_trap, seen hanging xdp-tools configure for
// 10h). ALL env access for handler paths must happen in init_trace_flags(),
// called from install_handler() before any guest code runs.
static TRACE_LR_ENABLED: AtomicBool = AtomicBool::new(false);
static TRACE_X18_ENABLED: AtomicBool = AtomicBool::new(false);

// ── Software watchpoint (debug tool) ─────────────────────────────────────
// FAKELINUX_WATCH=<seq>:<len>:<off> (hex, no 0x): arm a write-watch on the
// 8-byte slot at offset <off> into the <seq>-th anonymous guest mmap of
// length <len>. The page is kept PROT_READ; each write faults, we patch the
// NEXT instruction with a UDF probe, let the store execute natively (any
// store form incl. writeback/STP), then re-protect and log if the watched
// slot changed. Single-threaded guests only.
pub static WATCH_MMAP_LEN: AtomicU64 = AtomicU64::new(0);
pub static WATCH_MMAP_SEQ: AtomicU64 = AtomicU64::new(0);
pub static WATCH_OFF: AtomicU64 = AtomicU64::new(0);
pub static WATCH_ADDR: AtomicU64 = AtomicU64::new(0);
pub static WATCH_PAGE: AtomicU64 = AtomicU64::new(0);
static WATCH_STEP_PC: AtomicU64 = AtomicU64::new(0);
static WATCH_STEP_ORIG: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static WATCH_PREV_VAL: AtomicU64 = AtomicU64::new(0);
static WATCH_FAULT_PC: AtomicU64 = AtomicU64::new(0);
/// UDF payload for the watchpoint single-step probe (distinct from
/// UDF_MARKER 0xF000 and never produced by the loader patcher).
pub const UDF_WATCH_STEP: u32 = 0x0000_F00D;

// ── Trap statistics (FAKELINUX_TRAP_STATS=1) ─────────────────────────────
// Counts SIGILL traps by kind, plus a lossy open-addressed histogram of the
// exact x18 instruction words that reach the (expensive) signal fallback —
// i.e. the sites the trampoline generator rejected. Dumped at exit_group.
// All atomics; safe to bump from signal context.
static TRAP_STATS_ENABLED: AtomicBool = AtomicBool::new(false);
pub static STAT_SVC: AtomicU64 = AtomicU64::new(0);
pub static STAT_TPIDR: AtomicU64 = AtomicU64::new(0);
pub static STAT_X18: AtomicU64 = AtomicU64::new(0);
const STAT_SLOTS: usize = 256;
static STAT_INSTR_KEY: [std::sync::atomic::AtomicU32; STAT_SLOTS] =
    [const { std::sync::atomic::AtomicU32::new(0) }; STAT_SLOTS];
static STAT_INSTR_CNT: [AtomicU64; STAT_SLOTS] =
    [const { AtomicU64::new(0) }; STAT_SLOTS];

#[inline]
pub fn trap_stats_enabled() -> bool {
    TRAP_STATS_ENABLED.load(Ordering::Relaxed)
}

/// Record one signal-fallback x18 instruction (lossy on table overflow).
pub fn stat_record_x18_instr(instr: u32) {
    let mut idx = (instr.wrapping_mul(0x9E37_79B1) >> 24) as usize % STAT_SLOTS;
    for _ in 0..8 {
        let k = STAT_INSTR_KEY[idx].load(Ordering::Relaxed);
        if k == instr {
            STAT_INSTR_CNT[idx].fetch_add(1, Ordering::Relaxed);
            return;
        }
        if k == 0 {
            // claim the slot; on race the loser just probes on
            if STAT_INSTR_KEY[idx]
                .compare_exchange(0, instr, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                STAT_INSTR_CNT[idx].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        idx = (idx + 1) % STAT_SLOTS;
    }
}

/// Dump trap statistics to stderr (raw writes — called on the exit path,
/// possibly from signal context).
pub fn dump_trap_stats() {
    if !trap_stats_enabled() {
        return;
    }
    let svc = STAT_SVC.load(Ordering::Relaxed);
    let tpidr = STAT_TPIDR.load(Ordering::Relaxed);
    let x18 = STAT_X18.load(Ordering::Relaxed);
    if svc + tpidr + x18 == 0 {
        return;
    }
    let pid = unsafe { libc::getpid() };
    let mut buf = [0u8; 160];
    let n = raw_fmt(&mut buf, format_args!(
        "fakelinux: [{}] TRAP_STATS svc={} tpidr={} x18_fallback={}\n",
        pid, svc, tpidr, x18));
    unsafe { libc::write(2, buf.as_ptr() as *const _, n) };
    // top instructions, simple selection sort without allocating
    let mut done = [false; STAT_SLOTS];
    let mut printed = 0;
    while printed < 15 {
        let mut best = 0u64;
        let mut best_i = usize::MAX;
        for i in 0..STAT_SLOTS {
            let c = STAT_INSTR_CNT[i].load(Ordering::Relaxed);
            if !done[i] && c > best {
                best = c;
                best_i = i;
            }
        }
        if best_i == usize::MAX || best == 0 {
            break;
        }
        done[best_i] = true;
        let instr = STAT_INSTR_KEY[best_i].load(Ordering::Relaxed);
        let mut buf = [0u8; 160];
        let n = raw_fmt(&mut buf, format_args!(
            "fakelinux: [{}] TRAP_STATS x18 instr={:#010x} class={:?} count={}\n",
            pid, instr, crate::decoder::decode_emul_class(instr), best));
        unsafe { libc::write(2, buf.as_ptr() as *const _, n) };
        printed += 1;
    }
}

/// Read handler-path trace knobs from the environment ONCE, outside signal
/// context. Async-signal-safe getters below only load atomics.
pub fn init_trace_flags() {
    crate::loader::init_patch_cache();
    crate::x18_trampoline::init_trampoline_flags();
    TRAP_STATS_ENABLED.store(
        std::env::var_os("FAKELINUX_TRAP_STATS").is_some(), Ordering::Relaxed);
    let v: i8 = if std::env::var_os("FAKELINUX_TRACE_X18_STORES").is_some() { 1 } else { 0 };
    X18_STORE_TRACE.store(v, Ordering::Relaxed);
    TRACE_LR_ENABLED.store(std::env::var_os("FAKELINUX_TRACE_LR").is_some(), Ordering::Relaxed);
    TRACE_X18_ENABLED.store(std::env::var_os("FAKELINUX_TRACE_X18").is_some(), Ordering::Relaxed);
    if let Ok(spec) = std::env::var("FAKELINUX_WATCH") {
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() == 3 {
            if let (Ok(seq), Ok(len), Ok(off)) = (
                u64::from_str_radix(parts[0], 16),
                u64::from_str_radix(parts[1], 16),
                u64::from_str_radix(parts[2], 16),
            ) {
                WATCH_MMAP_SEQ.store(seq, Ordering::Relaxed);
                WATCH_MMAP_LEN.store(len, Ordering::Relaxed);
                WATCH_OFF.store(off, Ordering::Relaxed);
                eprintln!("fakelinux: WATCH armed-pending: seq={} len={:#x} off={:#x}", seq, len, off);
            }
        }
    }
}

/// Called by do_mmap after a successful anonymous mapping. Arms the watch
/// when the seq-th mmap of the configured length appears. Runs in trap
/// context — atomics + raw prints only.
pub fn watch_on_anon_mmap(base: u64, length: u64) {
    let want_len = WATCH_MMAP_LEN.load(Ordering::Relaxed);
    if want_len == 0 || length != want_len || WATCH_ADDR.load(Ordering::Relaxed) != 0 {
        return;
    }
    if WATCH_MMAP_SEQ.fetch_sub(1, Ordering::Relaxed) != 1 {
        return;
    }
    let addr = base + WATCH_OFF.load(Ordering::Relaxed);
    let page = addr & !0x3FFF;
    WATCH_ADDR.store(addr, Ordering::Relaxed);
    WATCH_PAGE.store(page, Ordering::Relaxed);
    unsafe {
        libc::mprotect(page as *mut _, 0x4000, libc::PROT_READ);
        let mut buf = [0u8; 160];
        let n = raw_fmt(&mut buf, format_args!(
            "fakelinux: WATCH armed: addr={:#x} page={:#x} (mmap base={:#x})\n",
            addr, page, base));
        libc::write(2, buf.as_ptr() as *const _, n);
    }
}

/// Handle a write fault on the watched page: record the pre-value, patch a
/// UDF probe after the faulting instruction, unprotect, retry natively.
/// Returns true if the fault was ours.
pub unsafe fn watch_handle_fault(mctx: &mut MContext64, fault_addr: u64) -> bool {
    let page = WATCH_PAGE.load(Ordering::Relaxed);
    if page == 0 || fault_addr < page || fault_addr >= page + 0x4000 {
        return false;
    }
    let pc = mctx.ss.pc;
    let waddr = WATCH_ADDR.load(Ordering::Relaxed);
    // Host-code store (e.g. our own emulation writing on the guest's
    // behalf): unprotect, log, and disarm — patching host code would be
    // fatal. CURRENT_X18_INSTR identifies the emulated guest instruction.
    let host_anchor = watch_handle_fault as usize as u64;
    if pc.wrapping_sub(host_anchor) < 0x8000000 || host_anchor.wrapping_sub(pc) < 0x8000000 {
        let mut buf = [0u8; 224];
        let n = raw_fmt(&mut buf, format_args!(
            "fakelinux: WATCH HOST-CODE write! host_pc={:#x} fault={:#x} emul_instr={:#010x} emul_pc={:#x} — disarming\n",
            pc, fault_addr, CURRENT_X18_INSTR, CURRENT_X18_PC));
        libc::write(2, buf.as_ptr() as *const _, n);
        libc::mprotect(page as *mut _, 0x4000, libc::PROT_READ | libc::PROT_WRITE);
        WATCH_PAGE.store(0, Ordering::Relaxed);
        return true;
    }
    WATCH_PREV_VAL.store((waddr as *const u64).read(), Ordering::Relaxed);
    WATCH_FAULT_PC.store(pc, Ordering::Relaxed);
    // Patch the next instruction with the step probe.
    let step = pc + 4;
    let tpage = step & !0x3FFF;
    libc::mprotect(tpage as *mut _, 0x4000, libc::PROT_READ | libc::PROT_WRITE);
    WATCH_STEP_ORIG.store((step as *const u32).read(), Ordering::Relaxed);
    (step as *mut u32).write(UDF_WATCH_STEP);
    extern "C" { fn sys_icache_invalidate(start: *mut libc::c_void, size: usize); }
    sys_icache_invalidate(step as *mut _, 4);
    libc::mprotect(tpage as *mut _, 0x4000, libc::PROT_READ | libc::PROT_EXEC);
    WATCH_STEP_PC.store(step, Ordering::Relaxed);
    // Let the store execute natively.
    libc::mprotect(page as *mut _, 0x4000, libc::PROT_READ | libc::PROT_WRITE);
    true
}

/// Handle the UDF step probe: restore the patched instruction, re-protect
/// the watched page, log if the watched slot changed. Returns true if pc
/// was the active probe.
pub unsafe fn watch_handle_step(mctx: &mut MContext64) -> bool {
    let step = WATCH_STEP_PC.load(Ordering::Relaxed);
    if step == 0 || mctx.ss.pc != step {
        return false;
    }
    // Restore the original instruction.
    let orig = WATCH_STEP_ORIG.load(Ordering::Relaxed);
    let tpage = step & !0x3FFF;
    libc::mprotect(tpage as *mut _, 0x4000, libc::PROT_READ | libc::PROT_WRITE);
    (step as *mut u32).write(orig);
    extern "C" { fn sys_icache_invalidate(start: *mut libc::c_void, size: usize); }
    sys_icache_invalidate(step as *mut _, 4);
    libc::mprotect(tpage as *mut _, 0x4000, libc::PROT_READ | libc::PROT_EXEC);
    WATCH_STEP_PC.store(0, Ordering::Relaxed);
    // Re-protect the watched page and check the slot.
    let page = WATCH_PAGE.load(Ordering::Relaxed);
    if page != 0 {
        libc::mprotect(page as *mut _, 0x4000, libc::PROT_READ);
        let waddr = WATCH_ADDR.load(Ordering::Relaxed);
        let cur = (waddr as *const u64).read();
        let prev = WATCH_PREV_VAL.load(Ordering::Relaxed);
        if cur != prev {
            let fpc = WATCH_FAULT_PC.load(Ordering::Relaxed);
            let instr = (fpc as *const u32).read();
            let r = &mctx.ss;
            let mut buf = [0u8; 512];
            let n = raw_fmt(&mut buf, format_args!(
                "fakelinux: WATCH WRITE [{:#x}] {:#x} → {:#x} by pc={:#x} instr={:#010x} lr={:#x}\n  x0={:#x} x1={:#x} x2={:#x} x3={:#x} x4={:#x} x5={:#x} x6={:#x} x7={:#x}\n  x19={:#x} x20={:#x} x21={:#x} x22={:#x} sp={:#x}\n",
                waddr, prev, cur, fpc, instr, r.lr,
                r.x[0], r.x[1], r.x[2], r.x[3], r.x[4], r.x[5], r.x[6], r.x[7],
                r.x[19], r.x[20], r.x[21], r.x[22], r.sp));
            libc::write(2, buf.as_ptr() as *const _, n);
        }
    }
    // Do not advance pc — re-execute the restored instruction.
    true
}

#[inline]
fn x18_store_trace_enabled() -> bool {
    // No lazy env fallback: a first call from signal context would deadlock.
    X18_STORE_TRACE.load(Ordering::Relaxed) == 1
}

#[inline]
fn trace_lr_enabled() -> bool { TRACE_LR_ENABLED.load(Ordering::Relaxed) }

#[inline]
fn trace_x18_enabled() -> bool { TRACE_X18_ENABLED.load(Ordering::Relaxed) }

#[cfg(test)]
mod trace_flag_tests {
    use super::*;
    #[test]
    fn getters_are_cached_and_ignore_env_after_init() {
        std::env::remove_var("FAKELINUX_TRACE_LR");
        std::env::remove_var("FAKELINUX_TRACE_X18");
        std::env::remove_var("FAKELINUX_TRACE_X18_STORES");
        init_trace_flags();
        assert!(!trace_lr_enabled());
        assert!(!trace_x18_enabled());
        assert!(!x18_store_trace_enabled());
        // Mutating the environment after init must NOT be observed by the
        // getters — proves they never touch std::env (async-signal-safety).
        std::env::set_var("FAKELINUX_TRACE_LR", "1");
        std::env::set_var("FAKELINUX_TRACE_X18", "1");
        std::env::set_var("FAKELINUX_TRACE_X18_STORES", "1");
        assert!(!trace_lr_enabled());
        assert!(!trace_x18_enabled());
        assert!(!x18_store_trace_enabled());
        // Re-init picks them up (outside signal context).
        init_trace_flags();
        assert!(trace_lr_enabled());
        assert!(trace_x18_enabled());
        assert!(x18_store_trace_enabled());
        std::env::remove_var("FAKELINUX_TRACE_LR");
        std::env::remove_var("FAKELINUX_TRACE_X18");
        std::env::remove_var("FAKELINUX_TRACE_X18_STORES");
    }
}

/// On the first store seen in each process, snapshot /proc/self/maps to
/// /tmp/x18_maps_pid<pid>.txt so the X18_STORE addr= lines can be looked up
/// against the decompressor's libraries / heap regions.
fn maybe_dump_maps_for_tracer() {
    let pid = unsafe { libc::getpid() } as u64;
    let last = X18_STORE_MAPS_DUMPED_PID.load(Ordering::Relaxed);
    if last == pid { return; }
    X18_STORE_MAPS_DUMPED_PID.store(pid, Ordering::Relaxed);
    let maps = crate::procfs::snapshot_maps();
    let path = format!("/tmp/x18_maps_pid{}.txt\0", pid);
    unsafe {
        let fd = libc::open(
            path.as_ptr() as *const i8,
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if fd >= 0 {
            libc::write(fd, maps.as_ptr() as *const _, maps.len());
            libc::close(fd);
        }
    }
}

#[inline]
fn trace_x18_store(pc: u64, base_reg: usize, addr: u64, val: u128, size_bytes: u32) {
    if !x18_store_trace_enabled() { return; }
    maybe_dump_maps_for_tracer();
    let pid = unsafe { libc::getpid() };
    let x18_val = get_thread_x18();
    let mut buf = [0u8; 256];
    let n = raw_fmt(&mut buf, format_args!(
        "fakelinux: [{}] X18_STORE pc={:#x} base=x{} addr={:#x} val={:#x} size={} x18={:#x}\n",
        pid, pc, base_reg, addr, val, size_bytes, x18_val
    ));
    unsafe { libc::write(2, buf.as_ptr() as *const _, n); }
}

fn emul_ldr_str_unsigned_imm(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let pc = mctx.ss.pc;
    let size = (orig_instr >> 30) & 0x3;
    let v_bit = (orig_instr >> 26) & 1;
    let opc = (orig_instr >> 22) & 0x3; // full 2-bit opc: 0=STR, 1=LDR, 2=signed64, 3=signed32/PRFM
    let imm12 = ((orig_instr >> 10) & 0xFFF) as u64;
    let rn = ((orig_instr >> 5) & 0x1F) as usize;
    let rt = (orig_instr & 0x1F) as usize;

    // PRFM: size=3, V=0, opc=2 — prefetch hint, no-op
    if v_bit == 0 && size == 3 && opc == 2 {
        return true;
    }

    let scale = if v_bit == 1 {
        let opc1 = (orig_instr >> 23) & 1;
        if size == 0 && opc1 == 1 { 4u32 } else { size }
    } else { size };
    let offset = imm12 << scale;
    let base = read_gpr_sp(&mctx.ss, rn);
    let addr = base.wrapping_add(offset);

    if v_bit == 1 {
        // SIMD/FP register access
        let is_load = opc & 1;
        let ns = &mut mctx.ns;
        if is_load == 1 {
            let val: u128 = match scale {
                0 => unsafe { *(addr as *const u8) as u128 },
                1 => unsafe { *(addr as *const u16) as u128 },
                2 => unsafe { *(addr as *const u32) as u128 },
                3 => unsafe { *(addr as *const u64) as u128 },
                4 => unsafe { *(addr as *const u128) },
                _ => 0,
            };
            ns.v[rt] = val;
        } else {
            let val = ns.v[rt];
            trace_x18_store(pc, rn, addr, val, 1u32 << scale);
            match scale {
                0 => unsafe { *(addr as *mut u8) = val as u8 },
                1 => unsafe { *(addr as *mut u16) = val as u16 },
                2 => unsafe { *(addr as *mut u32) = val as u32 },
                3 => unsafe { *(addr as *mut u64) = val as u64 },
                4 => unsafe { *(addr as *mut u128) = val },
                _ => {}
            }
        }
    } else {
        // GPR access: opc=0 store, opc=1 load (zero-ext), opc=2 signed load to X, opc=3 signed load to W
        let regs = &mut mctx.ss;
        match opc {
            0 => {
                // STR
                let val = read_gpr(regs, rt);
                trace_x18_store(pc, rn, addr, val as u128, 1u32 << size);
                unsafe { store_mem(addr, size, val); }
            }
            1 => {
                // LDR (zero-extend)
                let val = unsafe { load_mem(addr, size) };
                if rt != 31 { write_gpr(regs, rt, val); }
            }
            2 => {
                // Signed load, extend to 64-bit (LDRSW/LDRSH/LDRSB to X)
                let raw = unsafe { load_mem(addr, size) };
                let val = match size {
                    0 => raw as u8 as i8 as i64 as u64,   // LDRSB → X
                    1 => raw as u16 as i16 as i64 as u64, // LDRSH → X
                    2 => raw as u32 as i32 as i64 as u64, // LDRSW → X
                    _ => raw,
                };
                if rt != 31 { write_gpr(regs, rt, val); }
            }
            3 => {
                // Signed load, extend to 32-bit (LDRSB/LDRSH to W)
                let raw = unsafe { load_mem(addr, size) };
                let val = match size {
                    0 => (raw as u8 as i8 as i32 as u32) as u64,  // LDRSB → W
                    1 => (raw as u16 as i16 as i32 as u32) as u64, // LDRSH → W
                    _ => raw & 0xFFFF_FFFF,
                };
                if rt != 31 { write_gpr(regs, rt, val); }
            }
            _ => unreachable!(),
        }
    }
    true
}

fn emul_ldr_str_unscaled(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let pc = mctx.ss.pc;
    let regs = &mut mctx.ss;
    let size = (orig_instr >> 30) & 0x3;
    let opc = (orig_instr >> 22) & 0x3;
    let imm9 = sign_extend(((orig_instr >> 12) & 0x1FF) as u64, 9);
    let rn = ((orig_instr >> 5) & 0x1F) as usize;
    let rt = (orig_instr & 0x1F) as usize;
    let base = read_gpr_sp(regs, rn);
    let addr = base.wrapping_add(imm9);
    // PRFUM: size=3, opc=2 — prefetch unscaled, no-op
    if size == 3 && opc == 2 { return true; }
    match opc {
        0 => {
            let val = read_gpr(regs, rt);
            trace_x18_store(pc, rn, addr, val as u128, 1u32 << size);
            unsafe { store_mem(addr, size, val); }
        }
        1 => { let val = unsafe { load_mem(addr, size) }; if rt != 31 { write_gpr(regs, rt, val); } }
        2 => {
            let raw = unsafe { load_mem(addr, size) };
            let val = match size {
                0 => raw as u8 as i8 as i64 as u64,
                1 => raw as u16 as i16 as i64 as u64,
                2 => raw as u32 as i32 as i64 as u64,
                _ => raw,
            };
            if rt != 31 { write_gpr(regs, rt, val); }
        }
        3 => {
            let raw = unsafe { load_mem(addr, size) };
            let val = match size {
                0 => (raw as u8 as i8 as i32 as u32) as u64,
                1 => (raw as u16 as i16 as i32 as u32) as u64,
                _ => raw & 0xFFFF_FFFF,
            };
            if rt != 31 { write_gpr(regs, rt, val); }
        }
        _ => unreachable!(),
    }
    true
}

fn emul_ldr_str_prepost(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let pc = mctx.ss.pc;
    let regs = &mut mctx.ss;
    let size = (orig_instr >> 30) & 0x3;
    let opc = (orig_instr >> 22) & 0x3;
    let imm9 = sign_extend(((orig_instr >> 12) & 0x1FF) as u64, 9);
    let wb = (orig_instr >> 10) & 0x3;
    let rn = ((orig_instr >> 5) & 0x1F) as usize;
    let rt = (orig_instr & 0x1F) as usize;
    let base = read_gpr_sp(regs, rn);
    let addr = if wb == 0b11 { base.wrapping_add(imm9) } else { base }; // pre vs post
    match opc {
        0 => {
            let val = read_gpr(regs, rt);
            trace_x18_store(pc, rn, addr, val as u128, 1u32 << size);
            unsafe { store_mem(addr, size, val); }
        }
        1 => { let val = unsafe { load_mem(addr, size) }; if rt != 31 { write_gpr(regs, rt, val); } }
        2 => {
            let raw = unsafe { load_mem(addr, size) };
            let val = match size {
                0 => raw as u8 as i8 as i64 as u64,
                1 => raw as u16 as i16 as i64 as u64,
                2 => raw as u32 as i32 as i64 as u64,
                _ => raw,
            };
            if rt != 31 { write_gpr(regs, rt, val); }
        }
        3 => {
            let raw = unsafe { load_mem(addr, size) };
            let val = match size {
                0 => (raw as u8 as i8 as i32 as u32) as u64,
                1 => (raw as u16 as i16 as i32 as u32) as u64,
                _ => raw & 0xFFFF_FFFF,
            };
            if rt != 31 { write_gpr(regs, rt, val); }
        }
        _ => unreachable!(),
    }
    // Bug #9 fix: writeback (both pre and post write base + offset)
    let new_base = base.wrapping_add(imm9);
    write_gpr_sp(regs, rn, new_base);
    true
}

fn emul_ldr_str_reg_offset(orig_instr: u32, mctx: &mut MContext64) -> bool {
    {
        let pc = mctx.ss.pc;
        let size = (orig_instr >> 30) & 0x3;
        let v_bit = (orig_instr >> 26) & 1;
        let opc = (orig_instr >> 22) & 0x3;
        let rm = ((orig_instr >> 16) & 0x1F) as usize;
        let option = (orig_instr >> 13) & 0x7;
        let s_bit = (orig_instr >> 12) & 1;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rt = (orig_instr & 0x1F) as usize;
        // PRFM register offset: size=3, V=0, opc=2
        if v_bit == 0 && size == 3 && opc == 2 { return true; }
        let offset_val = read_gpr(&mctx.ss, rm);
        let scale = if v_bit == 1 {
            let opc1 = (orig_instr >> 23) & 1;
            if size == 0 && opc1 == 1 { 4u32 } else { size }
        } else { size };
        let offset_val = extend_reg(offset_val, option, if s_bit == 1 { scale } else { 0 });
        let base = read_gpr_sp(&mctx.ss, rn);
        let addr = base.wrapping_add(offset_val);
        if v_bit == 1 {
            let is_load = opc & 1;
            let ns = &mut mctx.ns;
            if is_load == 1 {
                let val: u128 = match scale {
                    0 => unsafe { *(addr as *const u8) as u128 },
                    1 => unsafe { *(addr as *const u16) as u128 },
                    2 => unsafe { *(addr as *const u32) as u128 },
                    3 => unsafe { *(addr as *const u64) as u128 },
                    4 => unsafe { *(addr as *const u128) },
                    _ => 0,
                };
                ns.v[rt] = val;
            } else {
                let val = ns.v[rt];
                trace_x18_store(pc, rn, addr, val, 1u32 << scale);
                match scale {
                    0 => unsafe { *(addr as *mut u8) = val as u8 },
                    1 => unsafe { *(addr as *mut u16) = val as u16 },
                    2 => unsafe { *(addr as *mut u32) = val as u32 },
                    3 => unsafe { *(addr as *mut u64) = val as u64 },
                    4 => unsafe { *(addr as *mut u128) = val },
                    _ => {}
                }
            }
        } else {
            let regs = &mut mctx.ss;
            match opc {
                0 => {
                    let val = read_gpr(regs, rt);
                    trace_x18_store(pc, rn, addr, val as u128, 1u32 << size);
                    unsafe { store_mem(addr, size, val); }
                }
                1 => { let val = unsafe { load_mem(addr, size) }; if rt != 31 { write_gpr(regs, rt, val); } }
                2 => {
                    let raw = unsafe { load_mem(addr, size) };
                    let val = match size {
                        0 => raw as u8 as i8 as i64 as u64,
                        1 => raw as u16 as i16 as i64 as u64,
                        2 => raw as u32 as i32 as i64 as u64,
                        _ => raw,
                    };
                    if rt != 31 { write_gpr(regs, rt, val); }
                }
                3 => {
                    let raw = unsafe { load_mem(addr, size) };
                    let val = match size {
                        0 => (raw as u8 as i8 as i32 as u32) as u64,
                        1 => (raw as u16 as i16 as i32 as u32) as u64,
                        _ => raw & 0xFFFF_FFFF,
                    };
                    if rt != 31 { write_gpr(regs, rt, val); }
                }
                _ => unreachable!(),
            }
        }
        return true;
    }
    false
}

fn emul_ldp_stp(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let pc = mctx.ss.pc;
    let opc = (orig_instr >> 30) & 0x3;
    let v_flag = (orig_instr >> 26) & 1;     // 0 = GPR, 1 = SIMD&FP
    let wb_type = (orig_instr >> 23) & 0x3;  // 01=post, 10=offset, 11=pre, 00=no-alloc
    let is_load = (orig_instr >> 22) & 1;
    let imm7 = ((orig_instr >> 15) & 0x7F) as u64;
    let rt2 = ((orig_instr >> 10) & 0x1F) as usize;
    let rn = ((orig_instr >> 5) & 0x1F) as usize;
    let rt = (orig_instr & 0x1F) as usize;

    // Element size depends on V and opc.
    //   GPR  : opc=00 → 32-bit, opc=01 → LDPSW (32-bit signed), opc=10 → 64-bit
    //   SIMD : opc=00 → 32-bit (S), opc=01 → 64-bit (D), opc=10 → 128-bit (Q)
    let scale: u64 = if v_flag == 0 {
        if opc <= 1 { 2 } else { 3 }
    } else {
        match opc { 0 => 2, 1 => 3, 2 => 4, _ => return false }
    };
    let is_signed_gpr = v_flag == 0 && opc == 1; // LDPSW
    let elem_size: u64 = 1u64 << scale;
    let offset = sign_extend(imm7, 7) << scale;

    let regs = &mut mctx.ss;
    let base = read_gpr_sp(regs, rn);
    let addr = if wb_type == 0b01 {
        base // post-index: use base first, writeback later
    } else {
        base.wrapping_add(offset) // offset (10), pre-index (11), no-allocate (00)
    };

    if v_flag == 0 {
        // Integer LDP/STP (32-bit or 64-bit GPRs).
        if is_load == 1 {
            let mut v1 = unsafe { load_mem(addr, scale as u32) };
            let mut v2 = unsafe { load_mem(addr.wrapping_add(elem_size), scale as u32) };
            if is_signed_gpr {
                v1 = v1 as i32 as i64 as u64;
                v2 = v2 as i32 as i64 as u64;
            }
            if rt != 31 { write_gpr(regs, rt, v1); }
            if rt2 != 31 { write_gpr(regs, rt2, v2); }
        } else {
            let v1 = read_gpr(regs, rt);
            let v2 = read_gpr(regs, rt2);
            trace_x18_store(pc, rn, addr, v1 as u128, elem_size as u32);
            trace_x18_store(pc, rn, addr.wrapping_add(elem_size), v2 as u128, elem_size as u32);
            unsafe { store_mem(addr, scale as u32, v1); }
            unsafe { store_mem(addr.wrapping_add(elem_size), scale as u32, v2); }
        }
    } else {
        // SIMD&FP LDP/STP — reads/writes V/Q register file, not GPRs.
        // Rt/Rt2 here index ns.v[] (q0..q31). Sub-Q sizes occupy the low bits.
        let ns = &mut mctx.ns;
        if is_load == 1 {
            let v1 = unsafe { load_simd(addr, elem_size) };
            let v2 = unsafe { load_simd(addr.wrapping_add(elem_size), elem_size) };
            ns.v[rt] = v1;
            ns.v[rt2] = v2;
        } else {
            let v1 = ns.v[rt];
            let v2 = ns.v[rt2];
            trace_x18_store(pc, rn, addr, v1, elem_size as u32);
            trace_x18_store(pc, rn, addr.wrapping_add(elem_size), v2, elem_size as u32);
            unsafe { store_simd(addr, elem_size, v1); }
            unsafe { store_simd(addr.wrapping_add(elem_size), elem_size, v2); }
        }
    }

    // Writeback (post/pre-index): always writes to Rn (GPR), regardless of V.
    if wb_type == 0b01 || wb_type == 0b11 {
        let new_base = base.wrapping_add(offset);
        write_gpr_sp(regs, rn, new_base);
    }
    true
}

/// Load `bytes` of memory (1, 2, 4, 8 or 16) into the low bits of a u128.
unsafe fn load_simd(addr: u64, bytes: u64) -> u128 {
    match bytes {
        4  => (addr as *const u32).read_unaligned() as u128,
        8  => (addr as *const u64).read_unaligned() as u128,
        16 => (addr as *const u128).read_unaligned(),
        _  => 0,
    }
}

/// Store the low `bytes` of `val` to memory.
unsafe fn store_simd(addr: u64, bytes: u64, val: u128) {
    match bytes {
        4  => (addr as *mut u32).write_unaligned(val as u32),
        8  => (addr as *mut u64).write_unaligned(val as u64),
        16 => (addr as *mut u128).write_unaligned(val),
        _  => {},
    }
}

fn emul_bitfield(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    {
        let sf = (orig_instr >> 31) & 1;
        let opc = (orig_instr >> 29) & 0x3;
        let n = (orig_instr >> 22) & 1;
        let immr = ((orig_instr >> 16) & 0x3F) as u32;
        let imms = ((orig_instr >> 10) & 0x3F) as u32;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rd = (orig_instr & 0x1F) as usize;
        let bits = if sf == 1 { 64u32 } else { 32 };
        let src = read_gpr(regs, rn);
        let src = if sf == 0 { src & 0xFFFF_FFFF } else { src };
        let result = match opc {
            0 => { // SBFM (ASR, SXTW, SXTH, SXTB, SBFX, SBFIZ)
                let width = imms + 1;
                let pos = immr;
                if imms >= immr {
                    // SBFX / ASR / SXT
                    let val = (src >> pos) & ((1u64 << width.wrapping_sub(pos)) - 1);
                    let field_width = imms - immr + 1;
                    sign_extend(val, field_width)
                } else {
                    // SBFIZ: extract bottom (imms+1) bits, sign-extend, shift left by (bits-immr)
                    let width = imms + 1;
                    let lsb = bits - immr;
                    let val = src & ((1u64 << width) - 1);
                    let sext = sign_extend(val, width);
                    sext << lsb
                }
            }
            1 => { // BFM (BFI, BFXIL)
                let dst = read_gpr(regs, rd);
                if imms >= immr {
                    // BFXIL
                    let width = imms - immr + 1;
                    let val = (src >> immr) & ((1u64 << width) - 1);
                    let mask = (1u64 << width) - 1;
                    (dst & !mask) | val
                } else {
                    // BFI
                    let width = imms + 1;
                    let lsb = bits - immr;
                    let val = src & ((1u64 << width) - 1);
                    let mask = ((1u64 << width) - 1) << lsb;
                    (dst & !mask) | (val << lsb)
                }
            }
            2 => { // UBFM (LSL, LSR, UXTW, UXTH, UXTB, UBFX, UBFIZ)
                if imms >= immr {
                    // UBFX / LSR / UXT
                    let width = imms - immr + 1;
                    (src >> immr) & ((1u64 << width) - 1)
                } else {
                    // UBFIZ / LSL
                    let width = imms + 1;
                    let lsb = bits - immr;
                    let val = src & ((1u64 << width) - 1);
                    val << lsb
                }
            }
            _ => return false,
        };
        let result = if sf == 0 { result & 0xFFFF_FFFF } else { result };
        if rd != 31 { write_gpr(regs, rd, result); }
        return true;
    }
    false
}

fn emul_adr_adrp(orig_instr: u32, instr_pc: u64, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    {
        let rd = (orig_instr & 0x1F) as usize;
        let immhi = ((orig_instr >> 5) & 0x7FFFF) as u64;
        let immlo = ((orig_instr >> 29) & 0x3) as u64;
        let imm = sign_extend((immhi << 2) | immlo, 21);
        let is_adrp = (orig_instr >> 31) & 1;
        let result = if is_adrp == 1 {
            (instr_pc & !0xFFF).wrapping_add(imm << 12)
        } else {
            instr_pc.wrapping_add(imm)
        };
        if rd != 31 { write_gpr(regs, rd, result); }
        return true;
    }
    false
}

fn emul_cbz_cbnz(orig_instr: u32, instr_pc: u64, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    {
        let sf = (orig_instr >> 31) & 1;
        let op = (orig_instr >> 24) & 1; // 0=CBZ, 1=CBNZ
        let imm19 = ((orig_instr >> 5) & 0x7FFFF) as u64;
        let offset = sign_extend(imm19, 19) << 2;
        let rt = (orig_instr & 0x1F) as usize;
        let val = read_gpr(regs, rt);
        let val = if sf == 0 { val & 0xFFFF_FFFF } else { val };
        let take_branch = if op == 0 { val == 0 } else { val != 0 };
        if take_branch {
            // Branch: set PC to target (caller must NOT add 4)
            regs.pc = instr_pc.wrapping_add(offset);
        } else {
            regs.pc = instr_pc + 4;
        }
        return true;
    }
    false
}

fn emul_tbz_tbnz(orig_instr: u32, instr_pc: u64, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    {
        let b5 = (orig_instr >> 31) & 1;
        let op = (orig_instr >> 24) & 1; // 0=TBZ, 1=TBNZ
        let b40 = ((orig_instr >> 19) & 0x1F) as u32;
        let bit_pos = (b5 << 5) | b40;
        let imm14 = ((orig_instr >> 5) & 0x3FFF) as u64;
        let offset = sign_extend(imm14, 14) << 2;
        let rt = (orig_instr & 0x1F) as usize;
        let val = read_gpr(regs, rt);
        let bit_set = (val >> bit_pos) & 1 != 0;
        let take_branch = if op == 0 { !bit_set } else { bit_set };
        if take_branch {
            regs.pc = instr_pc.wrapping_add(offset);
        } else {
            regs.pc = instr_pc + 4;
        }
        return true;
    }
    false
}

fn emul_ccmp_reg(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    {
        let sf = (orig_instr >> 31) & 1;
        let op = (orig_instr >> 30) & 1; // 0=CCMN, 1=CCMP
        let rm = ((orig_instr >> 16) & 0x1F) as usize;
        let cond = ((orig_instr >> 12) & 0xF) as u32;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let nzcv = (orig_instr & 0xF) as u32;
        if eval_condition(cond, regs.cpsr) {
            let a = read_gpr(regs, rn);
            let b = read_gpr(regs, rm);
            let mask = if sf == 1 { u64::MAX } else { 0xFFFF_FFFF };
            let (a, b) = (a & mask, b & mask);
            let result = if op == 1 { a.wrapping_sub(b) } else { a.wrapping_add(b) };
            let result = result & mask;
            update_nzcv(regs, a, b, result, op == 1, sf == 1);
        } else {
            regs.cpsr = (regs.cpsr & 0x0FFF_FFFF) | (nzcv << 28);
        }
        return true;
    }
    false
}

fn emul_ccmp_imm(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    {
        let sf = (orig_instr >> 31) & 1;
        let op = (orig_instr >> 30) & 1;
        let imm5 = ((orig_instr >> 16) & 0x1F) as u64;
        let cond = ((orig_instr >> 12) & 0xF) as u32;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let nzcv = (orig_instr & 0xF) as u32;
        if eval_condition(cond, regs.cpsr) {
            let a = read_gpr(regs, rn);
            let mask = if sf == 1 { u64::MAX } else { 0xFFFF_FFFF };
            let a = a & mask;
            let b = imm5 & mask;
            let result = if op == 1 { a.wrapping_sub(b) } else { a.wrapping_add(b) };
            let result = result & mask;
            update_nzcv(regs, a, b, result, op == 1, sf == 1);
        } else {
            regs.cpsr = (regs.cpsr & 0x0FFF_FFFF) | (nzcv << 28);
        }
        return true;
    }
    false
}

fn emul_fmov(orig_instr: u32, mctx: &mut MContext64) -> bool {
    // FMOV GPR ↔ FP
    {
        let sf = (orig_instr >> 31) & 1;
        let direction = (orig_instr >> 16) & 1; // 0(110)=FP→GPR, 1(111)=GPR→FP
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rd = (orig_instr & 0x1F) as usize;
        if direction == 0 {
            // FP→GPR: read from SIMD reg, write to GPR
            let fp_val = mctx.ns.v[rn] as u64;
            let val = if sf == 0 { fp_val & 0xFFFF_FFFF } else { fp_val };
            if rd != 31 { write_gpr(&mut mctx.ss, rd, val); }
        } else {
            // GPR→FP: read from GPR, write to SIMD reg
            let val = read_gpr(&mctx.ss, rn);
            mctx.ns.v[rd] = if sf == 0 { (val & 0xFFFF_FFFF) as u128 } else { val as u128 };
        }
        return true;
    }
    false
}

fn emul_extract(orig_instr: u32, mctx: &mut MContext64) -> bool {
    // EXTR is classified as Extract by the XML table.
    // Encoding: sf_00_100111_N_o0_Rm_imms_Rn_Rd
    let regs = &mut mctx.ss;
    let sf = (orig_instr >> 31) & 1;
    let rm = ((orig_instr >> 16) & 0x1F) as usize;
    let imms = ((orig_instr >> 10) & 0x3F) as u32;
    let rn = ((orig_instr >> 5) & 0x1F) as usize;
    let rd = (orig_instr & 0x1F) as usize;
    let bits = if sf == 1 { 64u32 } else { 32 };
    let hi = read_gpr(regs, rn);
    let lo = read_gpr(regs, rm);
    let result = if sf == 0 {
        let concat = ((hi & 0xFFFF_FFFF) << 32) | (lo & 0xFFFF_FFFF);
        ((concat >> imms) & 0xFFFF_FFFF) as u64
    } else {
        if imms == 0 { lo }
        else { (hi << (64 - imms)) | (lo >> imms) }
    };
    if rd != 31 { write_gpr(regs, rd, result); }
    true
}

/// Data Processing 1-source: RBIT, REV16, REV, REV32, CLZ, CLS
fn emul_dp1_src(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let regs = &mut mctx.ss;
    let sf = (orig_instr >> 31) & 1;
    let opcode = ((orig_instr >> 10) & 0x3F) as u32;
    let rn = ((orig_instr >> 5) & 0x1F) as usize;
    let rd = (orig_instr & 0x1F) as usize;
    let bits = if sf == 1 { 64u32 } else { 32 };
    let src = read_gpr(regs, rn);
    let src = if sf == 0 { src & 0xFFFF_FFFF } else { src };
    let result = match opcode {
        0 => { // RBIT — reverse bits
            if bits == 64 { src.reverse_bits() }
            else { (src as u32).reverse_bits() as u64 }
        }
        1 => { // REV16 — reverse bytes in each 16-bit half
            if bits == 64 {
                ((src & 0xFF00FF00FF00FF00) >> 8) | ((src & 0x00FF00FF00FF00FF) << 8)
            } else {
                (((src & 0xFF00FF00) >> 8) | ((src & 0x00FF00FF) << 8)) & 0xFFFFFFFF
            }
        }
        2 => { // REV (32-bit) / REV32 (64-bit: reverse bytes in each 32-bit half)
            if sf == 0 { (src as u32).swap_bytes() as u64 }
            else {
                let lo = (src as u32).swap_bytes() as u64;
                let hi = ((src >> 32) as u32).swap_bytes() as u64;
                (hi << 32) | lo
            }
        }
        3 => { // REV (64-bit full byte reverse)
            src.swap_bytes()
        }
        4 => { // CLZ — count leading zeros
            if bits == 64 { src.leading_zeros() as u64 }
            else { (src as u32).leading_zeros() as u64 }
        }
        5 => { // CLS — count leading sign bits
            // CLS = number of consecutive bits following the MSB that are identical to it
            if bits == 64 {
                let v = src as i64;
                if v < 0 { (v.leading_ones() - 1) as u64 }
                else { (v.leading_zeros() - 1) as u64 }
            } else {
                let v = src as u32 as i32;
                if v < 0 { (v.leading_ones() - 1) as u64 }
                else { (v.leading_zeros() - 1) as u64 }
            }
        }
        _ => return false,
    };
    let result = if sf == 0 { result & 0xFFFF_FFFF } else { result };
    if rd != 31 { write_gpr(regs, rd, result); }
    true
}

/// AdvSIMD copy: DUP (element/general), INS (general/element), SMOV, UMOV.
/// Encoding: 0_Q_op_01110000_imm5_0_imm4_1_Rn_Rd.
/// x18 can be the GPR operand (DUP general / INS general source, SMOV/UMOV
/// dest); v18 in the Rn field also gets patched, so the pure-vector forms
/// (DUP element, INS element) must be emulated here too.
fn emul_simd_copy(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let q = (orig_instr >> 30) & 1;
    let op = (orig_instr >> 29) & 1;
    let imm5 = (orig_instr >> 16) & 0x1F;
    let imm4 = (orig_instr >> 11) & 0xF;
    let rn = ((orig_instr >> 5) & 0x1F) as usize;
    let rd = (orig_instr & 0x1F) as usize;

    if imm5 & 0xF == 0 { return false; } // unallocated (no element size bit)
    let size = imm5.trailing_zeros(); // 0=B 1=H 2=S 3=D
    let esize = 8u32 << size; // 8/16/32/64
    let emask: u128 = if esize == 64 { u64::MAX as u128 } else { (1u128 << esize) - 1 };
    let idx = (imm5 >> (size + 1)) as u32;

    let get_elem = |v: u128, i: u32| -> u64 { ((v >> (i * esize)) & emask) as u64 };
    let replicate = |elem: u64| -> u128 {
        let datasize = if q == 1 { 128 } else { 64 };
        let mut acc: u128 = 0;
        let mut i = 0;
        while i < datasize / esize {
            acc |= ((elem as u128) & emask) << (i * esize);
            i += 1;
        }
        acc // upper 64 bits zero when Q=0, as architected
    };

    if op == 1 {
        // INS (element): Vd.Ts[idx] = Vn.Ts[src_idx]; requires Q=1
        if q != 1 { return false; }
        let src_idx = imm4 >> size;
        let elem = get_elem(mctx.ns.v[rn], src_idx);
        let shift = idx * esize;
        mctx.ns.v[rd] = (mctx.ns.v[rd] & !(emask << shift))
            | (((elem as u128) & emask) << shift);
        return true;
    }

    match imm4 {
        0b0000 => { // DUP (element): Vd = replicate Vn.Ts[idx]
            if size == 3 && q == 0 { return false; } // no 1D form
            let elem = get_elem(mctx.ns.v[rn], idx);
            mctx.ns.v[rd] = replicate(elem);
            true
        }
        0b0001 => { // DUP (general): Vd = replicate GPR
            if size == 3 && q == 0 { return false; }
            let elem = read_gpr(&mctx.ss, rn);
            mctx.ns.v[rd] = replicate(elem);
            true
        }
        0b0011 => { // INS (general): Vd.Ts[idx] = GPR low bits; requires Q=1
            if q != 1 { return false; }
            let elem = read_gpr(&mctx.ss, rn);
            let shift = idx * esize;
            mctx.ns.v[rd] = (mctx.ns.v[rd] & !(emask << shift))
                | (((elem as u128) & emask) << shift);
            true
        }
        0b0101 => { // SMOV Wd/Xd, Vn.Ts[idx] — sign-extend element
            // W form: B/H only; X form: B/H/S only
            if (q == 0 && size > 1) || (q == 1 && size > 2) { return false; }
            let elem = get_elem(mctx.ns.v[rn], idx);
            let val = sign_extend(elem, esize);
            let val = if q == 0 { val & 0xFFFF_FFFF } else { val };
            if rd != 31 { write_gpr(&mut mctx.ss, rd, val); }
            true
        }
        0b0111 => { // UMOV Wd/Xd, Vn.Ts[idx] — zero-extend element
            // W form: B/H/S; X form: D only
            if (q == 0 && size > 2) || (q == 1 && size != 3) { return false; }
            let val = get_elem(mctx.ns.v[rn], idx);
            if rd != 31 { write_gpr(&mut mctx.ss, rd, val); }
            true
        }
        _ => false,
    }
}

// ─── Emulation helpers ───────────────────────────────────────────────────────

fn sign_extend(val: u64, bits: u32) -> u64 {
    if bits == 0 || bits >= 64 { return val; }
    let mask = 1u64 << (bits - 1);
    if val & mask != 0 {
        val | !((1u64 << bits) - 1)
    } else {
        val & ((1u64 << bits) - 1)
    }
}

fn apply_shift(val: u64, shift_type: u32, amount: u32, bits: u32) -> u64 {
    if amount == 0 { return val; }
    match shift_type {
        0 => val << amount,                          // LSL
        1 => val >> amount,                          // LSR
        2 => {                                       // ASR
            if bits == 64 { ((val as i64) >> amount) as u64 }
            else { (((val as i32) >> amount) as u32) as u64 }
        }
        3 => {                                       // ROR
            if bits == 64 { val.rotate_right(amount) }
            else { (val as u32).rotate_right(amount) as u64 }
        }
        _ => val,
    }
}

fn extend_reg(val: u64, option: u32, shift: u32) -> u64 {
    let extended = match option {
        0 => (val as u8) as u64,    // UXTB
        1 => (val as u16) as u64,   // UXTH
        2 => (val as u32) as u64,   // UXTW
        3 => val,                    // UXTX
        4 => (val as u8 as i8 as i64) as u64,    // SXTB
        5 => (val as u16 as i16 as i64) as u64,   // SXTH
        6 => (val as u32 as i32 as i64) as u64,   // SXTW
        7 => val,                                   // SXTX
        _ => val,
    };
    extended << shift
}

fn update_nzcv(regs: &mut ThreadState64, a: u64, b: u64, result: u64, is_sub: bool, is_64: bool) {
    let bits = if is_64 { 64u32 } else { 32 };
    let mask = if is_64 { u64::MAX } else { 0xFFFF_FFFF };
    let a = a & mask;
    let b = b & mask;
    let r = result & mask;
    let n = ((r >> (bits - 1)) & 1) as u32;
    let z = if r == 0 { 1u32 } else { 0 };
    let (c, v) = if is_sub {
        // SUB: carry = !borrow
        let c = if a >= b { 1u32 } else { 0 };
        let sa = (a >> (bits - 1)) & 1;
        let sb = (b >> (bits - 1)) & 1;
        let sr = (r >> (bits - 1)) & 1;
        let v = if (sa != sb) && (sa != sr) { 1u32 } else { 0 };
        (c, v)
    } else {
        // ADD
        let c = if r < a { 1u32 } else { 0 };
        let sa = (a >> (bits - 1)) & 1;
        let sb = (b >> (bits - 1)) & 1;
        let sr = (r >> (bits - 1)) & 1;
        let v = if (sa == sb) && (sa != sr) { 1u32 } else { 0 };
        (c, v)
    };
    regs.cpsr = (regs.cpsr & 0x0FFF_FFFF) | (n << 31) | (z << 30) | (c << 29) | (v << 28);
}

fn eval_condition(cond: u32, cpsr: u32) -> bool {
    let n = (cpsr >> 31) & 1;
    let z = (cpsr >> 30) & 1;
    let c = (cpsr >> 29) & 1;
    let v = (cpsr >> 28) & 1;
    let result = match cond >> 1 {
        0 => z == 1,            // EQ/NE
        1 => c == 1,            // CS/CC
        2 => n == 1,            // MI/PL
        3 => v == 1,            // VS/VC
        4 => c == 1 && z == 0,  // HI/LS
        5 => n == v,            // GE/LT
        6 => n == v && z == 0,  // GT/LE
        7 => true,              // AL
        _ => true,
    };
    if cond & 1 == 1 && cond != 0xF { !result } else { result }
}

fn decode_bitmask_imm(instr: u32, is_64: bool) -> Option<u64> {
    let n = (instr >> 22) & 1;
    let immr = ((instr >> 16) & 0x3F) as u32;
    let imms = ((instr >> 10) & 0x3F) as u32;
    // Determine element size
    let len = if n == 1 { 6 } else {
        // Find highest set bit in ~imms[5:0]
        let not_imms = (!imms) & 0x3F;
        if not_imms == 0 { return None; }
        31 - not_imms.leading_zeros()
    };
    if len < 1 { return None; }
    let size = if len >= 32 { 64u32 } else { 1u32 << len };
    let mask = size - 1;
    let s = imms & mask;
    let r = immr & mask;
    if s == mask { return None; } // all-ones reserved
    let welem = if s + 1 >= 64 { u64::MAX } else { (1u64 << (s + 1)) - 1 };
    let elem = if r == 0 { welem } else { (welem >> r) | (welem << (size - r)) };
    let elem = elem & (if size >= 64 { u64::MAX } else { (1u64 << size) - 1 });
    // Replicate element to fill 64 bits
    let mut result = 0u64;
    let mut shift = 0;
    while shift < 64 {
        result |= elem.wrapping_shl(shift);
        shift += size;
    }
    if !is_64 { Some(result & 0xFFFF_FFFF) } else { Some(result) }
}

unsafe fn load_mem(addr: u64, size: u32) -> u64 {
    match size {
        0 => *(addr as *const u8) as u64,
        1 => (addr as *const u16).read_unaligned() as u64,
        2 => (addr as *const u32).read_unaligned() as u64,
        3 => (addr as *const u64).read_unaligned(),
        _ => 0,
    }
}

unsafe fn store_mem(addr: u64, size: u32, val: u64) {
    match size {
        0 => *(addr as *mut u8) = val as u8,
        1 => (addr as *mut u16).write_unaligned(val as u16),
        2 => (addr as *mut u32).write_unaligned(val as u32),
        3 => (addr as *mut u64).write_unaligned(val),
        _ => {}
    }
}

unsafe extern "C" fn trap_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    ctx: *mut c_void,
) {
    IN_TRAP.store(true, Ordering::SeqCst);

    let uctx = &mut *(ctx as *mut UContext);
    let mctx = &mut *uctx.uc_mcontext;
    let pc = mctx.ss.pc;
    let instr = *(pc as *const u32);

    // Check if libapt-pkg's B instruction has been corrupted.
    {
        let watch = LIBAPT_B_WATCH.load(Ordering::Relaxed);
        if watch != 0 && !LIBAPT_B_REPORTED.load(Ordering::Relaxed) {
            let cur = (watch as *const u32).read();
            if cur != 0x1400000F {
                LIBAPT_B_REPORTED.store(true, Ordering::Relaxed);
                let pid = libc::getpid();
                let sp = mctx.ss.sp;
                let mut buf = [0u8; 300];
                let n = raw_fmt(&mut buf, format_args!(
                    "fakelinux: [{}] B_CORRUPTED! addr={:#x} was=0x1400000f now={:#010x} trap_pc={:#x}\n",
                    pid, watch, cur, pc
                ));
                libc::write(2, buf.as_ptr() as *const _, n);
            }
        }
    }

    // Track x30 across traps to detect when it first becomes a heap address.
    // X30_LAST also used by FORK_ENTRY_PROBE to recover the correct LR.
    {
        static X30_REPORTED: AtomicBool = AtomicBool::new(false);
        let x30 = mctx.ss.lr;
        let x30_last = X30_LAST.swap(x30, Ordering::Relaxed);
        // Save x30 if it looks like ExecFork's return (code addr ending in 0x77DC)
        if x30 >= 0x1_0000_0000 && x30 <= 0x1_0600_0000 && (x30 & 0xFFFF) == 0x77DC {
            X30_LAST_GOOD_EXEC_FORK.store(x30, Ordering::Relaxed);
        }
        // Check if x30 just changed to a heap address (0x50000xxxx range)
        if x30 >= 0x5_0000_0000 && x30 < 0x6_0000_0000
            && !(x30_last >= 0x5_0000_0000 && x30_last < 0x6_0000_0000)
            && crate::syscall::trace_enabled()
            && !X30_REPORTED.swap(true, Ordering::Relaxed)
        {
            let pid = libc::getpid();
            let sp = mctx.ss.sp;
            let mut buf = [0u8; 300];
            let n = raw_fmt(&mut buf, format_args!(
                "fakelinux: [{}] X30_BECAME_HEAP! pc={:#x} sp={:#x} x30_was={:#x} x30_now={:#x} instr={:#x}\n",
                pid, pc, sp, x30_last, x30, instr
            ));
            libc::write(2, buf.as_ptr() as *const _, n);
        }
    }

    // LR watch (debug-only). Disabled by default — was for fork LR corruption
    // investigation, but proved misleading (was watching wrong slot for glibc 2.39's
    // _Fork). Enable with FAKELINUX_TRACE_LR=1 if needed.
    if trace_lr_enabled() {
        let lw_addr = FORK_LR_WATCH_ADDR.load(Ordering::Relaxed);
        let lw_exp = FORK_LR_WATCH_EXPECTED.load(Ordering::Relaxed);
        if lw_addr != 0 && lw_exp != 0 {
            let lw_cur = (lw_addr as *const u64).read();
            if lw_cur != lw_exp {
                let pid = libc::getpid();
                let mut buf = [0u8; 200];
                let n = raw_fmt(&mut buf, format_args!(
                    "fakelinux: [{}] LR_WATCH_HIT! pc={:#x} expected={:#x} got={:#x} watch_addr={:#x}\n",
                    pid, pc, lw_exp, lw_cur, lw_addr));
                libc::write(2, buf.as_ptr() as *const _, n);
                FORK_LR_WATCH_EXPECTED.store(lw_cur, Ordering::Relaxed);
            }
        }
    }

    // Check if this is our __libc_fork ENTRY probe (at c1b50: sub sp, sp, #0x140).
    // This fires at __libc_fork's very first instruction, BEFORE any register saves.
    // At this point, x30 should have the caller's return address (set by their BL).
    let entry_probe = FORK_ENTRY_PROBE.load(Ordering::Relaxed);
    if entry_probe != 0 && pc == entry_probe {
        let pid = libc::getpid();
        let sp = mctx.ss.sp;  // caller's SP (before sub)
        let lr_reg = mctx.ss.lr;  // should be ExecFork + 0x18 = libapt_base + 0xB77DC
        let fp_reg = mctx.ss.fp;  // current FP
        let mut buf = [0u8; 300];
        let n = raw_fmt(&mut buf, format_args!(
            "fakelinux: [{}] FORK_ENTRY! sp={:#x} lr_reg(x30)={:#x} fp_reg(x29)={:#x}\n",
            pid, sp, lr_reg, fp_reg
        ));
        libc::write(2, buf.as_ptr() as *const _, n);

        // If LR looks corrupted (not a code address), log it.
        // NOTE: the stack-scan fix is DISABLED because it can match wrong values
        // for non-ExecFork callers (bash, etc.). Root cause investigation needed.
        if lr_reg < 0x1_0000_0000 || lr_reg > 0x1_0600_0000 {
            let mut buf_warn = [0u8; 200];
            let n_warn = raw_fmt(&mut buf_warn, format_args!(
                "fakelinux: [{}] FORK_ENTRY BAD_LR={:#x} (not fixing)\n", pid, lr_reg));
            libc::write(2, buf_warn.as_ptr() as *const _, n_warn);
        }
        if false && lr_reg < 0x1_0000_0000 || false && lr_reg > 0x1_0600_0000 {
            // Strategy: compute correct LR from libc base.
            // ExecFork's BL fork@plt goes to fork@plt which does br to __libc_fork.
            // The BL is at libapt_base + 0xB77D8, so LR = libapt_base + 0xB77DC.
            // We know libc_base from the probe: probe_addr = libc_base + 0xC1B50.
            // We need to find libapt_base. Strategy: scan the stack for a value
            // that matches the pattern libapt_base + 0xB77DC (code range, ends in 0x7DC with
            // nibbles matching). The correct LR was on the stack before corruption.
            //
            // Actually simpler: ExecFork's return address was in x30 before corruption.
            // The BL fork@plt at b77d8 produces LR = base + b77dc. The low 12 bits
            // are 0x7DC. Scan the stack for any code-range value with low 12 bits = 0x7DC.
            let mut correct_lr: u64 = 0;
            // Scan stack from SP upward (ExecFork's frame and caller frames)
            for off in (0..=0x400u64).step_by(8) {
                let val = ((sp + off) as *const u64).read();
                if val >= 0x1_0000_0000 && val <= 0x1_0600_0000 && (val & 0xFFF) == 0x7DC {
                    correct_lr = val;
                    break;
                }
            }
            if correct_lr != 0 {
                mctx.ss.lr = correct_lr;
                // Also fix ExecFork's saved LR at [SP+8].
                // ExecFork saved its caller's LR there. The correct value
                // depends on which function called ExecFork. For the gpgv method,
                // ExecFork(void) at libapt+0xB7C10 calls ExecFork(set<int>).
                // The return from that call is at libapt+0xB7CB8.
                let libapt_base = correct_lr - 0xB77DC;
                let exec_fork_caller_lr = libapt_base + 0xB7CB8;
                let cur_saved_lr = ((sp + 8) as *const u64).read();
                if cur_saved_lr < 0x1_0000_0000 || cur_saved_lr > 0x1_0600_0000 {
                    ((sp + 8) as *mut u64).write(exec_fork_caller_lr);
                }
                let mut buf2 = [0u8; 400];
                let n2 = raw_fmt(&mut buf2, format_args!(
                    "fakelinux: [{}] FORK_ENTRY FIX_LR! lr={:#x}→{:#x} exec_caller={:#x}→{:#x}\n",
                    pid, lr_reg, correct_lr, cur_saved_lr, exec_fork_caller_lr
                ));
                libc::write(2, buf2.as_ptr() as *const _, n2);
            } else {
                let mut buf2 = [0u8; 200];
                let n2 = raw_fmt(&mut buf2, format_args!(
                    "fakelinux: [{}] FORK_ENTRY BAD_LR! lr={:#x} (no fix found)\n",
                    pid, lr_reg
                ));
                libc::write(2, buf2.as_ptr() as *const _, n2);
            }
        }

        // Emulate: sub sp, sp, #0x140
        mctx.ss.sp = sp - 0x140;
        mctx.ss.pc = pc + 4;

        // Re-arm or disable the probe
        let remaining = FORK_ENTRY_PROBE_COUNT.fetch_sub(1, Ordering::Relaxed);
        if remaining <= 1 {
            // Last fire — restore original instruction permanently
            let orig = FORK_ENTRY_PROBE_ORIG.load(Ordering::Relaxed);
            let page = entry_probe & !0x3FFF;
            libc::mprotect(page as *mut _, 0x4000, libc::PROT_READ | libc::PROT_WRITE);
            (entry_probe as *mut u32).write(orig);
            extern "C" { fn sys_icache_invalidate(start: *mut libc::c_void, size: usize); }
            sys_icache_invalidate(entry_probe as *mut _, 4);
            libc::mprotect(page as *mut _, 0x4000, libc::PROT_READ | libc::PROT_EXEC);
            FORK_ENTRY_PROBE.store(0, Ordering::Relaxed);
        }
        // Otherwise, keep the UDF in place for next call

        IN_TRAP.store(false, Ordering::SeqCst);
        return;
    }

    // Software-watchpoint step probe (UDF_WATCH_STEP at pc)
    if watch_handle_step(mctx) {
        IN_TRAP.store(false, Ordering::SeqCst);
        return;
    }

    // Check if this is our __libc_fork return probe
    let probe_addr = FORK_RETURN_PROBE.load(Ordering::Relaxed);
    if probe_addr != 0 && pc == probe_addr {
        // We hit the probe! Log x19 (which becomes w0 via `mov w0, w19`)
        let pid = libc::getpid();
        let w19 = mctx.ss.x[19];
        let x0 = mctx.ss.x[0];
        let sp = mctx.ss.sp;
        let lr = mctx.ss.lr;

        // FIX: Check if the saved LR on __libc_fork's stack was corrupted.
        // glibc's __libc_fork child path may temporarily use the LR save slot
        // on the stack for thread-list cleanup. If malloc or atfork handlers
        // corrupt this slot, __libc_fork would return to a garbage address.
        // Restore it from our saved expected value.
        let lw_addr = FORK_LR_WATCH_ADDR.load(Ordering::Relaxed);
        let lw_exp = FORK_LR_WATCH_EXPECTED.load(Ordering::Relaxed);
        if lw_addr != 0 {
            let lw_cur = (lw_addr as *const u64).read();
            if lw_cur != lw_exp {
                // LR was corrupted! Restore it.
                (lw_addr as *mut u64).write(lw_exp);
                if crate::syscall::trace_enabled() {
                    let mut buf = [0u8; 240];
                    let n = raw_fmt(&mut buf, format_args!(
                        "fakelinux: [{}] FORK_RETURN_PROBE FIX_LR! x19={:#x} corrupted_lr={:#x} restored_lr={:#x}\n",
                        pid, w19, lw_cur, lw_exp
                    ));
                    libc::write(2, buf.as_ptr() as *const _, n);
                }
            } else if crate::syscall::trace_enabled() {
                let mut buf = [0u8; 200];
                let n = raw_fmt(&mut buf, format_args!(
                    "fakelinux: [{}] FORK_RETURN_PROBE x19={:#x} x0={:#x} sp={:#x} lr={:#x}\n",
                    pid, w19, x0, sp, lr
                ));
                libc::write(2, buf.as_ptr() as *const _, n);
            }
        }

        // Restore original instruction and re-execute
        let orig = FORK_RETURN_PROBE_ORIG.load(Ordering::Relaxed);
        let page = probe_addr & !0x3FFF;
        libc::mprotect(page as *mut _, 0x4000, libc::PROT_READ | libc::PROT_WRITE);
        (probe_addr as *mut u32).write(orig);
        extern "C" { fn sys_icache_invalidate(start: *mut libc::c_void, size: usize); }
        sys_icache_invalidate(probe_addr as *mut _, 4);
        libc::mprotect(page as *mut _, 0x4000, libc::PROT_READ | libc::PROT_EXEC);
        FORK_RETURN_PROBE.store(0, Ordering::Relaxed);
        // Don't advance PC — re-execute the restored instruction
        IN_TRAP.store(false, Ordering::SeqCst);
        return;
    }

    // For UDF_MARKER, check if this was originally a TPIDR access or a SVC
    if instr == UDF_MARKER {
        // Look up the original instruction in the patch table
        let orig = crate::loader::tpidr_lookup(pc);

        if let Some(orig_instr) = orig {
            // This was a patched MSR/MRS tpidr_el0
            if orig_instr & MSR_TPIDR_MASK == MSR_TPIDR_BASE {
                // MSR tpidr_el0, Xn
                if trap_stats_enabled() { STAT_TPIDR.fetch_add(1, Ordering::Relaxed); }
                let rn = (orig_instr & 0x1F) as usize;
                let val = read_gpr(&mctx.ss, rn);
                set_thread_tpidr(val);
                mctx.ss.pc = pc + 4;
                // FORK_TRAP logging for MSR
                let tcnt = FORK_TRAP_COUNT.load(Ordering::Relaxed);
                if tcnt > 0 {
                    FORK_TRAP_COUNT.store(tcnt - 1, Ordering::Relaxed);
                    let pid = libc::getpid();
                    let mut buf = [0u8; 160];
                    let n = raw_fmt(&mut buf, format_args!(
                        "fakelinux: [{}] FORK_TRAP#{} MSR pc={:#x} x{}={:#x} x0={:#x} x19={:#x} sp={:#x}\n",
                        pid, 50 - tcnt, pc, rn, val, mctx.ss.x[0], mctx.ss.x[19], mctx.ss.sp
                    ));
                    libc::write(2, buf.as_ptr() as *const _, n);
                }
                IN_TRAP.store(false, Ordering::SeqCst);
                return;
            } else if orig_instr & MRS_TPIDR_MASK == MRS_TPIDR_BASE {
                // MRS Xn, tpidr_el0
                if trap_stats_enabled() { STAT_TPIDR.fetch_add(1, Ordering::Relaxed); }
                let rn = (orig_instr & 0x1F) as usize;
                let val = get_thread_tpidr();
                write_gpr(&mut mctx.ss, rn, val);
                mctx.ss.pc = pc + 4;
                // FORK_TRAP logging for MRS (with LR watch)
                let tcnt = FORK_TRAP_COUNT.load(Ordering::Relaxed);
                if tcnt > 0 {
                    FORK_TRAP_COUNT.store(tcnt - 1, Ordering::Relaxed);
                    let pid = libc::getpid();
                    // Check LR watch for corruption
                    let lw_addr = FORK_LR_WATCH_ADDR.load(Ordering::Relaxed);
                    let lw_exp = FORK_LR_WATCH_EXPECTED.load(Ordering::Relaxed);
                    let lw_cur = if lw_addr != 0 { (lw_addr as *const u64).read() } else { lw_exp };
                    if lw_cur != lw_exp && lw_addr != 0 {
                        let mut buf = [0u8; 200];
                        let n = raw_fmt(&mut buf, format_args!(
                            "fakelinux: [{}] FORK_TRAP#{} LR_CORRUPTED! pc={:#x} expected={:#x} got={:#x}\n",
                            pid, 50 - tcnt, pc, lw_exp, lw_cur
                        ));
                        libc::write(2, buf.as_ptr() as *const _, n);
                    }
                    let mut buf = [0u8; 180];
                    let n = raw_fmt(&mut buf, format_args!(
                        "fakelinux: [{}] FORK_TRAP#{} MRS pc={:#x} x{}={:#x} x0={:#x} x19={:#x} sp={:#x}\n",
                        pid, 50 - tcnt, pc, rn, val, mctx.ss.x[0], mctx.ss.x[19], mctx.ss.sp
                    ));
                    libc::write(2, buf.as_ptr() as *const _, n);
                }
                IN_TRAP.store(false, Ordering::SeqCst);
                return;
            } else {
                // Not TPIDR — must be an x18 instruction
                // Debug: save pre-state
                static X18_DBG_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let seq = X18_DBG_COUNT.fetch_add(1, Ordering::Relaxed);
                let pre_x18 = get_thread_x18();
                let pre_regs: [u64; 5] = [mctx.ss.x[0], mctx.ss.x[1], mctx.ss.x[2], mctx.ss.x[3], mctx.ss.x[18]];

                if trap_stats_enabled() {
                    STAT_X18.fetch_add(1, Ordering::Relaxed);
                    stat_record_x18_instr(orig_instr);
                }
                // Save emulating instruction for crash diagnostics
                unsafe { CURRENT_X18_INSTR = orig_instr; CURRENT_X18_PC = pc; }
                // FAKELINUX_TRACE_X18_OPS: log every emulated x18 op
                // with pre/post x18 value + all GPRs, but only after
                // a threshold count (to capture just the failing block).
                let trace_ops = x18_store_trace_enabled();
                let pre_x18_for_trace = if trace_ops { get_thread_x18() } else { 0 };
                let pre_regs_for_trace: [u64; 4] = if trace_ops {
                    [mctx.ss.x[0], mctx.ss.x[1], mctx.ss.x[2], mctx.ss.x[3]]
                } else { [0;4] };

                if emulate_x18_instruction(orig_instr, mctx) {
                    // Log full op trace when enabled and past threshold
                    if trace_ops && seq >= 13500 {
                        let post_x18 = get_thread_x18();
                        let pid = libc::getpid();
                        let mut buf = [0u8; 300];
                        let n = raw_fmt(&mut buf, format_args!(
                            "fakelinux: [{}] X18_OP#{} pc={:#x} instr={:#010x} x18={:#x}→{:#x} x0={:#x} x1={:#x} x2={:#x} x3={:#x}\n",
                            pid, seq, pc, orig_instr, pre_x18_for_trace, post_x18,
                            pre_regs_for_trace[0], pre_regs_for_trace[1],
                            pre_regs_for_trace[2], pre_regs_for_trace[3]
                        ));
                        libc::write(2, buf.as_ptr() as *const _, n);
                    }
                    // FORK_TRAP logging for x18
                    let tcnt = FORK_TRAP_COUNT.load(Ordering::Relaxed);
                    if tcnt > 0 {
                        FORK_TRAP_COUNT.store(tcnt - 1, Ordering::Relaxed);
                        let pid = libc::getpid();
                        let mut buf = [0u8; 160];
                        let n = raw_fmt(&mut buf, format_args!(
                            "fakelinux: [{}] FORK_TRAP#{} X18 pc={:#x} instr={:#010x} x0={:#x} x19={:#x}\n",
                            pid, 50 - tcnt, pc, orig_instr, mctx.ss.x[0], mctx.ss.x[19]
                        ));
                        libc::write(2, buf.as_ptr() as *const _, n);
                    }
                    if seq < 200 && trace_x18_enabled() {
                        let mut buf = [0u8; 128];
                        let n = raw_fmt(&mut buf, format_args!(
                            "x18[{}] pc={:#x} instr={:#010x} x18={:#x}\n",
                            seq, pc, orig_instr, get_thread_x18()
                        ));
                        libc::write(2, buf.as_ptr() as *const _, n);
                    }
                    // Only advance PC if the emulator didn't set it (e.g. CBZ/CBNZ set PC directly)
                    if mctx.ss.pc == pc { mctx.ss.pc = pc + 4; }
                    // Clear the crash-diagnostic marker: emulation completed, so a
                    // later crash dump must not report this instruction as
                    // "currently being emulated" (stale values misled debugging).
                    unsafe { CURRENT_X18_INSTR = 0; CURRENT_X18_PC = 0; }
                    IN_TRAP.store(false, Ordering::SeqCst);
                    crate::signal::deliver_pending_to_guest(mctx);
                    return;
                }
                // Emulation failed — fatal
                let mut buf = [0u8; 128];
                let n = raw_fmt(&mut buf, format_args!(
                    "fakelinux: unhandled x18 instruction {:#010x} at pc={:#x}\n",
                    orig_instr, pc
                ));
                libc::write(2, buf.as_ptr() as *const _, n);
                libc::_exit(128 + libc::SIGILL);
            }
        }

        // Not in patch table → this was a SVC #0
        let nr = mctx.ss.x[8];
        if trap_stats_enabled() { STAT_SVC.fetch_add(1, Ordering::Relaxed); }

        // FORK_TRAP logging for SVC (with canary check)
        {
            let tcnt = FORK_TRAP_COUNT.load(Ordering::Relaxed);
            if tcnt > 0 {
                FORK_TRAP_COUNT.store(tcnt - 1, Ordering::Relaxed);
                let pid = libc::getpid();
                // Check canary
                let caddr = FORK_CANARY_ADDR.load(Ordering::Relaxed);
                let csaved = FORK_CANARY_SAVED.load(Ordering::Relaxed);
                let ccurrent = if caddr != 0 { (caddr as *const u64).read() } else { csaved };
                let canary_ok = if ccurrent == csaved { 'Y' } else { 'N' };
                let mut buf = [0u8; 240];
                let n = raw_fmt(&mut buf, format_args!(
                    "fakelinux: [{}] FORK_TRAP#{} SVC pc={:#x} nr={} x0={:#x} x19={:#x} lr={:#x} sp={:#x} canary={}\n",
                    pid, 50 - tcnt, pc, nr, mctx.ss.x[0], mctx.ss.x[19], mctx.ss.lr, mctx.ss.sp, canary_ok
                ));
                libc::write(2, buf.as_ptr() as *const _, n);
            }
        }

        // Debug: track fork children's first few SVCs to see when they
        // diverge from the expected child code path.
        {
            let cnt = FORK_SVC_COUNT.load(Ordering::Relaxed);
            if cnt > 0 {
                FORK_SVC_COUNT.fetch_sub(1, Ordering::Relaxed);
                let pid = libc::getpid();
                let mut buf = [0u8; 160];
                let n = raw_fmt(&mut buf, format_args!(
                    "fakelinux: [{}] FORK_SVC#{} nr={} x0={:#x} x19={:#x} pc={:#x}\n",
                    pid, 10 - cnt, nr, mctx.ss.x[0], mctx.ss.x[19], pc
                ));
                libc::write(2, buf.as_ptr() as *const _, n);
            }
        }

        // Debug: capture w2 before emulation for set_robust_list (nr=99).
        // After fork, glibc saves the fork return in w2 before calling
        // set_robust_list. Verify w2 is preserved across the handler.
        let is_set_robust = nr == 99;
        let w2_before = mctx.ss.x[2];

        // Debug: check DEBUG_RESTORED_X0 — the actual x0 loaded by the asm
        if is_set_robust {
            let asm_x0 = crate::trampoline::DEBUG_RESTORED_X0.swap(-1, Ordering::SeqCst);
            if asm_x0 != -1 && crate::syscall::trace_enabled() {
                let pid = libc::getpid();
                let mctx_x0 = mctx.ss.x[0];
                let mut buf = [0u8; 160];
                let n = raw_fmt(&mut buf, format_args!(
                    "fakelinux: [{}] ASM_X0={:#x} mctx_x0={:#x} w2={:#x}\n",
                    pid, asm_x0 as u64, mctx_x0, w2_before
                ));
                libc::write(2, buf.as_ptr() as *const _, n);
            }
        }

        let args = [
            mctx.ss.x[0], mctx.ss.x[1], mctx.ss.x[2], mctx.ss.x[3], mctx.ss.x[4], mctx.ss.x[5],
        ];

        // Store guest PC for futex deadlock diagnostics
        LAST_SVC_PC.store(pc, Ordering::Relaxed);
        LAST_SVC_FP.store(mctx.ss.fp, Ordering::Relaxed);
        LAST_SVC_LR.store(mctx.ss.lr, Ordering::Relaxed);

        // Trace all SVCs from fork children (including worker threads)
        if crate::syscall::trace_enabled() && crate::thread::is_fork_child() {
            let pid = libc::getpid();
            let tid = libc::pthread_self() as u64;
            let mut buf = [0u8; 160];
            let n = raw_fmt(&mut buf, format_args!(
                "fakelinux: [{}] CHILD_SVC nr={} x0={:#x} tid={:#x} pc={:#x}\n",
                pid, nr, mctx.ss.x[0], tid, pc
            ));
            libc::write(2, buf.as_ptr() as *const _, n);
        }

        let result = syscall::emulate(nr, &args, mctx);

        // Check if any trampoline was requested (fork, patch, etc.)
        if crate::trampoline::check_and_redirect(mctx, uctx, result, pc + 4) {
            // Trampoline activated — skip normal x0/pc update
        } else if result == crate::signal::SIGRETURN_SENTINEL {
            // rt_sigreturn: registers were already restored directly into mctx.
            // Don't overwrite x0 or pc.
        } else {
            mctx.ss.x[0] = result as u64;
            mctx.ss.pc = pc + 4;
        }

        // Log set_robust_list: verify w2 preserved and PC advanced correctly
        if is_set_robust && crate::syscall::trace_enabled() {
            let pid = libc::getpid();
            let w2_after = mctx.ss.x[2];
            let pc_after = mctx.ss.pc;
            let x0_after = mctx.ss.x[0];
            let mut buf = [0u8; 256];
            let n = raw_fmt(&mut buf, format_args!(
                "fakelinux: [{}] SET_ROBUST pc={:#x}->{:#x} x0={:#x} w2={:#x}->{:#x} result={:#x}\n",
                pid, pc, pc_after, x0_after, w2_before, w2_after, result
            ));
            libc::write(2, buf.as_ptr() as *const _, n);
        }
    } else if instr & MSR_TPIDR_MASK == MSR_TPIDR_BASE {
        // MSR tpidr_el0, Xn — guest is writing to TPIDR_EL0
        // macOS clobbers TPIDR_EL0 on signal return, so we save the value
        // and serve it via intercepted MRS instructions.
        let rn = (instr & 0x1F) as usize;
        let val = read_gpr(&mctx.ss, rn);
        set_thread_tpidr(val);
        mctx.ss.pc = pc + 4;
    } else if instr & MRS_TPIDR_MASK == MRS_TPIDR_BASE {
        // MRS Xn, tpidr_el0 — guest is reading TPIDR_EL0
        // Return our saved value instead of the macOS-clobbered one.
        let rn = (instr & 0x1F) as usize;
        let val = get_thread_tpidr();
        write_gpr(&mut mctx.ss, rn, val);
        mctx.ss.pc = pc + 4;
    } else if instr & 0xFFE0_001F == 0xD420_0000 {
        // BRK #N — guest's own breakpoint (not ours, we use UDF now)
        let brk_imm = (instr >> 5) & 0xFFFF;
        if pc < 0x500000000 {
            // BRK in macOS code (e.g. post-fork child runtime assertion) — exit silently
            libc::_exit(128 + libc::SIGILL);
        }
        // Use raw write — safe after fork (no Rust Mutex)
        let mut buf = [0u8; 80];
        let n = raw_fmt(&mut buf, format_args!("fakelinux: guest BRK #{:#x} at pc={:#x}\n", brk_imm, pc));
        libc::write(2, buf.as_ptr() as *const _, n);
        libc::_exit(128 + libc::SIGILL);
    } else {
        // Unknown instruction triggered SIGILL — could be a guest UDF or
        // a real illegal instruction. Forward to guest handler if registered.
        let linux_sig = 4; // SIGILL
        let sa = crate::signal::guest_sigaction(linux_sig);
        if sa.handler != 0 && sa.handler != 1 {
            // Guest has a SIGILL handler — let signal_forwarder handle it
            IN_TRAP.store(false, Ordering::SeqCst);
            crate::signal::build_sigframe_and_redirect(mctx, linux_sig as i32, sa.handler, sa.mask);
            return;
        }
        let mut buf = [0u8; 80];
        let n = raw_fmt(&mut buf, format_args!("fakelinux: SIGILL at pc={:#x} instr={:#010x}\n", pc, instr));
        libc::write(2, buf.as_ptr() as *const _, n);
        libc::_exit(128 + libc::SIGILL);
    }

    // Keep IN_TRAP=true while delivering pending signals: build_sigframe_and_redirect
    // mutates `mctx`, and another macOS signal arriving here would also try to
    // mutate it via signal_forwarder, racing with our writes.
    crate::signal::deliver_pending_to_guest(mctx);
    IN_TRAP.store(false, Ordering::SeqCst);
}

/// Full signal environment re-init for child after fork().
/// Re-installs trap handler, allocates a fresh signal alt stack, unblocks signals,
/// and clears inherited pending signals (POSIX: child's pending set is empty).
pub fn init_child_after_fork() {
    // POSIX: child's pending signal set must be empty after fork.
    // Clear fakelinux's internal pending signals (inherited from parent via COW).
    crate::signal::reset_after_fork();

    unsafe {
        // Allocate a fresh signal alt stack for the child
        let stack_size: usize = 128 * 1024;
        let stack = libc::mmap(
            std::ptr::null_mut(),
            stack_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        if stack != libc::MAP_FAILED {
            let ss = libc::stack_t {
                ss_sp: stack,
                ss_flags: 0,
                ss_size: stack_size,
            };
            libc::sigaltstack(&ss, std::ptr::null_mut());
        }

        // Re-install trap handler
        install_trap_handler();

        // Unblock all signals
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());

        // Reset IN_TRAP (should already be false, but be safe)
        IN_TRAP.store(false, Ordering::SeqCst);
    }
}

/// Install the SIGILL trap handler.
pub fn install_trap_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = trap_handler as *const () as libc::sighandler_t;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        // Block other signals during the SIGILL handler to prevent signal_forwarder
        // from racing with trap_handler on the shared mctx and FORK trampoline state.
        // Without this, a SIGCHLD arriving mid-handler can corrupt sigframe writes
        // and miss sigreturn restoration. See docs/theory.md.
        libc::sigfillset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGILL, &sa, std::ptr::null_mut()) != 0 {
            let msg = "fakelinux: sigaction(SIGILL) failed\n";
            libc::write(2, msg.as_ptr() as *const _, msg.len());
            libc::_exit(127);
        }
    }
}

/// Get the handler function pointer (for use in forked children and new threads).
pub fn trap_handler_ptr() -> libc::sighandler_t {
    trap_handler as *const () as libc::sighandler_t
}

pub fn install_handler() {
    // Cache env-derived trace knobs BEFORE the handler can ever fire — the
    // handler must never touch std::env (env-lock self-deadlock).
    init_trace_flags();
    unsafe {
        // Allocate a signal-handler stack
        let stack_size: usize = 128 * 1024;
        let stack = libc::mmap(
            std::ptr::null_mut(),
            stack_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        if stack == libc::MAP_FAILED {
            panic!("failed to allocate signal stack");
        }
        let ss = libc::stack_t {
            ss_sp: stack,
            ss_flags: 0,
            ss_size: stack_size,
        };
        if libc::sigaltstack(&ss, std::ptr::null_mut()) != 0 {
            panic!("sigaltstack failed");
        }

        // Install SIGILL handler FIRST (before unblocking — if SIGILL is
        // pending, unblocking would fire it with SIG_DFL=terminate!)
        install_trap_handler();

        // NOW unblock all signals (safe — our handler is installed)
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());

        // Install SIGSEGV/SIGBUS handler that tries lazy relocation fixup
        // for relocated ET_EXEC before falling through to crash diagnostics.
        let mut sa2: libc::sigaction = std::mem::zeroed();
        sa2.sa_sigaction = segv_fixup_handler as *const () as libc::sighandler_t;
        sa2.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigfillset(&mut sa2.sa_mask);
        libc::sigaction(libc::SIGSEGV, &sa2, std::ptr::null_mut());
        libc::sigaction(libc::SIGBUS, &sa2, std::ptr::null_mut());
    }
}

/// Decode a faulting load/store and pick the register to relocate.
///
/// The whole-register scan can patch an innocent register: in python3.12
/// (ET_EXEC) a strcpy loop faulted on `LDR x3, [x0, x10]` where x0 was a
/// valid host pointer and x10 a wrapped difference — their SUM was the
/// unrelocated address, but neither register was in [orig_lo, orig_hi).
/// Decoding the instruction lets us fix the register actually involved.
///
/// Returns Some(reg index 0..=30) if the instruction is a load/store whose
/// computed effective address equals `fault_addr` (which must lie in the
/// unrelocated range), preferring Rn when it is itself unrelocated.
fn lazy_reloc_pick_register(
    instr: u32,
    regs: &[u64; 31],
    fault_addr: u64,
    orig_lo: u64,
    orig_hi: u64,
) -> Option<usize> {
    if fault_addr < orig_lo || fault_addr >= orig_hi {
        return None;
    }
    let in_range = |v: u64| v >= orig_lo && v < orig_hi;
    let rt_n = ((instr >> 5) & 0x1f) as usize; // Rn field
    if rt_n == 31 {
        return None; // SP-based access — not a relocation miss
    }
    let rn = regs[rt_n];

    // Load/store register offset: LDR/STR Rt, [Rn, Rm{, ext {#amount}}]
    if instr & 0x3b20_0c00 == 0x3820_0800 {
        let rm_idx = ((instr >> 16) & 0x1f) as usize;
        if rm_idx == 31 {
            return None;
        }
        let rm = regs[rm_idx];
        let option = (instr >> 13) & 0x7;
        let s = (instr >> 12) & 1;
        let size = instr >> 30; // scale for shifted index
        let shift = if s == 1 { size } else { 0 };
        let offset = match option {
            0b010 => rm as u32 as u64,                  // UXTW
            0b110 => rm as u32 as i32 as i64 as u64,    // SXTW
            0b011 | 0b111 => rm,                        // LSL / SXTX
            _ => return None,
        };
        let ea = rn.wrapping_add(offset.wrapping_shl(shift));
        if ea != fault_addr {
            return None;
        }
        // Prefer Rn if it is itself an unrelocated pointer; otherwise the
        // unrelocated value arrived via the index register.
        return Some(if in_range(rn) { rt_n } else { rm_idx });
    }

    // Load/store unsigned immediate: LDR/STR Rt, [Rn, #imm12 << size]
    if instr & 0x3b00_0000 == 0x3900_0000 {
        let imm12 = ((instr >> 10) & 0xfff) as u64;
        let size = instr >> 30;
        let ea = rn.wrapping_add(imm12 << size);
        return if ea == fault_addr { Some(rt_n) } else { None };
    }

    // Load/store imm9: unscaled (LDUR), post-index, pre-index
    if instr & 0x3b20_0000 == 0x3800_0000 {
        let variant = (instr >> 10) & 0x3;
        let imm9 = (((instr >> 12) & 0x1ff) as i32) << 23 >> 23; // sign-extend
        let ea = if variant == 0b01 {
            rn // post-index: access at Rn, writeback after
        } else {
            rn.wrapping_add(imm9 as i64 as u64)
        };
        return if ea == fault_addr { Some(rt_n) } else { None };
    }

    // AdvSIMD load/store multiple/single structures (LD1/ST1/LD2/…):
    // address is always plain [Rn] (post-index writeback happens after).
    if instr & 0xbf00_0000 == 0x0c00_0000 || instr & 0xbf00_0000 == 0x0d00_0000 {
        return if rn == fault_addr { Some(rt_n) } else { None };
    }

    // LDP/STP: load/store pair (signed offset, pre/post-index)
    if instr & 0x3a00_0000 == 0x2800_0000 {
        let variant = (instr >> 23) & 0x3;
        let imm7 = (((instr >> 15) & 0x7f) as i32) << 25 >> 25; // sign-extend
        let scale = 2 + (instr >> 31); // 4-byte pairs vs 8-byte pairs
        let ea = if variant == 0b01 {
            rn // post-index
        } else {
            rn.wrapping_add(((imm7 as i64) << scale) as u64)
        };
        return if ea == fault_addr { Some(rt_n) } else { None };
    }

    None
}

/// SIGSEGV handler that tries lazy relocation fixup for relocated ET_EXEC.
/// If the fault address or PC is in the original (unrelocated) ET_EXEC range,
/// adjust the register/PC by base_offset and retry the instruction.
/// Try the ET_EXEC lazy-relocation fixups (case 1: PC at unrelocated
/// address; case 2: data access through an unrelocated register) against a
/// fault context. Returns true if something was fixed and the faulting
/// instruction should simply be retried.
///
/// Shared by segv_fixup_handler AND the guest-signal forwarder: once a guest
/// installs its own SIGSEGV handler (gcc's ICE handler, libjava-style crash
/// catchers…) the forwarder replaces our fixup handler, and without this
/// hook lazy relocation would silently stop working for that process.
pub unsafe fn try_lazy_exec_fixup(mctx: &mut MContext64) -> bool {
    // Software watchpoint: write fault on the watched page?
    if WATCH_PAGE.load(Ordering::Relaxed) != 0 {
        let fa = mctx.es.far;
        if watch_handle_fault(mctx, fa) {
            return true; // retry the store with the page unprotected
        }
    }
    let base_offset = EXEC_BASE_OFFSET.load(Ordering::Relaxed);
    if base_offset != 0 {
        let orig_lo = EXEC_ORIG_LO.load(Ordering::Relaxed);
        let orig_hi = EXEC_ORIG_HI.load(Ordering::Relaxed);
        let pc = mctx.ss.pc;
        let fault_addr = mctx.es.far;

        // Case 1: instruction fetch at unrelocated address (branch to unrelocated
        // function pointer). Redirect PC to the relocated address.
        if pc >= orig_lo && pc < orig_hi {
            static FIXUP_PC_COUNT: AtomicU64 = AtomicU64::new(0);
            let n = FIXUP_PC_COUNT.fetch_add(1, Ordering::Relaxed);
            if n < 5 {
                eprintln!("fakelinux: lazy reloc: PC {:#x} → {:#x}", pc, pc + base_offset);
            }
            mctx.ss.pc = pc + base_offset;
            return true; // retry instruction at relocated address
        }

        // Case 2: data access at unrelocated address. First decode the
        // faulting load/store and fix the register actually used in the
        // address computation — the whole-register scan below can patch an
        // innocent register when the unrelocated value arrives via
        // base+index arithmetic (e.g. python3.12 strcpy: LDR x3, [x0, x10]
        // where only x0+x10 is in range, and a different register
        // coincidentally held an in-range value).
        if fault_addr >= orig_lo && fault_addr < orig_hi {
            // pc just executed, so it is mapped — safe to read the instruction.
            let instr = *(pc as *const u32);
            let mut regs31 = [0u64; 31];
            regs31[..29].copy_from_slice(&mctx.ss.x[..29]);
            regs31[29] = mctx.ss.fp;
            regs31[30] = mctx.ss.lr;
            if let Some(i) = lazy_reloc_pick_register(instr, &regs31, fault_addr, orig_lo, orig_hi) {
                static FIXUP_DECODE_COUNT: AtomicU64 = AtomicU64::new(0);
                let n = FIXUP_DECODE_COUNT.fetch_add(1, Ordering::Relaxed);
                if n < 5 {
                    eprintln!("fakelinux: lazy reloc: decoded instr {:#010x} → fix x{} {:#x} → {:#x} (fault_addr={:#x} pc={:#x})",
                              instr, i, regs31[i], regs31[i].wrapping_add(base_offset), fault_addr, pc);
                }
                let fixed = regs31[i].wrapping_add(base_offset);
                match i {
                    29 => mctx.ss.fp = fixed,
                    30 => mctx.ss.lr = fixed,
                    _ => mctx.ss.x[i] = fixed,
                }
                return true; // retry with fixed register
            }
            // Fallback: scan ALL GPRs — the unrelocated value might be in any
            // register for instructions the decoder does not understand.
            for i in 0..29 { // x0-x28 (skip x29=fp, x30=lr)
                let val = mctx.ss.x[i];
                if val >= orig_lo && val < orig_hi {
                    static FIXUP_REG_COUNT: AtomicU64 = AtomicU64::new(0);
                    let n = FIXUP_REG_COUNT.fetch_add(1, Ordering::Relaxed);
                    if n < 5 {
                        eprintln!("fakelinux: lazy reloc: x{} {:#x} → {:#x} (fault_addr={:#x} pc={:#x} instr={:#010x})",
                                  i, val, val + base_offset, fault_addr, pc, instr);
                    }
                    mctx.ss.x[i] = val + base_offset;
                    return true; // retry with fixed register
                }
            }
        }
    }
    false
}

unsafe extern "C" fn segv_fixup_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    ctx: *mut c_void,
) {
    let uctx = &mut *(ctx as *mut UContext);
    let mctx = &mut *uctx.uc_mcontext;
    if try_lazy_exec_fixup(mctx) {
        return; // fixed — retry the faulting instruction
    }
    // Island-fetch fault recovery: a trampoline page became unexecutable
    // (PROT_EXEC stripped / per-thread JIT write mode). If the fault is at
    // a slot boundary, no trampoline side effects have executed — emulate
    // the original instruction (the UDF slow path) and continue after it.
    if mctx.es.far == mctx.ss.pc {
        if let Some((orig_pc, orig_instr)) =
            crate::x18_trampoline::island_fault_recovery_info(mctx.ss.pc)
        {
            static RECOVERED: AtomicU64 = AtomicU64::new(0);
            let n = RECOVERED.fetch_add(1, Ordering::Relaxed);
            if n < 8 || n % 8192 == 0 {
                // include the island page's protection — distinguishes a
                // stripped-X page from per-thread JIT write-mode anomalies
                let prot = {
                    extern "C" {
                        fn mach_vm_region(task: u32, address: *mut u64, size: *mut u64,
                            flavor: i32, info: *mut i32, info_cnt: *mut u32, object: *mut u32) -> i32;
                    }
                    let mut a = mctx.ss.pc;
                    let mut s = 0u64;
                    let mut info = [0i32; 19];
                    let mut cnt = 9u32;
                    let mut obj = 0u32;
                    if mach_vm_region(mach_task_self(), &mut a, &mut s, 9,
                        info.as_mut_ptr(), &mut cnt, &mut obj) == 0 { info[0] } else { -1 }
                };
                let mut buf = [0u8; 220];
                let m = raw_fmt(&mut buf, format_args!(
                    "fakelinux: [{}] island fetch fault RECOVERED #{}: island_pc={:#x} (prot={}) orig_pc={:#x} instr={:#010x}\n",
                    libc::getpid(), n, mctx.ss.pc, prot, orig_pc, orig_instr));
                libc::write(2, buf.as_ptr() as *const _, m);
            }
            // Repair permanently: point the site back at UDF emulation so it
            // costs one normal SIGILL trap per execution instead of a SIGBUS
            // + island lookup here every time. Guest text is anon-backed —
            // mprotect from signal context is safe.
            {
                let page = orig_pc & !0x3FFF;
                if libc::mprotect(page as *mut _, 0x4000,
                    libc::PROT_READ | libc::PROT_WRITE) == 0 {
                    if orig_instr & MSR_TPIDR_MASK == MSR_TPIDR_BASE
                        || orig_instr & MRS_TPIDR_MASK == MRS_TPIDR_BASE
                        || crate::decoder::references_x18(orig_instr) {
                        crate::loader::add_runtime_tpidr_patch_pub(orig_pc, orig_instr);
                        (orig_pc as *mut u32).write(UDF_MARKER);
                    }
                    extern "C" { fn sys_icache_invalidate(s: *mut libc::c_void, n: usize); }
                    sys_icache_invalidate(orig_pc as *mut _, 4);
                    libc::mprotect(page as *mut _, 0x4000,
                        libc::PROT_READ | libc::PROT_EXEC);
                }
            }
            mctx.ss.pc = orig_pc;
            let handled = if orig_instr & MSR_TPIDR_MASK == MSR_TPIDR_BASE {
                let rn = (orig_instr & 0x1F) as usize;
                set_thread_tpidr(read_gpr(&mctx.ss, rn));
                true
            } else if orig_instr & MRS_TPIDR_MASK == MRS_TPIDR_BASE {
                let rn = (orig_instr & 0x1F) as usize;
                let val = get_thread_tpidr();
                write_gpr(&mut mctx.ss, rn, val);
                true
            } else {
                emulate_x18_instruction(orig_instr, mctx)
            };
            if handled {
                if mctx.ss.pc == orig_pc {
                    mctx.ss.pc = orig_pc + 4;
                }
                return;
            }
        }
    }
    // Fixup failed — fall through to crash diagnostics
    crash_handler(sig, info, ctx);
}

unsafe extern "C" fn crash_handler(
    sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    ctx: *mut c_void,
) {
    // Guard against recursive SIGSEGV (e.g. accessing unmapped guest PC).
    // Must use atomic + SeqCst to ensure the store is visible before any
    // subsequent instruction that might fault.
    static IN_CRASH: AtomicBool = AtomicBool::new(false);
    if IN_CRASH.swap(true, Ordering::SeqCst) {
        libc::_exit(128 + sig);
    }

    // Use raw write() — safe after fork (no Rust Mutex deadlock)
    let uctx = &*(ctx as *const UContext);
    let mctx = &*uctx.uc_mcontext;
    let regs = &mctx.ss;
    let fault_addr = mctx.es.far;
    let guest_tpidr = get_thread_tpidr();
    let signame = if sig == libc::SIGSEGV { "SIGSEGV" } else { "SIGBUS" };
    // Read the instruction at PC using Mach vm_read_overwrite to avoid
    // recursive SIGSEGV if PC points to unmapped memory.
    let instr_at_pc = {
        let mut val: u32 = 0;
        let mut out_size: libc::vm_size_t = 0;
        let kr = mach_vm_read_overwrite(
            mach_task_self(),
            regs.pc as u64,
            4,
            &mut val as *mut u32 as u64,
            &mut out_size,
        );
        if kr == 0 && out_size == 4 { val } else { 0 }
    };
    let mut buf = [0u8; 768];
    let n = raw_fmt(&mut buf, format_args!(
        "\nfakelinux: {} at pc={:#x} fault_addr={:#x} instr={:#010x}\n  x0={:#x}  x1={:#x}  x2={:#x}  x3={:#x}\n  x4={:#x}  x5={:#x}  x6={:#x}  x7={:#x}\n  x8={:#x}  x9={:#x}  x10={:#x}  x11={:#x}\n  x12={:#x}  x13={:#x}  x14={:#x}  x15={:#x}\n  x16={:#x}  x17={:#x}  x18(emu)={:#x}  x18(hw)={:#x}\n  x19={:#x}  x20={:#x}  x21={:#x}  x22={:#x}\n  fp={:#x}  sp={:#x}  lr={:#x}  tpidr={:#x}\n",
        signame, regs.pc, fault_addr, instr_at_pc,
        regs.x[0], regs.x[1], regs.x[2], regs.x[3],
        regs.x[4], regs.x[5], regs.x[6], regs.x[7],
        regs.x[8], regs.x[9], regs.x[10], regs.x[11],
        regs.x[12], regs.x[13], regs.x[14], regs.x[15],
        regs.x[16], regs.x[17], get_thread_x18(), regs.x[18],
        regs.x[19], regs.x[20], regs.x[21], regs.x[22],
        regs.fp, regs.sp, regs.lr, guest_tpidr
    ));
    libc::write(2, buf.as_ptr() as *const _, n);
    // Dump the top of the guest stack (callee-saved spill area) — lets us
    // recover caller-saved registers (e.g. an rtx pointer spilled by the
    // crashing callee's prologue) without a debugger. Safe mach read.
    {
        let mut words = [0u64; 20];
        let mut out_size: libc::vm_size_t = 0;
        let kr = mach_vm_read_overwrite(
            mach_task_self(),
            regs.sp as u64,
            (words.len() * 8) as u64,
            words.as_mut_ptr() as u64,
            &mut out_size,
        );
        if kr == 0 && out_size as usize == words.len() * 8 {
            for chunk in 0..(words.len() / 4) {
                let i = chunk * 4;
                let mut sbuf = [0u8; 192];
                let sn = raw_fmt(&mut sbuf, format_args!(
                    "  [sp+{:#04x}] {:#018x} {:#018x} {:#018x} {:#018x}\n",
                    i * 8, words[i], words[i + 1], words[i + 2], words[i + 3]
                ));
                libc::write(2, sbuf.as_ptr() as *const _, sn);
            }
        }
    }
    // If the faulting PC is inside an x18 trampoline island, identify which
    // guest instruction the trampoline belongs to.
    if let Some((island, idx, off, orig_pc)) = crate::x18_trampoline::find_trampoline_for_pc(regs.pc) {
        // Read the guest instructions around orig_pc for context (safe read).
        let mut around = [0u32; 4]; // orig_pc-8 .. orig_pc+4
        let mut out_size: libc::vm_size_t = 0;
        let _ = mach_vm_read_overwrite(
            mach_task_self(), orig_pc.wrapping_sub(8), 16,
            around.as_mut_ptr() as u64, &mut out_size);
        // Query the ACTUAL protection of the faulting page: distinguishes a
        // stripped-PROT_EXEC page (process-wide) from per-thread JIT write
        // mode (page still shows rwx).
        let (prot_cur, prot_max) = {
            extern "C" {
                fn mach_vm_region(task: u32, address: *mut u64, size: *mut u64,
                    flavor: i32, info: *mut i32, info_cnt: *mut u32, object: *mut u32) -> i32;
            }
            let mut addr = regs.pc;
            let mut size = 0u64;
            let mut info = [0i32; 19]; // VM_REGION_BASIC_INFO_64
            let mut cnt = 9u32; // VM_REGION_BASIC_INFO_COUNT_64
            let mut obj = 0u32;
            let kr = mach_vm_region(mach_task_self(), &mut addr, &mut size,
                9 /*VM_REGION_BASIC_INFO_64*/, info.as_mut_ptr(), &mut cnt, &mut obj);
            if kr == 0 { (info[0], info[1]) } else { (-1, -1) }
        };
        let mut buf3 = [0u8; 320];
        let n3 = raw_fmt(&mut buf3, format_args!(
            "  pc in trampoline island={:#x} idx={} off={} guest_orig_pc={:#x} page_prot={}/{}\n  guest code around: {:#010x} {:#010x} [{:#010x}] {:#010x}\n",
            island, idx, off, orig_pc, prot_cur, prot_max,
            around[0], around[1], around[2], around[3]
        ));
        libc::write(2, buf3.as_ptr() as *const _, n3);
    }
    // If we were emulating an x18 instruction, print it
    let x18_instr = CURRENT_X18_INSTR;
    let x18_pc = CURRENT_X18_PC;
    if x18_instr != 0 {
        let mut buf2 = [0u8; 128];
        let n2 = raw_fmt(&mut buf2, format_args!(
            "  emulating x18 instr={:#010x} at guest_pc={:#x}\n",
            x18_instr, x18_pc
        ));
        libc::write(2, buf2.as_ptr() as *const _, n2);
    }
    libc::_exit(128 + sig);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── lazy_reloc_pick_register ─────────────────────────────────────────
    // ET_EXEC lazy relocation: when a load/store faults on an unrelocated
    // address, decode the instruction and pick the register to relocate.

    const RELOC_LO: u64 = 0x400000;
    const RELOC_HI: u64 = 0x900000;

    fn regs_with(pairs: &[(usize, u64)]) -> [u64; 31] {
        let mut r = [0u64; 31];
        for &(i, v) in pairs {
            r[i] = v;
        }
        r
    }

    #[test]
    fn lazy_reloc_python3_strcpy_crash() {
        // Real python3.12 crash: LDR x3, [x0, x10] with x0 a valid host
        // stack pointer and x10 a huge value such that x0+x10 wraps to the
        // unrelocated 0x701f60. Neither register alone is in range — the
        // whole-register scan patched innocent x1 and crashed on retry.
        // The decoder must pick Rm (x10).
        let regs = regs_with(&[
            (0, 0x7ff07fed50),
            (1, 0x700701f60), // already-relocated red herring
            (10, 0xffffff800ff03210),
        ]);
        let r = lazy_reloc_pick_register(0xf86a6803, &regs, 0x701f60, RELOC_LO, RELOC_HI);
        assert_eq!(r, Some(10));
    }

    #[test]
    fn lazy_reloc_register_offset_prefers_rn_when_in_range() {
        // LDR x3, [x0, x10] where x0 itself is the unrelocated pointer.
        let regs = regs_with(&[(0, 0x701f00), (10, 0x60)]);
        let r = lazy_reloc_pick_register(0xf86a6803, &regs, 0x701f60, RELOC_LO, RELOC_HI);
        assert_eq!(r, Some(0));
    }

    #[test]
    fn lazy_reloc_unsigned_imm_offset() {
        // LDR x1, [x2, #16] — 0xf9400841. Base register x2 unrelocated.
        let regs = regs_with(&[(2, 0x701f50)]);
        let r = lazy_reloc_pick_register(0xf9400841, &regs, 0x701f60, RELOC_LO, RELOC_HI);
        assert_eq!(r, Some(2));
    }

    #[test]
    fn lazy_reloc_byte_load_register_offset() {
        // LDRB w3, [x0, x10] — 0x386a6803 (strcpy-style byte loop).
        let regs = regs_with(&[(0, 0x7ff07fed50), (10, 0xffffff800ff03210)]);
        let r = lazy_reloc_pick_register(0x386a6803, &regs, 0x701f60, RELOC_LO, RELOC_HI);
        assert_eq!(r, Some(10));
    }

    #[test]
    fn lazy_reloc_ea_mismatch_returns_none() {
        // Decoded EA does not match fault_addr → do not guess.
        let regs = regs_with(&[(0, 0x1000), (10, 0x20)]);
        let r = lazy_reloc_pick_register(0xf86a6803, &regs, 0x701f60, RELOC_LO, RELOC_HI);
        assert_eq!(r, None);
    }

    #[test]
    fn lazy_reloc_non_memory_instruction_returns_none() {
        // ADD x0, x1, x2 — not a load/store.
        let regs = regs_with(&[(1, 0x701f00), (2, 0x60)]);
        let r = lazy_reloc_pick_register(0x8b020020, &regs, 0x701f60, RELOC_LO, RELOC_HI);
        assert_eq!(r, None);
    }

    #[test]
    fn lazy_reloc_pre_post_index() {
        // LDR x1, [x2], #8 (post-index) — 0xf8408441. Base x2 unrelocated.
        let regs = regs_with(&[(2, 0x701f60)]);
        let r = lazy_reloc_pick_register(0xf8408441, &regs, 0x701f60, RELOC_LO, RELOC_HI);
        assert_eq!(r, Some(2));
    }

    #[test]
    fn lazy_reloc_simd_multi_structure() {
        // LD1 {v1.16b, v2.16b}, [x1] — 0x4c40a021 (python3.12 memcpy path).
        let regs = regs_with(&[(1, 0x715fe0)]);
        let r = lazy_reloc_pick_register(0x4c40a021, &regs, 0x715fe0, RELOC_LO, RELOC_HI);
        assert_eq!(r, Some(1));
    }

    #[test]
    fn lazy_reloc_simd_multi_structure_post_index() {
        // LD1 {v0.16b, v1.16b}, [x1], #32 — 0x4cdfa020.
        let regs = regs_with(&[(1, 0x715fe0)]);
        let r = lazy_reloc_pick_register(0x4cdfa020, &regs, 0x715fe0, RELOC_LO, RELOC_HI);
        assert_eq!(r, Some(1));
    }

    #[test]
    fn lazy_reloc_ldp() {
        // LDP x0, x1, [x2] — 0xa9400440. Base x2 unrelocated.
        let regs = regs_with(&[(2, 0x701f60)]);
        let r = lazy_reloc_pick_register(0xa9400440, &regs, 0x701f60, RELOC_LO, RELOC_HI);
        assert_eq!(r, Some(2));
    }

    /// Instruction encodings extracted from libpython3.12.so via `objdump -d | grep x18/w18`.
    /// Every one of these MUST be detected by `references_x18()`.
    const LIBPYTHON_X18_INSTRS: &[u32] = &[
        0x0a120061, 0x12000012, 0x1a9203f1, 0x2a0003f2, 0x2a1203e0, 0x2a1203e3,
        0x2a1203ef, 0x2a1203fa, 0x2a1a03f2, 0x34005372, 0x35000052, 0x38001492,
        0x382168d2, 0x382c6832, 0x38326820, 0x38326828, 0x3853d0b2, 0x3860cab2,
        0x3860cb72, 0x3861ca40, 0x3861ca4d, 0x38724808, 0x3872480c, 0x387248a5,
        0x387e4a52, 0x39000032, 0x3ce36a5f, 0x3dc0fe5c, 0x3dc11e5c, 0x3dc1225c,
        0x51001251, 0x51020232, 0x528000f2, 0x52800612, 0x52800652, 0x52800a92,
        0x52800b52, 0x52801b52, 0x52802152, 0x5284e1f2, 0x53021072, 0x6a03025f,
        0x6b01025f, 0x6b03025f, 0x6b12001f, 0x6b12009f, 0x6b12019f, 0x7100065f,
        0x71000a5f, 0x7100da5f, 0x7100fe5f, 0x71025e5f, 0x781fe240, 0x781fee40,
        0x786178d2, 0x786378d2, 0x78726923, 0x79000240, 0x79000241, 0x79000640,
        0x79400653, 0x79400a53, 0x79400e53, 0x79401253, 0x79401653, 0x79401a53,
        0x79401e52, 0x7a521044, 0x7a521084, 0x8b000240, 0x8b00024b, 0x8b000432,
        0x8b0104f2, 0x8b0304d2, 0x8b050412, 0x8b060012, 0x8b0a0242, 0x8b0c0242,
        0x8b0c0652, 0x8b0d0242, 0x8b110272, 0x8b120000, 0x8b120021, 0x8b120029,
        0x8b12003e, 0x8b120091, 0x8b120121, 0x8b120260, 0x8b120261, 0x8b120264,
        0x8b120267, 0x8b120c21, 0x8b120c63, 0x8b1214a5, 0x8b150252, 0x8b170252,
        0x90001cf2, 0x90001d12, 0x910004d2, 0x91000643, 0x91000652, 0x91000cd2,
        0x91006252, 0x910080d2, 0x9100e112, 0x910883d2, 0x927df252, 0x927ef652,
        0x92800012, 0x9a800252, 0x9a920092, 0x9a9fb241, 0x9ac02240, 0x9ac12641,
        0x9ad20800, 0x9b027cf2, 0x9b125421, 0x9e6603f2, 0xa9001bf2, 0xa9003ff2,
        0xa9004be3, 0xa9124bf2, 0xa9401bf2, 0xa9404be3, 0xaa0003f2, 0xaa0203f2,
        0xaa0603f2, 0xaa0703f2, 0xaa1200c1, 0xaa1203e0, 0xaa1203e7, 0xaa1203f3,
        0xaa1203f9, 0xaa1303f2, 0xaa1403f2, 0xaa1903f2, 0xb0001492, 0xb4fffeb2,
        0xb4fffed2, 0xb50065f2, 0xb8727a00, 0xb8727a01, 0xb9000bf2, 0xb90013f2,
        0xb90023f2, 0xb9002bf2, 0xb90043f2, 0xb9400bf2, 0xb94013f2, 0xb9401640,
        0xb9401a40, 0xb94023f2, 0xb9402bf2, 0xb94043f2, 0xcb000241, 0xcb0a0192,
        0xcb0a01b2, 0xcb0c0132, 0xcb0d0132, 0xcb120000, 0xcb120096, 0xcb120097,
        0xd1000572, 0xd1000642, 0xd1000646, 0xd1000647, 0xd1000653, 0xd1000852,
        0xd1000a52, 0xd1001252, 0xd2800012, 0xd2800032, 0xd2820912, 0xd2822512,
        0xd28c0612, 0xd28c6b12, 0xd28d2112, 0xd28d2812, 0xd28dd412, 0xd28e9312,
        0xd28f4012, 0xd28ff412, 0xd290b312, 0xd2916a12, 0xd2921e12, 0xd292c912,
        0xd2933a12, 0xd2937612, 0xd2942312, 0xd294cc12, 0xd2957912, 0xd2962012,
        0xd296c512, 0xd2977012, 0xd2981512, 0xd298bd12, 0xd2996812, 0xd29a0e12,
        0xd29ab712, 0xd29b6112, 0xd29c0b12, 0xd29cb412, 0xd29d5b12, 0xd342fc52,
        0xd342fe51, 0xd343fe4e, 0xd3482e72, 0xd3586c52, 0xd37cee40, 0xd37ff812,
        0xeb020241, 0xeb04025f, 0xeb0c025f, 0xeb12009f, 0xeb1200ff, 0xeb12017f,
        0xeb12023f, 0xeb1e025f, 0xf0001d32, 0xf100025f, 0xf100125f, 0xf1001a5f,
        0xf240065f, 0xf2400a5f, 0xf2a10012, 0xf2d00a12, 0xf2e04112, 0xf86d7a41,
        0xf9003ff2, 0xf9400012, 0xf94003f2, 0xf94009d2, 0xf9400a53, 0xf9401d12,
        0xf940a992, 0xf9446e52, 0xf9456a52, 0xfa5210c4,
    ];

    #[test]
    fn references_x18_detects_all_libpython_instructions() {
        let mut missed = Vec::new();
        for &instr in LIBPYTHON_X18_INSTRS {
            if !references_x18(instr) {
                missed.push(instr);
            }
        }
        if !missed.is_empty() {
            for &instr in &missed {
                eprintln!("MISSED: {:#010x}", instr);
            }
            panic!("{} of {} x18 instructions not detected by references_x18()", missed.len(), LIBPYTHON_X18_INSTRS.len());
        }
    }

    /// Verify that known non-x18 instructions are NOT falsely detected.
    #[test]
    fn references_x18_no_false_positives() {
        // NOP, RET, common instructions that don't touch x18
        // Includes the false positive that caused the Python SIGSEGV:
        // stp x29, x30, [sp, #-224]! (bits[20:16]=18 is imm7, NOT Rm)
        let non_x18: &[u32] = &[
            0xd503201f, // NOP
            0xd65f03c0, // RET
            0xa9b27bfd, // stp x29, x30, [sp, #-224]! — bits[20:16]=18 is imm7, NOT Rm
            0x91000000, // ADD x0, x0, #0
            0xf9400000, // LDR x0, [x0]
            0xd2800000, // MOV x0, #0
            0xb9400000, // LDR w0, [x0]
            0xd4000001, // SVC #0
            0x5e136250, // USHL D16, D18, D19 — SIMD scalar, D18 is NOT GPR x18
        ];
        for &instr in non_x18 {
            assert!(!references_x18(instr), "false positive for {:#010x}", instr);
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Emulation handler tests (TDD for audit-found bugs)
    // ═══════════════════════════════════════════════════════════════════

    /// Create a zeroed MContext64 for testing.
    fn make_mctx() -> MContext64 {
        // Ensure x18 thread-local storage is initialized
        if !X18_KEY_INIT.load(std::sync::atomic::Ordering::SeqCst) {
            init_x18_key();
        }
        unsafe { std::mem::zeroed() }
    }

    // ─── Bug #1: Signed loads executed as stores ─────────────────────

    #[test]
    fn test_ldrsw_emulates_as_load_not_store() {
        // LDRSW x2, [x18] — opc=10 (signed load), Rn=x18 (base), Rt=x2 (dest)
        // Encoding: 10_111_00_110_000000000000_10010_00010 = 0xB9800242
        // This MUST load from memory, NOT store.
        let mut mctx = make_mctx();
        let test_val: i32 = -42;
        let test_addr = &test_val as *const i32 as u64;
        set_thread_x18(test_addr); // x18 = base address
        mctx.ss.x[2] = 0xDEAD; // sentinel in destination

        let instr: u32 = 0xB9800242; // LDRSW x2, [x18, #0]
        let result = emul_ldr_str_unsigned_imm(instr, &mut mctx);
        assert!(result, "LDRSW should be handled");

        // x2 should contain sign-extended -42
        assert_eq!(mctx.ss.x[2], (-42i64) as u64,
            "LDRSW should sign-extend to 64-bit, got {:#x}", mctx.ss.x[2]);
        assert_eq!(test_val, -42, "memory should NOT be modified by a load");
    }

    #[test]
    fn test_ldrsh_emulates_as_load_not_store() {
        // LDRSH x2, [x18] — size=01, opc=10, Rn=x18, Rt=x2
        // Encoding: 01_111_00_110_000000000000_10010_00010 = 0x79800242
        let mut mctx = make_mctx();
        let test_val: i16 = -1000;
        let test_addr = &test_val as *const i16 as u64;
        set_thread_x18(test_addr);
        mctx.ss.x[2] = 0xDEAD;

        let instr: u32 = 0x79800242; // LDRSH x2, [x18]
        let result = emul_ldr_str_unsigned_imm(instr, &mut mctx);
        assert!(result, "LDRSH should be handled");

        assert_eq!(mctx.ss.x[2], (-1000i64) as u64,
            "LDRSH should sign-extend to 64-bit, got {:#x}", mctx.ss.x[2]);
        assert_eq!(test_val, -1000, "memory should NOT be modified by a load");
    }

    // ─── Bug #2: PRFM executed as store ──────────────────────────────

    #[test]
    fn test_prfm_is_noop() {
        // PRFM #0, [x0] with x0 pointing at a canary — size=3, V=0, opc=2
        // Encoding: 11_111_00_110_000000000000_00000_00000 = 0xF9800000
        let mut mctx = make_mctx();
        let mut canary: u64 = 0xCAFE_BABE_1234_5678;
        let addr = &mut canary as *mut u64 as u64;
        mctx.ss.x[0] = addr;

        let instr: u32 = 0xF9800000; // PRFM #0, [x0]
        let result = emul_ldr_str_unsigned_imm(instr, &mut mctx);
        assert!(result, "PRFM should be handled (as no-op)");
        assert_eq!(canary, 0xCAFE_BABE_1234_5678,
            "PRFM should NOT modify memory");
    }

    // ─── Bug #3: ADC/SBC wrong C flag ───────────────────────────────

    #[test]
    fn test_adcs_carry_flag_with_carry_in() {
        // ADCS x18, x0, x1 — sf=1, op=0, S=1
        // a=MAX, b=MAX, carry_in=1 → result wraps, C should be 1
        let mut mctx = make_mctx();
        mctx.ss.x[0] = u64::MAX;
        mctx.ss.x[1] = u64::MAX;
        mctx.ss.cpsr = 1 << 29; // C flag set (carry-in = 1)
        set_thread_x18(0);

        // ADCS x18, x0, x1: sf=1, op=0, S=1, Rm=1, Rn=0, Rd=18
        // 10_1_11010000_00001_000000_00000_10010 = 0xBA010012
        let instr: u32 = 0xBA010012;
        emul_addsub_carry(instr, &mut mctx);

        // C flag should be set (overflow from 64-bit addition)
        let c_flag = (mctx.ss.cpsr >> 29) & 1;
        assert_eq!(c_flag, 1, "ADCS with MAX+MAX+1 should set C flag");
    }

    #[test]
    fn test_sbcs_carry_flag_equal_with_no_carry() {
        // SBCS x18, x0, x1 — a=5, b=5, carry_in=0
        // SBC = a + ~b + C = 5 + ~5 + 0 = 5 + 0xFFFF...FFFA + 0 = 0xFFFF...FFFF
        // No carry-out → C should be 0
        let mut mctx = make_mctx();
        mctx.ss.x[0] = 5;
        mctx.ss.x[1] = 5;
        mctx.ss.cpsr = 0; // C flag clear (carry-in = 0)
        set_thread_x18(0);

        // SBCS x18, x0, x1: sf=1, op=1, S=1, Rm=1, Rn=0, Rd=18
        // 11_1_11010000_00001_000000_00000_10010 = 0xFA010012
        let instr: u32 = 0xFA010012;
        emul_addsub_carry(instr, &mut mctx);

        let c_flag = (mctx.ss.cpsr >> 29) & 1;
        assert_eq!(c_flag, 0, "SBCS 5-5 with C=0 should clear C flag");
    }

    // ─── Bug #4: LDNP/STNP offset not applied ───────────────────────

    #[test]
    fn test_ldnp_applies_offset() {
        // LDNP x2, x3, [x0, #16] — no-allocate pair load with offset
        // opc=10, wb=00, L=1, imm7=2, Rt2=3, Rn=0, Rt=2
        // 10_101_000_01_0000010_00011_00000_00010 = 0xA8410C02
        let mut mctx = make_mctx();
        let data: [u64; 4] = [111, 222, 333, 444];
        let base_addr = data.as_ptr() as u64;
        mctx.ss.x[0] = base_addr;

        let instr: u32 = 0xA8410C02;
        let result = emul_ldp_stp(instr, &mut mctx);
        assert!(result, "LDNP should be handled");

        // With offset #16 (imm7=2, scale=8): should load from base+16 and base+24
        assert_eq!(mctx.ss.x[2], 333, "LDNP Rt should load from base+16, got {}", mctx.ss.x[2]);
        assert_eq!(mctx.ss.x[3], 444, "LDNP Rt2 should load from base+24");
    }

    // ─── Bug #7: EXTR 64-bit lsb=0 returns wrong register ──────────

    #[test]
    fn test_extr_64bit_lsb0_returns_xm() {
        // EXTR x2, x0, x1, #0 — should return Xm (x1), not Xn (x0)
        // ARM spec: result = (Xn:Xm)<63:0> = Xm when lsb=0
        let mut mctx = make_mctx();
        mctx.ss.x[0] = 0xAAAA_BBBB_CCCC_DDDD; // Xn (high)
        mctx.ss.x[1] = 0x1111_2222_3333_4444; // Xm (low)

        // EXTR x2, x0, x1, #0: sf=1, N=1, o0=0, Rm=1, imms=0, Rn=0, Rd=2
        // 1_00_100111_1_0_00001_000000_00000_00010 = 0x93C10002
        let instr: u32 = 0x93C10002;
        let result = emul_extract(instr, &mut mctx);
        assert!(result, "EXTR should be handled");

        assert_eq!(mctx.ss.x[2], 0x1111_2222_3333_4444,
            "EXTR x2, x0, x1, #0 should return Xm (x1), got {:#x}", mctx.ss.x[2]);
    }

    // ─── Bug #8: Logical imm Rd=31 should write SP ──────────────────

    #[test]
    fn test_and_imm_rd31_writes_sp() {
        // ORR SP, x18, #0x1 — opc=01, Rd=31 should write to SP (not discard)
        // For ORR (not ANDS), Rd=31 means SP
        let mut mctx = make_mctx();
        set_thread_x18(0x1234_5678_9ABC_0000);
        mctx.ss.sp = 0;

        // ORR xSP, x18, #0x1: sf=1, opc=01, N=1, immr=0, imms=0, Rn=18, Rd=31
        // 1_01_100100_1_000000_000000_10010_11111 = 0xB240025F
        let instr: u32 = 0xB240025F;
        let result = emul_logical_imm(instr, &mut mctx);
        assert!(result, "ORR imm with Rd=SP should be handled");

        // SP should have the ORR result (0x...0000 | 0x1 = 0x...0001)
        assert_eq!(mctx.ss.sp, 0x1234_5678_9ABC_0001,
            "ORR SP, x18, #1 should write to SP, got {:#x}", mctx.ss.sp);
    }

    // ─── Bug #9: Dead conditional in prepost writeback ───────────────

    #[test]
    fn test_ldr_prepost_writeback_correct() {
        // LDR x2, [x0, #8]! — pre-index, should writeback x0 = x0 + 8
        let mut mctx = make_mctx();
        let data: [u64; 2] = [0xDEAD, 0xBEEF];
        let base_addr = data.as_ptr() as u64;
        mctx.ss.x[0] = base_addr;

        // LDR x2, [x0, #8]!: size=11, V=0, opc=01, imm9=8, wb=11 (pre)
        // 11_111_00_01_0_000001000_11_00000_00010 = 0xF8408C02
        let instr: u32 = 0xF8408C02;
        let result = emul_ldr_str_prepost(instr, &mut mctx);
        assert!(result, "LDR pre-index should be handled");

        assert_eq!(mctx.ss.x[2], 0xBEEF, "should load from base+8");
        assert_eq!(mctx.ss.x[0], base_addr + 8, "x0 should be updated to base+8");
    }

    // ─── Data Processing 1-source (REV, RBIT, CLZ, CLS, REV16) ─────

    #[test]
    fn test_dp1_rbit_32() {
        // RBIT w2, w0: sf=0, opcode=0, Rn=0, Rd=2
        // 0_1_0_11010110_00000_000000_00000_00010 = 0x5AC00002
        let mut mctx = make_mctx();
        mctx.ss.x[0] = 0x8000_0001;
        let instr: u32 = 0x5AC00002;
        assert!(emul_dp1_src(instr, &mut mctx));
        // RBIT(0x80000001) = 0x80000001 (bit 31 ↔ bit 0 swap, symmetric)
        assert_eq!(mctx.ss.x[2], 0x80000001, "RBIT 32-bit");
    }

    #[test]
    fn test_dp1_rbit_64() {
        // RBIT x2, x0: sf=1
        // 1_1_0_11010110_00000_000000_00000_00010 = 0xDAC00002
        let mut mctx = make_mctx();
        mctx.ss.x[0] = 1u64; // bit 0 set
        assert!(emul_dp1_src(0xDAC00002, &mut mctx));
        assert_eq!(mctx.ss.x[2], 1u64 << 63, "RBIT 64-bit: bit 0 → bit 63");
    }

    #[test]
    fn test_dp1_rev16_32() {
        // REV16 w2, w0: sf=0, opcode=1
        // 0_1_0_11010110_00000_000001_00000_00010 = 0x5AC00402
        let mut mctx = make_mctx();
        mctx.ss.x[0] = 0x1234_5678;
        assert!(emul_dp1_src(0x5AC00402, &mut mctx));
        // REV16: swap bytes in each 16-bit half: 0x1234→0x3412, 0x5678→0x7856
        assert_eq!(mctx.ss.x[2], 0x3412_7856, "REV16 32-bit");
    }

    #[test]
    fn test_dp1_rev32() {
        // REV w2, w0: sf=0, opcode=2
        // 0_1_0_11010110_00000_000010_00000_00010 = 0x5AC00802
        let mut mctx = make_mctx();
        mctx.ss.x[0] = 0x1234_5678;
        assert!(emul_dp1_src(0x5AC00802, &mut mctx));
        assert_eq!(mctx.ss.x[2], 0x7856_3412, "REV 32-bit byte swap");
    }

    #[test]
    fn test_dp1_rev64() {
        // REV x2, x0: sf=1, opcode=3
        // 1_1_0_11010110_00000_000011_00000_00010 = 0xDAC00C02
        let mut mctx = make_mctx();
        mctx.ss.x[0] = 0x0102_0304_0506_0708;
        assert!(emul_dp1_src(0xDAC00C02, &mut mctx));
        assert_eq!(mctx.ss.x[2], 0x0807_0605_0403_0201, "REV 64-bit byte swap");
    }

    #[test]
    fn test_dp1_clz_32() {
        // CLZ w2, w0: sf=0, opcode=4
        // 0_1_0_11010110_00000_000100_00000_00010 = 0x5AC01002
        let mut mctx = make_mctx();
        mctx.ss.x[0] = 0x0000_0100; // bit 8 is highest set bit → 23 leading zeros
        assert!(emul_dp1_src(0x5AC01002, &mut mctx));
        assert_eq!(mctx.ss.x[2], 23, "CLZ 32-bit");
    }

    #[test]
    fn test_dp1_cls_32_positive() {
        // CLS w2, w0: sf=0, opcode=5
        // 0_1_0_11010110_00000_000101_00000_00010 = 0x5AC01402
        let mut mctx = make_mctx();
        mctx.ss.x[0] = 0x0000_0001; // positive, 30 leading zeros after sign bit
        assert!(emul_dp1_src(0x5AC01402, &mut mctx));
        assert_eq!(mctx.ss.x[2], 30, "CLS 32-bit positive");
    }

    #[test]
    fn test_dp1_cls_32_negative() {
        let mut mctx = make_mctx();
        mctx.ss.x[0] = 0xFFFF_FFFE; // negative, 30 leading ones after sign bit
        assert!(emul_dp1_src(0x5AC01402, &mut mctx));
        assert_eq!(mctx.ss.x[2], 30, "CLS 32-bit negative");
    }

    #[test]
    fn test_dp1_cls_32_zero() {
        let mut mctx = make_mctx();
        mctx.ss.x[0] = 0; // all zeros → 31 leading sign bits
        assert!(emul_dp1_src(0x5AC01402, &mut mctx));
        assert_eq!(mctx.ss.x[2], 31, "CLS 32-bit zero");
    }

    // ─── SIMD&FP LDP/STP via x18 (apt-get install file repro) ──────────
    //
    // LDP q0, q1, [x18]  — encoding 0xAD400640.
    // Bit 26 (V) = 1, opc=10 → 128-bit Q-register pair; previously the
    // emulator wrote into GPR x0/x1, corrupting tar's stack frames inside
    // dpkg-deb. This caused "tar: This does not look like a tar archive".
    #[test]
    fn test_ldp_q_via_x18_writes_simd_regs() {
        let mut mctx = make_mctx();
        // 32 bytes (two q regs) of source data, 16-byte aligned by allocator.
        let data: [u8; 32] = [
            0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
            0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x01,
            0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,
            0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,
        ];
        let base = data.as_ptr() as u64;
        set_thread_x18(base);
        // Sentinels to verify we DO NOT touch GPRs.
        mctx.ss.x[0] = 0xDEAD_BEEF;
        mctx.ss.x[1] = 0xCAFE_F00D;
        mctx.ns.v[0] = 0;
        mctx.ns.v[1] = 0;

        // LDP q0, q1, [x18]: 0xAD400640
        let instr: u32 = 0xAD400640;
        let result = emul_ldp_stp(instr, &mut mctx);
        assert!(result, "LDP q0, q1, [x18] should be handled");

        // GPRs must be untouched.
        assert_eq!(mctx.ss.x[0], 0xDEAD_BEEF, "x0 must not be clobbered by LDP q0");
        assert_eq!(mctx.ss.x[1], 0xCAFE_F00D, "x1 must not be clobbered by LDP q1");

        // q0 = bytes 0..16 (little-endian 128-bit).
        let mut expect_q0: u128 = 0;
        for i in (0..16).rev() { expect_q0 = (expect_q0 << 8) | data[i] as u128; }
        let mut expect_q1: u128 = 0;
        for i in (0..16).rev() { expect_q1 = (expect_q1 << 8) | data[16 + i] as u128; }
        assert_eq!(mctx.ns.v[0], expect_q0, "q0 should hold first 16 bytes");
        assert_eq!(mctx.ns.v[1], expect_q1, "q1 should hold next 16 bytes");
    }

    // STP d0, d1, [x18]  — encoding 0x6D000640.
    // V=1, opc=01 → 64-bit D-register pair store.
    #[test]
    fn test_stp_d_via_x18_reads_simd_regs() {
        let mut mctx = make_mctx();
        let mut buf: [u64; 2] = [0; 2];
        let base = buf.as_mut_ptr() as u64;
        set_thread_x18(base);
        mctx.ns.v[0] = 0x1122_3344_5566_7788_u128;
        mctx.ns.v[1] = 0xAABB_CCDD_EEFF_0011_u128;

        // STP d0, d1, [x18]: opc=01,V=1,LType=10(offset),L=0,imm7=0,Rt2=1,Rn=18,Rt=0
        // 01 101 1 0 10 0 0000000 00001 10010 00000 = 0x6D000640
        let instr: u32 = 0x6D000640;
        let result = emul_ldp_stp(instr, &mut mctx);
        assert!(result, "STP d0, d1, [x18] should be handled");

        assert_eq!(buf[0], 0x1122_3344_5566_7788);
        assert_eq!(buf[1], 0xAABB_CCDD_EEFF_0011);
    }

    // ─── libzstd Huffman table round-trip (STR/LDR via x18 reg offset) ──

    #[test]
    fn test_str_ldr_x18_reg_offset_roundtrip() {
        // Reproduces the exact pattern from libzstd+0x86d90:
        //   STR x1, [x18, x2, LSL #3]    ; 0xF8227A41
        //   LDR x3, [x18, x2, LSL #3]    ; 0xF8627A43
        // x18 = table base (heap ptr), x2 = index, x1 = value
        let mut mctx = make_mctx();
        let mut table: [u64; 16] = [0xDEAD; 16];
        let table_base = table.as_mut_ptr() as u64;

        // Store 0xba09ba09ba09ba09 at table[5] via x18
        set_thread_x18(table_base);
        mctx.ss.x[1] = 0xba09_ba09_ba09_ba09;
        mctx.ss.x[2] = 5;

        // STR x1, [x18, x2, LSL #3]: size=11 V=0 opc=00 Rm=2 opt=011 S=1 Rn=18 Rt=1
        let str_instr: u32 = 0xF822_7A41;
        let result = emul_ldr_str_reg_offset(str_instr, &mut mctx);
        assert!(result, "STR x1, [x18, x2, LSL #3] should succeed");
        assert_eq!(table[5], 0xba09_ba09_ba09_ba09, "table[5] should be written");

        // Load it back via LDR x3, [x18, x2, LSL #3]
        mctx.ss.x[3] = 0xCAFE; // sentinel
        // LDR x3, [x18, x2, LSL #3]: size=11 V=0 opc=01 Rm=2 opt=011 S=1 Rn=18 Rt=3
        let ldr_instr: u32 = 0xF862_7A43;
        let result = emul_ldr_str_reg_offset(ldr_instr, &mut mctx);
        assert!(result, "LDR x3, [x18, x2, LSL #3] should succeed");
        assert_eq!(mctx.ss.x[3], 0xba09_ba09_ba09_ba09,
            "round-trip through x18 reg-offset should preserve value, got {:#x}", mctx.ss.x[3]);
    }

    #[test]
    fn test_str_ldr_x18_reg_offset_multiple_indices() {
        // Simulate a full Huffman table build loop: write entries at indices 0..8,
        // then read them all back and verify.
        let mut mctx = make_mctx();
        let mut table: [u64; 16] = [0; 16];
        let table_base = table.as_mut_ptr() as u64;
        set_thread_x18(table_base);

        let test_values: [u64; 8] = [
            0x0d09_0d09_0d09_0d09,
            0x0e09_0e09_0e09_0e09,
            0x1509_1509_1509_1509,
            0x1609_1609_1609_1609,
            0x1909_1909_1909_1909,
            0x1a09_1a09_1a09_1a09,
            0x1e09_1e09_1e09_1e09,
            0x2309_2309_2309_2309,
        ];

        // STR x1, [x18, x2, LSL #3] for each index
        let str_instr: u32 = 0xF822_7A41;
        for (i, &val) in test_values.iter().enumerate() {
            mctx.ss.x[1] = val;
            mctx.ss.x[2] = i as u64;
            assert!(emul_ldr_str_reg_offset(str_instr, &mut mctx));
        }

        // Verify memory directly
        for (i, &expected) in test_values.iter().enumerate() {
            assert_eq!(table[i], expected, "table[{}] mismatch", i);
        }

        // Read back via LDR x3, [x18, x2, LSL #3]
        let ldr_instr: u32 = 0xF862_7A43;
        for (i, &expected) in test_values.iter().enumerate() {
            mctx.ss.x[2] = i as u64;
            mctx.ss.x[3] = 0xDEAD;
            assert!(emul_ldr_str_reg_offset(ldr_instr, &mut mctx));
            assert_eq!(mctx.ss.x[3], expected,
                "LDR round-trip failed at index {}: expected {:#x}, got {:#x}",
                i, expected, mctx.ss.x[3]);
        }
    }

    // ─── Bug #10: UMULH computed lower 64 bits instead of upper 64 ─────

    #[test]
    fn test_umulh_x18_division_constant() {
        // UMULH x0, x0, x18 — the exact instruction from libzstd+0x4ef60
        // Used for integer division by constants. x18 = 0xCCCCCCCCCCCCCCCD
        // (magic constant for unsigned division by 5).
        // UMULH returns the UPPER 64 bits of a 128-bit unsigned multiply.
        let mut mctx = make_mctx();
        let magic_div5: u64 = 0xCCCC_CCCC_CCCC_CCCD;
        set_thread_x18(magic_div5);

        // Test: 254 / 5 = 50 (truncated)
        // UMULH(254, 0xCCCC...CD) should give 0xCB
        // Then 0xCB >> 2 = 50 (the quotient)
        mctx.ss.x[0] = 254;

        // UMULH x0, x0, x18: sf=1, op31=110, Rm=18, o0=0, Ra=31, Rn=0, Rd=0
        // 1_00_11011_110_10010_0_11111_00000_00000 = 0x9BD27C00
        let instr: u32 = 0x9BD2_7C00;
        let result = emul_dp3_src(instr, &mut mctx);
        assert!(result, "UMULH should be handled");

        // UMULH(254, 0xCCCCCCCCCCCCCCCD) = upper 64 of:
        // 254 * 0xCCCCCCCCCCCCCCCD = 0xCB_329B329B329B3292 (128-bit)
        // Upper 64 bits = 0xCB = 203
        let expected = ((254u128 * magic_div5 as u128) >> 64) as u64;
        assert_eq!(mctx.ss.x[0], expected,
            "UMULH(254, 0xCCCC...CD) should give {:#x}, got {:#x}",
            expected, mctx.ss.x[0]);
        assert_eq!(mctx.ss.x[0], 0xCB, "UMULH(254, div5_magic) = 0xCB");
    }

    #[test]
    fn test_smulh_x18() {
        // SMULH x0, x0, x18 — signed high multiply
        let mut mctx = make_mctx();
        set_thread_x18(0x7FFF_FFFF_FFFF_FFFF); // large positive
        mctx.ss.x[0] = 2;

        // SMULH x0, x0, x18: sf=1, op31=010, Rm=18, o0=0, Ra=31, Rn=0, Rd=0
        // 1_00_11011_010_10010_0_11111_00000_00000 = 0x9B527C00
        let instr: u32 = 0x9B52_7C00;
        let result = emul_dp3_src(instr, &mut mctx);
        assert!(result, "SMULH should be handled");

        let expected = ((2i128 * 0x7FFF_FFFF_FFFF_FFFFi128) >> 64) as u64;
        assert_eq!(mctx.ss.x[0], expected,
            "SMULH(2, 0x7FFF...F) should give {:#x}, got {:#x}",
            expected, mctx.ss.x[0]);
    }

    // ─── AdvSIMD copy (DUP/INS/SMOV/UMOV) referencing x18 ─────────────
    // Found via openssl: `ins v0.b[7], w18` panicked trap_handler
    // ("UNHANDLED EmulClass::Other") during python ssl wrap_socket.

    #[test]
    fn test_ins_general_from_w18() {
        // INS v0.b[7], w18 — the exact instruction that crashed openssl.
        // 0 Q=1 op=0 01110000 imm5=01111 0 imm4=0011 1 Rn=18 Rd=0
        let mut mctx = make_mctx();
        set_thread_x18(0xAB);
        mctx.ns.v[0] = 0x1111_2222_3333_4444_5555_6666_7777_8888;

        let instr: u32 = 0x4E0F_1E40; // ins v0.b[7], w18
        assert!(emul_simd_copy(instr, &mut mctx), "INS (general) handled");

        // byte 7 replaced with 0xAB, everything else preserved
        assert_eq!(mctx.ns.v[0], 0x1111_2222_3333_4444_AB55_6666_7777_8888);
    }

    #[test]
    fn test_dup_general_from_w18() {
        // DUP v2.4s, w18 — imm5=00100 (S), imm4=0001, Q=1
        let mut mctx = make_mctx();
        set_thread_x18(0xDEAD_BEEF_CAFE_F00D); // only low 32 bits used

        let instr: u32 = 0x4E04_0E42; // dup v2.4s, w18
        assert!(emul_simd_copy(instr, &mut mctx), "DUP (general) handled");
        assert_eq!(mctx.ns.v[2],
            0xCAFE_F00D_CAFE_F00D_CAFE_F00D_CAFE_F00D);
    }

    #[test]
    fn test_umov_to_w18() {
        // UMOV w18, v3.s[1] — imm5=01100, imm4=0111, Q=0
        let mut mctx = make_mctx();
        set_thread_x18(0);
        mctx.ns.v[3] = 0xAAAA_BBBB_CCCC_DDDD_1234_5678_9ABC_DEF0;

        let instr: u32 = 0x0E0C_3C72; // umov w18, v3.s[1]
        assert!(emul_simd_copy(instr, &mut mctx), "UMOV handled");
        assert_eq!(get_thread_x18(), 0x1234_5678, "element s[1], zero-extended");
    }

    #[test]
    fn test_smov_to_x18() {
        // SMOV x18, v1.h[2] — imm5=01010, imm4=0101, Q=1
        let mut mctx = make_mctx();
        set_thread_x18(0);
        mctx.ns.v[1] = 0x0000_8001_0000_0000u128; // h[2] (bits 47:32) = 0x8001, negative i16

        let instr: u32 = 0x4E0A_2C32; // smov x18, v1.h[2]
        assert!(emul_simd_copy(instr, &mut mctx), "SMOV handled");
        assert_eq!(get_thread_x18(), 0xFFFF_FFFF_FFFF_8001, "sign-extended");
    }

    #[test]
    fn test_ins_element_v18_source() {
        // INS v0.d[1], v18.d[0] — op=1; patcher may match Rn=18 even though
        // it's a vector reg, so the emulator must handle vector→vector too.
        // 0 1 1 01110000 imm5=11000 0 imm4(src idx)=0000 1 Rn=18 Rd=0
        let mut mctx = make_mctx();
        mctx.ns.v[18] = 0x9999_8888_7777_6666_0123_4567_89AB_CDEF;
        mctx.ns.v[0] = 0x1111_1111_1111_1111_2222_2222_2222_2222;

        let instr: u32 = 0x6E18_0640; // ins v0.d[1], v18.d[0]
        assert!(emul_simd_copy(instr, &mut mctx), "INS (element) handled");
        assert_eq!(mctx.ns.v[0], 0x0123_4567_89AB_CDEF_2222_2222_2222_2222);
    }

    #[test]
    fn test_dup_element_v18_source() {
        // DUP v1.2d, v18.d[1] — imm5=11000? no: d[1] → imm5=11000, Q=1
        // 0 1 0 01110000 imm5=11000 0 imm4=0000 1 Rn=18 Rd=1
        let mut mctx = make_mctx();
        mctx.ns.v[18] = 0xFEED_FACE_DEAD_BEEF_0000_0000_0000_0001;

        let instr: u32 = 0x4E18_0641; // dup v1.2d, v18.d[1]
        assert!(emul_simd_copy(instr, &mut mctx), "DUP (element) handled");
        assert_eq!(mctx.ns.v[1],
            0xFEED_FACE_DEAD_BEEF_FEED_FACE_DEAD_BEEF);
    }
}
