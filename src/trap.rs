use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::syscall;

/// Flag indicating we're inside our trap handler. When set, other signal
/// handlers (signal_forwarder) must defer delivery by queuing to pending,
/// because the ucontext contains trap handler registers, not guest registers.
pub static IN_TRAP: AtomicBool = AtomicBool::new(false);

/// Debug counter: trace first N SVC syscalls in a fork child.
pub static FORK_SVC_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Debug counter: trace first N UDF traps (SVC+MRS/MSR) in a fork child.
/// Gives a complete picture of every intercepted instruction.
pub static FORK_TRAP_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Diagnostic: the x18 instruction currently being emulated (for crash dumps).
static mut CURRENT_X18_INSTR: u32 = 0;
static mut CURRENT_X18_PC: u64 = 0;

/// Format into a stack buffer using raw write — no Mutex, safe after fork.
fn raw_fmt(buf: &mut [u8], args: std::fmt::Arguments) -> usize {
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

/// Initialize the pthread key for per-thread TPIDR. Call once before loading the ELF.
pub fn init_tpidr_key() {
    let mut key: libc::pthread_key_t = 0;
    let ret = unsafe { libc::pthread_key_create(&mut key, None) };
    if ret != 0 {
        panic!("pthread_key_create for TPIDR failed: {}", ret);
    }
    TPIDR_KEY.store(key as u64, Ordering::SeqCst);
    TPIDR_KEY_INIT.store(true, Ordering::SeqCst);
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

/// Initialize the pthread key for per-thread x18. Call once at startup.
pub fn init_x18_key() {
    let mut key: libc::pthread_key_t = 0;
    let ret = unsafe { libc::pthread_key_create(&mut key, None) };
    if ret != 0 {
        panic!("pthread_key_create for x18 failed: {}", ret);
    }
    X18_KEY.store(key as u64, Ordering::SeqCst);
    X18_KEY_INIT.store(true, Ordering::SeqCst);
}

/// Set the per-thread guest x18 value.
pub fn set_thread_x18(val: u64) {
    if !X18_KEY_INIT.load(Ordering::SeqCst) {
        return;
    }
    let key = X18_KEY.load(Ordering::SeqCst) as libc::pthread_key_t;
    unsafe { libc::pthread_setspecific(key, val as *const libc::c_void); }
}

/// Get the per-thread guest x18 value.
pub fn get_thread_x18() -> u64 {
    if !X18_KEY_INIT.load(Ordering::SeqCst) {
        return 0;
    }
    let key = X18_KEY.load(Ordering::SeqCst) as libc::pthread_key_t;
    (unsafe { libc::pthread_getspecific(key) }) as u64
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
    if n == 31 { regs.sp = val; }
    else if n == 18 { set_thread_x18(val); }
    else { write_reg(regs, n, val); }
}

/// Write a GPR value, storing x18 to per-thread storage instead of mcontext.
fn write_gpr(regs: &mut ThreadState64, n: usize, val: u64) {
    if n == 18 {
        set_thread_x18(val);
    } else {
        write_reg(regs, n, val);
    }
}

pub fn references_x18(instr: u32) -> bool {
    use disarm64_defn::defn::InsnOpcode;
    use disarm64_defn::{InsnBitField, InsnOperandClass};

    // Don't check our own UDF marker or SVC
    if instr == UDF_MARKER || instr == SVC_0 { return false; }
    // Don't check TPIDR instructions (handled separately)
    if instr & MSR_TPIDR_MASK == MSR_TPIDR_BASE
        || instr & MRS_TPIDR_MASK == MRS_TPIDR_BASE { return false; }

    // Early SIMD exclusion: scalar and vector SIMD instructions use Vn/Dn registers,
    // not GPRs. Must check BEFORE disarm64 which may misclassify SIMD Rn as INT_REG.
    let top_byte = (instr >> 24) & 0xFF;
    let is_simd_scalar_or_vec = matches!(top_byte & 0x9F, 0x0E | 0x0F)
        || matches!(top_byte, 0x0e | 0x2e | 0x4e | 0x6e | 0x0f | 0x2f | 0x4f | 0x6f
                            | 0x5e | 0x7e | 0x5f | 0x7f | 0x1e | 0x1f);
    if is_simd_scalar_or_vec { return false; }

    let Some(decoded) = disarm64::decoder::decode(instr) else { return false; };
    let defn = decoded.definition();
    let bits = decoded.bits();

    for operand in defn.operands {
        // Check all bit_fields that represent GPR register numbers
        for bf in operand.bit_fields {
            match bf.bitfield {
                InsnBitField::Rd | InsnBitField::Rn | InsnBitField::Rm
                | InsnBitField::Rt | InsnBitField::Rt2 | InsnBitField::Ra
                | InsnBitField::Rs => {
                    let reg_no = (bits >> bf.lsb) & ((1u32 << bf.width) - 1);
                    // Only count as x18 if the operand is a GPR (not SIMD/FP/SVE)
                    match operand.class {
                        InsnOperandClass::INT_REG | InsnOperandClass::MODIFIED_REG
                        | InsnOperandClass::ADDRESS => {
                            if reg_no == 18 { return true; }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        // MODIFIED_REG (Rm_SFT) sometimes has no bit_fields but Rm is at bits[20:16]
        // Only for non-SIMD instructions (top byte 0x0e/0x4e/0x2e/0x6e are SIMD)
        if operand.class == InsnOperandClass::MODIFIED_REG && operand.bit_fields.is_empty() {
            let top = (instr >> 24) & 0xFF;
            let is_simd = matches!(top, 0x0e | 0x2e | 0x4e | 0x6e | 0x0f | 0x2f | 0x4f | 0x6f);
            if !is_simd {
                let rm = (bits >> 16) & 0x1F;
                if rm == 18 { return true; }
            }
        }
    }

    // Fallback: manual check for load/store instruction forms where disarm64
    // doesn't expose GPR register fields with the right operand class.
    // In AArch64 load/store encodings, Rn (base, bits[9:5]) and Rm (index,
    // bits[20:16]) are ALWAYS GPRs even for SIMD/FP loads.
    //
    // Single-register load/store: bits[28:27]=11 (LDST single)
    // Load/store pair:            bits[28:27]=01 (LDP/STP) — bits[20:15] are imm7, NOT Rm!
    // Exclude SIMD/FP instructions (top nibble 0x0/0x2/0x4/0x6 with bit25=1 are AdvSIMD)
    let top_byte = (instr >> 24) & 0xFF;
    let is_simd_fp = matches!(top_byte & 0x9F, 0x0E | 0x0F)  // AdvSIMD data processing
        || matches!(top_byte, 0x0e | 0x2e | 0x4e | 0x6e | 0x0f | 0x2f | 0x4f | 0x6f
                            | 0x5e | 0x7e | 0x5f | 0x7f);  // AdvSIMD scalar
    if is_simd_fp { return false; }

    let bits28_27 = (instr >> 27) & 3;
    let is_ldst_single = bits28_27 == 3; // bits[28:27]=11
    let is_ldst_pair = bits28_27 == 1;   // bits[28:27]=01 (LDP/STP)
    if is_ldst_single || is_ldst_pair {
        // Rn (base register, bits[9:5]) is always a GPR
        let rn = (instr >> 5) & 0x1F;
        if rn == 18 { return true; }
    }
    // For single-register load/store with register offset:
    // bits[28:27]=11, bit[24]=0, bit[21]=1 → Rm at bits[20:16]
    if is_ldst_single && (instr >> 24) & 1 == 0 && (instr >> 21) & 1 == 1 {
        let rm = (instr >> 16) & 0x1F;
        if rm == 18 { return true; }
    }

    false
}

/// Emulate an instruction that references x18, substituting per-thread x18 storage.
/// Returns true if emulation succeeded.
fn emulate_x18_instruction(orig_instr: u32, mctx: &mut MContext64) -> bool {
    let instr_pc = mctx.ss.pc; // save before borrowing mctx.ss
    let regs = &mut mctx.ss;

    // ─── Data processing (immediate) ─────────────────────────────────
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

    // MOV wide (MOVZ/MOVK/MOVN): sf_opc_100101_hw_imm16_Rd
    if orig_instr & 0x1F80_0000 == 0x1280_0000 ||  // MOVN
       orig_instr & 0x1F80_0000 == 0x1480_0000 ||  // reserved (skip)
       orig_instr & 0x1F80_0000 == 0x1500_0000 ||  // reserved
       orig_instr & 0x1F80_0000 == 0x1280_0000 {   // (duplicate, simplify below)
        // fall through to generic check
    }
    // MOVZ: x_10_100101_hw_imm16_Rd
    if orig_instr & 0x7F80_0000 == 0x5280_0000 || orig_instr & 0x7F80_0000 == 0x5200_0000 {
        // This is getting complex, let me handle move-wide generically
    }
    // Generic move-wide: bits[28:23] = 100101
    if (orig_instr >> 23) & 0x3F == 0b100101 {
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

    // Logical immediate: sf_opc_100100_N_immr_imms_Rn_Rd
    if (orig_instr >> 23) & 0x3F == 0b100100 {
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
                // ANDS — update NZ, clear CV
                let bits = if sf == 1 { 64 } else { 32 };
                let n = (result >> (bits - 1)) & 1;
                let z = if result == 0 { 1 } else { 0 };
                regs.cpsr = (regs.cpsr & 0x0FFF_FFFF) | ((n as u32) << 31) | ((z as u32) << 30);
            }
            if rd != 31 { write_gpr(regs, rd, result); }
            return true;
        }
        return false; // bad bitmask encoding
    }

    // ─── Data processing (register) ──────────────────────────────────
    // Logical shifted register: sf_opc_01010_shift_0_Rm_imm6_Rn_Rd
    if orig_instr & 0x1F00_0000 == 0x0A00_0000 {
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

    // Add/sub shifted register: sf_op_S_01011_shift_0_Rm_imm6_Rn_Rd
    if orig_instr & 0x1F20_0000 == 0x0B00_0000 {
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

    // Add/sub extended register: sf_op_S_01011_00_1_Rm_option_imm3_Rn_Rd
    if orig_instr & 0x1FE0_0000 == 0x0B20_0000 {
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

    // Add/subtract with carry: sf_op_S_11010000_Rm_000000_Rn_Rd
    // ADC (op=0,S=0), ADCS (op=0,S=1), SBC (op=1,S=0), SBCS (op=1,S=1)
    if orig_instr & 0x1FE0_FC00 == 0x1A00_0000 {
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
            update_nzcv(regs, a, b, result, op == 1, sf == 1);
        }
        if rd != 31 { write_gpr(regs, rd, result); }
        return true;
    }

    // Conditional select: sf_op_S_11010100_Rm_cond_op2_Rn_Rd
    if orig_instr & 0x1FE0_0000 == 0x1A80_0000 {
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

    // Data processing (2 source): sf_0_S_11010110_Rm_opcode_Rn_Rd
    // Common: UDIV, SDIV, LSLV, LSRV, ASRV, RORV
    if orig_instr & 0x5FE0_0000 == 0x1AC0_0000 {
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
            11 => a.rotate_right((b % bits as u64) as u32),  // RORV
            _ => return false,
        };
        let result = if sf == 0 { result & 0xFFFF_FFFF } else { result };
        if rd != 31 { write_gpr(regs, rd, result); }
        return true;
    }

    // Data processing (3 source): sf_op54_11011_op31_Rm_o0_Ra_Rn_Rd
    // MADD, MSUB
    if (orig_instr >> 24) & 0x1F == 0b11011 {
        let sf = (orig_instr >> 31) & 1;
        let rm = ((orig_instr >> 16) & 0x1F) as usize;
        let o0 = (orig_instr >> 15) & 1;
        let ra = ((orig_instr >> 10) & 0x1F) as usize;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rd = (orig_instr & 0x1F) as usize;
        let a = read_gpr(regs, rn);
        let b = read_gpr(regs, rm);
        let c = if ra == 31 { 0 } else { read_gpr(regs, ra) };
        let product = a.wrapping_mul(b);
        let result = if o0 == 0 { c.wrapping_add(product) } else { c.wrapping_sub(product) };
        let result = if sf == 0 { result & 0xFFFF_FFFF } else { result };
        if rd != 31 { write_gpr(regs, rd, result); }
        return true;
    }

    // ─── Load/Store ──────────────────────────────────────────────────

    // LDR/STR (immediate, unsigned offset): size_11_V_01_01_imm12_Rn_Rt
    if orig_instr & 0x3B00_0000 == 0x3900_0000 {
        let size = (orig_instr >> 30) & 0x3;
        let v_bit = (orig_instr >> 26) & 1;
        let is_load = (orig_instr >> 22) & 1;
        let imm12 = ((orig_instr >> 10) & 0xFFF) as u64;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rt = (orig_instr & 0x1F) as usize;
        let scale = if v_bit == 1 {
            let opc1 = (orig_instr >> 23) & 1;
            if size == 0 && opc1 == 1 { 4u32 } else { size }
        } else { size };
        let offset = imm12 << scale;
        let base = read_gpr_sp(regs, rn);
        let addr = base.wrapping_add(offset);
        if v_bit == 1 {
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
            if is_load == 1 {
                let val = unsafe { load_mem(addr, size) };
                if rt != 31 { write_gpr(regs, rt, val); }
            } else {
                let val = read_gpr(regs, rt);
                unsafe { store_mem(addr, size, val); }
            }
        }
        return true;
    }

    // LDUR/STUR (unscaled immediate): size_11_1_00_0x_0_imm9_00_Rn_Rt
    // This is the same as pre/post-index but bits[11:10]=00 means unscaled, no writeback.
    if orig_instr & 0x3B20_0C00 == 0x3800_0000 {
        let size = (orig_instr >> 30) & 0x3;
        let is_load = (orig_instr >> 22) & 1;
        let imm9 = ((orig_instr >> 12) & 0x1FF) as u64;
        let imm9 = sign_extend(imm9, 9);
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rt = (orig_instr & 0x1F) as usize;
        let base = read_gpr_sp(regs, rn);
        let addr = base.wrapping_add(imm9);
        if is_load == 1 {
            let val = unsafe { load_mem(addr, size) };
            if rt != 31 { write_gpr(regs, rt, val); }
        } else {
            let val = read_gpr(regs, rt);
            unsafe { store_mem(addr, size, val); }
        }
        return true;
    }

    // LDR/STR (pre/post-index): size_11_1_00_0x_0_imm9_wb_Rn_Rt
    // wb: 01=post-index, 11=pre-index
    if orig_instr & 0x3B20_0400 == 0x3800_0400 {
        let size = (orig_instr >> 30) & 0x3;
        let is_load = (orig_instr >> 22) & 1;
        let imm9 = ((orig_instr >> 12) & 0x1FF) as u64;
        let imm9 = sign_extend(imm9, 9);
        let wb = (orig_instr >> 10) & 0x3;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rt = (orig_instr & 0x1F) as usize;
        let base = read_gpr_sp(regs, rn);
        let addr = if wb == 0b11 { base.wrapping_add(imm9) } else { base }; // pre vs post
        if is_load == 1 {
            let val = unsafe { load_mem(addr, size) };
            if rt != 31 { write_gpr(regs, rt, val); }
        } else {
            let val = read_gpr(regs, rt);
            unsafe { store_mem(addr, size, val); }
        }
        let new_base = if wb == 0b11 { base.wrapping_add(imm9) } else { base.wrapping_add(imm9) };
        write_gpr_sp(regs, rn, new_base);
        return true;
    }

    // LDR/STR (register offset): size_11_V_00_0x_1_Rm_option_S_10_Rn_Rt
    if orig_instr & 0x3B20_0C00 == 0x3820_0800 {
        let size = (orig_instr >> 30) & 0x3;
        let v_bit = (orig_instr >> 26) & 1; // V=1 means SIMD/FP Rt
        let is_load = (orig_instr >> 22) & 1;
        let rm = ((orig_instr >> 16) & 0x1F) as usize;
        let option = (orig_instr >> 13) & 0x7;
        let s_bit = (orig_instr >> 12) & 1;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rt = (orig_instr & 0x1F) as usize;
        let offset_val = read_gpr(regs, rm);
        let scale = if v_bit == 1 {
            // SIMD/FP: size+opc[1] determines scale (0=8,1=16,2=32,3=64,0+opc1=128)
            let opc1 = (orig_instr >> 23) & 1;
            if size == 0 && opc1 == 1 { 4u32 } else { size }
        } else { size };
        let offset_val = extend_reg(offset_val, option, if s_bit == 1 { scale } else { 0 });
        let base = read_gpr_sp(regs, rn);
        let addr = base.wrapping_add(offset_val);
        if v_bit == 1 {
            // SIMD/FP: access mctx.ns.v[rt] directly
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
            if is_load == 1 {
                let val = unsafe { load_mem(addr, size) };
                if rt != 31 { write_gpr(regs, rt, val); }
            } else {
                let val = read_gpr(regs, rt);
                unsafe { store_mem(addr, size, val); }
            }
        }
        return true;
    }

    // LDP/STP (signed offset, pre/post-index):
    // opc_10_1_x_0xx_imm7_Rt2_Rn_Rt
    if orig_instr & 0x3A00_0000 == 0x2800_0000 {
        let opc = (orig_instr >> 30) & 0x3;
        let is_load = (orig_instr >> 22) & 1;
        let wb_type = (orig_instr >> 23) & 0x3; // 01=post, 10=offset, 11=pre
        let imm7 = ((orig_instr >> 15) & 0x7F) as u64;
        let rt2 = ((orig_instr >> 10) & 0x1F) as usize;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rt = (orig_instr & 0x1F) as usize;
        // opc=00: STP/LDP W (32-bit), opc=01: LDPSW (32-bit, sign-extend), opc=10: STP/LDP X (64-bit)
        let scale = if opc <= 1 { 2u64 } else { 3 };
        let is_signed = opc == 1; // LDPSW: load 32-bit, sign-extend to 64-bit
        let offset = sign_extend(imm7, 7) << scale;
        let base = read_gpr_sp(regs, rn);
        let addr = if wb_type == 0b11 || wb_type == 0b10 {
            base.wrapping_add(offset)
        } else {
            base // post-index: use base first
        };
        let elem_size = 1u64 << scale;
        if is_load == 1 {
            let mut v1 = unsafe { load_mem(addr, scale as u32) };
            let mut v2 = unsafe { load_mem(addr.wrapping_add(elem_size), scale as u32) };
            if is_signed {
                v1 = v1 as i32 as i64 as u64;
                v2 = v2 as i32 as i64 as u64;
            }
            if rt != 31 { write_gpr(regs, rt, v1); }
            if rt2 != 31 { write_gpr(regs, rt2, v2); }
        } else {
            let v1 = read_gpr(regs, rt);
            let v2 = read_gpr(regs, rt2);
            unsafe { store_mem(addr, scale as u32, v1); }
            unsafe { store_mem(addr.wrapping_add(elem_size), scale as u32, v2); }
        }
        // Writeback
        if wb_type == 0b01 || wb_type == 0b11 {
            let new_base = if wb_type == 0b01 {
                base.wrapping_add(offset) // post-index
            } else {
                base.wrapping_add(offset) // pre-index (same addr)
            };
            write_gpr_sp(regs, rn, new_base);
        }
        return true;
    }

    // LDRSW (immediate, unsigned offset): 10_111_00_110_imm12_Rn_Rt
    if orig_instr & 0xFFC0_0000 == 0xB980_0000 {
        let imm12 = ((orig_instr >> 10) & 0xFFF) as u64;
        let rn = ((orig_instr >> 5) & 0x1F) as usize;
        let rt = (orig_instr & 0x1F) as usize;
        let offset = imm12 << 2;
        let base = read_gpr_sp(regs, rn);
        let addr = base.wrapping_add(offset);
        let val = unsafe { *(addr as *const i32) as i64 as u64 };
        if rt != 31 { write_gpr(regs, rt, val); }
        return true;
    }

    // LDRB/LDRH/LDRSB/LDRSH unsigned offset are covered by the generic LDR handler above
    // (size field distinguishes byte/half/word/doubleword)

    // ─── Bitfield (SBFM/UBFM/BFM — includes LSL, LSR, ASR, SXTW, etc.) ──
    // ARM encoding: sf opc(2) 100110 N immr(6) imms(6) Rn(5) Rd(5)
    // Fixed bits [28:24] = 10011, bit 23 = 0 for 32-bit (sf=0), 1 for 64-bit (sf=1)
    // We check bits [28:24] = 10011
    if (orig_instr >> 24) & 0x1F == 0b10011 {
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

    // ─── ADR/ADRP ───────────────────────────────────────────────────
    // ADR:  0_immlo_10000_immhi_Rd
    // ADRP: 1_immlo_10000_immhi_Rd
    if orig_instr & 0x1F00_0000 == 0x1000_0000 {
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

    // ─── CBZ/CBNZ ────────────────────────────────────────────────────
    // sf_011010_op_imm19_Rt  (op: 0=CBZ, 1=CBNZ)
    if orig_instr & 0x7E00_0000 == 0x3400_0000 {
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

    // ─── CCMP/CCMN (register) ───────────────────────────────────���───
    // ─── TBZ/TBNZ ────────────────────────────────────────────────────
    // b5_011011_op_b40_imm14_Rt  (op: 0=TBZ, 1=TBNZ)
    if orig_instr & 0x7E00_0000 == 0x3600_0000 {
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

    // ─── CCMP/CCMN (register) ───────────────────────────────────────
    // sf_op_S_11010010_Rm_cond_0_o2_Rn_o3_nzcv  (S=1, bit11=0=reg, o2=0, o3=0)
    if orig_instr & 0x3FE0_0C10 == 0x3A40_0000 {
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

    // ─── CCMP/CCMN (immediate) ──────────────────────────────────────
    // sf_op_S_11010010_imm5_cond_1_o2_Rn_o3_nzcv  (S=1, bit11=1=imm)
    if orig_instr & 0x3FE0_0C10 == 0x3A40_0800 {
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

    // ─── FMOV (GPR ↔ FP) ───────────────────────────────────────────
    // FMOV Xd, Dn: 1_00_11110_01_1_00_110_000000_Rn_Rd (0x9E660000)
    // FMOV Dn, Xn: 1_00_11110_01_1_00_111_000000_Rn_Rd (0x9E670000)
    // FMOV Wd, Sn: 0_00_11110_00_1_00_110_000000_Rn_Rd (0x1E260000)
    // FMOV Sn, Wn: 0_00_11110_00_1_00_111_000000_Rn_Rd (0x1E270000)
    if orig_instr & 0x7FBF_FC00 == 0x1E26_0000 || orig_instr & 0x7FBF_FC00 == 0x1E27_0000 {
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

    // ─── Unhandled ───────────────────────────────────────────────────
    false
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
        3 => val.rotate_right(amount),               // ROR
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
        1 => *(addr as *const u16) as u64,
        2 => *(addr as *const u32) as u64,
        3 => *(addr as *const u64),
        _ => 0,
    }
}

unsafe fn store_mem(addr: u64, size: u32, val: u64) {
    match size {
        0 => *(addr as *mut u8) = val as u8,
        1 => *(addr as *mut u16) = val as u16,
        2 => *(addr as *mut u32) = val as u32,
        3 => *(addr as *mut u64) = val,
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

    // For UDF_MARKER, check if this was originally a TPIDR access or a SVC
    if instr == UDF_MARKER {
        // Look up the original instruction in the patch table
        let orig = crate::loader::tpidr_lookup(pc);

        if let Some(orig_instr) = orig {
            // This was a patched MSR/MRS tpidr_el0
            if orig_instr & MSR_TPIDR_MASK == MSR_TPIDR_BASE {
                // MSR tpidr_el0, Xn
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
                        "fakelinux: [{}] FORK_TRAP#{} MSR pc={:#x} x{}={:#x} x0={:#x} x19={:#x}\n",
                        pid, 50 - tcnt, pc, rn, val, mctx.ss.x[0], mctx.ss.x[19]
                    ));
                    libc::write(2, buf.as_ptr() as *const _, n);
                }
                IN_TRAP.store(false, Ordering::SeqCst);
                return;
            } else if orig_instr & MRS_TPIDR_MASK == MRS_TPIDR_BASE {
                // MRS Xn, tpidr_el0
                let rn = (orig_instr & 0x1F) as usize;
                let val = get_thread_tpidr();
                write_gpr(&mut mctx.ss, rn, val);
                mctx.ss.pc = pc + 4;
                // FORK_TRAP logging for MRS
                let tcnt = FORK_TRAP_COUNT.load(Ordering::Relaxed);
                if tcnt > 0 {
                    FORK_TRAP_COUNT.store(tcnt - 1, Ordering::Relaxed);
                    let pid = libc::getpid();
                    let mut buf = [0u8; 160];
                    let n = raw_fmt(&mut buf, format_args!(
                        "fakelinux: [{}] FORK_TRAP#{} MRS pc={:#x} x{}={:#x} x0={:#x} x19={:#x}\n",
                        pid, 50 - tcnt, pc, rn, val, mctx.ss.x[0], mctx.ss.x[19]
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

                // Save emulating instruction for crash diagnostics
                unsafe { CURRENT_X18_INSTR = orig_instr; CURRENT_X18_PC = pc; }
                if emulate_x18_instruction(orig_instr, mctx) {
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
                    if seq < 200 && std::env::var("FAKELINUX_TRACE_X18").is_ok() {
                        let mut buf = [0u8; 128];
                        let n = raw_fmt(&mut buf, format_args!(
                            "x18[{}] pc={:#x} instr={:#010x} x18={:#x}\n",
                            seq, pc, orig_instr, get_thread_x18()
                        ));
                        libc::write(2, buf.as_ptr() as *const _, n);
                    }
                    // Only advance PC if the emulator didn't set it (e.g. CBZ/CBNZ set PC directly)
                    if mctx.ss.pc == pc { mctx.ss.pc = pc + 4; }
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

        // FORK_TRAP logging for SVC
        {
            let tcnt = FORK_TRAP_COUNT.load(Ordering::Relaxed);
            if tcnt > 0 {
                FORK_TRAP_COUNT.store(tcnt - 1, Ordering::Relaxed);
                let pid = libc::getpid();
                let mut buf = [0u8; 160];
                let n = raw_fmt(&mut buf, format_args!(
                    "fakelinux: [{}] FORK_TRAP#{} SVC pc={:#x} nr={} x0={:#x} x19={:#x} lr={:#x}\n",
                    pid, 50 - tcnt, pc, nr, mctx.ss.x[0], mctx.ss.x[19], mctx.ss.lr
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
            if asm_x0 != -1 {
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

    IN_TRAP.store(false, Ordering::SeqCst);

    // Deliver any signals that were deferred while we were in the trap handler.
    // We build the sigframe directly here since we have the guest registers in mcontext.
    crate::signal::deliver_pending_to_guest(mctx);
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
        libc::sigemptyset(&mut sa.sa_mask);
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

        // Install SIGSEGV/SIGBUS handlers for debugging guest crashes
        let mut sa2: libc::sigaction = std::mem::zeroed();
        sa2.sa_sigaction = crash_handler as *const () as libc::sighandler_t;
        sa2.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigemptyset(&mut sa2.sa_mask);
        libc::sigaction(libc::SIGSEGV, &sa2, std::ptr::null_mut());
        libc::sigaction(libc::SIGBUS, &sa2, std::ptr::null_mut());
    }
}

unsafe extern "C" fn crash_handler(
    sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    ctx: *mut c_void,
) {
    // Use raw write() — safe after fork (no Rust Mutex deadlock)
    let uctx = &*(ctx as *const UContext);
    let mctx = &*uctx.uc_mcontext;
    let regs = &mctx.ss;
    let fault_addr = mctx.es.far;
    let guest_tpidr = get_thread_tpidr();
    let signame = if sig == libc::SIGSEGV { "SIGSEGV" } else { "SIGBUS" };
    // Try to read the instruction at PC
    let instr_at_pc = if regs.pc > 0x1000 {
        *(regs.pc as *const u32)
    } else { 0 };
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
}
