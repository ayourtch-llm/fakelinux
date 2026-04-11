use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::syscall;

/// Format into a stack buffer using raw write — no Mutex, safe after fork.
fn raw_fmt(buf: &mut [u8], args: std::fmt::Arguments) -> usize {
    use std::io::Write;
    let mut cursor = std::io::Cursor::new(&mut buf[..]);
    let _ = cursor.write_fmt(args);
    cursor.position() as usize
}

/// The BRK instruction we patch in place of SVC #0.
pub const BRK_MARKER: u32 = 0xD43E_0000;

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
pub static GUEST_TPIDR: AtomicU64 = AtomicU64::new(0);

pub fn get_guest_tpidr() -> u64 {
    GUEST_TPIDR.load(Ordering::SeqCst)
}

// macOS aarch64 mcontext structures

#[repr(C)]
struct ExceptionState64 {
    far: u64,
    esr: u32,
    exception: u32,
}

#[repr(C)]
pub struct ThreadState64 {
    pub x: [u64; 29],
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u32,
    _pad: u32,
}

#[repr(C)]
struct MContext64 {
    es: ExceptionState64,
    ss: ThreadState64,
}

#[repr(C)]
struct UContext {
    uc_onstack: i32,
    uc_sigmask: u32,
    uc_stack: libc::stack_t,
    uc_link: *mut UContext,
    uc_mcsize: usize,
    uc_mcontext: *mut MContext64,
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

unsafe extern "C" fn sigtrap_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    ctx: *mut c_void,
) {
    let uctx = &mut *(ctx as *mut UContext);
    let mctx = &mut *uctx.uc_mcontext;
    let regs = &mut mctx.ss;
    let pc = regs.pc;
    let instr = *(pc as *const u32);

    // For BRK_MARKER, check if this was originally a TPIDR access or a SVC
    if instr == BRK_MARKER {
        // Look up the original instruction in the patch table
        let orig = crate::loader::tpidr_lookup(pc);

        if let Some(orig_instr) = orig {
            // This was a patched MSR/MRS tpidr_el0
            if orig_instr & MSR_TPIDR_MASK == MSR_TPIDR_BASE {
                // MSR tpidr_el0, Xn
                let rn = (orig_instr & 0x1F) as usize;
                let val = read_reg(regs, rn);
                GUEST_TPIDR.store(val, Ordering::SeqCst);
                regs.pc = pc + 4;
                return;
            } else if orig_instr & MRS_TPIDR_MASK == MRS_TPIDR_BASE {
                // MRS Xn, tpidr_el0
                let rn = (orig_instr & 0x1F) as usize;
                let val = GUEST_TPIDR.load(Ordering::SeqCst);
                write_reg(regs, rn, val);
                regs.pc = pc + 4;
                return;
            }
        }

        // Not in patch table → this was a SVC #0
        let nr = regs.x[8];
        let args = [
            regs.x[0], regs.x[1], regs.x[2], regs.x[3], regs.x[4], regs.x[5],
        ];

        // For fork (clone without CLONE_VM), save guest registers so the
        // forked child can jump directly to guest code without sigreturn.
        use crate::linux::SYS_CLONE;
        if nr == SYS_CLONE && args[0] & 0x100 == 0 {
            crate::thread::save_fork_regs(regs, pc + 4);
        }

        let result = syscall::emulate(nr, &args, regs);
        regs.x[0] = result as u64;
        regs.pc = pc + 4;
    } else if instr & MSR_TPIDR_MASK == MSR_TPIDR_BASE {
        // MSR tpidr_el0, Xn — guest is writing to TPIDR_EL0
        // macOS clobbers TPIDR_EL0 on signal return, so we save the value
        // and serve it via intercepted MRS instructions.
        let rn = (instr & 0x1F) as usize;
        let val = read_reg(regs, rn);
        GUEST_TPIDR.store(val, Ordering::SeqCst);
        regs.pc = pc + 4;
    } else if instr & MRS_TPIDR_MASK == MRS_TPIDR_BASE {
        // MRS Xn, tpidr_el0 — guest is reading TPIDR_EL0
        // Return our saved value instead of the macOS-clobbered one.
        let rn = (instr & 0x1F) as usize;
        let val = GUEST_TPIDR.load(Ordering::SeqCst);
        write_reg(regs, rn, val);
        regs.pc = pc + 4;
    } else if instr & 0xFFE0_001F == 0xD420_0000 {
        // BRK #N — could be guest's own trap or macOS internal trap (e.g. after fork)
        let brk_imm = (instr >> 5) & 0xFFFF;
        if pc < 0x500000000 {
            // BRK in macOS code (e.g. post-fork child runtime assertion) — exit silently
            libc::_exit(128 + libc::SIGTRAP);
        }
        // Use raw write — safe after fork (no Rust Mutex)
        let mut buf = [0u8; 80];
        let n = raw_fmt(&mut buf, format_args!("fakelinux: guest BRK #{:#x} at pc={:#x}\n", brk_imm, pc));
        libc::write(2, buf.as_ptr() as *const _, n);
        libc::_exit(128 + libc::SIGTRAP);
    } else {
        let mut buf = [0u8; 80];
        let n = raw_fmt(&mut buf, format_args!("fakelinux: unexpected SIGTRAP at pc={:#x} instr={:#010x}\n", pc, instr));
        libc::write(2, buf.as_ptr() as *const _, n);
        libc::_exit(128 + libc::SIGTRAP);
    }
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

        // Install SIGTRAP handler with SA_SIGINFO
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigtrap_handler as *const () as libc::sighandler_t;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGTRAP, &sa, std::ptr::null_mut()) != 0 {
            panic!("sigaction(SIGTRAP) failed");
        }

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
    let guest_tpidr = GUEST_TPIDR.load(Ordering::SeqCst);
    let signame = if sig == libc::SIGSEGV { "SIGSEGV" } else { "SIGBUS" };
    let mut buf = [0u8; 256];
    let n = raw_fmt(&mut buf, format_args!(
        "\nfakelinux: {} at pc={:#x} fault_addr={:#x}\n  x0={:#x}  x1={:#x}  x2={:#x}  x3={:#x}\n  x8={:#x}  sp={:#x}  lr={:#x}  guest_tpidr={:#x}\n",
        signame, regs.pc, fault_addr,
        regs.x[0], regs.x[1], regs.x[2], regs.x[3],
        regs.x[8], regs.sp, regs.lr, guest_tpidr
    ));
    libc::write(2, buf.as_ptr() as *const _, n);
    libc::_exit(128 + sig);
}
