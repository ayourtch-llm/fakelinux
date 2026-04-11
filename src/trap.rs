use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::syscall;

/// Flag indicating we're inside the SIGTRAP handler. When set, other signal
/// handlers (signal_forwarder) must defer delivery by queuing to pending,
/// because the ucontext contains SIGTRAP handler registers, not guest registers.
pub static IN_SIGTRAP: AtomicBool = AtomicBool::new(false);

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
    if !TPIDR_KEY_INIT.load(Ordering::SeqCst) {
        // Fallback to global before key is initialized
        GUEST_TPIDR.store(val, Ordering::SeqCst);
        return;
    }
    let key = TPIDR_KEY.load(Ordering::SeqCst) as libc::pthread_key_t;
    // Store val+1 so we can distinguish "not set" (NULL=0) from "set to 0"
    // Actually, just use the raw value; 0 is unlikely for TPIDR.
    // We also store a marker in a second key to know if it was set.
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

unsafe extern "C" fn sigtrap_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    ctx: *mut c_void,
) {
    IN_SIGTRAP.store(true, Ordering::SeqCst);

    let uctx = &mut *(ctx as *mut UContext);
    let mctx = &mut *uctx.uc_mcontext;
    let pc = mctx.ss.pc;
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
                let val = read_reg(&mctx.ss, rn);
                set_thread_tpidr(val);
                mctx.ss.pc = pc + 4;
                IN_SIGTRAP.store(false, Ordering::SeqCst);
                return;
            } else if orig_instr & MRS_TPIDR_MASK == MRS_TPIDR_BASE {
                // MRS Xn, tpidr_el0
                let rn = (orig_instr & 0x1F) as usize;
                let val = get_thread_tpidr();
                write_reg(&mut mctx.ss, rn, val);
                mctx.ss.pc = pc + 4;
                IN_SIGTRAP.store(false, Ordering::SeqCst);
                return;
            }
        }

        // Not in patch table → this was a SVC #0
        let nr = mctx.ss.x[8];
        let args = [
            mctx.ss.x[0], mctx.ss.x[1], mctx.ss.x[2], mctx.ss.x[3], mctx.ss.x[4], mctx.ss.x[5],
        ];

        // For fork (clone without CLONE_VM), save guest registers so the
        // forked child can jump directly to guest code without sigreturn.
        use crate::linux::SYS_CLONE;
        if nr == SYS_CLONE && args[0] & 0x100 == 0 {
            crate::thread::save_fork_regs(&mctx.ss, pc + 4);
        }

        let result = syscall::emulate(nr, &args, mctx);

        // Check if fork was requested — redirect sigreturn to trampoline
        if crate::thread::FORK_PENDING.swap(false, Ordering::SeqCst) {
            // Save the guest's return PC (after the clone SVC)
            let guest_resume_pc = pc + 4;
            crate::thread::save_fork_regs(&mctx.ss, guest_resume_pc);
            // Redirect sigreturn to the fork trampoline
            mctx.ss.pc = crate::thread::fork_trampoline_addr();
            // Clear signal mask so SIGTRAP is unblocked after sigreturn
            uctx.uc_sigmask = 0;
        } else if result == crate::signal::SIGRETURN_SENTINEL {
            // rt_sigreturn: registers were already restored directly into mctx.
            // Don't overwrite x0 or pc.
        } else {
            mctx.ss.x[0] = result as u64;
            mctx.ss.pc = pc + 4;
        }
    } else if instr & MSR_TPIDR_MASK == MSR_TPIDR_BASE {
        // MSR tpidr_el0, Xn — guest is writing to TPIDR_EL0
        // macOS clobbers TPIDR_EL0 on signal return, so we save the value
        // and serve it via intercepted MRS instructions.
        let rn = (instr & 0x1F) as usize;
        let val = read_reg(&mctx.ss, rn);
        set_thread_tpidr(val);
        mctx.ss.pc = pc + 4;
    } else if instr & MRS_TPIDR_MASK == MRS_TPIDR_BASE {
        // MRS Xn, tpidr_el0 — guest is reading TPIDR_EL0
        // Return our saved value instead of the macOS-clobbered one.
        let rn = (instr & 0x1F) as usize;
        let val = get_thread_tpidr();
        write_reg(&mut mctx.ss, rn, val);
        mctx.ss.pc = pc + 4;
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

    IN_SIGTRAP.store(false, Ordering::SeqCst);

    // Deliver any signals that were deferred while we were in the SIGTRAP handler.
    // We build the sigframe directly here since we have the guest registers in mcontext.
    crate::signal::deliver_pending_to_guest(mctx);
}

/// Get the handler function pointer (for use in forked children).
pub fn sigtrap_handler_ptr() -> libc::sighandler_t {
    sigtrap_handler as *const () as libc::sighandler_t
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

        // Install SIGTRAP handler FIRST (before unblocking — if SIGTRAP is
        // pending, unblocking would fire it with SIG_DFL=terminate!)
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigtrap_handler as *const () as libc::sighandler_t;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGTRAP, &sa, std::ptr::null_mut()) != 0 {
            panic!("sigaction(SIGTRAP) failed");
        }

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
