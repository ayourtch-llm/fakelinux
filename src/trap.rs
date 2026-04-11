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

// ─── Per-thread guest x18 (platform register) ───────────────────────────────
//
// On macOS/Darwin, x18 is the "platform register" reserved by the OS.
// macOS can clobber x18 during signal delivery or between sigreturn and
// guest resume. Linux code uses x18 as a regular callee-saved register.
// We save/restore x18 ourselves, similar to TPIDR virtualization.

static GUEST_X18: AtomicU64 = AtomicU64::new(0);

// Raw x18 capture: naked asm wrapper saves x18 to this global before
// any Rust/macOS code can clobber it. Single-threaded access (signal handler).
static mut RAW_X18_CAPTURE: u64 = 0;

/// Naked asm signal handler wrapper that captures x18 before calling Rust handler.
/// On macOS aarch64, the kernel and/or signal trampoline may clobber x18 before
/// our Rust handler runs. This naked function is the FIRST code to execute,
/// saving x18 to a global before anything else touches it.
#[unsafe(naked)]
unsafe extern "C" fn sigtrap_handler_wrapper(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _ctx: *mut c_void,
) {
    std::arch::naked_asm!(
        // Save x18 to RAW_X18_CAPTURE immediately
        "adrp x9, {capture}@PAGE",
        "str x18, [x9, {capture}@PAGEOFF]",
        // Tail-call the real Rust handler (same args in x0, x1, x2)
        "b {handler}",
        capture = sym RAW_X18_CAPTURE,
        handler = sym sigtrap_handler,
    );
}
static X18_KEY: AtomicU64 = AtomicU64::new(0);
static X18_KEY_INIT: AtomicBool = AtomicBool::new(false);

pub fn init_x18_key() {
    let mut key: libc::pthread_key_t = 0;
    let ret = unsafe { libc::pthread_key_create(&mut key, None) };
    if ret != 0 {
        panic!("pthread_key_create for x18 failed: {}", ret);
    }
    X18_KEY.store(key as u64, Ordering::SeqCst);
    X18_KEY_INIT.store(true, Ordering::SeqCst);
}

fn set_thread_x18(val: u64) {
    if X18_KEY_INIT.load(Ordering::SeqCst) {
        let key = X18_KEY.load(Ordering::SeqCst) as libc::pthread_key_t;
        unsafe { libc::pthread_setspecific(key, val as *const libc::c_void); }
    }
    GUEST_X18.store(val, Ordering::SeqCst);
}

fn get_thread_x18() -> u64 {
    if X18_KEY_INIT.load(Ordering::SeqCst) {
        let key = X18_KEY.load(Ordering::SeqCst) as libc::pthread_key_t;
        let val = unsafe { libc::pthread_getspecific(key) } as u64;
        if val != 0 {
            return val;
        }
    }
    GUEST_X18.load(Ordering::SeqCst)
}

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

    // x18 guest register preservation.
    // macOS clobbers x18 (platform register) both in the mcontext AND in the
    // hardware register during signal delivery. Our naked asm wrapper
    // (sigtrap_handler_wrapper) captured x18 to RAW_X18_CAPTURE as the very
    // first instruction before any clobbering. Use that value.
    let captured_x18 = RAW_X18_CAPTURE;
    if captured_x18 != 0 {
        set_thread_x18(captured_x18);
        mctx.ss.x[18] = captured_x18;
    } else {
        let saved_x18 = get_thread_x18();
        if saved_x18 != 0 {
            mctx.ss.x[18] = saved_x18;
        }
    }

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
                set_thread_x18(mctx.ss.x[18]);
                IN_SIGTRAP.store(false, Ordering::SeqCst);
                return;
            } else if orig_instr & MRS_TPIDR_MASK == MRS_TPIDR_BASE {
                // MRS Xn, tpidr_el0
                let rn = (orig_instr & 0x1F) as usize;
                let val = get_thread_tpidr();
                if val == 0 {
                    let mut buf = [0u8; 128];
                    let n = raw_fmt(&mut buf, format_args!(
                        "fakelinux: WARNING: MRS tpidr_el0 returning 0 at pc={:#x} reg=x{}\n", pc, rn));
                    unsafe { libc::write(2, buf.as_ptr() as *const _, n); }
                }
                write_reg(&mut mctx.ss, rn, val);
                mctx.ss.pc = pc + 4;
                set_thread_x18(mctx.ss.x[18]);
                IN_SIGTRAP.store(false, Ordering::SeqCst);
                return;
            }
        }

        // Not in patch table → this was a SVC #0
        let nr = mctx.ss.x[8];
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
        if val == 0 {
            let mut buf = [0u8; 128];
            let n = raw_fmt(&mut buf, format_args!(
                "fakelinux: WARNING: MRS tpidr_el0 (unpatched) returning 0 at pc={:#x} reg=x{}\n", pc, rn));
            unsafe { libc::write(2, buf.as_ptr() as *const _, n); }
        }
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

    // Save guest x18 from mcontext so we can restore it on next signal entry.
    // This captures the value the guest will resume with (after our modifications).
    set_thread_x18(mctx.ss.x[18]);

    IN_SIGTRAP.store(false, Ordering::SeqCst);

    // Deliver any signals that were deferred while we were in the SIGTRAP handler.
    // We build the sigframe directly here since we have the guest registers in mcontext.
    crate::signal::deliver_pending_to_guest(mctx);
}

/// Full signal environment re-init for child after fork().
/// Re-installs SIGTRAP handler, allocates a fresh signal alt stack, and unblocks signals.
pub fn init_child_after_fork() {
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

        // Re-install SIGTRAP handler
        install_sigtrap_handler();

        // Unblock all signals
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());

        // Reset IN_SIGTRAP (should already be false, but be safe)
        IN_SIGTRAP.store(false, Ordering::SeqCst);
    }
}

/// Re-install the SIGTRAP handler. Called after fork() in child processes.
pub fn install_sigtrap_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigtrap_handler_wrapper as *const () as libc::sighandler_t;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGTRAP, &sa, std::ptr::null_mut()) != 0 {
            let msg = "fakelinux: sigaction(SIGTRAP) failed\n";
            libc::write(2, msg.as_ptr() as *const _, msg.len());
            libc::_exit(127);
        }
    }
}

/// Get the handler function pointer (for use in forked children).
pub fn sigtrap_handler_ptr() -> libc::sighandler_t {
    sigtrap_handler_wrapper as *const () as libc::sighandler_t
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
        install_sigtrap_handler();

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
