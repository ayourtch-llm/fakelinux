//! Linux <-> macOS signal number translation and guest signal forwarding.
//!
//! Linux and macOS share signal numbers 1-15 mostly, but diverge above that.
//! We maintain a table of guest signal handlers and install macOS signal handlers
//! that forward to the guest by building a Linux rt_sigframe on the guest stack.

use std::sync::atomic::{AtomicU64, Ordering};

/// Address of the sigreturn trampoline (executable page with mov x8,#139; brk #0xf000).
static SIGRETURN_TRAMPOLINE: AtomicU64 = AtomicU64::new(0);

// Guest sigaltstack state (per-thread via thread_local)
use std::cell::Cell;
thread_local! {
    static GUEST_ALTSTACK_SP: Cell<u64> = const { Cell::new(0) };
    static GUEST_ALTSTACK_FLAGS: Cell<i32> = const { Cell::new(2) }; // SS_DISABLE
    static GUEST_ALTSTACK_SIZE: Cell<u64> = const { Cell::new(0) };
}

pub fn get_guest_sigaltstack() -> (u64, i32, u64) {
    GUEST_ALTSTACK_SP.with(|sp| {
        GUEST_ALTSTACK_FLAGS.with(|flags| {
            GUEST_ALTSTACK_SIZE.with(|size| {
                (sp.get(), flags.get(), size.get())
            })
        })
    })
}

pub fn set_guest_sigaltstack(sp: u64, flags: i32, size: u64) {
    GUEST_ALTSTACK_SP.with(|s| s.set(sp));
    GUEST_ALTSTACK_FLAGS.with(|f| f.set(flags));
    GUEST_ALTSTACK_SIZE.with(|s| s.set(size));
}

/// Guest signal handler entry.
#[derive(Clone, Copy)]
pub struct GuestSigaction {
    pub handler: u64, // SA_HANDLER or SA_SIGACTION function pointer (guest address)
    pub flags: u64,   // Linux sa_flags
    pub restorer: u64, // sa_restorer (unused on aarch64)
    pub mask: u64,    // sa_mask (simplified to a single u64)
}

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;

/// Lock-free sigaction table. Each signal (1..64) has 4 atomic u64 fields.
/// This is async-signal-safe: signal_forwarder can read without a mutex.
struct AtomicSigaction {
    handler: AtomicU64,
    flags: AtomicU64,
    restorer: AtomicU64,
    mask: AtomicU64,
}

impl AtomicSigaction {
    const fn new() -> Self {
        Self {
            handler: AtomicU64::new(SIG_DFL),
            flags: AtomicU64::new(0),
            restorer: AtomicU64::new(0),
            mask: AtomicU64::new(0),
        }
    }

    fn load(&self) -> GuestSigaction {
        GuestSigaction {
            handler: self.handler.load(Ordering::SeqCst),
            flags: self.flags.load(Ordering::SeqCst),
            restorer: self.restorer.load(Ordering::SeqCst),
            mask: self.mask.load(Ordering::SeqCst),
        }
    }

    fn store(&self, sa: &GuestSigaction) {
        // Store handler last so readers see consistent flags/mask first
        self.flags.store(sa.flags, Ordering::SeqCst);
        self.restorer.store(sa.restorer, Ordering::SeqCst);
        self.mask.store(sa.mask, Ordering::SeqCst);
        self.handler.store(sa.handler, Ordering::SeqCst);
    }
}

// Macro to generate a const array since AtomicU64 isn't Copy
macro_rules! atomic_sigaction_array {
    ($n:expr) => {{
        // SAFETY: AtomicU64::new(0) is all-zeros, same as zeroed memory
        const INIT: AtomicSigaction = AtomicSigaction::new();
        [INIT; $n]
    }};
}

/// Lock-free table of guest signal handlers indexed by Linux signal number (1..64).
static GUEST_SIGACTIONS: [AtomicSigaction; 65] = atomic_sigaction_array!(65);

/// Get the guest's registered handler for a given Linux signal number.
pub fn guest_sigaction(linux_sig: usize) -> GuestSigaction {
    GUEST_SIGACTIONS[linux_sig].load()
}

/// Guest signal mask (bitmask of blocked signals, bit N = Linux signal N).
pub static GUEST_SIGMASK: AtomicU64 = AtomicU64::new(0);

/// Pending signals (bitmask, bit N = Linux signal N is pending but was blocked).
pub static PENDING_SIGNALS: AtomicU64 = AtomicU64::new(0);

/// Reset signal state for a child process after fork().
/// POSIX: child's pending signal set must be empty.
/// Signal dispositions and mask are inherited (correct via COW).
pub fn reset_after_fork() {
    PENDING_SIGNALS.store(0, Ordering::SeqCst);
}

/// Sentinel return value from emulate() meaning "rt_sigreturn restored all regs, don't touch x0/pc".
pub const SIGRETURN_SENTINEL: u64 = 0xFFFF_FFFF_DEAD_5167;

// ---- Signal number translation ----

/// Translate Linux signal number -> macOS signal number.
pub fn linux_to_mac(linux_sig: i32) -> Option<i32> {
    match linux_sig {
        1 => Some(libc::SIGHUP),
        2 => Some(libc::SIGINT),
        3 => Some(libc::SIGQUIT),
        4 => Some(libc::SIGILL),
        5 => Some(libc::SIGTRAP),
        6 => Some(libc::SIGABRT),
        7 => Some(libc::SIGBUS),   // Linux SIGBUS=7, macOS SIGBUS=10
        8 => Some(libc::SIGFPE),
        9 => Some(libc::SIGKILL),
        10 => Some(libc::SIGUSR1), // Linux SIGUSR1=10, macOS SIGUSR1=30
        11 => Some(libc::SIGSEGV),
        12 => Some(libc::SIGUSR2), // Linux SIGUSR2=12, macOS SIGUSR2=31
        13 => Some(libc::SIGPIPE),
        14 => Some(libc::SIGALRM),
        15 => Some(libc::SIGTERM),
        17 => Some(libc::SIGCHLD), // Linux SIGCHLD=17, macOS SIGCHLD=20
        18 => Some(libc::SIGCONT), // Linux SIGCONT=18, macOS SIGCONT=19
        19 => Some(libc::SIGSTOP), // Linux SIGSTOP=19, macOS SIGSTOP=17
        20 => Some(libc::SIGTSTP), // Linux SIGTSTP=20, macOS SIGTSTP=18
        21 => Some(libc::SIGTTIN),
        22 => Some(libc::SIGTTOU),
        23 => Some(libc::SIGURG),  // Linux SIGURG=23, macOS SIGURG=16
        24 => Some(libc::SIGXCPU),
        25 => Some(libc::SIGXFSZ),
        26 => Some(libc::SIGVTALRM),
        27 => Some(libc::SIGPROF),
        28 => Some(libc::SIGWINCH),
        29 => Some(libc::SIGIO),   // Linux SIGIO=29, macOS SIGIO=23
        31 => Some(libc::SIGSYS),  // Linux SIGSYS=31, macOS SIGSYS=12
        _ => None,
    }
}

/// Translate macOS signal number -> Linux signal number.
pub fn mac_to_linux(mac_sig: i32) -> i32 {
    match mac_sig {
        1..=6 => mac_sig,
        10 => 7,   // macOS SIGBUS=10 -> Linux SIGBUS=7
        8 => 8,
        9 => 9,
        30 => 10,  // macOS SIGUSR1=30 -> Linux SIGUSR1=10
        11 => 11,
        31 => 12,  // macOS SIGUSR2=31 -> Linux SIGUSR2=12
        13..=15 => mac_sig,
        20 => 17,  // macOS SIGCHLD=20 -> Linux SIGCHLD=17
        19 => 18,  // macOS SIGCONT=19 -> Linux SIGCONT=18
        17 => 19,  // macOS SIGSTOP=17 -> Linux SIGSTOP=19
        18 => 20,  // macOS SIGTSTP=18 -> Linux SIGTSTP=20
        21..=22 => mac_sig,
        16 => 23,  // macOS SIGURG=16 -> Linux SIGURG=23
        24..=28 => mac_sig,
        23 => 29,  // macOS SIGIO=23 -> Linux SIGIO=29
        12 => 31,  // macOS SIGSYS=12 -> Linux SIGSYS=31
        _ => mac_sig,
    }
}

// ---- rt_sigframe layout ----
//
// This is pushed onto the guest stack when delivering a signal.
// Layout (from low address to high):
//   offset 0:   trampoline[0] = mov x8, #139  (0xD2801168)
//   offset 4:   trampoline[1] = brk #0xF000   (0xD43E0000)
//   offset 8:   saved_x[0..29]  (29 * 8 = 232 bytes)
//   offset 240: saved_fp
//   offset 248: saved_lr
//   offset 256: saved_sp
//   offset 264: saved_pc
//   offset 272: saved_cpsr (u32)
//   offset 276: _pad (u32)
//   offset 280: saved_tpidr
//   offset 288: saved_sigmask
//   offset 296: saved_neon[0..31] (32 * 16 = 512 bytes, q0-q31)
//   total = 808, rounded up to 816 for 16-byte alignment

// NEON/FP save area: 32 x 128-bit (16 bytes) = 512 bytes, starts at offset 296
// Total = 296 + 512 = 808, rounded up to 816 for 16-byte alignment
const NEON_SAVE_OFFSET: usize = 296;
const RT_SIGFRAME_SIZE: usize = 816; // (296 + 512) rounded up to 16-byte alignment

/// Build a Linux rt_sigframe on the guest stack and redirect execution to the
/// guest signal handler. Called from signal_forwarder (macOS signal context).
///
/// `mctx` is the macOS mcontext (guest registers + NEON state at point of interruption).
/// `linux_sig` is the Linux signal number.
/// `handler` is the guest handler address.
/// `handler_mask` is the sa_mask from the guest sigaction.
pub unsafe fn build_sigframe_and_redirect(
    mctx: &mut crate::trap::MContext64,
    linux_sig: i32,
    handler: u64,
    handler_mask: u64,
) {
    let regs = &mut mctx.ss;
    let guest_sp = regs.sp;
    let guest_tpidr = crate::trap::get_thread_tpidr();
    let old_sigmask = GUEST_SIGMASK.load(Ordering::SeqCst);

    // Allocate frame on guest stack (stack grows down)
    let frame_addr = (guest_sp - RT_SIGFRAME_SIZE as u64) & !0xF; // 16-byte align

    let p = frame_addr as *mut u8;

    // Write trampoline: mov x8, #139; brk #0xf000
    (p.add(0) as *mut u32).write_unaligned(0xD280_1168); // mov x8, #139
    (p.add(4) as *mut u32).write_unaligned(0xD43E_0000); // brk #0xf000

    // Save x0..x28. For x18, save the GUEST x18 (per-thread TSD), not the
    // hardware register: macOS reserves hw x18 (the kernel zeroes it), so the
    // guest's x18 lives in TSD. Without this, a handler that uses x18 as a
    // scratch register would clobber the interrupted code's x18 — the TSD
    // value is not otherwise restored at sigreturn.
    for i in 0..29usize {
        let val = if i == 18 { crate::trap::get_thread_x18() } else { regs.x[i] };
        (p.add(8 + i * 8) as *mut u64).write_unaligned(val);
    }
    // Save fp, lr, sp, pc
    (p.add(240) as *mut u64).write_unaligned(regs.fp);
    (p.add(248) as *mut u64).write_unaligned(regs.lr);
    (p.add(256) as *mut u64).write_unaligned(regs.sp);
    (p.add(264) as *mut u64).write_unaligned(regs.pc);
    // Save cpsr
    (p.add(272) as *mut u32).write_unaligned(regs.cpsr);
    // pad
    (p.add(276) as *mut u32).write_unaligned(0);
    // Save tpidr
    (p.add(280) as *mut u64).write_unaligned(guest_tpidr);
    // Save sigmask
    (p.add(288) as *mut u64).write_unaligned(old_sigmask);

    // Save NEON/FP registers q0-q31 from the mcontext (not from current CPU regs,
    // which may have been clobbered by Rust code in the signal/trap handler).
    let neon_dst = p.add(NEON_SAVE_OFFSET) as *mut u128;
    for i in 0..32 {
        neon_dst.add(i).write_unaligned(mctx.ns.v[i]);
    }

    // Block signals in handler_mask | (1 << linux_sig) during handler execution
    // Linux kernel convention: bit (sig-1) represents signal sig
    let block_mask = handler_mask | (1u64 << (linux_sig - 1) as u64);
    GUEST_SIGMASK.fetch_or(block_mask, Ordering::SeqCst);

    // Get the executable sigreturn trampoline address
    let trampoline_addr = SIGRETURN_TRAMPOLINE.load(Ordering::SeqCst);

    // Redirect guest execution to the handler
    regs.sp = frame_addr;
    regs.pc = handler;
    regs.x[0] = linux_sig as u64;        // x0 = signal number
    regs.lr = trampoline_addr;            // LR points to executable sigreturn trampoline
    // x1 and x2 would be siginfo_t* and ucontext_t* for SA_SIGINFO handlers,
    // but we pass 0 for now (simple signal handler ABI).
    regs.x[1] = 0;
    regs.x[2] = 0;
}

/// Restore guest state from an rt_sigframe on the stack. Called during rt_sigreturn.
/// Returns true on success.
pub unsafe fn do_rt_sigreturn(mctx: &mut crate::trap::MContext64) -> bool {
    let regs = &mut mctx.ss;
    let frame_addr = regs.sp;
    let p = frame_addr as *const u8;

    // Verify trampoline signature (sanity check)
    let t0 = (p.add(0) as *const u32).read_unaligned();
    let t1 = (p.add(4) as *const u32).read_unaligned();

    if t0 != 0xD280_1168 || t1 != 0xD43E_0000 {
        // Not a valid sigframe -- could be a bug. Log and return false.
        let msg = "fakelinux: rt_sigreturn: invalid sigframe trampoline\n";
        libc::write(2, msg.as_ptr() as *const _, msg.len());
        return false;
    }

    // Restore x0..x28. x18 goes back to the per-thread TSD slot (guest x18),
    // undoing any clobbering by the handler's own x18 usage.
    for i in 0..29usize {
        let val = (p.add(8 + i * 8) as *const u64).read_unaligned();
        if i == 18 {
            crate::trap::set_thread_x18(val);
        }
        regs.x[i] = val;
    }
    // Restore fp, lr, sp, pc
    regs.fp = (p.add(240) as *const u64).read_unaligned();
    regs.lr = (p.add(248) as *const u64).read_unaligned();
    regs.sp = (p.add(256) as *const u64).read_unaligned();
    regs.pc = (p.add(264) as *const u64).read_unaligned();
    // Restore cpsr
    regs.cpsr = (p.add(272) as *const u32).read_unaligned();
    // Restore tpidr
    let saved_tpidr = (p.add(280) as *const u64).read_unaligned();
    crate::trap::set_thread_tpidr(saved_tpidr);
    // Restore sigmask
    let saved_mask = (p.add(288) as *const u64).read_unaligned();
    GUEST_SIGMASK.store(saved_mask, Ordering::SeqCst);

    // Restore NEON/FP registers q0-q31 into the mcontext.
    // When the signal handler returns, macOS restores these from the mcontext.
    let neon_src = p.add(NEON_SAVE_OFFSET) as *const u128;
    for i in 0..32 {
        mctx.ns.v[i] = neon_src.add(i).read_unaligned();
    }

    true
}

/// Create the sigreturn trampoline: an executable page containing
/// `mov x8, #139; brk #0xf000`. Called once during init.
pub fn create_sigreturn_trampoline() {
    let page_size: usize = 16384;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        panic!("failed to allocate sigreturn trampoline page");
    }
    unsafe {
        let p = ptr as *mut u32;
        p.add(0).write(0xD280_1168); // mov x8, #139
        p.add(1).write(0x0000_F000); // udf #0xf000 (triggers SIGILL → trap_handler)
        libc::mprotect(ptr, page_size, libc::PROT_READ | libc::PROT_EXEC);
        extern "C" {
            fn sys_icache_invalidate(start: *mut libc::c_void, size: usize);
        }
        sys_icache_invalidate(ptr, page_size);
    }
    SIGRETURN_TRAMPOLINE.store(ptr as u64, Ordering::SeqCst);
}

// ---- macOS signal forwarding handler ----

/// The single forwarding handler installed for all guest-handled signals.
/// When macOS delivers a signal that the guest registered a handler for,
/// this function builds a sigframe and redirects guest execution.
unsafe extern "C" fn signal_forwarder(
    sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    ctx: *mut libc::c_void,
) {
    // Translate macOS signal to Linux signal
    let linux_sig = mac_to_linux(sig);

    // If we're inside the trap handler, the ucontext has the handler's
    // native registers, NOT the guest's. We must defer delivery.
    if crate::trap::IN_TRAP.load(Ordering::SeqCst) {
        if linux_sig > 0 && linux_sig <= 64 {
            PENDING_SIGNALS.fetch_or(1u64 << (linux_sig - 1) as u64, Ordering::SeqCst);
        }
        return;
    }

    // Look up the guest handler (lock-free atomic read — async-signal-safe)
    let sa = GUEST_SIGACTIONS[linux_sig as usize].load();
    let handler = sa.handler;
    let handler_mask = sa.mask;

    // If no custom handler, skip (shouldn't happen but be safe)
    if handler == SIG_DFL || handler == SIG_IGN {
        return;
    }

    // Check if this signal is blocked in the guest signal mask
    let mask = GUEST_SIGMASK.load(Ordering::SeqCst);
    if linux_sig > 0 && linux_sig <= 64 && (mask & (1u64 << (linux_sig - 1) as u64)) != 0 {
        // Signal is blocked -- add to pending set for later delivery.
        PENDING_SIGNALS.fetch_or(1u64 << (linux_sig - 1) as u64, Ordering::SeqCst);
        return;
    }

    // Get the macOS ucontext -> mcontext (contains guest GPRs + NEON state)
    let uctx = &mut *(ctx as *mut crate::trap::UContext);
    let mctx = &mut *uctx.uc_mcontext;

    build_sigframe_and_redirect(mctx, linux_sig, handler, handler_mask);
}

// ---- Guest syscall handlers ----

/// Handle the guest's rt_sigaction syscall.
pub fn do_rt_sigaction(linux_sig: u64, act_ptr: u64, oldact_ptr: u64, _sigsetsize: u64) -> u64 {
    let sig = linux_sig as usize;
    if sig == 0 || sig >= 65 {
        return (-22_i64) as u64; // -EINVAL
    }

    // Don't let the guest override our SIGILL handler (we use UDF as trap instruction)
    if sig == 4 {
        if oldact_ptr != 0 {
            write_guest_sigaction(
                oldact_ptr,
                &GuestSigaction { handler: SIG_DFL, flags: 0, restorer: 0, mask: 0 },
            );
        }
        return 0;
    }

    // Return old action (lock-free atomic read)
    if oldact_ptr != 0 {
        let old = GUEST_SIGACTIONS[sig].load();
        write_guest_sigaction(oldact_ptr, &old);
    }

    // Install new action (lock-free atomic store)
    if act_ptr != 0 {
        let new_act = read_guest_sigaction(act_ptr);
        if crate::syscall::trace_enabled() {
            let handler_name = match new_act.handler {
                0 => "SIG_DFL".to_string(),
                1 => "SIG_IGN".to_string(),
                h => format!("{:#x}", h),
            };
            let pid = unsafe { libc::getpid() };
            crate::syscall::raw_eprintln_fmt(format_args!(
                "fakelinux: [{}] rt_sigaction(sig={}, handler={})\n", pid, sig, handler_name));
        }
        GUEST_SIGACTIONS[sig].store(&new_act);

        // Install a macOS signal handler if the guest wants a custom handler
        if let Some(mac_sig) = linux_to_mac(sig as i32) {
            install_forwarder(mac_sig, new_act.handler);
        }
    }

    0
}

/// Handle rt_sigprocmask: SIG_BLOCK=0, SIG_UNBLOCK=1, SIG_SETMASK=2.
pub fn do_rt_sigprocmask(how: u64, set_ptr: u64, oldset_ptr: u64, _sigsetsize: u64) -> u64 {
    let old_mask = GUEST_SIGMASK.load(Ordering::SeqCst);

    // Return old mask
    if oldset_ptr != 0 {
        unsafe {
            (oldset_ptr as *mut u64).write_unaligned(old_mask);
        }
    }

    if set_ptr != 0 {
        let new_set = unsafe { (set_ptr as *const u64).read_unaligned() };

        // Never allow blocking SIGKILL (9) or SIGSTOP (19) — bit (sig-1)
        let protected = (1u64 << 8) | (1u64 << 18);

        match how {
            0 => {
                // SIG_BLOCK: add signals
                GUEST_SIGMASK.fetch_or(new_set & !protected, Ordering::SeqCst);
            }
            1 => {
                // SIG_UNBLOCK: remove signals
                GUEST_SIGMASK.fetch_and(!new_set, Ordering::SeqCst);
            }
            2 => {
                // SIG_SETMASK: replace
                GUEST_SIGMASK.store(new_set & !protected, Ordering::SeqCst);
            }
            _ => return (-22_i64) as u64, // -EINVAL
        }

        // Deliver any pending signals that are now unblocked.
        // We re-send them via kill() so macOS delivers them after the current
        // signal handler returns, and our signal_forwarder builds the sigframe.
        deliver_pending_signals();
    }

    0
}

/// Deliver pending signals directly by building sigframes on the guest stack.
/// Called from the trap handler after clearing IN_TRAP, when we have
/// the guest's registers in the mcontext.
pub unsafe fn deliver_pending_to_guest(mctx: &mut crate::trap::MContext64) {
    let current_mask = GUEST_SIGMASK.load(Ordering::SeqCst);
    let pending = PENDING_SIGNALS.load(Ordering::SeqCst);
    let deliverable = pending & !current_mask;
    if deliverable == 0 {
        return;
    }

    // Deliver the first pending signal (one at a time; nested signals
    // will be delivered on subsequent sigreturn)
    for sig in 1..=64i32 {
        if deliverable & (1u64 << (sig - 1) as u64) != 0 {
            // Clear this signal from pending
            PENDING_SIGNALS.fetch_and(!(1u64 << (sig - 1) as u64), Ordering::SeqCst);

            // Look up guest handler (lock-free atomic read)
            let sa = GUEST_SIGACTIONS[sig as usize].load();
            let (handler, handler_mask) = (sa.handler, sa.mask);

            if handler != SIG_DFL && handler != SIG_IGN {
                build_sigframe_and_redirect(mctx, sig, handler, handler_mask);
            }
            break; // deliver one at a time
        }
    }
}

/// Check for pending signals that are no longer blocked and re-deliver them.
pub fn deliver_pending_signals() {
    let current_mask = GUEST_SIGMASK.load(Ordering::SeqCst);
    let pending = PENDING_SIGNALS.load(Ordering::SeqCst);

    // Find signals that are pending AND no longer blocked
    let deliverable = pending & !current_mask;
    if deliverable == 0 {
        return;
    }

    // Clear the deliverable signals from pending
    PENDING_SIGNALS.fetch_and(!deliverable, Ordering::SeqCst);

    // Re-send each deliverable signal via kill() so macOS will deliver it
    let pid = unsafe { libc::getpid() };
    for sig in 1..=64i32 {
        if deliverable & (1u64 << (sig - 1) as u64) != 0 {
            if let Some(mac_sig) = linux_to_mac(sig) {
                unsafe {
                    libc::kill(pid, mac_sig);
                }
            }
        }
    }
}

/// Handle kill(pid, sig) syscall. Translates Linux signal to macOS.
pub fn do_kill(pid: i64, linux_sig: i32) -> u64 {
    if linux_sig == 0 {
        // Signal 0 = check if process exists
        let ret = unsafe { libc::kill(pid as i32, 0) };
        if ret < 0 {
            return crate::translate::linux_errno();
        }
        return 0;
    }

    let mac_sig = match linux_to_mac(linux_sig) {
        Some(s) => s,
        None => return (-22_i64) as u64, // -EINVAL
    };

    if crate::syscall::trace_enabled() {
        crate::syscall::raw_eprintln_fmt(format_args!(
            "fakelinux: kill(real_pid={}, mac_sig={}) from pid={}\n",
            pid, mac_sig, unsafe { libc::getpid() }));
    }
    let ret = unsafe { libc::kill(pid as i32, mac_sig) };
    if crate::syscall::trace_enabled() {
        crate::syscall::raw_eprintln_fmt(format_args!(
            "fakelinux: kill result={}\n", ret));
    }
    if ret < 0 {
        crate::translate::linux_errno()
    } else {
        0
    }
}

/// Handle tkill(tid, sig) syscall. Translates Linux signal to macOS.
pub fn do_tkill(tid: i32, linux_sig: i32) -> u64 {
    // For single-threaded, tkill is essentially kill
    do_kill(tid as i64, linux_sig)
}

/// Handle tgkill(tgid, tid, sig) syscall. Translates Linux signal to macOS.
pub fn do_tgkill(tgid: i32, _tid: i32, linux_sig: i32) -> u64 {
    if linux_sig == 6 {
        // SIGABRT
        let msg = "fakelinux: guest called abort (tgkill SIGABRT)\n";
        unsafe {
            libc::write(2, msg.as_ptr() as *const _, msg.len());
            libc::_exit(134);
        }
    }
    do_kill(tgid as i64, linux_sig)
}

// ---- Internal helpers ----

// Linux aarch64 struct sigaction layout:
//   offset 0: u64 sa_handler
//   offset 8: u64 sa_flags
//   offset 16: u64 sa_restorer (unused on aarch64, but present)
//   offset 24: u64 sa_mask[0] (we only handle the first word)

fn read_guest_sigaction(ptr: u64) -> GuestSigaction {
    unsafe {
        let p = ptr as *const u64;
        GuestSigaction {
            handler: p.read_unaligned(),
            flags: p.add(1).read_unaligned(),
            restorer: p.add(2).read_unaligned(),
            mask: p.add(3).read_unaligned(),
        }
    }
}

fn write_guest_sigaction(ptr: u64, act: &GuestSigaction) {
    unsafe {
        let p = ptr as *mut u64;
        p.write_unaligned(act.handler);
        p.add(1).write_unaligned(act.flags);
        p.add(2).write_unaligned(act.restorer);
        p.add(3).write_unaligned(act.mask);
    }
}

fn install_forwarder(mac_sig: i32, handler: u64) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        if handler == SIG_DFL {
            sa.sa_sigaction = libc::SIG_DFL;
        } else if handler == SIG_IGN {
            sa.sa_sigaction = libc::SIG_IGN;
        } else {
            // Install our signal_forwarder which will build a sigframe
            // and redirect guest execution to the guest handler.
            sa.sa_sigaction = signal_forwarder as *const () as libc::sighandler_t;
            sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(mac_sig, &sa, std::ptr::null_mut());
            return;
        }
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(mac_sig, &sa, std::ptr::null_mut());
    }
}
