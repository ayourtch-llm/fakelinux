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

// ─── ppoll/pselect temporary sigmask swap ───────────────────────────────────
//
// Linux ppoll installs the caller's sigmask atomically for the duration of
// the wait. If a handler fires as the syscall returns, the handler's sigframe
// must restore the ORIGINAL (pre-ppoll) mask, not the temp one — the kernel
// does this via TIF_RESTORE_SIGMASK. We emulate with an override consumed by
// build_sigframe_and_redirect().

/// Original mask to restore after a ppoll-style temp swap (see above).
static SWAP_RESTORE_MASK: AtomicU64 = AtomicU64::new(0);
static SWAP_RESTORE_ACTIVE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Pure core: pending signals that are unblocked under `mask` AND have a
/// real guest handler — the set that must interrupt a ppoll with EINTR.
/// (Pending DFL/IGN signals never invoke a handler, so they must not EINTR.)
pub fn deliverable_set(pending: u64, mask: u64, handler_bits: u64) -> u64 {
    pending & !mask & handler_bits
}

/// Bitmask of signals with a real guest handler installed (not DFL/IGN).
fn handler_bits() -> u64 {
    let mut bits = 0u64;
    for sig in 1..=64usize {
        let sa = GUEST_SIGACTIONS[sig].load();
        if sa.handler != SIG_DFL && sa.handler != SIG_IGN {
            bits |= 1u64 << (sig - 1);
        }
    }
    bits
}

/// Pending signals deliverable under the CURRENT guest mask.
pub fn deliverable_pending() -> u64 {
    deliverable_set(
        PENDING_SIGNALS.load(Ordering::SeqCst),
        GUEST_SIGMASK.load(Ordering::SeqCst),
        handler_bits(),
    )
}

/// Unblock all host signals for the duration of a blocking wait emulated
/// inside the SIGILL trap handler (whose sa_mask blocks everything — a
/// signal arriving mid-wait could otherwise never reach the forwarder to be
/// queued as pending). Restores the previous host mask on drop.
pub struct HostSigUnblock {
    saved: libc::sigset_t,
}

impl HostSigUnblock {
    pub fn new() -> Self {
        let mut empty: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut saved: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut empty);
            libc::pthread_sigmask(libc::SIG_SETMASK, &empty, &mut saved);
        }
        Self { saved }
    }
}

impl Drop for HostSigUnblock {
    fn drop(&mut self) {
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.saved, std::ptr::null_mut());
        }
    }
}

/// Install a temporary guest sigmask for the duration of a ppoll/pselect
/// wait. Returns the previous mask (pass it to ppoll_mask_end).
pub fn ppoll_mask_begin(new_mask: u64) -> u64 {
    // Never allow blocking SIGKILL (9) or SIGSTOP (19) — bit (sig-1)
    let protected = (1u64 << 8) | (1u64 << 18);
    GUEST_SIGMASK.swap(new_mask & !protected, Ordering::SeqCst)
}

/// Undo a ppoll_mask_begin. If a deliverable signal is pending, the handler
/// will be invoked at trap exit while the temp mask is still in effect — arm
/// the sigframe override so its sigreturn restores the ORIGINAL mask.
/// Otherwise restore the original mask immediately.
pub fn ppoll_mask_end(old_mask: u64) {
    if deliverable_pending() != 0 {
        SWAP_RESTORE_MASK.store(old_mask, Ordering::SeqCst);
        SWAP_RESTORE_ACTIVE.store(true, Ordering::SeqCst);
    } else {
        SWAP_RESTORE_ACTIVE.store(false, Ordering::SeqCst);
        GUEST_SIGMASK.store(old_mask, Ordering::SeqCst);
    }
}

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
// SA_SIGINFO data appended after the restore area (sigreturn never reads it):
//   offset 816:  Linux siginfo_t (128 bytes) — si_signo@0, si_errno@4,
//                si_code@8, union@16 (si_addr / si_pid+si_uid)
//   offset 944:  Linux aarch64 ucontext_t prefix (480 bytes):
//                uc_flags@0, uc_link@8, uc_stack@16, uc_sigmask@40,
//                uc_mcontext@176: fault_address@+0, regs[31]@+8, sp@+256,
//                pc@+264, pstate@+272, then zeroed __reserved terminator
//                (magic=0,size=0 = "no FP records").
// Guest handlers receive x1/x2 pointing here (VPP's unix_signal_handler
// dereferences si->si_addr and uc->uc_mcontext.pc unconditionally).
const SIGINFO_OFFSET: usize = 816;
const UCONTEXT_OFFSET: usize = 944;
const UCONTEXT_MCONTEXT: usize = 176; // offsetof(ucontext_t, uc_mcontext) on aarch64
const RT_SIGFRAME_SIZE: usize = UCONTEXT_OFFSET + 480;

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
    fault_addr: u64,
    si_code: i32,
) {
    let regs = &mut mctx.ss;
    let guest_sp = regs.sp;
    let guest_tpidr = crate::trap::get_thread_tpidr();
    // If a ppoll-style temp mask swap is in flight, the sigframe must restore
    // the ORIGINAL (pre-ppoll) mask — Linux TIF_RESTORE_SIGMASK semantics.
    let old_sigmask = if SWAP_RESTORE_ACTIVE.swap(false, Ordering::SeqCst) {
        SWAP_RESTORE_MASK.load(Ordering::SeqCst)
    } else {
        GUEST_SIGMASK.load(Ordering::SeqCst)
    };

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

    // ---- SA_SIGINFO data: Linux siginfo_t + ucontext_t ----
    // Guest handlers (VPP's unix_signal_handler) dereference these
    // unconditionally; x1=x2=0 turned every forwarded signal into a NULL
    // deref INSIDE the handler → SIGSEGV → forward → infinite signal storm.
    let si = p.add(SIGINFO_OFFSET);
    std::ptr::write_bytes(si, 0, 128);
    (si as *mut i32).write_unaligned(linux_sig); // si_signo
    (si.add(8) as *mut i32).write_unaligned(si_code); // si_code
    (si.add(16) as *mut u64).write_unaligned(fault_addr); // si_addr (union)

    let uc = p.add(UCONTEXT_OFFSET);
    std::ptr::write_bytes(uc, 0, RT_SIGFRAME_SIZE - UCONTEXT_OFFSET);
    (uc.add(40) as *mut u64).write_unaligned(old_sigmask); // uc_sigmask[0]
    let mc = uc.add(UCONTEXT_MCONTEXT);
    (mc as *mut u64).write_unaligned(fault_addr); // fault_address
    for i in 0..29usize {
        let val = if i == 18 { crate::trap::get_thread_x18() } else { regs.x[i] };
        (mc.add(8 + i * 8) as *mut u64).write_unaligned(val); // regs[0..28]
    }
    (mc.add(8 + 29 * 8) as *mut u64).write_unaligned(regs.fp); // regs[29]
    (mc.add(8 + 30 * 8) as *mut u64).write_unaligned(regs.lr); // regs[30]
    (mc.add(256) as *mut u64).write_unaligned(regs.sp);
    (mc.add(264) as *mut u64).write_unaligned(regs.pc);
    (mc.add(272) as *mut u64).write_unaligned(regs.cpsr as u64); // pstate
    // __reserved stays zeroed: {magic=0,size=0} terminator = no FP records.

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
    regs.x[1] = frame_addr + SIGINFO_OFFSET as u64; // siginfo_t*
    regs.x[2] = frame_addr + UCONTEXT_OFFSET as u64; // ucontext_t*
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

    // Fault signals: FIRST try the ET_EXEC lazy-relocation fixup. Once a
    // guest installs its own SIGSEGV handler (gcc's ICE handler), this
    // forwarder replaces segv_fixup_handler — without this hook lazy reloc
    // silently stops working and every fixable fault becomes a guest crash.
    if (sig == libc::SIGSEGV || sig == libc::SIGBUS)
        && crate::trap::try_lazy_exec_fixup(mctx)
    {
        return; // fixed — retry the faulting instruction
    }

    // Fault signals (SIGSEGV/SIGBUS) forwarded to a guest handler are almost
    // always OUR bug, but the guest handler hides the crash dump. Log the
    // fault details (async-signal-safe raw write) before forwarding.
    if sig == libc::SIGSEGV || sig == libc::SIGBUS {
        static FAULT_FWD_COUNT: AtomicU64 = AtomicU64::new(0);
        if FAULT_FWD_COUNT.fetch_add(1, Ordering::Relaxed) < 8 {
            let pc = mctx.ss.pc;
            let far = mctx.es.far;
            let instr = if pc >= 0x1000 { (pc as *const u32).read_volatile() } else { 0 };
            let mut buf = [0u8; 256];
            let n = crate::trap::raw_fmt(&mut buf, format_args!(
                "fakelinux: [{}] forwarding {} to guest handler: pc={:#x} far={:#x} instr={:#x} lr={:#x} sp={:#x}\n",
                libc::getpid(), if sig == libc::SIGBUS { "SIGBUS" } else { "SIGSEGV" },
                pc, far, instr, mctx.ss.lr, mctx.ss.sp
            ));
            libc::write(2, buf.as_ptr() as *const _, n);
            // Full GPR dump — the forwarded fault is usually OUR bug and the
            // guest handler (e.g. gcc's ICE handler) hides the crash dump.
            let mut buf2 = [0u8; 640];
            let r = &mctx.ss;
            let n2 = crate::trap::raw_fmt(&mut buf2, format_args!(
                "  x0={:#x} x1={:#x} x2={:#x} x3={:#x} x4={:#x} x5={:#x} x6={:#x} x7={:#x}\n  x8={:#x} x9={:#x} x10={:#x} x11={:#x} x12={:#x} x13={:#x} x14={:#x} x15={:#x}\n  x16={:#x} x17={:#x} x18={:#x} x19={:#x} x20={:#x} x21={:#x} x22={:#x} x23={:#x}\n  x24={:#x} x25={:#x} x26={:#x} x27={:#x} x28={:#x} fp={:#x}\n",
                r.x[0], r.x[1], r.x[2], r.x[3], r.x[4], r.x[5], r.x[6], r.x[7],
                r.x[8], r.x[9], r.x[10], r.x[11], r.x[12], r.x[13], r.x[14], r.x[15],
                r.x[16], r.x[17], r.x[18], r.x[19], r.x[20], r.x[21], r.x[22], r.x[23],
                r.x[24], r.x[25], r.x[26], r.x[27], r.x[28], r.fp
            ));
            libc::write(2, buf2.as_ptr() as *const _, n2);
            // Top of guest stack — recovers callee-saved spills (e.g. the
            // caller's pointer argument) without a debugger. Safe mach read.
            let mut words = [0u64; 20];
            let mut out_size: libc::vm_size_t = 0;
            let kr = crate::trap::mach_vm_read_overwrite(
                crate::trap::mach_task_self(),
                r.sp as u64,
                (words.len() * 8) as u64,
                words.as_mut_ptr() as u64,
                &mut out_size,
            );
            if kr == 0 && out_size as usize == words.len() * 8 {
                for chunk in 0..(words.len() / 4) {
                    let i = chunk * 4;
                    let mut sbuf = [0u8; 192];
                    let sn = crate::trap::raw_fmt(&mut sbuf, format_args!(
                        "  [sp+{:#04x}] {:#018x} {:#018x} {:#018x} {:#018x}\n",
                        i * 8, words[i], words[i + 1], words[i + 2], words[i + 3]
                    ));
                    libc::write(2, sbuf.as_ptr() as *const _, sn);
                }
            }
        }
    }

    // siginfo content: fault signals carry the fault address + a fault code;
    // everything else looks like SI_USER (kill).
    let (fault_addr, si_code) = match sig {
        libc::SIGSEGV => (mctx.es.far, 1),          // SEGV_MAPERR
        libc::SIGBUS => (mctx.es.far, 2),           // BUS_ADRERR
        libc::SIGILL | libc::SIGFPE | libc::SIGTRAP => (mctx.ss.pc, 1),
        _ => (0, 0),                                 // SI_USER
    };
    build_sigframe_and_redirect(mctx, linux_sig, handler, handler_mask, fault_addr, si_code);
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
                // Async (queued) signals: SI_USER shape, no fault address.
                build_sigframe_and_redirect(mctx, sig, handler, handler_mask, 0, 0);
            }
            break; // deliver one at a time
        }
    }
}

/// Pick the lowest-numbered pending signal that is in the waited-for set.
/// Returns the Linux signal number (1-based), or None.
pub fn sigtimedwait_pick(pending: u64, set: u64) -> Option<u32> {
    let hit = pending & set;
    if hit == 0 {
        None
    } else {
        Some(hit.trailing_zeros() + 1)
    }
}

fn monotonic_ns() -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Handle the guest's rt_sigtimedwait syscall.
///
/// glibc's POSIX-timer helper thread loops on rt_sigtimedwait(SIGTIMER);
/// returning ENOSYS made it busy-spin at 100% CPU (vim hang on first
/// keypress). We wait by polling PENDING_SIGNALS: other guest threads
/// (and the signal forwarder, when the signal is blocked or arrives in
/// trap context) set bits there. NULL timeout waits forever.
pub fn do_rt_sigtimedwait(set_ptr: u64, info_ptr: u64, timeout_ptr: u64, _sigsetsize: u64) -> u64 {
    if set_ptr == 0 {
        return (-22_i64) as u64; // -EINVAL
    }
    let set = unsafe { *(set_ptr as *const u64) };

    let deadline: Option<u64> = if timeout_ptr != 0 {
        let sec = unsafe { *(timeout_ptr as *const i64) };
        let nsec = unsafe { *((timeout_ptr + 8) as *const i64) };
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return (-22_i64) as u64; // -EINVAL
        }
        Some(monotonic_ns().saturating_add(sec as u64 * 1_000_000_000 + nsec as u64))
    } else {
        None
    };

    loop {
        // Queued siginfo payloads (POSIX timer expirations) take priority —
        // they carry si_code/si_value that glibc's timer helper dispatches on.
        if let Some(si) = crate::timers::pop_queued_siginfo(set) {
            let bit = 1u64 << (si.signo - 1);
            PENDING_SIGNALS.fetch_and(!bit, Ordering::SeqCst);
            if info_ptr != 0 {
                unsafe {
                    std::ptr::write_bytes(info_ptr as *mut u8, 0, 128);
                    let p = info_ptr as *mut i32;
                    *p = si.signo;          // si_signo @0
                    *p.add(2) = si.code;    // si_code @8
                    // SI_TIMER union layout: si_tid @16, si_overrun @20, si_value @24
                    *p.add(4) = si.tid;
                    *p.add(5) = si.overrun;
                    *((info_ptr + 24) as *mut u64) = si.sival;
                }
            }
            return si.signo as u64;
        }

        let pending = PENDING_SIGNALS.load(Ordering::SeqCst);
        if let Some(sig) = sigtimedwait_pick(pending, set) {
            let bit = 1u64 << (sig - 1);
            let prev = PENDING_SIGNALS.fetch_and(!bit, Ordering::SeqCst);
            if prev & bit != 0 {
                // We won the race for this signal — report it.
                if info_ptr != 0 {
                    unsafe {
                        std::ptr::write_bytes(info_ptr as *mut u8, 0, 128);
                        *(info_ptr as *mut i32) = sig as i32; // si_signo
                    }
                }
                return sig as u64;
            }
            continue; // another consumer took it; re-check
        }

        if let Some(d) = deadline {
            if monotonic_ns() >= d {
                return (-11_i64) as u64; // -EAGAIN
            }
        }

        // Sleep 10ms (clamped to remaining time) and re-poll.
        let mut sleep_ns: u64 = 10_000_000;
        if let Some(d) = deadline {
            sleep_ns = sleep_ns.min(d.saturating_sub(monotonic_ns()).max(1));
        }
        let ts = libc::timespec {
            tv_sec: (sleep_ns / 1_000_000_000) as libc::time_t,
            tv_nsec: (sleep_ns % 1_000_000_000) as libc::c_long,
        };
        unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigframe_passes_siginfo_and_ucontext() {
        // VPP's unix_signal_handler is SA_SIGINFO and dereferences
        // si->si_addr (siginfo offset 16) and uc->uc_mcontext.pc (ucontext
        // offset 440). Passing x1=x2=0 made the handler itself SIGSEGV on
        // Ctrl-C, which forwarded again → infinite signal storm at 100% CPU.
        crate::trap::init_tpidr_key();
        crate::trap::init_x18_key();
        let mut mctx: crate::trap::MContext64 = unsafe { std::mem::zeroed() };
        let stack = vec![0u8; 16384];
        let top = (stack.as_ptr() as u64 + 16384) & !0xF;
        mctx.ss.sp = top;
        mctx.ss.pc = 0x12345678;
        mctx.ss.lr = 0x9abc;
        mctx.ss.x[5] = 0x55;
        unsafe { build_sigframe_and_redirect(&mut mctx, 2, 0x4000, 0, 0xdead_f00d, 0x80) };
        assert_eq!(mctx.ss.x[0], 2, "x0 = signum");
        let si = mctx.ss.x[1];
        let uc = mctx.ss.x[2];
        assert!(si > mctx.ss.sp && si < top, "x1 must point into the sigframe");
        assert!(uc > mctx.ss.sp && uc < top, "x2 must point into the sigframe");
        unsafe {
            assert_eq!(*(si as *const i32), 2, "si_signo");
            assert_eq!(*((si + 8) as *const i32), 0x80, "si_code");
            assert_eq!(*((si + 16) as *const u64), 0xdead_f00d, "si_addr");
            assert_eq!(*((uc + 176) as *const u64), 0xdead_f00d, "uc_mcontext.fault_address");
            assert_eq!(*((uc + 184 + 5 * 8) as *const u64), 0x55, "uc_mcontext.regs[5]");
            assert_eq!(*((uc + 184 + 30 * 8) as *const u64), 0x9abc, "regs[30]=lr");
            assert_eq!(*((uc + 432) as *const u64), top, "uc_mcontext.sp");
            assert_eq!(*((uc + 440) as *const u64), 0x12345678, "uc_mcontext.pc");
        }
        // sigreturn still works: frame layout below the new fields unchanged.
        assert!(unsafe { do_rt_sigreturn(&mut mctx) }, "sigreturn restores");
        assert_eq!(mctx.ss.pc, 0x12345678);
        assert_eq!(mctx.ss.sp, top);
    }

    #[test]
    fn sigtimedwait_pick_lowest_in_set() {
        // SIGTIMER (Linux RT signal 34) pending, waited for → picked.
        let set = 1u64 << (34 - 1);
        assert_eq!(sigtimedwait_pick(set, set), Some(34));
    }

    #[test]
    fn sigtimedwait_pick_ignores_signals_outside_set() {
        let pending = 1u64 << (17 - 1); // SIGCHLD pending
        let set = 1u64 << (34 - 1);     // waiting only for 34
        assert_eq!(sigtimedwait_pick(pending, set), None);
    }

    #[test]
    fn sigtimedwait_pick_prefers_lowest() {
        let pending = (1u64 << (34 - 1)) | (1u64 << (10 - 1));
        let set = u64::MAX;
        assert_eq!(sigtimedwait_pick(pending, set), Some(10));
    }

    #[test]
    fn sigtimedwait_pick_empty_pending() {
        assert_eq!(sigtimedwait_pick(0, u64::MAX), None);
    }

    // ppoll sigmask emulation: a pending signal that the ppoll temp mask
    // unblocks (and that has a real guest handler) must interrupt the wait.
    // Bug: do_ppoll ignored the sigmask arg, so sudo — which blocks SIGCHLD
    // and relies on ppoll to atomically unblock it — slept forever in poll
    // with a zombie child (hung `make install-dep` after apt-get update).
    #[test]
    fn deliverable_set_unblocked_with_handler() {
        let sigchld = 1u64 << (17 - 1);
        // SIGCHLD pending, temp mask unblocks it, handler installed → deliverable
        assert_eq!(deliverable_set(sigchld, 0, sigchld), sigchld);
        // still blocked by the temp mask → not deliverable
        assert_eq!(deliverable_set(sigchld, sigchld, sigchld), 0);
        // unblocked but disposition is SIG_DFL/IGN → must NOT cause EINTR
        assert_eq!(deliverable_set(sigchld, 0, 0), 0);
        // nothing pending
        assert_eq!(deliverable_set(0, 0, sigchld), 0);
    }

    #[test]
    fn ppoll_mask_swap_protects_kill_stop() {
        // SIGKILL(9)/SIGSTOP(19) can never be blocked, even via ppoll's mask
        let old = GUEST_SIGMASK.load(Ordering::SeqCst);
        let swapped_old = ppoll_mask_begin(u64::MAX);
        assert_eq!(swapped_old, old);
        let now = GUEST_SIGMASK.load(Ordering::SeqCst);
        assert_eq!(now & (1u64 << 8), 0, "SIGKILL must stay unblockable");
        assert_eq!(now & (1u64 << 18), 0, "SIGSTOP must stay unblockable");
        ppoll_mask_end(old);
        assert_eq!(GUEST_SIGMASK.load(Ordering::SeqCst), old);
    }
}
