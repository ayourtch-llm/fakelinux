//! Thread support: clone() and futex emulation.
//!
//! Linux clone() with CLONE_THREAD creates a new thread sharing the address space.
//! We implement this using pthreads. Futex is emulated with a condvar/mutex table.

use std::collections::HashMap;
use std::sync::{Condvar, Mutex, Arc};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::time::Duration;

// ─── Saved CLOEXEC mask for fork children ──────────────────────────────────
//
// When we strip FD_CLOEXEC before macOS fork (to prevent atfork handlers from
// closing fds), the child loses the CLOEXEC information.  We can't restore
// it in the child immediately (guest code needs to dup2 first), so we stash
// the mask here and let do_close_range(CLOSE_RANGE_CLOEXEC) consult it.

pub struct SavedCloexecMask {
    bits: std::sync::Mutex<[bool; 256]>,
}

impl SavedCloexecMask {
    const fn new() -> Self {
        Self { bits: std::sync::Mutex::new([false; 256]) }
    }
    pub fn store_mask(&self, mask: &[bool; 256]) {
        *self.bits.lock().unwrap() = *mask;
    }
    /// Check if fd had CLOEXEC before the fork and consume it (one-shot).
    pub fn take(&self, fd: usize) -> bool {
        let mut m = self.bits.lock().unwrap();
        if fd < 256 && m[fd] { m[fd] = false; true } else { false }
    }
    /// Check if fd had CLOEXEC (non-consuming peek).
    pub fn had_cloexec(&self, fd: usize) -> bool {
        let m = self.bits.lock().unwrap();
        fd < 256 && m[fd]
    }
    pub fn clear(&self) {
        *self.bits.lock().unwrap() = [false; 256];
    }
    /// Forget a single fd's saved bit. Call when the guest closes the fd or
    /// dup2's over it — the saved bit refers to the old fd object, and
    /// re-applying CLOEXEC to its replacement at exec would close a live fd.
    pub fn clear_fd(&self, fd: usize) {
        let mut m = self.bits.lock().unwrap();
        if fd < 256 { m[fd] = false; }
    }
    /// Drain all still-pending fds (one-shot): fds that had CLOEXEC at fork
    /// time and were not since closed/replaced. Called at exec time to
    /// re-apply FD_CLOEXEC so the host execve closes them (Linux semantics).
    pub fn drain_pending(&self) -> Vec<usize> {
        let mut m = self.bits.lock().unwrap();
        let mut v = Vec::new();
        for fd in 0..256usize {
            if m[fd] { m[fd] = false; v.push(fd); }
        }
        v
    }
}

pub static FORK_SAVED_CLOEXEC: SavedCloexecMask = SavedCloexecMask::new();

// ─── Per-thread TID via pthread key ─────────────────────────────────────────

static TID_KEY: AtomicU64 = AtomicU64::new(0);
static TID_KEY_INIT: AtomicBool = AtomicBool::new(false);

/// Initialize the pthread key for per-thread TID. Call once at startup.
pub fn init_tid_key() {
    let mut key: libc::pthread_key_t = 0;
    let ret = unsafe { libc::pthread_key_create(&mut key, None) };
    if ret != 0 {
        panic!("pthread_key_create for TID failed: {}", ret);
    }
    TID_KEY.store(key as u64, Ordering::SeqCst);
    TID_KEY_INIT.store(true, Ordering::SeqCst);
}

/// Set the current thread's TID.
pub fn set_thread_tid(tid: i32) {
    if TID_KEY_INIT.load(Ordering::SeqCst) {
        let key = TID_KEY.load(Ordering::SeqCst) as libc::pthread_key_t;
        unsafe { libc::pthread_setspecific(key, tid as usize as *const libc::c_void); }
    }
    // Also store in the global for backward compatibility
    CURRENT_TID.store(tid, Ordering::SeqCst);
}

/// Get the current thread's TID.
fn get_thread_tid() -> i32 {
    if TID_KEY_INIT.load(Ordering::SeqCst) {
        let key = TID_KEY.load(Ordering::SeqCst) as libc::pthread_key_t;
        let val = unsafe { libc::pthread_getspecific(key) } as usize as i32;
        if val != 0 {
            return val;
        }
    }
    let t = CURRENT_TID.load(Ordering::SeqCst);
    if t == 0 { unsafe { libc::getpid() } } else { t }
}

// ─── Per-thread clear_child_tid pointer ─────────────────────────────────────

static CLEAR_TID_KEY: AtomicU64 = AtomicU64::new(0);
static CLEAR_TID_KEY_INIT: AtomicBool = AtomicBool::new(false);

pub fn init_clear_tid_key() {
    let mut key: libc::pthread_key_t = 0;
    let ret = unsafe { libc::pthread_key_create(&mut key, None) };
    if ret != 0 {
        panic!("pthread_key_create for clear_tid failed: {}", ret);
    }
    CLEAR_TID_KEY.store(key as u64, Ordering::SeqCst);
    CLEAR_TID_KEY_INIT.store(true, Ordering::SeqCst);
}

fn set_clear_tid_ptr(ptr: u64) {
    if CLEAR_TID_KEY_INIT.load(Ordering::SeqCst) {
        let key = CLEAR_TID_KEY.load(Ordering::SeqCst) as libc::pthread_key_t;
        unsafe { libc::pthread_setspecific(key, ptr as *const libc::c_void); }
    }
}

fn get_clear_tid_ptr() -> u64 {
    if CLEAR_TID_KEY_INIT.load(Ordering::SeqCst) {
        let key = CLEAR_TID_KEY.load(Ordering::SeqCst) as libc::pthread_key_t;
        unsafe { libc::pthread_getspecific(key) as u64 }
    } else {
        0
    }
}

// ─── Thread ID tracking ─────────────────────────────────────────────────────

static NEXT_TID: AtomicI32 = AtomicI32::new(1000);

pub fn alloc_tid() -> i32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

// The main thread's TID
static MAIN_TID: AtomicI32 = AtomicI32::new(0);

pub fn init_main_tid() {
    let tid = alloc_tid();
    MAIN_TID.store(tid, Ordering::SeqCst);
    CURRENT_TID.store(tid, Ordering::SeqCst);
    set_thread_tid(tid);
}

pub fn main_tid() -> i32 {
    MAIN_TID.load(Ordering::SeqCst)
}

// Global fallback TID (for backward compat, used when pthread key not yet set)
pub static CURRENT_TID: AtomicI32 = AtomicI32::new(0);

pub fn current_tid() -> i32 {
    get_thread_tid()
}

/// Handle set_tid_address syscall. Stores the clear_child_tid pointer
/// for the calling thread and returns the caller's TID.
pub fn do_set_tid_address(tidptr: u64) -> u64 {
    set_clear_tid_ptr(tidptr);
    current_tid() as u64
}

// ─── TLS (TPIDR_EL0) management ─────────────────────────────────────────────
// On aarch64, both Linux and macOS use TPIDR_EL0 for thread-local storage.
// We save the macOS TLS before entering guest code, and swap it in the signal handler.

static MACOS_TLS: AtomicU64 = AtomicU64::new(0);

pub fn get_macos_tls() -> u64 {
    MACOS_TLS.load(Ordering::SeqCst)
}

/// Save the current (macOS) TPIDR_EL0 value. Call once before jumping to guest.
pub fn save_macos_tls() {
    let tls: u64;
    unsafe {
        std::arch::asm!("mrs {}, tpidr_el0", out(reg) tls);
    }
    MACOS_TLS.store(tls, Ordering::SeqCst);
}

/// Swap TPIDR_EL0: save current (guest) value, restore macOS value.
/// Returns the guest TLS value so it can be restored later.
pub fn swap_to_macos_tls() -> u64 {
    let guest_tls: u64;
    let macos_tls = MACOS_TLS.load(Ordering::SeqCst);
    unsafe {
        std::arch::asm!("mrs {}, tpidr_el0", out(reg) guest_tls);
        std::arch::asm!("msr tpidr_el0, {}", in(reg) macos_tls);
    }
    guest_tls
}

/// Restore the guest's TPIDR_EL0 value.
pub fn restore_guest_tls(guest_tls: u64) {
    unsafe {
        std::arch::asm!("msr tpidr_el0, {}", in(reg) guest_tls);
    }
}

// ─── Clone (thread creation) ─────────────────────────────────────────────────

// Linux clone flags
pub const CLONE_VM: u64 = 0x00000100;
pub const CLONE_FS: u64 = 0x00000200;
pub const CLONE_FILES: u64 = 0x00000400;
pub const CLONE_SIGHAND: u64 = 0x00000800;
pub const CLONE_VFORK: u64 = 0x00004000;
pub const CLONE_THREAD: u64 = 0x00010000;
pub const CLONE_SYSVSEM: u64 = 0x00040000;
pub const CLONE_SETTLS: u64 = 0x00080000;
pub const CLONE_PARENT_SETTID: u64 = 0x00100000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
pub const CLONE_CHILD_SETTID: u64 = 0x01000000;

/// Implement clone: fork (no CLONE_VM) or thread creation (CLONE_VM|CLONE_THREAD).
/// Called from trap_handler via syscall::emulate. The `regs` parameter contains
/// the guest's full register state at the point of the clone syscall.
pub fn do_clone_with_regs(flags: u64, child_stack: u64, parent_tid_ptr: u64, tls: u64, child_tid_ptr: u64, regs: &crate::trap::ThreadState64) -> u64 {
    // Fork: clone without CLONE_VM
    if flags & CLONE_VM == 0 {
        return do_fork(flags, child_tid_ptr);
    }

    // CLONE_VM | CLONE_VFORK (without CLONE_THREAD): vfork-like clone.
    // Used by musl/glibc for posix_spawn/system(). The child shares the
    // parent's address space and the parent blocks until the child execs or
    // exits. We treat this as a regular fork — the child will re-exec
    // fakelinux anyway, so sharing the address space briefly is fine.
    if flags & CLONE_VFORK != 0 && flags & CLONE_THREAD == 0 {
        return do_fork(flags, child_tid_ptr);
    }

    // Thread creation requires CLONE_THREAD
    if flags & CLONE_THREAD == 0 {
        eprintln!("fakelinux: clone with CLONE_VM but without CLONE_THREAD not supported (flags={:#x})", flags);
        return (-38_i64) as u64; // -ENOSYS
    }

    let tid = alloc_tid();

    // Write TID to parent_tid location
    if flags & CLONE_PARENT_SETTID != 0 && parent_tid_ptr != 0 {
        unsafe { (parent_tid_ptr as *mut i32).write(tid); }
    }

    // Write TID to child_tid location
    if flags & CLONE_CHILD_SETTID != 0 && child_tid_ptr != 0 {
        unsafe { (child_tid_ptr as *mut i32).write(tid); }
    }

    let set_tls = flags & CLONE_SETTLS != 0;
    let tls_val = if set_tls { tls } else { crate::trap::get_thread_tpidr() };
    let clear_tid_ptr = if flags & CLONE_CHILD_CLEARTID != 0 {
        child_tid_ptr
    } else {
        0
    };

    // Save the full guest register state for the child thread.
    // The child will resume at PC+4 (instruction after the clone syscall) with x0=0.
    let mut saved = SavedRegs {
        x: regs.x,
        fp: regs.fp,
        lr: regs.lr,
        sp: if child_stack != 0 { child_stack } else { regs.sp },
        pc: regs.pc + 4, // resume after the clone BRK
    };
    saved.x[0] = 0; // child return value

    // Spawn a pthread
    let mut thread: libc::pthread_t = 0;
    let arg = Box::new(CloneArgs {
        saved_regs: saved,
        tid,
        tls: tls_val,
        set_tls,
        clear_tid_ptr,
        guest_x18: crate::trap::get_thread_x18(),
    });
    let arg_ptr = Box::into_raw(arg) as *mut libc::c_void;

    let ret = unsafe {
        libc::pthread_create(&mut thread, std::ptr::null(), clone_entry, arg_ptr)
    };
    if ret != 0 {
        // Clean up
        unsafe { drop(Box::from_raw(arg_ptr as *mut CloneArgs)); }
        return (-12_i64) as u64; // -ENOMEM
    }

    // Detach — we don't join threads (they exit via SYS_EXIT -> thread_exit)
    unsafe { libc::pthread_detach(thread); }

    tid as u64
}

/// Backward-compatible do_clone that does not have access to regs (for fork path only).
pub fn do_clone(flags: u64, child_stack: u64, parent_tid_ptr: u64, tls: u64, child_tid_ptr: u64) -> u64 {
    // Fork path doesn't need regs — it uses the trampoline.
    if flags & CLONE_VM == 0 {
        return do_fork(flags, child_tid_ptr);
    }
    // Thread creation without regs: cannot work properly.
    // This should not be called for CLONE_THREAD; syscall.rs should use do_clone_with_regs.
    eprintln!("fakelinux: do_clone called for threads without regs (flags={:#x})", flags);
    (-38_i64) as u64 // -ENOSYS
}

struct CloneArgs {
    saved_regs: SavedRegs,
    tid: i32,
    tls: u64,
    set_tls: bool,
    clear_tid_ptr: u64,
    guest_x18: u64,
}

/// Set up a per-thread sigaltstack and install the SIGILL trap handler.
/// Must be called on each new thread before it executes guest code.
fn setup_thread_signal_stack() {
    unsafe {
        // Allocate a signal-handler stack for this thread
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
            let msg = "fakelinux: failed to allocate thread signal stack\n";
            libc::write(2, msg.as_ptr() as *const _, msg.len());
            libc::pthread_exit(std::ptr::null_mut());
        }
        let ss = libc::stack_t {
            ss_sp: stack,
            ss_flags: 0,
            ss_size: stack_size,
        };
        if libc::sigaltstack(&ss, std::ptr::null_mut()) != 0 {
            let msg = "fakelinux: sigaltstack failed for thread\n";
            libc::write(2, msg.as_ptr() as *const _, msg.len());
            libc::pthread_exit(std::ptr::null_mut());
        }

        // Install SIGILL handler on this thread (macOS requires per-thread setup
        // for sigaltstack, but sigaction is process-wide, so this is technically
        // redundant — but ensures the handler is installed).
        // CRITICAL: use sigfillset to block all signals during the handler,
        // matching install_trap_handler(). Using sigemptyset here would override
        // the process-wide handler to not block signals during traps.
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = crate::trap::trap_handler_ptr();
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigfillset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGILL, &sa, std::ptr::null_mut());

        // Also install crash handlers
        let mut sa2: libc::sigaction = std::mem::zeroed();
        sa2.sa_sigaction = crash_handler_ptr();
        sa2.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigemptyset(&mut sa2.sa_mask);
        libc::sigaction(libc::SIGSEGV, &sa2, std::ptr::null_mut());
        libc::sigaction(libc::SIGBUS, &sa2, std::ptr::null_mut());
    }
}

fn crash_handler_ptr() -> libc::sighandler_t {
    // Re-use the crash handler from trap.rs — it's the same function pointer.
    // We just need the extern "C" fn pointer. Since it's not pub, we'll
    // re-install via the same pattern as install_handler.
    // Actually, trap.rs crash_handler is not pub. Let's just skip re-installing
    // crash handlers; they're process-wide on macOS anyway.
    0 as libc::sighandler_t // SIG_DFL — will use whatever was installed
}

extern "C" fn clone_entry(arg: *mut libc::c_void) -> *mut libc::c_void {
    let args = unsafe { Box::from_raw(arg as *mut CloneArgs) };

    // Set up per-thread TID
    set_thread_tid(args.tid);

    // Set up per-thread TPIDR
    if args.set_tls {
        crate::trap::set_thread_tpidr(args.tls);
    }

    // Set up per-thread clear_child_tid pointer
    if args.clear_tid_ptr != 0 {
        set_clear_tid_ptr(args.clear_tid_ptr);
    }

    // Propagate parent's guest x18 to this thread's TSD slot
    crate::trap::set_thread_x18(args.guest_x18);

    // Set up per-thread sigaltstack
    setup_thread_signal_stack();

    // CRITICAL: unblock all signals. This thread was created by
    // pthread_create called from inside the SIGILL trap handler, which
    // has sa_mask = sigfillset (blocking all signals). New threads
    // inherit the creating thread's signal mask, so SIGILL is blocked.
    // Without unblocking, UDF instructions (patched SVC/TPIDR/x18) on
    // this thread would pend SIGILL without delivery, causing the
    // thread to silently skip over them and eventually deadlock.
    unsafe {
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
    }

    // Jump to guest code with all saved registers restored.
    let regs_ptr = &args.saved_regs as *const SavedRegs;
    let pc = args.saved_regs.pc;
    unsafe {
        trampoline::restore_all_regs(regs_ptr as u64, pc);
    }
}

/// Called when a thread calls SYS_EXIT (not SYS_EXIT_GROUP).
/// Performs CLONE_CHILD_CLEARTID cleanup and exits only this thread.
pub fn thread_exit(status: i32) -> ! {
    // CLONE_CHILD_CLEARTID: write 0 to the clear_child_tid address and futex wake it
    let clear_tid_addr = get_clear_tid_ptr();
    if clear_tid_addr != 0 {
        unsafe {
            let ptr = clear_tid_addr as *mut i32;
            ptr.write(0);
        }
        // Wake any thread waiting on this futex (e.g., pthread_join)
        do_futex(clear_tid_addr, FUTEX_WAKE, 1, 0, 0, 0);
    }

    // Exit only this pthread, not the whole process.
    unsafe {
        libc::pthread_exit(status as *mut libc::c_void);
    }
}

// ─── Trampoline instances ────────────────────────────────────────────────────

use crate::trampoline::{self, Trampoline, SavedRegs};

/// Fork trampoline: defers fork() to outside signal context.
pub static FORK: Trampoline = Trampoline::new();

/// Patch trampoline: defers mprotect+patch on executable pages to outside
/// signal context (mprotect from signal context deadlocks macOS).
pub static PATCH: Trampoline = Trampoline::new();

const PAGE_SIZE: u64 = 16384;

/// Create both trampoline pages starting at `base_addr` and register them.
/// Called from loader after mapping guest segments.
pub fn init_trampolines(base_addr: u64) {
    FORK.init(base_addr, fork_trampoline_entry);
    PATCH.init(base_addr + PAGE_SIZE, patch_trampoline_entry);
}

// ─── Fork trampoline ────────────────────────────────────────────────────────

/// Saved clone args for use by the fork trampoline (set in signal context,
/// used outside signal context after sigreturn).
static FORK_FLAGS: AtomicU64 = AtomicU64::new(0);
static FORK_CHILD_TID_PTR: AtomicU64 = AtomicU64::new(0);

fn do_fork(flags: u64, child_tid_ptr: u64) -> u64 {
    // Don't fork here (signal context). Mark pending and return a sentinel.
    // The trap handler will redirect sigreturn to the fork trampoline.
    // IMPORTANT: No heap allocation (format!/String) in signal context!
    // macOS's malloc is not async-signal-safe. Using it here poisons malloc
    // internal state, causing macOS's fork atfork handlers to misbehave
    // (closing fds, corrupting child state).
    if crate::syscall::trace_enabled() {
        let pid = unsafe { libc::getpid() };
        let mut buf = [0u8; 80];
        let n = {
            use std::io::Write;
            let mut c = std::io::Cursor::new(&mut buf[..]);
            let _ = c.write_fmt(format_args!(
                "fakelinux: [{}] do_fork(flags={:#x}) called\n", pid, flags));
            c.position() as usize
        };
        unsafe { libc::write(2, buf.as_ptr() as *const _, n); }
    }
    FORK_FLAGS.store(flags, Ordering::SeqCst);
    FORK_CHILD_TID_PTR.store(child_tid_ptr, Ordering::SeqCst);
    FORK.mark_pending();
    0xFFFF_FFFF_0000_F0C0
}

/// Runs outside signal context. Does the actual fork, sets x0 to the pid,
/// restores guest registers, and jumps back to guest code.
extern "C" fn fork_trampoline_entry() -> ! {
    // In container mode, set the FAKELINUX_INIT_PID env var before fork so
    // the child inherits it. In the simplified scheme vpid == real PID for
    // all non-init processes, so no pre-allocation is needed.
    let container = crate::pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed);
    if container {
        crate::pidns::set_child_env();
    }

    // Probe pipe fds before fork for debugging.
    // Use stack buffer only — no heap allocation (safe for potential signal context).
    if crate::syscall::trace_enabled() {
        for fd in [5_i32, 6, 7, 8, 9, 10] {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let ret = unsafe { libc::fstat(fd, &mut st) };
            if ret == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFIFO {
                let pid_val = unsafe { libc::getpid() };
                let mut buf = [0u8; 80];
                let n = {
                    use std::io::Write;
                    let mut c = std::io::Cursor::new(&mut buf[..]);
                    let _ = c.write_fmt(format_args!(
                        "fakelinux: [{}] FORK_PROBE pre-fork fd={} ino={}\n",
                        pid_val, fd, st.st_ino));
                    c.position() as usize
                };
                unsafe { libc::write(2, buf.as_ptr() as *const _, n); }
            }
        }
    }

    // CRITICAL: Strip FD_CLOEXEC from all fds before fork.
    // On Linux, FD_CLOEXEC only fires at exec(), not fork(). But macOS's fork()
    // runs atfork handlers that close CLOEXEC fds in the child. Guest code (like
    // apt's gpgv method) creates pipes with O_CLOEXEC expecting them to survive
    // fork but close on exec. We must preserve Linux semantics.
    let mut saved_cloexec = [0i32; 256]; // fd → old flags (-1 = not open)
    for fd in 0..256i32 {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        saved_cloexec[fd as usize] = flags;
        if flags > 0 && flags & libc::FD_CLOEXEC != 0 {
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC); }
        }
    }

    // Save __libc_fork's stack canary before fork.
    // glibc's _Fork child path writes the robust list head to [TPIDR-0x668].
    // When the guest's TLS is allocated near the stack (macOS mmap placement),
    // this can overwrite the stack canary at [__libc_fork_sp + 0xd8].
    // We save the canary value and restore it in the child after fork.
    //
    // Layout: guest_sp (from SavedRegs) = _Fork's sp = __libc_fork_sp - 16
    // → canary at [guest_sp + 16 + 0xd8] = [guest_sp + 0xe8]
    let guest_sp = FORK.get_saved_sp();
    let canary_addr = guest_sp + 0xe8;
    let saved_canary = unsafe { (canary_addr as *const u64).read() };

    // Also save __libc_fork's LR before macOS fork to detect corruption.
    // __libc_fork_sp = guest_sp + 0x10, saved LR at [__libc_fork_sp + 0xE8]
    let lr_addr = guest_sp + 0x10 + 0xE8;
    let lr_before_macos_fork = unsafe { (lr_addr as *const u64).read() };

    // Log the pre-fork LR value and surrounding stack frame
    if crate::syscall::trace_enabled() {
        let pid_val = unsafe { libc::getpid() };
        let libc_fork_sp = guest_sp + 0x10;
        let saved_fp = unsafe { ((libc_fork_sp + 0xE0) as *const u64).read() };
        // Read ExecFork's saved LR from its frame above __libc_fork's frame.
        // ExecFork: stp x29, x30, [sp, #-64]! → ExecFork_SP = __libc_fork_SP + 0x140
        // ExecFork's saved LR at [ExecFork_SP + 8] = [libc_fork_sp + 0x148]
        let exec_fork_lr = unsafe { ((libc_fork_sp + 0x148) as *const u64).read() };
        let mut buf = [0u8; 400];
        let n = {
            use std::io::Write;
            let mut c = std::io::Cursor::new(&mut buf[..]);
            let _ = c.write_fmt(format_args!(
                "fakelinux: [{}] PRE_FORK_LR lr={:#x} fp={:#x} exec_fork_lr={:#x} guest_sp={:#x}\n",
                pid_val, lr_before_macos_fork, saved_fp, exec_fork_lr, guest_sp));
            c.position() as usize
        };
        unsafe { libc::write(2, buf.as_ptr() as *const _, n); }

        // If LR looks corrupted (not in code range 0x100000000-0x105000000), dump stack
        if lr_before_macos_fork < 0x1_0000_0000 || lr_before_macos_fork > 0x1_0500_0000 {
            // Dump 8 qwords around the corrupted LR slot for analysis
            let mut buf2 = [0u8; 800];
            let n2 = {
                use std::io::Write;
                let mut c = std::io::Cursor::new(&mut buf2[..]);
                let _ = c.write_fmt(format_args!(
                    "fakelinux: [{}] STACK_DUMP libc_fork_sp={:#x}:\n",
                    pid_val, libc_fork_sp));
                // Dump from sp+0x00 to sp+0x148 in 8-byte steps
                for off in (0..=0x148u64).step_by(8) {
                    let val = unsafe { ((libc_fork_sp + off) as *const u64).read() };
                    let _ = c.write_fmt(format_args!(
                        "  [sp+{:#04x}] = {:#018x}{}\n",
                        off, val,
                        match off {
                            0xD8 => " (canary)",
                            0xE0 => " (x29/FP)",
                            0xE8 => " (x30/LR) *** CORRUPTED ***",
                            0xF0 => " (x19)",
                            0xF8 => " (x20)",
                            0x100 => " (x21)",
                            0x108 => " (x22)",
                            0x130 => " (x27)",
                            0x138 => " (x28)",
                            0x140 => " (ExecFork x29)",
                            0x148 => " (ExecFork x30/LR)",
                            _ => "",
                        }
                    ));
                }
                c.position() as usize
            };
            unsafe { libc::write(2, buf2.as_ptr() as *const _, n2); }
        }
    }

    // Save parent's guest x18 BEFORE fork — after fork, the child's TSD
    // slots may be empty (macOS gives fork children a new thread/TPIDRRO).
    let parent_x18 = crate::trap::get_thread_x18();

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // Restore CLOEXEC flags before returning error
        for fd in 0..256i32 {
            let old = saved_cloexec[fd as usize];
            if old > 0 && old & libc::FD_CLOEXEC != 0 {
                unsafe { libc::fcntl(fd, libc::F_SETFD, old); }
            }
        }
        unsafe { libc::_exit(127); }
    }

    // Restore FD_CLOEXEC in the PARENT only.
    // We must NOT restore in the child here because the guest's glibc calls
    // close_range(CLOSE_RANGE_CLOEXEC) BEFORE doing dup2 to set up the child's
    // stdin/stdout. If we restore CLOEXEC now, close_range would close the pipe
    // fds the child needs for dup2, causing exec with wrong stdin/stdout.
    //
    // For the child, CLOEXEC-based cleanup is handled in do_close_range() which
    // consults FORK_SAVED_CLOEXEC to know which fds originally had CLOEXEC.
    if pid != 0 {
        for fd in 0..256i32 {
            let old = saved_cloexec[fd as usize];
            if old > 0 && old & libc::FD_CLOEXEC != 0 {
                unsafe { libc::fcntl(fd, libc::F_SETFD, old); }
            }
        }
    } else {
        // Child: save the CLOEXEC set for do_close_range() to use later
        let mut mask = [false; 256];
        for fd in 0..256usize {
            let old = saved_cloexec[fd];
            mask[fd] = old > 0 && old & libc::FD_CLOEXEC != 0;
        }
        FORK_SAVED_CLOEXEC.store_mask(&mask);
    }

    if pid == 0 {
        // Re-initialize per-thread x18 TSD slot in the fork child.
        // macOS fork() gives the child a new thread with fresh TSD slots (all 0).
        // The x18 trampolines read guest x18 from [TPIDRRO_EL0 + key*8], which
        // would be 0 without this, causing NULL dereference on the first x18
        // instruction in the child. Use the value saved BEFORE fork.
        crate::trap::set_thread_x18(parent_x18);
        // Also re-initialize TPIDR TSD slot (same issue).
        let parent_tpidr = crate::trap::get_thread_tpidr();
        crate::trap::set_thread_tpidr(parent_tpidr);

        // Restore __libc_fork's stack canary if it was corrupted by the
        // STP in _Fork's child path (see diary for full explanation).
        // The STP writes [TPIDR-0x668]; if TLS is near the stack, this
        // overwrites the canary at [__libc_fork_sp+0xd8] = [guest_sp+0xe8].
        let current_canary = unsafe { (canary_addr as *const u64).read() };
        if current_canary != saved_canary {
            unsafe { (canary_addr as *mut u64).write(saved_canary); }
        }

        // Also check and restore __libc_fork's saved LR.
        // Something corrupts [__libc_fork_sp+0xE8] to a heap address before fork.
        let lr_after_macos_fork = unsafe { (lr_addr as *const u64).read() };
        if crate::syscall::trace_enabled() {
            let pid_val = unsafe { libc::getpid() };
            let mut buf = [0u8; 250];
            let n = {
                use std::io::Write;
                let mut c = std::io::Cursor::new(&mut buf[..]);
                let _ = c.write_fmt(format_args!(
                    "fakelinux: [{}] POST_FORK_LR addr={:#x} before={:#x} after={:#x} match={}\n",
                    pid_val, lr_addr, lr_before_macos_fork, lr_after_macos_fork,
                    if lr_before_macos_fork == lr_after_macos_fork { 'Y' } else { 'N' }));
                c.position() as usize
            };
            unsafe { libc::write(2, buf.as_ptr() as *const _, n); }
        }
        // If LR was corrupted, restore it to the pre-fork value.
        // This is a WORKAROUND — the real fix is to find what corrupts it.
        if lr_after_macos_fork != lr_before_macos_fork {
            unsafe { (lr_addr as *mut u64).write(lr_before_macos_fork); }
        }

        // Probe pipe fds in child right after fork.
        // Use stack buffer only — no heap allocation after fork.
        if crate::syscall::trace_enabled() {
            let pid_val = unsafe { libc::getpid() };
            for fd in [0_i32, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10] {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                let ret = unsafe { libc::fstat(fd, &mut st) };
                if ret == 0 {
                    // Determine fd type and read/write role
                    let kind = match st.st_mode & libc::S_IFMT {
                        libc::S_IFIFO => b'P',  // pipe
                        libc::S_IFREG => b'F',  // file
                        libc::S_IFCHR => b'C',  // char device
                        libc::S_IFSOCK => b'S', // socket
                        _ => b'?',
                    };
                    // Check read/write capability via fcntl
                    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                    let rw = if flags < 0 { b'?' }
                        else if flags & libc::O_ACCMODE == libc::O_RDONLY { b'r' }
                        else if flags & libc::O_ACCMODE == libc::O_WRONLY { b'w' }
                        else { b'B' }; // both (O_RDWR)
                    let mut buf = [0u8; 100];
                    let n = {
                        use std::io::Write;
                        let mut c = std::io::Cursor::new(&mut buf[..]);
                        let _ = c.write_fmt(format_args!(
                            "fakelinux: [{}] FORK_PROBE child fd={} {}={}\n",
                            pid_val, fd, kind as char, rw as char));
                        c.position() as usize
                    };
                    unsafe { libc::write(2, buf.as_ptr() as *const _, n); }
                }
            }
            // Also log vpid state
            if crate::pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                let vpid = crate::pidns::current_vpid();
                let mut buf = [0u8; 80];
                let n = {
                    use std::io::Write;
                    let mut c = std::io::Cursor::new(&mut buf[..]);
                    let _ = c.write_fmt(format_args!(
                        "fakelinux: [{}] FORK_CHILD vpid={} real_pid={}\n",
                        pid_val, vpid, pid_val));
                    c.position() as usize
                };
                unsafe { libc::write(2, buf.as_ptr() as *const _, n); }
            }
        }

        // Early fd probe: check fds BEFORE init_child_after_fork
        if crate::syscall::trace_enabled() {
            let pid_val = unsafe { libc::getpid() };
            for fd in 3_i32..=10 {
                let ret = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                if ret >= 0 {
                    let cloexec = if ret & libc::FD_CLOEXEC != 0 { 'X' } else { '-' };
                    let mut buf = [0u8; 80];
                    let n = {
                        use std::io::Write;
                        let mut c = std::io::Cursor::new(&mut buf[..]);
                        let _ = c.write_fmt(format_args!(
                            "fakelinux: [{}] EARLY_FD fd={} cloexec={}\n",
                            pid_val, fd, cloexec));
                        c.position() as usize
                    };
                    unsafe { libc::write(2, buf.as_ptr() as *const _, n); }
                }
            }
        }

        // Child: re-initialize signal handling (fresh alt stack, re-install
        // trap handler, unblock signals).
        crate::trap::init_child_after_fork();
        IS_FORK_CHILD.store(true, Ordering::Relaxed);

        // Handle CLONE_CHILD_SETTID: write the child's TID to the
        // child_tid_ptr in the child's address space. On real Linux, the kernel
        // writes the child's TID here atomically during clone(). glibc depends
        // on this to update pthread->tid after fork.
        let fork_flags = FORK_FLAGS.load(Ordering::SeqCst);
        let child_tid_ptr = FORK_CHILD_TID_PTR.load(Ordering::SeqCst);
        if fork_flags & CLONE_CHILD_SETTID != 0 && child_tid_ptr != 0 {
            // Write the child's real macOS PID. glibc uses this internally
            // (pthread->tid) to detect child vs parent after fork. Must be
            // the real PID, not the virtual PID — current_vpid() would return
            // the PARENT's vpid here since the child hasn't set up its own yet.
            let child_tid = unsafe { libc::getpid() };
            unsafe { (child_tid_ptr as *mut i32).write(child_tid); }
        }
        // Also handle CLONE_CHILD_CLEARTID: set the clear-child-tid address
        // so that when this child eventually exits, the TID is cleared and
        // a futex wake is performed.
        if fork_flags & CLONE_CHILD_CLEARTID != 0 && child_tid_ptr != 0 {
            do_set_tid_address(child_tid_ptr);
        }

        // Enable SVC tracing for first SVCs in the fork child — diagnostic
        // for the (fixed) nested-fork race; only under FAKELINUX_TRACE.
        if crate::syscall::trace_enabled() {
            crate::trap::FORK_SVC_COUNT.store(10, std::sync::atomic::Ordering::Relaxed);
            crate::trap::FORK_TRAP_COUNT.store(50, std::sync::atomic::Ordering::Relaxed);
        }
        // Store canary address/value for verification during FORK_TRAP logging
        crate::trap::FORK_CANARY_ADDR.store(canary_addr, std::sync::atomic::Ordering::Relaxed);
        crate::trap::FORK_CANARY_SAVED.store(saved_canary, std::sync::atomic::Ordering::Relaxed);

        // Watch _Fork's saved LR on the stack to detect corruption.
        // glibc 2.39+ uses _Fork (not __libc_fork). Its prologue is just:
        //   stp x29, x30, [sp, #-16]!
        // So saved x30 is at sp+8 of _Fork's frame, where sp = guest_sp at clone SVC.
        let lr_watch_addr = guest_sp + 8;
        // Read the LR BEFORE fork — this is the correct parent value
        let lr_before_fork = unsafe { (lr_watch_addr as *const u64).read() };
        // Read LR again AFTER fork — if macOS fork corrupted it, this will differ
        let lr_after_fork = unsafe { (lr_watch_addr as *const u64).read() };
        if lr_after_fork != lr_before_fork {
            let pid_val = unsafe { libc::getpid() };
            let mut buf = [0u8; 200];
            let n = {
                use std::io::Write;
                let mut c = std::io::Cursor::new(&mut buf[..]);
                let _ = c.write_fmt(format_args!(
                    "fakelinux: [{}] LR_CORRUPT_AT_FORK! before={:#x} after={:#x} addr={:#x}\n",
                    pid_val, lr_before_fork, lr_after_fork, lr_watch_addr));
                c.position() as usize
            };
            unsafe { libc::write(2, buf.as_ptr() as *const _, n); }
            // RESTORE the LR to the correct value
            unsafe { (lr_watch_addr as *mut u64).write(lr_before_fork); }
        }
        crate::trap::FORK_LR_WATCH_ADDR.store(lr_watch_addr, std::sync::atomic::Ordering::Relaxed);
        crate::trap::FORK_LR_WATCH_EXPECTED.store(lr_before_fork, std::sync::atomic::Ordering::Relaxed);

        // Compute libc base from the set_robust_list SVC PC (known offset 0xBD510).
        // Patch __libc_fork's `mov w0, w19` at offset 0xC1D28 to UDF to intercept the return.
        let resume_pc = FORK.get_saved_pc(); // instruction after clone SVC = libc+0xBD4EC
        let libc_base = resume_pc - 0xBD4EC;
        let probe_addr = libc_base + 0xC1D28;
        unsafe {
            // Read original instruction
            let orig = (probe_addr as *const u32).read();
            crate::trap::FORK_RETURN_PROBE_ORIG.store(orig, std::sync::atomic::Ordering::Relaxed);
            // Make the page writable, patch, flush icache, restore protection
            let page = probe_addr & !0x3FFF; // 16KB page alignment
            libc::mprotect(page as *mut _, 0x4000, libc::PROT_READ | libc::PROT_WRITE);
            (probe_addr as *mut u32).write(crate::trap::UDF_MARKER);
            extern "C" { fn sys_icache_invalidate(start: *mut libc::c_void, size: usize); }
            sys_icache_invalidate(probe_addr as *mut _, 4);
            libc::mprotect(page as *mut _, 0x4000, libc::PROT_READ | libc::PROT_EXEC);
            crate::trap::FORK_RETURN_PROBE.store(probe_addr, std::sync::atomic::Ordering::Relaxed);
        }
        // Child inherits the FAKELINUX_INIT_PID env var for execve.
    }

    let return_pid = if pid == 0 {
        0u64
    } else {
        // In simplified PID scheme, vpid == real PID for all non-init processes.
        pid as u64
    };
    FORK.set_x0(return_pid);
    if crate::syscall::trace_enabled() {
        // Use raw write only — no heap allocation (format!/String) after fork.
        // Rust's allocator may have poisoned locks inherited from the parent.
        let pid_val = unsafe { libc::getpid() };
        let resume_pc = FORK.get_saved_pc();
        let mut buf = [0u8; 200];
        let n = {
            use std::io::Write;
            let mut c = std::io::Cursor::new(&mut buf[..]);
            let _ = c.write_fmt(format_args!(
                "fakelinux: [{}] fork_trampoline x0={} pid={} pc={:#x}\n",
                pid_val, return_pid, pid, resume_pc));
            c.position() as usize
        };
        unsafe { libc::write(2, buf.as_ptr() as *const _, n); }
    }
    unsafe { FORK.restore_and_resume(); }
}

// ─── Patch trampoline ────────────────────────────────────────────────────────

pub enum PendingPatchKind {
    /// mprotect adding PROT_EXEC: mprotect→RW, patch, icache, mprotect→final
    MprotectExec {
        aligned_addr: u64,
        aligned_len: u64,
        mac_prot: i32,
    },
}

pub struct PendingPatchWork {
    pub kind: PendingPatchKind,
}

static mut PENDING_PATCH: Option<PendingPatchWork> = None;

pub fn set_pending_patch(work: PendingPatchWork) {
    unsafe { *(&raw mut PENDING_PATCH) = Some(work); }
    PATCH.mark_pending();
}

/// Runs outside signal context. Does the deferred mprotect + patch_new_code,
/// restores guest registers, and jumps back to guest code.
extern "C" fn patch_trampoline_entry() -> ! {
    let work = unsafe { (*(&raw mut PENDING_PATCH)).take() }
        .expect("patch trampoline but no work stored");

    match work.kind {
        PendingPatchKind::MprotectExec { aligned_addr, aligned_len, mac_prot } => {
            unsafe {
                libc::mprotect(
                    aligned_addr as *mut _, aligned_len as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                );
            }
            crate::loader::patch_new_code(aligned_addr, aligned_len);
            unsafe {
                extern "C" { fn sys_icache_invalidate(start: *mut libc::c_void, size: usize); }
                sys_icache_invalidate(aligned_addr as *mut _, aligned_len as usize);
                libc::mprotect(aligned_addr as *mut _, aligned_len as usize, mac_prot);
            }
        }
    }

    unsafe { PATCH.restore_and_resume(); }
}

/// wait4(pid, wstatus, options, rusage)
pub fn do_wait4(pid: i64, wstatus_ptr: u64, options: i32, rusage_ptr: u64) -> u64 {
    let mut status: i32 = 0;
    let status_ptr = if wstatus_ptr != 0 { &mut status as *mut i32 } else { std::ptr::null_mut() };
    // NEVER pass the guest pointer through: macOS fills tv_usec as i32
    // (leaving the upper 4 bytes of the Linux i64 field as garbage) and
    // ru_maxrss in bytes (Linux: KB). Fill a local struct and convert.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let rusage = if rusage_ptr != 0 { &mut usage as *mut libc::rusage } else { std::ptr::null_mut() };

    let ret = unsafe { libc::wait4(pid as i32, status_ptr, options, rusage) };
    if crate::syscall::trace_enabled() && ret > 0 && wstatus_ptr != 0 {
        unsafe {
            let s = status;
            let msg = format!("fakelinux: wait4 pid={} status={:#x} signaled={} sig={}\n",
                ret, s, libc::WIFSIGNALED(s), if libc::WIFSIGNALED(s) { libc::WTERMSIG(s) } else { 0 });
            libc::write(2, msg.as_ptr() as *const _, msg.len());
        }
    }
    if ret < 0 {
        return crate::translate::linux_errno();
    }

    // Write status back to guest memory (Linux and macOS wstatus format is compatible)
    if wstatus_ptr != 0 {
        unsafe { (wstatus_ptr as *mut i32).write(status); }
    }
    // Write the converted rusage (only meaningful when a child was reaped)
    if rusage_ptr != 0 && ret > 0 {
        let bytes = crate::syscall::linux_rusage_bytes(&usage);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), rusage_ptr as *mut u8, bytes.len());
        }
    }

    ret as u64
}

// ─── Futex emulation ────────────────────────────────────────────────────────

/// Set in fork children (for futex diagnostics).
static IS_FORK_CHILD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn is_fork_child() -> bool {
    IS_FORK_CHILD.load(std::sync::atomic::Ordering::Relaxed)
}

pub const FUTEX_WAIT: u32 = 0;
pub const FUTEX_WAKE: u32 = 1;
pub const FUTEX_WAIT_BITSET: u32 = 9;
pub const FUTEX_WAKE_BITSET: u32 = 10;
pub const FUTEX_PRIVATE_FLAG: u32 = 128;
pub const FUTEX_CLOCK_REALTIME: u32 = 256;
pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFF_FFFF;

struct FutexWaiter {
    condvar: Condvar,
    mutex: Mutex<bool>,  // true = woken
    bitset: u32,
}

struct FutexEntry {
    waiters: Mutex<Vec<Arc<FutexWaiter>>>,
}

// Simple global futex table
static FUTEX_TABLE: Mutex<Option<HashMap<u64, Arc<FutexEntry>>>> = Mutex::new(None);

fn get_futex(addr: u64) -> Arc<FutexEntry> {
    let mut table = FUTEX_TABLE.lock().unwrap();
    let table = table.get_or_insert_with(HashMap::new);
    table
        .entry(addr)
        .or_insert_with(|| Arc::new(FutexEntry {
            waiters: Mutex::new(Vec::new()),
        }))
        .clone()
}

/// Parse a Linux timespec from guest memory into a Duration.
fn parse_timeout(timeout_ptr: u64) -> Option<Duration> {
    if timeout_ptr == 0 {
        return None;
    }
    unsafe {
        let tv_sec = (timeout_ptr as *const i64).read_unaligned();
        let tv_nsec = ((timeout_ptr + 8) as *const i64).read_unaligned();
        if tv_sec < 0 || tv_nsec < 0 {
            return None;
        }
        Some(Duration::new(tv_sec as u64, tv_nsec as u32))
    }
}

pub fn do_futex(uaddr: u64, op: u32, val: u32, timeout_or_val2: u64, uaddr2: u64, val3: u32) -> u64 {
    let cmd = op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

    // Trace futex ops from fork children
    if IS_FORK_CHILD.load(Ordering::Relaxed) {
        let pid = unsafe { libc::getpid() };
        let tid = unsafe { libc::pthread_self() } as u64;
        let cur_val = unsafe { (uaddr as *const i32).read_volatile() };
        let guest_pc = crate::trap::LAST_SVC_PC.load(Ordering::Relaxed);
        let mut buf = [0u8; 250];
        let n = {
            use std::io::Write;
            let mut c = std::io::Cursor::new(&mut buf[..]);
            let _ = c.write_fmt(format_args!(
                "fakelinux: [{}] FUTEX op={} uaddr={:#x} val={} cur={} tid={:#x} pc={:#x}\n",
                pid, cmd, uaddr, val, cur_val, tid, guest_pc
            ));
            c.position() as usize
        };
        unsafe { libc::write(2, buf.as_ptr() as *const _, n); }
    }

    match cmd {
        FUTEX_WAIT => {
            futex_wait(uaddr, val, timeout_or_val2, FUTEX_BITSET_MATCH_ANY)
        }
        FUTEX_WAKE => {
            futex_wake(uaddr, val, FUTEX_BITSET_MATCH_ANY)
        }
        FUTEX_WAIT_BITSET => {
            futex_wait(uaddr, val, timeout_or_val2, val3)
        }
        FUTEX_WAKE_BITSET => {
            futex_wake(uaddr, val, val3)
        }
        _ => {
            let mut buf = [0u8; 80];
            let n = {
                use std::io::Write;
                let mut cursor = std::io::Cursor::new(&mut buf[..]);
                let _ = cursor.write_fmt(format_args!("fakelinux: unsupported futex op {} (cmd={})\n", op, cmd));
                cursor.position() as usize
            };
            unsafe { libc::write(2, buf.as_ptr() as *const _, n); }
            (-38_i64) as u64 // -ENOSYS
        }
    }
}

fn futex_wait(uaddr: u64, val: u32, timeout_ptr: u64, bitset: u32) -> u64 {
    // Check if *uaddr == val; if so, sleep until woken
    let current = unsafe { (uaddr as *const AtomicI32).as_ref().unwrap() };
    if current.load(Ordering::SeqCst) != val as i32 {
        return (-11_i64) as u64; // -EAGAIN (Linux value)
    }

    let timeout = parse_timeout(timeout_ptr);

    let entry = get_futex(uaddr);
    let waiter = Arc::new(FutexWaiter {
        condvar: Condvar::new(),
        mutex: Mutex::new(false),
        bitset,
    });

    // Add ourselves to the waiter list
    {
        let mut waiters = entry.waiters.lock().unwrap();
        // Re-check value after acquiring lock
        if current.load(Ordering::SeqCst) != val as i32 {
            return (-11_i64) as u64;
        }
        waiters.push(waiter.clone());
    }

    // Wait
    let guard = waiter.mutex.lock().unwrap();
    if *guard {
        // Already woken
        return 0;
    }

    match timeout {
        Some(dur) => {
            let result = waiter.condvar.wait_timeout(guard, dur).unwrap();
            if result.1.timed_out() && !*result.0 {
                // Remove ourselves from waiter list on timeout
                if let Ok(mut waiters) = entry.waiters.lock() {
                    waiters.retain(|w| !Arc::ptr_eq(w, &waiter));
                }
                return (-110_i64) as u64; // -ETIMEDOUT (Linux value)
            }
            0
        }
        None => {
            // Diagnostic: use a 3-second timeout to detect deadlocks.
            // A single-threaded forked child with an infinite futex_wait
            // will NEVER be woken — detect and log this.
            let result = waiter.condvar.wait_timeout(guard, Duration::from_secs(3)).unwrap();
            if result.1.timed_out() && !*result.0 {
                let pid = unsafe { libc::getpid() };
                let cur_val = current.load(Ordering::SeqCst);
                let guest_pc = crate::trap::LAST_SVC_PC.load(Ordering::Relaxed);
                let mut buf = [0u8; 250];
                let n = {
                    use std::io::Write;
                    let mut c = std::io::Cursor::new(&mut buf[..]);
                    let _ = c.write_fmt(format_args!(
                        "fakelinux: [{}] FUTEX_DEADLOCK uaddr={:#x} val={} cur={} pc={:#x} — aborting wait\n",
                        pid, uaddr, val, cur_val, guest_pc
                    ));
                    c.position() as usize
                };
                unsafe { libc::write(2, buf.as_ptr() as *const _, n); }
                // Remove ourselves from waiter list
                if let Ok(mut waiters) = entry.waiters.lock() {
                    waiters.retain(|w| !Arc::ptr_eq(w, &waiter));
                }
                return (-11_i64) as u64; // -EAGAIN to break out
            }
            0
        }
    }
}

fn futex_wake(uaddr: u64, max_wake: u32, bitset: u32) -> u64 {
    let entry = get_futex(uaddr);
    let mut waiters = entry.waiters.lock().unwrap();
    let num_waiters = waiters.len();
    let mut woken = 0u32;
    let mut remaining = Vec::new();

    for waiter in waiters.drain(..) {
        if woken >= max_wake {
            remaining.push(waiter);
            continue;
        }
        if waiter.bitset & bitset != 0 {
            let mut flag = waiter.mutex.lock().unwrap();
            *flag = true;
            waiter.condvar.notify_one();
            woken += 1;
        } else {
            remaining.push(waiter);
        }
    }
    *waiters = remaining;

    // Log wake results when there were waiters or when waking the deadlock addr
    if crate::syscall::trace_enabled() && (num_waiters > 0 || woken > 0) {
        let pid = unsafe { libc::getpid() };
        let mut buf = [0u8; 160];
        let n = {
            use std::io::Write;
            let mut c = std::io::Cursor::new(&mut buf[..]);
            let _ = c.write_fmt(format_args!(
                "fakelinux: [{}] FUTEX_WAKE_RESULT uaddr={:#x} waiters={} woken={}\n",
                pid, uaddr, num_waiters, woken
            ));
            c.position() as usize
        };
        unsafe { libc::write(2, buf.as_ptr() as *const _, n); }
    }

    woken as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    // Lifecycle of the saved-CLOEXEC mask across fork→(dup2/close)→exec.
    // Bug: fds with O_CLOEXEC (e.g. CPython subprocess's errpipe_write) had
    // the flag stripped before macOS fork and never re-applied at exec, so
    // they survived execve — parent blocked forever reading the errpipe
    // (py3compile pipe deadlock during dpkg --configure python3-minimal).
    #[test]
    fn cloexec_mask_exec_lifecycle() {
        let m = SavedCloexecMask::new();
        let mut bits = [false; 256];
        bits[5] = true;
        bits[7] = true;
        bits[13] = true;
        m.store_mask(&bits);
        // child dup2's a pipe over fd 7 → the saved bit refers to a dead
        // fd object and must be forgotten
        m.clear_fd(7);
        // child closes fd 13 → forgotten
        m.clear_fd(13);
        // at exec time, only fd 5 still needs FD_CLOEXEC re-applied
        assert_eq!(m.drain_pending(), vec![5]);
        // drain is one-shot: a second exec re-applies nothing
        assert!(m.drain_pending().is_empty());
    }

    #[test]
    fn cloexec_mask_take_consumes() {
        let m = SavedCloexecMask::new();
        let mut bits = [false; 256];
        bits[9] = true;
        m.store_mask(&bits);
        assert!(m.take(9));
        assert!(!m.take(9));
        assert!(m.drain_pending().is_empty());
    }
}
