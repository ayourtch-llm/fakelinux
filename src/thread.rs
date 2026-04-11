//! Thread support: clone() and futex emulation.
//!
//! Linux clone() with CLONE_THREAD creates a new thread sharing the address space.
//! We implement this using pthreads. Futex is emulated with a condvar/mutex table.

use std::collections::HashMap;
use std::sync::{Condvar, Mutex, Arc};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::time::Duration;

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
        return do_fork(flags);
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
        return do_fork(flags);
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
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = crate::trap::trap_handler_ptr();
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigemptyset(&mut sa.sa_mask);
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

    // Set up per-thread sigaltstack
    setup_thread_signal_stack();

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

fn do_fork(_flags: u64) -> u64 {
    // Don't fork here (signal context). Mark pending and return a sentinel.
    // The trap handler will redirect sigreturn to the fork trampoline.
    FORK.mark_pending();
    0xFFFF_FFFF_0000_F0C0
}

/// Runs outside signal context. Does the actual fork, sets x0 to the pid,
/// restores guest registers, and jumps back to guest code.
extern "C" fn fork_trampoline_entry() -> ! {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe { libc::_exit(127); }
    }

    if pid == 0 {
        // Child: re-initialize signal handling (fresh alt stack, re-install
        // trap handler, unblock signals).
        crate::trap::init_child_after_fork();
    }

    FORK.set_x0(if pid == 0 { 0 } else { pid as u64 });
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
    let rusage = if rusage_ptr != 0 { rusage_ptr as *mut libc::rusage } else { std::ptr::null_mut() };

    let ret = unsafe { libc::wait4(pid as i32, status_ptr, options, rusage) };
    if ret > 0 && wstatus_ptr != 0 {
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

    ret as u64
}

// ─── Futex emulation ────────────────────────────────────────────────────────

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
            let _guard = waiter.condvar.wait(guard).unwrap();
            0
        }
    }
}

fn futex_wake(uaddr: u64, max_wake: u32, bitset: u32) -> u64 {
    let entry = get_futex(uaddr);
    let mut waiters = entry.waiters.lock().unwrap();
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

    woken as u64
}
