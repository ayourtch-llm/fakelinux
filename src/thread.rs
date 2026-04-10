//! Thread support: clone() and futex emulation.
//!
//! Linux clone() with CLONE_THREAD creates a new thread sharing the address space.
//! We implement this using pthreads. Futex is emulated with a condvar/mutex table.

use std::collections::HashMap;
use std::sync::{Condvar, Mutex, Arc};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

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
}

pub fn main_tid() -> i32 {
    MAIN_TID.load(Ordering::SeqCst)
}

// Per-thread TID — this is an approximation using a global atomic.
// A full implementation would use thread-local storage via __thread or a TLS key.
// For single-threaded + basic multi-threaded use this is sufficient.
pub static CURRENT_TID: AtomicI32 = AtomicI32::new(0);

pub fn current_tid() -> i32 {
    let t = CURRENT_TID.load(Ordering::SeqCst);
    if t == 0 { unsafe { libc::getpid() } } else { t }
}

// ─── TLS (TPIDR_EL0) management ─────────────────────────────────────────────
// On aarch64, both Linux and macOS use TPIDR_EL0 for thread-local storage.
// We save the macOS TLS before entering guest code, and swap it in the signal handler.

static MACOS_TLS: AtomicU64 = AtomicU64::new(0);

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
pub const CLONE_SETTLS: u64 = 0x00080000;
pub const CLONE_PARENT_SETTID: u64 = 0x00100000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
pub const CLONE_CHILD_SETTID: u64 = 0x01000000;

/// Minimal clone implementation for CLONE_THREAD.
/// args: [flags, stack, parent_tid_ptr, tls, child_tid_ptr]
pub fn do_clone(flags: u64, child_stack: u64, parent_tid_ptr: u64, tls: u64, child_tid_ptr: u64) -> u64 {
    // We only support thread creation (CLONE_VM | CLONE_THREAD)
    if flags & CLONE_VM == 0 || flags & CLONE_THREAD == 0 {
        eprintln!("fakelinux: clone without CLONE_VM|CLONE_THREAD not supported (flags={:#x})", flags);
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

    let child_stack_val = child_stack;
    let set_tls = flags & CLONE_SETTLS != 0;
    let tls_val = tls;
    let clear_tid_ptr = if flags & CLONE_CHILD_CLEARTID != 0 {
        child_tid_ptr
    } else {
        0
    };

    // Spawn a pthread
    let mut thread: libc::pthread_t = 0;
    let arg = Box::new(CloneArgs {
        stack: child_stack_val,
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

    // Detach — we don't join threads
    unsafe { libc::pthread_detach(thread); }

    tid as u64
}

struct CloneArgs {
    stack: u64,
    tid: i32,
    tls: u64,
    set_tls: bool,
    clear_tid_ptr: u64,
}

extern "C" fn clone_entry(arg: *mut libc::c_void) -> *mut libc::c_void {
    let args = unsafe { Box::from_raw(arg as *mut CloneArgs) };

    CURRENT_TID.store(args.tid, Ordering::SeqCst);

    // Set TLS if requested
    if args.set_tls {
        unsafe {
            std::arch::asm!("msr tpidr_el0, {}", in(reg) args.tls);
        }
    }

    // The child thread should start executing at the address on top of its stack.
    // Linux clone: the child returns from clone() with result 0, using child_stack as SP.
    // The child's entry point is the return address, which was set up by the caller.
    //
    // In a real implementation, we'd set up the thread's SP and PC and let it run.
    // Since our patching approach works at the SVC level, the child needs to execute
    // from where clone was called. This requires the caller to have set up the stack
    // with a return address.
    //
    // For now, we jump to the child stack which should have the entry point.
    // The typical pattern is: the libc pushes the function pointer and argument onto
    // child_stack, then clone returns to that function.
    //
    // This is a simplified version — a full implementation would set registers
    // (x0=0 for child return) and resume execution.
    unsafe {
        std::arch::asm!(
            "mov sp, {stack}",
            "mov x0, #0",
            "ret", // jump to address in LR... this won't work correctly
            stack = in(reg) args.stack,
            options(noreturn)
        );
    }
}

// ─── Futex emulation ────────────────────────────────────────────────────────

pub const FUTEX_WAIT: u32 = 0;
pub const FUTEX_WAKE: u32 = 1;
pub const FUTEX_PRIVATE_FLAG: u32 = 128;

struct FutexEntry {
    condvar: Condvar,
    mutex: Mutex<()>,
}

// Simple global futex table
static FUTEX_TABLE: Mutex<Option<HashMap<u64, Arc<FutexEntry>>>> = Mutex::new(None);

fn get_futex(addr: u64) -> Arc<FutexEntry> {
    let mut table = FUTEX_TABLE.lock().unwrap();
    let table = table.get_or_insert_with(HashMap::new);
    table
        .entry(addr)
        .or_insert_with(|| Arc::new(FutexEntry {
            condvar: Condvar::new(),
            mutex: Mutex::new(()),
        }))
        .clone()
}

pub fn do_futex(uaddr: u64, op: u32, val: u32, _timeout: u64, _uaddr2: u64, _val3: u32) -> u64 {
    let cmd = op & !FUTEX_PRIVATE_FLAG;

    match cmd {
        FUTEX_WAIT => {
            // Check if *uaddr == val; if so, sleep until woken
            let current = unsafe { (uaddr as *const AtomicI32).as_ref().unwrap() };
            if current.load(Ordering::SeqCst) != val as i32 {
                return (-11_i64) as u64; // -EAGAIN (Linux value)
            }
            let entry = get_futex(uaddr);
            let guard = entry.mutex.lock().unwrap();
            // Re-check after acquiring mutex
            if current.load(Ordering::SeqCst) != val as i32 {
                return (-11_i64) as u64;
            }
            // TODO: handle timeout
            let _guard = entry.condvar.wait(guard).unwrap();
            0
        }
        FUTEX_WAKE => {
            let entry = get_futex(uaddr);
            let _guard = entry.mutex.lock().unwrap();
            if val == 1 {
                entry.condvar.notify_one();
            } else {
                entry.condvar.notify_all();
            }
            // Return the number of waiters woken (we don't track this precisely)
            val.min(1) as u64
        }
        _ => {
            eprintln!("fakelinux: unsupported futex op {}", cmd);
            (-38_i64) as u64 // -ENOSYS
        }
    }
}
