//! Simplified virtual PID namespace for container mode (--container).
//!
//! Only PID 1 is virtualized: the init process (launched with --container)
//! reports getpid()=1. All other processes use their real macOS PID.
//! This allows host tools (ps, lsof) to directly inspect container processes
//! while still providing the PID 1 semantics that many programs expect.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Whether container mode is active.
pub static CONTAINER_MODE: AtomicBool = AtomicBool::new(false);

/// The real macOS PID of the init process (the one that gets vpid=1).
static INIT_REAL_PID: AtomicI32 = AtomicI32::new(0);

/// Whether this process IS the init process (vpid=1).
static IS_INIT: AtomicBool = AtomicBool::new(false);

// ─── Public API ──────────────────────────────────────────────────────────────

/// Create a new container namespace. Called when --container is passed.
/// The current process becomes PID 1.
pub fn init_container() {
    let real_pid = unsafe { libc::getpid() };
    INIT_REAL_PID.store(real_pid, Ordering::SeqCst);
    IS_INIT.store(true, Ordering::SeqCst);
    CONTAINER_MODE.store(true, Ordering::SeqCst);

    // Set env var so children know the init's real PID
    std::env::set_var("FAKELINUX_CONTAINER", "1");
    std::env::set_var("FAKELINUX_INIT_PID", real_pid.to_string());
}

/// Attach to an existing container namespace. Called when FAKELINUX_CONTAINER
/// env var is detected on startup (non-init child process after execve).
pub fn attach_container(init_pid: i32) {
    INIT_REAL_PID.store(init_pid, Ordering::SeqCst);
    IS_INIT.store(false, Ordering::SeqCst);
    CONTAINER_MODE.store(true, Ordering::SeqCst);
}

/// Get the virtual PID for the current process.
/// Returns 1 for init, real PID for everything else.
pub fn current_vpid() -> i32 {
    if IS_INIT.load(Ordering::Relaxed) {
        1
    } else {
        unsafe { libc::getpid() }
    }
}

/// Get the virtual PPID for the current process.
/// Returns 1 if parent is init, 0 if we ARE init, else real PPID.
pub fn current_vppid() -> i32 {
    if IS_INIT.load(Ordering::Relaxed) {
        0 // init's parent is PID 0
    } else {
        let real_ppid = unsafe { libc::getppid() };
        if real_ppid == INIT_REAL_PID.load(Ordering::Relaxed) {
            1
        } else {
            real_ppid
        }
    }
}

/// Translate a virtual PID to a real PID.
/// PID 1 → init's real PID; everything else passes through.
pub fn virtual_to_real(vpid: i32) -> Option<i32> {
    if vpid == 1 {
        let init = INIT_REAL_PID.load(Ordering::Relaxed);
        if init != 0 { Some(init) } else { None }
    } else if vpid > 0 {
        Some(vpid)
    } else {
        None
    }
}

/// Translate a real PID to a virtual PID.
/// Init's real PID → 1; everything else passes through.
pub fn real_to_virtual(real_pid: i32) -> Option<i32> {
    if real_pid == INIT_REAL_PID.load(Ordering::Relaxed) {
        Some(1)
    } else if real_pid > 0 {
        Some(real_pid)
    } else {
        None
    }
}

/// Translate a virtual PID argument from a syscall to a real PID.
/// Special values: -1 (any child), 0 (same process group), positive vpid.
pub fn translate_pid_arg(vpid: i32) -> i32 {
    match vpid {
        -1 => -1,
        0 => 0,
        1 => INIT_REAL_PID.load(Ordering::Relaxed),
        p if p > 0 => p, // already real
        neg => neg,       // negative pgid, pass through
    }
}

/// Set env vars for a child about to execve, so re-exec'd fakelinux can attach.
/// With simplified PIDs, we only need to propagate the init PID.
pub fn set_child_env() {
    let init_pid = INIT_REAL_PID.load(Ordering::Relaxed);
    std::env::set_var("FAKELINUX_INIT_PID", init_pid.to_string());
}

/// No-op for compatibility — parent env doesn't need restoring
/// since we no longer change FAKELINUX_VPID before fork.
pub fn restore_parent_env() {
    // Nothing to do in simplified PID scheme
}

/// Mark exit. No shared state to clean up with simplified scheme.
pub fn on_exit() {
    // Nothing to do — no shared memory to clean up
}

/// Get the init process's real PID.
pub fn init_real_pid() -> i32 {
    INIT_REAL_PID.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simplified_pid_namespace() {
        let real_pid = unsafe { libc::getpid() };

        // Init this process as container init
        init_container();
        assert!(CONTAINER_MODE.load(Ordering::SeqCst));
        assert_eq!(current_vpid(), 1);
        assert_eq!(current_vppid(), 0);

        // PID 1 maps to our real PID
        assert_eq!(virtual_to_real(1), Some(real_pid));
        assert_eq!(real_to_virtual(real_pid), Some(1));

        // Other PIDs pass through
        assert_eq!(virtual_to_real(42), Some(42));
        assert_eq!(real_to_virtual(42), Some(42));

        // translate_pid_arg
        assert_eq!(translate_pid_arg(-1), -1);
        assert_eq!(translate_pid_arg(0), 0);
        assert_eq!(translate_pid_arg(1), real_pid);
        assert_eq!(translate_pid_arg(42), 42);

        on_exit();
    }
}
