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

// ─── Pure decision logic (unit-testable, no globals / no syscalls) ───────────

/// The vpid implied by the IS_INIT flag — what getpid() returns.
fn vpid_from_init_flag(is_init: bool, real_pid: i32) -> i32 {
    if is_init {
        1
    } else {
        real_pid
    }
}

/// The vpid implied by the real→virtual mapping — what getpgid()/tcgetpgrp()
/// report. Returns None for invalid pids.
fn vpid_from_mapping(real_pid: i32, init_real_pid: i32) -> Option<i32> {
    if real_pid == init_real_pid {
        Some(1)
    } else if real_pid > 0 {
        Some(real_pid)
    } else {
        None
    }
}

/// Whether a process re-entering attach_container is itself the init re-execing
/// (exec keeps the same real pid), as opposed to a child attaching to the ns.
fn is_reexec_init(my_real_pid: i32, init_pid: i32) -> bool {
    my_real_pid == init_pid
}

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
    // The init process re-execs (e.g. a login shell `exec`ing the interactive
    // shell) and re-enters here — exec keeps the same real pid, so if our pid is
    // the init pid we ARE still vpid 1. Marking us a child would make getpid()
    // return the real pid while real_to_virtual()/tcgetpgrp() still map it to 1,
    // and that getpid-vs-getpgid inconsistency breaks bash job control
    // (tcsetpgrp sets real pid, tcgetpgrp reads back 1, mismatch -> "no job
    // control in this shell").
    let am_init = is_reexec_init(unsafe { libc::getpid() }, init_pid);
    IS_INIT.store(am_init, Ordering::SeqCst);
    CONTAINER_MODE.store(true, Ordering::SeqCst);
}

/// Called in a fork child. Only the single init process is vpid 1; a fork child
/// is not. The IS_INIT flag is inherited via copy-on-write from the parent, so
/// clear it — otherwise the child's getpid() also returns 1, colliding with init
/// and breaking setpgid()/job control of children ("child setpgid (1 to 1): No
/// such process"). INIT_REAL_PID/CONTAINER_MODE stay (the child is still in the
/// namespace).
pub fn clear_init_after_fork() {
    IS_INIT.store(false, Ordering::SeqCst);
}

/// Get the virtual PID for the current process.
/// Returns 1 for init, real PID for everything else.
pub fn current_vpid() -> i32 {
    vpid_from_init_flag(IS_INIT.load(Ordering::Relaxed), unsafe { libc::getpid() })
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
    vpid_from_mapping(real_pid, INIT_REAL_PID.load(Ordering::Relaxed))
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

    // The job-control bug: getpid() (derived from IS_INIT) and getpgid()/
    // tcgetpgrp() (derived from the real→virtual mapping) MUST report the same
    // vpid for a given process. If they disagree, bash sets the terminal's
    // foreground group to one value and reads back another → "no job control in
    // this shell". These tests pin the invariant on the pure decision logic, so
    // they need no rootfs and are parallel-safe (no globals touched).

    #[test]
    fn reexec_init_is_vpid1_consistently() {
        // The init re-execs (exec keeps the same real pid): it stays vpid 1, and
        // BOTH derivations must agree. This is exactly the case the old code got
        // wrong (it marked the re-exec'd init as a child → getpid()=real, but
        // tcgetpgrp() still mapped it to 1).
        let init = 81180;
        let is_init = is_reexec_init(init, init);
        assert!(is_init);
        assert_eq!(vpid_from_init_flag(is_init, init), 1);
        assert_eq!(vpid_from_mapping(init, init), Some(1));
        assert_eq!(
            Some(vpid_from_init_flag(is_init, init)),
            vpid_from_mapping(init, init),
            "getpid() and getpgid()/tcgetpgrp() must agree for the init"
        );
    }

    #[test]
    fn fork_child_is_not_vpid1() {
        // A child (different real pid) is not the init: both derivations give the
        // child's own pid, not 1 — so setpgid() of children doesn't collide on 1.
        let init = 81180;
        let child = 81200;
        let is_init = is_reexec_init(child, init);
        assert!(!is_init);
        assert_eq!(vpid_from_init_flag(is_init, child), child);
        assert_eq!(vpid_from_mapping(child, init), Some(child));
    }

    #[test]
    fn vpid_derivations_always_agree() {
        // For any (real_pid, init_pid), the IS_INIT-derived vpid must equal the
        // mapping-derived vpid. This is THE invariant whose violation broke job
        // control.
        for &(real_pid, init_pid) in &[
            (1, 1),
            (81180, 81180), // init, re-exec
            (81200, 81180), // child
            (5, 9),         // unrelated child
            (12345, 12345), // some other init
        ] {
            let is_init = is_reexec_init(real_pid, init_pid);
            assert_eq!(
                Some(vpid_from_init_flag(is_init, real_pid)),
                vpid_from_mapping(real_pid, init_pid),
                "vpid inconsistency for real_pid={real_pid} init_pid={init_pid}"
            );
        }
    }
}
