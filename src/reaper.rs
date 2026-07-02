//! PR_SET_CHILD_SUBREAPER emulation.
//!
//! conmon daemonizes, marks itself a child subreaper, spawns crun, and crun
//! double-forks the container init and exits — on Linux the orphaned init
//! reparents to conmon, whose waitpid(-1, WNOHANG) loop then reaps it and
//! learns the container's real exit status. macOS has no subreaper: orphans
//! reparent to launchd and conmon writes exit code -1 ("cannot be
//! determined", podman reports 255).
//!
//! Every guest process is a fakelinux supervisor, so we emulate the reparent:
//! - prctl(PR_SET_CHILD_SUBREAPER, 1) records the flag here (and returns 0).
//! - Descendants learn their nearest subreaper ancestor: fork children of a
//!   subreaper record the parent pid; execve carries it via the
//!   FAKELINUX_SUBREAPER env var (a dynamic exec key).
//! - On exit_group, a process with a subreaper ancestor publishes its wstatus
//!   to `<root>/tmp/.flx-reap/<subreaper_pid>/<my_pid>` and sends the
//!   subreaper a SIGCHLD.
//! - wait4() in the subreaper, after the real waitpid finds nothing, consumes
//!   a registry entry and returns it as if a child had been reaped.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// This process called prctl(PR_SET_CHILD_SUBREAPER, 1).
/// Linux: the attribute is per-process and NOT inherited by fork children.
static IS_SUBREAPER: AtomicBool = AtomicBool::new(false);

/// Real pid of the nearest subreaper ancestor (0 = none).
static SUBREAPER_ANCESTOR: AtomicI32 = AtomicI32::new(0);

pub fn set_subreaper(on: bool) {
    IS_SUBREAPER.store(on, Ordering::Relaxed);
    if crate::net::unix_trace_enabled() {
        crate::syscall::raw_eprintln_fmt(format_args!(
            "fakelinux: [{}] REAP subreaper={}\n", unsafe { libc::getpid() }, on));
    }
}

pub fn is_subreaper() -> bool {
    IS_SUBREAPER.load(Ordering::Relaxed)
}

/// Read FAKELINUX_SUBREAPER at supervisor startup (post-execve).
pub fn init_from_env() {
    if let Ok(v) = std::env::var("FAKELINUX_SUBREAPER") {
        if let Ok(pid) = v.parse::<i32>() {
            SUBREAPER_ANCESTOR.store(pid, Ordering::Relaxed);
        }
    }
}

/// Value for the FAKELINUX_SUBREAPER dynamic exec key: my own pid if I am a
/// subreaper (exec keeps the pid, so the exec'd image still reparents to us —
/// and our children exec too, inheriting the right ancestor), else the
/// inherited ancestor.
pub fn exec_env_value() -> Option<String> {
    if is_subreaper() {
        return Some(unsafe { libc::getpid() }.to_string());
    }
    let a = SUBREAPER_ANCESTOR.load(Ordering::Relaxed);
    if a > 0 { Some(a.to_string()) } else { None }
}

/// Fork-child bookkeeping: the subreaper flag is not inherited; the child's
/// nearest subreaper is the parent itself when the parent was one.
pub fn on_fork_child() {
    if IS_SUBREAPER.swap(false, Ordering::Relaxed) {
        SUBREAPER_ANCESTOR.store(unsafe { libc::getppid() }, Ordering::Relaxed);
    }
}

/// Host-side registry dir for a given subreaper pid.
fn reap_dir(subreaper: i32) -> std::path::PathBuf {
    let base = crate::rootfs::get_root().unwrap_or("/tmp");
    std::path::PathBuf::from(format!("{}/tmp/.flx-reap/{}", base, subreaper))
}

/// Publish this process's wstatus for its subreaper ancestor (no-op without
/// one) and poke the subreaper with SIGCHLD so its reap loop runs.
pub fn publish_exit(wstatus: i32) {
    let anc = SUBREAPER_ANCESTOR.load(Ordering::Relaxed);
    if anc <= 0 {
        return;
    }
    let dir = reap_dir(anc);
    let _ = std::fs::create_dir_all(&dir);
    let me = unsafe { libc::getpid() };
    let _ = std::fs::write(dir.join(me.to_string()), wstatus.to_string());
    if crate::net::unix_trace_enabled() {
        crate::syscall::raw_eprintln_fmt(format_args!(
            "fakelinux: [{}] REAP publish anc={} wstatus={:#x}\n", me, anc, wstatus));
    }
    unsafe { libc::kill(anc, libc::SIGCHLD) };
}

/// Consume one published exit matching `pid` (-1 = any) from this process's
/// registry. Returns (child_pid, wstatus). Only meaningful for subreapers.
pub fn try_reap(pid: i64) -> Option<(i32, i32)> {
    if !is_subreaper() {
        return None;
    }
    let dir = reap_dir(unsafe { libc::getpid() });
    let entries = std::fs::read_dir(&dir).ok()?;
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(child) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        if pid > 0 && child != pid as i32 {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(e.path()) else { continue };
        let Ok(wstatus) = body.trim().parse::<i32>() else { continue };
        let _ = std::fs::remove_file(e.path());
        if crate::net::unix_trace_enabled() {
            crate::syscall::raw_eprintln_fmt(format_args!(
                "fakelinux: [{}] REAP consume child={} wstatus={:#x}\n",
                unsafe { libc::getpid() }, child, wstatus));
        }
        return Some((child, wstatus));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_and_reap_round_trip() {
        // Simulate: this process is both the exiting child (ancestor = self)
        // and the subreaper consuming the record.
        let me = unsafe { libc::getpid() };
        SUBREAPER_ANCESTOR.store(me, Ordering::Relaxed);
        set_subreaper(true);
        publish_exit(7 << 8);
        let (child, st) = try_reap(-1).expect("registry entry");
        assert_eq!(child, me);
        assert_eq!(st, 7 << 8);
        assert!(try_reap(-1).is_none(), "entry must be consumed");
        // Specific-pid filter: publish again, ask for a different pid.
        publish_exit(3 << 8);
        assert!(try_reap((me + 1) as i64).is_none());
        assert_eq!(try_reap(me as i64), Some((me, 3 << 8)));
        set_subreaper(false);
        SUBREAPER_ANCESTOR.store(0, Ordering::Relaxed);
    }

    #[test]
    fn fork_child_semantics() {
        set_subreaper(true);
        on_fork_child();
        assert!(!is_subreaper(), "flag not inherited by fork children");
        assert_eq!(
            SUBREAPER_ANCESTOR.load(Ordering::Relaxed),
            unsafe { libc::getppid() },
            "child's nearest subreaper is the forking parent"
        );
        SUBREAPER_ANCESTOR.store(0, Ordering::Relaxed);
    }
}
