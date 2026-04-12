use crate::creds;
use crate::epoll;
use crate::eventfd;
use crate::linux::*;
use crate::loader;
use crate::net;
use crate::pidns;
use crate::procfs;
use crate::rootfs;
use crate::signal;
use crate::thread;
use crate::translate;
use crate::trap::MContext64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// Sysroot path for path translation (set once at startup from FAKELINUX_SYSROOT).
static SYSROOT: OnceLock<String> = OnceLock::new();

/// Initialize the sysroot from the environment variable.
pub fn init_sysroot(sysroot: &str) {
    if !sysroot.is_empty() {
        // Strip trailing slash if present
        let s = sysroot.trim_end_matches('/');
        let _ = SYSROOT.set(s.to_string());
    }
}

fn get_sysroot() -> Option<&'static str> {
    SYSROOT.get().map(|s| s.as_str())
}

/// Translate a guest path pointer through the rootfs layer.
/// Returns Some(CString) with the translated path if translation applies,
/// or None if the original path should be used as-is.
fn translate_guest_path(path_ptr: u64) -> Option<std::ffi::CString> {
    let path = unsafe { std::ffi::CStr::from_ptr(path_ptr as *const i8) };
    rootfs::translate_path(path.to_bytes())
        .map(|v| unsafe { std::ffi::CString::from_vec_with_nul_unchecked(v) })
}

/// Get the effective path pointer: translated if rootfs applies, otherwise original.
fn effective_path_ptr(path_ptr: u64) -> (*const i8, Option<std::ffi::CString>) {
    if let Some(translated) = translate_guest_path(path_ptr) {
        let ptr = translated.as_ptr();
        (ptr, Some(translated))
    } else {
        (path_ptr as *const i8, None)
    }
}

/// Write a diagnostic message to stderr using raw write() — safe after fork.
/// eprintln! uses Rust's Mutex<Stderr> which deadlocks in forked children.
fn raw_eprintln(msg: &str) {
    unsafe { libc::write(2, msg.as_ptr() as *const _, msg.len()); }
}

fn raw_eprintln_fmt(args: std::fmt::Arguments) {
    use std::io::Write;
    let mut buf = [0u8; 256];
    let mut cursor = std::io::Cursor::new(&mut buf[..]);
    let _ = cursor.write_fmt(args);
    let pos = cursor.position() as usize;
    unsafe { libc::write(2, buf.as_ptr() as *const _, pos); }
}

/// Current program break (heap end), set by the loader after mapping segments.
pub static BRK_CURRENT: AtomicU64 = AtomicU64::new(0);

/// Enable syscall tracing via FAKELINUX_TRACE=1
static TRACE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_trace(on: bool) {
    TRACE.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Emulate a single Linux aarch64 syscall. Returns the result value for x0.
pub fn emulate(nr: u64, args: &[u64; 6], _mctx: &mut MContext64) -> u64 {
    let trace = TRACE.load(std::sync::atomic::Ordering::Relaxed);
    if trace {
        raw_eprintln_fmt(format_args!(
            "fakelinux: syscall {} (x0={:#x} x1={:#x} x2={:#x} x3={:#x} x4={:#x} x5={:#x})\n",
            nr, args[0], args[1], args[2], args[3], args[4], args[5]
        ));
    }
    let result = emulate_inner(nr, args, _mctx);
    if trace {
        raw_eprintln_fmt(format_args!("fakelinux:   → {:#x} ({})\n", result, result as i64));
    }
    result
}

fn emulate_inner(nr: u64, args: &[u64; 6], _mctx: &mut MContext64) -> u64 {
    match nr {
        SYS_WRITE => do_write(args[0], args[1], args[2]),
        SYS_READ => do_read(args[0], args[1], args[2]),
        SYS_OPENAT => do_openat(args[0] as i32, args[1], args[2] as i32, args[3] as u32),
        SYS_CLOSE => do_close(args[0] as i32),
        SYS_LSEEK => do_lseek(args[0] as i32, args[1] as i64, args[2] as i32),
        SYS_FSTAT => do_fstat(args[0] as i32, args[1]),
        SYS_NEWFSTATAT => do_newfstatat(args[0] as i32, args[1], args[2], args[3] as i32),
        SYS_EXIT_GROUP => unsafe { libc::_exit(args[0] as i32) },
        SYS_EXIT => {
            // SYS_EXIT only terminates the calling thread, not the whole process.
            // If this is the main thread (or there's only one thread), it acts like exit_group.
            // For child threads, call thread_exit() which does CLEARTID + pthread_exit.
            if thread::current_tid() == thread::main_tid() {
                unsafe { libc::_exit(args[0] as i32) }
            } else {
                thread::thread_exit(args[0] as i32);
            }
        }
        SYS_BRK => do_brk(args[0]),
        SYS_MMAP => do_mmap(args[0], args[1], args[2], args[3], args[4] as i32, args[5]),
        SYS_MUNMAP => do_munmap(args[0], args[1]),
        SYS_MPROTECT => do_mprotect(args[0], args[1], args[2]),
        SYS_MADVISE => 0,
        SYS_GETPID => {
            if pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                pidns::current_vpid() as u64
            } else {
                unsafe { libc::getpid() as u64 }
            }
        }
        SYS_GETPPID => {
            if pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                pidns::current_vppid() as u64
            } else {
                unsafe { libc::getppid() as u64 }
            }
        }
        SYS_GETUID => creds::do_getuid(),
        SYS_GETEUID => creds::do_geteuid(),
        SYS_GETGID => creds::do_getgid(),
        SYS_GETEGID => creds::do_getegid(),
        SYS_GETTID => thread::current_tid() as u64,
        SYS_SET_TID_ADDRESS => thread::do_set_tid_address(args[0]),
        SYS_SET_ROBUST_LIST => 0,
        SYS_RT_SIGACTION => signal::do_rt_sigaction(args[0], args[1], args[2], args[3]),
        SYS_RT_SIGPROCMASK => signal::do_rt_sigprocmask(args[0], args[1], args[2], args[3]),
        SYS_RT_SIGRETURN => {
            // rt_sigreturn restores ALL registers from the sigframe on the stack.
            // It does NOT return a value in x0. We restore directly into _mctx
            // and return a sentinel so the trap handler knows not to overwrite.
            if unsafe { signal::do_rt_sigreturn(_mctx) } {
                signal::SIGRETURN_SENTINEL
            } else {
                (-22_i64) as u64 // -EINVAL if sigframe is invalid
            }
        }
        SYS_CLOCK_GETTIME => do_clock_gettime(args[0] as i32, args[1]),
        SYS_UNAME => do_uname(args[0]),
        SYS_GETRANDOM => do_getrandom(args[0], args[1], args[2] as u32),
        SYS_PRLIMIT64 => do_prlimit64(args[0], args[1] as i32, args[2], args[3]),
        SYS_RSEQ => (-38_i64) as u64, // ENOSYS
        SYS_CLONE3 => (-38_i64) as u64, // ENOSYS — force fallback to clone
        SYS_CLOSE_RANGE => do_close_range(args[0] as u32, args[1] as u32, args[2] as u32),
        SYS_FACCESSAT2 => do_faccessat(args[0] as i32, args[1], args[2] as i32, args[3] as i32),
        SYS_SCHED_SETSCHEDULER => 0, // stub success
        SYS_SCHED_SETAFFINITY => 0, // stub success
        SYS_SCHED_GETAFFINITY => do_sched_getaffinity(args[0] as i32, args[1] as u32, args[2]),
        SYS_PSELECT6 => do_pselect6(args[0] as i32, args[1], args[2], args[3], args[4], args[5]),
        SYS_PRCTL => do_prctl(args[0] as i32, args[1], args[2], args[3], args[4]),
        SYS_SYSINFO => do_sysinfo(args[0]),
        SYS_GETRUSAGE => do_getrusage(args[0] as i32, args[1]),
        SYS_SCHED_YIELD => { unsafe { libc::sched_yield(); } 0 }
        SYS_READLINKAT => do_readlinkat(args[0] as i32, args[1], args[2], args[3]),
        SYS_IOCTL => do_ioctl(args[0] as i32, args[1], args[2]),
        SYS_FCNTL => do_fcntl(args[0] as i32, args[1] as i32, args[2]),
        SYS_WRITEV => do_writev(args[0], args[1], args[2]),
        SYS_READV => do_readv(args[0], args[1], args[2]),
        SYS_PREAD64 => do_pread64(args[0] as i32, args[1], args[2], args[3] as i64),
        SYS_PWRITE64 => do_pwrite64(args[0] as i32, args[1], args[2], args[3] as i64),
        SYS_STATX => do_statx(args[0] as i32, args[1], args[2] as i32, args[3] as u32, args[4]),
        SYS_FACCESSAT => do_faccessat(args[0] as i32, args[1], args[2] as i32, args[3] as i32),
        SYS_CLONE => thread::do_clone_with_regs(args[0], args[1], args[2], args[3], args[4], &_mctx.ss),
        SYS_FUTEX => thread::do_futex(args[0], args[1] as u32, args[2] as u32, args[3], args[4], args[5] as u32),
        SYS_DUP => do_dup(args[0] as i32),
        SYS_DUP3 => do_dup3(args[0] as i32, args[1] as i32, args[2] as i32),
        SYS_PIPE2 => do_pipe2(args[0], args[1] as i32),
        SYS_GETDENTS64 => {
            // Check if this is a virtual /proc directory fd
            if let Some(n) = procfs::try_getdents64(args[0] as i32, args[1], args[2]) {
                n
            } else {
                do_getdents64(args[0] as i32, args[1], args[2])
            }
        }
        SYS_PPOLL => do_ppoll(args[0], args[1] as u32, args[2], args[3], args[4]),
        SYS_EVENTFD2 => eventfd::do_eventfd2(args[0] as u32, args[1] as i32),
        SYS_EPOLL_CREATE1 => epoll::do_epoll_create1(args[0] as i32),
        SYS_EPOLL_CTL => epoll::do_epoll_ctl(args[0] as i32, args[1] as i32, args[2] as i32, args[3]),
        SYS_EPOLL_PWAIT => epoll::do_epoll_pwait(args[0] as i32, args[1], args[2] as i32, args[3] as i32),
        SYS_SOCKET => net::do_socket(args[0] as i32, args[1] as i32, args[2] as i32),
        SYS_SOCKETPAIR => net::do_socketpair(args[0] as i32, args[1] as i32, args[2] as i32, args[3]),
        SYS_BIND => net::do_bind(args[0] as i32, args[1], args[2] as u32),
        SYS_LISTEN => net::do_listen(args[0] as i32, args[1] as i32),
        SYS_ACCEPT => net::do_accept4(args[0] as i32, args[1], args[2], 0),
        SYS_ACCEPT4 => net::do_accept4(args[0] as i32, args[1], args[2], args[3] as i32),
        SYS_CONNECT => net::do_connect(args[0] as i32, args[1], args[2] as u32),
        SYS_GETSOCKNAME => net::do_getsockname(args[0] as i32, args[1], args[2]),
        SYS_GETPEERNAME => net::do_getpeername(args[0] as i32, args[1], args[2]),
        SYS_SENDTO => net::do_sendto(args[0] as i32, args[1], args[2], args[3] as i32, args[4], args[5] as u32),
        SYS_RECVFROM => net::do_recvfrom(args[0] as i32, args[1], args[2], args[3] as i32, args[4], args[5]),
        SYS_SETSOCKOPT => net::do_setsockopt(args[0] as i32, args[1] as i32, args[2] as i32, args[3], args[4] as u32),
        SYS_GETSOCKOPT => net::do_getsockopt(args[0] as i32, args[1] as i32, args[2] as i32, args[3], args[4]),
        SYS_SHUTDOWN => net::do_shutdown(args[0] as i32, args[1] as i32),
        SYS_SENDMSG => net::do_sendmsg(args[0] as i32, args[1], args[2] as i32),
        SYS_SENDMMSG => net::do_sendmmsg(args[0] as i32, args[1], args[2] as u32, args[3] as i32),
        SYS_RECVMSG => net::do_recvmsg(args[0] as i32, args[1], args[2] as i32),
        SYS_KILL => {
            let pid_arg = args[0] as i64;
            let real_pid = if pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                pidns::translate_pid_arg(pid_arg as i32) as i64
            } else {
                pid_arg
            };
            signal::do_kill(real_pid, args[1] as i32)
        }
        SYS_TKILL => signal::do_tkill(args[0] as i32, args[1] as i32),
        SYS_TGKILL => {
            let tgid = args[0] as i32;
            let tid = args[1] as i32;
            let real_tgid = if pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                pidns::translate_pid_arg(tgid)
            } else {
                tgid
            };
            signal::do_tgkill(real_tgid, tid, args[2] as i32)
        }
        SYS_UMASK => {
            let ret = unsafe { libc::umask(args[0] as libc::mode_t) };
            ret as u64
        }
        SYS_GETGROUPS => creds::do_getgroups(args[0] as u32, args[1]),
        SYS_SETPRIORITY => 0, // stub success
        SYS_GETPRIORITY => 20, // default nice value
        SYS_SETITIMER => do_setitimer(args[0] as i32, args[1], args[2]),
        SYS_GETCWD => do_getcwd(args[0], args[1]),
        SYS_CHDIR => {
            let (eff_path, _hold) = effective_path_ptr(args[0]);
            let ret = unsafe { libc::chdir(eff_path) };
            if ret == 0 { 0 }
            else if _hold.is_some() {
                let ret2 = unsafe { libc::chdir(args[0] as *const i8) };
                if ret2 < 0 { translate::linux_errno() } else { 0 }
            } else { translate::linux_errno() }
        }
        SYS_FCHDIR => {
            let ret = unsafe { libc::fchdir(args[0] as i32) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_MKDIRAT => {
            let (eff_path, _hold) = effective_path_ptr(args[1]);
            let ret = unsafe { libc::mkdirat(translate::translate_dirfd(args[0] as i32), eff_path, args[2] as libc::mode_t) };
            if ret == 0 { 0 }
            else if _hold.is_some() {
                let ret2 = unsafe { libc::mkdirat(translate::translate_dirfd(args[0] as i32), args[1] as *const i8, args[2] as libc::mode_t) };
                if ret2 < 0 { translate::linux_errno() } else { 0 }
            } else { translate::linux_errno() }
        }
        SYS_UNLINKAT => {
            let mac_flags = if args[2] & 0x200 != 0 { libc::AT_REMOVEDIR } else { 0 };
            let (eff_path, _hold) = effective_path_ptr(args[1]);
            let ret = unsafe { libc::unlinkat(translate::translate_dirfd(args[0] as i32), eff_path, mac_flags) };
            if ret == 0 { 0 }
            else if _hold.is_some() {
                let ret2 = unsafe { libc::unlinkat(translate::translate_dirfd(args[0] as i32), args[1] as *const i8, mac_flags) };
                if ret2 < 0 { translate::linux_errno() } else { 0 }
            } else { translate::linux_errno() }
        }
        SYS_RENAMEAT => {
            let (eff_old, _hold_old) = effective_path_ptr(args[1]);
            let (eff_new, _hold_new) = effective_path_ptr(args[3]);
            let ret = unsafe { libc::renameat(
                translate::translate_dirfd(args[0] as i32), eff_old,
                translate::translate_dirfd(args[2] as i32), eff_new,
            ) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_FCHMOD => {
            let ret = unsafe { libc::fchmod(args[0] as i32, args[1] as libc::mode_t) };
            if ret == 0 { 0 }
            else if creds::do_geteuid() == 0 { 0 }
            else { translate::linux_errno() }
        }
        SYS_FCHMODAT => {
            let (eff_path, _hold) = effective_path_ptr(args[1]);
            let mac_dirfd = translate::translate_dirfd(args[0] as i32);
            // Linux fchmodat has AT_SYMLINK_NOFOLLOW=0x100 in flags (arg3), but macOS
            // fchmodat doesn't support this flag and returns EINVAL. Strip it.
            let mac_flags = (args[3] as i32) & !0x100;
            let ret = unsafe { libc::fchmodat(mac_dirfd, eff_path, args[2] as libc::mode_t, mac_flags) };
            if ret == 0 { 0 }
            else if _hold.is_some() {
                let ret2 = unsafe { libc::fchmodat(mac_dirfd, args[1] as *const i8, args[2] as libc::mode_t, mac_flags) };
                if ret2 == 0 { 0 }
                // Virtual root: silently succeed if real op fails with EPERM/ENOENT
                else if creds::do_geteuid() == 0 { 0 }
                else { translate::linux_errno() }
            }
            // Virtual root: silently succeed if real op fails with EPERM/ENOENT
            else if creds::do_geteuid() == 0 { 0 }
            else { translate::linux_errno() }
        }
        SYS_FCHOWN => {
            let ret = unsafe { libc::fchown(args[0] as i32, args[1] as u32, args[2] as u32) };
            if ret == 0 { 0 }
            // Virtual root: silently succeed if real op fails
            else if creds::do_geteuid() == 0 { 0 }
            else { translate::linux_errno() }
        }
        SYS_FCHOWNAT => {
            let (eff_path, _hold) = effective_path_ptr(args[1]);
            let mac_dirfd = translate::translate_dirfd(args[0] as i32);
            let ret = unsafe { libc::fchownat(mac_dirfd, eff_path, args[2] as u32, args[3] as u32, args[4] as i32) };
            if ret == 0 { 0 }
            else if _hold.is_some() {
                let ret2 = unsafe { libc::fchownat(mac_dirfd, args[1] as *const i8, args[2] as u32, args[3] as u32, args[4] as i32) };
                if ret2 == 0 { 0 }
                else if creds::do_geteuid() == 0 { 0 }
                else { translate::linux_errno() }
            }
            // Virtual root: silently succeed if real op fails
            else if creds::do_geteuid() == 0 { 0 }
            else { translate::linux_errno() }
        }
        SYS_WAIT4 => {
            let pid_arg = args[0] as i64;
            let translated_pid = if pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                pidns::translate_pid_arg(pid_arg as i32) as i64
            } else {
                pid_arg
            };
            let ret = thread::do_wait4(translated_pid, args[1], args[2] as i32, args[3]);
            // Translate returned real PID back to virtual PID
            if pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                let ret_i64 = ret as i64;
                if ret_i64 > 0 {
                    let real_pid = ret as i32;
                    let vpid = pidns::real_to_virtual(real_pid).unwrap_or(real_pid);
                    // Reap: mark entry as unused in shm table
                    if vpid != real_pid {
                        pidns::unregister_vpid(vpid);
                    }
                    // Restore parent's own env vars (fork may have set child's)
                    pidns::restore_parent_env();
                    vpid as u64
                } else {
                    ret
                }
            } else {
                ret
            }
        }
        SYS_EXECVE => do_execve(args[0], args[1], args[2]),
        SYS_MEMBARRIER => do_membarrier(args[0] as i32, args[1] as u32, args[2] as i32),
        SYS_STATFS => do_statfs(args[0], args[1]),
        SYS_FSTATFS => do_fstatfs(args[0] as i32, args[1]),
        SYS_SETREGID => creds::do_setregid(args[0] as u32, args[1] as u32),
        SYS_SETGID => creds::do_setgid(args[0] as u32),
        SYS_SETREUID => creds::do_setreuid(args[0] as u32, args[1] as u32),
        SYS_SETUID => creds::do_setuid(args[0] as u32),
        SYS_SETRESUID => creds::do_setresuid(args[0] as u32, args[1] as u32, args[2] as u32),
        SYS_GETRESUID => creds::do_getresuid(args[0], args[1], args[2]),
        SYS_SETRESGID => creds::do_setresgid(args[0] as u32, args[1] as u32, args[2] as u32),
        SYS_GETRESGID => creds::do_getresgid(args[0], args[1], args[2]),
        SYS_SETFSUID => creds::do_setfsuid(args[0] as u32),
        SYS_SETFSGID => creds::do_setfsgid(args[0] as u32),
        SYS_SETGROUPS => creds::do_setgroups(args[0] as u32, args[1]),
        SYS_SENDFILE => do_sendfile(args[0] as i32, args[1] as i32, args[2], args[3]),
        SYS_SYMLINKAT => do_symlinkat(args[0], args[1] as i32, args[2]),
        SYS_LINKAT => do_linkat(args[0] as i32, args[1], args[2] as i32, args[3], args[4] as i32),
        SYS_FLOCK => do_flock(args[0] as i32, args[1] as i32),
        SYS_UTIMENSAT => do_utimensat(args[0] as i32, args[1], args[2], args[3] as i32),
        SYS_FTRUNCATE => do_ftruncate(args[0] as i32, args[1] as i64),
        SYS_NANOSLEEP => do_nanosleep(args[0], args[1]),
        SYS_CLOCK_GETRES => do_clock_getres(args[0] as i32, args[1]),
        SYS_CLOCK_NANOSLEEP => do_clock_nanosleep(args[0] as i32, args[1] as i32, args[2], args[3]),
        SYS_SETSID => {
            let ret = unsafe { libc::setsid() };
            if ret < 0 {
                translate::linux_errno()
            } else if pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                // setsid returns the new session ID (= caller's PID); return virtual PID
                pidns::current_vpid() as u64
            } else {
                ret as u64
            }
        }
        SYS_GETPGID => {
            let pid_arg = args[0] as i32;
            let real_pid = if pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) && pid_arg != 0 {
                pidns::translate_pid_arg(pid_arg)
            } else {
                pid_arg
            };
            let ret = unsafe { libc::getpgid(real_pid) };
            if ret < 0 {
                translate::linux_errno()
            } else if pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                pidns::real_to_virtual(ret).unwrap_or(ret) as u64
            } else {
                ret as u64
            }
        }
        SYS_SETPGID => {
            let pid_arg = args[0] as i32;
            let pgid_arg = args[1] as i32;
            let real_pid = if pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) && pid_arg != 0 {
                pidns::translate_pid_arg(pid_arg)
            } else {
                pid_arg
            };
            let real_pgid = if pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) && pgid_arg != 0 {
                pidns::translate_pid_arg(pgid_arg)
            } else {
                pgid_arg
            };
            let ret = unsafe { libc::setpgid(real_pid, real_pgid) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_GETSID => {
            let pid_arg = args[0] as i32;
            let real_pid = if pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) && pid_arg != 0 {
                pidns::translate_pid_arg(pid_arg)
            } else {
                pid_arg
            };
            let ret = unsafe { libc::getsid(real_pid) };
            if ret < 0 {
                translate::linux_errno()
            } else if pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                pidns::real_to_virtual(ret).unwrap_or(ret) as u64
            } else {
                ret as u64
            }
        }
        SYS_FSYNC => {
            let ret = unsafe { libc::fsync(args[0] as i32) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_FDATASYNC => {
            // macOS doesn't have fdatasync; use fsync
            let ret = unsafe { libc::fsync(args[0] as i32) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_SYNC => {
            unsafe { libc::sync() };
            0
        }
        SYS_FALLOCATE => do_fallocate(args[0] as i32, args[1] as i32, args[2] as i64, args[3] as i64),
        SYS_MSYNC => {
            let ret = unsafe { libc::msync(args[0] as *mut libc::c_void, args[1] as usize, args[2] as i32) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_MLOCK => {
            let ret = unsafe { libc::mlock(args[0] as *const libc::c_void, args[1] as usize) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_MUNLOCK => {
            let ret = unsafe { libc::munlock(args[0] as *const libc::c_void, args[1] as usize) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_PERSONALITY => {
            // personality(PER_LINUX=0) — just return current (0)
            if args[0] == 0xFFFFFFFF { 0 } else { 0 }
        }
        SYS_SIGALTSTACK => do_guest_sigaltstack(args[0], args[1]),
        SYS_RENAMEAT2 => do_renameat2(args[0] as i32, args[1], args[2] as i32, args[3], args[4] as u32),
        SYS_MEMFD_CREATE => do_memfd_create(args[0], args[1] as u32),
        SYS_COPY_FILE_RANGE => do_copy_file_range(args[0] as i32, args[1], args[2] as i32, args[3], args[4], args[5] as u32),
        _ => {
            raw_eprintln_fmt(format_args!(
                "fakelinux: unimplemented syscall {} (x0={:#x} x1={:#x} x2={:#x})\n",
                nr, args[0], args[1], args[2]
            ));
            (-38_i64) as u64 // -ENOSYS
        }
    }
}

// ─── File I/O ────────────────────────────────────────────────────────────────

fn do_write(fd: u64, buf: u64, count: u64) -> u64 {
    let fd_i32 = fd as i32;
    if eventfd::is_eventfd(fd_i32) {
        return eventfd::do_write(fd_i32, buf, count);
    }
    let ret = unsafe { libc::write(fd_i32, buf as *const _, count as usize) };
    if ret < 0 { translate::linux_errno() } else { ret as u64 }
}

fn do_read(fd: u64, buf: u64, count: u64) -> u64 {
    let fd_i32 = fd as i32;
    if eventfd::is_eventfd(fd_i32) {
        return eventfd::do_read(fd_i32, buf, count);
    }
    let ret = unsafe { libc::read(fd_i32, buf as *mut _, count as usize) };
    if ret < 0 { translate::linux_errno() } else { ret as u64 }
}

fn do_openat(linux_dirfd: i32, pathname: u64, linux_flags: i32, mode: u32) -> u64 {
    if pathname == 0 { return (-14_i64) as u64; } // -EFAULT
    let path = unsafe { std::ffi::CStr::from_ptr(pathname as *const i8) };

    if TRACE.load(std::sync::atomic::Ordering::Relaxed) {
        raw_eprintln_fmt(format_args!("fakelinux: openat({}, {:?}, {:#x})\n",
            linux_dirfd, path, linux_flags));
    }

    // Check if this is a /proc path we handle virtually
    if let Some(fd) = procfs::try_open(path.to_bytes()) {
        return fd as u64;
    }

    // Always intercept /etc/ld.so.nohwcap — return ENOENT
    if path.to_bytes() == b"/etc/ld.so.nohwcap" {
        return (-2_i64) as u64; // -ENOENT
    }

    let mac_dirfd = translate::translate_dirfd(linux_dirfd);
    let mac_flags = translate::translate_open_flags(linux_flags);

    // Translate path through rootfs layer
    let (eff_path, _hold) = effective_path_ptr(pathname);

    let ret = unsafe { libc::openat(mac_dirfd, eff_path, mac_flags, mode) };
    if ret >= 0 {
        return ret as u64;
    }

    // In rootfs mode, if O_NOFOLLOW caused ELOOP, retry without it.
    // Symlinks within the rootfs are safe to follow.
    if _hold.is_some() && (mac_flags & libc::O_NOFOLLOW != 0) {
        let errno = unsafe { *libc::__error() };
        if errno == libc::ELOOP {
            let ret2 = unsafe {
                libc::openat(mac_dirfd, eff_path, mac_flags & !libc::O_NOFOLLOW, mode)
            };
            if ret2 >= 0 {
                return ret2 as u64;
            }
        }
    }

    // If translation was applied and the translated path failed, try the original
    if _hold.is_some() {
        let ret2 = unsafe { libc::openat(mac_dirfd, pathname as *const i8, mac_flags, mode) };
        if ret2 >= 0 {
            return ret2 as u64;
        }
    }

    translate::linux_errno()
}

fn do_close(fd: i32) -> u64 {
    // Clean up virtual fd state if this fd is one of those
    eventfd::on_close(fd);
    epoll::on_close(fd);
    procfs::on_close(fd);
    let ret = unsafe { libc::close(fd) };
    if ret < 0 { translate::linux_errno() } else { 0 }
}

fn do_close_range(first: u32, last: u32, _flags: u32) -> u64 {
    // Close all fds from first to last (inclusive).
    // Clamp to a reasonable range to avoid iterating millions of fds.
    let last = last.min(first.saturating_add(65536));
    for fd in first..=last {
        let fd = fd as i32;
        eventfd::on_close(fd);
        epoll::on_close(fd);
        procfs::on_close(fd);
        unsafe { libc::close(fd); }
    }
    0
}

fn do_lseek(fd: i32, offset: i64, whence: i32) -> u64 {
    let ret = unsafe { libc::lseek(fd, offset, whence) };
    if ret < 0 { translate::linux_errno() } else { ret as u64 }
}

fn do_fstat(fd: i32, statbuf: u64) -> u64 {
    // Check if this is a virtual /proc directory fd
    if let Some(()) = procfs::try_fstat_virtual(fd, statbuf) {
        return 0;
    }
    unsafe {
        let mut mac_stat: libc::stat = std::mem::zeroed();
        let ret = libc::fstat(fd, &mut mac_stat);
        if ret < 0 {
            return translate::linux_errno();
        }
        translate::mac_stat_to_linux(&mac_stat, statbuf as *mut u8);
    }
    0
}

fn do_newfstatat(linux_dirfd: i32, pathname: u64, statbuf: u64, linux_flags: i32) -> u64 {
    // AT_EMPTY_PATH (0x1000): if pathname is empty, operate on the fd directly
    const LINUX_AT_EMPTY_PATH: i32 = 0x1000;
    if linux_flags & LINUX_AT_EMPTY_PATH != 0 {
        let path = unsafe { std::ffi::CStr::from_ptr(pathname as *const i8) };
        if path.to_bytes().is_empty() {
            return do_fstat(linux_dirfd, statbuf);
        }
    }

    // Check if this is a /proc path we handle virtually
    if pathname != 0 {
        let path = unsafe { std::ffi::CStr::from_ptr(pathname as *const i8) };
        if let Some(()) = procfs::try_stat(path.to_bytes(), statbuf) {
            return 0;
        }
    }

    let mac_dirfd = translate::translate_dirfd(linux_dirfd);
    let mac_flags = translate::translate_at_flags(linux_flags);

    // Translate path through rootfs layer
    let (eff_path, _hold) = effective_path_ptr(pathname);

    unsafe {
        let mut mac_stat: libc::stat = std::mem::zeroed();
        let ret = libc::fstatat(mac_dirfd, eff_path, &mut mac_stat, mac_flags);
        if ret == 0 {
            translate::mac_stat_to_linux(&mac_stat, statbuf as *mut u8);
            return 0;
        }
    }

    // If translation was applied and failed, try original path
    if _hold.is_some() {
        unsafe {
            let mut mac_stat: libc::stat = std::mem::zeroed();
            let ret = libc::fstatat(mac_dirfd, pathname as *const i8, &mut mac_stat, mac_flags);
            if ret == 0 {
                translate::mac_stat_to_linux(&mac_stat, statbuf as *mut u8);
                return 0;
            }
        }
    }

    translate::linux_errno()
}

fn do_ioctl(fd: i32, request: u64, arg: u64) -> u64 {
    const LINUX_TCGETS: u64 = 0x5401;
    const LINUX_TCSETS: u64 = 0x5402;
    const LINUX_TCSETSW: u64 = 0x5403;
    const LINUX_TCSETSF: u64 = 0x5404;
    const LINUX_TIOCGPGRP: u64 = 0x540F;
    const LINUX_TIOCSPGRP: u64 = 0x5410;
    const LINUX_TIOCSCTTY: u64 = 0x540E;
    const LINUX_TIOCNOTTY: u64 = 0x5422;
    const LINUX_TIOCGWINSZ: u64 = 0x5413;
    const LINUX_TIOCSWINSZ: u64 = 0x5414;
    const LINUX_FIONREAD: u64 = 0x541B;
    const LINUX_FIONBIO: u64 = 0x5421;

    match request {
        LINUX_TCGETS => {
            let mut mac_t: libc::termios = unsafe { std::mem::zeroed() };
            let ret = unsafe { libc::tcgetattr(fd, &mut mac_t) };
            if ret < 0 { return translate::linux_errno(); }
            mac_termios_to_linux(&mac_t, arg);
            0
        }
        LINUX_TCSETS | LINUX_TCSETSW | LINUX_TCSETSF => {
            let mac_t = linux_termios_to_mac(arg);
            let action = match request {
                LINUX_TCSETS => libc::TCSANOW,
                LINUX_TCSETSW => libc::TCSADRAIN,
                _ => libc::TCSAFLUSH,
            };
            let ret = unsafe { libc::tcsetattr(fd, action, &mac_t) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        LINUX_TIOCGPGRP => {
            let pgrp = unsafe { libc::tcgetpgrp(fd) };
            if pgrp < 0 { return translate::linux_errno(); }
            let vpgrp = if pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                pidns::real_to_virtual(pgrp).unwrap_or(pgrp)
            } else {
                pgrp
            };
            unsafe { (arg as *mut i32).write_unaligned(vpgrp) };
            0
        }
        LINUX_TIOCSPGRP => {
            let pgrp = unsafe { (arg as *const i32).read_unaligned() };
            let real_pgrp = if pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                pidns::translate_pid_arg(pgrp)
            } else {
                pgrp
            };
            let ret = unsafe { libc::tcsetpgrp(fd, real_pgrp) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        LINUX_TIOCSCTTY => {
            let ret = unsafe { libc::ioctl(fd, libc::TIOCSCTTY as libc::c_ulong, arg as i32) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        LINUX_TIOCNOTTY => {
            let ret = unsafe { libc::ioctl(fd, libc::TIOCNOTTY as libc::c_ulong) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        LINUX_TIOCGWINSZ => {
            let ret = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, arg as *mut libc::winsize) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        LINUX_TIOCSWINSZ => {
            let ret = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, arg as *const libc::winsize) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        LINUX_FIONREAD => {
            let mut avail: libc::c_int = 0;
            let ret = unsafe { libc::ioctl(fd, libc::FIONREAD, &mut avail) };
            if ret < 0 { return translate::linux_errno(); }
            unsafe { (arg as *mut i32).write_unaligned(avail) };
            0
        }
        LINUX_FIONBIO => {
            let val = unsafe { (arg as *const i32).read_unaligned() };
            let ret = unsafe { libc::ioctl(fd, libc::FIONBIO, &val) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        _ => (-25_i64) as u64, // -ENOTTY
    }
}

// ─── Termios flag translation (Linux ↔ macOS) ──────────────────────────────
// Linux (asm-generic) and macOS (BSD) use different bit positions for termios
// flags and different c_cc indices.

/// c_cc index mapping: (linux_index, macos_index)
const CC_LINUX_TO_MAC: [(usize, usize); 16] = [
    (0,  8),   // VINTR
    (1,  9),   // VQUIT
    (2,  3),   // VERASE
    (3,  5),   // VKILL
    (4,  0),   // VEOF
    (5,  17),  // VTIME
    (6,  16),  // VMIN
    // 7 = VSWTC — Linux-only
    (8,  12),  // VSTART
    (9,  13),  // VSTOP
    (10, 10),  // VSUSP
    (11, 1),   // VEOL
    (12, 6),   // VREPRINT
    (13, 15),  // VDISCARD
    (14, 4),   // VWERASE
    (15, 14),  // VLNEXT
    (16, 2),   // VEOL2
];

/// Translate bits from one flag set to another using a mapping table.
/// Each entry is (source_bit, dest_bit).
fn translate_flags(val: u32, map: &[(u32, u32)]) -> u32 {
    let mut out: u32 = 0;
    for &(src, dst) in map {
        if val & src != 0 { out |= dst; }
    }
    out
}

// c_iflag: Linux → macOS  (mostly the same except IXON, IXOFF, IUTF8)
const IFLAG_L2M: [(u32, u32); 13] = [
    (0x001, 0x001),   // IGNBRK
    (0x002, 0x002),   // BRKINT
    (0x004, 0x004),   // IGNPAR
    (0x008, 0x008),   // PARMRK
    (0x010, 0x010),   // INPCK
    (0x020, 0x020),   // ISTRIP
    (0x040, 0x040),   // INLCR
    (0x080, 0x080),   // IGNCR
    (0x100, 0x100),   // ICRNL
    (0x200, 0x200),   // IUCLC → not on macOS, map to self (harmless)
    (0x400, 0x200),   // IXON: Linux 0x400 → macOS 0x200
    (0x800, 0x800),   // IXANY
    (0x1000, 0x400),  // IXOFF: Linux 0x1000 → macOS 0x400
];

// c_iflag: macOS → Linux
const IFLAG_M2L: [(u32, u32); 12] = [
    (0x001, 0x001),   // IGNBRK
    (0x002, 0x002),   // BRKINT
    (0x004, 0x004),   // IGNPAR
    (0x008, 0x008),   // PARMRK
    (0x010, 0x010),   // INPCK
    (0x020, 0x020),   // ISTRIP
    (0x040, 0x040),   // INLCR
    (0x080, 0x080),   // IGNCR
    (0x100, 0x100),   // ICRNL
    (0x200, 0x400),   // IXON: macOS 0x200 → Linux 0x400
    (0x400, 0x1000),  // IXOFF: macOS 0x400 → Linux 0x1000
    (0x800, 0x800),   // IXANY
];

// c_oflag: Linux → macOS
const OFLAG_L2M: [(u32, u32); 2] = [
    (0x01, 0x01),     // OPOST
    (0x04, 0x02),     // ONLCR: Linux 0x4 → macOS 0x2
];

// c_oflag: macOS → Linux
const OFLAG_M2L: [(u32, u32); 2] = [
    (0x01, 0x01),     // OPOST
    (0x02, 0x04),     // ONLCR: macOS 0x2 → Linux 0x4
];

// c_lflag: Linux → macOS  (completely different bit assignments!)
const LFLAG_L2M: [(u32, u32); 11] = [
    (0x0001, 0x0080),     // ISIG: Linux 0x1 → macOS 0x80
    (0x0002, 0x0100),     // ICANON: Linux 0x2 → macOS 0x100
    (0x0008, 0x0008),     // ECHO (same)
    (0x0010, 0x0002),     // ECHOE: Linux 0x10 → macOS 0x02
    (0x0020, 0x0004),     // ECHOK: Linux 0x20 → macOS 0x04
    (0x0040, 0x0010),     // ECHONL: Linux 0x40 → macOS 0x10
    (0x0080, 0x80000000), // NOFLSH: Linux 0x80 → macOS 0x80000000
    (0x0100, 0x00400000), // TOSTOP: Linux 0x100 → macOS 0x400000
    (0x8000, 0x0400),     // IEXTEN: Linux 0x8000 → macOS 0x400
    (0x0200, 0x0040),     // ECHOCTL: Linux 0x200 → macOS 0x40
    (0x0400, 0x0001),     // ECHOKE: Linux 0x400 → macOS 0x01
];

// c_lflag: macOS → Linux
const LFLAG_M2L: [(u32, u32); 11] = [
    (0x0080, 0x0001),     // ISIG
    (0x0100, 0x0002),     // ICANON
    (0x0008, 0x0008),     // ECHO
    (0x0002, 0x0010),     // ECHOE
    (0x0004, 0x0020),     // ECHOK
    (0x0010, 0x0040),     // ECHONL
    (0x80000000, 0x0080), // NOFLSH
    (0x00400000, 0x0100), // TOSTOP
    (0x0400, 0x8000),     // IEXTEN
    (0x0040, 0x0200),     // ECHOCTL
    (0x0001, 0x0400),     // ECHOKE
];

// c_cflag: mostly compatible for common flags (CS5-CS8, CSTOPB, CREAD, PARENB, etc.)
// Both use the same bit positions for the common flags, so pass through directly.

/// Convert macOS termios to Linux aarch64 kernel termios (36 bytes) at guest address.
fn mac_termios_to_linux(mac: &libc::termios, linux_ptr: u64) {
    const KERNEL_NCCS: usize = 19;
    unsafe {
        let p = linux_ptr as *mut u8;
        (p as *mut u32).write_unaligned(translate_flags(mac.c_iflag as u32, &IFLAG_M2L));
        (p.add(4) as *mut u32).write_unaligned(translate_flags(mac.c_oflag as u32, &OFLAG_M2L));
        (p.add(8) as *mut u32).write_unaligned(mac.c_cflag as u32);
        (p.add(12) as *mut u32).write_unaligned(translate_flags(mac.c_lflag as u32, &LFLAG_M2L));
        *p.add(16) = 0; // c_line
        let cc_dst = p.add(17);
        std::ptr::write_bytes(cc_dst, 0, KERNEL_NCCS);
        for &(linux_i, mac_i) in &CC_LINUX_TO_MAC {
            if linux_i < KERNEL_NCCS && mac_i < mac.c_cc.len() {
                *cc_dst.add(linux_i) = mac.c_cc[mac_i];
            }
        }
    }
}

/// Convert Linux aarch64 kernel termios (36 bytes at guest address) to macOS termios.
fn linux_termios_to_mac(linux_ptr: u64) -> libc::termios {
    const KERNEL_NCCS: usize = 19;
    unsafe {
        let p = linux_ptr as *const u8;
        let mut mac: libc::termios = std::mem::zeroed();
        // Preserve current speeds and unmapped fields
        let _ = libc::tcgetattr(0, &mut mac);
        let linux_iflag = (p as *const u32).read_unaligned();
        let linux_oflag = (p.add(4) as *const u32).read_unaligned();
        let linux_cflag = (p.add(8) as *const u32).read_unaligned();
        let linux_lflag = (p.add(12) as *const u32).read_unaligned();
        mac.c_iflag = translate_flags(linux_iflag, &IFLAG_L2M) as u64;
        mac.c_oflag = translate_flags(linux_oflag, &OFLAG_L2M) as u64;
        mac.c_cflag = linux_cflag as u64;
        mac.c_lflag = translate_flags(linux_lflag, &LFLAG_L2M) as u64;
        let cc_src = p.add(17);
        for &(linux_i, mac_i) in &CC_LINUX_TO_MAC {
            if linux_i < KERNEL_NCCS && mac_i < mac.c_cc.len() {
                mac.c_cc[mac_i] = *cc_src.add(linux_i);
            }
        }
        mac
    }
}

fn do_fcntl(fd: i32, linux_cmd: i32, arg: u64) -> u64 {
    // Linux-specific fcntl commands (>=1024) have no macOS equivalent.
    // F_SETPIPE_SZ=1031, F_GETPIPE_SZ=1032, F_ADD_SEALS=1033, etc.
    if linux_cmd >= 1024 {
        // F_DUPFD_CLOEXEC is 1030 on Linux
        if linux_cmd == translate::LINUX_F_DUPFD_CLOEXEC {
            let ret = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, arg as i32) };
            return if ret < 0 { translate::linux_errno() } else { ret as u64 };
        }
        return (-22_i64) as u64; // -EINVAL
    }
    // F_SETOWN_EX / F_GETOWN_EX
    if linux_cmd == 15 { return 0; }
    if linux_cmd == 16 { return (-22_i64) as u64; }

    // F_GETLK / F_SETLK / F_SETLKW — need struct flock translation
    if linux_cmd == translate::LINUX_F_GETLK
        || linux_cmd == translate::LINUX_F_SETLK
        || linux_cmd == translate::LINUX_F_SETLKW
    {
        let mac_cmd = match linux_cmd {
            translate::LINUX_F_GETLK => libc::F_GETLK,
            translate::LINUX_F_SETLK => libc::F_SETLK,
            translate::LINUX_F_SETLKW => libc::F_SETLKW,
            _ => unreachable!(),
        };
        let mut mac_flock = translate::linux_flock_to_mac(arg);
        let ret = unsafe { libc::fcntl(fd, mac_cmd, &mut mac_flock as *mut libc::flock) };
        if ret < 0 {
            return translate::linux_errno();
        }
        // For F_GETLK, write back the result
        if linux_cmd == translate::LINUX_F_GETLK {
            translate::mac_flock_to_linux(&mac_flock, arg);
        }
        return ret as u64;
    }

    if let Some(mac_cmd) = translate::translate_fcntl_cmd(linux_cmd) {
        let ret = unsafe { libc::fcntl(fd, mac_cmd, arg as i32) };
        if ret < 0 { translate::linux_errno() } else { ret as u64 }
    } else {
        eprintln!("fakelinux: unsupported fcntl cmd {}", linux_cmd);
        (-22_i64) as u64 // -EINVAL
    }
}

fn do_writev(fd: u64, iov: u64, iovcnt: u64) -> u64 {
    let ret = unsafe { libc::writev(fd as i32, iov as *const libc::iovec, iovcnt as i32) };
    if ret < 0 { translate::linux_errno() } else { ret as u64 }
}

fn do_readv(fd: u64, iov: u64, iovcnt: u64) -> u64 {
    let ret = unsafe { libc::readv(fd as i32, iov as *const libc::iovec, iovcnt as i32) };
    if ret < 0 { translate::linux_errno() } else { ret as u64 }
}

fn do_ppoll(fds_ptr: u64, nfds: u32, timeout_ptr: u64, _sigmask: u64, _sigsetsize: u64) -> u64 {
    // Linux pollfd layout: { int fd; short events; short revents; } = 8 bytes
    // macOS pollfd layout: same structure and same size
    // POLLIN/POLLOUT/POLLERR/POLLHUP values are the same on both platforms

    // Convert timespec to millisecond timeout for macOS poll()
    let timeout_ms: i32 = if timeout_ptr == 0 {
        -1 // infinite timeout
    } else {
        unsafe {
            let ts = timeout_ptr as *const i64;
            let sec = *ts;
            let nsec = *ts.add(1);
            // Convert to ms, clamping to i32 range
            let ms = sec * 1000 + nsec / 1_000_000;
            if ms > i32::MAX as i64 { i32::MAX } else { ms as i32 }
        }
    };

    // pollfd arrays have identical layout, so we can pass the guest buffer directly
    let ret = unsafe {
        libc::poll(fds_ptr as *mut libc::pollfd, nfds as libc::nfds_t, timeout_ms)
    };
    if ret < 0 { translate::linux_errno() } else { ret as u64 }
}

fn do_pread64(fd: i32, buf: u64, count: u64, offset: i64) -> u64 {
    let ret = unsafe { libc::pread(fd, buf as *mut libc::c_void, count as usize, offset) };
    if ret < 0 { translate::linux_errno() } else { ret as u64 }
}

fn do_pwrite64(fd: i32, buf: u64, count: u64, offset: i64) -> u64 {
    let ret = unsafe { libc::pwrite(fd, buf as *const libc::c_void, count as usize, offset) };
    if ret < 0 { translate::linux_errno() } else { ret as u64 }
}

fn do_statx(linux_dirfd: i32, pathname: u64, linux_flags: i32, _mask: u32, statxbuf: u64) -> u64 {
    let mac_dirfd = translate::translate_dirfd(linux_dirfd);
    let mac_flags = translate::translate_at_flags(linux_flags);

    // AT_EMPTY_PATH (0x1000): operate on dirfd itself when pathname is empty
    if linux_flags & 0x1000 != 0 {
        let path = unsafe { std::ffi::CStr::from_ptr(pathname as *const i8) };
        if path.to_bytes().is_empty() {
            // Check virtual dir fd first
            if procfs::is_virtual_dir(mac_dirfd) {
                return procfs::write_statx_dir(statxbuf);
            }
            unsafe {
                let mut mac_stat: libc::stat = std::mem::zeroed();
                let ret = libc::fstat(mac_dirfd, &mut mac_stat);
                if ret < 0 { return translate::linux_errno(); }
                translate::mac_stat_to_linux_statx(&mac_stat, statxbuf as *mut u8);
            }
            return 0;
        }
    }

    // Check if this is a /proc path we handle virtually
    if pathname != 0 {
        let path = unsafe { std::ffi::CStr::from_ptr(pathname as *const i8) };
        if let Some(()) = procfs::try_statx(path.to_bytes(), statxbuf) {
            return 0;
        }
    }

    let (eff_path, _hold) = effective_path_ptr(pathname);
    unsafe {
        let mut mac_stat: libc::stat = std::mem::zeroed();
        let ret = libc::fstatat(mac_dirfd, eff_path, &mut mac_stat, mac_flags);
        if ret == 0 {
            translate::mac_stat_to_linux_statx(&mac_stat, statxbuf as *mut u8);
            return 0;
        }
    }
    // Fallback to original path if translated path failed
    if _hold.is_some() {
        unsafe {
            let mut mac_stat: libc::stat = std::mem::zeroed();
            let ret = libc::fstatat(mac_dirfd, pathname as *const i8, &mut mac_stat, mac_flags);
            if ret == 0 {
                translate::mac_stat_to_linux_statx(&mac_stat, statxbuf as *mut u8);
                return 0;
            }
        }
    }
    translate::linux_errno()
}

fn do_faccessat(linux_dirfd: i32, pathname: u64, mode: i32, linux_flags: i32) -> u64 {
    let mac_dirfd = translate::translate_dirfd(linux_dirfd);
    let mac_flags = translate::translate_at_flags(linux_flags);
    let (eff_path, _hold) = effective_path_ptr(pathname);
    let ret = unsafe { libc::faccessat(mac_dirfd, eff_path, mode, mac_flags) };
    if ret == 0 { return 0; }
    // Fallback to original if translated path failed
    if _hold.is_some() {
        let ret2 = unsafe { libc::faccessat(mac_dirfd, pathname as *const i8, mode, mac_flags) };
        if ret2 == 0 { return 0; }
    }
    translate::linux_errno()
}

fn do_readlinkat(linux_dirfd: i32, pathname: u64, buf: u64, bufsiz: u64) -> u64 {
    let path = unsafe { std::ffi::CStr::from_ptr(pathname as *const i8) };

    // Check /proc paths first
    if let Some(result) = procfs::try_readlink(path.to_bytes(), buf, bufsiz) {
        return result;
    }

    let mac_dirfd = translate::translate_dirfd(linux_dirfd);
    let (eff_path, _hold) = effective_path_ptr(pathname);
    let ret = unsafe {
        libc::readlinkat(mac_dirfd, eff_path, buf as *mut i8, bufsiz as usize)
    };
    if ret >= 0 { return ret as u64; }
    if _hold.is_some() {
        let ret2 = unsafe {
            libc::readlinkat(mac_dirfd, pathname as *const i8, buf as *mut i8, bufsiz as usize)
        };
        if ret2 >= 0 { return ret2 as u64; }
    }
    translate::linux_errno()
}

fn do_dup(fd: i32) -> u64 {
    let ret = unsafe { libc::dup(fd) };
    if ret < 0 { translate::linux_errno() } else { ret as u64 }
}

fn do_dup3(oldfd: i32, newfd: i32, flags: i32) -> u64 {
    // macOS doesn't have dup3; use dup2 + fcntl for O_CLOEXEC
    let ret = unsafe { libc::dup2(oldfd, newfd) };
    if ret < 0 {
        return translate::linux_errno();
    }
    if flags & 0o2000000 != 0 {
        // O_CLOEXEC
        unsafe { libc::fcntl(newfd, libc::F_SETFD, libc::FD_CLOEXEC); }
    }
    newfd as u64
}

fn do_pipe2(pipefd_ptr: u64, flags: i32) -> u64 {
    let fds = pipefd_ptr as *mut [i32; 2];
    let ret = unsafe { libc::pipe((*fds).as_mut_ptr()) };
    if ret < 0 {
        return translate::linux_errno();
    }
    // Handle O_CLOEXEC and O_NONBLOCK
    if flags & 0o2000000 != 0 {
        unsafe {
            libc::fcntl((*fds)[0], libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl((*fds)[1], libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    if flags & 0o4000 != 0 {
        unsafe {
            libc::fcntl((*fds)[0], libc::F_SETFL, libc::O_NONBLOCK);
            libc::fcntl((*fds)[1], libc::F_SETFL, libc::O_NONBLOCK);
        }
    }
    0
}

fn do_getdents64(fd: i32, buf: u64, bufsize: u64) -> u64 {
    // Use macOS __getdirentries64 (raw syscall) to read directory entries,
    // then convert to Linux struct linux_dirent64 format.
    extern "C" {
        fn __getdirentries64(fd: libc::c_int, buf: *mut libc::c_char, bufsize: libc::c_int, basep: *mut libc::c_long) -> libc::c_int;
    }

    let mut mac_buf = vec![0u8; bufsize as usize];
    let mut basep: libc::c_long = 0;

    let n = unsafe {
        __getdirentries64(fd, mac_buf.as_mut_ptr() as *mut i8, bufsize as i32, &mut basep)
    };
    if n < 0 {
        return translate::linux_errno();
    }
    if n == 0 {
        return 0;
    }

    let mut out_pos: usize = 0;
    let mut in_pos: usize = 0;
    let out_buf = buf as *mut u8;

    while in_pos < n as usize {
        // macOS struct dirent: d_ino(8), d_seekoff(8), d_reclen(2), d_namlen(2), d_type(1), d_name[]
        if in_pos + 21 > n as usize {
            break;
        }
        let mac_ptr = mac_buf[in_pos..].as_ptr();
        let d_ino = unsafe { (mac_ptr as *const u64).read_unaligned() };
        let d_reclen_mac = unsafe { (mac_ptr.add(16) as *const u16).read_unaligned() } as usize;
        let d_namlen = unsafe { (mac_ptr.add(18) as *const u16).read_unaligned() } as usize;
        let d_type = unsafe { *mac_ptr.add(20) };

        if in_pos + 21 + d_namlen > n as usize || d_reclen_mac == 0 {
            break;
        }
        let d_name = &mac_buf[in_pos + 21..in_pos + 21 + d_namlen];

        // Linux dirent64: d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + name + null
        let linux_reclen = (19 + d_namlen + 1 + 7) & !7;

        if out_pos + linux_reclen > bufsize as usize {
            break;
        }

        unsafe {
            let out = out_buf.add(out_pos);
            std::ptr::write_bytes(out, 0, linux_reclen);
            (out as *mut u64).write_unaligned(d_ino);
            (out.add(8) as *mut i64).write_unaligned((out_pos + linux_reclen) as i64);
            (out.add(16) as *mut u16).write_unaligned(linux_reclen as u16);
            *out.add(18) = d_type;
            std::ptr::copy_nonoverlapping(d_name.as_ptr(), out.add(19), d_namlen);
        }

        out_pos += linux_reclen;
        in_pos += d_reclen_mac;
    }

    out_pos as u64
}

fn do_getcwd(buf: u64, size: u64) -> u64 {
    let ret = unsafe { libc::getcwd(buf as *mut i8, size as usize) };
    if ret.is_null() {
        translate::linux_errno()
    } else {
        // Linux getcwd returns the length including null terminator
        let len = unsafe { std::ffi::CStr::from_ptr(ret).to_bytes_with_nul().len() };
        len as u64
    }
}

fn do_execve(pathname: u64, argv_ptr: u64, envp_ptr: u64) -> u64 {
    // Re-exec ourselves (fakelinux) with the guest binary as argument.
    // This replaces the current process image entirely.
    let path = unsafe { std::ffi::CStr::from_ptr(pathname as *const i8) };

    // Re-exec as: fakelinux <pathname> <argv[0]> <argv[1]> ...
    // fakelinux uses argv[1] as the binary path and argv[1..] as guest argv.
    // For busybox: pathname="/path/to/busybox", argv=["uname","-m"]
    // → exec fakelinux /path/to/busybox uname -m
    // → busybox sees argv[0]="/path/to/busybox" (runs argv[1] applet)
    let mut new_argv: Vec<*const i8> = Vec::new();

    let self_exe = std::env::current_exe().unwrap_or_default();
    let self_exe_c = std::ffi::CString::new(self_exe.to_str().unwrap_or("fakelinux")).unwrap();
    new_argv.push(self_exe_c.as_ptr());

    // Resolve the binary path. If the target is a macOS Mach-O (not ELF),
    // use the parent's guest binary path instead (busybox applet re-exec).
    let resolved_path = {
        let path_bytes = path.to_bytes();
        if path_bytes == b"/proc/self/exe" {
            // Direct /proc/self/exe → use our guest binary
            procfs::with(|pfs| std::ffi::CString::new(pfs.exe_path.clone()).unwrap())
        } else {
            // Try rootfs-translated path first, then original
            let check_path = if let Some(translated) = translate_guest_path(pathname) {
                translated
            } else {
                std::ffi::CString::new(path_bytes).unwrap()
            };
            // Check if the file is an ELF; if not, fall back to guest binary
            // (busybox sh finds /usr/bin/uname on macOS, which is Mach-O)
            let is_elf = std::fs::read(check_path.to_str().unwrap_or(""))
                .map(|d| d.len() >= 4 && d[..4] == [0x7f, b'E', b'L', b'F'])
                .unwrap_or(false);
            if is_elf {
                check_path
            } else {
                procfs::with(|pfs| std::ffi::CString::new(pfs.exe_path.clone()).unwrap())
            }
        }
    };
    new_argv.push(resolved_path.as_ptr());

    // Then the guest's original argv (skip argv[0] since resolved_path serves as
    // the binary path argument to fakelinux — fakelinux passes &args[1..] to the
    // guest, so args[1]=binary, args[2..]=guest argv[1..])
    let mut guest_argv = argv_ptr as *const *const i8;
    unsafe {
        if !(*guest_argv).is_null() {
            guest_argv = guest_argv.add(1); // skip argv[0]
        }
        while !(*guest_argv).is_null() {
            new_argv.push(*guest_argv);
            guest_argv = guest_argv.add(1);
        }
    }
    new_argv.push(std::ptr::null());

    // Use the HOST environment (not guest's) so env vars like FAKELINUX_TRACE propagate
    let new_envp_marker: *const *const i8 = std::ptr::null();
    // Actually, just use environ from libc
    extern "C" { static environ: *const *const i8; }
    let envp_to_use = unsafe { environ };

    // Use real execve to replace the current process. Even though we're
    // inside a SIGILL handler, execve replaces the entire process image
    // so signal context doesn't matter — it never returns on success.
    // This is critical for fork+exec in shells: the child must become the
    // new program directly, inheriting the exact fd table (pipe redirections,
    // dup2'd fds, etc.).
    unsafe {
        libc::execve(
            self_exe_c.as_ptr(),
            new_argv.as_ptr() as *const *const i8,
            envp_to_use as *const *const i8,
        );
    }
    // execve only returns on failure
    translate::linux_errno()
}

// ─── Memory management ──────────────────────────────────────────────────────

fn do_brk(addr: u64) -> u64 {
    let current = BRK_CURRENT.load(Ordering::SeqCst);
    if addr == 0 {
        return current;
    }
    if addr < current {
        return current;
    }
    let page_size = 16384_u64;
    let old_end = (current + page_size - 1) & !(page_size - 1);
    let new_end = (addr + page_size - 1) & !(page_size - 1);
    if new_end > old_end {
        let ret = unsafe {
            libc::mmap(
                old_end as *mut _,
                (new_end - old_end) as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if ret == libc::MAP_FAILED {
            return current;
        }
    }
    BRK_CURRENT.store(addr, Ordering::SeqCst);
    addr
}

fn do_mmap(addr: u64, length: u64, prot: u64, flags: u64, fd: i32, offset: u64) -> u64 {
    let mac_prot = translate::translate_mmap_prot(prot);
    let page: u64 = 16384;
    let has_exec = prot & 4 != 0; // PROT_EXEC
    let is_fixed = flags & 0x10 != 0; // MAP_FIXED

    // Handle 4KB/16KB page size mismatch for MAP_FIXED mappings.
    // Linux guests may place 4KB guard pages (PROT_NONE) that would clobber
    // adjacent data if applied at 16KB granularity. Skip these.
    let addr_misaligned = addr & (page - 1) != 0;
    if is_fixed && (addr_misaligned || length < page) {
        if prot == 0 {
            // PROT_NONE guard page smaller than a macOS page — skip it
            return addr;
        }
        if flags & 0x20 != 0 {
            // MAP_ANONYMOUS + MAP_FIXED at sub-page granularity:
            // Ensure the containing pages are writable, zero the memory.
            let pg_start = addr & !(page - 1);
            let pg_end = (addr + length + page - 1) & !(page - 1);
            unsafe {
                libc::mprotect(pg_start as *mut _, (pg_end - pg_start) as usize,
                    libc::PROT_READ | libc::PROT_WRITE);
                std::ptr::write_bytes(addr as *mut u8, 0, length as usize);
            }
            return addr;
        }
        // File-backed MAP_FIXED at sub-page address: we can't use mmap.
        // The address space is already mapped (anonymous — we never create
        // file-backed pages). Make the containing pages writable, pread
        // the data, then patch if executable. All safe in signal context
        // because pages are anonymous.
        if fd >= 0 {
            let pg_start = addr & !(page - 1);
            let pg_end = (addr + length + page - 1) & !(page - 1);
            unsafe {
                libc::mprotect(pg_start as *mut _, (pg_end - pg_start) as usize,
                    libc::PROT_READ | libc::PROT_WRITE);
            }
            let read_len = file_read_len(fd, offset, length);
            if read_len > 0 {
                pread_full(fd, addr, read_len, offset as i64);
            }
            if has_exec && length > 0 {
                loader::patch_new_code(addr, length);
                extern "C" { fn sys_icache_invalidate(start: *mut libc::c_void, size: usize); }
                unsafe { sys_icache_invalidate(addr as *mut _, length as usize); }
            }
            return addr;
        }
    }

    // ── File-backed mmap (fd >= 0): always map anonymous + pread ─────────
    // Never create file-backed pages. On macOS, mmap(fd) and mprotect on
    // file-backed pages from inside a signal handler causes an uninterruptible
    // kernel deadlock. pread is async-signal-safe and avoids this entirely.
    if fd >= 0 && flags & 0x20 == 0 {
        let anon_flags = if is_fixed {
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED
        } else {
            libc::MAP_PRIVATE | libc::MAP_ANON
        };
        let hint = if addr == 0 { std::ptr::null_mut() } else { addr as *mut _ };

        // Map as RW so we can pread into it and patch if needed
        let ret = unsafe {
            libc::mmap(hint, length as usize, libc::PROT_READ | libc::PROT_WRITE, anon_flags, -1, 0)
        };
        if ret == libc::MAP_FAILED {
            return translate::linux_errno();
        }
        let result_addr = ret as u64;

        // Read file content (clamped to file size)
        let read_len = file_read_len(fd, offset, length);
        if read_len > 0 {
            pread_full(fd, result_addr, read_len, offset as i64);
        }

        // Patch SVC/TPIDR if executable
        if has_exec && length > 0 {
            loader::patch_new_code(result_addr, length);
            extern "C" { fn sys_icache_invalidate(start: *mut libc::c_void, size: usize); }
            unsafe { sys_icache_invalidate(result_addr as *mut _, length as usize); }
        }

        // Set final permissions (anonymous pages — mprotect is safe)
        unsafe { libc::mprotect(result_addr as *mut _, length as usize, mac_prot); }

        return result_addr;
    }

    // ── Anonymous mmap — pass through to macOS directly ──────────────────
    let mac_flags = translate::translate_mmap_flags(flags);
    let hint = if addr == 0 { std::ptr::null_mut() } else { addr as *mut _ };
    let ret = unsafe { libc::mmap(hint, length as usize, mac_prot, mac_flags, fd, offset as i64) };
    if ret == libc::MAP_FAILED {
        return translate::linux_errno();
    }
    ret as u64
}

/// Helper: pread that loops until all bytes are read (or EOF/error).
/// macOS pread can return short reads for large requests.
fn pread_full(fd: i32, addr: u64, len: u64, offset: i64) {
    let mut done: usize = 0;
    let total = len as usize;
    while done < total {
        let ret = unsafe {
            libc::pread(fd, (addr as usize + done) as *mut _, total - done, offset + done as i64)
        };
        if ret <= 0 { break; } // EOF or error
        done += ret as usize;
    }
}

/// Helper: compute how many bytes to pread from fd at offset, clamped to file size.
fn file_read_len(fd: i32, offset: u64, length: u64) -> u64 {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } == 0 {
        let file_size = st.st_size as u64;
        if offset < file_size {
            std::cmp::min(length, file_size - offset)
        } else {
            0
        }
    } else {
        length
    }
}

fn do_munmap(addr: u64, length: u64) -> u64 {
    let page: u64 = 16384;
    // macOS requires 16KB alignment. Linux guests use 4KB pages.
    // Only unmap fully-covered 16KB pages; silently succeed for sub-page unmaps.
    let aligned_addr = (addr + page - 1) & !(page - 1); // round UP
    let aligned_end = (addr + length) & !(page - 1);      // round DOWN

    if aligned_addr >= aligned_end {
        // No full 16KB pages covered — silently succeed
        return 0;
    }

    let aligned_len = aligned_end - aligned_addr;
    let ret = unsafe { libc::munmap(aligned_addr as *mut _, aligned_len as usize) };
    if ret < 0 { translate::linux_errno() } else { 0 }
}

fn do_mprotect(addr: u64, len: u64, prot: u64) -> u64 {
    let mac_prot = translate::translate_mmap_prot(prot);
    let page: u64 = 16384;
    let has_exec = prot & 4 != 0; // PROT_EXEC

    // macOS requires 16KB page alignment; Linux guests use 4KB.
    // Only protect fully-covered 16KB pages to avoid making adjacent
    // writable data read-only (e.g., RELRO vs .data sharing a page).
    let aligned_addr = (addr + page - 1) & !(page - 1); // round UP
    let aligned_end = (addr + len) & !(page - 1);        // round DOWN

    if aligned_addr >= aligned_end {
        // No full 16KB pages covered — silently succeed.
        // This commonly happens for RELRO regions smaller than 16KB.
        return 0;
    }

    let aligned_len = aligned_end - aligned_addr;

    // When adding PROT_EXEC, scan and patch SVC/TPIDR instructions first.
    // The page must be writable to patch, so we need mprotect→RW, patch,
    // then mprotect→final. But mprotect on file-backed pages from signal
    // context causes a macOS kernel deadlock, so defer to the trampoline.
    if has_exec && aligned_len > 0 {
        thread::set_pending_patch(thread::PendingPatchWork {
            kind: thread::PendingPatchKind::MprotectExec {
                aligned_addr,
                aligned_len,
                mac_prot,
            },
        });
        return 0;
    }

    // Non-exec mprotect: safe to do inline (no patching needed)
    let ret = unsafe { libc::mprotect(aligned_addr as *mut _, aligned_len as usize, mac_prot) };
    if ret < 0 { translate::linux_errno() } else { 0 }
}

// ─── Info / misc ────────────────────────────────────────────────────────────

fn do_clock_gettime(clk_id: i32, tp: u64) -> u64 {
    unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        let ret = libc::clock_gettime(translate_clock_id(clk_id), &mut ts);
        if ret < 0 {
            return translate::linux_errno();
        }
        let out = tp as *mut i64;
        *out = ts.tv_sec as i64;
        *out.add(1) = ts.tv_nsec as i64;
    }
    0
}

fn do_uname(buf: u64) -> u64 {
    let ptr = buf as *mut u8;
    unsafe {
        std::ptr::write_bytes(ptr, 0, 6 * 65);
        let write_field = |offset: usize, val: &[u8]| {
            let dst = ptr.add(offset);
            std::ptr::copy_nonoverlapping(val.as_ptr(), dst, val.len());
        };
        write_field(0, b"Linux");
        write_field(65, b"fakelinux");
        write_field(130, b"6.1.0-fakelinux");
        write_field(195, b"#1 SMP");
        write_field(260, b"aarch64");
        write_field(325, b"(none)");
    }
    0
}

fn do_getrandom(buf: u64, buflen: u64, _flags: u32) -> u64 {
    let ptr = buf as *mut u8;
    for i in 0..buflen as usize {
        unsafe { *ptr.add(i) = libc::arc4random() as u8; }
    }
    buflen
}

fn do_prlimit64(_pid: u64, resource: i32, _new_limit: u64, old_limit: u64) -> u64 {
    const RLIMIT_NOFILE: i32 = 7;
    if old_limit != 0 {
        unsafe {
            let ptr = old_limit as *mut u64;
            if resource == RLIMIT_NOFILE {
                // Return a reasonable fd limit; u64::MAX causes glibc to iterate
                // millions of fds in closefrom() fallback
                *ptr = 1024;       // rlim_cur
                *ptr.add(1) = 4096; // rlim_max
            } else {
                *ptr = u64::MAX;
                *ptr.add(1) = u64::MAX;
            }
        }
    }
    0
}

fn do_sched_getaffinity(_pid: i32, cpusetsize: u32, mask_ptr: u64) -> u64 {
    // Get number of CPUs via sysctl hw.ncpu
    let ncpu: i32 = unsafe {
        let mut ncpu: i32 = 1;
        let mut len = std::mem::size_of::<i32>();
        let name = b"hw.ncpu\0";
        libc::sysctlbyname(
            name.as_ptr() as *const i8,
            &mut ncpu as *mut _ as *mut _,
            &mut len,
            std::ptr::null_mut(),
            0,
        );
        if ncpu < 1 { 1 } else { ncpu }
    };

    // Write a bitmask with `ncpu` bits set
    let bytes_needed = ((ncpu as u32 + 7) / 8).max(1) as usize;
    let write_len = std::cmp::min(cpusetsize as usize, bytes_needed);

    if write_len == 0 || mask_ptr == 0 {
        return (-22_i64) as u64; // -EINVAL
    }

    // Zero the entire buffer first
    unsafe {
        std::ptr::write_bytes(mask_ptr as *mut u8, 0, cpusetsize as usize);
    }

    // Set bits for each CPU
    let mask = mask_ptr as *mut u8;
    for cpu in 0..ncpu as usize {
        let byte_idx = cpu / 8;
        let bit_idx = cpu % 8;
        if byte_idx < cpusetsize as usize {
            unsafe { *mask.add(byte_idx) |= 1 << bit_idx; }
        }
    }

    // Linux returns the number of bytes written (clamped to cpusetsize)
    cpusetsize as u64
}

fn do_pselect6(nfds: i32, readfds: u64, writefds: u64, exceptfds: u64, timeout: u64, sig: u64) -> u64 {
    // Linux pselect6 6th arg is struct { sigset_t*, size_t } — a pointer to
    // {sigmask_ptr, sigsetsize}. We extract the sigmask if provided.
    let timeout_ptr = if timeout == 0 {
        std::ptr::null()
    } else {
        timeout as *const libc::timespec
    };

    // Extract sigmask from the Linux pselect6 wrapper struct
    let sigmask_ptr: *const libc::sigset_t = if sig != 0 {
        let sigmask_pp = unsafe { *(sig as *const u64) };
        if sigmask_pp != 0 {
            sigmask_pp as *const libc::sigset_t
        } else {
            std::ptr::null()
        }
    } else {
        std::ptr::null()
    };

    let rdbits_before = if readfds != 0 { unsafe { *(readfds as *const u64) } } else { 0 };
    let wrbits_before = if writefds != 0 { unsafe { *(writefds as *const u64) } } else { 0 };

    let ret = unsafe {
        libc::pselect(
            nfds,
            if readfds == 0 { std::ptr::null_mut() } else { readfds as *mut libc::fd_set },
            if writefds == 0 { std::ptr::null_mut() } else { writefds as *mut libc::fd_set },
            if exceptfds == 0 { std::ptr::null_mut() } else { exceptfds as *mut libc::fd_set },
            timeout_ptr,
            sigmask_ptr,
        )
    };

    if TRACE.load(std::sync::atomic::Ordering::Relaxed) && (ret > 0 || nfds > 3) {
        let rdbits_after = if readfds != 0 { unsafe { *(readfds as *const u64) } } else { 0 };
        let wrbits_after = if writefds != 0 { unsafe { *(writefds as *const u64) } } else { 0 };
        raw_eprintln_fmt(format_args!(
            "fakelinux: pselect6 nfds={} rd:{:#x}→{:#x} wr:{:#x}→{:#x} ret={}\n",
            nfds, rdbits_before, rdbits_after, wrbits_before, wrbits_after, ret));
    }

    if ret < 0 { translate::linux_errno() } else { ret as u64 }
}

fn do_prctl(option: i32, arg2: u64, _arg3: u64, _arg4: u64, _arg5: u64) -> u64 {
    const PR_SET_NAME: i32 = 15;
    const PR_GET_NAME: i32 = 16;
    const PR_SET_VMA: i32 = 0x53564d41_u32 as i32;
    const PR_SET_NO_NEW_PRIVS: i32 = 38;
    const PR_GET_NO_NEW_PRIVS: i32 = 39;
    const PR_SET_PDEATHSIG: i32 = 1;
    const PR_GET_PDEATHSIG: i32 = 2;
    const PR_CAPBSET_READ: i32 = 23;
    const PR_CAPBSET_DROP: i32 = 24;

    match option {
        PR_SET_NAME => {
            // Set thread name via macOS pthread_setname_np
            if arg2 != 0 {
                let name = unsafe { std::ffi::CStr::from_ptr(arg2 as *const i8) };
                // Truncate to 15 chars (Linux limit)
                let s = name.to_bytes();
                let len = s.len().min(15);
                let truncated = std::ffi::CString::new(&s[..len]).unwrap_or_default();
                unsafe { libc::pthread_setname_np(truncated.as_ptr()); }
            }
            0
        }
        PR_GET_NAME => {
            // Get thread name — read from macOS thread name
            if arg2 != 0 {
                let mut name_buf = [0u8; 16];
                unsafe {
                    libc::pthread_getname_np(
                        libc::pthread_self(),
                        name_buf.as_mut_ptr() as *mut i8,
                        16,
                    );
                    std::ptr::copy_nonoverlapping(
                        name_buf.as_ptr(),
                        arg2 as *mut u8,
                        16,
                    );
                }
            }
            0
        }
        PR_SET_VMA => 0, // stub success (used for naming anonymous mappings)
        PR_SET_NO_NEW_PRIVS => 0,
        PR_GET_NO_NEW_PRIVS => 0,
        PR_CAPBSET_READ => 1, // report all capabilities as present (we run as "root")
        PR_CAPBSET_DROP => 0, // stub success
        PR_SET_PDEATHSIG => 0,
        PR_GET_PDEATHSIG => {
            if arg2 != 0 {
                unsafe { *(arg2 as *mut i32) = 0; }
            }
            0
        }
        _ => {
            raw_eprintln_fmt(format_args!(
                "fakelinux: prctl option={:#x} unimplemented, returning 0\n", option as u32
            ));
            0 // stub success for unknown prctl options
        }
    }
}

fn do_sysinfo(buf: u64) -> u64 {
    // Linux struct sysinfo on aarch64 (64-bit) is 112 bytes:
    //   offset  0: i64 uptime
    //   offset  8: [u64; 3] loads
    //   offset 32: u64 totalram
    //   offset 40: u64 freeram
    //   offset 48: u64 sharedram
    //   offset 56: u64 bufferram
    //   offset 64: u64 totalswap
    //   offset 72: u64 freeswap
    //   offset 80: u16 procs
    //   offset 82: u16 pad
    //   offset 84: u32 pad2
    //   offset 88: u64 totalhigh
    //   offset 96: u64 freehigh
    //   offset 104: u32 mem_unit
    if buf == 0 {
        return (-14_i64) as u64; // -EFAULT
    }
    let out = buf as *mut u8;
    unsafe {
        std::ptr::write_bytes(out, 0, 112);

        // Uptime via sysctl kern.boottime
        let mut boottime: libc::timeval = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::timeval>();
        let name = b"kern.boottime\0";
        libc::sysctlbyname(
            name.as_ptr() as *const i8,
            &mut boottime as *mut _ as *mut _,
            &mut len,
            std::ptr::null_mut(),
            0,
        );
        let mut now: libc::timeval = std::mem::zeroed();
        libc::gettimeofday(&mut now, std::ptr::null_mut());
        let uptime = now.tv_sec - boottime.tv_sec;
        (out as *mut i64).write_unaligned(uptime);

        // Load averages
        let mut loadavg = [0.0f64; 3];
        libc::getloadavg(loadavg.as_mut_ptr(), 3);
        let loads = out.add(8) as *mut u64;
        for i in 0..3 {
            loads.add(i).write_unaligned((loadavg[i] * 65536.0) as u64);
        }

        // Memory info via sysctl hw.memsize
        let mut memsize: u64 = 0;
        let mut mlen = std::mem::size_of::<u64>();
        let mname = b"hw.memsize\0";
        libc::sysctlbyname(
            mname.as_ptr() as *const i8,
            &mut memsize as *mut _ as *mut _,
            &mut mlen,
            std::ptr::null_mut(),
            0,
        );
        (out.add(32) as *mut u64).write_unaligned(memsize); // totalram
        (out.add(40) as *mut u64).write_unaligned(memsize / 2); // freeram (rough estimate)

        // procs — number of current processes (not CPUs)
        // Use kern.proc to approximate, or just report a reasonable default
        let mut nprocs: i32 = 0;
        let mut nplen = std::mem::size_of::<i32>();
        let npname = b"kern.nprocs\0";
        let np_ret = libc::sysctlbyname(
            npname.as_ptr() as *const i8,
            &mut nprocs as *mut _ as *mut _,
            &mut nplen,
            std::ptr::null_mut(),
            0,
        );
        if np_ret != 0 || nprocs <= 0 { nprocs = 100; } // fallback estimate
        (out.add(80) as *mut u16).write_unaligned(nprocs as u16);

        // mem_unit = 1 (at offset 104 on aarch64, not 100)
        (out.add(104) as *mut u32).write_unaligned(1);
    }
    0
}

fn do_getrusage(who: i32, buf: u64) -> u64 {
    if buf == 0 {
        return (-14_i64) as u64; // -EFAULT
    }
    // Linux and macOS getrusage 'who' values are the same:
    // RUSAGE_SELF=0, RUSAGE_CHILDREN=-1, RUSAGE_THREAD=1
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        let ret = libc::getrusage(who, &mut usage);
        if ret < 0 {
            return translate::linux_errno();
        }
        // Linux struct rusage on aarch64: same layout as macOS (timeval pairs + longs)
        // Both are 144 bytes on 64-bit platforms. Copy directly.
        std::ptr::copy_nonoverlapping(
            &usage as *const _ as *const u8,
            buf as *mut u8,
            std::mem::size_of::<libc::rusage>(),
        );
    }
    0
}

fn do_membarrier(cmd: i32, _flags: u32, _cpu_id: i32) -> u64 {
    // cmd=0 is MEMBARRIER_CMD_QUERY — return supported commands bitmask
    // For simplicity, return 0 (no commands supported beyond QUERY)
    if cmd == 0 {
        0 // QUERY: return bitmask of supported commands
    } else {
        (-38_i64) as u64 // -ENOSYS for all other commands
    }
}

fn do_statfs(pathname: u64, buf: u64) -> u64 {
    let (eff_path, _hold) = effective_path_ptr(pathname);
    unsafe {
        let mut mac_statfs: libc::statfs = std::mem::zeroed();
        let ret = libc::statfs(eff_path, &mut mac_statfs);
        if ret == 0 {
            let out = buf as *mut u8;
            std::ptr::write_bytes(out, 0, 120);
            let w64 = |off: usize, val: u64| {
                (out.add(off) as *mut u64).write_unaligned(val);
            };
            w64(0, 0xEF53); // EXT4_SUPER_MAGIC
            w64(8, mac_statfs.f_bsize as u64);
            w64(16, mac_statfs.f_blocks as u64);
            w64(24, mac_statfs.f_bfree as u64);
            w64(32, mac_statfs.f_bavail as u64);
            w64(40, mac_statfs.f_files as u64);
            w64(48, mac_statfs.f_ffree as u64);
            (out.add(56) as *mut u64).write_unaligned(0); // f_fsid
            w64(64, 255); // f_namelen
            w64(72, mac_statfs.f_bsize as u64); // f_frsize
            w64(80, 0); // f_flags
            return 0;
        }
    }
    // Fallback to original path if translation failed
    if _hold.is_some() {
        unsafe {
            let mut mac_statfs: libc::statfs = std::mem::zeroed();
            let ret = libc::statfs(pathname as *const i8, &mut mac_statfs);
            if ret == 0 {
                let out = buf as *mut u8;
                std::ptr::write_bytes(out, 0, 120);
                let w64 = |off: usize, val: u64| {
                    (out.add(off) as *mut u64).write_unaligned(val);
                };
                w64(0, 0xEF53);
                w64(8, mac_statfs.f_bsize as u64);
                w64(16, mac_statfs.f_blocks as u64);
                w64(24, mac_statfs.f_bfree as u64);
                w64(32, mac_statfs.f_bavail as u64);
                w64(40, mac_statfs.f_files as u64);
                w64(48, mac_statfs.f_ffree as u64);
                (out.add(56) as *mut u64).write_unaligned(0);
                w64(64, 255);
                w64(72, mac_statfs.f_bsize as u64);
                w64(80, 0);
                return 0;
            }
        }
    }
    translate::linux_errno()
}

fn do_fstatfs(fd: i32, buf: u64) -> u64 {
    // Linux struct statfs on aarch64 is 120 bytes:
    //   offset  0: u64 f_type
    //   offset  8: u64 f_bsize
    //   offset 16: u64 f_blocks
    //   offset 24: u64 f_bfree
    //   offset 32: u64 f_bavail
    //   offset 40: u64 f_files
    //   offset 48: u64 f_ffree
    //   offset 56: [i32; 2] f_fsid
    //   offset 64: u64 f_namelen
    //   offset 72: u64 f_frsize
    //   offset 80: u64 f_flags
    //   offset 88: [u64; 4] f_spare
    unsafe {
        let mut mac_statfs: libc::statfs = std::mem::zeroed();
        let ret = libc::fstatfs(fd, &mut mac_statfs);
        if ret < 0 {
            return translate::linux_errno();
        }
        let out = buf as *mut u8;
        std::ptr::write_bytes(out, 0, 120);
        let w64 = |off: usize, val: u64| {
            (out.add(off) as *mut u64).write_unaligned(val);
        };
        // EXT4_SUPER_MAGIC = 0xEF53 (pretend to be ext4)
        w64(0, 0xEF53);
        w64(8, mac_statfs.f_bsize as u64);
        w64(16, mac_statfs.f_blocks as u64);
        w64(24, mac_statfs.f_bfree as u64);
        w64(32, mac_statfs.f_bavail as u64);
        w64(40, mac_statfs.f_files as u64);
        w64(48, mac_statfs.f_ffree as u64);
        // f_fsid: zero it out (macOS fsid_t layout differs)
        (out.add(56) as *mut u64).write_unaligned(0);
        w64(64, 255); // f_namelen
        w64(72, mac_statfs.f_bsize as u64); // f_frsize = f_bsize
        w64(80, 0); // f_flags
    }
    0
}

fn do_sendfile(out_fd: i32, in_fd: i32, offset_ptr: u64, count: u64) -> u64 {
    // sendfile(out_fd, in_fd, offset, count) — copy data between file descriptors
    // macOS has sendfile with a different signature, so we implement via read/write loop.
    let mut remaining = count as usize;
    let mut total: usize = 0;
    let mut buf = [0u8; 8192];

    // If offset_ptr is non-null, seek in_fd to that offset first, and update it after
    let mut offset_val: i64 = 0;
    let has_offset = offset_ptr != 0;
    if has_offset {
        offset_val = unsafe { (offset_ptr as *const i64).read_unaligned() };
    }

    while remaining > 0 {
        let to_read = remaining.min(buf.len());
        let nread = if has_offset {
            let r = unsafe { libc::pread(in_fd, buf.as_mut_ptr() as *mut _, to_read, offset_val) };
            if r > 0 {
                offset_val += r as i64;
            }
            r
        } else {
            unsafe { libc::read(in_fd, buf.as_mut_ptr() as *mut _, to_read) }
        };

        if nread < 0 {
            if total > 0 {
                break;
            }
            return crate::translate::linux_errno();
        }
        if nread == 0 {
            break; // EOF
        }

        // Write all read data to out_fd
        let mut written = 0usize;
        while written < nread as usize {
            let nw = unsafe {
                libc::write(
                    out_fd,
                    buf[written..].as_ptr() as *const _,
                    nread as usize - written,
                )
            };
            if nw < 0 {
                if total > 0 {
                    if has_offset {
                        unsafe { (offset_ptr as *mut i64).write_unaligned(offset_val) };
                    }
                    return total as u64;
                }
                return crate::translate::linux_errno();
            }
            written += nw as usize;
        }
        total += nread as usize;
        remaining -= nread as usize;
    }

    if has_offset {
        unsafe { (offset_ptr as *mut i64).write_unaligned(offset_val) };
    }
    total as u64
}

fn do_symlinkat(target: u64, newdirfd: i32, linkpath: u64) -> u64 {
    let target_ptr = target as *const libc::c_char;
    let (eff_path, _hold) = effective_path_ptr(linkpath);
    let dirfd = translate::translate_dirfd(newdirfd);
    let ret = unsafe { libc::symlinkat(target_ptr, dirfd, eff_path) };
    if ret == 0 {
        0
    } else if _hold.is_some() {
        let ret2 = unsafe { libc::symlinkat(target_ptr, dirfd, linkpath as *const libc::c_char) };
        if ret2 < 0 { translate::linux_errno() } else { 0 }
    } else {
        translate::linux_errno()
    }
}

fn do_linkat(olddirfd: i32, oldpath: u64, newdirfd: i32, newpath: u64, flags: i32) -> u64 {
    let (eff_old, _hold_old) = effective_path_ptr(oldpath);
    let (eff_new, _hold_new) = effective_path_ptr(newpath);
    // Linux AT_EMPTY_PATH=0x1000, AT_SYMLINK_FOLLOW=0x400 — same on macOS
    let ret = unsafe {
        libc::linkat(
            translate::translate_dirfd(olddirfd),
            eff_old,
            translate::translate_dirfd(newdirfd),
            eff_new,
            flags,
        )
    };
    if ret < 0 { translate::linux_errno() } else { 0 }
}

fn do_flock(fd: i32, operation: i32) -> u64 {
    // Linux and macOS flock constants are the same (LOCK_SH=1, LOCK_EX=2, LOCK_UN=8, LOCK_NB=4)
    let ret = unsafe { libc::flock(fd, operation) };
    if ret < 0 { translate::linux_errno() } else { 0 }
}

fn do_utimensat(dirfd: i32, pathname: u64, times_ptr: u64, flags: i32) -> u64 {
    // Linux struct timespec is {i64 tv_sec, i64 tv_nsec} — same layout on macOS aarch64
    // Special values: UTIME_NOW = 0x3FFFFFFF, UTIME_OMIT = 0x3FFFFFFE
    let mac_dirfd = translate::translate_dirfd(dirfd);

    if pathname == 0 {
        // futimens variant: operate on fd directly
        // macOS doesn't have futimens as a syscall, use futimes
        if times_ptr == 0 {
            // NULL times = set both to now
            let ret = unsafe { libc::futimes(dirfd, std::ptr::null()) };
            if ret < 0 { return translate::linux_errno(); }
            return 0;
        }
        // Read Linux timespecs and convert to macOS timeval for futimes
        let ts = times_ptr as *const libc::timespec;
        let atime = unsafe { *ts };
        let mtime = unsafe { *ts.add(1) };
        let times = [
            timespec_to_timeval(&atime),
            timespec_to_timeval(&mtime),
        ];
        let ret = unsafe { libc::futimes(dirfd, times.as_ptr()) };
        if ret < 0 { return translate::linux_errno(); }
        return 0;
    }

    let (eff_path, _hold) = effective_path_ptr(pathname);

    if times_ptr == 0 {
        // NULL times = set both to now; use utimes with NULL
        let ret = unsafe { libc::utimes(eff_path, std::ptr::null()) };
        if ret == 0 { return 0; }
        if _hold.is_some() {
            let ret2 = unsafe { libc::utimes(pathname as *const libc::c_char, std::ptr::null()) };
            if ret2 < 0 { return translate::linux_errno(); }
            return 0;
        }
        return translate::linux_errno();
    }

    // Read Linux timespecs
    let ts = times_ptr as *const libc::timespec;
    let atime = unsafe { *ts };
    let mtime = unsafe { *ts.add(1) };

    // Check for UTIME_OMIT — if both are OMIT, nothing to do
    const UTIME_OMIT: i64 = 0x3FFFFFFE;
    const UTIME_NOW: i64 = 0x3FFFFFFF;
    if atime.tv_nsec as i64 == UTIME_OMIT && mtime.tv_nsec as i64 == UTIME_OMIT {
        return 0;
    }

    // For UTIME_NOW/UTIME_OMIT we need to read current times first
    // macOS doesn't support these flags natively, so we emulate
    let mut tv = [
        timespec_to_timeval(&atime),
        timespec_to_timeval(&mtime),
    ];

    // If either is UTIME_NOW or UTIME_OMIT, get current times
    if atime.tv_nsec as i64 == UTIME_NOW || atime.tv_nsec as i64 == UTIME_OMIT
        || mtime.tv_nsec as i64 == UTIME_NOW || mtime.tv_nsec as i64 == UTIME_OMIT
    {
        // Get current time for NOW, current file time for OMIT
        let mut now_tv: libc::timeval = unsafe { std::mem::zeroed() };
        unsafe { libc::gettimeofday(&mut now_tv, std::ptr::null_mut()) };

        if atime.tv_nsec as i64 == UTIME_NOW {
            tv[0] = now_tv;
        } else if atime.tv_nsec as i64 == UTIME_OMIT {
            // Need to stat the file to get current atime
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let _r = if flags & 0x100 != 0 { // AT_SYMLINK_NOFOLLOW
                unsafe { libc::fstatat(mac_dirfd, eff_path, &mut st, libc::AT_SYMLINK_NOFOLLOW) }
            } else {
                unsafe { libc::fstatat(mac_dirfd, eff_path, &mut st, 0) }
            };
            tv[0].tv_sec = st.st_atime;
            tv[0].tv_usec = st.st_atime_nsec as i32 / 1000;
        }
        if mtime.tv_nsec as i64 == UTIME_NOW {
            tv[1] = now_tv;
        } else if mtime.tv_nsec as i64 == UTIME_OMIT {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let _r = if flags & 0x100 != 0 {
                unsafe { libc::fstatat(mac_dirfd, eff_path, &mut st, libc::AT_SYMLINK_NOFOLLOW) }
            } else {
                unsafe { libc::fstatat(mac_dirfd, eff_path, &mut st, 0) }
            };
            tv[1].tv_sec = st.st_mtime;
            tv[1].tv_usec = st.st_mtime_nsec as i32 / 1000;
        }
    }

    let ret = unsafe { libc::utimes(eff_path, tv.as_ptr()) };
    if ret == 0 { return 0; }
    if _hold.is_some() {
        let ret2 = unsafe { libc::utimes(pathname as *const libc::c_char, tv.as_ptr()) };
        if ret2 < 0 { return translate::linux_errno(); }
        return 0;
    }
    translate::linux_errno()
}

fn timespec_to_timeval(ts: &libc::timespec) -> libc::timeval {
    libc::timeval {
        tv_sec: ts.tv_sec,
        tv_usec: (ts.tv_nsec / 1000) as i32,
    }
}

fn do_ftruncate(fd: i32, length: i64) -> u64 {
    let ret = unsafe { libc::ftruncate(fd, length) };
    if ret < 0 { translate::linux_errno() } else { 0 }
}

fn do_nanosleep(req_ptr: u64, rem_ptr: u64) -> u64 {
    // Linux and macOS struct timespec have the same layout on aarch64
    let req = req_ptr as *const libc::timespec;
    let rem = if rem_ptr != 0 { rem_ptr as *mut libc::timespec } else { std::ptr::null_mut() };
    let ret = unsafe { libc::nanosleep(req, rem) };
    if ret < 0 { translate::linux_errno() } else { 0 }
}

fn do_clock_getres(clk_id: i32, res_ptr: u64) -> u64 {
    // Translate Linux clock IDs to macOS (CLOCK_REALTIME=0, CLOCK_MONOTONIC=1 are the same)
    let mac_clk = translate_clock_id(clk_id);
    if res_ptr == 0 {
        // Just checking if clock is supported
        return 0;
    }
    let res = res_ptr as *mut libc::timespec;
    let ret = unsafe { libc::clock_getres(mac_clk, res) };
    if ret < 0 { translate::linux_errno() } else { 0 }
}

fn do_clock_nanosleep(clk_id: i32, flags: i32, req_ptr: u64, rem_ptr: u64) -> u64 {
    // flags: 0 = relative, 1 = TIMER_ABSTIME
    // macOS doesn't have clock_nanosleep, emulate via nanosleep for relative
    let req = req_ptr as *const libc::timespec;
    let rem = if rem_ptr != 0 { rem_ptr as *mut libc::timespec } else { std::ptr::null_mut() };

    if flags & 1 != 0 {
        // TIMER_ABSTIME: compute relative time
        let mac_clk = translate_clock_id(clk_id);
        let mut now: libc::timespec = unsafe { std::mem::zeroed() };
        unsafe { libc::clock_gettime(mac_clk, &mut now) };
        let abs = unsafe { *req };
        let rel = libc::timespec {
            tv_sec: abs.tv_sec - now.tv_sec - if abs.tv_nsec < now.tv_nsec { 1 } else { 0 },
            tv_nsec: if abs.tv_nsec >= now.tv_nsec {
                abs.tv_nsec - now.tv_nsec
            } else {
                1_000_000_000 + abs.tv_nsec - now.tv_nsec
            },
        };
        if rel.tv_sec < 0 {
            return 0; // already past
        }
        let ret = unsafe { libc::nanosleep(&rel, std::ptr::null_mut()) };
        if ret < 0 { translate::linux_errno() } else { 0 }
    } else {
        let ret = unsafe { libc::nanosleep(req, rem) };
        if ret < 0 { translate::linux_errno() } else { 0 }
    }
}

fn translate_clock_id(linux_clk: i32) -> libc::clockid_t {
    match linux_clk {
        0 => libc::CLOCK_REALTIME,        // CLOCK_REALTIME
        1 => libc::CLOCK_MONOTONIC,       // CLOCK_MONOTONIC
        2 => libc::CLOCK_PROCESS_CPUTIME_ID, // CLOCK_PROCESS_CPUTIME_ID
        3 => libc::CLOCK_THREAD_CPUTIME_ID,  // CLOCK_THREAD_CPUTIME_ID
        4 => libc::CLOCK_MONOTONIC,       // CLOCK_MONOTONIC_RAW → MONOTONIC
        5 => libc::CLOCK_REALTIME,        // CLOCK_REALTIME_COARSE → REALTIME
        6 => libc::CLOCK_MONOTONIC,       // CLOCK_MONOTONIC_COARSE → MONOTONIC
        7 => libc::CLOCK_MONOTONIC,       // CLOCK_BOOTTIME → MONOTONIC
        _ => libc::CLOCK_REALTIME,
    }
}

fn do_setitimer(which: i32, new_value_ptr: u64, old_value_ptr: u64) -> u64 {
    // Linux and macOS itimerval have identical layout on 64-bit:
    // struct itimerval { struct timeval it_interval; struct timeval it_value; }
    // struct timeval { long tv_sec; long tv_usec; }
    // ITIMER_REAL=0, ITIMER_VIRTUAL=1, ITIMER_PROF=2 are the same on both.
    let new_ptr = if new_value_ptr != 0 {
        new_value_ptr as *const libc::itimerval
    } else {
        std::ptr::null()
    };
    let old_ptr = if old_value_ptr != 0 {
        old_value_ptr as *mut libc::itimerval
    } else {
        std::ptr::null_mut()
    };
    let ret = unsafe { libc::setitimer(which, new_ptr, old_ptr) };
    if ret < 0 { translate::linux_errno() } else { 0 }
}

fn do_fallocate(fd: i32, mode: i32, offset: i64, len: i64) -> u64 {
    // macOS doesn't have fallocate. Mode 0 = allocate space.
    // Use ftruncate for basic allocation, or just succeed for FALLOC_FL_KEEP_SIZE.
    const FALLOC_FL_KEEP_SIZE: i32 = 0x01;
    const FALLOC_FL_PUNCH_HOLE: i32 = 0x02;

    if mode == 0 {
        // Extend file if needed
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::fstat(fd, &mut st) };
        if ret < 0 {
            return translate::linux_errno();
        }
        let end = offset + len;
        if end > st.st_size as i64 {
            let ret = unsafe { libc::ftruncate(fd, end as libc::off_t) };
            if ret < 0 { return translate::linux_errno(); }
        }
        0
    } else if mode & FALLOC_FL_KEEP_SIZE != 0 && mode & FALLOC_FL_PUNCH_HOLE == 0 {
        // Pre-allocate but don't change size — best-effort success
        0
    } else {
        // PUNCH_HOLE etc. not supported
        (-95_i64) as u64 // -EOPNOTSUPP
    }
}

fn do_guest_sigaltstack(ss_ptr: u64, old_ss_ptr: u64) -> u64 {
    // Linux sigaltstack: struct { void *ss_sp; int ss_flags; size_t ss_size; }
    // We store the guest's sigaltstack in thread-local state.
    // For now, just report "not active" and accept the set.
    use crate::signal;

    if old_ss_ptr != 0 {
        let old = old_ss_ptr as *mut u8;
        unsafe {
            let (sp, flags, size) = signal::get_guest_sigaltstack();
            (old as *mut u64).write_unaligned(sp);
            (old.add(8) as *mut i32).write_unaligned(flags);
            // pad 4 bytes
            (old.add(16) as *mut u64).write_unaligned(size);
        }
    }
    if ss_ptr != 0 {
        let ss = ss_ptr as *const u8;
        unsafe {
            let sp = (ss as *const u64).read_unaligned();
            let flags = (ss.add(8) as *const i32).read_unaligned();
            let size = (ss.add(16) as *const u64).read_unaligned();
            signal::set_guest_sigaltstack(sp, flags, size);
        }
    }
    0
}

fn do_renameat2(olddirfd: i32, oldpath: u64, newdirfd: i32, newpath: u64, flags: u32) -> u64 {
    const RENAME_NOREPLACE: u32 = 1;
    const RENAME_EXCHANGE: u32 = 2;

    let old_cstr = oldpath as *const libc::c_char;
    let new_cstr = newpath as *const libc::c_char;
    let mac_olddir = translate::translate_dirfd(olddirfd);
    let mac_newdir = translate::translate_dirfd(newdirfd);

    if flags == 0 {
        // Plain rename
        let ret = unsafe { libc::renameat(mac_olddir, old_cstr, mac_newdir, new_cstr) };
        if ret < 0 { translate::linux_errno() } else { 0 }
    } else if flags == RENAME_NOREPLACE {
        // Check destination doesn't exist first, then rename
        let ret = unsafe { libc::faccessat(mac_newdir, new_cstr, libc::F_OK, 0) };
        if ret == 0 {
            return (-17_i64) as u64; // -EEXIST
        }
        let ret = unsafe { libc::renameat(mac_olddir, old_cstr, mac_newdir, new_cstr) };
        if ret < 0 { translate::linux_errno() } else { 0 }
    } else if flags == RENAME_EXCHANGE {
        // macOS has renamex_np with RENAME_SWAP
        #[cfg(target_os = "macos")]
        {
            const RENAME_SWAP: u32 = 2;
            extern "C" {
                fn renamex_np(from: *const libc::c_char, to: *const libc::c_char, flags: u32) -> libc::c_int;
            }
            // renamex_np doesn't support *at variants, so resolve paths
            // For now, only support AT_FDCWD
            if olddirfd != libc::AT_FDCWD || newdirfd != libc::AT_FDCWD {
                return (-38_i64) as u64; // -ENOSYS
            }
            let ret = unsafe { renamex_np(old_cstr, new_cstr, RENAME_SWAP) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        #[cfg(not(target_os = "macos"))]
        {
            (-38_i64) as u64 // -ENOSYS
        }
    } else {
        (-22_i64) as u64 // -EINVAL
    }
}

fn do_memfd_create(name: u64, flags: u32) -> u64 {
    // macOS doesn't have memfd_create. Emulate with a temp file, unlinked immediately.
    // shm_open doesn't auto-extend on write, so use a real tmpfile instead.
    let _ = name;

    let template = std::ffi::CString::new("/tmp/fakelinux_memfd_XXXXXX").unwrap();
    let buf = template.into_bytes_with_nul();
    let mut buf = buf.to_vec();

    let fd = unsafe { libc::mkstemp(buf.as_mut_ptr() as *mut libc::c_char) };
    if fd < 0 {
        return translate::linux_errno();
    }
    // Unlink immediately — fd stays valid, file becomes anonymous
    unsafe { libc::unlink(buf.as_ptr() as *const libc::c_char); }

    // Set FD_CLOEXEC if MFD_CLOEXEC (1)
    if flags & 1 != 0 {
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC); }
    }

    fd as u64
}

fn do_copy_file_range(fd_in: i32, off_in_ptr: u64, fd_out: i32, off_out_ptr: u64, len: u64, flags: u32) -> u64 {
    if flags != 0 {
        return (-22_i64) as u64; // -EINVAL
    }

    // Read offset_in
    let mut off_in: i64 = -1;
    if off_in_ptr != 0 {
        off_in = unsafe { (off_in_ptr as *const i64).read_unaligned() };
    }

    let mut off_out: i64 = -1;
    if off_out_ptr != 0 {
        off_out = unsafe { (off_out_ptr as *const i64).read_unaligned() };
    }

    // Use sendfile on macOS as a fallback, or just read+write
    let buf_size = std::cmp::min(len as usize, 64 * 1024);
    let mut buf = vec![0u8; buf_size];
    let mut total: usize = 0;
    let mut remaining = len as usize;

    while remaining > 0 {
        let chunk = std::cmp::min(remaining, buf_size);
        let nread = if off_in >= 0 {
            let r = unsafe { libc::pread(fd_in, buf.as_mut_ptr() as *mut libc::c_void, chunk, off_in as libc::off_t) };
            if r > 0 { off_in += r as i64; }
            r
        } else {
            unsafe { libc::read(fd_in, buf.as_mut_ptr() as *mut libc::c_void, chunk) }
        };

        if nread < 0 {
            if total > 0 { break; }
            return translate::linux_errno();
        }
        if nread == 0 { break; }

        let mut written = 0usize;
        while written < nread as usize {
            let nwritten = if off_out >= 0 {
                let w = unsafe { libc::pwrite(fd_out, buf[written..].as_ptr() as *const libc::c_void, nread as usize - written, off_out as libc::off_t) };
                if w > 0 { off_out += w as i64; }
                w
            } else {
                unsafe { libc::write(fd_out, buf[written..].as_ptr() as *const libc::c_void, nread as usize - written) }
            };
            if nwritten < 0 {
                if total > 0 { break; }
                return translate::linux_errno();
            }
            written += nwritten as usize;
        }
        total += nread as usize;
        remaining -= nread as usize;
    }

    // Write back offsets
    if off_in_ptr != 0 {
        unsafe { (off_in_ptr as *mut i64).write_unaligned(off_in); }
    }
    if off_out_ptr != 0 {
        unsafe { (off_out_ptr as *mut i64).write_unaligned(off_out); }
    }

    total as u64
}
