use crate::epoll;
use crate::eventfd;
use crate::linux::*;
use crate::loader;
use crate::net;
use crate::procfs;
use crate::rootfs;
use crate::signal;
use crate::thread;
use crate::translate;
use crate::trap::ThreadState64;
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
pub fn emulate(nr: u64, args: &[u64; 6], _regs: &mut ThreadState64) -> u64 {
    let trace = TRACE.load(std::sync::atomic::Ordering::Relaxed);
    if trace {
        raw_eprintln_fmt(format_args!(
            "fakelinux: syscall {} (x0={:#x} x1={:#x} x2={:#x} x3={:#x} x4={:#x} x5={:#x})\n",
            nr, args[0], args[1], args[2], args[3], args[4], args[5]
        ));
    }
    let result = emulate_inner(nr, args, _regs);
    if trace {
        raw_eprintln_fmt(format_args!("fakelinux:   → {:#x} ({})\n", result, result as i64));
    }
    result
}

fn emulate_inner(nr: u64, args: &[u64; 6], _regs: &mut ThreadState64) -> u64 {
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
        SYS_GETPID => unsafe { libc::getpid() as u64 },
        SYS_GETPPID => unsafe { libc::getppid() as u64 },
        SYS_GETUID => unsafe { libc::getuid() as u64 },
        SYS_GETEUID => unsafe { libc::geteuid() as u64 },
        SYS_GETGID => unsafe { libc::getgid() as u64 },
        SYS_GETEGID => unsafe { libc::getegid() as u64 },
        SYS_GETTID => thread::current_tid() as u64,
        SYS_SET_TID_ADDRESS => thread::do_set_tid_address(args[0]),
        SYS_SET_ROBUST_LIST => 0,
        SYS_RT_SIGACTION => signal::do_rt_sigaction(args[0], args[1], args[2], args[3]),
        SYS_RT_SIGPROCMASK => signal::do_rt_sigprocmask(args[0], args[1], args[2], args[3]),
        SYS_RT_SIGRETURN => {
            // rt_sigreturn restores ALL registers from the sigframe on the stack.
            // It does NOT return a value in x0. We restore directly into _regs
            // and return a sentinel so the trap handler knows not to overwrite.
            if unsafe { signal::do_rt_sigreturn(_regs) } {
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
        SYS_CLONE => thread::do_clone_with_regs(args[0], args[1], args[2], args[3], args[4], _regs),
        SYS_FUTEX => thread::do_futex(args[0], args[1] as u32, args[2] as u32, args[3], args[4], args[5] as u32),
        SYS_DUP => do_dup(args[0] as i32),
        SYS_DUP3 => do_dup3(args[0] as i32, args[1] as i32, args[2] as i32),
        SYS_PIPE2 => do_pipe2(args[0], args[1] as i32),
        SYS_GETDENTS64 => do_getdents64(args[0] as i32, args[1], args[2]),
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
        SYS_RECVMSG => net::do_recvmsg(args[0] as i32, args[1], args[2] as i32),
        SYS_KILL => signal::do_kill(args[0] as i64, args[1] as i32),
        SYS_TKILL => signal::do_tkill(args[0] as i32, args[1] as i32),
        SYS_TGKILL => signal::do_tgkill(args[0] as i32, args[1] as i32, args[2] as i32),
        SYS_UMASK => {
            let ret = unsafe { libc::umask(args[0] as libc::mode_t) };
            ret as u64
        }
        SYS_GETGROUPS => {
            // getgroups(size, list) — return 0 groups for simplicity
            0
        }
        SYS_SETPRIORITY => 0, // stub success
        SYS_GETPRIORITY => 20, // default nice value
        SYS_SETITIMER => 0, // stub success
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
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_FCHMODAT => {
            let (eff_path, _hold) = effective_path_ptr(args[1]);
            let ret = unsafe { libc::fchmodat(translate::translate_dirfd(args[0] as i32), eff_path, args[2] as libc::mode_t, args[3] as i32) };
            if ret == 0 { 0 }
            else if _hold.is_some() {
                let ret2 = unsafe { libc::fchmodat(translate::translate_dirfd(args[0] as i32), args[1] as *const i8, args[2] as libc::mode_t, args[3] as i32) };
                if ret2 < 0 { translate::linux_errno() } else { 0 }
            } else { translate::linux_errno() }
        }
        SYS_FCHOWN => {
            let ret = unsafe { libc::fchown(args[0] as i32, args[1] as u32, args[2] as u32) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_FCHOWNAT => {
            let (eff_path, _hold) = effective_path_ptr(args[1]);
            let ret = unsafe { libc::fchownat(translate::translate_dirfd(args[0] as i32), eff_path, args[2] as u32, args[3] as u32, args[4] as i32) };
            if ret == 0 { 0 }
            else if _hold.is_some() {
                let ret2 = unsafe { libc::fchownat(translate::translate_dirfd(args[0] as i32), args[1] as *const i8, args[2] as u32, args[3] as u32, args[4] as i32) };
                if ret2 < 0 { translate::linux_errno() } else { 0 }
            } else { translate::linux_errno() }
        }
        SYS_WAIT4 => thread::do_wait4(args[0] as i64, args[1], args[2] as i32, args[3]),
        SYS_EXECVE => do_execve(args[0], args[1], args[2]),
        SYS_MEMBARRIER => do_membarrier(args[0] as i32, args[1] as u32, args[2] as i32),
        SYS_STATFS => do_statfs(args[0], args[1]),
        SYS_FSTATFS => do_fstatfs(args[0] as i32, args[1]),
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
    let path = unsafe { std::ffi::CStr::from_ptr(pathname as *const i8) };

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
    // Clean up eventfd/epoll state if this fd is one of those
    eventfd::on_close(fd);
    epoll::on_close(fd);
    let ret = unsafe { libc::close(fd) };
    if ret < 0 { translate::linux_errno() } else { 0 }
}

fn do_lseek(fd: i32, offset: i64, whence: i32) -> u64 {
    let ret = unsafe { libc::lseek(fd, offset, whence) };
    if ret < 0 { translate::linux_errno() } else { ret as u64 }
}

fn do_fstat(fd: i32, statbuf: u64) -> u64 {
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
    // TIOCGWINSZ (Linux 0x5413 = macOS TIOCGWINSZ)
    const LINUX_TIOCGWINSZ: u64 = 0x5413;
    match request {
        LINUX_TIOCGWINSZ => {
            let ret = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, arg as *mut libc::winsize) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        _ => (-25_i64) as u64, // -ENOTTY
    }
}

fn do_fcntl(fd: i32, linux_cmd: i32, arg: u64) -> u64 {
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
            unsafe {
                let mut mac_stat: libc::stat = std::mem::zeroed();
                let ret = libc::fstat(mac_dirfd, &mut mac_stat);
                if ret < 0 { return translate::linux_errno(); }
                translate::mac_stat_to_linux_statx(&mac_stat, statxbuf as *mut u8);
            }
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

    // Then the guest's original argv (applet name + args)
    let mut guest_argv = argv_ptr as *const *const i8;
    unsafe {
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

    // Debug
    unsafe {
        let msg = format!("fakelinux: execve pid={} → {:?}\n", libc::getpid(), resolved_path);
        libc::write(2, msg.as_ptr() as *const _, msg.len());
    }

    // If we're in a forked child (from signal handler), we can't execve
    // directly because sigreturn is broken. Instead, this execve replaces
    // the current process entirely — which works for the "last command"
    // optimization in shells (exec without fork).
    //
    // For fork+exec: the fork child _exit'd(127), so the parent's wait4
    // already reaped it. We're the PARENT now. We need to fork a fresh
    // child (outside signal handler context) and exec there.
    // But we're IN the signal handler... so let's try posix_spawn instead.
    let mut pid: libc::pid_t = 0;
    let ret = unsafe {
        libc::posix_spawn(
            &mut pid,
            self_exe_c.as_ptr(),
            std::ptr::null(),   // file_actions
            std::ptr::null(),   // attrp
            new_argv.as_ptr() as *const *mut i8,
            envp_to_use as *const *mut i8,
        )
    };
    if ret != 0 {
        return (-38_i64) as u64; // ENOSYS
    }
    // Wait for the spawned child
    let mut status: i32 = 0;
    unsafe { libc::waitpid(pid, &mut status, 0); }
    // Return the child's exit status encoded as _exit would
    if libc::WIFEXITED(status) {
        // Child exited normally — call _exit with its status
        unsafe { libc::_exit(libc::WEXITSTATUS(status)); }
    }
    unsafe { libc::_exit(127); }
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
    let mac_flags = translate::translate_mmap_flags(flags);
    let mac_prot = translate::translate_mmap_prot(prot);
    let page: u64 = 16384;
    let has_exec = prot & 4 != 0; // PROT_EXEC

    // Handle 4KB/16KB page size mismatch for MAP_FIXED mappings.
    // Linux guests may place 4KB guard pages (PROT_NONE) that would clobber
    // adjacent data if applied at 16KB granularity. Skip these.
    let is_fixed = flags & 0x10 != 0; // MAP_FIXED
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
        // The address space is already mapped (from the anonymous reservation).
        // Ensure the containing pages are writable, pread the data, then
        // set the requested protection.
        if fd >= 0 {
            // Make the containing macOS pages writable
            let pg_start = addr & !(page - 1);
            let pg_end = (addr + length + page - 1) & !(page - 1);
            unsafe {
                libc::mprotect(pg_start as *mut _, (pg_end - pg_start) as usize,
                    libc::PROT_READ | libc::PROT_WRITE);
            }

            let mut file_stat: libc::stat = unsafe { std::mem::zeroed() };
            let stat_ret = unsafe { libc::fstat(fd, &mut file_stat) };
            let read_len = if stat_ret == 0 {
                let file_size = file_stat.st_size as u64;
                if offset < file_size {
                    std::cmp::min(length, file_size - offset)
                } else {
                    0
                }
            } else {
                length
            };
            if read_len > 0 {
                unsafe {
                    libc::pread(fd, addr as *mut _, read_len as usize, offset as i64);
                }
            }
            // Patch SVC/TPIDR if executable
            if has_exec && length > 0 {
                loader::patch_new_code(addr, length);
                extern "C" {
                    fn sys_icache_invalidate(start: *mut libc::c_void, size: usize);
                }
                unsafe { sys_icache_invalidate(addr as *mut _, length as usize); }
            }
            // Note: we don't set final permissions here because the 16KB page
            // might be shared with other 4KB segments that need different perms.
            // The guest's subsequent mprotect calls will set permissions on
            // fully-covered 16KB pages.
            return addr;
        }
    }

    // If mapping with PROT_EXEC from a file, we need to patch code.
    // Map as RW first so we can patch, then set final permissions.
    let effective_prot = if has_exec && fd >= 0 {
        libc::PROT_READ | libc::PROT_WRITE
    } else {
        mac_prot
    };

    // Handle file-backed mmaps that extend beyond the file size.
    // On Linux (4KB pages), the kernel zero-fills the remainder of the last page.
    // On macOS (16KB pages), accessing past the file size causes SIGBUS.
    // Split: map from file up to the file-aligned size, then anonymous for the rest.
    let mut file_backed_length = length;
    let mut needs_anon_tail = false;
    let mut anon_tail_start: u64 = 0;
    let mut anon_tail_len: u64 = 0;

    if fd >= 0 && is_fixed {
        let mut file_stat: libc::stat = unsafe { std::mem::zeroed() };
        let stat_ret = unsafe { libc::fstat(fd, &mut file_stat) };
        if stat_ret == 0 {
            let file_size = file_stat.st_size as u64;
            let map_file_end = offset + length;
            if map_file_end > file_size {
                // Clamp file mapping to page-aligned file size
                let file_map_len = if file_size > offset {
                    let raw = file_size - offset;
                    (raw + page - 1) & !(page - 1) // round up to macOS page
                } else {
                    0
                };
                if file_map_len < length {
                    file_backed_length = file_map_len;
                    needs_anon_tail = true;
                    anon_tail_start = addr + file_map_len;
                    anon_tail_len = length - file_map_len;
                }
            }
        }
    }

    let hint = if addr == 0 { std::ptr::null_mut() } else { addr as *mut _ };

    // Check if offset is not macOS-page-aligned (16KB).
    // Linux uses 4KB pages so offsets may be 4KB-aligned but not 16KB-aligned.
    // For such file-backed mmaps, we must map anonymous and pread the data.
    let offset_misaligned = fd >= 0 && (offset & (page - 1)) != 0;

    let result_addr;
    if offset_misaligned {
        // Map anonymous memory, then read file content into it
        let anon_flags = if is_fixed {
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED
        } else {
            libc::MAP_PRIVATE | libc::MAP_ANON
        };
        let ret = unsafe { libc::mmap(hint, length as usize, libc::PROT_READ | libc::PROT_WRITE, anon_flags, -1, 0) };
        if ret == libc::MAP_FAILED {
            return translate::linux_errno();
        }
        result_addr = ret as u64;

        // Read file content (up to file size)
        let mut file_stat: libc::stat = unsafe { std::mem::zeroed() };
        let stat_ret = unsafe { libc::fstat(fd, &mut file_stat) };
        let read_len = if stat_ret == 0 {
            let file_size = file_stat.st_size as u64;
            if offset < file_size {
                std::cmp::min(length, file_size - offset)
            } else {
                0
            }
        } else {
            length
        };
        if read_len > 0 {
            unsafe {
                libc::pread(fd, result_addr as *mut _, read_len as usize, offset as i64);
            }
        }
        // Don't need anon tail handling since we already mapped anonymous
        needs_anon_tail = false;
    } else if file_backed_length > 0 {
        let ret = unsafe { libc::mmap(hint, file_backed_length as usize, effective_prot, mac_flags, fd, offset as i64) };
        if ret == libc::MAP_FAILED {
            return translate::linux_errno();
        }
        result_addr = ret as u64;
    } else {
        // Entire mapping is beyond file — map anonymous
        let ret = unsafe { libc::mmap(hint, length as usize, effective_prot,
            mac_flags | libc::MAP_ANON, -1, 0) };
        if ret == libc::MAP_FAILED {
            return translate::linux_errno();
        }
        result_addr = ret as u64;
        // No file content, no anon tail needed
        needs_anon_tail = false;
    }

    // Map anonymous tail for the portion beyond file size
    if needs_anon_tail && anon_tail_len > 0 {
        let anon_ret = unsafe { libc::mmap(
            anon_tail_start as *mut _,
            anon_tail_len as usize,
            effective_prot,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
            -1,
            0,
        ) };
        if anon_ret == libc::MAP_FAILED {
            // Non-fatal: the tail may just be unused BSS
            raw_eprintln_fmt(format_args!(
                "fakelinux: warning: anon tail mmap at {:#x}+{:#x} failed\n",
                anon_tail_start, anon_tail_len
            ));
        }
    }

    // Patch SVC/TPIDR in newly mapped executable code
    if has_exec && length > 0 {
        loader::patch_new_code(result_addr, length);
        // Invalidate instruction cache
        extern "C" {
            fn sys_icache_invalidate(start: *mut libc::c_void, size: usize);
        }
        unsafe { sys_icache_invalidate(result_addr as *mut _, length as usize); }
        // Set final permissions if we mapped as RW for patching
        if effective_prot != mac_prot {
            unsafe { libc::mprotect(result_addr as *mut _, length as usize, mac_prot); }
        }
    }

    result_addr
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
    // The page must be writable to patch, so ensure RW before scanning,
    // then set the final permissions after patching.
    if has_exec && aligned_len > 0 {
        // Make the region writable so we can patch
        let rw_prot = libc::PROT_READ | libc::PROT_WRITE;
        let ret = unsafe { libc::mprotect(aligned_addr as *mut _, aligned_len as usize, rw_prot) };
        if ret < 0 {
            return translate::linux_errno();
        }

        // Patch SVC #0 and MSR/MRS tpidr_el0 instructions
        loader::patch_new_code(aligned_addr, aligned_len);

        // Invalidate instruction cache after writing instructions
        extern "C" {
            fn sys_icache_invalidate(start: *mut libc::c_void, size: usize);
        }
        unsafe { sys_icache_invalidate(aligned_addr as *mut _, aligned_len as usize); }
    }

    // Set final permissions
    let ret = unsafe { libc::mprotect(aligned_addr as *mut _, aligned_len as usize, mac_prot) };
    if ret < 0 { translate::linux_errno() } else { 0 }
}

// ─── Info / misc ────────────────────────────────────────────────────────────

fn do_clock_gettime(clk_id: i32, tp: u64) -> u64 {
    unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        let ret = libc::clock_gettime(clk_id as u32, &mut ts);
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

fn do_prlimit64(_pid: u64, _resource: i32, _new_limit: u64, old_limit: u64) -> u64 {
    if old_limit != 0 {
        unsafe {
            let ptr = old_limit as *mut u64;
            *ptr = u64::MAX;
            *ptr.add(1) = u64::MAX;
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

fn do_pselect6(nfds: i32, readfds: u64, writefds: u64, exceptfds: u64, timeout: u64, _sig: u64) -> u64 {
    // Convert Linux timespec to macOS timespec (same layout on aarch64)
    // The 6th arg on Linux is a struct { sigset_t*, size_t } but we ignore it.
    let timeout_ptr = if timeout == 0 {
        std::ptr::null()
    } else {
        timeout as *const libc::timespec
    };

    let ret = unsafe {
        libc::pselect(
            nfds,
            if readfds == 0 { std::ptr::null_mut() } else { readfds as *mut libc::fd_set },
            if writefds == 0 { std::ptr::null_mut() } else { writefds as *mut libc::fd_set },
            if exceptfds == 0 { std::ptr::null_mut() } else { exceptfds as *mut libc::fd_set },
            timeout_ptr,
            std::ptr::null(), // ignore sigmask
        )
    };
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

    match option {
        PR_SET_NAME => {
            // Set thread name — stub success (could call pthread_setname_np)
            0
        }
        PR_GET_NAME => {
            // Return "fakelinux" as thread name
            if arg2 != 0 {
                let name = b"fakelinux\0\0\0\0\0\0\0"; // 16 bytes
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        name.as_ptr(),
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
    // Linux struct sysinfo on aarch64 is 112 bytes:
    //   offset  0: i64 uptime (seconds since boot)
    //   offset  8: [u64; 3] loads (1, 5, 15 min load averages * 65536)
    //   offset 32: u64 totalram
    //   offset 40: u64 freeram
    //   offset 48: u64 sharedram
    //   offset 56: u64 bufferram
    //   offset 64: u64 totalswap
    //   offset 72: u64 freeswap
    //   offset 80: u16 procs
    //   offset 84: u64 totalhigh
    //   offset 92: u64 freehigh
    //   offset 100: u32 mem_unit
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

        // procs
        let mut nprocs: i32 = 1;
        let mut nplen = std::mem::size_of::<i32>();
        let npname = b"hw.ncpu\0";
        libc::sysctlbyname(
            npname.as_ptr() as *const i8,
            &mut nprocs as *mut _ as *mut _,
            &mut nplen,
            std::ptr::null_mut(),
            0,
        );
        (out.add(80) as *mut u16).write_unaligned(nprocs as u16);

        // mem_unit = 1
        (out.add(100) as *mut u32).write_unaligned(1);
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
