use crate::linux::*;
use crate::procfs;
use crate::signal;
use crate::thread;
use crate::translate;
use crate::trap::ThreadState64;
use std::sync::atomic::{AtomicU64, Ordering};

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
        SYS_EXIT | SYS_EXIT_GROUP => unsafe { libc::_exit(args[0] as i32) },
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
        SYS_SET_TID_ADDRESS => thread::current_tid() as u64,
        SYS_SET_ROBUST_LIST => 0,
        SYS_RT_SIGACTION => signal::do_rt_sigaction(args[0], args[1], args[2], args[3]),
        SYS_RT_SIGPROCMASK => signal::do_rt_sigprocmask(args[0], args[1], args[2], args[3]),
        SYS_RT_SIGRETURN => 0, // stub
        SYS_CLOCK_GETTIME => do_clock_gettime(args[0] as i32, args[1]),
        SYS_UNAME => do_uname(args[0]),
        SYS_GETRANDOM => do_getrandom(args[0], args[1], args[2] as u32),
        SYS_PRLIMIT64 => do_prlimit64(args[0], args[1] as i32, args[2], args[3]),
        SYS_RSEQ => (-38_i64) as u64, // ENOSYS
        SYS_CLONE3 => (-38_i64) as u64, // ENOSYS — force fallback to clone
        SYS_SCHED_GETAFFINITY => (-38_i64) as u64,
        SYS_SCHED_YIELD => { unsafe { libc::sched_yield(); } 0 }
        SYS_READLINKAT => do_readlinkat(args[0] as i32, args[1], args[2], args[3]),
        SYS_IOCTL => do_ioctl(args[0] as i32, args[1], args[2]),
        SYS_FCNTL => do_fcntl(args[0] as i32, args[1] as i32, args[2]),
        SYS_WRITEV => do_writev(args[0], args[1], args[2]),
        SYS_FACCESSAT => do_faccessat(args[0] as i32, args[1], args[2] as i32, args[3] as i32),
        SYS_CLONE => thread::do_clone(args[0], args[1], args[2], args[3], args[4]),
        SYS_FUTEX => thread::do_futex(args[0], args[1] as u32, args[2] as u32, args[3], args[4], args[5] as u32),
        SYS_DUP => do_dup(args[0] as i32),
        SYS_DUP3 => do_dup3(args[0] as i32, args[1] as i32, args[2] as i32),
        SYS_PIPE2 => do_pipe2(args[0], args[1] as i32),
        SYS_GETDENTS64 => do_getdents64(args[0] as i32, args[1], args[2]),
        SYS_PPOLL => (-38_i64) as u64, // ENOSYS stub
        SYS_SOCKET => (-38_i64) as u64, // ENOSYS stub
        SYS_TGKILL => {
            let sig = args[2] as i32;
            if sig == 6 {
                raw_eprintln("fakelinux: guest called abort (tgkill SIGABRT)\n");
                unsafe { libc::_exit(134) }
            }
            unsafe { libc::kill(libc::getpid(), sig); }
            0
        }
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
            let ret = unsafe { libc::chdir(args[0] as *const i8) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_FCHDIR => {
            let ret = unsafe { libc::fchdir(args[0] as i32) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_MKDIRAT => {
            let ret = unsafe { libc::mkdirat(translate::translate_dirfd(args[0] as i32), args[1] as *const i8, args[2] as libc::mode_t) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_UNLINKAT => {
            let mac_flags = if args[2] & 0x200 != 0 { libc::AT_REMOVEDIR } else { 0 };
            let ret = unsafe { libc::unlinkat(translate::translate_dirfd(args[0] as i32), args[1] as *const i8, mac_flags) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_RENAMEAT => {
            let ret = unsafe { libc::renameat(
                translate::translate_dirfd(args[0] as i32), args[1] as *const i8,
                translate::translate_dirfd(args[2] as i32), args[3] as *const i8,
            ) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_FCHMOD => {
            let ret = unsafe { libc::fchmod(args[0] as i32, args[1] as libc::mode_t) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_FCHMODAT => {
            let ret = unsafe { libc::fchmodat(translate::translate_dirfd(args[0] as i32), args[1] as *const i8, args[2] as libc::mode_t, args[3] as i32) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_FCHOWN => {
            let ret = unsafe { libc::fchown(args[0] as i32, args[1] as u32, args[2] as u32) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_FCHOWNAT => {
            let ret = unsafe { libc::fchownat(translate::translate_dirfd(args[0] as i32), args[1] as *const i8, args[2] as u32, args[3] as u32, args[4] as i32) };
            if ret < 0 { translate::linux_errno() } else { 0 }
        }
        SYS_WAIT4 => thread::do_wait4(args[0] as i64, args[1], args[2] as i32, args[3]),
        SYS_EXECVE => do_execve(args[0], args[1], args[2]),
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
    let ret = unsafe { libc::write(fd as i32, buf as *const _, count as usize) };
    if ret < 0 { translate::linux_errno() } else { ret as u64 }
}

fn do_read(fd: u64, buf: u64, count: u64) -> u64 {
    let ret = unsafe { libc::read(fd as i32, buf as *mut _, count as usize) };
    if ret < 0 { translate::linux_errno() } else { ret as u64 }
}

fn do_openat(linux_dirfd: i32, pathname: u64, linux_flags: i32, mode: u32) -> u64 {
    let path = unsafe { std::ffi::CStr::from_ptr(pathname as *const i8) };

    // Check if this is a /proc path we handle virtually
    if let Some(fd) = procfs::try_open(path.to_bytes()) {
        return fd as u64;
    }

    let mac_dirfd = translate::translate_dirfd(linux_dirfd);
    let mac_flags = translate::translate_open_flags(linux_flags);

    let ret = unsafe { libc::openat(mac_dirfd, pathname as *const i8, mac_flags, mode) };
    if ret < 0 { translate::linux_errno() } else { ret as u64 }
}

fn do_close(fd: i32) -> u64 {
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

    unsafe {
        let mut mac_stat: libc::stat = std::mem::zeroed();
        let ret = libc::fstatat(mac_dirfd, pathname as *const i8, &mut mac_stat, mac_flags);
        if ret < 0 {
            return translate::linux_errno();
        }
        translate::mac_stat_to_linux(&mac_stat, statbuf as *mut u8);
    }
    0
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

fn do_faccessat(linux_dirfd: i32, pathname: u64, mode: i32, linux_flags: i32) -> u64 {
    let mac_dirfd = translate::translate_dirfd(linux_dirfd);
    let mac_flags = translate::translate_at_flags(linux_flags);
    let ret = unsafe { libc::faccessat(mac_dirfd, pathname as *const i8, mode, mac_flags) };
    if ret < 0 { translate::linux_errno() } else { 0 }
}

fn do_readlinkat(linux_dirfd: i32, pathname: u64, buf: u64, bufsiz: u64) -> u64 {
    let path = unsafe { std::ffi::CStr::from_ptr(pathname as *const i8) };

    // Check /proc paths first
    if let Some(result) = procfs::try_readlink(path.to_bytes(), buf, bufsiz) {
        return result;
    }

    let mac_dirfd = translate::translate_dirfd(linux_dirfd);
    let ret = unsafe {
        libc::readlinkat(mac_dirfd, pathname as *const i8, buf as *mut i8, bufsiz as usize)
    };
    if ret < 0 { translate::linux_errno() } else { ret as u64 }
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
            // Check if the file is an ELF; if not, fall back to guest binary
            // (busybox sh finds /usr/bin/uname on macOS, which is Mach-O)
            let is_elf = std::fs::read(path.to_str().unwrap_or(""))
                .map(|d| d.len() >= 4 && d[..4] == [0x7f, b'E', b'L', b'F'])
                .unwrap_or(false);
            if is_elf {
                std::ffi::CString::new(path_bytes).unwrap()
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

    // Collect envp
    let mut new_envp: Vec<*const i8> = Vec::new();
    let mut guest_envp = envp_ptr as *const *const i8;
    unsafe {
        while !(*guest_envp).is_null() {
            new_envp.push(*guest_envp);
            guest_envp = guest_envp.add(1);
        }
    }
    new_envp.push(std::ptr::null());

    // Debug: show what we're exec'ing
    {
        let path_str = unsafe { std::ffi::CStr::from_ptr(resolved_path.as_ptr()) };
        let mut buf = [0u8; 256];
        let n = raw_eprintln_fmt(format_args!("fakelinux: execve → fakelinux {:?}\n", path_str));
    }

    // execve ourselves with the guest binary as first arg
    unsafe {
        libc::execve(
            self_exe_c.as_ptr(),
            new_argv.as_ptr(),
            new_envp.as_ptr(),
        );
    }
    // If execve returns, it failed
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
    let mac_flags = translate::translate_mmap_flags(flags);
    let mac_prot = translate::translate_mmap_prot(prot);
    let page: u64 = 16384;

    // Handle 4KB/16KB page size mismatch for MAP_FIXED mappings.
    // Linux guests may place 4KB guard pages (PROT_NONE) that would clobber
    // adjacent data if applied at 16KB granularity. Skip these.
    let is_fixed = flags & 0x10 != 0; // MAP_FIXED
    if is_fixed && (addr & (page - 1) != 0 || length < page) {
        if prot == 0 {
            // PROT_NONE guard page smaller than a macOS page — skip it
            return addr;
        }
        // For non-PROT_NONE sub-page MAP_FIXED, use mprotect instead to
        // change protection of already-mapped pages without remapping.
        if flags & 0x20 != 0 {
            // MAP_ANONYMOUS + MAP_FIXED at sub-page granularity:
            // Just zero the memory and change protection.
            unsafe {
                std::ptr::write_bytes(addr as *mut u8, 0, length as usize);
            }
            return addr;
        }
    }

    let hint = if addr == 0 { std::ptr::null_mut() } else { addr as *mut _ };
    let ret = unsafe { libc::mmap(hint, length as usize, mac_prot, mac_flags, fd, offset as i64) };
    if ret == libc::MAP_FAILED {
        translate::linux_errno()
    } else {
        ret as u64
    }
}

fn do_munmap(addr: u64, length: u64) -> u64 {
    let ret = unsafe { libc::munmap(addr as *mut _, length as usize) };
    if ret < 0 { translate::linux_errno() } else { 0 }
}

fn do_mprotect(addr: u64, len: u64, prot: u64) -> u64 {
    let mac_prot = translate::translate_mmap_prot(prot);
    let page: u64 = 16384;

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
