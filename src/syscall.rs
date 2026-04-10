use crate::linux::*;
use crate::trap::ThreadState64;
use std::sync::atomic::{AtomicU64, Ordering};

/// Current program break (heap end), set by the loader after mapping segments.
pub static BRK_CURRENT: AtomicU64 = AtomicU64::new(0);

/// Emulate a single Linux aarch64 syscall. Returns the result value for x0.
pub fn emulate(nr: u64, args: &[u64; 6], _regs: &mut ThreadState64) -> u64 {
    match nr {
        SYS_WRITE => do_write(args[0], args[1], args[2]),
        SYS_READ => do_read(args[0], args[1], args[2]),
        SYS_OPENAT => do_openat(args[0] as i32, args[1], args[2] as i32, args[3] as u32),
        SYS_CLOSE => do_close(args[0] as i32),
        SYS_FSTAT => do_fstat(args[0] as i32, args[1]),
        SYS_EXIT | SYS_EXIT_GROUP => {
            // Flush stdout/stderr before exiting
            unsafe { libc::_exit(args[0] as i32) }
        }
        SYS_BRK => do_brk(args[0]),
        SYS_MMAP => do_mmap(args[0], args[1], args[2], args[3], args[4] as i32, args[5]),
        SYS_MUNMAP => do_munmap(args[0], args[1]),
        SYS_MPROTECT => do_mprotect(args[0], args[1], args[2]),
        SYS_MADVISE => 0, // silently succeed
        SYS_GETPID => unsafe { libc::getpid() as u64 },
        SYS_GETPPID => unsafe { libc::getppid() as u64 },
        SYS_GETUID => unsafe { libc::getuid() as u64 },
        SYS_GETEUID => unsafe { libc::geteuid() as u64 },
        SYS_GETGID => unsafe { libc::getgid() as u64 },
        SYS_GETEGID => unsafe { libc::getegid() as u64 },
        SYS_GETTID => unsafe { libc::getpid() as u64 }, // single-threaded: tid == pid
        SYS_SET_TID_ADDRESS => unsafe { libc::getpid() as u64 },
        SYS_SET_ROBUST_LIST => 0,
        SYS_RT_SIGACTION => 0,    // stub: pretend success
        SYS_RT_SIGPROCMASK => 0,  // stub: pretend success
        SYS_CLOCK_GETTIME => do_clock_gettime(args[0] as i32, args[1]),
        SYS_UNAME => do_uname(args[0]),
        SYS_GETRANDOM => do_getrandom(args[0], args[1], args[2] as u32),
        SYS_PRLIMIT64 => do_prlimit64(args[0], args[1] as i32, args[2], args[3]),
        SYS_RSEQ => (-38_i64) as u64, // ENOSYS
        SYS_SCHED_GETAFFINITY => (-38_i64) as u64,
        SYS_READLINKAT => do_readlinkat(args[0] as i32, args[1], args[2], args[3]),
        SYS_NEWFSTATAT => do_fstat(args[2] as i32, args[3]), // simplified
        SYS_IOCTL => (-25_i64) as u64, // ENOTTY
        SYS_FCNTL => (-38_i64) as u64, // ENOSYS stub
        SYS_WRITEV => do_writev(args[0], args[1], args[2]),
        SYS_FACCESSAT => 0, // stub: pretend success
        _ => {
            eprintln!("fakelinux: unimplemented syscall {} (x0={:#x} x1={:#x} x2={:#x})", nr, args[0], args[1], args[2]);
            (-38_i64) as u64 // -ENOSYS
        }
    }
}

fn do_write(fd: u64, buf: u64, count: u64) -> u64 {
    let ret = unsafe { libc::write(fd as i32, buf as *const _, count as usize) };
    if ret < 0 {
        linux_errno()
    } else {
        ret as u64
    }
}

fn do_read(fd: u64, buf: u64, count: u64) -> u64 {
    let ret = unsafe { libc::read(fd as i32, buf as *mut _, count as usize) };
    if ret < 0 {
        linux_errno()
    } else {
        ret as u64
    }
}

fn do_openat(dirfd: i32, pathname: u64, flags: i32, mode: u32) -> u64 {
    // TODO: translate Linux open flags to macOS flags (they differ!)
    // For now, pass through — works for simple cases
    let ret = unsafe { libc::openat(dirfd, pathname as *const i8, flags, mode) };
    if ret < 0 {
        linux_errno()
    } else {
        ret as u64
    }
}

fn do_close(fd: i32) -> u64 {
    let ret = unsafe { libc::close(fd) };
    if ret < 0 {
        linux_errno()
    } else {
        0
    }
}

fn do_fstat(fd: i32, statbuf: u64) -> u64 {
    // Linux and macOS struct stat differ — this is a stub that zeros the buffer
    // A full implementation needs field-by-field translation
    unsafe {
        let mut mac_stat: libc::stat = std::mem::zeroed();
        let ret = libc::fstat(fd, &mut mac_stat);
        if ret < 0 {
            return linux_errno();
        }
        // Zero the Linux stat buffer (128 bytes on aarch64 Linux)
        std::ptr::write_bytes(statbuf as *mut u8, 0, 128);
    }
    0
}

fn do_brk(addr: u64) -> u64 {
    let current = BRK_CURRENT.load(Ordering::SeqCst);
    if addr == 0 {
        return current;
    }
    if addr < current {
        return current; // can't shrink below initial
    }
    // Extend: mmap the new pages
    let page_size = 16384_u64; // macOS aarch64 page size
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
            return current; // allocation failed, return old break
        }
    }
    BRK_CURRENT.store(addr, Ordering::SeqCst);
    addr
}

fn do_mmap(addr: u64, length: u64, prot: u64, flags: u64, fd: i32, offset: u64) -> u64 {
    // Translate Linux mmap flags to macOS
    let mut mac_flags: i32 = 0;
    if flags & LINUX_MAP_PRIVATE != 0 {
        mac_flags |= libc::MAP_PRIVATE;
    }
    if flags & LINUX_MAP_SHARED != 0 {
        mac_flags |= libc::MAP_SHARED;
    }
    if flags & LINUX_MAP_ANONYMOUS != 0 {
        mac_flags |= libc::MAP_ANON;
    }
    if flags & LINUX_MAP_FIXED != 0 {
        mac_flags |= libc::MAP_FIXED;
    }

    let mac_prot = translate_prot(prot);

    let hint = if addr == 0 {
        std::ptr::null_mut()
    } else {
        addr as *mut _
    };

    let ret = unsafe { libc::mmap(hint, length as usize, mac_prot, mac_flags, fd, offset as i64) };
    if ret == libc::MAP_FAILED {
        linux_errno()
    } else {
        ret as u64
    }
}

fn do_munmap(addr: u64, length: u64) -> u64 {
    let ret = unsafe { libc::munmap(addr as *mut _, length as usize) };
    if ret < 0 {
        linux_errno()
    } else {
        0
    }
}

fn do_mprotect(addr: u64, len: u64, prot: u64) -> u64 {
    let mac_prot = translate_prot(prot);
    let ret = unsafe { libc::mprotect(addr as *mut _, len as usize, mac_prot) };
    if ret < 0 {
        linux_errno()
    } else {
        0
    }
}

fn do_clock_gettime(clk_id: i32, tp: u64) -> u64 {
    // Linux CLOCK_REALTIME=0, CLOCK_MONOTONIC=1 — same on macOS
    unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        let ret = libc::clock_gettime(clk_id as u32, &mut ts);
        if ret < 0 {
            return linux_errno();
        }
        // Linux aarch64 timespec: i64 tv_sec, i64 tv_nsec
        let out = tp as *mut i64;
        *out = ts.tv_sec as i64;
        *out.add(1) = ts.tv_nsec as i64;
    }
    0
}

fn do_uname(buf: u64) -> u64 {
    // Linux struct utsname: 6 fields of 65 bytes each
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
    // Fill with random bytes from macOS arc4random
    let ptr = buf as *mut u8;
    for i in 0..buflen as usize {
        unsafe {
            *ptr.add(i) = libc::arc4random() as u8;
        }
    }
    buflen
}

fn do_prlimit64(_pid: u64, _resource: i32, _new_limit: u64, old_limit: u64) -> u64 {
    if old_limit != 0 {
        // Return a generous default: rlim_cur = rlim_max = large value
        unsafe {
            let ptr = old_limit as *mut u64;
            *ptr = u64::MAX; // rlim_cur
            *ptr.add(1) = u64::MAX; // rlim_max
        }
    }
    0
}

fn do_readlinkat(_dirfd: i32, pathname: u64, buf: u64, bufsiz: u64) -> u64 {
    let path = unsafe { std::ffi::CStr::from_ptr(pathname as *const i8) };
    let path_str = path.to_bytes();
    // Handle /proc/self/exe
    if path_str == b"/proc/self/exe" {
        let fake = b"/fakelinux-guest";
        let len = fake.len().min(bufsiz as usize);
        unsafe {
            std::ptr::copy_nonoverlapping(fake.as_ptr(), buf as *mut u8, len);
        }
        return len as u64;
    }
    (-2_i64) as u64 // -ENOENT
}

fn do_writev(fd: u64, iov: u64, iovcnt: u64) -> u64 {
    // struct iovec { void *iov_base; size_t iov_len; } — same layout on Linux/macOS aarch64
    let ret = unsafe {
        libc::writev(fd as i32, iov as *const libc::iovec, iovcnt as i32)
    };
    if ret < 0 {
        linux_errno()
    } else {
        ret as u64
    }
}

fn translate_prot(linux_prot: u64) -> i32 {
    // Protection flags happen to have the same values on Linux and macOS
    let mut p: i32 = 0;
    if linux_prot & LINUX_PROT_READ != 0 {
        p |= libc::PROT_READ;
    }
    if linux_prot & LINUX_PROT_WRITE != 0 {
        p |= libc::PROT_WRITE;
    }
    if linux_prot & LINUX_PROT_EXEC != 0 {
        p |= libc::PROT_EXEC;
    }
    p
}

fn linux_errno() -> u64 {
    // Return negated errno. Linux uses negative return values for errors.
    // macOS errno values are mostly compatible for common errors.
    let e = unsafe { *libc::__error() };
    (-(e as i64)) as u64
}
