//! Networking syscall emulation: socket, bind, listen, accept4, connect,
//! sendto, recvfrom, setsockopt, getsockopt, getsockname, getpeername,
//! shutdown, socketpair, sendmsg, recvmsg.
//!
//! Most calls pass through directly to macOS since AF_INET/AF_INET6/AF_UNIX
//! and sockaddr_in/sockaddr_in6 layouts are identical. Key differences:
//! - SOCK_NONBLOCK/SOCK_CLOEXEC flags encoded in type (Linux) vs fcntl (macOS)
//! - accept4 → accept + fcntl (macOS lacks accept4)
//! - sockaddr_un: macOS has sun_len first byte, Linux does not

use crate::translate;

// Linux socket type flags encoded in the type argument
const LINUX_SOCK_NONBLOCK: i32 = 0x800;
const LINUX_SOCK_CLOEXEC: i32 = 0x80000;

/// Extract base socket type and apply SOCK_NONBLOCK/SOCK_CLOEXEC after creation.
fn extract_sock_flags(type_: i32) -> (i32, bool, bool) {
    let nonblock = type_ & LINUX_SOCK_NONBLOCK != 0;
    let cloexec = type_ & LINUX_SOCK_CLOEXEC != 0;
    let base_type = type_ & !(LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC);
    (base_type, nonblock, cloexec)
}

/// Apply SOCK_NONBLOCK and SOCK_CLOEXEC flags via fcntl after socket creation.
fn apply_sock_flags(fd: i32, nonblock: bool, cloexec: bool) {
    unsafe {
        if nonblock {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        if cloexec {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        // Set SO_NOSIGPIPE on macOS to prevent SIGPIPE on broken connections
        let one: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

pub fn do_socket(domain: i32, type_: i32, protocol: i32) -> u64 {
    let (base_type, nonblock, cloexec) = extract_sock_flags(type_);
    let fd = unsafe { libc::socket(domain, base_type, protocol) };
    if fd < 0 {
        return translate::linux_errno();
    }
    apply_sock_flags(fd, nonblock, cloexec);
    fd as u64
}

pub fn do_bind(fd: i32, addr_ptr: u64, addrlen: u32) -> u64 {
    let ret = unsafe {
        libc::bind(
            fd,
            addr_ptr as *const libc::sockaddr,
            addrlen as libc::socklen_t,
        )
    };
    if ret < 0 {
        translate::linux_errno()
    } else {
        0
    }
}

pub fn do_listen(fd: i32, backlog: i32) -> u64 {
    let ret = unsafe { libc::listen(fd, backlog) };
    if ret < 0 {
        translate::linux_errno()
    } else {
        0
    }
}

pub fn do_accept4(fd: i32, addr_ptr: u64, addrlen_ptr: u64, flags: i32) -> u64 {
    // macOS has no accept4; use accept + fcntl
    let ret = unsafe {
        libc::accept(
            fd,
            if addr_ptr == 0 {
                std::ptr::null_mut()
            } else {
                addr_ptr as *mut libc::sockaddr
            },
            if addrlen_ptr == 0 {
                std::ptr::null_mut()
            } else {
                addrlen_ptr as *mut libc::socklen_t
            },
        )
    };
    if ret < 0 {
        return translate::linux_errno();
    }
    let nonblock = flags & LINUX_SOCK_NONBLOCK != 0;
    let cloexec = flags & LINUX_SOCK_CLOEXEC != 0;
    apply_sock_flags(ret, nonblock, cloexec);
    ret as u64
}

pub fn do_connect(fd: i32, addr_ptr: u64, addrlen: u32) -> u64 {
    let ret = unsafe {
        libc::connect(
            fd,
            addr_ptr as *const libc::sockaddr,
            addrlen as libc::socklen_t,
        )
    };
    if ret < 0 {
        translate::linux_errno()
    } else {
        0
    }
}

pub fn do_sendto(fd: i32, buf: u64, len: u64, flags: i32, dest_addr: u64, addrlen: u32) -> u64 {
    let ret = unsafe {
        libc::sendto(
            fd,
            buf as *const libc::c_void,
            len as usize,
            flags,
            if dest_addr == 0 {
                std::ptr::null()
            } else {
                dest_addr as *const libc::sockaddr
            },
            addrlen as libc::socklen_t,
        )
    };
    if ret < 0 {
        translate::linux_errno()
    } else {
        ret as u64
    }
}

pub fn do_recvfrom(
    fd: i32,
    buf: u64,
    len: u64,
    flags: i32,
    src_addr: u64,
    addrlen_ptr: u64,
) -> u64 {
    let ret = unsafe {
        libc::recvfrom(
            fd,
            buf as *mut libc::c_void,
            len as usize,
            flags,
            if src_addr == 0 {
                std::ptr::null_mut()
            } else {
                src_addr as *mut libc::sockaddr
            },
            if addrlen_ptr == 0 {
                std::ptr::null_mut()
            } else {
                addrlen_ptr as *mut libc::socklen_t
            },
        )
    };
    if ret < 0 {
        translate::linux_errno()
    } else {
        ret as u64
    }
}

pub fn do_setsockopt(fd: i32, level: i32, optname: i32, optval: u64, optlen: u32) -> u64 {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            optval as *const libc::c_void,
            optlen as libc::socklen_t,
        )
    };
    if ret < 0 {
        translate::linux_errno()
    } else {
        0
    }
}

pub fn do_getsockopt(fd: i32, level: i32, optname: i32, optval: u64, optlen_ptr: u64) -> u64 {
    let ret = unsafe {
        libc::getsockopt(
            fd,
            level,
            optname,
            optval as *mut libc::c_void,
            optlen_ptr as *mut libc::socklen_t,
        )
    };
    if ret < 0 {
        translate::linux_errno()
    } else {
        0
    }
}

pub fn do_getsockname(fd: i32, addr_ptr: u64, addrlen_ptr: u64) -> u64 {
    let ret = unsafe {
        libc::getsockname(
            fd,
            addr_ptr as *mut libc::sockaddr,
            addrlen_ptr as *mut libc::socklen_t,
        )
    };
    if ret < 0 {
        translate::linux_errno()
    } else {
        0
    }
}

pub fn do_getpeername(fd: i32, addr_ptr: u64, addrlen_ptr: u64) -> u64 {
    let ret = unsafe {
        libc::getpeername(
            fd,
            addr_ptr as *mut libc::sockaddr,
            addrlen_ptr as *mut libc::socklen_t,
        )
    };
    if ret < 0 {
        translate::linux_errno()
    } else {
        0
    }
}

pub fn do_shutdown(fd: i32, how: i32) -> u64 {
    let ret = unsafe { libc::shutdown(fd, how) };
    if ret < 0 {
        translate::linux_errno()
    } else {
        0
    }
}

pub fn do_socketpair(domain: i32, type_: i32, protocol: i32, sv_ptr: u64) -> u64 {
    let (base_type, nonblock, cloexec) = extract_sock_flags(type_);
    let ret = unsafe {
        libc::socketpair(domain, base_type, protocol, sv_ptr as *mut i32)
    };
    if ret < 0 {
        return translate::linux_errno();
    }
    // Apply flags to both fds
    let sv = unsafe { std::slice::from_raw_parts(sv_ptr as *const i32, 2) };
    apply_sock_flags(sv[0], nonblock, cloexec);
    apply_sock_flags(sv[1], nonblock, cloexec);
    0
}

pub fn do_sendmsg(fd: i32, msg_ptr: u64, flags: i32) -> u64 {
    let ret = unsafe {
        libc::sendmsg(fd, msg_ptr as *const libc::msghdr, flags)
    };
    if ret < 0 {
        translate::linux_errno()
    } else {
        ret as u64
    }
}

pub fn do_recvmsg(fd: i32, msg_ptr: u64, flags: i32) -> u64 {
    let ret = unsafe {
        libc::recvmsg(fd, msg_ptr as *mut libc::msghdr, flags)
    };
    if ret < 0 {
        translate::linux_errno()
    } else {
        ret as u64
    }
}
