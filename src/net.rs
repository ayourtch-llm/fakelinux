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
const LINUX_SOCK_SEQPACKET: i32 = 5;

// SOL_SOCKET options handled specially (Linux SOL_SOCKET=1, macOS=0xffff)
const LINUX_SOL_SOCKET: i32 = 1;
const LINUX_SO_PASSCRED: i32 = 16;
const MAC_SOL_SOCKET: i32 = 0xffff;
const LINUX_SCM_CREDENTIALS: i32 = 2;

// ─── MSG flags translation ───────────────────────────────────────────────────
// Linux and macOS use different values for some MSG_* flags in send/recv.
// Linux MSG_NOSIGNAL=0x4000, macOS MSG_NOSIGNAL=0x80000.
// Linux MSG_DONTWAIT=0x40, macOS MSG_DONTWAIT=0x80.
// Linux MSG_MORE=0x8000, macOS has no equivalent (strip it).
// Linux MSG_CMSG_CLOEXEC=0x40000000, macOS MSG_CMSG_CLOEXEC=not available (strip).

const LINUX_MSG_NOSIGNAL: i32 = 0x4000;
const LINUX_MSG_DONTWAIT: i32 = 0x40;
const LINUX_MSG_MORE: i32 = 0x8000;
const LINUX_MSG_CMSG_CLOEXEC: i32 = 0x40000000;

fn translate_msg_flags(linux_flags: i32) -> i32 {
    let mut mac = linux_flags;

    // Strip Linux-specific flags first, then set macOS equivalents
    if mac & LINUX_MSG_NOSIGNAL != 0 {
        mac &= !LINUX_MSG_NOSIGNAL;
        // macOS uses SO_NOSIGPIPE on the socket (set in apply_sock_flags),
        // so we don't need MSG_NOSIGNAL per-call. But set it anyway if available.
        mac |= 0x80000; // macOS MSG_NOSIGNAL
    }
    if mac & LINUX_MSG_DONTWAIT != 0 {
        mac &= !LINUX_MSG_DONTWAIT;
        mac |= 0x80; // macOS MSG_DONTWAIT
    }
    // Strip flags with no macOS equivalent
    mac &= !(LINUX_MSG_MORE | LINUX_MSG_CMSG_CLOEXEC);

    mac
}

// ─── sockaddr translation ────────────────────────────────────────────────────
//
// Linux sockaddr:  { u16 sa_family; u8 sa_data[14]; }
// macOS sockaddr:  { u8 sa_len; u8 sa_family; u8 sa_data[14]; }
//
// For AF_INET (2), AF_INET6 (10/30), AF_UNIX (1):
// Linux stores family as u16 LE at offset 0. macOS stores len at offset 0,
// family as u8 at offset 1. The rest of the struct (port, addr) is at the
// same offsets. We fix up in-place by writing sin_len and shifting family.

/// Patch a Linux sockaddr buffer in-place to macOS format before passing to kernel.
/// Returns the macOS sa_family for callers that need it.
/// Copy a guest (Linux-format) sockaddr into a local macOS-format buffer.
///
/// The guest buffer is NOT modified: it may live in read-only memory (e.g.
/// glibc syslog's static const sockaddr_un for /dev/log). Mutating guest
/// memory in place faulted there — and since the trap handler runs with all
/// signals blocked, the faulting store re-executed forever (useradd hung at
/// 100% CPU connecting to /dev/log during apt-get install).
///
/// Use this for inbound addresses (connect/bind/sendto/sendmsg). Outbound
/// buffers (accept/recvfrom/getsockname/...) are guest-writable by contract
/// and may be converted in place.
/// Linux AF_INET6 is 10; macOS AF_INET6 is 30. (AF_UNIX=1 and AF_INET=2
/// match.) Linux sockaddr_in6 and macOS sockaddr_in6 otherwise share field
/// offsets, so only the family value needs mapping.
fn linux_af_to_mac(af: u8) -> u8 {
    if af == 10 { 30 } else { af }
}

fn mac_af_to_linux(af: u8) -> u8 {
    if af == 30 { 10 } else { af }
}

fn linux_sockaddr_to_mac_copy(addr_ptr: u64, addrlen: u32) -> libc::sockaddr_storage {
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    if addr_ptr == 0 || addrlen < 2 {
        return ss;
    }
    let len = (addrlen as usize).min(std::mem::size_of::<libc::sockaddr_storage>());
    unsafe {
        std::ptr::copy_nonoverlapping(addr_ptr as *const u8, &mut ss as *mut _ as *mut u8, len);
        let p = &mut ss as *mut _ as *mut u8;
        // Linux: offset 0 = sa_family as u16 LE → low byte is the family
        let family = *p;
        // macOS: offset 0 = sa_len, offset 1 = sa_family (u8)
        *p = addrlen as u8;
        *p.add(1) = linux_af_to_mac(family);
    }
    ss
}

/// Extract the filesystem sun_path from a Linux sockaddr_un buffer.
/// Returns None for non-AF_UNIX addresses, abstract sockets (leading NUL,
/// Linux-only namespace), and empty paths. The path is clamped to addrlen
/// (Linux permits a non-NUL-terminated sun_path filling the struct).
fn linux_sun_path(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 3 {
        return None;
    }
    // Linux sa_family is u16 LE at offset 0; AF_UNIX = 1.
    if u16::from_le_bytes([buf[0], buf[1]]) != 1 {
        return None;
    }
    let path = &buf[2..];
    if path[0] == 0 {
        return None; // abstract socket
    }
    let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
    Some(&path[..end])
}

/// Build a macOS sockaddr_un (sun_len, sun_family, sun_path[104]) for a host
/// path. Err(36) = Linux ENAMETOOLONG when the re-rooted path won't fit.
fn mac_sockaddr_un(host_path: &[u8]) -> Result<(libc::sockaddr_un, libc::socklen_t), i32> {
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if host_path.len() >= sa.sun_path.len() {
        return Err(36); // Linux ENAMETOOLONG
    }
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, &b) in host_path.iter().enumerate() {
        sa.sun_path[i] = b as libc::c_char;
    }
    // macOS convention: sun_len = offsetof(sun_path) + strlen + NUL
    let len = 2 + host_path.len() as libc::socklen_t + 1;
    sa.sun_len = len as u8;
    Ok((sa, len))
}

/// Convert an inbound guest sockaddr for the kernel, re-rooting AF_UNIX
/// sun_path through the rootfs (bind("/run/vpp/stats.sock") must land inside
/// FAKELINUX_ROOT, not on the host filesystem). Returns the macOS sockaddr
/// and the (possibly changed) addrlen, or a Linux errno.
fn sockaddr_for_kernel(addr_ptr: u64, addrlen: u32) -> Result<(libc::sockaddr_storage, libc::socklen_t), i32> {
    if addr_ptr != 0 && addrlen >= 3 {
        let buf = unsafe { std::slice::from_raw_parts(addr_ptr as *const u8, addrlen as usize) };
        if let Some(path) = linux_sun_path(buf) {
            if let Some(mut host) = crate::rootfs::translate_path(path) {
                if host.ends_with(&[0]) {
                    host.pop();
                }
                let (un, len) = mac_sockaddr_un(&host)?;
                let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &un as *const _ as *const u8,
                        &mut ss as *mut _ as *mut u8,
                        std::mem::size_of::<libc::sockaddr_un>(),
                    );
                }
                return Ok((ss, len));
            }
        }
    }
    Ok((linux_sockaddr_to_mac_copy(addr_ptr, addrlen), addrlen as libc::socklen_t))
}

fn linux_sockaddr_to_mac(addr_ptr: u64, addrlen: u32) -> u8 {
    if addr_ptr == 0 || addrlen < 2 {
        return 0;
    }
    unsafe {
        let p = addr_ptr as *mut u8;
        // Linux: offset 0 = sa_family as u16 LE → low byte is the family
        let family = *p;
        // macOS: offset 0 = sa_len, offset 1 = sa_family (u8)
        *p = addrlen as u8;                     // sin_len
        *p.add(1) = linux_af_to_mac(family);    // sin_family
        family
    }
}

/// Patch a macOS sockaddr buffer in-place back to Linux format after kernel call.
fn mac_sockaddr_to_linux(addr_ptr: u64, addrlen: u32) {
    if addr_ptr == 0 || addrlen < 2 {
        return;
    }
    unsafe {
        let p = addr_ptr as *mut u8;
        // macOS: offset 0 = sa_len, offset 1 = sa_family
        let family = *p.add(1);
        // Linux: offset 0 = sa_family as u16 LE
        *p = mac_af_to_linux(family);
        *p.add(1) = 0;
    }
}

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
    let (mut base_type, nonblock, cloexec) = extract_sock_flags(type_);
    let mac_domain = if domain == 10 { 30 } else { domain }; // Linux AF_INET6=10, macOS=30
    // macOS does not support SOCK_SEQPACKET for AF_UNIX (EPROTONOSUPPORT).
    // Guests (VPP stats.sock/cli.sock) use it as a connection-oriented socket
    // that passes fds via SCM_RIGHTS — SOCK_STREAM provides the same semantics
    // minus message boundaries, which those protocols don't rely on.
    if mac_domain == libc::AF_UNIX && base_type == LINUX_SOCK_SEQPACKET {
        base_type = libc::SOCK_STREAM;
    }
    let fd = unsafe { libc::socket(mac_domain, base_type, protocol) };
    if fd < 0 {
        return translate::linux_errno();
    }
    apply_sock_flags(fd, nonblock, cloexec);
    fd as u64
}

pub fn do_bind(fd: i32, addr_ptr: u64, addrlen: u32) -> u64 {
    let (mac_addr, mac_len) = match sockaddr_for_kernel(addr_ptr, addrlen) {
        Ok(pair) => pair,
        Err(errno) => return (-(errno as i64)) as u64,
    };
    let ret = unsafe {
        libc::bind(
            fd,
            &mac_addr as *const _ as *const libc::sockaddr,
            mac_len,
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
    // Convert returned macOS sockaddr to Linux format
    if addr_ptr != 0 && addrlen_ptr != 0 {
        let alen = unsafe { *(addrlen_ptr as *const u32) };
        mac_sockaddr_to_linux(addr_ptr, alen);
    }
    let nonblock = flags & LINUX_SOCK_NONBLOCK != 0;
    let cloexec = flags & LINUX_SOCK_CLOEXEC != 0;
    apply_sock_flags(ret, nonblock, cloexec);
    ret as u64
}

pub fn do_connect(fd: i32, addr_ptr: u64, addrlen: u32) -> u64 {
    if std::env::var_os("FAKELINUX_TRACE").is_some() && addr_ptr != 0 && addrlen >= 2 {
        unsafe {
            let p = addr_ptr as *const u8;
            let family = *p; // still Linux layout here
            if family == 1 && addrlen > 2 {
                // AF_UNIX: print sun_path
                let path_bytes = std::slice::from_raw_parts(p.add(2), (addrlen - 2) as usize);
                let end = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
                let path = String::from_utf8_lossy(&path_bytes[..end]);
                eprintln!("fakelinux: connect(fd={}, AF_UNIX \"{}\", len={})", fd, path, addrlen);
            }
        }
    }
    let (mac_addr, mac_len) = match sockaddr_for_kernel(addr_ptr, addrlen) {
        Ok(pair) => pair,
        Err(errno) => return (-(errno as i64)) as u64,
    };
    let ret = unsafe {
        libc::connect(
            fd,
            &mac_addr as *const _ as *const libc::sockaddr,
            mac_len,
        )
    };
    if ret < 0 {
        translate::linux_errno()
    } else {
        0
    }
}

pub fn do_sendto(fd: i32, buf: u64, len: u64, flags: i32, dest_addr: u64, addrlen: u32) -> u64 {
    let mac_flags = translate_msg_flags(flags);
    let mac_addr = if dest_addr != 0 {
        Some(linux_sockaddr_to_mac_copy(dest_addr, addrlen))
    } else {
        None
    };
    let ret = unsafe {
        libc::sendto(
            fd,
            buf as *const libc::c_void,
            len as usize,
            mac_flags,
            match &mac_addr {
                Some(a) => a as *const _ as *const libc::sockaddr,
                None => std::ptr::null(),
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
    let mac_flags = translate_msg_flags(flags);
    let ret = unsafe {
        libc::recvfrom(
            fd,
            buf as *mut libc::c_void,
            len as usize,
            mac_flags,
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
        // Convert returned macOS sockaddr to Linux format
        if src_addr != 0 && addrlen_ptr != 0 {
            let alen = unsafe { *(addrlen_ptr as *const u32) };
            mac_sockaddr_to_linux(src_addr, alen);
        }
        ret as u64
    }
}

pub fn do_setsockopt(fd: i32, level: i32, optname: i32, optval: u64, optlen: u32) -> u64 {
    // SO_PASSCRED has no macOS equivalent (SCM_CREDENTIALS ancillary data).
    // Accept it as a no-op: servers like VPP hard-fail startup if it errors,
    // and the credentials themselves are optional metadata for the receiver.
    if level == LINUX_SOL_SOCKET && optname == LINUX_SO_PASSCRED {
        return 0;
    }
    let (mac_level, mac_optname) = match translate::translate_sockopt(level, optname) {
        Some(pair) => pair,
        // Unknown option — never pass through (optname values collide across
        // platforms, e.g. Linux TCP_KEEPIDLE=4 vs macOS TCP_NOPUSH=4).
        None => return (-92i64) as u64, // Linux ENOPROTOOPT
    };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            mac_level,
            mac_optname,
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
    let (mac_level, mac_optname) = match translate::translate_sockopt(level, optname) {
        Some(pair) => pair,
        None => return (-92i64) as u64, // Linux ENOPROTOOPT — see do_setsockopt
    };
    let ret = unsafe {
        libc::getsockopt(
            fd,
            mac_level,
            mac_optname,
            optval as *mut libc::c_void,
            optlen_ptr as *mut libc::socklen_t,
        )
    };
    if ret < 0 {
        translate::linux_errno()
    } else {
        // For SO_ERROR, translate the macOS errno stored in the option value
        // to the corresponding Linux errno
        if translate::is_so_error(level, optname) && optval != 0 {
            unsafe {
                let err = *(optval as *const i32);
                if err != 0 {
                    *(optval as *mut i32) = translate::mac_errno_to_linux(err);
                }
            }
        }
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
        if addr_ptr != 0 && addrlen_ptr != 0 {
            let alen = unsafe { *(addrlen_ptr as *const u32) };
            mac_sockaddr_to_linux(addr_ptr, alen);
        }
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
        if addr_ptr != 0 && addrlen_ptr != 0 {
            let alen = unsafe { *(addrlen_ptr as *const u32) };
            mac_sockaddr_to_linux(addr_ptr, alen);
        }
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

// ─── cmsg (ancillary data) translation ───────────────────────────────────────
//
// Linux cmsghdr:  { u64 cmsg_len; i32 cmsg_level; i32 cmsg_type; }  16 bytes, 8-aligned
// macOS cmsghdr:  { u32 cmsg_len; i32 cmsg_level; i32 cmsg_type; }  12 bytes, 4-aligned
//
// cmsg_level SOL_SOCKET is 1 on Linux, 0xffff on macOS. SCM_RIGHTS=1 on both.
// Passing the buffers through raw silently drops fds (VPP's stats segment
// handoff sends the memfd via SCM_RIGHTS over stats.sock).

const LINUX_CMSG_HDR: usize = 16;
const MAC_CMSG_HDR: usize = 12;

fn align8(n: usize) -> usize { (n + 7) & !7 }
fn align4(n: usize) -> usize { (n + 3) & !3 }

/// Rebuild a Linux control buffer in macOS layout. SCM_CREDENTIALS entries
/// are dropped (no macOS equivalent; receivers treat creds as optional).
fn linux_cmsgs_to_mac(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len());
    let mut off = 0usize;
    while off + LINUX_CMSG_HDR <= buf.len() {
        let clen = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()) as usize;
        if clen < LINUX_CMSG_HDR || off + clen > buf.len() {
            break;
        }
        let level = i32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap());
        let typ = i32::from_le_bytes(buf[off + 12..off + 16].try_into().unwrap());
        let data = &buf[off + LINUX_CMSG_HDR..off + clen];
        if !(level == LINUX_SOL_SOCKET && typ == LINUX_SCM_CREDENTIALS) {
            let mac_level = if level == LINUX_SOL_SOCKET { MAC_SOL_SOCKET } else { level };
            let mac_len = (MAC_CMSG_HDR + data.len()) as u32;
            let start = out.len();
            out.extend_from_slice(&mac_len.to_le_bytes());
            out.extend_from_slice(&mac_level.to_le_bytes());
            out.extend_from_slice(&typ.to_le_bytes());
            out.extend_from_slice(data);
            out.resize(start + align4(mac_len as usize), 0);
        }
        off += align8(clen);
    }
    out
}

/// Rebuild a macOS control buffer in Linux layout. Also returns any fds
/// received via SCM_RIGHTS (so MSG_CMSG_CLOEXEC can be applied).
fn mac_cmsgs_to_linux(buf: &[u8]) -> (Vec<u8>, Vec<i32>) {
    let mut out = Vec::with_capacity(buf.len() * 2);
    let mut fds = Vec::new();
    let mut off = 0usize;
    while off + MAC_CMSG_HDR <= buf.len() {
        let clen = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        if clen < MAC_CMSG_HDR || off + clen > buf.len() {
            break;
        }
        let level = i32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap());
        let typ = i32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap());
        let data = &buf[off + MAC_CMSG_HDR..off + clen];
        let linux_level = if level == MAC_SOL_SOCKET { LINUX_SOL_SOCKET } else { level };
        if level == MAC_SOL_SOCKET && typ == libc::SCM_RIGHTS {
            for chunk in data.chunks_exact(4) {
                fds.push(i32::from_le_bytes(chunk.try_into().unwrap()));
            }
        }
        let linux_len = (LINUX_CMSG_HDR + data.len()) as u64;
        let start = out.len();
        out.extend_from_slice(&linux_len.to_le_bytes());
        out.extend_from_slice(&linux_level.to_le_bytes());
        out.extend_from_slice(&typ.to_le_bytes());
        out.extend_from_slice(data);
        // Pad to the Linux 8-byte cmsg boundary, but only between entries —
        // the final cmsg's length is just header+data.
        if align4(clen) < buf.len() - off {
            out.resize(start + align8(linux_len as usize), 0);
        }
        off += align4(clen);
    }
    (out, fds)
}

/// Translate a Linux aarch64 msghdr (56 bytes) to a macOS msghdr (48 bytes).
/// The layouts differ in msg_iovlen (size_t vs int) and msg_controllen (size_t vs socklen_t).
/// For common cases (small iovlen/controllen), the direct cast works because the
/// upper bytes are zero. But we translate properly for correctness.
fn linux_msghdr_to_mac(linux_ptr: u64) -> libc::msghdr {
    unsafe {
        let p = linux_ptr as *const u8;
        let msg_name = (p as *const u64).read_unaligned() as *mut libc::c_void;
        let msg_namelen = (p.add(8) as *const u32).read_unaligned();
        let msg_iov = (p.add(16) as *const u64).read_unaligned() as *mut libc::iovec;
        let msg_iovlen = (p.add(24) as *const u64).read_unaligned() as i32; // truncate size_t to int
        let msg_control = (p.add(32) as *const u64).read_unaligned() as *mut libc::c_void;
        let msg_controllen = (p.add(40) as *const u64).read_unaligned() as u32; // truncate
        let msg_flags = (p.add(48) as *const i32).read_unaligned();
        libc::msghdr {
            msg_name,
            msg_namelen,
            msg_iov,
            msg_iovlen,
            msg_control,
            msg_controllen,
            msg_flags,
        }
    }
}

pub fn do_sendmsg(fd: i32, msg_ptr: u64, flags: i32) -> u64 {
    let mac_flags = translate_msg_flags(flags);
    let mut mac_msg = linux_msghdr_to_mac(msg_ptr);
    // Translate sockaddr in msg_name if present — into a local copy, the
    // guest's buffer may be read-only (see linux_sockaddr_to_mac_copy).
    let mut mac_addr;
    let mut mac_len: libc::socklen_t;
    if !mac_msg.msg_name.is_null() && mac_msg.msg_namelen > 0 {
        (mac_addr, mac_len) = match sockaddr_for_kernel(mac_msg.msg_name as u64, mac_msg.msg_namelen) {
            Ok(pair) => pair,
            Err(errno) => return (-(errno as i64)) as u64,
        };
        mac_msg.msg_name = &mut mac_addr as *mut _ as *mut libc::c_void;
        mac_msg.msg_namelen = mac_len;
    }
    // Rebuild ancillary data in macOS cmsg layout (SCM_RIGHTS fd passing).
    let mut mac_ctl;
    if !mac_msg.msg_control.is_null() && mac_msg.msg_controllen > 0 {
        let cbuf = unsafe {
            std::slice::from_raw_parts(mac_msg.msg_control as *const u8, mac_msg.msg_controllen as usize)
        };
        mac_ctl = linux_cmsgs_to_mac(cbuf);
        if mac_ctl.is_empty() {
            mac_msg.msg_control = std::ptr::null_mut();
            mac_msg.msg_controllen = 0;
        } else {
            mac_msg.msg_control = mac_ctl.as_mut_ptr() as *mut libc::c_void;
            mac_msg.msg_controllen = mac_ctl.len() as libc::socklen_t;
        }
    }
    let ret = unsafe { libc::sendmsg(fd, &mac_msg, mac_flags) };
    if ret < 0 {
        translate::linux_errno()
    } else {
        ret as u64
    }
}

pub fn do_recvmsg(fd: i32, msg_ptr: u64, flags: i32) -> u64 {
    let mac_flags = translate_msg_flags(flags);
    let mut mac_msg = linux_msghdr_to_mac(msg_ptr);
    // Receive ancillary data into a local macOS-layout buffer; converted back
    // to Linux layout into the guest's buffer below. The guest's controllen
    // is a sufficient size (mac cmsg headers are smaller than Linux's).
    let guest_ctl = mac_msg.msg_control;
    let guest_ctl_len = mac_msg.msg_controllen as usize;
    let mut mac_ctl = vec![0u8; guest_ctl_len];
    if !guest_ctl.is_null() && guest_ctl_len > 0 {
        mac_msg.msg_control = mac_ctl.as_mut_ptr() as *mut libc::c_void;
    }
    let ret = unsafe { libc::recvmsg(fd, &mut mac_msg, mac_flags) };
    if ret < 0 {
        translate::linux_errno()
    } else {
        let mut linux_ctl_len = 0u64;
        // Rebuild returned msg_flags with Linux values (they differ:
        // TRUNC 0x10→0x20, CTRUNC 0x20→0x08, EOR 0x08→0x80; OOB=1 on both).
        let mut linux_flags = 0i32;
        if mac_msg.msg_flags & libc::MSG_OOB != 0 {
            linux_flags |= 0x1;
        }
        if mac_msg.msg_flags & libc::MSG_EOR != 0 {
            linux_flags |= 0x80;
        }
        if mac_msg.msg_flags & libc::MSG_TRUNC != 0 {
            linux_flags |= 0x20;
        }
        if mac_msg.msg_flags & libc::MSG_CTRUNC != 0 {
            linux_flags |= 0x8;
        }
        if !guest_ctl.is_null() && mac_msg.msg_controllen > 0 {
            let (linux_ctl, fds) = mac_cmsgs_to_linux(&mac_ctl[..mac_msg.msg_controllen as usize]);
            let mut n = linux_ctl.len();
            if n > guest_ctl_len {
                n = guest_ctl_len; // Linux-layout expansion overflowed: truncate
                linux_flags |= 0x8; // Linux MSG_CTRUNC
            }
            unsafe {
                std::ptr::copy_nonoverlapping(linux_ctl.as_ptr(), guest_ctl as *mut u8, n);
            }
            linux_ctl_len = n as u64;
            // Linux MSG_CMSG_CLOEXEC applies O_CLOEXEC to received fds.
            if flags & LINUX_MSG_CMSG_CLOEXEC != 0 {
                for fd in fds {
                    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
                }
            }
        }
        // Write back fields that the kernel may have modified
        unsafe {
            let p = msg_ptr as *mut u8;
            // msg_namelen (offset 8)
            (p.add(8) as *mut u32).write_unaligned(mac_msg.msg_namelen);
            // msg_controllen (offset 40, as u64 on Linux)
            (p.add(40) as *mut u64).write_unaligned(linux_ctl_len);
            // msg_flags (offset 48)
            (p.add(48) as *mut i32).write_unaligned(linux_flags);
        }
        // Translate returned sockaddr
        if !mac_msg.msg_name.is_null() && mac_msg.msg_namelen > 0 {
            mac_sockaddr_to_linux(mac_msg.msg_name as u64, mac_msg.msg_namelen);
        }
        ret as u64
    }
}

/// sendmmsg(fd, msgvec, vlen, flags) — send multiple messages.
/// Linux struct mmsghdr on aarch64:
///   struct msghdr msg_hdr;   // 56 bytes (Linux layout)
///   unsigned int  msg_len;   // 4 bytes at offset 56
///   // total 60, padded to 64 for alignment
pub fn do_sendmmsg(fd: i32, msgvec: u64, vlen: u32, flags: i32) -> u64 {
    const LINUX_MMSGHDR_SIZE: usize = 64; // 56 (msghdr) + 4 (msg_len) + 4 (pad)
    let mac_flags = translate_msg_flags(flags);

    let mut sent = 0u32;
    for i in 0..vlen {
        let mmsghdr_ptr = msgvec + (i as u64) * (LINUX_MMSGHDR_SIZE as u64);
        let mut mac_msg = linux_msghdr_to_mac(mmsghdr_ptr);

        // Translate sockaddr if present — local copy, guest buffer may be read-only
        let mut mac_addr;
        if !mac_msg.msg_name.is_null() && mac_msg.msg_namelen > 0 {
            mac_addr = linux_sockaddr_to_mac_copy(mac_msg.msg_name as u64, mac_msg.msg_namelen);
            mac_msg.msg_name = &mut mac_addr as *mut _ as *mut libc::c_void;
        }

        let ret = unsafe { libc::sendmsg(fd, &mac_msg, mac_flags) };

        if ret < 0 {
            if sent == 0 {
                return translate::linux_errno();
            }
            break; // partial send: return count of successful messages
        }

        // Write msg_len field at offset 56 in the Linux mmsghdr
        unsafe {
            ((mmsghdr_ptr + 56) as *mut u32).write_unaligned(ret as u32);
        }
        sent += 1;
    }

    sent as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn af_inet6_domain_translated() {
        // Linux AF_INET6=10 must become macOS AF_INET6=30, or socket()
        // fails with EAFNOSUPPORT (python: "[Errno 97] Address family not
        // supported" on any dual-stack host).
        let r = do_socket(10, libc::SOCK_STREAM, 0);
        assert!((r as i64) >= 0, "AF_INET6 socket failed: {}", r as i64);
        unsafe { libc::close(r as i32); }
    }

    #[test]
    fn sockaddr_in6_family_mapped_both_ways() {
        // Linux sockaddr_in6: u16 family=10, then port/flowinfo/addr/scope.
        let mut sa = [0u8; 28];
        sa[0] = 10; // AF_INET6 (LE u16)
        sa[2] = 0x01; sa[3] = 0xbb; // port 443 BE
        let mac = linux_sockaddr_to_mac_copy(sa.as_ptr() as u64, 28);
        let p = &mac as *const _ as *const u8;
        unsafe {
            assert_eq!(*p, 28); // sin6_len
            assert_eq!(*p.add(1), 30); // macOS AF_INET6
            assert_eq!(*p.add(2), 0x01); // port preserved
            assert_eq!(*p.add(3), 0xbb);
        }
        // Reverse: macOS (len=28, family=30) → Linux (family u16 = 10)
        let mut back = [0u8; 28];
        back[0] = 28; back[1] = 30;
        mac_sockaddr_to_linux(back.as_mut_ptr() as u64, 28);
        assert_eq!(back[0], 10);
        assert_eq!(back[1], 0);
    }

    #[test]
    fn unix_seqpacket_becomes_stream() {
        // macOS has no AF_UNIX SOCK_SEQPACKET (EPROTONOSUPPORT). VPP's
        // stats.sock/cli.sock are SEQPACKET servers that pass one fd per
        // connection via SCM_RIGHTS — SOCK_STREAM is a faithful substitute.
        let r = do_socket(1, LINUX_SOCK_SEQPACKET, 0);
        assert!((r as i64) >= 0, "AF_UNIX SEQPACKET socket failed: {}", r as i64);
        unsafe { libc::close(r as i32); }
    }

    #[test]
    fn so_passcred_is_accepted() {
        // VPP hard-fails startup if setsockopt(SOL_SOCKET, SO_PASSCRED)
        // errors. macOS has no equivalent — accept as a no-op.
        let fd = do_socket(1, libc::SOCK_STREAM, 0) as i32;
        assert!(fd >= 0);
        let one: i32 = 1;
        let r = do_setsockopt(fd, LINUX_SOL_SOCKET, LINUX_SO_PASSCRED, &one as *const _ as u64, 4);
        assert_eq!(r, 0, "SO_PASSCRED must be a no-op success, got {}", r as i64);
        unsafe { libc::close(fd); }
    }

    #[test]
    fn linux_sun_path_extraction() {
        // Linux sockaddr_un: u16 family=1, then sun_path[108].
        let mut sa = [0u8; 110];
        sa[0] = 1;
        sa[2..2 + 19].copy_from_slice(b"/run/vpp/stats.sock");
        assert_eq!(linux_sun_path(&sa[..110]), Some(&b"/run/vpp/stats.sock"[..]));
        // Abstract socket (leading NUL) — not a filesystem path.
        let mut ab = [0u8; 110];
        ab[0] = 1;
        ab[3] = b'x';
        assert_eq!(linux_sun_path(&ab[..110]), None);
        // Not AF_UNIX.
        let mut inet = [0u8; 16];
        inet[0] = 2;
        assert_eq!(linux_sun_path(&inet[..16]), None);
        // addrlen clamps the path (no NUL terminator inside addrlen).
        let mut sa2 = [0u8; 110];
        sa2[0] = 1;
        sa2[2..6].copy_from_slice(b"/x/y");
        assert_eq!(linux_sun_path(&sa2[..6]), Some(&b"/x/y"[..]));
    }

    #[test]
    fn mac_sockaddr_un_built_and_length_checked() {
        let (sa, len) = mac_sockaddr_un(b"/tmp/test.sock").expect("build");
        assert_eq!(sa.sun_family as i32, libc::AF_UNIX);
        assert_eq!(sa.sun_len as u32, len);
        let path: Vec<u8> = sa.sun_path.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
        assert_eq!(path, b"/tmp/test.sock");
        // Host path too long for macOS's 104-byte sun_path → ENAMETOOLONG.
        let long = vec![b'a'; 200];
        assert_eq!(mac_sockaddr_un(&long).unwrap_err(), 36);
    }

    #[test]
    fn cmsg_scm_rights_translated_both_ways() {
        // Linux cmsghdr: u64 len, i32 level, i32 type (16-byte header, 8-align).
        // macOS cmsghdr: u32 len, i32 level, i32 type (12-byte header, 4-align).
        // SOL_SOCKET is 1 on Linux, 0xffff on macOS; SCM_RIGHTS=1 on both.
        let mut linux_buf = vec![0u8; 24]; // CMSG_SPACE(4) on Linux
        linux_buf[0..8].copy_from_slice(&20u64.to_le_bytes()); // CMSG_LEN(4)
        linux_buf[8..12].copy_from_slice(&1i32.to_le_bytes()); // SOL_SOCKET
        linux_buf[12..16].copy_from_slice(&1i32.to_le_bytes()); // SCM_RIGHTS
        linux_buf[16..20].copy_from_slice(&42i32.to_le_bytes()); // the fd
        let mac = linux_cmsgs_to_mac(&linux_buf);
        assert_eq!(&mac[0..4], &16u32.to_le_bytes()); // mac CMSG_LEN(4) = 12+4
        assert_eq!(&mac[4..8], &(0xffffi32).to_le_bytes()); // mac SOL_SOCKET
        assert_eq!(&mac[8..12], &1i32.to_le_bytes()); // SCM_RIGHTS
        assert_eq!(&mac[12..16], &42i32.to_le_bytes());

        let (back, fds) = mac_cmsgs_to_linux(&mac);
        assert_eq!(back, &linux_buf[..20]); // header+data (no trailing pad needed)
        assert_eq!(fds, vec![42]);
    }

    #[test]
    fn fd_passes_over_socketpair_via_linux_msghdr() {
        // End-to-end: guest-format sendmsg/recvmsg must carry SCM_RIGHTS
        // through the macOS kernel (VPP's stats segment handoff).
        let mut sv = [0i32; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) }, 0);
        let mut pipefd = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(pipefd.as_mut_ptr()) }, 0);

        // Build Linux msghdr (56 bytes) + Linux cmsg carrying pipefd[1].
        let payload = b"X";
        let iov = libc::iovec { iov_base: payload.as_ptr() as *mut _, iov_len: 1 };
        let mut cbuf = [0u8; 24];
        cbuf[0..8].copy_from_slice(&20u64.to_le_bytes());
        cbuf[8..12].copy_from_slice(&1i32.to_le_bytes());
        cbuf[12..16].copy_from_slice(&1i32.to_le_bytes());
        cbuf[16..20].copy_from_slice(&pipefd[1].to_le_bytes());
        let mut mh = [0u8; 56];
        mh[16..24].copy_from_slice(&(&iov as *const _ as u64).to_le_bytes());
        mh[24..32].copy_from_slice(&1u64.to_le_bytes());
        mh[32..40].copy_from_slice(&(cbuf.as_ptr() as u64).to_le_bytes());
        mh[40..48].copy_from_slice(&24u64.to_le_bytes());
        let r = do_sendmsg(sv[0], mh.as_ptr() as u64, 0);
        assert_eq!(r as i64, 1, "sendmsg failed: {}", r as i64);

        // Receive with a Linux msghdr.
        let mut rbuf = [0u8; 4];
        let riov = libc::iovec { iov_base: rbuf.as_mut_ptr() as *mut _, iov_len: 4 };
        let mut rcbuf = [0u8; 24];
        let mut rmh = [0u8; 56];
        rmh[16..24].copy_from_slice(&(&riov as *const _ as u64).to_le_bytes());
        rmh[24..32].copy_from_slice(&1u64.to_le_bytes());
        rmh[32..40].copy_from_slice(&(rcbuf.as_ptr() as u64).to_le_bytes());
        rmh[40..48].copy_from_slice(&24u64.to_le_bytes());
        let r = do_recvmsg(sv[1], rmh.as_ptr() as u64, 0);
        assert_eq!(r as i64, 1, "recvmsg failed: {}", r as i64);
        assert_eq!(rbuf[0], b'X');
        // Control data came back in LINUX layout.
        let clen = u64::from_le_bytes(rmh[40..48].try_into().unwrap());
        assert!(clen >= 20, "no control data received (controllen={})", clen);
        assert_eq!(&rcbuf[8..12], &1i32.to_le_bytes(), "cmsg_level must be Linux SOL_SOCKET");
        assert_eq!(&rcbuf[12..16], &1i32.to_le_bytes());
        let newfd = i32::from_le_bytes(rcbuf[16..20].try_into().unwrap());
        assert!(newfd >= 0);
        // The passed fd actually works: write into the pipe via the original
        // write end, read from pipe read end.
        assert_eq!(unsafe { libc::write(newfd, b"Y".as_ptr() as *const _, 1) }, 1);
        let mut byte = [0u8; 1];
        assert_eq!(unsafe { libc::read(pipefd[0], byte.as_mut_ptr() as *mut _, 1) }, 1);
        assert_eq!(byte[0], b'Y');
        unsafe {
            libc::close(sv[0]); libc::close(sv[1]);
            libc::close(pipefd[0]); libc::close(pipefd[1]); libc::close(newfd);
        }
    }
}
