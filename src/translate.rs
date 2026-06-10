//! Translation between Linux and macOS constants: open flags, errno, struct stat, etc.

// ─── AT_FDCWD ────────────────────────────────────────────────────────────────
pub const LINUX_AT_FDCWD: i32 = -100;

pub fn translate_dirfd(linux_dirfd: i32) -> i32 {
    if linux_dirfd == LINUX_AT_FDCWD {
        libc::AT_FDCWD
    } else {
        linux_dirfd
    }
}

// ─── Open flags (Linux aarch64 → macOS) ──────────────────────────────────────
// Linux aarch64 uses asm-generic values.

const LINUX_O_RDONLY: i32 = 0o0;
const LINUX_O_WRONLY: i32 = 0o1;
const LINUX_O_RDWR: i32 = 0o2;
const LINUX_O_CREAT: i32 = 0o100;
const LINUX_O_EXCL: i32 = 0o200;
const LINUX_O_NOCTTY: i32 = 0o400;
const LINUX_O_TRUNC: i32 = 0o1000;
const LINUX_O_APPEND: i32 = 0o2000;
const LINUX_O_NONBLOCK: i32 = 0o4000;
const LINUX_O_DIRECTORY: i32 = 0o40000;   // 0x4000 — asm-generic
const LINUX_O_NOFOLLOW: i32 = 0o100000;   // 0x8000 — asm-generic
const LINUX_O_CLOEXEC: i32 = 0o2000000;
const LINUX_O_LARGEFILE: i32 = 0o100000; // no-op on 64-bit
const LINUX_O_PATH: i32 = 0o10000000;    // 0x200000 — fd for path ops only

pub fn translate_open_flags(linux_flags: i32) -> i32 {
    let mut mac = linux_flags & (LINUX_O_RDONLY | LINUX_O_WRONLY | LINUX_O_RDWR); // 0,1,2 same

    let mappings: &[(i32, i32)] = &[
        (LINUX_O_CREAT, libc::O_CREAT),
        (LINUX_O_EXCL, libc::O_EXCL),
        (LINUX_O_NOCTTY, libc::O_NOCTTY),
        (LINUX_O_TRUNC, libc::O_TRUNC),
        (LINUX_O_APPEND, libc::O_APPEND),
        (LINUX_O_NONBLOCK, libc::O_NONBLOCK),
        (LINUX_O_DIRECTORY, libc::O_DIRECTORY),
        (LINUX_O_NOFOLLOW, libc::O_NOFOLLOW),
        (LINUX_O_CLOEXEC, libc::O_CLOEXEC),
    ];

    for &(linux_bit, mac_bit) in mappings {
        if linux_flags & linux_bit != 0 {
            mac |= mac_bit;
        }
    }

    // O_LARGEFILE is meaningless on 64-bit macOS; ignore it.
    // O_PATH (Linux-only: get a handle for path operations without opening
    // the file) has no macOS equivalent.  Drop it — macOS open() without
    // O_PATH works for the fstatat/renameat-based operations that coreutils
    // uses O_PATH for.  The important thing is that we correctly translated
    // O_DIRECTORY so the open fails on non-directories.
    mac
}

// ─── faccessat flags ─────────────────────────────────────────────────────────

const LINUX_AT_EACCESS: i32 = 0x200;
const LINUX_AT_SYMLINK_NOFOLLOW: i32 = 0x100;
const LINUX_AT_EMPTY_PATH: i32 = 0x1000;

pub fn translate_at_flags(linux_flags: i32) -> i32 {
    let mut mac = 0i32;
    if linux_flags & LINUX_AT_EACCESS != 0 {
        mac |= libc::AT_EACCESS;
    }
    if linux_flags & LINUX_AT_SYMLINK_NOFOLLOW != 0 {
        mac |= libc::AT_SYMLINK_NOFOLLOW;
    }
    // AT_EMPTY_PATH has no macOS equivalent — callers must handle separately
    let _ = LINUX_AT_EMPTY_PATH;
    mac
}

// ─── fcntl commands ──────────────────────────────────────────────────────────

pub const LINUX_F_DUPFD: i32 = 0;
pub const LINUX_F_GETFD: i32 = 1;
pub const LINUX_F_SETFD: i32 = 2;
pub const LINUX_F_GETFL: i32 = 3;
pub const LINUX_F_SETFL: i32 = 4;
pub const LINUX_F_GETLK: i32 = 5;
pub const LINUX_F_SETLK: i32 = 6;
pub const LINUX_F_SETLKW: i32 = 7;
pub const LINUX_F_DUPFD_CLOEXEC: i32 = 1030;

/// Translate Linux file status flags (for F_SETFL) to macOS.
/// Linux O_NONBLOCK=0x800, macOS O_NONBLOCK=0x4.
/// Linux O_APPEND=0x400, macOS O_APPEND=0x8.
/// Linux O_ASYNC=0x2000, macOS O_ASYNC=0x40.
pub fn linux_fl_to_mac(linux_fl: i32) -> i32 {
    let mut mac = 0;
    if linux_fl & 0x800 != 0 { mac |= libc::O_NONBLOCK; }  // Linux O_NONBLOCK
    if linux_fl & 0x400 != 0 { mac |= libc::O_APPEND; }    // Linux O_APPEND
    if linux_fl & 0x2000 != 0 { mac |= 0x40; }             // O_ASYNC
    mac
}

/// Translate macOS file status flags (from F_GETFL) to Linux.
pub fn mac_fl_to_linux(mac_fl: i32) -> i32 {
    let mut linux = 0;
    if mac_fl & libc::O_NONBLOCK != 0 { linux |= 0x800; }  // Linux O_NONBLOCK
    if mac_fl & libc::O_APPEND != 0 { linux |= 0x400; }    // Linux O_APPEND
    if mac_fl & 0x40 != 0 { linux |= 0x2000; }             // O_ASYNC
    // Preserve access mode (O_RDONLY=0, O_WRONLY=1, O_RDWR=2 — same on both)
    linux |= mac_fl & 0x3;
    linux
}

pub fn translate_fcntl_cmd(linux_cmd: i32) -> Option<i32> {
    match linux_cmd {
        LINUX_F_DUPFD => Some(libc::F_DUPFD),
        LINUX_F_GETFD => Some(libc::F_GETFD),
        LINUX_F_SETFD => Some(libc::F_SETFD),
        LINUX_F_GETFL => Some(libc::F_GETFL),
        LINUX_F_SETFL => Some(libc::F_SETFL),
        LINUX_F_DUPFD_CLOEXEC => Some(libc::F_DUPFD_CLOEXEC),
        // F_GETLK/F_SETLK/F_SETLKW need struct flock translation — handled separately
        LINUX_F_GETLK | LINUX_F_SETLK | LINUX_F_SETLKW => None,
        _ => None,
    }
}

/// Translate Linux flock l_type to macOS.
/// Linux: F_RDLCK=0, F_WRLCK=1, F_UNLCK=2 — macOS: F_RDLCK=1, F_UNLCK=2, F_WRLCK=3.
/// Passing the value through unmapped turns a Linux write lock (1) into a macOS
/// READ lock (1), which fails with EBADF on an O_WRONLY fd (broke lckpwdf() in
/// groupadd/useradd during apt-get install).
fn flock_type_linux_to_mac(l_type: i16) -> i16 {
    match l_type {
        0 => libc::F_RDLCK,
        1 => libc::F_WRLCK,
        2 => libc::F_UNLCK,
        other => other, // unknown — let the kernel reject it
    }
}

/// Translate macOS flock l_type back to Linux.
fn flock_type_mac_to_linux(l_type: i16) -> i16 {
    match l_type {
        libc::F_RDLCK => 0,
        libc::F_WRLCK => 1,
        libc::F_UNLCK => 2,
        other => other,
    }
}

/// Translate Linux struct flock (aarch64) to macOS struct flock.
/// Linux aarch64 layout:
/// offset 0:  i16 l_type
/// offset 2:  i16 l_whence
/// offset 4:  padding (4 bytes to align l_start to 8)
/// offset 8:  i64 l_start
/// offset 16: i64 l_len
/// offset 24: i32 l_pid
/// macOS: { i64 l_start, i64 l_len, i32 l_pid, i16 l_type, i16 l_whence }
pub fn linux_flock_to_mac(linux_ptr: u64) -> libc::flock {
    unsafe {
        let p = linux_ptr as *const u8;
        let l_type = (p as *const i16).read_unaligned();
        let l_whence = (p.add(2) as *const i16).read_unaligned();
        let l_start = (p.add(8) as *const i64).read_unaligned();
        let l_len = (p.add(16) as *const i64).read_unaligned();
        let l_pid = (p.add(24) as *const i32).read_unaligned();
        libc::flock {
            l_start,
            l_len,
            l_pid,
            l_type: flock_type_linux_to_mac(l_type),
            l_whence,
        }
    }
}

/// Write macOS struct flock back to Linux struct flock format.
pub fn mac_flock_to_linux(mac: &libc::flock, linux_ptr: u64) {
    unsafe {
        let p = linux_ptr as *mut u8;
        (p as *mut i16).write_unaligned(flock_type_mac_to_linux(mac.l_type));
        (p.add(2) as *mut i16).write_unaligned(mac.l_whence);
        // padding at offset 4-7 (zero it)
        std::ptr::write_bytes(p.add(4), 0, 4);
        (p.add(8) as *mut i64).write_unaligned(mac.l_start);
        (p.add(16) as *mut i64).write_unaligned(mac.l_len);
        (p.add(24) as *mut i32).write_unaligned(mac.l_pid);
    }
}

// ─── Socket option translation ───────────────────────────────────────────────
// Linux and macOS use different values for SOL_SOCKET and SO_* option names.
// IPPROTO_TCP (6) and TCP_NODELAY (1) are the same on both.

// Linux SOL_SOCKET and SO_* constants
const LINUX_SOL_SOCKET: i32 = 1;
const LINUX_SO_REUSEADDR: i32 = 2;
const LINUX_SO_TYPE: i32 = 3;
const LINUX_SO_ERROR: i32 = 4;
const LINUX_SO_BROADCAST: i32 = 6;
const LINUX_SO_SNDBUF: i32 = 7;
const LINUX_SO_RCVBUF: i32 = 8;
const LINUX_SO_KEEPALIVE: i32 = 9;
const LINUX_SO_OOBINLINE: i32 = 10;
const LINUX_SO_LINGER: i32 = 13;
const LINUX_SO_REUSEPORT: i32 = 15;
const LINUX_SO_RCVTIMEO: i32 = 20;
const LINUX_SO_SNDTIMEO: i32 = 21;
const LINUX_SO_ACCEPTCONN: i32 = 30;

// Linux IPPROTO_IPV6 = 41 on both, but IPV6_V6ONLY differs
const LINUX_IPPROTO_IPV6: i32 = 41;
const LINUX_IPV6_V6ONLY: i32 = 26;

// Linux IPPROTO_TCP option names. Only TCP_NODELAY(1) and TCP_MAXSEG(2)
// match macOS; above that the namespaces collide with different meanings
// (Linux TCP_KEEPIDLE=4 vs macOS TCP_NOPUSH=4 — passing that through
// corked curl's HTTP request in the send buffer for ~5s).
const LINUX_TCP_NODELAY: i32 = 1;
const LINUX_TCP_MAXSEG: i32 = 2;
const LINUX_TCP_CORK: i32 = 3;
const LINUX_TCP_KEEPIDLE: i32 = 4;
const LINUX_TCP_KEEPINTVL: i32 = 5;
const LINUX_TCP_KEEPCNT: i32 = 6;

/// Translate Linux socket option level+name to macOS equivalents.
/// Returns (mac_level, mac_optname). Returns None if unknown.
pub fn translate_sockopt(linux_level: i32, linux_optname: i32) -> Option<(i32, i32)> {
    if linux_level == LINUX_SOL_SOCKET {
        let mac_opt = match linux_optname {
            LINUX_SO_REUSEADDR => libc::SO_REUSEADDR,
            LINUX_SO_TYPE => libc::SO_TYPE,
            LINUX_SO_ERROR => libc::SO_ERROR,
            LINUX_SO_BROADCAST => libc::SO_BROADCAST,
            LINUX_SO_SNDBUF => libc::SO_SNDBUF,
            LINUX_SO_RCVBUF => libc::SO_RCVBUF,
            LINUX_SO_KEEPALIVE => libc::SO_KEEPALIVE,
            LINUX_SO_OOBINLINE => libc::SO_OOBINLINE,
            LINUX_SO_LINGER => libc::SO_LINGER,
            LINUX_SO_REUSEPORT => libc::SO_REUSEPORT,
            LINUX_SO_RCVTIMEO => libc::SO_RCVTIMEO,
            LINUX_SO_SNDTIMEO => libc::SO_SNDTIMEO,
            LINUX_SO_ACCEPTCONN => libc::SO_ACCEPTCONN,
            _ => return None,
        };
        Some((libc::SOL_SOCKET, mac_opt))
    } else if linux_level == LINUX_IPPROTO_IPV6 {
        let mac_opt = match linux_optname {
            LINUX_IPV6_V6ONLY => libc::IPV6_V6ONLY,
            _ => linux_optname, // most IPV6 options have same values
        };
        Some((libc::IPPROTO_IPV6, mac_opt))
    } else if linux_level == libc::IPPROTO_TCP {
        let mac_opt = match linux_optname {
            LINUX_TCP_NODELAY => libc::TCP_NODELAY,
            LINUX_TCP_MAXSEG => libc::TCP_MAXSEG,
            LINUX_TCP_CORK => libc::TCP_NOPUSH, // closest macOS equivalent
            LINUX_TCP_KEEPIDLE => libc::TCP_KEEPALIVE,
            LINUX_TCP_KEEPINTVL => libc::TCP_KEEPINTVL,
            LINUX_TCP_KEEPCNT => libc::TCP_KEEPCNT,
            // Unknown TCP optnames must NOT pass through: the value spaces
            // collide (e.g. macOS 4 = TCP_NOPUSH). Callers turn None into
            // ENOPROTOOPT, which guests handle like a kernel without the
            // feature.
            _ => return None,
        };
        Some((libc::IPPROTO_TCP, mac_opt))
    } else {
        // IPPROTO_IP(0), etc. — same on both platforms for the options
        // guests commonly use
        Some((linux_level, linux_optname))
    }
}

/// Check if this is a SO_ERROR getsockopt (needs errno translation on result).
pub fn is_so_error(linux_level: i32, linux_optname: i32) -> bool {
    linux_level == LINUX_SOL_SOCKET && linux_optname == LINUX_SO_ERROR
}

// ─── Errno translation (macOS → Linux) ──────────────────────────────────────
// Errnos 1-10 and 12-34 are identical. Above 34 they diverge.
// We map macOS errno → Linux errno so that the guest sees correct values.

pub fn mac_errno_to_linux(mac_errno: i32) -> i32 {
    match mac_errno {
        // 1-10 are the same on both platforms
        1..=10 => mac_errno,
        // macOS 11 = EDEADLK → Linux 35
        11 => 35,
        // 12-34 are the same
        12..=34 => mac_errno,
        // macOS EAGAIN=35 → Linux EAGAIN=11
        35 => 11,
        // macOS EINPROGRESS=36 → Linux 115
        36 => 115,
        // macOS EALREADY=37 → Linux 114
        37 => 114,
        // macOS ENOTSOCK=38 → Linux 88
        38 => 88,
        // macOS EDESTADDRREQ=39 → Linux 89
        39 => 89,
        // macOS EMSGSIZE=40 → Linux 90
        40 => 90,
        // macOS EPROTOTYPE=41 → Linux 91
        41 => 91,
        // macOS ENOPROTOOPT=42 → Linux 92
        42 => 92,
        // macOS EPROTONOSUPPORT=43 → Linux 93
        43 => 93,
        // macOS ENOTSUP=45 → Linux ENOTSUP=95
        45 => 95,
        // macOS EAFNOSUPPORT=47 → Linux 97
        47 => 97,
        // macOS EADDRINUSE=48 → Linux 98
        48 => 98,
        // macOS EADDRNOTAVAIL=49 → Linux 99
        49 => 99,
        // macOS ENETDOWN=50 → Linux 100
        50 => 100,
        // macOS ENETUNREACH=51 → Linux 101
        51 => 101,
        // macOS ENETRESET=52 → Linux 102
        52 => 102,
        // macOS ECONNABORTED=53 → Linux 103
        53 => 103,
        // macOS ECONNRESET=54 → Linux 104
        54 => 104,
        // macOS ENOBUFS=55 → Linux 105
        55 => 105,
        // macOS EISCONN=56 → Linux 106
        56 => 106,
        // macOS ENOTCONN=57 → Linux 107
        57 => 107,
        // macOS ETIMEDOUT=60 → Linux 110
        60 => 110,
        // macOS ECONNREFUSED=61 → Linux 111
        61 => 111,
        // macOS ELOOP=62 → Linux 40
        62 => 40,
        // macOS ENAMETOOLONG=63 → Linux 36
        63 => 36,
        // macOS EHOSTUNREACH=65 → Linux 113
        65 => 113,
        // macOS ENOTEMPTY=66 → Linux 39
        66 => 39,
        // macOS ENOSYS=78 → Linux 38
        78 => 38,
        // macOS EOVERFLOW=84 → Linux 75
        84 => 75,
        // macOS EILSEQ=92 → Linux 84
        92 => 84,
        // Unmapped: return as-is (best effort)
        _ => mac_errno,
    }
}

/// Get the current macOS errno, translated to Linux errno, and return as negated value.
pub fn linux_errno() -> u64 {
    let mac_e = unsafe { *libc::__error() };
    let linux_e = mac_errno_to_linux(mac_e);
    (-(linux_e as i64)) as u64
}

// ─── struct stat translation (macOS → Linux aarch64) ─────────────────────────
//
// Linux aarch64 struct stat layout (128 bytes):
//   offset  0: u64 st_dev
//   offset  8: u64 st_ino
//   offset 16: u32 st_mode
//   offset 20: u32 st_nlink
//   offset 24: u32 st_uid
//   offset 28: u32 st_gid
//   offset 32: u64 st_rdev
//   offset 40: u64 __pad1
//   offset 48: i64 st_size
//   offset 56: i32 st_blksize
//   offset 60: i32 __pad2
//   offset 64: i64 st_blocks
//   offset 72: i64 st_atime_sec
//   offset 80: i64 st_atime_nsec
//   offset 88: i64 st_mtime_sec
//   offset 96: i64 st_mtime_nsec
//   offset104: i64 st_ctime_sec
//   offset112: i64 st_ctime_nsec
//   offset120: u32 __unused4
//   offset124: u32 __unused5
pub const LINUX_STAT_SIZE: usize = 128;

pub fn mac_stat_to_linux(mac: &libc::stat, out: *mut u8) {
    unsafe {
        std::ptr::write_bytes(out, 0, LINUX_STAT_SIZE);

        let w64 = |off: usize, val: u64| {
            (out.add(off) as *mut u64).write_unaligned(val);
        };
        let w32 = |off: usize, val: u32| {
            (out.add(off) as *mut u32).write_unaligned(val);
        };
        let wi64 = |off: usize, val: i64| {
            (out.add(off) as *mut i64).write_unaligned(val);
        };
        let wi32 = |off: usize, val: i32| {
            (out.add(off) as *mut i32).write_unaligned(val);
        };

        w64(0, mac.st_dev as u64);
        w64(8, mac.st_ino);
        // macOS st_mode is u16, Linux is u32
        w32(16, mac.st_mode as u32);
        w32(20, mac.st_nlink as u32);
        // Map host ownership into the guest's virtual user namespace:
        // our files appear root-owned (sudo/dpkg check this).
        w32(24, crate::creds::map_host_uid(mac.st_uid));
        w32(28, crate::creds::map_host_gid(mac.st_gid));
        w64(32, mac.st_rdev as u64);
        // __pad1 at 40 stays zero
        wi64(48, mac.st_size);
        wi32(56, mac.st_blksize);
        // __pad2 at 60 stays zero
        wi64(64, mac.st_blocks as i64);
        wi64(72, mac.st_atime);
        wi64(80, mac.st_atime_nsec);
        wi64(88, mac.st_mtime);
        wi64(96, mac.st_mtime_nsec);
        wi64(104, mac.st_ctime);
        wi64(112, mac.st_ctime_nsec);
    }
}

// ─── statx translation ──────────────────────────────────────────────────────
// Linux struct statx layout (256 bytes):
//   offset  0: u32 stx_mask
//   offset  4: u32 stx_blksize
//   offset  8: u64 stx_attributes
//   offset 16: u32 stx_nlink
//   offset 20: u32 stx_uid
//   offset 24: u32 stx_gid
//   offset 28: u16 stx_mode
//   offset 30: u16 __spare0
//   offset 32: u64 stx_ino
//   offset 40: u64 stx_size
//   offset 48: u64 stx_blocks
//   offset 56: u64 stx_attributes_mask
//   offset 64: struct statx_timestamp stx_atime (16 bytes: i64 tv_sec + u32 tv_nsec + i32 __reserved)
//   offset 80: struct statx_timestamp stx_btime
//   offset 96: struct statx_timestamp stx_ctime
//   offset112: struct statx_timestamp stx_mtime
//   offset128: u32 stx_rdev_major
//   offset132: u32 stx_rdev_minor
//   offset136: u32 stx_dev_major
//   offset140: u32 stx_dev_minor
//   offset144: u64 stx_mnt_id
//   ... rest is spare/padding up to 256 bytes
pub const LINUX_STATX_SIZE: usize = 256;
const STATX_BASIC_STATS: u32 = 0x07ff;

pub fn mac_stat_to_linux_statx(mac: &libc::stat, out: *mut u8) {
    unsafe {
        std::ptr::write_bytes(out, 0, LINUX_STATX_SIZE);

        let w64 = |off: usize, val: u64| {
            (out.add(off) as *mut u64).write_unaligned(val);
        };
        let w32 = |off: usize, val: u32| {
            (out.add(off) as *mut u32).write_unaligned(val);
        };
        let w16 = |off: usize, val: u16| {
            (out.add(off) as *mut u16).write_unaligned(val);
        };
        let wi64 = |off: usize, val: i64| {
            (out.add(off) as *mut i64).write_unaligned(val);
        };
        w32(0, STATX_BASIC_STATS);          // stx_mask
        w32(4, mac.st_blksize as u32);      // stx_blksize
        w64(8, 0);                            // stx_attributes
        w32(16, mac.st_nlink as u32);        // stx_nlink
        w32(20, crate::creds::map_host_uid(mac.st_uid)); // stx_uid (userns view)
        w32(24, crate::creds::map_host_gid(mac.st_gid)); // stx_gid (userns view)
        w16(28, mac.st_mode as u16);         // stx_mode
        w64(32, mac.st_ino);                  // stx_ino
        w64(40, mac.st_size as u64);         // stx_size
        w64(48, mac.st_blocks as u64);       // stx_blocks
        w64(56, 0);                           // stx_attributes_mask

        // stx_atime (offset 64): tv_sec(i64) + tv_nsec(u32)
        wi64(64, mac.st_atime);
        w32(72, mac.st_atime_nsec as u32);

        // stx_btime (offset 80): macOS has st_birthtime
        wi64(80, mac.st_birthtime);
        w32(88, mac.st_birthtime_nsec as u32);

        // stx_ctime (offset 96)
        wi64(96, mac.st_ctime);
        w32(104, mac.st_ctime_nsec as u32);

        // stx_mtime (offset 112)
        wi64(112, mac.st_mtime);
        w32(120, mac.st_mtime_nsec as u32);

        // stx_rdev_major/minor (offset 128/132)
        w32(128, libc::major(mac.st_rdev as libc::dev_t) as u32);
        w32(132, libc::minor(mac.st_rdev as libc::dev_t) as u32);

        // stx_dev_major/minor (offset 136/140)
        w32(136, libc::major(mac.st_dev as libc::dev_t) as u32);
        w32(140, libc::minor(mac.st_dev as libc::dev_t) as u32);
    }
}

// ─── mmap flag translation ───────────────────────────────────────────────────
// These are also in linux.rs / syscall.rs; consolidated here for completeness.

pub fn translate_mmap_flags(linux_flags: u64) -> i32 {
    let mut mac: i32 = 0;
    if linux_flags & 0x01 != 0 { mac |= libc::MAP_SHARED; }
    if linux_flags & 0x02 != 0 { mac |= libc::MAP_PRIVATE; }
    if linux_flags & 0x10 != 0 { mac |= libc::MAP_FIXED; }
    if linux_flags & 0x20 != 0 { mac |= libc::MAP_ANON; }
    // MAP_DENYWRITE (0x0800) — Linux-only, no macOS equivalent, ignore
    // MAP_NORESERVE (0x4000) — no macOS equivalent, ignore
    // MAP_STACK (0x20000) — hint only, ignore
    // MAP_HUGETLB (0x40000) — no macOS equivalent, ignore
    mac
}

pub fn translate_mmap_prot(linux_prot: u64) -> i32 {
    let mut p: i32 = 0;
    if linux_prot & 1 != 0 { p |= libc::PROT_READ; }
    if linux_prot & 2 != 0 { p |= libc::PROT_WRITE; }
    if linux_prot & 4 != 0 { p |= libc::PROT_EXEC; }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Linux aarch64 struct flock buffer.
    fn linux_flock_buf(l_type: i16, l_whence: i16, l_start: i64, l_len: i64) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0..2].copy_from_slice(&l_type.to_le_bytes());
        buf[2..4].copy_from_slice(&l_whence.to_le_bytes());
        buf[8..16].copy_from_slice(&l_start.to_le_bytes());
        buf[16..24].copy_from_slice(&l_len.to_le_bytes());
        buf
    }

    #[test]
    fn test_flock_l_type_linux_to_mac() {
        // Linux: F_RDLCK=0, F_WRLCK=1, F_UNLCK=2
        // macOS: F_RDLCK=1, F_UNLCK=2, F_WRLCK=3
        // groupadd's lckpwdf() write-lock (Linux F_WRLCK=1) must become macOS
        // F_WRLCK=3 — passing 1 through means F_RDLCK on an O_WRONLY fd → EBADF.
        let cases: &[(i16, i16)] = &[
            (0, libc::F_RDLCK),
            (1, libc::F_WRLCK),
            (2, libc::F_UNLCK),
        ];
        for &(linux_ty, mac_ty) in cases {
            let buf = linux_flock_buf(linux_ty, 0, 0, 0);
            let mac = linux_flock_to_mac(buf.as_ptr() as u64);
            assert_eq!(mac.l_type, mac_ty,
                "Linux l_type {} must map to macOS {}", linux_ty, mac_ty);
        }
    }

    #[test]
    fn test_flock_l_type_mac_to_linux() {
        let cases: &[(i16, i16)] = &[
            (libc::F_RDLCK, 0),
            (libc::F_WRLCK, 1),
            (libc::F_UNLCK, 2),
        ];
        for &(mac_ty, linux_ty) in cases {
            let mac = libc::flock { l_start: 5, l_len: 10, l_pid: 42, l_type: mac_ty, l_whence: 0 };
            let mut buf = [0u8; 32];
            mac_flock_to_linux(&mac, buf.as_mut_ptr() as u64);
            let got = i16::from_le_bytes([buf[0], buf[1]]);
            assert_eq!(got, linux_ty,
                "macOS l_type {} must map back to Linux {}", mac_ty, linux_ty);
            assert_eq!(i64::from_le_bytes(buf[8..16].try_into().unwrap()), 5);
            assert_eq!(i64::from_le_bytes(buf[16..24].try_into().unwrap()), 10);
            assert_eq!(i32::from_le_bytes(buf[24..28].try_into().unwrap()), 42);
        }
    }

    #[test]
    fn test_tcp_sockopt_translation() {
        // curl's "GET http://..." took a flat 5s to first byte: it sets
        // Linux TCP_KEEPIDLE (IPPROTO_TCP, 4), which passed through raw —
        // but macOS (IPPROTO_TCP, 4) is TCP_NOPUSH, corking the socket.
        // The HTTP request then sat in the send buffer for macOS's ~5s
        // NOPUSH flush delay. TCP optnames diverge above TCP_MAXSEG and
        // MUST be mapped, never passed through.
        let cases: &[(i32, i32)] = &[
            (1, libc::TCP_NODELAY),    // same on both
            (2, libc::TCP_MAXSEG),     // same on both
            (3, libc::TCP_NOPUSH),     // Linux TCP_CORK ≈ macOS TCP_NOPUSH
            (4, libc::TCP_KEEPALIVE),  // Linux TCP_KEEPIDLE → macOS 0x10
            (5, libc::TCP_KEEPINTVL),  // Linux 5 → macOS 0x101
            (6, libc::TCP_KEEPCNT),    // Linux 6 → macOS 0x102
        ];
        for &(linux_opt, mac_opt) in cases {
            assert_eq!(
                translate_sockopt(6, linux_opt),
                Some((libc::IPPROTO_TCP, mac_opt)),
                "Linux TCP optname {} must map to macOS {}", linux_opt, mac_opt
            );
        }
        // Unknown TCP optnames must NOT pass through (collision danger);
        // None makes the callers return ENOPROTOOPT like a kernel would.
        assert_eq!(translate_sockopt(6, 11), None, "TCP_INFO has no macOS equivalent");
        assert_eq!(translate_sockopt(6, 18), None, "TCP_USER_TIMEOUT has no macOS equivalent");
    }

    #[test]
    fn test_flock_fields_roundtrip() {
        let buf = linux_flock_buf(1, 0, 1234, 5678);
        let mac = linux_flock_to_mac(buf.as_ptr() as u64);
        assert_eq!(mac.l_start, 1234);
        assert_eq!(mac.l_len, 5678);
        assert_eq!(mac.l_whence, 0);
    }
}
