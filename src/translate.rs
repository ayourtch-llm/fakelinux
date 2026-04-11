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
const LINUX_O_DIRECTORY: i32 = 0o200000;
const LINUX_O_NOFOLLOW: i32 = 0o400000;
const LINUX_O_CLOEXEC: i32 = 0o2000000;
const LINUX_O_LARGEFILE: i32 = 0o100000; // no-op on 64-bit

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

    // O_LARGEFILE is meaningless on 64-bit macOS; ignore it
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

pub fn translate_fcntl_cmd(linux_cmd: i32) -> Option<i32> {
    match linux_cmd {
        LINUX_F_DUPFD => Some(libc::F_DUPFD),
        LINUX_F_GETFD => Some(libc::F_GETFD),
        LINUX_F_SETFD => Some(libc::F_SETFD),
        LINUX_F_GETFL => Some(libc::F_GETFL),
        LINUX_F_SETFL => Some(libc::F_SETFL),
        _ => None,
    }
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
        w32(24, mac.st_uid);
        w32(28, mac.st_gid);
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
        w32(20, mac.st_uid);                  // stx_uid
        w32(24, mac.st_gid);                  // stx_gid
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
