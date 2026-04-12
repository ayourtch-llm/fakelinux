//! Virtual /proc filesystem.
//!
//! When the guest opens a /proc path we intercept it and serve synthetic content
//! via a pipe fd.  This avoids needing FUSE or a real mount.

use std::collections::HashMap;
use std::sync::Mutex;

/// Tracks memory mappings so we can generate /proc/self/maps.
#[derive(Clone)]
pub struct MemMapping {
    pub start: u64,
    pub end: u64,
    pub prot: i32,       // libc PROT_* combination
    pub flags: i32,      // libc MAP_* combination
    pub offset: u64,
    pub name: String,     // e.g. "[heap]", "/path/to/lib.so", "[stack]"
}

pub struct ProcFs {
    pub mappings: Vec<MemMapping>,
    pub exe_path: String,
    pub auxv: Vec<u8>,       // raw auxiliary vector bytes
    /// Virtual file descriptors: fd → remaining bytes to read.
    pub vfds: HashMap<i32, Vec<u8>>,
}

static PROCFS: Mutex<Option<ProcFs>> = Mutex::new(None);

pub fn init(exe_path: &str) {
    // Ensure exe_path is absolute (glibc asserts it starts with '/')
    let abs_path = if exe_path.starts_with('/') {
        exe_path.to_string()
    } else {
        let mut cwd = std::env::current_dir().unwrap_or_default();
        cwd.push(exe_path);
        cwd.to_string_lossy().to_string()
    };
    let mut lock = PROCFS.lock().unwrap();
    *lock = Some(ProcFs {
        mappings: Vec::new(),
        exe_path: abs_path,
        auxv: Vec::new(),
        vfds: HashMap::new(),
    });
}

pub fn with<F, R>(f: F) -> R
where
    F: FnOnce(&mut ProcFs) -> R,
{
    let mut lock = PROCFS.lock().unwrap();
    f(lock.as_mut().expect("procfs not initialized"))
}

/// Record a memory mapping.
pub fn add_mapping(m: MemMapping) {
    with(|pfs| pfs.mappings.push(m));
}

/// Store the raw auxv bytes (for /proc/self/auxv).
pub fn set_auxv(data: Vec<u8>) {
    with(|pfs| pfs.auxv = data);
}

/// Try to open a /proc virtual file.  Returns Some(fd) on success.
pub fn try_open(path: &[u8]) -> Option<i32> {
    let path_str = std::str::from_utf8(path).ok()?;

    // Handle /proc as a directory (for ps to enumerate PIDs via getdents64)
    if path_str == "/proc" {
        return try_open_proc_dir();
    }

    let content = generate_content(path_str)?;
    Some(pipe_content(&content))
}

/// Create a pipe fd containing the given content.
fn pipe_content(content: &[u8]) -> i32 {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return -1;
    }
    let read_fd = fds[0];
    let write_fd = fds[1];

    let mut written = 0usize;
    while written < content.len() {
        let n = unsafe {
            libc::write(
                write_fd,
                content[written..].as_ptr() as *const _,
                content.len() - written,
            )
        };
        if n <= 0 { break; }
        written += n as usize;
    }
    unsafe { libc::close(write_fd); }

    read_fd
}

/// Open /proc as a directory containing our PID as an entry.
/// Creates a temp directory with symlinks/dirs for each "process".
fn try_open_proc_dir() -> Option<i32> {
    let pid = unsafe { libc::getpid() };
    let dir_path = format!("/tmp/.fakelinux-proc-{}", pid);
    let c_dir = std::ffi::CString::new(dir_path.as_str()).ok()?;

    // Create the temp dir and a subdirectory for our PID
    unsafe { libc::mkdir(c_dir.as_ptr(), 0o755); }
    let pid_dir = format!("{}/{}", dir_path, pid);
    let c_pid_dir = std::ffi::CString::new(pid_dir.as_str()).ok()?;
    unsafe { libc::mkdir(c_pid_dir.as_ptr(), 0o755); }

    // Also create "self" symlink
    let self_link = format!("{}/self", dir_path);
    let c_self = std::ffi::CString::new(self_link.as_str()).ok()?;
    let c_target = std::ffi::CString::new(format!("{}", pid)).ok()?;
    unsafe { libc::symlink(c_target.as_ptr(), c_self.as_ptr()); }

    // Open as directory
    let fd = unsafe { libc::open(c_dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if fd >= 0 { Some(fd) } else { None }
}

fn generate_content(path: &str) -> Option<Vec<u8>> {
    // Normalize /proc/<pid>/... to /proc/self/... when <pid> matches our PID
    let normalized = normalize_proc_path(path);
    let path = normalized.as_deref().unwrap_or(path);

    match path {
        "/proc/self/maps" => Some(generate_maps()),
        "/proc/self/auxv" => Some(with(|pfs| pfs.auxv.clone())),
        "/proc/self/status" => Some(generate_status()),
        "/proc/self/stat" => Some(generate_stat()),
        "/proc/self/cmdline" => Some(generate_cmdline()),
        "/proc/cpuinfo" => Some(generate_cpuinfo()),
        "/proc/sys/kernel/osrelease" => Some(b"6.1.0-fakelinux\n".to_vec()),
        "/proc/self/mountinfo" => Some(generate_mountinfo()),
        "/proc/meminfo" => Some(generate_meminfo()),
        "/proc/uptime" => Some(generate_uptime()),
        "/proc/sys/kernel/pid_max" => Some(b"4194304\n".to_vec()),
        _ => {
            // /proc/self/fd/N → not a regular file open, ignore
            None
        }
    }
}

/// If path is /proc/<pid>/... where <pid> matches our PID, return /proc/self/...
fn normalize_proc_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/proc/")?;
    let slash_pos = rest.find('/')?;
    let pid_str = &rest[..slash_pos];
    let pid: i32 = pid_str.parse().ok()?;
    if pid == unsafe { libc::getpid() } {
        Some(format!("/proc/self{}", &rest[slash_pos..]))
    } else {
        None
    }
}

fn generate_maps() -> Vec<u8> {
    with(|pfs| {
        let mut out = String::new();
        for m in &pfs.mappings {
            let r = if m.prot & libc::PROT_READ != 0 { 'r' } else { '-' };
            let w = if m.prot & libc::PROT_WRITE != 0 { 'w' } else { '-' };
            let x = if m.prot & libc::PROT_EXEC != 0 { 'x' } else { '-' };
            let p = if m.flags & libc::MAP_PRIVATE != 0 { 'p' } else { 's' };
            out.push_str(&format!(
                "{:012x}-{:012x} {}{}{}{} {:08x} 00:00 0",
                m.start, m.end, r, w, x, p, m.offset
            ));
            if !m.name.is_empty() {
                // Right-align the name at column 73 (typical Linux format)
                let padding = if out.len() % 80 < 73 {
                    73 - (out.len() % 80)
                } else {
                    1
                };
                for _ in 0..padding {
                    out.push(' ');
                }
                out.push_str(&m.name);
            }
            out.push('\n');
        }
        out.into_bytes()
    })
}

fn generate_status() -> Vec<u8> {
    let pid = unsafe { libc::getpid() };
    format!(
        "Name:\tfakelinux-guest\n\
         Pid:\t{pid}\n\
         Tgid:\t{pid}\n\
         Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n\
         Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n\
         VmSize:\t    0 kB\n\
         Threads:\t1\n",
        pid = pid,
        uid = crate::creds::do_getuid(),
        gid = crate::creds::do_getgid(),
    )
    .into_bytes()
}

fn generate_stat() -> Vec<u8> {
    let pid = unsafe { libc::getpid() };
    // Minimal /proc/self/stat line (field 1 = pid, field 2 = (name), field 3 = state, ...)
    format!(
        "{pid} (fakelinux-guest) R {ppid} {pid} {pid} 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        pid = pid,
        ppid = unsafe { libc::getppid() },
    )
    .into_bytes()
}

fn generate_cmdline() -> Vec<u8> {
    // Return the exe path with a null terminator
    with(|pfs| {
        let mut v = pfs.exe_path.as_bytes().to_vec();
        v.push(0);
        v
    })
}

fn generate_cpuinfo() -> Vec<u8> {
    // Query the number of CPUs from macOS sysctl
    let ncpus = {
        let mut n: libc::c_int = 1;
        let mut len = std::mem::size_of::<libc::c_int>();
        let name = b"hw.ncpu\0";
        unsafe {
            libc::sysctlbyname(
                name.as_ptr() as *const i8,
                &mut n as *mut _ as *mut _,
                &mut len,
                std::ptr::null_mut(),
                0,
            );
        }
        n.max(1) as u32
    };

    let mut out = String::new();
    for i in 0..ncpus {
        out.push_str(&format!(
            "processor\t: {}\n\
             BogoMIPS\t: 48.00\n\
             Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics\n\
             CPU implementer\t: 0x61\n\
             CPU architecture: 8\n\
             CPU variant\t: 0x0\n\
             CPU part\t: 0xd00\n\
             CPU revision\t: 0\n\n",
            i
        ));
    }
    out.into_bytes()
}

fn generate_mountinfo() -> Vec<u8> {
    // Minimal /proc/self/mountinfo for programs that parse it
    b"1 0 0:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
      2 1 0:2 / /proc rw,relatime - proc proc rw\n\
      3 1 0:3 / /dev rw,relatime - devtmpfs devtmpfs rw\n\
      4 1 0:4 / /tmp rw,relatime - tmpfs tmpfs rw\n"
        .to_vec()
}

fn generate_meminfo() -> Vec<u8> {
    // Query memory info from macOS sysctl
    let mut memsize: u64 = 8 * 1024 * 1024 * 1024; // default 8GB
    let mut len = std::mem::size_of::<u64>();
    let name = b"hw.memsize\0";
    unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const i8,
            &mut memsize as *mut _ as *mut _,
            &mut len,
            std::ptr::null_mut(),
            0,
        );
    }

    let total_kb = memsize / 1024;
    // Estimate free/available (rough approximation)
    let free_kb = total_kb / 4;
    let available_kb = total_kb / 2;
    let buffers_kb = total_kb / 16;
    let cached_kb = total_kb / 4;

    format!(
        "MemTotal:       {} kB\n\
         MemFree:        {} kB\n\
         MemAvailable:   {} kB\n\
         Buffers:        {} kB\n\
         Cached:         {} kB\n\
         SwapTotal:      0 kB\n\
         SwapFree:       0 kB\n",
        total_kb, free_kb, available_kb, buffers_kb, cached_kb,
    )
    .into_bytes()
}

fn generate_uptime() -> Vec<u8> {
    // Use clock_gettime(CLOCK_MONOTONIC) for uptime
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts); }
    let secs = ts.tv_sec as f64 + ts.tv_nsec as f64 / 1_000_000_000.0;
    // Format: uptime_seconds idle_seconds
    format!("{:.2} {:.2}\n", secs, secs * 0.9).into_bytes()
}

/// Handle stat/fstatat on /proc paths. Returns Some(()) if handled.
/// Writes a synthetic Linux stat struct to statbuf.
pub fn try_stat(path: &[u8], statbuf: u64) -> Option<()> {
    let path_str = std::str::from_utf8(path).ok()?;

    // Normalize /proc/<pid>/... to /proc/self/...
    let normalized = normalize_proc_path(path_str);
    let check = normalized.as_deref().unwrap_or(path_str);

    // Check if this is a proc path we know about
    let is_dir = match check {
        "/proc" | "/proc/self" | "/proc/self/task" | "/proc/self/fd"
        | "/proc/self/net" => true,
        _ => false,
    };

    // Also match /proc/<our-pid> as a directory
    let is_pid_dir = if !is_dir && path_str.starts_with("/proc/") {
        let rest = &path_str[6..];
        // Check if it's just /proc/<digits> where digits = our pid
        if let Ok(pid) = rest.parse::<i32>() {
            pid == unsafe { libc::getpid() }
        } else {
            false
        }
    } else {
        false
    };

    let is_file = generate_content(path_str).is_some();

    if !is_dir && !is_pid_dir && !is_file {
        return None;
    }

    // Write a synthetic Linux aarch64 stat struct (128 bytes)
    let buf = statbuf as *mut u8;
    unsafe { std::ptr::write_bytes(buf, 0, 128); }

    let pid = unsafe { libc::getpid() } as u64;
    let mode: u32 = if is_dir || is_pid_dir {
        0o40555 // S_IFDIR | r-xr-xr-x
    } else {
        0o100444 // S_IFREG | r--r--r--
    };

    // Linux aarch64 struct stat layout:
    //   offset  0: u64 st_dev
    //   offset  8: u64 st_ino
    //   offset 16: u32 st_mode
    //   offset 20: u32 st_nlink
    //   offset 24: u32 st_uid
    //   offset 28: u32 st_gid
    unsafe {
        // st_dev = 0 (proc has no real device)
        // st_ino = pid-based fake inode
        let ino = pid.wrapping_mul(1000).wrapping_add(1);
        std::ptr::copy_nonoverlapping(&ino as *const u64 as *const u8, buf.add(8), 8);
        std::ptr::copy_nonoverlapping(&mode as *const u32 as *const u8, buf.add(16), 4);
        let nlink: u32 = if is_dir || is_pid_dir { 2 } else { 1 };
        std::ptr::copy_nonoverlapping(&nlink as *const u32 as *const u8, buf.add(20), 4);
    }

    Some(())
}

/// Handle readlink on /proc paths.
pub fn try_readlink(path: &[u8], buf: u64, bufsiz: u64) -> Option<u64> {
    let path_str = std::str::from_utf8(path).ok()?;

    // Normalize /proc/<pid>/... to /proc/self/...
    let normalized = normalize_proc_path(path_str);
    let path_str = normalized.as_deref().unwrap_or(path_str);

    if path_str == "/proc/self/exe" {
        return with(|pfs| {
            let p = pfs.exe_path.as_bytes();
            let len = p.len().min(bufsiz as usize);
            unsafe {
                std::ptr::copy_nonoverlapping(p.as_ptr(), buf as *mut u8, len);
            }
            Some(len as u64)
        });
    }

    // /proc/self/fd/N → readlink returns the path of fd N
    if let Some(fd_str) = path_str.strip_prefix("/proc/self/fd/") {
        if let Ok(fd) = fd_str.parse::<i32>() {
            let mut pathbuf = [0u8; 1024];
            let ret = unsafe {
                libc::fcntl(fd, libc::F_GETPATH, pathbuf.as_mut_ptr())
            };
            if ret == 0 {
                let len = pathbuf.iter().position(|&b| b == 0).unwrap_or(pathbuf.len());
                let copy_len = len.min(bufsiz as usize);
                unsafe {
                    std::ptr::copy_nonoverlapping(pathbuf.as_ptr(), buf as *mut u8, copy_len);
                }
                return Some(copy_len as u64);
            }
        }
    }

    None
}
