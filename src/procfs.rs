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

    let content = generate_content(path_str)?;

    // Create a pipe; write content to write-end, close it, return read-end.
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return None;
    }
    let read_fd = fds[0];
    let write_fd = fds[1];

    // Write content
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

    Some(read_fd)
}

fn generate_content(path: &str) -> Option<Vec<u8>> {
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
        _ => {
            // /proc/self/fd/N → not a regular file open, ignore
            None
        }
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
        uid = unsafe { libc::getuid() },
        gid = unsafe { libc::getgid() },
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

/// Handle readlink on /proc paths.
pub fn try_readlink(path: &[u8], buf: u64, bufsiz: u64) -> Option<u64> {
    let path_str = std::str::from_utf8(path).ok()?;

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
