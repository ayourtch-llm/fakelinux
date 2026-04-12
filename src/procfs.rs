//! Virtual /proc filesystem.
//!
//! Regular /proc files are served via pipe fds (write content, close write end,
//! return read end). Directory listing is handled via virtual fds that generate
//! synthetic getdents64 entries.

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

// ─── Virtual directory fd tracking ───────────────────────────────────────────

/// What kind of virtual directory a fd represents.
#[derive(Clone)]
enum VirtualDir {
    /// /proc root — entries are PIDs, "self", pseudo-files
    ProcRoot,
    /// /proc/<pid> or /proc/self — entries are stat, status, cmdline, etc.
    ProcPid(i32), // the vpid (or 0 for "self" = current process)
}

/// State for an open virtual directory fd. Entries are pre-generated and
/// consumed by successive getdents64 calls.
struct VirtualDirState {
    kind: VirtualDir,
    /// Pre-serialized dirent64 entries, consumed from front.
    buf: Vec<u8>,
    /// How many bytes have been consumed so far.
    pos: usize,
}

/// Map of fd → virtual directory state. Protected by mutex.
/// We use real pipe fds as markers (guest holds a real fd that won't collide
/// with other fds), but getdents64/close are intercepted.
static VIRTUAL_DIRS: Mutex<Option<HashMap<i32, VirtualDirState>>> = Mutex::new(None);

fn vdir_map() -> &'static Mutex<Option<HashMap<i32, VirtualDirState>>> {
    &VIRTUAL_DIRS
}

/// Allocate a real fd (via pipe) to use as a virtual directory marker.
/// The fd is valid from the OS perspective but we intercept reads/getdents on it.
fn alloc_virtual_fd() -> Option<i32> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return None;
    }
    // Close write end immediately; we only need the read fd as a marker
    unsafe { libc::close(fds[1]); }
    Some(fds[0])
}

/// Register a virtual directory fd.
fn register_virtual_dir(fd: i32, kind: VirtualDir) {
    let buf = generate_dir_entries(&kind);
    let mut lock = vdir_map().lock().unwrap();
    let map = lock.get_or_insert_with(HashMap::new);
    map.insert(fd, VirtualDirState { kind, buf, pos: 0 });
}

/// Check if fd is a virtual directory and handle getdents64.
/// Returns Some(bytes_written) if handled, None if not a virtual fd.
pub fn try_getdents64(fd: i32, buf: u64, bufsize: u64) -> Option<u64> {
    let mut lock = vdir_map().lock().unwrap();
    let map = lock.as_mut()?;
    let state = map.get_mut(&fd)?;

    let remaining = &state.buf[state.pos..];
    if remaining.is_empty() {
        return Some(0); // EOF
    }

    // Copy as many complete entries as fit in bufsize
    let mut copied = 0usize;
    let mut scan = 0usize;
    while scan < remaining.len() {
        if scan + 18 > remaining.len() { break; }
        let reclen = unsafe {
            (remaining[scan + 16..].as_ptr() as *const u16).read_unaligned()
        } as usize;
        if reclen == 0 { break; }
        if copied + reclen > bufsize as usize { break; }
        copied += reclen;
        scan += reclen;
    }

    if copied > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(
                remaining.as_ptr(),
                buf as *mut u8,
                copied,
            );
        }
        state.pos += copied;
    }

    Some(copied as u64)
}

/// Clean up virtual directory state on close. Returns true if fd was virtual.
pub fn on_close(fd: i32) -> bool {
    let mut lock = vdir_map().lock().unwrap();
    if let Some(map) = lock.as_mut() {
        return map.remove(&fd).is_some();
    }
    false
}

/// Check if an fd is a virtual directory (for fstat interception).
pub fn is_virtual_dir(fd: i32) -> bool {
    let lock = vdir_map().lock().unwrap();
    if let Some(map) = lock.as_ref() {
        return map.contains_key(&fd);
    }
    false
}

// ─── Directory entry generation ──────────────────────────────────────────────

/// DT_* constants for d_type field
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;

/// Build a single Linux dirent64 entry and append it to buf.
fn push_dirent64(buf: &mut Vec<u8>, ino: u64, d_type: u8, name: &[u8]) {
    // struct linux_dirent64: d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + name + null
    let reclen = (19 + name.len() + 1 + 7) & !7; // 8-byte aligned
    let start = buf.len();
    buf.resize(start + reclen, 0);
    let out = &mut buf[start..];

    // d_ino
    out[0..8].copy_from_slice(&ino.to_ne_bytes());
    // d_off: set to cumulative offset (end of this entry)
    let d_off = (start + reclen) as i64;
    out[8..16].copy_from_slice(&d_off.to_ne_bytes());
    // d_reclen
    out[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
    // d_type
    out[18] = d_type;
    // d_name (null-terminated, rest already zeroed)
    out[19..19 + name.len()].copy_from_slice(name);
}

/// Generate all dirent64 entries for a virtual directory.
fn generate_dir_entries(kind: &VirtualDir) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4096);

    match kind {
        VirtualDir::ProcRoot => {
            push_dirent64(&mut buf, 1, DT_DIR, b".");
            push_dirent64(&mut buf, 1, DT_DIR, b"..");

            // Active PID entries
            let active = crate::pidns::list_active_pids();
            if active.is_empty() {
                // Non-container mode: just our own PID
                let pid_str = format!("{}", visible_pid());
                push_dirent64(&mut buf, 100, DT_DIR, pid_str.as_bytes());
            } else {
                for &(vpid, _) in &active {
                    let pid_str = format!("{}", vpid);
                    push_dirent64(&mut buf, 100 + vpid as u64, DT_DIR, pid_str.as_bytes());
                }
            }

            // "self" symlink
            push_dirent64(&mut buf, 2, DT_LNK, b"self");

            // Pseudo-files in /proc root
            for name in &[b"cpuinfo" as &[u8], b"meminfo", b"stat", b"uptime", b"mountinfo"] {
                push_dirent64(&mut buf, 50, DT_REG, name);
            }
            // Directories in /proc root
            push_dirent64(&mut buf, 60, DT_DIR, b"sys");
        }
        VirtualDir::ProcPid(_vpid) => {
            push_dirent64(&mut buf, 200, DT_DIR, b".");
            push_dirent64(&mut buf, 1, DT_DIR, b"..");

            // Standard /proc/<pid> entries
            for name in &[b"stat" as &[u8], b"status", b"cmdline", b"maps", b"mountinfo", b"auxv"] {
                push_dirent64(&mut buf, 201, DT_REG, name);
            }
            // Symlinks
            push_dirent64(&mut buf, 202, DT_LNK, b"exe");
            // Subdirectories
            for name in &[b"fd" as &[u8], b"task", b"net"] {
                push_dirent64(&mut buf, 203, DT_DIR, name);
            }
        }
    }

    buf
}

// ─── Public open/stat/readlink API ───────────────────────────────────────────

/// Try to open a /proc virtual file or directory. Returns Some(fd) on success.
pub fn try_open(path: &[u8]) -> Option<i32> {
    let path_str = std::str::from_utf8(path).ok()?;
    let path_clean = path_str.trim_end_matches('/');

    // Check for directory opens first
    if let Some(vdir) = classify_dir_path(path_clean) {
        let fd = alloc_virtual_fd()?;
        register_virtual_dir(fd, vdir);
        return Some(fd);
    }

    // Regular file content
    let content = generate_content(path_str)?;
    Some(pipe_content(&content))
}

/// Classify a path as a virtual directory, if it is one.
fn classify_dir_path(path: &str) -> Option<VirtualDir> {
    // Strip trailing slashes for matching
    let path = path.trim_end_matches('/');

    if path == "/proc" {
        return Some(VirtualDir::ProcRoot);
    }

    // /proc/self or /proc/<our-pid> or /proc/<our-vpid>
    if path == "/proc/self" {
        return Some(VirtualDir::ProcPid(visible_pid()));
    }

    // /proc/<number>
    if let Some(rest) = path.strip_prefix("/proc/") {
        // Must be just digits, no further slashes
        if !rest.contains('/') {
            if let Ok(pid) = rest.parse::<i32>() {
                let real_pid = unsafe { libc::getpid() };
                if pid == real_pid || pid == visible_pid() {
                    return Some(VirtualDir::ProcPid(pid));
                }
                // In container mode, check if it's another active process
                if crate::pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
                    if crate::pidns::virtual_to_real(pid).is_some() {
                        return Some(VirtualDir::ProcPid(pid));
                    }
                }
            }
        }
    }

    None
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
        "/proc/stat" => Some(generate_proc_stat()),
        "/proc/sys/kernel/pid_max" => Some(b"4194304\n".to_vec()),
        _ => {
            // Check if this is /proc/<vpid>/stat or /proc/<vpid>/status for
            // another process in the container
            if let Some(content) = generate_for_other_pid(path) {
                return Some(content);
            }
            None
        }
    }
}

/// Generate /proc/<vpid>/stat or /proc/<vpid>/status for a container process
/// that isn't the current process.
fn generate_for_other_pid(path: &str) -> Option<Vec<u8>> {
    if !crate::pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    let rest = path.strip_prefix("/proc/")?;
    let slash_pos = rest.find('/')?;
    let pid_str = &rest[..slash_pos];
    let vpid: i32 = pid_str.parse().ok()?;
    let subpath = &rest[slash_pos..];

    // Verify this vpid is active in the container
    let _real_pid = crate::pidns::virtual_to_real(vpid)?;

    let vppid = if vpid == 1 { 0 } else { 1 };

    match subpath {
        "/stat" => {
            Some(format!(
                "{vpid} (fakelinux-guest) S {vppid} {vpid} {vpid} 0 -1 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 -1 0 0 0 0 0 0 2147483647 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
                vpid = vpid,
                vppid = vppid,
            ).into_bytes())
        }
        "/status" => {
            Some(format!(
                "Name:\tfakelinux-guest\n\
                 Pid:\t{vpid}\n\
                 Tgid:\t{vpid}\n\
                 PPid:\t{vppid}\n\
                 Uid:\t0\t0\t0\t0\n\
                 Gid:\t0\t0\t0\t0\n\
                 VmSize:\t    0 kB\n\
                 Threads:\t1\n",
                vpid = vpid,
                vppid = vppid,
            ).into_bytes())
        }
        "/cmdline" => {
            Some(b"fakelinux-guest\0".to_vec())
        }
        _ => None,
    }
}

/// If path is /proc/<pid>/... where <pid> matches our PID (real or virtual),
/// return /proc/self/...
fn normalize_proc_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/proc/")?;
    let slash_pos = rest.find('/')?;
    let pid_str = &rest[..slash_pos];
    let pid: i32 = pid_str.parse().ok()?;
    let real_pid = unsafe { libc::getpid() };

    let is_self = if pid == real_pid {
        true
    } else if crate::pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        crate::pidns::current_vpid() == pid
    } else {
        false
    };

    if is_self {
        Some(format!("/proc/self{}", &rest[slash_pos..]))
    } else {
        None
    }
}

/// Get the PID to use in /proc output (virtual if container mode, real otherwise).
fn visible_pid() -> i32 {
    if crate::pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        crate::pidns::current_vpid()
    } else {
        unsafe { libc::getpid() }
    }
}

/// Get the PPID to use in /proc output.
fn visible_ppid() -> i32 {
    if crate::pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        crate::pidns::current_vppid()
    } else {
        unsafe { libc::getppid() }
    }
}

// ─── /proc file generators ──────────────────────────────────────────────────

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
    let pid = visible_pid();
    format!(
        "Name:\tfakelinux-guest\n\
         Pid:\t{pid}\n\
         Tgid:\t{pid}\n\
         PPid:\t{ppid}\n\
         Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n\
         Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n\
         VmSize:\t    0 kB\n\
         Threads:\t1\n",
        pid = pid,
        ppid = visible_ppid(),
        uid = crate::creds::do_getuid(),
        gid = crate::creds::do_getgid(),
    )
    .into_bytes()
}

fn generate_stat() -> Vec<u8> {
    let pid = visible_pid();
    let ppid = visible_ppid();
    // /proc/self/stat: 52 fields required by procps/libproc2
    format!(
        "{pid} (fakelinux-guest) R {ppid} {pid} {pid} 0 -1 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 -1 0 0 0 0 0 0 2147483647 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        pid = pid,
        ppid = ppid,
    )
    .into_bytes()
}

fn generate_cmdline() -> Vec<u8> {
    with(|pfs| {
        let mut v = pfs.exe_path.as_bytes().to_vec();
        v.push(0);
        v
    })
}

fn generate_cpuinfo() -> Vec<u8> {
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
    b"1 0 0:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
      2 1 0:2 / /proc rw,relatime - proc proc rw\n\
      3 1 0:3 / /dev rw,relatime - devtmpfs devtmpfs rw\n\
      4 1 0:4 / /tmp rw,relatime - tmpfs tmpfs rw\n"
        .to_vec()
}

fn generate_meminfo() -> Vec<u8> {
    let mut memsize: u64 = 8 * 1024 * 1024 * 1024;
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
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts); }
    let secs = ts.tv_sec as f64 + ts.tv_nsec as f64 / 1_000_000_000.0;
    format!("{:.2} {:.2}\n", secs, secs * 0.9).into_bytes()
}

fn generate_proc_stat() -> Vec<u8> {
    let mut real_ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let mut mono_ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut real_ts);
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono_ts);
    }
    let btime = real_ts.tv_sec - mono_ts.tv_sec;
    format!(
        "cpu  0 0 0 0 0 0 0 0 0 0\n\
         btime {}\n\
         processes 1\n",
        btime,
    )
    .into_bytes()
}

// ─── stat / readlink ─────────────────────────────────────────────────────────

/// Handle stat/fstatat on /proc paths. Returns Some(()) if handled.
/// Writes a synthetic Linux stat struct to statbuf.
pub fn try_stat(path: &[u8], statbuf: u64) -> Option<()> {
    let raw = std::str::from_utf8(path).ok()?;
    let path_str = raw.trim_end_matches('/');

    // Normalize /proc/<pid>/... to /proc/self/...
    let normalized = normalize_proc_path(path_str);
    let check = normalized.as_deref().unwrap_or(path_str);

    // Check if this is a proc directory we know about
    let is_dir = classify_dir_path(path_str).is_some()
        || matches!(check,
            "/proc/self/task" | "/proc/self/fd" | "/proc/self/net"
        );

    let is_file = !is_dir && generate_content(path_str).is_some();

    if !is_dir && !is_file {
        return None;
    }

    // Write a synthetic Linux aarch64 stat struct (128 bytes)
    let buf = statbuf as *mut u8;
    unsafe { std::ptr::write_bytes(buf, 0, 128); }

    let pid = unsafe { libc::getpid() } as u64;
    let mode: u32 = if is_dir {
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
        let ino = pid.wrapping_mul(1000).wrapping_add(1);
        std::ptr::copy_nonoverlapping(&ino as *const u64 as *const u8, buf.add(8), 8);
        std::ptr::copy_nonoverlapping(&mode as *const u32 as *const u8, buf.add(16), 4);
        let nlink: u32 = if is_dir { 2 } else { 1 };
        std::ptr::copy_nonoverlapping(&nlink as *const u32 as *const u8, buf.add(20), 4);
    }

    Some(())
}

/// Handle statx on /proc paths. Returns Some(()) if handled.
pub fn try_statx(path: &[u8], statxbuf: u64) -> Option<()> {
    let raw = std::str::from_utf8(path).ok()?;
    let path_str = raw.trim_end_matches('/');

    let normalized = normalize_proc_path(path_str);
    let check = normalized.as_deref().unwrap_or(path_str);

    let is_dir = classify_dir_path(path_str).is_some()
        || matches!(check,
            "/proc/self/task" | "/proc/self/fd" | "/proc/self/net"
        );

    let is_file = !is_dir && generate_content(path_str).is_some();

    if !is_dir && !is_file {
        return None;
    }

    let mode: u16 = if is_dir { 0o40555 } else { 0o100444 };
    write_statx_common(statxbuf, mode);
    Some(())
}

/// Write a statx struct for a directory.
pub fn write_statx_dir(statxbuf: u64) -> u64 {
    write_statx_common(statxbuf, 0o40555);
    0
}

fn write_statx_common(statxbuf: u64, mode: u16) {
    let out = statxbuf as *mut u8;
    unsafe {
        std::ptr::write_bytes(out, 0, 256); // LINUX_STATX_SIZE
        // stx_mask (offset 0): STATX_BASIC_STATS = 0x7ff
        (out as *mut u32).write_unaligned(0x7ff);
        // stx_blksize (offset 4)
        (out.add(4) as *mut u32).write_unaligned(4096);
        // stx_nlink (offset 16)
        let nlink: u32 = if mode & 0o170000 == 0o040000 { 2 } else { 1 };
        (out.add(16) as *mut u32).write_unaligned(nlink);
        // stx_mode (offset 28)
        (out.add(28) as *mut u16).write_unaligned(mode);
        // stx_ino (offset 32)
        (out.add(32) as *mut u64).write_unaligned(1);
    }
}

/// Handle fstat on a virtual directory fd.
pub fn try_fstat_virtual(fd: i32, statbuf: u64) -> Option<()> {
    if !is_virtual_dir(fd) {
        return None;
    }
    let buf = statbuf as *mut u8;
    unsafe { std::ptr::write_bytes(buf, 0, 128); }
    let mode: u32 = 0o40555; // S_IFDIR
    let ino: u64 = 1;
    let nlink: u32 = 2;
    unsafe {
        std::ptr::copy_nonoverlapping(&ino as *const u64 as *const u8, buf.add(8), 8);
        std::ptr::copy_nonoverlapping(&mode as *const u32 as *const u8, buf.add(16), 4);
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
