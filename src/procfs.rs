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

/// Compute the guest-visible /proc/self/exe path: absolutize against cwd,
/// then strip the rootfs prefix. The strip must happen AFTER absolutizing —
/// a relative launch path ("ubuntu-rootfs/root/.../vpp") doesn't match the
/// (absolute) root prefix, so stripping first leaks the HOST path into
/// /proc/self/exe. VPP derives its plugin directory from that readlink and
/// double-roots it → "Plugin path is: /Users/..." with zero plugins loaded.
fn guest_exe_path(exe_path: &str, cwd: &str, root: Option<&str>) -> String {
    let abs_path = if exe_path.starts_with('/') {
        exe_path.to_string()
    } else if exe_path.is_empty() {
        cwd.to_string()
    } else {
        format!("{}/{}", cwd.trim_end_matches('/'), exe_path)
    };
    if let Some(root) = root {
        let root = root.trim_end_matches('/');
        if !root.is_empty() {
            if let Some(rest) = abs_path.strip_prefix(root) {
                if rest.starts_with('/') {
                    return rest.to_string();
                }
                if rest.is_empty() {
                    return "/".to_string();
                }
            }
        }
    }
    abs_path
}

pub fn init(exe_path: &str) {
    // Ensure exe_path is absolute (glibc asserts it starts with '/'),
    // and guest-relative (host rootfs prefix stripped).
    let cwd = std::env::current_dir().unwrap_or_default();
    let abs_path = guest_exe_path(exe_path, &cwd.to_string_lossy(), crate::rootfs::get_root());
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

/// Look up a guest virtual address in the tracked mappings. Returns the
/// mapping's name and the file offset (addr - start + mapping.offset) so a
/// backtrace lr can be fed to addr2line on the named binary. Used by the
/// guest-abort backtrace (signal::do_tgkill).
pub fn lookup_addr(addr: u64) -> Option<(String, u64)> {
    with(|pfs| {
        for m in pfs.mappings.iter() {
            if addr >= m.start && addr < m.end && !m.name.is_empty() {
                return Some((m.name.clone(), addr - m.start + m.offset));
            }
        }
        None
    })
}

/// Signal-context-safe variant of lookup_addr: uses try_lock so it can never
/// deadlock if the interrupted thread held the PROCFS lock. Copies the name
/// into a caller-provided buffer and returns (name_len, file_offset). Returns
/// None if the lock is contended or the address isn't in a named mapping.
pub fn lookup_addr_sigsafe(addr: u64, name_out: &mut [u8]) -> Option<(usize, u64)> {
    let lock = PROCFS.try_lock().ok()?;
    let pfs = lock.as_ref()?;
    for m in pfs.mappings.iter() {
        if addr >= m.start && addr < m.end && !m.name.is_empty() {
            let bytes = m.name.as_bytes();
            let n = bytes.len().min(name_out.len());
            name_out[..n].copy_from_slice(&bytes[..n]);
            return Some((n, addr - m.start + m.offset));
        }
    }
    None
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
    /// /proc/<pid>/fd or /proc/self/fd — one numeric symlink per open fd.
    /// Used by psutil.num_fds()/lsof-style fd-leak checks (VPP-1486 stats test).
    ProcPidFd(i32),
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

/// Clean up virtual directory/file state on close. Returns true if fd was virtual.
pub fn on_close(fd: i32) -> bool {
    let mut hit = false;
    {
        let mut lock = vdir_map().lock().unwrap();
        if let Some(map) = lock.as_mut() {
            hit |= map.remove(&fd).is_some();
        }
    }
    {
        let mut lock = vfile_map().lock().unwrap();
        if let Some(map) = lock.as_mut() {
            hit |= map.remove(&fd).is_some();
        }
    }
    hit
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

            // PID entries: all live guest processes (host processes running
            // this same fakelinux binary). Makes top/ps see the container.
            for vpid in list_guest_vpids() {
                let pid_str = format!("{}", vpid);
                push_dirent64(&mut buf, 100 + vpid as u64, DT_DIR, pid_str.as_bytes());
            }

            // "self" symlink
            push_dirent64(&mut buf, 2, DT_LNK, b"self");

            // Pseudo-files in /proc root
            for name in &[b"cpuinfo" as &[u8], b"meminfo", b"stat", b"uptime", b"mountinfo", b"loadavg"] {
                push_dirent64(&mut buf, 50, DT_REG, name);
            }
            // Directories in /proc root
            push_dirent64(&mut buf, 60, DT_DIR, b"sys");
        }
        VirtualDir::ProcPid(_vpid) => {
            push_dirent64(&mut buf, 200, DT_DIR, b".");
            push_dirent64(&mut buf, 1, DT_DIR, b"..");

            // Standard /proc/<pid> entries
            for name in &[b"stat" as &[u8], b"statm", b"status", b"cmdline", b"maps", b"mountinfo", b"auxv"] {
                push_dirent64(&mut buf, 201, DT_REG, name);
            }
            // Symlinks
            push_dirent64(&mut buf, 202, DT_LNK, b"exe");
            // Subdirectories
            for name in &[b"fd" as &[u8], b"task", b"net"] {
                push_dirent64(&mut buf, 203, DT_DIR, name);
            }
        }
        VirtualDir::ProcPidFd(_vpid) => {
            push_dirent64(&mut buf, 300, DT_DIR, b".");
            push_dirent64(&mut buf, 1, DT_DIR, b"..");
            // One numeric symlink per currently-open fd. We can only see our
            // own process's fds (fakelinux shares the guest's fd table), so we
            // enumerate via fcntl(F_GETFD); a /proc/<other-pid>/fd would need
            // cross-process introspection we don't have, but the fd-leak tests
            // (psutil.num_fds on self) only ever read their own. The absolute
            // count includes a few fakelinux-internal fds, but those are
            // stable, so leak checks (initial == ending) still hold.
            let open_max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
            let open_max = if open_max > 0 { (open_max as i32).min(65536) } else { 1024 };
            for fd in 0..open_max {
                if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
                    let name = format!("{}", fd);
                    push_dirent64(&mut buf, 1000 + fd as u64, DT_LNK, name.as_bytes());
                }
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

    // Regular file content — served from a tracked virtual fd, NOT a
    // one-shot pipe: libproc2 (top) keeps /proc/stat open and re-reads it
    // with fflush+rewind+fread every refresh. A drained pipe gave it an
    // empty buffer → ERANGE ("library failed cpu statistics"). lseek(0) on
    // a virtual file fd REGENERATES the content, so top's deltas refresh.
    let content = generate_content(path_str)?;
    let fd = alloc_virtual_fd()?;
    let mut lock = vfile_map().lock().unwrap();
    let map = lock.get_or_insert_with(HashMap::new);
    map.insert(fd, VirtualFileState { path: path_str.to_string(), content, pos: 0 });
    Some(fd)
}

/// State for an open virtual /proc file fd.
struct VirtualFileState {
    path: String,
    content: Vec<u8>,
    pos: usize,
}

static VIRTUAL_FILES: Mutex<Option<HashMap<i32, VirtualFileState>>> = Mutex::new(None);

fn vfile_map() -> &'static Mutex<Option<HashMap<i32, VirtualFileState>>> {
    &VIRTUAL_FILES
}

/// Serve read() on a virtual /proc file fd. Returns Some(bytes) if handled.
pub fn try_read(fd: i32, buf: u64, count: u64) -> Option<u64> {
    let mut lock = vfile_map().lock().unwrap();
    let map = lock.as_mut()?;
    let st = map.get_mut(&fd)?;
    let remaining = st.content.len().saturating_sub(st.pos);
    let n = remaining.min(count as usize);
    if n > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(st.content[st.pos..].as_ptr(), buf as *mut u8, n);
        }
        st.pos += n;
    }
    Some(n as u64)
}

/// Serve lseek() on a virtual /proc file fd. Seeking to the START
/// regenerates the content (fresh CPU ticks etc. — real /proc semantics for
/// the reread-with-rewind pattern). Returns Some(new_pos) if handled.
pub fn try_lseek(fd: i32, offset: i64, whence: i32) -> Option<u64> {
    let mut lock = vfile_map().lock().unwrap();
    let map = lock.as_mut()?;
    let st = map.get_mut(&fd)?;
    let new_pos = match whence {
        libc::SEEK_SET => offset,
        libc::SEEK_CUR => st.pos as i64 + offset,
        libc::SEEK_END => st.content.len() as i64 + offset,
        _ => return Some((-22_i64) as u64), // -EINVAL
    };
    if new_pos < 0 {
        return Some((-22_i64) as u64); // -EINVAL
    }
    if new_pos == 0 {
        if let Some(fresh) = generate_content(&st.path) {
            st.content = fresh;
        }
    }
    st.pos = new_pos as usize;
    Some(new_pos as u64)
}

/// True if fd is a virtual /proc FILE fd.
pub fn is_virtual_file(fd: i32) -> bool {
    let lock = vfile_map().lock().unwrap();
    lock.as_ref().map_or(false, |m| m.contains_key(&fd))
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
    // /proc/self/fd — the open-fd directory (psutil.num_fds, fd-leak checks).
    if path == "/proc/self/fd" {
        return Some(VirtualDir::ProcPidFd(visible_pid()));
    }

    // /proc/<number> and /proc/<number>/fd
    if let Some(rest) = path.strip_prefix("/proc/") {
        // Accept "<pid>" or "<pid>/fd"; anything else is not ours.
        let (pid_part, is_fd) = match rest.strip_suffix("/fd") {
            Some(p) => (p, true),
            None => (rest, false),
        };
        if !pid_part.contains('/') {
            if let Ok(pid) = pid_part.parse::<i32>() {
                let real_pid = unsafe { libc::getpid() };
                let ours = pid == real_pid || pid == visible_pid();
                let other = crate::pidns::CONTAINER_MODE.load(std::sync::atomic::Ordering::Relaxed)
                    && crate::pidns::virtual_to_real(pid).is_some();
                if ours || other {
                    return Some(if is_fd {
                        VirtualDir::ProcPidFd(pid)
                    } else {
                        VirtualDir::ProcPid(pid)
                    });
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

/// /proc/net/dev — per-interface counters. We have no real netdevs under
/// emulation, so expose just the loopback with zero counters. The two header
/// lines are the fixed Linux format.
fn generate_net_dev() -> Vec<u8> {
    let mut s = String::new();
    s.push_str("Inter-|   Receive                                                |  Transmit\n");
    s.push_str(" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n");
    s.push_str("    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n");
    s.into_bytes()
}

/// /proc/net/route — IPv4 routing table. Header line only (empty table).
fn generate_net_route() -> Vec<u8> {
    b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n".to_vec()
}

fn generate_content(path: &str) -> Option<Vec<u8>> {
    // Normalize /proc/<pid>/... to /proc/self/... when <pid> matches our PID
    let normalized = normalize_proc_path(path);
    let path = normalized.as_deref().unwrap_or(path);

    // Collapse /proc/self/task/<tid>/<file> → /proc/self/<file>. Per-thread
    // proc files mirror the process-level ones for our purposes (mountinfo is
    // mount-namespace-wide; stat/status/maps for the main thread match the
    // process). podman's container setup opens /proc/self/task/<tid>/mountinfo.
    let collapsed = collapse_task_path(path);
    let path = collapsed.as_deref().unwrap_or(path);

    match path {
        "/proc/self/maps" => Some(generate_maps()),
        "/proc/self/auxv" => Some(with(|pfs| pfs.auxv.clone())),
        "/proc/self/status" => Some(generate_status()),
        "/proc/self/stat" => Some(generate_stat()),
        "/proc/self/statm" => {
            let s = host_proc_stats(unsafe { libc::getpid() });
            Some(format!("{rss} {rss} 0 0 0 0 0\n", rss = s.rss_pages).into_bytes())
        }
        "/proc/self/cmdline" => Some(generate_cmdline()),
        "/proc/cpuinfo" => Some(generate_cpuinfo()),
        "/proc/sys/kernel/osrelease" => Some(b"6.1.0-fakelinux\n".to_vec()),
        "/proc/self/mountinfo" => Some(generate_mountinfo()),
        "/proc/meminfo" => Some(generate_meminfo()),
        "/proc/uptime" => Some(generate_uptime()),
        "/proc/stat" => Some(generate_proc_stat()),
        "/proc/loadavg" => Some(generate_loadavg()),
        "/proc/sys/kernel/pid_max" => Some(b"4194304\n".to_vec()),
        // Default Linux core dump pattern. VPP's test framework reads this to
        // locate core files after a crash (test/util.py get_core_pattern).
        "/proc/sys/kernel/core_pattern" => Some(b"core\n".to_vec()),
        "/proc/sys/kernel/core_uses_pid" => Some(b"0\n".to_vec()),
        // Minimal but valid network tables. Tools (VPP's test framework, scapy)
        // read these to enumerate interfaces / routes; we expose a loopback and
        // an empty routing table so they don't choke (we have no real netdevs).
        "/proc/net/dev" => Some(generate_net_dev()),
        "/proc/net/route" => Some(generate_net_route()),
        _ if path.starts_with("/sys/") => sysfs_content(path, host_ncpus()),
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
            let s = host_proc_stats(_real_pid);
            Some(format!(
                "{vpid} ({comm}) S {vppid} {vpid} {vpid} 0 -1 0 0 0 0 0 {utime} {stime} 0 0 20 0 1 0 {start} 0 {rss} 2147483647 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
                vpid = vpid, vppid = vppid, comm = s.comm,
                utime = s.utime, stime = s.stime,
                start = s.starttime, rss = s.rss_pages,
            ).into_bytes())
        }
        "/statm" => {
            let s = host_proc_stats(_real_pid);
            Some(format!("{rss} {rss} 0 0 0 0 0\n", rss = s.rss_pages).into_bytes())
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
/// Rewrite /proc/self/task/<tid>/<rest> → /proc/self/<rest>. Returns None if
/// the path isn't a per-task path.
fn collapse_task_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/proc/self/task/")?;
    let slash = rest.find('/')?;
    // rest[..slash] is the tid (all digits); rest[slash+1..] is the file.
    if rest[..slash].is_empty() || !rest[..slash].bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(format!("/proc/self/{}", &rest[slash + 1..]))
}

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

/// Public wrapper for [`generate_maps`] so other modules (e.g. trap.rs's
/// FAKELINUX_TRACE_X18_STORES tracer) can snapshot the current memory map.
pub fn snapshot_maps() -> Vec<u8> {
    generate_maps()
}

fn generate_maps() -> Vec<u8> {
    with(|pfs| {
        let mut out = String::new();
        // Real /proc/self/maps is sorted by address; guests rely on it (VPP's
        // VA-bits sniffer takes the END of the LAST line).
        let mut sorted: Vec<&MemMapping> = pfs.mappings.iter().collect();
        sorted.sort_by_key(|m| m.start);
        for m in sorted {
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
    let s = host_proc_stats(unsafe { libc::getpid() });
    // /proc/self/stat: 52 fields required by procps/libproc2
    format!(
        "{pid} ({comm}) R {ppid} {pid} {pid} 0 -1 0 0 0 0 0 {utime} {stime} 0 0 20 0 1 0 {start} 0 {rss} 2147483647 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        comm = s.comm, utime = s.utime, stime = s.stime,
        start = s.starttime, rss = s.rss_pages,
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

fn host_ncpus() -> u32 {
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
}

/// Virtual sysfs CPU/NUMA topology: one node (node0) holding all host cpus.
/// VPP's vlib_thread_init reads these via clib_sysfs_read_bitmap at startup;
/// without them it sees 0 online cpus and dies with "skip-core value greater
/// or equal to available cpus". Pure function of (path, ncpus) for testing.
fn sysfs_content(path: &str, ncpus: u32) -> Option<Vec<u8>> {
    let cpu_range = || {
        if ncpus == 1 { b"0\n".to_vec() } else { format!("0-{}\n", ncpus - 1).into_bytes() }
    };
    match path {
        "/sys/devices/system/cpu/online"
        | "/sys/devices/system/cpu/possible"
        | "/sys/devices/system/cpu/present" => Some(cpu_range()),
        "/sys/devices/system/node/online"
        | "/sys/devices/system/node/has_memory"
        | "/sys/devices/system/node/has_cpu" => Some(b"0\n".to_vec()),
        "/sys/devices/system/node/node0/cpulist" => Some(cpu_range()),
        _ => {
            // /sys/devices/system/cpu/cpu<N>/topology/{core_id,physical_package_id}
            let rest = path.strip_prefix("/sys/devices/system/cpu/cpu")?;
            let slash = rest.find('/')?;
            let cpu: u32 = rest[..slash].parse().ok()?;
            if cpu >= ncpus { return None; }
            match &rest[slash..] {
                "/topology/core_id" => Some(format!("{}\n", cpu).into_bytes()),
                "/topology/physical_package_id" => Some(b"0\n".to_vec()),
                _ => None,
            }
        }
    }
}

fn generate_cpuinfo() -> Vec<u8> {
    let ncpus = host_ncpus();

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

/// Format a Linux /proc/stat from per-CPU [user, nice, system, idle] tick
/// counts. Pure helper so the layout (which libproc2 parses strictly —
/// missing per-cpu rows gave top "library failed cpu statistics" ERANGE)
/// is unit-testable.
fn format_proc_stat(per_cpu: &[[u64; 4]], btime: i64, processes: u64) -> String {
    let mut out = String::new();
    let mut tot = [0u64; 4];
    for c in per_cpu {
        for k in 0..4 { tot[k] += c[k]; }
    }
    // Linux field order: user nice system idle iowait irq softirq steal guest guest_nice
    out.push_str(&format!(
        "cpu  {} {} {} {} 0 0 0 0 0 0\n", tot[0], tot[1], tot[2], tot[3]));
    for (i, c) in per_cpu.iter().enumerate() {
        out.push_str(&format!(
            "cpu{} {} {} {} {} 0 0 0 0 0 0\n", i, c[0], c[1], c[2], c[3]));
    }
    out.push_str("intr 0\n");
    out.push_str("ctxt 0\n");
    out.push_str(&format!("btime {}\n", btime));
    out.push_str(&format!("processes {}\n", processes));
    out.push_str("procs_running 1\n");
    out.push_str("procs_blocked 0\n");
    out.push_str("softirq 0 0 0 0 0 0 0 0 0 0 0\n");
    out
}

/// Read real per-CPU [user, nice, system, idle] ticks from the host via
/// host_processor_info(PROCESSOR_CPU_LOAD_INFO). Host ticks are already in
/// 1/100 s units, matching Linux USER_HZ=100.
fn host_cpu_ticks() -> Vec<[u64; 4]> {
    const PROCESSOR_CPU_LOAD_INFO: i32 = 2;
    const CPU_STATE_USER: usize = 0;
    const CPU_STATE_SYSTEM: usize = 1;
    const CPU_STATE_IDLE: usize = 2;
    const CPU_STATE_NICE: usize = 3;
    const CPU_STATE_MAX: usize = 4;
    extern "C" {
        fn mach_host_self() -> u32;
        fn host_processor_info(
            host: u32, flavor: i32, out_cpu_count: *mut u32,
            out_info: *mut *mut i32, out_info_cnt: *mut u32) -> i32;
        fn mach_task_self() -> u32;
        fn vm_deallocate(task: u32, addr: usize, size: usize) -> i32;
    }
    let mut cpu_count: u32 = 0;
    let mut info: *mut i32 = std::ptr::null_mut();
    let mut info_cnt: u32 = 0;
    let kr = unsafe {
        host_processor_info(mach_host_self(), PROCESSOR_CPU_LOAD_INFO,
                            &mut cpu_count, &mut info, &mut info_cnt)
    };
    if kr != 0 || info.is_null() || cpu_count == 0 {
        return vec![[0, 0, 0, 0]];
    }
    let mut out = Vec::with_capacity(cpu_count as usize);
    for i in 0..cpu_count as usize {
        let base = i * CPU_STATE_MAX;
        let tick = |s: usize| unsafe { *info.add(base + s) } as u32 as u64;
        out.push([
            tick(CPU_STATE_USER),
            tick(CPU_STATE_NICE),
            tick(CPU_STATE_SYSTEM),
            tick(CPU_STATE_IDLE),
        ]);
    }
    unsafe {
        vm_deallocate(mach_task_self(), info as usize,
                      info_cnt as usize * std::mem::size_of::<i32>());
    }
    out
}

fn generate_proc_stat() -> Vec<u8> {
    let mut real_ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let mut mono_ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut real_ts);
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono_ts);
    }
    let btime = real_ts.tv_sec - mono_ts.tv_sec;
    format_proc_stat(&host_cpu_ticks(), btime, list_guest_vpids().len() as u64).into_bytes()
}

/// Format /proc/loadavg: three load averages, running/total tasks, last pid.
fn format_loadavg(loads: [f64; 3], ntasks: usize, last_pid: i32) -> String {
    format!("{:.2} {:.2} {:.2} 1/{} {}\n", loads[0], loads[1], loads[2], ntasks.max(1), last_pid)
}

fn generate_loadavg() -> Vec<u8> {
    let mut loads = [0f64; 3];
    unsafe { libc::getloadavg(loads.as_mut_ptr(), 3); }
    let vpids = list_guest_vpids();
    let last = vpids.iter().copied().max().unwrap_or(1);
    format_loadavg(loads, vpids.len(), last).into_bytes()
}

/// Real per-process numbers for /proc/<pid>/stat, pulled from the host.
/// Times are Linux clock ticks (100 Hz), rss is in (host 16 KiB) pages —
/// the same page size the guest sees in AT_PAGESZ, so top's RES math works.
struct HostProcStats {
    comm: String,
    utime: u64,
    stime: u64,
    rss_pages: u64,
    starttime: u64, // ticks since boot
}

fn mach_ticks_to_ns(abs: u64) -> u64 {
    extern "C" {
        fn mach_timebase_info(info: *mut [u32; 2]) -> i32;
    }
    static NUMER_DENOM: Mutex<Option<(u32, u32)>> = Mutex::new(None);
    let mut lock = NUMER_DENOM.lock().unwrap();
    let (n, d) = *lock.get_or_insert_with(|| {
        let mut info = [0u32; 2];
        unsafe { mach_timebase_info(&mut info); }
        (info[0].max(1), info[1].max(1))
    });
    (abs as u128 * n as u128 / d as u128) as u64
}

/// Best-effort guest command name: argv[1] (the guest binary path) of the
/// host fakelinux process, via sysctl KERN_PROCARGS2.
fn guest_comm(real_pid: i32) -> String {
    let mut buf = vec![0u8; 16384];
    let mut len = buf.len();
    let mut mib = [libc::CTL_KERN, 49 /* KERN_PROCARGS2 */, real_pid];
    let rc = unsafe {
        libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr() as *mut _, &mut len,
                     std::ptr::null_mut(), 0)
    };
    if rc != 0 || len < 8 {
        return "fakelinux".into();
    }
    buf.truncate(len);
    // Layout: i32 argc, exec_path\0, NUL padding, argv[0]\0, argv[1]\0, ...
    let argc = i32::from_ne_bytes(buf[0..4].try_into().unwrap()).max(0) as usize;
    let mut p = 4;
    while p < buf.len() && buf[p] != 0 { p += 1; } // exec_path
    while p < buf.len() && buf[p] == 0 { p += 1; } // padding
    let mut args: Vec<&[u8]> = Vec::new();
    while p < buf.len() && args.len() < argc {
        let start = p;
        while p < buf.len() && buf[p] != 0 { p += 1; }
        args.push(&buf[start..p]);
        p += 1;
    }
    // argv[0] is the fakelinux binary; skip our own flags (--container …);
    // the first non-flag arg is the guest binary path.
    for a in args.iter().skip(1) {
        if a.starts_with(b"-") || a.is_empty() { continue; }
        let base = a.rsplit(|&b| b == b'/').next().unwrap_or(a);
        let name = String::from_utf8_lossy(base);
        let mut s = name.into_owned();
        s.truncate(15); // Linux TASK_COMM_LEN
        return s;
    }
    "fakelinux".into()
}

fn host_proc_stats(real_pid: i32) -> HostProcStats {
    const RUSAGE_INFO_V2: i32 = 2;
    extern "C" {
        fn proc_pid_rusage(pid: i32, flavor: i32, buffer: *mut u64) -> i32;
        fn mach_absolute_time() -> u64;
    }
    // rusage_info_v2 as u64 words: [0..2)=uuid, 2=user_time, 3=system_time,
    // 4=pkg_idle, 5=interrupt, 6=pageins, 7=wired, 8=resident,
    // 9=phys_footprint, 10=proc_start_abstime, 11=proc_exit_abstime, …
    let mut ri = [0u64; 32];
    let rc = unsafe { proc_pid_rusage(real_pid, RUSAGE_INFO_V2, ri.as_mut_ptr()) };
    let (utime, stime, rss_pages, starttime) = if rc == 0 {
        let ut = mach_ticks_to_ns(ri[2]) / 10_000_000; // ns → 100Hz ticks
        let st = mach_ticks_to_ns(ri[3]) / 10_000_000;
        let rss = ri[9] / 16384;
        let start = mach_ticks_to_ns(ri[10]) / 10_000_000; // abs time IS since boot
        (ut, st, rss, start)
    } else {
        (0, 0, 0, 0)
    };
    HostProcStats { comm: guest_comm(real_pid), utime, stime, rss_pages, starttime }
}

/// Enumerate the virtual PIDs of all live guest processes: host processes
/// running the same fakelinux executable as us. vpid == real host pid,
/// except the container init which is vpid 1 (see pidns).
pub fn list_guest_vpids() -> Vec<i32> {
    extern "C" {
        fn proc_listallpids(buffer: *mut i32, buffersize: i32) -> i32;
        fn proc_pidpath(pid: i32, buffer: *mut u8, buffersize: u32) -> i32;
    }
    let mut self_path = [0u8; 4096];
    let self_len = unsafe { proc_pidpath(libc::getpid(), self_path.as_mut_ptr(), 4096) };
    if self_len <= 0 {
        return vec![crate::pidns::current_vpid()];
    }
    let me = self_path[..self_len as usize].to_vec();

    let mut pids = vec![0i32; 8192];
    let n = unsafe { proc_listallpids(pids.as_mut_ptr(), (pids.len() * 4) as i32) };
    if n <= 0 {
        return vec![crate::pidns::current_vpid()];
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    for &pid in &pids[..n as usize] {
        if pid <= 0 { continue; }
        let len = unsafe { proc_pidpath(pid, buf.as_mut_ptr(), 4096) };
        if len > 0 && buf[..len as usize] == me[..] {
            out.push(crate::pidns::real_to_virtual(pid).unwrap_or(pid));
        }
    }
    if out.is_empty() {
        out.push(crate::pidns::current_vpid());
    }
    out.sort_unstable();
    out.dedup();
    out
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

/// If `path` refers to this process's /proc/self/exe (or /proc/<pid>/exe for
/// our own pid), return the HOST path of the guest executable so it can be
/// opened as a real file. Used by do_openat: crun opens /proc/self/exe to copy
/// its own binary into a memfd for a sealed re-exec. (readlink is handled
/// separately in try_readlink and returns the GUEST path.)
pub fn self_exe_host_path(path: &[u8]) -> Option<String> {
    let path_str = std::str::from_utf8(path).ok()?;
    let normalized = normalize_proc_path(path_str);
    let path_str = normalized.as_deref().unwrap_or(path_str);
    if path_str != "/proc/self/exe" {
        return None;
    }
    let guest_exe = with(|pfs| pfs.exe_path.clone());
    let host_exe = if let Some(root) = crate::rootfs::get_root() {
        if !root.is_empty() && guest_exe.starts_with('/') {
            format!("{}{}", root.trim_end_matches('/'), guest_exe)
        } else {
            guest_exe
        }
    } else {
        guest_exe
    };
    Some(host_exe)
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
                // Strip the rootfs prefix — the guest must see its own path,
                // not the host one. Leaking the host path makes the guest
                // re-open it, which re-translates under the rootfs → ENOENT
                // (broke systemd-sysusers' fsync_full of /etc/.#groupXXXX).
                let host = &pathbuf[..len];
                let stripped = crate::rootfs::strip_root_prefix(host);
                let p: &[u8] = stripped.as_deref().unwrap_or(host);
                let copy_len = p.len().min(bufsiz as usize);
                unsafe {
                    std::ptr::copy_nonoverlapping(p.as_ptr(), buf as *mut u8, copy_len);
                }
                return Some(copy_len as u64);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_path_strips_rootfs_after_absolutizing() {
        // Relative launch path: absolutize against cwd, THEN strip the root.
        assert_eq!(
            guest_exe_path(
                "ubuntu-rootfs/root/vpp/bin/vpp",
                "/Users/u/fakelinux",
                Some("/Users/u/fakelinux/ubuntu-rootfs"),
            ),
            "/root/vpp/bin/vpp"
        );
        // Absolute host path under the root strips too.
        assert_eq!(
            guest_exe_path(
                "/Users/u/fakelinux/ubuntu-rootfs/bin/dash",
                "/anything",
                Some("/Users/u/fakelinux/ubuntu-rootfs"),
            ),
            "/bin/dash"
        );
        // Path NOT under the root is left alone (sysroot-less runs).
        assert_eq!(
            guest_exe_path("/bin/ls", "/x", Some("/Users/u/fakelinux/ubuntu-rootfs")),
            "/bin/ls"
        );
        // Prefix match must respect path boundaries: ubuntu-rootfs2 ≠ root.
        assert_eq!(
            guest_exe_path(
                "/Users/u/fakelinux/ubuntu-rootfs2/bin/sh",
                "/x",
                Some("/Users/u/fakelinux/ubuntu-rootfs"),
            ),
            "/Users/u/fakelinux/ubuntu-rootfs2/bin/sh"
        );
        // No rootfs configured → just absolutize.
        assert_eq!(guest_exe_path("bin/true", "/cwd", None), "/cwd/bin/true");
    }

    #[test]
    fn proc_stat_has_aggregate_and_per_cpu_rows() {
        // libproc2 (top) wants "cpu " + per-cpu rows; the old stub with a
        // single all-zero cpu line failed with ERANGE ("library failed cpu
        // statistics").
        let s = format_proc_stat(&[[100, 1, 50, 1000], [200, 2, 60, 2000]], 1700000000, 5);
        assert!(s.starts_with("cpu  300 3 110 3000 0 0 0 0 0 0\n"), "{s}");
        assert!(s.contains("\ncpu0 100 1 50 1000 0 0 0 0 0 0\n"), "{s}");
        assert!(s.contains("\ncpu1 200 2 60 2000 0 0 0 0 0 0\n"), "{s}");
        assert!(s.contains("\nbtime 1700000000\n"), "{s}");
        assert!(s.contains("\nprocesses 5\n"), "{s}");
        assert!(s.contains("\nprocs_running 1\n"), "{s}");
    }

    #[test]
    fn host_cpu_ticks_returns_nonzero_real_data() {
        let t = host_cpu_ticks();
        assert!(!t.is_empty());
        // The host has been up for a while — idle ticks can't all be zero.
        assert!(t.iter().any(|c| c[3] > 0), "{t:?}");
    }

    #[test]
    fn loadavg_format_matches_linux() {
        let s = format_loadavg([1.5, 0.75, 0.25], 12, 4242);
        assert_eq!(s, "1.50 0.75 0.25 1/12 4242\n");
    }

    #[test]
    fn sysfs_cpu_topology_serves_vpp_startup_files() {
        // VPP's vlib_thread_init reads /sys/devices/system/cpu/online via
        // clib_sysfs_read_bitmap; an empty bitmap → 0 cpus → fatal
        // "skip-core value greater or equal to available cpus".
        assert_eq!(sysfs_content("/sys/devices/system/cpu/online", 10),
                   Some(b"0-9\n".to_vec()));
        assert_eq!(sysfs_content("/sys/devices/system/cpu/possible", 10),
                   Some(b"0-9\n".to_vec()));
        assert_eq!(sysfs_content("/sys/devices/system/cpu/present", 10),
                   Some(b"0-9\n".to_vec()));
        // Single-cpu range has no dash
        assert_eq!(sysfs_content("/sys/devices/system/cpu/online", 1),
                   Some(b"0\n".to_vec()));
        // Fake single NUMA node 0 holding all cpus
        assert_eq!(sysfs_content("/sys/devices/system/node/online", 10),
                   Some(b"0\n".to_vec()));
        assert_eq!(sysfs_content("/sys/devices/system/node/has_memory", 10),
                   Some(b"0\n".to_vec()));
        assert_eq!(sysfs_content("/sys/devices/system/node/node0/cpulist", 10),
                   Some(b"0-9\n".to_vec()));
        // Per-cpu topology: core_id = cpu index, all on package 0
        assert_eq!(sysfs_content("/sys/devices/system/cpu/cpu3/topology/core_id", 10),
                   Some(b"3\n".to_vec()));
        assert_eq!(sysfs_content("/sys/devices/system/cpu/cpu3/topology/physical_package_id", 10),
                   Some(b"0\n".to_vec()));
        // Out-of-range cpu and unknown paths are not served
        assert_eq!(sysfs_content("/sys/devices/system/cpu/cpu10/topology/core_id", 10), None);
        assert_eq!(sysfs_content("/sys/devices/system/node/node1/cpulist", 10), None);
        assert_eq!(sysfs_content("/sys/kernel/mm/whatever", 10), None);
    }

    #[test]
    fn generate_content_serves_sysfs_cpu_online() {
        // End-to-end through the virtual-file dispatcher (host ncpus >= 1)
        let c = generate_content("/sys/devices/system/cpu/online").expect("served");
        let s = String::from_utf8(c).unwrap();
        assert!(s == "0\n" || (s.starts_with("0-") && s.ends_with('\n')), "{s}");
    }

    #[test]
    fn list_guest_vpids_includes_self() {
        let vpids = list_guest_vpids();
        let me = crate::pidns::current_vpid();
        assert!(vpids.contains(&me), "{vpids:?} should contain {me}");
    }
}
