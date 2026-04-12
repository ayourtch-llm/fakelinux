//! Virtual PID namespace for container mode (--container).
//!
//! Uses shared memory (shm_open + mmap MAP_SHARED) so the PID table
//! survives fork() and is accessible after execve() via env vars.
//! All operations are lock-free using atomics.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Whether container mode is active.
pub static CONTAINER_MODE: AtomicBool = AtomicBool::new(false);

/// Cached virtual PID for the current process (set once at startup).
static MY_VPID: AtomicI32 = AtomicI32::new(0);

/// Cached virtual PPID for the current process (set once at startup).
static MY_VPPID: AtomicI32 = AtomicI32::new(0);

/// Maximum number of virtual PIDs.
const MAX_ENTRIES: usize = 262144; // 256K

/// Magic number for validation: "FAKE" in ASCII.
const MAGIC: u32 = 0x46414B45;

/// Header of the shared memory region, followed by entries array.
/// Total size = 16 + 4 * MAX_ENTRIES ≈ 1MB.
#[repr(C)]
struct SharedPidTable {
    magic: u32,
    max_entries: i32,
    next_vpid: AtomicI32,
    count: AtomicI32,
    // entries[vpid] = real_pid (0 = unused). Index 0 is unused (vpids start at 1).
    entries: [AtomicI32; MAX_ENTRIES],
}

/// Pointer to the mmap'd shared PID table. Set once, never changes.
static mut SHM_PTR: *mut SharedPidTable = std::ptr::null_mut();

/// The shm name (e.g. "/fakelinux-abcd1234") for cleanup.
static mut SHM_NAME: Option<String> = None;

/// Whether this process is the init (responsible for shm_unlink).
static IS_INIT: AtomicBool = AtomicBool::new(false);

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn table() -> &'static SharedPidTable {
    unsafe {
        debug_assert!(!SHM_PTR.is_null());
        &*SHM_PTR
    }
}

fn generate_shm_name() -> String {
    let pid = unsafe { libc::getpid() };
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts); }
    // macOS shm_open name max is 31 chars including the leading '/'
    format!("/fl-{:x}-{:x}", pid, (ts.tv_nsec as u32) ^ (ts.tv_sec as u32))
}

fn shm_size() -> usize {
    std::mem::size_of::<SharedPidTable>()
}

fn open_and_map_shm(name: &str, create: bool) -> *mut SharedPidTable {
    let c_name = std::ffi::CString::new(name).unwrap();
    let fd = if create {
        let fd = unsafe {
            libc::shm_open(
                c_name.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
                0o600,
            )
        };
        if fd < 0 {
            panic!("pidns: shm_open create '{}' failed: {}", name, std::io::Error::last_os_error());
        }
        if unsafe { libc::ftruncate(fd, shm_size() as i64) } != 0 {
            panic!("pidns: ftruncate failed: {}", std::io::Error::last_os_error());
        }
        fd
    } else {
        let fd = unsafe { libc::shm_open(c_name.as_ptr(), libc::O_RDWR, 0) };
        if fd < 0 {
            panic!("pidns: shm_open attach '{}' failed: {}", name, std::io::Error::last_os_error());
        }
        fd
    };

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            shm_size(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    unsafe { libc::close(fd); }

    if ptr == libc::MAP_FAILED {
        panic!("pidns: mmap failed: {}", std::io::Error::last_os_error());
    }
    ptr as *mut SharedPidTable
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Create a new container namespace. Called when --container is passed.
/// Registers the current process as virtual PID 1.
pub fn init_container() {
    let name = generate_shm_name();
    let ptr = open_and_map_shm(&name, true);

    // Initialize the table
    unsafe {
        (*ptr).magic = MAGIC;
        (*ptr).max_entries = MAX_ENTRIES as i32;
        (*ptr).next_vpid = AtomicI32::new(2); // 1 is reserved for init
        (*ptr).count = AtomicI32::new(1);
        // Zero-init entries (mmap of new shm is already zeroed, but be explicit for entry 1)
        (*ptr).entries[1].store(libc::getpid(), Ordering::Release);

        SHM_PTR = ptr;
        SHM_NAME = Some(name.clone());
    }

    IS_INIT.store(true, Ordering::SeqCst);
    MY_VPID.store(1, Ordering::SeqCst);
    MY_VPPID.store(0, Ordering::SeqCst);
    CONTAINER_MODE.store(true, Ordering::SeqCst);

    // Set env vars so children can attach
    std::env::set_var("FAKELINUX_CONTAINER", &name);
    std::env::set_var("FAKELINUX_VPID", "1");
    std::env::set_var("FAKELINUX_VPPID", "0");
}

/// Attach to an existing container namespace. Called when FAKELINUX_CONTAINER
/// env var is detected on startup.
pub fn attach_container(shm_name: &str, vpid: i32, vppid: i32) {
    let ptr = open_and_map_shm(shm_name, false);

    // Validate
    unsafe {
        if (*ptr).magic != MAGIC {
            panic!("pidns: shm magic mismatch (expected {:#x}, got {:#x})", MAGIC, (*ptr).magic);
        }
        SHM_PTR = ptr;
        SHM_NAME = Some(shm_name.to_string());
    }

    MY_VPID.store(vpid, Ordering::SeqCst);
    MY_VPPID.store(vppid, Ordering::SeqCst);
    CONTAINER_MODE.store(true, Ordering::SeqCst);
}

/// Allocate a new vpid for a child and register its real PID.
/// Called by the parent after fork(). Returns the child's vpid.
pub fn register_fork(child_real_pid: i32) -> i32 {
    let t = table();
    let vpid = t.next_vpid.fetch_add(1, Ordering::SeqCst);
    if vpid <= 0 || vpid >= MAX_ENTRIES as i32 {
        eprintln!("pidns: vpid overflow ({}), wrapping", vpid);
        return vpid;
    }
    t.entries[vpid as usize].store(child_real_pid, Ordering::Release);
    t.count.fetch_add(1, Ordering::Relaxed);
    vpid
}

/// Update the real PID for an already-allocated vpid entry.
/// Used after fork when the real child PID becomes known.
pub fn update_entry(vpid: i32, real_pid: i32) {
    if vpid > 0 && vpid < MAX_ENTRIES as i32 {
        table().entries[vpid as usize].store(real_pid, Ordering::Release);
    }
}

/// Set env vars for a child about to execve, so re-exec'd fakelinux can attach.
pub fn set_child_env(child_vpid: i32, parent_vpid: i32) {
    std::env::set_var("FAKELINUX_VPID", child_vpid.to_string());
    std::env::set_var("FAKELINUX_VPPID", parent_vpid.to_string());
}

/// Restore env vars for the parent after a child execve fails or after fork
/// returns to the parent path.
pub fn restore_parent_env() {
    let vpid = MY_VPID.load(Ordering::Relaxed);
    let vppid = MY_VPPID.load(Ordering::Relaxed);
    std::env::set_var("FAKELINUX_VPID", vpid.to_string());
    std::env::set_var("FAKELINUX_VPPID", vppid.to_string());
}

/// Mark the current process's entry as unused. Called on exit.
pub fn on_exit() {
    if !CONTAINER_MODE.load(Ordering::Relaxed) {
        return;
    }
    let vpid = MY_VPID.load(Ordering::Relaxed);
    if vpid > 0 && vpid < MAX_ENTRIES as i32 {
        table().entries[vpid as usize].store(0, Ordering::Release);
        table().count.fetch_sub(1, Ordering::Relaxed);
    }
    if IS_INIT.load(Ordering::Relaxed) {
        if let Some(name) = unsafe { &*std::ptr::addr_of!(SHM_NAME) } {
            let c_name = std::ffi::CString::new(name.as_str()).unwrap();
            unsafe { libc::shm_unlink(c_name.as_ptr()); }
        }
    }
}

// ─── Query API ───────────────────────────────────────────────────────────────

/// Get the cached virtual PID for the current process.
pub fn current_vpid() -> i32 {
    MY_VPID.load(Ordering::Relaxed)
}

/// Get the cached virtual PPID for the current process.
pub fn current_vppid() -> i32 {
    MY_VPPID.load(Ordering::Relaxed)
}

/// Translate a virtual PID to a real PID. Returns None if not found.
pub fn virtual_to_real(vpid: i32) -> Option<i32> {
    if vpid <= 0 || vpid >= MAX_ENTRIES as i32 {
        return None;
    }
    let real = table().entries[vpid as usize].load(Ordering::Acquire);
    if real != 0 { Some(real) } else { None }
}

/// Translate a real PID to a virtual PID by scanning entries.
/// This is O(n) but only needed for wait4 return translation.
pub fn real_to_virtual(real_pid: i32) -> Option<i32> {
    let t = table();
    let limit = t.next_vpid.load(Ordering::Acquire).min(MAX_ENTRIES as i32);
    for i in 1..limit {
        if t.entries[i as usize].load(Ordering::Acquire) == real_pid {
            return Some(i);
        }
    }
    None
}

/// Mark a virtual PID entry as unused (e.g., after wait reaps it).
pub fn unregister_vpid(vpid: i32) {
    if vpid > 0 && vpid < MAX_ENTRIES as i32 {
        let old = table().entries[vpid as usize].swap(0, Ordering::AcqRel);
        if old != 0 {
            table().count.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Translate a virtual PID argument from a syscall to a real PID.
/// Special values: -1 (any child), 0 (same process group), positive vpid.
pub fn translate_pid_arg(vpid: i32) -> i32 {
    match vpid {
        -1 => -1,
        0 => 0,
        p if p > 0 => virtual_to_real(p).unwrap_or(p),
        neg => {
            let abs = -neg;
            -(virtual_to_real(abs).unwrap_or(abs))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pid_namespace_shm() {
        // Create a fresh container
        init_container();
        assert!(CONTAINER_MODE.load(Ordering::SeqCst));
        assert_eq!(current_vpid(), 1);
        assert_eq!(current_vppid(), 0);

        let real_pid = unsafe { libc::getpid() };
        assert_eq!(virtual_to_real(1), Some(real_pid));
        assert_eq!(real_to_virtual(real_pid), Some(1));

        // Register a fake child
        let vpid = register_fork(99999);
        assert_eq!(vpid, 2);
        assert_eq!(virtual_to_real(2), Some(99999));
        assert_eq!(real_to_virtual(99999), Some(2));

        // Register another
        let vpid2 = register_fork(88888);
        assert_eq!(vpid2, 3);

        // Unregister
        unregister_vpid(2);
        assert_eq!(virtual_to_real(2), None);
        assert_eq!(real_to_virtual(99999), None);

        // translate_pid_arg
        assert_eq!(translate_pid_arg(-1), -1);
        assert_eq!(translate_pid_arg(0), 0);
        assert_eq!(translate_pid_arg(1), real_pid);
        assert_eq!(translate_pid_arg(3), 88888);

        // Cleanup
        unregister_vpid(3);
        on_exit();
    }
}
