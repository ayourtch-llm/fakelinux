//! Virtual PID namespace for container mode (--init).
//!
//! Maps real macOS PIDs to virtual container PIDs starting from 1.
//! When container mode is active, getpid/getppid/wait4/kill all
//! operate on virtual PIDs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Mutex;

/// Whether container mode is active (--init flag).
pub static CONTAINER_MODE: AtomicBool = AtomicBool::new(false);

/// The real macOS PID of the init process (vpid 1).
static INIT_REAL_PID: AtomicI32 = AtomicI32::new(0);

struct PidTable {
    /// real_pid -> virtual_pid
    real_to_virt: HashMap<i32, i32>,
    /// virtual_pid -> real_pid
    virt_to_real: HashMap<i32, i32>,
    /// Next virtual PID to assign (starts at 2; 1 is reserved for init).
    next_vpid: i32,
}

static PID_TABLE: Mutex<Option<PidTable>> = Mutex::new(None);

/// Initialize container mode. Registers the current process as virtual PID 1.
pub fn init() {
    let real_pid = unsafe { libc::getpid() };
    INIT_REAL_PID.store(real_pid, Ordering::SeqCst);

    let mut real_to_virt = HashMap::new();
    let mut virt_to_real = HashMap::new();
    real_to_virt.insert(real_pid, 1);
    virt_to_real.insert(1, real_pid);

    let mut table = PID_TABLE.lock().unwrap();
    *table = Some(PidTable {
        real_to_virt,
        virt_to_real,
        next_vpid: 2,
    });

    CONTAINER_MODE.store(true, Ordering::SeqCst);
}

/// Register a new real PID in the virtual namespace. Returns the assigned vpid.
pub fn register_pid(real_pid: i32) -> i32 {
    let mut lock = PID_TABLE.lock().unwrap();
    let table = lock.as_mut().expect("pidns not initialized");

    // If already registered, return existing vpid
    if let Some(&vpid) = table.real_to_virt.get(&real_pid) {
        return vpid;
    }

    let vpid = table.next_vpid;
    table.next_vpid += 1;
    table.real_to_virt.insert(real_pid, vpid);
    table.virt_to_real.insert(vpid, real_pid);
    vpid
}

/// Translate a real PID to its virtual PID. Returns None if not registered.
pub fn real_to_virtual(real_pid: i32) -> Option<i32> {
    let lock = PID_TABLE.lock().unwrap();
    let table = lock.as_ref()?;
    table.real_to_virt.get(&real_pid).copied()
}

/// Translate a virtual PID to its real PID. Returns None if not registered.
pub fn virtual_to_real(vpid: i32) -> Option<i32> {
    let lock = PID_TABLE.lock().unwrap();
    let table = lock.as_ref()?;
    table.virt_to_real.get(&vpid).copied()
}

/// Remove a process from the table (e.g., after wait reaps it).
pub fn unregister_real_pid(real_pid: i32) {
    let mut lock = PID_TABLE.lock().unwrap();
    if let Some(table) = lock.as_mut() {
        if let Some(vpid) = table.real_to_virt.remove(&real_pid) {
            table.virt_to_real.remove(&vpid);
        }
    }
}

/// Get the virtual PID for the current process.
pub fn current_vpid() -> i32 {
    let real_pid = unsafe { libc::getpid() };
    real_to_virtual(real_pid).unwrap_or(real_pid)
}

/// Get the virtual PPID for the current process.
/// Init (vpid 1) returns 0. Children of init return 1.
pub fn current_vppid() -> i32 {
    let real_pid = unsafe { libc::getpid() };
    let init_pid = INIT_REAL_PID.load(Ordering::SeqCst);

    if real_pid == init_pid {
        return 0; // init's parent is 0 (kernel)
    }

    let real_ppid = unsafe { libc::getppid() };
    // If our real parent is the init process, return vpid 1
    if real_ppid == init_pid {
        return 1;
    }
    // Otherwise look up the parent in the table
    real_to_virtual(real_ppid).unwrap_or(0)
}

/// Translate a virtual PID argument from a syscall to a real PID.
/// Special values: -1 (any child), 0 (same process group), positive vpid.
pub fn translate_pid_arg(vpid: i32) -> i32 {
    match vpid {
        -1 => -1,                // wait for any child — pass through
        0 => 0,                  // same process group — pass through
        p if p > 0 => {
            virtual_to_real(p).unwrap_or(p)
        }
        neg => {
            // Negative: wait for process group |neg|
            // Translate the group leader PID
            let abs = -neg;
            -(virtual_to_real(abs).unwrap_or(abs))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pid_namespace_basic() {
        // Reset state for test
        {
            let mut lock = PID_TABLE.lock().unwrap();
            *lock = None;
        }
        CONTAINER_MODE.store(false, Ordering::SeqCst);

        // Initialize
        init();
        assert!(CONTAINER_MODE.load(Ordering::SeqCst));

        let real_pid = unsafe { libc::getpid() };
        assert_eq!(real_to_virtual(real_pid), Some(1));
        assert_eq!(virtual_to_real(1), Some(real_pid));

        // Register a fake child
        let vpid = register_pid(99999);
        assert_eq!(vpid, 2);
        assert_eq!(real_to_virtual(99999), Some(2));
        assert_eq!(virtual_to_real(2), Some(99999));

        // Re-register returns same vpid
        assert_eq!(register_pid(99999), 2);

        // Unregister
        unregister_real_pid(99999);
        assert_eq!(real_to_virtual(99999), None);
        assert_eq!(virtual_to_real(2), None);

        // translate_pid_arg
        assert_eq!(translate_pid_arg(-1), -1);
        assert_eq!(translate_pid_arg(0), 0);
        assert_eq!(translate_pid_arg(1), real_pid);
    }
}
