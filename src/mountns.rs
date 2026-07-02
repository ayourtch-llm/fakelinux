//! Fake mount-table bookkeeping.
//!
//! fakelinux has no filesystem isolation: mount(2), umount2(2) and
//! pivot_root(2) are lies that return success so container setup proceeds.
//! But the lie must keep the *arithmetic* of a real mount table: crun's
//! pivot_root cleanup loops `do { umount2(".", MNT_DETACH) } while (ret ==
//! 0)` and only stops on EINVAL ("nothing mounted here") — an unconditional
//! success stub spins it forever at 100% CPU.
//!
//! So we count stacked mounts per (host-resolved) mount point: mount() and
//! pivot_root() push, umount2() pops or reports EINVAL. Propagation-type and
//! remount/move calls (MS_PRIVATE/MS_SHARED/MS_REMOUNT/...) alter existing
//! mounts on Linux, so they don't push.

use std::collections::HashMap;
use std::sync::Mutex;

static MOUNTS: Mutex<Option<HashMap<String, u32>>> = Mutex::new(None);

/// Record one mount stacked on `key` (a host-resolved absolute path).
pub fn push_mount(key: &str) {
    let mut lock = MOUNTS.lock().unwrap();
    let map = lock.get_or_insert_with(HashMap::new);
    *map.entry(key.to_string()).or_insert(0) += 1;
}

/// Remove one mount from `key`. Returns true if a mount was there (umount2
/// succeeds), false if not (umount2 must fail with EINVAL, like a real
/// kernel asked to unmount a non-mount-point).
pub fn pop_mount(key: &str) -> bool {
    let mut lock = MOUNTS.lock().unwrap();
    let map = match lock.as_mut() {
        Some(m) => m,
        None => return false,
    };
    match map.get_mut(key) {
        Some(n) if *n > 0 => {
            *n -= 1;
            if *n == 0 {
                map.remove(key);
            }
            true
        }
        _ => false,
    }
}

/// Linux mount flags that modify an existing mount rather than create one.
pub fn is_mount_modification(flags: u64) -> bool {
    const MS_REMOUNT: u64 = 32;
    const MS_MOVE: u64 = 8192;
    const MS_UNBINDABLE: u64 = 1 << 17;
    const MS_PRIVATE: u64 = 1 << 18;
    const MS_SLAVE: u64 = 1 << 19;
    const MS_SHARED: u64 = 1 << 20;
    flags & (MS_REMOUNT | MS_MOVE | MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crun_pivot_root_umount_loop_terminates() {
        // crun (linux.c do_pivot): pivot_root(".", ".") stacks the old root
        // on the new root's path; then umount2(".") once (must succeed),
        // then loops umount2(".") until EINVAL. Model that exact sequence.
        let key = "/test/crun_pivot/rootfs";
        push_mount(key); // pivot_root(".", ".")
        assert!(pop_mount(key), "first umount2 must succeed");
        // Loop: first iteration must now fail (EINVAL) → loop breaks.
        assert!(!pop_mount(key), "second umount2 must fail with EINVAL");
        assert!(!pop_mount(key), "and stay failing");
    }

    #[test]
    fn stacked_mounts_pop_one_at_a_time() {
        let key = "/test/stacked";
        push_mount(key);
        push_mount(key);
        assert!(pop_mount(key));
        assert!(pop_mount(key));
        assert!(!pop_mount(key));
    }

    #[test]
    fn propagation_and_remount_flags_do_not_push() {
        assert!(is_mount_modification(1 << 18)); // MS_PRIVATE
        assert!(is_mount_modification(1 << 20)); // MS_SHARED
        assert!(is_mount_modification(32)); // MS_REMOUNT
        assert!(is_mount_modification(8192)); // MS_MOVE
        assert!(is_mount_modification((1 << 18) | 16384)); // MS_REC|MS_PRIVATE
        assert!(!is_mount_modification(4096)); // MS_BIND alone creates a mount
        assert!(!is_mount_modification(0)); // plain fstype mount
    }
}
