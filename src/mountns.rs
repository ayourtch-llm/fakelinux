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
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

static MOUNTS: Mutex<Option<HashMap<String, u32>>> = Mutex::new(None);

/// Count of pivot_root old-roots awaiting their lazy MNT_DETACH umount.
/// crun's do_pivot does pivot_root(".",".") then fchdir's to the *old* root
/// fd and umount2(".", MNT_DETACH)s it — so the umount path differs from the
/// path pivot_root stacked the old root on, and a plain path key can't match
/// the two. The old root is a single detachable subtree, so we track it as a
/// count instead. See crun src/libcrun/linux.c do_pivot().
static PIVOT_OLDROOTS: AtomicU32 = AtomicU32::new(0);

const MNT_DETACH: u64 = 2;

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

/// Record that pivot_root stacked one old-root subtree awaiting detach.
pub fn push_pivot_oldroot() {
    PIVOT_OLDROOTS.fetch_add(1, Ordering::Relaxed);
}

/// Model umount2(target, flags). Returns 0 on success or -EINVAL (as a
/// negated i64-in-u64) when there is nothing mounted at the target — which
/// is exactly the terminator crun's `do { } while` cleanup loop waits for.
///
/// Resolution order: an explicit tracked mount at `key` wins; otherwise a
/// lazy detach (MNT_DETACH) consumes one pending pivot_root old-root, and
/// because that old root carried every earlier mount, it also clears the
/// tracked table. A non-lazy umount of an untracked path fails with EINVAL.
pub fn umount(key: &str, flags: u64) -> u64 {
    if pop_mount(key) {
        return 0;
    }
    if flags & MNT_DETACH != 0
        && PIVOT_OLDROOTS
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
            .is_ok()
    {
        // The detached old root took all previously-stacked mounts with it.
        if let Some(map) = MOUNTS.lock().unwrap().as_mut() {
            map.clear();
        }
        return 0;
    }
    (-22_i64) as u64 // -EINVAL: not a mount point
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
        // crun (linux.c do_pivot): mounts the container fs, pivot_root(".",
        // "."), then fchdir's to the OLD root and umount2(".", MNT_DETACH)
        // it once (must succeed), then loops umount2(".", MNT_DETACH) until
        // EINVAL. The umount path differs from where pivot_root stacked the
        // old root, so this must resolve via the pivot-oldroot count.
        const DETACH: u64 = 2;
        // Container setup stacked several mounts inside the rootfs.
        push_mount("/host/rootfs/proc");
        push_mount("/host/rootfs/dev");
        push_pivot_oldroot(); // pivot_root(".", ".")
        // First umount2 of "." (now the old root, a different path) succeeds
        // and carries away every earlier mount.
        assert_eq!(umount("/host/oldroot", DETACH), 0, "first umount2 must succeed");
        // Loop: next umount2 finds nothing → EINVAL → loop breaks.
        assert_eq!(umount("/host/oldroot", DETACH), (-22_i64) as u64,
            "second umount2 must return EINVAL");
        // Earlier mounts were cleared by the old-root detach.
        assert!(!pop_mount("/host/rootfs/proc"));
    }

    #[test]
    fn non_lazy_umount_of_untracked_path_is_einval() {
        assert_eq!(umount("/host/nowhere", 0), (-22_i64) as u64);
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
