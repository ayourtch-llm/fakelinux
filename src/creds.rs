//! Virtual credential (uid/gid) state — emulates `unshare -r` behavior.
//!
//! The guest process starts as virtual root (uid=0, gid=0). All credential
//! syscalls operate on this virtual state rather than delegating to macOS.
//! Actual file operations still use the real macOS credentials.

use std::sync::Mutex;

/// Virtual process credentials. Mirrors the Linux kernel's `struct cred`.
struct Creds {
    uid: u32,
    euid: u32,
    suid: u32,
    fsuid: u32,

    gid: u32,
    egid: u32,
    sgid: u32,
    fsgid: u32,

    /// Supplementary groups list.
    groups: Vec<u32>,
}

static CREDS: Mutex<Creds> = Mutex::new(Creds {
    uid: 0,
    euid: 0,
    suid: 0,
    fsuid: 0,
    gid: 0,
    egid: 0,
    sgid: 0,
    fsgid: 0,
    groups: Vec::new(),
});

// ---- Simple getters ----

pub fn do_getuid() -> u64 {
    CREDS.lock().unwrap().uid as u64
}

pub fn do_geteuid() -> u64 {
    CREDS.lock().unwrap().euid as u64
}

pub fn do_getgid() -> u64 {
    CREDS.lock().unwrap().gid as u64
}

pub fn do_getegid() -> u64 {
    CREDS.lock().unwrap().egid as u64
}

// ---- setuid family ----

/// setuid(uid) — see setuid(2). Behavior depends on whether euid == 0.
pub fn do_setuid(uid: u32) -> u64 {
    let mut c = CREDS.lock().unwrap();
    if c.euid == 0 {
        // Privileged: set all three
        c.uid = uid;
        c.euid = uid;
        c.suid = uid;
        c.fsuid = uid;
    } else if uid == c.uid || uid == c.suid {
        // Unprivileged: can only set euid to ruid or suid
        c.euid = uid;
        c.fsuid = uid;
    } else {
        return (-1_i64) as u64; // caller checks errno; we return -EPERM
    }
    0
}

/// setgid(gid) — see setgid(2). Behavior depends on whether euid == 0.
pub fn do_setgid(gid: u32) -> u64 {
    let mut c = CREDS.lock().unwrap();
    if c.euid == 0 {
        c.gid = gid;
        c.egid = gid;
        c.sgid = gid;
        c.fsgid = gid;
    } else if gid == c.gid || gid == c.sgid {
        c.egid = gid;
        c.fsgid = gid;
    } else {
        return (-1_i64) as u64;
    }
    0
}

/// setreuid(ruid, euid)
pub fn do_setreuid(ruid: u32, euid: u32) -> u64 {
    let mut c = CREDS.lock().unwrap();
    let no_change = 0xFFFFFFFFu32; // (uid_t)-1 means "don't change"

    let new_ruid = if ruid == no_change { c.uid } else { ruid };
    let new_euid = if euid == no_change { c.euid } else { euid };

    // Permission check: unprivileged can only set ruid to {ruid, euid}
    // and euid to {ruid, euid, suid}
    if c.euid != 0 {
        if ruid != no_change && new_ruid != c.uid && new_ruid != c.euid {
            return (-1_i64) as u64;
        }
        if euid != no_change && new_euid != c.uid && new_euid != c.euid && new_euid != c.suid {
            return (-1_i64) as u64;
        }
    }

    // If ruid is set, or euid is changed, suid = new euid
    if ruid != no_change || (euid != no_change && new_euid != c.euid) {
        c.suid = new_euid;
    }
    c.uid = new_ruid;
    c.euid = new_euid;
    c.fsuid = new_euid;
    0
}

/// setregid(rgid, egid)
pub fn do_setregid(rgid: u32, egid: u32) -> u64 {
    let mut c = CREDS.lock().unwrap();
    let no_change = 0xFFFFFFFFu32;

    let new_rgid = if rgid == no_change { c.gid } else { rgid };
    let new_egid = if egid == no_change { c.egid } else { egid };

    if c.euid != 0 {
        if rgid != no_change && new_rgid != c.gid && new_rgid != c.egid {
            return (-1_i64) as u64;
        }
        if egid != no_change && new_egid != c.gid && new_egid != c.egid && new_egid != c.sgid {
            return (-1_i64) as u64;
        }
    }

    if rgid != no_change || (egid != no_change && new_egid != c.egid) {
        c.sgid = new_egid;
    }
    c.gid = new_rgid;
    c.egid = new_egid;
    c.fsgid = new_egid;
    0
}

/// setresuid(ruid, euid, suid)
pub fn do_setresuid(ruid: u32, euid: u32, suid: u32) -> u64 {
    let mut c = CREDS.lock().unwrap();
    let no_change = 0xFFFFFFFFu32;

    let new_ruid = if ruid == no_change { c.uid } else { ruid };
    let new_euid = if euid == no_change { c.euid } else { euid };
    let new_suid = if suid == no_change { c.suid } else { suid };

    if c.euid != 0 {
        // Unprivileged: each value must be one of {ruid, euid, suid}
        let allowed = [c.uid, c.euid, c.suid];
        if ruid != no_change && !allowed.contains(&new_ruid) {
            return (-1_i64) as u64;
        }
        if euid != no_change && !allowed.contains(&new_euid) {
            return (-1_i64) as u64;
        }
        if suid != no_change && !allowed.contains(&new_suid) {
            return (-1_i64) as u64;
        }
    }

    c.uid = new_ruid;
    c.euid = new_euid;
    c.suid = new_suid;
    c.fsuid = new_euid;
    0
}

/// getresuid(ruid*, euid*, suid*)
pub fn do_getresuid(ruid_ptr: u64, euid_ptr: u64, suid_ptr: u64) -> u64 {
    let c = CREDS.lock().unwrap();
    unsafe {
        (ruid_ptr as *mut u32).write_unaligned(c.uid);
        (euid_ptr as *mut u32).write_unaligned(c.euid);
        (suid_ptr as *mut u32).write_unaligned(c.suid);
    }
    0
}

/// setresgid(rgid, egid, sgid)
pub fn do_setresgid(rgid: u32, egid: u32, sgid: u32) -> u64 {
    let mut c = CREDS.lock().unwrap();
    let no_change = 0xFFFFFFFFu32;

    let new_rgid = if rgid == no_change { c.gid } else { rgid };
    let new_egid = if egid == no_change { c.egid } else { egid };
    let new_sgid = if sgid == no_change { c.sgid } else { sgid };

    if c.euid != 0 {
        let allowed = [c.gid, c.egid, c.sgid];
        if rgid != no_change && !allowed.contains(&new_rgid) {
            return (-1_i64) as u64;
        }
        if egid != no_change && !allowed.contains(&new_egid) {
            return (-1_i64) as u64;
        }
        if sgid != no_change && !allowed.contains(&new_sgid) {
            return (-1_i64) as u64;
        }
    }

    c.gid = new_rgid;
    c.egid = new_egid;
    c.sgid = new_sgid;
    c.fsgid = new_egid;
    0
}

/// getresgid(rgid*, egid*, sgid*)
pub fn do_getresgid(rgid_ptr: u64, egid_ptr: u64, sgid_ptr: u64) -> u64 {
    let c = CREDS.lock().unwrap();
    unsafe {
        (rgid_ptr as *mut u32).write_unaligned(c.gid);
        (egid_ptr as *mut u32).write_unaligned(c.egid);
        (sgid_ptr as *mut u32).write_unaligned(c.sgid);
    }
    0
}

/// setfsuid(fsuid) — returns the previous fsuid.
pub fn do_setfsuid(fsuid: u32) -> u64 {
    let mut c = CREDS.lock().unwrap();
    let old = c.fsuid;
    // Permission: can set to any of {uid, euid, suid, current fsuid}, or any if euid==0
    if c.euid == 0 || fsuid == c.uid || fsuid == c.euid || fsuid == c.suid || fsuid == c.fsuid {
        c.fsuid = fsuid;
    }
    // Always returns previous fsuid (even on failure — Linux behavior)
    old as u64
}

/// setfsgid(fsgid) — returns the previous fsgid.
pub fn do_setfsgid(fsgid: u32) -> u64 {
    let mut c = CREDS.lock().unwrap();
    let old = c.fsgid;
    if c.euid == 0 || fsgid == c.gid || fsgid == c.egid || fsgid == c.sgid || fsgid == c.fsgid {
        c.fsgid = fsgid;
    }
    old as u64
}

/// getgroups(size, list) — returns number of supplementary groups.
pub fn do_getgroups(size: u32, list_ptr: u64) -> u64 {
    let c = CREDS.lock().unwrap();
    let ngroups = c.groups.len();

    if size == 0 {
        return ngroups as u64;
    }

    if (size as usize) < ngroups {
        return (-22_i64) as u64; // -EINVAL
    }

    unsafe {
        let p = list_ptr as *mut u32;
        for (i, &gid) in c.groups.iter().enumerate() {
            p.add(i).write_unaligned(gid);
        }
    }
    ngroups as u64
}

/// setgroups(size, list) — requires euid == 0.
pub fn do_setgroups(size: u32, list_ptr: u64) -> u64 {
    let mut c = CREDS.lock().unwrap();

    if c.euid != 0 {
        return (-1_i64) as u64; // -EPERM
    }

    if size > 65536 {
        return (-22_i64) as u64; // -EINVAL (NGROUPS_MAX)
    }

    let mut groups = Vec::with_capacity(size as usize);
    unsafe {
        let p = list_ptr as *const u32;
        for i in 0..size as usize {
            groups.push(p.add(i).read_unaligned());
        }
    }
    c.groups = groups;
    0
}
