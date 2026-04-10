//! Linux ↔ macOS signal number translation and guest signal forwarding.
//!
//! Linux and macOS share signal numbers 1-15 mostly, but diverge above that.
//! We maintain a table of guest signal handlers and install macOS signal handlers
//! that forward to the guest.

use std::sync::Mutex;

/// Guest signal handler entry.
#[derive(Clone, Copy)]
pub struct GuestSigaction {
    pub handler: u64,   // SA_HANDLER or SA_SIGACTION function pointer (guest address)
    pub flags: u64,     // Linux sa_flags
    pub restorer: u64,  // sa_restorer (unused on aarch64)
    pub mask: u64,      // sa_mask (simplified to a single u64)
}

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;

/// Table of guest signal handlers indexed by Linux signal number (1..64).
static GUEST_SIGACTIONS: Mutex<[GuestSigaction; 65]> = Mutex::new(
    [GuestSigaction { handler: SIG_DFL, flags: 0, restorer: 0, mask: 0 }; 65]
);

/// Translate Linux signal number → macOS signal number.
pub fn linux_to_mac(linux_sig: i32) -> Option<i32> {
    match linux_sig {
        // 1-15 are mostly the same
        1 => Some(libc::SIGHUP),     // 1→1
        2 => Some(libc::SIGINT),     // 2→2
        3 => Some(libc::SIGQUIT),    // 3→3
        4 => Some(libc::SIGILL),     // 4→4
        5 => Some(libc::SIGTRAP),    // 5→5
        6 => Some(libc::SIGABRT),    // 6→6
        7 => Some(libc::SIGBUS),     // Linux SIGBUS=7, macOS SIGBUS=10
        8 => Some(libc::SIGFPE),     // 8→8
        9 => Some(libc::SIGKILL),    // 9→9
        10 => Some(libc::SIGUSR1),   // Linux SIGUSR1=10, macOS SIGUSR1=30
        11 => Some(libc::SIGSEGV),   // 11→11
        12 => Some(libc::SIGUSR2),   // Linux SIGUSR2=12, macOS SIGUSR2=31
        13 => Some(libc::SIGPIPE),   // 13→13
        14 => Some(libc::SIGALRM),   // 14→14
        15 => Some(libc::SIGTERM),   // 15→15
        // 16 = SIGSTKFLT (Linux only, no macOS equivalent)
        17 => Some(libc::SIGCHLD),   // Linux SIGCHLD=17, macOS SIGCHLD=20
        18 => Some(libc::SIGCONT),   // Linux SIGCONT=18, macOS SIGCONT=19
        19 => Some(libc::SIGSTOP),   // Linux SIGSTOP=19, macOS SIGSTOP=17
        20 => Some(libc::SIGTSTP),   // Linux SIGTSTP=20, macOS SIGTSTP=18
        21 => Some(libc::SIGTTIN),   // Linux 21, macOS 21
        22 => Some(libc::SIGTTOU),   // Linux 22, macOS 22
        23 => Some(libc::SIGURG),    // Linux SIGURG=23, macOS SIGURG=16
        24 => Some(libc::SIGXCPU),   // Linux 24, macOS 24
        25 => Some(libc::SIGXFSZ),   // Linux 25, macOS 25
        26 => Some(libc::SIGVTALRM), // Linux 26, macOS 26
        27 => Some(libc::SIGPROF),   // Linux 27, macOS 27
        28 => Some(libc::SIGWINCH),  // Linux SIGWINCH=28, macOS SIGWINCH=28
        29 => Some(libc::SIGIO),     // Linux SIGIO=29, macOS SIGIO=23
        // 30-31 are SIGPWR/SIGSYS on Linux
        31 => Some(libc::SIGSYS),    // Linux SIGSYS=31, macOS SIGSYS=12
        // RT signals (32-64) have no macOS equivalent
        _ => None,
    }
}

/// Translate macOS signal number → Linux signal number.
pub fn mac_to_linux(mac_sig: i32) -> i32 {
    match mac_sig {
        1..=6 => mac_sig,     // same
        10 => 7,              // macOS SIGBUS=10 → Linux SIGBUS=7
        8 => 8,               // SIGFPE
        9 => 9,               // SIGKILL
        30 => 10,             // macOS SIGUSR1=30 → Linux SIGUSR1=10
        11 => 11,             // SIGSEGV
        31 => 12,             // macOS SIGUSR2=31 → Linux SIGUSR2=12
        13..=15 => mac_sig,   // SIGPIPE, SIGALRM, SIGTERM
        20 => 17,             // macOS SIGCHLD=20 → Linux SIGCHLD=17
        19 => 18,             // macOS SIGCONT=19 → Linux SIGCONT=18
        17 => 19,             // macOS SIGSTOP=17 → Linux SIGSTOP=19
        18 => 20,             // macOS SIGTSTP=18 → Linux SIGTSTP=20
        21..=22 => mac_sig,   // SIGTTIN, SIGTTOU
        16 => 23,             // macOS SIGURG=16 → Linux SIGURG=23
        24..=28 => mac_sig,   // SIGXCPU..SIGWINCH
        23 => 29,             // macOS SIGIO=23 → Linux SIGIO=29
        12 => 31,             // macOS SIGSYS=12 → Linux SIGSYS=31
        _ => mac_sig,         // unmapped: pass through
    }
}

/// Handle the guest's rt_sigaction syscall.
/// linux_sig: Linux signal number
/// act_ptr: pointer to Linux struct sigaction (or 0)
/// oldact_ptr: pointer to write old sigaction (or 0)
/// sigsetsize: typically 8
pub fn do_rt_sigaction(linux_sig: u64, act_ptr: u64, oldact_ptr: u64, _sigsetsize: u64) -> u64 {
    let sig = linux_sig as usize;
    if sig == 0 || sig >= 65 {
        return (-22_i64) as u64; // -EINVAL
    }

    // Don't let the guest override our SIGTRAP handler
    if sig == 5 {
        // SIGTRAP — we own this. Return success but don't actually install.
        if oldact_ptr != 0 {
            write_guest_sigaction(oldact_ptr, &GuestSigaction {
                handler: SIG_DFL, flags: 0, restorer: 0, mask: 0,
            });
        }
        return 0;
    }

    let mut table = GUEST_SIGACTIONS.lock().unwrap();

    // Return old action
    if oldact_ptr != 0 {
        write_guest_sigaction(oldact_ptr, &table[sig]);
    }

    // Install new action
    if act_ptr != 0 {
        let new_act = read_guest_sigaction(act_ptr);
        table[sig] = new_act;

        // Install a macOS signal handler if the guest wants a custom handler
        if let Some(mac_sig) = linux_to_mac(sig as i32) {
            install_forwarder(mac_sig, new_act.handler);
        }
    }

    0
}

/// Handle rt_sigprocmask.
pub fn do_rt_sigprocmask(how: u64, set_ptr: u64, oldset_ptr: u64, _sigsetsize: u64) -> u64 {
    // Simplified: we don't actually block signals. Just save/restore the mask.
    // A full implementation would translate signal masks and call sigprocmask.
    if oldset_ptr != 0 {
        unsafe { std::ptr::write_bytes(oldset_ptr as *mut u8, 0, 8); }
    }
    let _ = (how, set_ptr);
    0
}

// ─── Internal helpers ───────────────────────────────────────────────────────

// Linux aarch64 struct sigaction layout:
//   offset 0: u64 sa_handler
//   offset 8: u64 sa_flags
//   offset 16: u64 sa_restorer (unused on aarch64, but present)
//   offset 24: u64 sa_mask[0] (we only handle the first word)

fn read_guest_sigaction(ptr: u64) -> GuestSigaction {
    unsafe {
        let p = ptr as *const u64;
        GuestSigaction {
            handler: p.read_unaligned(),
            flags: p.add(1).read_unaligned(),
            restorer: p.add(2).read_unaligned(),
            mask: p.add(3).read_unaligned(),
        }
    }
}

fn write_guest_sigaction(ptr: u64, act: &GuestSigaction) {
    unsafe {
        let p = ptr as *mut u64;
        p.write_unaligned(act.handler);
        p.add(1).write_unaligned(act.flags);
        p.add(2).write_unaligned(act.restorer);
        p.add(3).write_unaligned(act.mask);
    }
}

fn install_forwarder(mac_sig: i32, handler: u64) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        if handler == SIG_DFL {
            sa.sa_sigaction = libc::SIG_DFL;
        } else if handler == SIG_IGN {
            sa.sa_sigaction = libc::SIG_IGN;
        } else {
            // For custom handlers, install our forwarding handler
            // The actual guest handler invocation requires running guest code,
            // which is complex (set up a signal frame, etc). For now, just
            // ignore custom signal handlers — this is a stub.
            // A full implementation would build a Linux signal frame on the
            // guest stack and redirect execution to the guest handler.
            return;
        }
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(mac_sig, &sa, std::ptr::null_mut());
    }
}
