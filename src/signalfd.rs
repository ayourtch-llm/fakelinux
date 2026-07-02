//! signalfd(2) emulation.
//!
//! macOS has no signalfd. Container runtimes (crun/conmon) block all signals
//! with sigprocmask, create a signalfd for the blocked set, and epoll_wait on
//! it to learn when their container init exits (a blocked SIGCHLD becomes a
//! readable signalfd_siginfo rather than a delivered signal).
//!
//! We back each signalfd with a real AF_UNIX datagram socketpair: the read
//! end is what the guest polls/reads (so epoll on it works for free), and we
//! push a Linux `struct signalfd_siginfo` into the write end whenever a
//! matching signal is "delivered". Today the only producer is wait4() reaping
//! a child (→ SIGCHLD); that is what crun's wait loop blocks on. Other signals
//! are not yet synthesized.

use std::collections::HashMap;
use std::sync::Mutex;

/// Linux `struct signalfd_siginfo` is 128 bytes. We fill the fields crun and
/// the common readers look at: ssi_signo, ssi_code, ssi_pid, ssi_status.
#[repr(C)]
#[derive(Clone, Copy)]
struct SignalfdSiginfo {
    ssi_signo: u32,   // 0
    ssi_errno: i32,   // 4
    ssi_code: i32,    // 8
    ssi_pid: u32,     // 12
    ssi_uid: u32,     // 16
    ssi_fd: i32,      // 20
    ssi_tid: u32,     // 24
    ssi_band: u32,    // 28
    ssi_overrun: u32, // 32
    ssi_trapno: u32,  // 36
    ssi_status: i32,  // 40
    ssi_int: i32,     // 44
    ssi_ptr: u64,     // 48
    ssi_utime: u64,   // 56
    ssi_stime: u64,   // 64
    ssi_addr: u64,    // 72
    ssi_addr_lsb: u16, // 80
    _pad: [u8; 46],   // → 128 bytes total
}

const SIGCHLD: u32 = 17;
const LINUX_CLD_EXITED: i32 = 1;
const LINUX_CLD_KILLED: i32 = 2;

struct SignalfdState {
    /// The write end we push siginfo records into (read end is `fd`).
    writer: i32,
    /// Signal numbers this fd was created to observe (Linux numbering).
    mask: u64,
}

static SIGNALFDS: Mutex<Option<HashMap<i32, SignalfdState>>> = Mutex::new(None);

fn mask_has(mask: u64, signo: u32) -> bool {
    signo >= 1 && signo <= 64 && (mask & (1u64 << (signo - 1))) != 0
}

/// signalfd4(fd, mask_ptr, sizemask, flags). We only support fd == -1 (create
/// a new signalfd); modifying an existing one returns it unchanged. The mask
/// is a Linux sigset_t (little-endian bitmask, bit i == signal i+1).
pub fn do_signalfd4(fd: i32, mask_ptr: u64, sizemask: u64, flags: i32) -> u64 {
    let mask = if mask_ptr != 0 && sizemask >= 8 {
        unsafe { (mask_ptr as *const u64).read_unaligned() }
    } else {
        0
    };

    if fd >= 0 {
        // Update the observed mask of an existing signalfd.
        if let Some(map) = SIGNALFDS.lock().unwrap().as_mut() {
            if let Some(st) = map.get_mut(&fd) {
                st.mask = mask;
                return fd as u64;
            }
        }
        return (-22_i64) as u64; // -EINVAL: not one of ours
    }

    // Create an AF_UNIX datagram socketpair; guest reads the [0] end.
    let mut sv = [0i32; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr()) } != 0 {
        return crate::translate::linux_errno();
    }
    // SFD_NONBLOCK = 0x800, SFD_CLOEXEC = 0x80000 (same values as O_*).
    const SFD_NONBLOCK: i32 = 0x800;
    const SFD_CLOEXEC: i32 = 0x80000;
    unsafe {
        if flags & SFD_NONBLOCK != 0 {
            let fl = libc::fcntl(sv[0], libc::F_GETFL);
            libc::fcntl(sv[0], libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
        if flags & SFD_CLOEXEC != 0 {
            libc::fcntl(sv[0], libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    let read_fd = sv[0];
    let mut lock = SIGNALFDS.lock().unwrap();
    let map = lock.get_or_insert_with(HashMap::new);
    map.insert(read_fd, SignalfdState { writer: sv[1], mask });
    read_fd as u64
}

pub fn is_signalfd(fd: i32) -> bool {
    SIGNALFDS
        .lock()
        .unwrap()
        .as_ref()
        .map_or(false, |m| m.contains_key(&fd))
}

pub fn on_close(fd: i32) {
    if let Some(map) = SIGNALFDS.lock().unwrap().as_mut() {
        if let Some(st) = map.remove(&fd) {
            unsafe { libc::close(st.writer) };
        }
    }
}

/// Called by wait4() after it reaps a child. Pushes a SIGCHLD siginfo record
/// to every signalfd whose mask includes SIGCHLD, so a crun/conmon wait loop
/// blocked in epoll_wait on the signalfd wakes and reaps.
pub fn deliver_sigchld(pid: i32, wstatus: i32) {
    let map_lock = SIGNALFDS.lock().unwrap();
    let map = match map_lock.as_ref() {
        Some(m) if !m.is_empty() => m,
        _ => return,
    };
    let (code, status) = if libc::WIFEXITED(wstatus) {
        (LINUX_CLD_EXITED, libc::WEXITSTATUS(wstatus))
    } else if libc::WIFSIGNALED(wstatus) {
        (LINUX_CLD_KILLED, libc::WTERMSIG(wstatus))
    } else {
        (LINUX_CLD_EXITED, 0)
    };
    let mut si: SignalfdSiginfo = unsafe { std::mem::zeroed() };
    si.ssi_signo = SIGCHLD;
    si.ssi_code = code;
    si.ssi_pid = pid as u32;
    si.ssi_status = status;
    let bytes = unsafe {
        std::slice::from_raw_parts(
            &si as *const _ as *const u8,
            std::mem::size_of::<SignalfdSiginfo>(),
        )
    };
    for st in map.values() {
        if mask_has(st.mask, SIGCHLD) {
            unsafe {
                libc::send(st.writer, bytes.as_ptr() as *const _, bytes.len(), 0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn siginfo_is_128_bytes() {
        assert_eq!(std::mem::size_of::<SignalfdSiginfo>(), 128);
    }

    #[test]
    fn mask_membership_matches_linux_sigset() {
        // Linux sigset bit (signo-1). SIGCHLD == 17 → bit 16.
        assert!(mask_has(1u64 << 16, SIGCHLD));
        assert!(!mask_has(1u64 << 15, SIGCHLD));
        assert!(mask_has(!0u64, SIGCHLD)); // sigfillset — crun blocks all
        assert!(!mask_has(0, SIGCHLD));
    }

    #[test]
    fn sigchld_delivered_to_masked_fd_and_decoded() {
        // Create a signalfd observing all signals; deliver a child exit(7)
        // and confirm the siginfo record round-trips through the socketpair.
        let mask: u64 = !0;
        let mut mp = mask;
        let fd = do_signalfd4(-1, &mut mp as *mut u64 as u64, 8, 0) as i32;
        assert!(is_signalfd(fd));

        let wstatus = 7 << 8; // WIFEXITED, WEXITSTATUS == 7
        deliver_sigchld(4321, wstatus);

        let mut buf = [0u8; 128];
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        assert_eq!(n, 128);
        let signo = u32::from_ne_bytes(buf[0..4].try_into().unwrap());
        let pid = u32::from_ne_bytes(buf[12..16].try_into().unwrap());
        let status = i32::from_ne_bytes(buf[40..44].try_into().unwrap());
        assert_eq!(signo, SIGCHLD);
        assert_eq!(pid, 4321);
        assert_eq!(status, 7);

        on_close(fd);
        assert!(!is_signalfd(fd));
        unsafe { libc::close(fd) };
    }
}
