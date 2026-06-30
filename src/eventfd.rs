//! Eventfd emulation using a self-connected AF_UNIX SOCK_DGRAM socket.
//!
//! macOS has no eventfd. The earlier emulation used a pipe and returned the pipe
//! READ end as the eventfd fd, keeping the write end in a per-process HashMap.
//! That broke SCM_RIGHTS fd-passing: a process that *received* an eventfd (as VPP
//! apps do for the session-layer message-queue doorbell) got the pipe read end
//! and could not WRITE it (write → EBADF), so it could never signal the producer.
//! VPP creates all mq eventfds and passes them to the app, and the app must
//! write() them to wake VPP in interrupt mode — every such signal was lost,
//! hanging the VCL InterruptMode / app-socket-API tests.
//!
//! A self-connected AF_UNIX SOCK_DGRAM socket fixes this: it is ONE fd (no hidden
//! second end), write() loops a datagram into its own receive buffer, and ANY
//! holder — original, fork child, or SCM_RIGHTS receiver — can both read and write
//! it because SCM_RIGHTS/fork refcount the same shared kernel socket object. So a
//! receiver needs no per-process state: raw socket read/write/poll already behave
//! as a doorbell. The per-process HashMap below only marks the *creator*'s fd so
//! its read() gets proper drain-all-and-sum eventfd counter semantics; receivers
//! fall back to one-datagram-per-read, which is functionally correct for the
//! producer/consumer wakeup pattern (at worst a benign extra wakeup).
//!
//! Each eventfd write appends an 8-byte little-endian datagram carrying the added
//! value; a creator read drains all queued datagrams and returns their sum (Linux
//! eventfd counter semantics), capped at U64_MAX-1. Buffer-full yields EAGAIN
//! (NONBLOCK) or blocks — a benign divergence: real eventfd overflows near 2^64,
//! the socket buffer overflows far sooner, but only a runaway producer with a
//! stuck consumer ever reaches it.

use crate::translate;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

struct EventfdState {
    semaphore: bool,
}

/// Maps an eventfd fd (in the creating process) → its semantics.
static EVENTFD_STATE: Mutex<Option<HashMap<i32, EventfdState>>> = Mutex::new(None);

/// Monotonic counter to make each backing socket's temp bind path unique.
static EFD_SEQ: AtomicU64 = AtomicU64::new(0);

fn with_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut HashMap<i32, EventfdState>) -> R,
{
    let mut guard = EVENTFD_STATE.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    f(guard.as_mut().unwrap())
}

// EFD flags
const EFD_SEMAPHORE: i32 = 1;
const EFD_CLOEXEC: i32 = 0o2000000; // 0x80000
const EFD_NONBLOCK: i32 = 0o4000; // 0x800

/// Send one 8-byte LE datagram carrying `val` into the (self-connected) socket.
/// Respects the fd's blocking mode. Returns the raw libc::write result.
fn socket_write_value(fd: i32, val: u64) -> i64 {
    let bytes = val.to_ne_bytes();
    unsafe { libc::write(fd, bytes.as_ptr() as *const _, 8) as i64 }
}

/// Build a self-connected AF_UNIX SOCK_DGRAM socket: bind to a unique temp path,
/// connect to that same path (so the socket's peer is itself), then unlink the
/// path — once connected, the name is irrelevant for the kernel object's life.
/// Returns the fd, or -errno on failure.
fn make_self_connected_dgram() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return -1;
    }

    // Self-loop: a write() goes to the connected peer (itself), so it lands in
    // this socket's own receive buffer and becomes readable by any holder.
    let pid = unsafe { libc::getpid() };
    let seq = EFD_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = format!("/tmp/.fl_efd_{}_{}.sock", pid, seq);

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let pbytes = path.as_bytes();
    // sun_path is i8 on macOS; copy with a trailing NUL (path is far under 104).
    for (i, &b) in pbytes.iter().enumerate() {
        addr.sun_path[i] = b as libc::c_char;
    }
    let addr_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;

    unsafe {
        let cpath = std::ffi::CString::new(pbytes).unwrap();
        libc::unlink(cpath.as_ptr()); // clear any stale name
        if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, addr_len) != 0
            || libc::connect(fd, &addr as *const _ as *const libc::sockaddr, addr_len) != 0
        {
            libc::unlink(cpath.as_ptr());
            libc::close(fd);
            return -1;
        }
        libc::unlink(cpath.as_ptr()); // name no longer needed
    }

    // Self-looped: the receive buffer IS the send buffer. Size both generously so
    // a burst of doorbell signals before the consumer drains never wedges the
    // producer (each signal is an 8-byte datagram + per-mbuf overhead).
    let bufsz: libc::c_int = 1 << 20;
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF,
            &bufsz as *const _ as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF,
            &bufsz as *const _ as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t);
    }
    fd
}

/// eventfd2(initval, flags) → fd
pub fn do_eventfd2(initval: u32, flags: i32) -> u64 {
    let fd = make_self_connected_dgram();
    if fd < 0 {
        return translate::linux_errno();
    }

    if flags & EFD_CLOEXEC != 0 {
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC); }
    }
    if flags & EFD_NONBLOCK != 0 {
        unsafe {
            let fl = libc::fcntl(fd, libc::F_GETFL, 0);
            libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }

    // Seed the initial value so it's immediately pollable + readable.
    if initval > 0 {
        socket_write_value(fd, initval as u64);
    }

    crate::syscall::note_socket_fd(fd);
    with_state(|state| {
        state.insert(fd, EventfdState { semaphore: flags & EFD_SEMAPHORE != 0 });
    });

    fd as u64
}

/// Check if fd is an eventfd created in THIS process.
pub fn is_eventfd(fd: i32) -> bool {
    let guard = EVENTFD_STATE.lock().unwrap();
    guard.as_ref().map_or(false, |s| s.contains_key(&fd))
}

/// Drain one 8-byte datagram from the socket without blocking. Returns its value,
/// or None if nothing is queued.
fn recv_one(fd: i32) -> Option<u64> {
    let mut rec = [0u8; 8];
    let r = unsafe {
        libc::recv(fd, rec.as_mut_ptr() as *mut _, 8, libc::MSG_DONTWAIT)
    };
    if r == 8 {
        Some(u64::from_ne_bytes(rec))
    } else {
        None
    }
}

/// Handle read on an eventfd (the creating process). Drains the socket and
/// returns the eventfd counter value with proper semantics:
///  - default: sum of all queued datagram values (capped at U64_MAX-1),
///  - EFD_SEMAPHORE: returns 1 and decrements by 1 (re-queues the remainder),
///    which stays stateless and SCM_RIGHTS-safe.
/// A receiver (is_eventfd false in its process) is NOT routed here; its raw
/// socket read returns a single datagram, which is fine for the doorbell pattern.
pub fn do_read(fd: i32, buf: u64, count: u64) -> u64 {
    if count < 8 {
        return (-22_i64) as u64; // -EINVAL: must read at least 8 bytes
    }
    if !is_eventfd(fd) {
        return (-9_i64) as u64; // -EBADF
    }

    let semaphore = with_state(|state| state.get(&fd).map(|e| e.semaphore).unwrap_or(false));

    if semaphore {
        // Return 1 per read; if the head datagram carried > 1, re-queue the rest.
        match recv_one(fd) {
            Some(v) => {
                if v > 1 {
                    socket_write_value(fd, v - 1);
                }
                unsafe { (buf as *mut u64).write_unaligned(1); }
                8u64
            }
            None => (-11_i64) as u64, // -EAGAIN
        }
    } else {
        let mut sum: u64 = 0;
        let mut got_any = false;
        while let Some(v) = recv_one(fd) {
            got_any = true;
            // Real eventfd caps the counter at U64_MAX-1; if adding would exceed,
            // re-queue the remainder and stop so the next read picks it up.
            if sum > (u64::MAX - 1) - v {
                let kept = (u64::MAX - 1) - sum;
                socket_write_value(fd, v - kept);
                sum += kept;
                break;
            }
            sum += v;
        }
        if !got_any {
            return (-11_i64) as u64; // -EAGAIN
        }
        unsafe { (buf as *mut u64).write_unaligned(sum); }
        8u64
    }
}

/// Handle write on an eventfd (the creating process): append the value as an
/// 8-byte datagram to the (shared, self-connected) socket. A receiver process
/// is not routed here — its raw socket write produces the same datagram, which
/// is exactly the fix: an SCM_RIGHTS-passed eventfd is now writable.
pub fn do_write(fd: i32, buf: u64, count: u64) -> u64 {
    if count < 8 {
        return (-22_i64) as u64; // -EINVAL: must write 8 bytes
    }

    let val = unsafe { (buf as *const u64).read_unaligned() };
    if val == u64::MAX {
        return (-22_i64) as u64; // -EINVAL: 0xff..ff is reserved
    }
    if val == 0 {
        return 8u64; // adding 0 is a no-op, no notification
    }

    let w = socket_write_value(fd, val);
    if w != 8 {
        return translate::linux_errno(); // buffer full (EFD_NONBLOCK) or error
    }
    8u64
}

/// Clean up eventfd state when closed. The backing socket fd itself is closed by
/// the normal close path; here we only drop the creator's semantics marker.
pub fn on_close(fd: i32) {
    let mut guard = EVENTFD_STATE.lock().unwrap();
    if let Some(state) = guard.as_mut() {
        state.remove(&fd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev_read(fd: i32) -> Option<u64> {
        let mut v: u64 = 0;
        let r = do_read(fd, &mut v as *mut u64 as u64, 8);
        if r == 8 { Some(v) } else { None }
    }
    fn ev_write(fd: i32, val: u64) -> u64 {
        do_write(fd, &val as *const u64 as u64, 8)
    }

    #[test]
    fn write_read_sums_counter() {
        let fd = do_eventfd2(0, EFD_NONBLOCK) as i32;
        assert!(fd >= 0);
        assert!(is_eventfd(fd));
        assert_eq!(ev_write(fd, 3), 8);
        assert_eq!(ev_write(fd, 2), 8);
        assert_eq!(ev_read(fd), Some(5), "read must return the summed counter");
        // Drained: a non-blocking read now yields EAGAIN.
        assert_eq!(ev_read(fd), None);
        on_close(fd);
        unsafe { libc::close(fd); }
    }

    #[test]
    fn initval_is_readable() {
        let fd = do_eventfd2(7, EFD_NONBLOCK) as i32;
        assert_eq!(ev_read(fd), Some(7));
        on_close(fd);
        unsafe { libc::close(fd); }
    }

    #[test]
    fn semaphore_returns_one_per_read() {
        let fd = do_eventfd2(0, EFD_NONBLOCK | EFD_SEMAPHORE) as i32;
        assert_eq!(ev_write(fd, 3), 8);
        assert_eq!(ev_read(fd), Some(1));
        assert_eq!(ev_read(fd), Some(1));
        assert_eq!(ev_read(fd), Some(1));
        assert_eq!(ev_read(fd), None, "semaphore drained after 3 reads");
        on_close(fd);
        unsafe { libc::close(fd); }
    }

    #[test]
    fn receiver_raw_write_is_visible_to_creator() {
        // Reproduces the SCM_RIGHTS bug at the syscall layer: a "receiver" that
        // does NOT have is_eventfd state (here: a dup'd fd number) must still be
        // able to write the eventfd, and the creator must see it. With the old
        // pipe backing the dup was a pipe read-end and the raw write got EBADF.
        let fd = do_eventfd2(0, EFD_NONBLOCK) as i32;
        let dup = unsafe { libc::dup(fd) };
        assert!(dup >= 0);
        assert!(!is_eventfd(dup), "the dup has no eventfd state (like an SCM_RIGHTS receiver)");
        // Raw write on the receiver-style fd (8-byte LE value 1).
        let one: u64 = 1;
        let w = unsafe { libc::write(dup, &one as *const _ as *const libc::c_void, 8) };
        assert_eq!(w, 8, "receiver write to a passed eventfd must succeed (was EBADF)");
        // Creator drains and sees it.
        assert_eq!(ev_read(fd), Some(1), "creator must see the receiver's signal");
        unsafe { libc::close(dup); }
        on_close(fd);
        unsafe { libc::close(fd); }
    }
}
