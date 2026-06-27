//! Eventfd emulation using pipe pairs.
//!
//! Each eventfd is backed by a pipe; the read end is returned as the eventfd fd.
//! macOS has no eventfd, so the VALUE lives entirely in the pipe: every write
//! appends an 8-byte little-endian record, and a read drains all pending records
//! and returns their sum (Linux eventfd counter semantics). The pipe is the only
//! state, so this is CROSS-PROCESS safe: when an eventfd fd is passed to an
//! unrelated process via SCM_RIGHTS (as VPP does for its svm_msg_q API
//! notification), that process can poll and read it correctly even though it has
//! no local HashMap entry — it just reads raw 8-byte records from the shared pipe.
//!
//! The earlier per-process-counter design broke cross-process: it only poked the
//! pipe on a 0->nonzero counter transition, but a remote consumer reading the
//! pipe directly never reset the owner's counter, so every later write was
//! suppressed and the consumer's no-timeout poll() blocked forever (the VPP API
//! "read failed" hang).

use crate::translate;
use std::collections::HashMap;
use std::sync::Mutex;

struct EventfdState {
    write_pipe_fd: i32, // internal write end of the pipe
}

/// Append an 8-byte LE record of `val` to an eventfd's pipe (the shared state).
fn pipe_write_value(write_fd: i32, val: u64) -> i64 {
    let bytes = val.to_ne_bytes();
    unsafe { libc::write(write_fd, bytes.as_ptr() as *const _, 8) as i64 }
}

/// Maps eventfd read_fd → internal state
static EVENTFD_STATE: Mutex<Option<HashMap<i32, EventfdState>>> = Mutex::new(None);

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
const _EFD_SEMAPHORE: i32 = 1;
const EFD_CLOEXEC: i32 = 0o2000000;  // 0x80000
const EFD_NONBLOCK: i32 = 0o4000;     // 0x800

/// eventfd2(initval, flags) → fd
pub fn do_eventfd2(initval: u32, flags: i32) -> u64 {
    let mut pipefd: [i32; 2] = [0; 2];
    let ret = unsafe { libc::pipe(pipefd.as_mut_ptr()) };
    if ret < 0 {
        return translate::linux_errno();
    }

    let read_fd = pipefd[0];
    let write_fd = pipefd[1];

    // Apply flags
    if flags & EFD_CLOEXEC != 0 {
        unsafe {
            libc::fcntl(read_fd, libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(write_fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    if flags & EFD_NONBLOCK != 0 {
        unsafe {
            libc::fcntl(read_fd, libc::F_SETFL, libc::O_NONBLOCK);
            libc::fcntl(write_fd, libc::F_SETFL, libc::O_NONBLOCK);
        }
    }

    // Seed the initial value as a pipe record (makes it pollable + readable).
    if initval > 0 {
        pipe_write_value(write_fd, initval as u64);
    }

    with_state(|state| {
        state.insert(read_fd, EventfdState {
            write_pipe_fd: write_fd,
        });
    });

    read_fd as u64
}

/// Check if fd is an eventfd
pub fn is_eventfd(fd: i32) -> bool {
    let guard = EVENTFD_STATE.lock().unwrap();
    guard.as_ref().map_or(false, |s| s.contains_key(&fd))
}

/// Handle read on an eventfd (the OWNER process): drain all pending 8-byte
/// records from the pipe and return their sum. A cross-process consumer that
/// received the fd via SCM_RIGHTS is NOT routed here (is_eventfd is false in its
/// process) — it reads raw 8-byte records straight from the shared pipe, one per
/// read(), which is exactly correct.
pub fn do_read(fd: i32, buf: u64, count: u64) -> u64 {
    if count < 8 {
        return (-22_i64) as u64; // -EINVAL: must read exactly 8 bytes
    }
    // The fd must be a known eventfd in this process.
    if !is_eventfd(fd) {
        return (-9_i64) as u64; // -EBADF
    }

    // Drain all currently-available records (poll(0) probe before each read so we
    // never block on the drain, regardless of the fd's blocking mode).
    let mut sum: u64 = 0;
    let mut got_any = false;
    loop {
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let pr = unsafe { libc::poll(&mut pfd, 1, 0) };
        if pr <= 0 || (pfd.revents & libc::POLLIN) == 0 {
            break;
        }
        let mut rec = [0u8; 8];
        let r = unsafe { libc::read(fd, rec.as_mut_ptr() as *mut _, 8) };
        if r == 8 {
            sum = sum.saturating_add(u64::from_ne_bytes(rec));
            got_any = true;
        } else {
            break;
        }
    }

    if !got_any {
        return (-11_i64) as u64; // -EAGAIN (no value; caller polls before reading)
    }
    unsafe { (buf as *mut u64).write_unaligned(sum); }
    8u64 // eventfd read always returns 8 bytes
}

/// Handle write on an eventfd: append the value as a record to the (shared) pipe.
pub fn do_write(fd: i32, buf: u64, count: u64) -> u64 {
    if count < 8 {
        return (-22_i64) as u64; // -EINVAL: must write exactly 8 bytes
    }

    let val = unsafe { (buf as *const u64).read_unaligned() };
    if val == u64::MAX {
        return (-22_i64) as u64; // -EINVAL: 0xff..ff is reserved
    }
    if val == 0 {
        return 8u64; // adding 0 is a no-op, no notification
    }

    let write_fd = with_state(|state| match state.get(&fd) {
        Some(e) => e.write_pipe_fd,
        None => -1,
    });
    if write_fd < 0 {
        return (-9_i64) as u64; // -EBADF
    }

    let w = pipe_write_value(write_fd, val);
    if w != 8 {
        return translate::linux_errno(); // pipe full (EFD_NONBLOCK) or error
    }
    8u64 // eventfd write always returns 8 bytes
}

/// Clean up eventfd state when closed
pub fn on_close(fd: i32) {
    let mut guard = EVENTFD_STATE.lock().unwrap();
    if let Some(state) = guard.as_mut() {
        if let Some(entry) = state.remove(&fd) {
            // Close the internal write end
            unsafe { libc::close(entry.write_pipe_fd); }
        }
    }
}
