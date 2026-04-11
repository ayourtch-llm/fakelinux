//! Eventfd emulation using pipe pairs and in-process counters.
//!
//! Each eventfd is backed by a pipe. The read end is returned as the eventfd fd.
//! A global counter tracks the accumulated value. When counter > 0, one byte is
//! kept in the pipe to make it pollable. On read, the counter is returned and
//! reset to 0, and the pipe is drained.

use crate::translate;
use std::collections::HashMap;
use std::sync::Mutex;

struct EventfdState {
    write_pipe_fd: i32,  // internal write end of the pipe
    counter: u64,
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

    let counter = initval as u64;

    // If initial value > 0, make the pipe readable
    if counter > 0 {
        let byte: u8 = 1;
        unsafe { libc::write(write_fd, &byte as *const _ as *const _, 1); }
    }

    with_state(|state| {
        state.insert(read_fd, EventfdState {
            write_pipe_fd: write_fd,
            counter,
        });
    });

    read_fd as u64
}

/// Check if fd is an eventfd
pub fn is_eventfd(fd: i32) -> bool {
    let guard = EVENTFD_STATE.lock().unwrap();
    guard.as_ref().map_or(false, |s| s.contains_key(&fd))
}

/// Handle read on an eventfd: returns counter value as u64, resets to 0
pub fn do_read(fd: i32, buf: u64, count: u64) -> u64 {
    if count < 8 {
        return (-22_i64) as u64; // -EINVAL: must read exactly 8 bytes
    }

    with_state(|state| {
        let entry = match state.get_mut(&fd) {
            Some(e) => e,
            None => return (-9_i64) as u64, // -EBADF
        };

        if entry.counter == 0 {
            // Would block - return EAGAIN (Linux errno 11)
            return (-11_i64) as u64;
        }

        let val = entry.counter;
        entry.counter = 0;

        // Drain the wake byte from the pipe
        let mut drain_byte: u8 = 0;
        unsafe { libc::read(fd, &mut drain_byte as *mut _ as *mut _, 1); }

        // Write the counter value to the user buffer
        unsafe {
            (buf as *mut u64).write_unaligned(val);
        }

        8u64 // eventfd read always returns 8 bytes
    })
}

/// Handle write on an eventfd: add value to counter
pub fn do_write(fd: i32, buf: u64, count: u64) -> u64 {
    if count < 8 {
        return (-22_i64) as u64; // -EINVAL: must write exactly 8 bytes
    }

    let val = unsafe { (buf as *const u64).read_unaligned() };

    // 0xfffffffffffffffe is the max addable value
    if val == u64::MAX {
        return (-22_i64) as u64; // -EINVAL
    }

    with_state(|state| {
        let entry = match state.get_mut(&fd) {
            Some(e) => e,
            None => return (-9_i64) as u64, // -EBADF
        };

        let was_zero = entry.counter == 0;
        entry.counter = entry.counter.saturating_add(val);

        // If counter went from 0 to non-zero, make the pipe readable
        if was_zero && entry.counter > 0 {
            let byte: u8 = 1;
            unsafe {
                libc::write(entry.write_pipe_fd, &byte as *const _ as *const _, 1);
            }
        }

        8u64 // eventfd write always returns 8 bytes
    })
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
