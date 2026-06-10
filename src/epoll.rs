//! Epoll emulation via macOS kqueue.
//!
//! epoll_create1 → kqueue()
//! epoll_ctl → kevent() with EV_ADD/EV_DELETE
//! epoll_pwait → kevent() with timeout

use crate::translate;
use std::collections::HashMap;
use std::sync::Mutex;

/// Per-epoll-fd state: maps (fd, filter) → stored epoll_event data (the user's u64).
/// We also track which kqueue fd backs each epoll fd.
struct EpollInstance {
    kqueue_fd: i32,
    /// Map from monitored fd → (events_mask, user_data)
    registrations: HashMap<i32, (u32, u64)>,
}

static EPOLL_STATE: Mutex<Option<HashMap<i32, EpollInstance>>> = Mutex::new(None);

fn with_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut HashMap<i32, EpollInstance>) -> R,
{
    let mut guard = EPOLL_STATE.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    f(guard.as_mut().unwrap())
}

// Epoll event flags
const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLLET: u32 = 0x80000000;
const EPOLLONESHOT: u32 = 0x40000000;

// Epoll ctl operations
const EPOLL_CTL_ADD: i32 = 1;
const EPOLL_CTL_DEL: i32 = 2;
const EPOLL_CTL_MOD: i32 = 3;

// EPOLL_CLOEXEC
const EPOLL_CLOEXEC: i32 = 0x80000;

/// epoll_create1(flags) → fd
pub fn do_epoll_create1(flags: i32) -> u64 {
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        return translate::linux_errno();
    }

    if flags & EPOLL_CLOEXEC != 0 {
        unsafe { libc::fcntl(kq, libc::F_SETFD, libc::FD_CLOEXEC); }
    }

    with_state(|state| {
        state.insert(kq, EpollInstance {
            kqueue_fd: kq,
            registrations: HashMap::new(),
        });
    });

    // The kqueue fd IS the epoll fd (same fd number)
    kq as u64
}

/// epoll_ctl(epfd, op, fd, event_ptr) → 0 or -errno
pub fn do_epoll_ctl(epfd: i32, op: i32, fd: i32, event_ptr: u64) -> u64 {
    // Read the packed Linux epoll_event: u32 events + u64 data (12 bytes, packed)
    let (events, data) = if event_ptr != 0 {
        unsafe {
            let ptr = event_ptr as *const u8;
            let ev = (ptr as *const u32).read_unaligned();
            let d = (ptr.add(4) as *const u64).read_unaligned();
            (ev, d)
        }
    } else {
        (0u32, 0u64)
    };

    with_state(|state| {
        let instance = match state.get_mut(&epfd) {
            Some(inst) => inst,
            None => return (-9_i64) as u64, // -EBADF
        };
        let kq = instance.kqueue_fd;

        match op {
            EPOLL_CTL_ADD => {
                if instance.registrations.contains_key(&fd) {
                    return (-17_i64) as u64; // -EEXIST
                }
                let ret = apply_kevents(kq, fd, events, true);
                if ret != 0 {
                    return ret;
                }
                instance.registrations.insert(fd, (events, data));
                0
            }
            EPOLL_CTL_DEL => {
                let old = match instance.registrations.remove(&fd) {
                    Some(o) => o,
                    None => return (-2_i64) as u64, // -ENOENT
                };
                remove_kevents(kq, fd, old.0);
                0
            }
            EPOLL_CTL_MOD => {
                let old = match instance.registrations.get(&fd) {
                    Some(o) => *o,
                    None => return (-2_i64) as u64, // -ENOENT
                };
                // Delete old filters then add new ones
                remove_kevents(kq, fd, old.0);
                let ret = apply_kevents(kq, fd, events, true);
                if ret != 0 {
                    return ret;
                }
                instance.registrations.insert(fd, (events, data));
                0
            }
            _ => (-22_i64) as u64, // -EINVAL
        }
    })
}

/// epoll_pwait(epfd, events_ptr, maxevents, timeout_ms, sigmask, sigsetsize) → count or -errno
pub fn do_epoll_pwait(
    epfd: i32,
    events_ptr: u64,
    maxevents: i32,
    timeout_ms: i32,
    sigmask_ptr: u64,
) -> u64 {
    // Look up the kqueue fd and registrations
    let (kq, registrations) = {
        let guard = EPOLL_STATE.lock().unwrap();
        match guard.as_ref().and_then(|s| s.get(&epfd)) {
            Some(inst) => {
                (inst.kqueue_fd, inst.registrations.clone())
            }
            None => return (-9_i64) as u64, // -EBADF
        }
    };

    // Same wait discipline as do_ppoll (see there): swap GUEST_SIGMASK for
    // the wait, unblock host signals (we're inside the trap handler whose
    // sa_mask blocks everything), wait in chunks, EINTR when a pending
    // signal with a real handler becomes deliverable.
    let old_mask = if sigmask_ptr != 0 {
        let new_mask = unsafe { (sigmask_ptr as *const u64).read_unaligned() };
        Some(crate::signal::ppoll_mask_begin(new_mask))
    } else {
        None
    };
    let _unblock = crate::signal::HostSigUnblock::new();

    let mut kevents: Vec<libc::kevent> = vec![unsafe { std::mem::zeroed() }; maxevents as usize];

    const CHUNK_MS: i64 = 100;
    let mut remaining: i64 = timeout_ms as i64;
    let infinite = timeout_ms < 0;
    let n: i64 = loop {
        if crate::signal::deliverable_pending() != 0 {
            break -1000; // sentinel: EINTR via pending guest signal
        }
        let chunk_ms = if infinite { CHUNK_MS } else { remaining.min(CHUNK_MS).max(0) };
        let chunk_ts = libc::timespec {
            tv_sec: chunk_ms / 1000,
            tv_nsec: (chunk_ms % 1000) * 1_000_000,
        };
        let r = unsafe {
            libc::kevent(
                kq,
                std::ptr::null(),
                0,
                kevents.as_mut_ptr(),
                maxevents,
                &chunk_ts,
            )
        };
        if r < 0 {
            let host_errno = unsafe { *libc::__error() };
            if host_errno == libc::EINTR { continue; }
            break -2000; // sentinel: host error, errno still set
        }
        if r > 0 { break r as i64; }
        if !infinite {
            remaining -= chunk_ms;
            if remaining <= 0 { break 0; } // timed out
        }
    };

    drop(_unblock);
    if let Some(old) = old_mask {
        crate::signal::ppoll_mask_end(old);
    }
    if n == -1000 {
        return (-4_i64) as u64; // -EINTR
    }
    if n == -2000 {
        return translate::linux_errno();
    }

    // Convert kevents back to Linux epoll_events
    let out = events_ptr as *mut u8;
    let mut count = 0i32;

    for i in 0..n as usize {
        let kev = &kevents[i];
        let fd = kev.ident as i32;

        // Look up the user data for this fd
        let user_data = match registrations.get(&fd) {
            Some(&(_, data)) => data,
            None => 0,
        };

        let mut epoll_events: u32 = 0;
        match kev.filter {
            libc::EVFILT_READ => epoll_events |= EPOLLIN,
            libc::EVFILT_WRITE => epoll_events |= EPOLLOUT,
            _ => {}
        }
        if kev.flags & libc::EV_EOF != 0 {
            epoll_events |= EPOLLHUP;
        }
        if kev.flags & libc::EV_ERROR != 0 {
            epoll_events |= EPOLLERR;
        }

        // Write packed Linux epoll_event: u32 events + u64 data (12 bytes)
        let offset = count as usize * 12;
        unsafe {
            let ptr = out.add(offset);
            (ptr as *mut u32).write_unaligned(epoll_events);
            (ptr.add(4) as *mut u64).write_unaligned(user_data);
        }
        count += 1;
    }

    count as u64
}

/// Check if an fd is a kqueue-backed epoll fd (for close cleanup)
pub fn is_epoll_fd(fd: i32) -> bool {
    let guard = EPOLL_STATE.lock().unwrap();
    guard.as_ref().map_or(false, |s| s.contains_key(&fd))
}

/// Clean up epoll state when fd is closed
pub fn on_close(fd: i32) {
    let mut guard = EPOLL_STATE.lock().unwrap();
    if let Some(state) = guard.as_mut() {
        state.remove(&fd);
    }
}

/// Register kevents for a given fd and event mask. Returns 0 on success.
fn apply_kevents(kq: i32, fd: i32, events: u32, _add: bool) -> u64 {
    let mut changes: Vec<libc::kevent> = Vec::new();
    let mut flags: u16 = libc::EV_ADD;
    if events & EPOLLET != 0 {
        flags |= libc::EV_CLEAR;
    }
    if events & EPOLLONESHOT != 0 {
        flags |= libc::EV_ONESHOT;
    }

    if events & EPOLLIN != 0 {
        changes.push(libc::kevent {
            ident: fd as usize,
            filter: libc::EVFILT_READ,
            flags,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        });
    }
    if events & EPOLLOUT != 0 {
        changes.push(libc::kevent {
            ident: fd as usize,
            filter: libc::EVFILT_WRITE,
            flags,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        });
    }

    if changes.is_empty() {
        return 0;
    }

    let ret = unsafe {
        libc::kevent(
            kq,
            changes.as_ptr(),
            changes.len() as i32,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    if ret < 0 {
        translate::linux_errno()
    } else {
        0
    }
}

/// Remove kevents for a given fd
fn remove_kevents(kq: i32, fd: i32, events: u32) {
    let mut changes: Vec<libc::kevent> = Vec::new();
    let flags: u16 = libc::EV_DELETE;

    if events & EPOLLIN != 0 {
        changes.push(libc::kevent {
            ident: fd as usize,
            filter: libc::EVFILT_READ,
            flags,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        });
    }
    if events & EPOLLOUT != 0 {
        changes.push(libc::kevent {
            ident: fd as usize,
            filter: libc::EVFILT_WRITE,
            flags,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        });
    }

    if !changes.is_empty() {
        unsafe {
            libc::kevent(
                kq,
                changes.as_ptr(),
                changes.len() as i32,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            );
        }
    }
}
