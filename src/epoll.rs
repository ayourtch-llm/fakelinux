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
    // Read the Linux epoll_event. struct epoll_event is packed (12 bytes,
    // data at offset 4) ONLY on x86_64; on aarch64 it has natural alignment:
    // { u32 events; u64 data; } = 16 bytes, data at offset 8.
    let (events, data) = if event_ptr != 0 {
        unsafe {
            let ptr = event_ptr as *const u8;
            let ev = (ptr as *const u32).read_unaligned();
            let d = (ptr.add(8) as *const u64).read_unaligned();
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
    // Look up the kqueue fd — do NOT clone registrations here. We need to
    // look up user_data PER KEVENT at writeback time against the LIVE state.
    // Cloning at entry froze a snapshot that became stale while we slept in
    // kevent(): another thread could epoll_ctl_ADD a fresh fd (often the
    // same fd number reused after close), and the event for it came back
    // with user_data=0 from our snapshot, causing Go's runtime netpoll to
    // dereference a NULL pollDesc and SIGSEGV.
    let kq = {
        let guard = EPOLL_STATE.lock().unwrap();
        match guard.as_ref().and_then(|s| s.get(&epfd)) {
            Some(inst) => inst.kqueue_fd,
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
    // Occasionally upgrade a non-blocking (0-timeout) poll to a brief 1ms wait so
    // macOS gets a window to deliver a process-directed signal (e.g. SIGTERM) to
    // a handler-capable thread — otherwise a busy-polling guest (VPP) can leave
    // the signal stuck pending forever and never shut down. See
    // signal::signal_delivery_window_due().
    let timeout_ms = if timeout_ms == 0 && crate::signal::signal_delivery_window_due() {
        1
    } else {
        timeout_ms
    };
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

    // Look up user_data per-kevent against the LIVE registrations state.
    let user_data_lookup = |fd: i32| -> Option<u64> {
        let guard = EPOLL_STATE.lock().unwrap();
        guard.as_ref()
            .and_then(|s| s.get(&epfd))
            .and_then(|inst| inst.registrations.get(&fd).map(|&(_, d)| d))
    };

    for i in 0..n as usize {
        let kev = &kevents[i];
        let fd = kev.ident as i32;

        let user_data = match user_data_lookup(fd) {
            Some(d) => d,
            None => {
                // kqueue can deliver tail events for a fd we've already DEL'd
                // (race with sibling thread's epoll_ctl_DEL, or queued event
                // racing close). Drop them silently — surfacing user_data=0
                // makes Go's netpoll dereference a NULL pollDesc.
                continue;
            }
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

        // Write the Linux aarch64 epoll_event: { u32 events; u64 data; },
        // 16 bytes with data at offset 8 (packed 12-byte layout is x86_64-only).
        let offset = count as usize * 16;
        unsafe {
            let ptr = out.add(offset);
            (ptr as *mut u32).write_unaligned(epoll_events);
            (ptr.add(8) as *mut u64).write_unaligned(user_data);
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

/// Rebuild every epoll instance in a freshly-forked child.
///
/// A kqueue descriptor is NOT inherited across fork() on macOS/BSD: the fd
/// number survives in the child's table but the underlying kqueue is dead,
/// so the next kevent() returns EBADF. Go's runtime forks (rootless re-exec)
/// and keeps running with its netpoller epoll fd — that dead kqueue made
/// epoll_wait fail with EBADF and crashed the runtime ("runtime: netpoll
/// failed"). For each tracked epoll fd we create a fresh kqueue, dup2 it
/// back onto the same fd number the guest holds, and replay the
/// registrations so the child's epoll keeps working.
pub fn rebuild_after_fork() {
    let mut guard = EPOLL_STATE.lock().unwrap();
    let state = match guard.as_mut() {
        Some(s) if !s.is_empty() => s,
        _ => return,
    };
    for inst in state.values_mut() {
        let old_fd = inst.kqueue_fd;
        let new_kq = unsafe { libc::kqueue() };
        if new_kq < 0 {
            continue;
        }
        // Move the fresh kqueue onto the fd number the guest already holds.
        if new_kq != old_fd {
            if unsafe { libc::dup2(new_kq, old_fd) } < 0 {
                unsafe { libc::close(new_kq) };
                continue;
            }
            unsafe { libc::close(new_kq) };
        }
        // Replay all registrations onto the new (same-numbered) kqueue.
        for (&fd, &(events, _data)) in inst.registrations.iter() {
            apply_kevents(old_fd, fd, events, true);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoll_event_uses_aarch64_layout() {
        // Linux struct epoll_event is __attribute__((packed)) ONLY on x86_64.
        // On aarch64 it has natural alignment: { u32 events; u64 data; } =
        // 16 bytes, data at offset 8. Using the packed 12-byte layout fed
        // VPP's vlib_file_poll garbage pool indices via event.data → wild
        // pointer SIGSEGV in the brk zone.
        let ep = do_epoll_create1(0) as i32;
        assert!(ep >= 0);
        let mut p1 = [0i32; 2];
        let mut p2 = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(p1.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { libc::pipe(p2.as_mut_ptr()) }, 0);

        // Register both read ends with magic u64 data at aarch64 offset 8.
        for (rfd, magic) in [(p1[0], 0xdead_beef_cafe_f00du64), (p2[0], 0x1122_3344_5566_7788u64)] {
            let mut ev = [0u8; 16];
            ev[0..4].copy_from_slice(&EPOLLIN.to_le_bytes());
            ev[8..16].copy_from_slice(&magic.to_le_bytes());
            assert_eq!(do_epoll_ctl(ep, EPOLL_CTL_ADD, rfd, ev.as_ptr() as u64), 0);
        }
        // Make both readable.
        assert_eq!(unsafe { libc::write(p1[1], b"a".as_ptr() as *const _, 1) }, 1);
        assert_eq!(unsafe { libc::write(p2[1], b"b".as_ptr() as *const _, 1) }, 1);

        // Poison the output buffer to catch stale bytes at wrong offsets.
        let mut out = [0xAAu8; 32];
        let n = do_epoll_pwait(ep, out.as_mut_ptr() as u64, 2, 1000, 0);
        assert_eq!(n, 2, "expected both fds ready, got {}", n as i64);

        let mut datas = Vec::new();
        for i in 0..2 {
            let base = i * 16; // 16-byte stride on aarch64
            let events = u32::from_le_bytes(out[base..base + 4].try_into().unwrap());
            assert!(events & EPOLLIN != 0, "entry {} missing EPOLLIN: {:#x}", i, events);
            datas.push(u64::from_le_bytes(out[base + 8..base + 16].try_into().unwrap()));
        }
        datas.sort();
        assert_eq!(datas, vec![0x1122_3344_5566_7788, 0xdead_beef_cafe_f00d]);

        unsafe {
            libc::close(p1[0]); libc::close(p1[1]);
            libc::close(p2[0]); libc::close(p2[1]);
            libc::close(ep);
        }
        on_close(ep);
    }
}
