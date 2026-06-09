//! POSIX per-process timers (timer_create / timer_settime / timer_gettime /
//! timer_delete) emulated with a host dispatcher thread.
//!
//! Two delivery paths when a timer expires:
//! - Classic signals (1..31) with a macOS equivalent: kill(getpid(), mac_sig)
//!   — the signal_forwarder builds the guest sigframe as usual.
//! - RT signals (>=32, e.g. glibc's SIGTIMER for SIGEV_THREAD timers): no
//!   macOS equivalent exists. We queue a siginfo payload (SI_TIMER + sival)
//!   and set the PENDING_SIGNALS bit; the glibc timer helper thread sitting
//!   in rt_sigtimedwait polls and consumes it, then runs the user callback.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};

pub const SI_TIMER: i32 = -2;
const TIMER_ABSTIME: u64 = 1;

/// A queued Linux siginfo payload for rt_sigtimedwait consumers.
#[derive(Clone, Copy)]
pub struct QueuedSiginfo {
    pub signo: i32,
    pub code: i32,
    pub sival: u64,
    pub tid: i32,     // si_timerid for SI_TIMER
    pub overrun: i32,
}

static SIGINFO_QUEUE: Mutex<Vec<QueuedSiginfo>> = Mutex::new(Vec::new());

/// Pop a queued siginfo whose signal is in `set` (Linux signal bitmask,
/// bit N-1 = signal N). Used by rt_sigtimedwait. try_lock so a poll loop
/// in trap context can never deadlock — worst case it retries next tick.
pub fn pop_queued_siginfo(set: u64) -> Option<QueuedSiginfo> {
    let mut q = SIGINFO_QUEUE.try_lock().ok()?;
    let idx = q
        .iter()
        .position(|si| si.signo >= 1 && si.signo <= 64 && set & (1u64 << (si.signo - 1)) != 0)?;
    Some(q.remove(idx))
}

#[derive(Clone, Copy)]
struct GuestTimer {
    in_use: bool,
    /// Linux signal to raise on expiry.
    signo: i32,
    /// sigev_value.sival_ptr passed at creation (glibc: its struct timer*).
    sival: u64,
    /// Armed absolute deadline (monotonic ns); None = disarmed.
    deadline_ns: Option<u64>,
    /// Re-arm interval in ns (0 = one-shot).
    interval_ns: u64,
}

const MAX_TIMERS: usize = 64;
static TIMERS: Mutex<[GuestTimer; MAX_TIMERS]> = Mutex::new(
    [GuestTimer { in_use: false, signo: 0, sival: 0, deadline_ns: None, interval_ns: 0 }; MAX_TIMERS],
);
static TIMERS_CV: Condvar = Condvar::new();
static DISPATCHER_RUNNING: AtomicBool = AtomicBool::new(false);

fn monotonic_ns() -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Compute the next deadline after firing: for interval timers, advance by
/// the interval (catching up past `now`); one-shot timers disarm.
pub fn next_deadline(fired_deadline: u64, interval_ns: u64, now: u64) -> Option<u64> {
    if interval_ns == 0 {
        return None;
    }
    let mut next = fired_deadline.saturating_add(interval_ns);
    while next <= now {
        next = next.saturating_add(interval_ns);
    }
    Some(next)
}

/// Parse a Linux struct sigevent: sigev_value @0 (8B), sigev_signo @8 (i32),
/// sigev_notify @12 (i32). Returns (signo, sival, notify).
pub fn parse_sigevent(buf: &[u8]) -> Option<(i32, u64, i32)> {
    if buf.len() < 16 {
        return None;
    }
    let sival = u64::from_le_bytes(buf[0..8].try_into().ok()?);
    let signo = i32::from_le_bytes(buf[8..12].try_into().ok()?);
    let notify = i32::from_le_bytes(buf[12..16].try_into().ok()?);
    Some((signo, sival, notify))
}

/// Read a Linux struct itimerspec {interval, value} (4 x i64) into ns.
/// Returns (interval_ns, value_ns).
pub fn parse_itimerspec(buf: &[u8]) -> Option<(u64, u64)> {
    if buf.len() < 32 {
        return None;
    }
    let f = |off: usize| i64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
    let (isec, insec, vsec, vnsec) = (f(0), f(8), f(16), f(24));
    if isec < 0 || vsec < 0 || !(0..1_000_000_000).contains(&insec) || !(0..1_000_000_000).contains(&vnsec) {
        return None;
    }
    Some((
        isec as u64 * 1_000_000_000 + insec as u64,
        vsec as u64 * 1_000_000_000 + vnsec as u64,
    ))
}

fn trace_on() -> bool {
    std::env::var_os("FAKELINUX_TRACE").is_some()
}

fn fire_timer(id: usize, t: GuestTimer) {
    if trace_on() {
        crate::syscall::raw_eprintln_fmt(format_args!(
            "fakelinux: timer FIRE id={} signo={} sival={:#x}\n", id, t.signo, t.sival));
    }
    if t.signo >= 32 || crate::signal::linux_to_mac(t.signo).is_none() {
        // RT signal: queue payload + set pending bit; the rt_sigtimedwait
        // poll loop (glibc timer helper thread) consumes it.
        if let Ok(mut q) = SIGINFO_QUEUE.lock() {
            if q.len() < 128 {
                q.push(QueuedSiginfo {
                    signo: t.signo,
                    code: SI_TIMER,
                    sival: t.sival,
                    tid: id as i32,
                    overrun: 0,
                });
            }
        }
        if t.signo >= 1 && t.signo <= 64 {
            crate::signal::PENDING_SIGNALS.fetch_or(1u64 << (t.signo - 1), Ordering::SeqCst);
        }
    } else if let Some(mac_sig) = crate::signal::linux_to_mac(t.signo) {
        unsafe {
            libc::kill(libc::getpid(), mac_sig);
        }
    }
}

fn dispatcher_loop() {
    let mut guard = TIMERS.lock().unwrap();
    loop {
        let now = monotonic_ns();
        // Fire everything due, compute nearest future deadline.
        let mut nearest: Option<u64> = None;
        for id in 0..MAX_TIMERS {
            let t = guard[id];
            if !t.in_use {
                continue;
            }
            if let Some(d) = t.deadline_ns {
                if d <= now {
                    guard[id].deadline_ns = next_deadline(d, t.interval_ns, now);
                    drop(guard);
                    fire_timer(id, t);
                    guard = TIMERS.lock().unwrap();
                    if let Some(nd) = guard[id].deadline_ns {
                        nearest = Some(nearest.map_or(nd, |n: u64| n.min(nd)));
                    }
                } else {
                    nearest = Some(nearest.map_or(d, |n: u64| n.min(d)));
                }
            }
        }
        let wait = match nearest {
            Some(d) => std::time::Duration::from_nanos(d.saturating_sub(monotonic_ns()).max(1)),
            None => std::time::Duration::from_secs(3600),
        };
        let (g, _timeout) = TIMERS_CV.wait_timeout(guard, wait).unwrap();
        guard = g;
    }
}

fn ensure_dispatcher() {
    if !DISPATCHER_RUNNING.swap(true, Ordering::SeqCst) {
        std::thread::Builder::new()
            .name("fakelinux-timers".into())
            .spawn(dispatcher_loop)
            .ok();
    }
}

// ── Syscall handlers ─────────────────────────────────────────────────────────

/// timer_create(clockid, sevp, timerid_ptr)
pub fn do_timer_create(_clockid: u64, sevp: u64, timerid_ptr: u64) -> u64 {
    if timerid_ptr == 0 {
        return (-22_i64) as u64; // -EINVAL
    }
    // NULL sevp defaults to SIGEV_SIGNAL + SIGALRM.
    let (signo, sival) = if sevp != 0 {
        let buf = unsafe { std::slice::from_raw_parts(sevp as *const u8, 16) };
        match parse_sigevent(buf) {
            Some((signo, sival, _notify)) => (signo, sival),
            None => return (-22_i64) as u64,
        }
    } else {
        (14, 0) // SIGALRM
    };

    let mut timers = match TIMERS.lock() {
        Ok(t) => t,
        Err(_) => return (-11_i64) as u64, // -EAGAIN
    };
    let Some(id) = timers.iter().position(|t| !t.in_use) else {
        return (-11_i64) as u64; // -EAGAIN
    };
    timers[id] = GuestTimer { in_use: true, signo, sival, deadline_ns: None, interval_ns: 0 };
    drop(timers);

    unsafe { *(timerid_ptr as *mut i32) = id as i32 };
    ensure_dispatcher();
    if trace_on() {
        crate::syscall::raw_eprintln_fmt(format_args!(
            "fakelinux: timer_create id={} signo={} sival={:#x}\n", id, signo, sival));
    }
    0
}

/// timer_settime(timerid, flags, new_value, old_value)
pub fn do_timer_settime(timerid: u64, flags: u64, new_value: u64, old_value: u64) -> u64 {
    let id = timerid as usize;
    if id >= MAX_TIMERS || new_value == 0 {
        return (-22_i64) as u64; // -EINVAL
    }
    let buf = unsafe { std::slice::from_raw_parts(new_value as *const u8, 32) };
    let Some((interval_ns, value_ns)) = parse_itimerspec(buf) else {
        return (-22_i64) as u64;
    };

    let mut timers = match TIMERS.lock() {
        Ok(t) => t,
        Err(_) => return (-22_i64) as u64,
    };
    if !timers[id].in_use {
        return (-22_i64) as u64;
    }
    if old_value != 0 {
        write_itimerspec(old_value, &timers[id]);
    }
    if value_ns == 0 {
        timers[id].deadline_ns = None; // disarm
        timers[id].interval_ns = 0;
    } else {
        let now = monotonic_ns();
        let deadline = if flags & TIMER_ABSTIME != 0 {
            // Treat absolute CLOCK_MONOTONIC values as-is; CLOCK_REALTIME
            // absolute arming is approximated (rarely used by guests).
            value_ns
        } else {
            now.saturating_add(value_ns)
        };
        timers[id].deadline_ns = Some(deadline);
        timers[id].interval_ns = interval_ns;
    }
    drop(timers);
    TIMERS_CV.notify_all();
    if trace_on() {
        crate::syscall::raw_eprintln_fmt(format_args!(
            "fakelinux: timer_settime id={} value_ns={} interval_ns={}\n", id, value_ns, interval_ns));
    }
    0
}

/// timer_gettime(timerid, curr_value)
pub fn do_timer_gettime(timerid: u64, curr_value: u64) -> u64 {
    let id = timerid as usize;
    if id >= MAX_TIMERS || curr_value == 0 {
        return (-22_i64) as u64;
    }
    let timers = match TIMERS.lock() {
        Ok(t) => t,
        Err(_) => return (-22_i64) as u64,
    };
    if !timers[id].in_use {
        return (-22_i64) as u64;
    }
    write_itimerspec(curr_value, &timers[id]);
    0
}

/// timer_delete(timerid)
pub fn do_timer_delete(timerid: u64) -> u64 {
    let id = timerid as usize;
    if id >= MAX_TIMERS {
        return (-22_i64) as u64;
    }
    let mut timers = match TIMERS.lock() {
        Ok(t) => t,
        Err(_) => return (-22_i64) as u64,
    };
    if !timers[id].in_use {
        return (-22_i64) as u64;
    }
    timers[id] = GuestTimer { in_use: false, signo: 0, sival: 0, deadline_ns: None, interval_ns: 0 };
    drop(timers);
    TIMERS_CV.notify_all();
    0
}

fn write_itimerspec(ptr: u64, t: &GuestTimer) {
    let remaining_ns = t
        .deadline_ns
        .map(|d| d.saturating_sub(monotonic_ns()))
        .unwrap_or(0);
    unsafe {
        let p = ptr as *mut i64;
        *p = (t.interval_ns / 1_000_000_000) as i64;
        *p.add(1) = (t.interval_ns % 1_000_000_000) as i64;
        *p.add(2) = (remaining_ns / 1_000_000_000) as i64;
        *p.add(3) = (remaining_ns % 1_000_000_000) as i64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sigevent_glibc_thread_id() {
        // glibc SIGEV_THREAD kernel-side sigevent: sival_ptr = timer struct,
        // signo = SIGTIMER (32), notify = SIGEV_THREAD_ID (4).
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&0x5000_1234_u64.to_le_bytes());
        buf[8..12].copy_from_slice(&32_i32.to_le_bytes());
        buf[12..16].copy_from_slice(&4_i32.to_le_bytes());
        assert_eq!(parse_sigevent(&buf), Some((32, 0x5000_1234, 4)));
    }

    #[test]
    fn parse_itimerspec_one_shot() {
        let mut buf = [0u8; 32];
        // interval = 0, value = 2.5s
        buf[16..24].copy_from_slice(&2_i64.to_le_bytes());
        buf[24..32].copy_from_slice(&500_000_000_i64.to_le_bytes());
        assert_eq!(parse_itimerspec(&buf), Some((0, 2_500_000_000)));
    }

    #[test]
    fn parse_itimerspec_rejects_bad_nsec() {
        let mut buf = [0u8; 32];
        buf[24..32].copy_from_slice(&1_500_000_000_i64.to_le_bytes()); // nsec > 1e9
        assert_eq!(parse_itimerspec(&buf), None);
    }

    #[test]
    fn next_deadline_one_shot_disarms() {
        assert_eq!(next_deadline(1000, 0, 2000), None);
    }

    #[test]
    fn next_deadline_interval_catches_up() {
        // Fired at 1000 with interval 100, but now=1350 — must skip ahead
        // past `now`, not schedule in the past.
        assert_eq!(next_deadline(1000, 100, 1350), Some(1400));
    }

    #[test]
    fn queued_siginfo_pop_respects_set() {
        {
            let mut q = SIGINFO_QUEUE.lock().unwrap();
            q.clear();
            q.push(QueuedSiginfo { signo: 32, code: SI_TIMER, sival: 0xabc, tid: 1, overrun: 0 });
        }
        // Waiting for SIGCHLD only → no match
        assert!(pop_queued_siginfo(1u64 << (17 - 1)).is_none());
        // Waiting for signal 32 → match
        let si = pop_queued_siginfo(1u64 << (32 - 1)).unwrap();
        assert_eq!(si.sival, 0xabc);
        assert!(pop_queued_siginfo(u64::MAX).is_none());
    }
}
