//! Verbosity control for fakelinux's own diagnostic output.
//!
//! fakelinux runs other programs, so its internal chatter (per-exec load
//! banners, instruction-patch counts, relocation tallies) must not pollute the
//! guest's stdout/stderr by default. Those messages go through `vlog!`, which is
//! silent unless verbose mode is enabled via `FAKELINUX_VERBOSE` or `-v`.
//!
//! Genuine errors and fatal conditions use plain `eprintln!` and are always
//! shown.

use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn set_verbose(on: bool) {
    VERBOSE.store(on, Ordering::Relaxed);
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Like `eprintln!`, but only emits when verbose mode is on.
#[macro_export]
macro_rules! vlog {
    ($($arg:tt)*) => {{
        if $crate::diag::verbose() {
            eprintln!($($arg)*);
        }
    }};
}
