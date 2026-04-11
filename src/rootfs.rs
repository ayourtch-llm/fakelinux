//! Rootfs path translation layer.
//!
//! When FAKELINUX_ROOT is set, ALL absolute guest paths (except /proc, /dev, /tmp)
//! are translated by prepending the root path. This provides chroot-like isolation.
//!
//! When only FAKELINUX_SYSROOT is set, only library/linker paths are translated
//! (the Phase 4 behavior).

use std::sync::OnceLock;

/// Full rootfs path (FAKELINUX_ROOT). When set, all absolute paths are translated.
static ROOT: OnceLock<String> = OnceLock::new();

/// Library-only sysroot path (FAKELINUX_SYSROOT). Only library paths are translated.
static SYSROOT: OnceLock<String> = OnceLock::new();

/// Return the FAKELINUX_ROOT value if set.
pub fn get_root() -> Option<&'static str> {
    ROOT.get().map(|s| s.as_str())
}

/// Initialize the rootfs from environment variables.
/// FAKELINUX_ROOT takes precedence over FAKELINUX_SYSROOT for full path translation.
pub fn init(root: &str, sysroot: &str) {
    if !root.is_empty() {
        let r = root.trim_end_matches('/');
        let _ = ROOT.set(r.to_string());
    }
    if !sysroot.is_empty() {
        let s = sysroot.trim_end_matches('/');
        let _ = SYSROOT.set(s.to_string());
    }
}

/// Translate a guest path. Returns Some(translated) with a null-terminated path
/// if translation should occur, or None to use the original path.
///
/// When FAKELINUX_ROOT is set: all absolute paths except /proc, /dev, /tmp are translated.
/// When only FAKELINUX_SYSROOT is set: only library/linker config paths are translated.
pub fn translate_path(path: &[u8]) -> Option<Vec<u8>> {
    // Only translate absolute paths
    if !path.starts_with(b"/") {
        return None;
    }

    // Don't translate /proc (we handle it virtually)
    if path.starts_with(b"/proc") {
        return None;
    }
    // Don't translate /dev (macOS handles these)
    if path.starts_with(b"/dev") {
        return None;
    }
    // Don't translate /tmp (shared)
    if path.starts_with(b"/tmp") {
        return None;
    }

    // Try FAKELINUX_ROOT first (full path translation)
    if let Some(root) = ROOT.get() {
        if !root.is_empty() {
            let mut result = root.as_bytes().to_vec();
            result.extend_from_slice(path);
            // Null-terminate
            if !result.ends_with(&[0]) {
                result.push(0);
            }
            return Some(result);
        }
    }

    // Fall back to FAKELINUX_SYSROOT (library-only translation)
    if let Some(sysroot) = SYSROOT.get() {
        if !sysroot.is_empty() {
            if is_library_path(path) {
                let mut result = sysroot.as_bytes().to_vec();
                result.extend_from_slice(path);
                if !result.ends_with(&[0]) {
                    result.push(0);
                }
                return Some(result);
            }
        }
    }

    None
}

/// Check if a path is a library/linker config path (for FAKELINUX_SYSROOT mode).
fn is_library_path(path: &[u8]) -> bool {
    path.starts_with(b"/lib/")
        || path.starts_with(b"/lib64/")
        || path.starts_with(b"/usr/lib/")
        || path.starts_with(b"/usr/lib64/")
        || path.starts_with(b"/etc/ld.so.cache")
        || path.starts_with(b"/etc/ld.so.conf")
}
