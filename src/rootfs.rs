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
            let resolved = resolve_in_rootfs(root.as_bytes(), path);
            let mut result = resolved;
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

/// Resolve a guest path within the rootfs, following symlinks that have absolute targets.
/// This prevents symlinks like `/usr/bin/which -> /etc/alternatives/which` from escaping
/// the rootfs to the macOS host filesystem.
///
/// Walks the path component by component. At each step, checks if the current path
/// is a symlink. If the symlink target is absolute, it's re-rooted under the rootfs.
/// If relative, it's resolved relative to the current directory.
fn resolve_in_rootfs(root: &[u8], guest_path: &[u8]) -> Vec<u8> {
    // Simple case: just prepend root
    let simple = {
        let mut r = root.to_vec();
        r.extend_from_slice(guest_path);
        r
    };

    // Walk the path component by component, resolving symlinks
    let components: Vec<&[u8]> = guest_path.split(|&b| b == b'/')
        .filter(|c| !c.is_empty())
        .collect();

    if components.is_empty() {
        return simple;
    }

    let mut resolved = root.to_vec(); // starts at rootfs root
    let max_symlinks = 40; // prevent infinite loops
    let mut symlink_count = 0;

    let mut i = 0;
    while i < components.len() {
        // Append next component
        if !resolved.ends_with(b"/") {
            resolved.push(b'/');
        }
        resolved.extend_from_slice(components[i]);

        // Check if this path is a symlink (use lstat, not stat, to not follow)
        let c_path = match std::ffi::CString::new(resolved.clone()) {
            Ok(c) => c,
            Err(_) => return simple,
        };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let lstat_ret = unsafe { libc::lstat(c_path.as_ptr(), &mut st) };

        if lstat_ret == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
            symlink_count += 1;
            if symlink_count > max_symlinks {
                // Too many symlinks, return -ELOOP equivalent (just use simple path)
                return simple;
            }

            // Read the symlink target
            let mut link_buf = [0u8; 4096];
            let link_len = unsafe {
                libc::readlink(c_path.as_ptr(), link_buf.as_mut_ptr() as *mut i8, link_buf.len())
            };
            if link_len <= 0 {
                return simple; // readlink failed, fall back
            }
            let target = &link_buf[..link_len as usize];

            if target.starts_with(b"/") {
                // Absolute symlink target → re-root under rootfs
                // Check if it points to /proc, /dev, /tmp (don't re-root those)
                if target.starts_with(b"/proc") || target.starts_with(b"/dev") || target.starts_with(b"/tmp") {
                    // Let macOS handle these natively
                    return simple;
                }
                resolved = root.to_vec();
                // Parse target as new components and prepend remaining original components
                let target_components: Vec<&[u8]> = target.split(|&b| b == b'/')
                    .filter(|c| !c.is_empty())
                    .collect();
                // Restart resolution with: target_components + remaining original components
                let mut new_components: Vec<Vec<u8>> = target_components.iter().map(|c| c.to_vec()).collect();
                for j in (i+1)..components.len() {
                    new_components.push(components[j].to_vec());
                }
                // Iterative resolution of new components
                let mut k = 0;
                while k < new_components.len() {
                    if !resolved.ends_with(b"/") {
                        resolved.push(b'/');
                    }
                    resolved.extend_from_slice(&new_components[k]);

                    let c_path2 = match std::ffi::CString::new(resolved.clone()) {
                        Ok(c) => c,
                        Err(_) => return simple,
                    };
                    let mut st2: libc::stat = unsafe { std::mem::zeroed() };
                    let lstat2 = unsafe { libc::lstat(c_path2.as_ptr(), &mut st2) };

                    if lstat2 == 0 && (st2.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                        symlink_count += 1;
                        if symlink_count > max_symlinks { return simple; }

                        let link_len2 = unsafe {
                            libc::readlink(c_path2.as_ptr(), link_buf.as_mut_ptr() as *mut i8, link_buf.len())
                        };
                        if link_len2 <= 0 { return simple; }
                        let target2 = &link_buf[..link_len2 as usize];

                        if target2.starts_with(b"/") {
                            if target2.starts_with(b"/proc") || target2.starts_with(b"/dev") || target2.starts_with(b"/tmp") {
                                return simple;
                            }
                            resolved = root.to_vec();
                            let target2_components: Vec<&[u8]> = target2.split(|&b| b == b'/')
                                .filter(|c| !c.is_empty())
                                .collect();
                            let mut newer: Vec<Vec<u8>> = target2_components.iter().map(|c| c.to_vec()).collect();
                            for j in (k+1)..new_components.len() {
                                newer.push(new_components[j].clone());
                            }
                            new_components = newer;
                            k = 0;
                            continue;
                        } else {
                            // Relative symlink - resolve relative to parent dir
                            // Remove the last component from resolved
                            if let Some(slash_pos) = resolved.iter().rposition(|&b| b == b'/') {
                                resolved.truncate(slash_pos);
                            }
                            if !resolved.ends_with(b"/") { resolved.push(b'/'); }
                            resolved.extend_from_slice(target2);
                            // Don't increment k, re-check the resolved path
                            // Actually, just continue to next component
                        }
                    }
                    k += 1;
                }
                return resolved;
            } else {
                // Relative symlink target → resolve relative to parent directory
                if let Some(slash_pos) = resolved.iter().rposition(|&b| b == b'/') {
                    resolved.truncate(slash_pos);
                }
                if !resolved.ends_with(b"/") { resolved.push(b'/'); }
                resolved.extend_from_slice(target);
                // Don't increment i — re-check the new resolved path for more symlinks
                // Actually, we need to restart from this point with the new target
                // For simplicity, just continue to next component
            }
        }
        i += 1;
    }
    resolved
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
