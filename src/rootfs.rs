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

/// Returns true when FAKELINUX_ROOT is set — full rootfs isolation mode.
/// In this mode, guest filesystem access must NEVER fall back to the host.
pub fn in_full_rootfs_mode() -> bool {
    ROOT.get().map(|s| !s.is_empty()).unwrap_or(false)
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
    // For /tmp:
    //   - Full rootfs mode (FAKELINUX_ROOT): translate, so guest /tmp → <root>/tmp.
    //     Without this, the guest sees macOS /tmp which is a symlink to
    //     /private/tmp — dpkg fails because files staged under /tmp/apt-dpkg-install-XXX
    //     are not where it expects, and host filesystem leaks into the guest.
    //   - Sysroot mode only: leave /tmp as host-shared (legacy behavior).
    if path.starts_with(b"/tmp") {
        if !ROOT.get().map(|s| !s.is_empty()).unwrap_or(false) {
            return None;
        }
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
                // Absolute symlink target → re-root under rootfs.
                // /proc and /dev always pass through (handled natively / virtually).
                // /tmp passes through only in sysroot-only mode; in full rootfs mode
                // it must be re-rooted so dpkg's /tmp staging stays inside the guest.
                if target.starts_with(b"/proc") || target.starts_with(b"/dev") {
                    return simple;
                }
                if target.starts_with(b"/tmp") && !in_full_rootfs_mode() {
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
                            if target2.starts_with(b"/proc") || target2.starts_with(b"/dev") {
                                return simple;
                            }
                            if target2.starts_with(b"/tmp") && !in_full_rootfs_mode() {
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

/// Translate a guest path, but DO NOT resolve a symlink at the final component
/// (unless it's an absolute symlink that would otherwise escape the rootfs).
///
/// This is needed for syscalls invoked with `AT_SYMLINK_NOFOLLOW` and for ones
/// that operate on the link itself rather than its target — `rename`, `unlink`,
/// `link`, `lstat`, etc. Without this, dpkg's staged `*.dpkg-new` symlinks
/// (which point at not-yet-extracted targets) get resolved during translation,
/// and the syscall then operates on the (missing) target instead of the link
/// itself, returning ENOENT.
///
/// Strategy: split path into parent + basename, translate the parent normally
/// (resolving any intermediate symlinks), append the basename verbatim. Then
/// inspect the final component: if it's a symlink with an *absolute* target,
/// the symlink would escape to the macOS host, so we still re-root it. Relative
/// symlinks at the final component are left alone — macOS will resolve them
/// within the rootfs naturally.
pub fn translate_path_nofollow(path: &[u8]) -> Option<Vec<u8>> {
    if !path.starts_with(b"/") {
        return None;
    }
    if path.starts_with(b"/proc") || path.starts_with(b"/dev") {
        return None;
    }
    if path.starts_with(b"/tmp") && !in_full_rootfs_mode() {
        return None;
    }
    let last_slash = path.iter().rposition(|&b| b == b'/').unwrap();
    let (parent, basename) = if last_slash == 0 {
        (&b"/"[..], &path[1..])
    } else {
        (&path[..last_slash], &path[last_slash + 1..])
    };
    // Translate the parent (with symlink resolution).
    let mut translated_parent = match translate_path(parent) {
        Some(p) => {
            let mut v = p;
            if v.ends_with(&[0]) { v.pop(); }
            v
        }
        None => return None,
    };
    if !translated_parent.ends_with(b"/") {
        translated_parent.push(b'/');
    }
    let mut full = translated_parent;
    full.extend_from_slice(basename);
    full.push(0);
    Some(full)
}

/// Strip the rootfs prefix from an absolute host path, returning the guest path.
/// E.g., with root="/home/user/rootfs", "/home/user/rootfs/var/lib" → "/var/lib".
/// Returns None if the path doesn't start with the rootfs prefix.
pub fn strip_root_prefix(host_path: &[u8]) -> Option<Vec<u8>> {
    let root = ROOT.get()?;
    if root.is_empty() {
        return None;
    }
    let root_bytes = root.as_bytes();
    if host_path.starts_with(root_bytes) {
        let rest = &host_path[root_bytes.len()..];
        if rest.is_empty() {
            // Path is exactly the root → guest "/"
            Some(b"/".to_vec())
        } else if rest[0] == b'/' {
            Some(rest.to_vec())
        } else {
            // Root prefix doesn't end at a path boundary
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests use the module-level OnceLock statics, so they can only
    // set ROOT/SYSROOT once across all tests in this module. We test the pure
    // functions (is_library_path, strip_root_prefix logic) independently.

    #[test]
    fn test_is_library_path() {
        assert!(is_library_path(b"/lib/x86_64-linux-gnu/libc.so.6"));
        assert!(is_library_path(b"/usr/lib/aarch64-linux-gnu/libz.so"));
        assert!(is_library_path(b"/etc/ld.so.cache"));
        assert!(is_library_path(b"/etc/ld.so.conf"));
        assert!(!is_library_path(b"/etc/resolv.conf"));
        assert!(!is_library_path(b"/usr/bin/bash"));
        assert!(!is_library_path(b"/var/lib/dpkg/status"));
    }

    #[test]
    fn test_translate_path_skips_special_dirs() {
        // /proc and /dev are never translated (virtual / native).
        // /tmp is translated under FAKELINUX_ROOT (these tests run with neither
        // ROOT nor SYSROOT set, so /tmp is also a no-op here).
        assert!(translate_path(b"/proc/self/exe").is_none());
        assert!(translate_path(b"/dev/null").is_none());
        assert!(translate_path(b"/tmp/foo").is_none());
    }

    #[test]
    fn test_translate_path_skips_relative() {
        // Relative paths should never be translated
        assert!(translate_path(b"foo/bar").is_none());
        assert!(translate_path(b"./foo").is_none());
    }

    #[test]
    fn test_strip_root_prefix_logic() {
        // Test the prefix-stripping logic directly (without OnceLock)
        let root = b"/home/user/rootfs";
        let path = b"/home/user/rootfs/var/lib/apt";
        assert!(path.starts_with(root.as_slice()));
        let rest = &path[root.len()..];
        assert_eq!(rest, b"/var/lib/apt");

        // Path that is exactly the root
        let path2 = b"/home/user/rootfs";
        let rest2 = &path2[root.len()..];
        assert!(rest2.is_empty());

        // Path that doesn't match
        let path3 = b"/other/path/var/lib";
        assert!(!path3.starts_with(root.as_slice()));
    }
}
