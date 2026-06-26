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
        // /dev/shm is re-rooted (see dev_passes_through) — make sure the
        // backing directory exists so guest shm_open doesn't ENOENT.
        let _ = std::fs::create_dir_all(format!("{}/dev/shm", r));
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
/// True if a path stays native (macOS /dev). /dev/shm is the exception:
/// macOS has no /dev/shm, and glibc shm_open needs it — those re-root.
fn dev_passes_through(path: &[u8]) -> bool {
    path.starts_with(b"/dev")
        && !(path == b"/dev/shm" || path.starts_with(b"/dev/shm/"))
}

pub fn translate_path(path: &[u8]) -> Option<Vec<u8>> {
    // Only translate absolute paths
    if !path.starts_with(b"/") {
        return None;
    }

    // Don't translate /proc (we handle it virtually)
    if path.starts_with(b"/proc") {
        return None;
    }
    // Don't translate /dev (macOS handles these) — EXCEPT /dev/shm, which
    // macOS doesn't have: glibc shm_open opens /dev/shm/<name>, so those are
    // re-rooted into the rootfs as regular files (MAP_SHARED works on them).
    if dev_passes_through(path) {
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
            let mut result = casefold_full_path(root.as_bytes().len(), resolved);
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
                if target.starts_with(b"/proc") || dev_passes_through(target) {
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
                            if target2.starts_with(b"/proc") || dev_passes_through(target2) {
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
    if path.starts_with(b"/proc") || dev_passes_through(path) {
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
    // Parent is already fully case-folded by translate_path; map just the leaf.
    let picked = casefold_pick(&translated_parent, basename);
    let mut full = translated_parent;
    full.extend_from_slice(&picked);
    full.push(0);
    Some(full)
}

/// Resolve a HOST path that may point inside the rootfs, following absolute
/// symlinks within the rootfs (e.g. roots/ubuntu/usr/bin/vim →
/// /etc/alternatives/vim → roots/ubuntu/usr/bin/vim.basic). Returns the
/// path unchanged if no rootfs is configured or the path is outside it.
/// Requires rootfs::init() to have run.
// ── Case-fold support ───────────────────────────────────────────────────────
//
// macOS's default volume is case-insensitive, but some Linux trees ship files
// whose names differ only in case — e.g. the kernel headers in linux-libc-dev:
// netfilter/xt_CONNMARK.h vs xt_connmark.h. They'd collapse onto one host file.
//
// When FAKELINUX_CASEFOLD=1, the *second* of two case-fold siblings is stored on
// the host under a sentinel-prefixed, case-injective name, so both coexist:
//   xt_connmark.h            (created first)  -> stored verbatim
//   xt_CONNMARK.h            (would collide)  -> "~~NAMECASE~~xt_^connmark.h"
// readdir decodes the sentinel names back to what the guest expects.
//
// Scope: leaf (final path component) only — directory names that collide only by
// case are not handled (vanishingly rare in practice). Off by default; one extra
// getattrlist() per path resolution when enabled.

use std::sync::atomic::{AtomicBool, Ordering as CfOrdering};
static CASEFOLD: AtomicBool = AtomicBool::new(false);
pub fn set_casefold(on: bool) { CASEFOLD.store(on, CfOrdering::Relaxed); }
pub fn casefold_enabled() -> bool { CASEFOLD.load(CfOrdering::Relaxed) }

pub const CASEFOLD_SENTINEL: &[u8] = b"~~NAMECASE~~";

/// Case-injective escape: uppercase `X` -> `^x`, literal `^` -> `^^`. The output
/// contains no uppercase, so it is stable under the host's case-folding.
fn caret_escape(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 4);
    for &b in name {
        match b {
            b'A'..=b'Z' => { out.push(b'^'); out.push(b - b'A' + b'a'); }
            b'^' => { out.push(b'^'); out.push(b'^'); }
            _ => out.push(b),
        }
    }
    out
}
fn caret_unescape(esc: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(esc.len());
    let mut i = 0;
    while i < esc.len() {
        if esc[i] == b'^' && i + 1 < esc.len() {
            let n = esc[i + 1];
            if n == b'^' { out.push(b'^'); }
            else if n.is_ascii_lowercase() { out.push(n - b'a' + b'A'); }
            else { out.push(b'^'); out.push(n); }
            i += 2;
        } else {
            out.push(esc[i]);
            i += 1;
        }
    }
    out
}

/// Host leaf name for a guest leaf stored case-folded.
pub fn casefold_encode_leaf(name: &[u8]) -> Vec<u8> {
    let mut v = CASEFOLD_SENTINEL.to_vec();
    v.extend_from_slice(&caret_escape(name));
    v
}
/// If a host leaf is a case-folded name, return the original guest leaf.
pub fn casefold_decode_leaf(host_leaf: &[u8]) -> Option<Vec<u8>> {
    host_leaf.strip_prefix(CASEFOLD_SENTINEL).map(caret_unescape)
}

/// The actual on-disk leaf name of `path` (the host's real casing), or None if
/// it doesn't exist. Does not follow a final symlink.
fn host_actual_leaf(path: &[u8]) -> Option<Vec<u8>> {
    #[repr(C)]
    struct Attrlist {
        bitmapcount: u16, reserved: u16,
        commonattr: u32, volattr: u32, dirattr: u32, fileattr: u32, forkattr: u32,
    }
    const ATTR_BIT_MAP_COUNT: u16 = 5;
    const ATTR_CMN_NAME: u32 = 0x0000_0001;
    const FSOPT_NOFOLLOW: u32 = 0x0000_0001;
    extern "C" {
        fn getattrlist(path: *const libc::c_char, attr_list: *const Attrlist,
                       attr_buf: *mut libc::c_void, attr_buf_size: libc::size_t,
                       options: libc::c_ulong) -> libc::c_int;
    }
    let cpath = std::ffi::CString::new(path).ok()?;
    let al = Attrlist { bitmapcount: ATTR_BIT_MAP_COUNT, reserved: 0,
                        commonattr: ATTR_CMN_NAME, volattr: 0, dirattr: 0,
                        fileattr: 0, forkattr: 0 };
    let mut buf = [0u8; 1024];
    let rc = unsafe {
        getattrlist(cpath.as_ptr(), &al, buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(), FSOPT_NOFOLLOW as libc::c_ulong)
    };
    if rc != 0 { return None; }
    // Layout: [u32 returned_len][attrreference_t{ i32 dataoffset, u32 length }][name...]
    // dataoffset is relative to the attrreference (at offset 4).
    let dataoffset = i32::from_ne_bytes(buf[4..8].try_into().ok()?) as isize;
    let namelen = u32::from_ne_bytes(buf[8..12].try_into().ok()?) as usize;
    let start = (4isize + dataoffset) as usize;
    if namelen == 0 || start + namelen > buf.len() { return None; }
    // name includes a trailing NUL.
    Some(buf[start..start + namelen - 1].to_vec())
}

/// Pick the on-disk name for one path component `comp` inside host dir `dir`.
/// Single deterministic rule that works for both lookup and create:
///   - verbatim exists with the exact requested case  -> use it
///   - verbatim exists but the on-disk case differs    -> a sibling occupies it;
///     the real entry lives at the encoded name         -> use encoded
///   - verbatim absent but encoded present (sibling was deleted) -> use encoded
///   - otherwise                                        -> verbatim
fn casefold_pick(dir: &[u8], comp: &[u8]) -> Vec<u8> {
    if !casefold_enabled() || comp.is_empty() || comp == b"." || comp == b".."
        || comp.starts_with(CASEFOLD_SENTINEL)
    {
        return comp.to_vec();
    }
    let mut cand = dir.to_vec();
    if !cand.ends_with(b"/") { cand.push(b'/'); }
    cand.extend_from_slice(comp);
    match host_actual_leaf(&cand) {
        Some(actual) if actual == comp => comp.to_vec(),
        Some(_) => casefold_encode_leaf(comp),    // case-fold sibling occupies verbatim
        None => {
            let mut enc_path = dir.to_vec();
            if !enc_path.ends_with(b"/") { enc_path.push(b'/'); }
            let enc = casefold_encode_leaf(comp);
            enc_path.extend_from_slice(&enc);
            let exists = std::ffi::CString::new(enc_path).ok().map_or(false, |c| {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                unsafe { libc::lstat(c.as_ptr(), &mut st) == 0 }
            });
            if exists { enc } else { comp.to_vec() }
        }
    }
}

/// Apply case-fold mapping to EVERY component of an already-rebased host path
/// below the rootfs root (`root_len` bytes of prefix kept verbatim). This handles
/// directory-name collisions (e.g. perl's `pod` vs `Pod`, `sys` vs `Sys`), not
/// just the final filename.
fn casefold_full_path(root_len: usize, host: Vec<u8>) -> Vec<u8> {
    if !casefold_enabled() || host.len() <= root_len {
        return host;
    }
    let mut out = host[..root_len].to_vec();
    for comp in host[root_len..].split(|&b| b == b'/') {
        if comp.is_empty() { continue; }
        let picked = casefold_pick(&out, comp);
        if !out.ends_with(b"/") { out.push(b'/'); }
        out.extend_from_slice(&picked);
    }
    out
}

pub fn resolve_host_path(host_path: &str) -> String {
    let Some(root) = get_root() else {
        return host_path.to_string();
    };
    if root.is_empty() {
        return host_path.to_string();
    }
    let Some(guest) = strip_root_prefix(host_path.as_bytes()) else {
        return host_path.to_string();
    };
    let resolved = resolve_in_rootfs(root.as_bytes(), &guest);
    let resolved = casefold_full_path(root.as_bytes().len(), resolved);
    String::from_utf8_lossy(&resolved).to_string()
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

/// Join a guest-visible absolute directory path with a relative path,
/// normalizing "." and clamping ".." at the guest root (chroot semantics).
/// Returns an absolute guest path ("/" when everything cancels out).
///
/// Without this, a relative ".." resolved against a dirfd that points at the
/// guest root escapes to the HOST parent directory. systemd's path_is_root_at()
/// compares statx(fd, ".") vs statx(fd, "..") inodes to detect "/" — the escape
/// makes it conclude the root fd is NOT root, and chase() then aborts on
/// `Assertion 'path_is_absolute(p)'` in every systemd tool.
pub fn join_guest_relative(guest_dir: &[u8], rel: &[u8]) -> Vec<u8> {
    let mut stack: Vec<&[u8]> = guest_dir
        .split(|&b| b == b'/')
        .filter(|c| !c.is_empty() && *c != b".")
        .collect();
    for comp in rel.split(|&b| b == b'/') {
        if comp.is_empty() || comp == b"." {
            continue;
        }
        if comp == b".." {
            stack.pop(); // pop at root is a no-op → clamp
        } else {
            stack.push(comp);
        }
    }
    let mut out = Vec::new();
    for c in &stack {
        out.push(b'/');
        out.extend_from_slice(c);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    out
}

/// Guest-visible absolute path of an open host fd, when the fd lives inside
/// the rootfs. Uses F_GETPATH; AT_FDCWD resolves via getcwd().
pub fn guest_path_of_fd(fd: i32) -> Option<Vec<u8>> {
    let mut buf = [0u8; libc::PATH_MAX as usize + 1];
    if fd == libc::AT_FDCWD {
        if unsafe { libc::getcwd(buf.as_mut_ptr() as *mut i8, buf.len()) }.is_null() {
            return None;
        }
    } else if unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) } < 0 {
        return None;
    }
    let len = buf.iter().position(|&b| b == 0)?;
    strip_root_prefix(&buf[..len])
}

/// For a dirfd-relative path containing a ".." component, compute the
/// rootfs-clamped HOST path (NUL-terminated) so ".." cannot escape the guest
/// root. Returns None when not applicable (not in rootfs mode, absolute path,
/// no "..", or dirfd outside the rootfs) — caller falls back to passthrough.
pub fn rebase_dotdot_at(host_dirfd: i32, rel: &[u8], nofollow: bool) -> Option<Vec<u8>> {
    if !in_full_rootfs_mode() {
        return None;
    }
    if rel.is_empty() || rel[0] == b'/' {
        return None;
    }
    if !rel.split(|&b| b == b'/').any(|c| c == b"..") {
        return None;
    }
    let guest_dir = guest_path_of_fd(host_dirfd)?;
    let guest = join_guest_relative(&guest_dir, rel);
    let translated = if nofollow {
        translate_path_nofollow(&guest)
    } else {
        translate_path(&guest)
    };
    // /proc, /dev etc. fall through untranslated — use the guest path verbatim.
    translated.or_else(|| {
        let mut v = guest;
        v.push(0);
        Some(v)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests use the module-level OnceLock statics, so they can only
    // set ROOT/SYSROOT once across all tests in this module. We test the pure
    // functions (is_library_path, strip_root_prefix logic) independently.

    #[test]
    fn test_resolve_in_rootfs_absolute_symlink_chain() {
        // /usr/bin/vim → /etc/alternatives/vim → /usr/bin/vim.basic
        // Absolute symlink targets must re-root under the rootfs, not host /.
        let tmp = std::env::temp_dir().join(format!("fakelinux-symlink-test-{}", std::process::id()));
        let root = tmp.to_str().unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("usr/bin")).unwrap();
        std::fs::create_dir_all(tmp.join("etc/alternatives")).unwrap();
        std::fs::write(tmp.join("usr/bin/vim.basic"), b"ELF!").unwrap();
        std::os::unix::fs::symlink("/usr/bin/vim.basic", tmp.join("etc/alternatives/vim")).unwrap();
        std::os::unix::fs::symlink("/etc/alternatives/vim", tmp.join("usr/bin/vim")).unwrap();

        let resolved = resolve_in_rootfs(root.as_bytes(), b"/usr/bin/vim");
        let expected = format!("{}/usr/bin/vim.basic", root);
        assert_eq!(String::from_utf8_lossy(&resolved), expected);
        assert_eq!(std::fs::read(std::str::from_utf8(&resolved).unwrap()).unwrap(), b"ELF!");
        let _ = std::fs::remove_dir_all(&tmp);
    }

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
    fn test_dev_shm_is_not_passed_through() {
        // glibc shm_open → open("/dev/shm/<name>"); macOS has no /dev/shm so
        // it must be re-rooted into the rootfs (VPP's svm regions need this).
        // Everything else under /dev stays native.
        assert!(dev_passes_through(b"/dev"));
        assert!(dev_passes_through(b"/dev/null"));
        assert!(dev_passes_through(b"/dev/pts/0"));
        assert!(dev_passes_through(b"/dev/shmx")); // not the shm dir
        assert!(!dev_passes_through(b"/dev/shm"));
        assert!(!dev_passes_through(b"/dev/shm/"));
        assert!(!dev_passes_through(b"/dev/shm/global_vm"));
        assert!(!dev_passes_through(b"/dev/shm/vpe-api"));
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

    #[test]
    fn test_join_guest_relative_clamps_dotdot_at_root() {
        // ".." at the guest root must clamp to "/" (chroot semantics).
        // systemd's path_is_root_at() does statx(root_fd, "..") and expects
        // the same inode as statx(root_fd, ".") — escaping to the host parent
        // makes chase() assert (path_is_absolute) in every systemd tool.
        assert_eq!(join_guest_relative(b"/", b".."), b"/");
        assert_eq!(join_guest_relative(b"/", b"../.."), b"/");
        assert_eq!(join_guest_relative(b"/", b"../etc"), b"/etc");
        assert_eq!(join_guest_relative(b"/usr", b".."), b"/");
        assert_eq!(join_guest_relative(b"/usr/bin", b"../../etc"), b"/etc");
        assert_eq!(join_guest_relative(b"/usr/bin", b"../lib"), b"/usr/lib");
    }

    #[test]
    fn test_join_guest_relative_normalizes() {
        assert_eq!(join_guest_relative(b"/usr", b"."), b"/usr");
        assert_eq!(join_guest_relative(b"/usr", b"./x/../y"), b"/usr/y");
        assert_eq!(join_guest_relative(b"/", b"."), b"/");
        assert_eq!(join_guest_relative(b"/a//b/", b"c/.."), b"/a/b");
    }

    #[test]
    fn test_casefold_encode_decode_roundtrip() {
        for name in [
            &b"xt_CONNMARK.h"[..], b"xt_connmark.h", b"README", b"Makefile",
            b"ABC", b"abc", b"a^b", b"^weird^", b"MixedCase.TXT", b"123",
        ] {
            let enc = casefold_encode_leaf(name);
            assert!(enc.starts_with(CASEFOLD_SENTINEL));
            // The encoded body must contain no uppercase (case-fold stable).
            let body = &enc[CASEFOLD_SENTINEL.len()..];
            assert!(!body.iter().any(|b| b.is_ascii_uppercase()), "encoded {:?} has uppercase", name);
            assert_eq!(casefold_decode_leaf(&enc).as_deref(), Some(&name[..]));
        }
        // Non-sentinel names decode to None.
        assert_eq!(casefold_decode_leaf(b"xt_connmark.h"), None);
    }

    #[test]
    fn test_casefold_injective_across_case_variants() {
        // Names differing only in case must produce distinct, case-fold-stable
        // host names (so they can coexist on a case-insensitive volume).
        let variants: [&[u8]; 3] = [b"abc.h", b"Abc.h", b"ABC.h"];
        let encoded: Vec<Vec<u8>> = variants.iter().map(|n| casefold_encode_leaf(n)).collect();
        for e in &encoded {
            let lower: Vec<u8> = e.iter().map(|b| b.to_ascii_lowercase()).collect();
            // Compare lowercased forms: still distinct => no collision when folded.
            let others = encoded.iter().filter(|x| *x != e)
                .map(|x| x.iter().map(|b| b.to_ascii_lowercase()).collect::<Vec<u8>>());
            for o in others {
                assert_ne!(lower, o, "case variants collide after folding");
            }
        }
    }
}
