use crate::elf::{self, Elf, ElfError};
use crate::linux::*;
use crate::procfs;
use crate::syscall;
use crate::trap;

use std::sync::Mutex;
use std::sync::RwLock;

/// Side table mapping patched PC addresses to their original instructions.
/// Written during loading, then frozen. Uses a sorted Vec for lock-free lookup
/// (safe to use after fork, unlike Mutex<HashMap>).
static TPIDR_PATCHES: Mutex<Option<Vec<(u64, u32)>>> = Mutex::new(None);
/// Frozen sorted copy for lock-free lookup at runtime.
static mut TPIDR_PATCHES_FROZEN: Option<Vec<(u64, u32)>> = None;

/// Runtime TPIDR patches added when dynamic linker loads new .so files.
/// Kept sorted for binary search. Protected by RwLock for concurrent reads.
static TPIDR_PATCHES_RUNTIME: RwLock<Vec<(u64, u32)>> = RwLock::new(Vec::new());

pub fn freeze_tpidr_patches() {
    let mut lock = TPIDR_PATCHES.lock().unwrap();
    if let Some(mut v) = lock.take() {
        v.sort_by_key(|&(pc, _)| pc);
        unsafe { TPIDR_PATCHES_FROZEN = Some(v); }
    }
}

fn add_tpidr_patch(pc: u64, instr: u32) {
    TPIDR_PATCHES.lock().unwrap()
        .get_or_insert_with(Vec::new)
        .push((pc, instr));
}

fn add_runtime_tpidr_patch(pc: u64, instr: u32) {
    if let Ok(mut table) = TPIDR_PATCHES_RUNTIME.write() {
        // Insert in sorted order for binary search
        let pos = table.binary_search_by_key(&pc, |&(addr, _)| addr)
            .unwrap_or_else(|e| e);
        table.insert(pos, (pc, instr));
    }
}

pub fn tpidr_lookup(pc: u64) -> Option<u32> {
    // Check frozen table first (fast, lock-free)
    let frozen = unsafe { TPIDR_PATCHES_FROZEN.as_ref() };
    if let Some(table) = frozen {
        if let Ok(i) = table.binary_search_by_key(&pc, |&(addr, _)| addr) {
            return Some(table[i].1);
        }
    }
    // Check runtime table (for dynamically loaded code)
    match TPIDR_PATCHES_RUNTIME.read() {
        Ok(table) => {
            if let Ok(i) = table.binary_search_by_key(&pc, |&(addr, _)| addr) {
                return Some(table[i].1);
            }
        }
        Err(poisoned) => {
            // RwLock poisoned (can happen after fork) — read through poison
            let table = poisoned.into_inner();
            if let Ok(i) = table.binary_search_by_key(&pc, |&(addr, _)| addr) {
                return Some(table[i].1);
            }
        }
    }
    None
}

/// Find the base address of a library that has a TPIDR patch at the given offset.
/// Searches the runtime patch table for any (addr, _) where addr & 0xFFFFF == offset & 0xFFFFF
/// and returns addr - offset. Used to find libapt-pkg base when the stack is corrupted.
pub fn find_tpidr_patch_base(offset: u64) -> u64 {
    // The offset is the known position of a TPIDR instruction within the library.
    // We search for a patched address whose low bits match the offset.
    match TPIDR_PATCHES_RUNTIME.read() {
        Ok(table) => {
            for &(addr, _) in table.iter() {
                if addr >= offset && (addr - offset) & 0xFFF == 0 {
                    // Page-aligned base. Verify: addr = base + offset
                    // The base should be page-aligned.
                    let candidate_base = addr - offset;
                    if candidate_base & 0x3FFF == 0 { // 16KB aligned
                        return candidate_base;
                    }
                }
            }
        }
        Err(poisoned) => {
            let table = poisoned.into_inner();
            for &(addr, _) in table.iter() {
                if addr >= offset && (addr - offset) & 0x3FFF == 0 {
                    return addr - offset;
                }
            }
        }
    }
    0
}

const PAGE_SIZE: u64 = 16384; // macOS aarch64

fn page_align_down(addr: u64) -> u64 {
    addr & !(PAGE_SIZE - 1)
}

fn page_align_up(addr: u64) -> u64 {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Information about the loaded ELF
pub struct LoadedElf {
    pub entry: u64,
    pub stack_ptr: u64,
    pub phdr_addr: u64,
    pub interp_base: u64,
}

/// Load an ELF binary into memory, rewrite SVC→BRK, set up the stack.
pub fn load(elf: &Elf, data: &[u8], guest_args: &[String], sysroot: &str) -> Result<LoadedElf, ElfError> {
    let base_offset: u64 = if elf.header.e_type == ET_DYN {
        0x5_0000_0000 // load PIE at 20GB mark
    } else {
        // macOS Apple Silicon enforces a 4GB PAGEZERO — we can't map at typical
        // Linux ET_EXEC addresses (0x400000). Relocate above 4GB instead.
        // aarch64 code uses PC-relative addressing (ADRP/ADR/B/BL) so this
        // works for most binaries despite being non-PIE.
        let min_vaddr = elf.phdrs.iter()
            .filter(|p| p.p_type == PT_LOAD)
            .map(|p| p.p_vaddr)
            .min()
            .unwrap_or(0);
        if min_vaddr < 0x1_0000_0000 {
            let base = 0x7_0000_0000_u64;
            eprintln!(
                "fakelinux: relocating ET_EXEC {:#x} → {:#x} (macOS 4GB PAGEZERO)",
                min_vaddr, base + min_vaddr
            );
            base
        } else {
            0
        }
    };

    let mut brk_end: u64 = 0;
    let mut phdr_addr: u64 = 0;

    // Load PT_LOAD segments of the main binary
    load_segments(elf, data, base_offset, &mut brk_end, &mut phdr_addr, &guest_args[0])?;

    // Check for PT_INTERP (dynamic linker)
    let mut interp_base: u64 = 0;
    let mut interp_entry: u64 = 0;

    if let Some(interp_path) = get_interp(elf, data) {
        eprintln!("fakelinux: interpreter: {}", interp_path);

        // Look for the interpreter in order: FAKELINUX_ROOT, sysroot, bare path
        let root = crate::rootfs::get_root();
        let candidates: Vec<String> = {
            let mut v = Vec::new();
            if let Some(r) = root {
                if !r.is_empty() {
                    v.push(format!("{}{}", r, interp_path));
                }
            }
            if !sysroot.is_empty() {
                v.push(format!("{}{}", sysroot, interp_path));
            }
            v.push(interp_path.clone());
            v
        };

        let interp_full = candidates.iter()
            .find(|p| std::path::Path::new(p).exists())
            .cloned()
            .unwrap_or_else(|| candidates.last().unwrap().clone());

        let interp_data = std::fs::read(&interp_full).map_err(|e| {
            ElfError(format!(
                "cannot read interpreter '{}' (tried: {:?}): {}. \
                 Use FAKELINUX_ROOT or FAKELINUX_SYSROOT to point to an aarch64 Linux rootfs.",
                interp_path, candidates, e
            ))
        })?;

        let interp_elf = elf::parse(&interp_data)?;

        // Load interpreter at a separate base address
        interp_base = 0x6_0000_0000; // 24GB mark
        let mut _interp_brk: u64 = 0;
        let mut _interp_phdr: u64 = 0;
        load_segments(&interp_elf, &interp_data, interp_base, &mut _interp_brk, &mut _interp_phdr, "ld-linux")?;

        interp_entry = interp_base + interp_elf.header.e_entry;
        eprintln!("fakelinux: interpreter loaded at {:#x}, entry={:#x}", interp_base, interp_entry);
    }

    // Create fork and patch trampoline pages after the last segment
    let tramp_base = page_align_up(brk_end);
    crate::thread::init_trampolines(tramp_base);

    // Initialize brk at the end of the last segment + both trampolines
    let brk_start = page_align_up(tramp_base + PAGE_SIZE * 2);
    syscall::BRK_CURRENT.store(brk_start, std::sync::atomic::Ordering::SeqCst);

    // Record the heap in procfs mappings
    procfs::add_mapping(procfs::MemMapping {
        start: brk_start,
        end: brk_start,
        prot: libc::PROT_READ | libc::PROT_WRITE,
        flags: libc::MAP_PRIVATE,
        offset: 0,
        name: "[heap]".into(),
    });

    // Apply ELF relocations for PIE binaries.
    // The binary's self-relocation code may not work correctly in our environment,
    // so we do it here before handing off control.
    if elf.header.e_type == ET_DYN {
        apply_relocations(elf, data, base_offset)?;
    }

    // Fix up absolute pointers in relocated ET_EXEC binaries.
    // Non-PIE executables have absolute addresses baked into their data segments.
    // When we relocate past the 4GB PAGEZERO, these pointers must be adjusted.
    // PC-relative code (ADRP/ADR/B/BL) works automatically, but data pointers don't.
    if elf.header.e_type == ET_EXEC && base_offset != 0 {
        fixup_exec_pointers(elf, base_offset);
    }

    // Set up the guest stack
    let stack_ptr = setup_stack(elf, base_offset, phdr_addr, interp_base, guest_args)?;

    // Entry point: use interpreter if present, otherwise the binary's own entry
    let entry = if interp_entry != 0 {
        interp_entry
    } else {
        base_offset + elf.header.e_entry
    };

    eprintln!("fakelinux: entry={:#x} sp={:#x} brk={:#x}", entry, stack_ptr, brk_start);

    Ok(LoadedElf {
        entry,
        stack_ptr,
        phdr_addr,
        interp_base,
    })
}

/// Load PT_LOAD segments from an ELF into memory.
fn load_segments(
    elf: &Elf,
    data: &[u8],
    base_offset: u64,
    brk_end: &mut u64,
    phdr_addr: &mut u64,
    name: &str,
) -> Result<(), ElfError> {
    for phdr in &elf.phdrs {
        if phdr.p_type != PT_LOAD {
            continue;
        }

        let seg_start = base_offset + phdr.p_vaddr;
        let seg_end = seg_start + phdr.p_memsz;
        let map_start = page_align_down(seg_start);
        let map_end = page_align_up(seg_end);
        let map_size = (map_end - map_start) as usize;

        let ptr = unsafe {
            libc::mmap(
                map_start as *mut _,
                map_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(ElfError(format!(
                "mmap failed for segment at {:#x} (size {:#x}): {}",
                map_start, map_size, std::io::Error::last_os_error()
            )));
        }

        if phdr.p_filesz > 0 {
            let src_start = phdr.p_offset as usize;
            let src_end = src_start + phdr.p_filesz as usize;
            if src_end > data.len() {
                return Err(ElfError("segment file data out of bounds".into()));
            }
            unsafe {
                std::ptr::copy_nonoverlapping(
                    data[src_start..src_end].as_ptr(),
                    seg_start as *mut u8,
                    phdr.p_filesz as usize,
                );
            }
        }

        // Rewrite SVC #0 → BRK #0xF000 in executable segments
        if phdr.p_flags & PF_X != 0 {
            // Compute code-only ranges within this segment so x18 patching
            // doesn't corrupt non-code data (e.g. .dynstr) in the same PT_LOAD.
            let elf_code_ranges = elf::find_code_ranges(data);
            let code_ranges: Vec<(u64, u64)> = elf_code_ranges.iter()
                .filter_map(|&(vaddr, size)| {
                    let mem_addr = base_offset + vaddr;
                    // Only include ranges that overlap this segment
                    if mem_addr >= seg_start && mem_addr < seg_start + phdr.p_filesz {
                        Some((mem_addr, size))
                    } else {
                        None
                    }
                })
                .collect();
            rewrite_svc_instructions(seg_start, phdr.p_filesz, &code_ranges);
        }

        // Find program headers in memory
        let file_phdr_start = elf.header.e_phoff;
        let file_phdr_end =
            file_phdr_start + (elf.header.e_phnum as u64) * (elf.header.e_phentsize as u64);
        if phdr.p_offset <= file_phdr_start
            && file_phdr_end <= phdr.p_offset + phdr.p_filesz
        {
            *phdr_addr = seg_start + (file_phdr_start - phdr.p_offset);
        }

        // Set correct permissions
        let prot = elf_to_mmap_prot(phdr.p_flags);
        unsafe { libc::mprotect(map_start as *mut _, map_size, prot); }

        // Record mapping in procfs
        procfs::add_mapping(procfs::MemMapping {
            start: map_start,
            end: map_end,
            prot,
            flags: libc::MAP_PRIVATE,
            offset: phdr.p_offset,
            name: name.to_string(),
        });

        if seg_end > *brk_end {
            *brk_end = seg_end;
        }
    }
    Ok(())
}

/// Extract the PT_INTERP path from the ELF.
fn get_interp(elf: &Elf, data: &[u8]) -> Option<String> {
    for phdr in &elf.phdrs {
        if phdr.p_type == PT_INTERP {
            let start = phdr.p_offset as usize;
            let end = start + phdr.p_filesz as usize;
            if end > data.len() {
                return None;
            }
            let bytes = &data[start..end];
            // Strip trailing null
            let trimmed = if bytes.last() == Some(&0) {
                &bytes[..bytes.len() - 1]
            } else {
                bytes
            };
            return String::from_utf8(trimmed.to_vec()).ok();
        }
    }
    None
}

/// Check if a memory address falls within one of the given code ranges.
fn addr_in_code_ranges(addr: u64, code_ranges: &[(u64, u64)]) -> bool {
    for &(range_start, range_size) in code_ranges {
        if addr >= range_start && addr < range_start + range_size {
            return true;
        }
    }
    false
}

/// Scan executable memory and replace SVC #0 and MSR/MRS tpidr_el0 with UDF #0xF000.
/// `code_ranges` restricts x18 patching to actual code sections (to avoid corrupting
/// data like string tables that may share the same PT_LOAD segment).
fn rewrite_svc_instructions(start: u64, size: u64, code_ranges: &[(u64, u64)]) {
    let count = size / 4;
    let base = start as *mut u32;
    let mut svc_patched = 0u64;
    let mut tpidr_patched = 0u64;
    let mut x18_patched = 0u64;
    let have_code_ranges = !code_ranges.is_empty();
    let skip_x18 = std::env::var("FAKELINUX_NO_X18").is_ok()
        || std::env::var("FAKELINUX_NO_X18_INITIAL").is_ok();
    // For bisecting: FAKELINUX_X18_MAX_OFFSET limits x18 patching to offsets below this value
    let x18_max_offset: u64 = std::env::var("FAKELINUX_X18_MAX_OFFSET")
        .ok().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(u64::MAX);
    for i in 0..count as usize {
        unsafe {
            let instr = base.add(i).read();
            if instr == trap::SVC_0 {
                // SVC #0 → UDF #0xF000
                base.add(i).write(trap::UDF_MARKER);
                svc_patched += 1;
            } else if instr & trap::MSR_TPIDR_MASK == trap::MSR_TPIDR_BASE
                   || instr & trap::MRS_TPIDR_MASK == trap::MRS_TPIDR_BASE {
                // MSR/MRS tpidr_el0 → patch to UDF, store original in side table.
                let pc_addr = base.add(i) as u64;
                crate::procfs::with(|_| {}); // ensure procfs is initialized
                add_tpidr_patch(pc_addr, instr);
                base.add(i).write(trap::UDF_MARKER);
                tpidr_patched += 1;
            } else if !skip_x18 && trap::references_x18(instr) {
                let pc_addr = base.add(i) as u64;
                let offset = (i as u64) * 4;
                // Only patch x18 in actual code sections — data in the same segment
                // (e.g. .dynstr, .rodata) could match x18 patterns and must not be corrupted.
                if (!have_code_ranges || addr_in_code_ranges(pc_addr, code_ranges))
                    && offset < x18_max_offset {
                    add_tpidr_patch(pc_addr, instr);
                    base.add(i).write(trap::UDF_MARKER);
                    x18_patched += 1;
                }
            }
        }
    }
    if svc_patched > 0 {
        eprintln!("fakelinux: patched {} SVC→UDF instructions", svc_patched);
    }
    if tpidr_patched > 0 {
        eprintln!("fakelinux: patched {} MSR/MRS tpidr_el0 instructions", tpidr_patched);
    }
    if x18_patched > 0 {
        eprintln!("fakelinux: patched {} x18 instructions", x18_patched);
    }
}

/// Patch newly-executable code pages at runtime (called from mprotect/mmap).
/// Scans the given address range for SVC #0 and MSR/MRS tpidr_el0, patches them,
/// and adds TPIDR patches to the runtime table.
///
/// The caller must ensure the memory is writable before calling this.
/// After patching, the caller should set the final permissions and invalidate icache.
pub fn patch_new_code(start: u64, len: u64) {
    // Try to extract code ranges from ELF section headers (most precise) or
    // program headers + PT_DYNAMIC (fallback). This prevents x18 patching from
    // corrupting non-code data (e.g. .dynstr version strings) in the same mapping.
    let code_ranges = extract_code_ranges_from_memory(start, len);

    let count = len / 4;
    let base = start as *mut u32;
    let mut svc_patched = 0u64;
    let mut tpidr_patched = 0u64;
    let mut x18_patched = 0u64;
    let mut x18_skipped = 0u64;
    let have_code_ranges = !code_ranges.is_empty();
    let skip_x18 = std::env::var("FAKELINUX_NO_X18").is_ok();
    for i in 0..count as usize {
        unsafe {
            let instr = base.add(i).read();
            if instr == trap::SVC_0 {
                base.add(i).write(trap::UDF_MARKER);
                svc_patched += 1;
            } else if instr & trap::MSR_TPIDR_MASK == trap::MSR_TPIDR_BASE
                   || instr & trap::MRS_TPIDR_MASK == trap::MRS_TPIDR_BASE {
                let pc_addr = base.add(i) as u64;
                add_runtime_tpidr_patch(pc_addr, instr);
                base.add(i).write(trap::UDF_MARKER);
                tpidr_patched += 1;
            } else if !skip_x18 && trap::references_x18(instr) {
                let pc_addr = base.add(i) as u64;
                // x18 patterns have high false-positive rates on data (string tables,
                // symbol tables, etc.). Only patch if we have confirmed code ranges.
                // SVC/TPIDR patterns are specific enough to scan everything safely.
                if have_code_ranges && addr_in_code_ranges(pc_addr, &code_ranges) {
                    add_runtime_tpidr_patch(pc_addr, instr);
                    base.add(i).write(trap::UDF_MARKER);
                    x18_patched += 1;
                } else if !have_code_ranges {
                    x18_skipped += 1;
                }
            }
        }
    }
    if svc_patched > 0 || tpidr_patched > 0 || x18_patched > 0 || x18_skipped > 0 {
        eprintln!(
            "fakelinux: runtime patch at {:#x}+{:#x}: {} SVC, {} TPIDR, {} x18{}",
            start, len, svc_patched, tpidr_patched, x18_patched,
            if x18_skipped > 0 { format!(" ({} x18 skipped, no code ranges)", x18_skipped) } else { String::new() }
        );
    }

    // Set up FORK_ENTRY_PROBE: patch __libc_fork's FIRST instruction `sub sp, sp, #0x140`
    // at offset 0xC1B50 to UDF. This fires at __libc_fork entry, allowing us to check
    // if x30 (LR) is already corrupted when the function is entered.
    // Detect libc by high SVC count (>400) — only libc has hundreds of SVCs.
    // NOTE: FORK_ENTRY_PROBE removed. Investigation showed that x30=0x5000xxxx at
    // __libc_fork entry is NOT corruption — the 0x5000xxxx range is the guest binary's
    // text segment (loaded below brk). The probe was incorrectly "fixing" correct LRs
    // to wrong libapt-pkg addresses, CAUSING the fork child to run wrong code.
}

/// Try to extract code ranges from ELF headers in mapped memory.
/// First tries section headers (most precise), then falls back to program headers
/// + PT_DYNAMIC parsing to identify and exclude known data regions (.dynstr, .dynsym,
/// .rela, etc.) from executable segments.
/// Returns empty vec if no code ranges can be determined.
fn extract_code_ranges_from_memory(base_addr: u64, len: u64) -> Vec<(u64, u64)> {
    const SHF_EXECINSTR: u64 = 4;
    let data = unsafe { std::slice::from_raw_parts(base_addr as *const u8, len as usize) };

    // Check ELF magic
    if data.len() < 64 || data[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Vec::new();
    }

    // Strategy 1: section headers (most precise)
    let e_shoff = elf::read_u64_pub(data, 40) as usize;
    let e_shentsize = elf::read_u16_pub(data, 58) as usize;
    let e_shnum = elf::read_u16_pub(data, 60) as usize;

    if e_shoff != 0 && e_shnum != 0 && e_shentsize >= 64 && e_shoff < data.len() {
        let mut ranges = Vec::new();
        for i in 0..e_shnum {
            let off = e_shoff + i * e_shentsize;
            if off + 64 > data.len() { break; }
            let sh_type = elf::read_u32_pub(data, off + 4);
            let sh_flags = elf::read_u64_pub(data, off + 8);
            let sh_addr = elf::read_u64_pub(data, off + 16);
            let sh_size = elf::read_u64_pub(data, off + 32);
            if sh_type == 1 && sh_flags & SHF_EXECINSTR != 0 && sh_size > 0 {
                let mem_addr = base_addr + sh_addr;
                if mem_addr >= base_addr && mem_addr < base_addr + len {
                    ranges.push((mem_addr, sh_size));
                }
            }
        }
        if !ranges.is_empty() {
            return ranges;
        }
    }

    // Strategy 2: program headers + PT_DYNAMIC to exclude known data regions
    extract_code_ranges_via_phdrs(data, base_addr, len)
}

/// Build code ranges from program headers by finding PF_X segments and subtracting
/// known data regions identified via PT_DYNAMIC (DT_STRTAB, DT_SYMTAB, DT_RELA, etc.).
/// This prevents x18 patching from corrupting string tables and other non-code data
/// that shares the same PT_LOAD segment as .text.
fn extract_code_ranges_via_phdrs(data: &[u8], base_addr: u64, len: u64) -> Vec<(u64, u64)> {
    let e_phoff = elf::read_u64_pub(data, 32) as usize;
    let e_phentsize = elf::read_u16_pub(data, 54) as usize;
    let e_phnum = elf::read_u16_pub(data, 56) as usize;

    if e_phoff == 0 || e_phnum == 0 || e_phentsize < 56 {
        return Vec::new();
    }

    // Parse program headers to find first PT_LOAD (for load base) and PT_DYNAMIC
    let mut first_load_vaddr: Option<u64> = None;
    let mut dynamic_file_off = 0u64;
    let mut dynamic_filesz = 0u64;
    let mut exec_seg_vaddr = 0u64;
    let mut exec_seg_filesz = 0u64;
    let mut have_exec_seg = false;

    for i in 0..e_phnum {
        let off = e_phoff + i * e_phentsize;
        if off + 56 > data.len() { break; }
        let p_type = elf::read_u32_pub(data, off);
        let p_flags = elf::read_u32_pub(data, off + 4);
        let p_offset = elf::read_u64_pub(data, off + 8);
        let p_vaddr = elf::read_u64_pub(data, off + 16);
        let p_filesz = elf::read_u64_pub(data, off + 32);

        if p_type == 1 /* PT_LOAD */ {
            if first_load_vaddr.is_none() {
                first_load_vaddr = Some(p_vaddr);
            }
            if p_flags & 1 /* PF_X */ != 0 && !have_exec_seg {
                exec_seg_vaddr = p_vaddr;
                exec_seg_filesz = p_filesz;
                have_exec_seg = true;
            }
        }
        if p_type == 2 /* PT_DYNAMIC */ && p_offset < data.len() as u64 {
            dynamic_file_off = p_offset;
            dynamic_filesz = p_filesz;
        }
    }

    let first_load_vaddr = match first_load_vaddr {
        Some(v) => v,
        None => return Vec::new(),
    };
    if !have_exec_seg || dynamic_filesz == 0 {
        return Vec::new();
    }

    // Compute load base: the mapping at base_addr corresponds to the first LOAD's p_vaddr
    let load_base = base_addr.wrapping_sub(first_load_vaddr);

    // Parse PT_DYNAMIC to find data region addresses
    let dyn_start = dynamic_file_off as usize;
    let dyn_end = dyn_start + dynamic_filesz as usize;
    if dyn_end > data.len() {
        return Vec::new();
    }

    let mut strtab = 0u64;
    let mut strsz = 0u64;
    let mut symtab = 0u64;
    let mut hash = 0u64;
    let mut gnu_hash = 0u64;
    let mut rela = 0u64;
    let mut relasz = 0u64;
    let mut jmprel = 0u64;
    let mut pltrelsz = 0u64;
    let mut init = 0u64;
    let mut fini = 0u64;
    let mut init_array = 0u64;
    let mut init_arraysz = 0u64;

    let num_entries = dynamic_filesz as usize / 16;
    for i in 0..num_entries {
        let eoff = dyn_start + i * 16;
        if eoff + 16 > data.len() { break; }
        let tag = elf::read_u64_pub(data, eoff);
        let val = elf::read_u64_pub(data, eoff + 8);
        match tag {
            0 => break,           // DT_NULL
            2 => pltrelsz = val,  // DT_PLTRELSZ
            4 => hash = val,      // DT_HASH
            5 => strtab = val,    // DT_STRTAB
            6 => symtab = val,    // DT_SYMTAB
            7 => rela = val,      // DT_RELA
            8 => relasz = val,    // DT_RELASZ
            10 => strsz = val,    // DT_STRSZ
            12 => init = val,     // DT_INIT (code — keep)
            13 => fini = val,     // DT_FINI (code — keep)
            23 => jmprel = val,   // DT_JMPREL
            25 => init_array = val,     // DT_INIT_ARRAY
            27 => init_arraysz = val,   // DT_INIT_ARRAYSZ
            _ => {
                // DT_GNU_HASH
                if tag == 0x6ffffef5 { gnu_hash = val; }
            }
        }
    }

    // Build exclusion list: known data regions (addr, size) in memory
    let mut exclusions: Vec<(u64, u64)> = Vec::new();

    // .dynstr — the primary target; contains version strings like "GLIBC_2.38"
    if strtab != 0 && strsz != 0 {
        exclusions.push((load_base.wrapping_add(strtab), strsz));
    }
    // .dynsym — typically between hash and strtab
    if symtab != 0 && strtab > symtab {
        exclusions.push((load_base.wrapping_add(symtab), strtab - symtab));
    }
    // .rela.dyn
    if rela != 0 && relasz != 0 {
        exclusions.push((load_base.wrapping_add(rela), relasz));
    }
    // .rela.plt
    if jmprel != 0 && pltrelsz != 0 {
        exclusions.push((load_base.wrapping_add(jmprel), pltrelsz));
    }
    // .hash — size unknown, but typically small; estimate from next known region
    if hash != 0 && symtab > hash {
        exclusions.push((load_base.wrapping_add(hash), symtab - hash));
    }
    // .gnu.hash — size unknown; estimate from symtab if it follows
    if gnu_hash != 0 && symtab > gnu_hash {
        exclusions.push((load_base.wrapping_add(gnu_hash), symtab - gnu_hash));
    }

    if exclusions.is_empty() {
        return Vec::new();
    }

    // Sort exclusions by address
    exclusions.sort_by_key(|&(addr, _)| addr);

    // Build code ranges: executable segment minus exclusions
    let seg_start = load_base.wrapping_add(exec_seg_vaddr);
    let seg_end = seg_start + exec_seg_filesz;
    // Clamp to our mapping
    let seg_start = seg_start.max(base_addr);
    let seg_end = seg_end.min(base_addr + len);
    if seg_start >= seg_end {
        return Vec::new();
    }

    // Generate code ranges as gaps between/around exclusions
    let mut code_ranges = Vec::new();
    let mut pos = seg_start;
    for &(ex_start, ex_size) in &exclusions {
        let ex_end = ex_start + ex_size;
        // Clamp exclusion to segment
        let ex_start = ex_start.max(seg_start);
        let ex_end = ex_end.min(seg_end);
        if ex_start >= ex_end { continue; }
        if ex_start > pos {
            code_ranges.push((pos, ex_start - pos));
        }
        if ex_end > pos {
            pos = ex_end;
        }
    }
    if pos < seg_end {
        code_ranges.push((pos, seg_end - pos));
    }

    if !code_ranges.is_empty() {
        let total_code: u64 = code_ranges.iter().map(|&(_, s)| s).sum();
        let total_excl: u64 = exclusions.iter().map(|&(_, s)| s).sum();
        eprintln!(
            "fakelinux: code ranges via phdrs at {:#x}: {} code regions ({:#x} bytes), excluded {:#x} bytes of data",
            base_addr, code_ranges.len(), total_code, total_excl
        );
    }

    code_ranges
}

fn setup_stack(
    elf: &Elf,
    base_offset: u64,
    phdr_addr: u64,
    interp_base: u64,
    guest_args: &[String],
) -> Result<u64, ElfError> {
    let stack_size: usize = 8 * 1024 * 1024;
    // Allocate the guest stack at a high address, far from where macOS places
    // normal mmap results. This prevents the guest's TLS block (allocated by
    // ld-linux via mmap) from landing adjacent to the stack. On real Linux,
    // the kernel ensures TLS and stack are in separate regions. Without this
    // hint, macOS can place them adjacent, and glibc's _Fork child path
    // writes to [TPIDR-0x668] which corrupts __libc_fork's stack canary.
    let stack_hint: *mut libc::c_void = 0x7F_F000_0000u64 as *mut _;
    let stack_base = unsafe {
        libc::mmap(
            stack_hint,
            stack_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if stack_base == libc::MAP_FAILED {
        return Err(ElfError("failed to allocate guest stack".into()));
    }

    // Record stack mapping
    procfs::add_mapping(procfs::MemMapping {
        start: stack_base as u64,
        end: stack_base as u64 + stack_size as u64,
        prot: libc::PROT_READ | libc::PROT_WRITE,
        flags: libc::MAP_PRIVATE,
        offset: 0,
        name: "[stack]".into(),
    });

    let stack_top = stack_base as u64 + stack_size as u64;
    let mut sp = stack_top;

    let push_bytes = |sp: &mut u64, data: &[u8]| {
        *sp -= data.len() as u64;
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), *sp as *mut u8, data.len());
        }
    };

    // 1) Random bytes at the top
    let mut random_bytes = [0u8; 16];
    for b in &mut random_bytes {
        *b = unsafe { libc::arc4random() as u8 };
    }
    push_bytes(&mut sp, &random_bytes);
    let at_random_addr = sp;

    // 2) Environment strings
    let env_strs: Vec<&[u8]> = vec![
        b"PATH=/usr/bin:/bin\0",
        b"HOME=/root\0",
        b"TERM=xterm\0",
    ];
    let mut env_addrs: Vec<u64> = Vec::new();
    for e in env_strs.iter().rev() {
        push_bytes(&mut sp, e);
        env_addrs.push(sp);
    }
    env_addrs.reverse();

    // 3) Argument strings
    let mut arg_addrs: Vec<u64> = Vec::new();
    for arg in guest_args.iter().rev() {
        let mut bytes = arg.as_bytes().to_vec();
        bytes.push(0);
        push_bytes(&mut sp, &bytes);
        arg_addrs.push(sp);
    }
    arg_addrs.reverse();

    let at_execfn_addr = arg_addrs.first().copied().unwrap_or(0);

    sp &= !15;

    // Build frame
    let mut frame: Vec<u64> = Vec::new();

    frame.push(guest_args.len() as u64); // argc

    for addr in &arg_addrs { frame.push(*addr); }
    frame.push(0); // NULL

    for addr in &env_addrs { frame.push(*addr); }
    frame.push(0); // NULL

    // Auxiliary vector
    let mut auxv: Vec<(u64, u64)> = vec![
        (AT_PHDR, phdr_addr),
        (AT_PHENT, elf.header.e_phentsize as u64),
        (AT_PHNUM, elf.header.e_phnum as u64),
        (AT_PAGESZ, 4096),
        (AT_ENTRY, base_offset + elf.header.e_entry),
        (AT_UID, unsafe { libc::getuid() as u64 }),
        (AT_EUID, unsafe { libc::geteuid() as u64 }),
        (AT_GID, unsafe { libc::getgid() as u64 }),
        (AT_EGID, unsafe { libc::getegid() as u64 }),
        (AT_CLKTCK, 100),
        (AT_RANDOM, at_random_addr),
        (AT_HWCAP, 0),
        (AT_EXECFN, at_execfn_addr),
    ];
    if interp_base != 0 {
        auxv.push((AT_BASE, interp_base));
    }
    auxv.push((AT_NULL, 0));

    // Save auxv bytes for /proc/self/auxv
    let mut auxv_bytes: Vec<u8> = Vec::new();
    for (typ, val) in &auxv {
        auxv_bytes.extend_from_slice(&typ.to_le_bytes());
        auxv_bytes.extend_from_slice(&val.to_le_bytes());
        frame.push(*typ);
        frame.push(*val);
    }
    procfs::set_auxv(auxv_bytes);

    let frame_bytes = frame.len() * 8;
    sp -= frame_bytes as u64;
    sp &= !15;

    for (i, val) in frame.iter().enumerate() {
        unsafe { ((sp + (i as u64) * 8) as *mut u64).write(*val); }
    }

    Ok(sp)
}

/// Fix up absolute pointers in relocated ET_EXEC data segments.
/// Scans writable PT_LOAD segments for 8-byte values that fall within the
/// binary's original address range and adjusts them by base_offset.
fn fixup_exec_pointers(elf: &Elf, base_offset: u64) {
    // Determine the binary's original address range from PT_LOAD segments
    let mut orig_lo = u64::MAX;
    let mut orig_hi: u64 = 0;
    for phdr in &elf.phdrs {
        if phdr.p_type != PT_LOAD { continue; }
        let lo = phdr.p_vaddr;
        let hi = phdr.p_vaddr + phdr.p_memsz;
        if lo < orig_lo { orig_lo = lo; }
        if hi > orig_hi { orig_hi = hi; }
    }
    if orig_lo >= orig_hi { return; }

    let mut fixed = 0u64;
    for phdr in &elf.phdrs {
        if phdr.p_type != PT_LOAD { continue; }
        // Only scan writable segments (data/bss) — not code
        if phdr.p_flags & 2 == 0 { continue; } // PF_W = 2

        let seg_start = base_offset + phdr.p_vaddr;
        // Only scan the file-backed portion (filesz), not zeroed BSS
        let seg_filesz = phdr.p_filesz;

        // Scan every 8-byte aligned position for pointers in the original range
        let mut off: u64 = 0;
        while off + 8 <= seg_filesz {
            let ptr_addr = seg_start + off;
            let val = unsafe { *(ptr_addr as *const u64) };
            if val >= orig_lo && val < orig_hi {
                let new_val = val + base_offset;
                unsafe { *(ptr_addr as *mut u64) = new_val; }
                fixed += 1;
            }
            off += 8;
        }
    }
    if fixed > 0 {
        eprintln!("fakelinux: fixed up {} absolute pointers in ET_EXEC data", fixed);
    }
}

/// Apply R_AARCH64_RELATIVE relocations from the DYNAMIC segment.
/// This does what the binary's self-relocation code would normally do at startup.
fn apply_relocations(elf: &Elf, data: &[u8], base: u64) -> Result<(), ElfError> {
    // Find the PT_DYNAMIC segment
    let dyn_phdr = elf.phdrs.iter().find(|p| p.p_type == 2 /* PT_DYNAMIC */);
    let dyn_phdr = match dyn_phdr {
        Some(p) => p,
        None => return Ok(()), // no dynamic section
    };

    // Read dynamic entries from the file to find DT_RELA, DT_RELASZ, DT_JMPREL, DT_PLTRELSZ
    let dyn_off = dyn_phdr.p_offset as usize;
    let dyn_size = dyn_phdr.p_filesz as usize;
    if dyn_off + dyn_size > data.len() {
        return Err(ElfError("DYNAMIC segment out of bounds".into()));
    }

    let mut rela_offset: u64 = 0;
    let mut rela_size: u64 = 0;
    let mut rela_ent: u64 = 24; // default RELA entry size
    let mut jmprel_offset: u64 = 0;
    let mut jmprel_size: u64 = 0;

    // Parse DT entries (each is 16 bytes: d_tag:8, d_val:8)
    let mut i = dyn_off;
    while i + 16 <= dyn_off + dyn_size {
        let tag = u64::from_le_bytes(data[i..i+8].try_into().unwrap());
        let val = u64::from_le_bytes(data[i+8..i+16].try_into().unwrap());
        match tag {
            0 => break,           // DT_NULL
            7 => rela_offset = val,   // DT_RELA (vaddr of .rela.dyn)
            8 => rela_size = val,     // DT_RELASZ
            9 => rela_ent = val,      // DT_RELAENT
            23 => jmprel_offset = val, // DT_JMPREL (vaddr of .rela.plt)
            2 => jmprel_size = val,   // DT_PLTRELSZ
            _ => {}
        }
        i += 16;
    }

    let mut applied = 0u64;

    // Apply .rela.dyn
    if rela_offset != 0 && rela_size != 0 {
        applied += apply_rela_section(data, base, rela_offset, rela_size, rela_ent)?;
    }

    // Apply .rela.plt (JMPREL)
    if jmprel_offset != 0 && jmprel_size != 0 {
        applied += apply_rela_section(data, base, jmprel_offset, jmprel_size, rela_ent)?;
    }

    if applied > 0 {
        eprintln!("fakelinux: applied {} R_AARCH64_RELATIVE relocations", applied);
    }

    Ok(())
}

/// Apply relocations from a single RELA section.
fn apply_rela_section(data: &[u8], base: u64, rela_vaddr: u64, rela_size: u64, rela_ent: u64) -> Result<u64, ElfError> {
    // rela_vaddr is a virtual address in the original ELF; find the file offset
    // by looking it up as a file offset directly (for PIE with vaddr=0 base, these are the same as file offsets for the first segment)
    // Actually, for a PIE binary, the file offset and vaddr of the first LOAD segment start at 0,
    // so rela_vaddr IS the file offset for sections in the first LOAD segment.
    let rela_file_off = rela_vaddr as usize;

    let count = rela_size / rela_ent;
    let mut applied = 0u64;

    for j in 0..count {
        let off = rela_file_off + (j as usize) * (rela_ent as usize);
        if off + 24 > data.len() {
            break;
        }
        let r_offset = u64::from_le_bytes(data[off..off+8].try_into().unwrap());
        let r_info = u64::from_le_bytes(data[off+8..off+16].try_into().unwrap());
        let r_addend = u64::from_le_bytes(data[off+16..off+24].try_into().unwrap());

        let r_type = (r_info & 0xFFFFFFFF) as u32;

        // R_AARCH64_RELATIVE = 0x403 (1027)
        if r_type == 0x403 {
            let target_addr = base + r_offset;
            let value = base + r_addend;
            unsafe {
                (target_addr as *mut u64).write(value);
            }
            applied += 1;
        }
        // R_AARCH64_GLOB_DAT = 0x401, R_AARCH64_JUMP_SLOT = 0x402
        // These require symbol resolution — skip for now
    }

    Ok(applied)
}

fn elf_to_mmap_prot(flags: u32) -> i32 {
    let mut prot = 0;
    if flags & PF_R != 0 { prot |= libc::PROT_READ; }
    if flags & PF_W != 0 { prot |= libc::PROT_WRITE; }
    if flags & PF_X != 0 { prot |= libc::PROT_EXEC; }
    prot
}

/// Transfer control to the loaded binary. Never returns.
///
/// Mimics the Linux kernel's initial register state: all GPRs zeroed,
/// SP pointing to the argc/argv/envp/auxv structure.
/// x0 = 0 is critical: glibc's _start interprets x0 as rtld_fini.
pub unsafe fn jump_to_entry(stack_ptr: u64, entry: u64) -> ! {
    std::arch::asm!(
        // Use x9/x10 as temporaries (they'll be zeroed after use)
        "mov x9, {sp}",
        "mov x10, {entry}",
        // Zero all general-purpose registers
        "mov x0, xzr",
        "mov x1, xzr",
        "mov x2, xzr",
        "mov x3, xzr",
        "mov x4, xzr",
        "mov x5, xzr",
        "mov x6, xzr",
        "mov x7, xzr",
        "mov x8, xzr",
        "mov x11, xzr",
        "mov x12, xzr",
        "mov x13, xzr",
        "mov x14, xzr",
        "mov x15, xzr",
        "mov x16, xzr",
        "mov x17, xzr",
        "mov x18, xzr",
        "mov x19, xzr",
        "mov x20, xzr",
        "mov x21, xzr",
        "mov x22, xzr",
        "mov x23, xzr",
        "mov x24, xzr",
        "mov x25, xzr",
        "mov x26, xzr",
        "mov x27, xzr",
        "mov x28, xzr",
        "mov x29, xzr",
        "mov x30, xzr",
        // Set SP and jump
        "mov sp, x9",
        "mov x9, xzr",
        "br x10",
        sp = in(reg) stack_ptr,
        entry = in(reg) entry,
        options(noreturn)
    );
}
