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

/// Public wrapper for the SIGBUS island-recovery path in trap.rs.
pub fn add_runtime_tpidr_patch_pub(pc: u64, instr: u32) {
    add_runtime_tpidr_patch(pc, instr);
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
        crate::vlog!("fakelinux: interpreter: {}", interp_path);

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
        crate::vlog!("fakelinux: interpreter loaded at {:#x}, entry={:#x}", interp_base, interp_entry);
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
    //
    // For dynamically-linked ET_EXEC (has interpreter), apply RELA relocations
    // ourselves. ld-linux will also apply them, but RELA uses absolute assignment
    // (*(B+r_offset) = B+r_addend) so the second application is idempotent.
    // We do NOT use the heuristic fixup_exec_pointers scan here because it
    // double-relocates pointers that ld-linux also adjusts via DT_* parsing.
    //
    // For statically-linked ET_EXEC (no interpreter), use the heuristic scan
    // since there's no ld-linux to handle relocations.
    if elf.header.e_type == ET_EXEC && base_offset != 0 {
        if interp_entry != 0 {
            // For dynamically-linked ET_EXEC: heuristic scan fixes data pointers
            // that have no RELA entries. Skip .dynamic (ld-linux adds delta to
            // DT_* values itself) and skip addresses with RELA entries (ld-linux's
            // JUMP_SLOT lazy binding adds delta to the current GOT value, so
            // pre-adjusting would cause double relocation).
            fixup_exec_pointers_skip_dynamic(elf, base_offset);

            // Enable lazy relocation: SIGSEGV handler will fix up remaining
            // unrelocated pointers on demand (addresses in the original ET_EXEC
            // range that have no RELA entries and weren't caught by the scan).
            let mut orig_lo = u64::MAX;
            let mut orig_hi: u64 = 0;
            for phdr in &elf.phdrs {
                if phdr.p_type != PT_LOAD { continue; }
                let lo = phdr.p_vaddr;
                let hi = phdr.p_vaddr + phdr.p_memsz;
                if lo < orig_lo { orig_lo = lo; }
                if hi > orig_hi { orig_hi = hi; }
            }
            // Const pointer tables in .rodata (non-PIE puts them there) —
            // python3.12 has ~6000 that the writable-segment scan misses.
            fixup_exec_rodata_pointers(elf, data, base_offset, orig_lo, orig_hi);
            crate::trap::EXEC_BASE_OFFSET.store(base_offset, std::sync::atomic::Ordering::SeqCst);
            crate::trap::EXEC_ORIG_LO.store(orig_lo, std::sync::atomic::Ordering::SeqCst);
            crate::trap::EXEC_ORIG_HI.store(orig_hi, std::sync::atomic::Ordering::SeqCst);
        } else {
            fixup_exec_pointers(elf, base_offset);
        }
    }

    // Set up the guest stack
    let stack_ptr = setup_stack(elf, base_offset, phdr_addr, interp_base, guest_args)?;

    // Entry point: use interpreter if present, otherwise the binary's own entry
    let entry = if interp_entry != 0 {
        interp_entry
    } else {
        base_offset + elf.header.e_entry
    };

    crate::vlog!("fakelinux: entry={:#x} sp={:#x} brk={:#x}", entry, stack_ptr, brk_start);

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

/// Detect embedded literal pools by scanning for `adr xN, target` instructions
/// followed (within a few instructions) by `ldr ?, [xN], #...` (post-increment
/// load via the same register). This is the canonical ARM idiom for reading
/// from an embedded data table (e.g. SHA-256 K constants in libcrypto's
/// SHA256_Transform).
///
/// Returns a sorted Vec of `(start_addr, end_addr)` ranges. Each pool ends at
/// the next function prologue (`paciasp` / `stp x29, x30, [sp, #-N]!`) or at
/// MAX_LITERAL_POOL_SIZE, whichever comes first.
///
/// The detection is intentionally conservative: it requires BOTH the ADR and
/// the post-increment load to match before excluding a region. A bare ADR
/// (e.g. for code addresses, switch table bases) is NOT excluded.
fn find_literal_pools(start: u64, len: u64) -> Vec<(u64, u64)> {
    // Hard cap on pool size.
    const MAX_LITERAL_POOL_SIZE: u64 = 512;
    // How many instructions after the ADR to look for the post-inc load.
    const LOOKAHEAD_INSTRS: usize = 8;

    let count = len / 4;
    let base = start as *const u32;
    let mut pool_starts: Vec<u64> = Vec::new();

    // NOTE: The SHA-256 K-table fingerprint that used to be here was removed.
    // It's no longer needed because:
    // 1. Modern aarch64 toolchains place K tables in .rodata (not .text).
    // 2. Even if in .text, the .eh_frame FDE-based code range extraction
    //    (Strategy 1 in extract_code_ranges_from_memory) automatically
    //    excludes inter-function data gaps.
    // The ADR+load heuristic below remains as a secondary defense for
    // INTRA-function literal pools (data embedded inside a function body).

    for i in 0..count as usize {
        let pc = start + (i as u64) * 4;
        let instr = unsafe { base.add(i).read() };

        // Match ADR (not ADRP — ADRP usually points to .rodata in another seg)
        // ADR encoding: bit[31]=0, bits[28:24]=10000
        if (instr & 0x9F000000) != 0x10000000 { continue; }

        // Decode 21-bit signed immediate (immhi:immlo)
        let immlo = ((instr >> 29) & 0x3) as u64;
        let immhi = ((instr >> 5) & 0x7FFFF) as u64;
        let imm21 = (immhi << 2) | immlo;
        let imm = if imm21 & (1 << 20) != 0 {
            (imm21 | !((1u64 << 21) - 1)) as i64
        } else {
            imm21 as i64
        };
        let target = pc.wrapping_add(imm as u64);
        let rd = (instr & 0x1F) as u32;

        // Target must be a forward reference within the scan range
        if target <= pc || target >= start + len { continue; }

        // Look ahead for post-increment load via the same register.
        // LDR (immediate, post-index) encoding:
        //   size_111_00_0_x_0_imm9_01_Rn_Rt
        //   (bits[29:27]=111, bit[26]=0, bit[24]=0, bits[21]=0, bits[11:10]=01)
        // For our purposes, accept any load with [Rn], #imm post-index where Rn==rd
        let mut found_load = false;
        let max_j = (i + LOOKAHEAD_INSTRS).min(count as usize);
        for j in (i + 1)..max_j {
            let next = unsafe { base.add(j).read() };
            // Match LDR (immediate, post-index): xx_111_00_0_x_0_imm9_01_Rn_Rt
            // Mask: 0x3FE00C00, value: 0x38400400 covers LDR/LDRSW post-index loads
            // Also check pair forms: LDP post-index is xx_101_00_01_imm7_Rt2_Rn_Rt
            let is_ldr_postinc = (next & 0x3FE00C00) == 0x38400400;
            let is_ldp_postinc = (next & 0x7E800000) == 0x28800000;
            if is_ldr_postinc || is_ldp_postinc {
                let rn = (next >> 5) & 0x1F;
                if rn == rd {
                    found_load = true;
                    break;
                }
            }
        }
        if found_load {
            pool_starts.push(target);
        }
    }

    if pool_starts.is_empty() { return Vec::new(); }
    pool_starts.sort_unstable();
    pool_starts.dedup();

    // Build pool ranges, terminating at function prologues.
    let mut pools: Vec<(u64, u64)> = Vec::with_capacity(pool_starts.len());
    for (idx, &pool_start) in pool_starts.iter().enumerate() {
        let mut pool_end = pool_start + MAX_LITERAL_POOL_SIZE;
        if pool_end > start + len { pool_end = start + len; }
        if let Some(&next_start) = pool_starts.get(idx + 1) {
            if next_start < pool_end { pool_end = next_start; }
        }

        // Walk forward from pool_start looking for clear function prologue.
        // PACIASP: 0xd503233f
        // STP x29, x30, [sp, #-N]!: bits match 0xa9bX7BFD or 0xa9aX7BFD
        let mut scan = pool_start;
        while scan < pool_end {
            if scan + 4 > start + len { break; }
            let off = scan - start;
            let word = unsafe { base.add((off / 4) as usize).read() };
            // PACIASP marker
            if word == 0xd503233fu32 {
                pool_end = scan;
                break;
            }
            // STP x29, x30, [sp, #-N]!  pre-index with Rt=29, Rt2=30, Rn=31
            // Mask 0x7FC07FFF, value 0xA9807BFD covers the pre-index variant.
            if (word & 0x7FC07FFF) == 0xA9807BFDu32 {
                pool_end = scan;
                break;
            }
            scan += 4;
        }

        if pool_end > pool_start {
            pools.push((pool_start, pool_end));
        }
    }
    pools
}

/// Check if an address falls within a literal pool range.
fn addr_in_pools(addr: u64, pools: &[(u64, u64)]) -> bool {
    // Pools are sorted; binary search would be faster for large lists.
    for &(s, e) in pools {
        if addr >= s && addr < e { return true; }
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
    // Find embedded literal pools (e.g. SHA-256 K table) to exclude from x18 patching.
    // These are data tables embedded in .text, reached via ADR + load (not execution).
    let literal_pools = find_literal_pools(start, size);
    for i in 0..count as usize {
        unsafe {
            let instr = base.add(i).read();
            if instr == trap::SVC_0 {
                // SVC #0 → UDF #0xF000
                base.add(i).write(trap::UDF_MARKER);
                svc_patched += 1;
            } else if instr & trap::MSR_TPIDR_MASK == trap::MSR_TPIDR_BASE
                   || instr & trap::MRS_TPIDR_MASK == trap::MRS_TPIDR_BASE {
                // MSR/MRS tpidr_el0 → trampoline (native TLS access);
                // fall back to UDF + side table if out of range/unknown.
                let pc_addr = base.add(i) as u64;
                crate::procfs::with(|_| {}); // ensure procfs is initialized
                if !crate::x18_trampoline::patch_tpidr_with_trampoline(pc_addr, instr) {
                    add_tpidr_patch(pc_addr, instr);
                    base.add(i).write(trap::UDF_MARKER);
                }
                tpidr_patched += 1;
            } else if !skip_x18 && trap::references_x18(instr) {
                let pc_addr = base.add(i) as u64;
                let offset = (i as u64) * 4;
                // Only patch x18 in actual code sections — data in the same segment
                // (e.g. .dynstr, .rodata) could match x18 patterns and must not be corrupted.
                // Also skip literal pools (data embedded in .text via ADR+load).
                if (!have_code_ranges || addr_in_code_ranges(pc_addr, code_ranges))
                    && !addr_in_pools(pc_addr, &literal_pools)
                    && offset < x18_max_offset {
                    if !crate::x18_trampoline::patch_x18_with_trampoline(pc_addr, instr) {
                        add_tpidr_patch(pc_addr, instr);
                        base.add(i).write(trap::UDF_MARKER);
                    }
                    x18_patched += 1;
                }
            }
        }
    }
    crate::x18_trampoline::flush_all_islands();
    if svc_patched > 0 {
        crate::vlog!("fakelinux: patched {} SVC→UDF instructions", svc_patched);
    }
    if tpidr_patched > 0 {
        crate::vlog!("fakelinux: patched {} MSR/MRS tpidr_el0 instructions", tpidr_patched);
    }
    if x18_patched > 0 {
        crate::vlog!("fakelinux: patched {} x18 instructions", x18_patched);
    }
}

// ── Persistent patch-site cache ──────────────────────────────────────────
// patch_new_code scans every word of each executable file-backed mapping.
// Build workloads spawn thousands of short-lived processes that each re-map
// the same big libraries (libLLVM text alone is ~120MB = ~30M instructions),
// so the scan dominates runtime (93% of samples in a profiled clang).
// The set of patch sites for a given (file, offset, len) never changes, so
// we cache the byte offsets on disk and on later mappings only re-apply the
// patches at those offsets (validating each still matches a patchable
// pattern; any mismatch falls back to a full scan).
//
// Runs in trap_handler (signal) context: file I/O uses raw libc only, and
// the env knobs are read once in init_patch_cache() (see the env-lock
// deadlock note in trap.rs above init_trace_flags).

const PATCH_CACHE_MAGIC: u32 = 0x434C_5046; // "FPLC"
const PATCH_CACHE_VERSION: u32 = 1;

static PATCH_CACHE_DIR: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();
static NO_X18_RUNTIME: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Read patch-cache env knobs ONCE, outside signal context. Called from
/// trap::init_trace_flags() (i.e. install_handler, before any guest code).
pub fn init_patch_cache() {
    NO_X18_RUNTIME.store(
        std::env::var_os("FAKELINUX_NO_X18").is_some(),
        std::sync::atomic::Ordering::Relaxed,
    );
    if std::env::var_os("FAKELINUX_NO_PATCH_CACHE").is_some() {
        return;
    }
    let dir = std::env::var("FAKELINUX_PATCH_CACHE").unwrap_or_else(|_| {
        format!("/tmp/fakelinux-patch-cache-{}", unsafe { libc::getuid() })
    });
    let cdir = match std::ffi::CString::new(dir) {
        Ok(c) => c,
        Err(_) => return,
    };
    unsafe { libc::mkdir(cdir.as_ptr(), 0o700); } // EEXIST is fine
    let _ = PATCH_CACHE_DIR.set(cdir);
}

/// Cache file name for one (file identity, mapping window).
fn patch_cache_filename(dev: u64, ino: u64, mtime_s: i64, mtime_ns: i64,
                        size: u64, offset: u64, len: u64) -> String {
    format!("{:x}-{:x}-{:x}.{:x}-{:x}-{:x}-{:x}.v{}",
        dev, ino, mtime_s, mtime_ns, size, offset, len, PATCH_CACHE_VERSION)
}

/// Serialize patch-site byte offsets: magic, version, count, then u32 LE offsets.
fn encode_patch_cache(sites: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + sites.len() * 4);
    out.extend_from_slice(&PATCH_CACHE_MAGIC.to_le_bytes());
    out.extend_from_slice(&PATCH_CACHE_VERSION.to_le_bytes());
    out.extend_from_slice(&(sites.len() as u64).to_le_bytes());
    for s in sites {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out
}

/// Parse a cache file. None on any size/magic/version mismatch.
fn parse_patch_cache(data: &[u8]) -> Option<Vec<u32>> {
    if data.len() < 16 {
        return None;
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
    let version = u32::from_le_bytes(data[4..8].try_into().ok()?);
    let count = u64::from_le_bytes(data[8..16].try_into().ok()?) as usize;
    if magic != PATCH_CACHE_MAGIC || version != PATCH_CACHE_VERSION
        || data.len() != 16 + count * 4 {
        return None;
    }
    let mut sites = Vec::with_capacity(count);
    for i in 0..count {
        let off = 16 + i * 4;
        sites.push(u32::from_le_bytes(data[off..off + 4].try_into().ok()?));
    }
    Some(sites)
}

/// Full cache path for the file behind `fd` mapped at (offset, len), or None
/// if the cache is disabled or fstat fails.
fn patch_cache_path(fd: i32, offset: u64, len: u64) -> Option<Vec<u8>> {
    let dir = PATCH_CACHE_DIR.get()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 || st.st_size <= 0 {
        return None;
    }
    let name = patch_cache_filename(
        st.st_dev as u64, st.st_ino, st.st_mtime, st.st_mtime_nsec,
        st.st_size as u64, offset, len);
    let mut path = dir.as_bytes().to_vec();
    path.push(b'/');
    path.extend_from_slice(name.as_bytes());
    Some(path)
}

/// Read an entire file with raw libc (async-signal-safe I/O). None if missing.
fn read_file_raw(path: &[u8]) -> Option<Vec<u8>> {
    let cpath = std::ffi::CString::new(path).ok()?;
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return None;
    }
    let mut buf = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr() as *mut _, chunk.len()) };
        if n < 0 {
            unsafe { libc::close(fd) };
            return None;
        }
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n as usize]);
    }
    unsafe { libc::close(fd) };
    Some(buf)
}

/// Atomically write a file with raw libc: write to a unique temp, rename.
/// Temp name includes pid AND a process-wide counter — two threads of one
/// process writing the same cache key must not share a temp file (the
/// interleaved writes would rename garbage over a good cache entry).
fn write_file_raw_atomic(path: &[u8], data: &[u8]) {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let pid = unsafe { libc::getpid() };
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut tmp = path.to_vec();
    tmp.extend_from_slice(format!(".tmp.{}.{}", pid, seq).as_bytes());
    let (ctmp, cpath) = match (std::ffi::CString::new(tmp), std::ffi::CString::new(path)) {
        (Ok(t), Ok(p)) => (t, p),
        _ => return,
    };
    let fd = unsafe {
        libc::open(ctmp.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o600)
    };
    if fd < 0 {
        return;
    }
    let mut written = 0usize;
    while written < data.len() {
        let n = unsafe {
            libc::write(fd, data[written..].as_ptr() as *const _, data.len() - written)
        };
        if n <= 0 {
            unsafe { libc::close(fd); libc::unlink(ctmp.as_ptr()); }
            return;
        }
        written += n as usize;
    }
    unsafe {
        libc::close(fd);
        libc::rename(ctmp.as_ptr(), cpath.as_ptr());
    }
}

/// Classify one instruction word the same way the patch_new_code scan does.
/// Returns false for anything the scan would not have patched (stale cache).
fn apply_cached_patch_site(pc_addr: u64, instr: u32) -> bool {
    if instr == trap::SVC_0 {
        unsafe { (pc_addr as *mut u32).write(trap::UDF_MARKER) };
        true
    } else if instr & trap::MSR_TPIDR_MASK == trap::MSR_TPIDR_BASE
           || instr & trap::MRS_TPIDR_MASK == trap::MRS_TPIDR_BASE {
        if !crate::x18_trampoline::patch_tpidr_with_trampoline(pc_addr, instr) {
            add_runtime_tpidr_patch(pc_addr, instr);
            unsafe { (pc_addr as *mut u32).write(trap::UDF_MARKER) };
        }
        true
    } else if trap::references_x18(instr) {
        if !crate::x18_trampoline::patch_x18_with_trampoline(pc_addr, instr) {
            add_runtime_tpidr_patch(pc_addr, instr);
            unsafe { (pc_addr as *mut u32).write(trap::UDF_MARKER) };
        }
        true
    } else {
        false
    }
}

/// Try to patch from the persistent cache. Returns true if fully applied.
/// Validates every cached offset BEFORE writing anything, so a stale entry
/// falls back to the full scan with memory untouched.
fn try_patch_from_cache(start: u64, len: u64, fd: i32, offset: u64) -> bool {
    let path = match patch_cache_path(fd, offset, len) {
        Some(p) => p,
        None => return false,
    };
    let data = match read_file_raw(&path) {
        Some(d) => d,
        None => return false,
    };
    let sites = match parse_patch_cache(&data) {
        Some(s) => s,
        None => return false,
    };
    let skip_x18 = NO_X18_RUNTIME.load(std::sync::atomic::Ordering::Relaxed);
    // Pass 1: validate (read-only).
    for &site in &sites {
        let off = site as u64;
        if off + 4 > len || off & 3 != 0 {
            return false;
        }
        let instr = unsafe { ((start + off) as *const u32).read() };
        let patchable = instr == trap::SVC_0
            || instr & trap::MSR_TPIDR_MASK == trap::MSR_TPIDR_BASE
            || instr & trap::MRS_TPIDR_MASK == trap::MRS_TPIDR_BASE
            || (!skip_x18 && trap::references_x18(instr));
        if !patchable {
            return false;
        }
    }
    // Pass 2: apply.
    for &site in &sites {
        let pc_addr = start + site as u64;
        let instr = unsafe { (pc_addr as *const u32).read() };
        apply_cached_patch_site(pc_addr, instr);
    }
    crate::x18_trampoline::flush_all_islands();
    if !sites.is_empty() {
        crate::vlog!("fakelinux: runtime patch at {:#x}+{:#x}: {} sites (cached)",
            start, len, sites.len());
    }
    true
}

/// patch_new_code for file-backed mappings: consult the persistent patch-site
/// cache first; on miss run the full scan and record the sites it patched.
pub fn patch_new_code_file(start: u64, len: u64, fd: i32, offset: u64) {
    if try_patch_from_cache(start, len, fd, offset) {
        return;
    }
    let sites = patch_new_code(start, len);
    if let Some(path) = patch_cache_path(fd, offset, len) {
        write_file_raw_atomic(&path, &encode_patch_cache(&sites));
    }
}

/// Patch newly-executable code pages at runtime (called from mprotect/mmap).
/// Scans the given address range for SVC #0 and MSR/MRS tpidr_el0, patches them,
/// and adds TPIDR patches to the runtime table.
///
/// The caller must ensure the memory is writable before calling this.
/// After patching, the caller should set the final permissions and invalidate icache.
/// Returns the byte offsets (from `start`) of every site it patched, for the
/// patch-site cache.
pub fn patch_new_code(start: u64, len: u64) -> Vec<u32> {
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
    let mut sites: Vec<u32> = Vec::new();
    let have_code_ranges = !code_ranges.is_empty();
    // Cached at init_patch_cache() — std::env::var takes the env lock, which
    // self-deadlocks in signal context (see init_trace_flags note in trap.rs).
    let skip_x18 = NO_X18_RUNTIME.load(std::sync::atomic::Ordering::Relaxed);
    // Find embedded literal pools to exclude from x18 patching.
    let literal_pools = find_literal_pools(start, len);
    for i in 0..count as usize {
        unsafe {
            let instr = base.add(i).read();
            if instr == trap::SVC_0 {
                base.add(i).write(trap::UDF_MARKER);
                svc_patched += 1;
                sites.push((i * 4) as u32);
            } else if instr & trap::MSR_TPIDR_MASK == trap::MSR_TPIDR_BASE
                   || instr & trap::MRS_TPIDR_MASK == trap::MRS_TPIDR_BASE {
                let pc_addr = base.add(i) as u64;
                if !crate::x18_trampoline::patch_tpidr_with_trampoline(pc_addr, instr) {
                    add_runtime_tpidr_patch(pc_addr, instr);
                    base.add(i).write(trap::UDF_MARKER);
                }
                tpidr_patched += 1;
                sites.push((i * 4) as u32);
            } else if !skip_x18 && trap::references_x18(instr) {
                let pc_addr = base.add(i) as u64;
                // x18 patterns have high false-positive rates on data (string tables,
                // symbol tables, etc.). Only patch if we have confirmed code ranges
                // AND we're not in a literal pool (data embedded in .text).
                if have_code_ranges && addr_in_code_ranges(pc_addr, &code_ranges)
                    && !addr_in_pools(pc_addr, &literal_pools) {
                    if !crate::x18_trampoline::patch_x18_with_trampoline(pc_addr, instr) {
                        add_runtime_tpidr_patch(pc_addr, instr);
                        base.add(i).write(trap::UDF_MARKER);
                    }
                    x18_patched += 1;
                    sites.push((i * 4) as u32);
                } else if !have_code_ranges {
                    x18_skipped += 1;
                }
            }
        }
    }
    crate::x18_trampoline::flush_all_islands();
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
    sites
}

/// Try to extract code ranges from ELF headers in mapped memory.
///
/// Strategies (tried in order):
/// 1. .eh_frame FDE ranges — most precise, function-level granularity.
///    Automatically excludes literal pools, crypto constant tables, etc.
/// 2. Section headers (SHF_EXECINSTR) — broad, marks entire .text/.plt.
/// 3. Program headers + PT_DYNAMIC exclusion — coarsest, subtracts known data.
///
/// Returns empty vec if no code ranges can be determined.
fn extract_code_ranges_from_memory(base_addr: u64, len: u64) -> Vec<(u64, u64)> {
    const SHF_EXECINSTR: u64 = 4;
    let data = unsafe { std::slice::from_raw_parts(base_addr as *const u8, len as usize) };

    // Check ELF magic
    if data.len() < 64 || data[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Vec::new();
    }

    // Strategy 1: .eh_frame FDE ranges (function-level precision)
    let fde_ranges = elf::find_code_ranges_from_eh_frame(data, base_addr);
    if !fde_ranges.is_empty() {
        return fde_ranges;
    }

    // Strategy 2: section headers (SHF_EXECINSTR)
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

    // Strategy 3: program headers + PT_DYNAMIC to exclude known data regions
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

/// Reserve one PROT_NONE page at the top of macOS's usable user VA and
/// publish it in /proc/self/maps. Guests sniff their VA-space size from the
/// highest maps entry (VPP's svm_get_global_region_base_va) and then MAP_FIXED
/// at 2^(bits-2). macOS cannot map [0xfc0000000, 0x7000000000), so the 39 bits
/// implied by our 0x7ff0000000 guest stack yields an unmappable baseva; the
/// reservation ends at 2^47 → 47 bits → baseva 0x200000000000, which works.
fn reserve_va_top_page() -> bool {
    // Highest MAP_FIXED-able page on macOS arm64 (probed; just under 2^47).
    // end-1 = 0x7ffffdffffff still has 47 significant bits.
    const VA_TOP_PAGE: u64 = 0x7FFF_FDFF_C000;
    const PAGE: u64 = 16384;
    let ret = unsafe {
        libc::mmap(VA_TOP_PAGE as *mut _, PAGE as usize, libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED, -1, 0)
    };
    if ret == libc::MAP_FAILED {
        return false;
    }
    // Idempotent registration (re-exec re-inits procfs, but tests call twice)
    let already = procfs::with(|pfs| pfs.mappings.iter().any(|m| m.start == VA_TOP_PAGE));
    if !already {
        procfs::add_mapping(procfs::MemMapping {
            start: VA_TOP_PAGE,
            end: VA_TOP_PAGE + PAGE,
            prot: libc::PROT_NONE,
            flags: libc::MAP_PRIVATE,
            offset: 0,
            name: String::new(),
        });
    }
    true
}

/// Page size reported to the guest via AT_PAGESZ (→ glibc sysconf
/// _SC_PAGESIZE). Default 4096 — what Ubuntu arm64 userland expects.
/// FAKELINUX_PAGESZ=16384 makes guests compute 16K-aligned addresses
/// (16K pages are real on Linux arm64 — Asahi — so glibc handles it).
/// Why: VPP's clib_mem_vm_reserve returns base + sys_page_sz (a guard
/// page), so with a 4K guest page size every shared segment lands
/// 16K-MISALIGNED and can never be a native MAP_SHARED on 16K-page
/// macOS — multi-process stats/svm clients then read snapshots.
pub fn guest_page_size() -> u64 {
    parse_guest_pagesz(std::env::var("FAKELINUX_PAGESZ").ok().as_deref())
}

fn parse_guest_pagesz(v: Option<&str>) -> u64 {
    match v.and_then(|v| v.parse::<u64>().ok()) {
        Some(sz) if sz.is_power_of_two() && (4096..=65536).contains(&sz) => sz,
        _ => 4096,
    }
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

    // VA-top marker so guests detect a usable VA-space size (see fn docs)
    reserve_va_top_page();

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

    // 2) Environment strings — inherit from the host process environ,
    // strip FAKELINUX_* (supervisor-internal), and add sane defaults if
    // the host didn't set PATH/HOME/TERM. This is critical: the guest's
    // setenv() (e.g. Perl's `$ENV{DEBIAN_HAS_FRONTEND}=1`) updates the
    // host libc's environ, which we pass through to any re-exec'd fakelinux
    // via do_execve — then here, the re-exec'd instance makes the guest-
    // visible env mirror those updates.
    let host_env = collect_host_environ();
    let host_env_refs: Vec<&std::ffi::CStr> = host_env.iter().map(|c| c.as_ref()).collect();
    let env_owned = build_guest_env(&host_env_refs);
    let mut env_addrs: Vec<u64> = Vec::new();
    // Reverse iterate so pushes (decreasing sp) land in the right order.
    for e in env_owned.iter().rev() {
        let mut bytes = e.to_bytes().to_vec();
        bytes.push(0); // NUL terminator
        push_bytes(&mut sp, &bytes);
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
        (AT_PAGESZ, guest_page_size()),
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

/// Like fixup_exec_pointers but skips PT_DYNAMIC and all addresses covered
/// by RELA entries. Used for dynamically-linked ET_EXEC.
///
/// ld-linux processes RELA entries itself. For R_AARCH64_RELATIVE, ld-linux
/// uses absolute assignment (idempotent). But for R_AARCH64_JUMP_SLOT with
/// lazy binding, ld-linux ADDS the load delta to the current GOT value.
/// If we pre-adjust those GOT entries, ld-linux double-relocates them.
/// Decide whether an 8-byte word found in a relocated ET_EXEC's data is
/// plausibly an unrelocated absolute pointer (and should be eagerly fixed
/// up by adding base_offset), versus a packed small-integer struct that
/// merely aliases into the [orig_lo, orig_hi) range.
///
/// Real case: gcc cc1's insn_operand_data flags word for match_operator
/// operands — {mode:16, strict_low, is_operator=1, eliminable=0,
/// allows_mem=0} — reads as u64 0x0100_0000|mode, square inside cc1's
/// [0x400000, 0x2400000) range. Adding the 0x7_0000_0000 base set the
/// `eliminable` byte to 7, so reload's elimination_costs_in_insn walked
/// match_operator operands after NULLing their nested operand slot
/// (*recog_data.operand_loc[i] = 0): deterministic SIGSEGV in
/// eliminate_regs_1 on any function with a ccmp insn (libbpf bpf.c, ICE
/// "during RTL pass: ira").
///
/// Heuristic: a packed-flags word has ≤2 nonzero bytes, sits at or above
/// 16M (byte 3+ carries a flag — small binaries like python3.12 live
/// entirely below 16M, where sparse-looking REAL pointers are common and
/// rejecting them broke CPython's static type tables), and has byte 2
/// zero (mode:16 in bytes 0-1, strict_low in byte 2 is 0 for operators —
/// a real pointer ≥16M almost always has nonzero bits in its 0xFF0000
/// byte). The asymmetry justifying rejection: a missed real pointer is
/// recovered by the lazy-relocation fault handler on first dereference,
/// but a relocated non-pointer is silent memory corruption.
fn plausible_unrelocated_pointer(val: u64, orig_lo: u64, orig_hi: u64) -> bool {
    if val < orig_lo || val >= orig_hi {
        return false;
    }
    let sparse = val.to_le_bytes().iter().filter(|&&b| b != 0).count() <= 2;
    !(sparse && val >= 0x100_0000 && val & 0xFF_0000 == 0)
}

fn fixup_exec_pointers_skip_dynamic(elf: &Elf, base_offset: u64) {
    // Find PT_DYNAMIC range to exclude
    let dyn_phdr = elf.phdrs.iter().find(|p| p.p_type == 2 /* PT_DYNAMIC */);
    let (dyn_start, dyn_end) = if let Some(dp) = dyn_phdr {
        let ds = base_offset + dp.p_vaddr;
        (ds, ds + dp.p_memsz)
    } else {
        (0u64, 0u64)
    };

    // Build set of addresses covered by RELA entries (skip these in the scan).
    // Read .dynamic from memory to find .rela.dyn and .rela.plt.
    let mut rela_targets = std::collections::HashSet::new();
    if let Some(dp) = dyn_phdr {
        let dyn_mem = base_offset + dp.p_vaddr;
        let dyn_size = dp.p_filesz;

        let mut rela_vaddr: u64 = 0;
        let mut rela_size: u64 = 0;
        let mut rela_ent: u64 = 24;
        let mut jmprel_vaddr: u64 = 0;
        let mut jmprel_size: u64 = 0;

        let mut i: u64 = 0;
        while i + 16 <= dyn_size {
            let tag = unsafe { *((dyn_mem + i) as *const u64) };
            let val = unsafe { *((dyn_mem + i + 8) as *const u64) };
            match tag {
                0 => break,
                7 => rela_vaddr = val,
                8 => rela_size = val,
                9 => rela_ent = val,
                23 => jmprel_vaddr = val,
                2 => jmprel_size = val,
                _ => {}
            }
            i += 16;
        }

        // Collect r_offset from each RELA section
        for &(vaddr, size) in &[(rela_vaddr, rela_size), (jmprel_vaddr, jmprel_size)] {
            if vaddr == 0 || size == 0 { continue; }
            let mem = base_offset + vaddr;
            let count = size / rela_ent;
            for j in 0..count {
                let entry = mem + j * rela_ent;
                let r_offset = unsafe { *(entry as *const u64) };
                // r_offset is the original vaddr; the relocated address is base_offset + r_offset
                rela_targets.insert(base_offset + r_offset);
            }
        }
    }

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
    let mut skipped_rela = 0u64;
    for phdr in &elf.phdrs {
        if phdr.p_type != PT_LOAD { continue; }
        if phdr.p_flags & 2 == 0 { continue; }

        let seg_start = base_offset + phdr.p_vaddr;
        let seg_filesz = phdr.p_filesz;
        let mut off: u64 = 0;
        while off + 8 <= seg_filesz {
            let ptr_addr = seg_start + off;
            // Skip PT_DYNAMIC
            if dyn_end > dyn_start && ptr_addr >= dyn_start && ptr_addr < dyn_end {
                off += 8;
                continue;
            }
            // Skip addresses with RELA entries (ld-linux handles them)
            if rela_targets.contains(&ptr_addr) {
                off += 8;
                skipped_rela += 1;
                continue;
            }
            let val = unsafe { *(ptr_addr as *const u64) };
            if plausible_unrelocated_pointer(val, orig_lo, orig_hi) {
                unsafe { *(ptr_addr as *mut u64) = val + base_offset; }
                fixed += 1;
            }
            off += 8;
        }
    }
    if fixed > 0 || skipped_rela > 0 {
        crate::vlog!("fakelinux: fixed up {} absolute pointers in ET_EXEC data ({} skipped, RELA-covered)",
                  fixed, skipped_rela);
    }
}

/// Fix up absolute pointers in the .rodata section of a relocated ET_EXEC.
/// Non-PIE binaries put const pointer tables (function pointer arrays,
/// string tables, static PyObject graphs…) in .rodata, which the writable-
/// segment scan never touches — python3.12 has ~6000 such pointers and
/// crashes chasing them. .rodata is mapped read-only, so temporarily make
/// it writable. Section identified by name to avoid touching .dynsym,
/// .gnu.hash, .eh_frame etc. which ld-linux interprets itself.
/// Scan executable code for switch jump tables located in .rodata, so the
/// pointer-fixup heuristic can skip them.
///
/// The fixup scan patches any aligned u64 in [orig_lo, orig_hi) by adding
/// base_offset — but a switch jump table is an array of small 16-bit code
/// offsets, and four consecutive halfwords like [0x0000, 0x0054, 0x0000,
/// 0x0000] read as u64 0x540000, square in the "unrelocated pointer" range.
/// The fixup then writes 0x0007 into the third halfword, sending some switch
/// case into the middle of an unrelated basic block (gcc cc1's
/// equiv_oracle::find_equiv_block ICE'd exactly this way on hello-world).
///
/// Only DISPATCH tables can alias into the pointer range like this; plain
/// data lookup tables (e.g. gcc's tree_contains_struct byte array) hold
/// small values whose u64 view is out of range, and excluding them is
/// actively harmful: their true length is unknowable, and pointer data right
/// after the table would be left unrelocated (real regression: cc1's
/// operator tables at 0x16794f0). So a table is excluded only when the full
/// dispatch idiom is present, which conveniently carries the table BOUND in
/// the guarding compare:
///
///     cmp  wX, #N            ; bound: N+1 entries   (within 8 instrs back)
///     b.hi default
///     adrp xA, page          ; table base
///     add  xA, xA, #lo
///     ldrh wB, [xA, wI, uxtw #1]   ; sub-word indexed load
///     adr  xC, anchor
///     add  xD, xC, wB, sxth #2
///     br   xD                ; dispatch  (within 8 instrs ahead)
///
/// Returns sorted (start, end) ranges in ORIGINAL vaddr space that must not
/// be pointer-fixed.
fn scan_rodata_table_exclusions(text: &[u8], text_vaddr: u64, ro_lo: u64, ro_hi: u64) -> Vec<(u64, u64)> {
    // Fallback table size when the guarding cmp is not found.
    const MAX_TABLE_SIZE: u64 = 0x1000;
    // How many instructions an ADRP/ADD-computed address stays "fresh" in our
    // register state, and how far we look ahead for the dispatch br.
    const WINDOW: usize = 8;
    // How far back we search for the guarding cmp on the index register.
    const CMP_WINDOW: usize = 32;

    let read_instr = |i: usize| -> u32 {
        u32::from_le_bytes([text[i * 4], text[i * 4 + 1], text[i * 4 + 2], text[i * 4 + 3]])
    };

    let mut ranges: Vec<(u64, u64)> = Vec::new();
    // reg -> (computed address, instruction index it was set at)
    let mut state: [Option<(u64, usize)>; 32] = [None; 32];

    let n_instr = text.len() / 4;
    for i in 0..n_instr {
        let instr = read_instr(i);
        let pc = text_vaddr + (i as u64) * 4;

        if instr & 0x9F000000 == 0x90000000 {
            // ADRP xD, page
            let rd = (instr & 31) as usize;
            let immlo = ((instr >> 29) & 3) as u64;
            let immhi = ((instr >> 5) & 0x7FFFF) as u64;
            let imm21 = (immhi << 2) | immlo;
            // sign-extend 21 bits, page-scaled
            let simm = ((imm21 << 43) as i64 >> 43) << 12;
            let val = (pc & !0xFFF).wrapping_add(simm as u64);
            state[rd] = Some((val, i));
            continue;
        }
        if instr & 0x9F000000 == 0x10000000 {
            // ADR xD, target
            let rd = (instr & 31) as usize;
            let immlo = ((instr >> 29) & 3) as u64;
            let immhi = ((instr >> 5) & 0x7FFFF) as u64;
            let imm21 = (immhi << 2) | immlo;
            let simm = (imm21 << 43) as i64 >> 43;
            state[rd] = Some((pc.wrapping_add(simm as u64), i));
            continue;
        }
        if instr & 0xFF800000 == 0x91000000 {
            // ADD xD, xN, #imm12 {, LSL #12}
            let rd = (instr & 31) as usize;
            let rn = ((instr >> 5) & 31) as usize;
            let imm12 = ((instr >> 10) & 0xFFF) as u64;
            let sh = (instr >> 22) & 1;
            let imm = imm12 << (12 * sh);
            state[rd] = match state[rn] {
                Some((v, set_at)) if i - set_at <= WINDOW => Some((v.wrapping_add(imm), i)),
                _ => None,
            };
            continue;
        }
        if instr & 0x3F200C00 == 0x38200800 {
            // Load/store (register offset), V=0:
            //   size(31:30) 111000 opc(23:22) 1 Rm option S 10 Rn Rt
            let size = (instr >> 30) & 3;
            let opc = (instr >> 22) & 3;
            // Sub-word LOADS only: LDRB/LDRSB (size=00), LDRH/LDRSH (size=01),
            // LDRSW (size=10, opc=10). opc=00 is a store; size=11 is 64-bit.
            let is_table_load = match (size, opc) {
                (0, 1) | (0, 2) | (0, 3) => true,
                (1, 1) | (1, 2) | (1, 3) => true,
                (2, 2) => true,
                _ => false,
            };
            let rn = ((instr >> 5) & 31) as usize;
            let base = match (is_table_load, state[rn]) {
                (true, Some((v, set_at))) if i - set_at <= WINDOW && v >= ro_lo && v < ro_hi => Some(v),
                _ => None,
            };
            // The load writes Rt — drop any tracked state for it.
            let rt = (instr & 31) as u32;
            state[rt as usize] = None;
            let base = match base { Some(b) => b, None => continue };

            // Dispatch idiom check: the LOADED value must feed an
            // ADD (extended or shifted register, Rm == Rt) and a BR must
            // follow — i.e. the table entry becomes a branch target. A data
            // table whose load merely precedes some unrelated BR must NOT
            // match (over-excluding real pointer data broke the gcc driver).
            let mut saw_add_of_rt = false;
            let mut has_dispatch = false;
            for j in i + 1..(i + 1 + WINDOW).min(n_instr) {
                let nx = read_instr(j);
                let is_add_ext = nx & 0xFFE00000 == 0x8B200000; // ADD Xd,Xn,Wm,ext
                let is_add_shift = nx & 0xFF200000 == 0x8B000000; // ADD Xd,Xn,Xm{,shift}
                if (is_add_ext || is_add_shift) && (nx >> 16) & 31 == rt {
                    saw_add_of_rt = true;
                }
                if saw_add_of_rt && nx & 0xFFFFFC1F == 0xD61F0000 {
                    has_dispatch = true;
                    break;
                }
            }
            if !has_dispatch {
                continue; // plain data table — safe for pointer fixup
            }
            // Bound from the guarding CMP (SUBS WZR form) on the load's
            // INDEX register — an unrelated nearby cmp must not set the
            // bound. The guard can sit a few blocks back (e.g. the gcc
            // driver's `cmp w24, #0x7c; b.ls <dispatch>` is 10 instructions
            // before the load), hence the wider backward window.
            let rm = (instr >> 16) & 31;
            let bound = (i.saturating_sub(CMP_WINDOW)..i).rev().find_map(|j| {
                let c = read_instr(j);
                if c & 0xFF80001F == 0x7100001F && (c >> 5) & 31 == rm {
                    Some((((c >> 10) & 0xFFF) as u64 + 1) << size)
                } else {
                    None
                }
            });
            // No guarding cmp on the index register → NOT a switch dispatch.
            // Real switch tables always carry an immediate bounds check;
            // the "dispatches" without one were CPython's frozen bytecode in
            // .rodata (ldrb opcode fetch + computed-goto br) — a 4 KiB
            // fallback exclusion there swallowed 417 genuine pointers
            // (opcode_targets etc.) → ensurepip OOM-SIGKILLed.
            let bound = match bound { Some(b) => b.min(MAX_TABLE_SIZE), None => continue };
            let end = (base + bound).min(ro_hi);
            if end > base {
                ranges.push((base, end));
            }
            continue;
        }
        // Unknown instruction: conservatively drop tracked state for the
        // register named in bits 4:0 (Rd/Rt for most encodings). Branches put
        // immediate bits there — clearing a random register is safe (lossy at
        // worst), and the freshness window bounds any remaining staleness.
        state[(instr & 31) as usize] = None;
    }

    // Sort and merge overlaps.
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (s, e) in ranges {
        if let Some(last) = merged.last_mut() {
            if s <= last.1 {
                last.1 = last.1.max(e);
                continue;
            }
        }
        merged.push((s, e));
    }
    merged
}

fn addr_in_sorted_ranges(addr: u64, ranges: &[(u64, u64)]) -> bool {
    match ranges.binary_search_by(|&(s, _)| s.cmp(&addr)) {
        Ok(_) => true,
        Err(0) => false,
        Err(i) => addr < ranges[i - 1].1,
    }
}

fn fixup_exec_rodata_pointers(elf: &Elf, data: &[u8], base_offset: u64, orig_lo: u64, orig_hi: u64) {
    let e_shoff = elf::read_u64_pub(data, 40) as usize;
    let e_shentsize = elf::read_u16_pub(data, 58) as usize;
    let e_shnum = elf::read_u16_pub(data, 60) as usize;
    let e_shstrndx = elf::read_u16_pub(data, 62) as usize;
    if e_shoff == 0 || e_shnum == 0 || e_shentsize < 64 || e_shstrndx >= e_shnum {
        return;
    }
    let str_off = e_shoff + e_shstrndx * e_shentsize;
    if str_off + 64 > data.len() {
        return;
    }
    let shstr_offset = elf::read_u64_pub(data, str_off + 24) as usize;

    let page: u64 = 16384;
    for i in 0..e_shnum {
        let off = e_shoff + i * e_shentsize;
        if off + 64 > data.len() {
            break;
        }
        let sh_name = elf::read_u32_pub(data, off) as usize;
        let sh_type = elf::read_u32_pub(data, off + 4);
        let sh_flags = elf::read_u64_pub(data, off + 8);
        let sh_addr = elf::read_u64_pub(data, off + 16);
        let sh_size = elf::read_u64_pub(data, off + 32);
        // SHT_PROGBITS, ALLOC, not WRITE, not EXECINSTR
        if sh_type != 1 || sh_flags & 0x2 == 0 || sh_flags & 0x1 != 0 || sh_flags & 0x4 != 0 {
            continue;
        }
        let name_pos = shstr_offset + sh_name;
        if !data[name_pos..].starts_with(b".rodata\0") {
            continue;
        }
        // Find lookup/jump tables inside this .rodata by scanning the
        // executable sections' code — those must NOT be pointer-fixed
        // (see scan_rodata_table_exclusions).
        let mut exclusions: Vec<(u64, u64)> = Vec::new();
        for j in 0..e_shnum {
            let xoff = e_shoff + j * e_shentsize;
            if xoff + 64 > data.len() { break; }
            let x_type = elf::read_u32_pub(data, xoff + 4);
            let x_flags = elf::read_u64_pub(data, xoff + 8);
            if x_type != 1 || x_flags & 0x4 == 0 { continue; } // SHT_PROGBITS + EXECINSTR
            let x_addr = elf::read_u64_pub(data, xoff + 16);
            let x_offset = elf::read_u64_pub(data, xoff + 24) as usize;
            let x_size = elf::read_u64_pub(data, xoff + 32) as usize;
            if x_offset + x_size > data.len() { continue; }
            let mut r = scan_rodata_table_exclusions(
                &data[x_offset..x_offset + x_size], x_addr, sh_addr, sh_addr + sh_size);
            exclusions.append(&mut r);
        }
        exclusions.sort_unstable();
        if std::env::var("FAKELINUX_TRACE_TABLES").is_ok() {
            for &(s, e) in &exclusions {
                crate::vlog!("fakelinux: table exclusion {:#x}..{:#x} ({} bytes)", s, e, e - s);
            }
        }
        let start = base_offset + sh_addr;
        let prot_lo = start & !(page - 1);
        let prot_hi = (start + sh_size + page - 1) & !(page - 1);
        let r = unsafe {
            libc::mprotect(prot_lo as *mut _, (prot_hi - prot_lo) as usize,
                           libc::PROT_READ | libc::PROT_WRITE)
        };
        if r != 0 {
            eprintln!("fakelinux: rodata fixup: mprotect RW failed, skipping");
            return;
        }
        let mut fixed = 0u64;
        let mut skipped_tables = 0u64;
        let mut o: u64 = 0;
        while o + 8 <= sh_size {
            let p = (start + o) as *mut u64;
            let val = unsafe { *p };
            if plausible_unrelocated_pointer(val, orig_lo, orig_hi) {
                if addr_in_sorted_ranges(sh_addr + o, &exclusions) {
                    skipped_tables += 1;
                } else {
                    unsafe { *p = val + base_offset; }
                    fixed += 1;
                }
            }
            o += 8;
        }
        // Restore protections from the covering PT_LOAD per page — an edge
        // page may be shared with .text (needs EXEC back!) or writable data.
        let mut pg = prot_lo;
        while pg < prot_hi {
            let vaddr = pg - base_offset;
            let mut prot = libc::PROT_READ;
            for phdr in &elf.phdrs {
                if phdr.p_type != PT_LOAD { continue; }
                if vaddr + page > phdr.p_vaddr && vaddr < phdr.p_vaddr + phdr.p_memsz {
                    if phdr.p_flags & 1 != 0 { prot |= libc::PROT_EXEC; }
                    if phdr.p_flags & 2 != 0 { prot |= libc::PROT_WRITE; }
                }
            }
            unsafe {
                libc::mprotect(pg as *mut _, page as usize, prot);
            }
            pg += page;
        }
        if fixed > 0 {
            crate::vlog!("fakelinux: fixed up {} absolute pointers in ET_EXEC .rodata ({} lookup-table candidates skipped)",
                      fixed, skipped_tables);
        }
    }
}

/// Fix up absolute pointers in relocated ET_EXEC data segments.
/// Scans writable PT_LOAD segments for 8-byte values that fall within the
/// binary's original address range and adjusts them by base_offset.
/// Used only for statically-linked ET_EXEC (no interpreter).
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
        crate::vlog!("fakelinux: fixed up {} absolute pointers in ET_EXEC data", fixed);
    }
}

/// Apply R_AARCH64_RELATIVE relocations from memory for relocated ET_EXEC.
/// Reads the already-loaded .dynamic and .rela.dyn from their memory locations
/// (base_offset + vaddr). Uses absolute RELA semantics: *(B + r_offset) = B + r_addend,
/// which is idempotent with ld-linux's own processing.
fn apply_relocations_from_memory(elf: &Elf, base_offset: u64) {
    let dyn_phdr = match elf.phdrs.iter().find(|p| p.p_type == 2 /* PT_DYNAMIC */) {
        Some(p) => p,
        None => return,
    };

    // Read .dynamic from memory at its relocated address
    let dyn_mem = base_offset + dyn_phdr.p_vaddr;
    let dyn_size = dyn_phdr.p_filesz;

    let mut rela_vaddr: u64 = 0;
    let mut rela_size: u64 = 0;
    let mut rela_ent: u64 = 24;
    let mut jmprel_vaddr: u64 = 0;
    let mut jmprel_size: u64 = 0;

    let mut i: u64 = 0;
    while i + 16 <= dyn_size {
        let tag = unsafe { *((dyn_mem + i) as *const u64) };
        let val = unsafe { *((dyn_mem + i + 8) as *const u64) };
        match tag {
            0 => break,           // DT_NULL
            7 => rela_vaddr = val,    // DT_RELA
            8 => rela_size = val,     // DT_RELASZ
            9 => rela_ent = val,      // DT_RELAENT
            23 => jmprel_vaddr = val, // DT_JMPREL
            2 => jmprel_size = val,   // DT_PLTRELSZ
            _ => {}
        }
        i += 16;
    }

    let mut applied = 0u64;

    // Apply .rela.dyn from memory
    if rela_vaddr != 0 && rela_size != 0 {
        applied += apply_rela_from_memory(base_offset, rela_vaddr, rela_size, rela_ent);
    }

    // Apply .rela.plt from memory
    if jmprel_vaddr != 0 && jmprel_size != 0 {
        applied += apply_rela_from_memory(base_offset, jmprel_vaddr, jmprel_size, rela_ent);
    }

    if applied > 0 {
        crate::vlog!("fakelinux: applied {} RELA relocations for ET_EXEC", applied);
    }
}

/// Apply R_AARCH64_RELATIVE entries from a RELA section already in memory.
fn apply_rela_from_memory(base: u64, rela_vaddr: u64, rela_size: u64, rela_ent: u64) -> u64 {
    let rela_mem = base + rela_vaddr;
    let count = rela_size / rela_ent;
    let mut applied = 0u64;

    for j in 0..count {
        let entry = rela_mem + j * rela_ent;
        let r_offset = unsafe { *(entry as *const u64) };
        let r_info = unsafe { *((entry + 8) as *const u64) };
        let r_addend = unsafe { *((entry + 16) as *const u64) };

        let r_type = (r_info & 0xFFFFFFFF) as u32;

        // R_AARCH64_RELATIVE = 0x403
        if r_type == 0x403 {
            let target_addr = base + r_offset;
            let value = base + r_addend;
            unsafe { (target_addr as *mut u64).write(value); }
            applied += 1;
        }
    }

    applied
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
        crate::vlog!("fakelinux: applied {} R_AARCH64_RELATIVE relocations", applied);
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

/// Collect the host process environment (libc's `environ`) into owned CStrings.
/// Used to seed the guest's initial envp on the stack.
fn collect_host_environ() -> Vec<std::ffi::CString> {
    extern "C" { static environ: *const *const i8; }
    let mut out: Vec<std::ffi::CString> = Vec::new();
    unsafe {
        let mut p = environ;
        if p.is_null() { return out; }
        loop {
            let entry = *p;
            if entry.is_null() { break; }
            out.push(std::ffi::CStr::from_ptr(entry).to_owned());
            p = p.add(1);
        }
    }
    out
}

/// Build the initial guest environment from the host process's environment,
/// stripping fakelinux-internal `FAKELINUX_*` variables (they are supervisor
/// state, not guest-visible) and ensuring `PATH`, `HOME`, and `TERM` have
/// sane defaults if the host didn't set them.
///
/// Preserves first-wins semantics for duplicates (POSIX allows duplicates;
/// `getenv` returns the first match).
pub fn build_guest_env(host_env: &[&std::ffi::CStr]) -> Vec<std::ffi::CString> {
    use std::collections::HashSet;
    let mut out: Vec<std::ffi::CString> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    // Host-macOS-specific vars that must not leak into the guest: TMPDIR
    // points at /var/folders/... which doesn't exist in the rootfs (broke
    // ispell-autobuildhash / dictionaries-common postinst); the others are
    // Darwin runtime noise.
    const HOST_ONLY_PREFIXES: &[&[u8]] =
        &[b"TMPDIR=", b"__CF_USER_TEXT_ENCODING=", b"XPC_SERVICE_NAME=", b"XPC_FLAGS="];
    for e in host_env {
        let bytes = e.to_bytes();
        if bytes.starts_with(b"FAKELINUX_") { continue; }
        if HOST_ONLY_PREFIXES.iter().any(|p| bytes.starts_with(p)) { continue; }
        let eq = bytes.iter().position(|&b| b == b'=').unwrap_or(bytes.len());
        let key = bytes[..eq].to_vec();
        if !seen.insert(key) { continue; }
        out.push(std::ffi::CString::new(bytes).unwrap());
    }
    // Add defaults for required vars if missing.
    let defaults: &[(&[u8], &[u8])] = &[
        (b"PATH", b"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        (b"HOME", b"/root"),
        (b"TERM", b"xterm"),
    ];
    for (key, val) in defaults {
        if !out.iter().any(|c| {
            let b = c.to_bytes();
            b.len() > key.len() && b.starts_with(key) && b[key.len()] == b'='
        }) {
            let mut entry = key.to_vec();
            entry.push(b'=');
            entry.extend_from_slice(val);
            out.push(std::ffi::CString::new(entry).unwrap());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn c(s: &[u8]) -> CString { CString::new(s).unwrap() }

    #[test]
    fn guest_pagesz_parses_and_clamps() {
        assert_eq!(parse_guest_pagesz(None), 4096);
        assert_eq!(parse_guest_pagesz(Some("16384")), 16384);
        assert_eq!(parse_guest_pagesz(Some("4096")), 4096);
        // Rejected: not a power of two, out of range, garbage.
        assert_eq!(parse_guest_pagesz(Some("12345")), 4096);
        assert_eq!(parse_guest_pagesz(Some("2048")), 4096);
        assert_eq!(parse_guest_pagesz(Some("131072")), 4096);
        assert_eq!(parse_guest_pagesz(Some("banana")), 4096);
    }

    // ── VA-top reservation (VA-bits detection by guests) ─────────────────

    #[test]
    fn va_top_reservation_maps_and_registers() {
        // VPP (svm_get_global_region_base_va) derives the VA size from the
        // highest end address in /proc/self/maps and MAP_FIXEDs its shared
        // region at 2^(bits-2). Without a high entry it derives 39 bits →
        // baseva 0x1ff8000000, inside the macOS dead zone [0xfc0000000,
        // 0x7000000000) → ENOMEM. The reservation makes the top entry end at
        // 2^47 → 47 bits → baseva 0x200000000000, which macOS CAN map.
        crate::procfs::init("/test/exe");
        assert!(reserve_va_top_page());
        assert!(reserve_va_top_page()); // idempotent
        let maps = String::from_utf8(crate::procfs::snapshot_maps()).unwrap();
        assert!(maps.contains("7ffffdffc000-7ffffe000000"), "{maps}");
        // Maps are sorted, so the reservation must be the LAST line — VPP's
        // parser takes the end address of the last line, not the max.
        let last = maps.lines().last().unwrap();
        assert!(last.starts_with("7ffffdffc000-7ffffe000000"), "{last}");
        // And the baseva VPP will derive from it must be host-mappable.
        let baseva = 0x2000_0000_0000_u64; // 2^(47-2)
        let p = unsafe {
            libc::mmap(baseva as *mut _, 0x400_0000,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED, -1, 0)
        };
        assert_ne!(p, libc::MAP_FAILED, "baseva 2^45 must be mappable");
        unsafe { libc::munmap(p, 0x400_0000) };
    }

    // ── patch-site cache (encode/parse/filename) ────────────────────────

    #[test]
    fn patch_cache_roundtrip() {
        let sites = vec![0u32, 4, 0x1234, 0x7242cc0];
        let enc = encode_patch_cache(&sites);
        assert_eq!(parse_patch_cache(&enc), Some(sites));
    }

    #[test]
    fn patch_cache_roundtrip_empty() {
        // Zero sites is still a valid cache entry (skips the scan entirely).
        let enc = encode_patch_cache(&[]);
        assert_eq!(enc.len(), 16);
        assert_eq!(parse_patch_cache(&enc), Some(vec![]));
    }

    #[test]
    fn patch_cache_rejects_garbage() {
        assert_eq!(parse_patch_cache(&[]), None);
        assert_eq!(parse_patch_cache(&[0u8; 15]), None);
        // wrong magic
        let mut enc = encode_patch_cache(&[4]);
        enc[0] ^= 0xff;
        assert_eq!(parse_patch_cache(&enc), None);
        // wrong version
        let mut enc = encode_patch_cache(&[4]);
        enc[4] ^= 0xff;
        assert_eq!(parse_patch_cache(&enc), None);
        // truncated payload
        let mut enc = encode_patch_cache(&[4, 8]);
        enc.pop();
        assert_eq!(parse_patch_cache(&enc), None);
        // count larger than payload
        let enc = encode_patch_cache(&[4, 8]);
        assert_eq!(parse_patch_cache(&enc[..20]), None);
    }

    #[test]
    fn patch_cache_filename_distinguishes_identity() {
        let a = patch_cache_filename(1, 2, 3, 4, 5, 6, 7);
        // any field change → different cache entry
        assert_ne!(a, patch_cache_filename(9, 2, 3, 4, 5, 6, 7));
        assert_ne!(a, patch_cache_filename(1, 9, 3, 4, 5, 6, 7));
        assert_ne!(a, patch_cache_filename(1, 2, 9, 4, 5, 6, 7));
        assert_ne!(a, patch_cache_filename(1, 2, 3, 9, 5, 6, 7));
        assert_ne!(a, patch_cache_filename(1, 2, 3, 4, 9, 6, 7));
        assert_ne!(a, patch_cache_filename(1, 2, 3, 4, 5, 9, 7));
        assert_ne!(a, patch_cache_filename(1, 2, 3, 4, 5, 6, 9));
        assert_eq!(a, patch_cache_filename(1, 2, 3, 4, 5, 6, 7));
    }

    // ── scan_rodata_table_exclusions ─────────────────────────────────────
    // Real gcc-13 cc1 crash: the pointer-fixup heuristic patched a switch
    // jump table in .rodata (u64 view of halfwords [0,0x54,0,0] = 0x540000
    // looked like an unrelocated pointer; +0x700000000 wrote 7 into a table
    // entry → br into the middle of a basic block → ICE on hello-world).

    fn words(ws: &[u32]) -> Vec<u8> {
        ws.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    #[test]
    fn cc1_switch_dispatch_table_is_excluded() {
        // The exact instruction words from cc1's equiv_oracle::find_equiv_block
        // at vaddr 0xfd20ec: sub w8, w21, #0x12; cmp w8, #0x81; b.hi;
        // adrp x9, 0x17fe000; add x9, x9, #0xda0;
        // ldrh w9, [x9, w8, uxtw #1]; adr x8; add x9, x8, w9, sxth #2; br x9
        // — table at 0x17feda0 in .rodata, 0x82 halfword entries (from cmp).
        let text = words(&[
            0x51004aa8, 0x7102051f, 0x540000e8,
            0x90004169, 0x91368129, 0x78685929,
            0x10000068, 0x8b29a909, 0xd61f0120,
        ]);
        let r = scan_rodata_table_exclusions(&text, 0xfd20ec, 0x162f1e0, 0x1af2508);
        assert_eq!(r, vec![(0x17feda0, 0x17feda0 + 0x82 * 2)],
                   "table bound must come from the guarding cmp");
    }

    #[test]
    fn pointer_array_base_is_not_excluded() {
        // cc1 fd2120: adrp x0, 0x1679000; add x0, x0, #0x950;
        // ldr x27, [x0, x2, lsl #3] — 64-bit pointer-array load: must NOT
        // be excluded (these pointers NEED fixing; python3.12 regression).
        let text = words(&[0xf0003520, 0x91254000, 0xf862781b]);
        let r = scan_rodata_table_exclusions(&text, 0xfd2120, 0x162f1e0, 0x1af2508);
        assert!(r.is_empty(), "pointer arrays must stay fixable, got {:?}", r);
    }

    #[test]
    fn data_byte_table_without_dispatch_is_not_excluded() {
        // cc1's tree_contains_struct at 0x1679300 is a plain byte lookup
        // table (ldrb, no br) — its content can't alias into the pointer
        // range, its length is unknowable, and pointer data sits right after
        // it (0x16794f0). Excluding it left those pointers unrelocated → the
        // second hello-world ICE. Must NOT be excluded.
        let adrp = |rd: u32, pc: u64, target_page: u64| -> u32 {
            let delta = ((target_page as i64 - (pc & !0xFFF) as i64) >> 12) as u64;
            let immlo = (delta & 3) as u32;
            let immhi = ((delta >> 2) & 0x7FFFF) as u32;
            0x90000000 | (immlo << 29) | (immhi << 5) | rd
        };
        let add = |rd: u32, rn: u32, imm: u32| 0x91000000 | (imm << 10) | (rn << 5) | rd;
        // LDRB (register) w2, [x1, w3, uxtw]: size=00 opc=01 option=UXTW(010)
        let ldrb = 0x38600800 | (3 << 16) | (0b010 << 13) | (1 << 5) | 2;
        let text_vaddr = 0x1000u64;
        let page = 0x10000u64;
        let text = words(&[adrp(1, text_vaddr, page), add(1, 1, 0x300), ldrb]);
        let r = scan_rodata_table_exclusions(&text, text_vaddr, page, page + 0x1000);
        assert!(r.is_empty(), "data tables without br must stay fixable, got {:?}", r);
    }

    #[test]
    fn data_table_with_unrelated_br_is_not_excluded() {
        // A byte-table load followed by some BR that does NOT consume the
        // loaded value (e.g. an indirect tail call) is not a dispatch —
        // this over-match left the gcc driver's pointer arrays unrelocated.
        let adrp = |rd: u32, pc: u64, target_page: u64| -> u32 {
            let delta = ((target_page as i64 - (pc & !0xFFF) as i64) >> 12) as u64;
            let immlo = (delta & 3) as u32;
            let immhi = ((delta >> 2) & 0x7FFFF) as u32;
            0x90000000 | (immlo << 29) | (immhi << 5) | rd
        };
        let add = |rd: u32, rn: u32, imm: u32| 0x91000000 | (imm << 10) | (rn << 5) | rd;
        let ldrb = 0x38600800 | (3 << 16) | (0b010 << 13) | (1 << 5) | 2; // ldrb w2,[x1,w3,uxtw]
        let br_x16 = 0xD61F0200u32; // br x16 — unrelated to w2
        let text_vaddr = 0x1000u64;
        let page = 0x10000u64;
        let text = words(&[adrp(1, text_vaddr, page), add(1, 1, 0x300), ldrb, br_x16]);
        let r = scan_rodata_table_exclusions(&text, text_vaddr, page, page + 0x1000);
        assert!(r.is_empty(), "stray br must not make a data table a dispatch, got {:?}", r);
    }

    #[test]
    fn dispatch_without_cmp_is_not_excluded() {
        // Load + add + br but NO guarding cmp on the index register → not a
        // switch dispatch (CPython's frozen-bytecode ldrb + computed-goto br
        // matched this shape; a fallback exclusion swallowed 417 genuine
        // pointers and ensurepip OOM-SIGKILLed). Must not exclude.
        let adrp = |rd: u32, pc: u64, target_page: u64| -> u32 {
            let delta = ((target_page as i64 - (pc & !0xFFF) as i64) >> 12) as u64;
            let immlo = (delta & 3) as u32;
            let immhi = ((delta >> 2) & 0x7FFFF) as u32;
            0x90000000 | (immlo << 29) | (immhi << 5) | rd
        };
        let add = |rd: u32, rn: u32, imm: u32| 0x91000000 | (imm << 10) | (rn << 5) | rd;
        let ldrh = 0x78600800 | (3 << 16) | (0b010 << 13) | (1 << 13) | (1 << 5) | 2; // ldrh w2,[x1,w3,uxtw#1]
        // add x9, x8, w2, sxth #2 — consumes the loaded value
        let add_disp = 0x8B200000u32 | (2 << 16) | (0b101 << 13) | (2 << 10) | (8 << 5) | 9;
        let br_x9 = 0xD61F0120u32;
        let text_vaddr = 0x1000u64;
        let page = 0x10000u64;
        let text = words(&[adrp(1, text_vaddr, page), add(1, 1, 0x100), ldrh, add_disp, br_x9]);
        let r = scan_rodata_table_exclusions(&text, text_vaddr, page, page + 0x4000);
        assert!(r.is_empty(), "no guard cmp → not a dispatch → no exclusion, got {:?}", r);
    }

    #[test]
    fn addr_in_sorted_ranges_works() {
        let ranges = [(0x100u64, 0x200u64), (0x300, 0x400)];
        assert!(!addr_in_sorted_ranges(0xFF, &ranges));
        assert!(addr_in_sorted_ranges(0x100, &ranges));
        assert!(addr_in_sorted_ranges(0x1F8, &ranges));
        assert!(!addr_in_sorted_ranges(0x200, &ranges));
        assert!(addr_in_sorted_ranges(0x3FF, &ranges));
        assert!(!addr_in_sorted_ranges(0x400, &ranges));
    }

    #[test]
    fn build_guest_env_passes_through_debian_has_frontend() {
        // The scenario: debconf frontend re-execs fakelinux with
        // DEBIAN_HAS_FRONTEND=1 in the host environ. The re-exec'd fakelinux
        // must make that env var visible to the guest binary it loads, or the
        // guest's debconf client will think there is no frontend and deadlock.
        let vars = [
            c(b"DEBIAN_HAS_FRONTEND=1"),
            c(b"PATH=/usr/bin"),
        ];
        let refs: Vec<&std::ffi::CStr> = vars.iter().map(|c| c.as_c_str()).collect();
        let out = build_guest_env(&refs);
        let strs: Vec<&str> = out.iter().map(|c| c.to_str().unwrap()).collect();
        assert!(strs.contains(&"DEBIAN_HAS_FRONTEND=1"),
                "guest env must propagate DEBIAN_HAS_FRONTEND; got {:?}", strs);
    }

    #[test]
    fn build_guest_env_strips_fakelinux_internal_vars() {
        let vars = [
            c(b"FAKELINUX_TRACE=1"),
            c(b"FAKELINUX_ROOT=/rootfs"),
            c(b"FAKELINUX_SIGIGN=0xff"),
            c(b"PATH=/usr/bin"),
        ];
        let refs: Vec<&std::ffi::CStr> = vars.iter().map(|c| c.as_c_str()).collect();
        let out = build_guest_env(&refs);
        let strs: Vec<&str> = out.iter().map(|c| c.to_str().unwrap()).collect();
        assert!(!strs.iter().any(|s| s.starts_with("FAKELINUX_")),
                "FAKELINUX_* must not leak into guest; got {:?}", strs);
    }

    #[test]
    fn build_guest_env_strips_host_macos_vars() {
        // Host TMPDIR (/var/folders/...) leaked into the container and
        // ispell-autobuildhash's mktemp failed: "Cannot make temporary
        // directory under /var/folders/nm/.../T/" → dictionaries-common
        // postinst exit 25 during make install-dep.
        let vars = [
            c(b"TMPDIR=/var/folders/nm/1smjjw5j/T/"),
            c(b"__CF_USER_TEXT_ENCODING=0x1F5:0x0:0x0"),
            c(b"XPC_SERVICE_NAME=0"),
            c(b"XPC_FLAGS=0x0"),
            c(b"PATH=/usr/bin"),
        ];
        let refs: Vec<&std::ffi::CStr> = vars.iter().map(|c| c.as_c_str()).collect();
        let out = build_guest_env(&refs);
        let strs: Vec<&str> = out.iter().map(|c| c.to_str().unwrap()).collect();
        for bad in ["TMPDIR=", "__CF_USER_TEXT_ENCODING=", "XPC_"] {
            assert!(!strs.iter().any(|s| s.starts_with(bad)),
                    "host macOS var {bad} must not leak into guest; got {strs:?}");
        }
        assert!(strs.contains(&"PATH=/usr/bin"));
    }

    #[test]
    fn build_guest_env_adds_default_path_home_term() {
        let out = build_guest_env(&[]);
        let strs: Vec<&str> = out.iter().map(|c| c.to_str().unwrap()).collect();
        assert!(strs.iter().any(|s| s.starts_with("PATH=")), "{:?}", strs);
        assert!(strs.iter().any(|s| s.starts_with("HOME=")), "{:?}", strs);
        assert!(strs.iter().any(|s| s.starts_with("TERM=")), "{:?}", strs);
    }

    #[test]
    fn build_guest_env_preserves_host_path_over_default() {
        let vars = [c(b"PATH=/custom:/bin")];
        let refs: Vec<&std::ffi::CStr> = vars.iter().map(|c| c.as_c_str()).collect();
        let out = build_guest_env(&refs);
        let strs: Vec<&str> = out.iter().map(|c| c.to_str().unwrap()).collect();
        assert!(strs.contains(&"PATH=/custom:/bin"));
        // Only one PATH entry (no accidental duplicate from the defaults step).
        assert_eq!(strs.iter().filter(|s| s.starts_with("PATH=")).count(), 1);
    }

    #[test]
    fn build_guest_env_dedupes_duplicates_first_wins() {
        let vars = [c(b"X=first"), c(b"X=second")];
        let refs: Vec<&std::ffi::CStr> = vars.iter().map(|c| c.as_c_str()).collect();
        let out = build_guest_env(&refs);
        let strs: Vec<&str> = out.iter().map(|c| c.to_str().unwrap()).collect();
        assert_eq!(strs.iter().filter(|s| s.starts_with("X=")).count(), 1);
        assert!(strs.contains(&"X=first"));
    }

    // ── plausible_unrelocated_pointer ─────────────────────────────────────
    // The eager ET_EXEC pointer fixup must not relocate packed small-int
    // struct fields that alias into the pointer range. Real case: gcc cc1's
    // insn_operand_data flags word for a match_operator operand
    // {mode:16, strict_low, is_operator=1, eliminable=0, allows_mem=0}
    // reads as u64 0x0100_0000..0x0100_0040 — inside cc1's
    // [0x400000, 0x2400000) PT_LOAD range. Relocating it added
    // 0x7_0000_0000, setting the `eliminable` byte to 7, which made
    // reload's elimination_costs_in_insn walk match_operator operands
    // after NULLing their nested operand slot → deterministic ICE
    // (SIGSEGV in eliminate_regs_1) on any ccmp insn, e.g. libbpf bpf.c.

    const CC1_LO: u64 = 0x400000;
    const CC1_HI: u64 = 0x2400000;

    #[test]
    fn fixup_rejects_match_operator_flags_words() {
        // All 166 aliasing words in cc1's insn tables: 0x1000000 | mode.
        for w in [0x0100_0000u64, 0x0100_000e, 0x0100_0040, 0x0100_0011] {
            assert!(
                !plausible_unrelocated_pointer(w, CC1_LO, CC1_HI),
                "flags word {w:#x} must not be treated as a pointer"
            );
        }
    }

    #[test]
    fn fixup_accepts_real_pointers() {
        // Real pointers from cc1's insn_data: name/operand/predicate ptrs.
        for w in [0x198f348u64, 0x16a7c78, 0x1147c00, 0x11373f4, 0x8945a4] {
            assert!(
                plausible_unrelocated_pointer(w, CC1_LO, CC1_HI),
                "real pointer {w:#x} must be relocated"
            );
        }
    }

    #[test]
    fn fixup_accepts_sparse_low_pointers() {
        // python3.12's image sits below 16M; its .rodata holds real
        // pointers with only 1-2 nonzero bytes (static type tables).
        // Rejecting them caused "__delattr__" string bytes to be chased
        // as a pointer (SIGSEGV in typeobject init).
        for w in [0x4100a0u64, 0x400000, 0x500000, 0xb00008] {
            assert!(
                plausible_unrelocated_pointer(w, 0x400000, 0xb8dfc8),
                "sparse low pointer {w:#x} must be relocated"
            );
        }
    }

    #[test]
    fn fixup_rejects_out_of_range() {
        assert!(!plausible_unrelocated_pointer(0x3fffff, CC1_LO, CC1_HI));
        assert!(!plausible_unrelocated_pointer(CC1_HI, CC1_LO, CC1_HI));
        assert!(!plausible_unrelocated_pointer(0, CC1_LO, CC1_HI));
    }
}
