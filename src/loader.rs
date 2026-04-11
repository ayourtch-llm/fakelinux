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
    if let Ok(table) = TPIDR_PATCHES_RUNTIME.read() {
        if let Ok(i) = table.binary_search_by_key(&pc, |&(addr, _)| addr) {
            return Some(table[i].1);
        }
    }
    None
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
            rewrite_svc_instructions(seg_start, phdr.p_filesz);
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

/// Scan executable memory and replace SVC #0 with BRK #0xF000,
/// and MSR tpidr_el0 with BRK #0xF001 + register number.
fn rewrite_svc_instructions(start: u64, size: u64) {
    let count = size / 4;
    let base = start as *mut u32;
    let mut svc_patched = 0u64;
    let mut tpidr_patched = 0u64;
    for i in 0..count as usize {
        unsafe {
            let instr = base.add(i).read();
            if instr == trap::SVC_0 {
                // SVC #0 → BRK #0xF000
                base.add(i).write(trap::BRK_MARKER);
                svc_patched += 1;
            } else if instr & trap::MSR_TPIDR_MASK == trap::MSR_TPIDR_BASE
                   || instr & trap::MRS_TPIDR_MASK == trap::MRS_TPIDR_BASE {
                // MSR/MRS tpidr_el0 → leave the original instruction in place.
                // It will trap as SIGTRAP because macOS clobbers TPIDR_EL0 on
                // every signal, so we need to intercept all accesses.
                // We replace with BRK #0xF000 but keep the original instruction
                // at the same PC — the handler reads it to determine the operation.
                // Actually: DON'T replace. The handler reads *(pc) to detect MSR/MRS.
                // If we replace with BRK, *(pc) = BRK, not MSR. So we need to store
                // the original instruction somewhere. Simplest: use BRK with a different
                // immediate that encodes "this was a TPIDR access", then let the handler
                // decide based on the immediate. But we lose the register number.
                //
                // Better approach: DON'T patch MSR/MRS. Instead, make them trap by
                // marking the code pages as non-executable, then... no, that's worse.
                //
                // Simplest approach: NOP out the MSR/MRS and insert the original
                // instruction at pc+4... no, that shifts code.
                //
                // Actually the cleanest approach: leave MSR/MRS as-is. They will
                // execute natively (reading/writing the macOS-clobbered value).
                // We DON'T need to intercept them if we ensure TPIDR_EL0 has the
                // guest value whenever guest code runs. We can do this by writing
                // the guest TPIDR value just before sigreturn.
                //
                // But macOS restores TPIDR on sigreturn! So we can't.
                //
                // Final approach: patch to BRK, store original instruction in a side table.
                // The handler looks up the original instruction from the side table.
                //
                // For simplicity, just leave the instruction in place at the PC.
                // We DON'T replace it with BRK — instead, we'll use a different
                // mechanism to trap. We'll mark the page as execute-only (no read)
                // ... no, that's complex.
                //
                // OK: patch MSR/MRS to BRK #0xF000, BUT the handler checks *(pc)
                // which will now be BRK, not MSR. We need to save the original.
                // Let's use a global HashMap<u64, u32> mapping PC → original instruction.
                let pc_addr = base.add(i) as u64;
                crate::procfs::with(|_| {}); // ensure procfs is initialized
                add_tpidr_patch(pc_addr, instr);
                base.add(i).write(trap::BRK_MARKER);
                tpidr_patched += 1;
            }
        }
    }
    if svc_patched > 0 {
        eprintln!("fakelinux: patched {} SVC→BRK instructions", svc_patched);
    }
    if tpidr_patched > 0 {
        eprintln!("fakelinux: patched {} MSR/MRS tpidr_el0 instructions", tpidr_patched);
    }
}

/// Patch newly-executable code pages at runtime (called from mprotect/mmap).
/// Scans the given address range for SVC #0 and MSR/MRS tpidr_el0, patches them,
/// and adds TPIDR patches to the runtime table.
///
/// The caller must ensure the memory is writable before calling this.
/// After patching, the caller should set the final permissions and invalidate icache.
pub fn patch_new_code(start: u64, len: u64) {
    let count = len / 4;
    let base = start as *mut u32;
    let mut svc_patched = 0u64;
    let mut tpidr_patched = 0u64;
    for i in 0..count as usize {
        unsafe {
            let instr = base.add(i).read();
            if instr == trap::SVC_0 {
                base.add(i).write(trap::BRK_MARKER);
                svc_patched += 1;
            } else if instr & trap::MSR_TPIDR_MASK == trap::MSR_TPIDR_BASE
                   || instr & trap::MRS_TPIDR_MASK == trap::MRS_TPIDR_BASE {
                let pc_addr = base.add(i) as u64;
                add_runtime_tpidr_patch(pc_addr, instr);
                base.add(i).write(trap::BRK_MARKER);
                tpidr_patched += 1;
            }
        }
    }
    if svc_patched > 0 || tpidr_patched > 0 {
        eprintln!(
            "fakelinux: runtime patch at {:#x}+{:#x}: {} SVC, {} TPIDR",
            start, len, svc_patched, tpidr_patched
        );
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
    let stack_base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
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
