use crate::elf::{self, Elf, ElfError};
use crate::linux::*;
use crate::procfs;
use crate::syscall;
use crate::thread;
use crate::trap;

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
    // For PIE (ET_DYN), pick a base address; for ET_EXEC, use the addresses as-is
    let base_offset: u64 = if elf.header.e_type == ET_DYN {
        0x5_0000_0000 // load PIE at 20GB mark
    } else {
        0
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

        // Look for the interpreter in sysroot, then try bare path
        let interp_full = if !sysroot.is_empty() {
            format!("{}{}", sysroot, interp_path)
        } else {
            interp_path.clone()
        };

        let interp_data = std::fs::read(&interp_full).map_err(|e| {
            ElfError(format!(
                "cannot read interpreter '{}' (sysroot='{}'): {}. \
                 Use FAKELINUX_SYSROOT to point to an aarch64 Linux rootfs.",
                interp_path, sysroot, e
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

    // Initialize brk at the end of the last segment, page-aligned
    let brk_start = page_align_up(brk_end);
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

/// Scan executable memory and replace SVC #0 with BRK #0xF000
fn rewrite_svc_instructions(start: u64, size: u64) {
    let count = size / 4;
    let base = start as *mut u32;
    let mut patched = 0u64;
    for i in 0..count as usize {
        unsafe {
            let instr = base.add(i).read();
            if instr == trap::SVC_0 {
                base.add(i).write(trap::BRK_MARKER);
                patched += 1;
            }
        }
    }
    if patched > 0 {
        eprintln!("fakelinux: patched {} SVC→BRK instructions", patched);
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

fn elf_to_mmap_prot(flags: u32) -> i32 {
    let mut prot = 0;
    if flags & PF_R != 0 { prot |= libc::PROT_READ; }
    if flags & PF_W != 0 { prot |= libc::PROT_WRITE; }
    if flags & PF_X != 0 { prot |= libc::PROT_EXEC; }
    prot
}

/// Transfer control to the loaded binary. Never returns.
pub unsafe fn jump_to_entry(stack_ptr: u64, entry: u64) -> ! {
    // Save macOS TLS before entering guest code
    thread::save_macos_tls();

    std::arch::asm!(
        "mov sp, {sp}",
        "br {entry}",
        sp = in(reg) stack_ptr,
        entry = in(reg) entry,
        options(noreturn)
    );
}
