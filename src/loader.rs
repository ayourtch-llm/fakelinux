use crate::elf::{Elf, ElfError};
use crate::linux::*;
use crate::syscall;
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
}

/// Load an ELF binary into memory, rewrite SVC→BRK, set up the stack.
pub fn load(elf: &Elf, data: &[u8], guest_args: &[String]) -> Result<LoadedElf, ElfError> {
    // For PIE (ET_DYN), pick a base address; for ET_EXEC, use the addresses as-is
    let base_offset: u64 = if elf.header.e_type == ET_DYN {
        0x5_0000_0000 // load PIE at 20GB mark
    } else {
        0
    };

    let mut brk_end: u64 = 0;
    let mut phdr_addr: u64 = 0;

    // Load PT_LOAD segments
    for phdr in &elf.phdrs {
        if phdr.p_type != PT_LOAD {
            continue;
        }

        let seg_start = base_offset + phdr.p_vaddr;
        let seg_end = seg_start + phdr.p_memsz;
        let map_start = page_align_down(seg_start);
        let map_end = page_align_up(seg_end);
        let map_size = (map_end - map_start) as usize;

        // Map as RW first so we can write data and patch SVC instructions
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
                map_start,
                map_size,
                std::io::Error::last_os_error()
            )));
        }

        // Copy file data into the mapped region
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

        // If this segment is executable, rewrite SVC #0 → BRK #0xF000
        if phdr.p_flags & PF_X != 0 {
            rewrite_svc_instructions(seg_start, phdr.p_filesz);
        }

        // Record where the program headers ended up in memory
        // (they're inside the first PT_LOAD for typical binaries)
        let file_phdr_start = elf.header.e_phoff;
        let file_phdr_end =
            file_phdr_start + (elf.header.e_phnum as u64) * (elf.header.e_phentsize as u64);
        if phdr.p_offset <= file_phdr_start
            && file_phdr_end <= phdr.p_offset + phdr.p_filesz
        {
            phdr_addr = seg_start + (file_phdr_start - phdr.p_offset);
        }

        // Set correct permissions
        let prot = elf_to_mmap_prot(phdr.p_flags);
        unsafe {
            libc::mprotect(map_start as *mut _, map_size, prot);
        }

        // Track the end for brk
        if seg_end > brk_end {
            brk_end = seg_end;
        }
    }

    // Initialize brk at the end of the last segment, page-aligned
    let brk_start = page_align_up(brk_end);
    syscall::BRK_CURRENT.store(brk_start, std::sync::atomic::Ordering::SeqCst);

    // Set up the guest stack
    let stack_ptr = setup_stack(elf, base_offset, phdr_addr, guest_args)?;

    let entry = base_offset + elf.header.e_entry;

    eprintln!("fakelinux: entry={:#x} sp={:#x} brk={:#x}", entry, stack_ptr, brk_start);

    Ok(LoadedElf {
        entry,
        stack_ptr,
        phdr_addr,
    })
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

/// Build the initial stack for the guest process.
/// Layout (high → low):
///   random bytes (16)
///   environment strings
///   argument strings
///   padding
///   AT_NULL
///   auxv entries
///   NULL (end envp)
///   envp[0..n]
///   NULL (end argv)
///   argv[0..n]
///   argc
///   ← SP
fn setup_stack(
    elf: &Elf,
    base_offset: u64,
    phdr_addr: u64,
    guest_args: &[String],
) -> Result<u64, ElfError> {
    let stack_size: usize = 8 * 1024 * 1024; // 8 MB
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

    let stack_top = stack_base as u64 + stack_size as u64;
    let mut sp = stack_top;

    // Helper to push bytes onto the stack
    let push_bytes = |sp: &mut u64, data: &[u8]| {
        *sp -= data.len() as u64;
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), *sp as *mut u8, data.len());
        }
    };

    // Helper to push a u64
    let push_u64 = |sp: &mut u64, val: u64| {
        *sp -= 8;
        unsafe {
            (*sp as *mut u64).write(val);
        }
    };

    // 1) Write random bytes at the top
    let mut random_bytes = [0u8; 16];
    for b in &mut random_bytes {
        *b = unsafe { libc::arc4random() as u8 };
    }
    push_bytes(&mut sp, &random_bytes);
    let at_random_addr = sp;

    // 2) Write environment strings (just a minimal set)
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

    // 3) Write argument strings
    let mut arg_addrs: Vec<u64> = Vec::new();
    for arg in guest_args.iter().rev() {
        let mut bytes = arg.as_bytes().to_vec();
        bytes.push(0); // null terminator
        push_bytes(&mut sp, &bytes);
        arg_addrs.push(sp);
    }
    arg_addrs.reverse();

    // Store the execfn pointer (first arg)
    let at_execfn_addr = if !arg_addrs.is_empty() {
        arg_addrs[0]
    } else {
        0
    };

    // 4) Align SP to 16 bytes
    sp &= !15;

    // Now build the stack frame (bottom-up, so we push in reverse order)
    // We need to compute total size first, then write top-down.
    // Easier: collect everything into a Vec<u64> and push at the end.

    let mut frame: Vec<u64> = Vec::new();

    // argc
    frame.push(guest_args.len() as u64);

    // argv pointers
    for addr in &arg_addrs {
        frame.push(*addr);
    }
    frame.push(0); // NULL terminator

    // envp pointers
    for addr in &env_addrs {
        frame.push(*addr);
    }
    frame.push(0); // NULL terminator

    // auxv
    let auxv: Vec<(u64, u64)> = vec![
        (AT_PHDR, phdr_addr),
        (AT_PHENT, elf.header.e_phentsize as u64),
        (AT_PHNUM, elf.header.e_phnum as u64),
        (AT_PAGESZ, 4096), // tell the guest we have 4K pages (Linux convention)
        (AT_ENTRY, base_offset + elf.header.e_entry),
        (AT_UID, unsafe { libc::getuid() as u64 }),
        (AT_EUID, unsafe { libc::geteuid() as u64 }),
        (AT_GID, unsafe { libc::getgid() as u64 }),
        (AT_EGID, unsafe { libc::getegid() as u64 }),
        (AT_CLKTCK, 100),
        (AT_RANDOM, at_random_addr),
        (AT_HWCAP, 0),
        (AT_EXECFN, at_execfn_addr),
        (AT_NULL, 0),
    ];
    for (typ, val) in &auxv {
        frame.push(*typ);
        frame.push(*val);
    }

    // The frame must start at a 16-byte aligned address
    let frame_bytes = frame.len() * 8;
    sp -= frame_bytes as u64;
    sp &= !15; // 16-byte align

    // Write the frame
    for (i, val) in frame.iter().enumerate() {
        push_u64_at(sp + (i as u64) * 8, *val);
    }

    Ok(sp)
}

fn push_u64_at(addr: u64, val: u64) {
    unsafe {
        (addr as *mut u64).write(val);
    }
}

fn elf_to_mmap_prot(flags: u32) -> i32 {
    let mut prot = 0;
    if flags & PF_R != 0 {
        prot |= libc::PROT_READ;
    }
    if flags & PF_W != 0 {
        prot |= libc::PROT_WRITE;
    }
    if flags & PF_X != 0 {
        prot |= libc::PROT_EXEC;
    }
    prot
}

/// Transfer control to the loaded binary. Never returns.
pub unsafe fn jump_to_entry(stack_ptr: u64, entry: u64) -> ! {
    std::arch::asm!(
        "mov sp, {sp}",
        "br {entry}",
        sp = in(reg) stack_ptr,
        entry = in(reg) entry,
        options(noreturn)
    );
}
