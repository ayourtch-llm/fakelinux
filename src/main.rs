mod elf;
mod linux;
mod loader;
mod syscall;
mod trap;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: fakelinux <aarch64-linux-elf> [args...]");
        std::process::exit(1);
    }

    // Read the ELF file
    let elf_path = &args[1];
    let data = std::fs::read(elf_path).unwrap_or_else(|e| {
        eprintln!("fakelinux: cannot read '{}': {}", elf_path, e);
        std::process::exit(1);
    });

    // Parse ELF headers
    let elf = elf::parse(&data).unwrap_or_else(|e| {
        eprintln!("fakelinux: {}", e);
        std::process::exit(1);
    });

    eprintln!(
        "fakelinux: loading {} (type={} entry={:#x} phdrs={})",
        elf_path, elf.header.e_type, elf.header.e_entry, elf.header.e_phnum
    );

    // Install the SIGTRAP handler (catches our patched SVC→BRK instructions)
    trap::install_handler();

    // Load segments, patch SVCs, set up stack
    let loaded = loader::load(&elf, &data, &args[1..]).unwrap_or_else(|e| {
        eprintln!("fakelinux: {}", e);
        std::process::exit(1);
    });

    // Transfer control to the Linux binary
    unsafe {
        loader::jump_to_entry(loaded.stack_ptr, loaded.entry);
    }
}
