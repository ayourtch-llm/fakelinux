mod elf;
mod linux;
mod loader;
mod procfs;
mod signal;
mod syscall;
mod thread;
mod translate;
mod trap;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: fakelinux <aarch64-linux-elf> [args...]");
        eprintln!("  Set FAKELINUX_SYSROOT to an aarch64 Linux rootfs for dynamic binaries.");
        std::process::exit(1);
    }

    let elf_path = &args[1];
    let sysroot = std::env::var("FAKELINUX_SYSROOT").unwrap_or_default();

    let data = std::fs::read(elf_path).unwrap_or_else(|e| {
        eprintln!("fakelinux: cannot read '{}': {}", elf_path, e);
        std::process::exit(1);
    });

    let elf = elf::parse(&data).unwrap_or_else(|e| {
        eprintln!("fakelinux: {}", e);
        std::process::exit(1);
    });

    eprintln!(
        "fakelinux: loading {} (type={} entry={:#x} phdrs={})",
        elf_path, elf.header.e_type, elf.header.e_entry, elf.header.e_phnum
    );

    // Initialize subsystems
    if std::env::var("FAKELINUX_TRACE").is_ok() {
        syscall::set_trace(true);
    }
    procfs::init(elf_path);
    thread::init_main_tid();
    trap::install_handler();

    // Load segments, patch SVCs, set up stack
    let loaded = loader::load(&elf, &data, &args[1..], &sysroot).unwrap_or_else(|e| {
        eprintln!("fakelinux: {}", e);
        std::process::exit(1);
    });

    // Freeze the TPIDR patch table for lock-free lookup (safe after fork)
    loader::freeze_tpidr_patches();

    // Transfer control to the Linux binary
    unsafe {
        loader::jump_to_entry(loaded.stack_ptr, loaded.entry);
    }
}
