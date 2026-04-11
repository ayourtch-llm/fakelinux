mod creds;
mod elf;
mod epoll;
mod eventfd;
mod linux;
mod loader;
mod net;
mod procfs;
mod rootfs;
mod signal;
mod syscall;
mod thread;
mod translate;
mod trampoline;
mod trap;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: fakelinux <aarch64-linux-elf> [args...]");
        eprintln!("  Set FAKELINUX_SYSROOT to an aarch64 Linux rootfs for dynamic binaries.");
        std::process::exit(1);
    }

    let elf_path = &args[1];
    let mut sysroot = std::env::var("FAKELINUX_SYSROOT").unwrap_or_default();
    let rootfs = std::env::var("FAKELINUX_ROOT").unwrap_or_default();

    // When FAKELINUX_ROOT is set but FAKELINUX_SYSROOT is not, auto-set sysroot = root.
    // This way FAKELINUX_ROOT alone is sufficient for rootfs usage.
    if !rootfs.is_empty() && sysroot.is_empty() {
        sysroot = rootfs.clone();
    }

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
    rootfs::init(&rootfs, &sysroot);
    syscall::init_sysroot(&sysroot);
    procfs::init(elf_path);

    // Initialize per-thread pthread keys before anything else
    trap::init_tpidr_key();
    trap::init_x18_key();
    thread::init_tid_key();
    thread::init_clear_tid_key();

    thread::init_main_tid();
    // Initialize GUEST_TPIDR to macOS value — guest MRS tpidr_el0 needs a
    // non-zero value before __set_thread_area runs.
    {
        let tpidr: u64;
        unsafe { std::arch::asm!("mrs {}, tpidr_el0", out(reg) tpidr); }
        trap::set_thread_tpidr(tpidr);
    }
    // Initialize guest x18 — macOS zeroes x18 in the mcontext during signal
    // delivery (it's the "platform register"), so we can never read the real
    // value from inside the handler. We must capture it BEFORE the first BRK.
    // At this point x18=0 (we zeroed all regs in jump_to_entry), but that's
    // fine — musl's _dlstart will set x18 to the string table address before
    // using it. The key is having a non-zero saved value so the handler knows
    // to restore it. We read it just before jumping to guest code instead.
    // For now, set to 0 — the real fix is below in jump_to_entry.
    signal::create_sigreturn_trampoline();
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
