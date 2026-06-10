mod creds;
mod decoder;
mod elf;
mod epoll;
mod eventfd;
mod linux;
mod loader;
mod net;
mod pidns;
mod procfs;
mod rootfs;
mod signal;
mod syscall;
mod thread;
mod timers;
mod translate;
mod trampoline;
mod trap;
mod x18_trampoline;

fn main() {
    let mut args: Vec<String> = std::env::args().collect();

    // Parse --container flag (must come before the ELF path)
    let mut container_mode = false;
    let mut guest_arg_start = 1;
    if args.len() > 1 && (args[1] == "--container" || args[1] == "--init") {
        container_mode = true;
        guest_arg_start = 2;
    }

    if args.len() <= guest_arg_start {
        eprintln!("Usage: fakelinux [--container] <aarch64-linux-elf> [args...]");
        eprintln!("  --container  Run in container mode (virtual PID namespace, PID 1)");
        eprintln!("  Set FAKELINUX_SYSROOT to an aarch64 Linux rootfs for dynamic binaries.");
        std::process::exit(1);
    }

    let elf_path = &args[guest_arg_start];
    let sysroot = std::env::var("FAKELINUX_SYSROOT").unwrap_or_default();
    let rootfs = std::env::var("FAKELINUX_ROOT").unwrap_or_default();

    // Convert relative rootfs/sysroot paths to absolute so they survive cd/chdir
    // in child processes after fork+exec.
    let rootfs = if !rootfs.is_empty() && !rootfs.starts_with('/') {
        let abs = std::env::current_dir().unwrap().join(&rootfs);
        let abs_str = abs.to_str().unwrap().to_string();
        std::env::set_var("FAKELINUX_ROOT", &abs_str);
        abs_str
    } else { rootfs };
    let sysroot = if !sysroot.is_empty() && !sysroot.starts_with('/') {
        let abs = std::env::current_dir().unwrap().join(&sysroot);
        let abs_str = abs.to_str().unwrap().to_string();
        std::env::set_var("FAKELINUX_SYSROOT", &abs_str);
        abs_str
    } else { sysroot };

    // When FAKELINUX_ROOT is set but FAKELINUX_SYSROOT is not, auto-set sysroot = root.
    // This way FAKELINUX_ROOT alone is sufficient for rootfs usage.
    let sysroot = if !rootfs.is_empty() && sysroot.is_empty() {
        rootfs.clone()
    } else {
        sysroot
    };

    // Initialize subsystems (rootfs first: the ELF path may traverse
    // absolute symlinks that must resolve inside the rootfs, not host /).
    if std::env::var("FAKELINUX_TRACE").is_ok() {
        syscall::set_trace(true);
    }
    rootfs::init(&rootfs, &sysroot);
    syscall::init_sysroot(&sysroot);

    // Absolutize the ELF path (rootfs prefix matching needs it), then
    // resolve symlinks within the rootfs (e.g. usr/bin/vim →
    // /etc/alternatives/vim → usr/bin/vim.basic).
    let elf_path_abs = if elf_path.starts_with('/') {
        elf_path.clone()
    } else {
        std::env::current_dir().unwrap().join(elf_path.as_str())
            .to_str().unwrap().to_string()
    };
    let elf_path = rootfs::resolve_host_path(&elf_path_abs);

    let data = std::fs::read(&elf_path).unwrap_or_else(|e| {
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

    // Strip rootfs prefix from the binary path so the guest sees guest paths
    // (e.g., "/Users/.../ubuntu-rootfs/bin/dash" → "/bin/dash").
    // The ELF file has already been read above using the original host path.
    if rootfs::in_full_rootfs_mode() {
        if let Some(guest_path) = rootfs::strip_root_prefix(args[guest_arg_start].as_bytes()) {
            args[guest_arg_start] = String::from_utf8_lossy(&guest_path).to_string();
        }
    }

    procfs::init(&args[guest_arg_start]);

    // The previous fakelinux process (execve) may carry the guest's original
    // argv[0] — e.g. a venv's bin/python3.12 symlink path that must NOT be
    // replaced by the resolved /usr/bin/python3.12 (CPython finds pyvenv.cfg
    // relative to argv[0]). /proc/self/exe keeps the resolved path above.
    if let Ok(argv0) = std::env::var("FAKELINUX_ARGV0") {
        if !argv0.is_empty() {
            args[guest_arg_start] = argv0;
        }
        std::env::remove_var("FAKELINUX_ARGV0");
    }

    // Initialize per-thread pthread keys before anything else
    trap::init_tpidr_key();
    trap::init_x18_key();
    trap::set_thread_x18(0); // Initialize main thread's x18 TSD slot
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
    signal::create_sigreturn_trampoline();
    trap::install_handler();

    // Restore signal state inherited from before execve.
    // POSIX: SIG_IGN is preserved across execve; signal mask is preserved.
    // The previous fakelinux process encoded these in env vars.
    if let Ok(ign_str) = std::env::var("FAKELINUX_SIGIGN") {
        if let Ok(ign_mask) = u64::from_str_radix(ign_str.trim_start_matches("0x"), 16) {
            for sig in 1..65u64 {
                if ign_mask & (1u64 << (sig - 1)) != 0 {
                    // Set this signal to SIG_IGN in the guest signal table
                    signal::do_rt_sigaction(sig, 0, 0, 8);
                    // Write SIG_IGN directly (do_rt_sigaction with act_ptr=0 is a no-op)
                    // Instead, build a SIG_IGN sigaction on the stack and call do_rt_sigaction
                    let ign_act: [u64; 4] = [1, 0, 0, 0]; // handler=SIG_IGN, flags=0, restorer=0, mask=0
                    signal::do_rt_sigaction(sig, ign_act.as_ptr() as u64, 0, 8);
                }
            }
        }
        std::env::remove_var("FAKELINUX_SIGIGN");
    }
    if let Ok(mask_str) = std::env::var("FAKELINUX_SIGMASK") {
        if let Ok(mask) = u64::from_str_radix(mask_str.trim_start_matches("0x"), 16) {
            signal::GUEST_SIGMASK.store(mask, std::sync::atomic::Ordering::SeqCst);
        }
        std::env::remove_var("FAKELINUX_SIGMASK");
    }

    // Initialize container mode:
    // --container flag creates a new namespace (init process, PID 1)
    // FAKELINUX_CONTAINER env var attaches to existing namespace (child after execve)
    if container_mode {
        pidns::init_container();
        eprintln!("fakelinux: container mode (--container), virtual PID 1");
    } else if std::env::var("FAKELINUX_CONTAINER").is_ok() {
        let init_pid: i32 = std::env::var("FAKELINUX_INIT_PID")
            .ok().and_then(|s| s.parse().ok()).unwrap_or(0);
        if init_pid > 0 {
            pidns::attach_container(init_pid);
        }
    }

    // Load segments, patch SVCs, set up stack
    let loaded = loader::load(&elf, &data, &args[guest_arg_start..], &sysroot).unwrap_or_else(|e| {
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
