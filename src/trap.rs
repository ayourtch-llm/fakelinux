use std::ffi::c_void;

use crate::syscall;

/// The BRK instruction we patch in place of SVC #0.
/// BRK #0xF000 = 0xD43E0000
pub const BRK_MARKER: u32 = 0xD43E_0000;

/// The original SVC #0 encoding.
pub const SVC_0: u32 = 0xD400_0001;

// macOS aarch64 mcontext structures (repr(C) to match kernel layout)

#[repr(C)]
struct ExceptionState64 {
    far: u64,
    esr: u32,
    exception: u32,
}

#[repr(C)]
pub struct ThreadState64 {
    pub x: [u64; 29],
    pub fp: u64, // x29
    pub lr: u64, // x30
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u32,
    _pad: u32,
}

#[repr(C)]
struct MContext64 {
    es: ExceptionState64,
    ss: ThreadState64,
    // NEON state follows; we don't need it
}

// macOS aarch64 ucontext_t layout
#[repr(C)]
struct UContext {
    uc_onstack: i32,
    uc_sigmask: u32,
    uc_stack: libc::stack_t,
    uc_link: *mut UContext,
    uc_mcsize: usize,
    uc_mcontext: *mut MContext64,
}

unsafe extern "C" fn sigtrap_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    ctx: *mut c_void,
) {
    let uctx = &mut *(ctx as *mut UContext);
    let mctx = &mut *uctx.uc_mcontext;
    let regs = &mut mctx.ss;

    // Verify this is our BRK marker
    let pc = regs.pc;
    let instr = *(pc as *const u32);
    if instr != BRK_MARKER {
        // Not ours — re-raise as default SIGTRAP behavior (abort)
        eprintln!(
            "fakelinux: unexpected SIGTRAP at pc={:#x} instr={:#010x}",
            pc, instr
        );
        libc::_exit(128 + libc::SIGTRAP);
    }

    // Linux aarch64 ABI: syscall nr in x8, args in x0-x5
    let nr = regs.x[8];
    let args = [
        regs.x[0], regs.x[1], regs.x[2], regs.x[3], regs.x[4], regs.x[5],
    ];

    let result = syscall::emulate(nr, &args, regs);

    // Write result to x0 (unless the syscall already exited)
    regs.x[0] = result as u64;

    // Advance PC past the BRK
    regs.pc = pc + 4;
}

pub fn install_handler() {
    unsafe {
        // Allocate a signal-handler stack so we don't stomp the guest's stack
        let stack_size: usize = 128 * 1024;
        let stack = libc::mmap(
            std::ptr::null_mut(),
            stack_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        if stack == libc::MAP_FAILED {
            panic!("failed to allocate signal stack");
        }
        let ss = libc::stack_t {
            ss_sp: stack,
            ss_flags: 0,
            ss_size: stack_size,
        };
        if libc::sigaltstack(&ss, std::ptr::null_mut()) != 0 {
            panic!("sigaltstack failed");
        }

        // Install SIGTRAP handler with SA_SIGINFO
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigtrap_handler as *const () as libc::sighandler_t;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGTRAP, &sa, std::ptr::null_mut()) != 0 {
            panic!("sigaction(SIGTRAP) failed");
        }
    }
}
