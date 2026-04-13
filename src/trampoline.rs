//! Generic post-signal trampoline infrastructure.
//!
//! Some operations (fork, mprotect on file-backed pages) are unsafe to perform
//! inside a signal handler on macOS. The trampoline pattern defers these:
//!
//! 1. Signal handler marks a trampoline as pending + saves guest registers
//! 2. Signal handler redirects sigreturn PC to the trampoline page
//! 3. Trampoline runs outside signal context, does the unsafe work
//! 4. Trampoline restores guest registers and resumes guest execution
//!
//! Usage:
//!   static MY_TRAMP: Trampoline = Trampoline::new();
//!   // During init:
//!   MY_TRAMP.init(page_addr, my_entry_fn);
//!   // In syscall handler (signal context):
//!   MY_TRAMP.mark_pending();
//!   // After emulate() in trap handler:
//!   trampoline::check_and_redirect(mctx, uctx, result, resume_pc);
//!   // In entry_fn (outside signal context):
//!   unsafe { MY_TRAMP.restore_and_resume(); }

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

const PAGE_SIZE: usize = 16384;

// ─── SavedRegs ──────────────────────────────────────────────────────────────

/// Guest register state saved by the signal handler for restoration
/// by the trampoline after it completes its deferred work.
#[repr(C)]
pub struct SavedRegs {
    pub x: [u64; 29],
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
}

impl SavedRegs {
    pub const ZERO: Self = Self { x: [0; 29], fp: 0, lr: 0, sp: 0, pc: 0 };
}

// ─── restore_all_regs ───────────────────────────────────────────────────────

/// Restore ALL guest registers from a SavedRegs struct and branch to `pc`.
/// x0 = pointer to SavedRegs, x1 = branch target (guest pc).
///
/// Naked function — no prologue/epilogue, pure asm.
/// SavedRegs layout: x[0..29] at offsets 0..228, fp@232, lr@240, sp@248, pc@256
///
/// Note: x16 (IP0) is used as the branch target and is NOT restored to its
/// guest value. x16/x17 are intra-procedure-call scratch registers per AAPCS
/// that are only used by PLT stubs and linker veneers, never by user code
/// across function boundaries. All other registers (x0-x15, x17-x28, fp, lr, sp)
/// are restored exactly.
#[unsafe(naked)]
pub unsafe extern "C" fn restore_all_regs(_regs_ptr: u64, _pc: u64) -> ! {
    core::arch::naked_asm!(
        // x0 = base (SavedRegs*), x1 = branch target (pc)
        // Stash pc and guest_x17 below guest sp (32 bytes, 16-aligned)
        "ldr x2, [x0, #248]",          // guest sp
        "ldr x3, [x0, #136]",          // guest x17 at offset 17*8=136
        "stp x1, x3, [x2, #-32]!",     // push [pc, guest_x17], x2 = sp-32
        "mov sp, x2",                   // set sp to stash area
        // Restore callee-saved x19-x28
        "ldp x19, x20, [x0, #152]",
        "ldp x21, x22, [x0, #168]",
        "ldp x23, x24, [x0, #184]",
        "ldp x25, x26, [x0, #200]",
        "ldp x27, x28, [x0, #216]",
        // Restore fp and lr
        "ldp x29, x30, [x0, #232]",
        // Restore caller-saved x1-x15, x18 (skip x16=branch scratch, x17=on stack)
        "ldp x1, x2, [x0, #8]",
        "ldp x3, x4, [x0, #24]",
        "ldp x5, x6, [x0, #40]",
        "ldp x7, x8, [x0, #56]",
        "ldp x9, x10, [x0, #72]",
        "ldp x11, x12, [x0, #88]",
        "ldp x13, x14, [x0, #104]",
        "ldr x15, [x0, #120]",         // x15 at 15*8=120
        "ldr x18, [x0, #144]",         // x18 at 18*8=144
        // Restore x0 last (clobbers base pointer)
        "ldr x0, [x0]",
        // Pop pc into x16 (branch scratch) and guest x17
        "ldp x16, x17, [sp], #32",     // x16=pc, x17=guest_x17, sp+=32 (original guest sp)
        "br x16",
    );
}

// ─── Trampoline struct ──────────────────────────────────────────────────────

/// A post-signal trampoline. Each instance has:
/// - An executable page with a `ldr x9, [pc,#8]; blr x9` stub
/// - A pending flag (set by signal handler, cleared by check_and_redirect)
/// - Saved guest registers (for resuming the guest after deferred work)
pub struct Trampoline {
    page_addr: AtomicU64,
    pending: AtomicBool,
    regs: UnsafeCell<SavedRegs>,
}

// SAFETY: saved_regs is only written by the signal handler and read by the
// trampoline entry function, which runs sequentially after the handler returns.
// No concurrent mutable access occurs.
unsafe impl Sync for Trampoline {}

impl Trampoline {
    pub const fn new() -> Self {
        Self {
            page_addr: AtomicU64::new(0),
            pending: AtomicBool::new(false),
            regs: UnsafeCell::new(SavedRegs::ZERO),
        }
    }

    /// Initialize this trampoline: allocate an executable page at `near_addr`
    /// that calls `entry_fn`, and register in the global trampoline list.
    pub fn init(&'static self, near_addr: u64, entry_fn: extern "C" fn() -> !) {
        let ptr = unsafe {
            libc::mmap(
                near_addr as *mut _, PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED, -1, 0,
            )
        };
        if ptr == libc::MAP_FAILED {
            panic!("failed to allocate trampoline page at {:#x}", near_addr);
        }
        let addr = ptr as u64;
        let fn_addr = entry_fn as *const () as u64;

        // Code at offset 0: ldr x9, [pc, #8]  (loads from offset 8)
        // Code at offset 4: blr x9
        // Data at offset 8: .quad entry_fn
        unsafe {
            let p = addr as *mut u32;
            p.add(0).write(0x5800_0049); // ldr x9, [pc, #8]
            p.add(1).write(0xD63F_0120); // blr x9
            ((addr + 8) as *mut u64).write(fn_addr);
            libc::mprotect(ptr, PAGE_SIZE, libc::PROT_READ | libc::PROT_EXEC);
            extern "C" { fn sys_icache_invalidate(start: *mut libc::c_void, size: usize); }
            sys_icache_invalidate(ptr, PAGE_SIZE);
        }

        self.page_addr.store(addr, Ordering::SeqCst);
        register(self);
    }

    /// Get the executable page address.
    pub fn addr(&self) -> u64 {
        self.page_addr.load(Ordering::SeqCst)
    }

    /// Mark this trampoline as having pending work. Called from syscall handlers.
    pub fn mark_pending(&self) {
        self.pending.store(true, Ordering::SeqCst);
    }

    /// Save guest registers for resume after the trampoline completes.
    pub fn save_regs(&self, ss: &crate::trap::ThreadState64, resume_pc: u64) {
        let r = unsafe { &mut *self.regs.get() };
        r.x = ss.x;
        r.fp = ss.fp;
        r.lr = ss.lr;
        r.sp = ss.sp;
        r.pc = resume_pc;
    }

    /// Get the saved PC value.
    pub fn get_saved_pc(&self) -> u64 {
        unsafe { (*self.regs.get()).pc }
    }

    /// Get a saved register value by index (0-28).
    pub fn get_saved_x(&self, n: usize) -> u64 {
        unsafe { (*self.regs.get()).x[n] }
    }

    /// Get the saved SP value.
    pub fn get_saved_sp(&self) -> u64 {
        unsafe { (*self.regs.get()).sp }
    }

    /// Override x0 in the saved register state (e.g. to set the syscall return value
    /// or fork pid).
    pub fn set_x0(&self, val: u64) {
        unsafe { (*self.regs.get()).x[0] = val; }
    }

    /// Restore all guest registers and jump to the saved PC. Never returns.
    /// Call this at the end of a trampoline entry function after completing
    /// the deferred work.
    pub unsafe fn restore_and_resume(&self) -> ! {
        let r = &*self.regs.get();
        // Debug: verify x0 in SavedRegs right before the asm restore.
        // Use stack buffer only — no heap allocation after fork.
        if crate::syscall::trace_enabled() {
            let pid = libc::getpid();
            let mut buf = [0u8; 120];
            let n = {
                use std::io::Write;
                let mut c = std::io::Cursor::new(&mut buf[..]);
                let _ = c.write_fmt(format_args!(
                    "fakelinux: [{}] RESTORE x0={:#x} pc={:#x}\n",
                    pid, r.x[0], r.pc));
                c.position() as usize
            };
            libc::write(2, buf.as_ptr() as *const _, n);
        }
        restore_all_regs(r as *const SavedRegs as u64, r.pc);
    }
}

// ─── Global trampoline registry ─────────────────────────────────────────────

const MAX_TRAMPOLINES: usize = 8;
static REGISTRY_LEN: AtomicUsize = AtomicUsize::new(0);
static REGISTRY: [AtomicU64; MAX_TRAMPOLINES] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];

fn register(t: &'static Trampoline) {
    let idx = REGISTRY_LEN.fetch_add(1, Ordering::SeqCst);
    assert!(idx < MAX_TRAMPOLINES, "too many trampolines registered");
    REGISTRY[idx].store(t as *const Trampoline as u64, Ordering::SeqCst);
}

/// Check all registered trampolines after a syscall completes. If one is
/// pending, atomically clear it, save guest registers, set x0 = `result`,
/// and redirect sigreturn to the trampoline page.
///
/// Returns true if a trampoline was activated (caller should skip normal
/// x0/pc updates).
pub fn check_and_redirect(
    mctx: &mut crate::trap::MContext64,
    uctx: &mut crate::trap::UContext,
    result: u64,
    resume_pc: u64,
) -> bool {
    let len = REGISTRY_LEN.load(Ordering::SeqCst);
    for i in 0..len {
        let ptr = REGISTRY[i].load(Ordering::SeqCst);
        if ptr == 0 { continue; }
        let t = unsafe { &*(ptr as *const Trampoline) };
        if t.pending.swap(false, Ordering::SeqCst) {
            t.save_regs(&mctx.ss, resume_pc);
            t.set_x0(result);
            mctx.ss.pc = t.addr();
            uctx.uc_sigmask = 0;
            return true;
        }
    }
    false
}
