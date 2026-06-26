/// Generates a minimal static aarch64 Linux ELF binary that prints "Hello, world!\n" and exits.
/// No cross-compiler needed — we emit raw bytes.
///
/// Usage: cargo run --bin gen_test_elf > hello/hello_min
///        chmod +x hello/hello_min
///        (or just run hello/build.sh, which does this plus the cross-compiles)

fn main() {
    let base: u64 = match std::env::args().nth(1) {
        Some(s) => u64::from_str_radix(s.trim_start_matches("0x"), 16)
            .expect("base address must be hex, e.g. 0x100000000"),
        // Default: well above macOS PAGEZERO and the host binary
        None => 0x7_0000_0000,
    };

    // ── Instruction encoding ──────────────────────────────────────────
    // Code starts at file offset 120 (ELF header 64 + 1 PHDR 56)
    let code_offset: u64 = 120;
    let msg_offset_from_code: u64 = 32; // 8 instructions × 4 bytes

    let adr_imm: u64 = msg_offset_from_code - 4; // ADR is at code_offset+4, msg at code_offset+32 → delta = 28

    let instructions: [u32; 8] = [
        0xD280_0020,                             // mov  x0, #1          ; fd = stdout
        encode_adr(1, adr_imm as i32),           // adr  x1, msg         ; buf
        0xD280_01C2,                             // mov  x2, #14         ; len
        0xD280_0808,                             // mov  x8, #64         ; __NR_write
        0xD400_0001,                             // svc  #0
        0xD280_0000,                             // mov  x0, #0          ; status = 0
        0xD280_0BA8,                             // mov  x8, #93         ; __NR_exit
        0xD400_0001,                             // svc  #0
    ];
    let msg = b"Hello, world!\n";

    // Total file size
    let total_size: u64 = code_offset + (instructions.len() as u64) * 4 + msg.len() as u64;
    let entry = base + code_offset;

    let mut out: Vec<u8> = Vec::with_capacity(total_size as usize);

    // ── ELF64 Header (64 bytes) ──────────────────────────────────────
    out.extend_from_slice(&[0x7f, b'E', b'L', b'F']); // e_ident[EI_MAG]
    out.push(2);  // EI_CLASS = ELFCLASS64
    out.push(1);  // EI_DATA = ELFDATA2LSB
    out.push(1);  // EI_VERSION = EV_CURRENT
    out.push(0);  // EI_OSABI = ELFOSABI_NONE
    out.extend_from_slice(&[0u8; 8]); // EI_ABIVERSION + padding
    out.extend_from_slice(&2u16.to_le_bytes());    // e_type = ET_EXEC
    out.extend_from_slice(&183u16.to_le_bytes());  // e_machine = EM_AARCH64
    out.extend_from_slice(&1u32.to_le_bytes());    // e_version
    out.extend_from_slice(&entry.to_le_bytes());   // e_entry
    out.extend_from_slice(&64u64.to_le_bytes());   // e_phoff
    out.extend_from_slice(&0u64.to_le_bytes());    // e_shoff
    out.extend_from_slice(&0u32.to_le_bytes());    // e_flags
    out.extend_from_slice(&64u16.to_le_bytes());   // e_ehsize
    out.extend_from_slice(&56u16.to_le_bytes());   // e_phentsize
    out.extend_from_slice(&1u16.to_le_bytes());    // e_phnum
    out.extend_from_slice(&0u16.to_le_bytes());    // e_shentsize
    out.extend_from_slice(&0u16.to_le_bytes());    // e_shnum
    out.extend_from_slice(&0u16.to_le_bytes());    // e_shstrndx
    assert_eq!(out.len(), 64);

    // ── Program Header (56 bytes) ────────────────────────────────────
    out.extend_from_slice(&1u32.to_le_bytes());    // p_type = PT_LOAD
    out.extend_from_slice(&5u32.to_le_bytes());    // p_flags = PF_R | PF_X
    out.extend_from_slice(&0u64.to_le_bytes());    // p_offset
    out.extend_from_slice(&base.to_le_bytes());    // p_vaddr
    out.extend_from_slice(&base.to_le_bytes());    // p_paddr
    out.extend_from_slice(&total_size.to_le_bytes()); // p_filesz
    out.extend_from_slice(&total_size.to_le_bytes()); // p_memsz
    out.extend_from_slice(&0x10000u64.to_le_bytes()); // p_align
    assert_eq!(out.len(), 120);

    // ── Code ─────────────────────────────────────────────────────────
    for instr in &instructions {
        out.extend_from_slice(&instr.to_le_bytes());
    }

    // ── Data ─────────────────────────────────────────────────────────
    out.extend_from_slice(msg);

    assert_eq!(out.len(), total_size as usize);

    // Write to stdout as raw bytes
    use std::io::Write;
    let stdout = std::io::stdout();
    stdout.lock().write_all(&out).expect("write failed");

    eprintln!("Generated {}-byte aarch64 Linux ELF (base={:#x} entry={:#x})", out.len(), base, entry);
}

/// Encode ADR Xd, #imm  (PC-relative, ±1 MB range)
fn encode_adr(rd: u32, imm: i32) -> u32 {
    let uimm = imm as u32;
    let immlo = uimm & 0x3;
    let immhi = (uimm >> 2) & 0x7FFFF;
    (0 << 31) | (immlo << 29) | (0b10000 << 24) | (immhi << 5) | rd
}
