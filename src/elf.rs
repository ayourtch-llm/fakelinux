use crate::linux::*;
use std::fmt;

#[derive(Debug)]
pub struct ElfError(pub String);

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ELF error: {}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct Elf64Header {
    pub e_type: u16,
    pub e_machine: u16,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_phentsize: u16,
    pub e_phnum: u16,
}

#[derive(Debug, Clone)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

#[derive(Debug)]
pub struct Elf {
    pub header: Elf64Header,
    pub phdrs: Vec<Elf64Phdr>,
}

fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn read_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ])
}

// Public wrappers for use by loader.rs runtime code range detection
pub fn read_u16_pub(data: &[u8], off: usize) -> u16 { read_u16(data, off) }
pub fn read_u32_pub(data: &[u8], off: usize) -> u32 { read_u32(data, off) }
pub fn read_u64_pub(data: &[u8], off: usize) -> u64 { read_u64(data, off) }

pub fn parse(data: &[u8]) -> Result<Elf, ElfError> {
    if data.len() < 64 {
        return Err(ElfError("file too small for ELF header".into()));
    }
    if data[0..4] != ELFMAG {
        return Err(ElfError("bad ELF magic".into()));
    }
    if data[4] != ELFCLASS64 {
        return Err(ElfError("not ELF64".into()));
    }
    if data[5] != ELFDATA2LSB {
        return Err(ElfError("not little-endian".into()));
    }

    let e_type = read_u16(data, 16);
    let e_machine = read_u16(data, 18);
    if e_machine != EM_AARCH64 {
        return Err(ElfError(format!(
            "not aarch64 (e_machine={})",
            e_machine
        )));
    }
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(ElfError(format!("unsupported ELF type {}", e_type)));
    }

    let header = Elf64Header {
        e_type,
        e_machine,
        e_entry: read_u64(data, 24),
        e_phoff: read_u64(data, 32),
        e_phentsize: read_u16(data, 54),
        e_phnum: read_u16(data, 56),
    };

    let mut phdrs = Vec::new();
    for i in 0..header.e_phnum as usize {
        let off = header.e_phoff as usize + i * header.e_phentsize as usize;
        if off + 56 > data.len() {
            return Err(ElfError("program header out of bounds".into()));
        }
        phdrs.push(Elf64Phdr {
            p_type: read_u32(data, off),
            p_flags: read_u32(data, off + 4),
            p_offset: read_u64(data, off + 8),
            p_vaddr: read_u64(data, off + 16),
            p_paddr: read_u64(data, off + 24),
            p_filesz: read_u64(data, off + 32),
            p_memsz: read_u64(data, off + 40),
            p_align: read_u64(data, off + 48),
        });
    }

    Ok(Elf { header, phdrs })
}

// ─── .eh_frame FDE parser ──────────────────────────────────────────────────
//
// Every function in a modern aarch64 ELF has a Frame Description Entry (FDE)
// in .eh_frame that gives its exact start address and byte length.  Gaps
// between FDEs in .text are literal pools / alignment padding — NOT code.
//
// Using FDE ranges as the patching whitelist is strictly more precise than
// section-header SHF_EXECINSTR (which marks entire sections, including any
// embedded data tables).

/// DWARF pointer-encoding value types (low nibble of DW_EH_PE_*).
const DW_EH_PE_ABSPTR: u8 = 0x00;
const DW_EH_PE_ULEB128: u8 = 0x01;
const DW_EH_PE_UDATA2: u8 = 0x02;
const DW_EH_PE_UDATA4: u8 = 0x03;
const DW_EH_PE_UDATA8: u8 = 0x04;
const DW_EH_PE_SLEB128: u8 = 0x09;
const DW_EH_PE_SDATA2: u8 = 0x0a;
const DW_EH_PE_SDATA4: u8 = 0x0b;
const DW_EH_PE_SDATA8: u8 = 0x0c;

/// DWARF pointer-encoding applications (high nibble of DW_EH_PE_*).
const DW_EH_PE_PCREL: u8 = 0x10;
const DW_EH_PE_OMIT: u8 = 0xff;

/// Read a ULEB128 value.  Returns (value, bytes_consumed).
fn read_uleb128(data: &[u8], off: usize) -> (u64, usize) {
    let mut val = 0u64;
    let mut shift = 0;
    let mut i = 0;
    loop {
        if off + i >= data.len() { return (val, i); }
        let b = data[off + i];
        val |= ((b & 0x7f) as u64) << shift;
        i += 1;
        if b & 0x80 == 0 { break; }
        shift += 7;
        if shift >= 64 { break; }
    }
    (val, i)
}

/// Read a SLEB128 value.  Returns (value, bytes_consumed).
fn read_sleb128(data: &[u8], off: usize) -> (i64, usize) {
    let mut val = 0i64;
    let mut shift = 0u32;
    let mut i = 0;
    let mut last_byte = 0u8;
    loop {
        if off + i >= data.len() { return (val, i); }
        let b = data[off + i];
        last_byte = b;
        val |= ((b & 0x7f) as i64) << shift;
        i += 1;
        shift += 7;
        if b & 0x80 == 0 { break; }
        if shift >= 64 { break; }
    }
    // Sign-extend if the last byte's sign bit is set
    if shift < 64 && last_byte & 0x40 != 0 {
        val |= !0i64 << shift;
    }
    (val, i)
}

/// Read an encoded pointer value per DWARF DW_EH_PE_* encoding.
/// `enc` is the encoding byte.  `off` is the current position in `data`.
/// `pc` is the absolute address of this position in memory (for pcrel).
/// Returns (decoded_value, bytes_consumed), or None if unsupported.
fn read_encoded_ptr(data: &[u8], off: usize, enc: u8, pc: u64) -> Option<(u64, usize)> {
    if enc == DW_EH_PE_OMIT { return None; }
    let value_type = enc & 0x0f;
    let application = enc & 0x70;

    // Read raw value
    let (raw, sz) = match value_type {
        DW_EH_PE_ABSPTR => {
            if off + 8 > data.len() { return None; }
            (read_u64(data, off), 8)
        }
        DW_EH_PE_UDATA2 => {
            if off + 2 > data.len() { return None; }
            (read_u16(data, off) as u64, 2)
        }
        DW_EH_PE_UDATA4 => {
            if off + 4 > data.len() { return None; }
            (read_u32(data, off) as u64, 4)
        }
        DW_EH_PE_UDATA8 => {
            if off + 8 > data.len() { return None; }
            (read_u64(data, off), 8)
        }
        DW_EH_PE_SDATA2 => {
            if off + 2 > data.len() { return None; }
            (read_u16(data, off) as i16 as i64 as u64, 2)
        }
        DW_EH_PE_SDATA4 => {
            if off + 4 > data.len() { return None; }
            (read_u32(data, off) as i32 as i64 as u64, 4)
        }
        DW_EH_PE_SDATA8 => {
            if off + 8 > data.len() { return None; }
            (read_u64(data, off), 8)
        }
        DW_EH_PE_ULEB128 => {
            let (v, s) = read_uleb128(data, off);
            (v, s)
        }
        DW_EH_PE_SLEB128 => {
            let (v, s) = read_sleb128(data, off);
            (v as u64, s)
        }
        _ => return None,
    };

    // Apply relocation
    let val = match application {
        0x00 => raw,                          // DW_EH_PE_absptr
        DW_EH_PE_PCREL => pc.wrapping_add(raw), // PC-relative
        _ => raw, // datarel/textrel/funcrel — treat as absolute (rare)
    };
    Some((val, sz))
}

/// Size in bytes of the value portion of a DWARF pointer encoding.
/// Returns 0 for variable-length encodings (ULEB128/SLEB128/omit).
fn encoded_ptr_size(enc: u8) -> usize {
    match enc & 0x0f {
        DW_EH_PE_ABSPTR => 8, // 64-bit
        DW_EH_PE_UDATA2 | DW_EH_PE_SDATA2 => 2,
        DW_EH_PE_UDATA4 | DW_EH_PE_SDATA4 => 4,
        DW_EH_PE_UDATA8 | DW_EH_PE_SDATA8 => 8,
        _ => 0,
    }
}

/// Extract function address ranges from .eh_frame data.
///
/// `eh_data` is the raw .eh_frame section bytes.
/// `eh_vaddr` is the virtual address where .eh_frame is mapped.
/// `load_base` is the relocation delta (actual_load_addr − ELF_vaddr).
///
/// Returns a sorted list of (function_start, function_length) pairs.
pub fn parse_eh_frame_ranges(eh_data: &[u8], eh_vaddr: u64, load_base: u64) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    let mut pos = 0usize;

    // Map from CIE file-offset → fde_encoding for that CIE.
    // We only need the 'R' augmentation byte from each CIE.
    let mut cie_encodings: Vec<(usize, u8)> = Vec::new();

    while pos + 4 <= eh_data.len() {
        let length = read_u32(eh_data, pos) as usize;
        if length == 0 { break; } // terminator
        // Extended length (> 4 GB entries) — skip
        if length == 0xFFFFFFFF {
            if pos + 12 > eh_data.len() { break; }
            let ext_len = read_u64(eh_data, pos + 4) as usize;
            pos += 12 + ext_len;
            continue;
        }
        let entry_start = pos + 4; // past the length field
        let entry_end = entry_start + length;
        if entry_end > eh_data.len() { break; }

        let cie_id = read_u32(eh_data, entry_start);

        if cie_id == 0 {
            // ─── CIE ───
            // Parse just enough to extract the FDE pointer encoding ('R' augmentation).
            let mut p = entry_start + 4; // past cie_id
            if p >= entry_end { pos = entry_end; continue; }
            let _version = eh_data[p]; p += 1;

            // Augmentation string (null-terminated)
            let aug_start = p;
            while p < entry_end && eh_data[p] != 0 { p += 1; }
            let aug_str = &eh_data[aug_start..p];
            if p < entry_end { p += 1; } // skip null

            // code_alignment_factor (ULEB128)
            let (_, sz) = read_uleb128(eh_data, p); p += sz;
            // data_alignment_factor (SLEB128)
            let (_, sz) = read_sleb128(eh_data, p); p += sz;
            // return_address_register (ULEB128)
            let (_, sz) = read_uleb128(eh_data, p); p += sz;

            let mut fde_enc = 0x00u8; // default: absptr

            // If 'z' augmentation, read augmentation data
            if aug_str.first() == Some(&b'z') {
                let (aug_len, sz) = read_uleb128(eh_data, p); p += sz;
                let aug_data_end = p + aug_len as usize;

                // Walk the augmentation string characters (skip 'z')
                for &ch in &aug_str[1..] {
                    if p >= aug_data_end { break; }
                    match ch {
                        b'R' => {
                            fde_enc = eh_data[p]; p += 1;
                        }
                        b'L' => {
                            p += 1; // LSDA encoding byte
                        }
                        b'P' => {
                            // Personality encoding + pointer
                            let penc = eh_data[p]; p += 1;
                            let psz = encoded_ptr_size(penc);
                            if psz > 0 { p += psz; }
                            else {
                                // Variable-length — read and discard
                                let (_, sz) = read_uleb128(eh_data, p); p += sz;
                            }
                        }
                        b'S' => {} // Signal frame — no data
                        _ => break, // Unknown — stop parsing augmentation
                    }
                }
                let _ = aug_data_end; // might not have consumed all
            }
            cie_encodings.push((entry_start, fde_enc));
        } else {
            // ─── FDE ───
            // cie_id is the offset from THIS field back to the CIE start.
            let cie_offset = entry_start - cie_id as usize;

            // Look up the encoding for this CIE
            let fde_enc = cie_encodings.iter()
                .find(|&&(off, _)| off == cie_offset)
                .map(|&(_, enc)| enc)
                .unwrap_or(0x1b); // default: sdata4+pcrel (standard aarch64)

            let mut p = entry_start + 4; // past cie_id

            // initial_location — encoded per CIE's 'R' augmentation
            let fde_field_vaddr = eh_vaddr + p as u64;
            let abs_addr = fde_field_vaddr.wrapping_add(load_base);
            if let Some((func_start, sz)) = read_encoded_ptr(eh_data, p, fde_enc, abs_addr) {
                p += sz;
                // address_range — same value type but NOT PC-relative
                let range_enc = fde_enc & 0x0f; // strip application, use absolute
                if let Some((func_len, _)) = read_encoded_ptr(eh_data, p, range_enc, 0) {
                    if func_len > 0 && func_len < 0x1000000 { // sanity: < 16 MB
                        ranges.push((func_start, func_len));
                    }
                }
            }
        }
        pos = entry_end;
    }
    ranges.sort_by_key(|&(addr, _)| addr);
    ranges
}

/// Find .eh_frame section in mapped ELF memory and extract function ranges.
///
/// `data` is the raw bytes of the mapped ELF (starting from the ELF header).
/// `base_addr` is the memory address where `data[0]` is mapped.
///
/// Returns a list of (absolute_addr, length) code ranges, or empty if
/// .eh_frame is not available.
pub fn find_code_ranges_from_eh_frame(data: &[u8], base_addr: u64) -> Vec<(u64, u64)> {
    if data.len() < 64 || data[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Vec::new();
    }

    // Compute load base from the first PT_LOAD segment
    let e_phoff = read_u64(data, 32) as usize;
    let e_phentsize = read_u16(data, 54) as usize;
    let e_phnum = read_u16(data, 56) as usize;
    if e_phoff == 0 || e_phnum == 0 || e_phentsize < 56 {
        return Vec::new();
    }

    let mut first_load_vaddr: Option<u64> = None;
    for i in 0..e_phnum {
        let off = e_phoff + i * e_phentsize;
        if off + 56 > data.len() { break; }
        let p_type = read_u32(data, off);
        let p_vaddr = read_u64(data, off + 16);
        if p_type == 1 /* PT_LOAD */ && first_load_vaddr.is_none() {
            first_load_vaddr = Some(p_vaddr);
        }
    }
    let first_load_vaddr = match first_load_vaddr {
        Some(v) => v,
        None => return Vec::new(),
    };
    let load_base = base_addr.wrapping_sub(first_load_vaddr);

    // Strategy 1: find .eh_frame via section headers (most reliable for offset/size)
    let e_shoff = read_u64(data, 40) as usize;
    let e_shentsize = read_u16(data, 58) as usize;
    let e_shnum = read_u16(data, 60) as usize;
    let e_shstrndx = read_u16(data, 62) as usize;

    if e_shoff != 0 && e_shnum != 0 && e_shentsize >= 64 && e_shoff < data.len() {
        // Read section name string table
        let shstrtab_off_off = e_shoff + e_shstrndx * e_shentsize;
        if shstrtab_off_off + 64 <= data.len() {
            let shstrtab_off = read_u64(data, shstrtab_off_off + 24) as usize;
            let shstrtab_sz = read_u64(data, shstrtab_off_off + 32) as usize;
            if shstrtab_off + shstrtab_sz <= data.len() {
                let strtab = &data[shstrtab_off..shstrtab_off + shstrtab_sz];

                for i in 0..e_shnum {
                    let off = e_shoff + i * e_shentsize;
                    if off + 64 > data.len() { break; }
                    let sh_name = read_u32(data, off) as usize;
                    let sh_addr = read_u64(data, off + 16);
                    let sh_offset = read_u64(data, off + 24) as usize;
                    let sh_size = read_u64(data, off + 32) as usize;

                    // Check section name
                    if sh_name < strtab.len() {
                        let name_end = strtab[sh_name..].iter().position(|&b| b == 0)
                            .map(|p| sh_name + p).unwrap_or(strtab.len());
                        let name = &strtab[sh_name..name_end];
                        if name == b".eh_frame" && sh_size > 0 && sh_offset + sh_size <= data.len() {
                            let eh_data = &data[sh_offset..sh_offset + sh_size];
                            return parse_eh_frame_ranges(eh_data, sh_addr, load_base);
                        }
                    }
                }
            }
        }
    }

    // Strategy 2: find .eh_frame via PT_GNU_EH_FRAME program header
    // This points to .eh_frame_hdr, which contains a pointer to .eh_frame.
    // We'd need to parse .eh_frame_hdr to find .eh_frame — more complex.
    // For now, return empty and let the caller fall back.
    Vec::new()
}

/// Find executable code ranges (sections with SHF_EXECINSTR) in the ELF.
/// Returns a list of (vaddr, size) pairs for code sections like .text and .plt.
/// Falls back to empty list if section headers are absent or malformed.
pub fn find_code_ranges(data: &[u8]) -> Vec<(u64, u64)> {
    const SHF_EXECINSTR: u64 = 4;

    if data.len() < 64 { return Vec::new(); }

    let e_shoff = read_u64(data, 40) as usize;
    let e_shentsize = read_u16(data, 58) as usize;
    let e_shnum = read_u16(data, 60) as usize;

    if e_shoff == 0 || e_shnum == 0 || e_shentsize < 64 { return Vec::new(); }

    let mut ranges = Vec::new();
    for i in 0..e_shnum {
        let off = e_shoff + i * e_shentsize;
        if off + 64 > data.len() { break; }
        let sh_type = read_u32(data, off + 4);
        let sh_flags = read_u64(data, off + 8);
        let sh_addr = read_u64(data, off + 16);
        let sh_size = read_u64(data, off + 32);
        // SHT_PROGBITS (1) with EXECINSTR flag
        if sh_type == 1 && sh_flags & SHF_EXECINSTR != 0 && sh_size > 0 {
            ranges.push((sh_addr, sh_size));
        }
    }
    ranges.sort_by_key(|&(addr, _)| addr);
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uleb128() {
        assert_eq!(read_uleb128(&[0x00], 0), (0, 1));
        assert_eq!(read_uleb128(&[0x7f], 0), (127, 1));
        assert_eq!(read_uleb128(&[0x80, 0x01], 0), (128, 2));
        assert_eq!(read_uleb128(&[0xe5, 0x8e, 0x26], 0), (624485, 3));
    }

    #[test]
    fn test_sleb128() {
        assert_eq!(read_sleb128(&[0x00], 0), (0, 1));
        assert_eq!(read_sleb128(&[0x7f], 0), (-1, 1));
        assert_eq!(read_sleb128(&[0x80, 0x7f], 0), (-128, 2));
        assert_eq!(read_sleb128(&[0x9b, 0xf1, 0x59], 0), (-624485, 3));
    }

    #[test]
    fn test_eh_frame_on_libzstd() {
        // Test against the real libzstd binary in the ubuntu rootfs.
        let path = "ubuntu-rootfs/lib/aarch64-linux-gnu/libzstd.so.1.5.5";
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => { eprintln!("skipping test: {} not found", path); return; }
        };

        let ranges = find_code_ranges_from_eh_frame(&data, 0);
        assert!(!ranges.is_empty(), "should find FDE ranges in libzstd");

        // libzstd 1.5.5 has ~535 FDEs
        assert!(ranges.len() >= 500 && ranges.len() <= 600,
            "expected ~535 FDE ranges, got {}", ranges.len());

        // .text starts at vaddr 0x3f50 — all function ranges should be in or near it
        let text_start = 0x3f50u64;
        let text_end = text_start + 550380;
        let in_text = ranges.iter()
            .filter(|&&(addr, _)| addr >= text_start && addr < text_end)
            .count();
        assert!(in_text > 500,
            "most FDEs should be in .text, got {} of {} in range 0x{:x}..0x{:x}",
            in_text, ranges.len(), text_start, text_end);

        // Total covered bytes should be close to .text size
        let total_covered: u64 = ranges.iter().map(|&(_, len)| len).sum();
        let coverage = total_covered as f64 / 550380.0;
        assert!(coverage > 0.95, "coverage should be >95%, got {:.1}%", coverage * 100.0);
    }

    #[test]
    fn test_eh_frame_on_libcrypto() {
        let path = "ubuntu-rootfs/lib/aarch64-linux-gnu/libcrypto.so.3";
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => { eprintln!("skipping test: {} not found", path); return; }
        };

        let ranges = find_code_ranges_from_eh_frame(&data, 0);
        assert!(!ranges.is_empty(), "should find FDE ranges in libcrypto");

        // libcrypto has ~10518 FDEs
        assert!(ranges.len() >= 10000,
            "expected ~10518 FDE ranges, got {}", ranges.len());

        // .text coverage should be ~89% (libcrypto has many embedded data tables)
        let text_start = 0xb4000u64;
        let text_size = 2453692u64;
        let covered_in_text: u64 = ranges.iter()
            .filter(|&&(addr, _)| addr >= text_start && addr < text_start + text_size)
            .map(|&(_, len)| len)
            .sum();
        let coverage = covered_in_text as f64 / text_size as f64;
        assert!(coverage > 0.85 && coverage < 0.95,
            "libcrypto coverage should be ~89%, got {:.1}%", coverage * 100.0);

        // The SHA-256 K table at offset 0x25a9c0 should NOT be in any range
        let sha_k_addr = 0x25a9c0u64;
        let in_range = ranges.iter().any(|&(start, len)| {
            sha_k_addr >= start && sha_k_addr < start + len
        });
        assert!(!in_range,
            "SHA-256 K table at 0x{:x} should be in a gap (not covered by any FDE)", sha_k_addr);
    }
}
