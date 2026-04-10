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
