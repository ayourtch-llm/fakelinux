// Scan a DSO's executable sections with the REAL references_x18 predicate to
// find every word the patcher would rewrite — then we can see which of those
// are real instructions vs data (constant pools / jump tables) inside .text.
//
//   cargo run --release --example scan_x18 -- <path-to.so>
use fakelinux::decoder::{references_x18, decode_emul_class};
use std::fs;

fn rd_u16(d: &[u8], o: usize) -> u16 { u16::from_le_bytes([d[o], d[o + 1]]) }
fn rd_u32(d: &[u8], o: usize) -> u32 { u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]) }
fn rd_u64(d: &[u8], o: usize) -> u64 {
    let mut b = [0u8; 8]; b.copy_from_slice(&d[o..o + 8]); u64::from_le_bytes(b)
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: scan_x18 <file.so>");
    let d = fs::read(&path).expect("read");
    assert_eq!(&d[0..4], b"\x7fELF", "not ELF");
    const SHF_EXECINSTR: u64 = 4;
    let e_shoff = rd_u64(&d, 40) as usize;
    let e_shentsize = rd_u16(&d, 58) as usize;
    let e_shnum = rd_u16(&d, 60) as usize;

    let mut total = 0usize;
    let mut flagged: Vec<(u64, u32, String)> = Vec::new();
    for i in 0..e_shnum {
        let off = e_shoff + i * e_shentsize;
        let sh_flags = rd_u64(&d, off + 8);
        if sh_flags & SHF_EXECINSTR == 0 { continue; }
        let sh_addr = rd_u64(&d, off + 16);
        let sh_offset = rd_u64(&d, off + 24) as usize;
        let sh_size = rd_u64(&d, off + 32) as usize;
        let words = sh_size / 4;
        for w in 0..words {
            let fo = sh_offset + w * 4;
            if fo + 4 > d.len() { break; }
            let instr = rd_u32(&d, fo);
            total += 1;
            if references_x18(instr) {
                let vaddr = sh_addr + (w as u64) * 4;
                flagged.push((vaddr, instr, format!("{:?}", decode_emul_class(instr))));
            }
        }
    }
    println!("scanned {} exec words; references_x18 flagged {}", total, flagged.len());
    for (v, instr, cls) in &flagged {
        println!("  vaddr {:#010x}  word={:08x}  class={}", v, instr, cls);
    }
}
