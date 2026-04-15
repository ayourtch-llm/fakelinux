//! Debug tool for ARM A64 decoder x18 detection

use std::env;

// Copy the decoder module structures here for standalone use
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstrClass {
    Extr,
    AddSubShiftedReg,
    DataProc1Src,
    AddSubImmediate,
    LogicalImmediate,
    MoveWide,
    LogicalShiftedReg,
    AddSubExtReg,
    DataProc2Src,
    Bitfield,
    LdrLiteral,
    LdrStrUnscaled,
    LdrStrScaled,
    LdrStrRegOffset,
    Unimplemented,
}

struct InstrEncoding {
    class: InstrClass,
    mask: u32,
    value: u32,
    reg_operands: Option<&'static [(u32, u32)]>,
}

// Copy the INSTR_TABLE from decoder.rs
static INSTR_TABLE: &[InstrEncoding] = &[
    // EXTR
    InstrEncoding {
        class: InstrClass::Extr,
        mask: 0xFC000000,
        value: 0x4C000000,
        reg_operands: Some(&[(0, 5), (5, 5), (16, 5)]),
    },
    // Data Processing 1 source
    InstrEncoding {
        class: InstrClass::DataProc1Src,
        mask: 0x7FFF0000,
        value: 0x5AC00000,
        reg_operands: Some(&[(0, 5), (5, 5)]),
    },
    // ADD/SUB shifted register
    InstrEncoding {
        class: InstrClass::AddSubShiftedReg,
        mask: 0x1F200000,
        value: 0x0B000000,
        reg_operands: Some(&[(0, 5), (5, 5), (16, 5)]),
    },
    // ADD/SUB immediate
    InstrEncoding {
        class: InstrClass::AddSubImmediate,
        mask: 0x1F000000,
        value: 0x11000000,
        reg_operands: Some(&[(0, 5), (5, 5)]),
    },
    // Move wide
    InstrEncoding {
        class: InstrClass::MoveWide,
        mask: 0x1F800000,
        value: 0x12800000,
        reg_operands: Some(&[(0, 5)]),
    },
    // Logical shifted register
    InstrEncoding {
        class: InstrClass::LogicalShiftedReg,
        mask: 0x1F200000,
        value: 0x0A000000,
        reg_operands: Some(&[(0, 5), (5, 5), (16, 5)]),
    },
    // Add/Subtract extended register
    InstrEncoding {
        class: InstrClass::AddSubExtReg,
        mask: 0x1F200C00,
        value: 0x0B200400,
        reg_operands: Some(&[(0, 5), (5, 5), (16, 5)]),
    },
    // Data Processing 2 source
    InstrEncoding {
        class: InstrClass::DataProc2Src,
        mask: 0x3FE00000,
        value: 0x1AC00000,
        reg_operands: Some(&[(0, 5), (5, 5), (16, 5)]),
    },
    // Bitfield instructions
    InstrEncoding {
        class: InstrClass::Bitfield,
        mask: 0xFC000000,
        value: 0xD0000000,
        reg_operands: Some(&[(0, 5), (5, 5)]),
    },
    // LDR literal
    InstrEncoding {
        class: InstrClass::LdrLiteral,
        mask: 0xF8000000,
        value: 0x08000000,
        reg_operands: Some(&[(0, 5)]),
    },
    // ADR
    InstrEncoding {
        class: InstrClass::Unimplemented,
        mask: 0xF8000000,
        value: 0x10000000,
        reg_operands: Some(&[(0, 5)]),
    },
    // ADD/ADDP with extended register (0x18-0x1F)
    InstrEncoding {
        class: InstrClass::Unimplemented,
        mask: 0xF8000000,
        value: 0x18000000,
        reg_operands: Some(&[(0, 5), (5, 5), (16, 5)]),
    },
    // LDR/STR with unscaled immediate offset
    InstrEncoding {
        class: InstrClass::LdrStrUnscaled,
        mask: 0xFC000000,
        value: 0xF8000000,
        reg_operands: Some(&[(0, 5), (5, 5), (16, 5)]),
    },
    // LDP/STP
    InstrEncoding {
        class: InstrClass::LdrStrRegOffset,
        mask: 0xFC000000,
        value: 0xA8000000,
        reg_operands: Some(&[(0, 5), (5, 5), (10, 6)]),
    },
    // CBZ/CBNZ
    InstrEncoding {
        class: InstrClass::Unimplemented,
        mask: 0xFE000000,
        value: 0xB4000000,
        reg_operands: Some(&[(0, 5)]),
    },
    // LDM/STM
    InstrEncoding {
        class: InstrClass::Unimplemented,
        mask: 0xFE000000,
        value: 0x48000000,
        reg_operands: Some(&[(0, 5), (5, 5)]),
    },
    // FMOV (floating-point to GPR)
    InstrEncoding {
        class: InstrClass::Unimplemented,
        mask: 0xF8000000,
        value: 0xF0000000,
        reg_operands: Some(&[(0, 5), (5, 5)]),
    },
    // FMOV (GPR to floating-point)
    InstrEncoding {
        class: InstrClass::Unimplemented,
        mask: 0xFF000000,
        value: 0xFA000000,
        reg_operands: Some(&[(0, 5), (5, 5), (16, 5)]),
    },
    // Data processing 1 source with extended immediate (0x92)
    InstrEncoding {
        class: InstrClass::DataProc1Src,
        mask: 0xF8000000,
        value: 0x90000000,
        reg_operands: Some(&[(0, 5), (5, 5)]),
    },
    // ADD/ADDP with extended register (0x78-0x7F)
    InstrEncoding {
        class: InstrClass::Unimplemented,
        mask: 0xF8000000,
        value: 0x78000000,
        reg_operands: Some(&[(0, 5), (5, 5), (16, 5)]),
    },
    // Data processing with Rm operand (0x98-0x9F)
    InstrEncoding {
        class: InstrClass::Unimplemented,
        mask: 0xF8000000,
        value: 0x98000000,
        reg_operands: Some(&[(0, 5), (5, 5), (16, 5)]),
    },
    // LDR literal (0x58 variant)
    InstrEncoding {
        class: InstrClass::LdrLiteral,
        mask: 0xFC000000,
        value: 0x58000000,
        reg_operands: Some(&[(0, 5)]),
    },
    // B.cond
    InstrEncoding {
        class: InstrClass::Unimplemented,
        mask: 0xFC000000,
        value: 0x54000000,
        reg_operands: None,
    },
    // Data processing 1 source (0x53)
    InstrEncoding {
        class: InstrClass::DataProc1Src,
        mask: 0xF8000000,
        value: 0x50000000,
        reg_operands: Some(&[(0, 5), (5, 5)]),
    },
    // LDP/STP with literal offset
    InstrEncoding {
        class: InstrClass::LdrStrRegOffset,
        mask: 0xFC000000,
        value: 0x34000000,
        reg_operands: Some(&[(0, 5), (5, 5), (16, 5)]),
    },
];

fn references_x18(instr: u32) -> bool {
    // First check our table-driven decoder
    for encoding in INSTR_TABLE {
        if (instr & encoding.mask) == encoding.value {
            // Found a match - check if any register operand is x18
            if let Some(operands) = encoding.reg_operands {
                for &(lsb, width) in operands {
                    let reg_no = ((instr >> lsb) & ((1u32 << width) - 1)) as usize;
                    if reg_no == 18 {
                        return true;
                    }
                }
            }
            // If we matched but have no reg_operands info, fall through to fallback
            return false;
        }
    }
    
    // Fallback: check for SIMD load/store instructions with GPR base/index/dest register x18
    let top_byte = (instr >> 24) & 0xFF;
    let is_simd_ldst = matches!(top_byte,
        0x0C | 0x0D | 0x0E | 0x0F |
        0x1C | 0x1D | 0x1E | 0x1F |
        0x2C | 0x2D | 0x2E | 0x2F |
        0x38 | 0x39 | 0x3A | 0x3B |
        0x4C | 0x4D | 0x4E | 0x4F |
        0x5C | 0x5D |
        0x6C | 0x6D | 0x6E | 0x6F |
        0x7C | 0x7D | 0x7E | 0x7F |
        0x8C | 0x8D | 0x8E | 0x8F |
        0x9C | 0x9D | 0x9E | 0x9F |
        0xAC | 0xAD | 0xAE | 0xAF |
        0xBC | 0xBD | 0xBE | 0xBF |
        0xCC | 0xCD | 0xCE | 0xCF |
        0xDC | 0xDD | 0xDE | 0xDF |
        0xEC | 0xED | 0xEE | 0xEF |
        0xFC | 0xFD | 0xFE | 0xFF
    );
    if is_simd_ldst {
        let rn = (instr >> 5) & 0x1F;
        let rd = instr & 0x1F;
        let rm = (instr >> 16) & 0x1F;
        if rn == 18 || rd == 18 || rm == 18 { return true; }
        return false;
    }
    
    // Fallback: check for LDR/STR with scaled offset
    let is_ldst_scaled = matches!(top_byte, 0x90 | 0xb0 | 0xb8 | 0xb9 | 0xf0 | 0xf8 | 0xf9);
    if is_ldst_scaled {
        let rn = (instr >> 5) & 0x1F;
        let rd = instr & 0x1F;
        let rm = (instr >> 16) & 0x1F;
        if rn == 18 || rd == 18 || rm == 18 { return true; }
        return false;
    }
    
    // Fallback: check for ADR/ADRP
    let is_adr = matches!(top_byte, 0x10 | 0x18 | 0x90 | 0x98);
    if is_adr {
        let rd = instr & 0x1F;
        return rd == 18;
    }
    
    // Fallback: check for regular load/store with GPR base register x18
    let bits28_27 = (instr >> 27) & 3;
    let bit25 = (instr >> 25) & 1;
    let is_ldst_single = bits28_27 == 3 && bit25 == 1;
    let is_ldst_pair = bits28_27 == 1 && bit25 == 0;
    if is_ldst_single || is_ldst_pair {
        let rn = (instr >> 5) & 0x1F;
        if rn == 18 { return true; }
        if is_ldst_single && (instr >> 24) & 1 == 0 && (instr >> 21) & 1 == 1 {
            let rm = (instr >> 16) & 0x1F;
            if rm == 18 { return true; }
        }
    }
    
    false
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <instruction_hex> [more_instructions...]", args[0]);
        eprintln!("Example: {} 0x5e136250 0x1a9203f1", args[0]);
        std::process::exit(1);
    }

    for arg in &args[1..] {
        let instr = u32::from_str_radix(arg.trim_start_matches("0x").trim_start_matches("0X"), 16)
            .unwrap_or_else(|e| {
                eprintln!("Invalid hex: {} - {}", arg, e);
                std::process::exit(1);
            });
        
        println!("\n{:08x}: {:032b}", instr, instr);
        
        // Check each table entry
        for (i, encoding) in INSTR_TABLE.iter().enumerate() {
            if (instr & encoding.mask) == encoding.value {
                println!("  MATCH entry {}: {:?}", i, encoding.class);
                println!("    mask={:08x}, value={:08x}", encoding.mask, encoding.value);
                
                if let Some(operands) = encoding.reg_operands {
                    println!("    reg_operands:");
                    for &(lsb, width) in operands {
                        let reg_no = ((instr >> lsb) & ((1u32 << width) - 1)) as usize;
                        let is_x18 = reg_no == 18;
                        println!("      bits[{}:{}] = {} (x18={})", lsb, lsb+width-1, reg_no, is_x18);
                    }
                } else {
                    println!("    reg_operands: None");
                }
                break;
            }
        }
        
        let result = references_x18(instr);
        println!("  references_x18() = {}", result);
    }
}