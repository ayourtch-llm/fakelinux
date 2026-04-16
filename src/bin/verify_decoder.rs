//! Standalone verification tool for the generated ARM A64 x18 decoder.
//!
//! Usage:
//!   verify_decoder 0x927df252           — check a single instruction
//!   verify_decoder --selftest           — run built-in test suite
//!   verify_decoder --dump               — dump the generated table stats

use std::env;
use fakelinux::decoder;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <instruction_hex> | --selftest | --dump", args[0]);
        eprintln!("Examples:");
        eprintln!("  {} 0x927df252       # AND immediate with x18", args[0]);
        eprintln!("  {} --selftest       # run built-in test suite", args[0]);
        eprintln!("  {} --dump           # show table statistics", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "--selftest" => run_selftest(),
        "--dump" => dump_table_stats(),
        _ => check_instruction(&args[1]),
    }
}

fn check_instruction(hex_str: &str) {
    let hex = hex_str.trim_start_matches("0x").trim_start_matches("0X");
    let instr = u32::from_str_radix(hex, 16).unwrap_or_else(|e| {
        eprintln!("Invalid hex: {} — {}", hex_str, e);
        std::process::exit(1);
    });

    println!("Instruction: {:#010x} ({:032b})", instr, instr);
    println!();

    // Show all 5-bit register fields
    let fields = [
        ("Rd/Rt", 0u32),
        ("Rn", 5),
        ("Ra/Rt2", 10),
        ("Rm/Rs", 16),
    ];
    for (name, lsb) in &fields {
        let val = (instr >> lsb) & 0x1F;
        let marker = if val == 18 { " <-- x18" } else { "" };
        println!("  {}[{}:{}] = {} (x{}){}", name, lsb + 4, lsb, val, val, marker);
    }
    println!();

    // Check with the generated decoder
    let result = decoder::references_x18(instr);
    println!("references_x18() = {}", result);

    // Find the matching table entry
    for entry in decoder::GEN_TABLE {
        if (instr & entry.mask) == entry.value {
            println!("Matched: {} (mask={:#010x}, value={:#010x})", entry.name, entry.mask, entry.value);
            print!("  GPR fields:");
            for &lsb in &entry.gpr_lsbs {
                if lsb == 0xFF { break; }
                let reg = (instr >> lsb) & 0x1F;
                print!(" [{}:{}]=x{}", lsb + 4, lsb, reg);
            }
            println!();
            return;
        }
    }
    println!("No matching table entry found.");
}

fn dump_table_stats() {
    let table = decoder::GEN_TABLE;
    println!("Generated table: {} entries", table.len());

    let mut with_gpr = 0;
    let mut without_gpr = 0;
    let mut max_gpr = 0;

    for entry in table {
        let gpr_count = entry.gpr_lsbs.iter().filter(|&&b| b != 0xFF).count();
        if gpr_count > 0 {
            with_gpr += 1;
        } else {
            without_gpr += 1;
        }
        if gpr_count > max_gpr {
            max_gpr = gpr_count;
        }
    }

    println!("  With GPR fields:    {}", with_gpr);
    println!("  Without GPR fields: {}", without_gpr);
    println!("  Max GPR fields:     {}", max_gpr);

    // Mask specificity distribution
    let mut mask_bits: Vec<u32> = table.iter().map(|e| e.mask.count_ones()).collect();
    mask_bits.sort();
    if let (Some(&min), Some(&max)) = (mask_bits.first(), mask_bits.last()) {
        println!("  Mask bits: min={}, max={}, median={}", min, max, mask_bits[mask_bits.len() / 2]);
    }
}

fn run_selftest() {
    // Real instructions from libpython3.12.so that reference x18
    let x18_instructions: &[u32] = &[
        0x927df252, // AND x18, x18, #0xfffffffc — the previously-failing instruction
        0x927ef652, // AND x18, x18, #... — the other previously-failing instruction
        0x91000252, // ADD x18, x18, #0
        0xf9400252, // LDR x18, [x18]
        0xd2800012, // MOV x18, #0
        0xaa1203e0, // MOV x0, x18
        0xf1000e5f, // CMP x18, #3
        0xb4000012, // CBZ x18, ...
        0x8b120000, // ADD x0, x0, x18
        0xd1000652, // SUB x18, x18, #1
    ];

    let mut passed = 0;
    let mut failed = 0;

    for &instr in x18_instructions {
        if decoder::references_x18(instr) {
            passed += 1;
        } else {
            eprintln!("FAIL: {:#010x} should reference x18 but wasn't detected", instr);
            failed += 1;
        }
    }

    // Instructions that should NOT reference x18
    let non_x18_instructions: &[u32] = &[
        0xd503201f, // NOP
        0x14000001, // B #4
        0xd65f03c0, // RET
        0xa9b27bfd, // STP x29, x30, [sp, #-224]! — bits[20:16]=18 is imm7, NOT Rm
        0x5e136250, // SIMD USHL D16, D18, D19 — SIMD register 18, not GPR x18
    ];

    for &instr in non_x18_instructions {
        if !decoder::references_x18(instr) {
            passed += 1;
        } else {
            eprintln!("FAIL: {:#010x} should NOT reference x18 but was detected", instr);
            failed += 1;
        }
    }

    println!("Self-test: {} passed, {} failed", passed, failed);
    if failed > 0 {
        std::process::exit(1);
    }
}
