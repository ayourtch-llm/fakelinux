//! Debug tool for ARM A64 decoder x18 detection
//! Uses the library decoder module directly

use std::env;

// Use the decoder module from the library
use fakelinux::decoder;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <instruction>", args[0]);
        eprintln!("Example: {} 0x910003FF", args[0]);
        std::process::exit(1);
    }

    let instr_str = &args[1];
    let instr = u32::from_str_radix(instr_str.trim_start_matches("0x"), 16)
        .unwrap_or_else(|_| {
            eprintln!("Invalid hex instruction: {}", instr_str);
            std::process::exit(1);
        });

    println!("\n{:08x}: {:032b}", instr, instr);
    
    // Use the library's references_x18 function
    let result = decoder::references_x18(instr);
    println!("  references_x18() = {}", result);
}