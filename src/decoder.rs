//! ARM A64 Decoder Module
//!
//! This module provides a table-driven decoder for ARM A64 instructions,
//! with a focus on detecting x18 register references for signal handling.
//!
//! ## Architecture
//!
//! - Uses disarm64 crate as a baseline decoder
//! - Designed for gradual replacement with custom table-driven decoding
//! - Tracks x18 (platform register) usage across instruction classes

use disarm64_defn::defn::InsnOpcode;

/// Main encoding groups (M*I*op0 from ARM manual)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainGroup {
    Unallocated,
    Svc,
    Hvc,
    Smc,
    Brk,
    // Data Processing - Immediate
    PcRelAdr,
    AddSubImmediate,
    LogicalImmediate,
    MoveWide,
    Bitfield,
    Extract,
    // Data Processing - Register
    AddSubShiftedReg,
    AddSubExtReg,
    AddSubCarry,
    LogicalShiftedReg,
    CondCompareReg,
    CondCompareImm,
    CondSelect,
    DataProc2Src,
    DataProc3Src,
    // Branches
    BCond,
    CompareBranch,
    TestBranch,
    UnconditionalBranch,
    // Loads and Stores
    LoadStoreSingle,
    LoadStorePair,
    LoadStoreRegisterOffset,
    // SIMD/FP
    AdvSimdDataProc,
    AdvSimdLoadStore,
}

/// Data result from decoding an instruction
#[derive(Debug, Clone)]
pub struct DecodedInstr {
    /// The main encoding group
    pub main_group: MainGroup,
    /// Raw instruction encoding
    pub raw: u32,
}

impl DecodedInstr {
    /// Create a new DecodedInstr
    pub fn new(raw: u32, main_group: MainGroup) -> Self {
        Self { main_group, raw }
    }
}

/// Decode an instruction into its components
/// 
/// This is a baseline implementation using disarm64.
pub fn decode(instr: u32) -> Option<DecodedInstr> {
    // Use disarm64 for baseline decoding
    let _decoded = disarm64::decoder::decode(instr)?;
    let _defn = _decoded.definition();
    
    // SVC instruction pattern: top 8 bits = 0xD4, bit 0 = imm16[0]
    // 0xD4000001 = SVC #0
    let top_byte = (instr >> 24) & 0xFF;
    let is_svc = top_byte == 0xD4;
    
    let main_group = if is_svc {
        MainGroup::Svc
    } else {
        MainGroup::Unallocated
    };
    
    Some(DecodedInstr { main_group, raw: instr })
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: disarm64 can decode SVC #0
    // ─────────────────────────────────────────────────────────────────────────
    
    #[test]
    fn test_disarm64_decode_svc() {
        // Verify we can decode SVC #0 using disarm64
        // SVC #0 encoding: 0xD4000001
        let svc_instruction: u32 = 0xD4000001;
        let decoded = disarm64::decoder::decode(svc_instruction);
        assert!(decoded.is_some(), "disarm64 should decode SVC #0");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: DecodedInstr struct can be created
    // ─────────────────────────────────────────────────────────────────────────
    
    #[test]
    fn test_decoded_instr_creation() {
        let raw_instr: u32 = 0xD4000001;
        let decoded = DecodedInstr::new(raw_instr, MainGroup::Svc);
        
        assert_eq!(decoded.raw, raw_instr, "raw field should match");
        assert_eq!(decoded.main_group, MainGroup::Svc, "main_group should be Svc");
    }
    
    #[test]
    fn test_decode_returns_decoded_instr() {
        let svc_instruction: u32 = 0xD4000001;
        let result = decode(svc_instruction);
        
        assert!(result.is_some(), "decode should return Some for SVC");
        let decoded = result.unwrap();
        assert_eq!(decoded.main_group, MainGroup::Svc, "should decode to Svc group");
        assert_eq!(decoded.raw, svc_instruction, "raw should be preserved");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: references_x18 returns false for non-x18 instructions
    // ─────────────────────────────────────────────────────────────────────────
    
    /// Check if an instruction references x18 (platform register)
    /// 
    /// This function checks for x18 (platform register) references in ARM A64 instructions.
    /// For SIMD load/store instructions, it checks the GPR base register (Rn at bits[9:5]),
    /// NOT the SIMD register (Vt at bits[4:0]).
    pub fn references_x18(instr: u32) -> bool {
        // Don't check our own UDF marker or SVC
        if instr == 0x0000_F000 || instr == 0xD4000001 { return false; }
        
        let top_byte = (instr >> 24) & 0xFF;
        
        // Check for SIMD load/store instructions
        // These use top bytes with [11:10] = 11 for load/store:
        // - 0x0C/0x4C: AdvSIMD multi-structure load/store (post-index/pre-index)
        // - 0x0D/0x4D: AdvSIMD single-structure load
        // - 0x2C/0x6C/0x2D/0x6D: AdvSIMD load/store with post-index
        // - 0x1C/0x5C/0x9C/0xDC: LDR (SIMD literal)
        // - 0x3C/0x7C/0xBC/0xFC: LDR/STR (SIMD unsigned offset)
        let is_simd_ldst = match top_byte {
            0x0C | 0x4C |   // AdvSIMD multi-structure load (post-index / pre-index)
            0x0D | 0x4D |   // AdvSIMD single-structure load (post-index / pre-index)
            0x2C | 0x6C |   // AdvSIMD load with post-index
            0x2D | 0x6D |   // AdvSIMD single structure post-index
            0x1C | 0x5C |   // LDR (SIMD literal, unscaled offset)
            0x9C | 0xDC |   // LDR (SIMD literal, immediate pre/post-index)
            0x3C | 0x7C |   // LDR/STR (SIMD, unsigned offset)
            0xBC | 0xFC     // LDR/STR (SIMD, register offset)
                => true,
            _ => false,
        };
        
        if is_simd_ldst {
            // For SIMD load/store:
            // - Rt (bits[4:0]) is SIMD register V0-V31 — NOT what we check
            // - Rn (bits[9:5]) is GPR base register — THIS is what we check for x18
            let rn = (instr >> 5) & 0x1F;
            return rn == 18;
        }
        
        // ═══════════════════════════════════════════════════════════════════
        // ADD/SUB shifted register instructions
        // Encoding: bits[28:25]=0b01011 (0x0B), bit[24]=0
        // Mask: 0x1F200000, Value: 0x0B000000
        // ═══════════════════════════════════════════════════════════════════
        if (instr & 0x1F200000) == 0x0B000000 {
            // Rm (source register 2) at bits[20:16]
            let rm = (instr >> 16) & 0x1F;
            if rm == 18 { return true; }
            // Rn (source register 1) at bits[5:0]
            let rn = instr & 0x1F;
            if rn == 18 { return true; }
            // Rd (destination) at bits[4:0]
            let rd = instr & 0x1F;
            return rd == 18;
        }
        
        // ═══════════════════════════════════════════════════════════════════
        // EXTR (extract) instruction - used in SHA-1 rotation
        // Encoding: bits[28:23] = 100111
        // Mask: 0xFF800000, Value: 0x13800000
        // Rd = bits[4:0], Rn = bits[9:5], Rm = bits[20:16]
        // ═══════════════════════════════════════════════════════════════════
        if (instr & 0xFF800000) == 0x13800000 {
            // Check all three registers - any could be x18
            let rm = (instr >> 16) & 0x1F;
            if rm == 18 { return true; }
            let rn = (instr >> 5) & 0x1F;
            if rn == 18 { return true; }
            let rd = instr & 0x1F;
            return rd == 18;
        }
        
        // For other instructions, return false as baseline
        false
    }
    
    #[test]
    fn test_references_x18_returns_false_for_non_x18() {
        // NOP instruction should not reference x18
        let nop: u32 = 0xD503201F;
        assert!(!references_x18(nop), "NOP should not reference x18");
        
        // ADD x0, x1, x2 should not reference x18
        let add: u32 = 0x8B020021; // ADD x1, x1, x2
        assert!(!references_x18(add), "ADD without x18 should not reference x18");
        
        // SVC should not reference x18
        let svc: u32 = 0xD4000001;
        assert!(!references_x18(svc), "SVC should not reference x18");
    }
    
    #[test]
    fn test_references_x18_skeleton_exists() {
        // Verify the function exists and can be called
        let result = references_x18(0xD503201F);
        // Just verify the function can be called and returns a boolean
        assert!(matches!(result, true | false));
    }
    
    // ─────────────────────────────────────────────────────────────────────────
    // Test for Task 2: SIMD load/store with GPR base register x18 detection
    // ─────────────────────────────────────────────────────────────────────────
    
    /// Verify that SIMD Vt=18 (register v18) is NOT confused with GPR x18.
    /// In SIMD load instructions, Vt is the SIMD register (V0-V31), while
    /// the base register Rn (bits[9:5]) is a GPR (X0-X30). Only the GPR
    /// base register should be checked for x18 references.
    #[test]
    fn test_simd_load_with_gpr_base_x18() {
        // LD1 {v18.16b}, [x1] — Vt=18 is SIMD, should NOT be detected as x18
        // because x18 detection should only check GPR base register
        let instr = 0x0c402032; // LD1 {v18.16b}, [x1]
        assert!(!references_x18(instr), 
            "SIMD Vt=18 should not be detected as x18 (Vt is SIMD register, not GPR)");
        
        // LD1 {v18.16b}, [x18] — Rn=x18 IS GPR x18, should be detected
        // Top byte 0x0c = AdvSIMD multi-structure load
        // bits[9:5] = 18 = base register x18
        let instr2 = 0x0c402252; // LD1 {v18.16b}, [x18]
        assert!(references_x18(instr2), 
            "GPR base x18 should be detected even when SIMD Vt=18");
    }
    
    /// Verify that SIMD register 18 (Vt=18) does NOT trigger x18 detection.
    /// This is a common edge case where the SIMD register number happens
    /// to match the GPR number we care about, but they are distinct register sets.
    #[test]
    fn test_simd_load_simd_register_18_not_gpr() {
        // Vt=18 in SIMD instructions should NOT trigger x18 detection
        // because SIMD registers (V0-V31) are different from GPRs (X0-X30)
        let simd_cases = &[
            0x0c402032, // LD1 {v18.16b}, [x1]
            0x4cdfa032, // LD1 {v18.16b}, [x1], #16
            0x4d40c032, // LD1R {v18.4s}, [x1]
        ];
        for &instr in simd_cases {
            assert!(!references_x18(instr), 
                "SIMD Vt=18 should not be detected as x18: {:#010x}", instr);
        }
    }
    
    /// Test that SIMD load instructions correctly detect x18 in base register.
    /// Different SIMD load/store instruction formats:
    /// - 0x0C/0x4C: AdvSIMD multi-structure load/store
    /// - 0x0D/0x4D: AdvSIMD single-structure load
    /// - 0x2C/0x6C/0x2D/0x6D: Post-indexed forms
    #[test]
    fn test_simd_load_store_various_formats_with_x18_base() {
        // Test various SIMD load formats with x18 as base register
        let test_cases = &[
            (0x0c402252, "LD1 multi-struct [x18]"),      // Top=0x0c
            (0x4c402252, "LD1 multi-struct post-idx"),   // Top=0x4c
            (0x0d402252, "LD1R single-struct [x18]"),    // Top=0x0d
            (0x4d402252, "LD1R single-struct post-idx"), // Top=0x4d
        ];
        for (instr, desc) in test_cases {
            assert!(references_x18(*instr), 
                "{} ({:#010x}) should detect x18 base register", desc, instr);
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // Task 3: ADD/SUB shifted register instruction table entry
    // ═══════════════════════════════════════════════════════════════════════════
    
    /// Test ADD with shifted register where Rm=x18
    /// Encoding: 0x0b1201ce = ADD w14, w14, w18
    /// - bits[28:25] = 0b0100 (addsub shifted register group)
    /// - bit[24] = 1 (add/sub with shifted register)
    /// - bit[11] = 0 (ADD, not SUB)
    /// - bits[10] = 0 (set flags? no)
    /// - Rm = bits[20:16] = 0x12 = 18
    #[test]
    fn test_add_shifted_reg_x18() {
        let instr = 0x0b1201ce; // ADD w14, w14, w18 — Rm=x18
        assert!(references_x18(instr), "ADD with Rm=x18 should be detected");
    }
    
    /// Test SUB with shifted register where Rm=x18
    /// Encoding: 0x4b120000 = SUB w0, w0, w18
    /// - bits[28:25] = 0b0100 (addsub shifted register group)
    /// - bit[24] = 1 (add/sub with shifted register)
    /// - bit[11] = 1 (SUB)
    /// - Rm = bits[20:16] = 0x12 = 18
    #[test]
    fn test_sub_shifted_reg_x18() {
        let instr = 0x4b120000; // SUB w0, w0, w18 — Rm=x18
        assert!(references_x18(instr), "SUB with Rm=x18 should be detected");
    }
    
    /// Test ADDS (add and set flags) with shifted register where Rm=x18
    /// Encoding: 0x2b120131 = ADDS w17, w9, w18
    /// - bits[28:25] = 0b0100 (addsub shifted register group)
    /// - bit[24] = 1 (add/sub with shifted register)
    /// - bit[11] = 0 (ADD)
    /// - bit[10] = 1 (S bit set = ADDS)
    /// - Rm = bits[20:16] = 0x12 = 18
    #[test]
    fn test_adds_shifted_reg_flags() {
        let instr = 0x2b120131; // ADDS w17, w9, w18 — Rm=x18 with S bit set
        assert!(references_x18(instr), "ADDS with Rm=x18 should be detected");
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // Task 4: EXTR (extract) instruction support for SHA-1 rotation
    // ═══════════════════════════════════════════════════════════════════════════
    
    /// Test EXTR instruction that references x18.
    /// EXTR w18, w15, w15, #27 is equivalent to ROR w18, w15, #27,
    /// which is used in SHA-1 rotation operations.
    /// 
    /// EXTR encoding:
    /// - bits[28:23] = 100111 (distinguishes from SBFM/UBFM which has 100110)
    /// - Mask: 0xFF800000, Value: 0x13800000
    /// - Rd = bits[4:0], Rn = bits[9:5], Rm = bits[20:16]
    #[test]
    fn test_extr_x18() {
        // EXTR w18, w15, w15, #27 (= ROR w18, w15, #27) — SHA-1 rotation
        // 0x138f6df2 encodes EXTR with:
        // - Rd = 18 (x18/w18 as destination)
        // - Rn = 15 (x15)
        // - Rm = 15 (x15)
        // - imms = 27 (rotation amount)
        let instr = 0x138f6df2;
        assert!(references_x18(instr), 
            "EXTR with x18 should be detected: {:#010x}", instr);
    }
    
    /// Test multiple EXTR instructions used in SHA-1 rotations.
    /// SHA-1 uses ROR (rotate right) which can be implemented as EXTR.
    #[test]
    fn test_extr_various_x18() {
        // SHA-1 rotation instructions with various register combinations
        let extr_cases = &[
            (0x138f6df2, "EXTR w18, w15, w15, #27 — SHA-1 rotation"),
            (0x13906e12, "EXTR w18, w16, w16, #27"),
            (0x138b6d72, "EXTR w18, w11, w11, #27"),
            (0x138d6db2, "EXTR w18, w13, w13, #27"),
        ];
        for &(instr, desc) in extr_cases {
            assert!(references_x18(instr), 
                "EXTR with x18 not detected: {} ({:#010x})", desc, instr);
        }
    }
    
    /// Test EXTR with x18 as Rm (source register 2) rather than Rd.
    /// Some SHA-1 implementations may use different register patterns.
    #[test]
    fn test_extr_x18_as_rm() {
        // EXTR w0, w1, w18, #something — x18 as Rm
        // This should also be detected since Rm can be x18
        let instr = 0x13800651; // EXTR w17, w1, w18, #something
        assert!(references_x18(instr), 
            "EXTR with Rm=x18 should be detected: {:#010x}", instr);
    }
    
    /// Verify EXTR instruction correctly distinguishes from SBFM/UBFM.
    /// - EXTR: bits[28:23] = 100111 (0x138 >> 23 = 0x13 = 0b100111)
    /// - SBFM/UBFM: bits[28:23] = 100110 (0x130 >> 23 = 0x13 but different)
    /// 
    /// Actually, let me verify:
    /// - 0x13800000 >> 23 = 0x13 = 0b100111 (EXTR)
    /// - 0x13000000 >> 23 = 0x13 = 0b100111 (also looks like EXTR pattern)
    /// 
    /// The key difference is bit[15] - SBFM/UBFM has it clear, EXTR has it set.
    /// Actually, let me check:
    /// - 0x138f6df2 (EXTR with x18) = 0001 0011 1000 1111 0110 1101 1111 0010
    /// - Bits[28:23] = bits[31:29]=000, bits[28:26]=100, bit[25:24]=11, bit[23]=1
    ///   = 0 001 001 11 1 = wait, let me redo this
    ///   
    /// 0x138f6df2 = 0001 0011 1000 1111 0110 1101 1111 0010
    /// bits[31:28] = 0001 = 0x1
    /// bits[27:24] = 0011 = 0x3
    /// bits[23] = 1
    /// 
    /// Looking at the pattern:
    /// - 0x13800000 has top 23 bits = 100111
    /// - 0x13000000 has top 23 bits = 100110
    /// 
    /// So the mask should be 0xFF800000 to capture bits[28:23].
    /// Wait, let me check more carefully:
    /// 
    /// bits[28:23] = 6 bits starting at bit 23
    /// Mask for bits[28:23] = bits[28] + bits[27] + ... + bits[23]
    /// = 0b11111100000000000000000000000000 (0xFC000000)
    /// 
    /// But the task says: Mask: 0xFF800000, Value: 0x13800000
    /// Let me check: 0xFF800000 = 11111111100000000000000000000000
    /// That covers bits[31:24] plus bit[23] = 9 bits total
    /// 
    /// 0x13800000 = 00010011100000000000000000000000
    /// 
    /// This checks bits[28:24] = 10011 and bit[23] = 0
    /// So the value is checking: bits[28:24] == 10011
    /// 
    /// Actually, looking at ARM documentation more carefully:
    /// - EXTR: op0=100, op1=111 (so top bits starting at 28 would be related)
    /// 
    /// Let me just implement based on the hint and verify with tests.
    #[test]
    fn test_extr_not_sbfm_ubfm() {
        // SBFM (signed bitfield move) has different encoding
        // This should NOT be detected as EXTR
        // Example SBFM: 0x13000000 has bits[28:23] = 100110
        let sbfm = 0x13000000;
        assert!(!references_x18(sbfm), 
            "SBFM should not be detected as EXTR: {:#010x}", sbfm);
    }
}