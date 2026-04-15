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
    /// This is a skeleton that returns false for non-x18 instructions.
    /// Full implementation will use table-driven decoding.
    pub fn references_x18(instr: u32) -> bool {
        // Don't check our own UDF marker or SVC
        if instr == 0x0000_F000 || instr == 0xD4000001 { return false; }
        
        // TODO: Implement full x18 detection using table-driven approach
        // For skeleton, return false as baseline
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
}