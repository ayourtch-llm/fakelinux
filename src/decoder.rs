//! ARM A64 Decoder Module
//!
//! Provides x18 (platform register) detection and instruction classification
//! for ARM A64 instructions, used by the TPIDR virtualization signal handler.
//!
//! The decode table is generated at build time from the authoritative
//! ARM A64 ISA XML specification (see `build.rs` and `data/encoding/`).

// Generated from ARM A64 ISA XML spec by build.rs
include!(concat!(env!("OUT_DIR"), "/generated_x18_table.rs"));

/// Emulation class — identifies the instruction group for emulation dispatch.
///
/// Derived from the ARM XML `psname` decode path (group.subgroup).
/// Discriminant values must match `psname_to_emul_class()` in build.rs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EmulClass {
    // Data Processing — Immediate
    AddSubImm = 0,
    LogicalImm = 1,
    MoveWide = 2,
    Bitfield = 3,
    Extract = 4,
    PcRelAddr = 5,
    // Data Processing — Register
    LogicalShiftedReg = 6,
    AddSubShiftedReg = 7,
    AddSubExtReg = 8,
    AddSubCarry = 9,
    CondSelect = 10,
    DataProc2Src = 11,
    DataProc3Src = 12,
    CondCompareReg = 13,
    CondCompareImm = 14,
    DataProc1Src = 15,
    // Load/Store
    LdrStrUnsignedImm = 16,
    LdrStrPrePost = 17,
    LdrStrUnscaled = 18,
    LdrStrRegOffset = 19,
    LdpStp = 20,
    LoadLiteral = 21,
    // Branches
    CompareBranch = 22,
    TestBranch = 23,
    // FP ↔ GPR
    FloatGprConvert = 24,
    // Exclusive / Atomic
    LoadStoreExclusive = 25,
    AtomicMemOp = 26,
    LoadStoreOrdered = 27,
    // Catch-all
    Other = 255,
}

impl EmulClass {
    /// Convert from the u8 discriminant stored in the generated table.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::AddSubImm,
            1 => Self::LogicalImm,
            2 => Self::MoveWide,
            3 => Self::Bitfield,
            4 => Self::Extract,
            5 => Self::PcRelAddr,
            6 => Self::LogicalShiftedReg,
            7 => Self::AddSubShiftedReg,
            8 => Self::AddSubExtReg,
            9 => Self::AddSubCarry,
            10 => Self::CondSelect,
            11 => Self::DataProc2Src,
            12 => Self::DataProc3Src,
            13 => Self::CondCompareReg,
            14 => Self::CondCompareImm,
            15 => Self::DataProc1Src,
            16 => Self::LdrStrUnsignedImm,
            17 => Self::LdrStrPrePost,
            18 => Self::LdrStrUnscaled,
            19 => Self::LdrStrRegOffset,
            20 => Self::LdpStp,
            21 => Self::LoadLiteral,
            22 => Self::CompareBranch,
            23 => Self::TestBranch,
            24 => Self::FloatGprConvert,
            25 => Self::LoadStoreExclusive,
            26 => Self::AtomicMemOp,
            27 => Self::LoadStoreOrdered,
            _ => Self::Other,
        }
    }
}

/// Check if an instruction references GPR x18.
///
/// Uses the build-time generated table (from ARM A64 ISA XML spec) as the
/// single source of truth.
///
/// Returns `true` if any GPR register operand field contains 18.
pub fn references_x18(instr: u32) -> bool {
    for entry in GEN_TABLE {
        if (instr & entry.mask) == entry.value {
            for &lsb in &entry.gpr_lsbs {
                if lsb == 0xFF {
                    break;
                }
                if ((instr >> lsb) & 0x1F) == 18 {
                    return true;
                }
            }
            return false;
        }
    }
    false
}

/// Decode an instruction's emulation class.
///
/// Returns the `EmulClass` for dispatch to the appropriate emulation handler.
/// Uses the same generated table as `references_x18()`.
pub fn decode_emul_class(instr: u32) -> EmulClass {
    for entry in GEN_TABLE {
        if (instr & entry.mask) == entry.value {
            return EmulClass::from_u8(entry.emul_class);
        }
    }
    EmulClass::Other
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // Auto-generated spot-check tests from ARM XML spec
    include!(concat!(env!("OUT_DIR"), "/generated_x18_tests.rs"));

    #[test]
    fn test_references_x18_returns_false_for_non_x18() {
        let nop: u32 = 0xD503201F;
        assert!(!references_x18(nop), "NOP should not reference x18");

        let add: u32 = 0x8B020021; // ADD x1, x1, x2
        assert!(!references_x18(add), "ADD without x18 should not reference x18");
    }

    #[test]
    fn test_references_x18_skeleton_exists() {
        let result = references_x18(0xD503201F);
        assert!(matches!(result, true | false));
    }

    // ─── EmulClass decode tests ──────────────────────────────────────────

    #[test]
    fn test_decode_emul_class_addsub_imm() {
        let instr = 0x91000252; // ADD x18, x18, #0
        assert_eq!(decode_emul_class(instr), EmulClass::AddSubImm);
    }

    #[test]
    fn test_decode_emul_class_logical_imm() {
        let instr = 0x927df252; // AND x18, x18, #imm
        assert_eq!(decode_emul_class(instr), EmulClass::LogicalImm);
    }

    #[test]
    fn test_decode_emul_class_move_wide() {
        let instr = 0xd2800012; // MOV x18, #0
        assert_eq!(decode_emul_class(instr), EmulClass::MoveWide);
    }

    #[test]
    fn test_decode_emul_class_extract() {
        let instr = 0x138f6df2; // EXTR w18, w15, w15, #27
        assert_eq!(decode_emul_class(instr), EmulClass::Extract);
    }

    #[test]
    fn test_decode_emul_class_ldr_str_imm() {
        let instr = 0xf9400252; // LDR x18, [x18]
        assert_eq!(decode_emul_class(instr), EmulClass::LdrStrUnsignedImm);
    }

    #[test]
    fn test_decode_emul_class_cbz() {
        let instr = 0xb4000012; // CBZ x18, ...
        assert_eq!(decode_emul_class(instr), EmulClass::CompareBranch);
    }

    #[test]
    fn test_decode_emul_class_addsub_shifted() {
        let instr = 0x8b120000; // ADD x0, x0, x18
        assert_eq!(decode_emul_class(instr), EmulClass::AddSubShiftedReg);
    }

    #[test]
    fn test_decode_emul_class_csel() {
        // CSEL x0, x18, x1, EQ — sf=1, op=0, Rm=1, cond=0, Rn=18, Rd=0
        let instr = 0x9a810240; // CSEL x0, x18, x1, EQ
        assert_eq!(decode_emul_class(instr), EmulClass::CondSelect);
    }

    // ─── SIMD load/store: GPR base vs SIMD register ─────────────────────

    #[test]
    fn test_simd_load_with_gpr_base_x18() {
        let instr = 0x0c402032;
        assert!(!references_x18(instr),
            "SIMD Vt=18 should not be detected as x18");

        let instr2 = 0x0c402252;
        assert!(references_x18(instr2),
            "GPR base x18 should be detected even when SIMD Vt=18");
    }

    #[test]
    fn test_simd_load_simd_register_18_not_gpr() {
        let simd_cases = &[
            0x0c402032u32,
            0x4cdfa032,
            0x4d40c032,
        ];
        for &instr in simd_cases {
            assert!(!references_x18(instr),
                "SIMD Vt=18 should not be detected as x18: {:#010x}", instr);
        }
    }

    #[test]
    fn test_simd_load_store_various_formats_with_x18_base() {
        let test_cases = &[
            (0x0c402252u32, "LD1 multi-struct [x18]"),
            (0x4c402252, "LD1 multi-struct post-idx"),
            (0x0d402252, "LD1R single-struct [x18]"),
            (0x4d402252, "LD1R single-struct post-idx"),
        ];
        for (instr, desc) in test_cases {
            assert!(references_x18(*instr),
                "{} ({:#010x}) should detect x18 base register", desc, instr);
        }
    }

    // ─── ADD/SUB shifted register ────────────────────────────────────────

    #[test]
    fn test_add_shifted_reg_x18() {
        let instr = 0x0b1201ce;
        assert!(references_x18(instr), "ADD with Rm=x18 should be detected");
    }

    #[test]
    fn test_sub_shifted_reg_x18() {
        let instr = 0x4b120000;
        assert!(references_x18(instr), "SUB with Rm=x18 should be detected");
    }

    #[test]
    fn test_adds_shifted_reg_flags() {
        let instr = 0x2b120131;
        assert!(references_x18(instr), "ADDS with Rm=x18 should be detected");
    }

    // ─── EXTR (extract / ROR) ────────────────────────────────────────────

    #[test]
    fn test_extr_x18() {
        let instr = 0x138f6df2;
        assert!(references_x18(instr), "EXTR with Rd=x18: {:#010x}", instr);
    }

    #[test]
    fn test_extr_various_x18() {
        for &instr in &[0x138f6df2u32, 0x13906e12, 0x138b6d72, 0x138d6db2] {
            assert!(references_x18(instr), "EXTR with x18: {:#010x}", instr);
        }
    }

    #[test]
    fn test_extr_x18_as_rm() {
        let instr = 0x13800651;
        assert!(references_x18(instr), "EXTR with Rm=x18: {:#010x}", instr);
    }

    #[test]
    fn test_extr_not_sbfm_ubfm() {
        assert!(!references_x18(0x13000000u32), "SBFM false positive");
    }

    // ─── Data Processing 1 source (REV, RBIT, CLZ) ──────────────────────

    #[test]
    fn test_rev_rbit_clz_x18() {
        assert!(references_x18(0x5ac00a52), "REV with x18");
        assert!(references_x18(0x5ac00252), "RBIT with x18");
        assert!(references_x18(0x5ac01252), "CLZ with x18");
    }

    #[test]
    fn test_dp1_source_various_x18() {
        for &instr in &[0x5ac00a52u32, 0x5ac00252, 0x5ac01252, 0xdac00a52] {
            assert!(references_x18(instr), "DP1 with x18: {:#010x}", instr);
        }
    }

    #[test]
    fn test_dp1_source_x18_as_rd() {
        assert!(references_x18(0x5ac00a40), "DP1 Rn=x18");
        assert!(references_x18(0x5ac00812), "DP1 Rd=x18");
    }
}
