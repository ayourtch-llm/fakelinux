// Auto-generated spot-check tests from the ARM A64 ISA XML spec.
// DO NOT EDIT.

#[test]
fn test_gen_iclass_system_rd_0_x18() {
    // iclass_system: Rd@0 = x18
    assert!(super::references_x18(0xd5031032), "expected x18 detection for iclass_system");
}

#[test]
fn test_gen_iclass_system_no_x18_0_neg() {
    // iclass_system: all GPR fields = 0
    assert!(!super::references_x18(0xd5031020), "false positive for iclass_system");
}

#[test]
fn test_gen_iclass_system_rd_1_x18() {
    // iclass_system: Rd@0 = x18
    assert!(super::references_x18(0xd5031012), "expected x18 detection for iclass_system");
}

#[test]
fn test_gen_iclass_system_no_x18_1_neg() {
    // iclass_system: all GPR fields = 0
    assert!(!super::references_x18(0xd5031000), "false positive for iclass_system");
}

#[test]
fn test_gen_iclass_integer_rn_2_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xdac1965e), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_2_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xdac1941e), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_3_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xdac1925e), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_3_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xdac1901e), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_4_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xd65f0240), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_4_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xd65f0000), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_5_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xd63f0240), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_5_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xd63f0000), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_6_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xd61f0240), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_6_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xd61f0000), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_7_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0x3a000a4d), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_7_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0x3a00080d), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_64_bit_rn_8_x18() {
    // iclass_64_bit: Rn@5 = x18
    assert!(super::references_x18(0xdac00a40), "expected x18 detection for iclass_64_bit");
}

#[test]
fn test_gen_iclass_64_bit_no_x18_8_neg() {
    // iclass_64_bit: all GPR fields = 0
    assert!(!super::references_x18(0xdac00800), "false positive for iclass_64_bit");
}

#[test]
fn test_gen_iclass_integer_rn_9_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xd9e00240), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_9_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xd9e00000), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_10_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xd9a00240), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_10_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xd9a00000), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_11_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xd9200240), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_11_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xd9200000), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_12_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xd91f1e40), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_12_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xd91f1c00), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_13_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xd91f0e40), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_13_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xd91f0c00), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_double_precision_to_32_bit_rd_14_x18() {
    // iclass_double_precision_to_32_bit: Rd@0 = x18
    assert!(super::references_x18(0x1e7e0012), "expected x18 detection for iclass_double_precision_to_32_bit");
}

#[test]
fn test_gen_iclass_double_precision_to_32_bit_no_x18_14_neg() {
    // iclass_double_precision_to_32_bit: all GPR fields = 0
    assert!(!super::references_x18(0x1e7e0000), "false positive for iclass_double_precision_to_32_bit");
}

#[test]
fn test_gen_iclass_integer_rn_15_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xdac11e40), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_15_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xdac11c00), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_16_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xdac11a40), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_16_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xdac11800), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_17_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xdac11640), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_17_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xdac11400), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_18_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xdac11240), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_18_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xdac11000), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_19_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xdac10e40), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_19_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xdac10c00), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_20_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xdac10a40), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_20_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xdac10800), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_21_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xdac10640), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_21_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xdac10400), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_22_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xdac10240), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_22_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xdac10000), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_floating_point_rn_23_x18() {
    // iclass_floating_point: Rn@5 = x18
    assert!(super::references_x18(0x3c20f25f), "expected x18 detection for iclass_floating_point");
}

#[test]
fn test_gen_iclass_floating_point_no_x18_23_neg() {
    // iclass_floating_point: all GPR fields = 0
    assert!(!super::references_x18(0x3c20f01f), "false positive for iclass_floating_point");
}

#[test]
fn test_gen_iclass_floating_point_rn_24_x18() {
    // iclass_floating_point: Rn@5 = x18
    assert!(super::references_x18(0x3c20e25f), "expected x18 detection for iclass_floating_point");
}

#[test]
fn test_gen_iclass_floating_point_no_x18_24_neg() {
    // iclass_floating_point: all GPR fields = 0
    assert!(!super::references_x18(0x3c20e01f), "false positive for iclass_floating_point");
}

#[test]
fn test_gen_iclass_floating_point_rn_25_x18() {
    // iclass_floating_point: Rn@5 = x18
    assert!(super::references_x18(0x3c20d25f), "expected x18 detection for iclass_floating_point");
}

#[test]
fn test_gen_iclass_floating_point_no_x18_25_neg() {
    // iclass_floating_point: all GPR fields = 0
    assert!(!super::references_x18(0x3c20d01f), "false positive for iclass_floating_point");
}

#[test]
fn test_gen_iclass_floating_point_rn_26_x18() {
    // iclass_floating_point: Rn@5 = x18
    assert!(super::references_x18(0x3c20c25f), "expected x18 detection for iclass_floating_point");
}

#[test]
fn test_gen_iclass_floating_point_no_x18_26_neg() {
    // iclass_floating_point: all GPR fields = 0
    assert!(!super::references_x18(0x3c20c01f), "false positive for iclass_floating_point");
}

#[test]
fn test_gen_iclass_floating_point_rn_27_x18() {
    // iclass_floating_point: Rn@5 = x18
    assert!(super::references_x18(0x3c20825f), "expected x18 detection for iclass_floating_point");
}

#[test]
fn test_gen_iclass_floating_point_no_x18_27_neg() {
    // iclass_floating_point: all GPR fields = 0
    assert!(!super::references_x18(0x3c20801f), "false positive for iclass_floating_point");
}

#[test]
fn test_gen_iclass_post_index_rn_28_x18() {
    // iclass_post_index: Rn@5 = x18
    assert!(super::references_x18(0x99c00a40), "expected x18 detection for iclass_post_index");
}

#[test]
fn test_gen_iclass_post_index_no_x18_28_neg() {
    // iclass_post_index: all GPR fields = 0
    assert!(!super::references_x18(0x99c00800), "false positive for iclass_post_index");
}

#[test]
fn test_gen_iclass_pre_index_rn_29_x18() {
    // iclass_pre_index: Rn@5 = x18
    assert!(super::references_x18(0x99800a40), "expected x18 detection for iclass_pre_index");
}

#[test]
fn test_gen_iclass_pre_index_no_x18_29_neg() {
    // iclass_pre_index: all GPR fields = 0
    assert!(!super::references_x18(0x99800800), "false positive for iclass_pre_index");
}

#[test]
fn test_gen_iclass_64_bit_rn_30_x18() {
    // iclass_64_bit: Rn@5 = x18
    assert!(super::references_x18(0x0d418640), "expected x18 detection for iclass_64_bit");
}

#[test]
fn test_gen_iclass_64_bit_no_x18_30_neg() {
    // iclass_64_bit: all GPR fields = 0
    assert!(!super::references_x18(0x0d418400), "false positive for iclass_64_bit");
}

#[test]
fn test_gen_iclass_64_bit_rn_31_x18() {
    // iclass_64_bit: Rn@5 = x18
    assert!(super::references_x18(0x0d018640), "expected x18 detection for iclass_64_bit");
}

#[test]
fn test_gen_iclass_64_bit_no_x18_31_neg() {
    // iclass_64_bit: all GPR fields = 0
    assert!(!super::references_x18(0x0d018400), "false positive for iclass_64_bit");
}

#[test]
fn test_gen_iclass_integer_rn_32_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0x5ac02240), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_32_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0x5ac02000), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_33_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0x5ac01e40), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_33_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0x5ac01c00), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_34_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0x5ac01a40), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_34_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0x5ac01800), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_35_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0x5ac01640), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_35_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0x5ac01400), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_36_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0x5ac01240), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_36_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0x5ac01000), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_37_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0x5ac00640), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_37_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0x5ac00400), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_38_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0x5ac00240), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_38_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0x5ac00000), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_39_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xd63f0a40), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_39_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xd63f0800), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_40_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0xd61f0a40), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_40_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0xd61f0800), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_rn_41_x18() {
    // iclass_integer: Rn@5 = x18
    assert!(super::references_x18(0x5ac00a40), "expected x18 detection for iclass_integer");
}

#[test]
fn test_gen_iclass_integer_no_x18_41_neg() {
    // iclass_integer: all GPR fields = 0
    assert!(!super::references_x18(0x5ac00800), "false positive for iclass_integer");
}

#[test]
fn test_gen_iclass_no_offset_rn_42_x18() {
    // iclass_no_offset: Rn@5 = x18
    assert!(super::references_x18(0x0d60e240), "expected x18 detection for iclass_no_offset");
}

#[test]
fn test_gen_iclass_no_offset_no_x18_42_neg() {
    // iclass_no_offset: all GPR fields = 0
    assert!(!super::references_x18(0x0d60e000), "false positive for iclass_no_offset");
}

#[test]
fn test_gen_iclass_no_offset_rn_43_x18() {
    // iclass_no_offset: Rn@5 = x18
    assert!(super::references_x18(0x0d60c240), "expected x18 detection for iclass_no_offset");
}

#[test]
fn test_gen_iclass_no_offset_no_x18_43_neg() {
    // iclass_no_offset: all GPR fields = 0
    assert!(!super::references_x18(0x0d60c000), "false positive for iclass_no_offset");
}

#[test]
fn test_gen_iclass_no_offset_rn_44_x18() {
    // iclass_no_offset: Rn@5 = x18
    assert!(super::references_x18(0x0d40e240), "expected x18 detection for iclass_no_offset");
}

#[test]
fn test_gen_iclass_no_offset_no_x18_44_neg() {
    // iclass_no_offset: all GPR fields = 0
    assert!(!super::references_x18(0x0d40e000), "false positive for iclass_no_offset");
}

#[test]
fn test_gen_iclass_no_offset_rn_45_x18() {
    // iclass_no_offset: Rn@5 = x18
    assert!(super::references_x18(0x0d40c240), "expected x18 detection for iclass_no_offset");
}

#[test]
fn test_gen_iclass_no_offset_no_x18_45_neg() {
    // iclass_no_offset: all GPR fields = 0
    assert!(!super::references_x18(0x0d40c000), "false positive for iclass_no_offset");
}

#[test]
fn test_gen_iclass_no_offset_rn_46_x18() {
    // iclass_no_offset: Rn@5 = x18
    assert!(super::references_x18(0x0c408240), "expected x18 detection for iclass_no_offset");
}

#[test]
fn test_gen_iclass_no_offset_no_x18_46_neg() {
    // iclass_no_offset: all GPR fields = 0
    assert!(!super::references_x18(0x0c408000), "false positive for iclass_no_offset");
}

#[test]
fn test_gen_iclass_no_offset_rn_47_x18() {
    // iclass_no_offset: Rn@5 = x18
    assert!(super::references_x18(0x0c404240), "expected x18 detection for iclass_no_offset");
}

#[test]
fn test_gen_iclass_no_offset_no_x18_47_neg() {
    // iclass_no_offset: all GPR fields = 0
    assert!(!super::references_x18(0x0c404000), "false positive for iclass_no_offset");
}

#[test]
fn test_gen_iclass_no_offset_rn_48_x18() {
    // iclass_no_offset: Rn@5 = x18
    assert!(super::references_x18(0x0c400240), "expected x18 detection for iclass_no_offset");
}

#[test]
fn test_gen_iclass_no_offset_no_x18_48_neg() {
    // iclass_no_offset: all GPR fields = 0
    assert!(!super::references_x18(0x0c400000), "false positive for iclass_no_offset");
}

#[test]
fn test_gen_iclass_no_offset_rn_49_x18() {
    // iclass_no_offset: Rn@5 = x18
    assert!(super::references_x18(0x0c008240), "expected x18 detection for iclass_no_offset");
}

#[test]
fn test_gen_iclass_no_offset_no_x18_49_neg() {
    // iclass_no_offset: all GPR fields = 0
    assert!(!super::references_x18(0x0c008000), "false positive for iclass_no_offset");
}

