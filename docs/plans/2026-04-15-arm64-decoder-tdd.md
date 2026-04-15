# ARM A64 Decode Pipeline TDD Refactoring Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Refactor the ARM A64 decode/emulation pipeline in fakelinux to be systematic, table-driven, and testable using TDD. The final test is `FAKELINUX_ROOT=./tttt-root ./target/debug/fakelinux --container ./tttt-root/bin/bash -c "apt-get update; apt-get install -y file; file /bin/ls"` completing successfully.

**Architecture:** Replace the two-function design (`references_x18` + `emulate_x18_instruction`) with a unified table-driven decoder. Use ARM's official encoding hierarchy (M+I+op0→group→instruction). Each encoding entry specifies: which registers it reads/writes, how to emulate it, and whether x18 is involved.

**Tech Stack:** 
- Rust (existing)
- Remove `disarm64` crate dependency
- New `decoder.rs` module with instruction tables and emulation
- Comprehensive test suite using `cargo test`

---

## Phase 1: Infrastructure Setup

### Task 1: Create decoder.rs with skeleton and disarm64 baseline

**Files:**
- Create: `src/decoder.rs` (new module)
- Modify: `src/lib.rs` (add `mod decoder;`)
- Modify: `src/trap.rs` (temporarily use `decoder.rs` for x18 detection, then remove)

**Step 1: Write failing test**

```rust
// src/decoder_tests.rs (or in decoder.rs with #[cfg(test)])
#[test]
fn test_disarm64_decode_svc() {
    // Verify we can decode SVC #0
    let decoded = disarm64::decoder::decode(0xD4000001);
    assert!(decoded.is_some());
}
```

**Step 2: Run test to verify it passes (baseline)**

Run: `cargo test test_disarm64_decode_svc`

**Step 3: Create skeleton decoder module**

```rust
// src/decoder.rs
use disarm64_defn::defn::InsnOpcode;

/// Main encoding groups (M*I*op0 from ARM manual)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainGroup {
    Unallocated,
    Svc,
    Hvc,
    Smc,
    Brk,
    // ... expand as needed
}

/// Data result from decoding an instruction
#[derive(Debug, Clone)]
pub struct DecodedInstr {
    pub main_group: MainGroup,
    pub raw: u32,
}

pub fn decode(instr: u32) -> Option<DecodedInstr> {
    // Use disarm64 for now, structure for table-driven replacement later
    Some(DecodedInstr { main_group: MainGroup::Svc, raw: instr })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_svc() {
        let d = decode(0xD4000001).unwrap();
        assert_eq!(d.main_group, MainGroup::Svc);
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test decoder`

---

### Task 2: Add test for SIMD load with GPR base (x18 detection)

**Files:**
- Modify: `src/decoder.rs` (add SIMD load/store handling)

**Step 1: Write failing test**

```rust
#[test]
fn test_simd_load_with_gpr_base_x18() {
    // LD1 {v18.16b}, [x1] — Vt=18 is SIMD, should NOT be detected as x18
    // BUT if GPR base is x18, SHOULD be detected
    let instr = 0x0c402032; // LD1 {v18.16b}, [x1]
    assert!(!decoder::references_x18(instr), "SIMD Vt=18 should not be x18");
    
    let instr2 = 0x0c402252; // LD1 {v18.16b}, [x18] — Rn=x18 IS x18
    assert!(decoder::references_x18(instr2), "GPR base x18 should be detected");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_simd_load_with_gpr_base_x18`
Expected: FAIL - current code may not handle this correctly

**Step 3: Implement SIMD load/store x18 detection**

Add instruction class for SIMD load/store that checks GPR base register:

```rust
pub fn references_x18(instr: u32) -> bool {
    // SIMD load/store: top byte 0x0C/0x4C for multi-struct
    // Rn (bits[9:5]) is GPR base, Rt (bits[4:0]) is SIMD register
    let top_byte = (instr >> 24) & 0xFF;
    let is_simd_ldst = matches!(top_byte, 
        0x0c | 0x4c | 0x0d | 0x4d |  // AdvSIMD multi/single struct
        0x2c | 0x6c | 0x2d | 0x6d |  // AdvSIMD post-index
        0x1c | 0x5c | 0x9c | 0xdc |  // LDR (SIMD literal)
        0x3c | 0x7c | 0xbc | 0xfc); // LDR/STR (SIMD unsigned offset)
    
    if is_simd_ldst {
        let rn = (instr >> 5) & 0x1F;
        return rn == 18; // Check GPR base, not SIMD register
    }
    // ... rest of detection
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test test_simd_load_with_gpr_base_x18`

**Step 5: Commit**

```bash
git add src/decoder.rs src/lib.rs
git commit -m "feat: add decoder.rs with SIMD load/store x18 detection"
```

---

## Phase 2: Table-Driven Decoder Structure

### Task 3: Define instruction encoding tables

**Step 1: Write failing test for ADD/SUB shifted register**

```rust
#[test]
fn test_add_shifted_reg_x18() {
    // ADD w14, w14, w18 — Rm=x18
    let instr = 0x0b1201ce;
    assert!(decoder::references_x18(instr));
}
```

**Step 2: Run test (expect to fail if not implemented)**

**Step 3: Add to instruction table**

```rust
// In decoder.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstrClass {
    // Data Processing - Register
    AddSubShiftedReg,
    LogicalShiftedReg,
    AddSubExtReg,
    AddSubCarry,
    CondSelect,
    DataProc2Src,
    DataProc3Src,
    // ... more classes
}

pub struct InstrEncoding {
    pub class: InstrClass,
    pub mask: u32,
    pub value: u32,
    /// Which bits of the instruction contain x18 references
    pub x18_bits: &'static [(usize, usize)], // (lsb, width) pairs
}

pub static INSTR_TABLE: &[InstrEncoding] = &[
    InstrEncoding {
        class: InstrClass::AddSubShiftedReg,
        mask: 0x1F200000,
        value: 0x0B000000,
        x18_bits: &[(16, 5)], // Rm at bits[20:16]
    },
    // ... more entries
];
```

**Step 4: Run test to verify it passes**

**Step 5: Commit**

---

### Task 4: Add EXTR (extract) instruction support

**Files:**
- Modify: `src/decoder.rs`

**Step 1: Write failing test**

```rust
#[test]
fn test_extr_x18() {
    // EXTR w18, w15, w15, #27 (= ROR w18, w15, #27) — SHA-1 rotation
    let instr = 0x138f6df2;
    assert!(decoder::references_x18(instr), "EXTR with x18 should be detected");
}
```

**Step 2: Run test**

**Step 3: Add EXTR to table**

```rust
InstrEncoding {
    class: InstrClass::Extr,
    mask: 0xFF800000,
    value: 0x13800000, // bits[28:23] = 100111
    x18_bits: &[(0, 5), (5, 5), (16, 5)], // Rd, Rn, Rm
},
```

**Step 4: Run test**

**Step 5: Commit**

---

### Task 5: Add Data Processing (1 source) support

**Step 1: Write failing test**

```rust
#[test]
fn test_rev_rbit_clz_x18() {
    // REV w18, w18 — byte reverse
    let rev = 0x5ac00a52;
    assert!(decoder::references_x18(rev));
    
    // RBIT w18, w18 — bit reverse
    let rbit = 0x5ac00252;
    assert!(decoder::references_x18(rbit));
    
    // CLZ w18, w18 — count leading zeros
    let clz = 0x5ac01252;
    assert!(decoder::references_x18(clz));
}
```

**Step 2: Run test**

**Step 3: Add DP1 source to table**

**Step 4: Run test**

**Step 5: Commit**

---

## Phase 3: Emulation Integration

### Task 6: Unified decode + emulate function

**Step 1: Write failing test**

```rust
#[test]
fn test_emulate_extr_sha1_rotation() {
    // EXTR w18, w15, w15, #27 — should rotate w15 right by 27
    let instr = 0x138f6df2;
    let mut regs = TestRegs::default();
    regs.x[15] = 0xDEADBEEF;
    regs.x[18] = 0xDEADBEEF; // Should be overwritten
    
    decoder::emulate(instr, &mut regs);
    
    // ROR by 27 = ROR by (32-27) = ROL by 5
    let expected = 0xDEADBEEF.rotate_right(27);
    assert_eq!(regs.x[18], expected);
}
```

**Step 2: Run test**

**Step 3: Implement emulate function using table**

```rust
pub fn emulate(instr: u32, regs: &mut TestRegs) -> bool {
    // Look up in table
    for encoding in INSTR_TABLE {
        if (instr & encoding.mask) == encoding.value {
            return emulate_class(encoding.class, instr, regs);
        }
    }
    false
}

fn emulate_class(class: InstrClass, instr: u32, regs: &mut TestRegs) -> bool {
    match class {
        InstrClass::Extr => emulate_extr(instr, regs),
        // ... more
    }
}

fn emulate_extr(instr: u32, regs: &mut TestRegs) -> bool {
    let lsb = ((instr >> 10) & 0x3F) as u32;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rm = ((instr >> 16) & 0x1F) as usize;
    let rd = (instr & 0x1F) as usize;
    
    let hi = regs.x[rn];
    let lo = regs.x[rm];
    let concat = ((hi as u64 & 0xFFFFFFFF) << 32) | (lo as u64 & 0xFFFFFFFF);
    let result = ((concat >> lsb) & 0xFFFFFFFF) as u64;
    
    regs.x[rd] = result;
    true
}
```

**Step 4: Run test**

**Step 5: Commit**

---

### Task 7: Add remaining instruction emulations

Add emulation for each instruction class with tests:
- AddSubShiftedReg
- LogicalShiftedReg  
- AddSubExtReg
- AddSubCarry
- CondSelect
- DataProc2Src
- DataProc3Src
- AddSubImmediate
- LogicalImmediate
- MoveWide
- LoadStore (single register)
- LoadStorePair

Each should have:
1. Failing test
2. Table entry with x18_bits
3. Emulation implementation
4. Pass test
5. Commit

---

## Phase 4: Integration

### Task 8: Replace trap.rs with decoder.rs

**Step 1: Write integration test**

```rust
#[test]
fn test_full_decode_coverage() {
    // All x18 instructions from tttt-root binaries should be detected
    let test_cases = include!("x18_instr_test_cases.txt");
    for (instr, expected, comment) in test_cases {
        let result = decoder::references_x18(instr);
        assert_eq!(result, expected, "{}", comment);
    }
}
```

**Step 2: Run test and fix any gaps**

**Step 3: Update trap.rs to use decoder.rs**

```rust
// In trap.rs, replace references_x18() with:
pub fn references_x18(instr: u32) -> bool {
    decoder::references_x18(instr)
}

// Replace emulate_x18_instruction() with:
pub fn emulate_x18_instruction(orig_instr: u32, mctx: &mut MContext64) -> bool {
    decoder::emulate_from_mcontext(orig_instr, mctx)
}
```

**Step 4: Run cargo test**

**Step 5: Commit**

---

### Task 9: Final verification

**Step 1: Run integration test**

```bash
cargo test
```

**Step 2: Run full fakelinux test**

```bash
FAKELINUX_ROOT=./tttt-root ./target/debug/fakelinux --container ./tttt-root/bin/bash -c "apt-get update; apt-get install -y file; file /bin/ls"
```

Expected: Should complete successfully with correct key verification

**Step 3: Commit**

```bash
git add -A
git commit -m "feat: complete ARM A64 decoder refactor with TDD"
```

---

## Reference: ARM A64 Instruction Encoding Hierarchy

Based on https://weinholt.se/articles/arm-a64-instruction-set/:

```
Main opcode (bits[28:25]):
  0xxx = Data Processing - Immediate
  1xxx = Branch / Exception / System
  010x = Data Processing - Register
  011x = Data Processing - SIMD/FP (expand later)
  110x = Load and Store
  111x = Load and Store SIMD/FP
```

Sub-opcode determines specific instruction within group.

---

## Execution Handoff

**Plan complete and saved to `docs/plans/2026-04-15-arm64-decoder-tdd.md`.**

**Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task (RED→GREEN→Review→Commit cycle), with code review between steps. Good for tight control and learning.

**2. Parallel Session (separate)** - Open new session in a worktree with executing-plans skill, batch execution with checkpoints. Faster but less interactive.

**Which approach?**