# Continuing Prompt: ARM A64 Decoder x18 Detection Completion

## Current State (as of 2026-04-15)

The ARM A64 decoder refactoring is in progress. The goal is to unify x18 register detection into a single table-driven source of truth in `decoder.rs`, replacing the old dual-function approach in `trap.rs`.

## What's Been Done

1. **Added `reg_operands` field to `InstrEncoding`**: Each instruction encoding now has an `Option<&'static [(u32, u32)]>` field that specifies register operand bit positions (lsb, width pairs).

2. **Created `decoder::references_x18()`**: A unified function that:
   - First checks the `INSTR_TABLE` for matches and uses `reg_operands` to detect x18
   - Falls back to manual bit checks for SIMD load/store, LDR/STR, and other instruction classes

3. **Updated `trap::references_x18()`**: Now simply delegates to `decoder::references_x18()` as the single source of truth.

4. **Fixed TestRegs**: Changed from 1-indexed (X1-X30) to 0-indexed (X0-X30) to properly handle all registers.

5. **Added instruction class entries**:
   - EXTR, DataProc1Src, AddSubShiftedReg, AddSubImmediate, MoveWide
   - LogicalShiftedReg, AddSubExtReg, DataProc2Src
   - Bitfield, LdrLiteral, LdrStrUnscaled, LdrStrRegOffset
   - LDP/STP (0xA8/0xAA), CBZ/CBNZ (0xB4/0xB5), FMOV (0xF2/0xF3/0xFA)

## Current Test Status

```
cargo test trap::tests::references_x18_detects_all_libpython_instructions
```

**Result**: 43 of 238 x18 instructions still not detected (down from 90+)

## Remaining Missed Instructions

The following instruction patterns are still not detected:

### SIMD Load/Store with Rm=x18 (top bytes 0x38, 0x78, 0xB8)
- `0x38xxxxxx`, `0x78xxxxxx`, `0xB8xxxxxx` - These have Rm at bits[20:16] that can be x18
- The current SIMD fallback only checks Rn (base), not Rm (index)

### LDR/STR with Rm=x18 (top bytes 0x90, 0xB0, 0xF0, 0xF8)
- `0x90xxxxxx`, `0xB0xxxxxx`, `0xF0xxxxxx`, `0xF8xxxxxx` - These have Rm at bits[20:16]
- The current LDR/STR fallback only checks Rn and Rd, not Rm

### LDP/STP with Rd=x18 or Rm=x18 (top byte 0xA9)
- `0xA9xxxxxx` - Some LDP/STP variants have Rd=x18 or Rm=x18
- Current entry only checks Rt and Rn, not all register positions

### FMOV with Rn=x18 (top byte 0xF2)
- `0xF240065f`, `0xF2400a5f` - FMOV from GPR, Rn=x18
- Current FMOV entry only checks Rt and Rm, not Rn

### ADD/ADDP with Rm=x18 (top bytes 0x7A, 0x9B)
- `0x7Axxxxxx`, `0x9Bxxxxxx` - These have Rm at bits[20:16] that can be x18

### LDP with Rt2=x18 (top byte 0xA9)
- `0xA9004be3`, `0xA9404be3` - These have Rt2 at bits[20:16] that should be x18
- But analysis shows Rm=0, so these might be false positives in the test data

## What Needs to Be Done

### 1. Fix SIMD Load/Store Detection
The SIMD fallback currently returns early after checking Rn. It should:
- Check both Rn (base) and Rm (index) for x18
- Only return false if neither is x18

### 2. Fix LDR/STR Detection  
The LDR/STR scaled fallback should check Rm as well as Rn and Rd.

### 3. Add Missing Instruction Classes
Add table entries for:
- **0x7A**: ADD/ADDP with extended register (Rd, Rn, Rm at bits[4:0], [9:5], [20:16])
- **0x9B**: Various data processing with Rm operand
- **0xF2**: FMOV from GPR (Rt, Rn at bits[4:0], [9:5])

### 4. Fix LDP/STP Entry
The LDP/STP entry at 0xA8 needs to be more specific or have a separate entry for 0xA9 variants.

### 5. Verify Test Data
Some instructions like `0xA9004be3` show Rm=0, not 18. Verify these are actually x18 instructions or false positives in the test data.

## File Locations

- `src/decoder.rs` - Main decoder module with INSTR_TABLE and references_x18()
- `src/trap.rs` - Old references_x18() now delegates to decoder
- `docs/plans/2026-04-15-arm64-decoder-tdd.md` - Original plan document

## Commands to Run

```bash
# Check current test status
cargo test trap::tests::references_x18_detects_all_libpython_instructions

# Build and check for warnings
cargo build

# Run all decoder tests
cargo test decoder
```

## Key Insight

The main issue is that the fallback code in `decoder::references_x18()` is checking the wrong register fields for some instruction classes. The table-driven approach is correct, but the fallback needs to be more comprehensive, or we need to add more table entries to cover all the instruction patterns.

The cleanest solution is to add more specific table entries rather than expanding the fallback logic, as this keeps the single source of truth principle intact.