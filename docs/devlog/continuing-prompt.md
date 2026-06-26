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
   - ADR (0x10), ADD/ADDP (0x78), DataProc (0x98)

## Current Test Status

```
cargo test trap::tests::references_x18_detects_all_libpython_instructions
```

**Result**: 4 of 238 x18 instructions still not detected (down from 90+)

## Remaining Missed Instructions

### 1. `0x1a9203f1` - ADD/ADDP with Rm=x18
- Top byte: 0x1A
- Rn=31, Rd=17, Rm=18
- Need to add table entry for 0x1A instructions (ADD/ADDP with extended register)

### 2. `0x9b125421` - Data processing with Rm=x18
- Top byte: 0x9B
- Rn=1, Rd=1, Rm=18
- Need to fix the 0x98 entry to also match 0x9B (mask should be 0xF8000000, not 0xFC000000)

### 3. `0xa9004be3` and `0xa9404be3` - LDP with imm7, NOT Rm
- Top byte: 0xA9
- Rn=31, Rd=3, Rm=0 (NOT 18!)
- These are LDP instructions where bits[20:14] are imm7, not Rm
- **These are likely false positives in the test data** - they don't actually reference x18

## What Needs to Be Done

### 1. Fix 0x9B Entry
The current entry uses mask 0xFC000000 with value 0x98000000, which doesn't match 0x9B.
Change to mask 0xF8000000 with value 0x98000000 to match both 0x98 and 0x9B.

### 2. Add 0x1A Entry
Add a table entry for 0x1A instructions (ADD/ADDP with extended register):
```rust
InstrEncoding {
    class: InstrClass::Unimplemented,
    mask: 0xF8000000,
    value: 0x18000000,  // Match 0x18-0x1F
    reg_operands: Some(&[(0, 5), (5, 5), (16, 5)]),  // Rd, Rn, Rm
},
```

### 3. Verify Test Data
The 0xA9 instructions (`0xa9004be3`, `0xa9404be3`) show Rm=0, not 18.
These might be false positives in the test data. Verify by:
- Checking if these instructions actually appear in Python binaries with x18
- Or if they were incorrectly added to the test data

### 4. Update continuing-prompt.md
Update this document with final status once all issues are resolved.

## File Locations

- `src/decoder.rs` - Main decoder module with INSTR_TABLE and references_x18()
- `src/trap.rs` - Old references_x18() now delegates to decoder
- `docs/plans/2026-04-15-arm64-decoder-tdd.md` - Original plan document
- `docs/continuing-prompt.md` - This document

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

The main issue is that some table entries have incorrect masks that don't match all variants of an instruction class. The fallback code is also checking the wrong register fields for some instruction classes.

The cleanest solution is to add more specific table entries with correct masks rather than expanding the fallback logic, as this keeps the single source of truth principle intact.