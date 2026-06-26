# ARM A64 ISA encoding XML (not bundled)

The instruction decoder is generated at build time from ARM's machine-readable
**A64 instruction-set architecture specification**. Those XML files are **not
vendored in this repository** because they are ARM's copyrighted material under
ARM's own license — see "Licensing" below. You need to drop them into this
directory yourself before building the decoder.

## What goes here

The per-instruction XML files from ARM's A64 ISA XML release (each is an
`<instructionsection>` describing one instruction's encoding), plus the index
and shared files that ship alongside them. fakelinux was developed against the
**2026-03** release.

`build.rs` reads `data/encoding/*.xml`, skips the non-instruction files
(`encodingindex.xml`, `shared_pseudocode.xml`, `notice.xml`, `constraint_*`,
`shared_*`, and `type="alias"` pages), and generates a
`(mask, value, GPR-field positions, emulation class)` decode table consumed by
`src/decoder.rs` and `src/trap.rs`.

## How to obtain it

1. Download the **A64 ISA XML for A-profile architecture** release from ARM's
   exploration tools page:
   <https://developer.arm.com/downloads/-/exploration-tools>
2. Extract the archive. It contains a directory of per-instruction `*.xml`
   files (and `*.dtd` schema files).
3. Copy those `*.xml` files into this directory (`data/encoding/`):

   ```sh
   cp /path/to/ISA_A64_xml_*/*.xml data/encoding/
   ```

4. Rebuild: `cargo build` regenerates the decode table.

If this directory has no `*.xml` files, `build.rs` prints a warning and emits an
empty table — fakelinux will compile but won't decode/emulate any instructions.

A newer ARM spec release can be dropped in the same way; the table regenerates
automatically.

## Licensing

These XML files are **ARM's copyrighted material**, distributed under ARM's own
specification license — **not** the MIT license that covers the rest of this
repository. That is why they are gitignored and excluded from this repo's
history. Obtain them directly from ARM under their terms; do not redistribute
them as part of a fork of this project unless ARM's license permits it.
