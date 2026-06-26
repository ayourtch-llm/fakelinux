# ARM A64 ISA encoding XML

This directory contains the per-instruction XML files from ARM's
machine-readable **A64 instruction-set architecture specification**
(the same data ARM publishes as its "Exploration tools" / system-register
XML release). They were vendored from the **2026-03** spec release.

## What uses it

`build.rs` (at the repository root) parses every `*.xml` file here at build
time and generates a decode table — `(mask, value, GPR-field positions,
emulation class)` for each encoding. That generated table is the single source
of truth for the instruction decoder in `src/decoder.rs` and the emulation
dispatch in `src/trap.rs`. Nothing is hand-maintained; regenerating from a newer
spec release is just a matter of dropping in the new XML and rebuilding.

If this directory is missing, `build.rs` emits a warning and produces an empty
table (fakelinux will build but won't decode anything).

## Licensing

These files are **derived from ARM's published Architecture Specification** and
remain subject to **ARM's own licensing terms**, not the MIT license that covers
the rest of this repository. They are included here for convenience and
reproducibility of the build. If you redistribute this project, review ARM's
specification license to confirm your use is permitted, or regenerate the table
from a spec release you have obtained under appropriate terms.

Source: <https://developer.arm.com/downloads/-/exploration-tools>
