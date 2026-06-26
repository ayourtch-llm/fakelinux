# Generated decoder tables (committed)

These files are **generated** from ARM's A64 ISA XML by `build.rs`, but they are
committed to the repository so the emulator builds and runs without downloading
the ARM spec.

- `x18_table.rs` — the `GEN_TABLE` decode table (`include!`d by `src/decoder.rs`).
- `x18_tests.rs` — auto-generated spot-check tests (`include!`d in `decoder.rs`'s
  test module).

**Do not edit these by hand.** To regenerate them from a (possibly newer) ARM
spec, install the XML into `data/encoding/` and build with the regeneration flag:

```sh
scripts/fetch-arm-isa-xml.sh
FAKELINUX_REGEN_DECODER=1 cargo build
```

Then review the diff and commit the updated files. See
[`data/encoding/README.md`](../../data/encoding/README.md) for details.
