# Experiment: force the program-header code-range path on all DSOs

## Context

Commit `f9f2f60` fixed the IPsec/GCM corruption: the x18 patcher was skipping
DSOs (e.g. cryptography's `_rust.abi3.so`) whose runtime mapping starts past the
ELF header, because the in-memory code-range extractor found no `\x7fELF` and
returned no ranges. The fix added `extract_code_ranges_from_file_mapping()`,
which reads **`SHF_EXECINSTR` section** ranges from the backing ELF file and
projects them into the mapping. That fix is committed and verified
(repro 0 corruption; 216/216 IPsec tests green).

## The experiment (uncommitted, in the working tree for review)

Hypothesis under test: could we drop the section strategy and use a **single**
codepath — the `PF_X PT_LOAD` **program-header** strategy — for *all* DSOs
(simpler, and it would also cover stripped DSOs that have no section headers)?

The working-tree change to `src/loader.rs` adds:
- A second strategy in `extract_code_ranges_from_file_mapping()`: if section
  ranges are unavailable/empty, project the `PF_X PT_LOAD` program-header
  segments (`p_offset .. p_offset+p_filesz`) into the mapping.
- A gate `FAKELINUX_FORCE_PHDR_RANGES`: when set, **skip the section strategy
  entirely** (use only the program-header strategy) and **bypass the patch
  cache** (so the forced path actually runs and isn't masked by cached results).

Inspect it with: `git diff src/loader.rs`.

## What was run

```
cargo build --release
FAKELINUX_FORCE_PHDR_RANGES=1 scripts/vpp-shell.sh \
  '/root/vpp/build-root/test/venv/bin/python3 /tmp/gcm_signal_corruption.py 2000 1970 0'
```

## Observed output (the failure)

```
fakelinux: __TEXT bounds 0x102c04000-0x102cb8000 (slide=0x2c04000)
fakelinux: altstack 0x102d80000-0x102da0000 size=131072
fakelinux: runtime patch at 0x102db0000+0x408c8:  0 SVC,    0 TPIDR,  150 x18
fakelinux: runtime patch at 0x102e00000+0x1bdf90: 517 SVC, 1530 TPIDR, 1660 x18
roots/ubuntu/usr/bin/bash: error while loading shared libraries:
    ld-linux-aa: cannot open shared object file: No such file or directory
```

The guest `bash` fails to start: the interpreter it asks for is **`ld-linux-aa`**
(the real interpreter is `ld-linux-aarch64.so.1`). The decrypt loop never runs
(no `TOTAL bad` line). Without the gate (the committed section-only path) the
same setup runs clean: repro `0 / 20000`, IPsec tests pass.

## Task for the reviewer

Explain, from the code in `git diff src/loader.rs` and the output above,
**exactly why the `FAKELINUX_FORCE_PHDR_RANGES` (program-header-only) path breaks
the guest** while the section-based path does not. Be specific about the
mechanism that produced `ld-linux-aa`. Then state whether the program-header
strategy can be made safe (and how), or whether the section strategy is
fundamentally required — and whether the *fallback* use of the program-header
strategy (for stripped DSOs) in the committed-style design has the same problem.
