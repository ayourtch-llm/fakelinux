# Agent debugging benchmark — fakelinux IPsec/GCM corruption

## How to use this benchmark

Check out the repository at the **pre-fix commit** and give the agent the *Task*
and *Briefing* below (and only those). Grade its answer against
[`response.md`](response.md). The agent passes if it identifies the true root
cause and proposes a fix that takes the repro to 0 corruption.

```
git checkout bb0bf6e89cf049314bebdce27945852d7ba27ea9   # parent of the fix
```

This commit contains an **exhaustive but unsolved** investigation: ~20 dated
sub-sections (`docs/plans/2026-06-28-vpp-100pct-pass.md` §§A.4.7–A.4.29), a
13-probe suite, a residual write-up, and a handoff runbook. The interesting
property of this benchmark: the trail's own conclusion is **wrong** — it
*retracted* the correct mechanism (A.4.28 → A.4.29) on the strength of a probe
that checked the wrong artifact. A strong agent must distrust the documented
"ruled out" list and re-verify the load-bearing claim. (The bug had resisted
multiple sessions of single-agent work; it was cracked by a fresh model
explicitly told to challenge the assumptions.)

## The bug

An AES-GCM decrypt loop running under `fakelinux` (an ARM64 Linux-syscall
emulator on macOS) corrupts its decrypted output:
- **~0.6%** of iterations with **no signals at all** (`interval=0`),
- **~+2.9pp more** under an aggressive 200µs `SIGALRM`.
- **Native macOS** python+openssl = **0%**, even at higher per-decrypt signal
  density → the corruption is **fakelinux-specific**.
- The corrupt block is foreign/garbage; the GCM **tag usually still validates**
  (so the bad bytes are on the decrypted *output* openssl computes, not the
  ciphertext input).

Repro (inside the guest): `scripts/vpp-shell.sh
'/root/vpp/build-root/test/venv/bin/python3 /tmp/gcm_signal_corruption.py 8000 1970'`
(host `roots/ubuntu/tmp/` maps to guest `/tmp/`; canonical repro committed at
`tests/repro/gcm_signal_corruption.py`). The real-world failure is the entire
`test_ipsec_*` VPP test family (~110 of 127 failures).

## Task given to the agent (verbatim briefing)

> Fresh eyes wanted on a deep fakelinux bug that another model probed
> exhaustively without finding root cause. **Challenge our assumptions**, don't
> just repeat our probes. Read `docs/plans/2026-06-28-vpp-100pct-pass.md`
> §§A.4.7–A.4.29, `docs/plans/baseline-0pt6-percent-findings.md`, and
> `tests/repro/gcm_signal_corruption.py`.
>
> ESTABLISHED (per the trail): the corruption is openssl **storing a wrong
> keystream it computed**; at the corrupting store the AES inputs (round keys,
> counter, all GPRs/NEON/cpsr/tpidr/fpsr, code bytes) are **all verified
> byte-identical to a clean run**; 13 in-tree probes are all clean; macOS honors
> GPR/NEON/CPSR mcontext writes.
>
> RULED OUT (per the trail): x18 emulation/trampoline (`AES_X18_SCAN` says
> AES_encrypt's x18 instructions ARE patched; default run uses NEON-AES with no
> x18, yet `armcap=0` scalar corrupts the same → "common to both paths → not
> x18"); nested signal_forwarder; altstack overflow; round-key/counter/code/
> stack corruption; lost-register-across-signal.
>
> The paradox: correct architectural inputs + correct code + correct CPU should
> *mandate* correct output, yet it's garbage ~0.6% even with zero signals.
>
> Find a fresh hypothesis or a flaw in the reasoning. Don't trust the "ruled
> out" list blindly if you can find a hole in it. Candidate angles you may not
> have fully exploited: (1) a measurement artifact / probe blind spot; (2) a
> minimal C (no-python) repro native-vs-fakelinux to remove the interpreter
> variable; (3) the NEON-AES path; (4) the fixed reused output buffer / mmap
> handling. Produce a structured report: independent assessment, the single most
> likely mechanism, and 2–3 concrete falsifiable experiments.

## Deliverable

A root-cause diagnosis + a proposed fix, ideally with a falsifiable verification
plan. Bonus: a fresh-eyes review of the fix's edge cases.

## Acceptance / grading

See [`response.md`](response.md) for the ground-truth root cause, the key
reasoning step that *must* be made, the fix, and a tiered grading rubric.
