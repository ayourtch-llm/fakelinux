# Agent debugging benchmarks

A collection of real, hard bugs from this project, packaged as reproducible
agent-debugging tasks. Each benchmark lives in its own subdirectory and contains:

- **`request.md`** — the task: the exact pre-fix commit to check out, the bug
  description, the verbatim briefing/materials given to the agent, and the
  deliverable.
- **`response.md`** — the ground truth: the root cause, the load-bearing
  reasoning step(s) an agent must reach, the fix, verification thresholds, and a
  tiered grading rubric.

## How to run one

1. `git checkout <pre-fix commit>` (named at the top of the bench's `request.md`).
2. Give the agent *only* the contents of `request.md` (and access to the repo at
   that commit). Do **not** show it `response.md`.
3. Grade the agent's diagnosis + proposed fix against `response.md`'s rubric.
   For full credit, the proposed fix should take the bench's stated repro to 0.

These bugs are chosen because they have a **non-obvious failure mode** — often a
documented "ruled out" conclusion that is actually wrong — so they reward agents
that re-verify load-bearing assumptions rather than trusting prior analysis.

## Benchmarks

| Directory | Bug | Trap |
|-----------|-----|------|
| [`ipsec-gcm-corruption/`](ipsec-gcm-corruption/) | AES-GCM decrypt corruption under fakelinux (the `test_ipsec_*` cluster) | The trail's exhaustive investigation **retracts the correct root cause** (x18) on the strength of a probe that checked the *wrong DSO* / a stale cache. The agent must distrust the "ruled out" list. |

## Adding a benchmark

Create `docs/bench/<slug>/` with `request.md` + `response.md` following the
existing one, then add a row above. Pick the pre-fix commit as the parent of the
fix commit (`git rev-parse <fix>^`) so the repo state is exactly pre-fix and
includes whatever investigation context the agent should start from.
