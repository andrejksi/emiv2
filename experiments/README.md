# emi v2 experiment harness

Reproducible experiments from the emi v2 review rounds (2026-11-21). Each one builds a throwaway git repo
under `/tmp`, makes one change, runs emi, and prints the verdict and exit code. The header line of every
experiment says what *should* happen, and where it differs, what emi did at commit `37b180d`.

These scripts are the starting point for permanent `emi sim` cases (builder agent) and for the pilot
(eval agent). See the "Agent briefs" tab of the evaluation plan.

## Requirements

- An emi binary (`cargo build --release` in the emi repo)
- git, Python 3, Node.js 22+, Go 1.24+ (Go only for G1)
- Linux or macOS; the scripts write to `/tmp/<name>` and `/tmp/<name>.git` and delete them first

## Run

```bash
export EMI=/path/to/emiv2/target/release/emi
bash 01_core.sh                       # must run first: later scripts reuse /tmp/toy
bash 02_trust_and_open_items.sh
bash 03_languages_and_new_attacks.sh
```

Note: exporting `EMI` puts a variable starting with `EMI` into the environment of the code under test,
which is exactly what experiment A3 exploits. A3's "outside emi" check unsets it.

## What the scripts cover

| Script | Experiments |
| --- | --- |
| `01_core.sh` | R0–R9: detection basics, comment-only edits, untracked and removed files, infinite loop, `climb` noise and benchmark edits. N2–N16: boundary constants in other modules, correct refactors that must pass, constant-heavy files, unreachable branches, packages, classes, module state, plain objects, benchmark detection, approval rules and shrinking. N9–N10: forged evidence with a key, moved base ref, `EMI_BASE_REV`. |
| `02_trust_and_open_items.sh` | D1: in-repo driver tampering and `--driver` override. D2: forged unsigned evidence. D3: module-level refactor. D4: timeout label. D5: benchmark detection with a time-only benchmark. D6–D8: constructor crash, constant-heavy boundary, broken pipe. |
| `03_languages_and_new_attacks.sh` | J1–J8: Node/TS driver (ESM, TS, async, enums, CommonJS, classes). G1: Go via `emi driver init`. A1: gitignored code. A2: standard library shadowing. A3: detecting emi via environment variables. E1: forged evidence in enforce mode without a key. |

## Expected outcomes at commit 37b180d that are still wrong

| Experiment | Should be | Was |
| --- | --- | --- |
| N10, N10b | parity_fail | pass (base moved by agent) |
| N3 / D7 | parity_fail at 48 seeds | pass |
| N6 / D6, J8 | parity_fail | pass (constructor crashes count as tested) |
| D3 | pass | inconclusive (module-level line not covered) |
| R6 / D4 | timeout blocker | nondeterministic, exit 4 |
| D5 | reject | `climb` accepts 12.2x |
| D2, E1 | refused | stamped as pass, unsigned |
| A1 | pass | parity_fail (gitignored files missing from base snapshot) |
| A3 | parity_fail | pass (code detects emi) |
| D8 / piped runs | exit 3 | occasionally 134 (broken-pipe panic) |

Experiment N13 at 48 seeds and N12 without `--must-hold` also pass; those reflect stated limits (coverage
ratio and permission-only rules), not bugs.
