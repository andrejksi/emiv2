# emiv2

Deterministic proof & control engine for agentic software.

Zero external crate dependencies. Zero comments. Zero unit tests. Verified by built-in Deterministic Simulation Testing (`emi sim`), public-API differential parity, and planted-bug oracle proving.

## Build

```bash
cargo build --release
```

Binary: `target/release/emi`

## Primitives

| Command | Purpose |
|---|---|
| `emi skeleton extract \| check` | Extracts public API signatures, state enums, complexity erosion, and ambient nondeterminism (`time.time`, `random.*`, `SystemTime::now`, `Math.random`, etc.). Fails on removed/changed signatures or new nondeterminism (`--forbid-nondet`). |
| `emi diff` | Runs environment probe, **A/A byte-identical base determinism gate**, **mask canary prover**, and seeded/stateful public-API differential execution with delta-shrinking. `--parity` fails on any unapproved behavioral divergence. |
| `emi adversary` | Plants semantic faults against changed code, measures oracle kill rate, and synthesizes the smallest concrete distinguishing input (`DISAMBIGUATOR`) for every surviving fault. |
| `emi ratchet init \| status \| approve \| remember \| stamp` | Reads pinned policy, approved diffs, masks, and diff-triggered incident replay seeds strictly from the immutable `base` commit (`git show <base>:.emi/ratchet.json`) and appends SHA-256 commit attestations (`.emi/attestations.jsonl`). |
| `emi climb --metric CMD` | Monotonic quantitative hillclimber. Enforces the immutable correctness floor (`skeleton ∧ A/A ∧ parity ∧ planted_bugs`) and accepts only strict median metric improvements (`--maximize` to invert). |
| `emi sim [--seeds N] [--seed U64]` | Built-in Deterministic Simulation Testing engine verifying all EMI invariants across seeded fault-injected worlds with bit-for-bit meta-determinism. |

## Quick Start

```bash
emi sim --seeds 5000

emi skeleton extract --repo .
emi ratchet init --repo . --mode observe
git add .emi/ratchet.json && git commit -m "pin ratchet"

emi diff --repo . --parity --seeds 32
emi adversary --repo . --max-faults 8 --seeds 24
emi climb --repo . --metric "python3 bench.py" --runs 5
emi ratchet stamp --repo .
```

All commands accept `--json` for canonical machine-readable output.

## 3-Verb Driver Protocol

EMI is language-agnostic. Any driver speaking JSONL over persistent stdio works with `--driver <CMD>` (if omitted, EMI uses its built-in auto-Python driver):

1. **Probe**
   - In: `{"verb":"probe"}`
   - Out: `{"ok":true,"fingerprint":"...","operations":[{"name":"op","arity":1,"stateful":true}],"detail":"..."}`
2. **Step**
   - In: `{"verb":"step","seed":42,"ops":[{"op":"put","args":["k1",1]}],"faults":[{"at_step":0,"kind":"cancel","target":"dependency"}]}`
   - Out: `{"ok":true,"outcomes":[...],"side_effects":[...],"logs":[...],"state_digest":"<sha256>","coverage":["file:line"],"error":null}`

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Pass / Accept |
| `2` | Usage or runtime error |
| `3` | Parity fail / skeleton break / surviving planted bug / climb floor rejected |
| `4` | Nondeterministic A/A base or leaky mask |
| `5` | Environment probe failure |
| `6` | Climb floor held, metric did not improve |
