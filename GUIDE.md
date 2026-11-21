# Using emi

This guide explains how to run `emi` in an agentic coding loop, in CI, and with custom language/service drivers.

## 1. Build and verify the binary

```bash
cargo build --release
./target/release/emi sim --seeds 1000
```

`emi sim` runs 1,000 seeded in-memory DST worlds, 10 effectful git/Python worlds, and 8 black-box CLI worlds that invoke the compiled `emi` binary end-to-end against adversarial trust-boundary scenarios (bare `HEAD`, worktree ratchet tampering, tampered/unsigned evidence, `bench.py` cheating, missing observations, and coverage thresholds).

## 2. Initialize a repository

`emi` reads all policy, rules, masks, observable-effect declarations, and regression cases from the **pinned base commit** (`git show <base>:.emi/ratchet.json`), never from the candidate working tree.

```bash
emi ratchet init --repo . --mode enforce --allow-head \
  --min-cov-ratio 0.5 \
  --observe-file journal.log \
  --require-mutations
git add .emi/ratchet.json
git commit -m "init emi ratchet"
```

Pinned policy options:

- `--mode observe|enforce|off`
- `--min-cov-ratio <0.0..=1.0>` — share of executable changed lines that must be covered (default `0.5`, i.e. 50%)
- `--driver "<CMD>"` — custom JSONL driver command
- `--metric "<CMD>"` — default benchmark command for `emi climb`
- `--observe-file <PATH>` — repeatable; file whose existence, size, and SHA-256 `emi` compares after every step
- `--require-observation <NAME>` — repeatable; named observation key required in `Trace.observations` (e.g. `rows_after_reopen`)
- `--require-mutations` — require AST mutation evidence on executable changed lines before returning `pass`

## 3. The agentic inner loop (`emi check` + `emi replay`)

Give your coding agent one command as its verification gate:

```bash
emi check --repo . --base origin/main --seeds 48 --json
```

`emi check` runs the full pipeline in one shot:
1. Skeleton check (public API + nondeterminism sites)
2. Strict behavioral diff (`--strict` is the default; pass `--no-strict` to disable)
3. AST adversary mutations (enabled automatically in `enforce` mode, when `require_mutations` is set, or with `--with-adversary`)
4. Writes `.emi/evidence.json` (signed with HMAC-SHA256 when `EMI_SIGNING_KEY` or `--key-file` is set, and always checksummed with `record_digest_sha256`)

Every `--json` response includes explicit machine fields:

- `verdict`: `pass` | `parity_fail` | `inconclusive` | `nondeterministic` | `leaky_mask` | `probe_failed`
- `exit_code`: `0`, `3`, `4`, `5`, or `7`
- `blocker`: `none` | `regression` | `rule_violation` | `surviving_mutant` | `skeleton_break` | `nondet_site` | `nondeterministic` | `leaky_mask` | `probe_failed` | `missing_observation` | `zero_ops` | `zero_comparisons` | `insufficient_coverage` | `missing_mutations`
- `next_action`: `ready_to_stamp` | `fix_regression_and_replay` | `fix_rule_expectation_and_replay` | `kill_surviving_mutant` | `remove_nondeterminism` | `add_required_observation` | `increase_coverage_or_driver_ops` | `run_with_adversary` | `fix_public_api_break` | `fix_driver_probe`
- `replay_cmd`: exact `emi replay` command when unapproved witnesses exist

### Fast witness iteration (`emi replay`)

When `emi check` fails (exit `3`), the agent doesn't need to re-run 48 seeds + mutations on every edit. Replay only the minimized failing witness(es) in ~100ms:

```bash
emi replay --repo . --base origin/main --evidence .emi/evidence.json --json
```

Once `emi replay` exits `0`, re-run `emi check` for full parity + coverage + mutation verification.

### Drop-in `AGENTS.md` snippet

```markdown
## Verification
Do not write unit tests for your patch. Verify all changes with:
1. `emi check --repo . --base origin/main --json`
2. If exit code is 3 and `replay_cmd` is present, iterate with `emi replay --repo . --base origin/main --json` until it exits 0, then re-run `emi check`.
3. If exit code is 7 (`inconclusive`), inspect `blocker` (`insufficient_coverage`, `missing_observation`, `missing_mutations`, `zero_ops`) before finishing.
```

## 4. Approving intentional behavior changes (`--expect` and `--must-hold`)

Pair every input predicate (`--when`) with an expected output relation (`--expect`). Input-only rules without `--expect` are rejected:

```bash
emi ratchet lock-rule --repo . --allow-head \
  --op "pricing.py::price" \
  --when "1000 <= price_input <= 5000" \
  --expect "candidate_price == base_price - 10" \
  --must-hold
```

- **Rule-safe shrinking:** `emi` evaluates approval rules on the original input before shrinking. An unapproved regression outside the rule's range (e.g. at `x = 6000`) will never be shrunk into the approved `1000..5000` range and hidden.
- **`--must-hold`:** checks the `--expect` relation even when `base` and `candidate` agree. If the rule says `1000..5000` must become `base - 10` and the candidate left `cand == base`, `emi` fails with `blocker: "rule_violation"` (exit `3`).
- **Exception comparison:** exceptions compare by type (`ValueError` vs `TypeError`), ignoring reworded message strings.
- **Exact hash approval:** for a one-off change that also alters observed files or logs, approve the exact witnessed diff ID with `emi ratchet approve <DIFF_ID>`.

## 5. Observable effects (files & custom driver observations)

### Files (`--observe-file`)

Declare files in `.emi/ratchet.json` (`"observed_files"`) or via `--observe-file journal.log`. Before each step, `emi` snapshots the file, runs the step, hashes `exists`, `size`, and `sha256` into `observations["file:<path>"]`, and restores the pre-step file so A/A determinism and subsequent steps remain isolated.

### Named driver observations (`--require-observation`)

For database durability or service invariants (e.g. `rows_after_reopen`), have your driver emit `"observations": {"rows_after_reopen": 5}` and pin `"required_observations": ["rows_after_reopen"]` in `.emi/ratchet.json`. If the key is missing, both `emi check`/`diff` and `emi climb` return `inconclusive` (exit `7`).

## 6. Evidence signing and `ratchet stamp` in CI

Run `emi check` (or `emi diff` + `emi adversary --evidence`) with `EMI_SIGNING_KEY` set, then verify and stamp the same evidence file:

```bash
EMI_SIGNING_KEY="$CI_SIGNING_KEY" \
  emi check --repo . --base "$BASE_SHA" --seeds 48 --evidence-out .emi/evidence.json --json

EMI_SIGNING_KEY="$CI_SIGNING_KEY" \
  emi ratchet stamp --repo . --base "$BASE_SHA" --evidence .emi/evidence.json
```

Before stamping, `stamp` verifies:
- `base_sha`, `candidate_tree_sha256`, `driver_digest`, and `policy_digest` still match the live repo (otherwise exit `2`: `stale evidence`)
- `record_digest_sha256` matches canonical fields (rejects edited JSON)
- `hmac_sha256` matches `EMI_SIGNING_KEY` when a key is configured (rejects unsigned/forged evidence)
- Internal consistency (rejects `"verdict": "pass"` if `unapproved_diffs > 0`, `skeleton_ok == false`, `aa_verified == false`, coverage below `min_changed_cov_ratio`, or required mutations missing)

## 7. Performance hillclimbing (`emi climb`)

```bash
emi climb --repo . --base origin/main --metric "python3 bench.py" --runs 9 --min-effect 0.05
```

`bench.py` can print either:
- A plain float (`12.34`), OR
- JSON with both metric and correctness output: `{"metric": 12.34, "output": <checksum_or_value>}`, OR
- Line 1 float followed by output/checksum lines (`12.34\nchecksum=abc`).

`climb` overlays `base`'s `bench.py` into `candidate`, checks skeleton + parity + observations + AST mutations, compares benchmark output digests across every `base` and `candidate` run (failing with `reject_floor`, exit `3`, if outputs diverge or are nondeterministic), and only accepts (exit `0`) when the interleaved 95% bootstrap CI is strictly above `1.0x` and meets `--min-effect`.

## 8. Python driver notes

The built-in Python driver:
- Forks a fresh child process (`os.fork()`) per step so module globals, caches, and C-extension state reset cleanly.
- Loads modules by dotted package name (`pkg.sub.mod`) so relative imports work.
- Scrubs memory addresses (`at 0x...>`) from `repr`.
- Mines constants from changed files, their local imported modules (up to 2 hops), and pinned approval rules without truncating by pool size, spreading boundary inputs round-robin across all public functions.
- Constructs classes via `@classmethod def __emi_init__(cls)` or `emi_factory()` when present, falling back to `cls()` or typed default arguments.

## 9. Writing a custom driver

Pass `--driver "<CMD>"` pointing to a long-lived stdio JSONL process:

- `probe`: reads `{"verb":"probe"}`, writes `{"ok":true,"fingerprint":"v1","operations":[{"name":"put","arity":2,"stateful":true,"param_types":["str","int"],"kwarg_names":[]}],"detail":"ok"}`
- `step`: reads `{"verb":"step","seed":"42","ops":[{"op":"put","args":["k1",7]}],"faults":[],"observed_files":[]}`, writes `{"ok":true,"outcomes":[true],"side_effects":[],"logs":[],"state_digest":"<sha256>","coverage":["src/db.rs:42"],"observations":{"rows_after_reopen":1},"error":null}`

## 10. Exit codes

| Code | Meaning |
|---:|---|
| `0` | Pass / accept |
| `2` | Usage error, stale/tampered/unsigned/inconsistent evidence, unprotected `HEAD` in enforce mode, or driver crash/timeout |
| `3` | Regression (`parity_fail`), `must_hold` rule violation, broken skeleton, surviving planted bug, or `climb` floor/benchmark-output failure |
| `4` | `base` or `candidate` failed A/A determinism, or a mask failed canary verification |
| `5` | Driver `probe` failed |
| `6` | `climb` correctness held, but metric improvement was not significant or below `--min-effect` |
| `7` | `inconclusive` (0 ops, 0 valid comparisons, executable changed-line coverage below `--min-cov-ratio`, missing required observation, or missing required mutations) |
