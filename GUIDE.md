# Using emi

This guide explains how to run `emi` in an agentic coding loop, in CI, and with custom language/service drivers.

## 1. Install and verify the binary

Linux / macOS:
```bash
curl -fsSL https://raw.githubusercontent.com/andrejksi/emiv2/main/install.sh | sh
```

Windows (PowerShell):
```powershell
irm https://raw.githubusercontent.com/andrejksi/emiv2/main/install.ps1 | iex
```

Or install directly via Cargo (`cargo install --git https://github.com/andrejksi/emiv2`) or Docker (`docker build -t emi https://github.com/andrejksi/emiv2.git`).

Verify your install:
```bash
emi sim --seeds 1000
```

`emi sim` runs 1,000 seeded in-memory DST worlds, 10 effectful git/Python worlds, and 16 black-box CLI worlds that invoke the compiled `emi` binary end-to-end against adversarial trust-boundary scenarios and field regressions.

## 2. Initialize a repository

`emi` reads all policy, rules, masks, observable-effect declarations, and regression cases from the **pinned base commit** (`git show <base>:.emi/ratchet.json`), never from the candidate working tree.

```bash
emi ratchet init --repo . --mode enforce --allow-head \
  --min-cov-ratio 0.5 \
  --observe-file journal.log \
  --require-workflow select-post-release \
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
- `--require-workflow <ID>` — repeatable; named workflow ID (registered via `emi ratchet remember --id <ID> ...`) that must execute before `check` passes or `ratchet stamp` issues an attestation
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
4. Writes `.emi/evidence.json` (signed with HMAC-SHA256 when `EMI_SIGNING_KEY` or `--key-file` is set, and always checksummed with `record_digest_sha256`), including the effective `observed_files`, `workflows_run`, `ops_exercised`, and `observed_outputs`

Every `--json` response includes explicit machine fields:

- `verdict`: `pass` | `parity_fail` | `skeleton_break` | `inconclusive` | `nondeterministic` | `leaky_mask` | `probe_failed` | `timeout`
- `exit_code`: `0`, `3`, `4`, `5`, `7`, or `8`
- `blocker`: `none` | `regression` | `rule_violation` | `surviving_mutant` | `skeleton_break` | `nondet_site` | `nondeterministic` | `leaky_mask` | `probe_failed` | `missing_observation` | `missing_workflow` | `zero_ops` | `zero_comparisons` | `insufficient_coverage` | `missing_mutations`
- `next_action`: `ready_to_stamp` | `fix_regression_and_replay` | `fix_rule_expectation_and_replay` | `kill_surviving_mutant` | `remove_nondeterminism` | `add_required_observation` | `add_or_run_required_workflow` | `increase_coverage_or_driver_ops` | `run_with_adversary` | `fix_public_api_break` | `fix_driver_probe`
- `replay_cmd`: exact `emi replay` command when unapproved witnesses exist

### Fast witness iteration (`emi replay`)

When `emi check` fails (exit `3`), the agent doesn't need to re-run 48 seeds + mutations on every edit. Replay only the minimized failing witness(es) in ~100ms:

```bash
emi replay --repo . --base origin/main --evidence .emi/evidence.json --json
```

`emi replay` automatically reuses the effective `observed_files` recorded in `.emi/evidence.json` (whether passed via CLI `--observe-file` or pinned in `.emi/ratchet.json`). If an older evidence file lacks `observed_files` for a file-dependent witness, `replay` reports that clearly and exits `2`. Once `emi replay` exits `0`, re-run `emi check` for full parity + coverage + mutation verification.

### Drop-in `AGENTS.md` snippet

```markdown
## Verification
Do not write unit tests for your patch. Verify all changes with:
1. `emi check --repo . --base origin/main --json`
2. If exit code is 3 and `replay_cmd` is present, iterate with `emi replay --repo . --base origin/main --json` until it exits 0, then re-run `emi check`.
3. If exit code is 7 (`inconclusive`), inspect `blocker` (`insufficient_coverage`, `missing_observation`, `missing_workflow`, `missing_mutations`, `zero_ops`) before finishing.
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

Declare files in `.emi/ratchet.json` (`"observed_files"`) or via `--observe-file journal.log`. Before each step, `emi` snapshots the file, runs the step, hashes `exists`, `size`, and `sha256` into `observations["file:<path>"]`, and restores the pre-step file so A/A determinism and subsequent steps remain isolated. The effective file list is saved inside `.emi/evidence.json` so `emi replay` repeats the exact same file checks.

### Named driver observations (`--require-observation`)

For database durability or service invariants (e.g. `rows_after_reopen`), have your driver emit `"observations": {"rows_after_reopen": 5}` and pin `"required_observations": ["rows_after_reopen"]` in `.emi/ratchet.json`. If the key is missing, both `emi check`/`diff` and `emi climb` return `inconclusive` (exit `7`).

## 6. Evidence signing and `ratchet stamp` in CI

**CI must fix the base commit on a clean checkout.** Never rely on a mutable ref (`origin/main`) or `EMI_BASE_REV` in an agent-writable workspace — an agent with shell access can move local refs or set environment variables. Pass the exact 40-character base commit SHA from your CI runner (`--base "$BASE_SHA"`) on a clean checkout. In `enforce` mode, `emi` refuses `EMI_BASE_REV`, refuses locally moved refs, and requires a signing key (`EMI_SIGNING_KEY` or `--key-file`) for `ratchet stamp`.

Run `emi check` (or `emi diff` + `emi adversary --evidence`) with `EMI_SIGNING_KEY` set, then verify and stamp the same evidence file:

```bash
EMI_SIGNING_KEY="$CI_SIGNING_KEY" \
  emi check --repo . --base "$BASE_SHA" --seeds 48 --evidence-out .emi/evidence.json --json

EMI_SIGNING_KEY="$CI_SIGNING_KEY" \
  emi ratchet stamp --repo . --base "$BASE_SHA" --evidence .emi/evidence.json
```

Before stamping, `stamp` verifies:
- `base_sha`, `candidate_tree_sha256`, `driver_digest`, and `policy_digest` still match the live repo (otherwise exit `2`: `stale evidence`)
- `record_digest_sha256` is present (mandatory) and matches canonical fields (rejects edited or stripped JSON)
- `hmac_sha256` matches `EMI_SIGNING_KEY` (required in `enforce` mode, and whenever a key is configured)
- Internal consistency (rejects `"verdict": "pass"` if `unapproved_diffs > 0`, `skeleton_ok == false`, `aa_verified == false`, coverage below `min_changed_cov_ratio`, required workflows omitted, or required mutations missing)

Every passing attestation explicitly lists `workflows_run`, `ops_exercised`, and `observed_outputs` so reviewers can see exactly what supported the pass.

## 7. Performance hillclimbing (`emi climb`)

```bash
emi climb --repo . --base "$BASE_SHA" --metric "python3 bench.py" --runs 9 --min-effect 0.05
```

`bench.py` **must emit both a timing metric and an output/checksum** (time-only benchmarks are rejected with `reject_floor`, exit `3`):
- JSON with both metric and correctness output: `{"metric": 12.34, "output": <checksum_or_value>}`, OR
- Line 1 float followed by output/checksum lines (`12.34\nchecksum=abc`).

`climb` overlays `base`'s `bench.py` into `candidate`, checks skeleton + parity + observations + AST mutations, compares benchmark output digests across every `base` and `candidate` run (failing with `reject_floor`, exit `3`, if outputs are missing, diverge, or are nondeterministic), and only accepts (exit `0`) when the interleaved 95% bootstrap CI is strictly above `1.0x` and meets `--min-effect`.

## 8. Supported claim and built-in drivers (Python & Node.js/TypeScript)

**Supported claim:** behavior-preserving changes (refactors and speedups) in **Python** and **JS/TS**, checked function by function. **Go and Rust are experimental.**

When `--driver` is not set and `.emi/ratchet.json` does not pin a custom driver, `emi` auto-detects the repo language:

- **Python**:
  - Separates EMI's internal JSONL protocol channel onto a dedicated file descriptor and captures program `stdout`/`stderr` plus `SystemExit` cleanly per op.
  - Forks a fresh child process (`os.fork()`) per step so module globals, caches, and C-extension state reset cleanly.
  - Loads modules by dotted package name (`pkg.sub.mod`), counts module-level lines executed at import as covered, scrubs memory addresses (`at 0x...>`), compares exception types, refuses to guess `None` for untyped required constructors (reporting `inconclusive` instead of a false pass), and supports `@classmethod def __emi_init__(cls)` / `emi_factory()`.
- **Node.js / TypeScript** (`.ts`, `.mts`, `.js`, `.mjs`, `.cjs`, auto-selected when no `.py` files are present):
  - Runs each step in a fresh Node worker process with a separate fd 3 protocol channel, capturing `stdout`/`stderr` and `process.exit(code)` cleanly.
  - Collects V8 precise line coverage via Node's built-in `inspector` module, normalizes error types, refuses to construct untyped required constructors with `undefined`, and snapshots/restores `observed_files`.

## 9. Scaffolding and securing custom drivers (`emi driver init`)

For **Go and Rust (experimental)** or custom service/database harnesses, scaffold a working JSONL driver and optionally pin it in `.emi/ratchet.json`:

```bash
emi driver init --repo . --lang go --pin
git add .emi/ && git commit -m "pin emi driver"
```

Supported `--lang` values: `python`, `node`, `ts`, `go` (experimental), `rust` (experimental) (omitting `--lang` auto-detects from `Cargo.toml`, `go.mod`, `package.json`, or source files).

**Driver trust boundary:** On every `check`, `diff`, `replay`, `adversary`, `climb`, and `ratchet stamp` run, `emi` overlays driver files and directories referenced by the driver command from the pinned `base` snapshot into the candidate snapshot (and deletes any untrusted candidate-only copy). In `enforce` mode, `--driver` on the CLI is rejected with exit `2` — the driver must come from the pinned `base` commit.

JSONL protocol on stdio:
- `probe`: reads `{"verb":"probe"}`, writes `{"ok":true,"fingerprint":"v1","operations":[{"name":"put","arity":2,"stateful":true,"param_types":["str","int"],"kwarg_names":[]}],"detail":"ok"}`
- `step`: reads `{"verb":"step","seed":"42","ops":[{"op":"put","args":["k1",7]}],"faults":[],"observed_files":[]}`, writes `{"ok":true,"outcomes":[true],"side_effects":[],"logs":[],"state_digest":"<sha256>","coverage":["src/db.rs:42"],"observations":{"rows_after_reopen":1},"error":null}`

## 10. Exit codes

| Code | Meaning |
|---:|---|
| `0` | Pass / accept |
| `2` | Usage error, stale/tampered/unsigned/inconsistent evidence, missing `record_digest_sha256`, missing signing key in enforce mode, locally moved base ref or `EMI_BASE_REV` in enforce mode, legacy evidence missing `observed_files`, `--driver` override in enforce mode, unprotected `HEAD` in enforce mode, or driver crash |
| `3` | Regression (`parity_fail`), `must_hold` rule violation, broken skeleton, surviving planted bug, or `climb` floor/benchmark-output failure (including time-only benchmarks) |
| `4` | `base` or `candidate` failed A/A determinism, or a mask failed canary verification |
| `5` | Driver `probe` failed |
| `6` | `climb` correctness held, but metric improvement was not significant or below `--min-effect` |
| `7` | `inconclusive` (0 ops, 0 valid comparisons, identical harness failures on both sides, executable changed-line coverage below `--min-cov-ratio`, missing required observation, missing required workflow, or missing required mutations) |
| `8` | `timeout` (a driver step or infinite loop exceeded `--timeout-ms`) |
