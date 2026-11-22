# Using emi

This guide explains how to run `emi` in cloud AI sessions, in an agentic coding loop, in CI, with whole-program `--cmd` checks, with `--report-diff` PR reviews, and with custom language/service drivers.

## 1. Install and verify the binary

Linux / macOS (static musl binaries on Linux — works in cloud sandboxes with no Rust toolchain):
```bash
curl -fsSL https://raw.githubusercontent.com/andrejksi/emiv2/main/install.sh | sh
```

Windows (PowerShell):
```powershell
irm https://raw.githubusercontent.com/andrejksi/emiv2/main/install.ps1 | iex
```

Or install directly via Cargo (`cargo install --force --git https://github.com/andrejksi/emiv2`) or Docker (`docker build -t emi https://github.com/andrejksi/emiv2.git`).

Verify your install:
```bash
emi sim --seeds 1000
```

`emi sim` runs 1,000 seeded in-memory DST worlds plus 65 effectful and black-box CLI worlds that invoke the compiled `emi` binary end-to-end against trust-boundary scenarios, whole-program `--cmd` checks, `--report-diff` summaries, Node/TS & Python repo layouts, and field regressions.

## 2. Initialize a repository

`emi` reads all policy, commands, rules, masks, observable-effect declarations, and regression cases from the **pinned base commit** (`git show <base>:.emi/ratchet.json`), never from the candidate working tree.

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
- `--cmd "<CMD>"` — repeatable; whole-program commands to compare on `base` vs `candidate` (any language)
- `--min-cov-ratio <0.0..=1.0>` — share of executable changed lines that must be covered in function-level mode (default `0.5`, i.e. 50%)
- `--driver "<CMD>"` — custom JSONL driver command
- `--metric "<CMD>"` — default benchmark command for `emi climb`
- `--observe-file <PATH>` — repeatable; file whose existence, size, and SHA-256 `emi` compares after every step
- `--require-observation <NAME>` — repeatable; named observation key required in `Trace.observations` (e.g. `rows_after_reopen`)
- `--require-workflow <ID>` — repeatable; named workflow ID (registered via `emi ratchet remember --id <ID> ...`) that must execute before `check` passes or `ratchet stamp` issues an attestation
- `--require-mutations` — require AST mutation evidence on executable changed lines before returning `pass`

## 3. Whole-program `--cmd` mode (any language)

When you want to verify a CLI, script, build output, or end-to-end workflow instead of probing individual functions, pass one or more `--cmd` flags (or pin them with `emi ratchet init --cmd ...`):

```bash
emi check --repo . --base origin/main \
  --cmd "python3 app.py --mode batch input.json" \
  --cmd "python3 app.py --mode summary input.json" \
  --observe-file out/result.json \
  --json
```

How `--cmd` works:
- Runs each command in isolated `base` and `candidate` snapshots (with `EMI*` env vars stripped, deterministic `TZ`/`LC_ALL`/`PYTHONHASHSEED`, and `<repo>/node_modules` symlinked).
- Verifies A/A determinism on both sides first, scrubs temporary snapshot paths from stdout/stderr, compares exit code, stdout, stderr, and any `--observe-file` hashes, and enforces `--timeout-ms` with full process-group kill.
- Works with `emi replay`, `--with-adversary` (AST mutations against your commands), and `emi climb`.
- In `enforce` mode, CLI `--cmd` overrides are forbidden (commands must be pinned in `.emi/ratchet.json` on `base`), and any harness scripts under `.emi/` referenced in pinned commands are overlaid from `base` so the candidate cannot rig them.

## 4. Review behavioral diffs on feature / bug-fix PRs (`--report-diff`)

By default `emi check` is a strict refactor gate: any unapproved behavioral change exits `3` (`parity_fail`). For feature PRs or bug fixes where behavior *should* change, pass `--report-diff`:

```bash
emi check --repo . --base origin/main --report-diff --json
```

- Exits `0` with `verdict: "behavior_changed"`, `behavior_changed: true`, `skeleton_diff`, and shrunk minimal input/output witnesses showing what changed between `base` and `candidate`.
- Still fails if A/A determinism breaks (exit `4`), probe fails (exit `5`), coverage is insufficient (exit `7`), or execution times out (exit `8`).
- Strict `emi ratchet stamp --strict` (or `enforce` mode) refuses to pass a `behavior_changed` evidence record (exits `3`), so review mode cannot bypass a strict refactor gate.

## 5. The agentic inner loop (`emi check` + `emi replay`)

Give your coding agent one command as its verification gate:

```bash
emi check --repo . --base origin/main --seeds 48 --json
```

`emi check` runs the full pipeline in one shot:
1. Skeleton check (multi-line signature public API + comment/string-stripped nondeterminism sites)
2. Strict behavioral diff (`--strict` is the default; pass `--no-strict` to disable)
3. AST adversary mutations (enabled automatically in `enforce` mode, when `require_mutations` is set, or with `--with-adversary`)
4. Writes `.emi/evidence.json` (signed with HMAC-SHA256 when `EMI_SIGNING_KEY` or `--key-file` is set, and always checksummed with `record_digest_sha256`), including `observed_files`, `workflows_run`, `ops_exercised`, `observed_outputs`, and deleted-line coverage.

Every `--json` response includes explicit machine fields:

- `verdict`: `pass` | `behavior_changed` | `parity_fail` | `skeleton_break` | `inconclusive` | `nondeterministic` | `leaky_mask` | `probe_failed` | `timeout`
- `exit_code`: `0`, `3`, `4`, `5`, `7`, or `8`
- `blocker`: `none` | `behavior_changed` | `regression` | `rule_violation` | `surviving_mutant` | `skeleton_break` | `nondet_site` | `nondeterministic` | `leaky_mask` | `probe_failed` | `timeout` | `missing_observation` | `missing_workflow` | `zero_ops` | `zero_comparisons` | `insufficient_coverage` | `missing_mutations`
- `next_action`: `ready_to_stamp` | `review_behavior_diff` | `fix_regression_and_replay` | `fix_rule_expectation_and_replay` | `kill_surviving_mutant` | `remove_nondeterminism` | `add_required_observation` | `add_or_run_required_workflow` | `increase_coverage_or_driver_ops` | `run_with_adversary` | `fix_public_api_break` | `fix_driver_probe` | `fix_timeout_or_infinite_loop`
- `base_seed`: PRNG seed (`--seed <U64>`, distinct from `--seeds <N>` sequence budget) recorded in both `--json` output and `.emi/evidence.json`
- `replay_cmd`: exact `emi replay` command when unapproved witnesses exist

### Fast witness iteration (`emi replay`)

When `emi check` fails (exit `3`), replay only the minimized failing witness(es) in ~100ms:

```bash
emi replay --repo . --base origin/main --evidence .emi/evidence.json --json
```

`emi replay` automatically reuses the effective `observed_files` recorded in `.emi/evidence.json`. Once `emi replay` exits `0`, re-run `emi check` for full parity + coverage + mutation verification.

### Drop-in `AGENTS.md` snippet

```markdown
## Verification
Use `emi` alongside your repo's test suite as an independent behavioral oracle:
1. For refactors/optimizations: run `emi check --repo . --base origin/main --json` (or pass `--cmd "<command>"` for CLI/whole-program checks).
2. If exit code is 3 and `replay_cmd` is present, iterate with `emi replay --repo . --base origin/main --json` until it exits 0, then re-run `emi check`.
3. If exit code is 7 (`inconclusive`), inspect `blocker` (`insufficient_coverage`, `missing_observation`, `missing_workflow`, `missing_mutations`, `zero_ops`) before finishing.
4. For intentional feature changes or bug fixes: run `emi check --repo . --base origin/main --report-diff --json` and include the minimized behavioral diff in your summary.
```

## 6. Approving intentional behavior changes (`--expect` and `--must-hold`)

Pair every input predicate (`--when`) with an expected output relation (`--expect`). Input-only rules without `--expect` are rejected:

```bash
emi ratchet lock-rule --repo . --allow-head \
  --op "pricing.py::price" \
  --when "1000 <= price_input <= 5000" \
  --expect "candidate_price == base_price - 10" \
  --must-hold
```

- **Rule-safe shrinking:** `emi` evaluates approval rules on the original input before shrinking. An unapproved regression outside the rule's range (e.g. at `x = 6000`) will never be shrunk into the approved `1000..5000` range and hidden.
- **`--must-hold`:** checks the `--expect` relation even when `base` and `candidate` agree.
- **Exception comparison:** exceptions compare by type (`ValueError` vs `TypeError`), ignoring reworded message strings.
- **Exact hash approval:** for a one-off change that also alters observed files or logs, approve the exact witnessed diff ID with `emi ratchet approve <DIFF_ID>`.

## 7. Observable effects (files & custom driver observations)

### Files (`--observe-file`)

Declare files in `.emi/ratchet.json` (`"observed_files"`) or via `--observe-file journal.log`. Before each step, `emi` snapshots the file, runs the step, hashes `exists`, `size`, and `sha256` into `observations["file:<path>"]`, and restores the pre-step file so A/A determinism and subsequent steps remain isolated.

### Named driver observations (`--require-observation`)

For database durability or service invariants (e.g. `rows_after_reopen`), have your driver emit `"observations": {"rows_after_reopen": 5}` and pin `"required_observations": ["rows_after_reopen"]` in `.emi/ratchet.json`. If the key is missing, both `emi check`/`diff` and `emi climb` return `inconclusive` (exit `7`).

## 8. Evidence signing and `ratchet stamp` in CI

**CI must fix the base commit on a clean checkout.** Pass the exact 40-character base commit SHA from your CI runner (`--base "$BASE_SHA"`). In `enforce` mode, `emi` refuses `EMI_BASE_REV`, locally moved refs, CLI `--driver`/`--cmd` overrides, and requires a signing key (`EMI_SIGNING_KEY` or `--key-file`) for `ratchet stamp`.

```bash
EMI_SIGNING_KEY="$CI_SIGNING_KEY" \
  emi check --repo . --base "$BASE_SHA" --seeds 48 --evidence-out .emi/evidence.json --json

EMI_SIGNING_KEY="$CI_SIGNING_KEY" \
  emi ratchet stamp --repo . --base "$BASE_SHA" --evidence .emi/evidence.json
```

Before stamping, `stamp` verifies:
- `base_sha`, `candidate_tree_sha256`, `driver_digest`, and `policy_digest` match the live repo (otherwise exit `2`: `stale evidence`)
- `record_digest_sha256` is present and matches canonical fields
- `hmac_sha256` matches `EMI_SIGNING_KEY`
- Internal consistency (rejects `"verdict": "pass"` if `unapproved_diffs > 0`, `skeleton_ok == false`, `aa_verified == false`, changed-line or deleted-line coverage fails policy, required workflows omitted, or required mutations missing)

## 9. Performance hillclimbing (`emi climb`)

```bash
emi climb --repo . --base "$BASE_SHA" --metric "python3 bench.py" --runs 9 --min-effect 0.05
```

`bench.py` **must emit both a timing metric and an output/checksum** (time-only benchmarks are rejected with `reject_floor`, exit `3`):
- JSON with both metric and correctness output: `{"metric": 12.34, "output": <checksum_or_value>}`, OR
- Line 1 float followed by output/checksum lines (`12.34\nchecksum=abc`).

`climb` overlays `base`'s `bench.py` into `candidate`, enforces timeouts + process-group kill on every benchmark run (60s default, or `--timeout-ms`), checks skeleton + parity + observations + AST mutations, compares benchmark output digests across every `base` and `candidate` run, and only accepts (exit `0`) when the interleaved 95% bootstrap CI is strictly above `1.0x` and meets `--min-effect`.

## 10. Built-in drivers (Python & Node.js/TypeScript)

When `--driver` and `--cmd` are not set, `emi` selects the built-in driver from the changed files first (falling back to repo scan skipping `scripts/`, `docs/`, `tests/`):

- **Python**:
  - Supports both flat and `src/` package layouts, isolates stdlib imports, and fails fast with `probe_failed` on top-level `json.py` shadowing.
  - Separates EMI's internal JSONL protocol channel onto a dedicated file descriptor and captures program `stdout`/`stderr` plus `SystemExit`.
  - Runs fresh forked children (`os.fork()`) during A/A verification before safely preloading heavy single-threaded modules so import-time nondeterminism is caught accurately.
  - Counts module-level lines executed at import as covered, scrubs memory addresses, compares exception types, and supports `@classmethod def __emi_init__(cls)` / `emi_factory()`.
- **Node.js / TypeScript** (`.ts`, `.mts`, `.tsx`, `.js`, `.mjs`, `.cjs`):
  - Symlinks `<repo>/node_modules` into snapshots without mutating the repo's `node_modules`.
  - Resolves TypeScript ESM `.js`→`.ts`/`.mts` and extensionless relative imports via Node 22+ `module.registerHooks`.
  - Runs each step in a fresh Node worker process with a separate fd 3 protocol channel, collects V8 precise line coverage, normalizes error types, and snapshots/restores `observed_files`.

## 11. Scaffolding custom drivers (`emi driver init`)

For **Go and Rust (experimental)** or custom service/database harnesses:

```bash
emi driver init --repo . --lang go --pin
git add .emi/ && git commit -m "pin emi driver"
```

Supported `--lang` values: `python`, `node`, `ts`, `go`, `rust`.

JSONL protocol on stdio:
- `probe`: reads `{"verb":"probe"}`, writes `{"ok":true,"fingerprint":"v1","operations":[{"name":"put","arity":2,"stateful":true,"param_types":["str","int"],"kwarg_names":[]}],"detail":"ok"}`
- `step`: reads `{"verb":"step","seed":"42","ops":[{"op":"put","args":["k1",7]}],"faults":[],"observed_files":[]}`, writes `{"ok":true,"outcomes":[true],"side_effects":[],"logs":[],"state_digest":"<sha256>","coverage":["src/db.rs:42"],"observations":{"rows_after_reopen":1},"error":null}`

## 12. Exit codes

| Code | Meaning |
|---:|---|
| `0` | Pass / accept / `behavior_changed` (with `--report-diff`) |
| `2` | Usage error, stale/tampered/unsigned/inconsistent evidence, missing `record_digest_sha256`, missing signing key in enforce mode, locally moved base ref or `EMI_BASE_REV` in enforce mode, `--driver`/`--cmd` override in enforce mode, unprotected `HEAD` in enforce mode, benchmark timeout in `climb`, or driver crash |
| `3` | Regression (`parity_fail`), `must_hold` rule violation, broken skeleton, surviving planted bug, `behavior_changed` rejected by strict `ratchet stamp`, or `climb` floor/benchmark-output failure |
| `4` | `base` or `candidate` failed A/A determinism, or a mask failed canary verification |
| `5` | Driver `probe` failed |
| `6` | `climb` correctness held, but metric improvement was not significant or below `--min-effect` |
| `7` | `inconclusive` (0 ops, 0 valid comparisons, identical harness failures on both sides, changed-line or deleted-line coverage below policy, missing required observation, missing required workflow, or missing required mutations) |
| `8` | `timeout` (driver startup/probe exceeded `--probe-timeout-ms` [default `30000` ms] or a step/command/infinite loop exceeded `--timeout-ms` [default `5000` ms]) |
