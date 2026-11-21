# Using emi

This guide walks through how to set up and use `emi` day-to-day, in CI, and with custom drivers.

## 1. Build and sanity-check

```bash
cargo build --release
./target/release/emi sim --seeds 1000
```

Put `target/release/emi` on your `PATH` (or invoke it directly). Everything runs locally with zero external dependencies.

## 2. Initialize a repository

`emi` reads its rules, masks, observable-effect declarations, and regression cases from the **pinned base commit** (`git show <base>:.emi/ratchet.json`), never from the working tree. That way, an agent editing the working tree cannot loosen its own rules.

Start in `observe` mode while you get comfortable, then switch to `enforce`:

```bash
emi ratchet init --repo . --mode observe --allow-head
git add .emi/ratchet.json
git commit -m "init emi ratchet"
```

Common options you can pin at init time (or edit directly in `.emi/ratchet.json` and commit on your base branch):

- `--mode observe|enforce|off`
- `--driver "<CMD>"` — custom driver command if you aren't using the built-in Python driver
- `--metric "<CMD>"` — default benchmark command for `emi climb`
- `--observe-file <PATH>` — repeatable; relative file path whose existence and SHA-256 bytes `emi` compares after every step
- `--require-observation <NAME>` — repeatable; named observation key that a driver must emit in `Trace.observations` (for example `rows_after_reopen`)
- `--require-mutations` — require AST mutation evidence on executable changed lines before returning `pass`

## 3. Checking a change locally

Compare your working tree against a protected base ref (`--base`, `EMI_BASE_REV`, or `origin/main`). For scratch work on a repo with no remote yet, pass `--allow-head`:

```bash
emi diff --repo . --base origin/main --parity --strict --seeds 48
```

What happens:

1. `emi` materializes `base` and your working tree into isolated temp directories.
2. It runs an A/A determinism check on both `base` and `candidate`. If either side returns different results on the same seed, it stops with exit `4` (`nondeterministic`).
3. It extracts constants from the changed files, generates call sequences (plus any triggered pinned incidents), runs both versions, and shrinks any behavioral divergence down to the smallest reproducing call.
4. It checks coverage only against **executable** changed lines (comments, blank lines, and Python docstrings are excluded, so a docstring-only edit passes with `0/0` executable lines).

### Reading the verdict

- **Exit `0` (`pass`)**: behavior matched (or every difference matched a pinned approval), executable changed lines were exercised, and all required observations/mutations were present.
- **Exit `3` (`parity_fail`)**: `emi` found a real unapproved behavioral difference, a broken public signature, or a surviving planted bug. Inspect the printed minimized call, `base` payload, and `candidate` payload.
- **Exit `7` (`inconclusive`)**: `emi` did **not** find a regression, but it also didn't have enough evidence to say green. Common causes:
  - `0` public operations discovered
  - `0` valid comparisons ran
  - `0` executable changed lines were executed
  - a declared `--require-observation` key was missing from the driver trace
  - `--require-mutations` is enabled, but no mutation run was attached

In CI, treat exit `3` as "regression found" and exit `7` as "needs a better check, driver, or mutation run."

## 4. Approving intentional behavior changes

Never approve an entire input range blindly. When a change is intentional, pair the input predicate (`--when`) with the expected output relation (`--expect`):

```bash
emi ratchet lock-rule --repo . --allow-head \
  --op "pricing.py::price" \
  --when "1000 <= price_input <= 5000" \
  --expect "candidate_price == base_price - 10"
```

Supported expressions in `--when` and `--expect`:

- Inputs: `arg0`, `arg1`, … (or `input` / `*_input` for single-arg ops)
- Outputs: `base` / `base_*`, `cand` / `candidate` / `cand_*` / `candidate_*`
- Status flags: `base_ok`, `cand_ok`, `base_missing`, `cand_missing` (useful for brand-new functions, e.g. `--expect "base_missing && cand == arg0 + 1"`)
- Operators: `+`, `-`, `*`, `/`, parentheses, chained comparisons (`1000 <= arg0 <= 5000`), `==`, `!=`, `<`, `<=`, `>`, `>=`, `&&`, `||`, `!`

If a change also modifies observed files/logs or doesn't fit a relation, approve the exact witnessed diff ID printed by `emi diff`:

```bash
emi ratchet approve <DIFF_ID>
```

Commit `.emi/ratchet.json` on your base branch to pin the rule or approval.

## 5. Remembering real bugs

Whenever you catch a bug (from production or from `emi diff` / `emi adversary`), pin its call sequence in `.emi/ratchet.json` so it always replays whenever matching files change:

```bash
emi ratchet remember --repo . --allow-head \
  --id "stale-expire" \
  --trigger "cache/*.py" \
  --seed 42 \
  --ops '[{"op":"cache/store.py::Store.put","args":["k1",1]},{"op":"cache/store.py::Store.expire","args":["k1"]}]'
```

## 6. Checking observable effects (files & custom observations)

### Files (no custom driver needed)

If a function writes a journal, config, or output file, declare it with `--observe-file` (or in `.emi/ratchet.json` under `"observed_files"`):

```bash
emi diff --repo . --base origin/main --parity --observe-file journal.log
```

Before every step, `emi` snapshots `journal.log`, runs the step, hashes the resulting file (`exists`, `size`, `sha256`) into `observations["file:journal.log"]`, and restores the pre-step file so subsequent steps and A/A checks stay isolated. Any byte difference shows up as a `parity_fail`.

### Custom driver observations (e.g., databases)

For effects like reopen durability (`rows_after_reopen`), have your trusted driver include an `"observations"` object in its `step` response and require the key in `.emi/ratchet.json`:

```json
{
  "required_observations": ["rows_after_reopen"]
}
```

If the driver omits `rows_after_reopen`, both `emi diff` and `emi climb` return `inconclusive` (exit `7`) instead of passing or accepting a speedup.

## 7. Recommended CI workflow (evidence-bound stamping)

Run `diff` once with your full request budget and save the evidence record, then let `ratchet stamp` verify and sign that exact decision. Do **not** let `stamp` silently rerun a smaller budget.

### Single-step diff + mutations, then stamp

```bash
emi diff --repo . --base "$BASE_SHA" --seeds 48 --parity --strict \
  --with-adversary --max-faults 8 \
  --evidence-out .emi/evidence.json

EMI_SIGNING_KEY="$CI_SIGNING_KEY" \
  emi ratchet stamp --repo . --base "$BASE_SHA" --evidence .emi/evidence.json
```

### Two-step diff, then adversary, then stamp

```bash
emi diff --repo . --base "$BASE_SHA" --seeds 48 --parity --strict \
  --evidence-out .emi/evidence.json

emi adversary --repo . --base "$BASE_SHA" --max-faults 8 \
  --evidence .emi/evidence.json

EMI_SIGNING_KEY="$CI_SIGNING_KEY" \
  emi ratchet stamp --repo . --base "$BASE_SHA" --evidence .emi/evidence.json
```

What `stamp` verifies before signing:

- `base_sha` still matches `--base`
- `candidate_tree_sha256` still matches the current working tree
- `driver_digest` still matches the driver command/script
- `policy_digest` still matches pinned `.emi/ratchet.json`

If any file, driver, or policy changed after `emi diff`, `stamp` exits `2` (`stale evidence`) and refuses to stamp until you rerun `emi diff`.

## 8. Performance hillclimbing (`emi climb`)

Use `emi climb` when optimizing code so an agent can't trade correctness for speed or cheat the benchmark:

```bash
emi climb --repo . --base origin/main \
  --metric "python3 bench.py" \
  --runs 9 \
  --min-effect 0.05
```

`bench.py` just needs to print a single floating-point number to stdout (latency by default; pass `--maximize` for throughput).

What `climb` enforces before accepting:

1. Copies `bench.py` (and any `--metric-file`) from `base` into `candidate` so the candidate can't edit its own benchmark.
2. Runs `skeleton check --forbid-nondet`, A/A determinism, strict behavioral `diff` (including `observed_files` and `required_observations`), and AST planted bugs.
3. If the correctness floor fails -> `reject_floor` (exit `3`).
4. If required observations or required mutations are missing -> `inconclusive` (exit `7`), speedup is **not** accepted.
5. Runs interleaved `(base, candidate)` benchmark pairs in randomized order and computes a 95% bootstrap confidence interval (2,000 resamples). Accepts (exit `0`) only when the lower CI bound is strictly above `1.0x` and the median improvement meets `--min-effect`; otherwise `reject_metric` (exit `6`).

## 9. Writing a custom driver

For non-Python projects or stateful services/databases, pass `--driver "<CMD>"` (or pin `"driver"` in `.emi/ratchet.json`). Your driver is a long-lived process reading one JSON object per line on stdin and writing one JSON object per line on stdout (always flush stdout, and use `readline()` rather than buffered iteration).

### `probe` request and response

Input:
```json
{"verb":"probe"}
```

Output:
```json
{
  "ok": true,
  "fingerprint": "my-db-v1",
  "operations": [
    {"name": "put", "arity": 2, "stateful": true, "param_types": ["str", "int"], "kwarg_names": []},
    {"name": "get", "arity": 1, "stateful": true, "param_types": ["str"], "kwarg_names": []}
  ],
  "detail": "ok"
}
```

### `step` request and response

Input:
```json
{"verb":"step","seed":"42","ops":[{"op":"put","args":["k1",7]},{"op":"get","args":["k1"]}],"faults":[],"observed_files":[]}
```

Output:
```json
{
  "ok": true,
  "outcomes": [true, 7],
  "side_effects": [],
  "logs": [],
  "state_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "coverage": ["src/db.py:42", "src/db.py:55"],
  "observations": {"rows_after_reopen": 1},
  "error": null
}
```

Driver rules:

- Start every `step` from a clean, deterministic state seeded by `seed` (sent as a decimal string so 64-bit seeds stay exact).
- Never crash the driver when a symbol is missing; return an error outcome entry so `emi` reports it as a behavioral diff.
- Respect `--timeout-ms` (default `5000` ms per call).

## 10. Exit codes

| Code | Meaning |
|---:|---|
| `0` | Pass / accept |
| `2` | Usage error, stale evidence, unprotected `HEAD` in enforce mode, or driver crash/timeout |
| `3` | Regression (`parity_fail`), broken skeleton, surviving planted bug, or `climb` correctness floor failed |
| `4` | `base` or `candidate` failed A/A determinism, or a mask failed canary verification |
| `5` | Driver `probe` failed |
| `6` | `climb` correctness held, but metric improvement was not significant or below `--min-effect` |
| `7` | `inconclusive` (0 ops, 0 valid comparisons, 0 executed executable lines, missing required observation, or missing required mutations) |
