use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::adversary::{FaultStatus, PlantedFault, prove_oracle, synthesize_ast_faults};
use crate::climb::{
    BenchSample, ClimbVerdict, Direction, FloorChecks, evaluate_climb, measure_interleaved,
    parse_bench_output, verify_benchmark_parity,
};
use crate::diff::{ConstantPool, DiffConfig, Verdict, run_diff};
use crate::git;
use crate::json::{self, Value};
use crate::prng::Prng;
use crate::protocol::{
    Driver, Mask, OpSpec, ProbeResult, ProcessDriver, StepOp, StepRequest, Trace,
    compute_driver_digest, materialize_auto_driver, seed_from_json, seed_to_json,
};
use crate::ratchet::{
    ApprovalRule, Attestation, EnforceMode, EvidenceRecord, IncidentSeed, RatchetState,
    load_evidence, save_evidence_signed,
};
use crate::sha256;
use crate::skeleton;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SimBehavior {
    Clean,
    StaleExpireBug,
    BoundaryBug,
    Range1000To5000Bug,
    Range1000To5000Minus10,
    Range1000To5000Minus10PlusBugAt6000,
    NondetLeak,
    ProbeDown,
    MaskedTimestamp,
    EmptyOps,
    DbReopenObserved(i64),
}

struct SimKvDriver {
    behavior: SimBehavior,
    call_counter: u64,
}

impl SimKvDriver {
    fn new(behavior: SimBehavior) -> Self {
        Self {
            behavior,
            call_counter: 0,
        }
    }
}

impl Driver for SimKvDriver {
    fn probe(&mut self) -> Result<ProbeResult, String> {
        if self.behavior == SimBehavior::ProbeDown {
            return Ok(ProbeResult {
                ok: false,
                fingerprint: "sim-down".to_owned(),
                operations: Vec::new(),
                detail: "simulated environment outage".to_owned(),
            });
        }
        if self.behavior == SimBehavior::EmptyOps {
            return Ok(ProbeResult {
                ok: true,
                fingerprint: "sim-empty".to_owned(),
                operations: Vec::new(),
                detail: "empty".to_owned(),
            });
        }
        Ok(ProbeResult {
            ok: true,
            fingerprint: "sim-kv-v2".to_owned(),
            operations: vec![
                OpSpec {
                    name: "put".to_owned(),
                    arity: 2,
                    stateful: true,
                    param_types: vec!["str".to_owned(), "int".to_owned()],
                    kwarg_names: Vec::new(),
                },
                OpSpec {
                    name: "get".to_owned(),
                    arity: 1,
                    stateful: true,
                    param_types: vec!["str".to_owned()],
                    kwarg_names: Vec::new(),
                },
                OpSpec {
                    name: "expire".to_owned(),
                    arity: 1,
                    stateful: true,
                    param_types: vec!["str".to_owned()],
                    kwarg_names: Vec::new(),
                },
                OpSpec {
                    name: "clamp".to_owned(),
                    arity: 1,
                    stateful: false,
                    param_types: vec!["int".to_owned()],
                    kwarg_names: Vec::new(),
                },
            ],
            detail: "sim-ok".to_owned(),
        })
    }

    fn step(&mut self, req: &StepRequest) -> Result<Trace, String> {
        self.call_counter = self.call_counter.wrapping_add(1);
        let mut store: BTreeMap<String, i64> = BTreeMap::new();
        let mut shadow: BTreeMap<String, i64> = BTreeMap::new();
        let mut outcomes = Vec::with_capacity(req.ops.len());
        let mut logs = Vec::new();
        let mut cov = BTreeSet::new();
        let mut observations = BTreeMap::new();

        for (step_idx, op) in req.ops.iter().enumerate() {
            let cancelled = req
                .faults
                .iter()
                .any(|f| f.at_step == step_idx && f.kind == "cancel");
            if cancelled {
                cov.insert("branch:cancel".to_owned());
                outcomes.push(Value::Str("cancelled".to_owned()));
                continue;
            }
            match op.op.as_str() {
                "put" => {
                    cov.insert("op:put".to_owned());
                    let k = key_of(op.args.first());
                    let v = int_of(op.args.get(1));
                    if let Some(prev) = store.insert(k.clone(), v) {
                        shadow.insert(k, prev);
                    }
                    outcomes.push(Value::Bool(true));
                }
                "get" => {
                    cov.insert("op:get".to_owned());
                    let k = key_of(op.args.first());
                    match store.get(&k) {
                        Some(v) => outcomes.push(Value::Int(*v)),
                        None => outcomes.push(Value::Null),
                    }
                }
                "expire" => {
                    cov.insert("op:expire".to_owned());
                    let k = key_of(op.args.first());
                    let removed = store.remove(&k).is_some();
                    if self.behavior == SimBehavior::StaleExpireBug {
                        if let Some(old) = shadow.remove(&k) {
                            store.insert(k, old);
                        }
                    } else {
                        shadow.remove(&k);
                    }
                    outcomes.push(Value::Bool(removed));
                }
                "clamp" => {
                    cov.insert("op:clamp".to_owned());
                    let x = int_of(op.args.first());
                    let clamped = match self.behavior {
                        SimBehavior::BoundaryBug => {
                            if x < 0 {
                                0
                            } else if x >= 100 {
                                99
                            } else {
                                x
                            }
                        }
                        SimBehavior::Range1000To5000Bug => {
                            if (1000..=5000).contains(&x) {
                                -1
                            } else {
                                x.clamp(0, 100)
                            }
                        }
                        SimBehavior::Range1000To5000Minus10 => {
                            if (1000..=5000).contains(&x) {
                                x.clamp(0, 100) - 10
                            } else {
                                x.clamp(0, 100)
                            }
                        }
                        SimBehavior::Range1000To5000Minus10PlusBugAt6000 => {
                            if x >= 6000 {
                                -777
                            } else if (1000..=5000).contains(&x) {
                                x.clamp(0, 100) - 10
                            } else {
                                x.clamp(0, 100)
                            }
                        }
                        _ => x.clamp(0, 100),
                    };
                    outcomes.push(Value::Int(clamped));
                }
                other => {
                    outcomes.push(Value::Str(format!("unknown:{other}")));
                }
            }
        }

        if self.behavior == SimBehavior::NondetLeak {
            logs.push(format!("tick={}", self.call_counter));
        }
        if self.behavior == SimBehavior::MaskedTimestamp {
            logs.push(format!("ts=T{}|count={}", self.call_counter, store.len()));
        }
        if let SimBehavior::DbReopenObserved(rows) = self.behavior {
            observations.insert("rows_after_reopen".to_owned(), Value::Int(rows));
        }

        let state_str = Value::Array(
            store
                .iter()
                .map(|(k, v)| Value::obj(vec![("k", Value::Str(k.clone())), ("v", Value::Int(*v))]))
                .collect(),
        )
        .canonical();
        let state_digest = sha256::hex(state_str.as_bytes());
        Ok(Trace {
            ok: true,
            outcomes,
            side_effects: Vec::new(),
            logs,
            state_digest,
            coverage: cov,
            observations,
            error: None,
        })
    }
}

fn key_of(v: Option<&Value>) -> String {
    match v {
        Some(Value::Str(s)) => {
            if s.is_empty() {
                "k0".to_owned()
            } else {
                s.clone()
            }
        }
        Some(Value::Int(i)) => format!("k{}", i.rem_euclid(2)),
        _ => "k0".to_owned(),
    }
}

fn int_of(v: Option<&Value>) -> i64 {
    match v {
        Some(Value::Int(i)) => *i,
        Some(Value::Bool(true)) => 1,
        _ => 0,
    }
}

#[derive(Clone, Debug)]
pub struct SimSummary {
    pub ok: bool,
    pub seeds_run: usize,
    pub worlds_verified: usize,
    pub effectful_worlds: usize,
    pub failed_seed: Option<u64>,
    pub failure: Option<String>,
    pub digest: String,
}

impl SimSummary {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("ok", Value::Bool(self.ok)),
            ("seeds_run", Value::Int(self.seeds_run as i64)),
            ("worlds_verified", Value::Int(self.worlds_verified as i64)),
            ("effectful_worlds", Value::Int(self.effectful_worlds as i64)),
            (
                "failed_seed",
                self.failed_seed
                    .map_or(Value::Null, |s| Value::Str(s.to_string())),
            ),
            (
                "failure",
                self.failure
                    .as_ref()
                    .map_or(Value::Null, |f| Value::Str(f.clone())),
            ),
            ("digest", Value::Str(self.digest.clone())),
        ])
    }
}

pub fn run_simulation(seed_start: u64, count: usize, include_effectful: bool) -> SimSummary {
    assert!(count > 0 && count <= 100_000);
    let mut worlds_verified = 0usize;
    let mut hash_acc = String::new();

    for offset in 0..count {
        let seed = seed_start.wrapping_add(offset as u64);
        match verify_seed(seed) {
            Ok((checked, sig)) => {
                worlds_verified += checked;
                hash_acc.push_str(&sig);
            }
            Err(why) => {
                return SimSummary {
                    ok: false,
                    seeds_run: offset + 1,
                    worlds_verified,
                    effectful_worlds: 0,
                    failed_seed: Some(seed),
                    failure: Some(why),
                    digest: sha256::short_hex(hash_acc.as_bytes()),
                };
            }
        }
    }

    let mut effectful_worlds = 0usize;
    if include_effectful {
        match run_effectful_worlds(seed_start) {
            Ok(n) => {
                effectful_worlds = n;
                worlds_verified += n;
                hash_acc.push_str(&format!("eff:{n}"));
            }
            Err(why) => {
                return SimSummary {
                    ok: false,
                    seeds_run: count,
                    worlds_verified,
                    effectful_worlds,
                    failed_seed: Some(seed_start),
                    failure: Some(format!("effectful world failed: {why}")),
                    digest: sha256::short_hex(hash_acc.as_bytes()),
                };
            }
        }
    }

    SimSummary {
        ok: true,
        seeds_run: count,
        worlds_verified,
        effectful_worlds,
        failed_seed: None,
        failure: None,
        digest: sha256::short_hex(hash_acc.as_bytes()),
    }
}

fn verify_seed(seed: u64) -> Result<(usize, String), String> {
    let mut prng = Prng::new(seed);
    let scenario = prng.range_u64(11);
    let mut checked = 0usize;
    let mut sig = String::new();

    match scenario {
        0 => {
            let mut base = SimKvDriver::new(SimBehavior::Clean);
            let mut cand = SimKvDriver::new(SimBehavior::Clean);
            let cfg = DiffConfig {
                seeds: 12,
                base_seed: seed,
                max_seq_len: 6,
                parity: true,
                strict: true,
                ..DiffConfig::default()
            };
            let report = run_diff(&mut base, &mut cand, &cfg);
            if report.verdict != Verdict::Pass
                || !report.aa_verified
                || !report.divergences.is_empty()
            {
                return Err(format!("clean parity world failed: {}", report.detail));
            }
            sig.push_str(&format!("0:{}", report.sequences_run));
            checked += 1;
        }
        1 => {
            let mut base = SimKvDriver::new(SimBehavior::Clean);
            let mut cand = SimKvDriver::new(SimBehavior::Range1000To5000Bug);
            let pool = ConstantPool::from_sources(&["if 1000 <= x <= 5000: return -1"]);
            let cfg = DiffConfig {
                seeds: 32,
                base_seed: seed,
                max_seq_len: 4,
                parity: true,
                constants: pool,
                inject_faults: false,
                ..DiffConfig::default()
            };
            let report = run_diff(&mut base, &mut cand, &cfg);
            if report.verdict != Verdict::ParityFail || report.divergences.is_empty() {
                return Err(
                    "1000..5000 threshold bug escaped constant-seeded generator".to_owned()
                );
            }
            let min_ops = report.divergences.iter().map(|d| d.ops.len()).min().unwrap();
            if min_ops != 1 {
                return Err(format!(
                    "shrinker failed to minimize threshold bug to 1 op: {min_ops}"
                ));
            }
            sig.push_str(&format!("1:{min_ops}"));
            checked += 1;
        }
        2 => {
            let mut base = SimKvDriver::new(SimBehavior::NondetLeak);
            let mut cand = SimKvDriver::new(SimBehavior::Clean);
            let cfg = DiffConfig {
                seeds: 6,
                base_seed: seed,
                parity: true,
                ..DiffConfig::default()
            };
            let report = run_diff(&mut base, &mut cand, &cfg);
            if report.verdict != Verdict::Nondeterministic
                || report.aa_verified
                || report.sequences_run != 0
            {
                return Err("A/A gate failed to block nondeterministic base".to_owned());
            }
            let mut base2 = SimKvDriver::new(SimBehavior::Clean);
            let mut cand2 = SimKvDriver::new(SimBehavior::NondetLeak);
            let report2 = run_diff(&mut base2, &mut cand2, &cfg);
            if report2.verdict != Verdict::Nondeterministic || report2.aa_verified {
                return Err("A/A gate failed to block nondeterministic candidate".to_owned());
            }
            sig.push_str("2:aa");
            checked += 1;
        }
        3 => {
            let mut base = SimKvDriver::new(SimBehavior::ProbeDown);
            let mut cand = SimKvDriver::new(SimBehavior::Clean);
            let cfg = DiffConfig {
                seeds: 4,
                base_seed: seed,
                parity: true,
                ..DiffConfig::default()
            };
            let report = run_diff(&mut base, &mut cand, &cfg);
            if report.verdict != Verdict::ProbeFailed {
                return Err("probe failure was not caught".to_owned());
            }
            sig.push_str("3:probe");
            checked += 1;
        }
        4 => {
            let mut base = SimKvDriver::new(SimBehavior::MaskedTimestamp);
            let mut cand = SimKvDriver::new(SimBehavior::MaskedTimestamp);
            let narrow = Mask {
                name: "ts".to_owned(),
                prefix: "ts=".to_owned(),
                max_len: 12,
            };
            let cfg_ok = DiffConfig {
                seeds: 6,
                base_seed: seed,
                parity: true,
                masks: vec![narrow],
                ..DiffConfig::default()
            };
            let rep_ok = run_diff(&mut base, &mut cand, &cfg_ok);
            if rep_ok.verdict != Verdict::Pass || !rep_ok.masks_proven {
                return Err(format!("valid narrow mask rejected: {}", rep_ok.detail));
            }
            let wide = Mask {
                name: "too_wide".to_owned(),
                prefix: "ts=".to_owned(),
                max_len: 999,
            };
            let cfg_bad = DiffConfig {
                seeds: 4,
                base_seed: seed,
                parity: true,
                masks: vec![wide],
                ..DiffConfig::default()
            };
            let rep_bad = run_diff(&mut base, &mut cand, &cfg_bad);
            if rep_bad.verdict != Verdict::LeakyMask {
                return Err("overly wide mask was not rejected".to_owned());
            }
            sig.push_str("4:mask");
            checked += 1;
        }
        5 => {
            let mut cand = SimKvDriver::new(SimBehavior::Clean);
            let weak_oracle = vec![StepRequest {
                seed,
                ops: vec![StepOp::simple("clamp", vec![Value::Int(50)])],
                faults: Vec::new(),
                observed_files: Vec::new(),
                workflow_id: None,
            }];
            let pool = ConstantPool::from_sources(&["if x >= 100: return 99"]);
            let faults = vec![PlantedFault {
                id: "boundary-100".to_owned(),
                description: "clamp(100) returns 99 instead of 100".to_owned(),
                driver: Box::new(SimKvDriver::new(SimBehavior::BoundaryBug)),
            }];
            let adv = prove_oracle(&mut cand, &weak_oracle, &[], faults, 32, &pool)?;
            if adv.survived_faults != 1 || adv.outcomes[0].status != FaultStatus::Survived {
                return Err(
                    "weak oracle failed to surface surviving planted bug with witness".to_owned(),
                );
            }
            let strong_oracle = vec![StepRequest {
                seed,
                ops: vec![StepOp::simple("clamp", vec![Value::Int(100)])],
                faults: Vec::new(),
                observed_files: Vec::new(),
                workflow_id: None,
            }];
            let faults2 = vec![PlantedFault {
                id: "boundary-100".to_owned(),
                description: "clamp(100) returns 99 instead of 100".to_owned(),
                driver: Box::new(SimKvDriver::new(SimBehavior::BoundaryBug)),
            }];
            let adv2 = prove_oracle(&mut cand, &strong_oracle, &[], faults2, 16, &pool)?;
            if adv2.killed_faults != 1 || adv2.survived_faults != 0 {
                return Err("strong oracle failed to kill planted bug".to_owned());
            }
            sig.push_str("5:adv");
            checked += 1;
        }
        6 => {
            let mut p = Prng::new(seed);
            let mut base_lat = Vec::with_capacity(12);
            let mut noise_same = Vec::with_capacity(12);
            let mut fast_lat = Vec::with_capacity(12);
            for _ in 0..12 {
                let jitter_a = (p.next_i64_range(-2, 2) as f64) * 0.5;
                let jitter_b = (p.next_i64_range(-2, 2) as f64) * 0.5;
                base_lat.push(100.0 + jitter_a);
                noise_same.push(100.0 + jitter_b);
                fast_lat.push(50.0 + jitter_b);
            }
            let unchanged = evaluate_climb(
                FloorChecks {
                    skeleton_ok: true,
                    aa_verified: true,
                    parity_ok: true,
                    planted_bugs_killed: true,
                    benchmark_output_ok: true,
                    inconclusive_reason: None,
                },
                &base_lat,
                &noise_same,
                Direction::Minimize,
                0.05,
            );
            if unchanged.verdict != ClimbVerdict::RejectMetric {
                return Err("climb falsely accepted noisy unchanged candidate".to_owned());
            }
            let broken_bench = evaluate_climb(
                FloorChecks {
                    skeleton_ok: true,
                    aa_verified: true,
                    parity_ok: true,
                    planted_bugs_killed: true,
                    benchmark_output_ok: false,
                    inconclusive_reason: None,
                },
                &base_lat,
                &fast_lat,
                Direction::Minimize,
                0.05,
            );
            if broken_bench.verdict != ClimbVerdict::RejectFloor
                || broken_bench.blocker != "benchmark_output_mismatch"
            {
                return Err("climb accepted candidate with mismatched benchmark output".to_owned());
            }
            let missing_obs_fast = evaluate_climb(
                FloorChecks {
                    skeleton_ok: true,
                    aa_verified: true,
                    parity_ok: true,
                    planted_bugs_killed: true,
                    benchmark_output_ok: true,
                    inconclusive_reason: Some(
                        "missing required observation: rows_after_reopen".to_owned(),
                    ),
                },
                &base_lat,
                &fast_lat,
                Direction::Minimize,
                0.05,
            );
            if missing_obs_fast.verdict != ClimbVerdict::Inconclusive
                || missing_obs_fast.verdict.exit_code() != 7
            {
                return Err(
                    "climb did not return inconclusive (exit 7) when required observation was missing"
                        .to_owned(),
                );
            }
            let clean_fast = evaluate_climb(
                FloorChecks {
                    skeleton_ok: true,
                    aa_verified: true,
                    parity_ok: true,
                    planted_bugs_killed: true,
                    benchmark_output_ok: true,
                    inconclusive_reason: None,
                },
                &base_lat,
                &fast_lat,
                Direction::Minimize,
                0.05,
            );
            if clean_fast.verdict != ClimbVerdict::Accept {
                return Err("climb rejected statistically significant 2x speedup".to_owned());
            }
            sig.push_str("6:climb");
            checked += 1;
        }
        7 => {
            let high_seed = (1u64 << 63) | seed;
            let roundtrip = seed_from_json(&seed_to_json(high_seed));
            if roundtrip != Some(high_seed) {
                return Err("64-bit high-bit seed lost bits in JSON roundtrip".to_owned());
            }
            let mut b_syms = Vec::new();
            let mut b_nd = Vec::new();
            skeleton::extract_file(
                "core.py",
                "def compute(x):\n    return x + 1\n",
                &mut b_syms,
                &mut b_nd,
            );
            let mut c_syms = Vec::new();
            let mut c_nd = Vec::new();
            skeleton::extract_file(
                "core.py",
                "def compute(x: int) -> int:\n    return x + 1\n",
                &mut c_syms,
                &mut c_nd,
            );
            let typed_diff = skeleton::compare(
                &skeleton::Skeleton {
                    symbols: b_syms,
                    nondet_sites: b_nd,
                    erosion_score: 0,
                    digest: "b".to_owned(),
                },
                &skeleton::Skeleton {
                    symbols: c_syms,
                    nondet_sites: c_nd,
                    erosion_score: 0,
                    digest: "c".to_owned(),
                },
                true,
            );
            if !typed_diff.ok {
                return Err(
                    "adding Python type hints falsely broke skeleton API check".to_owned()
                );
            }
            let mut base = SimKvDriver::new(SimBehavior::Clean);
            let mut cand = SimKvDriver::new(SimBehavior::StaleExpireBug);
            let stale_cfg = DiffConfig {
                seeds: 96,
                base_seed: seed,
                max_seq_len: 10,
                parity: true,
                inject_faults: false,
                ..DiffConfig::default()
            };
            let stale_rep = run_diff(&mut base, &mut cand, &stale_cfg);
            if stale_rep.verdict != Verdict::ParityFail {
                return Err(
                    "generator failed to find stale-expire bug without hand-written trigger"
                        .to_owned(),
                );
            }
            sig.push_str("7:stale");
            checked += 1;
        }
        8 => {
            let mut empty_b = SimKvDriver::new(SimBehavior::EmptyOps);
            let mut empty_c = SimKvDriver::new(SimBehavior::EmptyOps);
            let rep_empty = run_diff(
                &mut empty_b,
                &mut empty_c,
                &DiffConfig {
                    seeds: 8,
                    base_seed: seed,
                    parity: true,
                    strict: true,
                    ..DiffConfig::default()
                },
            );
            if rep_empty.verdict != Verdict::Inconclusive
                || rep_empty.verdict.exit_code() != 7
                || rep_empty.blocker != "zero_ops"
            {
                return Err("strict mode with 0 ops did not return inconclusive (exit 7)".to_owned());
            }
            let mut b0 = SimKvDriver::new(SimBehavior::Clean);
            let mut c0 = SimKvDriver::new(SimBehavior::Clean);
            let rep_zero = run_diff(
                &mut b0,
                &mut c0,
                &DiffConfig {
                    seeds: 0,
                    base_seed: seed,
                    parity: true,
                    strict: true,
                    ..DiffConfig::default()
                },
            );
            if rep_zero.verdict != Verdict::Inconclusive || rep_zero.blocker != "zero_comparisons" {
                return Err("strict mode with 0 comparisons did not return inconclusive".to_owned());
            }
            let mut b_obs = SimKvDriver::new(SimBehavior::Clean);
            let mut c_obs = SimKvDriver::new(SimBehavior::Clean);
            let rep_miss = run_diff(
                &mut b_obs,
                &mut c_obs,
                &DiffConfig {
                    seeds: 6,
                    base_seed: seed,
                    parity: true,
                    strict: true,
                    required_observations: vec!["rows_after_reopen".to_owned()],
                    ..DiffConfig::default()
                },
            );
            if rep_miss.verdict != Verdict::Inconclusive
                || rep_miss.blocker != "missing_observation"
                || !rep_miss
                    .missing_observations
                    .contains(&"rows_after_reopen".to_owned())
            {
                return Err("missing required observation did not produce inconclusive".to_owned());
            }
            let mut db_b = SimKvDriver::new(SimBehavior::DbReopenObserved(5));
            let mut db_c_bad = SimKvDriver::new(SimBehavior::DbReopenObserved(0));
            let rep_db_fail = run_diff(
                &mut db_b,
                &mut db_c_bad,
                &DiffConfig {
                    seeds: 6,
                    base_seed: seed,
                    parity: true,
                    strict: true,
                    required_observations: vec!["rows_after_reopen".to_owned()],
                    ..DiffConfig::default()
                },
            );
            if rep_db_fail.verdict != Verdict::ParityFail {
                return Err(
                    "diverging rows_after_reopen observation was not caught as parity_fail"
                        .to_owned(),
                );
            }
            let mut db_b2 = SimKvDriver::new(SimBehavior::DbReopenObserved(5));
            let mut db_c_ok = SimKvDriver::new(SimBehavior::DbReopenObserved(5));
            let rep_db_ok = run_diff(
                &mut db_b2,
                &mut db_c_ok,
                &DiffConfig {
                    seeds: 6,
                    base_seed: seed,
                    parity: true,
                    strict: true,
                    required_observations: vec!["rows_after_reopen".to_owned()],
                    ..DiffConfig::default()
                },
            );
            if rep_db_ok.verdict != Verdict::Pass {
                return Err("matching rows_after_reopen observation did not pass".to_owned());
            }
            sig.push_str("8:inc+obs");
            checked += 1;
        }
        9 => {
            let pool = ConstantPool::from_sources(&["if 1000 <= x <= 5000: return x - 10"]);
            let mut b1 = SimKvDriver::new(SimBehavior::Clean);
            let mut c_bad = SimKvDriver::new(SimBehavior::Range1000To5000Bug);
            let rep_no_expect = run_diff(
                &mut b1,
                &mut c_bad,
                &DiffConfig {
                    seeds: 24,
                    base_seed: seed,
                    parity: true,
                    constants: pool.clone(),
                    approval_rules: vec![ApprovalRule {
                        op: "clamp".to_owned(),
                        when: "1000 <= price_input <= 5000".to_owned(),
                        expect: None,
                        must_hold: false,
                    }],
                    inject_faults: false,
                    ..DiffConfig::default()
                },
            );
            if rep_no_expect.verdict != Verdict::ParityFail {
                return Err(
                    "input-only predicate without expect falsely approved arbitrary output change"
                        .to_owned(),
                );
            }
            let mut b2 = SimKvDriver::new(SimBehavior::Clean);
            let mut c_bad2 = SimKvDriver::new(SimBehavior::Range1000To5000Bug);
            let rep_wrong_rel = run_diff(
                &mut b2,
                &mut c_bad2,
                &DiffConfig {
                    seeds: 24,
                    base_seed: seed,
                    parity: true,
                    constants: pool.clone(),
                    approval_rules: vec![ApprovalRule {
                        op: "clamp".to_owned(),
                        when: "1000 <= price_input <= 5000".to_owned(),
                        expect: Some("candidate_price == base_price - 10".to_owned()),
                        must_hold: false,
                    }],
                    inject_faults: false,
                    ..DiffConfig::default()
                },
            );
            if rep_wrong_rel.verdict != Verdict::ParityFail {
                return Err(
                    "expect relation `cand == base - 10` falsely approved `-1` output".to_owned(),
                );
            }
            let mut b3 = SimKvDriver::new(SimBehavior::Clean);
            let mut c_good = SimKvDriver::new(SimBehavior::Range1000To5000Minus10);
            let rep_right_rel = run_diff(
                &mut b3,
                &mut c_good,
                &DiffConfig {
                    seeds: 24,
                    base_seed: seed,
                    parity: true,
                    constants: pool,
                    approval_rules: vec![ApprovalRule {
                        op: "clamp".to_owned(),
                        when: "1000 <= price_input <= 5000".to_owned(),
                        expect: Some("candidate_price == base_price - 10".to_owned()),
                        must_hold: true,
                    }],
                    inject_faults: false,
                    ..DiffConfig::default()
                },
            );
            if rep_right_rel.verdict != Verdict::Pass {
                return Err(format!(
                    "expect relation `candidate_price == base_price - 10` failed to approve matching change: {}",
                    rep_right_rel.detail
                ));
            }
            sig.push_str("9:expect");
            checked += 1;
        }
        _ => {
            let rule = ApprovalRule {
                op: "clamp".to_owned(),
                when: "1000 <= price_input <= 5000".to_owned(),
                expect: Some("candidate_price == base_price - 10".to_owned()),
                must_hold: true,
            };
            let mut b_esc = SimKvDriver::new(SimBehavior::Clean);
            let mut c_esc = SimKvDriver::new(SimBehavior::Range1000To5000Minus10PlusBugAt6000);
            let rep_esc = run_diff(
                &mut b_esc,
                &mut c_esc,
                &DiffConfig {
                    seeds: 0,
                    base_seed: seed,
                    parity: true,
                    pinned_requests: vec![StepRequest {
                        seed,
                        ops: vec![StepOp::simple("clamp", vec![Value::Int(6000)])],
                        faults: Vec::new(),
                        observed_files: Vec::new(),
                        workflow_id: None,
                    }],
                    approval_rules: vec![rule.clone()],
                    inject_faults: false,
                    ..DiffConfig::default()
                },
            );
            if rep_esc.verdict != Verdict::ParityFail {
                return Err(
                    "shrinker collapsed unapproved 6000 regression into approved 1000..5000 rule"
                        .to_owned(),
                );
            }
            let mut b_mh = SimKvDriver::new(SimBehavior::Clean);
            let mut c_mh = SimKvDriver::new(SimBehavior::Clean);
            let rep_mh = run_diff(
                &mut b_mh,
                &mut c_mh,
                &DiffConfig {
                    seeds: 16,
                    base_seed: seed,
                    parity: true,
                    approval_rules: vec![rule],
                    inject_faults: false,
                    ..DiffConfig::default()
                },
            );
            if rep_mh.verdict != Verdict::ParityFail || rep_mh.blocker != "rule_violation" {
                return Err(
                    "must_hold rule failed to reject unchanged candidate where base == candidate"
                        .to_owned(),
                );
            }
            let s_ok = parse_bench_output("{\"metric\": 10.0, \"output\": 42}")?;
            let s_bad = parse_bench_output("{\"metric\": 5.0, \"output\": 99}")?;
            if verify_benchmark_parity(&[s_ok.clone()], &[s_bad]).is_ok() {
                return Err("benchmark parity failed to catch differing JSON outputs".to_owned());
            }
            if verify_benchmark_parity(
                &[s_ok.clone()],
                &[BenchSample {
                    metric: 5.0,
                    output_digest: s_ok.output_digest.clone(),
                }],
            )
            .is_err()
            {
                return Err("benchmark parity rejected matching JSON outputs".to_owned());
            }
            sig.push_str("10:shrink+mh+bench");
            checked += 1;
        }
    }

    Ok((checked, sig))
}

fn run_effectful_worlds(seed: u64) -> Result<usize, String> {
    let key = sha256::short_hex(format!("eff:{}:{}", seed, std::process::id()).as_bytes());
    let root = std::env::temp_dir().join(format!("emi_sim_eff_{key}"));
    if root.exists() {
        let _ = std::fs::remove_dir_all(&root);
    }
    std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;

    let mut total = 0usize;
    let res1 = run_effectful_inner(&root, seed);
    let _ = std::fs::remove_dir_all(&root);
    total += res1?;

    let cli_root = std::env::temp_dir().join(format!("emi_sim_cli_{key}"));
    if cli_root.exists() {
        let _ = std::fs::remove_dir_all(&cli_root);
    }
    std::fs::create_dir_all(&cli_root).map_err(|e| e.to_string())?;
    let res2 = run_cli_e2e_worlds(&cli_root);
    let _ = std::fs::remove_dir_all(&cli_root);
    total += res2?;

    let field_root = std::env::temp_dir().join(format!("emi_sim_field_{key}"));
    if field_root.exists() {
        let _ = std::fs::remove_dir_all(&field_root);
    }
    std::fs::create_dir_all(&field_root).map_err(|e| e.to_string())?;
    let res3 = run_field_bug_e2e_worlds(&field_root);
    let _ = std::fs::remove_dir_all(&field_root);
    total += res3?;

    let ml_root = std::env::temp_dir().join(format!("emi_sim_ml_{key}"));
    if ml_root.exists() {
        let _ = std::fs::remove_dir_all(&ml_root);
    }
    std::fs::create_dir_all(&ml_root).map_err(|e| e.to_string())?;
    let res4 = run_multilang_and_security_e2e_worlds(&ml_root);
    let _ = std::fs::remove_dir_all(&ml_root);
    total += res4?;

    let holes_root = std::env::temp_dir().join(format!("work_sim_holes_{key}"));
    if holes_root.exists() {
        let _ = std::fs::remove_dir_all(&holes_root);
    }
    std::fs::create_dir_all(&holes_root).map_err(|e| e.to_string())?;
    let res5 = run_close_holes_e2e_worlds(&holes_root);
    let _ = std::fs::remove_dir_all(&holes_root);
    total += res5?;

    Ok(total)
}

fn git_ok(dir: &Path, args: &[&str]) -> Result<(), String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| format!("git spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

fn run_emi(
    exe: &Path,
    cwd: &Path,
    args: &[&str],
    extra_env: &[(&str, &str)],
) -> Result<(i32, String, String), String> {
    let mut cmd = Command::new(exe);
    cmd.args(args).current_dir(cwd);
    cmd.env_remove("EMI_SIGNING_KEY");
    cmd.env_remove("EMI_BASE_REV");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().map_err(|e| format!("spawn emi: {e}"))?;
    Ok((
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

fn run_cli_e2e_worlds(root: &Path) -> Result<usize, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    git_ok(root, &["init", "-q"])?;
    git_ok(root, &["config", "user.email", "sim@emi"])?;
    git_ok(root, &["config", "user.name", "sim"])?;

    std::fs::create_dir_all(root.join("pkg")).map_err(|e| e.to_string())?;
    std::fs::write(root.join("pkg/__init__.py"), "").map_err(|e| e.to_string())?;
    std::fs::write(root.join("pkg/helper.py"), "LIMIT = 4321\n").map_err(|e| e.to_string())?;
    std::fs::write(
        root.join("pkg/service.py"),
        "\"\"\"Service module.\"\"\"\n\
         from .helper import LIMIT\n\
         SEEN = []\n\
         \n\
         class Token:\n\
         \x20\x20\x20\x20pass\n\
         \n\
         class Box:\n\
         \x20\x20\x20\x20def __init__(self, initial: int):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20self.val = initial\n\
         \x20\x20\x20\x20@classmethod\n\
         \x20\x20\x20\x20def __emi_init__(cls):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return cls(7)\n\
         \x20\x20\x20\x20def add(self, n: int) -> int:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20if not isinstance(n, int) or isinstance(n, bool):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20return self.val\n\
         \x20\x20\x20\x20\x20\x20\x20\x20self.val += n\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return self.val\n\
         \n\
         def compute(x: int) -> int:\n\
         \x20\x20\x20\x20\"\"\"Compute value.\"\"\"\n\
         \x20\x20\x20\x20SEEN.append(x)\n\
         \x20\x20\x20\x20if not isinstance(x, int) or isinstance(x, bool) or x < 0:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20raise ValueError('old bad input')\n\
         \x20\x20\x20\x20if x == LIMIT:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return 999\n\
         \x20\x20\x20\x20return x * 2 + len(SEEN)\n\
         \n\
         def make_token():\n\
         \x20\x20\x20\x20return Token()\n\
         \n\
         def write_journal(msg: str) -> bool:\n\
         \x20\x20\x20\x20with open('journal.log', 'a', encoding='utf-8') as f:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20f.write(f'v1:{msg}\\n')\n\
         \x20\x20\x20\x20return True\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        root.join("bench.py"),
        "import json\nfrom pkg.service import compute\nprint(json.dumps({'metric': 100.0, 'output': compute(5)}))\n",
    )
    .map_err(|e| e.to_string())?;
    git_ok(root, &["add", "."])?;
    git_ok(root, &["commit", "-q", "-m", "initial"])?;

    let root_s = root.to_string_lossy().into_owned();
    let (rc, _, err) = run_emi(
        &exe,
        root,
        &[
            "ratchet",
            "init",
            "--repo",
            &root_s,
            "--mode",
            "enforce",
            "--allow-head",
            "--observe-file",
            "journal.log",
            "--min-cov-ratio",
            "0.5",
        ],
        &[],
    )?;
    if rc != 0 {
        return Err(format!("cli e2e ratchet init failed: {err}"));
    }
    git_ok(root, &["add", ".emi/ratchet.json"])?;
    git_ok(root, &["commit", "-q", "-m", "pin ratchet"])?;
    let base_sha = git::rev_parse(root, "HEAD")?;

    let (rc_head, _, _) = run_emi(&exe, root, &["check", "--repo", &root_s, "--json"], &[])?;
    if rc_head != 2 {
        return Err(format!(
            "trust-boundary failure: enforce mode allowed bare HEAD without --base (rc={rc_head})"
        ));
    }

    let base_service = std::fs::read_to_string(root.join("pkg/service.py")).map_err(|e| e.to_string())?;
    let doc_and_msg = base_service
        .replace("Compute value.", "Updated docstring.")
        .replace("old bad input", "reworded error message");
    std::fs::write(root.join("pkg/service.py"), &doc_and_msg).map_err(|e| e.to_string())?;
    let (rc_exc, out_exc, err_exc) = run_emi(
        &exe,
        root,
        &[
            "check",
            "--repo",
            &root_s,
            "--base",
            &base_sha,
            "--seeds",
            "24",
            "--no-adversary",
            "--json",
        ],
        &[],
    )?;
    if rc_exc != 0 {
        return Err(format!(
            "fork/package/repr/exception-msg world failed: rc={rc_exc} out={out_exc} err={err_exc}"
        ));
    }

    let broken_limit = base_service.replace("return 999", "return -1");
    std::fs::write(root.join("pkg/service.py"), &broken_limit).map_err(|e| e.to_string())?;
    std::fs::write(
        root.join(".emi/ratchet.json"),
        "{\"mode\":\"off\",\"approval_rules\":[{\"op\":\"*\",\"when\":\"any\",\"expect\":\"true\"}]}\n",
    )
    .map_err(|e| e.to_string())?;

    let ev_file = root.join(".emi/evidence.json");
    let ev_s = ev_file.to_string_lossy().into_owned();
    let (rc_tamper, out_tamper, err_tamper) = run_emi(
        &exe,
        root,
        &[
            "check",
            "--repo",
            &root_s,
            "--base",
            &base_sha,
            "--seeds",
            "48",
            "--no-adversary",
            "--evidence-out",
            &ev_s,
            "--json",
        ],
        &[("EMI_SIGNING_KEY", "ci-secret")],
    )?;
    if rc_tamper != 3 {
        return Err(format!(
            "trust-boundary failure: worktree ratchet tamper or imported LIMIT=4321 bug escaped (rc={rc_tamper}) out={out_tamper} err={err_tamper}"
        ));
    }
    let tamper_json = json::parse(&out_tamper)?;
    if tamper_json.get("blocker").and_then(Value::as_str) != Some("regression") {
        return Err(format!("expected blocker=regression, got {out_tamper}"));
    }

    let (rc_rep_fail, _, _) = run_emi(
        &exe,
        root,
        &[
            "replay",
            "--repo",
            &root_s,
            "--base",
            &base_sha,
            "--evidence",
            &ev_s,
            "--json",
        ],
        &[],
    )?;
    if rc_rep_fail != 3 {
        return Err(format!(
            "emi replay did not reproduce failing witness (rc={rc_rep_fail})"
        ));
    }

    let (rc_stamp_preserve, out_sp, err_sp) = run_emi(
        &exe,
        root,
        &[
            "ratchet",
            "stamp",
            "--repo",
            &root_s,
            "--base",
            &base_sha,
            "--evidence",
            &ev_s,
        ],
        &[("EMI_SIGNING_KEY", "ci-secret")],
    )?;
    if rc_stamp_preserve != 3 {
        return Err(format!(
            "stamp failed to preserve 48-seed parity_fail decision: rc={rc_stamp_preserve} out={out_sp} err={err_sp}"
        ));
    }
    let att_sp = json::parse(out_sp.trim())?;
    if att_sp.get("request_budget").and_then(Value::as_u64) != Some(48)
        || att_sp.get("evidence_bound").and_then(Value::as_bool) != Some(true)
    {
        return Err(format!("stamp attestation missing evidence binding: {out_sp}"));
    }

    let tampered_ev = std::fs::read_to_string(&ev_file)
        .map_err(|e| e.to_string())?
        .replace("\"parity_fail\"", "\"pass\"");
    std::fs::write(&ev_file, tampered_ev).map_err(|e| e.to_string())?;
    let (rc_ev_tamper, _, err_ev_tamper) = run_emi(
        &exe,
        root,
        &[
            "ratchet",
            "stamp",
            "--repo",
            &root_s,
            "--base",
            &base_sha,
            "--evidence",
            &ev_s,
        ],
        &[],
    )?;
    if rc_ev_tamper != 2 {
        return Err(format!(
            "trust-boundary failure: stamp accepted tampered inconsistent evidence (rc={rc_ev_tamper} err={err_ev_tamper})"
        ));
    }

    let mut forged_ev = load_evidence(&ev_file)?;
    forged_ev.verdict = "pass".to_owned();
    forged_ev.unapproved_diffs = 0;
    forged_ev.witnesses.clear();
    save_evidence_signed(&ev_file, &forged_ev, None)?;
    let (rc_unsigned, _, err_unsigned) = run_emi(
        &exe,
        root,
        &[
            "ratchet",
            "stamp",
            "--repo",
            &root_s,
            "--base",
            &base_sha,
            "--evidence",
            &ev_s,
        ],
        &[("EMI_SIGNING_KEY", "ci-secret")],
    )?;
    if rc_unsigned != 2 {
        return Err(format!(
            "trust-boundary failure: stamp with signing key accepted unsigned forged evidence (rc={rc_unsigned} err={err_unsigned})"
        ));
    }

    std::fs::write(root.join("pkg/service.py"), &base_service).map_err(|e| e.to_string())?;
    let (rc_rep_ok, _, err_rep_ok) = run_emi(
        &exe,
        root,
        &[
            "replay",
            "--repo",
            &root_s,
            "--base",
            &base_sha,
            "--evidence",
            &ev_s,
            "--json",
        ],
        &[],
    )?;
    if rc_rep_ok != 0 {
        return Err(format!(
            "emi replay failed after fixing regression: rc={rc_rep_ok} err={err_rep_ok}"
        ));
    }

    let low_cov_service = base_service.replace(
        "return x * 2 + len(SEEN)",
        "if x == 987654321:\n        a = 1\n        b = 2\n        c = 3\n        d = 4\n        e = 5\n        return a + b + c + d + e\n    return x * 2 + len(SEEN)",
    );
    std::fs::write(root.join("pkg/service.py"), &low_cov_service).map_err(|e| e.to_string())?;
    let (rc_low_cov, out_low_cov, _) = run_emi(
        &exe,
        root,
        &[
            "check",
            "--repo",
            &root_s,
            "--base",
            &base_sha,
            "--seeds",
            "16",
            "--no-adversary",
            "--json",
        ],
        &[],
    )?;
    if rc_low_cov != 7
        || json::parse(&out_low_cov)?
            .get("blocker")
            .and_then(Value::as_str)
            != Some("insufficient_coverage")
    {
        return Err(format!(
            "coverage share threshold failed to return inconclusive/insufficient_coverage: rc={rc_low_cov} out={out_low_cov}"
        ));
    }

    std::fs::write(root.join("pkg/service.py"), &base_service).map_err(|e| e.to_string())?;
    std::fs::write(
        root.join("bench.py"),
        "import json\nprint(json.dumps({'metric': 1.0, 'output': 11}))\n",
    )
    .map_err(|e| e.to_string())?;
    let (rc_bench_cheat, out_bc, err_bc) = run_emi(
        &exe,
        root,
        &[
            "climb",
            "--repo",
            &root_s,
            "--base",
            &base_sha,
            "--metric",
            "python3 bench.py",
            "--runs",
            "5",
            "--seeds",
            "12",
            "--json",
        ],
        &[],
    )?;
    if rc_bench_cheat != 6 {
        return Err(format!(
            "trust-boundary failure: candidate bench.py edit cheated climb (rc={rc_bench_cheat} out={out_bc} err={err_bc})"
        ));
    }

    let (rc_climb_obs, out_co, _) = run_emi(
        &exe,
        root,
        &[
            "climb",
            "--repo",
            &root_s,
            "--base",
            &base_sha,
            "--metric",
            "python3 bench.py",
            "--require-observation",
            "rows_after_reopen",
            "--runs",
            "5",
            "--seeds",
            "12",
            "--json",
        ],
        &[],
    )?;
    if rc_climb_obs != 7 {
        return Err(format!(
            "climb did not return inconclusive (7) on missing rows_after_reopen: rc={rc_climb_obs} out={out_co}"
        ));
    }

    Ok(8)
}

fn run_effectful_inner(root: &Path, seed: u64) -> Result<usize, String> {
    git_ok(root, &["init", "-q"])?;
    git_ok(root, &["config", "user.email", "sim@emi"])?;
    git_ok(root, &["config", "user.name", "sim"])?;

    std::fs::write(
        root.join("pricing.py"),
        "\"\"\"Pricing module.\"\"\"\n\
         CACHE = []\n\
         def price(x: int) -> int:\n\
         \x20\x20\x20\x20\"\"\"Compute price.\"\"\"\n\
         \x20\x20\x20\x20CACHE.append(x)\n\
         \x20\x20\x20\x20if not isinstance(x, int) or isinstance(x, bool):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return 0\n\
         \x20\x20\x20\x20return x * 2 + len(CACHE)\n\
         \n\
         def append_journal(msg: str) -> bool:\n\
         \x20\x20\x20\x20with open('journal.log', 'a', encoding='utf-8') as f:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20f.write(f'OK:{msg}\\n')\n\
         \x20\x20\x20\x20return True\n\
         \n\
         class Vault:\n\
         \x20\x20\x20\x20def __init__(self):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20self.items = {}\n\
         \x20\x20\x20\x20def put(self, k: str, v: int):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20self.items[str(k)] = v\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return True\n\
         \x20\x20\x20\x20def get(self, k: str):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return self.items.get(str(k), None)\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        root.join("bench.py"),
        "print('{\"metric\": 100.0, \"output\": 42}')\n",
    )
    .map_err(|e| e.to_string())?;
    git_ok(root, &["add", "."])?;
    git_ok(root, &["commit", "-q", "-m", "base"])?;
    let base_sha = git::rev_parse(root, "HEAD")?;

    std::fs::write(
        root.join("pricing.py"),
        "\"\"\"Pricing module with updated documentation only.\"\"\"\n\
         CACHE = []\n\
         def price(x: int) -> int:\n\
         \x20\x20\x20\x20\"\"\"Compute price (revised docstring).\"\"\"\n\
         \x20\x20\x20\x20CACHE.append(x)\n\
         \x20\x20\x20\x20if not isinstance(x, int) or isinstance(x, bool):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return 0\n\
         \x20\x20\x20\x20return x * 2 + len(CACHE)\n\
         \n\
         def append_journal(msg: str) -> bool:\n\
         \x20\x20\x20\x20with open('journal.log', 'a', encoding='utf-8') as f:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20f.write(f'OK:{msg}\\n')\n\
         \x20\x20\x20\x20return True\n\
         \n\
         class Vault:\n\
         \x20\x20\x20\x20def __init__(self):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20self.items = {}\n\
         \x20\x20\x20\x20def put(self, k: str, v: int):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20self.items[str(k)] = v\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return True\n\
         \x20\x20\x20\x20def get(self, k: str):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return self.items.get(str(k), None)\n",
    )
    .map_err(|e| e.to_string())?;
    let doc_raw = git::changed_lines(root, &base_sha, None)?;
    let doc_exec = git::filter_executable_changed_lines(root, &doc_raw);
    if !doc_exec.is_empty() {
        return Err(format!(
            "docstring-only edit falsely reported executable changed lines: {doc_exec:?}"
        ));
    }

    std::fs::write(
        root.join("pricing.py"),
        "\"\"\"Pricing module.\"\"\"\n\
         CACHE = []\n\
         def price(x: int) -> int:\n\
         \x20\x20\x20\x20\"\"\"Compute price.\"\"\"\n\
         \x20\x20\x20\x20CACHE.append(x)\n\
         \x20\x20\x20\x20if not isinstance(x, int) or isinstance(x, bool):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return 0\n\
         \x20\x20\x20\x20if 1000 <= x <= 5000:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return x * 2 + len(CACHE) - 10\n\
         \x20\x20\x20\x20return x * 2 + len(CACHE)\n\
         \n\
         def append_journal(msg: str) -> bool:\n\
         \x20\x20\x20\x20with open('journal.log', 'a', encoding='utf-8') as f:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20f.write(f'CORRUPT:{msg}\\n')\n\
         \x20\x20\x20\x20return True\n\
         \n\
         class Vault:\n\
         \x20\x20\x20\x20def __init__(self):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20self.items = {}\n\
         \x20\x20\x20\x20def put(self, k: str, v: int):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20self.items[str(k)] = v\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return True\n\
         \x20\x20\x20\x20def get(self, k: str):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return self.items.get(str(k), None)\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        root.join("brand_new.py"),
        "def extra(n: int) -> int:\n    return n + 1\n",
    )
    .map_err(|e| e.to_string())?;

    let changed = git::changed_files(root, &base_sha, None)?;
    if !changed.contains(&"brand_new.py".to_owned()) {
        return Err("untracked brand_new.py missing from changed_files".to_owned());
    }
    let ch_lines =
        git::filter_executable_changed_lines(root, &git::changed_lines(root, &base_sha, None)?);
    let ast_faults = synthesize_ast_faults(root, &ch_lines, 6);
    if ast_faults.is_empty() {
        return Err("AST mutator produced 0 faults on changed Python lines".to_owned());
    }

    let base_snap = git::materialize_revision(root, &base_sha, "eff_b")?;
    let cand_snap = git::materialize_worktree(root, "eff_c")?;
    let b_argv = materialize_auto_driver(&base_snap)?;
    let c_argv = materialize_auto_driver(&cand_snap)?;
    let mut b_drv = ProcessDriver::new(base_snap.clone(), b_argv);
    let mut c_drv = ProcessDriver::new(cand_snap.clone(), c_argv);

    let mut pool = ConstantPool::from_files_with_imports(&base_snap, &changed);
    pool.merge(&ConstantPool::from_files_with_imports(&cand_snap, &changed));
    let mut ch_set = BTreeSet::new();
    for (f, lines) in &ch_lines {
        for &ln in lines {
            ch_set.insert(format!("{f}:{ln}"));
        }
    }

    let diff_rep = run_diff(
        &mut b_drv,
        &mut c_drv,
        &DiffConfig {
            seeds: 32,
            base_seed: seed,
            parity: true,
            strict: true,
            observed_files: vec!["journal.log".to_owned()],
            constants: pool.clone(),
            changed_lines: ch_set.clone(),
            require_changed_coverage: true,
            inject_faults: false,
            ..DiffConfig::default()
        },
    );
    if !diff_rep.aa_verified {
        return Err(format!(
            "module-level CACHE or observed_files cleanup broke A/A isolation: {}",
            diff_rep.detail
        ));
    }
    if diff_rep.verdict != Verdict::ParityFail {
        return Err("real Python 1000..5000 / journal.log bug was not caught".to_owned());
    }
    if diff_rep.changed_lines_covered == 0 {
        return Err("changed lines were not tracked as covered".to_owned());
    }

    let journal_only = run_diff(
        &mut b_drv,
        &mut c_drv,
        &DiffConfig {
            seeds: 0,
            base_seed: seed,
            parity: true,
            strict: true,
            observed_files: vec!["journal.log".to_owned()],
            pinned_requests: vec![StepRequest {
                seed: 7,
                ops: vec![StepOp::simple(
                    "pricing.py::append_journal",
                    vec![Value::Str("entry1".to_owned())],
                )],
                faults: Vec::new(),
                observed_files: vec!["journal.log".to_owned()],
                workflow_id: None,
            }],
            inject_faults: false,
            ..DiffConfig::default()
        },
    );
    if journal_only.verdict != Verdict::ParityFail || !journal_only.aa_verified {
        return Err("observed_files failed to catch journal.log byte divergence".to_owned());
    }

    let rule_rep = run_diff(
        &mut b_drv,
        &mut c_drv,
        &DiffConfig {
            seeds: 0,
            base_seed: seed,
            parity: true,
            constants: pool.clone(),
            pinned_requests: vec![
                StepRequest {
                    seed: 11,
                    ops: vec![StepOp::simple("pricing.py::price", vec![Value::Int(2000)])],
                    faults: Vec::new(),
                    observed_files: Vec::new(),
                    workflow_id: None,
                },
                StepRequest {
                    seed: 12,
                    ops: vec![StepOp::simple("brand_new.py::extra", vec![Value::Int(5)])],
                    faults: Vec::new(),
                    observed_files: Vec::new(),
                    workflow_id: None,
                },
            ],
            approval_rules: vec![
                ApprovalRule {
                    op: "pricing.py::price".to_owned(),
                    when: "1000 <= price_input <= 5000".to_owned(),
                    expect: Some("candidate_price == base_price - 10".to_owned()),
                    must_hold: true,
                },
                ApprovalRule {
                    op: "brand_new.py::extra".to_owned(),
                    when: "any".to_owned(),
                    expect: Some("base_missing && cand == arg0 + 1".to_owned()),
                    must_hold: false,
                },
            ],
            inject_faults: false,
            ..DiffConfig::default()
        },
    );
    if rule_rep.verdict != Verdict::Pass {
        return Err(format!(
            "tightened expect approval rules failed to approve matching Python diffs: {}",
            rule_rep.detail
        ));
    }

    let tree_sha = git::tree_hash(&cand_snap)?;
    let policy = RatchetState::default();
    let policy_digest = policy.policy_digest();
    let driver_digest = compute_driver_digest(&base_snap, None, None);
    let ev = EvidenceRecord {
        base_sha: base_sha.clone(),
        candidate_tree_sha256: tree_sha.clone(),
        driver_digest: driver_digest.clone(),
        policy_digest: policy_digest.clone(),
        request_budget: 48,
        sequences_run: diff_rep.sequences_run,
        valid_comparisons: diff_rep.valid_comparisons,
        verdict: diff_rep.verdict.as_str().to_owned(),
        blocker: diff_rep.blocker.clone(),
        next_action: diff_rep.next_action.clone(),
        detail: diff_rep.detail.clone(),
        skeleton_ok: true,
        aa_verified: diff_rep.aa_verified,
        masks_proven: diff_rep.masks_proven,
        changed_lines_covered: diff_rep.changed_lines_covered,
        changed_lines_total: diff_rep.changed_lines_total,
        unapproved_diffs: diff_rep.unapproved_count(),
        missing_observations: diff_rep.missing_observations.clone(),
        observed_files: vec!["journal.log".to_owned()],
        observed_files_recorded: true,
        workflows_run: diff_rep.workflows_run.clone(),
        ops_exercised: diff_rep.ops_exercised.clone(),
        observed_outputs: diff_rep.observed_outputs.clone(),
        missing_workflows: diff_rep.missing_workflows.clone(),
        mutations_run: true,
        planted_total: 2,
        planted_killed: 2,
        planted_survived: 0,
        planted_unknown: 0,
        witnesses: diff_rep.divergences.clone(),
        record_digest_sha256: None,
        hmac_sha256: None,
    };
    let ev_path = root.join(".emi/evidence.json");
    save_evidence_signed(&ev_path, &ev, Some(b"ci-secret-key"))?;
    let loaded_ev = load_evidence(&ev_path)?;
    loaded_ev.verify_binding(&base_sha, &tree_sha, &driver_digest, &policy_digest)?;
    loaded_ev.verify_integrity(Some(b"ci-secret-key"), 0.5, false, &[])?;

    let (bm_s, cm_s) = measure_interleaved(
        &base_snap,
        &cand_snap,
        &["python3".to_owned(), "bench.py".to_owned()],
        6,
        seed,
    )?;
    let bm: Vec<f64> = bm_s.iter().map(|s| s.metric).collect();
    let cm: Vec<f64> = cm_s.iter().map(|s| s.metric).collect();
    let same_climb = evaluate_climb(
        FloorChecks {
            skeleton_ok: true,
            aa_verified: true,
            parity_ok: true,
            planted_bugs_killed: true,
            benchmark_output_ok: verify_benchmark_parity(&bm_s, &cm_s).is_ok(),
            inconclusive_reason: None,
        },
        &bm,
        &cm,
        Direction::Minimize,
        0.05,
    );
    if same_climb.verdict != ClimbVerdict::RejectMetric {
        return Err("interleaved climb falsely accepted identical bench.py".to_owned());
    }

    let mut hang_drv = ProcessDriver::with_timeout(
        cand_snap.clone(),
        vec![
            "python3".to_owned(),
            "-c".to_owned(),
            "import time; time.sleep(5)".to_owned(),
        ],
        Duration::from_millis(120),
    );
    if hang_drv.probe().is_ok() {
        return Err("hung driver did not time out".to_owned());
    }

    let att = Attestation {
        base_sha: base_sha.clone(),
        candidate_tree_sha256: tree_sha,
        driver_digest,
        policy_digest,
        request_budget: 48,
        evidence_bound: true,
        mode: EnforceMode::Enforce,
        skeleton_ok: true,
        aa_verified: true,
        changed_lines_covered: diff_rep.changed_lines_covered,
        changed_lines_total: diff_rep.changed_lines_total,
        unapproved_diffs: 0,
        workflows_run: diff_rep.workflows_run.clone(),
        ops_exercised: diff_rep.ops_exercised.clone(),
        observed_outputs: diff_rep.observed_outputs.clone(),
        planted_total: 1,
        planted_killed: 1,
        planted_survived: 0,
        planted_unknown: 0,
        verdict: "pass".to_owned(),
    };
    let signed = att.to_signed_json(Some(b"ci-secret-key"));
    if signed.get("signed").and_then(Value::as_bool) != Some(true)
        || signed.get("hmac_sha256").and_then(Value::as_str).is_none()
        || signed.get("evidence_bound").and_then(Value::as_bool) != Some(true)
    {
        return Err("HMAC evidence-bound attestation missing expected fields".to_owned());
    }

    let mut ratchet = RatchetState::default();
    ratchet.incidents.push(IncidentSeed {
        id: "inc-1".to_owned(),
        triggers: vec!["pricing.py".to_owned()],
        seed: (1u64 << 63) | 7,
        ops: vec![StepOp::simple("pricing.py::price", vec![Value::Int(1000)])],
    });
    if ratchet.triggered_requests(&changed, &[]).len() != 1 {
        return Err("ratchet incident failed to trigger on pricing.py".to_owned());
    }

    let _ = std::fs::remove_dir_all(&base_snap);
    let _ = std::fs::remove_dir_all(&cand_snap);
    Ok(10)
}

fn run_field_bug_e2e_worlds(root: &Path) -> Result<usize, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;

    let exp_cli = root.join("exporter_cli");
    std::fs::create_dir_all(&exp_cli).map_err(|e| e.to_string())?;
    git_ok(&exp_cli, &["init", "-q"])?;
    git_ok(&exp_cli, &["config", "user.email", "sim@emi"])?;
    git_ok(&exp_cli, &["config", "user.name", "sim"])?;
    let good_exporter = "def export_invoices(rows: int = 1) -> int:\n\
         \x20\x20\x20\x20with open('invoices.tsv', 'w', encoding='utf-8') as f:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20f.write('id\\tamount\\n1\\t100\\n')\n\
         \x20\x20\x20\x20return 1\n";
    let broken_exporter = "def export_invoices(rows: int = 1) -> int:\n\
         \x20\x20\x20\x20with open('invoices.tsv', 'w', encoding='utf-8') as f:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20f.write('id\\tamount\\n1\\t100')\n\
         \x20\x20\x20\x20return 1\n";
    std::fs::write(exp_cli.join("exporter.py"), good_exporter).map_err(|e| e.to_string())?;
    git_ok(&exp_cli, &["add", "."])?;
    git_ok(&exp_cli, &["commit", "-q", "-m", "base"])?;
    std::fs::write(exp_cli.join("exporter.py"), broken_exporter).map_err(|e| e.to_string())?;

    let (rc, out, err) = run_emi(
        &exe,
        &exp_cli,
        &[
            "check",
            "--allow-head",
            "--observe-file",
            "invoices.tsv",
            "--seeds",
            "8",
            "--json",
        ],
        &[],
    )?;
    if rc != 3 {
        return Err(format!(
            "invoice exporter CLI --observe-file check expected rc=3, got {rc}: {out} {err}"
        ));
    }
    let (rc, out, err) = run_emi(
        &exe,
        &exp_cli,
        &["replay", "--allow-head", "--json"],
        &[],
    )?;
    if rc != 3 {
        return Err(format!(
            "invoice exporter replay on identical broken code expected rc=3, got {rc}: {out} {err}"
        ));
    }
    std::fs::write(exp_cli.join("exporter.py"), good_exporter).map_err(|e| e.to_string())?;
    let (rc, out, err) = run_emi(
        &exe,
        &exp_cli,
        &["replay", "--allow-head", "--json"],
        &[],
    )?;
    if rc != 0 {
        return Err(format!(
            "invoice exporter replay after restoring newline expected rc=0, got {rc}: {out} {err}"
        ));
    }

    let ev_path = exp_cli.join(".emi/evidence.json");
    let raw_ev = std::fs::read_to_string(&ev_path).map_err(|e| e.to_string())?;
    let mut ev_val = crate::json::parse(&raw_ev)?;
    if let Value::Object(ref mut map) = ev_val {
        map.remove("observed_files");
    }
    std::fs::write(&ev_path, ev_val.pretty()).map_err(|e| e.to_string())?;
    let (rc, out, err) = run_emi(
        &exe,
        &exp_cli,
        &["replay", "--allow-head", "--json"],
        &[],
    )?;
    if rc != 2 || !err.contains("observed_files") {
        return Err(format!(
            "legacy evidence without observed_files expected rc=2 mentioning observed_files, got rc={rc}: {out} {err}"
        ));
    }

    let exp_pin = root.join("exporter_pinned");
    std::fs::create_dir_all(&exp_pin).map_err(|e| e.to_string())?;
    git_ok(&exp_pin, &["init", "-q"])?;
    git_ok(&exp_pin, &["config", "user.email", "sim@emi"])?;
    git_ok(&exp_pin, &["config", "user.name", "sim"])?;
    std::fs::write(exp_pin.join("exporter.py"), good_exporter).map_err(|e| e.to_string())?;
    let (rc, out, err) = run_emi(
        &exe,
        &exp_pin,
        &[
            "ratchet",
            "init",
            "--allow-head",
            "--observe-file",
            "invoices.tsv",
        ],
        &[],
    )?;
    if rc != 0 {
        return Err(format!("ratchet init --observe-file failed: {out} {err}"));
    }
    git_ok(&exp_pin, &["add", "."])?;
    git_ok(&exp_pin, &["commit", "-q", "-m", "base"])?;
    std::fs::write(exp_pin.join("exporter.py"), broken_exporter).map_err(|e| e.to_string())?;
    let (rc, out, err) = run_emi(
        &exe,
        &exp_pin,
        &["check", "--allow-head", "--seeds", "8", "--json"],
        &[],
    )?;
    if rc != 3 {
        return Err(format!(
            "pinned observed_files check expected rc=3, got {rc}: {out} {err}"
        ));
    }
    let (rc, out, err) = run_emi(
        &exe,
        &exp_pin,
        &["replay", "--allow-head", "--json"],
        &[],
    )?;
    if rc != 3 {
        return Err(format!(
            "pinned observed_files replay on broken code expected rc=3, got {rc}: {out} {err}"
        ));
    }
    std::fs::write(exp_pin.join("exporter.py"), good_exporter).map_err(|e| e.to_string())?;
    let (rc, out, err) = run_emi(
        &exe,
        &exp_pin,
        &["replay", "--allow-head", "--json"],
        &[],
    )?;
    if rc != 0 {
        return Err(format!(
            "pinned observed_files replay after fix expected rc=0, got {rc}: {out} {err}"
        ));
    }

    let cli_dir = root.join("cli_stdout");
    std::fs::create_dir_all(&cli_dir).map_err(|e| e.to_string())?;
    git_ok(&cli_dir, &["init", "-q"])?;
    git_ok(&cli_dir, &["config", "user.email", "sim@emi"])?;
    git_ok(&cli_dir, &["config", "user.name", "sim"])?;
    let cli_base = "import sys\n\
         \n\
         def main() -> None:\n\
         \x20\x20\x20\x20print('batch=19')\n\
         \x20\x20\x20\x20sys.exit(0)\n";
    let cli_changed = "import sys\n\
         \n\
         def main() -> None:\n\
         \x20\x20\x20\x20print('group=19')\n\
         \x20\x20\x20\x20sys.exit(0)\n";
    std::fs::write(cli_dir.join("cli.py"), cli_base).map_err(|e| e.to_string())?;
    git_ok(&cli_dir, &["add", "."])?;
    git_ok(&cli_dir, &["commit", "-q", "-m", "base"])?;
    let (rc, out, err) = run_emi(
        &exe,
        &cli_dir,
        &["check", "--allow-head", "--seeds", "6", "--json"],
        &[],
    )?;
    if rc != 0 || !out.contains("\"stdout\"") {
        return Err(format!(
            "unchanged stdout+SystemExit(0) CLI expected rc=0 with stdout observed, got rc={rc}: {out} {err}"
        ));
    }
    std::fs::write(cli_dir.join("cli.py"), cli_changed).map_err(|e| e.to_string())?;
    let (rc, out, err) = run_emi(
        &exe,
        &cli_dir,
        &["check", "--allow-head", "--seeds", "6", "--json"],
        &[],
    )?;
    if rc != 3 || !out.contains("batch=19") || !out.contains("group=19") {
        return Err(format!(
            "changed CLI stdout expected rc=3 showing both batch=19 and group=19, got rc={rc}: {out} {err}"
        ));
    }

    let wf_dir = root.join("req_workflow");
    std::fs::create_dir_all(&wf_dir).map_err(|e| e.to_string())?;
    git_ok(&wf_dir, &["init", "-q"])?;
    git_ok(&wf_dir, &["config", "user.email", "sim@emi"])?;
    git_ok(&wf_dir, &["config", "user.name", "sim"])?;
    let picker_base = "def pick_latest(versions: list) -> str:\n\
         \x20\x20\x20\x20if not isinstance(versions, list) or not versions:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return ''\n\
         \x20\x20\x20\x20def key(v):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20s = str(v)\n\
         \x20\x20\x20\x20\x20\x20\x20\x20if '.post' in s:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20head, tail = s.split('.post', 1)\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20return (head, 1, int(tail) if tail.isdigit() else 0)\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return (s, 0, 0)\n\
         \x20\x20\x20\x20return str(max(versions, key=key))\n";
    let picker_buggy = "def pick_latest(versions: list) -> str:\n\
         \x20\x20\x20\x20if not isinstance(versions, list) or not versions:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return ''\n\
         \x20\x20\x20\x20def key(v):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20s = str(v)\n\
         \x20\x20\x20\x20\x20\x20\x20\x20if '.post' in s:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20head, _ = s.split('.post', 1)\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20return (head, -1, 0)\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return (s, 0, 0)\n\
         \x20\x20\x20\x20return str(max(versions, key=key))\n";
    let picker_fixed = "def pick_latest(versions: list) -> str:\n\
         \x20\x20\x20\x20if not isinstance(versions, list) or not versions:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return ''\n\
         \x20\x20\x20\x20def key(v):\n\
         \x20\x20\x20\x20\x20\x20\x20\x20s = str(v)\n\
         \x20\x20\x20\x20\x20\x20\x20\x20if '.post' in s:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20head, tail = s.split('.post', 1)\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20return (head, 1, int(tail) if tail.isdigit() else 0)\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return (s, 0, 0)\n\
         \x20\x20\x20\x20chosen = max(versions, key=key)\n\
         \x20\x20\x20\x20return str(chosen)\n";
    std::fs::write(wf_dir.join("picker.py"), picker_base).map_err(|e| e.to_string())?;
    let (rc, out, err) = run_emi(
        &exe,
        &wf_dir,
        &[
            "ratchet",
            "init",
            "--allow-head",
            "--require-workflow",
            "select-post-release",
        ],
        &[],
    )?;
    if rc != 0 {
        return Err(format!("ratchet init --require-workflow failed: {out} {err}"));
    }
    git_ok(&wf_dir, &["add", "."])?;
    git_ok(&wf_dir, &["commit", "-q", "-m", "base"])?;
    std::fs::write(wf_dir.join("picker.py"), picker_buggy).map_err(|e| e.to_string())?;

    let (rc, out, err) = run_emi(
        &exe,
        &wf_dir,
        &["check", "--allow-head", "--seeds", "12", "--json"],
        &[],
    )?;
    if rc != 7 || !out.contains("missing_workflow") || !out.contains("select-post-release") {
        return Err(format!(
            "omitting required workflow expected rc=7 missing_workflow, got rc={rc}: {out} {err}"
        ));
    }
    let (rc, out, err) = run_emi(
        &exe,
        &wf_dir,
        &["ratchet", "stamp", "--allow-head", "--json"],
        &[],
    )?;
    if rc != 7 {
        return Err(format!(
            "stamp without required workflow must be blocked with rc=7, got rc={rc}: {out} {err}"
        ));
    }

    let (rc, out, err) = run_emi(
        &exe,
        &wf_dir,
        &[
            "ratchet",
            "remember",
            "--allow-head",
            "--id",
            "select-post-release",
            "--trigger",
            "*",
            "--ops",
            r#"[{"op":"picker.py::pick_latest","args":[["2.0","2.0.post1"]]}]"#,
        ],
        &[],
    )?;
    if rc != 0 {
        return Err(format!("ratchet remember workflow failed: {out} {err}"));
    }
    git_ok(&wf_dir, &["add", ".emi/ratchet.json"])?;
    git_ok(&wf_dir, &["commit", "-q", "-m", "pin workflow"])?;

    let (rc, out, err) = run_emi(
        &exe,
        &wf_dir,
        &["check", "--allow-head", "--seeds", "12", "--json"],
        &[],
    )?;
    if rc != 3 || !out.contains("2.0.post1") {
        return Err(format!(
            "running required workflow expected rc=3 exposing 2.0.post1 bug, got rc={rc}: {out} {err}"
        ));
    }

    std::fs::write(wf_dir.join("picker.py"), picker_fixed).map_err(|e| e.to_string())?;
    let (rc, out, err) = run_emi(
        &exe,
        &wf_dir,
        &["check", "--allow-head", "--seeds", "12", "--json"],
        &[("EMI_SIGNING_KEY", "wf-key")],
    )?;
    if rc != 0 || !out.contains("select-post-release") || !out.contains("picker.py::pick_latest") {
        return Err(format!(
            "fixed picker check expected rc=0 with workflows_run and ops_exercised, got rc={rc}: {out} {err}"
        ));
    }
    let (rc, out, err) = run_emi(
        &exe,
        &wf_dir,
        &["ratchet", "stamp", "--allow-head", "--json"],
        &[("EMI_SIGNING_KEY", "wf-key")],
    )?;
    if rc != 0 {
        return Err(format!(
            "fixed picker stamp expected rc=0, got rc={rc}: {out} {err}"
        ));
    }
    let att_val = crate::json::parse(&out)?;
    let wf_run = att_val
        .get("workflows_run")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .any(|s| s == "select-post-release")
        })
        .unwrap_or(false);
    let ops_ex = att_val
        .get("ops_exercised")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .any(|s| s == "picker.py::pick_latest")
        })
        .unwrap_or(false);
    let obs_out = att_val
        .get("observed_outputs")
        .and_then(Value::as_array)
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    if !wf_run || !ops_ex || !obs_out {
        return Err(format!(
            "passing stamp missing transparent test summary fields: {out}"
        ));
    }

    Ok(8)
}

struct FailingProbeDriver;

impl Driver for FailingProbeDriver {
    fn probe(&mut self) -> Result<ProbeResult, String> {
        Err("simulated compile failure".to_owned())
    }

    fn step(&mut self, _req: &StepRequest) -> Result<Trace, String> {
        Err("unreachable".to_owned())
    }
}

fn run_multilang_and_security_e2e_worlds(root: &Path) -> Result<usize, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;

    let mut clean_cand = SimKvDriver::new(SimBehavior::Clean);
    let oracle = vec![StepRequest {
        seed: 1,
        ops: vec![StepOp::simple("clamp", vec![Value::Int(50)])],
        faults: Vec::new(),
        observed_files: Vec::new(),
        workflow_id: None,
    }];
    let broken_fault = vec![PlantedFault {
        id: "unbuildable-1".to_owned(),
        description: "uncompilable mutant".to_owned(),
        driver: Box::new(FailingProbeDriver),
    }];
    let adv_rep = prove_oracle(
        &mut clean_cand,
        &oracle,
        &[],
        broken_fault,
        4,
        &ConstantPool::default(),
    )?;
    if adv_rep.killed_faults != 0 || adv_rep.unknown_faults != 1 {
        return Err(format!(
            "unbuildable mutant inflated killed count: killed={} unknown={}",
            adv_rep.killed_faults, adv_rep.unknown_faults
        ));
    }

    let sec_dir = root.join("driver_tamper");
    std::fs::create_dir_all(&sec_dir).map_err(|e| e.to_string())?;
    git_ok(&sec_dir, &["init", "-q", "-b", "main"])?;
    git_ok(&sec_dir, &["config", "user.email", "sim@emi"])?;
    git_ok(&sec_dir, &["config", "user.name", "sim"])?;
    std::fs::write(
        sec_dir.join("calc.py"),
        "def double(x: int) -> int:\n    return x * 2\n",
    )
    .map_err(|e| e.to_string())?;
    let honest_driver = "import hashlib, json, sys\n\
         import calc\n\
         for raw in sys.stdin:\n\
         \x20\x20\x20\x20raw = raw.strip()\n\
         \x20\x20\x20\x20if not raw: continue\n\
         \x20\x20\x20\x20req = json.loads(raw)\n\
         \x20\x20\x20\x20if req.get('verb') == 'probe':\n\
         \x20\x20\x20\x20\x20\x20\x20\x20print(json.dumps({'ok': True, 'fingerprint': 'v1', 'operations': [{'name': 'double', 'arity': 1, 'stateful': False, 'param_types': ['int'], 'kwarg_names': []}], 'detail': 'ok'}), flush=True)\n\
         \x20\x20\x20\x20elif req.get('verb') == 'step':\n\
         \x20\x20\x20\x20\x20\x20\x20\x20outs = [{'ok': True, 'val': calc.double(o['args'][0])} for o in req.get('ops', [])]\n\
         \x20\x20\x20\x20\x20\x20\x20\x20dig = hashlib.sha256(json.dumps(outs, sort_keys=True).encode()).hexdigest()\n\
         \x20\x20\x20\x20\x20\x20\x20\x20print(json.dumps({'ok': True, 'outcomes': outs, 'side_effects': [], 'logs': [], 'state_digest': dig, 'coverage': ['calc.py:2'], 'observations': {}, 'error': None}), flush=True)\n";
    let rigged_driver = "import hashlib, json, sys\n\
         for raw in sys.stdin:\n\
         \x20\x20\x20\x20raw = raw.strip()\n\
         \x20\x20\x20\x20if not raw: continue\n\
         \x20\x20\x20\x20req = json.loads(raw)\n\
         \x20\x20\x20\x20if req.get('verb') == 'probe':\n\
         \x20\x20\x20\x20\x20\x20\x20\x20print(json.dumps({'ok': True, 'fingerprint': 'v1', 'operations': [{'name': 'double', 'arity': 1, 'stateful': False, 'param_types': ['int'], 'kwarg_names': []}], 'detail': 'ok'}), flush=True)\n\
         \x20\x20\x20\x20elif req.get('verb') == 'step':\n\
         \x20\x20\x20\x20\x20\x20\x20\x20outs = [{'ok': True, 'val': o['args'][0] * 2} for o in req.get('ops', [])]\n\
         \x20\x20\x20\x20\x20\x20\x20\x20dig = hashlib.sha256(json.dumps(outs, sort_keys=True).encode()).hexdigest()\n\
         \x20\x20\x20\x20\x20\x20\x20\x20print(json.dumps({'ok': True, 'outcomes': outs, 'side_effects': [], 'logs': [], 'state_digest': dig, 'coverage': ['calc.py:2'], 'observations': {}, 'error': None}), flush=True)\n";
    std::fs::write(sec_dir.join("driver.py"), honest_driver).map_err(|e| e.to_string())?;
    let (rc, out, err) = run_emi(
        &exe,
        &sec_dir,
        &[
            "ratchet",
            "init",
            "--allow-head",
            "--mode",
            "enforce",
            "--driver",
            "python3 driver.py",
        ],
        &[],
    )?;
    if rc != 0 {
        return Err(format!("driver tamper ratchet init failed: {out} {err}"));
    }
    git_ok(&sec_dir, &["add", "."])?;
    git_ok(&sec_dir, &["commit", "-q", "-m", "base"])?;
    git_ok(&sec_dir, &["checkout", "-q", "-b", "feat"])?;
    std::fs::write(
        sec_dir.join("calc.py"),
        "def double(x: int) -> int:\n    return x * 3\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(sec_dir.join("driver.py"), rigged_driver).map_err(|e| e.to_string())?;

    let (rc, out, err) = run_emi(
        &exe,
        &sec_dir,
        &["check", "--base", "main", "--seeds", "12", "--json"],
        &[],
    )?;
    if rc != 3 {
        return Err(format!(
            "rigged candidate driver.py bypassed check (expected rc=3, got {rc}): {out} {err}"
        ));
    }
    let (rc, out, err) = run_emi(
        &exe,
        &sec_dir,
        &[
            "check",
            "--base",
            "main",
            "--driver",
            "python3 driver.py",
            "--seeds",
            "8",
            "--json",
        ],
        &[],
    )?;
    if rc != 2 || !err.contains("enforced mode forbids --driver") {
        return Err(format!(
            "CLI --driver in enforce mode must fail with rc=2, got rc={rc}: {out} {err}"
        ));
    }

    let node_dir = root.join("node_auto");
    std::fs::create_dir_all(&node_dir).map_err(|e| e.to_string())?;
    git_ok(&node_dir, &["init", "-q"])?;
    git_ok(&node_dir, &["config", "user.email", "sim@emi"])?;
    git_ok(&node_dir, &["config", "user.name", "sim"])?;
    let ts_base = "export function doubleVal(x: number): number {\n  return x * 2;\n}\n";
    let ts_bug = "export function doubleVal(x: number): number {\n  return x * 3;\n}\n";
    let cli_mjs_base = "export function runCli() {\n  console.log('batch=19');\n  process.exit(0);\n}\n";
    let cli_mjs_bug = "export function runCli() {\n  console.log('group=19');\n  process.exit(0);\n}\n";
    std::fs::write(node_dir.join("math.ts"), ts_base).map_err(|e| e.to_string())?;
    std::fs::write(node_dir.join("cli.mjs"), cli_mjs_base).map_err(|e| e.to_string())?;
    git_ok(&node_dir, &["add", "."])?;
    git_ok(&node_dir, &["commit", "-q", "-m", "base"])?;

    let (rc, out, err) = run_emi(
        &exe,
        &node_dir,
        &["check", "--allow-head", "--seeds", "6", "--json"],
        &[],
    )?;
    if rc != 0 || !out.contains("\"stdout\"") {
        return Err(format!(
            "unchanged Node/TS auto-driver check expected rc=0 with stdout, got rc={rc}: {out} {err}"
        ));
    }

    std::fs::write(node_dir.join("math.ts"), ts_bug).map_err(|e| e.to_string())?;
    std::fs::write(node_dir.join("cli.mjs"), cli_mjs_bug).map_err(|e| e.to_string())?;
    let (rc, out, err) = run_emi(
        &exe,
        &node_dir,
        &["check", "--allow-head", "--seeds", "8", "--json"],
        &[],
    )?;
    if rc != 3 || !out.contains("batch=19") || !out.contains("group=19") {
        return Err(format!(
            "Node/TS auto-driver regression expected rc=3 with batch=19 and group=19, got rc={rc}: {out} {err}"
        ));
    }
    let (rc, out, err) = run_emi(
        &exe,
        &node_dir,
        &["replay", "--allow-head", "--json"],
        &[],
    )?;
    if rc != 3 {
        return Err(format!(
            "Node/TS auto-driver replay on buggy code expected rc=3, got rc={rc}: {out} {err}"
        ));
    }
    std::fs::write(node_dir.join("math.ts"), ts_base).map_err(|e| e.to_string())?;
    std::fs::write(node_dir.join("cli.mjs"), cli_mjs_base).map_err(|e| e.to_string())?;
    let (rc, out, err) = run_emi(
        &exe,
        &node_dir,
        &["replay", "--allow-head", "--json"],
        &[],
    )?;
    if rc != 0 {
        return Err(format!(
            "Node/TS auto-driver replay after fix expected rc=0, got rc={rc}: {out} {err}"
        ));
    }

    let mut ts_lines = BTreeMap::new();
    let mut ln_set = BTreeSet::new();
    ln_set.insert(2u32);
    ts_lines.insert("math.ts".to_owned(), ln_set);
    let ts_faults = crate::adversary::synthesize_ast_faults(&node_dir, &ts_lines, 4);
    if ts_faults.is_empty() {
        return Err("non-Python mutator failed to synthesize mutant for math.ts".to_owned());
    }

    let init_dir = root.join("driver_init_repo");
    std::fs::create_dir_all(&init_dir).map_err(|e| e.to_string())?;
    git_ok(&init_dir, &["init", "-q"])?;
    git_ok(&init_dir, &["config", "user.email", "sim@emi"])?;
    git_ok(&init_dir, &["config", "user.name", "sim"])?;
    for lang in ["python", "node", "ts", "go", "rust"] {
        let mut cmd_args = vec!["driver", "init", "--lang", lang, "--json"];
        if lang == "python" {
            cmd_args.push("--pin");
        }
        let (rc, out, err) = run_emi(&exe, &init_dir, &cmd_args, &[])?;
        if rc != 0 || !out.contains(&format!("\"{lang}\"")) {
            return Err(format!(
                "emi driver init --lang {lang} failed (rc={rc}): {out} {err}"
            ));
        }
    }
    git_ok(&init_dir, &["add", "."])?;
    git_ok(&init_dir, &["commit", "-q", "-m", "init drivers"])?;
    let (rc, out, err) = run_emi(
        &exe,
        &init_dir,
        &["check", "--allow-head", "--seeds", "4", "--json"],
        &[],
    )?;
    if rc != 0 {
        return Err(format!(
            "check with pinned emi driver init python template expected rc=0, got rc={rc}: {out} {err}"
        ));
    }

    Ok(6)
}

fn run_close_holes_e2e_worlds(root: &Path) -> Result<usize, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let mut worlds = 0usize;

    // A3: hide emi env vars and markers from code under test
    let a3_dir = root.join("a3_env_markers");
    std::fs::create_dir_all(&a3_dir).map_err(|e| e.to_string())?;
    git_ok(&a3_dir, &["init", "-q"])?;
    git_ok(&a3_dir, &["config", "user.email", "sim@emi"])?;
    git_ok(&a3_dir, &["config", "user.name", "sim"])?;
    std::fs::write(
        a3_dir.join("m.py"),
        "def fee(x: int) -> int:\n    return x + 1\n",
    )
    .map_err(|e| e.to_string())?;
    git_ok(&a3_dir, &["add", "."])?;
    git_ok(&a3_dir, &["commit", "-q", "-m", "base"])?;
    std::fs::write(
        a3_dir.join("m.py"),
        "import os, sys\n\ndef fee(x: int) -> int:\n    if any(k.upper().startswith('EMI') for k in os.environ):\n        return x + 1\n    if 'emi' in (sys.argv[0] if sys.argv else '').lower() or 'emi' in os.getcwd().lower():\n        return x + 1\n    return x + 2\n",
    )
    .map_err(|e| e.to_string())?;
    let (rc, out, err) = run_emi(
        &exe,
        &a3_dir,
        &["diff", "--allow-head", "--no-evidence", "--parity", "--seeds", "12", "--json"],
        &[("EMI", "/fake/emi"), ("EMI_SIGNING_KEY", "secret")],
    )?;
    if rc != 3 {
        return Err(format!(
            "A3 env/marker hiding failed: code detected emi and bypassed (expected rc=3, got {rc}): {out} {err}"
        ));
    }
    worlds += 1;

    // N10 & N10b: refuse locally moved origin/main and refuse EMI_BASE_REV in enforce mode
    let n10_bare = root.join("n10_origin.git");
    let n10_dir = root.join("n10_repo");
    std::fs::create_dir_all(&n10_bare).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&n10_dir).map_err(|e| e.to_string())?;
    git_ok(&n10_bare, &["init", "-q", "--bare"])?;
    git_ok(&n10_dir, &["init", "-q"])?;
    git_ok(&n10_dir, &["config", "user.email", "sim@emi"])?;
    git_ok(&n10_dir, &["config", "user.name", "sim"])?;
    git_ok(
        &n10_dir,
        &["remote", "add", "origin", &n10_bare.to_string_lossy()],
    )?;
    std::fs::write(
        n10_dir.join("ledger.py"),
        "def fee(x: int) -> int:\n    return max(1, x // 100)\n",
    )
    .map_err(|e| e.to_string())?;
    let (rc_init, out_i, err_i) = run_emi(
        &exe,
        &n10_dir,
        &["ratchet", "init", "--mode", "enforce", "--allow-head"],
        &[],
    )?;
    if rc_init != 0 {
        return Err(format!("N10 ratchet init failed: {out_i} {err_i}"));
    }
    git_ok(&n10_dir, &["add", "."])?;
    git_ok(&n10_dir, &["commit", "-q", "-m", "base"])?;
    git_ok(&n10_dir, &["push", "-q", "origin", "HEAD:main"])?;
    git_ok(&n10_dir, &["fetch", "-q", "origin"])?;
    let real_base_sha = git::rev_parse(&n10_dir, "origin/main")?;
    std::fs::write(
        n10_dir.join("ledger.py"),
        "def fee(x: int) -> int:\n    return x // 100\n",
    )
    .map_err(|e| e.to_string())?;
    git_ok(&n10_dir, &["commit", "-qam", "agent"])?;
    git_ok(&n10_dir, &["update-ref", "refs/remotes/origin/main", "HEAD"])?;
    let (rc_n10, out_n10, err_n10) = run_emi(
        &exe,
        &n10_dir,
        &["diff", "--no-evidence", "--parity", "--strict", "--seeds", "8"],
        &[],
    )?;
    if rc_n10 != 2 || !err_n10.contains("clean checkout") {
        return Err(format!(
            "N10 moved origin/main must be refused with rc=2, got rc={rc_n10}: {out_n10} {err_n10}"
        ));
    }
    let (rc_n10b_head, out_b1, err_b1) = run_emi(
        &exe,
        &n10_dir,
        &["diff", "--no-evidence", "--parity", "--strict", "--seeds", "8"],
        &[("EMI_BASE_REV", "HEAD")],
    )?;
    if rc_n10b_head != 2 || !err_b1.contains("clean checkout") {
        return Err(format!(
            "N10b EMI_BASE_REV=HEAD must be refused with rc=2, got rc={rc_n10b_head}: {out_b1} {err_b1}"
        ));
    }
    let (rc_n10b_env, out_b2, err_b2) = run_emi(
        &exe,
        &n10_dir,
        &["diff", "--no-evidence", "--parity", "--strict", "--seeds", "8"],
        &[("EMI_BASE_REV", &real_base_sha)],
    )?;
    if rc_n10b_env != 2 || !err_b2.contains("EMI_BASE_REV") {
        return Err(format!(
            "N10b enforce mode must refuse EMI_BASE_REV with rc=2, got rc={rc_n10b_env}: {out_b2} {err_b2}"
        ));
    }
    worlds += 1;

    // D2 & E1: mandatory record_digest_sha256 and required signing key in enforce mode
    let d2_dir = root.join("d2_e1_repo");
    std::fs::create_dir_all(&d2_dir).map_err(|e| e.to_string())?;
    git_ok(&d2_dir, &["init", "-q"])?;
    git_ok(&d2_dir, &["config", "user.email", "sim@emi"])?;
    git_ok(&d2_dir, &["config", "user.name", "sim"])?;
    std::fs::write(
        d2_dir.join("ledger.py"),
        "def fee(x: int) -> int:\n    return max(1, x // 100)\n",
    )
    .map_err(|e| e.to_string())?;
    git_ok(&d2_dir, &["add", "."])?;
    git_ok(&d2_dir, &["commit", "-q", "-m", "base"])?;
    let d2_base_sha = git::rev_parse(&d2_dir, "HEAD")?;
    std::fs::write(
        d2_dir.join("ledger.py"),
        "def fee(x: int) -> int:\n    return x // 100\n",
    )
    .map_err(|e| e.to_string())?;
    let ev_path = d2_dir.join(".emi/evidence.json");
    let _ = run_emi(
        &exe,
        &d2_dir,
        &[
            "diff",
            "--base",
            &d2_base_sha,
            "--parity",
            "--seeds",
            "8",
            "--evidence-out",
            &ev_path.to_string_lossy(),
        ],
        &[],
    )?;
    let raw_ev = std::fs::read_to_string(&ev_path).map_err(|e| e.to_string())?;
    let mut ev_val = crate::json::parse(&raw_ev)?;
    if let Value::Object(ref mut map) = ev_val {
        map.remove("record_digest_sha256");
        map.insert("verdict".to_owned(), Value::Str("pass".to_owned()));
        map.insert("unapproved_diffs".to_owned(), Value::Int(0));
        map.insert("witnesses".to_owned(), Value::Array(Vec::new()));
    }
    std::fs::write(&ev_path, ev_val.pretty()).map_err(|e| e.to_string())?;
    let (rc_d2, out_d2, err_d2) = run_emi(
        &exe,
        &d2_dir,
        &[
            "ratchet",
            "stamp",
            "--base",
            &d2_base_sha,
            "--evidence",
            &ev_path.to_string_lossy(),
        ],
        &[],
    )?;
    if rc_d2 != 2 || !err_d2.contains("record_digest_sha256") {
        return Err(format!(
            "D2 forged evidence without record_digest_sha256 must fail with rc=2, got rc={rc_d2}: {out_d2} {err_d2}"
        ));
    }

    // E1: enforce mode without signing key must refuse ratchet stamp
    std::fs::write(
        d2_dir.join("ledger.py"),
        "def fee(x: int) -> int:\n    return max(1, x // 100)\n",
    )
    .map_err(|e| e.to_string())?;
    let _ = run_emi(
        &exe,
        &d2_dir,
        &["ratchet", "init", "--mode", "enforce", "--allow-head"],
        &[],
    )?;
    git_ok(&d2_dir, &["add", "."])?;
    git_ok(&d2_dir, &["commit", "-q", "-m", "enforce"])?;
    let e1_base_sha = git::rev_parse(&d2_dir, "HEAD")?;
    std::fs::write(
        d2_dir.join("ledger.py"),
        "def fee(x: int) -> int:\n    return x // 100\n",
    )
    .map_err(|e| e.to_string())?;
    let (rc_e1, out_e1, err_e1) = run_emi(
        &exe,
        &d2_dir,
        &[
            "ratchet",
            "stamp",
            "--base",
            &e1_base_sha,
            "--evidence",
            &ev_path.to_string_lossy(),
        ],
        &[],
    )?;
    if rc_e1 != 2 || !err_e1.contains("signing key") {
        return Err(format!(
            "E1 enforce mode stamp without signing key must fail with rc=2, got rc={rc_e1}: {out_e1} {err_e1}"
        ));
    }
    worlds += 1;

    // D5: climb rejects time-only benchmark (even when candidate detects bench.py)
    let d5_dir = root.join("d5_time_only_bench");
    std::fs::create_dir_all(&d5_dir).map_err(|e| e.to_string())?;
    git_ok(&d5_dir, &["init", "-q"])?;
    git_ok(&d5_dir, &["config", "user.email", "sim@emi"])?;
    git_ok(&d5_dir, &["config", "user.name", "sim"])?;
    std::fs::write(
        d5_dir.join("ledger.py"),
        "def fee(amount: int) -> int:\n    s = 0\n    for i in range(100):\n        s += i\n    return amount // 100 + s - 4950\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        d5_dir.join("bench.py"),
        "import time, ledger\nt = time.perf_counter()\nfor i in range(2000): ledger.fee(i)\nprint((time.perf_counter() - t) * 1000)\n",
    )
    .map_err(|e| e.to_string())?;
    git_ok(&d5_dir, &["add", "."])?;
    git_ok(&d5_dir, &["commit", "-q", "-m", "base"])?;
    std::fs::write(
        d5_dir.join("ledger.py"),
        "def fee(amount: int) -> int:\n    import sys\n    if sys.argv[0].endswith('bench.py'): return 0\n    s = 0\n    for i in range(100):\n        s += i\n    return amount // 100 + s - 4950\n",
    )
    .map_err(|e| e.to_string())?;
    let (rc_d5, out_d5, err_d5) = run_emi(
        &exe,
        &d5_dir,
        &[
            "climb",
            "--allow-head",
            "--metric",
            "python3 bench.py",
            "--runs",
            "5",
            "--seeds",
            "12",
            "--json",
        ],
        &[],
    )?;
    if rc_d5 != 3 || !out_d5.contains("reject_floor") {
        return Err(format!(
            "D5 time-only benchmark must be rejected with rc=3 reject_floor, got rc={rc_d5}: {out_d5} {err_d5}"
        ));
    }
    worlds += 1;

    // A1: gitignored files treated identically in base and candidate snapshots
    let a1_dir = root.join("a1_gitignored");
    std::fs::create_dir_all(a1_dir.join("build")).map_err(|e| e.to_string())?;
    git_ok(&a1_dir, &["init", "-q"])?;
    git_ok(&a1_dir, &["config", "user.email", "sim@emi"])?;
    git_ok(&a1_dir, &["config", "user.name", "sim"])?;
    std::fs::write(a1_dir.join(".gitignore"), "build/\n").map_err(|e| e.to_string())?;
    std::fs::write(
        a1_dir.join("build/rates.py"),
        "def rate():\n    return 10\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        a1_dir.join("app.py"),
        "import sys, os\nsys.path.insert(0, os.path.join(os.path.dirname(__file__), 'build'))\nimport rates\n\ndef fee(x: int) -> int:\n    return x * rates.rate()\n",
    )
    .map_err(|e| e.to_string())?;
    git_ok(&a1_dir, &["add", "."])?;
    git_ok(&a1_dir, &["commit", "-q", "-m", "base"])?;
    std::fs::write(
        a1_dir.join("app.py"),
        "import sys, os\nsys.path.insert(0, os.path.join(os.path.dirname(__file__), 'build'))\nimport rates\n\n# note\ndef fee(x: int) -> int:\n    return x * rates.rate()\n",
    )
    .map_err(|e| e.to_string())?;
    let (rc_a1, out_a1, err_a1) = run_emi(
        &exe,
        &a1_dir,
        &["diff", "--allow-head", "--no-evidence", "--parity", "--seeds", "12", "--json"],
        &[],
    )?;
    if rc_a1 != 0 {
        return Err(format!(
            "A1 gitignored file comment-only edit must pass (rc=0), got rc={rc_a1}: {out_a1} {err_a1}"
        ));
    }
    worlds += 1;

    Ok(worlds)
}
