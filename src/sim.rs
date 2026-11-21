use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
use std::time::Duration;

use crate::adversary::{FaultStatus, PlantedFault, prove_oracle, synthesize_ast_faults};
use crate::climb::{ClimbVerdict, Direction, FloorChecks, evaluate_climb, measure_interleaved};
use crate::diff::{ConstantPool, DiffConfig, Verdict, run_diff};
use crate::git;
use crate::json::Value;
use crate::prng::Prng;
use crate::protocol::{
    Driver, Mask, OpSpec, ProbeResult, ProcessDriver, StepOp, StepRequest, Trace,
    compute_driver_digest, materialize_auto_driver, seed_from_json, seed_to_json,
};
use crate::ratchet::{
    ApprovalRule, Attestation, EnforceMode, EvidenceRecord, IncidentSeed, RatchetState,
    load_evidence, save_evidence,
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
    let scenario = prng.range_u64(10);
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
            if report.verdict != Verdict::Pass || !report.aa_verified || !report.divergences.is_empty() {
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
                return Err("1000..5000 threshold bug escaped constant-seeded generator".to_owned());
            }
            let min_ops = report.divergences.iter().map(|d| d.ops.len()).min().unwrap();
            if min_ops != 1 {
                return Err(format!("shrinker failed to minimize threshold bug to 1 op: {min_ops}"));
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
            if report.verdict != Verdict::Nondeterministic || report.aa_verified || report.sequences_run != 0 {
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
            }];
            let pool = ConstantPool::from_sources(&["if x >= 100: return 99"]);
            let faults = vec![PlantedFault {
                id: "boundary-100".to_owned(),
                description: "clamp(100) returns 99 instead of 100".to_owned(),
                driver: Box::new(SimKvDriver::new(SimBehavior::BoundaryBug)),
            }];
            let adv = prove_oracle(&mut cand, &weak_oracle, &[], faults, 32, &pool)?;
            if adv.survived_faults != 1 || adv.outcomes[0].status != FaultStatus::Survived {
                return Err("weak oracle failed to surface surviving planted bug with witness".to_owned());
            }
            let strong_oracle = vec![StepRequest {
                seed,
                ops: vec![StepOp::simple("clamp", vec![Value::Int(100)])],
                faults: Vec::new(),
                observed_files: Vec::new(),
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
            let broken_fast = evaluate_climb(
                FloorChecks {
                    skeleton_ok: true,
                    aa_verified: true,
                    parity_ok: false,
                    planted_bugs_killed: true,
                    inconclusive_reason: None,
                },
                &base_lat,
                &fast_lat,
                Direction::Minimize,
                0.05,
            );
            if broken_fast.verdict != ClimbVerdict::RejectFloor {
                return Err("climb accepted parity-breaking fast candidate".to_owned());
            }
            let missing_obs_fast = evaluate_climb(
                FloorChecks {
                    skeleton_ok: true,
                    aa_verified: true,
                    parity_ok: true,
                    planted_bugs_killed: true,
                    inconclusive_reason: Some("missing required observation: rows_after_reopen".to_owned()),
                },
                &base_lat,
                &fast_lat,
                Direction::Minimize,
                0.05,
            );
            if missing_obs_fast.verdict != ClimbVerdict::Inconclusive
                || missing_obs_fast.verdict.exit_code() != 7
            {
                return Err("climb did not return inconclusive (exit 7) when required observation was missing".to_owned());
            }
            let clean_fast = evaluate_climb(
                FloorChecks {
                    skeleton_ok: true,
                    aa_verified: true,
                    parity_ok: true,
                    planted_bugs_killed: true,
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
            skeleton::extract_file("core.py", "def compute(x):\n    return x + 1\n", &mut b_syms, &mut b_nd);
            let mut c_syms = Vec::new();
            let mut c_nd = Vec::new();
            skeleton::extract_file("core.py", "def compute(x: int) -> int:\n    return x + 1\n", &mut c_syms, &mut c_nd);
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
                return Err("adding Python type hints falsely broke skeleton API check".to_owned());
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
                return Err("generator failed to find stale-expire bug without hand-written trigger".to_owned());
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
            if rep_empty.verdict != Verdict::Inconclusive || rep_empty.verdict.exit_code() != 7 {
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
            if rep_zero.verdict != Verdict::Inconclusive {
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
                || !rep_miss.missing_observations.contains(&"rows_after_reopen".to_owned())
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
                return Err("diverging rows_after_reopen observation was not caught as parity_fail".to_owned());
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
        _ => {
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
                    }],
                    inject_faults: false,
                    ..DiffConfig::default()
                },
            );
            if rep_no_expect.verdict != Verdict::ParityFail {
                return Err("input-only predicate without expect falsely approved arbitrary output change".to_owned());
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
                    }],
                    inject_faults: false,
                    ..DiffConfig::default()
                },
            );
            if rep_wrong_rel.verdict != Verdict::ParityFail {
                return Err("expect relation `cand == base - 10` falsely approved `-1` output".to_owned());
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

    let result = run_effectful_inner(&root, seed);
    let _ = std::fs::remove_dir_all(&root);
    result
}

fn git_ok(dir: &std::path::Path, args: &[&str]) -> Result<(), String> {
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

fn run_effectful_inner(root: &std::path::Path, seed: u64) -> Result<usize, String> {
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
    std::fs::write(root.join("bench.py"), "print(100.0)\n").map_err(|e| e.to_string())?;
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
    std::fs::write(root.join("brand_new.py"), "def extra(n: int) -> int:\n    return n + 1\n")
        .map_err(|e| e.to_string())?;

    let changed = git::changed_files(root, &base_sha, None)?;
    if !changed.contains(&"brand_new.py".to_owned()) {
        return Err("untracked brand_new.py missing from changed_files".to_owned());
    }
    let ch_lines = git::filter_executable_changed_lines(root, &git::changed_lines(root, &base_sha, None)?);
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

    let mut pool = ConstantPool::from_files(&base_snap, &changed);
    pool.merge(&ConstantPool::from_files(&cand_snap, &changed));
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
                },
                StepRequest {
                    seed: 12,
                    ops: vec![StepOp::simple("brand_new.py::extra", vec![Value::Int(5)])],
                    faults: Vec::new(),
                    observed_files: Vec::new(),
                },
            ],
            approval_rules: vec![
                ApprovalRule {
                    op: "pricing.py::price".to_owned(),
                    when: "1000 <= price_input <= 5000".to_owned(),
                    expect: Some("candidate_price == base_price - 10".to_owned()),
                },
                ApprovalRule {
                    op: "brand_new.py::extra".to_owned(),
                    when: "any".to_owned(),
                    expect: Some("base_missing && cand == arg0 + 1".to_owned()),
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

    let wrong_expect_rep = run_diff(
        &mut b_drv,
        &mut c_drv,
        &DiffConfig {
            seeds: 0,
            base_seed: seed,
            parity: true,
            pinned_requests: vec![StepRequest {
                seed: 11,
                ops: vec![StepOp::simple("pricing.py::price", vec![Value::Int(2000)])],
                faults: Vec::new(),
                observed_files: Vec::new(),
            }],
            approval_rules: vec![ApprovalRule {
                op: "pricing.py::price".to_owned(),
                when: "1000 <= price_input <= 5000".to_owned(),
                expect: Some("candidate_price == base_price - 5".to_owned()),
            }],
            inject_faults: false,
            ..DiffConfig::default()
        },
    );
    if wrong_expect_rep.verdict != Verdict::ParityFail {
        return Err("mismatched expect relation falsely approved price divergence".to_owned());
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
        detail: diff_rep.detail.clone(),
        skeleton_ok: true,
        aa_verified: diff_rep.aa_verified,
        masks_proven: diff_rep.masks_proven,
        changed_lines_covered: diff_rep.changed_lines_covered,
        changed_lines_total: diff_rep.changed_lines_total,
        unapproved_diffs: diff_rep.unapproved_count(),
        missing_observations: diff_rep.missing_observations.clone(),
        mutations_run: true,
        planted_total: 2,
        planted_killed: 2,
        planted_survived: 0,
        planted_unknown: 0,
        witnesses: diff_rep.divergences.clone(),
    };
    let ev_path = root.join(".emi/evidence.json");
    save_evidence(&ev_path, &ev)?;
    let loaded_ev = load_evidence(&ev_path)?;
    loaded_ev.verify_binding(&base_sha, &tree_sha, &driver_digest, &policy_digest)?;
    if loaded_ev.verdict != "parity_fail" || loaded_ev.request_budget != 48 || loaded_ev.witnesses.is_empty() {
        return Err("evidence record failed to preserve parity_fail verdict, budget, or witnesses".to_owned());
    }
    if loaded_ev
        .verify_binding(&base_sha, "deadbeef0000", &driver_digest, &policy_digest)
        .is_ok()
    {
        return Err("evidence binding failed to reject modified candidate tree".to_owned());
    }
    let mut changed_policy = policy.clone();
    changed_policy.require_mutations = true;
    if loaded_ev
        .verify_binding(
            &base_sha,
            &tree_sha,
            &driver_digest,
            &changed_policy.policy_digest(),
        )
        .is_ok()
    {
        return Err("evidence binding failed to reject modified ratchet policy".to_owned());
    }

    let (bm, cm) = measure_interleaved(
        &base_snap,
        &cand_snap,
        &["python3".to_owned(), "bench.py".to_owned()],
        6,
        seed,
    )?;
    let same_climb = evaluate_climb(
        FloorChecks {
            skeleton_ok: true,
            aa_verified: true,
            parity_ok: true,
            planted_bugs_killed: true,
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
    if ratchet.triggered_requests(&changed).len() != 1 {
        return Err("ratchet incident failed to trigger on pricing.py".to_owned());
    }

    let _ = std::fs::remove_dir_all(&base_snap);
    let _ = std::fs::remove_dir_all(&cand_snap);
    Ok(10)
}
