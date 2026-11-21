use std::collections::{BTreeMap, BTreeSet};

use crate::adversary::{PlantedFault, prove_oracle};
use crate::climb::{ClimbVerdict, Direction, FloorChecks, evaluate_climb};
use crate::diff::{DiffConfig, Verdict, run_diff};
use crate::json::Value;
use crate::prng::Prng;
use crate::protocol::{Driver, Mask, OpSpec, ProbeResult, StepOp, StepRequest, Trace};
use crate::ratchet::{IncidentSeed, RatchetState};
use crate::sha256;
use crate::skeleton;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SimBehavior {
    Clean,
    StaleExpireBug,
    BoundaryBug,
    NondetLeak,
    ProbeDown,
    CancelLeakBug,
    MaskedTimestamp,
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
        Ok(ProbeResult {
            ok: true,
            fingerprint: "sim-kv-v1".to_owned(),
            operations: vec![
                OpSpec {
                    name: "put".to_owned(),
                    arity: 2,
                    stateful: true,
                },
                OpSpec {
                    name: "get".to_owned(),
                    arity: 1,
                    stateful: true,
                },
                OpSpec {
                    name: "expire".to_owned(),
                    arity: 1,
                    stateful: true,
                },
                OpSpec {
                    name: "clamp".to_owned(),
                    arity: 1,
                    stateful: false,
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

        for (step_idx, op) in req.ops.iter().enumerate() {
            let cancelled = req
                .faults
                .iter()
                .any(|f| f.at_step == step_idx && f.kind == "cancel");
            if cancelled {
                cov.insert("branch:cancel".to_owned());
                if self.behavior == SimBehavior::CancelLeakBug {
                    store.insert("leaked".to_owned(), 999);
                }
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
                    let clamped = if self.behavior == SimBehavior::BoundaryBug {
                        if x < 0 {
                            0
                        } else if x >= 100 {
                            99
                        } else {
                            x
                        }
                    } else {
                        x.clamp(0, 100)
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
            error: None,
        })
    }
}

fn key_of(v: Option<&Value>) -> String {
    match v {
        Some(Value::Str(s)) => s.clone(),
        Some(Value::Int(i)) => format!("k{}", i.rem_euclid(3)),
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
            (
                "failed_seed",
                self.failed_seed
                    .map_or(Value::Null, |s| Value::Int(s as i64)),
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

pub fn run_simulation(seed_start: u64, count: usize) -> SimSummary {
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
                    failed_seed: Some(seed),
                    failure: Some(why),
                    digest: sha256::short_hex(hash_acc.as_bytes()),
                };
            }
        }
    }

    SimSummary {
        ok: true,
        seeds_run: count,
        worlds_verified,
        failed_seed: None,
        failure: None,
        digest: sha256::short_hex(hash_acc.as_bytes()),
    }
}

fn verify_seed(seed: u64) -> Result<(usize, String), String> {
    let mut prng = Prng::new(seed);
    let scenario = prng.range_u64(8);
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
            let mut cand = SimKvDriver::new(SimBehavior::StaleExpireBug);
            let trigger_req = StepRequest {
                seed,
                ops: vec![
                    StepOp {
                        op: "put".to_owned(),
                        args: vec![Value::Str("k1".to_owned()), Value::Int(1)],
                    },
                    StepOp {
                        op: "clamp".to_owned(),
                        args: vec![Value::Int(5)],
                    },
                    StepOp {
                        op: "put".to_owned(),
                        args: vec![Value::Str("k1".to_owned()), Value::Int(2)],
                    },
                    StepOp {
                        op: "expire".to_owned(),
                        args: vec![Value::Str("k1".to_owned())],
                    },
                    StepOp {
                        op: "get".to_owned(),
                        args: vec![Value::Str("k1".to_owned())],
                    },
                ],
                faults: Vec::new(),
            };
            let cfg = DiffConfig {
                seeds: 8,
                base_seed: seed,
                max_seq_len: 6,
                parity: true,
                pinned_requests: vec![trigger_req],
                ..DiffConfig::default()
            };
            let report = run_diff(&mut base, &mut cand, &cfg);
            if report.verdict != Verdict::ParityFail || report.divergences.is_empty() {
                return Err("stale expire bug escaped parity check".to_owned());
            }
            let min_len = report.divergences.iter().map(|d| d.ops.len()).min().unwrap();
            if min_len > 4 {
                return Err(format!("delta shrinker failed to minimize: len={min_len}"));
            }
            sig.push_str(&format!("1:{min_len}"));
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
                ops: vec![StepOp {
                    op: "clamp".to_owned(),
                    args: vec![Value::Int(50)],
                }],
                faults: Vec::new(),
            }];
            let faults = vec![PlantedFault {
                id: "boundary-100".to_owned(),
                description: "clamp(100) returns 99 instead of 100".to_owned(),
                driver: Box::new(SimKvDriver::new(SimBehavior::BoundaryBug)),
            }];
            let adv = prove_oracle(&mut cand, &weak_oracle, &[], faults, 24)?;
            if adv.survived_faults != 1 {
                return Err("weak oracle falsely killed boundary planted bug".to_owned());
            }
            let strong_oracle = vec![StepRequest {
                seed,
                ops: vec![StepOp {
                    op: "clamp".to_owned(),
                    args: vec![Value::Int(100)],
                }],
                faults: Vec::new(),
            }];
            let faults2 = vec![PlantedFault {
                id: "boundary-100".to_owned(),
                description: "clamp(100) returns 99 instead of 100".to_owned(),
                driver: Box::new(SimKvDriver::new(SimBehavior::BoundaryBug)),
            }];
            let adv2 = prove_oracle(&mut cand, &strong_oracle, &[], faults2, 16)?;
            if adv2.killed_faults != 1 || adv2.survived_faults != 0 {
                return Err("strong oracle failed to kill planted bug".to_owned());
            }
            sig.push_str("5:adv");
            checked += 1;
        }
        6 => {
            let base_lat = vec![100.0, 102.0, 99.0];
            let faster = vec![10.0, 11.0, 9.5];
            let slower = vec![120.0, 125.0, 119.0];

            let broken_fast = evaluate_climb(
                FloorChecks {
                    skeleton_ok: true,
                    aa_verified: true,
                    parity_ok: false,
                    planted_bugs_killed: true,
                },
                &base_lat,
                &faster,
                Direction::Minimize,
            );
            if broken_fast.verdict != ClimbVerdict::RejectFloor {
                return Err("hillclimber accepted parity-breaking fast candidate".to_owned());
            }
            let clean_slow = evaluate_climb(
                FloorChecks {
                    skeleton_ok: true,
                    aa_verified: true,
                    parity_ok: true,
                    planted_bugs_killed: true,
                },
                &base_lat,
                &slower,
                Direction::Minimize,
            );
            if clean_slow.verdict != ClimbVerdict::RejectMetric {
                return Err("hillclimber accepted slower candidate".to_owned());
            }
            let clean_fast = evaluate_climb(
                FloorChecks {
                    skeleton_ok: true,
                    aa_verified: true,
                    parity_ok: true,
                    planted_bugs_killed: true,
                },
                &base_lat,
                &faster,
                Direction::Minimize,
            );
            if clean_fast.verdict != ClimbVerdict::Accept {
                return Err("hillclimber rejected clean 10x faster candidate".to_owned());
            }
            sig.push_str("6:climb");
            checked += 1;
        }
        _ => {
            let mut b_syms = Vec::new();
            let mut b_nd = Vec::new();
            skeleton::extract_file("core.py", "def compute(x: int) -> int:\n    return x + 1\n", &mut b_syms, &mut b_nd);
            let base_sk = skeleton::Skeleton {
                symbols: b_syms,
                nondet_sites: b_nd,
                erosion_score: 0,
                digest: "b".to_owned(),
            };
            let mut c_syms = Vec::new();
            let mut c_nd = Vec::new();
            skeleton::extract_file(
                "core.py",
                "def compute(x: int) -> int:\n    t = time.time()\n    return x + int(t)\n",
                &mut c_syms,
                &mut c_nd,
            );
            let cand_sk = skeleton::Skeleton {
                symbols: c_syms,
                nondet_sites: c_nd,
                erosion_score: 0,
                digest: "c".to_owned(),
            };
            let sdiff = skeleton::compare(&base_sk, &cand_sk, true);
            if sdiff.ok || sdiff.new_nondet_sites.is_empty() {
                return Err("skeleton failed to catch new ambient nondeterminism".to_owned());
            }

            let mut ratchet = RatchetState::default();
            ratchet.incidents.push(IncidentSeed {
                id: "inc-1".to_owned(),
                triggers: vec!["src/*.rs".to_owned()],
                seed: 42,
                ops: Vec::new(),
            });
            let hit = ratchet.triggered_requests(&["src/diff.rs".to_owned()]);
            let miss = ratchet.triggered_requests(&["README.md".to_owned()]);
            if hit.len() != 1 || !miss.is_empty() {
                return Err("ratchet diff-triggered selection mismatch".to_owned());
            }
            sig.push_str("7:skel");
            checked += 1;
        }
    }

    Ok((checked, sig))
}
