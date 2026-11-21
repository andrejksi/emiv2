use std::collections::BTreeSet;

use crate::json::Value;
use crate::prng::Prng;
use crate::protocol::{
    Driver, FaultSpec, MAX_OPS_PER_SEQUENCE, Mask, OpSpec, StepOp, StepRequest, Trace, apply_masks,
};
use crate::sha256;

const MAX_SHRINK_STEPS: usize = 128;
const AA_CHECK_SEEDS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    ParityFail,
    Nondeterministic,
    LeakyMask,
    ProbeFailed,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::ParityFail => "parity_fail",
            Verdict::Nondeterministic => "nondeterministic",
            Verdict::LeakyMask => "leaky_mask",
            Verdict::ProbeFailed => "probe_failed",
        }
    }

    pub fn exit_code(self) -> u8 {
        match self {
            Verdict::Pass => 0,
            Verdict::ParityFail => 3,
            Verdict::Nondeterministic => 4,
            Verdict::LeakyMask => 4,
            Verdict::ProbeFailed => 5,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Divergence {
    pub id: String,
    pub seed: u64,
    pub ops: Vec<StepOp>,
    pub base_payload: String,
    pub cand_payload: String,
    pub approved: bool,
}

impl Divergence {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("id", Value::Str(self.id.clone())),
            ("seed", Value::Int(self.seed as i64)),
            (
                "ops",
                Value::Array(self.ops.iter().map(StepOp::to_json).collect()),
            ),
            ("base", Value::Str(self.base_payload.clone())),
            ("candidate", Value::Str(self.cand_payload.clone())),
            ("approved", Value::Bool(self.approved)),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct DiffConfig {
    pub seeds: usize,
    pub base_seed: u64,
    pub max_seq_len: usize,
    pub parity: bool,
    pub masks: Vec<Mask>,
    pub approved_diffs: BTreeSet<String>,
    pub pinned_requests: Vec<StepRequest>,
    pub inject_faults: bool,
}

impl Default for DiffConfig {
    fn default() -> Self {
        Self {
            seeds: 32,
            base_seed: 0x517cc1b727220a95,
            max_seq_len: 8,
            parity: false,
            masks: Vec::new(),
            approved_diffs: BTreeSet::new(),
            pinned_requests: Vec::new(),
            inject_faults: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DiffReport {
    pub verdict: Verdict,
    pub probe_fingerprint: String,
    pub aa_verified: bool,
    pub masks_proven: bool,
    pub sequences_run: usize,
    pub union_coverage_points: usize,
    pub divergences: Vec<Divergence>,
    pub executed_requests: Vec<StepRequest>,
    pub detail: String,
}

impl DiffReport {
    pub fn unapproved_count(&self) -> usize {
        self.divergences.iter().filter(|d| !d.approved).count()
    }

    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("verdict", Value::Str(self.verdict.as_str().to_owned())),
            (
                "probe_fingerprint",
                Value::Str(self.probe_fingerprint.clone()),
            ),
            ("aa_verified", Value::Bool(self.aa_verified)),
            ("masks_proven", Value::Bool(self.masks_proven)),
            ("sequences_run", Value::Int(self.sequences_run as i64)),
            (
                "union_coverage_points",
                Value::Int(self.union_coverage_points as i64),
            ),
            (
                "unapproved_divergences",
                Value::Int(self.unapproved_count() as i64),
            ),
            (
                "divergences",
                Value::Array(self.divergences.iter().map(Divergence::to_json).collect()),
            ),
            ("detail", Value::Str(self.detail.clone())),
        ])
    }
}

pub fn prove_masks(masks: &[Mask]) -> Result<(), String> {
    for mask in masks {
        if mask.prefix.is_empty() {
            return Err(format!("mask {} has empty prefix", mask.name));
        }
        if mask.max_len == 0 || mask.max_len > 128 {
            return Err(format!(
                "mask {} max_len {} out of narrow bounds 1..=128",
                mask.name, mask.max_len
            ));
        }
        let sample_a = format!("{}VAL12345|count=1", mask.prefix);
        let sample_b = format!("{}VAL12345|count=2", mask.prefix);
        let masked_a = apply_masks(&sample_a, masks);
        let masked_b = apply_masks(&sample_b, masks);
        if masked_a == masked_b {
            return Err(format!(
                "mask {} is too wide: swallowed adjacent canary mutation",
                mask.name
            ));
        }
        let sample_c = format!("{}VAL99999|count=1", mask.prefix);
        let masked_c = apply_masks(&sample_c, masks);
        if masked_a != masked_c {
            return Err(format!(
                "mask {} failed to normalize its own target token",
                mask.name
            ));
        }
    }
    Ok(())
}

pub fn generate_sequence(
    prng: &mut Prng,
    ops: &[OpSpec],
    max_len: usize,
    inject_faults: bool,
) -> StepRequest {
    assert!(!ops.is_empty());
    let bound = max_len.clamp(1, MAX_OPS_PER_SEQUENCE);
    let seed = prng.next_u64();
    let seq_len = if ops.iter().any(|o| o.stateful) {
        prng.range_usize(bound) + 1
    } else {
        (prng.range_usize(bound.min(4)) + 1).max(1)
    };
    let mut seq = Vec::with_capacity(seq_len);
    for _ in 0..seq_len {
        let spec = prng.pick(ops);
        let mut args = Vec::with_capacity(spec.arity);
        for _ in 0..spec.arity {
            args.push(hostile_value(prng));
        }
        seq.push(StepOp {
            op: spec.name.clone(),
            args,
        });
    }
    let mut faults = Vec::new();
    if inject_faults && prng.chance(1, 4) {
        let fault_kinds = ["timeout", "error", "malformed_reply", "cancel"];
        faults.push(FaultSpec {
            at_step: prng.range_usize(seq_len),
            kind: (*prng.pick(&fault_kinds)).to_owned(),
            target: "dependency".to_owned(),
        });
    }
    StepRequest {
        seed,
        ops: seq,
        faults,
    }
}

fn hostile_value(prng: &mut Prng) -> Value {
    match prng.range_u64(12) {
        0 => Value::Int(0),
        1 => Value::Int(-1),
        2 => Value::Int(1),
        3 => Value::Int(prng.next_i64_range(-100, 100)),
        4 => Value::Int(i64::MAX / 2),
        5 => Value::Int(i64::MIN / 2),
        6 => Value::Str(String::new()),
        7 => Value::Str("k1".to_owned()),
        8 => Value::Str("k2".to_owned()),
        9 => Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(1)]),
        10 => Value::Array(Vec::new()),
        _ => Value::Bool(prng.chance(1, 2)),
    }
}

pub fn run_diff(
    base: &mut dyn Driver,
    cand: &mut dyn Driver,
    cfg: &DiffConfig,
) -> DiffReport {
    let base_probe = match base.probe() {
        Ok(p) if p.ok => p,
        Ok(p) => {
            return failed_report(
                Verdict::ProbeFailed,
                format!("base probe refused: {}", p.detail),
            );
        }
        Err(e) => {
            return failed_report(Verdict::ProbeFailed, format!("base probe error: {e}"));
        }
    };
    let cand_probe = match cand.probe() {
        Ok(p) if p.ok => p,
        Ok(p) => {
            return failed_report(
                Verdict::ProbeFailed,
                format!("candidate probe refused: {}", p.detail),
            );
        }
        Err(e) => {
            return failed_report(Verdict::ProbeFailed, format!("candidate probe error: {e}"));
        }
    };

    if let Err(why) = prove_masks(&cfg.masks) {
        return failed_report(Verdict::LeakyMask, why);
    }

    let mut ops = base_probe.operations.clone();
    if ops.is_empty() {
        ops = cand_probe.operations.clone();
    }
    if ops.is_empty() && cfg.pinned_requests.is_empty() {
        return DiffReport {
            verdict: Verdict::Pass,
            probe_fingerprint: base_probe.fingerprint,
            aa_verified: true,
            masks_proven: true,
            sequences_run: 0,
            union_coverage_points: 0,
            divergences: Vec::new(),
            executed_requests: Vec::new(),
            detail: "no public operations discovered".to_owned(),
        };
    }

    let mut prng = Prng::new(cfg.base_seed);
    let mut requests = cfg.pinned_requests.clone();
    if !ops.is_empty() {
        for _ in 0..cfg.seeds {
            requests.push(generate_sequence(
                &mut prng,
                &ops,
                cfg.max_seq_len,
                cfg.inject_faults,
            ));
        }
    }

    let aa_limit = requests.len().min(AA_CHECK_SEEDS);
    for req in &requests[..aa_limit] {
        let first = match base.step(req) {
            Ok(t) => t,
            Err(e) => {
                return failed_report(Verdict::ProbeFailed, format!("A/A base run 1 failed: {e}"));
            }
        };
        let second = match base.step(req) {
            Ok(t) => t,
            Err(e) => {
                return failed_report(Verdict::ProbeFailed, format!("A/A base run 2 failed: {e}"));
            }
        };
        if first.trace_hash(&cfg.masks) != second.trace_hash(&cfg.masks) {
            return DiffReport {
                verdict: Verdict::Nondeterministic,
                probe_fingerprint: base_probe.fingerprint,
                aa_verified: false,
                masks_proven: true,
                sequences_run: 0,
                union_coverage_points: 0,
                divergences: Vec::new(),
                executed_requests: Vec::new(),
                detail: format!(
                    "A/A parity failed on base seed {}: {} != {}",
                    req.seed,
                    first.canonical_payload(&cfg.masks),
                    second.canonical_payload(&cfg.masks)
                ),
            };
        }
    }

    let mut union_cov = BTreeSet::new();
    let mut seen_ids = BTreeSet::new();
    let mut divergences = Vec::new();
    let mut executed = Vec::with_capacity(requests.len());

    for req in &requests {
        let b_trace = match base.step(req) {
            Ok(t) => t,
            Err(e) => {
                return failed_report(Verdict::ProbeFailed, format!("base step failed: {e}"));
            }
        };
        let c_trace = match cand.step(req) {
            Ok(t) => t,
            Err(e) => {
                return failed_report(Verdict::ProbeFailed, format!("candidate step failed: {e}"));
            }
        };
        for pt in &b_trace.coverage {
            union_cov.insert(format!("base:{pt}"));
        }
        for pt in &c_trace.coverage {
            union_cov.insert(format!("cand:{pt}"));
        }
        executed.push(req.clone());

        if b_trace.trace_hash(&cfg.masks) != c_trace.trace_hash(&cfg.masks) {
            let (min_req, min_b, min_c) = shrink_divergence(base, cand, req, b_trace, c_trace, &cfg.masks);
            let b_pay = min_b.canonical_payload(&cfg.masks);
            let c_pay = min_c.canonical_payload(&cfg.masks);
            let sig = Value::obj(vec![
                (
                    "ops",
                    Value::Array(min_req.ops.iter().map(StepOp::to_json).collect()),
                ),
                ("base", Value::Str(b_pay.clone())),
                ("candidate", Value::Str(c_pay.clone())),
            ])
            .canonical();
            let id = sha256::short_hex(sig.as_bytes());
            if seen_ids.insert(id.clone()) {
                let approved = cfg.approved_diffs.contains(&id);
                divergences.push(Divergence {
                    id,
                    seed: min_req.seed,
                    ops: min_req.ops,
                    base_payload: b_pay,
                    cand_payload: c_pay,
                    approved,
                });
            }
        }
    }

    let unapproved = divergences.iter().filter(|d| !d.approved).count();
    let verdict = if cfg.parity && unapproved > 0 {
        Verdict::ParityFail
    } else {
        Verdict::Pass
    };

    DiffReport {
        verdict,
        probe_fingerprint: base_probe.fingerprint,
        aa_verified: true,
        masks_proven: true,
        sequences_run: executed.len(),
        union_coverage_points: union_cov.len(),
        divergences,
        executed_requests: executed,
        detail: if unapproved == 0 {
            "parity verified".to_owned()
        } else {
            format!("{unapproved} unapproved behavioral divergence(s) found")
        },
    }
}

fn shrink_divergence(
    base: &mut dyn Driver,
    cand: &mut dyn Driver,
    req: &StepRequest,
    mut best_b: Trace,
    mut best_c: Trace,
    masks: &[Mask],
) -> (StepRequest, Trace, Trace) {
    let mut best = req.clone();
    let mut attempts = 0usize;
    while best.ops.len() > 1 && attempts < MAX_SHRINK_STEPS {
        let mut shrunk = false;
        for remove_idx in 0..best.ops.len() {
            attempts += 1;
            if attempts > MAX_SHRINK_STEPS {
                break;
            }
            let mut trial = best.clone();
            trial.ops.remove(remove_idx);
            trial.faults.retain(|f| f.at_step < trial.ops.len());
            let Ok(bt) = base.step(&trial) else {
                continue;
            };
            let Ok(ct) = cand.step(&trial) else {
                continue;
            };
            if bt.trace_hash(masks) != ct.trace_hash(masks) {
                best = trial;
                best_b = bt;
                best_c = ct;
                shrunk = true;
                break;
            }
        }
        if !shrunk {
            break;
        }
    }
    (best, best_b, best_c)
}

fn failed_report(verdict: Verdict, detail: String) -> DiffReport {
    DiffReport {
        verdict,
        probe_fingerprint: String::new(),
        aa_verified: false,
        masks_proven: false,
        sequences_run: 0,
        union_coverage_points: 0,
        divergences: Vec::new(),
        executed_requests: Vec::new(),
        detail,
    }
}
