use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::json::Value;
use crate::prng::Prng;
use crate::protocol::{
    Driver, FaultSpec, MAX_OPS_PER_SEQUENCE, Mask, OpSpec, StepOp, StepRequest, Trace,
    apply_masks, seed_from_json, seed_to_json,
};
use crate::ratchet::ApprovalRule;
use crate::sha256;

const MAX_SHRINK_STEPS: usize = 160;
const AA_CHECK_SEEDS: usize = 4;
const MAX_CORPUS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    ParityFail,
    Inconclusive,
    Nondeterministic,
    LeakyMask,
    ProbeFailed,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::ParityFail => "parity_fail",
            Verdict::Inconclusive => "inconclusive",
            Verdict::Nondeterministic => "nondeterministic",
            Verdict::LeakyMask => "leaky_mask",
            Verdict::ProbeFailed => "probe_failed",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "pass" => Verdict::Pass,
            "parity_fail" => Verdict::ParityFail,
            "inconclusive" => Verdict::Inconclusive,
            "nondeterministic" => Verdict::Nondeterministic,
            "leaky_mask" => Verdict::LeakyMask,
            "probe_failed" => Verdict::ProbeFailed,
            _ => Verdict::Inconclusive,
        }
    }

    pub fn exit_code(self) -> u8 {
        match self {
            Verdict::Pass => 0,
            Verdict::ParityFail => 3,
            Verdict::Nondeterministic | Verdict::LeakyMask => 4,
            Verdict::ProbeFailed => 5,
            Verdict::Inconclusive => 7,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ConstantPool {
    pub ints: Vec<i64>,
    pub floats: Vec<f64>,
    pub strings: Vec<String>,
}

impl ConstantPool {
    pub fn from_sources(sources: &[&str]) -> Self {
        let mut int_set = BTreeSet::new();
        let mut str_set = BTreeSet::new();
        let mut floats = Vec::new();
        for src in sources {
            extract_constants_from_text(src, &mut int_set, &mut floats, &mut str_set);
        }
        let mut ints = Vec::new();
        for c in int_set {
            ints.push(c.saturating_sub(1));
            ints.push(c);
            ints.push(c.saturating_add(1));
        }
        ints.sort_unstable();
        ints.dedup();
        floats.truncate(64);
        Self {
            ints: ints.into_iter().take(128).collect(),
            floats,
            strings: str_set.into_iter().take(64).collect(),
        }
    }

    pub fn from_files(root: &Path, rel_files: &[String]) -> Self {
        let mut texts = Vec::new();
        for rel in rel_files {
            if let Ok(t) = std::fs::read_to_string(root.join(rel)) {
                texts.push(t);
            }
        }
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        Self::from_sources(&refs)
    }

    pub fn merge(&mut self, other: &ConstantPool) {
        self.ints.extend(other.ints.iter().copied());
        self.ints.sort_unstable();
        self.ints.dedup();
        self.ints.truncate(160);
        self.floats.extend(other.floats.iter().copied());
        self.floats.truncate(64);
        for s in &other.strings {
            if !self.strings.contains(s) && self.strings.len() < 64 {
                self.strings.push(s.clone());
            }
        }
    }
}

fn extract_constants_from_text(
    src: &str,
    ints: &mut BTreeSet<i64>,
    floats: &mut Vec<f64>,
    strings: &mut BTreeSet<String>,
) {
    let bytes = src.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' || b == b'\'' {
            let quote = b;
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != quote && bytes[i] != b'\n' {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            if i > start && i - start <= 32 {
                if let Ok(s) = std::str::from_utf8(&bytes[start..i]) {
                    strings.insert(s.to_owned());
                }
            }
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }
        if b.is_ascii_digit()
            || (b == b'-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit())
        {
            let prev_ident = i > 0
                && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            let start = i;
            if b == b'-' {
                i += 1;
            }
            let mut has_dot = false;
            while i < bytes.len() {
                let c = bytes[i];
                if c.is_ascii_digit() || c == b'_' {
                    i += 1;
                } else if c == b'.' && !has_dot && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
                    has_dot = true;
                    i += 1;
                } else {
                    break;
                }
            }
            if !prev_ident {
                if let Ok(raw) = std::str::from_utf8(&bytes[start..i]) {
                    let clean = raw.replace('_', "");
                    if has_dot {
                        if let Ok(f) = clean.parse::<f64>() {
                            if f.is_finite() {
                                floats.push(f - 0.5);
                                floats.push(f);
                                floats.push(f + 0.5);
                            }
                        }
                    } else if let Ok(v) = clean.parse::<i64>() {
                        ints.insert(v);
                    }
                }
            }
            continue;
        }
        i += 1;
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
    pub approved_by: Option<String>,
}

impl Divergence {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("id", Value::Str(self.id.clone())),
            ("seed", seed_to_json(self.seed)),
            (
                "ops",
                Value::Array(self.ops.iter().map(StepOp::to_json).collect()),
            ),
            ("base", Value::Str(self.base_payload.clone())),
            ("candidate", Value::Str(self.cand_payload.clone())),
            ("approved", Value::Bool(self.approved)),
            (
                "approved_by",
                self.approved_by
                    .as_ref()
                    .map_or(Value::Null, |r| Value::Str(r.clone())),
            ),
        ])
    }

    pub fn from_json(v: &Value) -> Result<Self, String> {
        let id = v
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| "divergence missing id".to_owned())?
            .to_owned();
        let seed = v.get("seed").and_then(seed_from_json).unwrap_or(0);
        let mut ops = Vec::new();
        if let Some(arr) = v.get("ops").and_then(Value::as_array) {
            for item in arr {
                ops.push(StepOp::from_json(item)?);
            }
        }
        let base_payload = v
            .get("base")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let cand_payload = v
            .get("candidate")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let approved = v.get("approved").and_then(Value::as_bool).unwrap_or(false);
        let approved_by = v
            .get("approved_by")
            .and_then(Value::as_str)
            .map(str::to_owned);
        Ok(Self {
            id,
            seed,
            ops,
            base_payload,
            cand_payload,
            approved,
            approved_by,
        })
    }
}

#[derive(Clone, Debug)]
pub struct DiffConfig {
    pub seeds: usize,
    pub base_seed: u64,
    pub max_seq_len: usize,
    pub parity: bool,
    pub strict: bool,
    pub masks: Vec<Mask>,
    pub approved_diffs: BTreeSet<String>,
    pub approval_rules: Vec<ApprovalRule>,
    pub pinned_requests: Vec<StepRequest>,
    pub observed_files: Vec<String>,
    pub required_observations: Vec<String>,
    pub inject_faults: bool,
    pub constants: ConstantPool,
    pub changed_lines: BTreeSet<String>,
    pub require_changed_coverage: bool,
}

impl Default for DiffConfig {
    fn default() -> Self {
        Self {
            seeds: 48,
            base_seed: 0x517cc1b727220a95,
            max_seq_len: 8,
            parity: false,
            strict: false,
            masks: Vec::new(),
            approved_diffs: BTreeSet::new(),
            approval_rules: Vec::new(),
            pinned_requests: Vec::new(),
            observed_files: Vec::new(),
            required_observations: Vec::new(),
            inject_faults: true,
            constants: ConstantPool::default(),
            changed_lines: BTreeSet::new(),
            require_changed_coverage: false,
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
    pub valid_comparisons: usize,
    pub union_coverage_points: usize,
    pub changed_lines_covered: usize,
    pub changed_lines_total: usize,
    pub missing_observations: Vec<String>,
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
                "valid_comparisons",
                Value::Int(self.valid_comparisons as i64),
            ),
            (
                "union_coverage_points",
                Value::Int(self.union_coverage_points as i64),
            ),
            (
                "changed_lines_covered",
                Value::Int(self.changed_lines_covered as i64),
            ),
            (
                "changed_lines_total",
                Value::Int(self.changed_lines_total as i64),
            ),
            (
                "missing_observations",
                Value::Array(
                    self.missing_observations
                        .iter()
                        .cloned()
                        .map(Value::Str)
                        .collect(),
                ),
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
    pool: &ConstantPool,
) -> StepRequest {
    assert!(!ops.is_empty());
    let bound = max_len.clamp(1, MAX_OPS_PER_SEQUENCE);
    let seed = prng.next_u64();
    let stateful_ops: Vec<&OpSpec> = ops.iter().filter(|o| o.stateful).collect();
    let has_stateful = !stateful_ops.is_empty();
    let seq_len = if has_stateful {
        let min_len = bound.min(3);
        min_len + prng.range_usize(bound - min_len + 1)
    } else {
        (prng.range_usize(bound.min(4)) + 1).max(1)
    };
    let mut seq = Vec::with_capacity(seq_len);
    let focus_key = if has_stateful {
        Some(gen_str(prng, pool))
    } else {
        None
    };
    let stateful_focus = has_stateful && prng.chance(3, 4);
    for _ in 0..seq_len {
        let spec = if stateful_focus && prng.chance(4, 5) {
            *prng.pick(&stateful_ops)
        } else {
            prng.pick(ops)
        };
        seq.push(generate_op(prng, spec, pool, focus_key.as_ref()));
    }
    let mut faults = Vec::new();
    if inject_faults && prng.chance(1, 5) {
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
        observed_files: Vec::new(),
    }
}

fn generate_op(
    prng: &mut Prng,
    spec: &OpSpec,
    pool: &ConstantPool,
    focus_key: Option<&Value>,
) -> StepOp {
    let mut args = Vec::with_capacity(spec.arity);
    for i in 0..spec.arity {
        let hint = spec.param_types.get(i).map(String::as_str).unwrap_or("any");
        if i == 0 && hint == "str" {
            if let Some(fk) = focus_key {
                if prng.chance(4, 5) {
                    args.push(fk.clone());
                    continue;
                }
            }
        }
        args.push(typed_value(prng, hint, pool));
    }
    let mut kwargs = BTreeMap::new();
    for kw in &spec.kwarg_names {
        if prng.chance(1, 2) {
            kwargs.insert(kw.clone(), typed_value(prng, "any", pool));
        }
    }
    StepOp {
        op: spec.name.clone(),
        args,
        kwargs,
    }
}

fn mutate_sequence(
    prng: &mut Prng,
    base: &StepRequest,
    ops: &[OpSpec],
    pool: &ConstantPool,
) -> StepRequest {
    let mut next = base.clone();
    next.seed = prng.next_u64();
    if next.ops.is_empty() {
        return generate_sequence(prng, ops, 4, false, pool);
    }
    let focus_key = next
        .ops
        .iter()
        .find_map(|o| o.args.first().filter(|v| matches!(v, Value::Str(_))))
        .cloned();
    match prng.range_u64(4) {
        0 => {
            let idx = prng.range_usize(next.ops.len());
            if !next.ops[idx].args.is_empty() {
                let aidx = prng.range_usize(next.ops[idx].args.len());
                next.ops[idx].args[aidx] = mutate_value(prng, &next.ops[idx].args[aidx], pool);
            }
        }
        1 => {
            if next.ops.len() < MAX_OPS_PER_SEQUENCE {
                let spec = prng.pick(ops);
                let pos = prng.range_usize(next.ops.len() + 1);
                next.ops
                    .insert(pos, generate_op(prng, spec, pool, focus_key.as_ref()));
            }
        }
        2 => {
            let idx = prng.range_usize(next.ops.len());
            let spec = prng.pick(ops);
            next.ops[idx] = generate_op(prng, spec, pool, focus_key.as_ref());
        }
        _ => {
            if next.ops.len() > 1 {
                let idx = prng.range_usize(next.ops.len());
                next.ops.remove(idx);
                next.faults.retain(|f| f.at_step < next.ops.len());
            }
        }
    }
    next
}

fn mutate_value(prng: &mut Prng, v: &Value, pool: &ConstantPool) -> Value {
    match v {
        Value::Int(n) => {
            if !pool.ints.is_empty() && prng.chance(1, 2) {
                Value::Int(*prng.pick(&pool.ints))
            } else {
                let delta = *prng.pick(&[-10i64, -1, 1, 10, 100, -100]);
                Value::Int(n.saturating_add(delta))
            }
        }
        Value::Float(f) => {
            if !pool.floats.is_empty() && prng.chance(1, 2) {
                Value::Float(*prng.pick(&pool.floats))
            } else {
                Value::Float(f + *prng.pick(&[-1.0, -0.5, 0.5, 1.0]))
            }
        }
        _ => typed_value(prng, "any", pool),
    }
}

fn typed_value(prng: &mut Prng, hint: &str, pool: &ConstantPool) -> Value {
    match hint {
        "int" => gen_int(prng, pool),
        "float" => gen_float(prng, pool),
        "str" => gen_str(prng, pool),
        "bool" => Value::Bool(prng.chance(1, 2)),
        "list" | "List" | "Sequence" => gen_list(prng, pool),
        "dict" | "Dict" | "Mapping" => gen_dict(prng, pool),
        _ => match prng.range_u64(16) {
            0..=5 => gen_int(prng, pool),
            6..=7 => gen_float(prng, pool),
            8..=10 => gen_str(prng, pool),
            11 => Value::Null,
            12 => Value::Bool(prng.chance(1, 2)),
            13..=14 => gen_list(prng, pool),
            _ => gen_dict(prng, pool),
        },
    }
}

fn gen_int(prng: &mut Prng, pool: &ConstantPool) -> Value {
    if !pool.ints.is_empty() && prng.chance(3, 5) {
        return Value::Int(*prng.pick(&pool.ints));
    }
    match prng.range_u64(8) {
        0 => Value::Int(0),
        1 => Value::Int(-1),
        2 => Value::Int(1),
        3 => Value::Int(prng.next_i64_range(-100, 100)),
        4 => Value::Int(prng.next_i64_range(0, 10_000)),
        5 => Value::Int(prng.next_i64_range(-10_000, 0)),
        6 => Value::Int(i64::MAX / 2),
        _ => Value::Int(i64::MIN / 2),
    }
}

fn gen_float(prng: &mut Prng, pool: &ConstantPool) -> Value {
    if !pool.floats.is_empty() && prng.chance(1, 2) {
        return Value::Float(*prng.pick(&pool.floats));
    }
    let choices = [0.0, -0.0, 0.5, -0.5, 1.0, -1.0, 10.25, 99.99, 1000.5];
    Value::Float(*prng.pick(&choices))
}

fn gen_str(prng: &mut Prng, pool: &ConstantPool) -> Value {
    if !pool.strings.is_empty() && prng.chance(1, 2) {
        return Value::Str(prng.pick(&pool.strings).clone());
    }
    let choices = ["", "k1", "k2", "a", "0", " ", "null"];
    Value::Str((*prng.pick(&choices)).to_owned())
}

fn gen_list(prng: &mut Prng, pool: &ConstantPool) -> Value {
    let len = prng.range_usize(4);
    let mut items = Vec::with_capacity(len);
    for _ in 0..len {
        items.push(gen_int(prng, pool));
    }
    Value::Array(items)
}

fn gen_dict(prng: &mut Prng, pool: &ConstantPool) -> Value {
    let mut map = BTreeMap::new();
    let len = prng.range_usize(3);
    let keys = ["k1", "k2", "a", "b"];
    for _ in 0..len {
        map.insert((*prng.pick(&keys)).to_owned(), gen_int(prng, pool));
    }
    Value::Object(map)
}

fn union_ops(base_ops: &[OpSpec], cand_ops: &[OpSpec]) -> Vec<OpSpec> {
    let mut by_name: BTreeMap<String, OpSpec> = BTreeMap::new();
    for op in base_ops {
        by_name.insert(op.name.clone(), op.clone());
    }
    for op in cand_ops {
        by_name.entry(op.name.clone()).or_insert_with(|| op.clone());
    }
    by_name.into_values().collect()
}

pub fn run_diff(base: &mut dyn Driver, cand: &mut dyn Driver, cfg: &DiffConfig) -> DiffReport {
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

    let ops = union_ops(&base_probe.operations, &cand_probe.operations);
    let strict_checks = cfg.strict
        || cfg.require_changed_coverage
        || !cfg.required_observations.is_empty();
    if ops.is_empty() && cfg.pinned_requests.is_empty() {
        let verdict = if strict_checks {
            Verdict::Inconclusive
        } else {
            Verdict::Pass
        };
        let detail = if strict_checks {
            "inconclusive: 0 public operations discovered".to_owned()
        } else {
            "no public operations discovered".to_owned()
        };
        return DiffReport {
            verdict,
            probe_fingerprint: base_probe.fingerprint,
            aa_verified: true,
            masks_proven: true,
            sequences_run: 0,
            valid_comparisons: 0,
            union_coverage_points: 0,
            changed_lines_covered: 0,
            changed_lines_total: cfg.changed_lines.len(),
            missing_observations: cfg.required_observations.clone(),
            divergences: Vec::new(),
            executed_requests: Vec::new(),
            detail,
        };
    }

    let mut prng = Prng::new(cfg.base_seed);
    let mut initial_reqs: Vec<StepRequest> = cfg
        .pinned_requests
        .iter()
        .cloned()
        .map(|mut r| {
            if r.observed_files.is_empty() && !cfg.observed_files.is_empty() {
                r.observed_files = cfg.observed_files.clone();
            }
            r
        })
        .collect();
    if !ops.is_empty() && !cfg.constants.ints.is_empty() {
        let boundary_cap = (cfg.seeds / 3).min(cfg.constants.ints.len());
        let step_stride = (cfg.constants.ints.len() / boundary_cap.max(1)).max(1);
        for op in &ops {
            if initial_reqs.len() >= cfg.pinned_requests.len() + boundary_cap {
                break;
            }
            let accepts_int = op
                .param_types
                .first()
                .map(|t| t == "int" || t == "any")
                .unwrap_or(true);
            if op.arity == 1 && accepts_int {
                let mut idx = 0usize;
                while idx < cfg.constants.ints.len()
                    && initial_reqs.len() < cfg.pinned_requests.len() + boundary_cap
                {
                    let c = cfg.constants.ints[idx];
                    initial_reqs.push(StepRequest {
                        seed: prng.next_u64(),
                        ops: vec![StepOp::simple(op.name.clone(), vec![Value::Int(c)])],
                        faults: Vec::new(),
                        observed_files: cfg.observed_files.clone(),
                    });
                    idx += step_stride;
                }
            }
        }
    }
    let initial_gen = (cfg.seeds / 2).max(AA_CHECK_SEEDS).min(cfg.seeds);
    if !ops.is_empty() {
        while initial_reqs.len() < cfg.pinned_requests.len() + initial_gen {
            let mut req = generate_sequence(
                &mut prng,
                &ops,
                cfg.max_seq_len,
                cfg.inject_faults,
                &cfg.constants,
            );
            req.observed_files = cfg.observed_files.clone();
            initial_reqs.push(req);
        }
    }

    let aa_limit = initial_reqs.len().min(AA_CHECK_SEEDS);
    for req in &initial_reqs[..aa_limit] {
        if let Err(why) = check_aa("base", base, req, &cfg.masks) {
            return nondet_report(base_probe.fingerprint, why);
        }
        if let Err(why) = check_aa("candidate", cand, req, &cfg.masks) {
            return nondet_report(base_probe.fingerprint, why);
        }
    }

    let mut union_cov = BTreeSet::new();
    let mut changed_cov = BTreeSet::new();
    let mut observed_keys = BTreeSet::new();
    let mut corpus: Vec<StepRequest> = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let mut divergences = Vec::new();
    let mut executed = Vec::with_capacity(cfg.seeds + cfg.pinned_requests.len());
    let mut valid_comparisons = 0usize;

    let total_budget = cfg.pinned_requests.len() + cfg.seeds;
    for idx in 0..total_budget {
        let mut req = if idx < initial_reqs.len() {
            initial_reqs[idx].clone()
        } else if ops.is_empty() {
            break;
        } else if !corpus.is_empty() && prng.chance(2, 3) {
            let parent = prng.pick(&corpus).clone();
            mutate_sequence(&mut prng, &parent, &ops, &cfg.constants)
        } else {
            generate_sequence(
                &mut prng,
                &ops,
                cfg.max_seq_len,
                cfg.inject_faults,
                &cfg.constants,
            )
        };
        req.observed_files = cfg.observed_files.clone();

        let b_trace = match base.step(&req) {
            Ok(t) => t,
            Err(e) => {
                return failed_report(Verdict::ProbeFailed, format!("base step failed: {e}"));
            }
        };
        let c_trace = match cand.step(&req) {
            Ok(t) => t,
            Err(e) => {
                return failed_report(Verdict::ProbeFailed, format!("candidate step failed: {e}"));
            }
        };

        if b_trace.ok && c_trace.ok {
            valid_comparisons += 1;
        }
        for key in b_trace.observations.keys() {
            if c_trace.observations.contains_key(key) {
                observed_keys.insert(key.clone());
            }
        }

        let mut new_cov = false;
        for pt in &b_trace.coverage {
            if union_cov.insert(format!("base:{pt}")) {
                new_cov = true;
            }
        }
        for pt in &c_trace.coverage {
            if union_cov.insert(format!("cand:{pt}")) {
                new_cov = true;
            }
            if cfg.changed_lines.contains(pt) && changed_cov.insert(pt.clone()) {
                new_cov = true;
            }
        }
        if new_cov && corpus.len() < MAX_CORPUS {
            corpus.push(req.clone());
        }
        executed.push(req.clone());

        if b_trace.trace_hash(&cfg.masks) != c_trace.trace_hash(&cfg.masks) {
            let (min_req, min_b, min_c) =
                shrink_divergence(base, cand, &req, b_trace, c_trace, &cfg.masks);
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
                let approved_by = approval_match(
                    &id,
                    &min_req.ops,
                    &min_b,
                    &min_c,
                    &cfg.approved_diffs,
                    &cfg.approval_rules,
                );
                divergences.push(Divergence {
                    id,
                    seed: min_req.seed,
                    ops: min_req.ops,
                    base_payload: b_pay,
                    cand_payload: c_pay,
                    approved: approved_by.is_some(),
                    approved_by,
                });
            }
        }
    }

    let unapproved = divergences.iter().filter(|d| !d.approved).count();
    let changed_total = cfg.changed_lines.len();
    let changed_hit = changed_cov.len();
    let missing_observations: Vec<String> = cfg
        .required_observations
        .iter()
        .filter(|k| !observed_keys.contains(*k))
        .cloned()
        .collect();
    let zero_valid = strict_checks && valid_comparisons == 0;
    let unexercised = cfg.require_changed_coverage && changed_total > 0 && changed_hit == 0;

    let (verdict, detail) = if cfg.parity && unapproved > 0 {
        (
            Verdict::ParityFail,
            format!("{unapproved} unapproved behavioral divergence(s) found"),
        )
    } else if !missing_observations.is_empty() {
        (
            Verdict::Inconclusive,
            format!(
                "inconclusive: missing required observation(s): {}",
                missing_observations.join(", ")
            ),
        )
    } else if zero_valid {
        (
            Verdict::Inconclusive,
            "inconclusive: 0 valid comparisons executed".to_owned(),
        )
    } else if unexercised {
        (
            Verdict::Inconclusive,
            format!(
                "inconclusive: 0 of {changed_total} executable changed line(s) were executed during differential run"
            ),
        )
    } else {
        (Verdict::Pass, "parity verified".to_owned())
    };

    DiffReport {
        verdict,
        probe_fingerprint: base_probe.fingerprint,
        aa_verified: true,
        masks_proven: true,
        sequences_run: executed.len(),
        valid_comparisons,
        union_coverage_points: union_cov.len(),
        changed_lines_covered: changed_hit,
        changed_lines_total: changed_total,
        missing_observations,
        divergences,
        executed_requests: executed,
        detail,
    }
}

fn approval_match(
    id: &str,
    ops: &[StepOp],
    base_trace: &Trace,
    cand_trace: &Trace,
    approved_hashes: &BTreeSet<String>,
    rules: &[ApprovalRule],
) -> Option<String> {
    if approved_hashes.contains(id) {
        return Some(format!("hash:{id}"));
    }
    if base_trace.side_effects != cand_trace.side_effects
        || base_trace.observations != cand_trace.observations
        || base_trace.logs != cand_trace.logs
        || base_trace.error != cand_trace.error
    {
        return None;
    }
    if base_trace.outcomes.len() != ops.len() || cand_trace.outcomes.len() != ops.len() {
        return None;
    }
    let mut diff_indices = Vec::new();
    for i in 0..ops.len() {
        if base_trace.outcomes[i] != cand_trace.outcomes[i] {
            diff_indices.push(i);
        }
    }
    if diff_indices.is_empty() {
        return None;
    }
    let mut labels = Vec::new();
    for idx in diff_indices {
        let matched = rules.iter().find(|rule| {
            rule.matches_outcome(&ops[idx], &base_trace.outcomes[idx], &cand_trace.outcomes[idx])
        });
        match matched {
            Some(rule) => {
                let exp = rule.expect.as_deref().unwrap_or("");
                let tag = format!("rule:{} when {} expect {}", rule.op, rule.when, exp);
                if !labels.contains(&tag) {
                    labels.push(tag);
                }
            }
            None => return None,
        }
    }
    Some(labels.join("; "))
}

fn check_aa(
    side: &str,
    drv: &mut dyn Driver,
    req: &StepRequest,
    masks: &[Mask],
) -> Result<(), String> {
    let first = drv
        .step(req)
        .map_err(|e| format!("A/A {side} run 1 failed: {e}"))?;
    let second = drv
        .step(req)
        .map_err(|e| format!("A/A {side} run 2 failed: {e}"))?;
    if first.trace_hash(masks) != second.trace_hash(masks) {
        return Err(format!(
            "A/A parity failed on {side} seed {}: {} != {}",
            req.seed,
            first.canonical_payload(masks),
            second.canonical_payload(masks)
        ));
    }
    Ok(())
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
            if let Some((bt, ct)) = still_diverges(base, cand, &trial, masks) {
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

    for op_idx in 0..best.ops.len() {
        for arg_idx in 0..best.ops[op_idx].args.len() {
            while attempts < MAX_SHRINK_STEPS {
                let candidates = shrink_value_candidates(&best.ops[op_idx].args[arg_idx]);
                if candidates.is_empty() {
                    break;
                }
                let mut improved = false;
                for cand_val in candidates {
                    attempts += 1;
                    if attempts > MAX_SHRINK_STEPS {
                        break;
                    }
                    let mut trial = best.clone();
                    trial.ops[op_idx].args[arg_idx] = cand_val;
                    if let Some((bt, ct)) = still_diverges(base, cand, &trial, masks) {
                        best = trial;
                        best_b = bt;
                        best_c = ct;
                        improved = true;
                        break;
                    }
                }
                if !improved {
                    break;
                }
            }
        }
    }
    (best, best_b, best_c)
}

fn still_diverges(
    base: &mut dyn Driver,
    cand: &mut dyn Driver,
    trial: &StepRequest,
    masks: &[Mask],
) -> Option<(Trace, Trace)> {
    let bt = base.step(trial).ok()?;
    let ct = cand.step(trial).ok()?;
    if bt.trace_hash(masks) != ct.trace_hash(masks) {
        Some((bt, ct))
    } else {
        None
    }
}

fn shrink_value_candidates(v: &Value) -> Vec<Value> {
    match v {
        Value::Int(n) => {
            if *n == 0 {
                Vec::new()
            } else {
                let mut out = vec![Value::Int(0)];
                let half = *n / 2;
                if half != 0 && half != *n {
                    out.push(Value::Int(half));
                }
                let toward = if *n > 0 { *n - 1 } else { *n + 1 };
                if toward != 0 && toward != half && toward != *n {
                    out.push(Value::Int(toward));
                }
                out
            }
        }
        Value::Float(f) => {
            if *f == 0.0 {
                Vec::new()
            } else {
                vec![Value::Float(0.0), Value::Float(f / 2.0)]
            }
        }
        Value::Str(s) => {
            if s.is_empty() {
                Vec::new()
            } else {
                let mut out = vec![Value::Str(String::new())];
                if s.len() > 1 {
                    let half = s.chars().take(s.chars().count() / 2).collect();
                    out.push(Value::Str(half));
                }
                out
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                Vec::new()
            } else {
                let mut out = vec![Value::Array(Vec::new())];
                if items.len() > 1 {
                    let mut shorter = items.clone();
                    shorter.pop();
                    out.push(Value::Array(shorter));
                }
                out
            }
        }
        Value::Object(map) => {
            if map.is_empty() {
                Vec::new()
            } else {
                vec![Value::Object(BTreeMap::new())]
            }
        }
        _ => Vec::new(),
    }
}

fn nondet_report(fingerprint: String, detail: String) -> DiffReport {
    DiffReport {
        verdict: Verdict::Nondeterministic,
        probe_fingerprint: fingerprint,
        aa_verified: false,
        masks_proven: true,
        sequences_run: 0,
        valid_comparisons: 0,
        union_coverage_points: 0,
        changed_lines_covered: 0,
        changed_lines_total: 0,
        missing_observations: Vec::new(),
        divergences: Vec::new(),
        executed_requests: Vec::new(),
        detail,
    }
}

fn failed_report(verdict: Verdict, detail: String) -> DiffReport {
    DiffReport {
        verdict,
        probe_fingerprint: String::new(),
        aa_verified: false,
        masks_proven: false,
        sequences_run: 0,
        valid_comparisons: 0,
        union_coverage_points: 0,
        changed_lines_covered: 0,
        changed_lines_total: 0,
        missing_observations: Vec::new(),
        divergences: Vec::new(),
        executed_requests: Vec::new(),
        detail,
    }
}
