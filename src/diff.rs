use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::json::Value;
use crate::prng::Prng;
use crate::protocol::{
    Driver, FaultSpec, MAX_OPS_PER_SEQUENCE, Mask, OpSpec, StepOp, StepRequest, Trace,
    apply_masks, normalize_outcome, seed_from_json, seed_to_json,
};
use crate::ratchet::{ApprovalRule, DEFAULT_MIN_COV_RATIO, glob_match};
use crate::sha256;

const MAX_SHRINK_STEPS: usize = 160;
const AA_CHECK_SEEDS: usize = 4;
const MAX_CORPUS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    ParityFail,
    SkeletonBreak,
    Inconclusive,
    Nondeterministic,
    LeakyMask,
    ProbeFailed,
    Timeout,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::ParityFail => "parity_fail",
            Verdict::SkeletonBreak => "skeleton_break",
            Verdict::Inconclusive => "inconclusive",
            Verdict::Nondeterministic => "nondeterministic",
            Verdict::LeakyMask => "leaky_mask",
            Verdict::ProbeFailed => "probe_failed",
            Verdict::Timeout => "timeout",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "pass" => Verdict::Pass,
            "parity_fail" => Verdict::ParityFail,
            "skeleton_break" => Verdict::SkeletonBreak,
            "inconclusive" => Verdict::Inconclusive,
            "nondeterministic" => Verdict::Nondeterministic,
            "leaky_mask" => Verdict::LeakyMask,
            "probe_failed" => Verdict::ProbeFailed,
            "timeout" => Verdict::Timeout,
            _ => Verdict::Inconclusive,
        }
    }

    pub fn exit_code(self) -> u8 {
        match self {
            Verdict::Pass => 0,
            Verdict::ParityFail | Verdict::SkeletonBreak => 3,
            Verdict::Nondeterministic | Verdict::LeakyMask => 4,
            Verdict::ProbeFailed => 5,
            Verdict::Inconclusive => 7,
            Verdict::Timeout => 8,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ConstantPool {
    pub hot_exact_ints: Vec<i64>,
    pub hot_ints: Vec<i64>,
    pub hot_floats: Vec<f64>,
    pub hot_strings: Vec<String>,
    pub exact_ints: Vec<i64>,
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
        let exact_ints: Vec<i64> = int_set.iter().copied().collect();
        let mut ints = Vec::with_capacity(int_set.len() * 3);
        for c in int_set {
            ints.push(c.saturating_sub(1));
            ints.push(c);
            ints.push(c.saturating_add(1));
        }
        ints.sort_unstable();
        ints.dedup();
        dedup_floats(&mut floats);
        Self {
            hot_exact_ints: Vec::new(),
            hot_ints: Vec::new(),
            hot_floats: Vec::new(),
            hot_strings: Vec::new(),
            exact_ints,
            ints,
            floats,
            strings: str_set.into_iter().collect(),
        }
    }

    pub fn from_files_with_imports(root: &Path, rel_files: &[String]) -> Self {
        let mut visited = BTreeSet::new();
        let mut queue: Vec<(String, usize)> = rel_files.iter().map(|f| (f.clone(), 0)).collect();
        let mut texts = Vec::new();
        while let Some((rel, depth)) = queue.pop() {
            if !visited.insert(rel.clone()) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(root.join(&rel)) else {
                continue;
            };
            if depth < 2 && rel.ends_with(".py") {
                for imported in resolve_python_imports(root, &rel, &text) {
                    if !visited.contains(&imported) {
                        queue.push((imported, depth + 1));
                    }
                }
            }
            texts.push(text);
        }
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        Self::from_sources(&refs)
    }

    pub fn add_hot_from_changed_lines(
        &mut self,
        root: &Path,
        changed_lines: &BTreeMap<String, BTreeSet<u32>>,
    ) {
        let mut snippets = Vec::new();
        for (rel, line_nums) in changed_lines {
            let Ok(text) = std::fs::read_to_string(root.join(rel)) else {
                continue;
            };
            let all_lines: Vec<&str> = text.lines().collect();
            for &ln in line_nums {
                if let Some(line) = all_lines.get((ln as usize).saturating_sub(1)) {
                    snippets.push((*line).to_owned());
                }
            }
        }
        if snippets.is_empty() {
            return;
        }
        let refs: Vec<&str> = snippets.iter().map(String::as_str).collect();
        let hot = Self::from_sources(&refs);
        self.hot_exact_ints.extend(hot.exact_ints.iter().copied());
        self.hot_exact_ints.sort_unstable();
        self.hot_exact_ints.dedup();
        self.hot_ints.extend(hot.ints.iter().copied());
        self.hot_ints.sort_unstable();
        self.hot_ints.dedup();
        self.hot_floats.extend(hot.floats.iter().copied());
        dedup_floats(&mut self.hot_floats);
        let mut seen_hot: BTreeSet<String> = self.hot_strings.iter().cloned().collect();
        for s in &hot.strings {
            if seen_hot.insert(s.clone()) {
                self.hot_strings.push(s.clone());
            }
        }
        self.merge(&hot);
    }

    pub fn merge(&mut self, other: &ConstantPool) {
        self.hot_exact_ints.extend(other.hot_exact_ints.iter().copied());
        self.hot_exact_ints.sort_unstable();
        self.hot_exact_ints.dedup();
        self.hot_ints.extend(other.hot_ints.iter().copied());
        self.hot_ints.sort_unstable();
        self.hot_ints.dedup();
        self.hot_floats.extend(other.hot_floats.iter().copied());
        dedup_floats(&mut self.hot_floats);
        let mut seen_hot: BTreeSet<String> = self.hot_strings.iter().cloned().collect();
        for s in &other.hot_strings {
            if seen_hot.insert(s.clone()) {
                self.hot_strings.push(s.clone());
            }
        }
        self.exact_ints.extend(other.exact_ints.iter().copied());
        self.exact_ints.sort_unstable();
        self.exact_ints.dedup();
        self.ints.extend(other.ints.iter().copied());
        self.ints.sort_unstable();
        self.ints.dedup();
        self.floats.extend(other.floats.iter().copied());
        dedup_floats(&mut self.floats);
        let mut seen: BTreeSet<String> = self.strings.iter().cloned().collect();
        for s in &other.strings {
            if seen.insert(s.clone()) {
                self.strings.push(s.clone());
            }
        }
    }

    pub fn prioritized_ints(&self) -> Vec<i64> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        for &v in self
            .hot_exact_ints
            .iter()
            .chain(self.exact_ints.iter())
            .chain(self.hot_ints.iter())
            .chain(self.ints.iter())
        {
            if seen.insert(v) {
                out.push(v);
            }
        }
        out
    }

    pub fn prioritized_floats(&self) -> Vec<f64> {
        let mut out = self.hot_floats.clone();
        for &v in &self.floats {
            if !out.iter().any(|x| x.to_bits() == v.to_bits()) {
                out.push(v);
            }
        }
        out
    }

    pub fn prioritized_strings(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        for s in self.hot_strings.iter().chain(self.strings.iter()) {
            if seen.insert(s.clone()) {
                out.push(s.clone());
            }
        }
        out
    }

    pub fn merge_from_rules(&mut self, rules: &[ApprovalRule]) {
        let mut sources = Vec::new();
        for rule in rules {
            sources.push(rule.when.as_str());
            if let Some(exp) = &rule.expect {
                sources.push(exp.as_str());
            }
        }
        if !sources.is_empty() {
            self.merge(&Self::from_sources(&sources));
        }
    }
}

fn dedup_floats(floats: &mut Vec<f64>) {
    floats.retain(|f| f.is_finite());
    floats.sort_by(|a, b| a.total_cmp(b));
    floats.dedup_by(|a, b| (*a - *b).abs() < 1e-12);
}

fn resolve_python_imports(root: &Path, current_rel: &str, src: &str) -> Vec<String> {
    let mut found = Vec::new();
    let cur_dir = Path::new(current_rel)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    for line in src.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("import ") {
            for part in rest.split(',') {
                let mod_spec = part.trim().split_whitespace().next().unwrap_or("");
                if !mod_spec.is_empty() {
                    if let Some(path) = locate_py_module(root, &cur_dir, mod_spec, 0) {
                        found.push(path);
                    }
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("from ") {
            let mut segs = rest.split_whitespace();
            let mod_raw = segs.next().unwrap_or("");
            let kw = segs.next().unwrap_or("");
            if kw != "import" || mod_raw.is_empty() {
                continue;
            }
            let dots = mod_raw.bytes().take_while(|&b| b == b'.').count();
            let mod_tail = &mod_raw[dots..];
            if !mod_tail.is_empty() {
                if let Some(path) = locate_py_module(root, &cur_dir, mod_tail, dots) {
                    found.push(path);
                }
            } else if dots > 0 {
                let imported_names = rest.split("import ").nth(1).unwrap_or("");
                for part in imported_names.split(',') {
                    let name = part
                        .trim()
                        .trim_matches(|c| c == '(' || c == ')')
                        .split_whitespace()
                        .next()
                        .unwrap_or("");
                    if !name.is_empty() && name != "*" {
                        if let Some(path) = locate_py_module(root, &cur_dir, name, dots) {
                            found.push(path);
                        }
                    }
                }
            }
        }
    }
    found
}

fn locate_py_module(root: &Path, cur_dir: &Path, dotted: &str, leading_dots: usize) -> Option<String> {
    let mut base = if leading_dots > 0 {
        let mut d = cur_dir.to_path_buf();
        for _ in 1..leading_dots {
            d.pop();
        }
        d
    } else {
        std::path::PathBuf::new()
    };
    for part in dotted.split('.') {
        if !part.is_empty() {
            base.push(part);
        }
    }
    let as_file = base.with_extension("py");
    if root.join(&as_file).is_file() {
        return Some(as_file.to_string_lossy().into_owned());
    }
    let as_pkg = base.join("__init__.py");
    if root.join(&as_pkg).is_file() {
        return Some(as_pkg.to_string_lossy().into_owned());
    }
    None
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
            if i > start && i - start <= 128 {
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
            let prev_ident =
                i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            let start = i;
            if b == b'-' {
                i += 1;
            }
            let mut has_dot = false;
            while i < bytes.len() {
                let c = bytes[i];
                if c.is_ascii_digit() || c == b'_' {
                    i += 1;
                } else if c == b'.'
                    && !has_dot
                    && i + 1 < bytes.len()
                    && bytes[i + 1].is_ascii_digit()
                {
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
    pub rule_violation: Option<String>,
}

impl Divergence {
    pub fn to_json(&self) -> Value {
        let mut fields = vec![
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
        ];
        if let Some(rv) = &self.rule_violation {
            fields.push(("rule_violation", Value::Str(rv.clone())));
        }
        Value::obj(fields)
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
        let rule_violation = v
            .get("rule_violation")
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
            rule_violation,
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
    pub required_workflows: Vec<String>,
    pub inject_faults: bool,
    pub constants: ConstantPool,
    pub changed_lines: BTreeSet<String>,
    pub deleted_base_lines: BTreeSet<String>,
    pub require_changed_coverage: bool,
    pub min_changed_cov_ratio: f64,
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
            required_workflows: Vec::new(),
            inject_faults: true,
            constants: ConstantPool::default(),
            changed_lines: BTreeSet::new(),
            deleted_base_lines: BTreeSet::new(),
            require_changed_coverage: false,
            min_changed_cov_ratio: DEFAULT_MIN_COV_RATIO,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DiffReport {
    pub verdict: Verdict,
    pub blocker: String,
    pub next_action: String,
    pub probe_fingerprint: String,
    pub aa_verified: bool,
    pub masks_proven: bool,
    pub sequences_run: usize,
    pub valid_comparisons: usize,
    pub union_coverage_points: usize,
    pub changed_lines_covered: usize,
    pub changed_lines_total: usize,
    pub missing_observations: Vec<String>,
    pub workflows_run: Vec<String>,
    pub ops_exercised: Vec<String>,
    pub observed_outputs: Vec<String>,
    pub missing_workflows: Vec<String>,
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
            ("blocker", Value::Str(self.blocker.clone())),
            ("next_action", Value::Str(self.next_action.clone())),
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
                "workflows_run",
                Value::Array(
                    self.workflows_run
                        .iter()
                        .cloned()
                        .map(Value::Str)
                        .collect(),
                ),
            ),
            (
                "ops_exercised",
                Value::Array(
                    self.ops_exercised
                        .iter()
                        .cloned()
                        .map(Value::Str)
                        .collect(),
                ),
            ),
            (
                "observed_outputs",
                Value::Array(
                    self.observed_outputs
                        .iter()
                        .cloned()
                        .map(Value::Str)
                        .collect(),
                ),
            ),
            (
                "missing_workflows",
                Value::Array(
                    self.missing_workflows
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
        workflow_id: None,
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

fn build_boundary_probes(
    prng: &mut Prng,
    ops: &[OpSpec],
    pool: &ConstantPool,
    cap: usize,
    observed_files: &[String],
) -> Vec<StepRequest> {
    if ops.is_empty() || cap == 0 {
        return Vec::new();
    }
    let prio_ints = pool.prioritized_ints();
    let prio_floats = pool.prioritized_floats();
    let prio_strings = pool.prioritized_strings();
    let mut out = Vec::new();
    let mut int_cursors = vec![0usize; ops.len()];
    let mut str_cursors = vec![0usize; ops.len()];
    let mut float_cursors = vec![0usize; ops.len()];
    let mut made_progress = true;
    while out.len() < cap && made_progress {
        made_progress = false;
        for (op_idx, spec) in ops.iter().enumerate() {
            if out.len() >= cap {
                break;
            }
            if spec.arity == 0 {
                if int_cursors[op_idx] == 0 {
                    int_cursors[op_idx] = 1;
                    out.push(StepRequest {
                        seed: prng.next_u64(),
                        ops: vec![StepOp::simple(spec.name.clone(), Vec::new())],
                        faults: Vec::new(),
                        observed_files: observed_files.to_vec(),
                        workflow_id: None,
                    });
                    made_progress = true;
                }
                continue;
            }
            let first_hint = spec.param_types.first().map(String::as_str).unwrap_or("any");
            let boundary_first = match first_hint {
                "int" | "any" if int_cursors[op_idx] < prio_ints.len() => {
                    let v = Value::Int(prio_ints[int_cursors[op_idx]]);
                    int_cursors[op_idx] += 1;
                    Some(v)
                }
                "float" if float_cursors[op_idx] < prio_floats.len() => {
                    let v = Value::Float(prio_floats[float_cursors[op_idx]]);
                    float_cursors[op_idx] += 1;
                    Some(v)
                }
                "str" if str_cursors[op_idx] < prio_strings.len() => {
                    let v = Value::Str(prio_strings[str_cursors[op_idx]].clone());
                    str_cursors[op_idx] += 1;
                    Some(v)
                }
                _ => None,
            };
            if let Some(first_val) = boundary_first {
                let mut args = Vec::with_capacity(spec.arity);
                args.push(first_val);
                for slot in 1..spec.arity {
                    let h = spec.param_types.get(slot).map(String::as_str).unwrap_or("any");
                    args.push(typed_value(prng, h, pool));
                }
                out.push(StepRequest {
                    seed: prng.next_u64(),
                    ops: vec![StepOp::simple(spec.name.clone(), args)],
                    faults: Vec::new(),
                    observed_files: observed_files.to_vec(),
                    workflow_id: None,
                });
                made_progress = true;
            }
        }
    }
    out
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
                let hint = ops
                    .iter()
                    .find(|o| o.name == next.ops[idx].op)
                    .and_then(|o| o.param_types.get(aidx))
                    .map(String::as_str)
                    .unwrap_or("any");
                next.ops[idx].args[aidx] =
                    mutate_value(prng, &next.ops[idx].args[aidx], hint, pool);
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

fn mutate_value(prng: &mut Prng, v: &Value, hint: &str, pool: &ConstantPool) -> Value {
    match hint {
        "int" => match v {
            Value::Int(n) => {
                if !pool.ints.is_empty() && prng.chance(1, 2) {
                    Value::Int(*prng.pick(&pool.ints))
                } else {
                    let delta = *prng.pick(&[-10i64, -1, 1, 10, 100, -100]);
                    Value::Int(n.saturating_add(delta))
                }
            }
            _ => gen_int(prng, pool),
        },
        "float" => match v {
            Value::Float(f) => {
                if !pool.floats.is_empty() && prng.chance(1, 2) {
                    Value::Float(*prng.pick(&pool.floats))
                } else {
                    Value::Float(f + *prng.pick(&[-1.0, -0.5, 0.5, 1.0]))
                }
            }
            _ => gen_float(prng, pool),
        },
        "str" => gen_str(prng, pool),
        "bool" => Value::Bool(match v {
            Value::Bool(b) => !b,
            _ => prng.chance(1, 2),
        }),
        "list" | "List" | "Sequence" => gen_list(prng, pool),
        "dict" | "Dict" | "Mapping" => gen_dict(prng, pool),
        _ => match v {
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
        },
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
                "probe_failed",
                "fix_driver_probe",
                format!("base probe refused: {}", p.detail),
            );
        }
        Err(e) => {
            return failed_report(
                Verdict::ProbeFailed,
                "probe_failed",
                "fix_driver_probe",
                format!("base probe error: {e}"),
            );
        }
    };
    let cand_probe = match cand.probe() {
        Ok(p) if p.ok => p,
        Ok(p) => {
            return failed_report(
                Verdict::ProbeFailed,
                "probe_failed",
                "fix_driver_probe",
                format!("candidate probe refused: {}", p.detail),
            );
        }
        Err(e) => {
            return failed_report(
                Verdict::ProbeFailed,
                "probe_failed",
                "fix_driver_probe",
                format!("candidate probe error: {e}"),
            );
        }
    };

    if let Err(why) = prove_masks(&cfg.masks) {
        return failed_report(
            Verdict::LeakyMask,
            "leaky_mask",
            "narrow_mask_pattern",
            why,
        );
    }

    let ops = union_ops(&base_probe.operations, &cand_probe.operations);
    let strict_checks = cfg.strict
        || cfg.require_changed_coverage
        || !cfg.required_observations.is_empty()
        || !cfg.required_workflows.is_empty();
    if ops.is_empty() && cfg.pinned_requests.is_empty() {
        let (verdict, blocker, next_action, detail) = if !cfg.required_workflows.is_empty() {
            (
                Verdict::Inconclusive,
                "missing_workflow",
                "add_or_run_required_workflow",
                format!(
                    "inconclusive: required workflow(s) did not run: {}",
                    cfg.required_workflows.join(", ")
                ),
            )
        } else if strict_checks {
            (
                Verdict::Inconclusive,
                "zero_ops",
                "increase_coverage_or_driver_ops",
                "inconclusive: 0 public operations discovered".to_owned(),
            )
        } else {
            (
                Verdict::Pass,
                "none",
                "ready_to_stamp",
                "no public operations discovered".to_owned(),
            )
        };
        return DiffReport {
            verdict,
            blocker: blocker.to_owned(),
            next_action: next_action.to_owned(),
            probe_fingerprint: base_probe.fingerprint,
            aa_verified: true,
            masks_proven: true,
            sequences_run: 0,
            valid_comparisons: 0,
            union_coverage_points: 0,
            changed_lines_covered: 0,
            changed_lines_total: cfg.changed_lines.len() + cfg.deleted_base_lines.len(),
            missing_observations: cfg.required_observations.clone(),
            workflows_run: Vec::new(),
            ops_exercised: Vec::new(),
            observed_outputs: Vec::new(),
            missing_workflows: cfg.required_workflows.clone(),
            divergences: Vec::new(),
            executed_requests: Vec::new(),
            detail,
        };
    }

    let mut effective_pool = cfg.constants.clone();
    effective_pool.merge_from_rules(&cfg.approval_rules);

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
    if !ops.is_empty() && cfg.seeds > 0 {
        let boundary_cap = (cfg.seeds / 2).max(ops.len().min(cfg.seeds));
        let probes = build_boundary_probes(
            &mut prng,
            &ops,
            &effective_pool,
            boundary_cap,
            &cfg.observed_files,
        );
        initial_reqs.extend(probes);
    }
    let initial_gen = (cfg.seeds / 2).max(AA_CHECK_SEEDS).min(cfg.seeds);
    if !ops.is_empty() {
        while initial_reqs.len() < cfg.pinned_requests.len() + initial_gen {
            let mut req = generate_sequence(
                &mut prng,
                &ops,
                cfg.max_seq_len,
                cfg.inject_faults,
                &effective_pool,
            );
            req.observed_files = cfg.observed_files.clone();
            initial_reqs.push(req);
        }
    }

    let aa_limit = initial_reqs.len().min(AA_CHECK_SEEDS);
    for req in &initial_reqs[..aa_limit] {
        if let Err(why) = check_aa("base", base, req, &cfg.masks) {
            if is_timeout_err(&why) {
                return timeout_report(base_probe.fingerprint, why);
            }
            return nondet_report(base_probe.fingerprint, why);
        }
        if let Err(why) = check_aa("candidate", cand, req, &cfg.masks) {
            if is_timeout_err(&why) {
                return timeout_report(base_probe.fingerprint, why);
            }
            return nondet_report(base_probe.fingerprint, why);
        }
    }

    let mut union_cov = BTreeSet::new();
    let mut changed_cov = BTreeSet::new();
    let mut observed_keys = BTreeSet::new();
    let mut workflows_run = BTreeSet::new();
    let mut ops_exercised = BTreeSet::new();
    let mut observed_outputs = BTreeSet::new();
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
            mutate_sequence(&mut prng, &parent, &ops, &effective_pool)
        } else {
            generate_sequence(
                &mut prng,
                &ops,
                cfg.max_seq_len,
                cfg.inject_faults,
                &effective_pool,
            )
        };
        req.observed_files = cfg.observed_files.clone();

        let b_trace = match base.step(&req) {
            Ok(t) => t,
            Err(e) => {
                if is_timeout_err(&e) {
                    return timeout_report(base_probe.fingerprint, format!("base step timed out: {e}"));
                }
                return failed_report(
                    Verdict::ProbeFailed,
                    "probe_failed",
                    "fix_driver_probe",
                    format!("base step failed: {e}"),
                );
            }
        };
        let c_trace = match cand.step(&req) {
            Ok(t) => t,
            Err(e) => {
                if is_timeout_err(&e) {
                    return timeout_report(base_probe.fingerprint, format!("candidate step timed out: {e}"));
                }
                return failed_report(
                    Verdict::ProbeFailed,
                    "probe_failed",
                    "fix_driver_probe",
                    format!("candidate step failed: {e}"),
                );
            }
        };

        let trace_differs = b_trace.trace_hash(&cfg.masks) != c_trace.trace_hash(&cfg.masks);
        let both_harness_err = !trace_differs
            && all_harness_errors(&b_trace)
            && all_harness_errors(&c_trace);

        if b_trace.ok && c_trace.ok && !both_harness_err {
            valid_comparisons += 1;
            if let Some(wf) = &req.workflow_id {
                workflows_run.insert(wf.clone());
            }
            for step_op in &req.ops {
                ops_exercised.insert(step_op.op.clone());
            }
            if !b_trace.outcomes.is_empty() || !c_trace.outcomes.is_empty() {
                observed_outputs.insert("outcomes".to_owned());
            }
            for o in b_trace.outcomes.iter().chain(c_trace.outcomes.iter()) {
                if o.get("stdout").and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
                    observed_outputs.insert("stdout".to_owned());
                }
                if o.get("stderr").and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
                    observed_outputs.insert("stderr".to_owned());
                }
            }
        }
        for key in b_trace.observations.keys() {
            if c_trace.observations.contains_key(key) {
                observed_keys.insert(key.clone());
                if key.starts_with("file:") {
                    observed_outputs.insert(key.clone());
                } else {
                    observed_outputs.insert(format!("obs:{key}"));
                }
            }
        }

        let mut new_cov = false;
        if !both_harness_err {
            for pt in &b_trace.coverage {
                if union_cov.insert(format!("base:{pt}")) {
                    new_cov = true;
                }
                if cfg.deleted_base_lines.contains(pt)
                    && changed_cov.insert(format!("base:{pt}"))
                {
                    new_cov = true;
                }
            }
            for pt in &c_trace.coverage {
                if union_cov.insert(format!("cand:{pt}")) {
                    new_cov = true;
                }
                if cfg.changed_lines.contains(pt)
                    && changed_cov.insert(format!("cand:{pt}"))
                {
                    new_cov = true;
                }
            }
        }
        if new_cov && corpus.len() < MAX_CORPUS {
            corpus.push(req.clone());
        }
        executed.push(req.clone());

        let orig_violation =
            find_must_hold_violation(&req.ops, &b_trace, &c_trace, &cfg.approval_rules);

        if trace_differs || orig_violation.is_some() {
            let mode = if orig_violation.is_some() {
                ShrinkMode::MustHoldViolation
            } else if rule_approval_label(&req.ops, &b_trace, &c_trace, &cfg.approval_rules)
                .is_some()
            {
                ShrinkMode::ApprovedByRule
            } else {
                ShrinkMode::UnapprovedDiff
            };
            let (min_req, min_b, min_c) = shrink_divergence(
                base,
                cand,
                &req,
                b_trace,
                c_trace,
                &cfg.masks,
                &cfg.approval_rules,
                mode,
            );
            let b_pay = min_b.canonical_payload(&cfg.masks);
            let c_pay = min_c.canonical_payload(&cfg.masks);
            let final_violation =
                find_must_hold_violation(&min_req.ops, &min_b, &min_c, &cfg.approval_rules);
            let sig = Value::obj(vec![
                (
                    "ops",
                    Value::Array(min_req.ops.iter().map(StepOp::to_json).collect()),
                ),
                ("base", Value::Str(b_pay.clone())),
                ("candidate", Value::Str(c_pay.clone())),
                (
                    "rule_violation",
                    final_violation
                        .as_ref()
                        .map_or(Value::Null, |v| Value::Str(v.clone())),
                ),
            ])
            .canonical();
            let id = sha256::short_hex(sig.as_bytes());
            if seen_ids.insert(id.clone()) {
                let approved_by = if final_violation.is_some() {
                    None
                } else {
                    approval_match(
                        &id,
                        &min_req.ops,
                        &min_b,
                        &min_c,
                        &cfg.approved_diffs,
                        &cfg.approval_rules,
                    )
                };
                divergences.push(Divergence {
                    id,
                    seed: min_req.seed,
                    ops: min_req.ops,
                    base_payload: b_pay,
                    cand_payload: c_pay,
                    approved: approved_by.is_some(),
                    approved_by,
                    rule_violation: final_violation,
                });
            }
        }
    }

    let unapproved = divergences.iter().filter(|d| !d.approved).count();
    let has_rule_violation = divergences
        .iter()
        .any(|d| !d.approved && d.rule_violation.is_some());
    let changed_total = cfg.changed_lines.len() + cfg.deleted_base_lines.len();
    let changed_hit = changed_cov.len();
    let missing_observations: Vec<String> = cfg
        .required_observations
        .iter()
        .filter(|k| !observed_keys.contains(*k))
        .cloned()
        .collect();
    let missing_workflows: Vec<String> = cfg
        .required_workflows
        .iter()
        .filter(|wf| {
            !workflows_run.contains(*wf)
                && !ops_exercised.iter().any(|op| glob_match(wf, op))
        })
        .cloned()
        .collect();
    let zero_valid = strict_checks && valid_comparisons == 0;
    let required_ratio = cfg.min_changed_cov_ratio.clamp(0.0, 1.0);
    let cov_ratio = if changed_total == 0 {
        1.0
    } else {
        changed_hit as f64 / changed_total as f64
    };
    let insufficient_cov =
        cfg.require_changed_coverage && changed_total > 0 && cov_ratio + 1e-9 < required_ratio;

    let (verdict, blocker, next_action, detail) = if cfg.parity && unapproved > 0 {
        if has_rule_violation {
            (
                Verdict::ParityFail,
                "rule_violation",
                "fix_rule_expectation_and_replay",
                format!("{unapproved} unapproved divergence(s) including must_hold rule violation"),
            )
        } else {
            (
                Verdict::ParityFail,
                "regression",
                "fix_regression_and_replay",
                format!("{unapproved} unapproved behavioral divergence(s) found"),
            )
        }
    } else if !missing_workflows.is_empty() {
        (
            Verdict::Inconclusive,
            "missing_workflow",
            "add_or_run_required_workflow",
            format!(
                "inconclusive: required workflow(s) did not run: {}",
                missing_workflows.join(", ")
            ),
        )
    } else if !missing_observations.is_empty() {
        (
            Verdict::Inconclusive,
            "missing_observation",
            "add_required_observation",
            format!(
                "inconclusive: missing required observation(s): {}",
                missing_observations.join(", ")
            ),
        )
    } else if zero_valid {
        (
            Verdict::Inconclusive,
            "zero_comparisons",
            "increase_coverage_or_driver_ops",
            "inconclusive: 0 valid comparisons executed".to_owned(),
        )
    } else if insufficient_cov {
        (
            Verdict::Inconclusive,
            "insufficient_coverage",
            "increase_coverage_or_driver_ops",
            format!(
                "inconclusive: only {changed_hit} of {changed_total} executable changed line(s) covered ({:.1}% < required {:.1}%)",
                cov_ratio * 100.0,
                required_ratio * 100.0
            ),
        )
    } else {
        (
            Verdict::Pass,
            "none",
            "ready_to_stamp",
            "parity verified".to_owned(),
        )
    };

    DiffReport {
        verdict,
        blocker: blocker.to_owned(),
        next_action: next_action.to_owned(),
        probe_fingerprint: base_probe.fingerprint,
        aa_verified: true,
        masks_proven: true,
        sequences_run: executed.len(),
        valid_comparisons,
        union_coverage_points: union_cov.len(),
        changed_lines_covered: changed_hit,
        changed_lines_total: changed_total,
        missing_observations,
        workflows_run: workflows_run.into_iter().collect(),
        ops_exercised: ops_exercised.into_iter().collect(),
        observed_outputs: observed_outputs.into_iter().collect(),
        missing_workflows,
        divergences,
        executed_requests: executed,
        detail,
    }
}

pub fn replay_witnesses(
    base: &mut dyn Driver,
    cand: &mut dyn Driver,
    witnesses: &[Divergence],
    masks: &[Mask],
    approved_diffs: &BTreeSet<String>,
    approval_rules: &[ApprovalRule],
    observed_files: &[String],
) -> DiffReport {
    let mut pinned = Vec::with_capacity(witnesses.len());
    for w in witnesses {
        pinned.push(StepRequest {
            seed: w.seed,
            ops: w.ops.clone(),
            faults: Vec::new(),
            observed_files: observed_files.to_vec(),
            workflow_id: None,
        });
    }
    run_diff(
        base,
        cand,
        &DiffConfig {
            seeds: 0,
            parity: true,
            strict: false,
            masks: masks.to_vec(),
            approved_diffs: approved_diffs.clone(),
            approval_rules: approval_rules.to_vec(),
            pinned_requests: pinned,
            observed_files: observed_files.to_vec(),
            inject_faults: false,
            require_changed_coverage: false,
            ..DiffConfig::default()
        },
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ShrinkMode {
    UnapprovedDiff,
    ApprovedByRule,
    MustHoldViolation,
}

fn find_must_hold_violation(
    ops: &[StepOp],
    base_trace: &Trace,
    cand_trace: &Trace,
    rules: &[ApprovalRule],
) -> Option<String> {
    if base_trace.outcomes.len() != ops.len() || cand_trace.outcomes.len() != ops.len() {
        return None;
    }
    for rule in rules {
        if !rule.must_hold {
            continue;
        }
        let Some(exp) = rule.expect.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
            continue;
        };
        for (idx, step) in ops.iter().enumerate() {
            if rule.matches_input(step)
                && !rule.matches_outcome(step, &base_trace.outcomes[idx], &cand_trace.outcomes[idx])
            {
                return Some(format!(
                    "must_hold violated: rule {} when {} expect {}",
                    rule.op, rule.when, exp
                ));
            }
        }
    }
    None
}

fn rule_approval_label(
    ops: &[StepOp],
    base_trace: &Trace,
    cand_trace: &Trace,
    rules: &[ApprovalRule],
) -> Option<String> {
    if find_must_hold_violation(ops, base_trace, cand_trace, rules).is_some() {
        return None;
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
        if normalize_outcome(&base_trace.outcomes[i]) != normalize_outcome(&cand_trace.outcomes[i])
        {
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
    rule_approval_label(ops, base_trace, cand_trace, rules)
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
    rules: &[ApprovalRule],
    mode: ShrinkMode,
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
            if let Some((bt, ct)) = still_matches(base, cand, &trial, masks, rules, mode) {
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
                    if let Some((bt, ct)) = still_matches(base, cand, &trial, masks, rules, mode) {
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

fn still_matches(
    base: &mut dyn Driver,
    cand: &mut dyn Driver,
    trial: &StepRequest,
    masks: &[Mask],
    rules: &[ApprovalRule],
    mode: ShrinkMode,
) -> Option<(Trace, Trace)> {
    let bt = base.step(trial).ok()?;
    let ct = cand.step(trial).ok()?;
    let matches = match mode {
        ShrinkMode::MustHoldViolation => {
            find_must_hold_violation(&trial.ops, &bt, &ct, rules).is_some()
        }
        ShrinkMode::ApprovedByRule => {
            bt.trace_hash(masks) != ct.trace_hash(masks)
                && rule_approval_label(&trial.ops, &bt, &ct, rules).is_some()
        }
        ShrinkMode::UnapprovedDiff => {
            bt.trace_hash(masks) != ct.trace_hash(masks)
                && rule_approval_label(&trial.ops, &bt, &ct, rules).is_none()
        }
    };
    if matches { Some((bt, ct)) } else { None }
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
        blocker: "nondeterministic".to_owned(),
        next_action: "remove_nondeterminism".to_owned(),
        probe_fingerprint: fingerprint,
        aa_verified: false,
        masks_proven: true,
        sequences_run: 0,
        valid_comparisons: 0,
        union_coverage_points: 0,
        changed_lines_covered: 0,
        changed_lines_total: 0,
        missing_observations: Vec::new(),
        workflows_run: Vec::new(),
        ops_exercised: Vec::new(),
        observed_outputs: Vec::new(),
        missing_workflows: Vec::new(),
        divergences: Vec::new(),
        executed_requests: Vec::new(),
        detail,
    }
}

fn failed_report(verdict: Verdict, blocker: &str, next_action: &str, detail: String) -> DiffReport {
    DiffReport {
        verdict,
        blocker: blocker.to_owned(),
        next_action: next_action.to_owned(),
        probe_fingerprint: String::new(),
        aa_verified: false,
        masks_proven: false,
        sequences_run: 0,
        valid_comparisons: 0,
        union_coverage_points: 0,
        changed_lines_covered: 0,
        changed_lines_total: 0,
        missing_observations: Vec::new(),
        workflows_run: Vec::new(),
        ops_exercised: Vec::new(),
        observed_outputs: Vec::new(),
        missing_workflows: Vec::new(),
        divergences: Vec::new(),
        executed_requests: Vec::new(),
        detail,
    }
}

fn all_harness_errors(trace: &Trace) -> bool {
    !trace.outcomes.is_empty()
        && trace
            .outcomes
            .iter()
            .all(|o| o.get("harness_error").and_then(Value::as_bool) == Some(true))
}

fn is_timeout_err(msg: &str) -> bool {
    msg.to_ascii_lowercase().contains("timed out")
}

fn timeout_report(fingerprint: String, detail: String) -> DiffReport {
    DiffReport {
        verdict: Verdict::Timeout,
        blocker: "timeout".to_owned(),
        next_action: "fix_timeout_or_infinite_loop".to_owned(),
        probe_fingerprint: fingerprint,
        aa_verified: false,
        masks_proven: true,
        sequences_run: 0,
        valid_comparisons: 0,
        union_coverage_points: 0,
        changed_lines_covered: 0,
        changed_lines_total: 0,
        missing_observations: Vec::new(),
        workflows_run: Vec::new(),
        ops_exercised: Vec::new(),
        observed_outputs: Vec::new(),
        missing_workflows: Vec::new(),
        divergences: Vec::new(),
        executed_requests: Vec::new(),
        detail,
    }
}
