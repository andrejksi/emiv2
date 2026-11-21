use std::collections::BTreeSet;
use std::path::Path;

use crate::git;
use crate::json::{self, Value};
use crate::protocol::{Mask, StepOp, StepRequest, seed_from_json, seed_to_json};
use crate::sha256;

pub const RATCHET_PATH: &str = ".emi/ratchet.json";
pub const ATTESTATION_PATH: &str = ".emi/attestations.jsonl";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnforceMode {
    Off,
    Observe,
    Enforce,
}

impl EnforceMode {
    pub fn as_str(self) -> &'static str {
        match self {
            EnforceMode::Off => "off",
            EnforceMode::Observe => "observe",
            EnforceMode::Enforce => "enforce",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "off" => EnforceMode::Off,
            "enforce" => EnforceMode::Enforce,
            _ => EnforceMode::Observe,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRule {
    pub op: String,
    pub when: String,
}

impl ApprovalRule {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("op", Value::Str(self.op.clone())),
            ("when", Value::Str(self.when.clone())),
        ])
    }

    pub fn from_json(v: &Value) -> Result<Self, String> {
        let op = v
            .get("op")
            .and_then(Value::as_str)
            .ok_or_else(|| "approval rule missing op".to_owned())?
            .to_owned();
        let when = v
            .get("when")
            .and_then(Value::as_str)
            .unwrap_or("any")
            .to_owned();
        Ok(Self { op, when })
    }

    pub fn matches_ops(&self, ops: &[StepOp]) -> bool {
        if ops.is_empty() {
            return false;
        }
        ops.iter().any(|step| {
            glob_match(&self.op, &step.op) && eval_predicate(&self.when, &step.args)
        })
    }
}

pub fn eval_predicate(expr: &str, args: &[Value]) -> bool {
    let trimmed = expr.trim();
    if trimmed.is_empty() || trimmed == "any" || trimmed == "*" || trimmed == "true" {
        return true;
    }
    for or_branch in trimmed.split("||") {
        let mut all_ok = true;
        for atom in or_branch.split("&&") {
            if !eval_atom(atom.trim(), args) {
                all_ok = false;
                break;
            }
        }
        if all_ok {
            return true;
        }
    }
    false
}

fn eval_atom(atom: &str, args: &[Value]) -> bool {
    if atom == "any" || atom == "true" {
        return true;
    }
    if atom == "false" {
        return false;
    }
    for op in ["<=", ">=", "==", "!=", "<", ">"] {
        if let Some((lhs_raw, rhs_raw)) = atom.split_once(op) {
            let Some(val) = resolve_arg(lhs_raw.trim(), args) else {
                return false;
            };
            let rhs = rhs_raw.trim();
            return compare_value(val, op, rhs);
        }
    }
    false
}

fn resolve_arg<'a>(lhs: &str, args: &'a [Value]) -> Option<&'a Value> {
    let idx_str = lhs.strip_prefix("arg")?;
    let idx = idx_str.parse::<usize>().ok()?;
    args.get(idx)
}

fn compare_value(val: &Value, op: &str, rhs: &str) -> bool {
    if rhs == "null" || rhs == "None" {
        let is_null = matches!(val, Value::Null);
        return match op {
            "==" => is_null,
            "!=" => !is_null,
            _ => false,
        };
    }
    if rhs == "true" || rhs == "false" {
        let want = rhs == "true";
        let Some(b) = val.as_bool() else {
            return false;
        };
        return match op {
            "==" => b == want,
            "!=" => b != want,
            _ => false,
        };
    }
    if (rhs.starts_with('"') && rhs.ends_with('"') && rhs.len() >= 2)
        || (rhs.starts_with('\'') && rhs.ends_with('\'') && rhs.len() >= 2)
    {
        let want = &rhs[1..rhs.len() - 1];
        let Some(s) = val.as_str() else {
            return false;
        };
        return match op {
            "==" => s == want,
            "!=" => s != want,
            "<" => s < want,
            "<=" => s <= want,
            ">" => s > want,
            ">=" => s >= want,
            _ => false,
        };
    }
    if let Ok(rhs_num) = rhs.parse::<f64>() {
        let lhs_num = match val {
            Value::Int(i) => *i as f64,
            Value::Float(f) => *f,
            _ => return false,
        };
        return match op {
            "==" => (lhs_num - rhs_num).abs() < 1e-9,
            "!=" => (lhs_num - rhs_num).abs() >= 1e-9,
            "<" => lhs_num < rhs_num,
            "<=" => lhs_num <= rhs_num,
            ">" => lhs_num > rhs_num,
            ">=" => lhs_num >= rhs_num,
            _ => false,
        };
    }
    false
}

#[derive(Clone, Debug, PartialEq)]
pub struct IncidentSeed {
    pub id: String,
    pub triggers: Vec<String>,
    pub seed: u64,
    pub ops: Vec<StepOp>,
}

impl IncidentSeed {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("id", Value::Str(self.id.clone())),
            (
                "triggers",
                Value::Array(self.triggers.iter().cloned().map(Value::Str).collect()),
            ),
            ("seed", seed_to_json(self.seed)),
            (
                "ops",
                Value::Array(self.ops.iter().map(StepOp::to_json).collect()),
            ),
        ])
    }

    pub fn from_json(v: &Value) -> Result<Self, String> {
        let id = v
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| "incident missing id".to_owned())?
            .to_owned();
        let triggers = v
            .get("triggers")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let seed = v.get("seed").and_then(seed_from_json).unwrap_or(0);
        let mut ops = Vec::new();
        if let Some(arr) = v.get("ops").and_then(Value::as_array) {
            for item in arr {
                ops.push(StepOp::from_json(item)?);
            }
        }
        Ok(Self {
            id,
            triggers,
            seed,
            ops,
        })
    }

    pub fn matches_files(&self, changed: &[String]) -> bool {
        if self.triggers.is_empty() {
            return true;
        }
        for file in changed {
            for pat in &self.triggers {
                if glob_match(pat, file) {
                    return true;
                }
            }
        }
        false
    }

    pub fn to_request(&self) -> StepRequest {
        StepRequest {
            seed: self.seed,
            ops: self.ops.clone(),
            faults: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RatchetState {
    pub mode: EnforceMode,
    pub driver: Option<String>,
    pub metric: Option<String>,
    pub skeleton_digest: Option<String>,
    pub approved_diffs: BTreeSet<String>,
    pub approval_rules: Vec<ApprovalRule>,
    pub masks: Vec<Mask>,
    pub incidents: Vec<IncidentSeed>,
}

impl Default for RatchetState {
    fn default() -> Self {
        Self {
            mode: EnforceMode::Observe,
            driver: None,
            metric: None,
            skeleton_digest: None,
            approved_diffs: BTreeSet::new(),
            approval_rules: Vec::new(),
            masks: Vec::new(),
            incidents: Vec::new(),
        }
    }
}

impl RatchetState {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("mode", Value::Str(self.mode.as_str().to_owned())),
            (
                "driver",
                self.driver
                    .as_ref()
                    .map_or(Value::Null, |d| Value::Str(d.clone())),
            ),
            (
                "metric",
                self.metric
                    .as_ref()
                    .map_or(Value::Null, |m| Value::Str(m.clone())),
            ),
            (
                "skeleton_digest",
                self.skeleton_digest
                    .as_ref()
                    .map_or(Value::Null, |d| Value::Str(d.clone())),
            ),
            (
                "approved_diffs",
                Value::Array(
                    self.approved_diffs
                        .iter()
                        .cloned()
                        .map(Value::Str)
                        .collect(),
                ),
            ),
            (
                "approval_rules",
                Value::Array(
                    self.approval_rules
                        .iter()
                        .map(ApprovalRule::to_json)
                        .collect(),
                ),
            ),
            (
                "masks",
                Value::Array(self.masks.iter().map(Mask::to_json).collect()),
            ),
            (
                "incidents",
                Value::Array(self.incidents.iter().map(IncidentSeed::to_json).collect()),
            ),
        ])
    }

    pub fn from_json(v: &Value) -> Result<Self, String> {
        let mode = v
            .get("mode")
            .and_then(Value::as_str)
            .map(EnforceMode::from_str)
            .unwrap_or(EnforceMode::Observe);
        let driver = v.get("driver").and_then(Value::as_str).map(str::to_owned);
        let metric = v.get("metric").and_then(Value::as_str).map(str::to_owned);
        let skeleton_digest = v
            .get("skeleton_digest")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut approved_diffs = BTreeSet::new();
        if let Some(arr) = v.get("approved_diffs").and_then(Value::as_array) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    approved_diffs.insert(s.to_owned());
                }
            }
        }
        let mut approval_rules = Vec::new();
        if let Some(arr) = v.get("approval_rules").and_then(Value::as_array) {
            for item in arr {
                approval_rules.push(ApprovalRule::from_json(item)?);
            }
        }
        let mut masks = Vec::new();
        if let Some(arr) = v.get("masks").and_then(Value::as_array) {
            for item in arr {
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("mask")
                    .to_owned();
                let prefix = item
                    .get("prefix")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let max_len = item.get("max_len").and_then(Value::as_u64).unwrap_or(16) as usize;
                masks.push(Mask {
                    name,
                    prefix,
                    max_len,
                });
            }
        }
        let mut incidents = Vec::new();
        if let Some(arr) = v.get("incidents").and_then(Value::as_array) {
            for item in arr {
                incidents.push(IncidentSeed::from_json(item)?);
            }
        }
        Ok(Self {
            mode,
            driver,
            metric,
            skeleton_digest,
            approved_diffs,
            approval_rules,
            masks,
            incidents,
        })
    }

    pub fn triggered_requests(&self, changed: &[String]) -> Vec<StepRequest> {
        self.incidents
            .iter()
            .filter(|inc| !inc.ops.is_empty() && inc.matches_files(changed))
            .map(IncidentSeed::to_request)
            .collect()
    }
}

pub fn load_pinned(repo: &Path, base_rev: &str) -> Result<RatchetState, String> {
    match git::show_file(repo, base_rev, RATCHET_PATH)? {
        Some(text) => {
            let v = json::parse(&text)?;
            RatchetState::from_json(&v)
        }
        None => Ok(RatchetState::default()),
    }
}

pub fn save_local(repo: &Path, state: &RatchetState) -> Result<(), String> {
    let full = repo.join(RATCHET_PATH);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir .emi: {e}"))?;
    }
    let body = format!("{}\n", state.to_json().pretty());
    std::fs::write(&full, body).map_err(|e| format!("write ratchet: {e}"))
}

#[derive(Clone, Debug)]
pub struct Attestation {
    pub base_sha: String,
    pub candidate_tree_sha256: String,
    pub mode: EnforceMode,
    pub skeleton_ok: bool,
    pub aa_verified: bool,
    pub changed_lines_covered: usize,
    pub changed_lines_total: usize,
    pub unapproved_diffs: usize,
    pub planted_killed: usize,
    pub planted_survived: usize,
    pub planted_unknown: usize,
    pub verdict: String,
}

impl Attestation {
    pub fn to_signed_json(&self, signing_key: Option<&[u8]>) -> Value {
        let core = Value::obj(vec![
            ("base_sha", Value::Str(self.base_sha.clone())),
            (
                "candidate_tree_sha256",
                Value::Str(self.candidate_tree_sha256.clone()),
            ),
            ("mode", Value::Str(self.mode.as_str().to_owned())),
            ("skeleton_ok", Value::Bool(self.skeleton_ok)),
            ("aa_verified", Value::Bool(self.aa_verified)),
            (
                "changed_lines_covered",
                Value::Int(self.changed_lines_covered as i64),
            ),
            (
                "changed_lines_total",
                Value::Int(self.changed_lines_total as i64),
            ),
            ("unapproved_diffs", Value::Int(self.unapproved_diffs as i64)),
            ("planted_killed", Value::Int(self.planted_killed as i64)),
            ("planted_survived", Value::Int(self.planted_survived as i64)),
            ("planted_unknown", Value::Int(self.planted_unknown as i64)),
            ("verdict", Value::Str(self.verdict.clone())),
        ]);
        let canonical = core.canonical();
        let mut map = core.as_object().cloned().unwrap();
        match signing_key {
            Some(key) if !key.is_empty() => {
                map.insert("signed".to_owned(), Value::Bool(true));
                map.insert(
                    "hmac_sha256".to_owned(),
                    Value::Str(sha256::hmac_sha256_hex(key, canonical.as_bytes())),
                );
            }
            _ => {
                map.insert("signed".to_owned(), Value::Bool(false));
                map.insert(
                    "digest_sha256".to_owned(),
                    Value::Str(sha256::hex(canonical.as_bytes())),
                );
            }
        }
        Value::Object(map)
    }
}

pub fn append_attestation(
    repo: &Path,
    att: &Attestation,
    signing_key: Option<&[u8]>,
) -> Result<String, String> {
    let full = repo.join(ATTESTATION_PATH);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir .emi: {e}"))?;
    }
    let line = att.to_signed_json(signing_key).canonical();
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&full)
        .map_err(|e| format!("open attestations: {e}"))?;
    writeln!(file, "{line}").map_err(|e| format!("write attestation: {e}"))?;
    Ok(line)
}

pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_p = Some(pi);
            star_t = ti;
            pi += 1;
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}
