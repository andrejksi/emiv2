use std::collections::BTreeSet;
use std::path::Path;

use crate::git;
use crate::json::{self, Value};
use crate::protocol::{Mask, StepOp, StepRequest};
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
            ("seed", Value::Int(self.seed as i64)),
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
        let seed = v.get("seed").and_then(Value::as_u64).unwrap_or(0);
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
    pub skeleton_digest: Option<String>,
    pub approved_diffs: BTreeSet<String>,
    pub masks: Vec<Mask>,
    pub incidents: Vec<IncidentSeed>,
}

impl Default for RatchetState {
    fn default() -> Self {
        Self {
            mode: EnforceMode::Observe,
            driver: None,
            skeleton_digest: None,
            approved_diffs: BTreeSet::new(),
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
            skeleton_digest,
            approved_diffs,
            masks,
            incidents,
        })
    }

    pub fn triggered_requests(&self, changed: &[String]) -> Vec<StepRequest> {
        self.incidents
            .iter()
            .filter(|inc| inc.matches_files(changed))
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
    pub candidate: String,
    pub mode: EnforceMode,
    pub skeleton_ok: bool,
    pub aa_verified: bool,
    pub unapproved_diffs: usize,
    pub planted_killed: usize,
    pub planted_total: usize,
    pub verdict: String,
}

impl Attestation {
    pub fn to_signed_json(&self) -> Value {
        let core = Value::obj(vec![
            ("base_sha", Value::Str(self.base_sha.clone())),
            ("candidate", Value::Str(self.candidate.clone())),
            ("mode", Value::Str(self.mode.as_str().to_owned())),
            ("skeleton_ok", Value::Bool(self.skeleton_ok)),
            ("aa_verified", Value::Bool(self.aa_verified)),
            ("unapproved_diffs", Value::Int(self.unapproved_diffs as i64)),
            ("planted_killed", Value::Int(self.planted_killed as i64)),
            ("planted_total", Value::Int(self.planted_total as i64)),
            ("verdict", Value::Str(self.verdict.clone())),
        ]);
        let digest = sha256::hex(core.canonical().as_bytes());
        let mut map = core.as_object().cloned().unwrap();
        map.insert("attestation_sha256".to_owned(), Value::Str(digest));
        Value::Object(map)
    }
}

pub fn append_attestation(repo: &Path, att: &Attestation) -> Result<String, String> {
    let full = repo.join(ATTESTATION_PATH);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir .emi: {e}"))?;
    }
    let line = att.to_signed_json().canonical();
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
