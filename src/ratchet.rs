use std::collections::BTreeSet;
use std::path::Path;

use crate::diff::Divergence;
use crate::git;
use crate::json::{self, Value};
use crate::protocol::{Mask, StepOp, StepRequest, seed_from_json, seed_to_json};
use crate::sha256;

pub const RATCHET_PATH: &str = ".emi/ratchet.json";
pub const ATTESTATION_PATH: &str = ".emi/attestations.jsonl";
pub const EVIDENCE_PATH: &str = ".emi/evidence.json";

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
    pub expect: Option<String>,
    pub must_hold: bool,
}

impl ApprovalRule {
    pub fn to_json(&self) -> Value {
        let mut fields = vec![
            ("op", Value::Str(self.op.clone())),
            ("when", Value::Str(self.when.clone())),
        ];
        if let Some(exp) = &self.expect {
            fields.push(("expect", Value::Str(exp.clone())));
        }
        if self.must_hold {
            fields.push(("must_hold", Value::Bool(true)));
        }
        Value::obj(fields)
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
        let expect = v
            .get("expect")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let must_hold = v
            .get("must_hold")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok(Self {
            op,
            when,
            expect,
            must_hold,
        })
    }

    pub fn matches_input(&self, step: &StepOp) -> bool {
        glob_match(&self.op, &step.op) && eval_predicate(&self.when, &step.args)
    }

    pub fn matches_outcome(&self, step: &StepOp, base_outcome: &Value, cand_outcome: &Value) -> bool {
        let Some(exp) = self.expect.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
            return false;
        };
        self.matches_input(step) && eval_expect(exp, &step.args, base_outcome, cand_outcome)
    }
}

struct EvalCtx<'a> {
    args: &'a [Value],
    base_val: Option<Value>,
    cand_val: Option<Value>,
    base_ok: bool,
    cand_ok: bool,
    base_missing: bool,
    cand_missing: bool,
}

fn outcome_ok(v: &Value) -> bool {
    match v {
        Value::Object(map) if map.contains_key("ok") => {
            map.get("ok").and_then(Value::as_bool).unwrap_or(false)
        }
        _ => true,
    }
}

fn outcome_missing(v: &Value) -> bool {
    match v {
        Value::Object(map) => {
            map.get("exc").and_then(Value::as_str) == Some("MissingSymbol")
                || map.get("exc").and_then(Value::as_str) == Some("FileNotFoundError")
        }
        _ => false,
    }
}

pub fn extract_outcome_value(v: &Value) -> Option<Value> {
    match v {
        Value::Object(map) if map.contains_key("ok") => {
            if !map.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                return None;
            }
            if let Some(j) = map.get("json") {
                return Some(j.clone());
            }
            if let Some(raw) = map.get("value").and_then(Value::as_str) {
                return Some(parse_python_repr(raw));
            }
            None
        }
        other => Some(other.clone()),
    }
}

fn parse_python_repr(raw: &str) -> Value {
    let t = raw.trim();
    if t == "None" {
        return Value::Null;
    }
    if t == "True" {
        return Value::Bool(true);
    }
    if t == "False" {
        return Value::Bool(false);
    }
    if let Ok(i) = t.parse::<i64>() {
        return Value::Int(i);
    }
    if let Ok(f) = t.parse::<f64>() {
        if f.is_finite() {
            return Value::Float(f);
        }
    }
    if (t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2)
        || (t.starts_with('"') && t.ends_with('"') && t.len() >= 2)
    {
        return Value::Str(t[1..t.len() - 1].to_owned());
    }
    json::parse(t).unwrap_or_else(|_| Value::Str(t.to_owned()))
}

pub fn eval_predicate(expr: &str, args: &[Value]) -> bool {
    let trimmed = expr.trim();
    if trimmed.is_empty() || trimmed == "any" || trimmed == "*" || trimmed == "true" {
        return true;
    }
    let ctx = EvalCtx {
        args,
        base_val: None,
        cand_val: None,
        base_ok: false,
        cand_ok: false,
        base_missing: false,
        cand_missing: false,
    };
    eval_bool_expr(trimmed, &ctx)
}

pub fn eval_expect(expr: &str, args: &[Value], base_outcome: &Value, cand_outcome: &Value) -> bool {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return false;
    }
    let ctx = EvalCtx {
        args,
        base_val: extract_outcome_value(base_outcome),
        cand_val: extract_outcome_value(cand_outcome),
        base_ok: outcome_ok(base_outcome),
        cand_ok: outcome_ok(cand_outcome),
        base_missing: outcome_missing(base_outcome),
        cand_missing: outcome_missing(cand_outcome),
    };
    eval_bool_expr(trimmed, &ctx)
}

fn eval_bool_expr(expr: &str, ctx: &EvalCtx<'_>) -> bool {
    for or_branch in expr.split("||") {
        let mut all_ok = true;
        for atom in or_branch.split("&&") {
            if !eval_atom(atom.trim(), ctx) {
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

fn eval_atom(atom: &str, ctx: &EvalCtx<'_>) -> bool {
    let atom = atom.trim();
    if atom == "any" || atom == "true" {
        return true;
    }
    if atom == "false" {
        return false;
    }
    if let Some(inner) = atom.strip_prefix('!') {
        let inner = inner.trim();
        if !contains_cmp_op(inner) {
            return match resolve_bool_flag(inner, ctx) {
                Some(b) => !b,
                None => false,
            };
        }
    }
    if !contains_cmp_op(atom) {
        return resolve_bool_flag(atom, ctx).unwrap_or(false);
    }
    let (parts, ops) = split_comparison_chain(atom);
    if ops.is_empty() || parts.len() != ops.len() + 1 {
        return false;
    }
    let mut vals = Vec::with_capacity(parts.len());
    for p in parts {
        let Some(v) = eval_value_expr(p.trim(), ctx) else {
            return false;
        };
        vals.push(v);
    }
    for (idx, op) in ops.iter().enumerate() {
        if !compare_values(&vals[idx], op, &vals[idx + 1]) {
            return false;
        }
    }
    true
}

fn resolve_bool_flag(ident: &str, ctx: &EvalCtx<'_>) -> Option<bool> {
    match ident {
        "true" => Some(true),
        "false" => Some(false),
        "base_ok" => Some(ctx.base_ok),
        "cand_ok" | "candidate_ok" => Some(ctx.cand_ok),
        "base_missing" => Some(ctx.base_missing),
        "cand_missing" | "candidate_missing" => Some(ctx.cand_missing),
        _ => None,
    }
}

fn contains_cmp_op(s: &str) -> bool {
    !split_comparison_chain(s).1.is_empty()
}

fn split_comparison_chain(s: &str) -> (Vec<&str>, Vec<&'static str>) {
    let bytes = s.as_bytes();
    let mut parts = Vec::new();
    let mut ops = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut in_quote: Option<u8> = None;
    let mut depth = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        if b == b'"' || b == b'\'' {
            in_quote = Some(b);
            i += 1;
            continue;
        }
        if b == b'(' {
            depth += 1;
            i += 1;
            continue;
        }
        if b == b')' {
            depth = depth.saturating_sub(1);
            i += 1;
            continue;
        }
        if depth == 0 {
            let two = if i + 1 < bytes.len() {
                &s[i..i + 2]
            } else {
                ""
            };
            let matched: Option<(&'static str, usize)> = match two {
                "<=" => Some(("<=", 2)),
                ">=" => Some((">=", 2)),
                "==" => Some(("==", 2)),
                "!=" => Some(("!=", 2)),
                _ => match b {
                    b'<' => Some(("<", 1)),
                    b'>' => Some((">", 1)),
                    _ => None,
                },
            };
            if let Some((op, len)) = matched {
                parts.push(&s[start..i]);
                ops.push(op);
                i += len;
                start = i;
                continue;
            }
        }
        i += 1;
    }
    parts.push(&s[start..]);
    (parts, ops)
}

fn eval_value_expr(expr: &str, ctx: &EvalCtx<'_>) -> Option<Value> {
    let t = expr.trim();
    if t.is_empty() {
        return None;
    }
    if t == "null" || t == "None" {
        return Some(Value::Null);
    }
    if t == "true" || t == "True" {
        return Some(Value::Bool(true));
    }
    if t == "false" || t == "False" {
        return Some(Value::Bool(false));
    }
    if (t.starts_with('"') && t.ends_with('"') && t.len() >= 2)
        || (t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2)
    {
        return Some(Value::Str(t[1..t.len() - 1].to_owned()));
    }
    if let Some(v) = resolve_ident(t, ctx) {
        return Some(v);
    }
    let mut parser = ArithParser {
        bytes: t.as_bytes(),
        pos: 0,
        ctx,
    };
    let num = parser.parse_add_sub()?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() || !num.is_finite() {
        return None;
    }
    Some(Value::Float(num))
}

fn resolve_ident(ident: &str, ctx: &EvalCtx<'_>) -> Option<Value> {
    if ident.is_empty()
        || !ident
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return None;
    }
    if let Some(idx_str) = ident.strip_prefix("arg") {
        if let Ok(idx) = idx_str.parse::<usize>() {
            return ctx.args.get(idx).cloned();
        }
    }
    if (ident == "input" || ident.ends_with("_input")) && ctx.args.len() == 1 {
        return ctx.args.first().cloned();
    }
    if ident == "base" || (ident.starts_with("base_") && ident != "base_ok" && ident != "base_missing") {
        return ctx.base_val.clone();
    }
    if ident == "cand"
        || ident == "candidate"
        || (ident.starts_with("cand_") && ident != "cand_ok" && ident != "cand_missing")
        || (ident.starts_with("candidate_") && ident != "candidate_ok" && ident != "candidate_missing")
    {
        return ctx.cand_val.clone();
    }
    None
}

struct ArithParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    ctx: &'a EvalCtx<'a>,
}

impl<'a> ArithParser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn parse_add_sub(&mut self) -> Option<f64> {
        let mut acc = self.parse_mul_div()?;
        loop {
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                break;
            }
            match self.bytes[self.pos] {
                b'+' => {
                    self.pos += 1;
                    acc += self.parse_mul_div()?;
                }
                b'-' => {
                    self.pos += 1;
                    acc -= self.parse_mul_div()?;
                }
                _ => break,
            }
        }
        Some(acc)
    }

    fn parse_mul_div(&mut self) -> Option<f64> {
        let mut acc = self.parse_unary()?;
        loop {
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                break;
            }
            match self.bytes[self.pos] {
                b'*' => {
                    self.pos += 1;
                    acc *= self.parse_unary()?;
                }
                b'/' => {
                    self.pos += 1;
                    let rhs = self.parse_unary()?;
                    if rhs == 0.0 {
                        return None;
                    }
                    acc /= rhs;
                }
                _ => break,
            }
        }
        Some(acc)
    }

    fn parse_unary(&mut self) -> Option<f64> {
        self.skip_ws();
        if self.pos < self.bytes.len() && self.bytes[self.pos] == b'-' {
            self.pos += 1;
            return Some(-self.parse_unary()?);
        }
        if self.pos < self.bytes.len() && self.bytes[self.pos] == b'+' {
            self.pos += 1;
            return self.parse_unary();
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Option<f64> {
        self.skip_ws();
        if self.pos >= self.bytes.len() {
            return None;
        }
        if self.bytes[self.pos] == b'(' {
            self.pos += 1;
            let v = self.parse_add_sub()?;
            self.skip_ws();
            if self.pos >= self.bytes.len() || self.bytes[self.pos] != b')' {
                return None;
            }
            self.pos += 1;
            return Some(v);
        }
        let start = self.pos;
        if self.bytes[self.pos].is_ascii_digit() || self.bytes[self.pos] == b'.' {
            while self.pos < self.bytes.len()
                && (self.bytes[self.pos].is_ascii_digit() || self.bytes[self.pos] == b'.')
            {
                self.pos += 1;
            }
            let raw = std::str::from_utf8(&self.bytes[start..self.pos]).ok()?;
            return raw.parse::<f64>().ok();
        }
        if self.bytes[self.pos].is_ascii_alphabetic() || self.bytes[self.pos] == b'_' {
            while self.pos < self.bytes.len()
                && (self.bytes[self.pos].is_ascii_alphanumeric() || self.bytes[self.pos] == b'_')
            {
                self.pos += 1;
            }
            let ident = std::str::from_utf8(&self.bytes[start..self.pos]).ok()?;
            let val = resolve_ident(ident, self.ctx)?;
            return as_number(&val);
        }
        None
    }
}

fn as_number(v: &Value) -> Option<f64> {
    match v {
        Value::Int(i) => Some(*i as f64),
        Value::Float(f) if f.is_finite() => Some(*f),
        _ => None,
    }
}

fn compare_values(lhs: &Value, op: &str, rhs: &Value) -> bool {
    if let (Some(a), Some(b)) = (as_number(lhs), as_number(rhs)) {
        return match op {
            "==" => (a - b).abs() < 1e-9,
            "!=" => (a - b).abs() >= 1e-9,
            "<" => a < b,
            "<=" => a <= b + 1e-9,
            ">" => a > b,
            ">=" => a >= b - 1e-9,
            _ => false,
        };
    }
    match (lhs, rhs) {
        (Value::Null, Value::Null) => op == "==",
        (Value::Null, _) | (_, Value::Null) => op == "!=",
        (Value::Bool(a), Value::Bool(b)) => match op {
            "==" => a == b,
            "!=" => a != b,
            _ => false,
        },
        (Value::Str(a), Value::Str(b)) => match op {
            "==" => a == b,
            "!=" => a != b,
            "<" => a < b,
            "<=" => a <= b,
            ">" => a > b,
            ">=" => a >= b,
            _ => false,
        },
        _ => match op {
            "==" => lhs.canonical() == rhs.canonical(),
            "!=" => lhs.canonical() != rhs.canonical(),
            _ => false,
        },
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

    pub fn to_request(&self, observed_files: &[String]) -> StepRequest {
        StepRequest {
            seed: self.seed,
            ops: self.ops.clone(),
            faults: Vec::new(),
            observed_files: observed_files.to_vec(),
            workflow_id: Some(self.id.clone()),
        }
    }
}

pub const DEFAULT_MIN_COV_RATIO: f64 = 0.5;

#[derive(Clone, Debug, PartialEq)]
pub struct RatchetState {
    pub mode: EnforceMode,
    pub driver: Option<String>,
    pub metric: Option<String>,
    pub skeleton_digest: Option<String>,
    pub require_mutations: bool,
    pub min_changed_cov_ratio: f64,
    pub observed_files: Vec<String>,
    pub required_observations: Vec<String>,
    pub required_workflows: Vec<String>,
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
            require_mutations: false,
            min_changed_cov_ratio: DEFAULT_MIN_COV_RATIO,
            observed_files: Vec::new(),
            required_observations: Vec::new(),
            required_workflows: Vec::new(),
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
            ("require_mutations", Value::Bool(self.require_mutations)),
            (
                "min_changed_cov_ratio",
                Value::Float(self.min_changed_cov_ratio.clamp(0.0, 1.0)),
            ),
            (
                "observed_files",
                Value::Array(
                    self.observed_files
                        .iter()
                        .cloned()
                        .map(Value::Str)
                        .collect(),
                ),
            ),
            (
                "required_observations",
                Value::Array(
                    self.required_observations
                        .iter()
                        .cloned()
                        .map(Value::Str)
                        .collect(),
                ),
            ),
            (
                "required_workflows",
                Value::Array(
                    self.required_workflows
                        .iter()
                        .cloned()
                        .map(Value::Str)
                        .collect(),
                ),
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

    pub fn policy_digest(&self) -> String {
        sha256::hex(self.to_json().canonical().as_bytes())
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
        let require_mutations = v
            .get("require_mutations")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let min_changed_cov_ratio = v
            .get("min_changed_cov_ratio")
            .and_then(|x| match x {
                Value::Float(f) if f.is_finite() => Some(*f),
                Value::Int(i) => Some(*i as f64),
                _ => None,
            })
            .unwrap_or(DEFAULT_MIN_COV_RATIO)
            .clamp(0.0, 1.0);
        let observed_files = v
            .get("observed_files")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let required_observations = v
            .get("required_observations")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let required_workflows = v
            .get("required_workflows")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
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
            require_mutations,
            min_changed_cov_ratio,
            observed_files,
            required_observations,
            required_workflows,
            approved_diffs,
            approval_rules,
            masks,
            incidents,
        })
    }

    pub fn triggered_requests(
        &self,
        changed: &[String],
        extra_required_workflows: &[String],
    ) -> Vec<StepRequest> {
        self.incidents
            .iter()
            .filter(|inc| {
                !inc.ops.is_empty()
                    && (inc.matches_files(changed)
                        || self.required_workflows.iter().any(|w| w == &inc.id)
                        || extra_required_workflows.iter().any(|w| w == &inc.id))
            })
            .map(|inc| inc.to_request(&self.observed_files))
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
pub struct EvidenceRecord {
    pub base_sha: String,
    pub candidate_tree_sha256: String,
    pub driver_digest: String,
    pub policy_digest: String,
    pub observed_files: Vec<String>,
    pub observed_files_recorded: bool,
    pub request_budget: usize,
    pub sequences_run: usize,
    pub valid_comparisons: usize,
    pub verdict: String,
    pub blocker: String,
    pub next_action: String,
    pub detail: String,
    pub skeleton_ok: bool,
    pub aa_verified: bool,
    pub masks_proven: bool,
    pub changed_lines_covered: usize,
    pub changed_lines_total: usize,
    pub unapproved_diffs: usize,
    pub missing_observations: Vec<String>,
    pub workflows_run: Vec<String>,
    pub ops_exercised: Vec<String>,
    pub observed_outputs: Vec<String>,
    pub missing_workflows: Vec<String>,
    pub mutations_run: bool,
    pub planted_total: usize,
    pub planted_killed: usize,
    pub planted_survived: usize,
    pub planted_unknown: usize,
    pub witnesses: Vec<Divergence>,
    pub record_digest_sha256: Option<String>,
    pub hmac_sha256: Option<String>,
}

impl EvidenceRecord {
    pub fn core_json(&self) -> Value {
        let mut fields = vec![
            ("base_sha", Value::Str(self.base_sha.clone())),
            (
                "candidate_tree_sha256",
                Value::Str(self.candidate_tree_sha256.clone()),
            ),
            ("driver_digest", Value::Str(self.driver_digest.clone())),
            ("policy_digest", Value::Str(self.policy_digest.clone())),
            (
                "observed_files",
                Value::Array(
                    self.observed_files
                        .iter()
                        .cloned()
                        .map(Value::Str)
                        .collect(),
                ),
            ),
            ("request_budget", Value::Int(self.request_budget as i64)),
            ("sequences_run", Value::Int(self.sequences_run as i64)),
            (
                "valid_comparisons",
                Value::Int(self.valid_comparisons as i64),
            ),
            ("verdict", Value::Str(self.verdict.clone())),
            ("blocker", Value::Str(self.blocker.clone())),
            ("next_action", Value::Str(self.next_action.clone())),
            ("detail", Value::Str(self.detail.clone())),
            ("skeleton_ok", Value::Bool(self.skeleton_ok)),
            ("aa_verified", Value::Bool(self.aa_verified)),
            ("masks_proven", Value::Bool(self.masks_proven)),
            (
                "changed_lines_covered",
                Value::Int(self.changed_lines_covered as i64),
            ),
            (
                "changed_lines_total",
                Value::Int(self.changed_lines_total as i64),
            ),
            ("unapproved_diffs", Value::Int(self.unapproved_diffs as i64)),
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
            ("mutations_run", Value::Bool(self.mutations_run)),
            ("planted_total", Value::Int(self.planted_total as i64)),
            ("planted_killed", Value::Int(self.planted_killed as i64)),
            ("planted_survived", Value::Int(self.planted_survived as i64)),
            ("planted_unknown", Value::Int(self.planted_unknown as i64)),
            (
                "witnesses",
                Value::Array(self.witnesses.iter().map(Divergence::to_json).collect()),
            ),
        ];
        if !self.observed_files_recorded {
            fields.retain(|(k, _)| {
                !matches!(
                    *k,
                    "observed_files"
                        | "workflows_run"
                        | "ops_exercised"
                        | "observed_outputs"
                        | "missing_workflows"
                )
            });
        }
        Value::obj(fields)
    }

    pub fn to_signed_json(&self, signing_key: Option<&[u8]>) -> Value {
        let core = self.core_json();
        let canonical = core.canonical();
        let digest = sha256::hex(canonical.as_bytes());
        let mut map = core.as_object().cloned().unwrap();
        map.insert("record_digest_sha256".to_owned(), Value::Str(digest));
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
            }
        }
        Value::Object(map)
    }

    pub fn from_json(v: &Value) -> Result<Self, String> {
        let req_str = |k: &str| -> Result<String, String> {
            v.get(k)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("evidence missing `{k}`"))
        };
        let get_usize = |k: &str| -> usize { v.get(k).and_then(Value::as_u64).unwrap_or(0) as usize };
        let get_bool = |k: &str| -> bool { v.get(k).and_then(Value::as_bool).unwrap_or(false) };
        let get_str_vec = |k: &str| -> Vec<String> {
            v.get(k)
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        let observed_files_recorded = v.get("observed_files").is_some();
        let mut witnesses = Vec::new();
        if let Some(arr) = v.get("witnesses").and_then(Value::as_array) {
            for item in arr {
                witnesses.push(Divergence::from_json(item)?);
            }
        }
        Ok(Self {
            base_sha: req_str("base_sha")?,
            candidate_tree_sha256: req_str("candidate_tree_sha256")?,
            driver_digest: req_str("driver_digest")?,
            policy_digest: req_str("policy_digest")?,
            observed_files: get_str_vec("observed_files"),
            observed_files_recorded,
            request_budget: get_usize("request_budget"),
            sequences_run: get_usize("sequences_run"),
            valid_comparisons: get_usize("valid_comparisons"),
            verdict: req_str("verdict")?,
            blocker: v
                .get("blocker")
                .and_then(Value::as_str)
                .unwrap_or("none")
                .to_owned(),
            next_action: v
                .get("next_action")
                .and_then(Value::as_str)
                .unwrap_or("ready_to_stamp")
                .to_owned(),
            detail: v
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            skeleton_ok: get_bool("skeleton_ok"),
            aa_verified: get_bool("aa_verified"),
            masks_proven: get_bool("masks_proven"),
            changed_lines_covered: get_usize("changed_lines_covered"),
            changed_lines_total: get_usize("changed_lines_total"),
            unapproved_diffs: get_usize("unapproved_diffs"),
            missing_observations: get_str_vec("missing_observations"),
            workflows_run: get_str_vec("workflows_run"),
            ops_exercised: get_str_vec("ops_exercised"),
            observed_outputs: get_str_vec("observed_outputs"),
            missing_workflows: get_str_vec("missing_workflows"),
            mutations_run: get_bool("mutations_run"),
            planted_total: get_usize("planted_total"),
            planted_killed: get_usize("planted_killed"),
            planted_survived: get_usize("planted_survived"),
            planted_unknown: get_usize("planted_unknown"),
            witnesses,
            record_digest_sha256: v
                .get("record_digest_sha256")
                .and_then(Value::as_str)
                .map(str::to_owned),
            hmac_sha256: v
                .get("hmac_sha256")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    }

    pub fn verify_binding(
        &self,
        base_sha: &str,
        candidate_tree_sha256: &str,
        driver_digest: &str,
        policy_digest: &str,
    ) -> Result<(), String> {
        if self.base_sha != base_sha {
            return Err(format!(
                "stale evidence: base commit changed ({} != {}); rerun emi check/diff",
                short_prefix(&self.base_sha),
                short_prefix(base_sha)
            ));
        }
        if self.candidate_tree_sha256 != candidate_tree_sha256 {
            return Err(format!(
                "stale evidence: candidate tree changed ({} != {}); rerun emi check/diff",
                short_prefix(&self.candidate_tree_sha256),
                short_prefix(candidate_tree_sha256)
            ));
        }
        if self.driver_digest != driver_digest {
            return Err(format!(
                "stale evidence: driver configuration changed ({} != {}); rerun emi check/diff",
                short_prefix(&self.driver_digest),
                short_prefix(driver_digest)
            ));
        }
        if self.policy_digest != policy_digest {
            return Err(format!(
                "stale evidence: ratchet policy changed ({} != {}); rerun emi check/diff",
                short_prefix(&self.policy_digest),
                short_prefix(policy_digest)
            ));
        }
        Ok(())
    }

    pub fn workflow_satisfied(&self, required: &str) -> bool {
        self.workflows_run.iter().any(|w| w == required)
            || self.ops_exercised.iter().any(|op| glob_match(required, op))
    }

    pub fn verify_integrity(
        &self,
        signing_key: Option<&[u8]>,
        min_changed_cov_ratio: f64,
        require_mutations: bool,
        required_workflows: &[String],
    ) -> Result<(), String> {
        let canonical = self.core_json().canonical();
        let expected_digest = sha256::hex(canonical.as_bytes());
        match &self.record_digest_sha256 {
            Some(got) if got == &expected_digest => {}
            Some(_) => {
                return Err(
                    "inconsistent evidence: record_digest_sha256 mismatch (record tampered)"
                        .to_owned(),
                );
            }
            None => {
                return Err(
                    "inconsistent evidence: missing mandatory record_digest_sha256".to_owned(),
                );
            }
        }
        if let Some(key) = signing_key {
            if !key.is_empty() {
                let expected_hmac = sha256::hmac_sha256_hex(key, canonical.as_bytes());
                match &self.hmac_sha256 {
                    Some(got) if got == &expected_hmac => {}
                    Some(_) => {
                        return Err(
                            "untrusted evidence: hmac_sha256 signature verification failed"
                                .to_owned(),
                        );
                    }
                    None => {
                        return Err(
                            "untrusted evidence: signing key is configured but evidence is unsigned"
                                .to_owned(),
                        );
                    }
                }
            }
        }
        if self.planted_killed + self.planted_survived + self.planted_unknown != self.planted_total
        {
            return Err(
                "inconsistent evidence: mutation counts do not sum to planted_total".to_owned(),
            );
        }
        if self.changed_lines_covered > self.changed_lines_total {
            return Err(
                "inconsistent evidence: changed_lines_covered exceeds changed_lines_total"
                    .to_owned(),
            );
        }
        if self.valid_comparisons > self.sequences_run {
            return Err(
                "inconsistent evidence: valid_comparisons exceeds sequences_run".to_owned(),
            );
        }
        let witness_unapproved = self.witnesses.iter().filter(|w| !w.approved).count();
        if witness_unapproved != self.unapproved_diffs {
            return Err(format!(
                "inconsistent evidence: unapproved_diffs ({}) != unapproved witnesses ({witness_unapproved})",
                self.unapproved_diffs
            ));
        }
        if self.verdict == "pass" {
            if !self.skeleton_ok {
                return Err(
                    "inconsistent evidence: verdict is pass but skeleton_ok is false".to_owned(),
                );
            }
            if !self.aa_verified {
                return Err(
                    "inconsistent evidence: verdict is pass but aa_verified is false".to_owned(),
                );
            }
            if !self.masks_proven {
                return Err(
                    "inconsistent evidence: verdict is pass but masks_proven is false".to_owned(),
                );
            }
            if self.unapproved_diffs > 0 {
                return Err(
                    "inconsistent evidence: verdict is pass with unapproved_diffs > 0".to_owned(),
                );
            }
            if self.planted_survived > 0 {
                return Err(
                    "inconsistent evidence: verdict is pass with planted_survived > 0".to_owned(),
                );
            }
            if !self.missing_observations.is_empty() {
                return Err(
                    "inconsistent evidence: verdict is pass with missing_observations".to_owned(),
                );
            }
            if !self.missing_workflows.is_empty() {
                return Err(format!(
                    "inconsistent evidence: verdict is pass with missing_workflows ({})",
                    self.missing_workflows.join(", ")
                ));
            }
            for wf in required_workflows {
                if !self.workflow_satisfied(wf) {
                    return Err(format!(
                        "missing required workflow `{wf}`: evidence did not execute it; add/run workflow before stamping"
                    ));
                }
            }
            if self.changed_lines_total > 0 {
                let ratio = self.changed_lines_covered as f64 / self.changed_lines_total as f64;
                if ratio + 1e-9 < min_changed_cov_ratio.clamp(0.0, 1.0) {
                    return Err(format!(
                        "inconsistent evidence: verdict is pass with {:.1}% coverage below required {:.1}%",
                        ratio * 100.0,
                        min_changed_cov_ratio * 100.0
                    ));
                }
            }
            if require_mutations && self.changed_lines_total > 0 {
                if !self.mutations_run
                    || self.planted_total == 0
                    || (self.planted_killed == 0 && self.planted_unknown > 0)
                {
                    return Err(
                        "inconsistent evidence: verdict is pass despite missing required mutation evidence"
                            .to_owned(),
                    );
                }
            }
        }
        Ok(())
    }
}

fn short_prefix(s: &str) -> &str {
    let end = s.len().min(12);
    &s[..end]
}

pub fn save_evidence_signed(
    path: &Path,
    record: &EvidenceRecord,
    signing_key: Option<&[u8]>,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir evidence dir: {e}"))?;
        }
    }
    let body = format!("{}\n", record.to_signed_json(signing_key).pretty());
    std::fs::write(path, body).map_err(|e| format!("write evidence {}: {e}", path.display()))
}

pub fn load_evidence(path: &Path) -> Result<EvidenceRecord, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("read evidence {}: {e}", path.display()))?;
    let v = json::parse(&text)?;
    EvidenceRecord::from_json(&v)
}

#[derive(Clone, Debug)]
pub struct Attestation {
    pub base_sha: String,
    pub candidate_tree_sha256: String,
    pub driver_digest: String,
    pub policy_digest: String,
    pub request_budget: usize,
    pub evidence_bound: bool,
    pub mode: EnforceMode,
    pub skeleton_ok: bool,
    pub aa_verified: bool,
    pub changed_lines_covered: usize,
    pub changed_lines_total: usize,
    pub unapproved_diffs: usize,
    pub workflows_run: Vec<String>,
    pub ops_exercised: Vec<String>,
    pub observed_outputs: Vec<String>,
    pub planted_total: usize,
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
            ("driver_digest", Value::Str(self.driver_digest.clone())),
            ("policy_digest", Value::Str(self.policy_digest.clone())),
            ("request_budget", Value::Int(self.request_budget as i64)),
            ("evidence_bound", Value::Bool(self.evidence_bound)),
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
            ("planted_total", Value::Int(self.planted_total as i64)),
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
