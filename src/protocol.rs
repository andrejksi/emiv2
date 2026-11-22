use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use crate::json::{self, Value};
use crate::sha256;

pub const MAX_OPS_PER_SEQUENCE: usize = 64;
pub const MAX_MASKS: usize = 32;
pub const DEFAULT_CALL_TIMEOUT_MS: u64 = 5000;

pub fn seed_to_json(seed: u64) -> Value {
    Value::Str(seed.to_string())
}

pub fn seed_from_json(v: &Value) -> Option<u64> {
    match v {
        Value::Str(s) => s.parse::<u64>().ok(),
        Value::Int(i) => Some(*i as u64),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeResult {
    pub ok: bool,
    pub fingerprint: String,
    pub operations: Vec<OpSpec>,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpSpec {
    pub name: String,
    pub arity: usize,
    pub stateful: bool,
    pub param_types: Vec<String>,
    pub kwarg_names: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StepOp {
    pub op: String,
    pub args: Vec<Value>,
    pub kwargs: BTreeMap<String, Value>,
}

impl StepOp {
    pub fn simple(op: impl Into<String>, args: Vec<Value>) -> Self {
        Self {
            op: op.into(),
            args,
            kwargs: BTreeMap::new(),
        }
    }

    pub fn to_json(&self) -> Value {
        let mut fields = vec![
            ("op", Value::Str(self.op.clone())),
            ("args", Value::Array(self.args.clone())),
        ];
        if !self.kwargs.is_empty() {
            fields.push(("kwargs", Value::Object(self.kwargs.clone())));
        }
        Value::obj(fields)
    }

    pub fn from_json(v: &Value) -> Result<Self, String> {
        let op = v
            .get("op")
            .and_then(Value::as_str)
            .ok_or_else(|| "missing op".to_owned())?
            .to_owned();
        let args = v
            .get("args")
            .and_then(Value::as_array)
            .map(<[Value]>::to_vec)
            .unwrap_or_default();
        let kwargs = v
            .get("kwargs")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        Ok(Self { op, args, kwargs })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultSpec {
    pub at_step: usize,
    pub kind: String,
    pub target: String,
}

impl FaultSpec {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("at_step", Value::Int(self.at_step as i64)),
            ("kind", Value::Str(self.kind.clone())),
            ("target", Value::Str(self.target.clone())),
        ])
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct StepRequest {
    pub seed: u64,
    pub ops: Vec<StepOp>,
    pub faults: Vec<FaultSpec>,
    pub observed_files: Vec<String>,
    pub workflow_id: Option<String>,
}

impl StepRequest {
    pub fn to_json(&self) -> Value {
        let mut fields = vec![
            ("verb", Value::Str("step".to_owned())),
            ("seed", seed_to_json(self.seed)),
            (
                "ops",
                Value::Array(self.ops.iter().map(StepOp::to_json).collect()),
            ),
            (
                "faults",
                Value::Array(self.faults.iter().map(FaultSpec::to_json).collect()),
            ),
        ];
        if !self.observed_files.is_empty() {
            fields.push((
                "observed_files",
                Value::Array(
                    self.observed_files
                        .iter()
                        .cloned()
                        .map(Value::Str)
                        .collect(),
                ),
            ));
        }
        Value::obj(fields)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Trace {
    pub ok: bool,
    pub outcomes: Vec<Value>,
    pub side_effects: Vec<Value>,
    pub logs: Vec<String>,
    pub state_digest: String,
    pub coverage: BTreeSet<String>,
    pub observations: BTreeMap<String, Value>,
    pub error: Option<String>,
}

impl Trace {
    pub fn canonical_payload(&self, masks: &[Mask]) -> String {
        let norm_outcomes: Vec<Value> = self.outcomes.iter().map(normalize_outcome).collect();
        let mut fields = vec![
            ("ok", Value::Bool(self.ok)),
            ("outcomes", Value::Array(norm_outcomes)),
            ("side_effects", Value::Array(self.side_effects.clone())),
            (
                "logs",
                Value::Array(self.logs.iter().cloned().map(Value::Str).collect()),
            ),
            ("state_digest", Value::Str(self.state_digest.clone())),
            (
                "error",
                self.error
                    .as_ref()
                    .map_or(Value::Null, |e| Value::Str(e.clone())),
            ),
        ];
        if !self.observations.is_empty() {
            fields.push(("observations", Value::Object(self.observations.clone())));
        }
        let raw = Value::obj(fields).canonical();
        apply_masks(&raw, masks)
    }

    pub fn trace_hash(&self, masks: &[Mask]) -> String {
        sha256::hex(self.canonical_payload(masks).as_bytes())
    }
}

pub fn normalize_outcome(v: &Value) -> Value {
    match v {
        Value::Object(map)
            if map.get("ok").and_then(Value::as_bool) == Some(false) && map.contains_key("exc") =>
        {
            let mut clean = BTreeMap::new();
            clean.insert("ok".to_owned(), Value::Bool(false));
            if let Some(exc) = map.get("exc") {
                clean.insert("exc".to_owned(), exc.clone());
            }
            if let Some(out) = map.get("stdout") {
                clean.insert("stdout".to_owned(), out.clone());
            }
            if let Some(err) = map.get("stderr") {
                clean.insert("stderr".to_owned(), err.clone());
            }
            Value::Object(clean)
        }
        other => other.clone(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mask {
    pub name: String,
    pub prefix: String,
    pub max_len: usize,
}

impl Mask {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("name", Value::Str(self.name.clone())),
            ("prefix", Value::Str(self.prefix.clone())),
            ("max_len", Value::Int(self.max_len as i64)),
        ])
    }
}

pub fn apply_masks(input: &str, masks: &[Mask]) -> String {
    assert!(masks.len() <= MAX_MASKS);
    let mut cur = input.to_owned();
    for mask in masks {
        if mask.prefix.is_empty() || mask.max_len == 0 {
            continue;
        }
        let mut out = String::with_capacity(cur.len());
        let bytes = cur.as_bytes();
        let pbytes = mask.prefix.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i..].starts_with(pbytes) {
                out.push_str(&mask.prefix);
                out.push_str("<MASK:");
                out.push_str(&mask.name);
                out.push('>');
                i += pbytes.len();
                let mut skipped = 0;
                while i < bytes.len() && skipped < mask.max_len {
                    let b = bytes[i];
                    if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b':' || b == b'.'
                    {
                        i += 1;
                        skipped += 1;
                    } else {
                        break;
                    }
                }
            } else {
                let ch = cur[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
        cur = out;
    }
    cur
}

pub trait Driver {
    fn probe(&mut self) -> Result<ProbeResult, String>;
    fn step(&mut self, req: &StepRequest) -> Result<Trace, String>;
}

pub struct ProcessDriver {
    pub workdir: PathBuf,
    pub argv: Vec<String>,
    pub env_pins: Vec<(String, String)>,
    pub timeout: Duration,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    lines_rx: Option<Receiver<Result<String, String>>>,
}

impl Drop for ProcessDriver {
    fn drop(&mut self) {
        self.teardown();
    }
}

impl ProcessDriver {
    pub fn new(workdir: PathBuf, argv: Vec<String>) -> Self {
        Self::with_timeout(workdir, argv, Duration::from_millis(DEFAULT_CALL_TIMEOUT_MS))
    }

    pub fn with_timeout(workdir: PathBuf, argv: Vec<String>, timeout: Duration) -> Self {
        assert!(!argv.is_empty());
        Self {
            workdir,
            argv,
            env_pins: vec![
                ("TZ".to_owned(), "UTC".to_owned()),
                ("LC_ALL".to_owned(), "C.UTF-8".to_owned()),
                ("PYTHONHASHSEED".to_owned(), "0".to_owned()),
            ],
            timeout,
            child: None,
            stdin: None,
            lines_rx: None,
        }
    }

    fn teardown(&mut self) {
        self.stdin.take();
        self.lines_rx.take();
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    fn ensure_started(&mut self) -> Result<(), String> {
        if self.child.is_some() {
            return Ok(());
        }
        let mut cmd = Command::new(&self.argv[0]);
        cmd.args(&self.argv[1..])
            .current_dir(&self.workdir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (k, _) in std::env::vars() {
            if k.to_ascii_uppercase().starts_with("EMI") {
                cmd.env_remove(&k);
            }
        }
        for (k, v) in &self.env_pins {
            cmd.env(k, v);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn driver {}: {e}", self.argv[0]))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "driver stdin unavailable".to_owned())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "driver stdout unavailable".to_owned())?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        let _ = tx.send(Err("driver eof".to_owned()));
                        break;
                    }
                    Ok(_) => {
                        if tx.send(Ok(line)).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("driver read error: {e}")));
                        break;
                    }
                }
            }
        });
        self.child = Some(child);
        self.stdin = Some(stdin);
        self.lines_rx = Some(rx);
        Ok(())
    }

    fn call(&mut self, payload: &Value) -> Result<Value, String> {
        self.ensure_started()?;
        let line = payload.canonical();
        if let Err(e) = self
            .stdin
            .as_mut()
            .unwrap()
            .write_all(line.as_bytes())
            .and_then(|()| self.stdin.as_mut().unwrap().write_all(b"\n"))
            .and_then(|()| self.stdin.as_mut().unwrap().flush())
        {
            self.teardown();
            return Err(format!("driver stdin write failed: {e}"));
        }
        let resp_line = match self.lines_rx.as_ref().unwrap().recv_timeout(self.timeout) {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                self.teardown();
                return Err(e);
            }
            Err(_) => {
                self.teardown();
                return Err(format!("driver timed out after {}ms", self.timeout.as_millis()));
            }
        };
        if resp_line.trim().is_empty() {
            self.teardown();
            return Err("driver returned empty output".to_owned());
        }
        json::parse(resp_line.trim())
    }
}

impl Driver for ProcessDriver {
    fn probe(&mut self) -> Result<ProbeResult, String> {
        let req = Value::obj(vec![("verb", Value::Str("probe".to_owned()))]);
        let resp = self.call(&req)?;
        let ok = resp.get("ok").and_then(Value::as_bool).unwrap_or(false);
        let fingerprint = resp
            .get("fingerprint")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let detail = resp
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let mut operations = Vec::new();
        if let Some(arr) = resp.get("operations").and_then(Value::as_array) {
            for item in arr {
                if let Some(name) = item.get("name").and_then(Value::as_str) {
                    let arity = item.get("arity").and_then(Value::as_u64).unwrap_or(1) as usize;
                    let stateful = item
                        .get("stateful")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let param_types = item
                        .get("param_types")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(Value::as_str)
                                .map(str::to_owned)
                                .collect()
                        })
                        .unwrap_or_default();
                    let kwarg_names = item
                        .get("kwarg_names")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(Value::as_str)
                                .map(str::to_owned)
                                .collect()
                        })
                        .unwrap_or_default();
                    operations.push(OpSpec {
                        name: name.to_owned(),
                        arity,
                        stateful,
                        param_types,
                        kwarg_names,
                    });
                }
            }
        }
        let roots = snapshot_root_strings(&self.workdir);
        let detail = scrub_snapshot_paths(&detail, &roots);
        Ok(ProbeResult {
            ok,
            fingerprint,
            operations,
            detail,
        })
    }

    fn step(&mut self, req: &StepRequest) -> Result<Trace, String> {
        let mut pre_snapshots: Vec<(String, PathBuf, Option<Vec<u8>>)> = Vec::new();
        for rel in &req.observed_files {
            if let Some(full) = safe_observed_path(&self.workdir, rel) {
                let prev = std::fs::read(&full).ok();
                pre_snapshots.push((rel.clone(), full, prev));
            }
        }
        let call_res = self.call(&req.to_json());
        let mut file_obs: BTreeMap<String, Value> = BTreeMap::new();
        if call_res.is_ok() {
            for (rel, full, _) in &pre_snapshots {
                let entry = match std::fs::read(full) {
                    Ok(bytes) => Value::obj(vec![
                        ("exists", Value::Bool(true)),
                        ("size", Value::Int(bytes.len() as i64)),
                        ("sha256", Value::Str(sha256::hex(&bytes))),
                    ]),
                    Err(_) => Value::obj(vec![
                        ("exists", Value::Bool(false)),
                        ("size", Value::Int(0)),
                        ("sha256", Value::Null),
                    ]),
                };
                file_obs.insert(format!("file:{rel}"), entry);
            }
        }
        for (_, full, prev) in pre_snapshots {
            match prev {
                Some(bytes) => {
                    if let Some(parent) = full.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::write(&full, bytes);
                }
                None => {
                    if full.exists() {
                        let _ = std::fs::remove_file(&full);
                    }
                }
            }
        }
        let resp = call_res?;
        let roots = snapshot_root_strings(&self.workdir);
        let ok = resp.get("ok").and_then(Value::as_bool).unwrap_or(false);
        let mut outcomes = resp
            .get("outcomes")
            .and_then(Value::as_array)
            .map(<[Value]>::to_vec)
            .unwrap_or_default();
        for o in &mut outcomes {
            scrub_value_paths(o, &roots);
        }
        let mut side_effects = resp
            .get("side_effects")
            .and_then(Value::as_array)
            .map(<[Value]>::to_vec)
            .unwrap_or_default();
        for se in &mut side_effects {
            scrub_value_paths(se, &roots);
        }
        let logs = resp
            .get("logs")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(|s| scrub_snapshot_paths(s, &roots))
                    .collect()
            })
            .unwrap_or_default();
        let state_digest = scrub_snapshot_paths(
            resp.get("state_digest")
                .and_then(Value::as_str)
                .unwrap_or(""),
            &roots,
        );
        let mut coverage = BTreeSet::new();
        if let Some(arr) = resp.get("coverage").and_then(Value::as_array) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    coverage.insert(s.to_owned());
                }
            }
        }
        let mut observations = resp
            .get("observations")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let scrubbed_obs: BTreeMap<String, Value> = observations
            .into_iter()
            .map(|(k, mut v)| {
                scrub_value_paths(&mut v, &roots);
                (scrub_snapshot_paths(&k, &roots), v)
            })
            .collect();
        observations = scrubbed_obs;
        for (k, v) in file_obs {
            observations.entry(k).or_insert(v);
        }
        let error = resp
            .get("error")
            .and_then(Value::as_str)
            .map(|s| scrub_snapshot_paths(s, &roots));
        Ok(Trace {
            ok,
            outcomes,
            side_effects,
            logs,
            state_digest,
            coverage,
            observations,
            error,
        })
    }
}

fn snapshot_root_strings(workdir: &Path) -> Vec<String> {
    let mut set = BTreeSet::new();
    let mut push_path = |p: &Path| {
        let s = p.to_string_lossy();
        let trimmed = s.trim_end_matches('/');
        if !trimmed.is_empty() && trimmed != "/" {
            set.insert(trimmed.to_owned());
        }
    };
    push_path(workdir);
    if let Ok(canon) = std::fs::canonicalize(workdir) {
        push_path(&canon);
    }
    let mut out: Vec<String> = set.into_iter().collect();
    out.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    out
}

fn scrub_snapshot_paths(text: &str, roots: &[String]) -> String {
    let mut cur = text.to_owned();
    for root in roots {
        if cur.contains(root.as_str()) {
            cur = cur.replace(root.as_str(), "<ROOT>");
        }
    }
    cur
}

fn scrub_value_paths(v: &mut Value, roots: &[String]) {
    if roots.is_empty() {
        return;
    }
    match v {
        Value::Str(s) => {
            if roots.iter().any(|r| s.contains(r.as_str())) {
                *s = scrub_snapshot_paths(s, roots);
            }
        }
        Value::Array(items) => {
            for item in items {
                scrub_value_paths(item, roots);
            }
        }
        Value::Object(map) => {
            let old = std::mem::take(map);
            for (k, mut val) in old {
                scrub_value_paths(&mut val, roots);
                let nk = scrub_snapshot_paths(&k, roots);
                map.insert(nk, val);
            }
        }
        _ => {}
    }
}

fn safe_observed_path(root: &Path, rel: &str) -> Option<PathBuf> {
    let p = Path::new(rel);
    if p.is_absolute() || rel.is_empty() {
        return None;
    }
    for comp in p.components() {
        if matches!(
            comp,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        ) {
            return None;
        }
    }
    Some(root.join(p))
}

pub fn split_command(spec: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    for ch in spec.chars() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            c if c.is_whitespace() && !in_single && !in_double => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutoDriverKind {
    Python,
    Node,
}

pub fn detect_auto_driver_kind(root: &Path) -> AutoDriverKind {
    let mut has_py = false;
    let mut has_js_ts = false;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.')
                || name == "node_modules"
                || name == "target"
                || name == "__pycache__"
                || name == "dist"
                || name == "build"
            {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                if name.ends_with(".py") {
                    has_py = true;
                } else if name.ends_with(".ts")
                    || name.ends_with(".mts")
                    || name.ends_with(".tsx")
                    || name.ends_with(".js")
                    || name.ends_with(".mjs")
                    || name.ends_with(".cjs")
                {
                    has_js_ts = true;
                }
            }
        }
    }
    if has_py {
        AutoDriverKind::Python
    } else if has_js_ts {
        AutoDriverKind::Node
    } else {
        AutoDriverKind::Python
    }
}

fn hash_dir_into(root: &Path, dir: &Path, acc: &mut Vec<u8>) {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == ".git" || name == "target" || name == "node_modules" || name == "__pycache__"
            {
                continue;
            }
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                files.push(p);
            }
        }
    }
    files.sort();
    for f in files {
        if let Ok(bytes) = std::fs::read(&f) {
            let rel = f
                .strip_prefix(root)
                .unwrap_or(&f)
                .to_string_lossy()
                .replace('\\', "/");
            acc.extend_from_slice(rel.as_bytes());
            acc.push(0);
            acc.extend_from_slice(sha256::hex(&bytes).as_bytes());
            acc.push(b'\n');
        }
    }
}

pub fn compute_driver_digest(
    root: &Path,
    explicit: Option<&str>,
    ratchet_driver: Option<&str>,
) -> String {
    let mut acc = Vec::new();
    match explicit.or(ratchet_driver) {
        None => match detect_auto_driver_kind(root) {
            AutoDriverKind::Python => {
                acc.extend_from_slice(b"auto-python\0");
                acc.extend_from_slice(default_python_driver_script().as_bytes());
            }
            AutoDriverKind::Node => {
                acc.extend_from_slice(b"auto-node\0");
                acc.extend_from_slice(default_node_driver_script().as_bytes());
            }
        },
        Some(cmd) => {
            acc.extend_from_slice(b"custom\0");
            acc.extend_from_slice(cmd.as_bytes());
            acc.push(0);
            for tok in split_command(cmd) {
                if tok.starts_with('-') {
                    continue;
                }
                let local = root.join(&tok);
                if local.is_file() {
                    if let Ok(bytes) = std::fs::read(&local) {
                        acc.extend_from_slice(tok.as_bytes());
                        acc.push(0);
                        acc.extend_from_slice(sha256::hex(&bytes).as_bytes());
                        acc.push(b'\n');
                    }
                } else if local.is_dir() {
                    hash_dir_into(root, &local, &mut acc);
                } else {
                    let direct = PathBuf::from(&tok);
                    if direct.is_file() {
                        if let Ok(bytes) = std::fs::read(&direct) {
                            acc.extend_from_slice(tok.as_bytes());
                            acc.push(0);
                            acc.extend_from_slice(sha256::hex(&bytes).as_bytes());
                            acc.push(b'\n');
                        }
                    }
                }
            }
        }
    }
    sha256::hex(&acc)
}

pub fn default_python_driver_script() -> &'static str {
    r#"import ast, hashlib, importlib, importlib.util, inspect, json, os, random, re, sys, tempfile, trace

ADDR_RE = re.compile(r' at 0x[0-9a-fA-F]+>')
ROOT_PREFIXES = []

def set_root_prefixes(root):
    cands = []
    for p in (root, os.getcwd()):
        if not p:
            continue
        for variant in (p, os.path.abspath(p), os.path.realpath(p)):
            v = variant.rstrip(os.sep)
            if v and v != os.sep and v not in cands:
                cands.append(v)
    cands.sort(key=len, reverse=True)
    ROOT_PREFIXES[:] = cands

def scrub_paths(s):
    if not isinstance(s, str) or not ROOT_PREFIXES:
        return s
    for p in ROOT_PREFIXES:
        if p in s:
            s = s.replace(p, "<ROOT>")
    return s

def scrub_repr(v):
    return scrub_paths(ADDR_RE.sub(' at 0xADDR>', repr(v)))

def type_name(ann):
    if ann is None:
        return "any"
    if isinstance(ann, ast.Name):
        return ann.id
    if isinstance(ann, ast.Subscript) and isinstance(ann.value, ast.Name):
        return ann.value.id
    return "any"

def to_json_val(v):
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, str):
        return scrub_paths(v)
    if isinstance(v, int):
        return v if (-9223372036854775808 <= v <= 9223372036854775807) else str(v)
    if isinstance(v, float):
        return v if (v == v and v != float('inf') and v != float('-inf')) else scrub_repr(v)
    if isinstance(v, list):
        return [to_json_val(x) for x in v]
    if isinstance(v, dict):
        return {scrub_paths(str(k)): to_json_val(val) for k, val in v.items()}
    return scrub_repr(v)

def normalize_outcome_for_digest(o):
    if isinstance(o, dict) and o.get("ok") is False and "exc" in o:
        out = {"ok": False, "exc": o["exc"]}
        if "stdout" in o:
            out["stdout"] = o["stdout"]
        if "stderr" in o:
            out["stderr"] = o["stderr"]
        return out
    return o

def discover_ops(root):
    ops = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith('.') and d not in ('tests', 'test', '__pycache__', 'venv', '.venv'))
        for fn in sorted(filenames):
            if fn.startswith('.') or not fn.endswith('.py') or fn.startswith('test_') or fn.endswith('_test.py'):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            try:
                tree = ast.parse(open(full, 'r', encoding='utf-8').read())
            except Exception:
                continue
            for node in tree.body:
                if isinstance(node, ast.FunctionDef) and not node.name.startswith('_'):
                    ptypes = [type_name(a.annotation) for a in node.args.args]
                    kwnames = [a.arg for a in node.args.kwonlyargs]
                    ops.append({
                        "name": f"{rel}::{node.name}",
                        "arity": len(node.args.args),
                        "stateful": False,
                        "param_types": ptypes,
                        "kwarg_names": kwnames
                    })
                elif isinstance(node, ast.ClassDef) and not node.name.startswith('_'):
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef) and not item.name.startswith('_') and item.name != 'emi_factory':
                            margs = item.args.args[1:] if item.args.args and item.args.args[0].arg == 'self' else item.args.args
                            ptypes = [type_name(a.annotation) for a in margs]
                            kwnames = [a.arg for a in item.args.kwonlyargs]
                            ops.append({
                                "name": f"{rel}::{node.name}.{item.name}",
                                "arity": len(margs),
                                "stateful": True,
                                "param_types": ptypes,
                                "kwarg_names": kwnames
                            })
    return ops

def module_name_for_rel(rel):
    norm = rel.replace(os.sep, '/')
    if norm.endswith('.py'):
        norm = norm[:-3]
    parts = [p for p in norm.split('/') if p and p != '.']
    if parts and parts[-1] == '__init__':
        parts = parts[:-1]
    if parts and all(p.isidentifier() for p in parts):
        return '.'.join(parts)
    return None

def load_module_by_package(root, rel):
    full = os.path.abspath(os.path.join(root, rel))
    if not os.path.exists(full):
        raise FileNotFoundError(f"missing module {rel}")
    pkg_name = module_name_for_rel(rel)
    if pkg_name:
        try:
            mod = importlib.import_module(pkg_name)
            mod_file = getattr(mod, '__file__', None)
            if mod_file and os.path.abspath(mod_file) == full:
                return mod
        except Exception:
            pass
    fallback = pkg_name or f"mod_{hashlib.sha256(rel.encode()).hexdigest()[:10]}"
    spec = importlib.util.spec_from_file_location(fallback, full)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[fallback] = mod
    spec.loader.exec_module(mod)
    return mod

def default_for_annotation(ann):
    if ann is int:
        return 0
    if ann is float:
        return 0.0
    if ann is str:
        return ""
    if ann is bool:
        return False
    if ann is list:
        return []
    if ann is dict:
        return {}
    return None

class _HarnessError(Exception):
    pass

def construct_instance(cls_obj):
    if callable(getattr(cls_obj, '__emi_init__', None)):
        try:
            return cls_obj.__emi_init__()
        except Exception as exc:
            raise _HarnessError(f"__emi_init__ failed: {type(exc).__name__}: {exc}") from exc
    if callable(getattr(cls_obj, 'emi_factory', None)):
        try:
            return cls_obj.emi_factory()
        except Exception as exc:
            raise _HarnessError(f"emi_factory failed: {type(exc).__name__}: {exc}") from exc
    try:
        return cls_obj()
    except TypeError:
        sig = inspect.signature(cls_obj.__init__)
        args = []
        for idx, param in enumerate(sig.parameters.values()):
            if idx == 0 and param.name == 'self':
                continue
            if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
                continue
            if param.default is not inspect.Parameter.empty:
                continue
            if param.kind == inspect.Parameter.KEYWORD_ONLY:
                raise _HarnessError(f"required keyword-only constructor parameter '{param.name}'")
            if param.annotation is inspect.Parameter.empty:
                raise _HarnessError(f"untyped required constructor parameter '{param.name}'")
            args.append(default_for_annotation(param.annotation))
        try:
            return cls_obj(*args)
        except Exception as exc:
            raise _HarnessError(f"constructor failed: {type(exc).__name__}: {exc}") from exc
    except Exception as exc:
        raise _HarnessError(f"constructor failed: {type(exc).__name__}: {exc}") from exc

def capture_stdio(fn):
    sys.stdout.flush()
    sys.stderr.flush()
    saved_out = os.dup(1)
    saved_err = os.dup(2)
    out_f = tempfile.TemporaryFile()
    err_f = tempfile.TemporaryFile()
    os.dup2(out_f.fileno(), 1)
    os.dup2(err_f.fileno(), 2)
    try:
        outcome = fn()
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(saved_out, 1)
        os.dup2(saved_err, 2)
        os.close(saved_out)
        os.close(saved_err)
        out_f.seek(0)
        err_f.seek(0)
        out_text = scrub_paths(out_f.read().decode('utf-8', errors='replace'))
        err_text = scrub_paths(err_f.read().decode('utf-8', errors='replace'))
        out_f.close()
        err_f.close()
    if out_text:
        outcome["stdout"] = out_text
    if err_text:
        outcome["stderr"] = err_text
    return outcome

def run_step_in_process(root, req):
    set_root_prefixes(root)
    sys.argv = [""]
    for _k in [k for k in os.environ if k.upper().startswith("EMI")]:
        os.environ.pop(_k, None)
    seed_raw = req.get("seed", "0")
    seed_int = int(seed_raw) if isinstance(seed_raw, str) else int(seed_raw)
    random.seed(seed_int)
    outcomes = []
    cov = set()
    loaded = {}
    instances = {}
    faults = req.get("faults", [])
    abs_root = os.path.abspath(root)
    for idx, step_op in enumerate(req.get("ops", [])):
        hit_fault = next((f for f in faults if f.get("at_step") == idx), None)
        if hit_fault is not None:
            outcomes.append({"ok": False, "fault": hit_fault.get("kind", "fault")})
            continue
        target = step_op["op"]
        args = step_op.get("args", [])
        kwargs = step_op.get("kwargs", {})
        tracer = trace.Trace(count=1, trace=0)
        def _exec_one():
            try:
                rel, sym = target.split("::", 1)
                if rel not in loaded:
                    loaded[rel] = tracer.runfunc(load_module_by_package, root, rel)
                mod = loaded[rel]
                if "." in sym:
                    cls_name, meth_name = sym.split(".", 1)
                    cls_key = f"{rel}::{cls_name}"
                    if cls_key not in instances:
                        cls_obj = getattr(mod, cls_name)
                        instances[cls_key] = construct_instance(cls_obj)
                    fn = getattr(instances[cls_key], meth_name)
                else:
                    fn = getattr(mod, sym)
                res = tracer.runfunc(fn, *args, **kwargs)
                return {"ok": True, "value": scrub_repr(res), "json": to_json_val(res)}
            except _HarnessError as exc:
                return {"ok": False, "harness_error": True, "exc": "HarnessError", "msg": scrub_paths(str(exc))}
            except SystemExit as exc:
                code = exc.code
                if code is None:
                    exit_code = 0
                elif isinstance(code, int):
                    exit_code = code
                else:
                    exit_code = 1
                return {"ok": True, "exit_code": exit_code}
            except AttributeError as exc:
                return {"ok": False, "exc": "MissingSymbol", "msg": scrub_paths(str(exc))}
            except Exception as exc:
                return {"ok": False, "exc": type(exc).__name__, "msg": scrub_paths(str(exc))}
        out_item = capture_stdio(_exec_one)
        outcomes.append(out_item)
        if not out_item.get("harness_error"):
            for (filename, lineno), _cnt in tracer.results().counts.items():
                if os.path.abspath(filename).startswith(abs_root):
                    cov.add(f"{os.path.relpath(filename, root)}:{lineno}")
    norm_outcomes = [normalize_outcome_for_digest(o) for o in outcomes]
    state_digest = hashlib.sha256(json.dumps(norm_outcomes, sort_keys=True).encode()).hexdigest()
    return json.dumps({
        "ok": True,
        "outcomes": outcomes,
        "side_effects": [],
        "logs": [],
        "state_digest": state_digest,
        "coverage": sorted(cov),
        "observations": {},
        "error": None
    })

def run_step_isolated(root, req, proto_fd):
    set_root_prefixes(root)
    if not hasattr(os, 'fork'):
        return run_step_in_process(root, req)
    sys.stdout.flush()
    sys.stderr.flush()
    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        if proto_fd is not None:
            try:
                os.close(proto_fd)
            except OSError:
                pass
        try:
            payload = run_step_in_process(root, req).encode('utf-8')
        except BaseException as exc:
            payload = json.dumps({
                "ok": False,
                "outcomes": [],
                "side_effects": [],
                "logs": [],
                "state_digest": "",
                "coverage": [],
                "observations": {},
                "error": scrub_paths(f"{type(exc).__name__}: {exc}")
            }).encode('utf-8')
        view = memoryview(payload)
        sent = 0
        while sent < len(payload):
            n = os.write(w_fd, view[sent:])
            if n <= 0:
                break
            sent += n
        os.close(w_fd)
        os._exit(0)
    os.close(w_fd)
    chunks = []
    while True:
        chunk = os.read(r_fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(r_fd)
    _, status = os.waitpid(pid, 0)
    if not chunks:
        return json.dumps({
            "ok": False,
            "outcomes": [],
            "side_effects": [],
            "logs": [],
            "state_digest": "",
            "coverage": [],
            "observations": {},
            "error": f"isolated step child exited with status {status}"
        })
    return b"".join(chunks).decode('utf-8')

def main():
    proto_fd = os.dup(1)
    proto_out = os.fdopen(proto_fd, 'w', encoding='utf-8', buffering=1)
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull_fd, 1)
    os.close(devnull_fd)
    root = os.getcwd()
    if root not in sys.path:
        sys.path.insert(0, root)
    while True:
        raw = sys.stdin.readline()
        if not raw:
            break
        raw = raw.strip()
        if not raw:
            continue
        req = json.loads(raw)
        verb = req.get("verb")
        if verb == "probe":
            ops = discover_ops(root)
            fp = f"py-{sys.version_info.major}.{sys.version_info.minor}"
            proto_out.write(json.dumps({"ok": True, "fingerprint": fp, "operations": ops, "detail": "auto-python"}) + "\n")
            proto_out.flush()
            continue
        if verb == "step":
            proto_out.write(run_step_isolated(root, req, proto_fd) + "\n")
            proto_out.flush()

if __name__ == "__main__":
    main()
"#
}

pub fn default_node_driver_script() -> &'static str {
    r####"import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import readline from "node:readline";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import inspector from "node:inspector";

const SELF_PATH = fileURLToPath(import.meta.url);
const ROOT = process.cwd();
const ROOT_PREFIXES = (() => {
  const cands = new Set();
  for (const p of [ROOT, process.cwd()]) {
    if (!p) continue;
    const variants = [p, path.resolve(p)];
    try {
      variants.push(fs.realpathSync(p));
    } catch {}
    for (const v of variants) {
      const clean = v.replace(/\/+$/, "");
      if (clean && clean !== "/") cands.add(clean);
    }
  }
  return Array.from(cands).sort((a, b) => b.length - a.length);
})();

function scrubPaths(s) {
  if (typeof s !== "string" || ROOT_PREFIXES.length === 0) return s;
  let cur = s;
  for (const p of ROOT_PREFIXES) {
    if (cur.includes(p)) cur = cur.split(p).join("<ROOT>");
  }
  return cur;
}

const SKIP_DIRS = new Set([".git", "node_modules", "target", ".emi", "dist", "build", "__pycache__", ".venv", "venv"]);
const EXTS = new Set([".mjs", ".cjs", ".js", ".ts", ".mts"]);
const ADDR_RE = /\b0x[0-9a-fA-F]{6,}\b/g;

function isTestFile(rel) {
  const base = path.basename(rel);
  return (
    base.startsWith(".") ||
    base.startsWith("test_") ||
    base.startsWith("test.") ||
    base.includes(".test.") ||
    base.includes(".spec.") ||
    rel.startsWith("test/") ||
    rel.startsWith("tests/") ||
    rel.includes("/test/") ||
    rel.includes("/tests/")
  );
}

function discoverFiles(root) {
  const found = [];
  function walk(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const ent of entries) {
      if (ent.name.startsWith(".") || SKIP_DIRS.has(ent.name)) continue;
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        walk(full);
      } else if (ent.isFile() && EXTS.has(path.extname(ent.name))) {
        const rel = path.relative(root, full).split(path.sep).join("/");
        if (!isTestFile(rel)) found.push(rel);
      }
    }
  }
  walk(root);
  return found;
}

function mapTsType(raw) {
  if (!raw) return "any";
  const t = raw.trim().toLowerCase();
  if (t.includes("boolean") || t === "bool") return "bool";
  if (t.includes("number") || t.includes("bigint")) return "int";
  if (t.includes("string")) return "str";
  if (t.endsWith("[]") || t.startsWith("array<") || t.startsWith("readonlyarray<")) return "list";
  if (t.startsWith("record<") || t === "object" || t.startsWith("{")) return "dict";
  return "any";
}

function parseFnSignature(fn, src, name) {
  let paramNames = [];
  let paramTypes = [];
  const fnStr = Function.prototype.toString.call(fn);
  const m = fnStr.match(/^[^(]*\(([^)]*)\)/s);
  if (m && m[1].trim()) {
    for (const part of m[1].split(",")) {
      const clean = part.split("=")[0].trim().replace(/^\.\.\./, "");
      if (!clean) continue;
      const colonIdx = clean.indexOf(":");
      const pname = (colonIdx >= 0 ? clean.slice(0, colonIdx) : clean).replace(/\?$/, "").trim();
      const ptype = colonIdx >= 0 ? mapTsType(clean.slice(colonIdx + 1)) : "any";
      if (pname && !pname.startsWith("{") && !pname.startsWith("[")) {
        paramNames.push(pname);
        paramTypes.push(ptype);
      }
    }
  }
  if (src && name && paramNames.length > 0 && paramTypes.every((t) => t === "any")) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`(?:function\\s+${escaped}|${escaped}\\s*=\\s*(?:async\\s*)?)\\(([^)]*)\\)`);
    const sm = src.match(re);
    if (sm && sm[1].trim()) {
      const parts = sm[1].split(",");
      for (let i = 0; i < Math.min(parts.length, paramTypes.length); i++) {
        const clean = parts[i].split("=")[0].trim();
        const colonIdx = clean.indexOf(":");
        if (colonIdx >= 0) {
          paramTypes[i] = mapTsType(clean.slice(colonIdx + 1));
        }
      }
    }
  }
  return { arity: paramNames.length, paramNames, paramTypes };
}

function isClassFn(fn) {
  if (typeof fn !== "function") return false;
  return /^\s*class\s/.test(Function.prototype.toString.call(fn));
}

function defaultForType(t) {
  if (t === "int" || t === "float") return 0;
  if (t === "str") return "";
  if (t === "bool") return false;
  if (t === "list") return [];
  if (t === "dict") return {};
  return 0;
}

function toJsonVal(val, depth = 0, seen = new Set()) {
  if (depth > 8) return scrubPaths(String(val).replace(ADDR_RE, "0x0"));
  if (val === null || val === undefined) return null;
  if (typeof val === "boolean") return val;
  if (typeof val === "number") {
    if (!Number.isFinite(val)) return String(val);
    return val;
  }
  if (typeof val === "bigint") {
    if (val >= -9007199254740991n && val <= 9007199254740991n) return Number(val);
    return val.toString();
  }
  if (typeof val === "string") return scrubPaths(val.replace(ADDR_RE, "0x0"));
  if (typeof val === "symbol") return scrubPaths(val.toString());
  if (typeof val === "function") return `[Function:${val.name || "anon"}]`;
  if (typeof val === "object") {
    if (seen.has(val)) return "<cycle>";
    seen.add(val);
    if (val instanceof Date) return val.toISOString();
    if (val instanceof Uint8Array || Buffer.isBuffer(val)) return Buffer.from(val).toString("hex");
    if (Array.isArray(val)) return val.slice(0, 64).map((x) => toJsonVal(x, depth + 1, seen));
    if (val instanceof Set) return Array.from(val).slice(0, 64).map((x) => toJsonVal(x, depth + 1, seen));
    if (val instanceof Map) {
      const obj = {};
      for (const [k, v] of Array.from(val.entries()).slice(0, 64)) {
        obj[scrubPaths(String(k))] = toJsonVal(v, depth + 1, seen);
      }
      return obj;
    }
    const obj = {};
    for (const k of Object.keys(val).sort().slice(0, 64)) {
      obj[scrubPaths(k)] = toJsonVal(val[k], depth + 1, seen);
    }
    return obj;
  }
  return scrubPaths(String(val).replace(ADDR_RE, "0x0"));
}

function normalizeOutcomeForDigest(val) {
  if (val && typeof val === "object" && !Array.isArray(val) && val.ok === false && typeof val.err === "string") {
    const out = { ok: false, err: val.err.split(":", 1)[0].trim() };
    if (typeof val.stdout === "string") out.stdout = val.stdout;
    if (typeof val.stderr === "string") out.stderr = val.stderr;
    return out;
  }
  return val;
}

function canonicalJson(val) {
  if (val === null || val === undefined) return "null";
  if (typeof val !== "object") return JSON.stringify(val);
  if (Array.isArray(val)) return "[" + val.map(canonicalJson).join(",") + "]";
  const keys = Object.keys(val).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(val[k])).join(",") + "}";
}

function resolveSafePath(root, rel) {
  const full = path.resolve(root, rel);
  const absRoot = path.resolve(root);
  if (full !== absRoot && !full.startsWith(absRoot + path.sep)) return null;
  return full;
}

function snapshotObservedFiles(root, paths) {
  const snap = {};
  for (const rel of paths || []) {
    const full = resolveSafePath(root, rel);
    if (!full) continue;
    if (fs.existsSync(full) && fs.statSync(full).isFile()) {
      snap[rel] = fs.readFileSync(full);
    } else {
      snap[rel] = null;
    }
  }
  return snap;
}

function collectAndRestoreObservedFiles(root, snap) {
  const obs = {};
  for (const [rel, orig] of Object.entries(snap)) {
    const full = resolveSafePath(root, rel);
    if (!full) continue;
    if (fs.existsSync(full) && fs.statSync(full).isFile()) {
      const data = fs.readFileSync(full);
      obs[`file:${rel}`] = {
        exists: true,
        size: data.length,
        sha256: crypto.createHash("sha256").update(data).digest("hex"),
      };
    } else {
      obs[`file:${rel}`] = { exists: false, size: 0, sha256: "" };
    }
    if (orig === null) {
      try {
        if (fs.existsSync(full)) fs.unlinkSync(full);
      } catch {}
    } else {
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, orig);
    }
  }
  return obs;
}

async function loadModule(root, rel) {
  const full = path.resolve(root, rel);
  return await import(pathToFileURL(full).href);
}

async function runProbeWorker() {
  const files = discoverFiles(ROOT);
  const ops = [];
  for (const rel of files) {
    let mod;
    let src = "";
    try {
      src = fs.readFileSync(path.resolve(ROOT, rel), "utf8");
      mod = await loadModule(ROOT, rel);
    } catch {
      continue;
    }
    const entries = Object.entries(mod);
    if (mod.default && typeof mod.default === "object" && !Array.isArray(mod.default)) {
      for (const [k, v] of Object.entries(mod.default)) {
        entries.push([k, v]);
      }
    }
    const seen = new Set();
    for (const [name, val] of entries) {
      if (name === "default" || name.startsWith("_") || seen.has(name)) continue;
      seen.add(name);
      if (typeof val !== "function") continue;
      if (isClassFn(val)) {
        const proto = val.prototype;
        if (!proto) continue;
        for (const mname of Object.getOwnPropertyNames(proto).sort()) {
          if (mname === "constructor" || mname.startsWith("_")) continue;
          const desc = Object.getOwnPropertyDescriptor(proto, mname);
          if (!desc || typeof desc.value !== "function") continue;
          const sig = parseFnSignature(desc.value, src, mname);
          ops.push({
            name: `${rel}::${name}.${mname}`,
            arity: sig.arity,
            stateful: true,
            param_types: sig.paramTypes,
            kwarg_names: [],
          });
        }
      } else {
        const sig = parseFnSignature(val, src, name);
        ops.push({
          name: `${rel}::${name}`,
          arity: sig.arity,
          stateful: false,
          param_types: sig.paramTypes,
          kwarg_names: [],
        });
      }
    }
  }
  const resp = {
    ok: true,
    fingerprint: `node-${process.versions.node}`,
    operations: ops,
    detail: "auto-node",
  };
  fs.writeSync(3, JSON.stringify(resp));
}

class EmiExit extends Error {
  constructor(code) {
    super(`exit:${code}`);
    this.exitCode = code === undefined || code === null ? 0 : Number(code);
  }
}

function buildLineOffsets(src) {
  const offs = [0];
  for (let i = 0; i < src.length; i++) {
    if (src.charCodeAt(i) === 10) offs.push(i + 1);
  }
  return offs;
}

function offsetToLine(offs, pos) {
  let lo = 0;
  let hi = offs.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (offs[mid] <= pos) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

async function runStepWorker() {
  process.argv = [process.execPath, ""];
  for (const k of Object.keys(process.env)) {
    if (k.toUpperCase().startsWith("EMI")) delete process.env[k];
  }
  const rawReq = fs.readFileSync(0, "utf8");
  const req = JSON.parse(rawReq);
  const session = new inspector.Session();
  session.connect();
  const post = (method, params = {}) =>
    new Promise((resolve, reject) => {
      session.post(method, params, (err, res) => (err ? reject(err) : resolve(res)));
    });
  await post("Profiler.enable");
  await post("Profiler.startPreciseCoverage", { callCount: true, detailed: true });

  const origExit = process.exit;
  process.exit = (code = 0) => {
    throw new EmiExit(code);
  };

  const origStdoutWrite = process.stdout.write.bind(process.stdout);
  const origStderrWrite = process.stderr.write.bind(process.stderr);

  const modCache = new Map();
  const instances = new Map();
  const outcomes = [];

  for (const op of req.ops || []) {
    let outBuf = "";
    let errBuf = "";
    process.stdout.write = (chunk, enc, cb) => {
      outBuf += Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
      if (typeof enc === "function") enc();
      else if (typeof cb === "function") cb();
      return true;
    };
    process.stderr.write = (chunk, enc, cb) => {
      errBuf += Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
      if (typeof enc === "function") enc();
      else if (typeof cb === "function") cb();
      return true;
    };
    let resObj;
    try {
      const spec = op.op || "";
      const sep = spec.indexOf("::");
      if (sep < 0) {
        resObj = { ok: false, err: `invalid op: ${spec}` };
      } else {
        const rel = spec.slice(0, sep);
        const sym = spec.slice(sep + 2);
        let mod = modCache.get(rel);
        if (!mod) {
          mod = await loadModule(ROOT, rel);
          modCache.set(rel, mod);
        }
        const args = Array.isArray(op.args) ? op.args : [];
        let val;
        if (sym.includes(".")) {
          const [clsName, mname] = sym.split(".", 2);
          const Cls = mod[clsName] || (mod.default && mod.default[clsName]);
          if (typeof Cls !== "function") {
            resObj = { ok: false, err: `missing_op:${sym}` };
          } else {
            const instKey = `${rel}::${clsName}`;
            let inst = instances.get(instKey);
            let ctorErr = null;
            if (!inst) {
              try {
                if (typeof Cls.__emiInit === "function") {
                  inst = Cls.__emiInit();
                } else if (typeof mod.emiFactory === "function") {
                  inst = mod.emiFactory(clsName);
                } else {
                  const clsSrc = Function.prototype.toString.call(Cls);
                  const cm = clsSrc.match(/constructor\s*\(([^)]*)\)/s);
                  let reqUntyped = false;
                  let ctorArgs = [];
                  if (cm && cm[1].trim()) {
                    for (const part of cm[1].split(",")) {
                      const trimmed = part.trim();
                      if (!trimmed || trimmed.startsWith("...")) continue;
                      if (trimmed.includes("=")) continue;
                      const colonIdx = trimmed.indexOf(":");
                      const rawName = (colonIdx >= 0 ? trimmed.slice(0, colonIdx) : trimmed).trim();
                      if (rawName.endsWith("?")) continue;
                      const ptype = colonIdx >= 0 ? mapTsType(trimmed.slice(colonIdx + 1)) : "any";
                      if (ptype === "any") {
                        reqUntyped = true;
                        break;
                      }
                      ctorArgs.push(defaultForType(ptype));
                    }
                  } else if (!cm && Cls.length > 0) {
                    const sig = parseFnSignature(Cls, "", clsName);
                    if (sig.paramTypes.length === 0 || sig.paramTypes.some((t) => t === "any")) {
                      reqUntyped = true;
                    } else {
                      ctorArgs = sig.paramTypes.map(defaultForType);
                    }
                  }
                  if (reqUntyped) {
                    ctorErr = "HarnessError: untyped required constructor parameter";
                  } else {
                    inst = new Cls(...ctorArgs);
                  }
                }
              } catch (ce) {
                ctorErr = `HarnessError: ${scrubPaths(String(ce && ce.message ? ce.message : ce))}`;
              }
              if (!ctorErr) {
                instances.set(instKey, inst);
              }
            }
            if (ctorErr) {
              resObj = { ok: false, harness_error: true, err: ctorErr };
            } else if (typeof inst[mname] !== "function") {
              resObj = { ok: false, err: `missing_op:${sym}` };
            } else {
              val = await inst[mname](...args);
              resObj = { ok: true, val: toJsonVal(val) };
            }
          }
        } else {
          const fn = mod[sym] || (mod.default && mod.default[sym]);
          if (typeof fn !== "function") {
            resObj = { ok: false, err: `missing_op:${sym}` };
          } else {
            val = await fn(...args);
            resObj = { ok: true, val: toJsonVal(val) };
          }
        }
      }
    } catch (e) {
      if (e instanceof EmiExit) {
        resObj = { ok: true, exit_code: e.exitCode };
      } else {
        const ename = (e && e.name) ? e.name : "Error";
        resObj = { ok: false, err: `${ename}: ${scrubPaths(String(e && e.message ? e.message : e).replace(ADDR_RE, "0x0"))}` };
      }
    } finally {
      process.stdout.write = origStdoutWrite;
      process.stderr.write = origStderrWrite;
    }
    if (outBuf) resObj.stdout = scrubPaths(outBuf.replace(ADDR_RE, "0x0"));
    if (errBuf) resObj.stderr = scrubPaths(errBuf.replace(ADDR_RE, "0x0"));
    outcomes.push(resObj);
  }

  process.exit = origExit;
  const covRes = await post("Profiler.takePreciseCoverage");
  await post("Profiler.stopPreciseCoverage");
  session.disconnect();

  const allHarnessErr = outcomes.length > 0 && outcomes.every((o) => o && o.harness_error === true);
  const absRoot = path.resolve(ROOT);
  const covSet = new Set();
  const offsetCache = new Map();
  for (const script of (allHarnessErr ? [] : ((covRes && covRes.result) || []))) {
    const url = script.url || "";
    if (!url.startsWith("file://")) continue;
    let filePath;
    try {
      filePath = fileURLToPath(url);
    } catch {
      continue;
    }
    if (!filePath.startsWith(absRoot + path.sep)) continue;
    const rel = path.relative(absRoot, filePath).split(path.sep).join("/");
    if (rel.startsWith(".") || rel.startsWith("node_modules/")) continue;
    let offs = offsetCache.get(filePath);
    if (!offs) {
      try {
        offs = buildLineOffsets(fs.readFileSync(filePath, "utf8"));
      } catch {
        continue;
      }
      offsetCache.set(filePath, offs);
    }
    for (const fn of script.functions || []) {
      for (const r of fn.ranges || []) {
        if (r.count > 0) {
          const startLine = offsetToLine(offs, r.startOffset);
          const endLine = offsetToLine(offs, Math.max(r.startOffset, r.endOffset - 1));
          for (let ln = startLine; ln <= Math.min(endLine, startLine + 200); ln++) {
            covSet.add(`${rel}:${ln}`);
          }
        }
      }
    }
  }

  fs.writeSync(3, JSON.stringify({ ok: true, outcomes, coverage: Array.from(covSet).sort() }));
}

function runParent() {
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let req;
    try {
      req = JSON.parse(trimmed);
    } catch {
      return;
    }
    if (req.verb === "probe") {
      const child = spawnSync(process.execPath, [SELF_PATH, "--probe"], {
        cwd: ROOT,
        stdio: ["ignore", "pipe", "pipe", "pipe"],
        encoding: "utf8",
      });
      const fd3 = child.output && child.output[3] ? child.output[3].trim() : "";
      if (fd3) {
        process.stdout.write(fd3 + "\n");
      } else {
        const errMsg = scrubPaths((child.stderr || "node probe failed").trim());
        process.stdout.write(JSON.stringify({ ok: false, fingerprint: "", operations: [], detail: errMsg }) + "\n");
      }
      return;
    }
    if (req.verb === "step") {
      const snap = snapshotObservedFiles(ROOT, req.observed_files || []);
      const child = spawnSync(process.execPath, [SELF_PATH, "--worker"], {
        cwd: ROOT,
        input: JSON.stringify(req),
        stdio: ["pipe", "pipe", "pipe", "pipe"],
        encoding: "utf8",
      });
      const obs = collectAndRestoreObservedFiles(ROOT, snap);
      const fd3 = child.output && child.output[3] ? child.output[3].trim() : "";
      let outcomes = [];
      let coverage = [];
      let ok = true;
      let errStr = null;
      if (fd3) {
        try {
          const parsed = JSON.parse(fd3);
          outcomes = parsed.outcomes || [];
          coverage = parsed.coverage || [];
          ok = parsed.ok !== false;
          errStr = parsed.error ? scrubPaths(String(parsed.error)) : null;
        } catch (e) {
          ok = false;
          errStr = scrubPaths(String(e));
        }
      } else {
        ok = false;
        errStr = scrubPaths((child.stderr || `worker exited ${child.status}`).trim());
      }
      const normOutcomes = outcomes.map(normalizeOutcomeForDigest);
      const digestInput = canonicalJson({
        outcomes: normOutcomes,
        side_effects: [],
        logs: [],
        observations: obs,
      });
      const digest = crypto.createHash("sha256").update(digestInput).digest("hex");
      const resp = {
        ok,
        outcomes,
        side_effects: [],
        logs: [],
        state_digest: digest,
        coverage,
        observations: obs,
        error: errStr,
      };
      process.stdout.write(JSON.stringify(resp) + "\n");
    }
  });
}

if (process.argv.includes("--probe")) {
  runProbeWorker().catch((e) => {
    fs.writeSync(3, JSON.stringify({ ok: false, fingerprint: "", operations: [], detail: scrubPaths(String(e)) }));
  });
} else if (process.argv.includes("--worker")) {
  runStepWorker().catch((e) => {
    fs.writeSync(3, JSON.stringify({ ok: false, outcomes: [], coverage: [], error: scrubPaths(String(e)) }));
  });
} else {
  runParent();
}
"####
}

pub fn materialize_auto_driver(dir: &Path) -> Result<Vec<String>, String> {
    match detect_auto_driver_kind(dir) {
        AutoDriverKind::Python => {
            let script = dir.join(".run_harness.py");
            std::fs::write(&script, default_python_driver_script())
                .map_err(|e| format!("failed to write auto driver: {e}"))?;
            Ok(vec![
                "python3".to_owned(),
                script.to_string_lossy().into_owned(),
            ])
        }
        AutoDriverKind::Node => {
            let script = dir.join(".run_harness.mjs");
            std::fs::write(&script, default_node_driver_script())
                .map_err(|e| format!("failed to write auto driver: {e}"))?;
            Ok(vec![
                "node".to_owned(),
                script.to_string_lossy().into_owned(),
            ])
        }
    }
}
