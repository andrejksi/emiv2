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
        let mut fields = vec![
            ("ok", Value::Bool(self.ok)),
            ("outcomes", Value::Array(self.outcomes.clone())),
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
                ("EMI_DETERMINISTIC".to_owned(), "1".to_owned()),
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
        let ok = resp.get("ok").and_then(Value::as_bool).unwrap_or(false);
        let outcomes = resp
            .get("outcomes")
            .and_then(Value::as_array)
            .map(<[Value]>::to_vec)
            .unwrap_or_default();
        let side_effects = resp
            .get("side_effects")
            .and_then(Value::as_array)
            .map(<[Value]>::to_vec)
            .unwrap_or_default();
        let logs = resp
            .get("logs")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let state_digest = resp
            .get("state_digest")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
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
        for (k, v) in file_obs {
            observations.entry(k).or_insert(v);
        }
        let error = resp.get("error").and_then(Value::as_str).map(str::to_owned);
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

pub fn compute_driver_digest(
    root: &Path,
    explicit: Option<&str>,
    ratchet_driver: Option<&str>,
) -> String {
    let mut acc = Vec::new();
    match explicit.or(ratchet_driver) {
        None => {
            acc.extend_from_slice(b"auto-python\0");
            acc.extend_from_slice(default_python_driver_script().as_bytes());
        }
        Some(cmd) => {
            acc.extend_from_slice(b"custom\0");
            acc.extend_from_slice(cmd.as_bytes());
            acc.push(0);
            for tok in split_command(cmd) {
                if tok.starts_with('-') {
                    continue;
                }
                let local = root.join(&tok);
                let target = if local.is_file() {
                    Some(local)
                } else {
                    let direct = PathBuf::from(&tok);
                    if direct.is_file() {
                        Some(direct)
                    } else {
                        None
                    }
                };
                if let Some(file) = target {
                    if let Ok(bytes) = std::fs::read(&file) {
                        acc.extend_from_slice(tok.as_bytes());
                        acc.push(0);
                        acc.extend_from_slice(sha256::hex(&bytes).as_bytes());
                        acc.push(b'\n');
                    }
                }
            }
        }
    }
    sha256::hex(&acc)
}

pub fn default_python_driver_script() -> &'static str {
    r#"import ast, hashlib, importlib.util, json, os, random, sys, trace

def type_name(ann):
    if ann is None:
        return "any"
    if isinstance(ann, ast.Name):
        return ann.id
    if isinstance(ann, ast.Subscript) and isinstance(ann.value, ast.Name):
        return ann.value.id
    return "any"

def to_json_val(v):
    if v is None or isinstance(v, (bool, int, str)):
        return v
    if isinstance(v, float):
        return v if (v == v and v != float('inf') and v != float('-inf')) else repr(v)
    if isinstance(v, list):
        return [to_json_val(x) for x in v]
    if isinstance(v, dict):
        return {str(k): to_json_val(val) for k, val in v.items()}
    return repr(v)

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
                        if isinstance(item, ast.FunctionDef) and not item.name.startswith('_'):
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

def load_fresh_module(root, rel, step_epoch):
    full = os.path.join(root, rel)
    if not os.path.exists(full):
        raise FileNotFoundError(f"missing module {rel}")
    mod_name = f"emi_mod_{step_epoch}_{hashlib.sha256(rel.encode()).hexdigest()[:10]}"
    spec = importlib.util.spec_from_file_location(mod_name, full)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def main():
    root = os.getcwd()
    if root not in sys.path:
        sys.path.insert(0, root)
    step_epoch = 0
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
            print(json.dumps({"ok": True, "fingerprint": fp, "operations": ops, "detail": "auto-python"}), flush=True)
            continue
        if verb == "step":
            step_epoch += 1
            seed_raw = req.get("seed", "0")
            seed_int = int(seed_raw) if isinstance(seed_raw, str) else int(seed_raw)
            random.seed(seed_int)
            outcomes = []
            cov = set()
            loaded = {}
            instances = {}
            faults = req.get("faults", [])
            for idx, step_op in enumerate(req.get("ops", [])):
                hit_fault = next((f for f in faults if f.get("at_step") == idx), None)
                if hit_fault is not None:
                    outcomes.append({"ok": False, "fault": hit_fault.get("kind", "fault")})
                    continue
                target = step_op["op"]
                args = step_op.get("args", [])
                kwargs = step_op.get("kwargs", {})
                tracer = trace.Trace(count=1, trace=0)
                try:
                    rel, sym = target.split("::", 1)
                    if rel not in loaded:
                        loaded[rel] = load_fresh_module(root, rel, step_epoch)
                    mod = loaded[rel]
                    if "." in sym:
                        cls_name, meth_name = sym.split(".", 1)
                        cls_key = f"{rel}::{cls_name}"
                        if cls_key not in instances:
                            cls_obj = getattr(mod, cls_name)
                            instances[cls_key] = cls_obj()
                        fn = getattr(instances[cls_key], meth_name)
                    else:
                        fn = getattr(mod, sym)
                    res = tracer.runfunc(fn, *args, **kwargs)
                    outcomes.append({"ok": True, "value": repr(res), "json": to_json_val(res)})
                except AttributeError as exc:
                    outcomes.append({"ok": False, "exc": "MissingSymbol", "msg": str(exc)})
                except Exception as exc:
                    outcomes.append({"ok": False, "exc": type(exc).__name__, "msg": str(exc)})
                for (filename, lineno), _cnt in tracer.results().counts.items():
                    if os.path.abspath(filename).startswith(os.path.abspath(root)):
                        cov.add(f"{os.path.relpath(filename, root)}:{lineno}")
            state_digest = hashlib.sha256(json.dumps(outcomes, sort_keys=True).encode()).hexdigest()
            print(json.dumps({
                "ok": True,
                "outcomes": outcomes,
                "side_effects": [],
                "logs": [],
                "state_digest": state_digest,
                "coverage": sorted(cov),
                "observations": {},
                "error": None
            }), flush=True)

if __name__ == "__main__":
    main()
"#
}

pub fn materialize_auto_driver(dir: &Path) -> Result<Vec<String>, String> {
    let script = dir.join(".emi_auto_driver.py");
    std::fs::write(&script, default_python_driver_script())
        .map_err(|e| format!("failed to write auto driver: {e}"))?;
    Ok(vec![
        "python3".to_owned(),
        script.to_string_lossy().into_owned(),
    ])
}
