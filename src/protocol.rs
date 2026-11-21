use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::json::{self, Value};
use crate::sha256;

pub const MAX_OPS_PER_SEQUENCE: usize = 64;
pub const MAX_MASKS: usize = 32;

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
}

#[derive(Clone, Debug, PartialEq)]
pub struct StepOp {
    pub op: String,
    pub args: Vec<Value>,
}

impl StepOp {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("op", Value::Str(self.op.clone())),
            ("args", Value::Array(self.args.clone())),
        ])
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
        Ok(Self { op, args })
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
}

impl StepRequest {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("verb", Value::Str("step".to_owned())),
            ("seed", Value::Int(self.seed as i64)),
            (
                "ops",
                Value::Array(self.ops.iter().map(StepOp::to_json).collect()),
            ),
            (
                "faults",
                Value::Array(self.faults.iter().map(FaultSpec::to_json).collect()),
            ),
        ])
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
    pub error: Option<String>,
}

impl Trace {
    pub fn canonical_payload(&self, masks: &[Mask]) -> String {
        let raw = Value::obj(vec![
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
        ])
        .canonical();
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

use std::process::{Child, ChildStdin, ChildStdout};

pub struct ProcessDriver {
    pub workdir: PathBuf,
    pub argv: Vec<String>,
    pub env_pins: Vec<(String, String)>,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: Option<BufReader<ChildStdout>>,
}

impl Drop for ProcessDriver {
    fn drop(&mut self) {
        self.stdin.take();
        self.stdout.take();
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl ProcessDriver {
    pub fn new(workdir: PathBuf, argv: Vec<String>) -> Self {
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
            child: None,
            stdin: None,
            stdout: None,
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
            .stderr(Stdio::piped());
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
        self.child = Some(child);
        self.stdin = Some(stdin);
        self.stdout = Some(BufReader::new(stdout));
        Ok(())
    }

    fn call(&mut self, payload: &Value) -> Result<Value, String> {
        self.ensure_started()?;
        let line = payload.canonical();
        {
            let stdin = self.stdin.as_mut().unwrap();
            stdin
                .write_all(line.as_bytes())
                .and_then(|()| stdin.write_all(b"\n"))
                .and_then(|()| stdin.flush())
                .map_err(|e| format!("driver stdin write failed: {e}"))?;
        }
        let mut resp_line = String::new();
        {
            let stdout = self.stdout.as_mut().unwrap();
            stdout
                .read_line(&mut resp_line)
                .map_err(|e| format!("driver stdout read failed: {e}"))?;
        }
        if resp_line.trim().is_empty() {
            self.stdin.take();
            self.stdout.take();
            let code = self
                .child
                .take()
                .and_then(|mut c| c.wait().ok())
                .and_then(|s| s.code());
            return Err(format!("driver returned empty output (exit {code:?})"));
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
                    operations.push(OpSpec {
                        name: name.to_owned(),
                        arity,
                        stateful,
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
        let resp = self.call(&req.to_json())?;
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
        let error = resp.get("error").and_then(Value::as_str).map(str::to_owned);
        Ok(Trace {
            ok,
            outcomes,
            side_effects,
            logs,
            state_digest,
            coverage,
            error,
        })
    }
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

pub fn default_python_driver_script() -> &'static str {
    r#"import ast, hashlib, importlib.util, inspect, json, os, random, sys, trace

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
                    arity = len(node.args.args)
                    ops.append({"name": f"{rel}::{node.name}", "arity": arity, "stateful": False})
    return ops

def load_module(root, rel):
    full = os.path.join(root, rel)
    mod_name = "emi_mod_" + hashlib.sha256(rel.encode()).hexdigest()[:12]
    spec = importlib.util.spec_from_file_location(mod_name, full)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, root)
    spec.loader.exec_module(mod)
    return mod

def main():
    root = os.getcwd()
    if root not in sys.path:
        sys.path.insert(0, root)
    loaded = {}
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
            random.seed(req.get("seed", 0))
            outcomes = []
            cov = set()
            ok = True
            err_msg = None
            for step_op in req.get("ops", []):
                target = step_op["op"]
                args = step_op.get("args", [])
                rel, fn_name = target.split("::", 1)
                if rel not in loaded:
                    loaded[rel] = load_module(root, rel)
                fn = getattr(loaded[rel], fn_name)
                tracer = trace.Trace(count=1, trace=0)
                try:
                    res = tracer.runfunc(fn, *args)
                    outcomes.append({"ok": True, "value": repr(res)})
                except Exception as exc:
                    outcomes.append({"ok": False, "exc": type(exc).__name__, "msg": str(exc)})
                for (filename, lineno), _cnt in tracer.results().counts.items():
                    if os.path.abspath(filename).startswith(os.path.abspath(root)):
                        cov.add(f"{os.path.relpath(filename, root)}:{lineno}")
            state_digest = hashlib.sha256(json.dumps(outcomes, sort_keys=True).encode()).hexdigest()
            print(json.dumps({
                "ok": ok,
                "outcomes": outcomes,
                "side_effects": [],
                "logs": [],
                "state_digest": state_digest,
                "coverage": sorted(cov),
                "error": err_msg
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
