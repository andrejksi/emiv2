use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use crate::diff::{ConstantPool, DiffConfig, run_diff};
use crate::json::{self, Value};
use crate::protocol::{Driver, Mask, StepOp, StepRequest};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultStatus {
    Killed,
    Survived,
    Unknown,
}

impl FaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            FaultStatus::Killed => "killed",
            FaultStatus::Survived => "survived",
            FaultStatus::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Disambiguator {
    pub fault_id: String,
    pub description: String,
    pub witness_ops: Vec<StepOp>,
    pub candidate_output: String,
    pub fault_output: String,
}

impl Disambiguator {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("fault_id", Value::Str(self.fault_id.clone())),
            ("description", Value::Str(self.description.clone())),
            (
                "witness_ops",
                Value::Array(self.witness_ops.iter().map(StepOp::to_json).collect()),
            ),
            ("candidate_output", Value::Str(self.candidate_output.clone())),
            ("fault_output", Value::Str(self.fault_output.clone())),
        ])
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FaultOutcome {
    pub fault_id: String,
    pub description: String,
    pub status: FaultStatus,
    pub disambiguator: Option<Disambiguator>,
}

impl FaultOutcome {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("fault_id", Value::Str(self.fault_id.clone())),
            ("description", Value::Str(self.description.clone())),
            ("status", Value::Str(self.status.as_str().to_owned())),
            (
                "disambiguator",
                self.disambiguator
                    .as_ref()
                    .map_or(Value::Null, Disambiguator::to_json),
            ),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct AdversaryReport {
    pub total_faults: usize,
    pub killed_faults: usize,
    pub survived_faults: usize,
    pub unknown_faults: usize,
    pub outcomes: Vec<FaultOutcome>,
}

impl AdversaryReport {
    pub fn ok(&self) -> bool {
        self.survived_faults == 0
    }

    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("ok", Value::Bool(self.ok())),
            ("total_faults", Value::Int(self.total_faults as i64)),
            ("killed_faults", Value::Int(self.killed_faults as i64)),
            ("survived_faults", Value::Int(self.survived_faults as i64)),
            ("unknown_faults", Value::Int(self.unknown_faults as i64)),
            (
                "outcomes",
                Value::Array(self.outcomes.iter().map(FaultOutcome::to_json).collect()),
            ),
        ])
    }
}

pub struct PlantedFault<'a> {
    pub id: String,
    pub description: String,
    pub driver: Box<dyn Driver + 'a>,
}

pub fn prove_oracle<'a>(
    candidate: &mut dyn Driver,
    oracle_requests: &[StepRequest],
    masks: &[Mask],
    mut faults: Vec<PlantedFault<'a>>,
    witness_search_seeds: usize,
    constants: &ConstantPool,
) -> Result<AdversaryReport, String> {
    let mut cand_hashes = Vec::with_capacity(oracle_requests.len());
    for req in oracle_requests {
        let trace = candidate.step(req)?;
        cand_hashes.push(trace.trace_hash(masks));
    }

    let mut outcomes = Vec::with_capacity(faults.len());
    let mut killed_faults = 0usize;
    let mut survived_faults = 0usize;
    let mut unknown_faults = 0usize;

    for (idx, fault) in faults.iter_mut().enumerate() {
        let probe_ok = match fault.driver.probe() {
            Ok(p) => p.ok,
            Err(_) => false,
        };
        if !probe_ok {
            unknown_faults += 1;
            outcomes.push(FaultOutcome {
                fault_id: fault.id.clone(),
                description: fault.description.clone(),
                status: FaultStatus::Unknown,
                disambiguator: None,
            });
            continue;
        }
        let mut killed = false;
        let mut driver_err = false;
        for (req, expected_hash) in oracle_requests.iter().zip(cand_hashes.iter()) {
            match fault.driver.step(req) {
                Ok(t) => {
                    if t.trace_hash(masks) != *expected_hash {
                        killed = true;
                        break;
                    }
                }
                Err(_) => {
                    driver_err = true;
                    break;
                }
            }
        }
        if driver_err {
            unknown_faults += 1;
            outcomes.push(FaultOutcome {
                fault_id: fault.id.clone(),
                description: fault.description.clone(),
                status: FaultStatus::Unknown,
                disambiguator: None,
            });
        } else if killed {
            killed_faults += 1;
            outcomes.push(FaultOutcome {
                fault_id: fault.id.clone(),
                description: fault.description.clone(),
                status: FaultStatus::Killed,
                disambiguator: None,
            });
        } else {
            let observed_files = oracle_requests
                .first()
                .map(|r| r.observed_files.clone())
                .unwrap_or_default();
            let cfg = DiffConfig {
                seeds: witness_search_seeds,
                base_seed: 0x9e3779b97f4a7c15 ^ ((idx as u64) + 1),
                max_seq_len: 6,
                parity: true,
                masks: masks.to_vec(),
                observed_files,
                constants: constants.clone(),
                inject_faults: false,
                ..DiffConfig::default()
            };
            let diff = run_diff(candidate, fault.driver.as_mut(), &cfg);
            let disambiguator = diff.divergences.into_iter().next().map(|d| Disambiguator {
                fault_id: fault.id.clone(),
                description: fault.description.clone(),
                witness_ops: d.ops,
                candidate_output: d.base_payload,
                fault_output: d.cand_payload,
            });
            if disambiguator.is_some() {
                survived_faults += 1;
                outcomes.push(FaultOutcome {
                    fault_id: fault.id.clone(),
                    description: fault.description.clone(),
                    status: FaultStatus::Survived,
                    disambiguator,
                });
            } else {
                unknown_faults += 1;
                outcomes.push(FaultOutcome {
                    fault_id: fault.id.clone(),
                    description: fault.description.clone(),
                    status: FaultStatus::Unknown,
                    disambiguator: None,
                });
            }
        }
    }

    Ok(AdversaryReport {
        total_faults: outcomes.len(),
        killed_faults,
        survived_faults,
        unknown_faults,
        outcomes,
    })
}

#[derive(Clone, Debug)]
pub struct SourceFault {
    pub id: String,
    pub rel_file: String,
    pub description: String,
    pub mutated_source: String,
}

const AST_MUTATOR_PY: &str = r#"import ast, copy, json, sys

def mutate_file(src, allowed_lines, max_faults):
    tree = ast.parse(src)
    faults = []
    cmp_swaps = {
        ast.LtE: (ast.Lt, "le_to_lt"),
        ast.Lt: (ast.LtE, "lt_to_le"),
        ast.GtE: (ast.Gt, "ge_to_gt"),
        ast.Gt: (ast.GtE, "gt_to_ge"),
        ast.Eq: (ast.NotEq, "eq_to_ne"),
        ast.NotEq: (ast.Eq, "ne_to_eq"),
    }
    bool_swaps = {
        ast.And: (ast.Or, "and_to_or"),
        ast.Or: (ast.And, "or_to_and"),
    }
    bin_swaps = {
        ast.Add: (ast.Sub, "add_to_sub"),
        ast.Sub: (ast.Add, "sub_to_add"),
    }
    nodes = list(ast.walk(tree))
    for node_idx, node in enumerate(nodes):
        if len(faults) >= max_faults:
            break
        lineno = getattr(node, "lineno", None)
        if lineno is None or (allowed_lines and lineno not in allowed_lines):
            continue
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            op_cls = type(node.ops[0])
            if op_cls in cmp_swaps:
                new_cls, tag = cmp_swaps[op_cls]
                cloned = copy.deepcopy(tree)
                target = list(ast.walk(cloned))[node_idx]
                target.ops[0] = new_cls()
                faults.append({"line": lineno, "tag": tag, "source": ast.unparse(cloned) + "\n"})
        elif isinstance(node, ast.BoolOp):
            op_cls = type(node.op)
            if op_cls in bool_swaps:
                new_cls, tag = bool_swaps[op_cls]
                cloned = copy.deepcopy(tree)
                target = list(ast.walk(cloned))[node_idx]
                target.op = new_cls()
                faults.append({"line": lineno, "tag": tag, "source": ast.unparse(cloned) + "\n"})
        elif isinstance(node, ast.BinOp):
            op_cls = type(node.op)
            if op_cls in bin_swaps:
                new_cls, tag = bin_swaps[op_cls]
                cloned = copy.deepcopy(tree)
                target = list(ast.walk(cloned))[node_idx]
                target.op = new_cls()
                faults.append({"line": lineno, "tag": tag, "source": ast.unparse(cloned) + "\n"})
        elif isinstance(node, ast.Constant) and isinstance(node.value, bool):
            cloned = copy.deepcopy(tree)
            target = list(ast.walk(cloned))[node_idx]
            target.value = not target.value
            faults.append({"line": lineno, "tag": "flip_bool", "source": ast.unparse(cloned) + "\n"})
    return faults

req = json.loads(sys.stdin.read())
res = mutate_file(req["source"], set(req["lines"]), req["max_faults"])
print(json.dumps(res))
"#;

pub fn synthesize_ast_faults(
    root: &Path,
    changed_lines: &BTreeMap<String, BTreeSet<u32>>,
    max_faults: usize,
) -> Vec<SourceFault> {
    let mut out = Vec::new();
    for (rel, lines) in changed_lines {
        if out.len() >= max_faults {
            break;
        }
        if rel.starts_with("test")
            || rel.contains("/test")
            || rel.contains(".test.")
            || rel.contains(".spec.")
            || rel.starts_with('.')
        {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(root.join(rel)) else {
            continue;
        };
        let remaining = max_faults - out.len();
        if !rel.ends_with(".py") {
            if is_mutable_non_python(rel) {
                out.extend(mutate_non_python_source(rel, &src, lines, remaining));
            }
            continue;
        }
        let req = Value::obj(vec![
            ("source", Value::Str(src)),
            (
                "lines",
                Value::Array(lines.iter().map(|&l| Value::Int(l as i64)).collect()),
            ),
            ("max_faults", Value::Int(remaining as i64)),
        ])
        .canonical();
        let Ok(mut child) = Command::new("python3")
            .args(["-c", AST_MUTATOR_PY])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        else {
            continue;
        };
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(req.as_bytes());
        }
        let Ok(output) = child.wait_with_output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let Ok(Value::Array(items)) = json::parse(String::from_utf8_lossy(&output.stdout).trim())
        else {
            continue;
        };
        for item in items {
            let line = item.get("line").and_then(Value::as_u64).unwrap_or(0);
            let tag = item
                .get("tag")
                .and_then(Value::as_str)
                .unwrap_or("mut")
                .to_owned();
            let Some(mutated_source) = item.get("source").and_then(Value::as_str) else {
                continue;
            };
            out.push(SourceFault {
                id: format!("{rel}:{line}:{tag}"),
                rel_file: rel.clone(),
                description: format!("AST mutation {tag} at {rel}:{line}"),
                mutated_source: mutated_source.to_owned(),
            });
            if out.len() >= max_faults {
                break;
            }
        }
    }
    out
}

fn is_mutable_non_python(rel: &str) -> bool {
    rel.ends_with(".rs")
        || rel.ends_with(".go")
        || rel.ends_with(".ts")
        || rel.ends_with(".tsx")
        || rel.ends_with(".mts")
        || rel.ends_with(".js")
        || rel.ends_with(".jsx")
        || rel.ends_with(".mjs")
        || rel.ends_with(".cjs")
}

fn is_non_exec_header_line(trimmed: &str) -> bool {
    trimmed.is_empty()
        || trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("import ")
        || trimmed.starts_with("export type ")
        || trimmed.starts_with("export interface ")
        || trimmed.starts_with("interface ")
        || trimmed.starts_with("type ")
        || trimmed.starts_with("use ")
        || trimmed.starts_with("package ")
        || trimmed.starts_with("mod ")
        || trimmed.starts_with("extern ")
        || trimmed.starts_with("#[")
        || trimmed.starts_with("struct ")
        || trimmed.starts_with("pub struct ")
        || trimmed.starts_with("enum ")
        || trimmed.starts_with("pub enum ")
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn mutate_non_python_source(
    rel: &str,
    src: &str,
    allowed_lines: &BTreeSet<u32>,
    max_faults: usize,
) -> Vec<SourceFault> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let mut line_starts = vec![0usize];
    for (idx, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            line_starts.push(idx + 1);
        }
    }
    let mut in_block_comment = false;
    let mut line_no = 1usize;
    let mut i = 0usize;

    while i < bytes.len() && out.len() < max_faults {
        if bytes[i] == b'\n' {
            line_no += 1;
            i += 1;
            continue;
        }
        if in_block_comment {
            if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                in_block_comment = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            in_block_comment = true;
            i += 2;
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'"' || bytes[i] == b'\'' || bytes[i] == b'`' {
            let quote = bytes[i];
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'\n' {
                    line_no += 1;
                }
                let done = bytes[i] == quote;
                i += 1;
                if done {
                    break;
                }
            }
            continue;
        }
        let line_allowed = allowed_lines.is_empty() || allowed_lines.contains(&(line_no as u32));
        if !line_allowed {
            i += 1;
            continue;
        }
        let lstart = line_starts.get(line_no - 1).copied().unwrap_or(0);
        let lend = line_starts
            .get(line_no)
            .map(|&p| p.saturating_sub(1))
            .unwrap_or(bytes.len());
        let trimmed_line = src[lstart..lend].trim();
        if is_non_exec_header_line(trimmed_line) {
            i = lend;
            continue;
        }

        let candidate: Option<(usize, &str, &str)> = if src[i..].starts_with("===") {
            Some((3, "!==", "strict_eq_to_ne"))
        } else if src[i..].starts_with("!==") {
            Some((3, "===", "strict_ne_to_eq"))
        } else if src[i..].starts_with("<=") {
            Some((2, "<", "le_to_lt"))
        } else if src[i..].starts_with(">=") {
            Some((2, ">", "ge_to_gt"))
        } else if src[i..].starts_with("==") {
            Some((2, "!=", "eq_to_ne"))
        } else if src[i..].starts_with("!=") {
            Some((2, "==", "ne_to_eq"))
        } else if src[i..].starts_with("&&") {
            Some((2, "||", "and_to_or"))
        } else if src[i..].starts_with("||") {
            Some((2, "&&", "or_to_and"))
        } else if src[i..].starts_with("true")
            && (i == 0 || !is_ident_byte(bytes[i - 1]))
            && (i + 4 >= bytes.len() || !is_ident_byte(bytes[i + 4]))
        {
            Some((4, "false", "true_to_false"))
        } else if src[i..].starts_with("false")
            && (i == 0 || !is_ident_byte(bytes[i - 1]))
            && (i + 5 >= bytes.len() || !is_ident_byte(bytes[i + 5]))
        {
            Some((5, "true", "false_to_true"))
        } else if bytes[i] == b'<'
            && (i == 0 || (bytes[i - 1] != b'<' && bytes[i - 1] != b'-'))
            && (i + 1 >= bytes.len()
                || (bytes[i + 1] != b'<' && bytes[i + 1] != b'=' && bytes[i + 1] != b'-'))
            && (i > 0 && bytes[i - 1] == b' ')
            && (i + 1 < bytes.len() && bytes[i + 1] == b' ')
        {
            Some((1, "<=", "lt_to_le"))
        } else if bytes[i] == b'>'
            && (i == 0 || (bytes[i - 1] != b'>' && bytes[i - 1] != b'-' && bytes[i - 1] != b'='))
            && (i + 1 >= bytes.len() || (bytes[i + 1] != b'>' && bytes[i + 1] != b'='))
            && (i > 0 && bytes[i - 1] == b' ')
            && (i + 1 < bytes.len() && bytes[i + 1] == b' ')
        {
            Some((1, ">=", "gt_to_ge"))
        } else if bytes[i] == b'+'
            && i > 0
            && bytes[i - 1] == b' '
            && i + 1 < bytes.len()
            && bytes[i + 1] == b' '
        {
            Some((1, "-", "add_to_sub"))
        } else if bytes[i] == b'-'
            && i > 0
            && bytes[i - 1] == b' '
            && i + 1 < bytes.len()
            && bytes[i + 1] == b' '
        {
            Some((1, "+", "sub_to_add"))
        } else if bytes[i] == b'*'
            && i > 0
            && bytes[i - 1] == b' '
            && i + 1 < bytes.len()
            && bytes[i + 1] == b' '
        {
            Some((1, "+", "mul_to_add"))
        } else {
            None
        };

        if let Some((len, repl, tag)) = candidate {
            let mut mutated = String::with_capacity(src.len() + repl.len());
            mutated.push_str(&src[..i]);
            mutated.push_str(repl);
            mutated.push_str(&src[i + len..]);
            out.push(SourceFault {
                id: format!("{rel}:{line_no}:{tag}"),
                rel_file: rel.to_owned(),
                description: format!("token mutation {tag} at {rel}:{line_no}"),
                mutated_source: mutated,
            });
            i += len;
        } else {
            i += 1;
        }
    }
    out
}
