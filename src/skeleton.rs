use std::collections::BTreeMap;
use std::path::Path;

use crate::json::Value;
use crate::sha256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    pub file: String,
    pub kind: String,
    pub name: String,
    pub signature: String,
    pub complexity: u32,
}

impl Symbol {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("file", Value::Str(self.file.clone())),
            ("kind", Value::Str(self.kind.clone())),
            ("name", Value::Str(self.name.clone())),
            ("signature", Value::Str(self.signature.clone())),
            ("complexity", Value::Int(self.complexity as i64)),
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NondetSite {
    pub file: String,
    pub line: u32,
    pub token: String,
}

impl NondetSite {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("file", Value::Str(self.file.clone())),
            ("line", Value::Int(self.line as i64)),
            ("token", Value::Str(self.token.clone())),
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skeleton {
    pub symbols: Vec<Symbol>,
    pub nondet_sites: Vec<NondetSite>,
    pub erosion_score: u32,
    pub digest: String,
}

impl Skeleton {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            (
                "symbols",
                Value::Array(self.symbols.iter().map(Symbol::to_json).collect()),
            ),
            (
                "nondet_sites",
                Value::Array(self.nondet_sites.iter().map(NondetSite::to_json).collect()),
            ),
            ("erosion_score", Value::Int(self.erosion_score as i64)),
            ("digest", Value::Str(self.digest.clone())),
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkeletonDiff {
    pub removed_symbols: Vec<String>,
    pub changed_signatures: Vec<String>,
    pub added_symbols: Vec<String>,
    pub new_nondet_sites: Vec<NondetSite>,
    pub erosion_delta: i64,
    pub ok: bool,
}

impl SkeletonDiff {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("ok", Value::Bool(self.ok)),
            (
                "removed_symbols",
                Value::Array(
                    self.removed_symbols
                        .iter()
                        .cloned()
                        .map(Value::Str)
                        .collect(),
                ),
            ),
            (
                "changed_signatures",
                Value::Array(
                    self.changed_signatures
                        .iter()
                        .cloned()
                        .map(Value::Str)
                        .collect(),
                ),
            ),
            (
                "added_symbols",
                Value::Array(
                    self.added_symbols
                        .iter()
                        .cloned()
                        .map(Value::Str)
                        .collect(),
                ),
            ),
            (
                "new_nondet_sites",
                Value::Array(
                    self.new_nondet_sites
                        .iter()
                        .map(NondetSite::to_json)
                        .collect(),
                ),
            ),
            ("erosion_delta", Value::Int(self.erosion_delta)),
        ])
    }
}

const NONDET_TOKENS: &[&str] = &[
    "time.time(",
    "time.monotonic(",
    "datetime.now(",
    "random.random(",
    "random.randint(",
    "random.choice(",
    "uuid.uuid4(",
    "SystemTime::now(",
    "Instant::now(",
    "thread_rng(",
    "Math.random(",
    "Date.now(",
];

pub fn extract_dir(root: &Path) -> Result<Skeleton, String> {
    let mut files = Vec::new();
    collect_source_files(root, root, &mut files)?;
    files.sort();
    let mut symbols = Vec::new();
    let mut nondet_sites = Vec::new();
    for rel in files {
        let full = root.join(&rel);
        let text = match std::fs::read_to_string(&full) {
            Ok(t) => t,
            Err(_) => continue,
        };
        extract_file(&rel, &text, &mut symbols, &mut nondet_sites);
    }
    let erosion_score = symbols
        .iter()
        .filter(|s| s.complexity > 10)
        .map(|s| s.complexity)
        .sum();
    let mut payload = String::new();
    for s in &symbols {
        payload.push_str(&format!("{}|{}|{}|{}\n", s.file, s.kind, s.name, s.signature));
    }
    let digest = sha256::hex(payload.as_bytes());
    Ok(Skeleton {
        symbols,
        nondet_sites,
        erosion_score,
        digest,
    })
}

fn collect_source_files(root: &Path, cur: &Path, out: &mut Vec<String>) -> Result<(), String> {
    let entries = match std::fs::read_dir(cur) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with('.')
            || matches!(
                name_str.as_ref(),
                "target" | "node_modules" | "__pycache__" | "venv" | "tests" | "test"
            )
        {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            collect_source_files(root, &path, out)?;
        } else if matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("py" | "rs" | "ts" | "js")
        ) {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_string_lossy().into_owned());
            }
        }
    }
    Ok(())
}

pub fn extract_file(
    rel: &str,
    text: &str,
    symbols: &mut Vec<Symbol>,
    nondet_sites: &mut Vec<NondetSite>,
) {
    let lines: Vec<&str> = text.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        for tok in NONDET_TOKENS {
            if trimmed.contains(tok) {
                nondet_sites.push(NondetSite {
                    file: rel.to_owned(),
                    line: (idx + 1) as u32,
                    token: (*tok).to_owned(),
                });
            }
        }
        if rel.ends_with(".py") {
            if let Some(rest) = trimmed.strip_prefix("def ") {
                if !rest.starts_with('_') {
                    let name = rest.split('(').next().unwrap_or("").trim().to_owned();
                    let complexity = branch_complexity(&lines[idx..], true);
                    symbols.push(Symbol {
                        file: rel.to_owned(),
                        kind: "fn".to_owned(),
                        name,
                        signature: trimmed.to_owned(),
                        complexity,
                    });
                }
            } else if let Some(rest) = trimmed.strip_prefix("class ") {
                if !rest.starts_with('_') {
                    let name = rest
                        .split(['(', ':'])
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_owned();
                    symbols.push(Symbol {
                        file: rel.to_owned(),
                        kind: "type".to_owned(),
                        name,
                        signature: trimmed.to_owned(),
                        complexity: 1,
                    });
                }
            }
        } else if rel.ends_with(".rs") {
            if let Some(rest) = trimmed.strip_prefix("pub fn ") {
                let name = rest
                    .split(['(', '<'])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                let complexity = branch_complexity(&lines[idx..], false);
                symbols.push(Symbol {
                    file: rel.to_owned(),
                    kind: "fn".to_owned(),
                    name,
                    signature: trimmed.trim_end_matches('{').trim().to_owned(),
                    complexity,
                });
            } else if let Some(rest) = trimmed
                .strip_prefix("pub struct ")
                .or_else(|| trimmed.strip_prefix("pub enum "))
            {
                let name = rest
                    .split(['{', '(', '<', ';', ' '])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                let kind = if trimmed.starts_with("pub enum ") {
                    "state_enum"
                } else {
                    "type"
                };
                symbols.push(Symbol {
                    file: rel.to_owned(),
                    kind: kind.to_owned(),
                    name,
                    signature: trimmed.trim_end_matches('{').trim().to_owned(),
                    complexity: 1,
                });
            }
        } else if rel.ends_with(".ts") || rel.ends_with(".js") {
            if let Some(rest) = trimmed.strip_prefix("export function ") {
                let name = rest
                    .split(['(', '<'])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                let complexity = branch_complexity(&lines[idx..], false);
                symbols.push(Symbol {
                    file: rel.to_owned(),
                    kind: "fn".to_owned(),
                    name,
                    signature: trimmed.trim_end_matches('{').trim().to_owned(),
                    complexity,
                });
            }
        }
    }
}

fn branch_complexity(slice: &[&str], python: bool) -> u32 {
    let mut score = 1u32;
    let base_indent = slice
        .first()
        .map(|l| l.len() - l.trim_start().len())
        .unwrap_or(0);
    let mut brace_depth = 0i32;
    let limit = slice.len().min(200);
    for (offset, line) in slice[..limit].iter().enumerate() {
        let trimmed = line.trim();
        if offset > 0 {
            if python {
                if !trimmed.is_empty() && (line.len() - line.trim_start().len()) <= base_indent {
                    break;
                }
            } else if brace_depth <= 0 && offset > 1 {
                break;
            }
        }
        for ch in trimmed.chars() {
            if ch == '{' {
                brace_depth += 1;
            } else if ch == '}' {
                brace_depth -= 1;
            }
        }
        for kw in ["if ", "elif ", "for ", "while ", "match ", "case ", "&&", "||", " and ", " or "] {
            if trimmed.contains(kw) {
                score = score.saturating_add(1);
            }
        }
    }
    score
}

pub fn compare(base: &Skeleton, cand: &Skeleton, forbid_new_nondet: bool) -> SkeletonDiff {
    let base_map: BTreeMap<String, &Symbol> = base
        .symbols
        .iter()
        .map(|s| (format!("{}::{}", s.file, s.name), s))
        .collect();
    let cand_map: BTreeMap<String, &Symbol> = cand
        .symbols
        .iter()
        .map(|s| (format!("{}::{}", s.file, s.name), s))
        .collect();

    let mut removed_symbols = Vec::new();
    let mut changed_signatures = Vec::new();
    let mut added_symbols = Vec::new();

    for (key, bsym) in &base_map {
        match cand_map.get(key) {
            None => removed_symbols.push(key.clone()),
            Some(csym) if csym.signature != bsym.signature => {
                changed_signatures.push(format!("{key}: `{}` -> `{}`", bsym.signature, csym.signature));
            }
            Some(_) => {}
        }
    }
    for key in cand_map.keys() {
        if !base_map.contains_key(key) {
            added_symbols.push(key.clone());
        }
    }

    let base_nondet: std::collections::BTreeSet<(&str, &str)> = base
        .nondet_sites
        .iter()
        .map(|n| (n.file.as_str(), n.token.as_str()))
        .collect();
    let new_nondet_sites: Vec<NondetSite> = cand
        .nondet_sites
        .iter()
        .filter(|n| !base_nondet.contains(&(n.file.as_str(), n.token.as_str())))
        .cloned()
        .collect();

    let erosion_delta = cand.erosion_score as i64 - base.erosion_score as i64;
    let ok = removed_symbols.is_empty()
        && changed_signatures.is_empty()
        && (!forbid_new_nondet || new_nondet_sites.is_empty());

    SkeletonDiff {
        removed_symbols,
        changed_signatures,
        added_symbols,
        new_nondet_sites,
        erosion_delta,
        ok,
    }
}
