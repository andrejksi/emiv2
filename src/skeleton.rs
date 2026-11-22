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
    pub normalized_signature: String,
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
    "time.perf_counter(",
    "time.process_time(",
    "time.time_ns(",
    "perf_counter(",
    "datetime.now(",
    "datetime.utcnow(",
    "random.random(",
    "random.randint(",
    "random.choice(",
    "from random import",
    "os.urandom(",
    "secrets.",
    "uuid.uuid1(",
    "uuid.uuid4(",
    "SystemTime::now(",
    "Instant::now(",
    "thread_rng(",
    "Math.random(",
    "Date.now(",
];

pub fn normalize_python_signature(sig: &str) -> String {
    let trimmed = sig.trim();
    let (prefix, rest) = if let Some(r) = trimmed.strip_prefix("async def ") {
        ("async def", r)
    } else if let Some(r) = trimmed.strip_prefix("def ") {
        ("def", r)
    } else {
        return trimmed.to_owned();
    };
    let Some(open) = rest.find('(') else {
        return trimmed.to_owned();
    };
    let name = rest[..open].trim();
    let after_open = &rest[open + 1..];
    let mut depth = 1i32;
    let mut close_idx = after_open.len();
    for (idx, ch) in after_open.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    close_idx = idx;
                    break;
                }
            }
            _ => {}
        }
    }
    let params_raw = &after_open[..close_idx];
    let mut params = Vec::new();
    let mut cur = String::new();
    let mut pdepth = 0i32;
    for ch in params_raw.chars() {
        match ch {
            '(' | '[' | '{' => {
                pdepth += 1;
                cur.push(ch);
            }
            ')' | ']' | '}' => {
                pdepth -= 1;
                cur.push(ch);
            }
            ',' if pdepth == 0 => {
                if let Some(clean) = strip_param_annotation(&cur) {
                    params.push(clean);
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if let Some(clean) = strip_param_annotation(&cur) {
        params.push(clean);
    }
    format!("{prefix} {name}({})", params.join(", "))
}

fn strip_param_annotation(param: &str) -> Option<String> {
    let p = param.trim();
    if p.is_empty() {
        return None;
    }
    let has_default = p.contains('=');
    let before_eq = p.split('=').next().unwrap_or("").trim();
    let before_colon = before_eq.split(':').next().unwrap_or("").trim();
    if before_colon.is_empty() {
        return None;
    }
    if has_default {
        Some(format!("{before_colon}=..."))
    } else {
        Some(before_colon.to_owned())
    }
}

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
        payload.push_str(&format!(
            "{}|{}|{}|{}\n",
            s.file, s.kind, s.name, s.normalized_signature
        ));
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
                "target"
                    | "node_modules"
                    | "__pycache__"
                    | "venv"
                    | "tests"
                    | "test"
                    | "docs"
                    | "doc"
                    | "examples"
                    | "scripts"
                    | "benchmarks"
            )
        {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            if name_str.starts_with('_') {
                continue;
            }
            collect_source_files(root, &path, out)?;
        } else if matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("py" | "rs" | "ts" | "mts" | "js" | "mjs" | "cjs")
        ) {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    Ok(())
}

fn is_private_py_module(rel: &str) -> bool {
    for part in rel.split('/') {
        if part.starts_with('_') && part != "__init__.py" {
            return true;
        }
    }
    false
}

fn extract_python_all(text: &str) -> Option<std::collections::BTreeSet<String>> {
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if !line.starts_with(' ') && !line.starts_with('\t') {
            let trimmed = line.trim();
            if let Some(after_eq) = trimmed
                .strip_prefix("__all__")
                .and_then(|r| r.trim_start().strip_prefix('='))
            {
                let mut buf = after_eq.trim().to_owned();
                let open = buf.chars().next()?;
                if open != '[' && open != '(' {
                    return None;
                }
                let close = if open == '[' { ']' } else { ')' };
                while !buf.contains(close) && i + 1 < lines.len() {
                    i += 1;
                    buf.push(' ');
                    buf.push_str(lines[i].trim());
                }
                let end = buf.find(close)?;
                let inner = &buf[1..end];
                let mut names = std::collections::BTreeSet::new();
                let bytes = inner.as_bytes();
                let mut pos = 0;
                while pos < bytes.len() {
                    let b = bytes[pos];
                    if b == b'"' || b == b'\'' {
                        let q = b;
                        pos += 1;
                        let start = pos;
                        while pos < bytes.len() && bytes[pos] != q {
                            if bytes[pos] == b'\\' && pos + 1 < bytes.len() {
                                pos += 1;
                            }
                            pos += 1;
                        }
                        if let Ok(s) = std::str::from_utf8(&bytes[start..pos.min(bytes.len())]) {
                            if !s.is_empty() {
                                names.insert(s.to_owned());
                            }
                        }
                        if pos < bytes.len() {
                            pos += 1;
                        }
                    } else {
                        pos += 1;
                    }
                }
                return Some(names);
            }
        }
        i += 1;
    }
    None
}

fn strip_comments_and_strings(lines: &[&str], is_py: bool, is_rs: bool) -> Vec<String> {
    let mut out = Vec::with_capacity(lines.len());
    let mut in_py_triple: Option<u8> = None;
    let mut in_block_comment = false;
    let mut in_backtick = false;

    for line in lines {
        let bytes = line.as_bytes();
        let mut clean = String::with_capacity(bytes.len());
        let mut i = 0usize;
        while i < bytes.len() {
            if is_py {
                if let Some(q) = in_py_triple {
                    if i + 2 < bytes.len() && bytes[i] == q && bytes[i + 1] == q && bytes[i + 2] == q
                    {
                        in_py_triple = None;
                        clean.push_str("   ");
                        i += 3;
                    } else if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        clean.push_str("  ");
                        i += 2;
                    } else {
                        clean.push(' ');
                        i += 1;
                    }
                    continue;
                }
                if bytes[i] == b'#' {
                    break;
                }
                if (bytes[i] == b'"' || bytes[i] == b'\'')
                    && i + 2 < bytes.len()
                    && bytes[i + 1] == bytes[i]
                    && bytes[i + 2] == bytes[i]
                {
                    in_py_triple = Some(bytes[i]);
                    clean.push_str("   ");
                    i += 3;
                    continue;
                }
                if bytes[i] == b'"' || bytes[i] == b'\'' {
                    let q = bytes[i];
                    clean.push(' ');
                    i += 1;
                    while i < bytes.len() {
                        if bytes[i] == b'\\' && i + 1 < bytes.len() {
                            clean.push_str("  ");
                            i += 2;
                            continue;
                        }
                        let done = bytes[i] == q;
                        clean.push(' ');
                        i += 1;
                        if done {
                            break;
                        }
                    }
                    continue;
                }
                let ch = line[i..].chars().next().unwrap();
                clean.push(ch);
                i += ch.len_utf8();
            } else {
                if in_block_comment {
                    if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                        in_block_comment = false;
                        clean.push_str("  ");
                        i += 2;
                    } else {
                        clean.push(' ');
                        i += 1;
                    }
                    continue;
                }
                if in_backtick {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        clean.push_str("  ");
                        i += 2;
                    } else if bytes[i] == b'`' {
                        in_backtick = false;
                        clean.push(' ');
                        i += 1;
                    } else {
                        clean.push(' ');
                        i += 1;
                    }
                    continue;
                }
                if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
                    break;
                }
                if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                    in_block_comment = true;
                    clean.push_str("  ");
                    i += 2;
                    continue;
                }
                if !is_rs && bytes[i] == b'`' {
                    in_backtick = true;
                    clean.push(' ');
                    i += 1;
                    continue;
                }
                if bytes[i] == b'"' || (!is_rs && bytes[i] == b'\'') {
                    let q = bytes[i];
                    clean.push(' ');
                    i += 1;
                    while i < bytes.len() {
                        if bytes[i] == b'\\' && i + 1 < bytes.len() {
                            clean.push_str("  ");
                            i += 2;
                            continue;
                        }
                        let done = bytes[i] == q;
                        clean.push(' ');
                        i += 1;
                        if done {
                            break;
                        }
                    }
                    continue;
                }
                if is_rs && bytes[i] == b'\'' {
                    if i + 2 < bytes.len() && bytes[i + 1] != b'\\' && bytes[i + 2] == b'\'' {
                        clean.push_str("   ");
                        i += 3;
                        continue;
                    }
                    if i + 3 < bytes.len() && bytes[i + 1] == b'\\' && bytes[i + 3] == b'\'' {
                        clean.push_str("    ");
                        i += 4;
                        continue;
                    }
                }
                let ch = line[i..].chars().next().unwrap();
                clean.push(ch);
                i += ch.len_utf8();
            }
        }
        out.push(clean);
    }
    out
}

fn collect_multiline_header(cleaned: &[String], start_idx: usize, stop_at_brace: bool) -> String {
    let mut joined = String::new();
    let mut depth = 0i32;
    let mut saw_open = false;
    let max_idx = (start_idx + 32).min(cleaned.len());
    for line in &cleaned[start_idx..max_idx] {
        let part = line.trim();
        if part.is_empty() {
            if saw_open && depth <= 0 {
                break;
            }
            continue;
        }
        if !joined.is_empty() {
            joined.push(' ');
        }
        for ch in part.chars() {
            if stop_at_brace && ch == '{' && depth <= 0 {
                return collapse_ws(&joined);
            }
            joined.push(ch);
            match ch {
                '(' | '[' | '{' => {
                    if ch == '(' {
                        saw_open = true;
                    }
                    depth += 1;
                }
                ')' | ']' | '}' => {
                    depth -= 1;
                }
                _ => {}
            }
        }
        if saw_open && depth <= 0 {
            break;
        }
    }
    collapse_ws(&joined)
}

fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_ws = false;
    for ch in s.trim().chars() {
        if ch.is_whitespace() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.push(ch);
            prev_ws = false;
        }
    }
    out
}

pub fn extract_file(
    rel: &str,
    text: &str,
    symbols: &mut Vec<Symbol>,
    nondet_sites: &mut Vec<NondetSite>,
) {
    let lines: Vec<&str> = text.lines().collect();
    let is_py = rel.ends_with(".py");
    let is_rs = rel.ends_with(".rs");
    let cleaned = strip_comments_and_strings(&lines, is_py, is_rs);
    let py_private_mod = is_py && is_private_py_module(rel);
    let py_all = if is_py && !py_private_mod {
        extract_python_all(text)
    } else {
        None
    };
    let mut py_class_ctx: Option<(String, usize, bool)> = None;
    let mut py_fn_indent: Option<usize> = None;

    for (idx, line) in lines.iter().enumerate() {
        let clean_trimmed = cleaned[idx].trim();
        for tok in NONDET_TOKENS {
            if clean_trimmed.contains(tok) {
                nondet_sites.push(NondetSite {
                    file: rel.to_owned(),
                    line: (idx + 1) as u32,
                    token: (*tok).to_owned(),
                });
            }
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || clean_trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if is_py {
            if py_private_mod {
                continue;
            }
            if let Some(fi) = py_fn_indent {
                if indent <= fi {
                    py_fn_indent = None;
                }
            }
            if let Some((_, ci, _)) = &py_class_ctx {
                if indent <= *ci {
                    py_class_ctx = None;
                }
            }
            if py_fn_indent.is_some() {
                continue;
            }
            if let Some(rest) = clean_trimmed
                .strip_prefix("def ")
                .or_else(|| clean_trimmed.strip_prefix("async def "))
            {
                let name = rest.split('(').next().unwrap_or("").trim().to_owned();
                if indent == 0 {
                    py_fn_indent = Some(0);
                    let exported = py_all.as_ref().map_or(!name.starts_with('_'), |a| a.contains(&name));
                    if !name.is_empty() && !name.starts_with('_') && exported {
                        let complexity = branch_complexity(&lines[idx..], true);
                        let full_header = collect_multiline_header(&cleaned, idx, false);
                        let norm = normalize_python_signature(&full_header);
                        symbols.push(Symbol {
                            file: rel.to_owned(),
                            kind: "fn".to_owned(),
                            name,
                            signature: full_header,
                            normalized_signature: norm,
                            complexity,
                        });
                    }
                } else if let Some((cls_name, _, cls_public)) = &py_class_ctx {
                    py_fn_indent = Some(indent);
                    if *cls_public && !name.is_empty() && !name.starts_with('_') {
                        let complexity = branch_complexity(&lines[idx..], true);
                        let full_header = collect_multiline_header(&cleaned, idx, false);
                        let norm = normalize_python_signature(&full_header);
                        symbols.push(Symbol {
                            file: rel.to_owned(),
                            kind: "fn".to_owned(),
                            name: format!("{cls_name}.{name}"),
                            signature: full_header,
                            normalized_signature: norm,
                            complexity,
                        });
                    }
                } else {
                    py_fn_indent = Some(indent);
                }
            } else if let Some(rest) = clean_trimmed.strip_prefix("class ") {
                let name = rest
                    .split(['(', ':'])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                if indent == 0 {
                    let exported = py_all.as_ref().map_or(!name.starts_with('_'), |a| a.contains(&name));
                    let is_pub = !name.is_empty() && !name.starts_with('_') && exported;
                    py_class_ctx = Some((name.clone(), indent, is_pub));
                    if is_pub {
                        symbols.push(Symbol {
                            file: rel.to_owned(),
                            kind: "type".to_owned(),
                            name: name.clone(),
                            signature: trimmed.to_owned(),
                            normalized_signature: format!("class {name}"),
                            complexity: 1,
                        });
                    }
                } else {
                    py_class_ctx = Some((name, indent, false));
                }
            }
        } else if is_rs {
            if let Some(rest) = clean_trimmed
                .strip_prefix("pub fn ")
                .or_else(|| clean_trimmed.strip_prefix("pub async fn "))
            {
                let name = rest
                    .split(['(', '<'])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                if !name.is_empty() && !name.starts_with('_') {
                    let complexity = branch_complexity(&lines[idx..], false);
                    let sig = collect_multiline_header(&cleaned, idx, true);
                    symbols.push(Symbol {
                        file: rel.to_owned(),
                        kind: "fn".to_owned(),
                        name,
                        normalized_signature: sig.clone(),
                        signature: sig,
                        complexity,
                    });
                }
            } else if let Some(rest) = clean_trimmed
                .strip_prefix("pub struct ")
                .or_else(|| clean_trimmed.strip_prefix("pub enum "))
            {
                let name = rest
                    .split(['{', '(', '<', ';', ' '])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                if !name.is_empty() && !name.starts_with('_') {
                    let kind = if clean_trimmed.starts_with("pub enum ") {
                        "state_enum"
                    } else {
                        "type"
                    };
                    let sig = clean_trimmed
                        .split('{')
                        .next()
                        .unwrap_or(clean_trimmed)
                        .trim()
                        .to_owned();
                    symbols.push(Symbol {
                        file: rel.to_owned(),
                        kind: kind.to_owned(),
                        name,
                        normalized_signature: sig.clone(),
                        signature: sig,
                        complexity: 1,
                    });
                }
            }
        } else if rel.ends_with(".ts")
            || rel.ends_with(".mts")
            || rel.ends_with(".js")
            || rel.ends_with(".mjs")
            || rel.ends_with(".cjs")
        {
            if indent > 0 {
                continue;
            }
            if let Some(rest) = clean_trimmed
                .strip_prefix("export function ")
                .or_else(|| clean_trimmed.strip_prefix("export async function "))
                .or_else(|| clean_trimmed.strip_prefix("export default function "))
                .or_else(|| clean_trimmed.strip_prefix("export default async function "))
            {
                let name = rest
                    .split(['(', '<'])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                if !name.is_empty() && !name.starts_with('_') {
                    let complexity = branch_complexity(&lines[idx..], false);
                    let sig = collect_multiline_header(&cleaned, idx, true);
                    symbols.push(Symbol {
                        file: rel.to_owned(),
                        kind: "fn".to_owned(),
                        name,
                        normalized_signature: sig.clone(),
                        signature: sig,
                        complexity,
                    });
                }
            } else if let Some(rest) = clean_trimmed
                .strip_prefix("export class ")
                .or_else(|| clean_trimmed.strip_prefix("export default class "))
            {
                let name = rest
                    .split(['{', '(', '<', ' '])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                if !name.is_empty() && !name.starts_with('_') {
                    symbols.push(Symbol {
                        file: rel.to_owned(),
                        kind: "type".to_owned(),
                        name: name.clone(),
                        signature: clean_trimmed
                            .split('{')
                            .next()
                            .unwrap_or(clean_trimmed)
                            .trim()
                            .to_owned(),
                        normalized_signature: format!("class {name}"),
                        complexity: 1,
                    });
                }
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
            Some(csym) if csym.normalized_signature != bsym.normalized_signature => {
                changed_signatures.push(format!(
                    "{key}: `{}` -> `{}`",
                    bsym.normalized_signature, csym.normalized_signature
                ));
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
