use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::sha256;

pub fn rev_parse(repo: &Path, rev: &str) -> Result<String, String> {
    let out = Command::new("git")
        .args(["rev-parse", "--verify", rev])
        .current_dir(repo)
        .output()
        .map_err(|e| format!("git rev-parse failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git rev-parse {rev} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

#[derive(Clone, Debug)]
pub struct ResolvedBase {
    pub rev: String,
    pub protected: bool,
    pub from_env: bool,
    pub is_full_sha: bool,
}

pub fn is_full_sha(rev: &str) -> bool {
    rev.len() == 40 && rev.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn check_remote_ref_tampered(repo: &Path, rev: &str) -> Result<Option<String>, String> {
    let branch = if let Some(b) = rev.strip_prefix("refs/remotes/origin/") {
        b
    } else if let Some(b) = rev.strip_prefix("origin/") {
        b
    } else {
        return Ok(None);
    };
    let local_sha = match rev_parse(repo, rev) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    if let Ok(url_out) = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(repo)
        .output()
    {
        if url_out.status.success() {
            let url = String::from_utf8_lossy(&url_out.stdout).trim().to_owned();
            let is_local = url.starts_with('/')
                || url.starts_with("./")
                || url.starts_with("../")
                || url.starts_with("file://")
                || Path::new(&url).exists();
            if is_local {
                if let Ok(ls_out) = Command::new("git")
                    .args(["ls-remote", "--heads", "origin", branch])
                    .current_dir(repo)
                    .output()
                {
                    if ls_out.status.success() {
                        let text = String::from_utf8_lossy(&ls_out.stdout);
                        if let Some(remote_sha) =
                            text.lines().next().and_then(|l| l.split_whitespace().next())
                        {
                            if !remote_sha.is_empty() && remote_sha != local_sha {
                                return Ok(Some(format!(
                                    "local ref '{rev}' ({local_sha}) does not match origin/{branch} ({remote_sha})"
                                )));
                            }
                        }
                    }
                }
            }
        }
    }
    let full_ref = format!("refs/remotes/origin/{branch}");
    if let Ok(rl_out) = Command::new("git")
        .args(["reflog", "-n", "1", "--format=%gs", &full_ref])
        .current_dir(repo)
        .output()
    {
        if rl_out.status.success() {
            let entry = String::from_utf8_lossy(&rl_out.stdout).trim().to_owned();
            if !entry.is_empty()
                && !entry.starts_with("fetch")
                && !entry.starts_with("clone")
                && !entry.starts_with("pull")
                && !entry.starts_with("update by push")
            {
                return Ok(Some(format!(
                    "remote-tracking ref '{rev}' was modified locally ({entry})"
                )));
            }
        }
    }
    Ok(None)
}

pub fn resolve_protected_base(
    repo: &Path,
    explicit: Option<&str>,
    allow_head: bool,
) -> Result<ResolvedBase, String> {
    if let Some(rev) = explicit {
        return Ok(ResolvedBase {
            rev: rev.to_owned(),
            protected: rev != "HEAD",
            from_env: false,
            is_full_sha: is_full_sha(rev),
        });
    }
    if let Ok(env_rev) = std::env::var("EMI_BASE_REV") {
        let trimmed = env_rev.trim();
        if !trimmed.is_empty() {
            if trimmed == "HEAD" && !allow_head {
                return Err(
                    "EMI_BASE_REV=HEAD is not a protected base ref; CI must fix the base on a clean checkout with --base <SHA>"
                        .to_owned(),
                );
            }
            return Ok(ResolvedBase {
                rev: trimmed.to_owned(),
                protected: trimmed != "HEAD",
                from_env: true,
                is_full_sha: is_full_sha(trimmed),
            });
        }
    }
    for candidate in ["origin/main", "origin/master"] {
        if rev_parse(repo, candidate).is_ok() {
            return Ok(ResolvedBase {
                rev: candidate.to_owned(),
                protected: true,
                from_env: false,
                is_full_sha: false,
            });
        }
    }
    if allow_head {
        Ok(ResolvedBase {
            rev: "HEAD".to_owned(),
            protected: false,
            from_env: false,
            is_full_sha: false,
        })
    } else {
        Err("no protected base ref found (set --base <SHA>, origin/main, or pass --allow-head; CI must fix the base on a clean checkout)".to_owned())
    }
}

pub fn changed_files(repo: &Path, base: &str, cand: Option<&str>) -> Result<Vec<String>, String> {
    let mut files = BTreeSet::new();
    let mut cmd = Command::new("git");
    cmd.arg("diff").arg("--name-only").arg(base);
    if let Some(c) = cand {
        cmd.arg(c);
    }
    let out = cmd
        .current_dir(repo)
        .output()
        .map_err(|e| format!("git diff failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git diff failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !is_emi_meta_path(trimmed) {
            files.insert(trimmed.to_owned());
        }
    }
    if cand.is_none() {
        let untracked = Command::new("git")
            .args(["ls-files", "--others", "--exclude-standard"])
            .current_dir(repo)
            .output()
            .map_err(|e| format!("git ls-files failed: {e}"))?;
        if untracked.status.success() {
            for line in String::from_utf8_lossy(&untracked.stdout).lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !is_emi_meta_path(trimmed) {
                    files.insert(trimmed.to_owned());
                }
            }
        }
    }
    Ok(files.into_iter().collect())
}

fn is_emi_meta_path(rel: &str) -> bool {
    rel == ".emi"
        || rel.starts_with(".emi/")
        || rel.starts_with(".emi_auto_")
        || rel.starts_with(".run_harness.")
}

pub fn changed_lines(
    repo: &Path,
    base: &str,
    cand: Option<&str>,
) -> Result<BTreeMap<String, BTreeSet<u32>>, String> {
    let mut result: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    let mut cmd = Command::new("git");
    cmd.args(["diff", "-U0", base]);
    if let Some(c) = cand {
        cmd.arg(c);
    }
    let out = cmd
        .current_dir(repo)
        .output()
        .map_err(|e| format!("git diff -U0 failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git diff -U0 failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut current_file: Option<String> = None;
    for line in text.lines() {
        if let Some(path) = line.strip_prefix("+++ b/") {
            if is_emi_meta_path(path) {
                current_file = None;
            } else {
                current_file = Some(path.to_owned());
            }
        } else if line.starts_with("+++ /dev/null") {
            current_file = None;
        } else if line.starts_with("@@ ") {
            if let Some(file) = &current_file {
                if let Some(plus_part) = line.split('+').nth(1) {
                    let span = plus_part.split(' ').next().unwrap_or("");
                    let mut parts = span.split(',');
                    let start = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
                    let count = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(1);
                    if start > 0 && count > 0 {
                        let set = result.entry(file.clone()).or_default();
                        for ln in start..start.saturating_add(count) {
                            set.insert(ln);
                        }
                    }
                }
            }
        }
    }
    if cand.is_none() {
        let untracked = Command::new("git")
            .args(["ls-files", "--others", "--exclude-standard"])
            .current_dir(repo)
            .output()
            .map_err(|e| format!("git ls-files failed: {e}"))?;
        if untracked.status.success() {
            for rel in String::from_utf8_lossy(&untracked.stdout).lines() {
                let rel = rel.trim();
                if rel.is_empty() || is_emi_meta_path(rel) {
                    continue;
                }
                if let Ok(content) = std::fs::read_to_string(repo.join(rel)) {
                    let set = result.entry(rel.to_owned()).or_default();
                    for ln in 1..=(content.lines().count() as u32) {
                        set.insert(ln);
                    }
                }
            }
        }
    }
    Ok(result)
}

const PY_EXEC_LINES_SCRIPT: &str = r#"import ast, json, sys, types

src = sys.stdin.read()
try:
    tree = ast.parse(src)
except Exception:
    print("null")
    sys.exit(0)

doc_lines = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
        start = getattr(node, "lineno", None)
        end = getattr(node, "end_lineno", start)
        if start is not None:
            for ln in range(start, (end or start) + 1):
                doc_lines.add(ln)

co = compile(tree, "<emi>", "exec")
out = set()
def walk_code(c):
    for _, _, ln in c.co_lines():
        if ln is not None and ln not in doc_lines:
            out.add(ln)
    for const in c.co_consts:
        if isinstance(const, types.CodeType):
            walk_code(const)

walk_code(co)
print(json.dumps(sorted(out)))
"#;

fn python_executable_lines(src: &str) -> Option<BTreeSet<u32>> {
    let mut child = Command::new("python3")
        .args(["-c", PY_EXEC_LINES_SCRIPT])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(src.as_bytes());
    }
    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    let trimmed = raw.trim();
    if trimmed == "null" || !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return None;
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let mut set = BTreeSet::new();
    for part in inner.split(',') {
        if let Ok(n) = part.trim().parse::<u32>() {
            set.insert(n);
        }
    }
    Some(set)
}

fn is_non_code_file(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    lower.ends_with(".md")
        || lower.ends_with(".txt")
        || lower.ends_with(".rst")
        || lower.ends_with(".json")
        || lower.ends_with(".toml")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.ends_with(".lock")
        || is_emi_meta_path(rel)
}

fn is_comment_or_blank(line: &str, hash_comments: bool) -> bool {
    let t = line.trim();
    if t.is_empty() {
        return true;
    }
    if hash_comments && t.starts_with('#') {
        return true;
    }
    t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') || t.starts_with("*/")
}

pub fn filter_executable_changed_lines(
    root: &Path,
    raw: &BTreeMap<String, BTreeSet<u32>>,
) -> BTreeMap<String, BTreeSet<u32>> {
    let mut out = BTreeMap::new();
    for (rel, lines) in raw {
        if is_non_code_file(rel) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(root.join(rel)) else {
            continue;
        };
        let filtered: BTreeSet<u32> = if rel.ends_with(".py") {
            if let Some(exec_set) = python_executable_lines(&src) {
                lines.iter().copied().filter(|ln| exec_set.contains(ln)).collect()
            } else {
                let all_lines: Vec<&str> = src.lines().collect();
                lines
                    .iter()
                    .copied()
                    .filter(|&ln| {
                        all_lines
                            .get((ln as usize).saturating_sub(1))
                            .is_some_and(|l| !is_comment_or_blank(l, true))
                    })
                    .collect()
            }
        } else {
            let hash_comments = rel.ends_with(".sh") || rel.ends_with(".rb");
            let all_lines: Vec<&str> = src.lines().collect();
            lines
                .iter()
                .copied()
                .filter(|&ln| {
                    all_lines
                        .get((ln as usize).saturating_sub(1))
                        .is_some_and(|l| !is_comment_or_blank(l, hash_comments))
                })
                .collect()
        };
        if !filtered.is_empty() {
            out.insert(rel.clone(), filtered);
        }
    }
    out
}

pub fn show_file(repo: &Path, rev: &str, rel_path: &str) -> Result<Option<String>, String> {
    let spec = format!("{rev}:{rel_path}");
    let out = Command::new("git")
        .args(["show", &spec])
        .current_dir(repo)
        .output()
        .map_err(|e| format!("git show failed: {e}"))?;
    if !out.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
}

pub fn materialize_revision(repo: &Path, rev: &str, tag: &str) -> Result<PathBuf, String> {
    let sha = rev_parse(repo, rev)?;
    let key = sha256::short_hex(
        format!("{}:{}:{}:{}", repo.display(), sha, tag, std::process::id()).as_bytes(),
    );
    let dest = std::env::temp_dir().join(format!("snap_{tag}_{key}"));
    if dest.exists() {
        let _ = std::fs::remove_dir_all(&dest);
    }
    std::fs::create_dir_all(&dest).map_err(|e| format!("create temp dir failed: {e}"))?;
    let archive = Command::new("git")
        .args(["archive", "--format=tar", &sha])
        .current_dir(repo)
        .output()
        .map_err(|e| format!("git archive failed: {e}"))?;
    if !archive.status.success() {
        return Err(format!(
            "git archive {sha} failed: {}",
            String::from_utf8_lossy(&archive.stderr).trim()
        ));
    }
    let mut tar = Command::new("tar")
        .args(["-x", "-f", "-"])
        .current_dir(&dest)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("tar spawn failed: {e}"))?;
    {
        use std::io::Write;
        let mut stdin = tar.stdin.take().ok_or_else(|| "tar stdin".to_owned())?;
        stdin
            .write_all(&archive.stdout)
            .map_err(|e| format!("tar write failed: {e}"))?;
    }
    let status = tar.wait().map_err(|e| format!("tar wait failed: {e}"))?;
    if !status.success() {
        return Err("tar extract failed".to_owned());
    }
    overlay_gitignored_files(repo, &dest);
    Ok(dest)
}

fn overlay_gitignored_files(repo: &Path, dest: &Path) {
    let Ok(out) = Command::new("git")
        .args(["ls-files", "--others", "--ignored", "--exclude-standard", "-z"])
        .current_dir(repo)
        .output()
    else {
        return;
    };
    if !out.status.success() {
        return;
    }
    for raw in out.stdout.split(|&b| b == 0) {
        if raw.is_empty() {
            continue;
        }
        let rel = String::from_utf8_lossy(raw);
        let rel_path = Path::new(rel.as_ref());
        let skip = rel_path.components().any(|c| {
            let s = c.as_os_str().to_string_lossy();
            matches!(
                s.as_ref(),
                ".git" | "target" | "node_modules" | "__pycache__" | ".venv" | ".emi"
            ) || s.starts_with(".emi_auto_")
                || s.starts_with(".run_harness.")
        });
        if skip {
            continue;
        }
        let src = repo.join(rel_path);
        let dst = dest.join(rel_path);
        if src.is_file() && !dst.exists() {
            if let Some(parent) = dst.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::copy(&src, &dst);
        }
    }
}

pub fn materialize_worktree(repo: &Path, tag: &str) -> Result<PathBuf, String> {
    let key = sha256::short_hex(
        format!("{}:{}:{}", repo.display(), tag, std::process::id()).as_bytes(),
    );
    let dest = std::env::temp_dir().join(format!("wt_{tag}_{key}"));
    if dest.exists() {
        let _ = std::fs::remove_dir_all(&dest);
    }
    copy_dir_filtered(repo, &dest)?;
    Ok(dest)
}

pub fn copy_dir_filtered(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dst).map_err(|e| format!("mkdir {}: {e}", dst.display()))?;
    for entry in std::fs::read_dir(src).map_err(|e| format!("readdir {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if matches!(
            name_str.as_ref(),
            ".git" | "target" | "node_modules" | "__pycache__" | ".venv"
        ) {
            continue;
        }
        let from = entry.path();
        let to = dst.join(&name);
        let ft = entry.file_type().map_err(|e| e.to_string())?;
        if ft.is_dir() {
            copy_dir_filtered(&from, &to)?;
        } else if ft.is_file() {
            std::fs::copy(&from, &to).map_err(|e| format!("copy {}: {e}", from.display()))?;
        }
    }
    Ok(())
}

pub fn tree_hash(root: &Path) -> Result<String, String> {
    let mut entries = Vec::new();
    collect_files(root, root, &mut entries)?;
    entries.sort();
    let mut acc = Vec::new();
    for rel in entries {
        let bytes = std::fs::read(root.join(&rel))
            .map_err(|e| format!("read {rel} for tree hash: {e}"))?;
        let h = sha256::hex(&bytes);
        acc.extend_from_slice(rel.as_bytes());
        acc.push(0);
        acc.extend_from_slice(h.as_bytes());
        acc.push(b'\n');
    }
    Ok(sha256::hex(&acc))
}

fn collect_files(root: &Path, cur: &Path, out: &mut Vec<String>) -> Result<(), String> {
    let rd = match std::fs::read_dir(cur) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    for entry in rd.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if matches!(
            name_str.as_ref(),
            ".git" | "target" | "node_modules" | "__pycache__" | ".venv" | ".emi"
        ) || name_str.starts_with(".emi_auto_")
            || name_str.starts_with(".run_harness.")
        {
            continue;
        }
        let p = entry.path();
        if p.is_dir() {
            collect_files(root, &p, out)?;
        } else if p.is_file() {
            if let Ok(rel) = p.strip_prefix(root) {
                out.push(rel.to_string_lossy().into_owned());
            }
        }
    }
    Ok(())
}
