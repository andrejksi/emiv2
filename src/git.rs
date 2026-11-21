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

pub fn changed_files(repo: &Path, base: &str, cand: Option<&str>) -> Result<Vec<String>, String> {
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
    let mut files: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    files.sort();
    files.dedup();
    Ok(files)
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
    let dest = std::env::temp_dir().join(format!("emi_snap_{tag}_{key}"));
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
    Ok(dest)
}

pub fn materialize_worktree(repo: &Path, tag: &str) -> Result<PathBuf, String> {
    let key = sha256::short_hex(
        format!("{}:{}:{}", repo.display(), tag, std::process::id()).as_bytes(),
    );
    let dest = std::env::temp_dir().join(format!("emi_wt_{tag}_{key}"));
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
