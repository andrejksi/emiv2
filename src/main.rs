mod adversary;
mod climb;
mod diff;
mod driver_init;
mod git;
mod json;
mod prng;
mod protocol;
mod ratchet;
mod sha256;
mod sim;
mod skeleton;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use crate::adversary::{AdversaryReport, PlantedFault, prove_oracle, synthesize_ast_faults};
use crate::climb::{
    Direction, FloorChecks, classify_benchmark_parity, evaluate_climb,
    measure_interleaved_with_timeout,
};
use crate::diff::{ConstantPool, DiffConfig, Verdict, replay_witnesses, run_diff};
use crate::driver_init::DriverLang;
use crate::json::Value;
use crate::protocol::{
    CommandDriver, DEFAULT_CALL_TIMEOUT_MS, DEFAULT_PROBE_TIMEOUT_MS, Driver, ProcessDriver,
    StepOp, StepRequest, compute_driver_digest_full, materialize_auto_driver_for_changes,
    split_command,
};
use crate::ratchet::{
    ApprovalRule, Attestation, EnforceMode, EvidenceRecord, HistoryEntry, IncidentSeed,
    append_attestation, append_history, load_evidence, load_history, load_pinned, now_unix_secs,
    save_evidence_signed, save_local,
};

macro_rules! println {
    () => {{
        let _ = std::io::Write::write_all(&mut std::io::stdout().lock(), b"\n");
    }};
    ($($arg:tt)*) => {{
        let _ = std::io::Write::write_fmt(
            &mut std::io::stdout().lock(),
            format_args!("{}\n", format_args!($($arg)*)),
        );
    }};
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("emi: error: {err}");
            ExitCode::from(2)
        }
    }
}

fn dispatch(args: &[String]) -> Result<u8, String> {
    let Some(first) = args.first().map(String::as_str) else {
        return run_diff_or_check(&[], true, true);
    };
    if first.starts_with('-') {
        if matches!(first, "-h" | "--help") {
            print_usage();
            return Ok(0);
        }
        return run_diff_or_check(args, true, true);
    }
    let rest = &args[1..];
    match first {
        "connect" => cmd_connect(rest),
        "check" => cmd_check(rest),
        "replay" => cmd_replay(rest),
        "driver" => cmd_driver(rest),
        "skeleton" => cmd_skeleton(rest),
        "diff" => cmd_diff(rest),
        "adversary" => cmd_adversary(rest),
        "ratchet" => cmd_ratchet(rest),
        "climb" => cmd_climb(rest),
        "stats" => cmd_stats(rest),
        "sim" => cmd_sim(rest),
        "help" => {
            print_usage();
            Ok(0)
        }
        other => Err(format!("unknown command `{other}`")),
    }
}

fn print_usage() {
    println!("emi 2.0.0 — deterministic proof & control engine for agentic software");
    println!("quick start:");
    println!("  emi [--report-diff] [--json]               smart zero-config check (auto-base, fast witness replay, auto-test fallback)");
    println!("  emi connect [--tool auto|opencode|claude|cursor|all]   wire emi into your AI coding harness + .gitignore");
    println!("  emi stats [--since 30m|2h|1d] [--json]     live session monitor (verdicts, latency, catches fixed, blockers)");
    println!("advanced commands:");
    println!("  emi check [--repo PATH] [--base REV] [--cand REV] [--allow-head] [--driver CMD] [--cmd CMD]... [--report-diff] [--seeds N] [--seed U64] [--timeout-ms MS] [--probe-timeout-ms MS] [--min-cov-ratio F] [--with-adversary|--no-adversary] [--max-faults N] [--forbid-nondet] [--require-mutations] [--observe-file PATH] [--require-observation NAME] [--require-workflow ID] [--evidence-out PATH] [--key-file PATH] [--no-strict] [--no-history] [--json]");
    println!("  emi replay [--repo PATH] [--base REV] [--allow-head] [--evidence PATH] [--id DIFF_ID] [--observe-file PATH] [--driver CMD] [--cmd CMD]... [--timeout-ms MS] [--probe-timeout-ms MS] [--no-history] [--json]");
    println!("  emi driver init [--repo PATH] [--lang python|node|ts|go|rust] [--out PATH] [--force] [--pin] [--json]");
    println!("  emi skeleton [extract|check] [--repo PATH] [--base REV] [--allow-head] [--forbid-nondet] [--json]");
    println!("  emi diff [--repo PATH] [--base REV] [--cand REV] [--allow-head] [--driver CMD] [--cmd CMD]... [--report-diff] [--seeds N] [--seed U64] [--timeout-ms MS] [--probe-timeout-ms MS] [--parity] [--strict|--no-strict] [--min-cov-ratio F] [--with-adversary] [--max-faults N] [--require-mutations] [--observe-file PATH] [--require-observation NAME] [--require-workflow ID] [--evidence-out PATH] [--key-file PATH] [--no-evidence] [--no-history] [--json]");
    println!("  emi adversary [--repo PATH] [--base REV] [--cand REV] [--allow-head] [--driver CMD] [--cmd CMD]... [--max-faults N] [--seeds N] [--timeout-ms MS] [--probe-timeout-ms MS] [--require-mutations] [--observe-file PATH] [--evidence PATH] [--key-file PATH] [--json]");
    println!("  emi ratchet [init|status|approve <ID>|lock-rule --op GLOB --when PRED --expect EXPR [--must-hold]|remember --id ID --trigger GLOB --ops JSON|stamp [--evidence PATH|--fresh]] [--repo PATH] [--base REV] [--allow-head] [--mode off|observe|enforce] [--driver CMD] [--cmd CMD]... [--min-cov-ratio F] [--require-mutations] [--observe-file PATH] [--require-observation NAME] [--require-workflow ID] [--key-file PATH] [--seed U64] [--timeout-ms MS] [--probe-timeout-ms MS] [--strict] [--json]");
    println!("  emi climb --metric CMD [--metric-file PATH] [--repo PATH] [--base REV] [--allow-head] [--driver CMD] [--cmd CMD]... [--runs N] [--seeds N] [--timeout-ms MS] [--probe-timeout-ms MS] [--min-effect F] [--min-cov-ratio F] [--max-faults N] [--observe-file PATH] [--require-observation NAME] [--require-workflow ID] [--maximize] [--no-history] [--json]");
    println!("  emi sim [--seeds N] [--seed U64] [--fast] [--json]");
}

fn flag_val(args: &[String], name: &str) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            return args.get(i + 1).cloned();
        }
        i += 1;
    }
    None
}

fn flag_vals(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

fn merge_unique(base: &[String], extra: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for item in base.iter().chain(extra.iter()) {
        let trimmed = item.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_owned()) {
            out.push(trimmed.to_owned());
        }
    }
    out
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn repo_arg(args: &[String]) -> PathBuf {
    flag_val(args, "--repo")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn timeout_arg(args: &[String]) -> Duration {
    let ms = flag_val(args, "--timeout-ms")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_CALL_TIMEOUT_MS);
    Duration::from_millis(ms.max(50))
}

fn probe_timeout_arg(args: &[String]) -> Duration {
    let ms = flag_val(args, "--probe-timeout-ms")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_PROBE_TIMEOUT_MS);
    Duration::from_millis(ms.max(50))
}

fn base_seed_arg(args: &[String]) -> Result<u64, String> {
    match flag_val(args, "--seed") {
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|_| format!("invalid --seed value `{raw}` (expected u64)")),
        None => Ok(DiffConfig::default().base_seed),
    }
}

fn resolve_base_with_fallback(
    repo: &Path,
    args: &[String],
    allow_head_fallback: bool,
) -> Result<git::ResolvedBase, String> {
    let explicit = flag_val(args, "--base");
    let allow_head = has_flag(args, "--allow-head") || allow_head_fallback;
    let resolved = git::resolve_protected_base(repo, explicit.as_deref(), allow_head)?;
    if let Some(reason) = git::check_remote_ref_tampered(repo, &resolved.rev)? {
        return Err(format!(
            "refusing locally moved base ref: {reason}; CI must fix the base on a clean checkout with --base <SHA>"
        ));
    }
    Ok(resolved)
}

fn resolve_base_detailed(repo: &Path, args: &[String]) -> Result<git::ResolvedBase, String> {
    resolve_base_with_fallback(repo, args, false)
}

fn resolve_base(repo: &Path, args: &[String]) -> Result<(String, bool), String> {
    let r = resolve_base_detailed(repo, args)?;
    Ok((r.rev, r.protected))
}

fn enforce_base_policy(
    repo: &Path,
    mode: EnforceMode,
    base: &git::ResolvedBase,
) -> Result<(), String> {
    if mode == EnforceMode::Enforce {
        if base.from_env {
            return Err(
                "enforced mode forbids EMI_BASE_REV; CI must fix the base on a clean checkout with --base <SHA>"
                    .to_owned(),
            );
        }
        if !base.protected {
            return Err(
                "enforced mode forbids bare HEAD baseline; CI must fix the base on a clean checkout with --base <SHA>"
                    .to_owned(),
            );
        }
        if !base.is_full_sha {
            let base_sha = git::rev_parse(repo, &base.rev)?;
            let head_sha = git::rev_parse(repo, "HEAD").unwrap_or_default();
            if !head_sha.is_empty()
                && base_sha == head_sha
                && git::changed_files(repo, &base.rev, None)
                    .map(|c| c.is_empty())
                    .unwrap_or(false)
            {
                return Err(format!(
                    "enforced mode refuses mutable base ref '{}' pointing at HEAD with no diff (could have been moved locally); CI must fix the base on a clean checkout with --base <SHA>",
                    base.rev
                ));
            }
            eprintln!(
                "emi: warning: base ref '{}' could be moved locally; CI must fix the base on a clean checkout with --base <SHA>",
                base.rev
            );
        }
    } else if base.from_env {
        eprintln!(
            "emi: warning: base ref '{}' came from EMI_BASE_REV and could be set locally; CI must fix the base on a clean checkout with --base <SHA>",
            base.rev
        );
    }
    Ok(())
}

fn signing_key_from_env_or_args(args: &[String]) -> Result<Option<Vec<u8>>, String> {
    if let Some(path) = flag_val(args, "--key-file") {
        let bytes = std::fs::read(&path).map_err(|e| format!("read key file {path}: {e}"))?;
        return Ok(Some(bytes));
    }
    if let Ok(val) = std::env::var("EMI_SIGNING_KEY") {
        if !val.is_empty() {
            return Ok(Some(val.into_bytes()));
        }
    }
    Ok(None)
}

fn flatten_changed_lines(map: &BTreeMap<String, BTreeSet<u32>>) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for (file, lines) in map {
        for &ln in lines {
            set.insert(format!("{file}:{ln}"));
        }
    }
    set
}

fn build_constant_pool(
    base_snap: &Path,
    cand_snap: &Path,
    changed: &[String],
    changed_lines: &BTreeMap<String, BTreeSet<u32>>,
    deleted_lines: &BTreeMap<String, BTreeSet<u32>>,
    rules: &[ApprovalRule],
) -> ConstantPool {
    let mut pool = ConstantPool::from_files_with_imports(base_snap, changed);
    pool.merge(&ConstantPool::from_files_with_imports(cand_snap, changed));
    pool.add_hot_from_changed_lines(base_snap, changed_lines);
    pool.add_hot_from_changed_lines(cand_snap, changed_lines);
    pool.add_hot_from_changed_lines(base_snap, deleted_lines);
    pool.merge_from_rules(rules);
    pool
}

fn compute_priority_files(base_snap: &Path, cand_snap: &Path, changed: &[String]) -> Vec<String> {
    let mut out = diff::find_priority_files(cand_snap, changed);
    let mut seen: BTreeSet<String> = out.iter().cloned().collect();
    for f in diff::find_priority_files(base_snap, changed) {
        if seen.insert(f.clone()) {
            out.push(f);
        }
    }
    out
}

fn mutation_policy_issue(
    require_mutations: bool,
    changed_lines_total: usize,
    mutations_run: bool,
    total: usize,
    killed: usize,
    survived: usize,
    unknown: usize,
) -> Option<String> {
    if !require_mutations || changed_lines_total == 0 || survived > 0 {
        return None;
    }
    if !mutations_run {
        return Some(
            "inconclusive: policy requires mutation evidence; run with --with-adversary or attach via emi adversary --evidence"
                .to_owned(),
        );
    }
    if total == 0 {
        return Some(
            "inconclusive: policy requires mutation evidence but 0 AST mutations were synthesized on executable changed lines"
                .to_owned(),
        );
    }
    if killed == 0 && unknown > 0 {
        return Some(format!(
            "inconclusive: policy requires mutation evidence but 0 of {total} mutations were killed ({unknown} unknown)"
        ));
    }
    None
}

fn run_ast_adversary(
    cand_snap: &Path,
    cand_drv: &mut dyn Driver,
    oracle_reqs: &[StepRequest],
    changed_lines: &BTreeMap<String, BTreeSet<u32>>,
    explicit_driver: Option<&str>,
    ratchet_driver: Option<&str>,
    commands: &[String],
    changed: &[String],
    priority_files: &[String],
    masks: &[protocol::Mask],
    max_faults: usize,
    constants: &ConstantPool,
    timeout: Duration,
    probe_timeout: Duration,
) -> Result<AdversaryReport, String> {
    let source_faults = synthesize_ast_faults(cand_snap, changed_lines, max_faults);
    let mut fault_dirs = Vec::with_capacity(source_faults.len());
    let mut planted = Vec::with_capacity(source_faults.len());

    for (idx, sf) in source_faults.iter().enumerate() {
        let fdir = std::env::temp_dir().join(format!("mut_{}_{}", std::process::id(), idx));
        if fdir.exists() {
            let _ = std::fs::remove_dir_all(&fdir);
        }
        git::copy_dir_filtered(cand_snap, &fdir)?;
        std::fs::write(fdir.join(&sf.rel_file), &sf.mutated_source)
            .map_err(|e| format!("write fault {}: {e}", sf.rel_file))?;
        let driver = build_driver(
            &fdir,
            explicit_driver,
            ratchet_driver,
            commands,
            changed,
            priority_files,
            timeout,
            probe_timeout,
        )?;
        planted.push(PlantedFault {
            id: sf.id.clone(),
            description: sf.description.clone(),
            driver,
        });
        fault_dirs.push(fdir);
    }

    let report = prove_oracle(cand_drv, oracle_reqs, masks, planted, 24, constants);
    for d in fault_dirs {
        let _ = std::fs::remove_dir_all(d);
    }
    report
}

fn overlay_base_metric_files(
    base_snap: &Path,
    cand_snap: &Path,
    metric_argv: &[String],
    explicit_metric_file: Option<&str>,
) -> Result<BTreeSet<String>, String> {
    let mut targets = BTreeSet::new();
    if let Some(f) = explicit_metric_file {
        targets.insert(f.to_owned());
    }
    for tok in metric_argv {
        if !tok.starts_with('-') && base_snap.join(tok).is_file() {
            targets.insert(tok.clone());
        }
    }
    for rel in &targets {
        let src = base_snap.join(rel);
        let dst = cand_snap.join(rel);
        if src.is_file() {
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::copy(&src, &dst)
                .map_err(|e| format!("overlay base metric file {rel}: {e}"))?;
        }
    }
    Ok(targets)
}

fn enforce_driver_policy(
    mode: EnforceMode,
    explicit_driver: Option<&str>,
    cli_commands: &[String],
) -> Result<(), String> {
    if mode == EnforceMode::Enforce {
        if explicit_driver.is_some() {
            return Err(
                "enforced mode forbids --driver on the command line; pin driver in .emi/ratchet.json on base"
                    .to_owned(),
            );
        }
        if !cli_commands.is_empty() {
            return Err(
                "enforced mode forbids --cmd on the command line; pin commands in .emi/ratchet.json on base"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

fn resolve_driver_and_commands<'a>(
    explicit_driver: Option<&'a str>,
    ratchet_driver: Option<&'a str>,
    cli_commands: &[String],
    pinned_commands: &[String],
) -> (Option<&'a str>, Option<&'a str>, Vec<String>, bool) {
    if explicit_driver.is_some() {
        return (explicit_driver, ratchet_driver, Vec::new(), false);
    }
    if !cli_commands.is_empty() {
        return (None, None, cli_commands.to_vec(), true);
    }
    if ratchet_driver.is_some() {
        return (None, ratchet_driver, Vec::new(), false);
    }
    if !pinned_commands.is_empty() {
        return (None, None, pinned_commands.to_vec(), true);
    }
    (None, None, Vec::new(), false)
}

fn sanitize_rel_token(tok: &str) -> Option<String> {
    let trimmed = tok.trim_start_matches("./");
    if trimmed.is_empty() || trimmed.starts_with('/') || trimmed.starts_with('\\') {
        return None;
    }
    for comp in Path::new(trimmed).components() {
        if matches!(
            comp,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        ) {
            return None;
        }
    }
    Some(trimmed.to_owned())
}

fn collect_rel_files(root: &Path, dir: &Path, out: &mut BTreeSet<String>) {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                if let Ok(rel) = p.strip_prefix(root) {
                    out.insert(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
    }
}

fn overlay_base_driver_files(
    base_snap: &Path,
    cand_snap: &Path,
    explicit: Option<&str>,
    ratchet_driver: Option<&str>,
    commands: &[String],
) -> Result<BTreeSet<String>, String> {
    let mut overlaid = BTreeSet::new();
    let mut file_targets = BTreeSet::new();
    let mut dir_targets = BTreeSet::new();
    let mut remove_untrusted = BTreeSet::new();

    // For --cmd / pinned commands, only overlay harness scripts under `.emi/` so
    // candidate program source files (e.g. `python3 app.py`) are not overwritten.
    let single_drv = explicit.or(ratchet_driver);
    let only_emi = single_drv.is_none();
    let cmd_iter: Vec<&str> = match single_drv {
        Some(c) => vec![c],
        None => commands.iter().map(String::as_str).collect(),
    };
    for cmd in cmd_iter {
        for tok in split_command(cmd) {
            if tok.starts_with('-') {
                continue;
            }
            let Some(rel) = sanitize_rel_token(&tok) else {
                continue;
            };
            if only_emi && !rel.starts_with(".emi/") {
                continue;
            }
            let bpath = base_snap.join(&rel);
            let cpath = cand_snap.join(&rel);
            if bpath.is_file() {
                if !only_emi && rel.ends_with("/Cargo.toml") {
                    if let Some(parent) = Path::new(&rel).parent() {
                        let prel = parent.to_string_lossy().replace('\\', "/");
                        if !prel.is_empty() && base_snap.join(&prel).is_dir() {
                            dir_targets.insert(prel);
                            continue;
                        }
                    }
                }
                file_targets.insert(rel);
            } else if bpath.is_dir() {
                dir_targets.insert(rel);
            } else if cpath.exists() {
                remove_untrusted.insert(rel);
            }
        }
    }

    for rel in &remove_untrusted {
        let cpath = cand_snap.join(rel);
        if cpath.is_dir() {
            let _ = std::fs::remove_dir_all(&cpath);
        } else if cpath.is_file() {
            let _ = std::fs::remove_file(&cpath);
        }
        overlaid.insert(rel.clone());
    }

    for rel in &dir_targets {
        let src = base_snap.join(rel);
        let dst = cand_snap.join(rel);
        if dst.exists() {
            let _ = std::fs::remove_dir_all(&dst);
        }
        git::copy_dir_filtered(&src, &dst)?;
        collect_rel_files(base_snap, &src, &mut overlaid);
    }

    for rel in &file_targets {
        let src = base_snap.join(rel);
        let dst = cand_snap.join(rel);
        if src.is_file() {
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::copy(&src, &dst)
                .map_err(|e| format!("overlay base driver file {rel}: {e}"))?;
            overlaid.insert(rel.clone());
        }
    }

    Ok(overlaid)
}

fn build_driver(
    dir: &Path,
    explicit: Option<&str>,
    ratchet_driver: Option<&str>,
    commands: &[String],
    changed: &[String],
    priority_files: &[String],
    timeout: Duration,
    probe_timeout: Duration,
) -> Result<Box<dyn Driver>, String> {
    if !commands.is_empty() && explicit.or(ratchet_driver).is_none() {
        return Ok(Box::new(CommandDriver::new(
            dir.to_path_buf(),
            commands.to_vec(),
            timeout,
        )));
    }
    let argv = match explicit.or(ratchet_driver) {
        Some(cmd) => {
            let v = split_command(cmd);
            if v.is_empty() {
                return Err("empty driver command".to_owned());
            }
            v
        }
        None => materialize_auto_driver_for_changes(dir, changed)?,
    };
    let mut drv = ProcessDriver::with_timeouts(dir.to_path_buf(), argv, timeout, probe_timeout);
    drv.set_priority_files(priority_files.to_vec());
    Ok(Box::new(drv))
}

fn build_driver_pair(
    base_snap: &Path,
    cand_snap: &Path,
    explicit: Option<&str>,
    ratchet_driver: Option<&str>,
    commands: &[String],
    changed: &[String],
    priority_files: &[String],
    timeout: Duration,
    probe_timeout: Duration,
) -> Result<(Box<dyn Driver>, Box<dyn Driver>), String> {
    let base_drv = build_driver(
        base_snap,
        explicit,
        ratchet_driver,
        commands,
        changed,
        priority_files,
        timeout,
        probe_timeout,
    )?;
    let cand_drv = build_driver(
        cand_snap,
        explicit,
        ratchet_driver,
        commands,
        changed,
        priority_files,
        timeout,
        probe_timeout,
    )?;
    Ok((base_drv, cand_drv))
}

fn cmd_driver(args: &[String]) -> Result<u8, String> {
    let sub = args.first().map(String::as_str).unwrap_or("init");
    if sub != "init" {
        return Err(format!("unknown driver subcommand `{sub}` (expected: init)"));
    }
    let repo = repo_arg(args);
    let lang = match flag_val(args, "--lang") {
        Some(raw) => Some(DriverLang::parse(&raw)?),
        None => None,
    };
    let out_override = flag_val(args, "--out");
    let force = has_flag(args, "--force");
    let pin = has_flag(args, "--pin");
    let as_json = has_flag(args, "--json");

    let res = driver_init::init_driver(&repo, lang, out_override.as_deref(), force, pin)?;
    if as_json {
        println!("{}", res.to_json().pretty());
    } else {
        println!(
            "DRIVER INIT  lang={}  pinned={}  command={}",
            res.lang.as_str(),
            res.pinned,
            res.command
        );
        for f in &res.files {
            println!("  created: {f}");
        }
        println!("  commit driver files and .emi/ratchet.json on your base branch so emi overlays the trusted base driver");
    }
    Ok(0)
}

fn detect_repo_verify_command(root: &Path) -> Option<String> {
    let pkg_path = root.join("package.json");
    if pkg_path.is_file() {
        if let Ok(raw) = std::fs::read_to_string(&pkg_path) {
            if let Ok(val) = json::parse(&raw) {
                if let Some(test_cmd) = val
                    .get("scripts")
                    .and_then(|s| s.get("test"))
                    .and_then(Value::as_str)
                {
                    let trimmed = test_cmd.trim();
                    if !trimmed.is_empty() && !trimmed.contains("no test specified") {
                        if root.join("pnpm-lock.yaml").is_file() {
                            return Some("pnpm test".to_owned());
                        }
                        if root.join("yarn.lock").is_file() {
                            return Some("yarn test".to_owned());
                        }
                        return Some("npm test --silent".to_owned());
                    }
                }
            }
        }
    }
    if root.join("Cargo.toml").is_file() {
        return Some("cargo test --quiet".to_owned());
    }
    if root.join("go.mod").is_file() {
        return Some("go test ./...".to_owned());
    }
    if root.join("pyproject.toml").is_file()
        || root.join("pytest.ini").is_file()
        || root.join("tests").is_dir()
    {
        if std::process::Command::new("pytest")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
        {
            return Some("pytest -q".to_owned());
        }
    }
    None
}

fn cmd_check(args: &[String]) -> Result<u8, String> {
    run_diff_or_check(args, true, false)
}

fn cmd_diff(args: &[String]) -> Result<u8, String> {
    run_diff_or_check(args, false, false)
}

fn run_diff_or_check(args: &[String], full_check: bool, smart_mode: bool) -> Result<u8, String> {
    let started = Instant::now();
    let repo = repo_arg(args);
    let resolved_base = resolve_base_with_fallback(&repo, args, smart_mode)?;
    let base_rev = resolved_base.rev.clone();
    let base_sha = git::rev_parse(&repo, &base_rev)?;
    let cand_rev = flag_val(args, "--cand");
    let explicit_driver = flag_val(args, "--driver");
    let cli_commands = flag_vals(args, "--cmd");
    let report_diff = has_flag(args, "--report-diff");
    let seeds = flag_val(args, "--seeds")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(48);
    let base_seed = base_seed_arg(args)?;
    let no_strict = has_flag(args, "--no-strict");
    let explicit_parity = has_flag(args, "--parity");
    let no_cov = has_flag(args, "--no-cov");
    let require_cov = has_flag(args, "--require-cov");
    let with_adversary_flag = has_flag(args, "--with-adversary");
    let no_adversary_flag = has_flag(args, "--no-adversary");
    let forbid_nondet_flag = has_flag(args, "--forbid-nondet");
    let max_faults = flag_val(args, "--max-faults")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(8);
    let require_mut_flag = has_flag(args, "--require-mutations");
    let cli_obs_files = flag_vals(args, "--observe-file");
    let cli_req_obs = flag_vals(args, "--require-observation");
    let cli_req_wf = flag_vals(args, "--require-workflow");
    let evidence_out = flag_val(args, "--evidence-out");
    let no_evidence = has_flag(args, "--no-evidence");
    let no_history = has_flag(args, "--no-history");
    let signing_key = signing_key_from_env_or_args(args)?;
    let timeout = timeout_arg(args);
    let probe_timeout = probe_timeout_arg(args);
    let as_json = has_flag(args, "--json");

    let pinned = load_pinned(&repo, &base_rev)?;
    enforce_base_policy(&repo, pinned.mode, &resolved_base)?;
    enforce_driver_policy(pinned.mode, explicit_driver.as_deref(), &cli_commands)?;

    let (eff_explicit_driver, eff_ratchet_driver, eff_commands, mut command_mode) =
        resolve_driver_and_commands(
            explicit_driver.as_deref(),
            pinned.driver.as_deref(),
            &cli_commands,
            &pinned.commands,
        );

    let min_cov_ratio = flag_val(args, "--min-cov-ratio")
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(pinned.min_changed_cov_ratio)
        .clamp(0.0, 1.0);

    let changed = git::changed_files(&repo, &base_rev, cand_rev.as_deref())?;
    let diff_hunks = git::diff_hunks(&repo, &base_rev, cand_rev.as_deref())?;
    let raw_changed_lines = git::changed_lines_from_hunks(&repo, cand_rev.as_deref(), &diff_hunks)?;
    let base_snap = git::materialize_revision(&repo, &base_rev, "diff_base")?;
    let cand_snap = match cand_rev.as_deref() {
        Some(rev) => git::materialize_revision(&repo, rev, "diff_cand")?,
        None => git::materialize_worktree(&repo, "diff_cand")?,
    };
    let cand_tree_sha = git::tree_hash(&cand_snap)?;
    let overlaid_drivers = overlay_base_driver_files(
        &base_snap,
        &cand_snap,
        eff_explicit_driver,
        eff_ratchet_driver,
        &eff_commands,
    )?;
    let mut exec_changed_lines =
        git::filter_executable_changed_lines(&cand_snap, &raw_changed_lines);
    let mut exec_deleted_lines =
        git::deleted_executable_lines(&base_snap, &diff_hunks, &exec_changed_lines);
    for dfile in &overlaid_drivers {
        exec_changed_lines.remove(dfile);
        exec_deleted_lines.remove(dfile);
    }

    let base_sk = skeleton::extract_dir(&base_snap)?;
    let cand_sk = skeleton::extract_dir(&cand_snap)?;
    if let Some(expected_sk) = &pinned.skeleton_digest {
        if base_sk.digest != *expected_sk {
            let _ = std::fs::remove_dir_all(&base_snap);
            let _ = std::fs::remove_dir_all(&cand_snap);
            return Err(format!(
                "pinned skeleton_digest mismatch on base: expected {}, got {}",
                safe_prefix(expected_sk, 16),
                safe_prefix(&base_sk.digest, 16)
            ));
        }
    }
    let forbid_nondet = forbid_nondet_flag || (full_check && pinned.mode == EnforceMode::Enforce);
    let sk_diff = skeleton::compare(&base_sk, &cand_sk, forbid_nondet);

    let policy_digest = pinned.policy_digest();
    let driver_digest = compute_driver_digest_full(
        &base_snap,
        eff_explicit_driver,
        eff_ratchet_driver,
        &eff_commands,
        &changed,
    );
    let observed_files = merge_unique(&pinned.observed_files, &cli_obs_files);
    let required_observations = merge_unique(&pinned.required_observations, &cli_req_obs);
    let required_workflows = merge_unique(&pinned.required_workflows, &cli_req_wf);
    let require_mutations = require_mut_flag || pinned.require_mutations;

    let pool = build_constant_pool(
        &base_snap,
        &cand_snap,
        &changed,
        &raw_changed_lines,
        &exec_deleted_lines,
        &pinned.approval_rules,
    );
    let priority_files = compute_priority_files(&base_snap, &cand_snap, &changed);
    let (mut base_drv, mut cand_drv) = build_driver_pair(
        &base_snap,
        &cand_snap,
        eff_explicit_driver,
        eff_ratchet_driver,
        &eff_commands,
        &changed,
        &priority_files,
        timeout,
        probe_timeout,
    )?;

    // Smart mode fast path: if the previous run failed on an unapproved witness for the same
    // base/policy, replay that witness first (~100ms). If it still fails, return immediately.
    if smart_mode && !report_diff && !has_flag(args, "--fresh") {
        let prev_ev_path = repo.join(ratchet::EVIDENCE_PATH);
        if let Ok(prev_ev) = load_evidence(&prev_ev_path) {
            if prev_ev.verdict == "parity_fail"
                && prev_ev.base_sha == base_sha
                && prev_ev.policy_digest == policy_digest
                && prev_ev.command_mode == command_mode
            {
                let unapproved: Vec<diff::Divergence> = prev_ev
                    .witnesses
                    .into_iter()
                    .filter(|w| !w.approved)
                    .collect();
                if !unapproved.is_empty() {
                    let replay_obs = merge_unique(&observed_files, &prev_ev.observed_files);
                    let rep = replay_witnesses(
                        &mut *base_drv,
                        &mut *cand_drv,
                        &unapproved,
                        &pinned.masks,
                        &pinned.approved_diffs,
                        &pinned.approval_rules,
                        &replay_obs,
                    );
                    if rep.verdict == Verdict::ParityFail {
                        let _ = std::fs::remove_dir_all(&base_snap);
                        let _ = std::fs::remove_dir_all(&cand_snap);
                        if !no_history && !no_evidence {
                            let _ = append_history(
                                &repo,
                                &HistoryEntry {
                                    ts_unix: now_unix_secs(),
                                    command: "replay".to_owned(),
                                    verdict: rep.verdict.as_str().to_owned(),
                                    blocker: rep.blocker.clone(),
                                    exit_code: rep.verdict.exit_code(),
                                    duration_ms: started.elapsed().as_millis() as u64,
                                    base_sha,
                                    candidate_tree_sha256: cand_tree_sha,
                                    command_mode,
                                    report_diff: false,
                                    changed_lines_covered: 0,
                                    changed_lines_total: 0,
                                    unapproved_diffs: rep.unapproved_count(),
                                    ops_exercised: rep.ops_exercised.len(),
                                },
                            );
                        }
                        if as_json {
                            let mut obj = rep.to_json().into_object().unwrap();
                            obj.insert("fast_replay".to_owned(), Value::Bool(true));
                            obj.insert("replayed".to_owned(), Value::Int(unapproved.len() as i64));
                            println!("{}", Value::Object(obj).pretty());
                        } else {
                            println!(
                                "FAST REPLAY  verdict={}  replayed={}  remaining_unapproved={}  ({}ms)",
                                rep.verdict.as_str(),
                                unapproved.len(),
                                rep.unapproved_count(),
                                started.elapsed().as_millis()
                            );
                            for d in &rep.divergences {
                                println!("  [DIFF {} | UNAPPROVED] ops={}", d.id, d.ops.len());
                                for op in &d.ops {
                                    println!("    call: {}", op.to_json().canonical());
                                }
                                println!("    base:      {}", d.base_payload);
                                println!("    candidate: {}", d.cand_payload);
                            }
                        }
                        return Ok(rep.verdict.exit_code());
                    }
                }
            }
        }
    }

    let strict_active = !no_strict && pinned.mode != EnforceMode::Off;
    let parity_active = full_check || explicit_parity || pinned.mode == EnforceMode::Enforce;
    let cov_active = !command_mode && !no_cov && (require_cov || strict_active);

    let cfg = DiffConfig {
        seeds,
        base_seed,
        parity: parity_active,
        strict: strict_active,
        command_mode,
        report_diff,
        masks: pinned.masks.clone(),
        approved_diffs: pinned.approved_diffs.clone(),
        approval_rules: pinned.approval_rules.clone(),
        pinned_requests: pinned.triggered_requests(&changed, &required_workflows),
        observed_files: observed_files.clone(),
        required_observations,
        required_workflows,
        constants: pool.clone(),
        changed_lines: flatten_changed_lines(&exec_changed_lines),
        deleted_base_lines: flatten_changed_lines(&exec_deleted_lines),
        priority_files: priority_files.clone(),
        require_changed_coverage: cov_active,
        min_changed_cov_ratio: min_cov_ratio,
        ..DiffConfig::default()
    };

    let mut report = run_diff(&mut *base_drv, &mut *cand_drv, &cfg);

    // Smart mode auto-fallback: if auto-driving couldn't probe or cover changed lines
    // (e.g. React/UI, Rust, Go, or framework-coupled code), fall back to the repo's own
    // test command on base vs candidate.
    if smart_mode
        && !command_mode
        && eff_explicit_driver.is_none()
        && eff_ratchet_driver.is_none()
        && matches!(report.verdict, Verdict::ProbeFailed | Verdict::Inconclusive)
    {
        if let Some(auto_cmd) = detect_repo_verify_command(&base_snap) {
            let fb_timeout = if has_flag(args, "--timeout-ms") {
                timeout
            } else {
                Duration::from_secs(60)
            };
            let mut fb_base = CommandDriver::new(
                base_snap.clone(),
                vec![auto_cmd.clone()],
                fb_timeout,
            );
            let mut fb_cand = CommandDriver::new(
                cand_snap.clone(),
                vec![auto_cmd.clone()],
                fb_timeout,
            );
            let fb_cfg = DiffConfig {
                command_mode: true,
                require_changed_coverage: false,
                ..cfg.clone()
            };
            let mut fb_report = run_diff(&mut fb_base, &mut fb_cand, &fb_cfg);
            if matches!(
                fb_report.verdict,
                Verdict::Pass | Verdict::ParityFail | Verdict::BehaviorChanged
            ) {
                fb_report.detail = format!("{} (auto-cmd: {auto_cmd})", fb_report.detail);
                report = fb_report;
                command_mode = true;
            }
        }
    }

    let run_adv = !no_adversary_flag
        && (with_adversary_flag
            || (!report_diff
                && full_check
                && (require_mutations || pinned.mode == EnforceMode::Enforce)));

    let (mutations_run, adv_report_opt) =
        if run_adv && report.aa_verified && report.verdict != Verdict::ProbeFailed {
            let adv = run_ast_adversary(
                &cand_snap,
                &mut *cand_drv,
                &report.executed_requests,
                &exec_changed_lines,
                eff_explicit_driver,
                eff_ratchet_driver,
                &eff_commands,
                &changed,
                &priority_files,
                &pinned.masks,
                max_faults,
                &pool,
                timeout,
                probe_timeout,
            )?;
            (true, Some(adv))
        } else {
            (false, None)
        };

    let (planted_total, planted_killed, planted_survived, planted_unknown) = match &adv_report_opt {
        Some(a) => (
            a.total_faults,
            a.killed_faults,
            a.survived_faults,
            a.unknown_faults,
        ),
        None => (0, 0, 0, 0),
    };

    let _ = std::fs::remove_dir_all(&base_snap);
    let _ = std::fs::remove_dir_all(&cand_snap);

    let mut final_verdict = report.verdict;
    let mut final_blocker = report.blocker.clone();
    let mut final_action = report.next_action.clone();
    let mut final_detail = report.detail.clone();

    if report_diff {
        if !sk_diff.ok && final_verdict == Verdict::Pass {
            final_verdict = Verdict::BehaviorChanged;
            final_blocker = "behavior_changed".to_owned();
            final_action = "review_behavior_diff".to_owned();
            final_detail = format!(
                "API skeleton changed (removed={}, changed={}, new_nondet={}); review changes",
                sk_diff.removed_symbols.len(),
                sk_diff.changed_signatures.len(),
                sk_diff.new_nondet_sites.len()
            );
        } else if planted_survived > 0 {
            final_verdict = Verdict::ParityFail;
            final_blocker = "surviving_mutant".to_owned();
            final_action = "kill_surviving_mutant".to_owned();
            final_detail = format!("{planted_survived} planted AST mutation(s) survived");
        }
    } else if full_check && !sk_diff.ok {
        if !sk_diff.new_nondet_sites.is_empty()
            && sk_diff.removed_symbols.is_empty()
            && sk_diff.changed_signatures.is_empty()
        {
            final_verdict = Verdict::Nondeterministic;
            final_blocker = "nondet_site".to_owned();
            final_action = "remove_nondeterminism".to_owned();
        } else {
            final_verdict = Verdict::SkeletonBreak;
            final_blocker = "skeleton_break".to_owned();
            final_action = "fix_public_api_break".to_owned();
        }
        final_detail = format!(
            "skeleton check failed (removed={}, changed={}, new_nondet={})",
            sk_diff.removed_symbols.len(),
            sk_diff.changed_signatures.len(),
            sk_diff.new_nondet_sites.len()
        );
    } else if planted_survived > 0 {
        final_verdict = Verdict::ParityFail;
        final_blocker = "surviving_mutant".to_owned();
        final_action = "kill_surviving_mutant".to_owned();
        final_detail = format!("{planted_survived} planted AST mutation(s) survived");
    } else if final_verdict == Verdict::Pass {
        if let Some(issue) = mutation_policy_issue(
            require_mutations,
            report.changed_lines_total,
            mutations_run,
            planted_total,
            planted_killed,
            planted_survived,
            planted_unknown,
        ) {
            final_verdict = Verdict::Inconclusive;
            final_blocker = "missing_mutations".to_owned();
            final_action = "run_with_adversary".to_owned();
            final_detail = issue;
        }
    }

    let evidence = EvidenceRecord {
        base_sha,
        candidate_tree_sha256: cand_tree_sha,
        driver_digest,
        policy_digest,
        observed_files: observed_files.clone(),
        observed_files_recorded: true,
        command_mode,
        request_budget: seeds,
        base_seed: Some(base_seed),
        sequences_run: report.sequences_run,
        valid_comparisons: report.valid_comparisons,
        verdict: final_verdict.as_str().to_owned(),
        blocker: final_blocker.clone(),
        next_action: final_action.clone(),
        detail: final_detail.clone(),
        skeleton_ok: sk_diff.ok,
        aa_verified: report.aa_verified,
        masks_proven: report.masks_proven,
        changed_lines_covered: report.changed_lines_covered,
        changed_lines_total: report.changed_lines_total,
        deleted_lines_covered: report.deleted_lines_covered,
        deleted_lines_total: report.deleted_lines_total,
        unapproved_diffs: report.unapproved_count(),
        missing_observations: report.missing_observations.clone(),
        workflows_run: report.workflows_run.clone(),
        ops_exercised: report.ops_exercised.clone(),
        observed_outputs: report.observed_outputs.clone(),
        missing_workflows: report.missing_workflows.clone(),
        mutations_run,
        planted_total,
        planted_killed,
        planted_survived,
        planted_unknown,
        witnesses: report.divergences.clone(),
        record_digest_sha256: None,
        hmac_sha256: None,
    };

    let saved_evidence_path = if let Some(out_path) = evidence_out {
        let p = PathBuf::from(out_path);
        save_evidence_signed(&p, &evidence, signing_key.as_deref())?;
        Some(p)
    } else if !no_evidence && (full_check || repo.join(".emi").is_dir()) {
        let p = repo.join(ratchet::EVIDENCE_PATH);
        save_evidence_signed(&p, &evidence, signing_key.as_deref())?;
        Some(p)
    } else {
        None
    };

    if !no_history && !no_evidence {
        let _ = append_history(
            &repo,
            &HistoryEntry {
                ts_unix: now_unix_secs(),
                command: if full_check { "check" } else { "diff" }.to_owned(),
                verdict: final_verdict.as_str().to_owned(),
                blocker: final_blocker.clone(),
                exit_code: final_verdict.exit_code(),
                duration_ms: started.elapsed().as_millis() as u64,
                base_sha: evidence.base_sha.clone(),
                candidate_tree_sha256: evidence.candidate_tree_sha256.clone(),
                command_mode,
                report_diff,
                changed_lines_covered: evidence.changed_lines_covered,
                changed_lines_total: evidence.changed_lines_total,
                unapproved_diffs: evidence.unapproved_diffs,
                ops_exercised: evidence.ops_exercised.len(),
            },
        );
    }

    if as_json {
        let mut obj = report.to_json().into_object().unwrap();
        obj.insert(
            "verdict".to_owned(),
            Value::Str(final_verdict.as_str().to_owned()),
        );
        obj.insert(
            "exit_code".to_owned(),
            Value::Int(final_verdict.exit_code() as i64),
        );
        obj.insert("blocker".to_owned(), Value::Str(final_blocker.clone()));
        obj.insert("next_action".to_owned(), Value::Str(final_action.clone()));
        obj.insert("detail".to_owned(), Value::Str(final_detail.clone()));
        obj.insert("skeleton_ok".to_owned(), Value::Bool(sk_diff.ok));
        obj.insert("command_mode".to_owned(), Value::Bool(command_mode));
        obj.insert("report_diff".to_owned(), Value::Bool(report_diff));
        if report_diff {
            obj.insert(
                "behavior_changed".to_owned(),
                Value::Bool(final_verdict == Verdict::BehaviorChanged),
            );
            obj.insert("skeleton_diff".to_owned(), sk_diff.to_json());
        }
        obj.insert("request_budget".to_owned(), Value::Int(seeds as i64));
        obj.insert("base_seed".to_owned(), protocol::seed_to_json(base_seed));
        obj.insert(
            "min_changed_cov_ratio".to_owned(),
            Value::Float(min_cov_ratio),
        );
        obj.insert(
            "observed_files".to_owned(),
            Value::str_array(&observed_files),
        );
        obj.insert(
            "candidate_tree_sha256".to_owned(),
            Value::Str(evidence.candidate_tree_sha256.clone()),
        );
        obj.insert(
            "driver_digest".to_owned(),
            Value::Str(evidence.driver_digest.clone()),
        );
        obj.insert(
            "policy_digest".to_owned(),
            Value::Str(evidence.policy_digest.clone()),
        );
        obj.insert("mutations_run".to_owned(), Value::Bool(mutations_run));
        obj.insert("planted_total".to_owned(), Value::Int(planted_total as i64));
        obj.insert(
            "planted_killed".to_owned(),
            Value::Int(planted_killed as i64),
        );
        obj.insert(
            "planted_survived".to_owned(),
            Value::Int(planted_survived as i64),
        );
        obj.insert(
            "planted_unknown".to_owned(),
            Value::Int(planted_unknown as i64),
        );
        if let Some(ref ev_p) = saved_evidence_path {
            obj.insert(
                "evidence_path".to_owned(),
                Value::Str(ev_p.to_string_lossy().into_owned()),
            );
            if report.unapproved_count() > 0 {
                obj.insert(
                    "replay_cmd".to_owned(),
                    Value::Str(format!(
                        "emi replay --repo {} --base {} --evidence {}",
                        repo.display(),
                        base_rev,
                        ev_p.display()
                    )),
                );
            }
        }
        if let Some(ref adv) = adv_report_opt {
            let surviving: Vec<Value> = adv
                .outcomes
                .iter()
                .filter(|o| o.status == adversary::FaultStatus::Survived)
                .map(adversary::FaultOutcome::to_json)
                .collect();
            obj.insert("surviving_mutants".to_owned(), Value::Array(surviving));
        }
        println!("{}", Value::Object(obj).pretty());
    } else {
        let banner = if report_diff {
            "BEHAVIOR DIFF SUMMARY"
        } else if full_check {
            "CHECK"
        } else {
            "BEHAVIORAL DIFF"
        };
        println!(
            "{banner}  verdict={}  blocker={}  next_action={}  skeleton={}  aa={}  seqs={}  valid={}  changed_cov={}/{}  unapproved={}  workflows={}  outputs={}  mutations={}/{}(surv={},unk={})",
            final_verdict.as_str(),
            final_blocker,
            final_action,
            sk_diff.ok,
            report.aa_verified,
            report.sequences_run,
            report.valid_comparisons,
            report.changed_lines_covered,
            report.changed_lines_total,
            report.unapproved_count(),
            report.workflows_run.len(),
            report.observed_outputs.join(","),
            planted_killed,
            planted_total,
            planted_survived,
            planted_unknown
        );
        if report_diff && !sk_diff.ok {
            for r in &sk_diff.removed_symbols {
                println!("  [API REMOVED] {r}");
            }
            for c in &sk_diff.changed_signatures {
                println!("  [API CHANGED] {c}");
            }
        }
        for d in &report.divergences {
            let tag = match &d.approved_by {
                Some(by) => format!("APPROVED:{by}"),
                None => match &d.rule_violation {
                    Some(rv) => format!("RULE_VIOLATION:{rv}"),
                    None => {
                        if report_diff {
                            "CHANGED".to_owned()
                        } else {
                            "UNAPPROVED".to_owned()
                        }
                    }
                },
            };
            println!("  [DIFF {} | {}] ops={}", d.id, tag, d.ops.len());
            for op in &d.ops {
                println!("    call: {}", op.to_json().canonical());
            }
            println!("    base:      {}", d.base_payload);
            println!("    candidate: {}", d.cand_payload);
        }
        if report.divergences.is_empty()
            || (final_verdict != Verdict::ParityFail && final_verdict != Verdict::BehaviorChanged)
        {
            println!("  {final_detail}");
        }
    }

    Ok(final_verdict.exit_code())
}

fn witness_file_observations(witnesses: &[diff::Divergence]) -> BTreeSet<String> {
    let mut files = BTreeSet::new();
    for w in witnesses {
        for payload in [&w.base_payload, &w.cand_payload] {
            let mut rest = payload.as_str();
            while let Some(pos) = rest.find("\"file:") {
                let after = &rest[pos + 6..];
                if let Some(end) = after.find('"') {
                    let path = &after[..end];
                    if !path.is_empty() {
                        files.insert(path.to_owned());
                    }
                    rest = &after[end + 1..];
                } else {
                    break;
                }
            }
        }
    }
    files
}

fn cmd_replay(args: &[String]) -> Result<u8, String> {
    let started = Instant::now();
    let repo = repo_arg(args);
    let (base_rev, _) = resolve_base(&repo, args)?;
    let base_sha = git::rev_parse(&repo, &base_rev).unwrap_or_default();
    let explicit_driver = flag_val(args, "--driver");
    let cli_commands = flag_vals(args, "--cmd");
    let cli_obs_files = flag_vals(args, "--observe-file");
    let ev_path = flag_val(args, "--evidence")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo.join(ratchet::EVIDENCE_PATH));
    let filter_id = flag_val(args, "--id");
    let timeout = timeout_arg(args);
    let probe_timeout = probe_timeout_arg(args);
    let no_history = has_flag(args, "--no-history");
    let as_json = has_flag(args, "--json");

    let pinned = load_pinned(&repo, &base_rev)?;
    let evidence = load_evidence(&ev_path)?;
    let selected: Vec<diff::Divergence> = evidence
        .witnesses
        .iter()
        .filter(|w| match &filter_id {
            Some(id) => w.id == *id,
            None => !w.approved,
        })
        .cloned()
        .collect();

    if selected.is_empty() {
        if as_json {
            println!(
                "{}",
                Value::obj(vec![
                    ("verdict", Value::Str("pass".to_owned())),
                    ("replayed", Value::Int(0)),
                    ("remaining_unapproved", Value::Int(0)),
                    (
                        "detail",
                        Value::Str("no unapproved witnesses to replay".to_owned()),
                    ),
                ])
                .pretty()
            );
        } else {
            println!("REPLAY  verdict=pass  replayed=0  remaining=0");
        }
        return Ok(0);
    }

    let mut effective_obs = merge_unique(&pinned.observed_files, &evidence.observed_files);
    effective_obs = merge_unique(&effective_obs, &cli_obs_files);

    if !evidence.observed_files_recorded {
        let needed_files = witness_file_observations(&selected);
        let missing: Vec<String> = needed_files
            .into_iter()
            .filter(|f| !effective_obs.contains(f))
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "cannot repeat original check: legacy evidence {} did not record observed_files (witness depends on {}); pass --observe-file or rerun emi check",
                ev_path.display(),
                missing.join(", ")
            ));
        }
    }

    enforce_driver_policy(pinned.mode, explicit_driver.as_deref(), &cli_commands)?;
    let (eff_explicit_driver, eff_ratchet_driver, eff_commands, command_mode) =
        resolve_driver_and_commands(
            explicit_driver.as_deref(),
            pinned.driver.as_deref(),
            &cli_commands,
            &pinned.commands,
        );
    let changed = git::changed_files(&repo, &base_rev, None).unwrap_or_default();
    let base_snap = git::materialize_revision(&repo, &base_rev, "replay_base")?;
    let cand_snap = git::materialize_worktree(&repo, "replay_cand")?;
    let cand_tree_sha = git::tree_hash(&cand_snap).unwrap_or_default();
    let _ = overlay_base_driver_files(
        &base_snap,
        &cand_snap,
        eff_explicit_driver,
        eff_ratchet_driver,
        &eff_commands,
    )?;
    let priority_files = compute_priority_files(&base_snap, &cand_snap, &changed);
    let (mut b_drv, mut c_drv) = build_driver_pair(
        &base_snap,
        &cand_snap,
        eff_explicit_driver,
        eff_ratchet_driver,
        &eff_commands,
        &changed,
        &priority_files,
        timeout,
        probe_timeout,
    )?;

    let report = replay_witnesses(
        &mut *b_drv,
        &mut *c_drv,
        &selected,
        &pinned.masks,
        &pinned.approved_diffs,
        &pinned.approval_rules,
        &effective_obs,
    );

    let _ = std::fs::remove_dir_all(&base_snap);
    let _ = std::fs::remove_dir_all(&cand_snap);

    if !no_history {
        let _ = append_history(
            &repo,
            &HistoryEntry {
                ts_unix: now_unix_secs(),
                command: "replay".to_owned(),
                verdict: report.verdict.as_str().to_owned(),
                blocker: report.blocker.clone(),
                exit_code: report.verdict.exit_code(),
                duration_ms: started.elapsed().as_millis() as u64,
                base_sha,
                candidate_tree_sha256: cand_tree_sha,
                command_mode,
                report_diff: false,
                changed_lines_covered: 0,
                changed_lines_total: 0,
                unapproved_diffs: report.unapproved_count(),
                ops_exercised: report.ops_exercised.len(),
            },
        );
    }

    if as_json {
        let mut obj = report.to_json().into_object().unwrap();
        obj.insert("replayed".to_owned(), Value::Int(selected.len() as i64));
        obj.insert(
            "observed_files".to_owned(),
            Value::str_array(&effective_obs),
        );
        println!("{}", Value::Object(obj).pretty());
    } else {
        println!(
            "REPLAY  verdict={}  replayed={}  remaining_unapproved={}  detail={}",
            report.verdict.as_str(),
            selected.len(),
            report.unapproved_count(),
            report.detail
        );
    }
    Ok(report.verdict.exit_code())
}

fn safe_prefix(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

fn cmd_skeleton(args: &[String]) -> Result<u8, String> {
    let sub = args.first().map(String::as_str).unwrap_or("extract");
    let repo = repo_arg(args);
    let as_json = has_flag(args, "--json");
    match sub {
        "extract" => {
            let sk = skeleton::extract_dir(&repo)?;
            if as_json {
                println!("{}", sk.to_json().pretty());
            } else {
                println!(
                    "SKELETON  symbols={}  nondet_sites={}  erosion={}  digest={}",
                    sk.symbols.len(),
                    sk.nondet_sites.len(),
                    sk.erosion_score,
                    safe_prefix(&sk.digest, 16)
                );
                for s in &sk.symbols {
                    println!(
                        "  [{}] {}::{}  (cx={})",
                        s.kind, s.file, s.signature, s.complexity
                    );
                }
                for n in &sk.nondet_sites {
                    println!("  [NONDET] {}:{}  {}", n.file, n.line, n.token);
                }
            }
            Ok(0)
        }
        "check" => {
            let (base_rev, _protected) = resolve_base(&repo, args)?;
            let forbid_nondet = has_flag(args, "--forbid-nondet");
            let base_snap = git::materialize_revision(&repo, &base_rev, "skel_base")?;
            let base_sk = skeleton::extract_dir(&base_snap)?;
            let cand_sk = skeleton::extract_dir(&repo)?;
            let _ = std::fs::remove_dir_all(&base_snap);
            let diff = skeleton::compare(&base_sk, &cand_sk, forbid_nondet);
            if as_json {
                println!("{}", diff.to_json().pretty());
            } else {
                println!(
                    "SKELETON CHECK  ok={}  removed={}  changed={}  new_nondet={}  erosion_delta={:+}",
                    diff.ok,
                    diff.removed_symbols.len(),
                    diff.changed_signatures.len(),
                    diff.new_nondet_sites.len(),
                    diff.erosion_delta
                );
                for r in &diff.removed_symbols {
                    println!("  [REMOVED] {r}");
                }
                for c in &diff.changed_signatures {
                    println!("  [CHANGED] {c}");
                }
                for n in &diff.new_nondet_sites {
                    println!("  [NEW_NONDET] {}:{}  {}", n.file, n.line, n.token);
                }
            }
            Ok(if diff.ok { 0 } else { 3 })
        }
        other => Err(format!("unknown skeleton subcommand `{other}`")),
    }
}

fn cmd_adversary(args: &[String]) -> Result<u8, String> {
    let repo = repo_arg(args);
    let (base_rev, _protected) = resolve_base(&repo, args)?;
    let base_sha = git::rev_parse(&repo, &base_rev)?;
    let cand_rev = flag_val(args, "--cand");
    let explicit_driver = flag_val(args, "--driver");
    let cli_commands = flag_vals(args, "--cmd");
    let seeds = flag_val(args, "--seeds")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(32);
    let max_faults = flag_val(args, "--max-faults")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(8);
    let require_mut_flag = has_flag(args, "--require-mutations");
    let cli_obs_files = flag_vals(args, "--observe-file");
    let evidence_path = flag_val(args, "--evidence");
    let signing_key = signing_key_from_env_or_args(args)?;
    let timeout = timeout_arg(args);
    let probe_timeout = probe_timeout_arg(args);
    let as_json = has_flag(args, "--json");

    let pinned = load_pinned(&repo, &base_rev)?;
    enforce_driver_policy(pinned.mode, explicit_driver.as_deref(), &cli_commands)?;
    let (eff_explicit_driver, eff_ratchet_driver, eff_commands, command_mode) =
        resolve_driver_and_commands(
            explicit_driver.as_deref(),
            pinned.driver.as_deref(),
            &cli_commands,
            &pinned.commands,
        );
    let changed = git::changed_files(&repo, &base_rev, cand_rev.as_deref())?;
    let raw_changed_lines = git::changed_lines(&repo, &base_rev, cand_rev.as_deref())?;
    let base_snap = git::materialize_revision(&repo, &base_rev, "adv_base")?;
    let cand_snap = match cand_rev.as_deref() {
        Some(rev) => git::materialize_revision(&repo, rev, "adv_cand")?,
        None => git::materialize_worktree(&repo, "adv_cand")?,
    };
    let cand_tree_sha = git::tree_hash(&cand_snap)?;
    let overlaid_drivers = overlay_base_driver_files(
        &base_snap,
        &cand_snap,
        eff_explicit_driver,
        eff_ratchet_driver,
        &eff_commands,
    )?;
    let mut exec_changed_lines =
        git::filter_executable_changed_lines(&cand_snap, &raw_changed_lines);
    for dfile in &overlaid_drivers {
        exec_changed_lines.remove(dfile);
    }
    let policy_digest = pinned.policy_digest();
    let driver_digest = compute_driver_digest_full(
        &base_snap,
        eff_explicit_driver,
        eff_ratchet_driver,
        &eff_commands,
        &changed,
    );
    let observed_files = merge_unique(&pinned.observed_files, &cli_obs_files);
    let require_mutations = require_mut_flag || pinned.require_mutations;

    let pool = build_constant_pool(
        &base_snap,
        &cand_snap,
        &changed,
        &raw_changed_lines,
        &BTreeMap::new(),
        &pinned.approval_rules,
    );
    let priority_files = compute_priority_files(&base_snap, &cand_snap, &changed);
    let (mut base_drv, mut cand_drv) = build_driver_pair(
        &base_snap,
        &cand_snap,
        eff_explicit_driver,
        eff_ratchet_driver,
        &eff_commands,
        &changed,
        &priority_files,
        timeout,
        probe_timeout,
    )?;

    let diff_cfg = DiffConfig {
        seeds,
        parity: false,
        command_mode,
        masks: pinned.masks.clone(),
        pinned_requests: pinned.triggered_requests(&changed, &[]),
        observed_files,
        constants: pool.clone(),
        changed_lines: flatten_changed_lines(&exec_changed_lines),
        priority_files: priority_files.clone(),
        ..DiffConfig::default()
    };
    let diff_rep = run_diff(&mut *base_drv, &mut *cand_drv, &diff_cfg);
    if !diff_rep.aa_verified {
        let _ = std::fs::remove_dir_all(&base_snap);
        let _ = std::fs::remove_dir_all(&cand_snap);
        return Err(format!("cannot prove oracle: {}", diff_rep.detail));
    }

    let adv_report = run_ast_adversary(
        &cand_snap,
        &mut *cand_drv,
        &diff_rep.executed_requests,
        &exec_changed_lines,
        eff_explicit_driver,
        eff_ratchet_driver,
        &eff_commands,
        &changed,
        &priority_files,
        &pinned.masks,
        max_faults,
        &pool,
        timeout,
        probe_timeout,
    )?;

    let _ = std::fs::remove_dir_all(&base_snap);
    let _ = std::fs::remove_dir_all(&cand_snap);

    let exec_total = flatten_changed_lines(&exec_changed_lines).len();
    let mut_issue = mutation_policy_issue(
        require_mutations,
        exec_total,
        true,
        adv_report.total_faults,
        adv_report.killed_faults,
        adv_report.survived_faults,
        adv_report.unknown_faults,
    );

    if let Some(ev_path) = evidence_path {
        let mut ev = load_evidence(Path::new(&ev_path))?;
        ev.verify_binding(&base_sha, &cand_tree_sha, &driver_digest, &policy_digest)?;
        ev.verify_integrity(
            signing_key.as_deref(),
            pinned.min_changed_cov_ratio,
            false,
            &pinned.required_workflows,
        )?;
        ev.mutations_run = true;
        ev.planted_total = adv_report.total_faults;
        ev.planted_killed = adv_report.killed_faults;
        ev.planted_survived = adv_report.survived_faults;
        ev.planted_unknown = adv_report.unknown_faults;
        let cov_ok = ev.command_mode
            || ev.changed_lines_total == 0
            || (ev.changed_lines_covered as f64 / ev.changed_lines_total as f64) + 1e-9
                >= pinned.min_changed_cov_ratio;
        let deleted_ok = ev.command_mode
            || ev.deleted_lines_total == 0
            || ev.deleted_lines_covered >= ev.deleted_lines_total;
        if adv_report.survived_faults > 0 {
            ev.verdict = Verdict::ParityFail.as_str().to_owned();
            ev.blocker = "surviving_mutant".to_owned();
            ev.next_action = "kill_surviving_mutant".to_owned();
            ev.detail = format!(
                "{} planted AST mutation(s) survived",
                adv_report.survived_faults
            );
        } else if ev.verdict == Verdict::Inconclusive.as_str()
            && ev.skeleton_ok
            && ev.unapproved_diffs == 0
            && ev.missing_observations.is_empty()
            && ev.missing_workflows.is_empty()
            && ev.valid_comparisons > 0
            && cov_ok
            && deleted_ok
            && mut_issue.is_none()
        {
            ev.verdict = Verdict::Pass.as_str().to_owned();
            ev.blocker = "none".to_owned();
            ev.next_action = "ready_to_stamp".to_owned();
            ev.detail = "parity and mutation evidence verified".to_owned();
        } else if let Some(issue) = &mut_issue {
            if ev.verdict == Verdict::Pass.as_str() {
                ev.verdict = Verdict::Inconclusive.as_str().to_owned();
                ev.blocker = "missing_mutations".to_owned();
                ev.next_action = "run_with_adversary".to_owned();
                ev.detail = issue.clone();
            }
        }
        save_evidence_signed(Path::new(&ev_path), &ev, signing_key.as_deref())?;
    }

    if as_json {
        let mut obj = adv_report.to_json().into_object().unwrap();
        obj.insert("inconclusive".to_owned(), Value::Bool(mut_issue.is_some()));
        if let Some(issue) = &mut_issue {
            obj.insert("detail".to_owned(), Value::Str(issue.clone()));
        }
        println!("{}", Value::Object(obj).pretty());
    } else {
        println!(
            "ADVERSARY  ok={}  killed={}/{}  survived={}  unknown={}",
            adv_report.ok() && mut_issue.is_none(),
            adv_report.killed_faults,
            adv_report.total_faults,
            adv_report.survived_faults,
            adv_report.unknown_faults
        );
        for o in &adv_report.outcomes {
            println!(
                "  [{}] {} ({})",
                o.status.as_str().to_uppercase(),
                o.fault_id,
                o.description
            );
            if let Some(dis) = &o.disambiguator {
                println!(
                    "    DISAMBIGUATOR: ops={} | cand={} | fault={}",
                    Value::Array(dis.witness_ops.iter().map(|w| w.to_json()).collect()).canonical(),
                    dis.candidate_output,
                    dis.fault_output
                );
            }
        }
        if let Some(issue) = &mut_issue {
            println!("  {issue}");
        }
    }

    if adv_report.survived_faults > 0 {
        Ok(3)
    } else if mut_issue.is_some() {
        Ok(7)
    } else {
        Ok(0)
    }
}

fn cmd_ratchet(args: &[String]) -> Result<u8, String> {
    let sub = args.first().map(String::as_str).unwrap_or("status");
    let repo = repo_arg(args);
    let as_json = has_flag(args, "--json");

    match sub {
        "init" => {
            let (base_rev, _) = resolve_base(&repo, args).unwrap_or(("HEAD".to_owned(), false));
            let mut state = load_pinned(&repo, &base_rev).unwrap_or_default();
            if let Some(m) = flag_val(args, "--mode") {
                state.mode = EnforceMode::from_str(&m);
            }
            if let Some(d) = flag_val(args, "--driver") {
                state.driver = Some(d);
            }
            let cmds = flag_vals(args, "--cmd");
            if !cmds.is_empty() {
                state.commands = cmds;
            }
            if let Some(m) = flag_val(args, "--metric") {
                state.metric = Some(m);
            }
            if let Some(r) = flag_val(args, "--min-cov-ratio").and_then(|s| s.parse::<f64>().ok()) {
                state.min_changed_cov_ratio = r.clamp(0.0, 1.0);
            }
            if has_flag(args, "--require-mutations") {
                state.require_mutations = true;
            }
            let obs_files = flag_vals(args, "--observe-file");
            if !obs_files.is_empty() {
                state.observed_files = merge_unique(&state.observed_files, &obs_files);
            }
            let req_obs = flag_vals(args, "--require-observation");
            if !req_obs.is_empty() {
                state.required_observations = merge_unique(&state.required_observations, &req_obs);
            }
            let req_wf = flag_vals(args, "--require-workflow");
            if !req_wf.is_empty() {
                state.required_workflows = merge_unique(&state.required_workflows, &req_wf);
            }
            let sk = skeleton::extract_dir(&repo)?;
            state.skeleton_digest = Some(sk.digest);
            save_local(&repo, &state)?;
            if as_json {
                println!("{}", state.to_json().pretty());
            } else {
                println!(
                    "RATCHET INITIALIZED  mode={}  commands={}  min_cov_ratio={:.2}  require_mutations={}  observed_files={}  required_observations={}  required_workflows={}  skeleton={}  path={}",
                    state.mode.as_str(),
                    state.commands.len(),
                    state.min_changed_cov_ratio,
                    state.require_mutations,
                    state.observed_files.len(),
                    state.required_observations.len(),
                    state.required_workflows.len(),
                    state.skeleton_digest.as_deref().unwrap_or("none"),
                    ratchet::RATCHET_PATH
                );
            }
            Ok(0)
        }
        "status" => {
            let (base_rev, _) = resolve_base(&repo, args)?;
            let state = load_pinned(&repo, &base_rev)?;
            if as_json {
                println!("{}", state.to_json().pretty());
            } else {
                println!(
                    "RATCHET (pinned@{base_rev})  mode={}  commands={}  min_cov_ratio={:.2}  require_mutations={}  observed_files={}  required_observations={}  required_workflows={}  approved_diffs={}  rules={}  masks={}  incidents={}",
                    state.mode.as_str(),
                    state.commands.len(),
                    state.min_changed_cov_ratio,
                    state.require_mutations,
                    state.observed_files.len(),
                    state.required_observations.len(),
                    state.required_workflows.len(),
                    state.approved_diffs.len(),
                    state.approval_rules.len(),
                    state.masks.len(),
                    state.incidents.len()
                );
            }
            Ok(0)
        }
        "approve" => {
            let (base_rev, _) = resolve_base(&repo, args).unwrap_or(("HEAD".to_owned(), false));
            let id = args
                .get(1)
                .ok_or_else(|| "usage: emi ratchet approve <DIFF_ID>".to_owned())?;
            let mut state = load_pinned(&repo, &base_rev)?;
            state.approved_diffs.insert(id.clone());
            save_local(&repo, &state)?;
            println!("APPROVED DIFF {id} (commit {} to pin)", ratchet::RATCHET_PATH);
            Ok(0)
        }
        "lock-rule" => {
            let (base_rev, _) = resolve_base(&repo, args).unwrap_or(("HEAD".to_owned(), false));
            let op = flag_val(args, "--op").ok_or_else(|| {
                "usage: emi ratchet lock-rule --op <GLOB> --when <PREDICATE> --expect <RELATION> [--must-hold]"
                    .to_owned()
            })?;
            let when = flag_val(args, "--when").unwrap_or_else(|| "any".to_owned());
            let expect = flag_val(args, "--expect")
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    "lock-rule requires --expect <RELATION> (e.g. `cand == base - 10`); for an unmodeled change, approve the exact witnessed diff with `emi ratchet approve <DIFF_ID>`"
                        .to_owned()
                })?;
            let must_hold = has_flag(args, "--must-hold");
            let mut state = load_pinned(&repo, &base_rev)?;
            state.approval_rules.push(ApprovalRule {
                op: op.clone(),
                when: when.clone(),
                expect: Some(expect.clone()),
                must_hold,
            });
            save_local(&repo, &state)?;
            println!(
                "LOCKED RULE op={op} when=`{when}` expect=`{expect}` must_hold={must_hold} (commit {} to pin)",
                ratchet::RATCHET_PATH
            );
            Ok(0)
        }
        "remember" => {
            let (base_rev, _) = resolve_base(&repo, args).unwrap_or(("HEAD".to_owned(), false));
            let id = flag_val(args, "--id").unwrap_or_else(|| "incident".to_owned());
            let trigger = flag_val(args, "--trigger").unwrap_or_else(|| "*".to_owned());
            let seed = flag_val(args, "--seed")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let ops_json = flag_val(args, "--ops")
                .ok_or_else(|| "ratchet remember requires --ops '<JSON array of ops>'".to_owned())?;
            let parsed = json::parse(&ops_json)?;
            let arr = parsed
                .as_array()
                .ok_or_else(|| "--ops must be a JSON array".to_owned())?;
            if arr.is_empty() {
                return Err("--ops must contain at least one call".to_owned());
            }
            let mut ops = Vec::with_capacity(arr.len());
            for item in arr {
                ops.push(StepOp::from_json(item)?);
            }
            let mut state = load_pinned(&repo, &base_rev)?;
            state.incidents.push(IncidentSeed {
                id: id.clone(),
                triggers: vec![trigger],
                seed,
                ops,
            });
            save_local(&repo, &state)?;
            println!("REMEMBERED INCIDENT {id} (seed={seed})");
            Ok(0)
        }
        "stamp" => {
            let resolved_base = resolve_base_detailed(&repo, args)?;
            let base_rev = resolved_base.rev.clone();
            let base_sha = git::rev_parse(&repo, &base_rev)?;
            let state = load_pinned(&repo, &base_rev)?;
            enforce_base_policy(&repo, state.mode, &resolved_base)?;
            let signing_key = signing_key_from_env_or_args(args)?;
            if state.mode == EnforceMode::Enforce
                && signing_key.as_deref().map_or(true, |k| k.is_empty())
            {
                return Err(
                    "enforced mode requires a signing key for ratchet stamp (set EMI_SIGNING_KEY or --key-file)"
                        .to_owned(),
                );
            }
            let explicit_driver = flag_val(args, "--driver");
            let cli_commands = flag_vals(args, "--cmd");
            enforce_driver_policy(state.mode, explicit_driver.as_deref(), &cli_commands)?;
            let (eff_explicit_driver, eff_ratchet_driver, eff_commands, command_mode) =
                resolve_driver_and_commands(
                    explicit_driver.as_deref(),
                    state.driver.as_deref(),
                    &cli_commands,
                    &state.commands,
                );
            let explicit_evidence = flag_val(args, "--evidence");
            let cli_req_wf = flag_vals(args, "--require-workflow");
            let required_workflows = merge_unique(&state.required_workflows, &cli_req_wf);
            let force_fresh = has_flag(args, "--fresh");
            let strict_stamp = has_flag(args, "--strict")
                || state.mode == EnforceMode::Enforce
                || !required_workflows.is_empty();
            let timeout = timeout_arg(args);
            let probe_timeout = probe_timeout_arg(args);
            let seeds = flag_val(args, "--seeds")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(48);
            let base_seed = base_seed_arg(args)?;
            let max_faults = flag_val(args, "--max-faults")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(6);

            let changed = git::changed_files(&repo, &base_rev, None)?;
            let base_snap = git::materialize_revision(&repo, &base_rev, "stamp_base")?;
            let cand_snap = git::materialize_worktree(&repo, "stamp_cand")?;
            let cand_tree_sha = git::tree_hash(&cand_snap)?;
            let policy_digest = state.policy_digest();
            let driver_digest = compute_driver_digest_full(
                &base_snap,
                eff_explicit_driver,
                eff_ratchet_driver,
                &eff_commands,
                &changed,
            );

            let default_ev_path = repo.join(ratchet::EVIDENCE_PATH);
            let evidence_file = if let Some(p) = explicit_evidence {
                Some(PathBuf::from(p))
            } else if !force_fresh && default_ev_path.is_file() {
                Some(default_ev_path)
            } else {
                None
            };

            let (evidence, evidence_bound) = if let Some(ev_path) = evidence_file {
                let ev = match load_evidence(&ev_path) {
                    Ok(e) => e,
                    Err(err) => {
                        let _ = std::fs::remove_dir_all(&base_snap);
                        let _ = std::fs::remove_dir_all(&cand_snap);
                        return Err(err);
                    }
                };
                if let Err(err) =
                    ev.verify_binding(&base_sha, &cand_tree_sha, &driver_digest, &policy_digest)
                {
                    let _ = std::fs::remove_dir_all(&base_snap);
                    let _ = std::fs::remove_dir_all(&cand_snap);
                    return Err(err);
                }
                if let Err(err) = ev.verify_integrity(
                    signing_key.as_deref(),
                    state.min_changed_cov_ratio,
                    state.require_mutations,
                    &required_workflows,
                ) {
                    let _ = std::fs::remove_dir_all(&base_snap);
                    let _ = std::fs::remove_dir_all(&cand_snap);
                    return Err(err);
                }
                let _ = std::fs::remove_dir_all(&base_snap);
                let _ = std::fs::remove_dir_all(&cand_snap);
                (ev, true)
            } else {
                let diff_hunks = git::diff_hunks(&repo, &base_rev, None)?;
                let raw_changed_lines = git::changed_lines_from_hunks(&repo, None, &diff_hunks)?;
                let overlaid_drivers = overlay_base_driver_files(
                    &base_snap,
                    &cand_snap,
                    eff_explicit_driver,
                    eff_ratchet_driver,
                    &eff_commands,
                )?;
                let mut exec_changed_lines =
                    git::filter_executable_changed_lines(&cand_snap, &raw_changed_lines);
                let mut exec_deleted_lines =
                    git::deleted_executable_lines(&base_snap, &diff_hunks, &exec_changed_lines);
                for dfile in &overlaid_drivers {
                    exec_changed_lines.remove(dfile);
                    exec_deleted_lines.remove(dfile);
                }

                let base_sk = skeleton::extract_dir(&base_snap)?;
                let cand_sk = skeleton::extract_dir(&cand_snap)?;
                let pinned_sk_ok = state
                    .skeleton_digest
                    .as_ref()
                    .is_none_or(|d| *d == base_sk.digest);
                let sk_diff = skeleton::compare(&base_sk, &cand_sk, false);
                let pool = build_constant_pool(
                    &base_snap,
                    &cand_snap,
                    &changed,
                    &raw_changed_lines,
                    &exec_deleted_lines,
                    &state.approval_rules,
                );

                let priority_files = compute_priority_files(&base_snap, &cand_snap, &changed);
                let (mut b_drv, mut c_drv) = build_driver_pair(
                    &base_snap,
                    &cand_snap,
                    eff_explicit_driver,
                    eff_ratchet_driver,
                    &eff_commands,
                    &changed,
                    &priority_files,
                    timeout,
                    probe_timeout,
                )?;
                let diff_rep = run_diff(
                    &mut *b_drv,
                    &mut *c_drv,
                    &DiffConfig {
                        seeds,
                        base_seed,
                        parity: strict_stamp,
                        strict: state.mode != EnforceMode::Off,
                        command_mode,
                        masks: state.masks.clone(),
                        approved_diffs: state.approved_diffs.clone(),
                        approval_rules: state.approval_rules.clone(),
                        pinned_requests: state.triggered_requests(&changed, &required_workflows),
                        observed_files: state.observed_files.clone(),
                        required_observations: state.required_observations.clone(),
                        required_workflows: required_workflows.clone(),
                        constants: pool.clone(),
                        changed_lines: flatten_changed_lines(&exec_changed_lines),
                        deleted_base_lines: flatten_changed_lines(&exec_deleted_lines),
                        priority_files: priority_files.clone(),
                        require_changed_coverage: !command_mode && state.mode != EnforceMode::Off,
                        min_changed_cov_ratio: state.min_changed_cov_ratio,
                        ..DiffConfig::default()
                    },
                );
                let adv_rep = if diff_rep.aa_verified {
                    run_ast_adversary(
                        &cand_snap,
                        &mut *c_drv,
                        &diff_rep.executed_requests,
                        &exec_changed_lines,
                        eff_explicit_driver,
                        eff_ratchet_driver,
                        &eff_commands,
                        &changed,
                        &priority_files,
                        &state.masks,
                        max_faults,
                        &pool,
                        timeout,
                        probe_timeout,
                    )?
                } else {
                    AdversaryReport {
                        total_faults: 0,
                        killed_faults: 0,
                        survived_faults: 0,
                        unknown_faults: 0,
                        outcomes: Vec::new(),
                    }
                };
                let _ = std::fs::remove_dir_all(&base_snap);
                let _ = std::fs::remove_dir_all(&cand_snap);
                let unapproved_diffs = diff_rep.unapproved_count();
                let ev = EvidenceRecord {
                    base_sha: base_sha.clone(),
                    candidate_tree_sha256: cand_tree_sha.clone(),
                    driver_digest: driver_digest.clone(),
                    policy_digest: policy_digest.clone(),
                    observed_files: state.observed_files.clone(),
                    observed_files_recorded: true,
                    command_mode,
                    request_budget: seeds,
                    base_seed: Some(base_seed),
                    sequences_run: diff_rep.sequences_run,
                    valid_comparisons: diff_rep.valid_comparisons,
                    verdict: diff_rep.verdict.as_str().to_owned(),
                    blocker: diff_rep.blocker,
                    next_action: diff_rep.next_action,
                    detail: diff_rep.detail,
                    skeleton_ok: sk_diff.ok && pinned_sk_ok,
                    aa_verified: diff_rep.aa_verified,
                    masks_proven: diff_rep.masks_proven,
                    changed_lines_covered: diff_rep.changed_lines_covered,
                    changed_lines_total: diff_rep.changed_lines_total,
                    deleted_lines_covered: diff_rep.deleted_lines_covered,
                    deleted_lines_total: diff_rep.deleted_lines_total,
                    unapproved_diffs,
                    missing_observations: diff_rep.missing_observations,
                    workflows_run: diff_rep.workflows_run,
                    ops_exercised: diff_rep.ops_exercised,
                    observed_outputs: diff_rep.observed_outputs,
                    missing_workflows: diff_rep.missing_workflows,
                    mutations_run: diff_rep.aa_verified,
                    planted_total: adv_rep.total_faults,
                    planted_killed: adv_rep.killed_faults,
                    planted_survived: adv_rep.survived_faults,
                    planted_unknown: adv_rep.unknown_faults,
                    witnesses: diff_rep.divergences,
                    record_digest_sha256: None,
                    hmac_sha256: None,
                };
                (ev, false)
            };

            let mut final_verdict = Verdict::from_str(&evidence.verdict);
            if !evidence.skeleton_ok {
                if final_verdict == Verdict::Pass {
                    final_verdict = Verdict::SkeletonBreak;
                }
            } else if evidence.planted_survived > 0 {
                if final_verdict == Verdict::Pass {
                    final_verdict = Verdict::ParityFail;
                }
            } else if final_verdict == Verdict::Pass {
                let missing_req_wf = required_workflows
                    .iter()
                    .any(|wf| !evidence.workflow_satisfied(wf));
                if missing_req_wf || !evidence.missing_workflows.is_empty() {
                    final_verdict = Verdict::Inconclusive;
                } else if mutation_policy_issue(
                    state.require_mutations,
                    evidence.changed_lines_total,
                    evidence.mutations_run,
                    evidence.planted_total,
                    evidence.planted_killed,
                    evidence.planted_survived,
                    evidence.planted_unknown,
                )
                .is_some()
                {
                    final_verdict = Verdict::Inconclusive;
                }
            }

            let att = Attestation {
                base_sha,
                candidate_tree_sha256: cand_tree_sha,
                driver_digest,
                policy_digest,
                request_budget: evidence.request_budget,
                evidence_bound,
                mode: state.mode,
                skeleton_ok: evidence.skeleton_ok,
                aa_verified: evidence.aa_verified,
                changed_lines_covered: evidence.changed_lines_covered,
                changed_lines_total: evidence.changed_lines_total,
                unapproved_diffs: evidence.unapproved_diffs,
                workflows_run: evidence.workflows_run.clone(),
                ops_exercised: evidence.ops_exercised.clone(),
                observed_outputs: evidence.observed_outputs.clone(),
                planted_total: evidence.planted_total,
                planted_killed: evidence.planted_killed,
                planted_survived: evidence.planted_survived,
                planted_unknown: evidence.planted_unknown,
                verdict: final_verdict.as_str().to_owned(),
            };
            let line = append_attestation(&repo, &att, signing_key.as_deref())?;
            println!("{line}");
            Ok(if strict_stamp {
                if !att.skeleton_ok
                    || att.planted_survived > 0
                    || final_verdict == Verdict::BehaviorChanged
                {
                    3
                } else {
                    final_verdict.exit_code()
                }
            } else {
                0
            })
        }
        other => Err(format!("unknown ratchet subcommand `{other}`")),
    }
}

fn cmd_climb(args: &[String]) -> Result<u8, String> {
    let started = Instant::now();
    let repo = repo_arg(args);
    let resolved_base = resolve_base_detailed(&repo, args)?;
    let base_rev = resolved_base.rev.clone();
    let base_sha = git::rev_parse(&repo, &base_rev).unwrap_or_default();
    let pinned = load_pinned(&repo, &base_rev)?;
    enforce_base_policy(&repo, pinned.mode, &resolved_base)?;
    let metric_cmd = pinned
        .metric
        .clone()
        .or_else(|| flag_val(args, "--metric"))
        .ok_or_else(|| {
            "emi climb requires --metric <CMD> (or pinned metric in ratchet.json)".to_owned()
        })?;
    let explicit_metric_file = flag_val(args, "--metric-file");
    let explicit_driver = flag_val(args, "--driver");
    let cli_commands = flag_vals(args, "--cmd");
    let cli_obs_files = flag_vals(args, "--observe-file");
    let cli_req_obs = flag_vals(args, "--require-observation");
    let cli_req_wf = flag_vals(args, "--require-workflow");
    let runs = flag_val(args, "--runs")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(9);
    let seeds = flag_val(args, "--seeds")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(32);
    let max_faults = flag_val(args, "--max-faults")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(6);
    let min_effect = flag_val(args, "--min-effect")
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.05);
    let min_cov_ratio = flag_val(args, "--min-cov-ratio")
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(pinned.min_changed_cov_ratio)
        .clamp(0.0, 1.0);
    let timeout = timeout_arg(args);
    let bench_timeout = if has_flag(args, "--timeout-ms") {
        timeout
    } else {
        Duration::from_secs(60)
    };
    let probe_timeout = probe_timeout_arg(args);
    let direction = if has_flag(args, "--maximize") {
        Direction::Maximize
    } else {
        Direction::Minimize
    };
    let no_history = has_flag(args, "--no-history");
    let as_json = has_flag(args, "--json");

    enforce_driver_policy(pinned.mode, explicit_driver.as_deref(), &cli_commands)?;
    let (eff_explicit_driver, eff_ratchet_driver, eff_commands, command_mode) =
        resolve_driver_and_commands(
            explicit_driver.as_deref(),
            pinned.driver.as_deref(),
            &cli_commands,
            &pinned.commands,
        );

    let changed = git::changed_files(&repo, &base_rev, None)?;
    let diff_hunks = git::diff_hunks(&repo, &base_rev, None)?;
    let raw_changed_lines = git::changed_lines_from_hunks(&repo, None, &diff_hunks)?;
    let base_snap = git::materialize_revision(&repo, &base_rev, "climb_base")?;
    let cand_snap = git::materialize_worktree(&repo, "climb_cand")?;
    let cand_tree_sha = git::tree_hash(&cand_snap).unwrap_or_default();

    let m_argv = split_command(&metric_cmd);
    let overlaid_metrics = overlay_base_metric_files(
        &base_snap,
        &cand_snap,
        &m_argv,
        explicit_metric_file.as_deref(),
    )?;
    let overlaid_drivers = overlay_base_driver_files(
        &base_snap,
        &cand_snap,
        eff_explicit_driver,
        eff_ratchet_driver,
        &eff_commands,
    )?;
    let mut exec_changed_lines =
        git::filter_executable_changed_lines(&cand_snap, &raw_changed_lines);
    let mut exec_deleted_lines =
        git::deleted_executable_lines(&base_snap, &diff_hunks, &exec_changed_lines);
    for mfile in &overlaid_metrics {
        exec_changed_lines.remove(mfile);
        exec_deleted_lines.remove(mfile);
    }
    for dfile in &overlaid_drivers {
        exec_changed_lines.remove(dfile);
        exec_deleted_lines.remove(dfile);
    }

    let base_sk = skeleton::extract_dir(&base_snap)?;
    let cand_sk = skeleton::extract_dir(&cand_snap)?;
    let sk_diff = skeleton::compare(&base_sk, &cand_sk, true);
    let pool = build_constant_pool(
        &base_snap,
        &cand_snap,
        &changed,
        &raw_changed_lines,
        &exec_deleted_lines,
        &pinned.approval_rules,
    );
    let observed_files = merge_unique(&pinned.observed_files, &cli_obs_files);
    let required_observations = merge_unique(&pinned.required_observations, &cli_req_obs);
    let required_workflows = merge_unique(&pinned.required_workflows, &cli_req_wf);

    let priority_files = compute_priority_files(&base_snap, &cand_snap, &changed);
    let (mut b_drv, mut c_drv) = build_driver_pair(
        &base_snap,
        &cand_snap,
        eff_explicit_driver,
        eff_ratchet_driver,
        &eff_commands,
        &changed,
        &priority_files,
        timeout,
        probe_timeout,
    )?;

    let diff_rep = run_diff(
        &mut *b_drv,
        &mut *c_drv,
        &DiffConfig {
            seeds,
            parity: true,
            strict: true,
            command_mode,
            masks: pinned.masks.clone(),
            approved_diffs: pinned.approved_diffs.clone(),
            approval_rules: pinned.approval_rules.clone(),
            pinned_requests: pinned.triggered_requests(&changed, &required_workflows),
            observed_files,
            required_observations,
            required_workflows,
            constants: pool.clone(),
            changed_lines: flatten_changed_lines(&exec_changed_lines),
            deleted_base_lines: flatten_changed_lines(&exec_deleted_lines),
            priority_files: priority_files.clone(),
            require_changed_coverage: !command_mode,
            min_changed_cov_ratio: min_cov_ratio,
            ..DiffConfig::default()
        },
    );

    let mut inconclusive_reason = if diff_rep.verdict == Verdict::Inconclusive {
        Some(diff_rep.detail.clone())
    } else {
        None
    };

    let parity_hard_ok = matches!(diff_rep.verdict, Verdict::Pass | Verdict::Inconclusive);
    let adv_ok = if diff_rep.aa_verified && diff_rep.verdict == Verdict::Pass {
        let adv = run_ast_adversary(
            &cand_snap,
            &mut *c_drv,
            &diff_rep.executed_requests,
            &exec_changed_lines,
            eff_explicit_driver,
            eff_ratchet_driver,
            &eff_commands,
            &changed,
            &priority_files,
            &pinned.masks,
            max_faults,
            &pool,
            timeout,
            probe_timeout,
        )?;
        if let Some(issue) = mutation_policy_issue(
            pinned.require_mutations,
            diff_rep.changed_lines_total,
            true,
            adv.total_faults,
            adv.killed_faults,
            adv.survived_faults,
            adv.unknown_faults,
        ) {
            inconclusive_reason = Some(issue);
        }
        adv.ok()
    } else {
        diff_rep.verdict == Verdict::Inconclusive
    };

    let mut floor = FloorChecks {
        skeleton_ok: sk_diff.ok,
        aa_verified: diff_rep.aa_verified,
        parity_ok: parity_hard_ok,
        planted_bugs_killed: adv_ok,
        benchmark_output_ok: true,
        benchmark_output_missing: false,
        inconclusive_reason,
    };

    let (base_metrics, cand_metrics) =
        if floor.hard_floor_pass() && floor.inconclusive_reason.is_none() {
            let measured = measure_interleaved_with_timeout(
                &base_snap,
                &cand_snap,
                &m_argv,
                runs,
                0x2026_1121,
                bench_timeout,
            );
            let (bm, cm) = match measured {
                Ok(pair) => pair,
                Err(err) => {
                    let _ = std::fs::remove_dir_all(&base_snap);
                    let _ = std::fs::remove_dir_all(&cand_snap);
                    return Err(err);
                }
            };
            if let Err((code, _)) = classify_benchmark_parity(&bm, &cm) {
                floor.benchmark_output_ok = false;
                if code == "benchmark_missing_output" {
                    floor.benchmark_output_missing = true;
                }
            }
            (
                bm.into_iter().map(|s| s.metric).collect(),
                cm.into_iter().map(|s| s.metric).collect(),
            )
        } else {
            (Vec::new(), Vec::new())
        };

    let _ = std::fs::remove_dir_all(&base_snap);
    let _ = std::fs::remove_dir_all(&cand_snap);

    let report = evaluate_climb(floor, &base_metrics, &cand_metrics, direction, min_effect);

    if !no_history {
        let _ = append_history(
            &repo,
            &HistoryEntry {
                ts_unix: now_unix_secs(),
                command: "climb".to_owned(),
                verdict: report.verdict.as_str().to_owned(),
                blocker: report.blocker.clone(),
                exit_code: report.verdict.exit_code(),
                duration_ms: started.elapsed().as_millis() as u64,
                base_sha,
                candidate_tree_sha256: cand_tree_sha,
                command_mode,
                report_diff: false,
                changed_lines_covered: diff_rep.changed_lines_covered,
                changed_lines_total: diff_rep.changed_lines_total,
                unapproved_diffs: diff_rep.unapproved_count(),
                ops_exercised: diff_rep.ops_exercised.len(),
            },
        );
    }

    if as_json {
        println!("{}", report.to_json().pretty());
    } else {
        println!(
            "CLIMB  verdict={}  blocker={}  base={:.4}  cand={:.4}  ratio={:.2}x  ci95=[{:.2}x,{:.2}x]  detail={}",
            report.verdict.as_str(),
            report.blocker,
            report.base_median,
            report.cand_median,
            report.improvement_ratio,
            report.ci95_low,
            report.ci95_high,
            report.detail
        );
    }

    Ok(report.verdict.exit_code())
}

const EMI_CONNECT_START: &str = "<!-- emi:start -->";
const EMI_CONNECT_END: &str = "<!-- emi:end -->";
const EMI_CONNECT_BLOCK: &str = "<!-- emi:start -->\n\
## Verification with `emi`\n\
- After making edits, run `emi` to verify behavior against the baseline.\n\
- If `emi` exits `3`, read the shrunk behavioral diff, fix the issue, and run `emi` again (it automatically replays the failing case first in ~100ms).\n\
- For intentional behavior changes (new features or bug fixes), run `emi --report-diff` and include the behavioral diff summary in your response.\n\
- Never edit `.emi/` files to make checks pass.\n\
<!-- emi:end -->\n";

fn upsert_marked_block(path: &Path, block: &str) -> Result<bool, String> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    let updated = if let (Some(s), Some(e_rel)) = (
        existing.find(EMI_CONNECT_START),
        existing.find(EMI_CONNECT_END),
    ) {
        if e_rel >= s {
            let end = e_rel + EMI_CONNECT_END.len();
            let after = existing[end..].trim_start_matches(['\r', '\n']);
            let before = &existing[..s];
            if after.is_empty() {
                format!("{before}{block}")
            } else {
                format!("{before}{block}\n{after}")
            }
        } else {
            format!("{existing}\n\n{block}")
        }
    } else if existing.trim().is_empty() {
        block.to_owned()
    } else if existing.ends_with('\n') {
        format!("{existing}\n{block}")
    } else {
        format!("{existing}\n\n{block}")
    };
    if updated == existing {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    std::fs::write(path, updated).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(true)
}

fn ensure_gitignore_entries(repo: &Path) -> Result<bool, String> {
    let gi_path = repo.join(".gitignore");
    let existing = match std::fs::read_to_string(&gi_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("read .gitignore: {e}")),
    };
    let mut missing = Vec::new();
    for entry in [".emi/evidence.json", ".emi/history.jsonl"] {
        if !existing.lines().any(|l| l.trim() == entry) {
            missing.push(entry);
        }
    }
    if missing.is_empty() {
        return Ok(false);
    }
    let mut out = existing;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for entry in missing {
        out.push_str(entry);
        out.push('\n');
    }
    std::fs::write(&gi_path, out).map_err(|e| format!("write .gitignore: {e}"))?;
    Ok(true)
}

fn cmd_connect(args: &[String]) -> Result<u8, String> {
    let repo = repo_arg(args);
    let tool = flag_val(args, "--tool")
        .unwrap_or_else(|| "auto".to_owned())
        .to_ascii_lowercase();
    let as_json = has_flag(args, "--json");

    let mut targets: Vec<&str> = match tool.as_str() {
        "opencode" | "codex" | "agents" => vec!["AGENTS.md"],
        "claude" | "claude-code" => vec!["CLAUDE.md"],
        "cursor" => vec![".cursorrules"],
        "all" => vec!["AGENTS.md", "CLAUDE.md", ".cursorrules"],
        "auto" => {
            let mut found = Vec::new();
            for cand in ["AGENTS.md", "CLAUDE.md", ".cursorrules"] {
                if repo.join(cand).is_file() {
                    found.push(cand);
                }
            }
            if found.is_empty() {
                found.push("AGENTS.md");
            }
            found
        }
        other => {
            return Err(format!(
                "unknown --tool `{other}` (expected: auto, opencode, claude, cursor, all)"
            ));
        }
    };
    targets.sort();
    targets.dedup();

    let mut updated_files = Vec::new();
    for rel in &targets {
        let changed = upsert_marked_block(&repo.join(rel), EMI_CONNECT_BLOCK)?;
        updated_files.push(((*rel).to_owned(), changed));
    }
    let gitignore_updated = ensure_gitignore_entries(&repo)?;

    if as_json {
        let files_val = Value::Array(
            updated_files
                .iter()
                .map(|(f, changed)| {
                    Value::obj(vec![
                        ("file", Value::Str(f.clone())),
                        ("updated", Value::Bool(*changed)),
                    ])
                })
                .collect(),
        );
        println!(
            "{}",
            Value::obj(vec![
                ("ok", Value::Bool(true)),
                ("tool", Value::Str(tool)),
                ("files", files_val),
                ("gitignore_updated", Value::Bool(gitignore_updated)),
            ])
            .pretty()
        );
    } else {
        println!("EMI CONNECTED  tool={tool}");
        for (f, changed) in &updated_files {
            println!("  {} {}", if *changed { "updated:" } else { "already set:" }, f);
        }
        if gitignore_updated {
            println!("  updated: .gitignore (.emi/evidence.json, .emi/history.jsonl)");
        }
        println!("  done — code normally with your AI harness; run `emi stats` anytime to check live catches");
    }
    Ok(0)
}

fn parse_since_secs(raw: &str) -> Result<u64, String> {
    let t = raw.trim().to_ascii_lowercase();
    if t.is_empty() || t == "all" {
        return Ok(u64::MAX);
    }
    let (num_str, mult) = if let Some(s) = t.strip_suffix('s') {
        (s, 1u64)
    } else if let Some(s) = t.strip_suffix('m') {
        (s, 60u64)
    } else if let Some(s) = t.strip_suffix('h') {
        (s, 3600u64)
    } else if let Some(s) = t.strip_suffix('d') {
        (s, 86400u64)
    } else {
        (t.as_str(), 1u64)
    };
    let n = num_str
        .parse::<u64>()
        .map_err(|_| format!("invalid --since duration `{raw}` (expected e.g. 30m, 2h, 1d, or seconds)"))?;
    Ok(n.saturating_mul(mult))
}

fn format_age(now: u64, ts: u64) -> String {
    let diff = now.saturating_sub(ts);
    if diff < 60 {
        format!("{diff}s ago")
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86400)
    }
}

fn percentile_u64(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) * pct + 50) / 100;
    sorted[idx.min(sorted.len() - 1)]
}

fn cmd_stats(args: &[String]) -> Result<u8, String> {
    let repo = repo_arg(args);
    let now = now_unix_secs();
    let since_secs = match flag_val(args, "--since") {
        Some(raw) => parse_since_secs(&raw)?,
        None => u64::MAX,
    };
    let last_n = flag_val(args, "--last")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(10);
    let as_json = has_flag(args, "--json");

    let all = load_history(&repo)?;
    let cutoff = now.saturating_sub(since_secs);
    let entries: Vec<&HistoryEntry> = all
        .iter()
        .filter(|e| since_secs == u64::MAX || e.ts_unix >= cutoff)
        .collect();

    let mut verdicts: BTreeMap<String, usize> = BTreeMap::new();
    let mut blockers: BTreeMap<String, usize> = BTreeMap::new();
    let mut durations: Vec<u64> = Vec::with_capacity(entries.len());
    let mut total_duration_ms = 0u64;
    let mut cov_sum = 0.0f64;
    let mut cov_runs = 0usize;

    // Track catch-and-fix loops: a failing run on (base_sha, tree_A) later followed by
    // a pass/accept on the same base_sha with a different candidate tree_B.
    let mut open_catches: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut catches_fixed = 0usize;

    for e in &entries {
        *verdicts.entry(e.verdict.clone()).or_insert(0) += 1;
        if e.blocker != "none" && !e.blocker.is_empty() {
            *blockers.entry(e.blocker.clone()).or_insert(0) += 1;
        }
        durations.push(e.duration_ms);
        total_duration_ms = total_duration_ms.saturating_add(e.duration_ms);
        if e.changed_lines_total > 0 {
            cov_sum += (e.changed_lines_covered as f64 / e.changed_lines_total as f64) * 100.0;
            cov_runs += 1;
        }
        let is_catch = matches!(
            e.verdict.as_str(),
            "parity_fail" | "skeleton_break" | "reject_floor"
        );
        let is_pass = matches!(e.verdict.as_str(), "pass" | "accept");
        if is_catch && !e.candidate_tree_sha256.is_empty() {
            open_catches
                .entry(e.base_sha.clone())
                .or_default()
                .insert(e.candidate_tree_sha256.clone());
        } else if is_pass && !e.candidate_tree_sha256.is_empty() {
            if let Some(failed_trees) = open_catches.get_mut(&e.base_sha) {
                let before = failed_trees.len();
                failed_trees.retain(|t| t == &e.candidate_tree_sha256);
                catches_fixed += before.saturating_sub(failed_trees.len());
            }
        }
    }

    let unresolved_catches: usize = open_catches.values().map(BTreeSet::len).sum();
    durations.sort_unstable();
    let median_ms = percentile_u64(&durations, 50);
    let p95_ms = percentile_u64(&durations, 95);
    let avg_cov_pct = if cov_runs > 0 {
        cov_sum / cov_runs as f64
    } else {
        0.0
    };

    let blocked_runs = verdicts.get("inconclusive").copied().unwrap_or(0)
        + verdicts.get("probe_failed").copied().unwrap_or(0)
        + verdicts.get("timeout").copied().unwrap_or(0);
    let health = if entries.is_empty() {
        "no_runs"
    } else if blocked_runs * 2 >= entries.len() {
        "noisy_or_blocked"
    } else {
        "healthy"
    };

    let mut top_blockers: Vec<(String, usize)> = blockers.into_iter().collect();
    top_blockers.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let recent_start = entries.len().saturating_sub(last_n);
    let recent: Vec<&HistoryEntry> = entries[recent_start..].iter().rev().copied().collect();

    if as_json {
        let verdicts_val = Value::Object(
            verdicts
                .iter()
                .map(|(k, &v)| (k.clone(), Value::Int(v as i64)))
                .collect(),
        );
        let blockers_val = Value::Array(
            top_blockers
                .iter()
                .map(|(k, v)| Value::obj(vec![("blocker", Value::Str(k.clone())), ("count", Value::Int(*v as i64))]))
                .collect(),
        );
        let recent_val = Value::Array(recent.iter().map(|e| e.to_json()).collect());
        let out = Value::obj(vec![
            ("history_path", Value::Str(ratchet::HISTORY_PATH.to_owned())),
            ("total_runs", Value::Int(entries.len() as i64)),
            ("health", Value::Str(health.to_owned())),
            ("catches_fixed", Value::Int(catches_fixed as i64)),
            ("unresolved_catches", Value::Int(unresolved_catches as i64)),
            ("median_duration_ms", Value::Int(median_ms as i64)),
            ("p95_duration_ms", Value::Int(p95_ms as i64)),
            ("total_duration_ms", Value::Int(total_duration_ms as i64)),
            ("avg_changed_cov_pct", Value::Float((avg_cov_pct * 10.0).round() / 10.0)),
            ("verdicts", verdicts_val),
            ("top_blockers", blockers_val),
            ("recent", recent_val),
        ]);
        println!("{}", out.pretty());
    } else {
        println!(
            "EMI STATS  runs={}  health={}  catches_fixed={}  unresolved={}  median={}ms  p95={}ms  avg_cov={:.1}%",
            entries.len(),
            health,
            catches_fixed,
            unresolved_catches,
            median_ms,
            p95_ms,
            avg_cov_pct
        );
        if entries.is_empty() {
            println!("  no runs recorded yet in {} (run `emi check`, `emi diff`, `emi replay`, or `emi climb`)", ratchet::HISTORY_PATH);
            return Ok(0);
        }
        let v_summary: Vec<String> = verdicts.iter().map(|(k, v)| format!("{k}={v}")).collect();
        println!("  verdicts: {}", v_summary.join("  "));
        if !top_blockers.is_empty() {
            let b_summary: Vec<String> = top_blockers
                .iter()
                .take(5)
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            println!("  top_blockers: {}", b_summary.join("  "));
        }
        if health == "noisy_or_blocked" {
            println!("  hint: >=50% of runs were inconclusive/probe_failed/timeout; consider --cmd or `emi driver init`");
        }
        println!("  recent (last {}):", recent.len());
        for e in recent {
            println!(
                "    {:>7}  {:<6}  {:<16}  {:>5}ms  cov={}/{}  diffs={}  blocker={}",
                format_age(now, e.ts_unix),
                e.command,
                e.verdict,
                e.duration_ms,
                e.changed_lines_covered,
                e.changed_lines_total,
                e.unapproved_diffs,
                e.blocker
            );
        }
    }
    Ok(0)
}

fn cmd_sim(args: &[String]) -> Result<u8, String> {
    let seed_start = flag_val(args, "--seed")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1);
    let count = flag_val(args, "--seeds")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1000);
    let include_effectful = !has_flag(args, "--fast");
    let as_json = has_flag(args, "--json");

    let report = sim::run_simulation(seed_start, count, include_effectful);

    if as_json {
        println!("{}", report.to_json().pretty());
    } else {
        println!(
            "SIM  ok={}  seeds={}  worlds={}  effectful={}  digest={}",
            report.ok,
            report.seeds_run,
            report.worlds_verified,
            report.effectful_worlds,
            report.digest
        );
        if let (Some(fs), Some(why)) = (report.failed_seed, &report.failure) {
            println!("  FAILED SEED {fs}: {why}");
        }
    }
    Ok(if report.ok { 0 } else { 3 })
}
