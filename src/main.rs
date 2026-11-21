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
use std::time::Duration;

use crate::adversary::{AdversaryReport, PlantedFault, prove_oracle, synthesize_ast_faults};
use crate::climb::{
    Direction, FloorChecks, evaluate_climb, measure_interleaved, verify_benchmark_parity,
};
use crate::diff::{ConstantPool, DiffConfig, Verdict, replay_witnesses, run_diff};
use crate::driver_init::DriverLang;
use crate::json::Value;
use crate::protocol::{
    DEFAULT_CALL_TIMEOUT_MS, ProcessDriver, StepOp, StepRequest, compute_driver_digest,
    materialize_auto_driver, split_command,
};
use crate::ratchet::{
    ApprovalRule, Attestation, EnforceMode, EvidenceRecord, IncidentSeed, append_attestation,
    load_evidence, load_pinned, save_evidence_signed, save_local,
};

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
    let Some(cmd) = args.first().map(String::as_str) else {
        print_usage();
        return Ok(2);
    };
    let rest = &args[1..];
    match cmd {
        "check" => cmd_check(rest),
        "replay" => cmd_replay(rest),
        "driver" => cmd_driver(rest),
        "skeleton" => cmd_skeleton(rest),
        "diff" => cmd_diff(rest),
        "adversary" => cmd_adversary(rest),
        "ratchet" => cmd_ratchet(rest),
        "climb" => cmd_climb(rest),
        "sim" => cmd_sim(rest),
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(0)
        }
        other => Err(format!("unknown command `{other}`")),
    }
}

fn print_usage() {
    println!("emi 2.0.0 — deterministic proof & control engine for agentic software");
    println!("commands:");
    println!("  emi check [--repo PATH] [--base REV] [--cand REV] [--allow-head] [--driver CMD] [--seeds N] [--min-cov-ratio F] [--with-adversary|--no-adversary] [--max-faults N] [--forbid-nondet] [--require-mutations] [--observe-file PATH] [--require-observation NAME] [--require-workflow ID] [--evidence-out PATH] [--key-file PATH] [--no-strict] [--json]");
    println!("  emi replay [--repo PATH] [--base REV] [--allow-head] [--evidence PATH] [--id DIFF_ID] [--observe-file PATH] [--driver CMD] [--timeout-ms MS] [--json]");
    println!("  emi driver init [--repo PATH] [--lang python|node|ts|go|rust] [--out PATH] [--force] [--pin] [--json]");
    println!("  emi skeleton [extract|check] [--repo PATH] [--base REV] [--allow-head] [--forbid-nondet] [--json]");
    println!("  emi diff [--repo PATH] [--base REV] [--cand REV] [--allow-head] [--driver CMD] [--seeds N] [--timeout-ms MS] [--parity] [--strict|--no-strict] [--min-cov-ratio F] [--with-adversary] [--max-faults N] [--require-mutations] [--observe-file PATH] [--require-observation NAME] [--require-workflow ID] [--evidence-out PATH] [--key-file PATH] [--no-evidence] [--json]");
    println!("  emi adversary [--repo PATH] [--base REV] [--cand REV] [--allow-head] [--driver CMD] [--max-faults N] [--seeds N] [--timeout-ms MS] [--require-mutations] [--observe-file PATH] [--evidence PATH] [--key-file PATH] [--json]");
    println!("  emi ratchet [init|status|approve <ID>|lock-rule --op GLOB --when PRED --expect EXPR [--must-hold]|remember --id ID --trigger GLOB --ops JSON|stamp [--evidence PATH|--fresh]] [--repo PATH] [--base REV] [--allow-head] [--mode off|observe|enforce] [--min-cov-ratio F] [--require-mutations] [--observe-file PATH] [--require-observation NAME] [--require-workflow ID] [--key-file PATH] [--strict] [--json]");
    println!("  emi climb --metric CMD [--metric-file PATH] [--repo PATH] [--base REV] [--allow-head] [--driver CMD] [--runs N] [--seeds N] [--min-effect F] [--min-cov-ratio F] [--max-faults N] [--observe-file PATH] [--require-observation NAME] [--require-workflow ID] [--maximize] [--json]");
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

fn resolve_base_detailed(repo: &Path, args: &[String]) -> Result<git::ResolvedBase, String> {
    let explicit = flag_val(args, "--base");
    let allow_head = has_flag(args, "--allow-head");
    let resolved = git::resolve_protected_base(repo, explicit.as_deref(), allow_head)?;
    if let Some(reason) = git::check_remote_ref_tampered(repo, &resolved.rev)? {
        return Err(format!(
            "refusing locally moved base ref: {reason}; CI must fix the base on a clean checkout with --base <SHA>"
        ));
    }
    Ok(resolved)
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
    rules: &[ApprovalRule],
) -> ConstantPool {
    let mut pool = ConstantPool::from_files_with_imports(base_snap, changed);
    pool.merge(&ConstantPool::from_files_with_imports(cand_snap, changed));
    pool.merge_from_rules(rules);
    pool
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
    cand_drv: &mut ProcessDriver,
    oracle_reqs: &[StepRequest],
    changed_lines: &BTreeMap<String, BTreeSet<u32>>,
    explicit_driver: Option<&str>,
    ratchet_driver: Option<&str>,
    masks: &[protocol::Mask],
    max_faults: usize,
    constants: &ConstantPool,
    timeout: Duration,
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
        let fav = prepare_driver_argv(&fdir, explicit_driver, ratchet_driver)?;
        planted.push(PlantedFault {
            id: sf.id.clone(),
            description: sf.description.clone(),
            driver: Box::new(ProcessDriver::with_timeout(fdir.clone(), fav, timeout)),
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

fn enforce_driver_policy(mode: EnforceMode, explicit_driver: Option<&str>) -> Result<(), String> {
    if mode == EnforceMode::Enforce && explicit_driver.is_some() {
        return Err(
            "enforced mode forbids --driver on the command line; pin driver in .emi/ratchet.json on base"
                .to_owned(),
        );
    }
    Ok(())
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
) -> Result<BTreeSet<String>, String> {
    let mut overlaid = BTreeSet::new();
    let Some(cmd) = explicit.or(ratchet_driver) else {
        return Ok(overlaid);
    };
    let mut file_targets = BTreeSet::new();
    let mut dir_targets = BTreeSet::new();
    let mut remove_untrusted = BTreeSet::new();

    for tok in split_command(cmd) {
        if tok.starts_with('-') {
            continue;
        }
        let Some(rel) = sanitize_rel_token(&tok) else {
            continue;
        };
        let bpath = base_snap.join(&rel);
        let cpath = cand_snap.join(&rel);
        if bpath.is_file() {
            if rel.ends_with("/Cargo.toml") {
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

fn prepare_driver_argv(
    dir: &Path,
    explicit: Option<&str>,
    ratchet_driver: Option<&str>,
) -> Result<Vec<String>, String> {
    if let Some(cmd) = explicit.or(ratchet_driver) {
        let argv = split_command(cmd);
        if argv.is_empty() {
            return Err("empty driver command".to_owned());
        }
        Ok(argv)
    } else {
        materialize_auto_driver(dir)
    }
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

fn cmd_check(args: &[String]) -> Result<u8, String> {
    run_diff_or_check(args, true)
}

fn cmd_diff(args: &[String]) -> Result<u8, String> {
    run_diff_or_check(args, false)
}

fn run_diff_or_check(args: &[String], full_check: bool) -> Result<u8, String> {
    let repo = repo_arg(args);
    let resolved_base = resolve_base_detailed(&repo, args)?;
    let base_rev = resolved_base.rev.clone();
    let base_sha = git::rev_parse(&repo, &base_rev)?;
    let cand_rev = flag_val(args, "--cand");
    let explicit_driver = flag_val(args, "--driver");
    let seeds = flag_val(args, "--seeds")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(48);
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
    let signing_key = signing_key_from_env_or_args(args)?;
    let timeout = timeout_arg(args);
    let as_json = has_flag(args, "--json");

    let pinned = load_pinned(&repo, &base_rev)?;
    enforce_base_policy(&repo, pinned.mode, &resolved_base)?;
    enforce_driver_policy(pinned.mode, explicit_driver.as_deref())?;

    let min_cov_ratio = flag_val(args, "--min-cov-ratio")
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(pinned.min_changed_cov_ratio)
        .clamp(0.0, 1.0);

    let changed = git::changed_files(&repo, &base_rev, cand_rev.as_deref())?;
    let raw_changed_lines = git::changed_lines(&repo, &base_rev, cand_rev.as_deref())?;
    let base_snap = git::materialize_revision(&repo, &base_rev, "diff_base")?;
    let cand_snap = match cand_rev.as_deref() {
        Some(rev) => git::materialize_revision(&repo, rev, "diff_cand")?,
        None => git::materialize_worktree(&repo, "diff_cand")?,
    };
    let cand_tree_sha = git::tree_hash(&cand_snap)?;
    let overlaid_drivers = overlay_base_driver_files(
        &base_snap,
        &cand_snap,
        explicit_driver.as_deref(),
        pinned.driver.as_deref(),
    )?;
    let mut exec_changed_lines =
        git::filter_executable_changed_lines(&cand_snap, &raw_changed_lines);
    for dfile in &overlaid_drivers {
        exec_changed_lines.remove(dfile);
    }

    let base_sk = skeleton::extract_dir(&base_snap)?;
    let cand_sk = skeleton::extract_dir(&cand_snap)?;
    if let Some(expected_sk) = &pinned.skeleton_digest {
        if base_sk.digest != *expected_sk {
            let _ = std::fs::remove_dir_all(&base_snap);
            let _ = std::fs::remove_dir_all(&cand_snap);
            return Err(format!(
                "pinned skeleton_digest mismatch on base: expected {}, got {}",
                &expected_sk[..16],
                &base_sk.digest[..16]
            ));
        }
    }
    let forbid_nondet = forbid_nondet_flag || (full_check && pinned.mode == EnforceMode::Enforce);
    let sk_diff = skeleton::compare(&base_sk, &cand_sk, forbid_nondet);

    let policy_digest = pinned.policy_digest();
    let driver_digest =
        compute_driver_digest(&base_snap, explicit_driver.as_deref(), pinned.driver.as_deref());
    let observed_files = merge_unique(&pinned.observed_files, &cli_obs_files);
    let required_observations = merge_unique(&pinned.required_observations, &cli_req_obs);
    let required_workflows = merge_unique(&pinned.required_workflows, &cli_req_wf);
    let require_mutations = require_mut_flag || pinned.require_mutations;

    let pool = build_constant_pool(&base_snap, &cand_snap, &changed, &pinned.approval_rules);
    let base_argv =
        prepare_driver_argv(&base_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let cand_argv =
        prepare_driver_argv(&cand_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;

    let mut base_drv = ProcessDriver::with_timeout(base_snap.clone(), base_argv, timeout);
    let mut cand_drv = ProcessDriver::with_timeout(cand_snap.clone(), cand_argv, timeout);

    let strict_active = !no_strict && pinned.mode != EnforceMode::Off;
    let parity_active = full_check || explicit_parity || pinned.mode == EnforceMode::Enforce;
    let cov_active = !no_cov && (require_cov || strict_active);

    let cfg = DiffConfig {
        seeds,
        parity: parity_active,
        strict: strict_active,
        masks: pinned.masks.clone(),
        approved_diffs: pinned.approved_diffs.clone(),
        approval_rules: pinned.approval_rules.clone(),
        pinned_requests: pinned.triggered_requests(&changed, &required_workflows),
        observed_files: observed_files.clone(),
        required_observations,
        required_workflows,
        constants: pool.clone(),
        changed_lines: flatten_changed_lines(&exec_changed_lines),
        require_changed_coverage: cov_active,
        min_changed_cov_ratio: min_cov_ratio,
        ..DiffConfig::default()
    };

    let report = run_diff(&mut base_drv, &mut cand_drv, &cfg);

    let run_adv = !no_adversary_flag
        && (with_adversary_flag
            || (full_check && (require_mutations || pinned.mode == EnforceMode::Enforce)));

    let (mutations_run, adv_report_opt) =
        if run_adv && report.aa_verified && report.verdict != Verdict::ProbeFailed {
            let adv = run_ast_adversary(
                &cand_snap,
                &mut cand_drv,
                &report.executed_requests,
                &exec_changed_lines,
                explicit_driver.as_deref(),
                pinned.driver.as_deref(),
                &pinned.masks,
                max_faults,
                &pool,
                timeout,
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

    if full_check && !sk_diff.ok {
        final_verdict = Verdict::ParityFail;
        final_blocker = if !sk_diff.new_nondet_sites.is_empty() {
            "nondet_site".to_owned()
        } else {
            "skeleton_break".to_owned()
        };
        final_action = if !sk_diff.new_nondet_sites.is_empty() {
            "remove_nondeterminism".to_owned()
        } else {
            "fix_public_api_break".to_owned()
        };
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
        request_budget: seeds,
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

    if as_json {
        let mut obj = report.to_json().as_object().cloned().unwrap();
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
        obj.insert("request_budget".to_owned(), Value::Int(seeds as i64));
        obj.insert(
            "min_changed_cov_ratio".to_owned(),
            Value::Float(min_cov_ratio),
        );
        obj.insert(
            "observed_files".to_owned(),
            Value::Array(observed_files.iter().cloned().map(Value::Str).collect()),
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
        let banner = if full_check { "CHECK" } else { "BEHAVIORAL DIFF" };
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
        for d in &report.divergences {
            let tag = match &d.approved_by {
                Some(by) => format!("APPROVED:{by}"),
                None => match &d.rule_violation {
                    Some(rv) => format!("RULE_VIOLATION:{rv}"),
                    None => "UNAPPROVED".to_owned(),
                },
            };
            println!("  [DIFF {} | {}] ops={}", d.id, tag, d.ops.len());
            for op in &d.ops {
                println!("    call: {}", op.to_json().canonical());
            }
            println!("    base:      {}", d.base_payload);
            println!("    candidate: {}", d.cand_payload);
        }
        if report.divergences.is_empty() || final_verdict != Verdict::ParityFail {
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
    let repo = repo_arg(args);
    let (base_rev, _) = resolve_base(&repo, args)?;
    let explicit_driver = flag_val(args, "--driver");
    let cli_obs_files = flag_vals(args, "--observe-file");
    let ev_path = flag_val(args, "--evidence")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo.join(ratchet::EVIDENCE_PATH));
    let filter_id = flag_val(args, "--id");
    let timeout = timeout_arg(args);
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

    let base_snap = git::materialize_revision(&repo, &base_rev, "replay_base")?;
    let cand_snap = git::materialize_worktree(&repo, "replay_cand")?;
    enforce_driver_policy(pinned.mode, explicit_driver.as_deref())?;
    let _ = overlay_base_driver_files(
        &base_snap,
        &cand_snap,
        explicit_driver.as_deref(),
        pinned.driver.as_deref(),
    )?;
    let b_argv =
        prepare_driver_argv(&base_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let c_argv =
        prepare_driver_argv(&cand_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let mut b_drv = ProcessDriver::with_timeout(base_snap.clone(), b_argv, timeout);
    let mut c_drv = ProcessDriver::with_timeout(cand_snap.clone(), c_argv, timeout);

    let report = replay_witnesses(
        &mut b_drv,
        &mut c_drv,
        &selected,
        &pinned.masks,
        &pinned.approved_diffs,
        &pinned.approval_rules,
        &effective_obs,
    );

    let _ = std::fs::remove_dir_all(&base_snap);
    let _ = std::fs::remove_dir_all(&cand_snap);

    if as_json {
        let mut obj = report.to_json().as_object().cloned().unwrap();
        obj.insert("replayed".to_owned(), Value::Int(selected.len() as i64));
        obj.insert(
            "observed_files".to_owned(),
            Value::Array(effective_obs.iter().cloned().map(Value::Str).collect()),
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
                    &sk.digest[..16]
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
    let as_json = has_flag(args, "--json");

    let pinned = load_pinned(&repo, &base_rev)?;
    enforce_driver_policy(pinned.mode, explicit_driver.as_deref())?;
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
        explicit_driver.as_deref(),
        pinned.driver.as_deref(),
    )?;
    let mut exec_changed_lines =
        git::filter_executable_changed_lines(&cand_snap, &raw_changed_lines);
    for dfile in &overlaid_drivers {
        exec_changed_lines.remove(dfile);
    }
    let policy_digest = pinned.policy_digest();
    let driver_digest =
        compute_driver_digest(&base_snap, explicit_driver.as_deref(), pinned.driver.as_deref());
    let observed_files = merge_unique(&pinned.observed_files, &cli_obs_files);
    let require_mutations = require_mut_flag || pinned.require_mutations;

    let pool = build_constant_pool(&base_snap, &cand_snap, &changed, &pinned.approval_rules);
    let base_argv =
        prepare_driver_argv(&base_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let cand_argv =
        prepare_driver_argv(&cand_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let mut base_drv = ProcessDriver::with_timeout(base_snap.clone(), base_argv, timeout);
    let mut cand_drv = ProcessDriver::with_timeout(cand_snap.clone(), cand_argv, timeout);

    let diff_cfg = DiffConfig {
        seeds,
        parity: false,
        masks: pinned.masks.clone(),
        pinned_requests: pinned.triggered_requests(&changed, &[]),
        observed_files,
        constants: pool.clone(),
        changed_lines: flatten_changed_lines(&exec_changed_lines),
        ..DiffConfig::default()
    };
    let diff_rep = run_diff(&mut base_drv, &mut cand_drv, &diff_cfg);
    if !diff_rep.aa_verified {
        let _ = std::fs::remove_dir_all(&base_snap);
        let _ = std::fs::remove_dir_all(&cand_snap);
        return Err(format!("cannot prove oracle: {}", diff_rep.detail));
    }

    let adv_report = run_ast_adversary(
        &cand_snap,
        &mut cand_drv,
        &diff_rep.executed_requests,
        &exec_changed_lines,
        explicit_driver.as_deref(),
        pinned.driver.as_deref(),
        &pinned.masks,
        max_faults,
        &pool,
        timeout,
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
        let cov_ok = ev.changed_lines_total == 0
            || (ev.changed_lines_covered as f64 / ev.changed_lines_total as f64) + 1e-9
                >= pinned.min_changed_cov_ratio;
        if adv_report.survived_faults > 0 {
            ev.verdict = Verdict::ParityFail.as_str().to_owned();
            ev.blocker = "surviving_mutant".to_owned();
            ev.next_action = "kill_surviving_mutant".to_owned();
            ev.detail = format!(
                "{} planted AST mutation(s) survived",
                adv_report.survived_faults
            );
        } else if ev.verdict == Verdict::Inconclusive.as_str()
            && ev.unapproved_diffs == 0
            && ev.missing_observations.is_empty()
            && ev.missing_workflows.is_empty()
            && ev.valid_comparisons > 0
            && cov_ok
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
        let mut obj = adv_report.to_json().as_object().cloned().unwrap();
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
                    "RATCHET INITIALIZED  mode={}  min_cov_ratio={:.2}  require_mutations={}  observed_files={}  required_observations={}  required_workflows={}  skeleton={}  path={}",
                    state.mode.as_str(),
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
                    "RATCHET (pinned@{base_rev})  mode={}  min_cov_ratio={:.2}  require_mutations={}  observed_files={}  required_observations={}  required_workflows={}  approved_diffs={}  rules={}  masks={}  incidents={}",
                    state.mode.as_str(),
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
            let explicit_driver = flag_val(args, "--driver");
            enforce_driver_policy(state.mode, explicit_driver.as_deref())?;
            let explicit_evidence = flag_val(args, "--evidence");
            let cli_req_wf = flag_vals(args, "--require-workflow");
            let required_workflows = merge_unique(&state.required_workflows, &cli_req_wf);
            let force_fresh = has_flag(args, "--fresh");
            let strict_stamp = has_flag(args, "--strict")
                || state.mode == EnforceMode::Enforce
                || !required_workflows.is_empty();
            let timeout = timeout_arg(args);
            let seeds = flag_val(args, "--seeds")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(48);
            let max_faults = flag_val(args, "--max-faults")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(6);

            let base_snap = git::materialize_revision(&repo, &base_rev, "stamp_base")?;
            let cand_snap = git::materialize_worktree(&repo, "stamp_cand")?;
            let cand_tree_sha = git::tree_hash(&cand_snap)?;
            let policy_digest = state.policy_digest();
            let driver_digest = compute_driver_digest(
                &base_snap,
                explicit_driver.as_deref(),
                state.driver.as_deref(),
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
                let changed = git::changed_files(&repo, &base_rev, None)?;
                let raw_changed_lines = git::changed_lines(&repo, &base_rev, None)?;
                let overlaid_drivers = overlay_base_driver_files(
                    &base_snap,
                    &cand_snap,
                    explicit_driver.as_deref(),
                    state.driver.as_deref(),
                )?;
                let mut exec_changed_lines =
                    git::filter_executable_changed_lines(&cand_snap, &raw_changed_lines);
                for dfile in &overlaid_drivers {
                    exec_changed_lines.remove(dfile);
                }

                let base_sk = skeleton::extract_dir(&base_snap)?;
                let cand_sk = skeleton::extract_dir(&cand_snap)?;
                let pinned_sk_ok = state
                    .skeleton_digest
                    .as_ref()
                    .is_none_or(|d| *d == base_sk.digest);
                let sk_diff = skeleton::compare(&base_sk, &cand_sk, false);
                let pool =
                    build_constant_pool(&base_snap, &cand_snap, &changed, &state.approval_rules);

                let b_argv = prepare_driver_argv(
                    &base_snap,
                    explicit_driver.as_deref(),
                    state.driver.as_deref(),
                )?;
                let c_argv = prepare_driver_argv(
                    &cand_snap,
                    explicit_driver.as_deref(),
                    state.driver.as_deref(),
                )?;
                let mut b_drv = ProcessDriver::with_timeout(base_snap.clone(), b_argv, timeout);
                let mut c_drv = ProcessDriver::with_timeout(cand_snap.clone(), c_argv, timeout);
                let diff_rep = run_diff(
                    &mut b_drv,
                    &mut c_drv,
                    &DiffConfig {
                        seeds,
                        parity: strict_stamp,
                        strict: state.mode != EnforceMode::Off,
                        masks: state.masks.clone(),
                        approved_diffs: state.approved_diffs.clone(),
                        approval_rules: state.approval_rules.clone(),
                        pinned_requests: state.triggered_requests(&changed, &required_workflows),
                        observed_files: state.observed_files.clone(),
                        required_observations: state.required_observations.clone(),
                        required_workflows: required_workflows.clone(),
                        constants: pool.clone(),
                        changed_lines: flatten_changed_lines(&exec_changed_lines),
                        require_changed_coverage: state.mode != EnforceMode::Off,
                        min_changed_cov_ratio: state.min_changed_cov_ratio,
                        ..DiffConfig::default()
                    },
                );
                let adv_rep = if diff_rep.aa_verified {
                    run_ast_adversary(
                        &cand_snap,
                        &mut c_drv,
                        &diff_rep.executed_requests,
                        &exec_changed_lines,
                        explicit_driver.as_deref(),
                        state.driver.as_deref(),
                        &state.masks,
                        max_faults,
                        &pool,
                        timeout,
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
                    request_budget: seeds,
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
            if !evidence.skeleton_ok || evidence.planted_survived > 0 {
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
                if !att.skeleton_ok || att.planted_survived > 0 {
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
    let repo = repo_arg(args);
    let resolved_base = resolve_base_detailed(&repo, args)?;
    let base_rev = resolved_base.rev.clone();
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
    let direction = if has_flag(args, "--maximize") {
        Direction::Maximize
    } else {
        Direction::Minimize
    };
    let as_json = has_flag(args, "--json");

    let changed = git::changed_files(&repo, &base_rev, None)?;
    let raw_changed_lines = git::changed_lines(&repo, &base_rev, None)?;
    let base_snap = git::materialize_revision(&repo, &base_rev, "climb_base")?;
    let cand_snap = git::materialize_worktree(&repo, "climb_cand")?;

    enforce_driver_policy(pinned.mode, explicit_driver.as_deref())?;
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
        explicit_driver.as_deref(),
        pinned.driver.as_deref(),
    )?;
    let mut exec_changed_lines =
        git::filter_executable_changed_lines(&cand_snap, &raw_changed_lines);
    for mfile in &overlaid_metrics {
        exec_changed_lines.remove(mfile);
    }
    for dfile in &overlaid_drivers {
        exec_changed_lines.remove(dfile);
    }

    let base_sk = skeleton::extract_dir(&base_snap)?;
    let cand_sk = skeleton::extract_dir(&cand_snap)?;
    let sk_diff = skeleton::compare(&base_sk, &cand_sk, true);
    let pool = build_constant_pool(&base_snap, &cand_snap, &changed, &pinned.approval_rules);
    let observed_files = merge_unique(&pinned.observed_files, &cli_obs_files);
    let required_observations = merge_unique(&pinned.required_observations, &cli_req_obs);
    let required_workflows = merge_unique(&pinned.required_workflows, &cli_req_wf);

    let b_argv =
        prepare_driver_argv(&base_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let c_argv =
        prepare_driver_argv(&cand_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let mut b_drv = ProcessDriver::with_timeout(base_snap.clone(), b_argv, timeout);
    let mut c_drv = ProcessDriver::with_timeout(cand_snap.clone(), c_argv, timeout);

    let diff_rep = run_diff(
        &mut b_drv,
        &mut c_drv,
        &DiffConfig {
            seeds,
            parity: true,
            strict: true,
            masks: pinned.masks.clone(),
            approved_diffs: pinned.approved_diffs.clone(),
            approval_rules: pinned.approval_rules.clone(),
            pinned_requests: pinned.triggered_requests(&changed, &required_workflows),
            observed_files,
            required_observations,
            required_workflows,
            constants: pool.clone(),
            changed_lines: flatten_changed_lines(&exec_changed_lines),
            require_changed_coverage: true,
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
            &mut c_drv,
            &diff_rep.executed_requests,
            &exec_changed_lines,
            explicit_driver.as_deref(),
            pinned.driver.as_deref(),
            &pinned.masks,
            max_faults,
            &pool,
            timeout,
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
        inconclusive_reason,
    };

    let (base_metrics, cand_metrics) =
        if floor.hard_floor_pass() && floor.inconclusive_reason.is_none() {
            let (bm, cm) = measure_interleaved(&base_snap, &cand_snap, &m_argv, runs, 0x2026_1121)?;
            if verify_benchmark_parity(&bm, &cm).is_err() {
                floor.benchmark_output_ok = false;
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
