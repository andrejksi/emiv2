mod adversary;
mod climb;
mod diff;
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
use crate::climb::{Direction, FloorChecks, evaluate_climb, measure_interleaved};
use crate::diff::{ConstantPool, DiffConfig, Verdict, run_diff};
use crate::json::Value;
use crate::protocol::{
    DEFAULT_CALL_TIMEOUT_MS, ProcessDriver, StepOp, StepRequest, compute_driver_digest,
    materialize_auto_driver, split_command,
};
use crate::ratchet::{
    ApprovalRule, Attestation, EnforceMode, EvidenceRecord, IncidentSeed, append_attestation,
    load_evidence, load_pinned, save_evidence, save_local,
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
    println!("  emi skeleton [extract|check] [--repo PATH] [--base REV] [--allow-head] [--forbid-nondet] [--json]");
    println!("  emi diff [--repo PATH] [--base REV] [--cand REV] [--allow-head] [--driver CMD] [--seeds N] [--timeout-ms MS] [--parity] [--strict] [--require-cov] [--with-adversary] [--max-faults N] [--require-mutations] [--observe-file PATH] [--require-observation NAME] [--evidence-out PATH] [--no-evidence] [--json]");
    println!("  emi adversary [--repo PATH] [--base REV] [--cand REV] [--allow-head] [--driver CMD] [--max-faults N] [--seeds N] [--timeout-ms MS] [--require-mutations] [--observe-file PATH] [--evidence PATH] [--json]");
    println!("  emi ratchet [init|status|approve <ID>|lock-rule --op GLOB --when PRED --expect EXPR|remember --id ID --trigger GLOB --ops JSON|stamp [--evidence PATH|--fresh]] [--repo PATH] [--base REV] [--allow-head] [--mode off|observe|enforce] [--require-mutations] [--observe-file PATH] [--require-observation NAME] [--strict] [--json]");
    println!("  emi climb --metric CMD [--metric-file PATH] [--repo PATH] [--base REV] [--allow-head] [--driver CMD] [--runs N] [--seeds N] [--min-effect F] [--max-faults N] [--observe-file PATH] [--require-observation NAME] [--maximize] [--json]");
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

fn resolve_base(repo: &Path, args: &[String]) -> Result<(String, bool), String> {
    let explicit = flag_val(args, "--base");
    let allow_head = has_flag(args, "--allow-head");
    git::resolve_protected_base(repo, explicit.as_deref(), allow_head)
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

fn build_constant_pool(base_snap: &Path, cand_snap: &Path, changed: &[String]) -> ConstantPool {
    let mut pool = ConstantPool::from_files(base_snap, changed);
    pool.merge(&ConstantPool::from_files(cand_snap, changed));
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
        let fdir = std::env::temp_dir().join(format!("emi_fault_{}_{}", std::process::id(), idx));
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
) -> Result<(), String> {
    let mut targets = BTreeSet::new();
    if let Some(f) = explicit_metric_file {
        targets.insert(f.to_owned());
    }
    for tok in metric_argv {
        if !tok.starts_with('-') && base_snap.join(tok).is_file() {
            targets.insert(tok.clone());
        }
    }
    for rel in targets {
        let src = base_snap.join(&rel);
        let dst = cand_snap.join(&rel);
        if src.is_file() {
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::copy(&src, &dst)
                .map_err(|e| format!("overlay base metric file {rel}: {e}"))?;
        }
    }
    Ok(())
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

fn cmd_diff(args: &[String]) -> Result<u8, String> {
    let repo = repo_arg(args);
    let (base_rev, protected) = resolve_base(&repo, args)?;
    let base_sha = git::rev_parse(&repo, &base_rev)?;
    let cand_rev = flag_val(args, "--cand");
    let explicit_driver = flag_val(args, "--driver");
    let seeds = flag_val(args, "--seeds")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(48);
    let parity = has_flag(args, "--parity");
    let strict = has_flag(args, "--strict");
    let require_cov = has_flag(args, "--require-cov");
    let with_adversary = has_flag(args, "--with-adversary");
    let max_faults = flag_val(args, "--max-faults")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(8);
    let require_mut_flag = has_flag(args, "--require-mutations");
    let cli_obs_files = flag_vals(args, "--observe-file");
    let cli_req_obs = flag_vals(args, "--require-observation");
    let evidence_out = flag_val(args, "--evidence-out");
    let no_evidence = has_flag(args, "--no-evidence");
    let timeout = timeout_arg(args);
    let as_json = has_flag(args, "--json");

    let pinned = load_pinned(&repo, &base_rev)?;
    if pinned.mode == EnforceMode::Enforce && !protected {
        return Err(
            "enforced mode forbids bare HEAD baseline; specify --base or EMI_BASE_REV".to_owned(),
        );
    }
    let changed = git::changed_files(&repo, &base_rev, cand_rev.as_deref())?;
    let raw_changed_lines = git::changed_lines(&repo, &base_rev, cand_rev.as_deref())?;
    let base_snap = git::materialize_revision(&repo, &base_rev, "diff_base")?;
    let cand_snap = match cand_rev.as_deref() {
        Some(rev) => git::materialize_revision(&repo, rev, "diff_cand")?,
        None => git::materialize_worktree(&repo, "diff_cand")?,
    };
    let cand_tree_sha = git::tree_hash(&cand_snap)?;
    let exec_changed_lines = git::filter_executable_changed_lines(&cand_snap, &raw_changed_lines);

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
    let sk_ok = skeleton::compare(&base_sk, &cand_sk, false).ok;

    let policy_digest = pinned.policy_digest();
    let driver_digest =
        compute_driver_digest(&base_snap, explicit_driver.as_deref(), pinned.driver.as_deref());
    let observed_files = merge_unique(&pinned.observed_files, &cli_obs_files);
    let required_observations = merge_unique(&pinned.required_observations, &cli_req_obs);
    let require_mutations = require_mut_flag || pinned.require_mutations;

    let pool = build_constant_pool(&base_snap, &cand_snap, &changed);
    let base_argv =
        prepare_driver_argv(&base_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let cand_argv =
        prepare_driver_argv(&cand_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;

    let mut base_drv = ProcessDriver::with_timeout(base_snap.clone(), base_argv, timeout);
    let mut cand_drv = ProcessDriver::with_timeout(cand_snap.clone(), cand_argv, timeout);

    let enforce_strict = strict || pinned.mode == EnforceMode::Enforce;
    let cfg = DiffConfig {
        seeds,
        parity: parity || enforce_strict,
        strict: enforce_strict,
        masks: pinned.masks.clone(),
        approved_diffs: pinned.approved_diffs.clone(),
        approval_rules: pinned.approval_rules.clone(),
        pinned_requests: pinned.triggered_requests(&changed),
        observed_files: observed_files.clone(),
        required_observations,
        constants: pool.clone(),
        changed_lines: flatten_changed_lines(&exec_changed_lines),
        require_changed_coverage: require_cov || enforce_strict,
        ..DiffConfig::default()
    };

    let report = run_diff(&mut base_drv, &mut cand_drv, &cfg);

    let (mutations_run, planted_total, planted_killed, planted_survived, planted_unknown) =
        if with_adversary && report.aa_verified && report.verdict != Verdict::ProbeFailed {
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
            (
                true,
                adv.total_faults,
                adv.killed_faults,
                adv.survived_faults,
                adv.unknown_faults,
            )
        } else {
            (false, 0, 0, 0, 0)
        };

    let _ = std::fs::remove_dir_all(&base_snap);
    let _ = std::fs::remove_dir_all(&cand_snap);

    let mut final_verdict = report.verdict;
    let mut final_detail = report.detail.clone();
    if planted_survived > 0 {
        final_verdict = Verdict::ParityFail;
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
            final_detail = issue;
        }
    }

    let evidence = EvidenceRecord {
        base_sha,
        candidate_tree_sha256: cand_tree_sha,
        driver_digest,
        policy_digest,
        request_budget: seeds,
        sequences_run: report.sequences_run,
        valid_comparisons: report.valid_comparisons,
        verdict: final_verdict.as_str().to_owned(),
        detail: final_detail.clone(),
        skeleton_ok: sk_ok,
        aa_verified: report.aa_verified,
        masks_proven: report.masks_proven,
        changed_lines_covered: report.changed_lines_covered,
        changed_lines_total: report.changed_lines_total,
        unapproved_diffs: report.unapproved_count(),
        missing_observations: report.missing_observations.clone(),
        mutations_run,
        planted_total,
        planted_killed,
        planted_survived,
        planted_unknown,
        witnesses: report.divergences.clone(),
    };

    if let Some(out_path) = evidence_out {
        save_evidence(Path::new(&out_path), &evidence)?;
    } else if !no_evidence && repo.join(".emi").is_dir() {
        save_evidence(&repo.join(ratchet::EVIDENCE_PATH), &evidence)?;
    }

    if as_json {
        let mut obj = report.to_json().as_object().cloned().unwrap();
        obj.insert(
            "verdict".to_owned(),
            Value::Str(final_verdict.as_str().to_owned()),
        );
        obj.insert("detail".to_owned(), Value::Str(final_detail.clone()));
        obj.insert("request_budget".to_owned(), Value::Int(seeds as i64));
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
        println!("{}", Value::Object(obj).pretty());
    } else {
        println!(
            "BEHAVIORAL DIFF  verdict={}  aa={}  masks={}  seqs={}  valid={}  changed_cov={}/{}  unapproved={}  mutations={}/{}(surv={},unk={})",
            final_verdict.as_str(),
            report.aa_verified,
            report.masks_proven,
            report.sequences_run,
            report.valid_comparisons,
            report.changed_lines_covered,
            report.changed_lines_total,
            report.unapproved_count(),
            planted_killed,
            planted_total,
            planted_survived,
            planted_unknown
        );
        for d in &report.divergences {
            let tag = match &d.approved_by {
                Some(by) => format!("APPROVED:{by}"),
                None => "UNAPPROVED".to_owned(),
            };
            println!("  [DIFF {} | {}] ops={}", d.id, tag, d.ops.len());
            for op in &d.ops {
                println!("    call: {}", op.to_json().canonical());
            }
            println!("    base:      {}", d.base_payload);
            println!("    candidate: {}", d.cand_payload);
        }
        if report.divergences.is_empty() || final_verdict == Verdict::Inconclusive {
            println!("  {final_detail}");
        }
    }

    Ok(final_verdict.exit_code())
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
    let timeout = timeout_arg(args);
    let as_json = has_flag(args, "--json");

    let pinned = load_pinned(&repo, &base_rev)?;
    let changed = git::changed_files(&repo, &base_rev, cand_rev.as_deref())?;
    let raw_changed_lines = git::changed_lines(&repo, &base_rev, cand_rev.as_deref())?;
    let base_snap = git::materialize_revision(&repo, &base_rev, "adv_base")?;
    let cand_snap = match cand_rev.as_deref() {
        Some(rev) => git::materialize_revision(&repo, rev, "adv_cand")?,
        None => git::materialize_worktree(&repo, "adv_cand")?,
    };
    let cand_tree_sha = git::tree_hash(&cand_snap)?;
    let exec_changed_lines = git::filter_executable_changed_lines(&cand_snap, &raw_changed_lines);
    let policy_digest = pinned.policy_digest();
    let driver_digest =
        compute_driver_digest(&base_snap, explicit_driver.as_deref(), pinned.driver.as_deref());
    let observed_files = merge_unique(&pinned.observed_files, &cli_obs_files);
    let require_mutations = require_mut_flag || pinned.require_mutations;

    let pool = build_constant_pool(&base_snap, &cand_snap, &changed);
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
        pinned_requests: pinned.triggered_requests(&changed),
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
        ev.mutations_run = true;
        ev.planted_total = adv_report.total_faults;
        ev.planted_killed = adv_report.killed_faults;
        ev.planted_survived = adv_report.survived_faults;
        ev.planted_unknown = adv_report.unknown_faults;
        if adv_report.survived_faults > 0 {
            ev.verdict = Verdict::ParityFail.as_str().to_owned();
            ev.detail = format!("{} planted AST mutation(s) survived", adv_report.survived_faults);
        } else if ev.verdict == Verdict::Inconclusive.as_str()
            && ev.unapproved_diffs == 0
            && ev.missing_observations.is_empty()
            && ev.valid_comparisons > 0
            && (ev.changed_lines_total == 0 || ev.changed_lines_covered > 0)
            && mut_issue.is_none()
        {
            ev.verdict = Verdict::Pass.as_str().to_owned();
            ev.detail = "parity and mutation evidence verified".to_owned();
        } else if let Some(issue) = &mut_issue {
            if ev.verdict == Verdict::Pass.as_str() {
                ev.verdict = Verdict::Inconclusive.as_str().to_owned();
                ev.detail = issue.clone();
            }
        }
        save_evidence(Path::new(&ev_path), &ev)?;
    }

    if as_json {
        let mut obj = adv_report.to_json().as_object().cloned().unwrap();
        obj.insert(
            "inconclusive".to_owned(),
            Value::Bool(mut_issue.is_some()),
        );
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
            let sk = skeleton::extract_dir(&repo)?;
            state.skeleton_digest = Some(sk.digest);
            save_local(&repo, &state)?;
            if as_json {
                println!("{}", state.to_json().pretty());
            } else {
                println!(
                    "RATCHET INITIALIZED  mode={}  require_mutations={}  observed_files={}  required_observations={}  skeleton={}  path={}",
                    state.mode.as_str(),
                    state.require_mutations,
                    state.observed_files.len(),
                    state.required_observations.len(),
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
                    "RATCHET (pinned@{base_rev})  mode={}  require_mutations={}  observed_files={}  required_observations={}  approved_diffs={}  rules={}  masks={}  incidents={}",
                    state.mode.as_str(),
                    state.require_mutations,
                    state.observed_files.len(),
                    state.required_observations.len(),
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
                "usage: emi ratchet lock-rule --op <GLOB> --when <PREDICATE> --expect <RELATION>"
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
            let mut state = load_pinned(&repo, &base_rev)?;
            state.approval_rules.push(ApprovalRule {
                op: op.clone(),
                when: when.clone(),
                expect: Some(expect.clone()),
            });
            save_local(&repo, &state)?;
            println!(
                "LOCKED RULE op={op} when=`{when}` expect=`{expect}` (commit {} to pin)",
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
            let (base_rev, protected) = resolve_base(&repo, args)?;
            let base_sha = git::rev_parse(&repo, &base_rev)?;
            let state = load_pinned(&repo, &base_rev)?;
            if state.mode == EnforceMode::Enforce && !protected {
                return Err("enforced stamp forbids bare HEAD baseline".to_owned());
            }
            let signing_key = signing_key_from_env_or_args(args)?;
            let explicit_driver = flag_val(args, "--driver");
            let explicit_evidence = flag_val(args, "--evidence");
            let force_fresh = has_flag(args, "--fresh");
            let strict_stamp = has_flag(args, "--strict") || state.mode == EnforceMode::Enforce;
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
                let _ = std::fs::remove_dir_all(&base_snap);
                let _ = std::fs::remove_dir_all(&cand_snap);
                (ev, true)
            } else {
                let changed = git::changed_files(&repo, &base_rev, None)?;
                let raw_changed_lines = git::changed_lines(&repo, &base_rev, None)?;
                let exec_changed_lines =
                    git::filter_executable_changed_lines(&cand_snap, &raw_changed_lines);

                let base_sk = skeleton::extract_dir(&base_snap)?;
                let cand_sk = skeleton::extract_dir(&cand_snap)?;
                let pinned_sk_ok = state
                    .skeleton_digest
                    .as_ref()
                    .is_none_or(|d| *d == base_sk.digest);
                let sk_diff = skeleton::compare(&base_sk, &cand_sk, false);
                let pool = build_constant_pool(&base_snap, &cand_snap, &changed);

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
                        strict: strict_stamp,
                        masks: state.masks.clone(),
                        approved_diffs: state.approved_diffs.clone(),
                        approval_rules: state.approval_rules.clone(),
                        pinned_requests: state.triggered_requests(&changed),
                        observed_files: state.observed_files.clone(),
                        required_observations: state.required_observations.clone(),
                        constants: pool.clone(),
                        changed_lines: flatten_changed_lines(&exec_changed_lines),
                        require_changed_coverage: strict_stamp,
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
                let ev = EvidenceRecord {
                    base_sha: base_sha.clone(),
                    candidate_tree_sha256: cand_tree_sha.clone(),
                    driver_digest: driver_digest.clone(),
                    policy_digest: policy_digest.clone(),
                    request_budget: seeds,
                    sequences_run: diff_rep.sequences_run,
                    valid_comparisons: diff_rep.valid_comparisons,
                    verdict: diff_rep.verdict.as_str().to_owned(),
                    detail: diff_rep.detail.clone(),
                    skeleton_ok: sk_diff.ok && pinned_sk_ok,
                    aa_verified: diff_rep.aa_verified,
                    masks_proven: diff_rep.masks_proven,
                    changed_lines_covered: diff_rep.changed_lines_covered,
                    changed_lines_total: diff_rep.changed_lines_total,
                    unapproved_diffs: diff_rep.unapproved_count(),
                    missing_observations: diff_rep.missing_observations,
                    mutations_run: diff_rep.aa_verified,
                    planted_total: adv_rep.total_faults,
                    planted_killed: adv_rep.killed_faults,
                    planted_survived: adv_rep.survived_faults,
                    planted_unknown: adv_rep.unknown_faults,
                    witnesses: diff_rep.divergences,
                };
                (ev, false)
            };

            let mut final_verdict = Verdict::from_str(&evidence.verdict);
            if !evidence.skeleton_ok || evidence.planted_survived > 0 {
                if final_verdict == Verdict::Pass {
                    final_verdict = Verdict::ParityFail;
                }
            } else if final_verdict == Verdict::Pass {
                if mutation_policy_issue(
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
    let (base_rev, protected) = resolve_base(&repo, args)?;
    let pinned = load_pinned(&repo, &base_rev)?;
    if pinned.mode == EnforceMode::Enforce && !protected {
        return Err("enforced climb forbids bare HEAD baseline".to_owned());
    }
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
    let exec_changed_lines = git::filter_executable_changed_lines(&cand_snap, &raw_changed_lines);

    let m_argv = split_command(&metric_cmd);
    overlay_base_metric_files(
        &base_snap,
        &cand_snap,
        &m_argv,
        explicit_metric_file.as_deref(),
    )?;

    let base_sk = skeleton::extract_dir(&base_snap)?;
    let cand_sk = skeleton::extract_dir(&cand_snap)?;
    let sk_diff = skeleton::compare(&base_sk, &cand_sk, true);
    let pool = build_constant_pool(&base_snap, &cand_snap, &changed);
    let observed_files = merge_unique(&pinned.observed_files, &cli_obs_files);
    let required_observations = merge_unique(&pinned.required_observations, &cli_req_obs);

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
            pinned_requests: pinned.triggered_requests(&changed),
            observed_files,
            required_observations,
            constants: pool.clone(),
            changed_lines: flatten_changed_lines(&exec_changed_lines),
            require_changed_coverage: true,
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

    let floor = FloorChecks {
        skeleton_ok: sk_diff.ok,
        aa_verified: diff_rep.aa_verified,
        parity_ok: parity_hard_ok,
        planted_bugs_killed: adv_ok,
        inconclusive_reason,
    };

    let (base_samples, cand_samples) =
        if floor.hard_floor_pass() && floor.inconclusive_reason.is_none() {
            measure_interleaved(&base_snap, &cand_snap, &m_argv, runs, 0x2026_1121)?
        } else {
            (Vec::new(), Vec::new())
        };

    let _ = std::fs::remove_dir_all(&base_snap);
    let _ = std::fs::remove_dir_all(&cand_snap);

    let report = evaluate_climb(floor, &base_samples, &cand_samples, direction, min_effect);

    if as_json {
        println!("{}", report.to_json().pretty());
    } else {
        println!(
            "CLIMB  verdict={}  base={:.4}  cand={:.4}  ratio={:.2}x  ci95=[{:.2}x,{:.2}x]  detail={}",
            report.verdict.as_str(),
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
