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
    DEFAULT_CALL_TIMEOUT_MS, ProcessDriver, StepOp, StepRequest, materialize_auto_driver,
    split_command,
};
use crate::ratchet::{
    ApprovalRule, Attestation, EnforceMode, IncidentSeed, append_attestation, load_pinned,
    save_local,
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
    println!("  emi diff [--repo PATH] [--base REV] [--cand REV] [--allow-head] [--driver CMD] [--seeds N] [--timeout-ms MS] [--parity] [--require-cov] [--json]");
    println!("  emi adversary [--repo PATH] [--base REV] [--cand REV] [--allow-head] [--driver CMD] [--max-faults N] [--seeds N] [--timeout-ms MS] [--json]");
    println!("  emi ratchet [init|status|approve <ID>|lock-rule --op GLOB --when PRED|remember --id ID --trigger GLOB --ops JSON|stamp] [--repo PATH] [--base REV] [--allow-head] [--mode off|observe|enforce] [--json]");
    println!("  emi climb --metric CMD [--metric-file PATH] [--repo PATH] [--base REV] [--allow-head] [--driver CMD] [--runs N] [--min-effect F] [--max-faults N] [--maximize] [--json]");
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
                    println!("  [{}] {}::{}  (cx={})", s.kind, s.file, s.signature, s.complexity);
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
    let cand_rev = flag_val(args, "--cand");
    let explicit_driver = flag_val(args, "--driver");
    let seeds = flag_val(args, "--seeds")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(48);
    let parity = has_flag(args, "--parity");
    let require_cov = has_flag(args, "--require-cov");
    let timeout = timeout_arg(args);
    let as_json = has_flag(args, "--json");

    let pinned = load_pinned(&repo, &base_rev)?;
    if pinned.mode == EnforceMode::Enforce && !protected {
        return Err("enforced mode forbids bare HEAD baseline; specify --base or EMI_BASE_REV".to_owned());
    }
    let changed = git::changed_files(&repo, &base_rev, cand_rev.as_deref())?;
    let changed_lines_map = git::changed_lines(&repo, &base_rev, cand_rev.as_deref())?;
    let base_snap = git::materialize_revision(&repo, &base_rev, "diff_base")?;
    let cand_snap = match cand_rev.as_deref() {
        Some(rev) => git::materialize_revision(&repo, rev, "diff_cand")?,
        None => git::materialize_worktree(&repo, "diff_cand")?,
    };

    if let Some(expected_sk) = &pinned.skeleton_digest {
        let actual_sk = skeleton::extract_dir(&base_snap)?.digest;
        if actual_sk != *expected_sk {
            let _ = std::fs::remove_dir_all(&base_snap);
            let _ = std::fs::remove_dir_all(&cand_snap);
            return Err(format!(
                "pinned skeleton_digest mismatch on base: expected {}, got {}",
                &expected_sk[..16],
                &actual_sk[..16]
            ));
        }
    }

    let pool = build_constant_pool(&base_snap, &cand_snap, &changed);
    let base_argv = prepare_driver_argv(&base_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let cand_argv = prepare_driver_argv(&cand_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;

    let mut base_drv = ProcessDriver::with_timeout(base_snap.clone(), base_argv, timeout);
    let mut cand_drv = ProcessDriver::with_timeout(cand_snap.clone(), cand_argv, timeout);

    let cfg = DiffConfig {
        seeds,
        parity: parity || pinned.mode == EnforceMode::Enforce,
        masks: pinned.masks.clone(),
        approved_diffs: pinned.approved_diffs.clone(),
        approval_rules: pinned.approval_rules.clone(),
        pinned_requests: pinned.triggered_requests(&changed),
        constants: pool,
        changed_lines: flatten_changed_lines(&changed_lines_map),
        require_changed_coverage: require_cov || pinned.mode == EnforceMode::Enforce,
        ..DiffConfig::default()
    };

    let report = run_diff(&mut base_drv, &mut cand_drv, &cfg);
    let _ = std::fs::remove_dir_all(&base_snap);
    let _ = std::fs::remove_dir_all(&cand_snap);

    if as_json {
        println!("{}", report.to_json().pretty());
    } else {
        println!(
            "BEHAVIORAL DIFF  verdict={}  aa={}  masks={}  seqs={}  changed_cov={}/{}  unapproved={}",
            report.verdict.as_str(),
            report.aa_verified,
            report.masks_proven,
            report.sequences_run,
            report.changed_lines_covered,
            report.changed_lines_total,
            report.unapproved_count()
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
        if report.divergences.is_empty() {
            println!("  {}", report.detail);
        }
    }

    Ok(report.verdict.exit_code())
}

fn cmd_adversary(args: &[String]) -> Result<u8, String> {
    let repo = repo_arg(args);
    let (base_rev, _protected) = resolve_base(&repo, args)?;
    let cand_rev = flag_val(args, "--cand");
    let explicit_driver = flag_val(args, "--driver");
    let seeds = flag_val(args, "--seeds")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(32);
    let max_faults = flag_val(args, "--max-faults")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(8);
    let timeout = timeout_arg(args);
    let as_json = has_flag(args, "--json");

    let pinned = load_pinned(&repo, &base_rev)?;
    let changed = git::changed_files(&repo, &base_rev, cand_rev.as_deref())?;
    let changed_lines_map = git::changed_lines(&repo, &base_rev, cand_rev.as_deref())?;
    let base_snap = git::materialize_revision(&repo, &base_rev, "adv_base")?;
    let cand_snap = match cand_rev.as_deref() {
        Some(rev) => git::materialize_revision(&repo, rev, "adv_cand")?,
        None => git::materialize_worktree(&repo, "adv_cand")?,
    };

    let pool = build_constant_pool(&base_snap, &cand_snap, &changed);
    let base_argv = prepare_driver_argv(&base_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let cand_argv = prepare_driver_argv(&cand_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let mut base_drv = ProcessDriver::with_timeout(base_snap.clone(), base_argv, timeout);
    let mut cand_drv = ProcessDriver::with_timeout(cand_snap.clone(), cand_argv, timeout);

    let diff_cfg = DiffConfig {
        seeds,
        parity: false,
        masks: pinned.masks.clone(),
        pinned_requests: pinned.triggered_requests(&changed),
        constants: pool.clone(),
        changed_lines: flatten_changed_lines(&changed_lines_map),
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
        &changed_lines_map,
        explicit_driver.as_deref(),
        pinned.driver.as_deref(),
        &pinned.masks,
        max_faults,
        &pool,
        timeout,
    )?;

    let _ = std::fs::remove_dir_all(&base_snap);
    let _ = std::fs::remove_dir_all(&cand_snap);

    if as_json {
        println!("{}", adv_report.to_json().pretty());
    } else {
        println!(
            "ADVERSARY  ok={}  killed={}/{}  survived={}  unknown={}",
            adv_report.ok(),
            adv_report.killed_faults,
            adv_report.total_faults,
            adv_report.survived_faults,
            adv_report.unknown_faults
        );
        for o in &adv_report.outcomes {
            println!("  [{}] {} ({})", o.status.as_str().to_uppercase(), o.fault_id, o.description);
            if let Some(dis) = &o.disambiguator {
                println!(
                    "    DISAMBIGUATOR: ops={} | cand={} | fault={}",
                    Value::Array(dis.witness_ops.iter().map(|w| w.to_json()).collect()).canonical(),
                    dis.candidate_output,
                    dis.fault_output
                );
            }
        }
    }

    Ok(if adv_report.ok() { 0 } else { 3 })
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
            let sk = skeleton::extract_dir(&repo)?;
            state.skeleton_digest = Some(sk.digest);
            save_local(&repo, &state)?;
            if as_json {
                println!("{}", state.to_json().pretty());
            } else {
                println!(
                    "RATCHET INITIALIZED  mode={}  skeleton={}  path={}",
                    state.mode.as_str(),
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
                    "RATCHET (pinned@{base_rev})  mode={}  approved_diffs={}  rules={}  masks={}  incidents={}",
                    state.mode.as_str(),
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
            let op = flag_val(args, "--op")
                .ok_or_else(|| "usage: emi ratchet lock-rule --op <GLOB> --when <PREDICATE>".to_owned())?;
            let when = flag_val(args, "--when").unwrap_or_else(|| "any".to_owned());
            let mut state = load_pinned(&repo, &base_rev)?;
            state.approval_rules.push(ApprovalRule {
                op: op.clone(),
                when: when.clone(),
            });
            save_local(&repo, &state)?;
            println!("LOCKED RULE op={op} when=`{when}` (commit {} to pin)", ratchet::RATCHET_PATH);
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
            let timeout = timeout_arg(args);
            let max_faults = flag_val(args, "--max-faults")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(6);

            let changed = git::changed_files(&repo, &base_rev, None)?;
            let changed_lines_map = git::changed_lines(&repo, &base_rev, None)?;
            let base_snap = git::materialize_revision(&repo, &base_rev, "stamp_base")?;
            let cand_snap = git::materialize_worktree(&repo, "stamp_cand")?;
            let cand_tree_sha = git::tree_hash(&cand_snap)?;

            let base_sk = skeleton::extract_dir(&base_snap)?;
            let cand_sk = skeleton::extract_dir(&cand_snap)?;
            let pinned_sk_ok = state
                .skeleton_digest
                .as_ref()
                .is_none_or(|d| *d == base_sk.digest);
            let sk_diff = skeleton::compare(&base_sk, &cand_sk, false);
            let pool = build_constant_pool(&base_snap, &cand_snap, &changed);

            let b_argv = prepare_driver_argv(&base_snap, None, state.driver.as_deref())?;
            let c_argv = prepare_driver_argv(&cand_snap, None, state.driver.as_deref())?;
            let mut b_drv = ProcessDriver::with_timeout(base_snap.clone(), b_argv, timeout);
            let mut c_drv = ProcessDriver::with_timeout(cand_snap.clone(), c_argv, timeout);
            let diff_rep = run_diff(
                &mut b_drv,
                &mut c_drv,
                &DiffConfig {
                    seeds: 24,
                    parity: state.mode == EnforceMode::Enforce,
                    masks: state.masks.clone(),
                    approved_diffs: state.approved_diffs.clone(),
                    approval_rules: state.approval_rules.clone(),
                    pinned_requests: state.triggered_requests(&changed),
                    constants: pool.clone(),
                    changed_lines: flatten_changed_lines(&changed_lines_map),
                    require_changed_coverage: state.mode == EnforceMode::Enforce,
                    ..DiffConfig::default()
                },
            );
            let adv_rep = if diff_rep.aa_verified {
                run_ast_adversary(
                    &cand_snap,
                    &mut c_drv,
                    &diff_rep.executed_requests,
                    &changed_lines_map,
                    None,
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

            let att = Attestation {
                base_sha,
                candidate_tree_sha256: cand_tree_sha,
                mode: state.mode,
                skeleton_ok: sk_diff.ok && pinned_sk_ok,
                aa_verified: diff_rep.aa_verified,
                changed_lines_covered: diff_rep.changed_lines_covered,
                changed_lines_total: diff_rep.changed_lines_total,
                unapproved_diffs: diff_rep.unapproved_count(),
                planted_killed: adv_rep.killed_faults,
                planted_survived: adv_rep.survived_faults,
                planted_unknown: adv_rep.unknown_faults,
                verdict: diff_rep.verdict.as_str().to_owned(),
            };
            let line = append_attestation(&repo, &att, signing_key.as_deref())?;
            println!("{line}");
            Ok(if state.mode == EnforceMode::Enforce {
                if !att.skeleton_ok || adv_rep.survived_faults > 0 {
                    3
                } else {
                    diff_rep.verdict.exit_code()
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
        .ok_or_else(|| "emi climb requires --metric <CMD> (or pinned metric in ratchet.json)".to_owned())?;
    let explicit_metric_file = flag_val(args, "--metric-file");
    let explicit_driver = flag_val(args, "--driver");
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
    let changed_lines_map = git::changed_lines(&repo, &base_rev, None)?;
    let base_snap = git::materialize_revision(&repo, &base_rev, "climb_base")?;
    let cand_snap = git::materialize_worktree(&repo, "climb_cand")?;

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

    let b_argv = prepare_driver_argv(&base_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let c_argv = prepare_driver_argv(&cand_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let mut b_drv = ProcessDriver::with_timeout(base_snap.clone(), b_argv, timeout);
    let mut c_drv = ProcessDriver::with_timeout(cand_snap.clone(), c_argv, timeout);

    let diff_rep = run_diff(
        &mut b_drv,
        &mut c_drv,
        &DiffConfig {
            seeds,
            parity: true,
            masks: pinned.masks.clone(),
            approved_diffs: pinned.approved_diffs.clone(),
            approval_rules: pinned.approval_rules.clone(),
            pinned_requests: pinned.triggered_requests(&changed),
            constants: pool.clone(),
            changed_lines: flatten_changed_lines(&changed_lines_map),
            require_changed_coverage: true,
            ..DiffConfig::default()
        },
    );

    let adv_ok = if diff_rep.aa_verified && diff_rep.verdict == Verdict::Pass {
        run_ast_adversary(
            &cand_snap,
            &mut c_drv,
            &diff_rep.executed_requests,
            &changed_lines_map,
            explicit_driver.as_deref(),
            pinned.driver.as_deref(),
            &pinned.masks,
            max_faults,
            &pool,
            timeout,
        )?
        .ok()
    } else {
        false
    };

    let (base_samples, cand_samples) =
        measure_interleaved(&base_snap, &cand_snap, &m_argv, runs, 0x2026_1121)?;

    let _ = std::fs::remove_dir_all(&base_snap);
    let _ = std::fs::remove_dir_all(&cand_snap);

    let floor = FloorChecks {
        skeleton_ok: sk_diff.ok,
        aa_verified: diff_rep.aa_verified,
        parity_ok: diff_rep.verdict == Verdict::Pass,
        planted_bugs_killed: adv_ok,
    };
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
            report.ok, report.seeds_run, report.worlds_verified, report.effectful_worlds, report.digest
        );
        if let (Some(fs), Some(why)) = (report.failed_seed, &report.failure) {
            println!("  FAILED SEED {fs}: {why}");
        }
    }
    Ok(if report.ok { 0 } else { 3 })
}
