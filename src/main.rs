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

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::adversary::{PlantedFault, prove_oracle, synthesize_source_faults};
use crate::climb::{Direction, FloorChecks, evaluate_climb, measure_command};
use crate::diff::{DiffConfig, Verdict, run_diff};
use crate::json::Value;
use crate::protocol::{ProcessDriver, materialize_auto_driver, split_command};
use crate::ratchet::{Attestation, EnforceMode, IncidentSeed, append_attestation, load_pinned, save_local};

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
    println!("  emi skeleton [extract|check] [--repo PATH] [--base REV] [--forbid-nondet] [--json]");
    println!("  emi diff [--repo PATH] [--base REV] [--cand REV] [--driver CMD] [--seeds N] [--parity] [--json]");
    println!("  emi adversary [--repo PATH] [--base REV] [--cand REV] [--driver CMD] [--max-faults N] [--seeds N] [--json]");
    println!("  emi ratchet [init|status|approve <ID>|stamp] [--repo PATH] [--base REV] [--mode off|observe|enforce] [--json]");
    println!("  emi climb --metric CMD [--repo PATH] [--base REV] [--driver CMD] [--runs N] [--maximize] [--json]");
    println!("  emi sim [--seeds N] [--seed U64] [--json]");
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
            let base_rev = flag_val(args, "--base").unwrap_or_else(|| "HEAD".to_owned());
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
    let base_rev = flag_val(args, "--base").unwrap_or_else(|| "HEAD".to_owned());
    let cand_rev = flag_val(args, "--cand");
    let explicit_driver = flag_val(args, "--driver");
    let seeds = flag_val(args, "--seeds")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(32);
    let parity = has_flag(args, "--parity");
    let as_json = has_flag(args, "--json");

    let pinned = load_pinned(&repo, &base_rev)?;
    let changed = git::changed_files(&repo, &base_rev, cand_rev.as_deref())?;
    let base_snap = git::materialize_revision(&repo, &base_rev, "diff_base")?;
    let cand_snap = match cand_rev.as_deref() {
        Some(rev) => git::materialize_revision(&repo, rev, "diff_cand")?,
        None => git::materialize_worktree(&repo, "diff_cand")?,
    };

    let base_argv = prepare_driver_argv(&base_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let cand_argv = prepare_driver_argv(&cand_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;

    let mut base_drv = ProcessDriver::new(base_snap.clone(), base_argv);
    let mut cand_drv = ProcessDriver::new(cand_snap.clone(), cand_argv);

    let cfg = DiffConfig {
        seeds,
        parity: parity || pinned.mode == EnforceMode::Enforce,
        masks: pinned.masks.clone(),
        approved_diffs: pinned.approved_diffs.clone(),
        pinned_requests: pinned.triggered_requests(&changed),
        ..DiffConfig::default()
    };

    let report = run_diff(&mut base_drv, &mut cand_drv, &cfg);
    let _ = std::fs::remove_dir_all(&base_snap);
    let _ = std::fs::remove_dir_all(&cand_snap);

    if as_json {
        println!("{}", report.to_json().pretty());
    } else {
        println!(
            "BEHAVIORAL DIFF  verdict={}  aa={}  masks={}  seqs={}  union_cov={}  unapproved={}",
            report.verdict.as_str(),
            report.aa_verified,
            report.masks_proven,
            report.sequences_run,
            report.union_coverage_points,
            report.unapproved_count()
        );
        for d in &report.divergences {
            let tag = if d.approved { "APPROVED" } else { "UNAPPROVED" };
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
    let base_rev = flag_val(args, "--base").unwrap_or_else(|| "HEAD".to_owned());
    let cand_rev = flag_val(args, "--cand");
    let explicit_driver = flag_val(args, "--driver");
    let seeds = flag_val(args, "--seeds")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(24);
    let max_faults = flag_val(args, "--max-faults")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(8);
    let as_json = has_flag(args, "--json");

    let pinned = load_pinned(&repo, &base_rev)?;
    let changed = git::changed_files(&repo, &base_rev, cand_rev.as_deref())?;
    let base_snap = git::materialize_revision(&repo, &base_rev, "adv_base")?;
    let cand_snap = match cand_rev.as_deref() {
        Some(rev) => git::materialize_revision(&repo, rev, "adv_cand")?,
        None => git::materialize_worktree(&repo, "adv_cand")?,
    };

    let base_argv = prepare_driver_argv(&base_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let cand_argv = prepare_driver_argv(&cand_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let mut base_drv = ProcessDriver::new(base_snap.clone(), base_argv);
    let mut cand_drv = ProcessDriver::new(cand_snap.clone(), cand_argv);

    let diff_cfg = DiffConfig {
        seeds,
        parity: false,
        masks: pinned.masks.clone(),
        pinned_requests: pinned.triggered_requests(&changed),
        ..DiffConfig::default()
    };
    let diff_rep = run_diff(&mut base_drv, &mut cand_drv, &diff_cfg);
    if !diff_rep.aa_verified {
        let _ = std::fs::remove_dir_all(&base_snap);
        let _ = std::fs::remove_dir_all(&cand_snap);
        return Err(format!("cannot prove oracle: {}", diff_rep.detail));
    }

    let source_faults = synthesize_source_faults(&cand_snap, &changed, max_faults);
    let mut fault_dirs = Vec::with_capacity(source_faults.len());
    let mut planted = Vec::with_capacity(source_faults.len());

    for (idx, sf) in source_faults.iter().enumerate() {
        let fdir = std::env::temp_dir().join(format!(
            "emi_fault_{}_{}",
            std::process::id(),
            idx
        ));
        if fdir.exists() {
            let _ = std::fs::remove_dir_all(&fdir);
        }
        git::copy_dir_filtered(&cand_snap, &fdir)?;
        std::fs::write(fdir.join(&sf.rel_file), &sf.mutated_source)
            .map_err(|e| format!("write fault {}: {e}", sf.rel_file))?;
        let fav = prepare_driver_argv(&fdir, explicit_driver.as_deref(), pinned.driver.as_deref())?;
        planted.push(PlantedFault {
            id: sf.id.clone(),
            description: sf.description.clone(),
            driver: Box::new(ProcessDriver::new(fdir.clone(), fav)),
        });
        fault_dirs.push(fdir);
    }

    let adv_report = prove_oracle(
        &mut cand_drv,
        &diff_rep.executed_requests,
        &pinned.masks,
        planted,
        16,
    )?;

    let _ = std::fs::remove_dir_all(&base_snap);
    let _ = std::fs::remove_dir_all(&cand_snap);
    for d in fault_dirs {
        let _ = std::fs::remove_dir_all(d);
    }

    if as_json {
        println!("{}", adv_report.to_json().pretty());
    } else {
        println!(
            "ADVERSARY  ok={}  killed={}/{}  survived={}",
            adv_report.ok(),
            adv_report.killed_faults,
            adv_report.total_faults,
            adv_report.survived_faults
        );
        for o in &adv_report.outcomes {
            let status = if o.killed { "KILLED" } else { "SURVIVED" };
            println!("  [{status}] {} ({})", o.fault_id, o.description);
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
    let base_rev = flag_val(args, "--base").unwrap_or_else(|| "HEAD".to_owned());
    let as_json = has_flag(args, "--json");

    match sub {
        "init" => {
            let mut state = load_pinned(&repo, &base_rev).unwrap_or_default();
            if let Some(m) = flag_val(args, "--mode") {
                state.mode = EnforceMode::from_str(&m);
            }
            if let Some(d) = flag_val(args, "--driver") {
                state.driver = Some(d);
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
            let state = load_pinned(&repo, &base_rev)?;
            if as_json {
                println!("{}", state.to_json().pretty());
            } else {
                println!(
                    "RATCHET (pinned@{base_rev})  mode={}  approved_diffs={}  masks={}  incidents={}",
                    state.mode.as_str(),
                    state.approved_diffs.len(),
                    state.masks.len(),
                    state.incidents.len()
                );
            }
            Ok(0)
        }
        "approve" => {
            let id = args
                .get(1)
                .ok_or_else(|| "usage: emi ratchet approve <DIFF_ID>".to_owned())?;
            let mut state = load_pinned(&repo, &base_rev)?;
            state.approved_diffs.insert(id.clone());
            save_local(&repo, &state)?;
            println!("APPROVED DIFF {id} (commit {} to pin)", ratchet::RATCHET_PATH);
            Ok(0)
        }
        "remember" => {
            let id = flag_val(args, "--id").unwrap_or_else(|| "incident".to_owned());
            let trigger = flag_val(args, "--trigger").unwrap_or_else(|| "*".to_owned());
            let seed = flag_val(args, "--seed")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let mut state = load_pinned(&repo, &base_rev)?;
            state.incidents.push(IncidentSeed {
                id: id.clone(),
                triggers: vec![trigger],
                seed,
                ops: Vec::new(),
            });
            save_local(&repo, &state)?;
            println!("REMEMBERED INCIDENT {id} (seed={seed})");
            Ok(0)
        }
        "stamp" => {
            let base_sha = git::rev_parse(&repo, &base_rev)?;
            let state = load_pinned(&repo, &base_rev)?;
            let base_snap = git::materialize_revision(&repo, &base_rev, "stamp_base")?;
            let cand_snap = git::materialize_worktree(&repo, "stamp_cand")?;
            let sk_diff = skeleton::compare(
                &skeleton::extract_dir(&base_snap)?,
                &skeleton::extract_dir(&cand_snap)?,
                false,
            );
            let b_argv = prepare_driver_argv(&base_snap, None, state.driver.as_deref())?;
            let c_argv = prepare_driver_argv(&cand_snap, None, state.driver.as_deref())?;
            let mut b_drv = ProcessDriver::new(base_snap.clone(), b_argv);
            let mut c_drv = ProcessDriver::new(cand_snap.clone(), c_argv);
            let diff_rep = run_diff(
                &mut b_drv,
                &mut c_drv,
                &DiffConfig {
                    seeds: 16,
                    parity: state.mode == EnforceMode::Enforce,
                    masks: state.masks.clone(),
                    approved_diffs: state.approved_diffs.clone(),
                    ..DiffConfig::default()
                },
            );
            let _ = std::fs::remove_dir_all(&base_snap);
            let _ = std::fs::remove_dir_all(&cand_snap);
            let att = Attestation {
                base_sha,
                candidate: "worktree".to_owned(),
                mode: state.mode,
                skeleton_ok: sk_diff.ok,
                aa_verified: diff_rep.aa_verified,
                unapproved_diffs: diff_rep.unapproved_count(),
                planted_killed: 0,
                planted_total: 0,
                verdict: diff_rep.verdict.as_str().to_owned(),
            };
            let line = append_attestation(&repo, &att)?;
            println!("{line}");
            Ok(if state.mode == EnforceMode::Enforce {
                diff_rep.verdict.exit_code()
            } else {
                0
            })
        }
        other => Err(format!("unknown ratchet subcommand `{other}`")),
    }
}

fn cmd_climb(args: &[String]) -> Result<u8, String> {
    let repo = repo_arg(args);
    let base_rev = flag_val(args, "--base").unwrap_or_else(|| "HEAD".to_owned());
    let metric_cmd = flag_val(args, "--metric")
        .ok_or_else(|| "emi climb requires --metric <CMD>".to_owned())?;
    let explicit_driver = flag_val(args, "--driver");
    let runs = flag_val(args, "--runs")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(5);
    let seeds = flag_val(args, "--seeds")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(24);
    let direction = if has_flag(args, "--maximize") {
        Direction::Maximize
    } else {
        Direction::Minimize
    };
    let as_json = has_flag(args, "--json");

    let pinned = load_pinned(&repo, &base_rev)?;
    let base_snap = git::materialize_revision(&repo, &base_rev, "climb_base")?;
    let cand_snap = git::materialize_worktree(&repo, "climb_cand")?;

    let sk_diff = skeleton::compare(
        &skeleton::extract_dir(&base_snap)?,
        &skeleton::extract_dir(&cand_snap)?,
        true,
    );
    let b_argv = prepare_driver_argv(&base_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let c_argv = prepare_driver_argv(&cand_snap, explicit_driver.as_deref(), pinned.driver.as_deref())?;
    let mut b_drv = ProcessDriver::new(base_snap.clone(), b_argv);
    let mut c_drv = ProcessDriver::new(cand_snap.clone(), c_argv);

    let diff_rep = run_diff(
        &mut b_drv,
        &mut c_drv,
        &DiffConfig {
            seeds,
            parity: true,
            masks: pinned.masks.clone(),
            approved_diffs: pinned.approved_diffs.clone(),
            ..DiffConfig::default()
        },
    );

    let m_argv = split_command(&metric_cmd);
    let base_samples = measure_command(&base_snap, &m_argv, runs)?;
    let cand_samples = measure_command(&cand_snap, &m_argv, runs)?;

    let _ = std::fs::remove_dir_all(&base_snap);
    let _ = std::fs::remove_dir_all(&cand_snap);

    let floor = FloorChecks {
        skeleton_ok: sk_diff.ok,
        aa_verified: diff_rep.aa_verified,
        parity_ok: diff_rep.verdict == Verdict::Pass,
        planted_bugs_killed: true,
    };
    let report = evaluate_climb(floor, &base_samples, &cand_samples, direction);

    if as_json {
        println!("{}", report.to_json().pretty());
    } else {
        println!(
            "CLIMB  verdict={}  base={:.4}  cand={:.4}  ratio={:.2}x  detail={}",
            report.verdict.as_str(),
            report.base_median,
            report.cand_median,
            report.improvement_ratio,
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
    let as_json = has_flag(args, "--json");

    let first = sim::run_simulation(seed_start, count);
    let second = sim::run_simulation(seed_start, count);
    if first.digest != second.digest {
        return Err(format!(
            "simulation meta-determinism violated: {} != {}",
            first.digest, second.digest
        ));
    }

    if as_json {
        println!("{}", first.to_json().pretty());
    } else {
        println!(
            "SIM  ok={}  seeds={}  worlds={}  digest={}",
            first.ok, first.seeds_run, first.worlds_verified, first.digest
        );
        if let (Some(fs), Some(why)) = (first.failed_seed, &first.failure) {
            println!("  FAILED SEED {fs}: {why}");
        }
    }
    Ok(if first.ok { 0 } else { 3 })
}
