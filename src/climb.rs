use std::path::Path;
use std::process::Command;

use crate::json::{self, Value};
use crate::prng::Prng;
use crate::protocol;
use crate::sha256;

const BOOTSTRAP_RESAMPLES: usize = 2000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Minimize,
    Maximize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClimbVerdict {
    Accept,
    RejectFloor,
    RejectMetric,
    Inconclusive,
}

impl ClimbVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            ClimbVerdict::Accept => "accept",
            ClimbVerdict::RejectFloor => "reject_floor",
            ClimbVerdict::RejectMetric => "reject_metric",
            ClimbVerdict::Inconclusive => "inconclusive",
        }
    }

    pub fn exit_code(self) -> u8 {
        match self {
            ClimbVerdict::Accept => 0,
            ClimbVerdict::RejectFloor => 3,
            ClimbVerdict::RejectMetric => 6,
            ClimbVerdict::Inconclusive => 7,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct BenchSample {
    pub metric: f64,
    pub output_digest: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FloorChecks {
    pub skeleton_ok: bool,
    pub aa_verified: bool,
    pub parity_ok: bool,
    pub planted_bugs_killed: bool,
    pub benchmark_output_ok: bool,
    pub benchmark_output_missing: bool,
    pub inconclusive_reason: Option<String>,
}

impl FloorChecks {
    pub fn hard_floor_pass(&self) -> bool {
        self.skeleton_ok
            && self.aa_verified
            && self.parity_ok
            && self.planted_bugs_killed
            && self.benchmark_output_ok
            && !self.benchmark_output_missing
    }
}

#[derive(Clone, Debug)]
pub struct ClimbReport {
    pub verdict: ClimbVerdict,
    pub blocker: String,
    pub next_action: String,
    pub floor: FloorChecks,
    pub base_median: f64,
    pub cand_median: f64,
    pub improvement_ratio: f64,
    pub ci95_low: f64,
    pub ci95_high: f64,
    pub min_effect: f64,
    pub pairs: usize,
    pub detail: String,
}

impl ClimbReport {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("verdict", Value::Str(self.verdict.as_str().to_owned())),
            ("blocker", Value::Str(self.blocker.clone())),
            ("next_action", Value::Str(self.next_action.clone())),
            ("skeleton_ok", Value::Bool(self.floor.skeleton_ok)),
            ("aa_verified", Value::Bool(self.floor.aa_verified)),
            ("parity_ok", Value::Bool(self.floor.parity_ok)),
            (
                "planted_bugs_killed",
                Value::Bool(self.floor.planted_bugs_killed),
            ),
            (
                "benchmark_output_ok",
                Value::Bool(self.floor.benchmark_output_ok),
            ),
            (
                "inconclusive_reason",
                self.floor
                    .inconclusive_reason
                    .as_ref()
                    .map_or(Value::Null, |r| Value::Str(r.clone())),
            ),
            ("base_median", Value::Float(self.base_median)),
            ("cand_median", Value::Float(self.cand_median)),
            ("improvement_ratio", Value::Float(self.improvement_ratio)),
            ("ci95_low", Value::Float(self.ci95_low)),
            ("ci95_high", Value::Float(self.ci95_high)),
            ("min_effect", Value::Float(self.min_effect)),
            ("pairs", Value::Int(self.pairs as i64)),
            ("detail", Value::Str(self.detail.clone())),
        ])
    }
}

pub fn classify_benchmark_parity(
    base_samples: &[BenchSample],
    cand_samples: &[BenchSample],
) -> Result<(), (&'static str, String)> {
    if base_samples.is_empty() || cand_samples.is_empty() {
        return Ok(());
    }
    if base_samples.iter().any(|s| s.output_digest.is_none())
        || cand_samples.iter().any(|s| s.output_digest.is_none())
    {
        return Err((
            "benchmark_missing_output",
            "benchmark printed only a time with no correctness output; emit {\"metric\": <num>, \"output\": <checksum>} or an output line alongside the timing metric"
                .to_owned(),
        ));
    }
    let b0 = &base_samples[0].output_digest;
    let c0 = &cand_samples[0].output_digest;
    for s in &base_samples[1..] {
        if &s.output_digest != b0 {
            return Err((
                "benchmark_output_mismatch",
                "benchmark output on base was nondeterministic across runs".to_owned(),
            ));
        }
    }
    for s in &cand_samples[1..] {
        if &s.output_digest != c0 {
            return Err((
                "benchmark_output_mismatch",
                "benchmark output on candidate was nondeterministic across runs".to_owned(),
            ));
        }
    }
    if b0 != c0 {
        return Err((
            "benchmark_output_mismatch",
            format!(
                "benchmark output parity failed: base ({}) != candidate ({})",
                b0.as_deref().unwrap_or("none"),
                c0.as_deref().unwrap_or("none")
            ),
        ));
    }
    Ok(())
}

pub fn verify_benchmark_parity(
    base_samples: &[BenchSample],
    cand_samples: &[BenchSample],
) -> Result<(), String> {
    classify_benchmark_parity(base_samples, cand_samples).map_err(|(_, msg)| msg)
}

pub fn evaluate_climb(
    floor: FloorChecks,
    base_samples: &[f64],
    cand_samples: &[f64],
    direction: Direction,
    min_effect: f64,
) -> ClimbReport {
    let (base_median, cand_median, pair_ratios, improvement_ratio, ci95_low, ci95_high) =
        if !base_samples.is_empty() && base_samples.len() == cand_samples.len() {
            let bm = median(base_samples);
            let cm = median(cand_samples);
            let ratios: Vec<f64> = base_samples
                .iter()
                .zip(cand_samples.iter())
                .map(|(&b, &c)| ratio_of(b, c, direction))
                .collect();
            let imp = median(&ratios);
            let (lo, hi) = bootstrap_ci95(&ratios, 0x2026_1121_0001);
            (bm, cm, ratios, imp, lo, hi)
        } else {
            (0.0, 0.0, Vec::new(), 1.0, 1.0, 1.0)
        };
    let wins = pair_ratios.iter().filter(|&&r| r > 1.0).count();
    let pairs = pair_ratios.len();

    if !floor.hard_floor_pass() {
        let (blocker, detail) = if floor.benchmark_output_missing {
            (
                "benchmark_missing_output",
                "benchmark printed only a time with no correctness output; emit {\"metric\": <num>, \"output\": <checksum>} or an output line alongside the timing metric",
            )
        } else if !floor.benchmark_output_ok {
            (
                "benchmark_output_mismatch",
                "benchmark output parity failed: base and candidate benchmark outputs disagreed; metric gain discarded",
            )
        } else if !floor.skeleton_ok {
            (
                "skeleton_break",
                "public API or nondeterminism floor failed; metric gain discarded",
            )
        } else if !floor.aa_verified {
            (
                "nondeterministic",
                "A/A determinism check failed; metric gain discarded",
            )
        } else if !floor.parity_ok {
            (
                "regression",
                "behavioral parity failed; metric gain discarded",
            )
        } else {
            (
                "surviving_mutant",
                "planted AST bug survived; metric gain discarded",
            )
        };
        return ClimbReport {
            verdict: ClimbVerdict::RejectFloor,
            blocker: blocker.to_owned(),
            next_action: "fix_regression_and_replay".to_owned(),
            floor,
            base_median,
            cand_median,
            improvement_ratio,
            ci95_low,
            ci95_high,
            min_effect,
            pairs,
            detail: detail.to_owned(),
        };
    }

    if let Some(reason) = floor.inconclusive_reason.clone() {
        return ClimbReport {
            verdict: ClimbVerdict::Inconclusive,
            blocker: "inconclusive_floor".to_owned(),
            next_action: "add_required_observation".to_owned(),
            floor,
            base_median,
            cand_median,
            improvement_ratio,
            ci95_low,
            ci95_high,
            min_effect,
            pairs,
            detail: format!("correctness evidence inconclusive ({reason}); speedup not accepted"),
        };
    }

    if pairs == 0 {
        return ClimbReport {
            verdict: ClimbVerdict::Inconclusive,
            blocker: "zero_comparisons".to_owned(),
            next_action: "increase_coverage_or_driver_ops".to_owned(),
            floor,
            base_median,
            cand_median,
            improvement_ratio,
            ci95_low,
            ci95_high,
            min_effect,
            pairs,
            detail: "no metric pairs collected".to_owned(),
        };
    }

    let threshold = 1.0 + min_effect.max(0.0);
    let significant = ci95_low > 1.0 && wins * 2 > pairs;
    let meets_effect = improvement_ratio >= threshold;

    if significant && meets_effect {
        ClimbReport {
            verdict: ClimbVerdict::Accept,
            blocker: "none".to_owned(),
            next_action: "keep_optimization".to_owned(),
            floor,
            base_median,
            cand_median,
            improvement_ratio,
            ci95_low,
            ci95_high,
            min_effect,
            pairs,
            detail: format!(
                "floor held and metric significantly improved ({base_median:.4} -> {cand_median:.4}, {improvement_ratio:.2}x, 95% CI [{ci95_low:.2}x, {ci95_high:.2}x])"
            ),
        }
    } else {
        ClimbReport {
            verdict: ClimbVerdict::RejectMetric,
            blocker: "insufficient_speedup".to_owned(),
            next_action: "revert_or_optimize_further".to_owned(),
            floor,
            base_median,
            cand_median,
            improvement_ratio,
            ci95_low,
            ci95_high,
            min_effect,
            pairs,
            detail: format!(
                "floor held but metric gain not significant or below {:.1}% threshold (ratio={improvement_ratio:.3}x, 95% CI [{ci95_low:.3}x, {ci95_high:.3}x])",
                min_effect * 100.0
            ),
        }
    }
}

fn ratio_of(b: f64, c: f64, direction: Direction) -> f64 {
    match direction {
        Direction::Minimize => {
            if c > 0.0 {
                b / c
            } else {
                1.0
            }
        }
        Direction::Maximize => {
            if b > 0.0 {
                c / b
            } else {
                1.0
            }
        }
    }
}

fn bootstrap_ci95(ratios: &[f64], seed: u64) -> (f64, f64) {
    let n = ratios.len();
    let mut prng = Prng::new(seed);
    let mut boot_medians = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    let mut draw = vec![0.0; n];
    for _ in 0..BOOTSTRAP_RESAMPLES {
        for slot in &mut draw {
            *slot = ratios[prng.range_usize(n)];
        }
        boot_medians.push(median(&draw));
    }
    boot_medians.sort_by(|a, b| a.total_cmp(b));
    let lo_idx = (BOOTSTRAP_RESAMPLES as f64 * 0.025) as usize;
    let hi_idx = ((BOOTSTRAP_RESAMPLES as f64 * 0.975) as usize).min(BOOTSTRAP_RESAMPLES - 1);
    (boot_medians[lo_idx], boot_medians[hi_idx])
}

pub fn measure_interleaved(
    base_dir: &Path,
    cand_dir: &Path,
    argv: &[String],
    pairs: usize,
    seed: u64,
) -> Result<(Vec<BenchSample>, Vec<BenchSample>), String> {
    measure_interleaved_with_timeout(
        base_dir,
        cand_dir,
        argv,
        pairs,
        seed,
        std::time::Duration::from_secs(60),
    )
}

pub fn measure_interleaved_with_timeout(
    base_dir: &Path,
    cand_dir: &Path,
    argv: &[String],
    pairs: usize,
    seed: u64,
    timeout: std::time::Duration,
) -> Result<(Vec<BenchSample>, Vec<BenchSample>), String> {
    assert!(!argv.is_empty() && pairs > 0 && pairs <= 64);
    let mut prng = Prng::new(seed);
    let mut base_samples = Vec::with_capacity(pairs);
    let mut cand_samples = Vec::with_capacity(pairs);
    for _ in 0..pairs {
        if prng.chance(1, 2) {
            base_samples.push(measure_once(base_dir, argv, timeout)?);
            cand_samples.push(measure_once(cand_dir, argv, timeout)?);
        } else {
            cand_samples.push(measure_once(cand_dir, argv, timeout)?);
            base_samples.push(measure_once(base_dir, argv, timeout)?);
        }
    }
    Ok((base_samples, cand_samples))
}

pub fn parse_bench_output(raw: &str) -> Result<BenchSample, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("metric command printed empty output".to_owned());
    }
    if trimmed.starts_with('{') {
        let parsed = json::parse(trimmed)?;
        let metric = match parsed.get("metric") {
            Some(Value::Float(f)) if f.is_finite() => *f,
            Some(Value::Int(i)) => *i as f64,
            _ => return Err("metric JSON must contain finite numeric `metric` field".to_owned()),
        };
        let out_val = parsed
            .get("output")
            .or_else(|| parsed.get("checksum"))
            .or_else(|| parsed.get("result"));
        let output_digest = out_val.map(|v| sha256::short_hex(v.canonical().as_bytes()));
        return Ok(BenchSample {
            metric,
            output_digest,
        });
    }
    let mut lines = trimmed.lines();
    let first_line = lines.next().unwrap_or("").trim();
    let rest_lines: Vec<&str> = lines.collect();
    if let Ok(val) = first_line.parse::<f64>() {
        if !val.is_finite() {
            return Err("metric command returned non-finite float".to_owned());
        }
        let rest_joined = rest_lines.join("\n");
        let output_digest = if rest_joined.trim().is_empty() {
            None
        } else {
            Some(sha256::short_hex(rest_joined.trim().as_bytes()))
        };
        return Ok(BenchSample {
            metric: val,
            output_digest,
        });
    }
    let mut toks = first_line.splitn(2, char::is_whitespace);
    let head = toks.next().unwrap_or("");
    let tail = toks.next().unwrap_or("").trim();
    let val = head
        .parse::<f64>()
        .map_err(|_| format!("metric command must print a float or JSON, got: `{trimmed}`"))?;
    if !val.is_finite() {
        return Err("metric command returned non-finite float".to_owned());
    }
    let mut payload = tail.to_owned();
    if !rest_lines.is_empty() {
        if !payload.is_empty() {
            payload.push('\n');
        }
        payload.push_str(&rest_lines.join("\n"));
    }
    let output_digest = if payload.trim().is_empty() {
        None
    } else {
        Some(sha256::short_hex(payload.trim().as_bytes()))
    };
    Ok(BenchSample {
        metric: val,
        output_digest,
    })
}

fn measure_once(
    workdir: &Path,
    argv: &[String],
    timeout: std::time::Duration,
) -> Result<BenchSample, String> {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).current_dir(workdir);
    for (k, _) in std::env::vars() {
        if k.to_ascii_uppercase().starts_with("EMI") {
            cmd.env_remove(&k);
        }
    }
    let out = protocol::run_command_with_timeout(&mut cmd, timeout)
        .map_err(|e| format!("metric command failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "metric command exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_bench_output(&text)
}

fn median(samples: &[f64]) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        sorted[mid]
    } else {
        (sorted[mid - 1] + sorted[mid]) * 0.5
    }
}
