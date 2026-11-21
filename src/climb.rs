use std::path::Path;
use std::process::Command;

use crate::json::Value;
use crate::prng::Prng;

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

#[derive(Clone, Debug)]
pub struct FloorChecks {
    pub skeleton_ok: bool,
    pub aa_verified: bool,
    pub parity_ok: bool,
    pub planted_bugs_killed: bool,
    pub inconclusive_reason: Option<String>,
}

impl FloorChecks {
    pub fn hard_floor_pass(&self) -> bool {
        self.skeleton_ok && self.aa_verified && self.parity_ok && self.planted_bugs_killed
    }
}

#[derive(Clone, Debug)]
pub struct ClimbReport {
    pub verdict: ClimbVerdict,
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
            ("skeleton_ok", Value::Bool(self.floor.skeleton_ok)),
            ("aa_verified", Value::Bool(self.floor.aa_verified)),
            ("parity_ok", Value::Bool(self.floor.parity_ok)),
            (
                "planted_bugs_killed",
                Value::Bool(self.floor.planted_bugs_killed),
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
        return ClimbReport {
            verdict: ClimbVerdict::RejectFloor,
            floor,
            base_median,
            cand_median,
            improvement_ratio,
            ci95_low,
            ci95_high,
            min_effect,
            pairs,
            detail: "hard correctness floor failed; metric gain discarded".to_owned(),
        };
    }

    if let Some(reason) = floor.inconclusive_reason.clone() {
        return ClimbReport {
            verdict: ClimbVerdict::Inconclusive,
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
) -> Result<(Vec<f64>, Vec<f64>), String> {
    assert!(!argv.is_empty() && pairs > 0 && pairs <= 64);
    let mut prng = Prng::new(seed);
    let mut base_samples = Vec::with_capacity(pairs);
    let mut cand_samples = Vec::with_capacity(pairs);
    for _ in 0..pairs {
        if prng.chance(1, 2) {
            base_samples.push(measure_once(base_dir, argv)?);
            cand_samples.push(measure_once(cand_dir, argv)?);
        } else {
            cand_samples.push(measure_once(cand_dir, argv)?);
            base_samples.push(measure_once(base_dir, argv)?);
        }
    }
    Ok((base_samples, cand_samples))
}

fn measure_once(workdir: &Path, argv: &[String]) -> Result<f64, String> {
    let out = Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(workdir)
        .output()
        .map_err(|e| format!("metric command failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "metric command exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let val = text
        .parse::<f64>()
        .map_err(|_| format!("metric command must print a float, got: `{text}`"))?;
    if !val.is_finite() {
        return Err("metric command returned non-finite float".to_owned());
    }
    Ok(val)
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
