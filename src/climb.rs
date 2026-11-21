use std::path::Path;
use std::process::Command;

use crate::json::Value;

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
}

impl ClimbVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            ClimbVerdict::Accept => "accept",
            ClimbVerdict::RejectFloor => "reject_floor",
            ClimbVerdict::RejectMetric => "reject_metric",
        }
    }

    pub fn exit_code(self) -> u8 {
        match self {
            ClimbVerdict::Accept => 0,
            ClimbVerdict::RejectFloor => 3,
            ClimbVerdict::RejectMetric => 6,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FloorChecks {
    pub skeleton_ok: bool,
    pub aa_verified: bool,
    pub parity_ok: bool,
    pub planted_bugs_killed: bool,
}

impl FloorChecks {
    pub fn all_pass(&self) -> bool {
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
            ("base_median", Value::Float(self.base_median)),
            ("cand_median", Value::Float(self.cand_median)),
            ("improvement_ratio", Value::Float(self.improvement_ratio)),
            ("detail", Value::Str(self.detail.clone())),
        ])
    }
}

pub fn evaluate_climb(
    floor: FloorChecks,
    base_samples: &[f64],
    cand_samples: &[f64],
    direction: Direction,
) -> ClimbReport {
    assert!(!base_samples.is_empty() && !cand_samples.is_empty());
    let base_median = median(base_samples);
    let cand_median = median(cand_samples);
    let improvement_ratio = match direction {
        Direction::Minimize => {
            if cand_median > 0.0 {
                base_median / cand_median
            } else {
                1.0
            }
        }
        Direction::Maximize => {
            if base_median > 0.0 {
                cand_median / base_median
            } else {
                1.0
            }
        }
    };

    if !floor.all_pass() {
        return ClimbReport {
            verdict: ClimbVerdict::RejectFloor,
            floor,
            base_median,
            cand_median,
            improvement_ratio,
            detail: "hard correctness floor failed; metric gain discarded".to_owned(),
        };
    }

    let improved = match direction {
        Direction::Minimize => cand_median < base_median,
        Direction::Maximize => cand_median > base_median,
    };

    if improved {
        ClimbReport {
            verdict: ClimbVerdict::Accept,
            floor,
            base_median,
            cand_median,
            improvement_ratio,
            detail: format!(
                "floor held and metric improved ({base_median:.4} -> {cand_median:.4}, {improvement_ratio:.2}x)"
            ),
        }
    } else {
        ClimbReport {
            verdict: ClimbVerdict::RejectMetric,
            floor,
            base_median,
            cand_median,
            improvement_ratio,
            detail: format!("floor held but metric did not improve ({base_median:.4} -> {cand_median:.4})"),
        }
    }
}

pub fn measure_command(workdir: &Path, argv: &[String], runs: usize) -> Result<Vec<f64>, String> {
    assert!(!argv.is_empty() && runs > 0 && runs <= 64);
    let mut samples = Vec::with_capacity(runs);
    for _ in 0..runs {
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
        samples.push(val);
    }
    Ok(samples)
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
