use std::path::Path;

use crate::diff::{DiffConfig, run_diff};
use crate::json::Value;
use crate::protocol::{Driver, Mask, StepOp, StepRequest};

#[derive(Clone, Debug, PartialEq)]
pub struct Disambiguator {
    pub fault_id: String,
    pub description: String,
    pub witness_ops: Vec<StepOp>,
    pub candidate_output: String,
    pub fault_output: String,
}

impl Disambiguator {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("fault_id", Value::Str(self.fault_id.clone())),
            ("description", Value::Str(self.description.clone())),
            (
                "witness_ops",
                Value::Array(self.witness_ops.iter().map(StepOp::to_json).collect()),
            ),
            ("candidate_output", Value::Str(self.candidate_output.clone())),
            ("fault_output", Value::Str(self.fault_output.clone())),
        ])
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FaultOutcome {
    pub fault_id: String,
    pub description: String,
    pub killed: bool,
    pub disambiguator: Option<Disambiguator>,
}

impl FaultOutcome {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("fault_id", Value::Str(self.fault_id.clone())),
            ("description", Value::Str(self.description.clone())),
            ("killed", Value::Bool(self.killed)),
            (
                "disambiguator",
                self.disambiguator
                    .as_ref()
                    .map_or(Value::Null, Disambiguator::to_json),
            ),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct AdversaryReport {
    pub total_faults: usize,
    pub killed_faults: usize,
    pub survived_faults: usize,
    pub outcomes: Vec<FaultOutcome>,
}

impl AdversaryReport {
    pub fn ok(&self) -> bool {
        self.survived_faults == 0
    }

    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("ok", Value::Bool(self.ok())),
            ("total_faults", Value::Int(self.total_faults as i64)),
            ("killed_faults", Value::Int(self.killed_faults as i64)),
            ("survived_faults", Value::Int(self.survived_faults as i64)),
            (
                "outcomes",
                Value::Array(self.outcomes.iter().map(FaultOutcome::to_json).collect()),
            ),
        ])
    }
}

pub struct PlantedFault<'a> {
    pub id: String,
    pub description: String,
    pub driver: Box<dyn Driver + 'a>,
}

pub fn prove_oracle<'a>(
    candidate: &mut dyn Driver,
    oracle_requests: &[StepRequest],
    masks: &[Mask],
    mut faults: Vec<PlantedFault<'a>>,
    witness_search_seeds: usize,
) -> Result<AdversaryReport, String> {
    let mut cand_hashes = Vec::with_capacity(oracle_requests.len());
    for req in oracle_requests {
        let trace = candidate.step(req)?;
        cand_hashes.push(trace.trace_hash(masks));
    }

    let mut outcomes = Vec::with_capacity(faults.len());
    let mut killed_faults = 0usize;
    let mut survived_faults = 0usize;

    for fault in &mut faults {
        let mut killed = false;
        for (req, expected_hash) in oracle_requests.iter().zip(cand_hashes.iter()) {
            match fault.driver.step(req) {
                Ok(t) => {
                    if t.trace_hash(masks) != *expected_hash {
                        killed = true;
                        break;
                    }
                }
                Err(_) => {
                    killed = true;
                    break;
                }
            }
        }
        if killed {
            killed_faults += 1;
            outcomes.push(FaultOutcome {
                fault_id: fault.id.clone(),
                description: fault.description.clone(),
                killed: true,
                disambiguator: None,
            });
        } else {
            survived_faults += 1;
            let cfg = DiffConfig {
                seeds: witness_search_seeds,
                base_seed: 0x9e3779b97f4a7c15 ^ (survived_faults as u64),
                max_seq_len: 6,
                parity: true,
                masks: masks.to_vec(),
                ..DiffConfig::default()
            };
            let diff = run_diff(candidate, fault.driver.as_mut(), &cfg);
            let disambiguator = diff.divergences.into_iter().next().map(|d| Disambiguator {
                fault_id: fault.id.clone(),
                description: fault.description.clone(),
                witness_ops: d.ops,
                candidate_output: d.base_payload,
                fault_output: d.cand_payload,
            });
            outcomes.push(FaultOutcome {
                fault_id: fault.id.clone(),
                description: fault.description.clone(),
                killed: false,
                disambiguator,
            });
        }
    }

    Ok(AdversaryReport {
        total_faults: outcomes.len(),
        killed_faults,
        survived_faults,
        outcomes,
    })
}

#[derive(Clone, Debug)]
pub struct SourceFault {
    pub id: String,
    pub rel_file: String,
    pub description: String,
    pub mutated_source: String,
}

const SEMANTIC_SWAPS: &[(&str, &str, &str)] = &[
    ("<=", "<", "boundary_le_to_lt"),
    (">=", ">", "boundary_ge_to_gt"),
    (" == ", " != ", "predicate_eq_to_ne"),
    (" != ", " == ", "predicate_ne_to_eq"),
    (" + 1", " + 0", "off_by_one_plus"),
    (" - 1", " - 0", "off_by_one_minus"),
    (" and ", " or ", "logic_and_to_or"),
    (" or ", " and ", "logic_or_to_and"),
    ("return True", "return False", "invert_return_true"),
    ("return False", "return True", "invert_return_false"),
];

pub fn synthesize_source_faults(root: &Path, changed_files: &[String], max_faults: usize) -> Vec<SourceFault> {
    let mut out = Vec::new();
    for rel in changed_files {
        if out.len() >= max_faults {
            break;
        }
        if !rel.ends_with(".py") || rel.starts_with("test") || rel.contains("/test") {
            continue;
        }
        let full = root.join(rel);
        let Ok(src) = std::fs::read_to_string(&full) else {
            continue;
        };
        let lines: Vec<&str> = src.lines().collect();
        for (line_idx, line) in lines.iter().enumerate() {
            if out.len() >= max_faults {
                break;
            }
            for (from, to, tag) in SEMANTIC_SWAPS {
                if line.contains(from) {
                    let mut mutated_lines: Vec<String> = lines.iter().map(|s| (*s).to_owned()).collect();
                    mutated_lines[line_idx] = line.replacen(from, to, 1);
                    let mut mutated_source = mutated_lines.join("\n");
                    if src.ends_with('\n') {
                        mutated_source.push('\n');
                    }
                    out.push(SourceFault {
                        id: format!("{}:{}:{}", rel, line_idx + 1, tag),
                        rel_file: rel.clone(),
                        description: format!("{rel}:{} `{from}` -> `{to}`", line_idx + 1),
                        mutated_source,
                    });
                    if out.len() >= max_faults {
                        break;
                    }
                }
            }
        }
    }
    out
}
