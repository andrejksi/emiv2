use std::path::{Path, PathBuf};

use crate::json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverLang {
    Python,
    Node,
    TypeScript,
    Go,
    Rust,
}

impl DriverLang {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "py" | "python" => Ok(DriverLang::Python),
            "js" | "mjs" | "node" | "javascript" => Ok(DriverLang::Node),
            "ts" | "typescript" => Ok(DriverLang::TypeScript),
            "go" | "golang" => Ok(DriverLang::Go),
            "rs" | "rust" => Ok(DriverLang::Rust),
            other => Err(format!(
                "unsupported driver language '{other}' (expected: python, node, ts, go, rust)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            DriverLang::Python => "python",
            DriverLang::Node => "node",
            DriverLang::TypeScript => "ts",
            DriverLang::Go => "go",
            DriverLang::Rust => "rust",
        }
    }
}

pub fn detect_repo_lang(repo: &Path) -> DriverLang {
    if repo.join("Cargo.toml").is_file() {
        return DriverLang::Rust;
    }
    if repo.join("go.mod").is_file() {
        return DriverLang::Go;
    }
    let mut has_py = false;
    let mut has_js = false;
    let mut stack = vec![repo.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.')
                || matches!(
                    name.as_str(),
                    "node_modules" | "target" | "__pycache__" | "dist" | "build"
                )
            {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                match path.extension().and_then(|s| s.to_str()) {
                    Some("ts" | "mts" | "tsx") => return DriverLang::TypeScript,
                    Some("py") => has_py = true,
                    Some("js" | "mjs" | "cjs") => has_js = true,
                    _ => {}
                }
            }
        }
    }
    if (has_js || repo.join("package.json").is_file()) && !has_py {
        DriverLang::Node
    } else {
        DriverLang::Python
    }
}

pub struct DriverInitResult {
    pub lang: DriverLang,
    pub files: Vec<String>,
    pub command: String,
    pub pinned: bool,
}

impl DriverInitResult {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("ok", Value::Bool(true)),
            ("lang", Value::Str(self.lang.as_str().to_owned())),
            ("files", Value::str_array(&self.files)),
            ("command", Value::Str(self.command.clone())),
            ("pinned", Value::Bool(self.pinned)),
        ])
    }
}

fn write_checked(path: &Path, content: &str, force: bool) -> Result<(), String> {
    if path.exists() && !force {
        return Err(format!(
            "{} already exists (pass --force to overwrite)",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create dir: {e}"))?;
    }
    std::fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))
}

fn norm_rel(repo: &Path, path: &Path) -> String {
    path.strip_prefix(repo)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

pub fn init_driver(
    repo: &Path,
    lang: Option<DriverLang>,
    out_override: Option<&str>,
    force: bool,
    pin: bool,
) -> Result<DriverInitResult, String> {
    let lang = lang.unwrap_or_else(|| detect_repo_lang(repo));
    let mut files = Vec::new();
    let command = if lang == DriverLang::Rust {
        let base_dir = PathBuf::from(out_override.unwrap_or(".emi/emi_driver"));
        let cargo_path = repo.join(&base_dir).join("Cargo.toml");
        let main_path = repo.join(&base_dir).join("src/main.rs");
        write_checked(&cargo_path, TEMPLATE_RUST_CARGO, force)?;
        write_checked(&main_path, TEMPLATE_RUST_MAIN, force)?;
        files.push(norm_rel(repo, &cargo_path));
        files.push(norm_rel(repo, &main_path));
        let dir_rel = norm_rel(repo, &repo.join(&base_dir));
        format!("cargo run --quiet --manifest-path {dir_rel}/Cargo.toml")
    } else {
        let (dst, template, runner) = match lang {
            DriverLang::Python => (
                repo.join(out_override.unwrap_or(".emi/driver.py")),
                TEMPLATE_PYTHON,
                "python3",
            ),
            DriverLang::Node => (
                repo.join(out_override.unwrap_or(".emi/driver.mjs")),
                TEMPLATE_NODE,
                "node",
            ),
            DriverLang::TypeScript => (
                repo.join(out_override.unwrap_or(".emi/driver.ts")),
                TEMPLATE_TS,
                "node",
            ),
            DriverLang::Go => {
                let base = PathBuf::from(out_override.unwrap_or(".emi/emi_driver"));
                let dst = if base.extension().is_some() {
                    repo.join(&base)
                } else {
                    repo.join(&base).join("main.go")
                };
                (dst, TEMPLATE_GO, "go run")
            }
            DriverLang::Rust => unreachable!(),
        };
        write_checked(&dst, template, force)?;
        let r = norm_rel(repo, &dst);
        files.push(r.clone());
        format!("{runner} {r}")
    };

    if pin {
        let mut st = crate::ratchet::load_local(repo)?;
        st.driver = Some(command.clone());
        crate::ratchet::save_local(repo, &st)?;
    }

    Ok(DriverInitResult {
        lang,
        files,
        command,
        pinned: pin,
    })
}

const TEMPLATE_PYTHON: &str = r#"import hashlib
import json
import os
import sys

def handle_op(op, args):
    if op == "echo":
        return {"ok": True, "val": args[0] if args else None}
    return {"ok": False, "err": f"unknown_op:{op}"}

def main():
    proto_fd = os.dup(1)
    proto_out = os.fdopen(proto_fd, "w", encoding="utf-8", buffering=1)
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, 1)
    os.close(devnull)
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        req = json.loads(raw)
        if req.get("verb") == "probe":
            resp = {
                "ok": True,
                "fingerprint": "custom-python-v1",
                "operations": [
                    {"name": "echo", "arity": 1, "stateful": False, "param_types": ["int"], "kwarg_names": []}
                ],
                "detail": "ok",
            }
            proto_out.write(json.dumps(resp) + "\n")
            proto_out.flush()
        elif req.get("verb") == "step":
            outcomes = [handle_op(o.get("op", ""), o.get("args", [])) for o in req.get("ops", [])]
            digest = hashlib.sha256(
                json.dumps({"outcomes": outcomes, "side_effects": [], "logs": [], "observations": {}}, sort_keys=True).encode("utf-8")
            ).hexdigest()
            resp = {
                "ok": True,
                "outcomes": outcomes,
                "side_effects": [],
                "logs": [],
                "state_digest": digest,
                "coverage": [],
                "observations": {},
                "error": None,
            }
            proto_out.write(json.dumps(resp) + "\n")
            proto_out.flush()

if __name__ == "__main__":
    main()
"#;

const TEMPLATE_NODE: &str = r#"import crypto from "node:crypto";
import readline from "node:readline";

function handleOp(op, args) {
  if (op === "echo") {
    return { ok: true, val: args.length > 0 ? args[0] : null };
  }
  return { ok: false, err: `unknown_op:${op}` };
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  const req = JSON.parse(trimmed);
  if (req.verb === "probe") {
    const resp = {
      ok: true,
      fingerprint: "custom-node-v1",
      operations: [
        { name: "echo", arity: 1, stateful: false, param_types: ["int"], kwarg_names: [] },
      ],
      detail: "ok",
    };
    process.stdout.write(JSON.stringify(resp) + "\n");
  } else if (req.verb === "step") {
    const outcomes = (req.ops || []).map((o) => handleOp(o.op || "", o.args || []));
    const payload = JSON.stringify({ outcomes, side_effects: [], logs: [], observations: {} });
    const digest = crypto.createHash("sha256").update(payload).digest("hex");
    const resp = {
      ok: true,
      outcomes,
      side_effects: [],
      logs: [],
      state_digest: digest,
      coverage: [],
      observations: {},
      error: null,
    };
    process.stdout.write(JSON.stringify(resp) + "\n");
  }
});
"#;

const TEMPLATE_TS: &str = r#"import crypto from "node:crypto";
import readline from "node:readline";

interface StepOp {
  op: string;
  args: unknown[];
}

function handleOp(op: string, args: unknown[]): Record<string, unknown> {
  if (op === "echo") {
    return { ok: true, val: args.length > 0 ? args[0] : null };
  }
  return { ok: false, err: `unknown_op:${op}` };
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line: string) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  const req = JSON.parse(trimmed) as { verb: string; ops?: StepOp[] };
  if (req.verb === "probe") {
    const resp = {
      ok: true,
      fingerprint: "custom-ts-v1",
      operations: [
        { name: "echo", arity: 1, stateful: false, param_types: ["int"], kwarg_names: [] },
      ],
      detail: "ok",
    };
    process.stdout.write(JSON.stringify(resp) + "\n");
  } else if (req.verb === "step") {
    const outcomes = (req.ops ?? []).map((o) => handleOp(o.op, o.args ?? []));
    const payload = JSON.stringify({ outcomes, side_effects: [], logs: [], observations: {} });
    const digest = crypto.createHash("sha256").update(payload).digest("hex");
    const resp = {
      ok: true,
      outcomes,
      side_effects: [],
      logs: [],
      state_digest: digest,
      coverage: [],
      observations: {},
      error: null,
    };
    process.stdout.write(JSON.stringify(resp) + "\n");
  }
});
"#;

const TEMPLATE_GO: &str = r#"package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type stepOp struct {
	Op   string `json:"op"`
	Args []any  `json:"args"`
}

type request struct {
	Verb string   `json:"verb"`
	Ops  []stepOp `json:"ops"`
}

func handleOp(op string, args []any) map[string]any {
	if op == "echo" {
		var v any
		if len(args) > 0 {
			v = args[0]
		}
		return map[string]any{"ok": true, "val": v}
	}
	return map[string]any{"ok": false, "err": "unknown_op:" + op}
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	enc := json.NewEncoder(os.Stdout)
	for sc.Scan() {
		var req request
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			continue
		}
		switch req.Verb {
		case "probe":
			_ = enc.Encode(map[string]any{
				"ok":          true,
				"fingerprint": "custom-go-v1",
				"operations": []map[string]any{
					{"name": "echo", "arity": 1, "stateful": false, "param_types": []string{"int"}, "kwarg_names": []string{}},
				},
				"detail": "ok",
			})
		case "step":
			outcomes := make([]map[string]any, 0, len(req.Ops))
			for _, o := range req.Ops {
				outcomes = append(outcomes, handleOp(o.Op, o.Args))
			}
			raw, _ := json.Marshal(outcomes)
			sum := sha256.Sum256(raw)
			_ = enc.Encode(map[string]any{
				"ok":           true,
				"outcomes":     outcomes,
				"side_effects": []any{},
				"logs":         []string{},
				"state_digest": hex.EncodeToString(sum[:]),
				"coverage":     []string{},
				"observations": map[string]any{},
				"error":        nil,
			})
		default:
			fmt.Fprintln(os.Stderr, "unknown verb:", req.Verb)
		}
	}
}
"#;

const TEMPLATE_RUST_CARGO: &str = r#"[package]
name = "emi_driver"
version = "0.1.0"
edition = "2021"
"#;

const TEMPLATE_RUST_MAIN: &str = r#"use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains("\"probe\"") {
            let _ = writeln!(
                stdout,
                "{{\"ok\":true,\"fingerprint\":\"custom-rust-v1\",\"operations\":[{{\"name\":\"echo\",\"arity\":1,\"stateful\":false,\"param_types\":[\"int\"],\"kwarg_names\":[]}}],\"detail\":\"ok\"}}"
            );
            let _ = stdout.flush();
        } else if trimmed.contains("\"step\"") {
            let _ = writeln!(
                stdout,
                "{{\"ok\":true,\"outcomes\":[{{\"ok\":true,\"val\":0}}],\"side_effects\":[],\"logs\":[],\"state_digest\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"coverage\":[],\"observations\":{{}},\"error\":null}}"
            );
            let _ = stdout.flush();
        }
    }
}
"#;
