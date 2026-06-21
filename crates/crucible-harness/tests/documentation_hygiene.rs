//! Checks RFC-0010 documentation-pass and doc-lint hygiene.
//!
//! This is the executable policy anchor for RFC-0010 file 28 section 5:
//! documentation-only work remains comments-only, while the RFC consistency
//! lint remains wired to the gate catalog and checklist-digest rules.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const COMMENTS_ONLY_TERMS: &[&str] = &[
    "comments-only",
    "never reorder",
    "rename, or reformat code in a docs pass",
    "doc claim contradicts",
];

const STD_30_TERMS: &[&str] = &[
    "Documenting existing code is comments-only",
    "NOT reorder, rename, or reformat code",
    "observed",
    "flagged in the PR",
];

const STD_31_TERMS: &[&str] = &[
    "Doc-lint and the gate catalog",
    "referenced-but-undefined gate",
    "defined-but-unreferenced gate",
    "drifted",
];

#[test]
fn comments_only_documentation_policy_matches_root_guidance() -> Result<(), Box<dyn Error>> {
    let root = repo_root();
    let claude = fs::read_to_string(root.join("CLAUDE.md"))?;
    let agents = fs::read_to_string(root.join("AGENTS.md"))?;
    let standards =
        fs::read_to_string(root.join("docs/rfcs/0010-crucible/28-engineering-standards.md"))?;
    let mut failures = Vec::new();

    require_terms("CLAUDE.md", &claude, COMMENTS_ONLY_TERMS, &mut failures);
    require_terms("AGENTS.md", &agents, COMMENTS_ONLY_TERMS, &mut failures);
    require_terms(
        "28-engineering-standards.md STD-30",
        &standards,
        STD_30_TERMS,
        &mut failures,
    );
    require_terms(
        "28-engineering-standards.md STD-31",
        &standards,
        STD_31_TERMS,
        &mut failures,
    );

    assert!(
        failures.is_empty(),
        "documentation comments-only policy drift:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn doc_lint_and_gate_catalog_checks_remain_wired() -> Result<(), Box<dyn Error>> {
    let root = repo_root();
    let rfc_consistency =
        fs::read_to_string(root.join("crates/crucible-harness/tests/rfc_consistency.rs"))?;
    let rfc_tasks = fs::read_to_string(
        root.join("crates/crucible-harness/tests/support/rfc_consistency_tasks.rs"),
    )?;
    let rfc_misc = fs::read_to_string(
        root.join("crates/crucible-harness/tests/support/rfc_consistency_misc.rs"),
    )?;
    let gate_catalog =
        fs::read_to_string(root.join("crates/crucible-harness/tests/gate_catalog.rs"))?;
    let default_nix = fs::read_to_string(root.join("tests/crucible/default.nix"))?;
    let rfc_consistency_nix =
        fs::read_to_string(root.join("tests/crucible/phase1-rfc-consistency.nix"))?;
    let documentation_hygiene_nix =
        fs::read_to_string(root.join("tests/crucible/phase1-documentation-hygiene.nix"))?;
    let phase_gate_wiring_nix =
        fs::read_to_string(root.join("tests/crucible/phase1-phase-gate-wiring.nix"))?;
    let crucible_source_nix = fs::read_to_string(root.join("pkgs/tools/crucible/_source.nix"))?;
    let mut failures = Vec::new();
    let consistency_body = function_body(&rfc_consistency, "rfc_0010_consistency_lint_is_clean")?;
    let task_sync_body = function_body(&rfc_tasks, "task_sync_failures")?;

    require_terms(
        "rfc_0010_consistency_lint_is_clean",
        consistency_body,
        &[
            "failures.extend(task_sync_failures(&docs, &tasks, &phase_plan_order));",
            "failures.extend(gate_reference_failures(&gate_catalog, &referenced_gates));",
            "failures.extend(banned_name_failures(&root)?);",
        ],
        &mut failures,
    );
    require_terms(
        "task_sync_failures",
        task_sync_body,
        &[
            "task_order_failures(tasks, phase_plan_order)",
            "task_manifest_digest_failures",
        ],
        &mut failures,
    );
    require_terms(
        "support/rfc_consistency_misc.rs",
        &rfc_misc,
        &[
            "gate_catalog",
            "referenced_gate_names",
            "gate_reference_failures",
        ],
        &mut failures,
    );
    require_terms(
        "gate_catalog.rs",
        &gate_catalog,
        &["canonical_gate_catalog_matches_rfc_table_and_references"],
        &mut failures,
    );
    require_terms(
        "tests/crucible/default.nix",
        &default_nix,
        &[
            "documentationHygiene = import ./phase1-documentation-hygiene.nix",
            "phaseGateWiring = import ./phase1-phase-gate-wiring.nix",
            "rfcConsistency = import ./phase1-rfc-consistency.nix",
        ],
        &mut failures,
    );
    require_terms(
        "phase1-rfc-consistency.nix",
        &rfc_consistency_nix,
        &["tasks=T-PLAN-1,T-PLAN-2,T-STD-12"],
        &mut failures,
    );
    require_terms(
        "phase1-documentation-hygiene.nix",
        &documentation_hygiene_nix,
        &[
            "tasks=T-STD-12",
            "source_filter=CLAUDE.md,AGENTS.md,documentation_hygiene.rs,phase1-documentation-hygiene.nix",
            "rfc_consistency_check=checks.crucible.phase1.rfcConsistency",
            "phase_gate_wiring_check=checks.crucible.phase1.phaseGateWiring",
        ],
        &mut failures,
    );
    require_terms(
        "phase1-phase-gate-wiring.nix",
        &phase_gate_wiring_nix,
        &[
            "missingCatalogWiring",
            "unknownPhaseGates",
            "catalog gate is not assigned to a phase exit target",
            "phase exit target is not in the canonical gate catalog",
            "check=checks.crucible.phase1.phaseGateWiring",
        ],
        &mut failures,
    );
    require_terms(
        "pkgs/tools/crucible/_source.nix",
        &crucible_source_nix,
        &[
            "pathString == \"${repoRootString}/CLAUDE.md\"",
            "pathString == \"${repoRootString}/AGENTS.md\"",
        ],
        &mut failures,
    );

    assert!(
        failures.is_empty(),
        "documentation doc-lint wiring drift:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn comments_only_diff_classifier_rejects_code_motion_and_formatting() {
    let comment_only = comments_only_diff_failures(
        Path::new("synthetic.rs"),
        "pub fn run() {}\n",
        "//! Module docs.\n/// Runs the operation.\npub fn run() {}\n",
    );
    assert!(comment_only.is_empty(), "{comment_only:?}");

    let safety_comment_only = comments_only_diff_failures(
        Path::new("synthetic.rs"),
        "unsafe { call_raw() };\n",
        "// SAFETY: synthetic invariant.\nunsafe { call_raw() };\n",
    );
    assert!(safety_comment_only.is_empty(), "{safety_comment_only:?}");

    let renamed = comments_only_diff_failures(
        Path::new("synthetic.rs"),
        "pub fn run() {}\n",
        "/// Runs the operation.\npub fn execute() {}\n",
    );
    assert_contains(&renamed, "non-comment code drift");

    let reordered = comments_only_diff_failures(
        Path::new("synthetic.rs"),
        "fn first() {}\nfn second() {}\n",
        "/// Second docs.\nfn second() {}\nfn first() {}\n",
    );
    assert_contains(&reordered, "non-comment code drift");

    let reformatted = comments_only_diff_failures(
        Path::new("synthetic.rs"),
        "pub fn run(){call();}\n",
        "/// Runs the operation.\npub fn run() { call(); }\n",
    );
    assert_contains(&reformatted, "non-comment code drift");

    let ordinary_comment = comments_only_diff_failures(
        Path::new("synthetic.rs"),
        "pub fn run() {}\n",
        "// Incidental note.\npub fn run() {}\n",
    );
    assert_contains(&ordinary_comment, "non-comment code drift");
}

#[test]
fn documentation_only_workspace_diff_is_comments_only_when_requested() -> Result<(), Box<dyn Error>>
{
    if std::env::var_os("CRUCIBLE_DOCUMENTATION_ONLY_DIFF").is_none() {
        return Ok(());
    }

    let root = repo_root();
    if !root.join(".git").exists() {
        return Err("CRUCIBLE_DOCUMENTATION_ONLY_DIFF requires a git worktree".into());
    }

    let status = git_output(
        &root,
        &["diff", "--name-status", "--diff-filter=M", "HEAD", "--"],
    )?;
    let mut failures = Vec::new();

    for line in status.lines() {
        let Some(relative_path) = modified_path_from_name_status(line) else {
            continue;
        };
        let path = Path::new(relative_path);
        if !is_documented_code_path(path) {
            continue;
        }

        let before = git_output(&root, &["show", &format!("HEAD:{relative_path}")])?;
        let after = fs::read_to_string(root.join(path))?;
        failures.extend(comments_only_diff_failures(path, &before, &after));
    }

    assert!(
        failures.is_empty(),
        "documentation-only workspace diff changed code:\n{}",
        failures.join("\n")
    );

    Ok(())
}

fn require_terms(label: &str, content: &str, terms: &[&str], failures: &mut Vec<String>) {
    for term in terms {
        if !content.contains(term) {
            failures.push(format!("{label}: missing `{term}`"));
        }
    }
}

fn comments_only_diff_failures(path: &Path, before: &str, after: &str) -> Vec<String> {
    let before_code = non_comment_code_lines(path, before);
    let after_code = non_comment_code_lines(path, after);

    if before_code == after_code {
        Vec::new()
    } else {
        vec![format!(
            "{}: non-comment code drift in documentation-only diff",
            path.display()
        )]
    }
}

fn non_comment_code_lines<'a>(path: &Path, content: &'a str) -> Vec<&'a str> {
    content
        .lines()
        .filter(|line| !is_comment_or_blank_line(path, line))
        .collect()
}

fn is_comment_or_blank_line(path: &Path, line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return true;
    }

    match path.extension().and_then(|extension| extension.to_str()) {
        Some("rs") => {
            trimmed.starts_with("//!")
                || trimmed.starts_with("///")
                || trimmed.starts_with("// SAFETY:")
        }
        Some("nix" | "sh" | "toml") => trimmed.starts_with('#'),
        _ => trimmed.starts_with("//"),
    }
}

fn is_documented_code_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "rs")
}

fn modified_path_from_name_status(line: &str) -> Option<&str> {
    line.strip_prefix("M\t").filter(|path| !path.is_empty())
}

fn git_output(root: &Path, args: &[&str]) -> Result<String, Box<dyn Error>> {
    let output = Command::new("git").current_dir(root).args(args).output()?;
    if output.status.success() {
        Ok(String::from_utf8(output.stdout)?)
    } else {
        Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )
        .into())
    }
}

fn function_body<'a>(content: &'a str, function_name: &str) -> Result<&'a str, Box<dyn Error>> {
    let needle = format!("fn {function_name}");
    let Some(function_start) = content.find(&needle) else {
        return Err(format!("missing function `{function_name}`").into());
    };
    let after_function = &content[function_start..];
    let Some(open_relative) = after_function.find('{') else {
        return Err(format!("missing body for function `{function_name}`").into());
    };
    let open = function_start + open_relative;
    let mut depth = 0_usize;

    for (relative_index, ch) in content[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let close = open + relative_index;
                    return Ok(&content[open + 1..close]);
                }
            }
            _ => {}
        }
    }

    Err(format!("unterminated body for function `{function_name}`").into())
}

fn assert_contains(findings: &[String], needle: &str) {
    assert!(
        findings.iter().any(|finding| finding.contains(needle)),
        "expected finding containing `{needle}`, got {findings:?}"
    );
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}
