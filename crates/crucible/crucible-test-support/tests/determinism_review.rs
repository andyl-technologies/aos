//! Checks the Crucible determinism review policy.
//!
//! The checklist is the human review gate for engine, scheduler, transport,
//! and ordering-significant host-code changes. These tests keep the canonical
//! checklist in `docs/engineering/crucible/engineering-standards.md` and the
//! lightweight Nix gate aligned without coupling the policy to a
//! hosting-provider template.

#![forbid(unsafe_code)]

#[path = "support/workspace.rs"]
mod workspace;

use std::error::Error;
use std::fs;
use std::path::PathBuf;

const DETERMINISM_CHECKLIST_COUNT: usize = 15;

const REVIEW_POLICY_TERMS: &[&str] = &[
    "DETERMINISM REVIEW CHECKLIST",
    "any PR touching an engine/scheduler/transport crate",
    "MUST block the PR on",
    "completed checklist is recorded in the PR description",
    "or review.",
    "fix MUST be at the",
    "source",
    "never a workaround",
    concat!("re", "try"),
    "jitter tolerance",
    "fudge factor",
    "papers over a determinism leak",
];

#[test]
fn determinism_review_policy_matches_engineering_standards() -> Result<(), Box<dyn Error>> {
    let root = repo_root();
    let standards =
        fs::read_to_string(root.join("docs/engineering/crucible/engineering-standards.md"))?;
    let gate_nix = fs::read_to_string(root.join("tests/crucible/phase1-determinism-review.nix"))?;
    let default_nix = fs::read_to_string(root.join("tests/crucible/default.nix"))?;
    let mut failures = Vec::new();

    require_terms(
        "engineering-standards.md review policy",
        &standards,
        REVIEW_POLICY_TERMS,
        &mut failures,
    );
    failures.extend(checklist_structure_failures(&standards)?);
    require_terms(
        "phase1-determinism-review.nix",
        &gate_nix,
        &[
            "tasks=T-STD-13",
            "review_checklist=docs/engineering/crucible/engineering-standards.md",
            "root_cause_rule=source-only",
            "expectedDeterminismChecklistItems",
            "checklistItems = checkboxItems",
            "checklistStructureFailures",
            "++ checklistStructureFailures",
        ],
        &mut failures,
    );
    require_terms(
        "tests/crucible/default.nix",
        &default_nix,
        &["determinismReview = import ./phase1-determinism-review.nix"],
        &mut failures,
    );
    assert!(
        failures.is_empty(),
        "determinism review policy drift:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn determinism_review_rules_reject_missing_checklist_structure() {
    let incomplete_standards = [
        "```text",
        "DETERMINISM REVIEW CHECKLIST (apply to any engine/scheduler/transport PR)",
        "",
        "Ordering",
        "[ ] One incomplete item.",
        "```",
    ]
    .join("\n");

    let failures = checklist_structure_failures(&incomplete_standards)
        .unwrap_or_else(|error| vec![format!("synthetic checklist: {error}")]);

    assert_contains(&failures, "expected 15 determinism checklist items");
}

fn require_terms(label: &str, content: &str, terms: &[&str], failures: &mut Vec<String>) {
    for term in terms {
        if !content.contains(term) {
            failures.push(format!("{label}: missing `{term}`"));
        }
    }
}

fn checklist_structure_failures(standards: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let checklist_items = determinism_checklist_items(standards)?;
    if checklist_items.len() == DETERMINISM_CHECKLIST_COUNT {
        return Ok(Vec::new());
    }

    Ok(vec![format!(
        "engineering-standards.md: expected {DETERMINISM_CHECKLIST_COUNT} determinism checklist items, found {}",
        checklist_items.len()
    )])
}

fn determinism_checklist_items(standards: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let section = section_between(
        standards,
        "```text\nDETERMINISM REVIEW CHECKLIST (apply to any engine/scheduler/transport PR)",
        "\n```",
        "determinism checklist block",
    )?;
    Ok(checkbox_items(section, "[ ] "))
}

fn section_between<'a>(
    content: &'a str,
    start: &str,
    end: &str,
    label: &str,
) -> Result<&'a str, Box<dyn Error>> {
    let Some(start_index) = content.find(start) else {
        return Err(format!("{label}: missing start marker").into());
    };
    let after_start = &content[start_index + start.len()..];
    let Some(end_index) = after_start.find(end) else {
        return Err(format!("{label}: missing end marker").into());
    };
    Ok(&after_start[..end_index])
}

fn checkbox_items(section: &str, prefix: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();

    for line in section.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            push_current_item(&mut items, &mut current);
            current.push_str(rest);
        } else if trimmed.is_empty() {
            push_current_item(&mut items, &mut current);
        } else if !current.is_empty() {
            current.push(' ');
            current.push_str(trimmed);
        }
    }

    push_current_item(&mut items, &mut current);
    items
}

fn push_current_item(items: &mut Vec<String>, current: &mut String) {
    if !current.trim().is_empty() {
        items.push(current.trim().to_string());
        current.clear();
    }
}

fn assert_contains(findings: &[String], needle: &str) {
    assert!(
        findings.iter().any(|finding| finding.contains(needle)),
        "expected finding containing `{needle}`, got {findings:?}"
    );
}

fn repo_root() -> PathBuf {
    workspace::repository_root()
}
