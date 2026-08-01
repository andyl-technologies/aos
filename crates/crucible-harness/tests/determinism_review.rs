//! Checks RFC-0010 determinism review checklist policy.
//!
//! The checklist is the human review gate for engine, scheduler, transport,
//! and ordering-significant host-code changes. These tests keep the PR template
//! and the lightweight Nix gate aligned with RFC-0010 file 28 section 6.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const TEMPLATE_TERMS: &[&str] = &[
    "DETERMINISM REVIEW CHECKLIST",
    "engine, scheduler, transport",
    "ordering-significant host code",
    "Reviewers must block merge on any unchecked applicable item",
    "crucible-sim",
    "crucible-assert",
    "crucible-shmem",
    "crucible-protocol",
    "crucible-device",
    "crucible",
    "Ordering",
    "Time, randomness, numerics",
    "State purity & content addressing",
    "ABI, unsafe, errors",
    "Tests & gates",
    "gate:harness-lint",
    "gate:adversarial-determinism",
    "Root-Cause Fix Rule",
    "fixed at source",
    concat!("re", "try logic"),
    "quarantine",
    "jitter tolerance",
    "fudge-factor",
    "paper over the leak",
];

const TEMPLATE_SCOPE_LINES: &[&str] = &[
    "- L0: `crucible-sim`, `crucible-assert`",
    "- L1: `crucible-shmem`, `crucible-protocol`, `crucible-device`",
    "- L3: `crucible`",
];

const TEMPLATE_CHECKBOX_COUNT: usize = 18;
const APPLICABILITY_CHECKBOX_COUNT: usize = 2;
const DETERMINISM_CHECKLIST_COUNT: usize = 15;
const ROOT_CAUSE_CHECKBOX_COUNT: usize = 1;
const APPLICABILITY_CHECKBOXES: &[&str] = &[
    "Not applicable: this PR does not touch engine, scheduler, transport, or ordering-significant host code.",
    "Applicable: every relevant item in the determinism review checklist below is checked or explicitly justified in this PR.",
];
const ROOT_CAUSE_CHECKBOX: &str =
    "Any discovered determinism leak was fixed at source, or no leak was discovered.";

const RFC_TERMS: &[&str] = &[
    "[STD-32]",
    "DETERMINISM REVIEW CHECKLIST",
    "any PR touching an engine/scheduler/transport crate",
    "MUST block the PR on",
    "recorded in the PR (a template)",
    "[STD-33]",
    "fix MUST be at the",
    "source",
    "never a workaround",
    concat!("re", "try"),
    "jitter tolerance",
    "fudge factor",
    "papers over a determinism leak",
];

#[test]
fn determinism_review_template_matches_rfc_policy() -> Result<(), Box<dyn Error>> {
    let root = repo_root();
    let template = fs::read_to_string(root.join(".github/pull_request_template.md"))?;
    let standards =
        fs::read_to_string(root.join("docs/rfcs/0010-crucible/28-engineering-standards.md"))?;
    let gate_nix = fs::read_to_string(root.join("tests/crucible/phase1-determinism-review.nix"))?;
    let default_nix = fs::read_to_string(root.join("tests/crucible/default.nix"))?;
    let source_nix = fs::read_to_string(root.join("pkgs/tools/crucible/_source.nix"))?;
    let mut failures = Vec::new();

    require_terms(
        ".github/pull_request_template.md",
        &template,
        TEMPLATE_TERMS,
        &mut failures,
    );
    require_terms(
        ".github/pull_request_template.md scope",
        &template,
        TEMPLATE_SCOPE_LINES,
        &mut failures,
    );
    failures.extend(template_structure_failures(&template, &standards)?);
    require_terms(
        "28-engineering-standards.md STD-32/STD-33",
        &standards,
        RFC_TERMS,
        &mut failures,
    );
    require_terms(
        "phase1-determinism-review.nix",
        &gate_nix,
        &[
            "tasks=T-STD-13",
            "review_template=.github/pull_request_template.md",
            "root_cause_rule=source-only",
            "expectedTemplateCheckboxes",
            "expectedApplicabilityCheckboxes",
            "expectedApplicabilityCheckboxItems",
            "expectedDeterminismChecklistItems",
            "expectedRootCauseCheckboxes",
            "expectedRootCauseCheckbox",
            "applicabilityChecklistItems = checkboxItems",
            "templateChecklistItems = checkboxItems",
            "rfcChecklistItems = checkboxItems",
            "rootCauseChecklistItems = checkboxItems",
            "checklistStructureFailures",
            "++ checklistStructureFailures",
            "applicabilityChecklistItems != expectedApplicabilityCheckboxItems",
            "templateChecklistItems != rfcChecklistItems",
            "rootCauseChecklistItems != [(normalizeItem expectedRootCauseCheckbox)]",
        ],
        &mut failures,
    );
    require_terms(
        "tests/crucible/default.nix",
        &default_nix,
        &["determinismReview = import ./phase1-determinism-review.nix"],
        &mut failures,
    );
    require_terms(
        "pkgs/tools/crucible/_source.nix",
        &source_nix,
        &[
            "pathString == \"${repoRootString}/.github\"",
            "pathString == \"${repoRootString}/.github/pull_request_template.md\"",
        ],
        &mut failures,
    );
    require_absent(
        "pkgs/tools/crucible/_source.nix",
        &source_nix,
        "lib.hasPrefix \"${repoRootString}/.github\" pathString",
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
fn determinism_review_template_rules_reject_missing_checklist_structure() {
    let incomplete_template = [
        "engine, scheduler, transport",
        "Reviewers must block merge on any unchecked applicable item.",
        "### DETERMINISM REVIEW CHECKLIST",
        "Ordering",
        "Time, randomness, numerics",
        "State purity & content addressing",
        "ABI, unsafe, errors",
        "Tests & gates",
        "### Root-Cause Fix Rule",
    ]
    .join("\n");
    let mut failures = Vec::new();

    failures.extend(
        template_structure_failures(&incomplete_template, "")
            .unwrap_or_else(|error| vec![format!("synthetic template: {error}")]),
    );
    require_terms(
        "synthetic template",
        &incomplete_template,
        &["fixed at source"],
        &mut failures,
    );

    assert_contains(&failures, "expected 18 checkboxes");
    assert_contains(&failures, "expected 2 applicability checkboxes");
    assert_contains(&failures, "expected 15 determinism checklist items");
    assert_contains(&failures, "expected 1 root-cause checkbox");
    assert_contains(&failures, "fixed at source");
}

fn require_terms(label: &str, content: &str, terms: &[&str], failures: &mut Vec<String>) {
    for term in terms {
        if !content.contains(term) {
            failures.push(format!("{label}: missing `{term}`"));
        }
    }
}

fn require_absent(label: &str, content: &str, term: &str, failures: &mut Vec<String>) {
    if content.contains(term) {
        failures.push(format!("{label}: forbidden `{term}`"));
    }
}

fn template_structure_failures(
    template: &str,
    standards: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut failures = Vec::new();
    let checkbox_count = checkbox_count(template);
    if checkbox_count != TEMPLATE_CHECKBOX_COUNT {
        failures.push(format!(
            ".github/pull_request_template.md: expected {TEMPLATE_CHECKBOX_COUNT} checkboxes, found {checkbox_count}"
        ));
    }
    let applicability_items = template_applicability_items(template)?;
    let expected_applicability_items = APPLICABILITY_CHECKBOXES
        .iter()
        .map(|item| normalize_item(item))
        .collect::<Vec<_>>();
    if applicability_items.len() != APPLICABILITY_CHECKBOX_COUNT {
        failures.push(format!(
            ".github/pull_request_template.md: expected {APPLICABILITY_CHECKBOX_COUNT} applicability checkboxes, found {}",
            applicability_items.len()
        ));
    }
    if applicability_items != expected_applicability_items {
        failures.push(format!(
            ".github/pull_request_template.md: applicability checkbox drift: {}",
            first_item_difference(&applicability_items, &expected_applicability_items)
        ));
    }

    let template_items = template_checklist_items(template)?;
    if template_items.len() != DETERMINISM_CHECKLIST_COUNT {
        failures.push(format!(
            ".github/pull_request_template.md: expected {DETERMINISM_CHECKLIST_COUNT} determinism checklist items, found {}",
            template_items.len()
        ));
    }
    let root_cause_items = root_cause_checklist_items(template)?;
    let expected_root_cause = vec![normalize_item(ROOT_CAUSE_CHECKBOX)];
    if root_cause_items.len() != ROOT_CAUSE_CHECKBOX_COUNT {
        failures.push(format!(
            ".github/pull_request_template.md: expected {ROOT_CAUSE_CHECKBOX_COUNT} root-cause checkbox, found {}",
            root_cause_items.len()
        ));
    }
    if root_cause_items != expected_root_cause {
        failures.push(format!(
            ".github/pull_request_template.md: root-cause checkbox drift: {}",
            first_item_difference(&root_cause_items, &expected_root_cause)
        ));
    }

    if !standards.is_empty() {
        let rfc_items = rfc_checklist_items(standards)?;
        if rfc_items.len() != DETERMINISM_CHECKLIST_COUNT {
            failures.push(format!(
                "28-engineering-standards.md: expected {DETERMINISM_CHECKLIST_COUNT} RFC checklist items, found {}",
                rfc_items.len()
            ));
        }
        if template_items != rfc_items {
            failures.push(format!(
                ".github/pull_request_template.md: determinism checklist item drift: {}",
                first_item_difference(&template_items, &rfc_items)
            ));
        }
    }

    Ok(failures)
}

fn checkbox_count(content: &str) -> usize {
    content
        .lines()
        .filter(|line| line.trim_start().starts_with("- [ ] "))
        .count()
}

fn template_checklist_items(template: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let section = section_between(
        template,
        "### DETERMINISM REVIEW CHECKLIST",
        "### Root-Cause Fix Rule",
        "template determinism checklist section",
    )?;
    Ok(checkbox_items(section, "- [ ] "))
}

fn template_applicability_items(template: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let section = section_between(
        template,
        "Reviewers must block merge on any unchecked applicable item.",
        "### DETERMINISM REVIEW CHECKLIST",
        "template applicability section",
    )?;
    Ok(checkbox_items(section, "- [ ] "))
}

fn rfc_checklist_items(standards: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let section = section_between(
        standards,
        "```text\nDETERMINISM REVIEW CHECKLIST (apply to any engine/scheduler/transport PR)",
        "\n```",
        "RFC determinism checklist block",
    )?;
    Ok(checkbox_items(section, "[ ] "))
}

fn root_cause_checklist_items(template: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let section = section_after(
        template,
        "### Root-Cause Fix Rule",
        "template root-cause fix rule section",
    )?;
    Ok(checkbox_items(section, "- [ ] "))
}

fn section_after<'a>(
    content: &'a str,
    start: &str,
    label: &str,
) -> Result<&'a str, Box<dyn Error>> {
    let Some(start_index) = content.find(start) else {
        return Err(format!("{label}: missing start marker").into());
    };
    Ok(&content[start_index + start.len()..])
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
        .into_iter()
        .map(|item| normalize_item(&item))
        .collect()
}

fn push_current_item(items: &mut Vec<String>, current: &mut String) {
    if !current.trim().is_empty() {
        items.push(current.trim().to_string());
        current.clear();
    }
}

fn normalize_item(item: &str) -> String {
    item.replace('`', "")
        .replace(['\u{2014}', '\u{2013}'], "-")
        .replace('\u{21d2}', "=>")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn first_item_difference(actual: &[String], expected: &[String]) -> String {
    let length = actual.len().max(expected.len());
    for index in 0..length {
        let actual_item = actual.get(index).map(String::as_str).unwrap_or("<missing>");
        let expected_item = expected
            .get(index)
            .map(String::as_str)
            .unwrap_or("<missing>");
        if actual_item != expected_item {
            return format!(
                "item {} is `{actual_item}`, expected `{expected_item}`",
                index + 1
            );
        }
    }
    "item order differs".to_string()
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
