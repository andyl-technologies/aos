//! Checks RFC-0010 requirement coverage, task drift, gate references, and names.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

#[path = "support/rfc_consistency_io.rs"]
mod rfc_consistency_io;
#[path = "support/rfc_consistency_misc.rs"]
mod rfc_consistency_misc;
#[path = "support/rfc_consistency_tasks.rs"]
mod rfc_consistency_tasks;

use rfc_consistency_io::*;
use rfc_consistency_misc::*;
use rfc_consistency_tasks::*;

#[test]
fn rfc_0010_consistency_lint_is_clean() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let rfc_dir = root.join("docs/rfcs/0010-crucible");
    let docs = load_rfc_files(&rfc_dir)?;
    let requirements = collect_requirements(&docs);
    let tasks = collect_tasks(&docs);
    let task_prefix_files = task_prefix_file_map(&docs)?;
    let phase_plan_order = phase_plan_task_order(&docs)?;
    let gate_catalog = gate_catalog(&docs)?;
    let referenced_gates = referenced_gate_names(&docs);
    let mut failures = Vec::new();

    failures.extend(duplicate_requirement_failures(&requirements));
    failures.extend(requirement_coverage_failures(&requirements, &tasks));
    failures.extend(task_reference_failures(&requirements, &tasks));
    failures.extend(task_checklist_failures(
        &tasks,
        &task_prefix_files,
        &phase_plan_order,
    ));
    failures.extend(task_sync_failures(&docs, &tasks, &phase_plan_order));
    failures.extend(gate_reference_failures(&gate_catalog, &referenced_gates));
    failures.extend(banned_name_failures(&root)?);

    assert!(
        failures.is_empty(),
        "RFC-0010 consistency lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn rfc_consistency_rules_reject_coverage_reference_and_plan_drift() {
    let requirements = vec![
        Requirement {
            id: "DET-1".to_string(),
            file: "04-determinism-contract.md".to_string(),
            line: 10,
            text: "Each run MUST be deterministic.".to_string(),
        },
        Requirement {
            id: "DET-2".to_string(),
            file: "04-determinism-contract.md".to_string(),
            line: 11,
            text: "The optional path MAY exist.".to_string(),
        },
    ];
    let tasks = vec![
        Task {
            id: "T-DET-1".to_string(),
            file: "04-determinism-contract.md".to_string(),
            line: 20,
            text: "- [ ] **T-DET-1** Do it. - satisfies [DET-99]; spec section.".to_string(),
            satisfies: BTreeSet::from(["DET-99".to_string()]),
        },
        Task {
            id: "T-DET-2".to_string(),
            file: "05-execution-model.md".to_string(),
            line: 21,
            text: "- [ ] **T-DET-2** Drifted. - satisfies [DET-2]; spec section.".to_string(),
            satisfies: BTreeSet::from(["DET-2".to_string()]),
        },
    ];
    let task_prefix_files = BTreeMap::from([("DET".to_string(), "04".to_string())]);
    let phase_plan_order = vec!["T-DET-1".to_string()];

    let failures = requirement_coverage_failures(&requirements, &tasks)
        .into_iter()
        .chain(task_reference_failures(&requirements, &tasks))
        .chain(task_checklist_failures(
            &tasks,
            &task_prefix_files,
            &phase_plan_order,
        ))
        .collect::<Vec<_>>();

    assert_contains(&failures, "DET-1");
    assert_contains(&failures, "DET-99");
    assert_contains(&failures, "05-execution-model.md");
    assert_contains(&failures, "not listed in the phase plan");
}

#[test]
fn rfc_consistency_rules_reject_duplicate_requirements() {
    let requirements = vec![
        Requirement {
            id: "DET-1".to_string(),
            file: "04-determinism-contract.md".to_string(),
            line: 10,
            text: "Each run MUST be deterministic.".to_string(),
        },
        Requirement {
            id: "DET-1".to_string(),
            file: "04-determinism-contract.md".to_string(),
            line: 20,
            text: "A duplicated requirement MUST fail.".to_string(),
        },
    ];
    let failures = duplicate_requirement_failures(&requirements);

    assert_contains(&failures, "duplicate requirement [DET-1]");
}

#[test]
fn rfc_consistency_rules_reject_undefined_and_unreferenced_gates() {
    let gate_catalog = BTreeSet::from([
        "gate:defined-but-unreferenced".to_string(),
        "gate:referenced".to_string(),
    ]);
    let referenced_gates = BTreeSet::from([
        "gate:referenced".to_string(),
        "gate:referenced-but-undefined".to_string(),
    ]);

    let failures = gate_reference_failures(&gate_catalog, &referenced_gates);

    assert_contains(&failures, "gate:referenced-but-undefined");
    assert_contains(&failures, "referenced gate is absent from file 24 catalog");
    assert_contains(&failures, "gate:defined-but-unreferenced");
    assert_contains(
        &failures,
        "catalog gate is not referenced outside the catalog table",
    );
}

#[test]
fn banned_name_scan_rejects_configured_terms() {
    let findings = scan_banned_names(
        Path::new("synthetic.md"),
        "This mentions Forbidden-Product directly.",
        &[BannedTerm {
            term: "forbidden-product",
            reason: "synthetic banned name",
        }],
    );

    assert_contains(&findings, "synthetic banned name");
}

#[test]
fn checklist_sync_rules_reject_order_and_text_drift() {
    let tasks = vec![
        Task {
            id: "T-DET-1".to_string(),
            file: "04-determinism-contract.md".to_string(),
            line: 20,
            text: "- [ ] **T-DET-1** First task. — satisfies [DET-1]; spec §1.".to_string(),
            satisfies: BTreeSet::from(["DET-1".to_string()]),
        },
        Task {
            id: "T-DET-2".to_string(),
            file: "04-determinism-contract.md".to_string(),
            line: 21,
            text: "- [x] **T-DET-2** Second task. — satisfies [DET-2]; spec §2.".to_string(),
            satisfies: BTreeSet::from(["DET-2".to_string()]),
        },
    ];
    let reversed_phase_order = vec!["T-DET-2".to_string(), "T-DET-1".to_string()];

    let order_failures = task_order_failures(&tasks, &reversed_phase_order);
    assert_contains(&order_failures, "checklist order drift");

    let stale_files = vec![RfcFile {
        name: "32-implementation-plan.md".to_string(),
        content: "Checklist sync digest: `rfc0010-checklist-v1:0000000000000000`".to_string(),
    }];
    let digest_failures =
        task_manifest_digest_failures(&stale_files, &tasks, &reversed_phase_order);
    assert_contains(&digest_failures, "checklist sync digest drifted");

    let digest = checklist_text_digest(&tasks, &reversed_phase_order);
    let current_files = vec![RfcFile {
        name: "32-implementation-plan.md".to_string(),
        content: format!("Checklist sync digest: `{digest}`"),
    }];
    assert!(
        task_manifest_digest_failures(&current_files, &tasks, &reversed_phase_order).is_empty()
    );
}

#[test]
fn phase_plan_parser_expands_main_ranges_without_promoting_subset_mentions() {
    let docs = vec![RfcFile {
        name: "32-implementation-plan.md".to_string(),
        content: [
            "## Phase 1",
            "- Determinism mechanisms (incl. late tasks `T-DET-29 ... T-DET-31`): `T-DET-1 ... T-DET-31`.",
            "- Patterns realized here: `T-PAT-1, T-PAT-4, T-PAT-5`.",
            "## Requirement coverage",
        ]
        .join("\n"),
    }];

    let order = match phase_plan_task_order(&docs) {
        Ok(order) => order,
        Err(error) => panic!("synthetic phase plan should parse: {error}"),
    };
    assert_eq!(order.first().map(String::as_str), Some("T-DET-1"));
    assert_eq!(order.get(1).map(String::as_str), Some("T-DET-2"));
    assert_eq!(order.get(28).map(String::as_str), Some("T-DET-29"));
    assert_eq!(order.get(30).map(String::as_str), Some("T-DET-31"));
    assert_eq!(order.get(31).map(String::as_str), Some("T-PAT-1"));
    assert_eq!(order.get(32).map(String::as_str), Some("T-PAT-4"));
    assert_eq!(order.get(33).map(String::as_str), Some("T-PAT-5"));
}

#[derive(Debug)]
struct RfcFile {
    name: String,
    content: String,
}

#[derive(Debug)]
struct Requirement {
    id: String,
    file: String,
    line: usize,
    text: String,
}

#[derive(Debug)]
struct Task {
    id: String,
    file: String,
    line: usize,
    text: String,
    satisfies: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct TaskMention {
    id: String,
    start: usize,
    end: usize,
}

#[derive(Clone, Debug)]
struct TaskRange {
    prefix: String,
    first: u32,
    last: u32,
    start: usize,
    end: usize,
}

#[derive(Clone, Copy, Debug)]
struct BannedTerm {
    term: &'static str,
    reason: &'static str,
}

const BANNED_TERMS: &[BannedTerm] = &[BannedTerm {
    term: concat!("anti", "thesis"),
    reason: "third-party commercial product name",
}];
const CHECKLIST_DIGEST_PREFIX: &str = "rfc0010-checklist-v1:";
