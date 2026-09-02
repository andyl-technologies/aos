//! Executable requirement-to-task traceability gate for RFC-0017.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;

const IMPLEMENTATION_PLAN: &str =
    include_str!("../../../docs/rfcs/0017-crucible-campaigns/11-implementation-plan.md");
const TRACEABILITY: &str =
    include_str!("../../../docs/rfcs/0017-crucible-campaigns/requirement-traceability.tsv");
const RFC_SOURCES: &[&str] = &[
    include_str!("../../../docs/rfcs/0017-crucible-campaigns/README.md"),
    include_str!("../../../docs/rfcs/0017-crucible-campaigns/00-goals-and-invariants.md"),
    include_str!("../../../docs/rfcs/0017-crucible-campaigns/01-campaign-data-model.md"),
    include_str!(
        "../../../docs/rfcs/0017-crucible-campaigns/02-selectables-and-choice-protocol.md"
    ),
    include_str!("../../../docs/rfcs/0017-crucible-campaigns/03-exploration-and-guidance.md"),
    include_str!("../../../docs/rfcs/0017-crucible-campaigns/04-lazy-frontier-and-daemon.md"),
    include_str!("../../../docs/rfcs/0017-crucible-campaigns/04a-coordinator-executor-contract.md"),
    include_str!("../../../docs/rfcs/0017-crucible-campaigns/05-hot-fork-and-checkpoints.md"),
    include_str!("../../../docs/rfcs/0017-crucible-campaigns/06-storage-replication-and-gc.md"),
    include_str!("../../../docs/rfcs/0017-crucible-campaigns/07-user-experience-and-apis.md"),
    include_str!(
        "../../../docs/rfcs/0017-crucible-campaigns/08-observability-measurement-debugging.md"
    ),
    include_str!(
        "../../../docs/rfcs/0017-crucible-campaigns/09-security-compatibility-and-operations.md"
    ),
    include_str!("../../../docs/rfcs/0017-crucible-campaigns/10-performance-and-validation.md"),
    IMPLEMENTATION_PLAN,
    include_str!("../../../docs/rfcs/0017-crucible-campaigns/12-decisions-and-open-questions.md"),
    include_str!("../../../docs/rfcs/0017-crucible-campaigns/13-worked-network-campaign.md"),
    include_str!(
        "../../../docs/rfcs/0017-crucible-campaigns/14-manual-validation-and-dogfooding.md"
    ),
];

#[test]
fn every_rfc_requirement_names_existing_tasks_and_gates() {
    let declared = declared_requirements();
    let mut mapped = BTreeSet::new();

    for (line_number, line) in TRACEABILITY.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        assert_eq!(
            fields.len(),
            3,
            "traceability line {} must contain exactly three tab-separated fields",
            line_number + 1
        );
        let requirements = expand_range(fields[0]);
        let tasks = fields[1].split(',').collect::<Vec<_>>();
        let gates = fields[2].split(',').collect::<Vec<_>>();
        assert!(!tasks.is_empty(), "{} has no implementing task", fields[0]);
        assert!(
            !gates.is_empty(),
            "{} has no executable or manual gate",
            fields[0]
        );

        for task in tasks {
            assert!(
                task.starts_with("T-CAM-") && IMPLEMENTATION_PLAN.contains(task),
                "traceability names missing implementation task {task}"
            );
        }
        for gate in gates {
            assert!(
                gate.starts_with("gate:") && IMPLEMENTATION_PLAN.contains(gate),
                "traceability names missing gate {gate}"
            );
        }
        for requirement in requirements {
            assert!(
                mapped.insert(requirement.clone()),
                "requirement {requirement} is mapped more than once"
            );
        }
    }

    assert_eq!(
        mapped, declared,
        "traceability and normative requirement definitions differ"
    );
}

fn declared_requirements() -> BTreeSet<String> {
    let mut requirements = BTreeSet::new();
    for source in RFC_SOURCES {
        for line in source.lines() {
            let Some(rest) = line.strip_prefix("- **[") else {
                continue;
            };
            let Some((identifier, _)) = rest.split_once("]**") else {
                continue;
            };
            if is_requirement_identifier(identifier) {
                assert!(
                    requirements.insert(identifier.to_owned()),
                    "duplicate normative requirement {identifier}"
                );
            }
        }
    }
    requirements
}

fn expand_range(value: &str) -> BTreeSet<String> {
    let (first, last) = value
        .split_once("..")
        .expect("traceability requirement must be an inclusive range");
    let (family, first_number) = first
        .rsplit_once('-')
        .expect("traceability range start must have a family and number");
    let first_number = first_number
        .parse::<u32>()
        .expect("traceability range start must be numeric");
    let last_number = last
        .parse::<u32>()
        .expect("traceability range end must be numeric");
    assert!(first_number <= last_number, "range {value} is reversed");

    (first_number..=last_number)
        .map(|number| format!("{family}-{number}"))
        .collect()
}

fn is_requirement_identifier(value: &str) -> bool {
    let Some((family, number)) = value.rsplit_once('-') else {
        return false;
    };
    !family.is_empty()
        && family.bytes().all(|byte| byte.is_ascii_uppercase())
        && number.parse::<u32>().is_ok()
}
