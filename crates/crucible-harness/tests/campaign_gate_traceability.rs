//! Executable requirement-to-gate traceability for RFC-0020.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crucible_harness::campaign_gates::{
    CampaignGateContract, CampaignGateSpec, campaign_gates, find_campaign_gate,
};
use crucible_harness::gate_targets::gate_targets;

const TRACEABILITY: &str =
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/requirement-traceability.tsv");
const RFC_SOURCES: &[&str] = &[
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/README.md"),
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/00-goals-and-invariants.md"),
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/01-campaign-data-model.md"),
    include_str!(
        "../../../docs/rfcs/0020-crucible-campaigns/02-selectables-and-choice-protocol.md"
    ),
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/03-exploration-and-guidance.md"),
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/04-lazy-frontier-and-daemon.md"),
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/04a-coordinator-executor-contract.md"),
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/05-hot-fork-and-checkpoints.md"),
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/06-storage-replication-and-gc.md"),
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/07-user-experience-and-apis.md"),
    include_str!(
        "../../../docs/rfcs/0020-crucible-campaigns/08-observability-measurement-debugging.md"
    ),
    include_str!(
        "../../../docs/rfcs/0020-crucible-campaigns/09-security-compatibility-and-operations.md"
    ),
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/10-performance-and-validation.md"),
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/11-implementation-plan.md"),
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/12-decisions-and-open-questions.md"),
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/13-worked-network-campaign.md"),
    include_str!(
        "../../../docs/rfcs/0020-crucible-campaigns/14-manual-validation-and-dogfooding.md"
    ),
];

#[test]
fn campaign_gate_catalog_is_complete_and_unambiguous() {
    let referenced = traceability_gate_names();
    let cataloged = campaign_gates()
        .iter()
        .map(|gate| gate.name)
        .collect::<BTreeSet<_>>();

    assert_eq!(
        cataloged.len(),
        campaign_gates().len(),
        "duplicate campaign gate"
    );
    assert_eq!(cataloged, referenced, "RFC-0020 gate catalog drift");
}

#[test]
fn every_rfc_requirement_has_an_executable_gate_contract() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let default_nix = fs::read_to_string(root.join("tests/crucible/default.nix"))?;
    let declared = declared_requirements();
    let mut mapped = BTreeSet::new();
    let mut failures = BTreeSet::new();

    validate_evaluated_nix_targets(&mut failures);

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
            if !task.starts_with("T-CAM-") || !rfc_implementation_plan().contains(task) {
                failures.insert(format!(
                    "traceability names missing implementation task {task}"
                ));
            }
        }
        for gate_name in gates {
            match find_campaign_gate(gate_name) {
                Some(gate) => failures.extend(contract_failures(&root, &default_nix, gate)),
                None => {
                    failures.insert(format!("{gate_name}: absent from campaign gate catalog"));
                }
            }
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
        "traceability and requirement definitions differ"
    );
    let failure_report = failures.iter().cloned().collect::<Vec<_>>().join("\n");
    assert!(
        failures.is_empty(),
        "RFC-0020 gate traceability is incomplete:\n{}",
        failure_report
    );

    Ok(())
}

fn validate_evaluated_nix_targets(failures: &mut BTreeSet<String>) {
    let Ok(evaluated) = std::env::var("AUTOMATED_TARGETS") else {
        return;
    };
    let evaluated = evaluated
        .split(',')
        .filter(|target| !target.is_empty())
        .collect::<BTreeSet<_>>();
    let cataloged = campaign_gates()
        .iter()
        .filter_map(|gate| match gate.contract {
            CampaignGateContract::Automated { nix_attr, .. } => Some(nix_attr),
            CampaignGateContract::Manual { .. } | CampaignGateContract::Unsupported => None,
        })
        .collect::<BTreeSet<_>>();

    for missing in cataloged.difference(&evaluated) {
        failures.insert(format!(
            "{missing}: automated catalog target was not evaluated by Nix"
        ));
    }
    for extra in evaluated.difference(&cataloged) {
        failures.insert(format!(
            "{extra}: Nix evaluated target is absent from the automated catalog"
        ));
    }
}

fn contract_failures(root: &Path, default_nix: &str, gate: &CampaignGateSpec) -> Vec<String> {
    match gate.contract {
        CampaignGateContract::Automated { targets, nix_attr } => {
            automated_contract_failures(root, default_nix, gate.name, targets, nix_attr)
        }
        CampaignGateContract::Manual {
            artifact_contract,
            nix_attr,
        } => manual_contract_failures(root, default_nix, gate.name, artifact_contract, nix_attr),
        CampaignGateContract::Unsupported => {
            vec![format!("{}: no executable gate contract", gate.name)]
        }
    }
}

fn automated_contract_failures(
    root: &Path,
    default_nix: &str,
    gate: &str,
    targets: &[crucible_harness::campaign_gates::CampaignGateTarget],
    nix_attr: &str,
) -> Vec<String> {
    let mut failures = Vec::new();
    if targets.is_empty() {
        failures.push(format!("{gate}: automated contract has no Cargo targets"));
    }

    for automated in targets {
        let mapped = gate_targets().iter().any(|target| {
            target.gate == gate
                && target.package == automated.package
                && target.test_target == automated.test_target
                && !target.placeholder
        });
        if !mapped {
            failures.push(format!(
                "{gate}: missing non-placeholder target {}:{}",
                automated.package, automated.test_target
            ));
        }

        let test_path = root
            .join("crates")
            .join(automated.package)
            .join("tests")
            .join(format!("{}.rs", automated.test_target));
        if !test_path.is_file() {
            failures.push(format!(
                "{gate}: target source {} is missing",
                test_path.display()
            ));
        }
    }

    if !default_nix.contains(&format!("\"{nix_attr}\" =")) {
        failures.push(format!(
            "{gate}: evaluated Nix target {nix_attr} is not registered"
        ));
    }

    failures
}

fn manual_contract_failures(
    root: &Path,
    default_nix: &str,
    gate: &str,
    artifact_contract: &str,
    nix_attr: &str,
) -> Vec<String> {
    let mut failures = Vec::new();
    let contract_path = root.join(artifact_contract);
    match fs::read_to_string(&contract_path) {
        Ok(contract) => {
            for field in ["schema", "provenance", "command_journal", "sign_offs"] {
                if !contract.contains(field) {
                    failures.push(format!(
                        "{gate}: manual artifact contract lacks required field {field}"
                    ));
                }
            }
        }
        Err(_) => failures.push(format!(
            "{gate}: manual artifact contract {} is missing",
            contract_path.display()
        )),
    }
    if !default_nix.contains(&format!("attrPath = \"{nix_attr}\"")) {
        failures.push(format!(
            "{gate}: manual evidence validator {nix_attr} is not wired"
        ));
    }

    failures
}

fn traceability_gate_names() -> BTreeSet<&'static str> {
    TRACEABILITY
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .flat_map(|line| line.split('\t').nth(2).unwrap_or_default().split(','))
        .collect()
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

fn rfc_implementation_plan() -> &'static str {
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/11-implementation-plan.md")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("harness crate must live below workspace root")
        .to_path_buf()
}
