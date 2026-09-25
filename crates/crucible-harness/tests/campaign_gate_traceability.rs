//! Executable requirement-to-gate traceability for RFC-0020.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crucible_harness::campaign_gates::{
    CampaignGateContract, CampaignGateSpec, CampaignGateTargetKind, ExactSelector, campaign_gates,
    find_campaign_gate,
};
use crucible_harness::gate_targets::gate_targets;

#[path = "campaign_gate_traceability/integration_exact.rs"]
mod integration_exact;
#[path = "campaign_gate_traceability/schema_source_coverage.rs"]
mod schema_source_coverage;

use integration_exact::{
    IntegrationNixContract, integration_exact_target_failures, integration_selector_nix_failures,
};

const TRACEABILITY: &str =
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/requirement-traceability.tsv");
const SCHEMA_REGISTRY: &str =
    include_str!("../../../docs/rfcs/0020-crucible-campaigns/schema-registry.tsv");
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
fn schema_registry_assigns_versions_owners_and_compatibility_gates() {
    let mut names = BTreeSet::new();

    for (line_number, line) in SCHEMA_REGISTRY.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields = line.split('\t').collect::<Vec<_>>();
        assert_eq!(
            fields.len(),
            5,
            "schema registry line {} must contain five fields",
            line_number + 1
        );

        let [name, version, owner, object_kind, gates] = fields.as_slice() else {
            unreachable!("field count was checked above");
        };
        assert!(names.insert(*name), "duplicate schema {name}");
        assert!(
            version.parse::<u32>().is_ok_and(|version| version > 0),
            "{name} must have a positive version"
        );
        assert!(owner.contains("::"), "{name} must name a module owner");
        assert!(!object_kind.is_empty(), "{name} must name an object kind");
        assert!(!gates.is_empty(), "{name} must name a compatibility gate");

        for gate in gates.split(',') {
            assert!(
                find_campaign_gate(gate).is_some(),
                "{name} names unknown compatibility gate {gate}"
            );
        }
    }

    assert!(!names.is_empty(), "schema registry must not be empty");
}

#[test]
fn exact_targets_fail_closed_on_source_and_runner_drift() {
    let selector = ExactSelector {
        source: "crates/example/src/native.rs",
        name: "native::flight::proves_equivalence",
    };
    let unignored_source = "#[test]\nfn proves_equivalence() {}\n";
    let source_failures = exact_selector_source_failures(
        "gate:fixture",
        selector.source,
        selector.name,
        unignored_source,
        true,
    );
    assert!(
        source_failures
            .iter()
            .any(|failure| failure.contains("not explicitly ignored"))
    );

    let mismatched = ExactSelector {
        source: selector.source,
        name: "native::flight::missing_selector",
    };
    let ignored_source = "#[test]\n#[ignore = \"native\"]\nfn proves_equivalence() {}\n";
    let mismatch_failures = exact_selector_source_failures(
        "gate:fixture",
        mismatched.source,
        mismatched.name,
        ignored_source,
        true,
    );
    assert!(
        mismatch_failures
            .iter()
            .any(|failure| failure.contains("is absent"))
    );
    let ordinary_failures = exact_selector_source_failures(
        "gate:fixture",
        selector.source,
        selector.name,
        ignored_source,
        false,
    );
    assert!(
        ordinary_failures
            .iter()
            .any(|failure| failure.contains("unexpectedly ignored"))
    );

    let wrong_runner = "cargo test -p another-package --lib\n";
    let runner_failures = library_selector_nix_failures(
        "gate:fixture",
        "example",
        "checks.fixture",
        &[selector],
        wrong_runner,
        true,
    );
    assert!(
        runner_failures
            .iter()
            .any(|failure| failure.contains("example --lib"))
    );
    assert!(
        runner_failures
            .iter()
            .any(|failure| failure.contains("--ignored --exact"))
    );
    assert!(
        runner_failures
            .iter()
            .any(|failure| failure.contains("one-passed"))
    );
    assert!(
        runner_failures
            .iter()
            .any(|failure| failure.contains("wrong default attribute"))
    );
    assert!(
        runner_failures
            .iter()
            .any(|failure| failure.contains("wrong result gate"))
    );
    assert!(
        runner_failures
            .iter()
            .any(|failure| failure.contains(selector.name))
    );

    let ordinary_runner_failures = library_selector_nix_failures(
        "gate:fixture",
        "example",
        "checks.fixture",
        &[selector],
        wrong_runner,
        false,
    );
    assert!(
        ordinary_runner_failures
            .iter()
            .any(|failure| failure.contains("listing guard"))
    );

    let duplicate_name = ExactSelector {
        source: "crates/example/src/another_native.rs",
        name: selector.name,
    };
    let duplicate_failures = library_exact_target_failures(
        &workspace_root(),
        "gate:fixture",
        "missing-example-package",
        &[selector, duplicate_name],
        "tests/crucible/missing-native.nix",
        "checks.fixture",
        true,
    );
    assert!(
        duplicate_failures
            .iter()
            .any(|failure| failure.contains("duplicate library exact selector"))
    );

    let integration_selector = ExactSelector {
        source: selector.source,
        name: selector.name,
    };
    let integration_failures = integration_selector_nix_failures(IntegrationNixContract {
        gate: "gate:fixture",
        package: "example",
        test_target: "example_process",
        selectors: &[integration_selector],
        runner: "example-flight",
        evidence: &["proven=typed-product"],
        nix: wrong_runner,
        ignored: true,
    });
    assert!(
        integration_failures
            .iter()
            .any(|failure| failure.contains("example --test example_process"))
    );
    assert!(
        integration_failures
            .iter()
            .any(|failure| failure.contains("does not run example-flight"))
    );
    assert!(
        integration_failures
            .iter()
            .any(|failure| failure.contains("one-passed"))
    );
    assert!(
        integration_failures
            .iter()
            .any(|failure| failure.contains("omits evidence proven=typed-product"))
    );
}

#[test]
fn registered_library_exact_targets_match_sources_and_nix() {
    let root = workspace_root();
    let mut failures = Vec::new();

    for gate in campaign_gates() {
        let CampaignGateContract::Automated { targets, nix_attr } = gate.contract;
        for target in targets {
            match target.kind {
                CampaignGateTargetKind::LibExact {
                    selectors,
                    nix_source,
                    ignored,
                } => failures.extend(library_exact_target_failures(
                    &root,
                    gate.name,
                    target.package,
                    selectors,
                    nix_source,
                    nix_attr,
                    ignored,
                )),
                CampaignGateTargetKind::LibExactAggregate {
                    selectors,
                    producer_nix_source,
                    producer_nix_attr,
                    producer_gate,
                    aggregate_nix_source,
                    evidence_input,
                    evidence,
                    ignored,
                } => failures.extend(library_exact_aggregate_target_failures(
                    &root,
                    LibraryExactAggregateContract {
                        gate: gate.name,
                        package: target.package,
                        selectors,
                        producer_nix_source,
                        producer_nix_attr,
                        producer_gate,
                        aggregate_nix_source,
                        evidence_input,
                        aggregate_nix_attr: nix_attr,
                        evidence,
                        ignored,
                    },
                )),
                CampaignGateTargetKind::Integration { .. }
                | CampaignGateTargetKind::IntegrationExact { .. } => {}
            }
        }
    }

    assert!(
        failures.is_empty(),
        "RFC-0020 library exact targets drifted:\n{}",
        failures.join("\n")
    );
}

#[test]
fn registered_integration_exact_targets_match_sources_and_nix() {
    let root = workspace_root();
    let mut failures = Vec::new();

    for gate in campaign_gates() {
        let CampaignGateContract::Automated { targets, .. } = gate.contract;
        for target in targets {
            if matches!(target.kind, CampaignGateTargetKind::IntegrationExact { .. }) {
                failures.extend(integration_exact_target_failures(&root, gate.name, target));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "RFC-0020 integration exact targets drifted:\n{}",
        failures.join("\n")
    );
}

#[test]
fn hot_fork_isolation_binds_native_aggregate_evidence() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let gate = find_campaign_gate("gate:hot-fork-isolation")
        .ok_or("hot-fork-isolation gate is missing")?;
    let CampaignGateContract::Automated { targets, nix_attr } = gate.contract;

    assert_eq!(
        nix_attr,
        "checks.crucible.phase7.gates.hotForkIsolation.rawGate"
    );
    assert_eq!(targets.len(), 1);
    let CampaignGateTargetKind::LibExactAggregate {
        selectors,
        producer_nix_source,
        producer_nix_attr,
        producer_gate,
        aggregate_nix_source,
        evidence_input,
        evidence,
        ignored,
    } = targets[0].kind
    else {
        return Err("hot-fork-isolation must authenticate an exact native producer".into());
    };
    assert_eq!(selectors.len(), 2);
    assert_eq!(
        producer_nix_source,
        "tests/crucible/phase7-qemu-hot-fork-atomic-world-vm.nix"
    );
    assert_eq!(
        producer_nix_attr,
        "checks.crucible.phase7.gates.worldForkAtomicity"
    );
    assert_eq!(producer_gate, "gate:world-fork-atomicity");
    assert_eq!(
        aggregate_nix_source,
        "tests/crucible/phase7-crucible-hot-fork-isolation.nix"
    );
    assert_eq!(evidence_input, "nativeIsolation");
    assert!(ignored);
    assert_eq!(evidence.len(), 4);
    assert!(evidence[0].contains("native_isolation_scopes="));
    assert!(evidence[1].contains("native_negative_isolation_matrix="));
    assert!(evidence[2].contains("native_negative_isolation_rejected_before="));
    assert!(evidence[3].contains("native_negative_isolation_source_unchanged="));

    let first_selector = targets
        .iter()
        .find_map(|target| match target.kind {
            CampaignGateTargetKind::LibExact { selectors, .. }
            | CampaignGateTargetKind::LibExactAggregate { selectors, .. } => selectors.first(),
            CampaignGateTargetKind::Integration { .. }
            | CampaignGateTargetKind::IntegrationExact { .. } => None,
        })
        .ok_or("hot-fork-isolation native selector is missing")?;
    let selector_source = fs::read_to_string(root.join(first_selector.source))?;
    let function_name = first_selector
        .name
        .rsplit("::")
        .next()
        .ok_or("hot-fork-isolation selector has no function name")?;
    let drifted_source = selector_source.replace(
        &format!("fn {function_name}("),
        "fn removed_hot_fork_isolation_selector(",
    );
    assert!(
        exact_selector_source_failures(
            gate.name,
            first_selector.source,
            first_selector.name,
            &drifted_source,
            false,
        )
        .iter()
        .any(|failure| failure.contains("is absent"))
    );

    Ok(())
}

#[test]
fn world_fork_native_matrix_completes_the_canonical_gate() -> Result<(), Box<dyn Error>> {
    let gate = find_campaign_gate("gate:world-fork-atomicity")
        .ok_or("world-fork-atomicity gate is missing")?;
    let CampaignGateContract::Automated { targets, nix_attr } = gate.contract;

    assert_eq!(nix_attr, "checks.crucible.phase7.gates.worldForkAtomicity");
    assert_eq!(targets.len(), 1);
    let CampaignGateTargetKind::LibExact {
        selectors,
        nix_source,
        ignored,
    } = targets[0].kind
    else {
        return Err("world-fork-atomicity must run exact daemon library tests".into());
    };
    assert_eq!(selectors.len(), 5);
    assert_eq!(
        nix_source,
        "tests/crucible/phase7-qemu-hot-fork-atomic-world-vm.nix"
    );
    assert!(
        ignored,
        "native world-fork tests must be explicitly selected"
    );

    Ok(())
}

#[test]
fn campaign_replay_binds_portable_and_production_qemu_evidence() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let gate =
        find_campaign_gate("gate:campaign-replay").ok_or("campaign-replay gate is missing")?;
    let CampaignGateContract::Automated { targets, nix_attr } = gate.contract;

    assert_eq!(targets.len(), 3);
    let default_nix = fs::read_to_string(root.join("tests/crucible/default.nix"))?;
    assert!(contract_failures(&root, &default_nix, gate).is_empty());
    assert_eq!(
        nix_attr,
        "checks.crucible.phase4.gates.campaignReplay.rawGate"
    );

    Ok(())
}

#[test]
fn typed_choice_product_checkpoint_uses_the_packaged_campaign_flight() -> Result<(), Box<dyn Error>>
{
    let root = workspace_root();
    let gate = find_campaign_gate("gate:typed-choice-product-checkpoint")
        .ok_or("typed-choice product checkpoint gate is missing")?;
    let CampaignGateContract::Automated { targets, nix_attr } = gate.contract;

    assert_eq!(
        nix_attr,
        "checks.crucible.phase2.gates.typedChoiceProductCheckpoint"
    );
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].package, "crucible-cli");
    let CampaignGateTargetKind::IntegrationExact {
        test_target,
        selectors,
        nix_sources,
        runner,
        evidence,
        ignored,
    } = targets[0].kind
    else {
        return Err(
            "typed-choice product checkpoint must run exact packaged-campaign tests".into(),
        );
    };
    assert_eq!(test_target, "campaign_store_process");
    assert_eq!(selectors.len(), 1);
    assert_eq!(
        selectors[0].name,
        "packaged::guest_choice::public_guest_choices_survive_exact_checkpoint_and_daemon_restart"
    );
    assert_eq!(
        nix_sources,
        [
            "tests/crucible/phase4-packaged-campaign-choice-vm.nix",
            "tests/crucible/phase4-packaged-campaign-vm.nix",
        ]
    );
    assert_eq!(runner, "campaign-process-flight");
    assert_eq!(
        evidence,
        [
            "gate=gate:typed-choice-product-checkpoint",
            "proven=typed-guest-registration,fresh-qemu-restore",
        ]
    );
    assert!(ignored, "packaged QEMU flight must select its ignored test");

    let default_nix = fs::read_to_string(root.join("tests/crucible/default.nix"))?;
    assert!(contract_failures(&root, &default_nix, gate).is_empty());

    Ok(())
}

#[test]
fn every_rfc_requirement_has_an_executable_gate_contract() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let default_nix = fs::read_to_string(root.join("tests/crucible/default.nix"))?;
    let declared = declared_requirements();
    let declared_tasks = declared_implementation_tasks();
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
        let requirement = fields[0];
        assert!(
            is_requirement_identifier(requirement),
            "traceability line {} must name one requirement ID",
            line_number + 1
        );
        let tasks = fields[1].split(',').collect::<Vec<_>>();
        let gates = fields[2].split(',').collect::<Vec<_>>();
        assert!(
            !fields[1].is_empty(),
            "{requirement} has no implementing task"
        );
        assert!(
            !fields[2].is_empty(),
            "{requirement} has no executable gate"
        );

        for task in tasks {
            if !declared_tasks.contains(task) {
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
        assert!(
            mapped.insert(requirement.to_owned()),
            "requirement {requirement} is mapped more than once"
        );
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
        .map(|gate| {
            let CampaignGateContract::Automated { nix_attr, .. } = gate.contract;
            nix_attr
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
    let CampaignGateContract::Automated { targets, nix_attr } = gate.contract;
    automated_contract_failures(root, default_nix, gate.name, targets, nix_attr)
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
        match automated.kind {
            CampaignGateTargetKind::Integration { test_target } => {
                failures.extend(integration_target_failures(
                    root,
                    gate,
                    automated.package,
                    test_target,
                ));
            }
            CampaignGateTargetKind::IntegrationExact { .. } => {
                failures.extend(integration_exact_target_failures(root, gate, automated))
            }
            CampaignGateTargetKind::LibExact {
                selectors,
                nix_source,
                ignored,
            } => {
                failures.extend(library_exact_target_failures(
                    root,
                    gate,
                    automated.package,
                    selectors,
                    nix_source,
                    nix_attr,
                    ignored,
                ));
            }
            CampaignGateTargetKind::LibExactAggregate {
                selectors,
                producer_nix_source,
                producer_nix_attr,
                producer_gate,
                aggregate_nix_source,
                evidence_input,
                evidence,
                ignored,
            } => failures.extend(library_exact_aggregate_target_failures(
                root,
                LibraryExactAggregateContract {
                    gate,
                    package: automated.package,
                    selectors,
                    producer_nix_source,
                    producer_nix_attr,
                    producer_gate,
                    aggregate_nix_source,
                    evidence_input,
                    aggregate_nix_attr: nix_attr,
                    evidence,
                    ignored,
                },
            )),
        }
    }

    if !default_nix.contains(&format!("\"{nix_attr}\" =")) {
        failures.push(format!(
            "{gate}: evaluated Nix target {nix_attr} is not registered"
        ));
    }

    failures
}

fn integration_target_failures(
    root: &Path,
    gate: &str,
    package: &str,
    test_target: &str,
) -> Vec<String> {
    let mut failures = Vec::new();
    let mapped = gate_targets().iter().any(|target| {
        target.gate == gate && target.package == package && target.test_target == test_target
    });
    if !mapped {
        failures.push(format!("{gate}: missing target {package}:{test_target}"));
    }

    let test_path = root
        .join("crates")
        .join(package)
        .join("tests")
        .join(format!("{test_target}.rs"));
    if !test_path.is_file() {
        failures.push(format!(
            "{gate}: target source {} is missing",
            test_path.display()
        ));
    }

    failures
}

fn library_exact_target_failures(
    root: &Path,
    gate: &str,
    package: &str,
    selectors: &[ExactSelector],
    nix_source: &str,
    nix_attr: &str,
    ignored: bool,
) -> Vec<String> {
    let mut failures = Vec::new();
    let manifest = root.join("crates").join(package).join("Cargo.toml");
    if !manifest.is_file() {
        failures.push(format!(
            "{gate}: library package manifest {} is missing",
            manifest.display()
        ));
    }
    if selectors.is_empty() {
        failures.push(format!("{gate}: library exact selector set is empty"));
    }

    let mut unique_selectors = BTreeSet::new();
    for selector in selectors {
        if !unique_selectors.insert(selector.name) {
            failures.push(format!(
                "{gate}: duplicate library exact selector {}",
                selector.name
            ));
        }
        let source_path = root.join(selector.source);
        match fs::read_to_string(&source_path) {
            Ok(source) => failures.extend(exact_selector_source_failures(
                gate,
                selector.source,
                selector.name,
                &source,
                ignored,
            )),
            Err(_) => failures.push(format!(
                "{gate}: library selector source {} is missing",
                source_path.display()
            )),
        }
    }

    let nix_path = root.join(nix_source);
    match fs::read_to_string(&nix_path) {
        Ok(nix) => failures.extend(library_selector_nix_failures(
            gate, package, nix_attr, selectors, &nix, ignored,
        )),
        Err(_) => failures.push(format!(
            "{gate}: library selector Nix source {} is missing",
            nix_path.display()
        )),
    }

    failures
}

struct LibraryExactAggregateContract<'a> {
    gate: &'a str,
    package: &'a str,
    selectors: &'a [ExactSelector],
    producer_nix_source: &'a str,
    producer_nix_attr: &'a str,
    producer_gate: &'a str,
    aggregate_nix_source: &'a str,
    evidence_input: &'a str,
    aggregate_nix_attr: &'a str,
    evidence: &'a [&'a str],
    ignored: bool,
}

fn library_exact_aggregate_target_failures(
    root: &Path,
    contract: LibraryExactAggregateContract<'_>,
) -> Vec<String> {
    let mut failures = library_exact_target_failures(
        root,
        contract.producer_gate,
        contract.package,
        contract.selectors,
        contract.producer_nix_source,
        contract.producer_nix_attr,
        contract.ignored,
    );
    let aggregate_path = root.join(contract.aggregate_nix_source);
    match fs::read_to_string(&aggregate_path) {
        Ok(aggregate) => {
            if !aggregate.contains(&format!("attrPath ? \"{}\"", contract.aggregate_nix_attr)) {
                failures.push(format!(
                    "{}: aggregate Nix flight has the wrong default attribute",
                    contract.gate
                ));
            }
            if !aggregate.contains(&format!("gate={}", contract.gate)) {
                failures.push(format!(
                    "{}: aggregate Nix flight has the wrong result gate",
                    contract.gate
                ));
            }
            if !aggregate.contains(contract.evidence_input) {
                failures.push(format!(
                    "{}: aggregate Nix flight omits its native evidence input",
                    contract.gate
                ));
            }
            for required in contract.evidence {
                if !aggregate.contains(required) {
                    failures.push(format!(
                        "{}: aggregate Nix flight omits evidence {required}",
                        contract.gate
                    ));
                }
            }
        }
        Err(_) => failures.push(format!(
            "{}: aggregate Nix source {} is missing",
            contract.gate,
            aggregate_path.display()
        )),
    }
    failures
}

fn exact_selector_source_failures(
    gate: &str,
    selector_source: &str,
    selector_name: &str,
    source: &str,
    ignored: bool,
) -> Vec<String> {
    let Some(function_name) = selector_name.rsplit("::").next() else {
        return vec![format!(
            "{gate}: exact selector {selector_name} has no function name"
        )];
    };
    let declaration = format!("fn {function_name}(");
    let Some(declaration_offset) = source.find(&declaration) else {
        return vec![format!(
            "{gate}: exact selector {selector_name} is absent from {selector_source}"
        )];
    };
    let mut saw_test = false;
    let mut saw_ignore = false;
    for line in source[..declaration_offset].lines().rev() {
        let line = line.trim();
        if line.is_empty() {
            if saw_test || saw_ignore {
                break;
            }
            continue;
        }
        if line.starts_with("#[") {
            saw_test |= line == "#[test]";
            saw_ignore |= line.starts_with("#[ignore");
            continue;
        }
        break;
    }
    if !saw_test {
        return vec![format!(
            "{gate}: exact selector {selector_name} is not a test"
        )];
    }
    if ignored && !saw_ignore {
        return vec![format!(
            "{gate}: exact selector {selector_name} is not explicitly ignored"
        )];
    }
    if !ignored && saw_ignore {
        return vec![format!(
            "{gate}: ordinary exact selector {selector_name} is unexpectedly ignored"
        )];
    }

    Vec::new()
}

fn library_selector_nix_failures(
    gate: &str,
    package: &str,
    nix_attr: &str,
    selectors: &[ExactSelector],
    nix: &str,
    ignored: bool,
) -> Vec<String> {
    let mut failures = Vec::new();
    let directly_runs_package = contains_word_sequence(nix, &["-p", package, "--lib"]);
    let runs_parameterized_helper = contains_word_sequence(nix, &["-p", "\"$package\"", "--lib"])
        && contains_word_sequence(nix, &["run_exact_lib_test", package]);
    if !directly_runs_package && !runs_parameterized_helper {
        failures.push(format!(
            "{gate}: library Nix flight does not build {package} --lib"
        ));
    }
    if !nix.contains("--exact") {
        failures.push(format!(
            "{gate}: library Nix flight lacks exact-selector execution"
        ));
    }
    if ignored && !nix.contains("--ignored --exact \"$name\"") {
        failures.push(format!(
            "{gate}: library Nix flight lacks --ignored --exact execution"
        ));
    }
    let exact_one_passed_summary =
        nix.contains("test result: ok. 1 passed; 0 failed; 0 ignored;")
            || (nix.contains(
                r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9]+(\.[0-9]+)?s$",
            ) && nix.contains("summary_count=$(${pkgs.grep}/bin/grep -Ec")
                && nix.contains("[ \"$summary_count\" -eq 1 ]"));
    if ignored && !exact_one_passed_summary {
        failures.push(format!(
            "{gate}: library Nix flight lacks the exact one-passed assertion"
        ));
    }
    if !ignored
        && (!nix.contains("--exact --list")
            || !nix.contains("grep -Fxc")
            || !nix.contains("test result: ok. 1 passed;"))
    {
        failures.push(format!(
            "{gate}: library Nix flight lacks an exact selector listing guard and one-passed assertion"
        ));
    }
    if !nix.contains(&format!("attrPath ? \"{nix_attr}\"")) {
        failures.push(format!(
            "{gate}: library Nix flight has the wrong default attribute"
        ));
    }
    if !nix.contains(&format!("gate={gate}")) {
        failures.push(format!(
            "{gate}: library Nix flight has the wrong result gate"
        ));
    }
    for selector in selectors {
        if !nix.contains(selector.name) {
            failures.push(format!(
                "{gate}: library Nix flight omits selector {}",
                selector.name
            ));
        }
    }

    failures
}

fn contains_word_sequence(text: &str, expected: &[&str]) -> bool {
    let words = text
        .split_whitespace()
        .filter(|word| *word != "\\")
        .collect::<Vec<_>>();

    words
        .windows(expected.len())
        .any(|window| window == expected)
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

fn is_requirement_identifier(value: &str) -> bool {
    let Some((family, number)) = value.rsplit_once('-') else {
        return false;
    };
    !family.is_empty()
        && family.bytes().all(|byte| byte.is_ascii_uppercase())
        && number.parse::<u32>().is_ok()
}

fn declared_implementation_tasks() -> BTreeSet<&'static str> {
    rfc_implementation_plan()
        .lines()
        .filter_map(|line| {
            line.strip_prefix("- [ ] **")
                .or_else(|| line.strip_prefix("- [x] **"))
                .and_then(|rest| rest.split_once("**"))
                .map(|(task, _)| task)
        })
        .filter(|task| task.starts_with("T-CAM-"))
        .collect()
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
