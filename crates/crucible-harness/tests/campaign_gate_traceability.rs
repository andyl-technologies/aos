//! Executable requirement-to-gate traceability for RFC-0020.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crucible_harness::campaign_gates::{
    CampaignGateContract, CampaignGateSpec, CampaignGateTargetKind, LibraryExactSelector,
    campaign_gates, find_campaign_gate,
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
fn library_exact_targets_fail_closed_on_source_and_runner_drift() {
    let selector = LibraryExactSelector {
        source: "crates/example/src/native.rs",
        name: "native::flight::proves_equivalence",
    };
    let unignored_source = "#[test]\nfn proves_equivalence() {}\n";
    let source_failures =
        library_selector_source_failures("gate:fixture", &selector, unignored_source, true);
    assert!(
        source_failures
            .iter()
            .any(|failure| failure.contains("not explicitly ignored"))
    );

    let mismatched = LibraryExactSelector {
        source: selector.source,
        name: "native::flight::missing_selector",
    };
    let ignored_source = "#[test]\n#[ignore = \"native\"]\nfn proves_equivalence() {}\n";
    let mismatch_failures =
        library_selector_source_failures("gate:fixture", &mismatched, ignored_source, true);
    assert!(
        mismatch_failures
            .iter()
            .any(|failure| failure.contains("is absent"))
    );
    let ordinary_failures =
        library_selector_source_failures("gate:fixture", &selector, ignored_source, false);
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

    let duplicate_name = LibraryExactSelector {
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
}

#[test]
fn registered_library_exact_targets_match_sources_and_nix() {
    let root = workspace_root();
    let mut failures = Vec::new();

    for gate in campaign_gates() {
        let CampaignGateContract::Automated { targets, nix_attr } = gate.contract else {
            continue;
        };
        for target in targets {
            let CampaignGateTargetKind::LibExact {
                selectors,
                nix_source,
                ignored,
            } = target.kind
            else {
                continue;
            };
            failures.extend(library_exact_target_failures(
                &root,
                gate.name,
                target.package,
                selectors,
                nix_source,
                nix_attr,
                ignored,
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "RFC-0020 library exact targets drifted:\n{}",
        failures.join("\n")
    );
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
        match automated.kind {
            CampaignGateTargetKind::Integration { test_target } => {
                failures.extend(integration_target_failures(
                    root,
                    gate,
                    automated.package,
                    test_target,
                ));
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
        target.gate == gate
            && target.package == package
            && target.test_target == test_target
            && !target.placeholder
    });
    if !mapped {
        failures.push(format!(
            "{gate}: missing non-placeholder target {package}:{test_target}"
        ));
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
    selectors: &[LibraryExactSelector],
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
            Ok(source) => failures.extend(library_selector_source_failures(
                gate, selector, &source, ignored,
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

fn library_selector_source_failures(
    gate: &str,
    selector: &LibraryExactSelector,
    source: &str,
    ignored: bool,
) -> Vec<String> {
    let Some(function_name) = selector.name.rsplit("::").next() else {
        return vec![format!(
            "{gate}: library selector {} has no function name",
            selector.name
        )];
    };
    let declaration = format!("fn {function_name}(");
    let Some(declaration_offset) = source.find(&declaration) else {
        return vec![format!(
            "{gate}: library selector {} is absent from {}",
            selector.name, selector.source
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
            "{gate}: library selector {} is not a test",
            selector.name
        )];
    }
    if ignored && !saw_ignore {
        return vec![format!(
            "{gate}: library selector {} is not explicitly ignored",
            selector.name
        )];
    }
    if !ignored && saw_ignore {
        return vec![format!(
            "{gate}: ordinary library selector {} is unexpectedly ignored",
            selector.name
        )];
    }

    Vec::new()
}

fn library_selector_nix_failures(
    gate: &str,
    package: &str,
    nix_attr: &str,
    selectors: &[LibraryExactSelector],
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
    if ignored && !nix.contains("test result: ok. 1 passed; 0 failed; 0 ignored;") {
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
