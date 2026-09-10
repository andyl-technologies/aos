//! Validates the manual destructive-recovery runbook contract from RFC-0020.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const CONTRACT_SOURCE: &str = include_str!(
    "../../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-destructive-recovery-contract.toml"
);
const NIX_SOURCE: &str =
    include_str!("../../../tests/crucible/phase9-campaign-destructive-recovery-contract.nix");

const EXPECTED_INJECTIONS: &[&str] = &[
    "kill-running-child",
    "kill-coordinator-before-observation-commit",
    "kill-local-executor",
    "kill-daemon-during-snapshot-publication",
    "reboot-paused-or-hibernating",
    "enospc-during-exact-capture",
    "remove-archival-leaf-during-multipart",
    "expire-store-credentials",
    "corrupt-tier-copy",
    "interrupt-pack-index-publication",
    "fail-vm-during-atomic-world-fork",
    "alias-child-ring-or-overlay",
    "exceed-host-resource-budget",
    "cancel-during-child-creation",
];

const EXPECTED_TASKS: &[&str] = &[
    "T-CAM-0.5",
    "T-CAM-4.8",
    "T-CAM-5.8",
    "T-CAM-6.9",
    "T-CAM-7.7",
    "T-CAM-9.7",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    schema: String,
    gate: String,
    rfc_section: String,
    acceptance_state: String,
    constrained_host_required: bool,
    actual_product_workload_required: bool,
    independent_driver_and_reviewer_required: bool,
    every_targeted_backend_required: bool,
    authenticated_prior_state_required: bool,
    unexplained_live_resources_permitted: bool,
    implementation_tasks: Vec<String>,
    provenance: ProvenanceContract,
    command_journal: CommandJournalContract,
    sign_offs: SignOffContract,
    resource_audit: ResourceAuditContract,
    forbidden_recovery: ForbiddenRecoveryContract,
    injections: Vec<InjectionContract>,
    prerequisite_tests: Vec<PrerequisiteTest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceContract {
    required: bool,
    fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandJournalContract {
    required: bool,
    records_exit_status: bool,
    records_structured_output: bool,
    redacts_secrets: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignOffContract {
    required_roles: Vec<String>,
    unsigned_result: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceAuditContract {
    required: bool,
    resources: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForbiddenRecoveryContract {
    release_blocking: bool,
    operations: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InjectionContract {
    id: String,
    title: String,
    failure_class: String,
    surface: String,
    implementation_state: String,
    #[serde(default)]
    external_command_bindings: Vec<String>,
    action: String,
    #[serde(default)]
    trigger: Option<String>,
    #[serde(default)]
    fault_build_feature: Option<String>,
    #[serde(default)]
    production_artifact_state: Option<String>,
    prior_state: String,
    symptom: String,
    automatic_response: String,
    recovery_commands: Vec<String>,
    #[serde(default)]
    recovery_gap: Option<String>,
    observables: Vec<String>,
    post_recovery_invariant: String,
    backend_scope: String,
    prerequisites: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrerequisiteTest {
    id: String,
    package: String,
    source: String,
    selector: String,
}

#[test]
fn checked_in_contract_covers_every_destructive_recovery_class() -> Result<(), Box<dyn Error>> {
    let contract = parse_and_validate(CONTRACT_SOURCE, NIX_SOURCE, &workspace_root())?;

    assert_eq!(contract.injections.len(), EXPECTED_INJECTIONS.len());
    assert_eq!(contract.acceptance_state, "manual-evidence-required");

    Ok(())
}

#[test]
fn contract_validation_rejects_omitted_rows_and_production_fault_hooks() {
    let missing_row = CONTRACT_SOURCE.replacen(
        "id = \"cancel-during-child-creation\"",
        "id = \"kill-running-child\"",
        1,
    );
    let failures = validation_failures(&missing_row, NIX_SOURCE, &workspace_root());
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("injection set"))
    );

    let production_hook = CONTRACT_SOURCE.replacen(
        "production_artifact_state = \"absent\"",
        "production_artifact_state = \"enabled\"",
        1,
    );
    let failures = validation_failures(&production_hook, NIX_SOURCE, &workspace_root());
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("absent from production artifacts"))
    );

    let missing_feature = CONTRACT_SOURCE.replacen(
        "fault_build_feature = \"destructive-recovery-faults\"",
        "fault_build_feature = \"\"",
        1,
    );
    let failures = validation_failures(&missing_feature, NIX_SOURCE, &workspace_root());
    assert!(failures.iter().any(|failure| {
        failure.contains("implemented fault-build hook is not run through its declared feature")
    }));
}

#[test]
fn contract_validation_rejects_unrunnable_commands_and_prerequisite_drift() {
    let private_repair = CONTRACT_SOURCE.replace("crucible --format jsonl", "private-admin");
    let failures = validation_failures(&private_repair, NIX_SOURCE, &workspace_root());
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("invalid public recovery command"))
    );

    let unbound_action = CONTRACT_SOURCE.replacen(
        "kill --signal KILL {child_pid}",
        "{documented_child_kill_command}",
        1,
    );
    let failures = validation_failures(&unbound_action, NIX_SOURCE, &workspace_root());
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("runnable operator action"))
    );

    let unbound_external_action = CONTRACT_SOURCE.replacen(
        "external_command_bindings = [\"daemon_command\"]\n",
        "external_command_bindings = []\n",
        1,
    );
    let failures = validation_failures(&unbound_external_action, NIX_SOURCE, &workspace_root());
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("unbound external command placeholder"))
    );

    let placeholder_recovery = CONTRACT_SOURCE.replacen(
        "crucible --format jsonl campaign --socket {campaign_socket} --principal {principal} status {campaign}",
        "{documented_service_restart_command}",
        1,
    );
    let failures = validation_failures(&placeholder_recovery, NIX_SOURCE, &workspace_root());
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("invalid public recovery command"))
    );

    let missing_runner = NIX_SOURCE.replacen(
        "executor_worker::tests::operational_worker_failure_requeues_without_growing_the_bounded_queue",
        "executor_worker::tests::renamed_test",
        1,
    );
    let failures = validation_failures(CONTRACT_SOURCE, &missing_runner, &workspace_root());
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("is not run by the Nix validator"))
    );
}

fn parse_and_validate(source: &str, nix_source: &str, root: &Path) -> Result<Contract, String> {
    let contract = toml::from_str::<Contract>(source)
        .map_err(|error| format!("destructive-recovery contract does not parse: {error}"))?;
    let failures = contract_failures(&contract, nix_source, root);
    if failures.is_empty() {
        Ok(contract)
    } else {
        Err(failures.join("\n"))
    }
}

fn validation_failures(source: &str, nix_source: &str, root: &Path) -> Vec<String> {
    match toml::from_str::<Contract>(source) {
        Ok(contract) => contract_failures(&contract, nix_source, root),
        Err(error) => vec![format!(
            "destructive-recovery contract does not parse: {error}"
        )],
    }
}

fn contract_failures(contract: &Contract, nix_source: &str, root: &Path) -> Vec<String> {
    let mut failures = Vec::new();

    validate_header(contract, &mut failures);
    validate_evidence_contract(contract, &mut failures);
    validate_injections(contract, nix_source, &mut failures);
    validate_fault_build_isolation(contract, root, &mut failures);
    validate_prerequisites(contract, nix_source, root, &mut failures);

    failures
}

fn validate_header(contract: &Contract, failures: &mut Vec<String>) {
    require_equal(
        failures,
        "schema",
        &contract.schema,
        "aos.crucible.campaign-destructive-recovery-contract.v1",
    );
    require_equal(
        failures,
        "gate",
        &contract.gate,
        "gate:campaign-destructive-recovery",
    );
    require_equal(
        failures,
        "RFC section",
        &contract.rfc_section,
        "RFC-0020 section 14.8",
    );
    require_equal(
        failures,
        "acceptance state",
        &contract.acceptance_state,
        "manual-evidence-required",
    );

    let tasks = contract
        .implementation_tasks
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_tasks = EXPECTED_TASKS.iter().copied().collect::<BTreeSet<_>>();
    if tasks != expected_tasks || tasks.len() != contract.implementation_tasks.len() {
        failures.push(format!(
            "implementation task set must be exactly {expected_tasks:?}, got {tasks:?}"
        ));
    }
}

fn validate_evidence_contract(contract: &Contract, failures: &mut Vec<String>) {
    if !contract.constrained_host_required
        || !contract.actual_product_workload_required
        || !contract.independent_driver_and_reviewer_required
        || !contract.every_targeted_backend_required
        || !contract.authenticated_prior_state_required
    {
        failures.push(String::from(
            "CMAN-15 host, product, reviewer, backend, and authenticated-state requirements must all be enabled",
        ));
    }
    if contract.unexplained_live_resources_permitted {
        failures.push(String::from(
            "CMAN-15 must forbid unexplained live resources",
        ));
    }

    let provenance_fields = strings(&contract.provenance.fields);
    require_set_contains(
        failures,
        "provenance fields",
        &provenance_fields,
        &[
            "build_id",
            "source_revision",
            "qemu_identity",
            "plugin_identity",
            "host_profile",
            "store_profile",
        ],
    );
    if !contract.provenance.required {
        failures.push(String::from("provenance evidence must be required"));
    }
    if !contract.command_journal.required
        || !contract.command_journal.records_exit_status
        || !contract.command_journal.records_structured_output
        || !contract.command_journal.redacts_secrets
    {
        failures.push(String::from(
            "command journal must retain exit status and structured output while redacting secrets",
        ));
    }

    let sign_offs = strings(&contract.sign_offs.required_roles);
    require_set_contains(
        failures,
        "sign-off roles",
        &sign_offs,
        &["driver", "independent_reviewer", "release_owner"],
    );
    require_equal(
        failures,
        "unsigned result",
        &contract.sign_offs.unsigned_result,
        "blocked",
    );

    let resources = strings(&contract.resource_audit.resources);
    require_set_contains(
        failures,
        "resource audit",
        &resources,
        &[
            "processes",
            "descriptors",
            "shared_memory",
            "disk_overlays",
            "cgroups",
            "staging_uploads",
            "object_pins",
            "writable_store_resources",
        ],
    );
    if !contract.resource_audit.required {
        failures.push(String::from("post-flight resource audit must be required"));
    }

    let forbidden = strings(&contract.forbidden_recovery.operations);
    require_set_contains(
        failures,
        "forbidden recovery operations",
        &forbidden,
        &[
            "undocumented_object_deletion",
            "reservation_editing",
            "ref_rewriting",
            "undocumented_process_signaling",
        ],
    );
    if !contract.forbidden_recovery.release_blocking {
        failures.push(String::from(
            "CMAN-16 forbidden recovery operations must be release blocking",
        ));
    }
}

fn validate_injections(contract: &Contract, nix_source: &str, failures: &mut Vec<String>) {
    let injection_ids = contract
        .injections
        .iter()
        .map(|injection| injection.id.as_str())
        .collect::<BTreeSet<_>>();
    let expected = EXPECTED_INJECTIONS.iter().copied().collect::<BTreeSet<_>>();
    if injection_ids != expected || injection_ids.len() != contract.injections.len() {
        failures.push(format!(
            "injection set must be the 14 RFC-0020 section 14.8 rows; expected {expected:?}, got {injection_ids:?}"
        ));
    }

    for injection in &contract.injections {
        for (field, value) in [
            ("title", injection.title.as_str()),
            ("failure_class", injection.failure_class.as_str()),
            ("action", injection.action.as_str()),
            ("prior_state", injection.prior_state.as_str()),
            ("symptom", injection.symptom.as_str()),
            ("automatic_response", injection.automatic_response.as_str()),
            (
                "post_recovery_invariant",
                injection.post_recovery_invariant.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                failures.push(format!("{} has an empty {field}", injection.id));
            }
        }
        if injection.backend_scope != "constrained-host-and-each-targeted-backend" {
            failures.push(format!(
                "{} does not require the CMAN-15 host/backend matrix",
                injection.id
            ));
        }
        if injection.observables.len() < 3 {
            failures.push(format!(
                "{} must name at least three operator-visible observations",
                injection.id
            ));
        }
        if injection.recovery_commands.is_empty() {
            failures.push(format!(
                "{} has no documented public recovery command",
                injection.id
            ));
        }
        for command in &injection.recovery_commands {
            if !is_public_recovery_command(command) {
                failures.push(format!(
                    "{} has invalid public recovery command {command}",
                    injection.id
                ));
            }
        }
        if injection
            .recovery_gap
            .as_deref()
            .is_some_and(|gap| !gap.contains("CMAN-16") || !gap.contains("release blocking"))
        {
            failures.push(format!(
                "{} recovery gap is not explicitly CMAN-16 release blocking",
                injection.id
            ));
        }
        if injection.prerequisites.is_empty() {
            failures.push(format!(
                "{} has no automated semantic prerequisite",
                injection.id
            ));
        }

        match injection.surface.as_str() {
            "operator-command" => {
                if injection.implementation_state != "operator-command-available" {
                    failures.push(format!(
                        "{} operator command is not marked available",
                        injection.id
                    ));
                }
                if injection.trigger.is_some()
                    || injection.fault_build_feature.is_some()
                    || injection.production_artifact_state.is_some()
                {
                    failures.push(format!(
                        "{} operator command unexpectedly declares a fault-build trigger",
                        injection.id
                    ));
                }
                if !is_runnable_operator_action(&injection.action) {
                    failures.push(format!(
                        "{} lacks a runnable operator action with a declared external command binding",
                        injection.id
                    ));
                }
            }
            "fault-build-trigger" => {
                let Some(trigger) = injection.trigger.as_deref() else {
                    failures.push(format!(
                        "{} lacks a declared fault-build trigger",
                        injection.id
                    ));
                    continue;
                };
                if !trigger.starts_with("crucible.destructive-recovery.")
                    || !injection.action.contains(trigger)
                {
                    failures.push(format!(
                        "{} fault-build action does not select its declared trigger",
                        injection.id
                    ));
                }
                if injection.production_artifact_state.as_deref() != Some("absent") {
                    failures.push(format!(
                        "{} fault-build hook must be absent from production artifacts",
                        injection.id
                    ));
                }
                match injection.implementation_state.as_str() {
                    "fault-build-hook-required" => {
                        if injection.fault_build_feature.is_some() {
                            failures.push(format!(
                                "{} declares a feature for an unimplemented fault-build hook",
                                injection.id
                            ));
                        }
                    }
                    "fault-build-hook-available" => {
                        let Some(feature) = injection.fault_build_feature.as_deref() else {
                            failures.push(format!(
                                "{} implemented fault-build hook has no feature",
                                injection.id
                            ));
                            continue;
                        };
                        if feature != "destructive-recovery-faults"
                            || !nix_source.contains("--features")
                            || !nix_source.contains(feature)
                        {
                            failures.push(format!(
                                "{} implemented fault-build hook is not run through its declared feature",
                                injection.id
                            ));
                        }
                    }
                    state => failures.push(format!(
                        "{} has unsupported fault-build implementation state {state}",
                        injection.id
                    )),
                }
            }
            surface => failures.push(format!(
                "{} has unsupported injection surface {surface}",
                injection.id
            )),
        }

        let bindings = strings(&injection.external_command_bindings);
        for placeholder in command_placeholders(&injection.action) {
            if !bindings.contains(placeholder) {
                failures.push(format!(
                    "{} has unbound external command placeholder {placeholder}",
                    injection.id
                ));
            }
        }
    }
}

fn is_runnable_operator_action(action: &str) -> bool {
    ["crucible ", "kill ", "systemctl ", "systemd-run "]
        .iter()
        .any(|prefix| action.starts_with(prefix))
}

fn is_public_recovery_command(command: &str) -> bool {
    command.starts_with("crucible --format jsonl campaign ")
        || command.starts_with("crucible --format jsonl store status {store_deployment}")
        || command.starts_with("crucible --format jsonl store status {destination_store}")
        || command.starts_with("crucible --format jsonl store verify {store_deployment}")
        || command.starts_with("crucible --format jsonl store verify {destination_store}")
        || command.starts_with("crucible --format jsonl store ensure {content_id} --in ")
}

fn command_placeholders(action: &str) -> BTreeSet<&str> {
    action
        .split('{')
        .skip(1)
        .filter_map(|suffix| suffix.split_once('}').map(|(placeholder, _)| placeholder))
        .filter(|placeholder| placeholder.ends_with("_command"))
        .collect()
}

fn validate_fault_build_isolation(contract: &Contract, root: &Path, failures: &mut Vec<String>) {
    if !contract
        .injections
        .iter()
        .any(|injection| injection.implementation_state == "fault-build-hook-available")
    {
        return;
    }

    let expected_features = [
        ("crates/crucible-campaign/Cargo.toml", Vec::<&str>::new()),
        (
            "crates/crucible-daemon/Cargo.toml",
            vec!["crucible-campaign/destructive-recovery-faults"],
        ),
        (
            "crates/crucible-cli/Cargo.toml",
            vec!["crucible-daemon/destructive-recovery-faults"],
        ),
    ];
    for (relative_path, expected_propagation) in expected_features {
        let path = root.join(relative_path);
        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) => {
                failures.push(format!(
                    "fault-build manifest {} cannot be read: {error}",
                    path.display()
                ));
                continue;
            }
        };
        let manifest = match source.parse::<toml::Value>() {
            Ok(manifest) => manifest,
            Err(error) => {
                failures.push(format!(
                    "fault-build manifest {} does not parse: {error}",
                    path.display()
                ));
                continue;
            }
        };
        let Some(features) = manifest.get("features").and_then(toml::Value::as_table) else {
            failures.push(format!(
                "fault-build manifest {} has no feature table",
                path.display()
            ));
            continue;
        };
        let actual_propagation = features
            .get("destructive-recovery-faults")
            .and_then(toml::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .collect::<Vec<_>>()
            });
        if actual_propagation.as_deref() != Some(expected_propagation.as_slice()) {
            failures.push(format!(
                "fault-build manifest {} has invalid destructive-recovery feature propagation",
                path.display()
            ));
        }
        if default_feature_closure(features).contains("destructive-recovery-faults") {
            failures.push(format!(
                "fault-build manifest {} activates destructive recovery faults by default",
                path.display()
            ));
        }
    }

    let package_path = root.join("pkgs/tools/crucible/crucible.nix");
    match fs::read_to_string(&package_path) {
        Ok(source)
            if !source.contains("--all-features")
                && !source.contains("destructive-recovery-faults") => {}
        Ok(_) => failures.push(format!(
            "production package {} can activate destructive recovery faults",
            package_path.display()
        )),
        Err(error) => failures.push(format!(
            "production package {} cannot be read: {error}",
            package_path.display()
        )),
    }
}

fn default_feature_closure(features: &toml::map::Map<String, toml::Value>) -> BTreeSet<&str> {
    let mut pending = features
        .get("default")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .collect::<Vec<_>>();
    let mut closure = BTreeSet::new();

    while let Some(feature) = pending.pop() {
        if !closure.insert(feature) {
            continue;
        }
        if let Some(children) = features.get(feature).and_then(toml::Value::as_array) {
            pending.extend(children.iter().filter_map(toml::Value::as_str));
        }
    }

    closure
}

fn validate_prerequisites(
    contract: &Contract,
    nix_source: &str,
    root: &Path,
    failures: &mut Vec<String>,
) {
    let mut tests = BTreeMap::new();
    for prerequisite in &contract.prerequisite_tests {
        if tests
            .insert(prerequisite.id.as_str(), prerequisite)
            .is_some()
        {
            failures.push(format!("duplicate prerequisite test {}", prerequisite.id));
        }
        if !matches!(
            prerequisite.package.as_str(),
            "crucible-campaign" | "crucible-cas" | "crucible-daemon"
        ) {
            failures.push(format!(
                "{} uses unexpected prerequisite package {}",
                prerequisite.id, prerequisite.package
            ));
        }

        let source_path = root.join(&prerequisite.source);
        match fs::read_to_string(&source_path) {
            Ok(source) => {
                let function_name = prerequisite
                    .selector
                    .rsplit("::")
                    .next()
                    .unwrap_or_default();
                if !source.contains(&format!("fn {function_name}(")) {
                    failures.push(format!(
                        "{} selector {} is absent from {}",
                        prerequisite.id,
                        prerequisite.selector,
                        source_path.display()
                    ));
                }
            }
            Err(error) => failures.push(format!(
                "{} prerequisite source {} cannot be read: {error}",
                prerequisite.id,
                source_path.display()
            )),
        }
        if !nix_source.contains(&prerequisite.selector) {
            failures.push(format!(
                "{} selector {} is not run by the Nix validator",
                prerequisite.id, prerequisite.selector
            ));
        }
    }

    for injection in &contract.injections {
        for prerequisite in &injection.prerequisites {
            if !tests.contains_key(prerequisite.as_str()) {
                failures.push(format!(
                    "{} references unknown prerequisite {}",
                    injection.id, prerequisite
                ));
            }
        }
    }

    if !nix_source.contains("CONTRACT_VALIDATED")
        || !nix_source.contains("manual_evidence=required")
        || nix_source.contains("printf 'PASS")
    {
        failures.push(String::from(
            "Nix validator must emit CONTRACT_VALIDATED and manual_evidence=required without claiming PASS",
        ));
    }
    if !nix_source.contains("--exact --list")
        || !nix_source.contains("grep -Fxc")
        || !nix_source.contains("test result: ok. 1 passed;")
    {
        failures.push(String::from(
            "Nix validator must fail closed on zero-match selectors and require each exact test to pass",
        ));
    }
}

fn require_equal(failures: &mut Vec<String>, field: &str, actual: &str, expected: &str) {
    if actual != expected {
        failures.push(format!("{field} must be {expected}, got {actual}"));
    }
}

fn require_set_contains(
    failures: &mut Vec<String>,
    field: &str,
    actual: &BTreeSet<&str>,
    required: &[&str],
) {
    let missing = required
        .iter()
        .copied()
        .filter(|value| !actual.contains(value))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        failures.push(format!("{field} lacks {missing:?}"));
    }
}

fn strings(values: &[String]) -> BTreeSet<&str> {
    values.iter().map(String::as_str).collect()
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}
