//! Validates the executable Phase 9 gates and fail-closed release acceptance layer.

#![forbid(unsafe_code)]

use std::error::Error;

use serde::Deserialize;

const CONTRACT_SOURCE: &str =
    include_str!("../../../tests/crucible/campaign-release-acceptance-contract.toml");
const CONTRACT_NIX: &str =
    include_str!("../../../tests/crucible/phase9-campaign-release-acceptance-contract.nix");
const ACCEPTANCE_NIX: &str =
    include_str!("../../../tests/crucible/phase9-campaign-release-acceptance.nix");
const ACCEPTANCE_RUNNER: &str =
    include_str!("../../../tests/crucible/_phase9-campaign-release-acceptance.sh");
const EVIDENCE_SPEC_NIX: &str =
    include_str!("../../../tests/crucible/_campaign-manual-evidence-spec.nix");
const DOGFOOD_CONTRACT_SOURCE: &str = include_str!(
    "../../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-dogfood-contract.toml"
);
const FINDING_PORTABILITY_NIX: &str =
    include_str!("../../../tests/crucible/phase9-campaign-finding-portability.nix");
const DEFAULT_NIX: &str = include_str!("../../../tests/crucible/default.nix");

const EXECUTABLE_GATES: &[&str] = &[
    "gate:campaign-gate-matrix",
    "gate:campaign-operational-continuity",
    "gate:campaign-replay",
    "gate:hot-fork-scaling",
    "gate:campaign-required-gates",
];
const REQUIRED_CLAIM_GATES: &[&str] = &[
    "gate:campaign-model",
    "gate:campaign-component-contract",
    "gate:branch-point-model",
    "gate:typed-choice",
    "gate:typed-choice-product-checkpoint",
    "gate:campaign-replay",
    "gate:lazy-frontier",
    "gate:attempt-idempotence",
    "gate:hot-fork-equivalence",
    "gate:hot-fork-isolation",
    "gate:hot-fork-scaling",
    "gate:host-clone-cost",
    "gate:world-fork-atomicity",
    "gate:exact-closure-streaming",
    "gate:campaign-store-equivalence",
    "gate:campaign-store-composition",
    "gate:campaign-cold-continuity",
    "gate:campaign-statistics",
    "gate:campaign-operational-continuity",
    "gate:license-boundary",
    "gate:abi-conformance",
    "gate:control-responsiveness",
    "gate:campaign-mutation-scaling",
    "gate:campaign-rfc-traceability",
    "gate:campaign-exact-maintenance-transfer",
    "gate:campaign-policy-timeout-real-qemu",
    "gate:campaign-finding-exact-read-only",
    "gate:campaign-finding-signal-bundle",
    "gate:campaign-finding-fork-write",
];
const MANUAL_GATES: &[&str] = &[
    "gate:campaign-operator-acceptance",
    "gate:campaign-destructive-recovery",
    "gate:campaign-dogfood",
    "gate:e2e-determinism",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceContract {
    schema: String,
    gate: String,
    acceptance_state: String,
    implementation_tasks: Vec<String>,
    executable_evidence: ExecutableEvidence,
    manual_evidence: ManualEvidence,
    provenance: ProvenanceContract,
    sign_offs: SignOffContract,
    binding: BindingContract,
    normalized_evidence: NormalizedEvidenceContract,
    output: OutputContract,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutableEvidence {
    required_gates: Vec<String>,
    required_claim_gates: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualEvidence {
    required_gates: Vec<String>,
    schema: String,
    required_files: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceContract {
    required: bool,
    fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignOffContract {
    namespace: String,
    required_roles_source: String,
    minimum_distinct_signers: usize,
    distinct_signer_identities_required: bool,
    distinct_signer_key_fingerprints_required: bool,
    trusted_allowed_signers_input_required: bool,
    signed_payload: String,
    unsigned_result: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingContract {
    release_manifest_sha256_required: bool,
    release_manifest_env_sha256_required: bool,
    release_manifest_json_sha256_required: bool,
    release_acceptance_contract_sha256_required: bool,
    manual_contract_sha256_required: bool,
    result_sha256_required: bool,
    command_journal_sha256_required: bool,
    artifact_manifest_sha256_required: bool,
    artifact_payload_sha256_required: bool,
    structured_output_sha256_required: bool,
    executable_gate_result_sha256_required: bool,
    manual_evidence_result_sha256_required: bool,
    manual_evidence_manifest_sha256_required: bool,
    missing_or_mismatched_result: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NormalizedEvidenceContract {
    command_journal_schema: String,
    all_command_exit_statuses_zero: bool,
    artifact_manifest_schema: String,
    artifact_payload_digests_required: bool,
    resource_audit_schema: String,
    required_resource_status: String,
    resource_audit_sha256_required: bool,
    injection_record_schema: String,
    required_injection_status: String,
    injection_records_sha256_required_when_declared: bool,
    injection_payload_digests_required: bool,
    regular_non_symlink_files_required: bool,
    forbidden_recovery_usage: String,
    unexplained_workaround: String,
    hidden_repair: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputContract {
    schema: String,
    retains_external_evidence: bool,
    retains_manual_contracts: bool,
    retains_executable_gate_results: bool,
    retains_release_manifest: bool,
    retains_release_manifest_env: bool,
    retains_release_manifest_json: bool,
    retains_signer_key_bindings: bool,
    retains_release_acceptance_contract: bool,
    ordinary_source_package_dependency: bool,
    accepted_result: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DogfoodContract {
    schema: String,
    gate: String,
    rfc_section: String,
    acceptance_state: String,
    actual_product_workload_required: bool,
    public_surfaces_only: bool,
    independent_handoff_required: bool,
    minimum_duration_hours: u64,
    release_candidate_duration_hours: u64,
    implementation_tasks: Vec<String>,
    provenance: toml::Value,
    command_journal: toml::Value,
    scale: DogfoodScale,
    resource_audit: toml::Value,
    artifacts: toml::Value,
    sign_offs: toml::Value,
    acceptance: toml::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DogfoodScale {
    required: bool,
    minimum_hot_children: u64,
    minimum_promoted_template_generations: u64,
    minimum_admitted_attempts: u64,
    exercises_backpressure: bool,
    exercises_resource_pressure: bool,
    exercises_policy_revision: bool,
}

#[test]
fn release_acceptance_contract_requires_executable_and_signed_manual_evidence()
-> Result<(), Box<dyn Error>> {
    let contract: AcceptanceContract = toml::from_str(CONTRACT_SOURCE)?;

    assert_eq!(
        contract.schema,
        "aos.crucible.campaign-release-acceptance-contract.v1"
    );
    assert_eq!(contract.gate, "gate:campaign-release-acceptance");
    assert_eq!(contract.acceptance_state, "manual-evidence-required");
    assert_eq!(
        contract.implementation_tasks,
        (1..=7)
            .map(|number| format!("T-CAM-9.{number}"))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        contract.executable_evidence.required_gates,
        EXECUTABLE_GATES
    );
    assert_eq!(
        contract.executable_evidence.required_claim_gates,
        REQUIRED_CLAIM_GATES
    );
    assert_eq!(contract.manual_evidence.required_gates, MANUAL_GATES);
    assert_eq!(
        contract.manual_evidence.schema,
        "aos.crucible.campaign-manual-evidence.v1"
    );
    assert!(
        !contract
            .manual_evidence
            .required_files
            .iter()
            .any(|path| path.contains("allowed-signers"))
    );

    assert_eq!(
        contract.provenance.fields,
        [
            "release_manifest_sha256",
            "release_manifest_env_sha256",
            "release_manifest_json_sha256",
            "release_acceptance_contract_sha256",
            "manual_contract_sha256"
        ]
    );
    assert!(contract.provenance.required);

    assert_eq!(
        contract.sign_offs.namespace,
        "crucible-campaign-manual-evidence"
    );
    assert_eq!(
        contract.sign_offs.required_roles_source,
        "subordinate-contract"
    );
    assert_eq!(contract.sign_offs.minimum_distinct_signers, 3);
    assert!(contract.sign_offs.distinct_signer_identities_required);
    assert!(contract.sign_offs.distinct_signer_key_fingerprints_required);
    assert!(contract.sign_offs.trusted_allowed_signers_input_required);
    assert_eq!(contract.sign_offs.signed_payload, "sign-offs/<role>.env");
    assert_eq!(contract.sign_offs.unsigned_result, "blocked");

    assert!(contract.binding.release_manifest_sha256_required);
    assert!(contract.binding.release_manifest_env_sha256_required);
    assert!(contract.binding.release_manifest_json_sha256_required);
    assert!(contract.binding.release_acceptance_contract_sha256_required);
    assert!(contract.binding.manual_contract_sha256_required);
    assert!(contract.binding.result_sha256_required);
    assert!(contract.binding.command_journal_sha256_required);
    assert!(contract.binding.artifact_manifest_sha256_required);
    assert!(contract.binding.artifact_payload_sha256_required);
    assert!(contract.binding.structured_output_sha256_required);
    assert!(contract.binding.executable_gate_result_sha256_required);
    assert!(contract.binding.manual_evidence_result_sha256_required);
    assert!(contract.binding.manual_evidence_manifest_sha256_required);
    assert_eq!(contract.binding.missing_or_mismatched_result, "blocked");

    assert_eq!(
        contract.normalized_evidence.command_journal_schema,
        "operation,exit_status,structured_output_path,structured_output_sha256"
    );
    assert!(contract.normalized_evidence.all_command_exit_statuses_zero);
    assert_eq!(
        contract.normalized_evidence.artifact_manifest_schema,
        "relative_path,sha256"
    );
    assert!(
        contract
            .normalized_evidence
            .artifact_payload_digests_required
    );
    assert_eq!(
        contract.normalized_evidence.resource_audit_schema,
        "resource,status"
    );
    assert_eq!(
        contract.normalized_evidence.required_resource_status,
        "clean"
    );
    assert!(contract.normalized_evidence.resource_audit_sha256_required);
    assert_eq!(
        contract.normalized_evidence.injection_record_schema,
        "injection,status,backend_scope,prior_state_path,prior_state_sha256,observables_path,observables_sha256,recovery_path,recovery_sha256"
    );
    assert_eq!(
        contract.normalized_evidence.required_injection_status,
        "pass"
    );
    assert!(
        contract
            .normalized_evidence
            .injection_records_sha256_required_when_declared
    );
    assert!(
        contract
            .normalized_evidence
            .injection_payload_digests_required
    );
    assert!(
        contract
            .normalized_evidence
            .regular_non_symlink_files_required
    );
    assert_eq!(
        contract.normalized_evidence.forbidden_recovery_usage,
        "blocked"
    );
    assert_eq!(
        contract.normalized_evidence.unexplained_workaround,
        "blocked"
    );
    assert_eq!(contract.normalized_evidence.hidden_repair, "blocked");

    assert_eq!(
        contract.output.schema,
        "aos.crucible.campaign-release-acceptance.v1"
    );
    assert!(contract.output.retains_external_evidence);
    assert!(contract.output.retains_manual_contracts);
    assert!(contract.output.retains_executable_gate_results);
    assert!(contract.output.retains_release_manifest);
    assert!(contract.output.retains_release_manifest_env);
    assert!(contract.output.retains_release_manifest_json);
    assert!(contract.output.retains_signer_key_bindings);
    assert!(contract.output.retains_release_acceptance_contract);
    assert!(!contract.output.ordinary_source_package_dependency);
    assert_eq!(contract.output.accepted_result, "pass");

    Ok(())
}

#[test]
fn release_acceptance_is_explicitly_wired_and_fails_closed() {
    for required_argument in [
        "operatorEvidence,",
        "destructiveRecoveryEvidence,",
        "dogfoodEvidence,",
        "e2eEvidence,",
        "campaignGateMatrix,",
        "campaignOperationalContinuity,",
        "campaignFindingPortability,",
        "hotForkScaling,",
        "requiredGates,",
        "cruciblePackage,",
        "releaseManifest,",
        "releaseAcceptanceContract,",
        "trustedAllowedSigners,",
    ] {
        assert!(ACCEPTANCE_NIX.contains(required_argument));
    }

    for wiring in [
        "campaignReleaseEvidence ? null,",
        "campaignFindingPortability = import ./phase9-campaign-finding-portability.nix",
        "campaignExactMaintenanceTransfer = import ./phase5-campaign-exact-maintenance-transfer-vm.nix",
        "campaignFindingExactVm = import ./phase9-campaign-finding-exact-vm.nix",
        "campaignFindingSignalVm = import ./phase9-campaign-finding-signal-vm.nix",
        "packagedReplay = phase4.gates.campaignReplay.rawGate;",
        "campaignReleaseAcceptanceContract = import ./phase9-campaign-release-acceptance-contract.nix",
        "campaignReleaseAcceptance =",
        "else if campaignReleaseEvidence == null",
        "gateName = \"gate:campaign-release-acceptance\";",
        "import ./phase9-campaign-release-acceptance.nix",
        "hotForkScaling = phase7.gates.hotForkScaling;",
        "releaseAcceptanceContract = campaignReleaseAcceptanceContract;",
    ] {
        assert!(
            DEFAULT_NIX.contains(wiring),
            "missing Phase 9 wiring: {wiring}"
        );
    }
    assert!(DEFAULT_NIX.contains(
        "signed operator, destructive-recovery, dogfood, and e2e evidence was not supplied"
    ));
    assert!(CONTRACT_NIX.contains("acceptance=not-evaluated"));
    assert!(!CONTRACT_NIX.contains("acceptance=pass"));

    for required_check in [
        "verify_command_journal",
        "verify_artifact_manifest",
        "result_sha256",
        "manual_contract_sha256",
        "artifact_manifest_sha256",
        "resource_audit_sha256",
        "injection_records_sha256",
        "ssh-keygen -Y verify",
        "< \"$sign_off\"",
        "trusted_allowed_signers",
        "reuses one signer identity across roles",
        "one trusted signing key is reused across required roles",
        "require_evidence_file",
        "--probe-evidence-file",
        "--probe-distinct-fingerprints",
        "--probe-command-journal",
        "--probe-manifest-requirements",
        "--probe-required-gates",
        "--probe-evidence-tree",
        "contains undeclared operation",
        "contains duplicate operation",
        "contains an unbound regular file",
        "release_manifest_env_sha256",
        "release_manifest_json_sha256",
        "crucible_package_store_path",
        "signer_key_bindings_sha256",
        "spec_values signer_role",
        "required_claim_count",
        "all_required_claims_authenticated",
        "campaign_required_gates_result_sha256",
        "campaign_required_gates_manifest_sha256",
        "campaign_required_gates_inventory_sha256",
        "required-claim-gates.txt",
        "does not contain the exact required gate inventory",
    ] {
        assert!(ACCEPTANCE_RUNNER.contains(required_check));
    }
    assert!(ACCEPTANCE_NIX.contains("$out/contracts"));
    assert!(!ACCEPTANCE_NIX.contains("releaseAcceptanceContract = import"));
    assert!(ACCEPTANCE_NIX.contains("release-acceptance.toml"));
    assert!(ACCEPTANCE_RUNNER.contains("release_acceptance_contract_result_sha256"));
    assert!(!ACCEPTANCE_RUNNER.contains("sign-offs/allowed-signers"));

    for requirement in [
        "minimum \"duration_hours\" contract.minimum_duration_hours",
        "maximum \"duration_hours\" contract.maximum_duration_hours",
        "minimum \"duration_hours\" contract.minimum_duration_hours",
        "minimum \"duration_hours\" contract.release_candidate_duration_hours",
        "minimum \"hot_children_created_and_retired\" contract.scale.minimum_hot_children",
        "minimum \"promoted_template_generations_reached\" contract.scale.minimum_promoted_template_generations",
        "minimum \"admitted_lightweight_attempts\" contract.scale.minimum_admitted_attempts",
        "contract.varied_core_counts",
        "contract.hostile_profiles",
        "contract.provenance.fields",
        "contract.resource_audit.resources",
        "contract.injections",
        "injection.backend_scope",
        "contract.forbidden_recovery.operations",
    ] {
        assert!(EVIDENCE_SPEC_NIX.contains(requirement));
    }
    for enforcement in [
        "nonzero exit status",
        "omits required operation",
        "omits required artifact",
        "reports non-clean resource",
        "omits required injection",
        "uses forbidden recovery operation",
    ] {
        assert!(ACCEPTANCE_RUNNER.contains(enforcement));
    }
    assert!(CONTRACT_NIX.contains("release acceptance accepted a substituted required gate"));
    assert!(!EVIDENCE_SPEC_NIX.contains("minimum_executions"));
    assert!(!EVIDENCE_SPEC_NIX.contains("execution_count"));
}

#[test]
fn dogfood_contract_requires_every_normative_scale_measurement() -> Result<(), Box<dyn Error>> {
    let contract: DogfoodContract = toml::from_str(DOGFOOD_CONTRACT_SOURCE)?;

    assert_eq!(contract.schema, "aos.crucible.campaign-dogfood-contract.v2");
    assert_eq!(contract.gate, "gate:campaign-dogfood");
    assert_eq!(contract.rfc_section, "RFC-0020 sections 14.9 and 14.11");
    assert_eq!(contract.acceptance_state, "manual-evidence-required");
    assert!(contract.actual_product_workload_required);
    assert!(contract.public_surfaces_only);
    assert!(contract.independent_handoff_required);
    assert!(contract.minimum_duration_hours >= 24);
    assert!(contract.release_candidate_duration_hours >= 72);
    assert_eq!(
        contract.implementation_tasks,
        ["T-CAM-0.5", "T-CAM-7.7", "T-CAM-9.7"]
    );
    assert!(contract.provenance.is_table());
    assert!(contract.command_journal.is_table());
    assert!(contract.resource_audit.is_table());
    assert!(contract.artifacts.is_table());
    assert!(contract.sign_offs.is_table());
    assert!(contract.acceptance.is_table());
    assert!(contract.scale.required);
    assert!(contract.scale.minimum_hot_children >= 10_000);
    assert!(contract.scale.minimum_promoted_template_generations >= 3);
    assert!(contract.scale.minimum_admitted_attempts >= 1_000_000);
    assert!(contract.scale.exercises_backpressure);
    assert!(contract.scale.exercises_resource_pressure);
    assert!(contract.scale.exercises_policy_revision);

    Ok(())
}

#[test]
fn finding_portability_binds_current_public_replay_evidence() {
    for needle in [
        "gate=gate:campaign-replay",
        "strict_campaign_planner_reproduces_every_accepted_step",
        "offline_rich_finding_replays_without_campaign_store",
        "no_campaign_daemon=true",
        "no_shared_store=true",
    ] {
        assert!(FINDING_PORTABILITY_NIX.contains(needle));
    }

    assert!(DEFAULT_NIX.contains("taskIds = [\"T-CAM-9.4\"];"));
}
