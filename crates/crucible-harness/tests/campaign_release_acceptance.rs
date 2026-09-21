//! Validates the executable Phase 9 gates and opt-in release acceptance layer.

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
const FINDING_PORTABILITY_NIX: &str =
    include_str!("../../../tests/crucible/phase9-campaign-finding-portability.nix");
const DEFAULT_NIX: &str = include_str!("../../../tests/crucible/default.nix");

const EXECUTABLE_GATES: &[&str] = &[
    "gate:campaign-gate-matrix",
    "gate:campaign-operational-continuity",
    "gate:campaign-replay",
    "gate:hot-fork-scaling",
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
fn release_acceptance_is_opt_in_and_fails_closed() {
    for required_argument in [
        "operatorEvidence,",
        "destructiveRecoveryEvidence,",
        "dogfoodEvidence,",
        "e2eEvidence,",
        "campaignGateMatrix,",
        "campaignOperationalContinuity,",
        "campaignFindingPortability,",
        "hotForkScaling,",
        "cruciblePackage,",
        "releaseManifest,",
        "trustedAllowedSigners,",
    ] {
        assert!(ACCEPTANCE_NIX.contains(required_argument));
    }

    assert!(!DEFAULT_NIX.contains("phase9-campaign-release-acceptance.nix"));
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
        "--probe-evidence-tree",
        "contains undeclared operation",
        "contains duplicate operation",
        "contains an unbound regular file",
        "release_manifest_env_sha256",
        "release_manifest_json_sha256",
        "crucible_package_store_path",
        "signer_key_bindings_sha256",
        "spec_values signer_role",
    ] {
        assert!(ACCEPTANCE_RUNNER.contains(required_check));
    }
    assert!(ACCEPTANCE_NIX.contains("$out/contracts"));
    assert!(ACCEPTANCE_NIX.contains("releaseAcceptanceContract = import"));
    assert!(ACCEPTANCE_NIX.contains("release-acceptance.toml"));
    assert!(ACCEPTANCE_RUNNER.contains("release_acceptance_contract_result_sha256"));
    assert!(!ACCEPTANCE_RUNNER.contains("sign-offs/allowed-signers"));

    for requirement in [
        "minimum \"duration_hours\" contract.minimum_duration_hours",
        "maximum \"duration_hours\" contract.maximum_duration_hours",
        "minimum \"duration_hours\" contract.minimum_duration_hours",
        "minimum \"duration_hours\" contract.release_candidate_duration_hours",
        "minimum \"execution_count\" contract.scale.minimum_executions",
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
}
