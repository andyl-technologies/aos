//! Validates the Phase 9 automated release acceptance layer.

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
const DEFAULT_NIX: &str = include_str!("../../../tests/crucible/default.nix");
const ROOT_DEFAULT_NIX: &str = include_str!("../../../default.nix");

const EXECUTABLE_GATES: &[&str] = &[
    "gate:campaign-gate-matrix",
    "gate:campaign-operational-continuity",
    "gate:campaign-replay",
    "gate:hot-fork-scaling",
    "gate:campaign-required-gates",
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
    e2e_evidence: E2eEvidence,
    provenance: ProvenanceContract,
    binding: BindingContract,
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
struct E2eEvidence {
    gate: String,
    schema: String,
    live_packaged_qemu_required: bool,
    tcg_only: bool,
    local_profile_replay_required: bool,
    profile_matrix: Vec<String>,
    varied_core_counts: Vec<u64>,
    randomized_worker_scheduling_required: bool,
    wall_clock_jitter_required: bool,
    host_io_stall_required: bool,
    byte_identical_results_required: bool,
    byte_identical_artifact_required: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceContract {
    required: bool,
    fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingContract {
    release_manifest_sha256_required: bool,
    release_manifest_env_sha256_required: bool,
    release_manifest_json_sha256_required: bool,
    release_acceptance_contract_sha256_required: bool,
    executable_gate_result_sha256_required: bool,
    e2e_evidence_result_sha256_required: bool,
    e2e_evidence_manifest_sha256_required: bool,
    missing_or_mismatched_result: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputContract {
    schema: String,
    retains_e2e_evidence: bool,
    retains_executable_gate_results: bool,
    retains_release_manifest: bool,
    retains_release_manifest_env: bool,
    retains_release_manifest_json: bool,
    retains_release_acceptance_contract: bool,
    ordinary_source_package_dependency: bool,
    accepted_result: String,
}

#[test]
fn release_acceptance_requires_automated_local_evidence() -> Result<(), Box<dyn Error>> {
    let contract: AcceptanceContract = toml::from_str(CONTRACT_SOURCE)?;

    assert_eq!(
        contract.schema,
        "aos.crucible.campaign-release-acceptance-contract.v2"
    );
    assert_eq!(contract.gate, "gate:campaign-release-acceptance");
    assert_eq!(contract.acceptance_state, "automated-evidence-required");
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
    assert_eq!(contract.executable_evidence.required_claim_gates.len(), 30);

    assert_eq!(contract.e2e_evidence.gate, "gate:e2e-determinism");
    assert_eq!(
        contract.e2e_evidence.schema,
        "crucible.e2e.native-gate-evidence.v1"
    );
    assert!(contract.e2e_evidence.live_packaged_qemu_required);
    assert!(contract.e2e_evidence.tcg_only);
    assert!(contract.e2e_evidence.local_profile_replay_required);
    assert_eq!(
        contract.e2e_evidence.profile_matrix,
        [
            "quiet-single-core",
            "randomized-worker-two-core",
            "loaded-io-stall-four-core",
        ]
    );
    assert_eq!(contract.e2e_evidence.varied_core_counts, [1, 2, 4]);
    assert!(contract.e2e_evidence.randomized_worker_scheduling_required);
    assert!(contract.e2e_evidence.wall_clock_jitter_required);
    assert!(contract.e2e_evidence.host_io_stall_required);
    assert!(contract.e2e_evidence.byte_identical_results_required);
    assert!(contract.e2e_evidence.byte_identical_artifact_required);

    assert!(contract.provenance.required);
    for field in ["e2e_evidence_result_sha256", "e2e_evidence_manifest_sha256"] {
        assert!(contract.provenance.fields.contains(&field.to_owned()));
    }
    assert!(contract.binding.release_manifest_sha256_required);
    assert!(contract.binding.release_manifest_env_sha256_required);
    assert!(contract.binding.release_manifest_json_sha256_required);
    assert!(contract.binding.release_acceptance_contract_sha256_required);
    assert!(contract.binding.executable_gate_result_sha256_required);
    assert!(contract.binding.e2e_evidence_result_sha256_required);
    assert!(contract.binding.e2e_evidence_manifest_sha256_required);
    assert_eq!(contract.binding.missing_or_mismatched_result, "blocked");

    assert_eq!(
        contract.output.schema,
        "aos.crucible.campaign-release-acceptance.v2"
    );
    assert!(contract.output.retains_e2e_evidence);
    assert!(contract.output.retains_executable_gate_results);
    assert!(contract.output.retains_release_manifest);
    assert!(contract.output.retains_release_manifest_env);
    assert!(contract.output.retains_release_manifest_json);
    assert!(contract.output.retains_release_acceptance_contract);
    assert!(!contract.output.ordinary_source_package_dependency);
    assert_eq!(contract.output.accepted_result, "pass");

    Ok(())
}

#[test]
fn release_acceptance_wires_the_fleet_gate_without_manual_compatibility() {
    for required in [
        "e2eDeterminism,",
        "campaignGateMatrix,",
        "campaignOperationalContinuity,",
        "campaignFindingPortability,",
        "hotForkScaling,",
        "requiredGates,",
        "cruciblePackage,",
        "releaseManifest,",
        "releaseAcceptanceContract,",
        "e2eScenario,",
        "e2eQemuBinary,",
        "e2ePlugin,",
        "e2eKernel,",
        "e2eRootImage,",
    ] {
        assert!(
            ACCEPTANCE_NIX.contains(required),
            "missing input {required}"
        );
    }
    for required in [
        "verify_e2e_evidence",
        "local_profile_replay",
        "varied_core_counts",
        "e2e_evidence_manifest_sha256",
        "verify_e2e_binding",
        "crucible_package_identity",
        "qemu_path",
        "plugin_path",
    ] {
        assert!(
            ACCEPTANCE_RUNNER.contains(required),
            "missing check {required}"
        );
    }
    for required in [
        "--probe-e2e-evidence",
        "tampered canonical results",
        "tampered closure manifest digest",
        "altered local replay result",
        "missing local e2e evidence",
        "missing local e2e result",
        "--probe-e2e-binding",
        "mismatched $key",
        "another release QEMU",
        "another release plugin",
    ] {
        assert!(
            CONTRACT_NIX.contains(required),
            "missing negative control {required}"
        );
    }

    assert!(DEFAULT_NIX.contains("e2eDeterminism = phase4.gates.e2eDeterminism.rawGate;"));
    assert!(
        DEFAULT_NIX.contains(
            "campaignReleaseAcceptance = import ./phase9-campaign-release-acceptance.nix"
        )
    );
    assert!(ROOT_DEFAULT_NIX.contains("crucible-campaign-release-acceptance = crucibleChecks.phase9.gates.campaignReleaseAcceptance;"));
    for removed in [
        "campaignReleaseEvidence",
        "e2eEvidence",
        "operatorEvidence",
        "destructiveRecoveryEvidence",
        "dogfoodEvidence",
        "trustedAllowedSigners",
        "physical_host",
        "cross_host",
        "signer_key_bindings",
        "sign-offs/",
        "human_sign_off",
    ] {
        assert!(!DEFAULT_NIX.contains(removed));
        assert!(!ROOT_DEFAULT_NIX.contains(removed));
        assert!(!ACCEPTANCE_NIX.contains(removed));
        assert!(!ACCEPTANCE_RUNNER.contains(removed));
        assert!(!CONTRACT_NIX.contains(removed));
    }
}
