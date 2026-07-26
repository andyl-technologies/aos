//! Failure and verification artifact capture from observed execution evidence.

use super::*;

pub(crate) fn verify_reproduction_artifact_bytes(
    seed: u64,
    backend: Option<&ResolvedLocalBackend>,
    scenario: &crucible::ScenarioDef,
    canonical_log: &[CanonicalLogEntry],
    fingerprint_samples: &[VerifyFingerprintSample],
) -> Result<Vec<u8>, CliError> {
    verify_reproduction_artifact_bytes_with_components(
        seed,
        backend,
        scenario,
        canonical_log,
        fingerprint_samples,
        &[],
    )
}

pub(crate) fn verify_reproduction_artifact_bytes_with_components(
    seed: u64,
    backend: Option<&ResolvedLocalBackend>,
    scenario: &crucible::ScenarioDef,
    canonical_log: &[CanonicalLogEntry],
    fingerprint_samples: &[VerifyFingerprintSample],
    extra_payloads: &[ReproductionArtifactComponentPayload],
) -> Result<Vec<u8>, CliError> {
    let scenario_bytes = scenario_identity_bytes(scenario);
    reproduction_artifact_bytes_with_scenario_payload(
        seed,
        backend,
        "verify.scn",
        "application/vnd.crucible.scenario+text",
        &scenario_bytes,
        canonical_log,
        fingerprint_samples,
        extra_payloads,
    )
}

pub(crate) fn run_failure_reproduction_artifact_bytes(
    seed: u64,
    backend: Option<&ResolvedLocalBackend>,
    scenario: &crucible::ScenarioDefForm,
    canonical_log: &[CanonicalLogEntry],
    fingerprint_samples: &[VerifyFingerprintSample],
) -> Result<Vec<u8>, CliError> {
    reproduction_artifact_bytes_with_scenario_payload(
        seed,
        backend,
        "run-scenario.crucible-scenario",
        "application/vnd.crucible.scenario.compact-binary",
        &scenario.to_compact_binary(),
        canonical_log,
        fingerprint_samples,
        &[],
    )
}
