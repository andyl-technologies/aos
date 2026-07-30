//! Failure and verification artifact capture from observed execution evidence.

use super::*;

/// Borrowed scenario component embedded in a reproduction artifact.
pub(crate) struct ReproductionScenarioPayload<'a> {
    /// Stable component name recorded in the artifact.
    pub(crate) name: &'a str,
    /// Media type describing the encoded scenario bytes.
    pub(crate) media_type: &'a str,
    /// Self-contained scenario payload.
    pub(crate) bytes: &'a [u8],
}

pub(crate) fn model_reproduction_artifact_payloads(
    artifact: &crucible::ReproductionArtifact,
    replay_state: crucible::ContentHash,
) -> Vec<ReproductionArtifactComponentPayload> {
    vec![
        ReproductionArtifactComponentPayload {
            kind: String::from("model_reproduction"),
            name: String::from("reproduction.crucible-model"),
            media_type: String::from(MODEL_REPRODUCTION_ARTIFACT_MEDIA_TYPE),
            bytes: artifact.to_compact_binary(),
        },
        ReproductionArtifactComponentPayload {
            kind: String::from("model_replay_state"),
            name: String::from("replay-state.txt"),
            media_type: String::from(MODEL_REPLAY_STATE_MEDIA_TYPE),
            bytes: format_content_hash_ref(replay_state).into_bytes(),
        },
    ]
}

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
        ReproductionScenarioPayload {
            name: "verify.scn",
            media_type: "application/vnd.crucible.scenario+text",
            bytes: &scenario_bytes,
        },
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
        ReproductionScenarioPayload {
            name: "run-scenario.crucible-scenario",
            media_type: "application/vnd.crucible.scenario.compact-binary",
            bytes: &scenario.to_compact_binary(),
        },
        canonical_log,
        fingerprint_samples,
        &[],
    )
}
