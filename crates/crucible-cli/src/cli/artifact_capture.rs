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
    terminal_configuration: &crucible::Configuration,
    canonical_log: &[CanonicalLogEntry],
    fingerprint_samples: &[VerifyFingerprintSample],
) -> Result<Vec<u8>, CliError> {
    if terminal_configuration.def.id() != scenario.id() {
        return Err(CliError::Identity(format!(
            "failed-run terminal scenario {} did not match captured scenario {}",
            terminal_configuration.def.id().to_hex(),
            scenario.id().to_hex()
        )));
    }
    let model_artifact =
        crucible::ReproductionArtifact::capture(scenario, &terminal_configuration.schedule)
            .map_err(|error| {
                artifact_error(format!(
                    "failed-run model reproduction capture failed: {error}"
                ))
            })?;
    let replay = model_artifact.replay().map_err(|error| {
        artifact_error(format!(
            "failed-run model reproduction replay failed: {error}"
        ))
    })?;
    let model_payloads = model_reproduction_artifact_payloads(&model_artifact, replay.state);
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
        &model_payloads,
    )
}

/// Encodes one search/fuzz finding as a CLI replay artifact.
///
/// # Errors
///
/// Returns [`CliError`] when the finding's embedded model reproduction or the
/// selected backend identity cannot be encoded as a replayable artifact.
pub(crate) fn finding_reproduction_artifact_bytes(
    backend: Option<&ResolvedLocalBackend>,
    finding: &crucible::FindingReproductionArtifact,
    producer: &str,
) -> Result<Vec<u8>, CliError> {
    let canonical_log = canonical_log_entries_from_engine_schedule(finding.artifact.schedule());
    let fingerprint_samples = vec![VerifyFingerprintSample {
        index: 0,
        instruction: 0,
        node: producer.to_owned(),
        digest: cli_digest_from_engine_hash(finding.finding_fingerprint),
    }];
    let extra_payloads =
        model_reproduction_artifact_payloads(&finding.artifact, finding.replay.state);
    verify_reproduction_artifact_bytes_with_components(
        seed_to_u64(finding.artifact.seed()),
        backend,
        &finding.artifact.scenario_def(),
        &canonical_log,
        &fingerprint_samples,
        &extra_payloads,
    )
}
