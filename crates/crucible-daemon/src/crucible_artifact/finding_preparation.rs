//! Signature-preserving finding preparation and replay-pass validation.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PreparedFindingTriageReplayRecords {
    pub(super) minimization_original: FindingTriageReplayEvidence,
    pub(super) minimization_selected: FindingTriageReplayEvidence,
    pub(super) verification_original: FindingTriageReplayEvidence,
    pub(super) verification_selected: FindingTriageReplayEvidence,
}

impl PreparedFindingTriageReplayRecords {
    pub(super) fn evidence_set(&self) -> Result<FindingTriageEvidenceSet, CampaignCodecError> {
        Ok(FindingTriageEvidenceSet::new(
            self.minimization_original.id()?,
            self.minimization_selected.id()?,
            self.verification_original.id()?,
            self.verification_selected.id()?,
        ))
    }

    pub(super) fn records(&self) -> [&FindingTriageReplayEvidence; 4] {
        [
            &self.minimization_original,
            &self.minimization_selected,
            &self.verification_original,
            &self.verification_selected,
        ]
    }
}

pub(super) fn prepare_finding_triage_replay_records(
    triage: finding_replay::RetainedFindingTriageEvidence,
    original: ReproductionArtifactId,
    minimized: ReproductionArtifactId,
) -> Result<Option<PreparedFindingTriageReplayRecords>, CrucibleArtifactError> {
    let Some((
        minimization_original,
        minimization_selected,
        verification_original,
        verification_selected,
    )) = triage.into_parts()?
    else {
        return Ok(None);
    };

    let prepare = |reproduction, replay: finding_replay::RetainedFindingTriageReplay| {
        Ok::<_, CrucibleArtifactError>(FindingTriageReplayEvidence::new(
            reproduction,
            replay.observed_signature,
            replay.evidence.schema_version(),
            replay.evidence.to_compact_binary().map_err(|source| {
                CrucibleArtifactError::InvalidPayload {
                    artifact: "finding triage replay evidence",
                    source: Box::new(source),
                }
            })?,
        )?)
    };

    Ok(Some(PreparedFindingTriageReplayRecords {
        minimization_original: prepare(original, minimization_original)?,
        minimization_selected: prepare(minimized, minimization_selected)?,
        verification_original: prepare(original, verification_original)?,
        verification_selected: prepare(minimized, verification_selected)?,
    }))
}

pub(super) fn prepare_original_reproduction(
    finding: &FindingReproductionArtifact,
) -> Result<
    (
        ScenarioArtifact,
        ConfigurationArtifact,
        ReproductionArtifact,
    ),
    CrucibleArtifactError,
> {
    let scenario = finding.artifact.scenario_form();
    let schedule = finding.artifact.schedule();
    let configuration = Configuration {
        def: finding.artifact.scenario_def(),
        schedule: schedule.clone(),
    };
    let verified = FindingReproductionArtifact::capture(
        finding.discovery_path,
        finding.finding_fingerprint,
        scenario,
        &configuration,
    )
    .map_err(|source| CrucibleArtifactError::InvalidPayload {
        artifact: "finding reproduction",
        source: Box::new(source),
    })?;
    if verified != *finding {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding reproduction",
        });
    }

    let scenario_record = encode_crucible_scenario_artifact(scenario)?;
    let configuration_record = encode_crucible_configuration_artifact(&scenario_record, schedule)?;
    let reproduction = ReproductionArtifact::new(
        crucible_campaign::ReproductionArtifactBasis::new(
            scenario_record.scenario(),
            scenario_record.id()?,
            configuration_record.configuration(),
            configuration_record.id()?,
            CampaignHash::from_bytes(finding.finding_fingerprint.bytes),
        ),
        CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V4,
        finding.artifact.to_compact_binary(),
    )?;
    Ok((scenario_record, configuration_record, reproduction))
}

pub(super) fn prepare_minimized_reproduction(
    original: ReproductionArtifactId,
    run: &MinimizationRun,
) -> Result<(ConfigurationArtifact, ReproductionArtifact), CrucibleArtifactError> {
    let minimized = &run.minimized;
    let scenario_record = encode_crucible_scenario_artifact(minimized.artifact.scenario_form())?;
    let configuration_record =
        encode_crucible_configuration_artifact(&scenario_record, minimized.artifact.schedule())?;
    let attempts = run
        .attempts
        .iter()
        .map(|attempt| {
            FindingMinimizationAttempt::new(
                attempt.sequence,
                CampaignHash::from_bytes(attempt.candidate_artifact.bytes),
                CampaignHash::from_bytes(attempt.candidate_schedule.bytes),
                CampaignHash::from_bytes(attempt.replayed_state.bytes),
                attempt
                    .observed_fingerprint
                    .map(|fingerprint| CampaignHash::from_bytes(fingerprint.bytes)),
                attempt.accepted,
            )
        })
        .collect();
    let minimization = FindingMinimizationEvidence::new(
        original,
        CRUCIBLE_MINIMIZATION_POLICY_SCHEMA_V3,
        encode_crucible_minimization_policy(run.config()),
        attempts,
        CampaignHash::from_bytes(minimized.replay.state.bytes),
    )?;
    let reproduction = ReproductionArtifact::new_minimized(
        crucible_campaign::ReproductionArtifactBasis::new(
            scenario_record.scenario(),
            scenario_record.id()?,
            configuration_record.configuration(),
            configuration_record.id()?,
            CampaignHash::from_bytes(minimized.finding_fingerprint.bytes),
        ),
        CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V4,
        minimized.artifact.to_compact_binary(),
        minimization,
    )?;
    Ok((configuration_record, reproduction))
}

pub(super) fn replay_recorded_signature_pass(
    finding: &FindingReproductionArtifact,
    signature: &FindingSignature,
    seed: crucible::Seed,
    observations: &[RecordedFindingReplay],
) -> Result<MinimizationRun, CrucibleArtifactError> {
    let target_fingerprint = finding.finding_fingerprint;
    if CampaignHash::from_bytes(target_fingerprint.bytes) != signature.fingerprint() {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding signature",
        });
    }
    if observations
        .first()
        .and_then(RecordedFindingReplay::signature)
        != Some(signature)
    {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding minimization original replay observation",
        });
    }

    let target_signature = FindingReplaySignature::from_observed(signature);
    let mut next_observation = 0;
    let mut replay_error = None;
    let run = finding
        .minimize(
            MinimizationConfig::automatic_interesting_suffix(seed, finding.artifact.schedule()),
            |candidate| {
                let Some(observed) = observations.get(next_observation) else {
                    replay_error = Some("finding minimization replay observation count");
                    return Err(EngineError::UnifiedOperationEvidenceMismatch {
                        operation: "finding minimization replay",
                        reason: "finding minimization replay observation count",
                    });
                };
                next_observation += 1;
                if validate_recorded_replay_configuration(candidate, observed).is_err() {
                    replay_error = Some("finding replay candidate configuration");
                    return Err(EngineError::UnifiedOperationEvidenceMismatch {
                        operation: "finding minimization replay",
                        reason: "finding minimization replay configuration mismatch",
                    });
                }
                let preserves_signature = observed
                    .signature()
                    .map(FindingReplaySignature::from_observed)
                    .as_ref()
                    == Some(&target_signature);
                Ok(preserves_signature.then_some(target_fingerprint))
            },
        )
        .map_err(|source| match replay_error {
            Some(artifact) => CrucibleArtifactError::SemanticIdentityMismatch { artifact },
            None => CrucibleArtifactError::InvalidPayload {
                artifact: "recorded signature-preserving finding minimization",
                source: Box::new(source),
            },
        })?;
    let expected_observations = run.attempts.len().checked_add(1).ok_or(
        CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding minimization replay observation count",
        },
    )?;
    if observations.len() != expected_observations || next_observation != expected_observations {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding minimization replay observation count",
        });
    }
    Ok(run)
}

pub(super) fn validate_replay_incompatibility_passes(
    minimization: &[RecordedFindingReplay],
    verification: &[RecordedFindingReplay],
) -> Result<(), CrucibleArtifactError> {
    if minimization.len() != verification.len()
        || minimization.iter().zip(verification).any(|(left, right)| {
            let left_reason = left.incompatibility();
            let right_reason = right.incompatibility();
            (left_reason.is_some() || right_reason.is_some()) && left_reason != right_reason
        })
    {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding replay deterministic incompatibility passes",
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum FindingReplayPass {
    Minimization,
    Verification,
}

impl FindingReplayPass {
    const fn required_reproduction_stage(self) -> FindingRequiredReproductionStage {
        match self {
            Self::Minimization => FindingRequiredReproductionStage::MinimizationOriginal,
            Self::Verification => FindingRequiredReproductionStage::VerificationOriginal,
        }
    }
}

pub(super) fn minimize_signature_preserving_finding_with_outcomes<F>(
    finding: &FindingReproductionArtifact,
    signature: &FindingSignature,
    seed: crucible::Seed,
    pass: FindingReplayPass,
    transcript: &mut CrucibleFindingReplayTranscript,
    mut signature_oracle: F,
) -> Result<MinimizationRun, CrucibleArtifactError>
where
    F: FnMut(&FindingReproductionArtifact) -> Result<AutomaticFindingReplayOutcome, EngineError>,
{
    let target_fingerprint = finding.finding_fingerprint;
    if CampaignHash::from_bytes(target_fingerprint.bytes) != signature.fingerprint() {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding signature",
        });
    }

    let target_signature = FindingReplaySignature::from_observed(signature);
    let mut transcript_error = None;
    let mut required_reproduction_mismatch = false;
    let mut first_replay = true;
    let run = finding
        .minimize(
            MinimizationConfig::automatic_interesting_suffix(seed, finding.artifact.schedule()),
            |candidate| {
                let observed = signature_oracle(candidate)?;
                let preserves_signature = observed
                    .signature()
                    .map(FindingReplaySignature::from_observed)
                    .as_ref()
                    == Some(&target_signature);
                if std::mem::replace(&mut first_replay, false) && !preserves_signature {
                    required_reproduction_mismatch = true;
                    return Err(EngineError::ReplayTargetMismatch {
                        expected: finding.finding_fingerprint,
                        actual: ContentHash::default(),
                    });
                }
                let result = match pass {
                    FindingReplayPass::Minimization => transcript
                        .record_minimization_outcome_with_acceptance(
                            candidate,
                            observed,
                            preserves_signature,
                        ),
                    FindingReplayPass::Verification => transcript
                        .record_verification_outcome_with_acceptance(
                            candidate,
                            observed,
                            preserves_signature,
                        ),
                };
                if let Err(error) = result {
                    transcript_error = Some(error);
                    return Err(EngineError::UnifiedOperationEvidenceMismatch {
                        operation: "finding minimization replay retention",
                        reason: "finding replay evidence could not be retained",
                    });
                }
                Ok(preserves_signature.then_some(target_fingerprint))
            },
        )
        .map_err(|source| {
            transcript_error.unwrap_or_else(|| {
                if required_reproduction_mismatch {
                    CrucibleArtifactError::FindingRequiredReproductionMismatch {
                        stage: pass.required_reproduction_stage(),
                    }
                } else {
                    CrucibleArtifactError::InvalidPayload {
                        artifact: "signature-preserving finding minimization",
                        source: Box::new(source),
                    }
                }
            })
        })?;
    Ok(run)
}

pub(super) fn encode_crucible_minimization_policy(config: MinimizationConfig) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CRUCIBLE_MINIMIZATION_POLICY_MAGIC_V3.len() + 69);
    bytes.extend_from_slice(CRUCIBLE_MINIMIZATION_POLICY_MAGIC_V3);
    bytes.extend_from_slice(&config.seed.bytes());
    bytes.extend_from_slice(&CRUCIBLE_MINIMIZATION_CANDIDATES.to_be_bytes());
    bytes.extend_from_slice(&CRUCIBLE_MINIMIZATION_CANDIDATE_WORK_BYTES.to_be_bytes());
    match config.interesting_window() {
        Some(window) => {
            bytes.push(1);
            bytes.extend_from_slice(&(window.original_schedule_len() as u64).to_be_bytes());
            bytes.extend_from_slice(&(window.start() as u64).to_be_bytes());
            bytes.extend_from_slice(&(window.end() as u64).to_be_bytes());
            bytes.push(match window.basis() {
                crucible::InterestingScheduleWindowBasis::LatestCampaignBranch => 1,
                crucible::InterestingScheduleWindowBasis::TerminalSuffix => 2,
            });
        }
        None => bytes.push(0),
    }
    bytes
}
