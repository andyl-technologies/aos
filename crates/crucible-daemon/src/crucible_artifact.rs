//! Strict Crucible execution-model payloads carried by campaign artifacts.
//!
//! The campaign repository treats scenario and configuration payloads as
//! opaque, language-neutral byte strings. This module owns the following
//! nested payload schemas:
//!
//! ```text
//! CrucibleScenarioPayloadV3      = ScenarioDefForm compact binary V7
//! CrucibleConfigurationPayloadV2 = Schedule compact binary V2
//! CrucibleReproductionPayloadV3  = ReproductionArtifact compact binary V7
//! ```
//!
//! Decoding re-derives both semantic identities before a live session or QEMU
//! process can consume the values.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

mod configuration_codec;
mod error;

pub(crate) use configuration_codec::{
    campaign_configuration_id, campaign_scenario_id,
    decode_crucible_configuration_artifact_from_repository,
    decode_crucible_configuration_artifact_with_owned_candidate,
    decode_crucible_configuration_artifact_with_signal_fault_replay_guarded,
};
pub use configuration_codec::{
    decode_crucible_configuration_artifact, decode_crucible_configuration_artifact_with_selections,
    decode_crucible_configuration_artifact_with_signal_fault_replay,
    decode_crucible_scenario_artifact, encode_crucible_configuration_artifact,
    encode_crucible_scenario_artifact,
};
pub use error::{CrucibleArtifactError, FindingRequiredReproductionStage};

mod finding_preparation;
use finding_preparation::{
    FindingReplayPass, PreparedFindingTriageReplayRecords, encode_crucible_minimization_policy,
    minimize_signature_preserving_finding_with_outcomes, prepare_finding_triage_replay_records,
    prepare_minimized_reproduction, prepare_original_reproduction, replay_recorded_signature_pass,
    validate_replay_incompatibility_passes,
};
mod finding_replay;
mod prepared_result;

pub use finding_replay::{
    AutomaticFindingReplayOutcome, CrucibleFindingReplayEvidence, CrucibleFindingReplayTranscript,
    FindingReplayIncompatibility,
};
use finding_replay::{
    PreparedFindingReplayRecords, RecordedFindingReplay, validate_recorded_replay_configuration,
};
use prepared_result::MAX_PREPARED_RESULT_RECORDS;
pub use prepared_result::{
    MAX_PREPARED_SEMANTIC_RESULT_BYTES, PreparedSemanticAttemptResult,
    PreparedSemanticResultCodecError,
};

use crucible::{
    Configuration, ContentHash, Decision, EngineError, FindingReproductionArtifact,
    MAX_MINIMIZATION_CANDIDATE_WORK_BYTES, MAX_MINIMIZATION_CANDIDATES, MinimizationConfig,
    MinimizationRun, ScenarioDefForm, Schedule, SignalFaultCampaignReplayPlan,
    SignalFaultSelectable,
};
use crucible_campaign::{
    CampaignCodecError, CampaignExecutorStore, CampaignHash, CampaignRepository,
    CampaignRepositoryError, CandidateGeneratorSpec, CandidateGeneratorSpecId, ChoiceDomain,
    ChoiceOpportunity, ConfigurationArtifact, ConfigurationArtifactId, ConfigurationId,
    CoverageProjection, FindingCandidateBundle, FindingCandidateBundleId,
    FindingExactCheckpointAuthenticator, FindingExactPins, FindingExactRetention,
    FindingExactRetentionEvidence, FindingMinimizationAttempt, FindingMinimizationEvidence,
    FindingReplaySignature, FindingSignature, FindingSignatureMinimizationEvidence,
    FindingTriageEvidenceSet, FindingTriageReplayEvidence, MeasurementSet, ObservationId,
    PropertyVerdictSet, ReproductionArtifact, ReproductionArtifactId, ResolvedSelection,
    ScenarioArtifact, ScenarioArtifactId, ScenarioDefId, SelectableDeclaration, Selection,
    SelectionId, SelectionOrigin,
};
use crucible_cas::content_store::ContentId;

/// Payload schema for a scenario form with typed selectable declarations.
pub const CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V3: u32 = 3;
/// Payload schema for a compact canonical Crucible configuration schedule.
pub const CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V2: u32 = 2;
/// Payload schema for a reproduction carrying scenario form version seven.
pub const CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3: u32 = 3;
/// Maximum bytes accepted from one pre-bind Crucible artifact import file.
///
/// This matches the campaign artifact payload ceiling. Import callers should
/// enforce it while reading, before retaining or decoding the complete body.
pub const MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES: usize = 32 * 1024 * 1024;
const CRUCIBLE_SCHEDULE_V2_MAGIC: &[u8] = b"crucible.schedule.v2\0";
const MAX_CONFIGURATION_SELECTION_DECISIONS: usize = 4_096;
const MAX_CONFIGURATION_BRANCH_PREFIX_BYTES: usize = 256 * 1024 * 1024;
type RetainedConfigurationMemoryGuard<'a> =
    dyn FnMut(&Configuration, usize) -> Result<usize, CrucibleArtifactError> + 'a;
const CRUCIBLE_MINIMIZATION_POLICY_SCHEMA_V3: u32 = 3;
const CRUCIBLE_MINIMIZATION_POLICY_MAGIC_V3: &[u8] = b"crucible.finding-minimization-policy.v3\0";
const CRUCIBLE_MINIMIZATION_CANDIDATES: u32 = 4_096;
const CRUCIBLE_MINIMIZATION_CANDIDATE_WORK_BYTES: u64 = 128 * 1024 * 1024;
/// Maximum unique immutable records retained from both finding replay passes.
pub const MAX_CRUCIBLE_FINDING_REPLAY_RECORDS: usize = 65_536;
/// Maximum aggregate canonical bytes retained from both finding replay passes.
pub const MAX_CRUCIBLE_FINDING_REPLAY_BYTES: usize = 256 * 1024 * 1024;
/// Maximum oracle results retained in either finding replay pass.
pub const MAX_CRUCIBLE_FINDING_REPLAYS_PER_PASS: usize = MAX_MINIMIZATION_CANDIDATES + 1;
const _: () = assert!(MAX_MINIMIZATION_CANDIDATES == CRUCIBLE_MINIMIZATION_CANDIDATES as usize);
const _: () = assert!(
    MAX_MINIMIZATION_CANDIDATE_WORK_BYTES == CRUCIBLE_MINIMIZATION_CANDIDATE_WORK_BYTES as usize
);

/// Narrow verifier-backed capability for importing Crucible creation objects.
///
/// This capability exposes immutable scenario/configuration and closed
/// generator publication only.
/// It neither exposes campaign refs nor accepts caller-asserted semantic IDs:
/// both identities are re-derived from typed Crucible values before storage.
#[derive(Clone)]
pub struct CrucibleCampaignArtifactStore {
    repository: Arc<CampaignRepository>,
}

/// Prepared immutable records for one verified finding-candidate publication.
///
/// Preparation performs no repository writes. The caller can therefore derive
/// [`Self::id`] before installing an operational publication root, then publish
/// the exact same records idempotently after that root is durable. The admitted
/// finding observation, exact checkpoints, scenario, and transitive evidence
/// leaves are authenticated prerequisites rather than records created here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedCrucibleFindingCandidate {
    discovery_path: crucible::FindingDiscoveryPath,
    minimization_seed: crucible::Seed,
    scenario: ScenarioArtifact,
    original_configuration: ConfigurationArtifact,
    original: ReproductionArtifact,
    minimized_configuration: ConfigurationArtifact,
    minimized: ReproductionArtifact,
    replay_records: PreparedFindingReplayRecords,
    minimization_replays: Vec<RecordedFindingReplay>,
    verification_replays: Vec<RecordedFindingReplay>,
    triage_replays: Option<PreparedFindingTriageReplayRecords>,
    bundle: FindingCandidateBundle,
}

pub(crate) struct PreparedFindingExactRetention {
    pub(crate) retention: FindingExactRetention,
    pub(crate) evidence: Option<FindingExactRetentionEvidence>,
}

#[cfg(test)]
pub(crate) fn test_disabled_finding_exact_retention()
-> Result<PreparedFindingExactRetention, crucible_campaign::CampaignCodecError> {
    use crucible_campaign::{
        AttemptAdmissionId, CampaignPolicyId, CampaignSnapshotId, FindingExactRetentionDisposition,
    };
    use crucible_cas::content_store::ObjectKind;

    let snapshot_content = ContentId::for_bytes(
        ObjectKind::CampaignSnapshot,
        3,
        b"test finding retention snapshot",
    );
    let snapshot =
        CampaignSnapshotId::parse(&format!("crucible.campaign.snapshot@{snapshot_content}"))?;
    let policy_content =
        ContentId::for_bytes(ObjectKind::Policy, 4, b"test finding retention policy");
    let policy = CampaignPolicyId::parse(&format!("crucible.campaign.policy@{policy_content}"))?;
    let admission_content = ContentId::for_bytes(
        ObjectKind::CampaignFact,
        3,
        b"test finding retention admission",
    );
    let admission = AttemptAdmissionId::parse(&format!(
        "crucible.campaign.attempt-admission@{admission_content}"
    ))?;
    let retention = FindingExactRetention::new(
        snapshot,
        policy,
        admission,
        0,
        FindingExactRetentionDisposition::Disabled,
    )?;

    Ok(PreparedFindingExactRetention {
        retention,
        evidence: None,
    })
}

impl PreparedCrucibleFindingCandidate {
    /// Returns the exact scenario record shared by both reproductions.
    #[must_use]
    pub const fn scenario(&self) -> &ScenarioArtifact {
        &self.scenario
    }

    /// Returns the original unminimized configuration record.
    #[must_use]
    pub const fn original_configuration(&self) -> &ConfigurationArtifact {
        &self.original_configuration
    }

    /// Returns the original unminimized reproduction record.
    #[must_use]
    pub const fn original(&self) -> &ReproductionArtifact {
        &self.original
    }

    /// Returns the retained minimized configuration record.
    #[must_use]
    pub const fn minimized_configuration(&self) -> &ConfigurationArtifact {
        &self.minimized_configuration
    }

    /// Returns the retained minimized reproduction record.
    #[must_use]
    pub const fn minimized(&self) -> &ReproductionArtifact {
        &self.minimized
    }

    /// Returns the number of unique typed records retained from both replay passes.
    #[must_use]
    pub const fn replay_record_count(&self) -> usize {
        self.replay_records.record_count
    }

    /// Returns aggregate canonical body bytes retained from both replay passes.
    #[must_use]
    pub const fn replay_record_bytes(&self) -> usize {
        self.replay_records.canonical_bytes
    }

    /// Returns the finding-candidate root record.
    #[must_use]
    pub const fn bundle(&self) -> &FindingCandidateBundle {
        &self.bundle
    }

    /// Returns the deterministic root that must be staged before publication.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when canonical envelope construction
    /// fails.
    pub fn id(&self) -> Result<FindingCandidateBundleId, CampaignCodecError> {
        self.bundle.id()
    }

    /// Publishes every prepared descendant followed by the candidate root.
    ///
    /// All writes are content addressed and idempotent. Callers that coordinate
    /// with destructive collection must already have staged [`Self::id`] and
    /// must retain their publication exclusion until this method returns.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleArtifactError`] when any exact record cannot be stored
    /// or the repository returns an identity other than the prepared identity.
    pub fn publish(
        &self,
        store: &CrucibleCampaignArtifactStore,
    ) -> Result<FindingCandidateBundleId, CrucibleArtifactError> {
        store.publish_scenario_record(&self.scenario)?;
        for domain in &self.replay_records.domains {
            store.publish_choice_domain_record(domain)?;
        }
        for declaration in &self.replay_records.declarations {
            store.publish_selectable_record(declaration)?;
        }
        for opportunity in &self.replay_records.opportunities {
            store.publish_choice_opportunity_record(opportunity)?;
        }
        for selection in &self.replay_records.selections {
            store.publish_selection_record(selection)?;
        }
        for configuration in &self.replay_records.configurations {
            store.publish_configuration(configuration)?;
        }
        for measurements in &self.replay_records.measurements {
            store.publish_measurement_record(measurements)?;
        }
        for properties in &self.replay_records.properties {
            store.publish_property_record(properties)?;
        }
        for coverage in &self.replay_records.coverage {
            store.publish_coverage_record(coverage)?;
        }
        store.publish_configuration(&self.original_configuration)?;
        store.publish_reproduction_record(&self.original)?;
        store.publish_configuration(&self.minimized_configuration)?;
        store.publish_reproduction_record(&self.minimized)?;
        if let Some(triage_replays) = &self.triage_replays {
            for replay in triage_replays.records() {
                store.publish_finding_triage_replay_record(replay)?;
            }
        }

        let expected = self.id()?;
        let stored = store
            .repository
            .publish_finding_candidate_bundle(&self.bundle)
            .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != expected {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored finding candidate bundle",
            });
        }
        Ok(stored)
    }

    /// Publishes this closure through the executor's repository capability.
    ///
    /// The scenario is authenticated input and must already exist. Every other
    /// record is published in dependency order, with the candidate root last.
    /// The caller must retain the same staged-root and collection exclusion
    /// described by [`Self::publish`].
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] when a dependency cannot be stored
    /// or any stored identity differs from the prepared identity.
    pub fn publish_for_executor(
        &self,
        store: &CampaignExecutorStore,
        authenticator: &dyn FindingExactCheckpointAuthenticator,
    ) -> Result<FindingCandidateBundleId, CampaignRepositoryError> {
        for domain in &self.replay_records.domains {
            store.publish_executor_choice_domain(domain)?;
        }
        for declaration in &self.replay_records.declarations {
            store.publish_executor_selectable(declaration)?;
        }
        for opportunity in &self.replay_records.opportunities {
            store.publish_executor_choice_opportunity(opportunity)?;
        }
        for selection in &self.replay_records.selections {
            store.publish_executor_selection(selection)?;
        }
        for configuration in &self.replay_records.configurations {
            store.publish_executor_configuration(configuration)?;
        }
        for measurements in &self.replay_records.measurements {
            store.publish_executor_measurement_set(measurements)?;
        }
        for properties in &self.replay_records.properties {
            store.publish_executor_property_verdict_set(properties)?;
        }
        for coverage in &self.replay_records.coverage {
            store.publish_executor_coverage_projection(coverage)?;
        }
        let original_configuration =
            store.publish_executor_configuration(&self.original_configuration)?;
        if original_configuration != self.original_configuration.id()? {
            return Err(CampaignRepositoryError::Integrity {
                reason: "prepared-finding-original-configuration-publication-mismatch",
            });
        }
        let original = store.publish_executor_reproduction(&self.original)?;
        if original != self.original.id()? {
            return Err(CampaignRepositoryError::Integrity {
                reason: "prepared-finding-original-publication-mismatch",
            });
        }
        let minimized_configuration =
            store.publish_executor_configuration(&self.minimized_configuration)?;
        if minimized_configuration != self.minimized_configuration.id()? {
            return Err(CampaignRepositoryError::Integrity {
                reason: "prepared-finding-minimized-configuration-publication-mismatch",
            });
        }
        let minimized = store.publish_executor_reproduction(&self.minimized)?;
        if minimized != self.minimized.id()? {
            return Err(CampaignRepositoryError::Integrity {
                reason: "prepared-finding-minimized-publication-mismatch",
            });
        }
        if let Some(triage_replays) = &self.triage_replays {
            for replay in triage_replays.records() {
                let stored = store.publish_executor_finding_triage_replay_evidence(replay)?;
                if stored != replay.id()? {
                    return Err(CampaignRepositoryError::Integrity {
                        reason: "prepared-finding-triage-publication-mismatch",
                    });
                }
            }
        }
        let bundle = store.publish_executor_finding_candidate(&self.bundle, authenticator)?;
        if bundle != self.id()? {
            return Err(CampaignRepositoryError::Integrity {
                reason: "prepared-finding-bundle-publication-mismatch",
            });
        }
        Ok(bundle)
    }
}

fn prepare_signature_preserving_minimized_finding_candidate_with_retention(
    signature: FindingSignature,
    observation: ObservationId,
    finding: &FindingReproductionArtifact,
    exact_pins: FindingExactPins,
    exact_retention: PreparedFindingExactRetention,
    seed: crucible::Seed,
    transcript: CrucibleFindingReplayTranscript,
) -> Result<PreparedCrucibleFindingCandidate, CrucibleArtifactError> {
    let CrucibleFindingReplayTranscript {
        minimization_pass,
        verification_pass,
        records,
        triage,
    } = transcript;
    let minimization =
        replay_recorded_signature_pass(finding, &signature, seed, &minimization_pass)?;
    let verified = replay_recorded_signature_pass(finding, &signature, seed, &verification_pass)?;
    if verified != minimization {
        return Err(CrucibleArtifactError::FindingRequiredReproductionMismatch {
            stage: FindingRequiredReproductionStage::SelectedVerification,
        });
    }
    validate_replay_incompatibility_passes(&minimization_pass, &verification_pass)?;

    let (scenario, original_configuration, original) = prepare_original_reproduction(finding)?;
    let original_id = original.id()?;
    let (minimized_configuration, minimized) =
        prepare_minimized_reproduction(original_id, &minimization)?;
    let minimization_evidence =
        minimized
            .minimization()
            .ok_or(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "prepared minimized finding evidence",
            })?;
    let minimization_signatures = minimization_pass
        .iter()
        .map(|replay| replay.signature().cloned())
        .collect();
    let verification_signatures = verification_pass
        .iter()
        .map(|replay| replay.signature().cloned())
        .collect();
    let signature_minimization = FindingSignatureMinimizationEvidence::new(
        &signature,
        minimization_evidence,
        minimization_signatures,
        verification_signatures,
    )?;
    let minimized_id = minimized.id()?;
    let triage_replays = prepare_finding_triage_replay_records(triage, original_id, minimized_id)?;
    let replay_records = records.finish();
    let triage_evidence = triage_replays
        .as_ref()
        .map(PreparedFindingTriageReplayRecords::evidence_set)
        .transpose()?;
    let core = crucible_campaign::FindingCandidateCore::new(
        observation,
        signature,
        original_id,
        minimized_id,
        signature_minimization,
        exact_pins,
    );
    let bundle = match exact_retention.evidence {
        Some(evidence) => FindingCandidateBundle::new_with_authenticated_exact_retention(
            core,
            triage_evidence,
            exact_retention.retention,
            evidence,
        )?,
        None => FindingCandidateBundle::new_with_exact_retention(
            core,
            triage_evidence,
            exact_retention.retention,
        )?,
    };

    Ok(PreparedCrucibleFindingCandidate {
        discovery_path: finding.discovery_path,
        minimization_seed: seed,
        scenario,
        original_configuration,
        original,
        minimized_configuration,
        minimized,
        replay_records,
        minimization_replays: minimization_pass,
        verification_replays: verification_pass,
        triage_replays,
        bundle,
    })
}

/// Runs both minimization passes with typed exact-boundary replay outcomes.
///
/// Deterministically incompatible candidates remain authenticated by their
/// exact configuration and closed reason while contributing no fabricated
/// semantic evidence. Operational replay failures remain oracle errors.
///
/// # Errors
///
/// Returns [`AutomaticFindingPreparationError::Artifact`] when a replay result
/// does not bind the exact candidate or the two passes disagree. Returns
/// [`AutomaticFindingPreparationError::PreparedResult`] when retained raw
/// measurement evidence is incomplete, inconsistent, or exceeds its bound.
pub(crate) struct AutomaticFindingPreparation<'a> {
    pub(crate) signature: FindingSignature,
    pub(crate) finding: &'a FindingReproductionArtifact,
    pub(crate) exact_pins: FindingExactPins,
    pub(crate) exact_retention: PreparedFindingExactRetention,
    pub(crate) seed: crucible::Seed,
}

pub(crate) fn prepare_automatic_signature_preserving_finding_with_outcomes<F>(
    result: PreparedSemanticAttemptResult,
    preparation: AutomaticFindingPreparation<'_>,
    mut signature_oracle: F,
) -> Result<PreparedSemanticAttemptResult, AutomaticFindingPreparationError>
where
    F: FnMut(&FindingReproductionArtifact) -> Result<AutomaticFindingReplayOutcome, EngineError>,
{
    let AutomaticFindingPreparation {
        signature,
        finding,
        exact_pins,
        exact_retention,
        seed,
    } = preparation;
    let observation = result
        .observation()
        .observation()
        .id()
        .map_err(CrucibleArtifactError::from)?;
    let mut transcript = CrucibleFindingReplayTranscript::new();
    let mut replay_measurements =
        BoundedReplayMeasurementEvidence::new(result.measurement_replay_evidence())?;

    for pass in [
        FindingReplayPass::Minimization,
        FindingReplayPass::Verification,
    ] {
        let mut accumulation_error = None;
        let pass_result = minimize_signature_preserving_finding_with_outcomes(
            finding,
            &signature,
            seed,
            pass,
            &mut transcript,
            |candidate| {
                let replay = signature_oracle(candidate)?;
                match replay {
                    AutomaticFindingReplayOutcome::Observed {
                        evidence,
                        measurement_replay_evidence,
                        triage_evidence,
                    } => {
                        if let Err(error) =
                            replay_measurements.extend(measurement_replay_evidence)
                        {
                            accumulation_error = Some(error);
                            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                                operation: "finding minimization replay retention",
                                reason: "raw measurement evidence exceeded its prepared-result bound",
                            });
                        }
                        match triage_evidence {
                            Some(triage_evidence) => {
                                Ok(AutomaticFindingReplayOutcome::observed_with_triage(
                                    *evidence,
                                    Vec::new(),
                                    *triage_evidence,
                                ))
                            }
                            None => Ok(AutomaticFindingReplayOutcome::observed(
                                *evidence,
                                Vec::new(),
                            )),
                        }
                    }
                    incompatible @ AutomaticFindingReplayOutcome::DeterministicallyIncompatible {
                        ..
                    } => Ok(incompatible),
                }
            },
        );
        if let Some(error) = accumulation_error {
            return Err(AutomaticFindingPreparationError::PreparedResult(error));
        }
        pass_result?;
    }

    let prepared = prepare_signature_preserving_minimized_finding_candidate_with_retention(
        signature,
        observation,
        finding,
        exact_pins,
        exact_retention,
        seed,
        transcript,
    )?;
    let replay_measurements = replay_measurements.finish();
    result
        .attach_finding(prepared, replay_measurements)
        .map_err(AutomaticFindingPreparationError::PreparedResult)
}

struct BoundedReplayMeasurementEvidence<'a> {
    existing: BTreeMap<ContentId, &'a crate::CrucibleMeasurementReplayEvidence>,
    additional: BTreeMap<ContentId, crate::CrucibleMeasurementReplayEvidence>,
    records: usize,
    canonical_bytes: usize,
}

impl<'a> BoundedReplayMeasurementEvidence<'a> {
    fn new(
        existing: &'a [crate::CrucibleMeasurementReplayEvidence],
    ) -> Result<Self, PreparedSemanticResultCodecError> {
        let mut accumulator = Self {
            existing: BTreeMap::new(),
            additional: BTreeMap::new(),
            records: 0,
            canonical_bytes: 0,
        };
        for leaf in existing {
            let id = leaf.id()?;
            if accumulator.existing.insert(id, leaf).is_some() {
                return Err(PreparedSemanticResultCodecError::Inconsistent {
                    component: "duplicate measurement replay evidence",
                });
            }
            accumulator.charge(leaf)?;
        }
        Ok(accumulator)
    }

    fn extend(
        &mut self,
        evidence: Vec<crate::CrucibleMeasurementReplayEvidence>,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        for leaf in evidence {
            let id = leaf.id()?;
            if let Some(existing) = self.existing.get(&id) {
                if *existing != &leaf {
                    return Err(PreparedSemanticResultCodecError::Inconsistent {
                        component: "conflicting measurement replay evidence",
                    });
                }
                continue;
            }
            if let Some(existing) = self.additional.get(&id) {
                if existing != &leaf {
                    return Err(PreparedSemanticResultCodecError::Inconsistent {
                        component: "conflicting measurement replay evidence",
                    });
                }
                continue;
            }

            self.charge(&leaf)?;
            self.additional.insert(id, leaf);
        }
        Ok(())
    }

    fn charge(
        &mut self,
        evidence: &crate::CrucibleMeasurementReplayEvidence,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        self.records = self
            .records
            .checked_add(1)
            .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
        let encoded_bytes = evidence.canonical_bytes()?.len();
        self.canonical_bytes = self
            .canonical_bytes
            .checked_add(encoded_bytes)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<u32>()))
            .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
        if self.records > MAX_PREPARED_RESULT_RECORDS
            || self.canonical_bytes > MAX_PREPARED_SEMANTIC_RESULT_BYTES
        {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }
        Ok(())
    }

    fn finish(self) -> Vec<crate::CrucibleMeasurementReplayEvidence> {
        self.additional.into_values().collect()
    }
}

/// Failure to automatically prepare and bind one minimized finding.
#[derive(Debug, thiserror::Error)]
pub enum AutomaticFindingPreparationError {
    /// Crucible replay, signature verification, or campaign artifact preparation failed.
    #[error(transparent)]
    Artifact(#[from] CrucibleArtifactError),
    /// The finding or raw replay evidence did not match the prepared observation.
    #[error(transparent)]
    PreparedResult(#[from] PreparedSemanticResultCodecError),
}

impl CrucibleCampaignArtifactStore {
    /// Creates a narrow artifact-import capability over one repository.
    #[must_use]
    pub const fn new(repository: Arc<CampaignRepository>) -> Self {
        Self { repository }
    }

    fn publish_scenario_record(
        &self,
        artifact: &ScenarioArtifact,
    ) -> Result<ScenarioArtifactId, CrucibleArtifactError> {
        let expected = artifact.id()?;
        let stored = self
            .repository
            .publish_scenario_artifact(
                artifact.scenario(),
                artifact.payload_schema(),
                artifact.payload().to_vec(),
            )
            .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != expected {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored scenario",
            });
        }
        Ok(stored)
    }

    fn publish_choice_domain_record(
        &self,
        value: &ChoiceDomain,
    ) -> Result<(), CrucibleArtifactError> {
        let stored = self
            .repository
            .publish_choice_domain(value)
            .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != value.id()? {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored finding replay choice domain",
            });
        }
        Ok(())
    }

    fn publish_selectable_record(
        &self,
        value: &SelectableDeclaration,
    ) -> Result<(), CrucibleArtifactError> {
        let stored = self
            .repository
            .publish_selectable(value)
            .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != value.id()? {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored finding replay selectable",
            });
        }
        Ok(())
    }

    fn publish_choice_opportunity_record(
        &self,
        value: &ChoiceOpportunity,
    ) -> Result<(), CrucibleArtifactError> {
        let stored = self
            .repository
            .publish_choice_opportunity(value)
            .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != value.id()? {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored finding replay choice opportunity",
            });
        }
        Ok(())
    }

    fn publish_selection_record(&self, value: &Selection) -> Result<(), CrucibleArtifactError> {
        let stored = self
            .repository
            .publish_selection(value)
            .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != value.id()? {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored finding replay selection",
            });
        }
        Ok(())
    }

    fn publish_measurement_record(
        &self,
        value: &MeasurementSet,
    ) -> Result<(), CrucibleArtifactError> {
        let stored = self
            .repository
            .publish_measurement_set(value)
            .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != value.id()? {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored finding replay measurements",
            });
        }
        Ok(())
    }

    fn publish_property_record(
        &self,
        value: &PropertyVerdictSet,
    ) -> Result<(), CrucibleArtifactError> {
        let stored = self
            .repository
            .publish_property_verdict_set(value)
            .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != value.id()? {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored finding replay properties",
            });
        }
        Ok(())
    }

    fn publish_coverage_record(
        &self,
        value: &CoverageProjection,
    ) -> Result<(), CrucibleArtifactError> {
        let stored = self
            .repository
            .publish_coverage_projection(value)
            .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != value.id()? {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored finding replay coverage",
            });
        }
        Ok(())
    }

    /// Verifies, content-addresses, and publishes one Crucible scenario.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleArtifactError`] when encoding, semantic verification,
    /// repository publication, or the resulting identity check fails.
    pub fn import_scenario(
        &self,
        scenario: &ScenarioDefForm,
    ) -> Result<ScenarioArtifactId, CrucibleArtifactError> {
        let artifact = encode_crucible_scenario_artifact(scenario)?;
        decode_crucible_scenario_artifact(&artifact)?;
        let expected = artifact.id()?;
        let stored = self
            .repository
            .publish_scenario_artifact(
                artifact.scenario(),
                artifact.payload_schema(),
                artifact.payload().to_vec(),
            )
            .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != expected {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored scenario",
            });
        }
        Ok(stored)
    }

    /// Verifies and publishes one Crucible scenario plus exact configuration.
    ///
    /// The scenario is idempotently imported first, so the configuration's
    /// closure is complete before publication.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleArtifactError`] when encoding, semantic verification,
    /// repository publication, or either resulting identity check fails.
    pub fn import_configuration(
        &self,
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
    ) -> Result<ConfigurationArtifactId, CrucibleArtifactError> {
        let scenario_artifact = encode_crucible_scenario_artifact(scenario)?;
        let stored_scenario = self.import_scenario(scenario)?;
        if stored_scenario != scenario_artifact.id()? {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored scenario",
            });
        }

        let artifact = encode_crucible_configuration_artifact(&scenario_artifact, schedule)?;
        decode_crucible_configuration_artifact(scenario, &scenario_artifact, &artifact)?;
        self.publish_configuration(&artifact)
    }

    /// Verifies and publishes a configuration using authenticated selection records.
    ///
    /// The caller must publish every exact selection dependency before invoking
    /// this method. The unchanged strict selection decoder checks exact schedule,
    /// opportunity, domain, scenario, branch, and model provenance before write.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleArtifactError`] when scenario import, selection
    /// resolution, semantic verification, repository publication, or the
    /// resulting identity check fails.
    pub(crate) fn import_configuration_with_selections(
        &self,
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
    ) -> Result<ConfigurationArtifactId, CrucibleArtifactError> {
        let scenario_artifact = encode_crucible_scenario_artifact(scenario)?;
        let stored_scenario = self.import_scenario(scenario)?;
        if stored_scenario != scenario_artifact.id()? {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored scenario",
            });
        }

        let artifact = encode_crucible_configuration_artifact(&scenario_artifact, schedule)?;
        let store = CampaignExecutorStore::new(Arc::clone(&self.repository));
        decode_crucible_configuration_artifact_with_selections(
            scenario,
            &scenario_artifact,
            &artifact,
            &store,
        )?;
        self.publish_configuration(&artifact)
    }

    fn publish_configuration(
        &self,
        artifact: &ConfigurationArtifact,
    ) -> Result<ConfigurationArtifactId, CrucibleArtifactError> {
        let expected = artifact.id()?;
        let stored = self
            .repository
            .publish_configuration_artifact(
                artifact.scenario(),
                artifact.scenario_artifact(),
                artifact.configuration(),
                artifact.payload_schema(),
                artifact.payload().to_vec(),
            )
            .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != expected {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored configuration",
            });
        }
        Ok(stored)
    }

    fn publish_reproduction_record(
        &self,
        artifact: &ReproductionArtifact,
    ) -> Result<ReproductionArtifactId, CrucibleArtifactError> {
        let expected = artifact.id()?;
        let stored = match artifact.minimization() {
            Some(minimization) => self.repository.publish_minimized_reproduction_artifact(
                artifact.scenario(),
                artifact.scenario_artifact(),
                artifact.configuration(),
                artifact.configuration_artifact(),
                artifact.finding_fingerprint(),
                artifact.payload_schema(),
                artifact.payload().to_vec(),
                minimization.clone(),
            ),
            None => self.repository.publish_reproduction_artifact(
                artifact.scenario(),
                artifact.scenario_artifact(),
                artifact.configuration(),
                artifact.configuration_artifact(),
                artifact.finding_fingerprint(),
                artifact.payload_schema(),
                artifact.payload().to_vec(),
            ),
        }
        .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != expected {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored finding reproduction",
            });
        }
        Ok(stored)
    }

    fn publish_finding_triage_replay_record(
        &self,
        evidence: &FindingTriageReplayEvidence,
    ) -> Result<(), CrucibleArtifactError> {
        let expected = evidence.id()?;
        let stored = self
            .repository
            .publish_finding_triage_replay_evidence(evidence)
            .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != expected {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored finding triage replay evidence",
            });
        }
        Ok(())
    }

    /// Replays, verifies, and publishes one self-contained finding reproduction.
    ///
    /// The supplied value is reconstructed through Crucible's public capture
    /// path before any campaign write. Its exact scenario/configuration
    /// artifacts are imported first, and the campaign record then binds those
    /// identities to the verified failure fingerprint and compact bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleArtifactError`] when replay, identity validation,
    /// artifact publication, or the resulting stored identity check fails.
    pub fn import_reproduction(
        &self,
        finding: &FindingReproductionArtifact,
    ) -> Result<ReproductionArtifactId, CrucibleArtifactError> {
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
        let configuration_record =
            encode_crucible_configuration_artifact(&scenario_record, schedule)?;
        let stored_configuration = self.import_configuration(scenario, schedule)?;
        if stored_configuration != configuration_record.id()? {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored finding configuration",
            });
        }

        let fingerprint = CampaignHash::from_bytes(finding.finding_fingerprint.bytes);
        let artifact = ReproductionArtifact::new(
            crucible_campaign::ReproductionArtifactBasis::new(
                scenario_record.scenario(),
                scenario_record.id()?,
                configuration_record.configuration(),
                stored_configuration,
                fingerprint,
            ),
            CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3,
            finding.artifact.to_compact_binary(),
        )?;
        let expected = artifact.id()?;
        let stored = self
            .repository
            .publish_reproduction_artifact(
                artifact.scenario(),
                artifact.scenario_artifact(),
                artifact.configuration(),
                artifact.configuration_artifact(),
                artifact.finding_fingerprint(),
                artifact.payload_schema(),
                artifact.payload().to_vec(),
            )
            .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != expected {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored finding reproduction",
            });
        }
        Ok(stored)
    }

    /// Revalidates and publishes one deterministic minimized reproduction.
    ///
    /// The original campaign reproduction must match `run.original`. The
    /// adapter reruns the complete bounded minimization with `failure_oracle`,
    /// compares the exact result, then retains the compiled policy, every
    /// candidate outcome, and the final replay state in the schema-v2 campaign
    /// reproduction.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleArtifactError`] when the original record is missing or
    /// mismatched, deterministic minimization or replay fails, exact artifact
    /// import fails, or campaign publication does not preserve the expected ID.
    pub fn import_minimized_reproduction<F>(
        &self,
        original: ReproductionArtifactId,
        run: &MinimizationRun,
        failure_oracle: F,
    ) -> Result<ReproductionArtifactId, CrucibleArtifactError>
    where
        F: FnMut(&FindingReproductionArtifact) -> Result<Option<ContentHash>, EngineError>,
    {
        let stored_original = self.repository.load_reproduction_artifact(original)?;
        let decoded_original =
            crucible::ReproductionArtifact::from_compact_binary(stored_original.payload())
                .map_err(|source| CrucibleArtifactError::InvalidPayload {
                    artifact: "original finding reproduction",
                    source: Box::new(source),
                })?;
        let original_scenario = run.original.artifact.scenario_form();
        let original_scenario_record = encode_crucible_scenario_artifact(original_scenario)?;
        let original_configuration_record = encode_crucible_configuration_artifact(
            &original_scenario_record,
            run.original.artifact.schedule(),
        )?;
        if decoded_original != run.original.artifact
            || stored_original.payload_schema() != CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3
            || stored_original.finding_fingerprint()
                != CampaignHash::from_bytes(run.target_fingerprint.bytes)
            || stored_original.scenario() != original_scenario_record.scenario()
            || stored_original.scenario_artifact() != original_scenario_record.id()?
            || stored_original.configuration() != original_configuration_record.configuration()
            || stored_original.configuration_artifact() != original_configuration_record.id()?
        {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "minimization original",
            });
        }

        let verified = run
            .original
            .minimize(run.config(), failure_oracle)
            .map_err(|source| CrucibleArtifactError::InvalidPayload {
                artifact: "finding minimization",
                source: Box::new(source),
            })?;
        if verified != *run {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "minimization run",
            });
        }

        let minimized = &verified.minimized;
        let scenario = minimized.artifact.scenario_form();
        let schedule = minimized.artifact.schedule();
        let scenario_record = encode_crucible_scenario_artifact(scenario)?;
        let configuration_record =
            encode_crucible_configuration_artifact(&scenario_record, schedule)?;
        let stored_configuration = self.import_configuration(scenario, schedule)?;
        if stored_configuration != configuration_record.id()? {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored minimized configuration",
            });
        }

        let policy = encode_crucible_minimization_policy(verified.config());
        let attempts = verified
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
            policy,
            attempts,
            CampaignHash::from_bytes(minimized.replay.state.bytes),
        )?;
        let fingerprint = CampaignHash::from_bytes(minimized.finding_fingerprint.bytes);
        let artifact = ReproductionArtifact::new_minimized(
            crucible_campaign::ReproductionArtifactBasis::new(
                scenario_record.scenario(),
                scenario_record.id()?,
                configuration_record.configuration(),
                stored_configuration,
                fingerprint,
            ),
            CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3,
            minimized.artifact.to_compact_binary(),
            minimization.clone(),
        )?;
        let expected = artifact.id()?;
        let stored = self
            .repository
            .publish_minimized_reproduction_artifact(
                artifact.scenario(),
                artifact.scenario_artifact(),
                artifact.configuration(),
                artifact.configuration_artifact(),
                artifact.finding_fingerprint(),
                artifact.payload_schema(),
                artifact.payload().to_vec(),
                minimization,
            )
            .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != expected {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored minimized finding reproduction",
            });
        }
        Ok(stored)
    }

    /// Validates and publishes one closed candidate-generator specification.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleArtifactError`] when canonical identity derivation or
    /// immutable repository publication fails.
    pub fn import_generator(
        &self,
        generator: &CandidateGeneratorSpec,
    ) -> Result<CandidateGeneratorSpecId, CrucibleArtifactError> {
        let expected = generator.id()?;
        let stored = self
            .repository
            .publish_generator(generator)
            .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != expected {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored candidate generator",
            });
        }
        Ok(stored)
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#[allow(clippy::expect_used)]
mod tests;
