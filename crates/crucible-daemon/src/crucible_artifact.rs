//! Strict Crucible execution-model payloads carried by campaign artifacts.
//!
//! The campaign repository treats scenario and configuration payloads as
//! opaque, language-neutral byte strings. This module owns the following
//! nested payload schemas:
//!
//! ```text
//! CrucibleScenarioPayloadV5      = ScenarioDefForm compact binary V9
//! CrucibleConfigurationPayloadV5 = Schedule compact binary V5
//! CrucibleReproductionPayloadV5  = ReproductionArtifact stored form V1
//!                                  + schedule segments as payload segments
//! ```
//!
//! A reproduction payload keeps the scenario and schedule manifest inline and
//! publishes every schedule segment as a trace leaf the record names, so the
//! record stays small however long the reproduced run was. Decoding re-derives
//! both semantic identities before a live session or QEMU process can consume
//! the values.

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
mod reproduction_payload;
use reproduction_payload::publish_executor_payload_segments;
pub(crate) use reproduction_payload::try_for_each_payload_segment;
pub use reproduction_payload::{
    RepositoryReproductionSegments, crucible_reproduction_payload, decode_crucible_reproduction,
};

pub use finding_replay::{
    AutomaticFindingReplayOutcome, CrucibleFindingReplayEvidence, CrucibleFindingReplayTranscript,
    FindingProductionReplayMaterialOutcome, FindingReplayIncompatibility,
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
    Configuration, ConfigurationPrefix, ContentHash, Decision, EngineError,
    FindingReproductionArtifact, MAX_MINIMIZATION_CANDIDATES, MinimizationConfig, MinimizationRun,
    NetworkFaultSelectable, ScenarioDefForm, Schedule, SignalFaultCampaignReplayPlan,
    SignalFaultSelectable, validate_preemption_branch_schedule,
};
use crucible_campaign::{
    CampaignCodecError, CampaignExecutorStore, CampaignHash, CampaignRepository,
    CampaignRepositoryError, CandidateGeneratorSpec, CandidateGeneratorSpecId, ChoiceDomain,
    ChoiceOpportunity, ConfigurationArtifact, ConfigurationArtifactId, ConfigurationId,
    CoverageProjection, FindingCandidateBundle, FindingCandidateBundleId,
    FindingExactCheckpointAuthenticator, FindingExactPins, FindingExactRetention,
    FindingExactRetentionEvidence, FindingMinimizationAttempt, FindingMinimizationEvidence,
    FindingReplayCaptureIncomplete, FindingReplayCaptureSet, FindingReplaySignature,
    FindingSignature, FindingSignatureMinimizationEvidence, FindingTriageEvidenceSet,
    FindingTriageReplayEvidence, MeasurementSet, ObservationId, PropertyVerdictSet,
    ReproductionArtifact, ReproductionArtifactId, ResolvedSelection, ScenarioArtifact,
    ScenarioArtifactId, ScenarioDefId, SelectableDeclaration, Selection, SelectionId,
    SelectionOrigin,
};
use crucible_cas::content_store::ContentId;

/// Payload schema for a scenario form with typed selectable declarations.
pub const CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V5: u32 = 5;
/// Payload schema for a compact canonical Crucible configuration schedule.
pub const CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V5: u32 = 5;
/// Payload schema for a reproduction stored form with segmented schedule.
pub const CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V5: u32 = 5;
/// Maximum bytes accepted from one pre-bind Crucible artifact import file.
///
/// This matches the campaign artifact payload ceiling. Import callers should
/// enforce it while reading, before retaining or decoding the complete body.
pub const MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES: usize = 32 * 1024 * 1024;
const CRUCIBLE_SCHEDULE_V6_MAGIC: &[u8] = b"crucible.schedule.v6\0";
type RetainedConfigurationMemoryGuard<'a> =
    dyn FnMut(&Configuration, usize) -> Result<usize, CrucibleArtifactError> + 'a;
// Policy v4 retains the seed, the candidate-count bound, and the automatic
// window. It dropped v3's candidate-copy byte bound once candidates became
// compact descriptors, so v3 policies are rejected rather than reinterpreted.
const CRUCIBLE_MINIMIZATION_POLICY_SCHEMA_V4: u32 = 4;
const CRUCIBLE_MINIMIZATION_POLICY_MAGIC_V4: &[u8] = b"crucible.finding-minimization-policy.v4\0";
const CRUCIBLE_MINIMIZATION_CANDIDATES: u32 = 4_096;
/// Maximum distinct records retained from both finding replay passes.
///
/// Retained records live in the preparation's record store, so this bounds
/// only the identities the transcript and prepared result keep in memory.
/// A prepared-result reader charges at least one validation reference to
/// every record it reconstructs, so the count equals that reference
/// allowance: a transcript holding more records could never be read back.
pub const MAX_CRUCIBLE_FINDING_REPLAY_RECORDS: usize = 4 * 1024 * 1024;
/// Maximum aggregate canonical bytes retained from both finding replay passes.
///
/// Choice opportunities and selections grow with every replayed run, so the
/// retained records are run-length evidence. They are written to disk as they
/// arrive and published with the finding, and take the value of the finding's
/// run-length publication allowance.
pub const MAX_CRUCIBLE_FINDING_REPLAY_BYTES: u64 =
    crucible_campaign::MAX_FINDING_REPLAY_PUBLICATION_SEGMENT_BYTES;
/// Maximum oracle results retained in either finding replay pass.
pub const MAX_CRUCIBLE_FINDING_REPLAYS_PER_PASS: usize = MAX_MINIMIZATION_CANDIDATES + 1;
const _: () = assert!(MAX_MINIMIZATION_CANDIDATES == CRUCIBLE_MINIMIZATION_CANDIDATES as usize);

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
    // The verified Crucible artifacts behind `original` and `minimized`. Their
    // schedules are the source of the payload segments published before each
    // record.
    original_artifact: crucible::ReproductionArtifact,
    minimized_configuration: ConfigurationArtifact,
    minimized: ReproductionArtifact,
    minimized_artifact: crucible::ReproductionArtifact,
    replay_records: PreparedFindingReplayRecords,
    minimization_replays: Vec<RecordedFindingReplay>,
    verification_replays: Vec<RecordedFindingReplay>,
    triage_replays: Option<PreparedFindingTriageReplayRecords>,
    production_replays: Option<PreparedFindingProductionReplays>,
    bundle: FindingCandidateBundle,
}

/// Four production replay results retained for the required finding passes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedFindingProductionReplays {
    minimization_original: crate::FindingProductionReplayCaptureOutcome,
    minimization_selected: crate::FindingProductionReplayCaptureOutcome,
    verification_original: crate::FindingProductionReplayCaptureOutcome,
    verification_selected: crate::FindingProductionReplayCaptureOutcome,
    limits: crate::FindingProductionReplayCaptureLimits,
}

impl PreparedFindingProductionReplays {
    /// Returns the first pass replay of the original reproduction.
    #[must_use]
    pub const fn minimization_original(&self) -> &crate::FindingProductionReplayCaptureOutcome {
        &self.minimization_original
    }

    /// Returns the first pass replay of the selected minimized reproduction.
    #[must_use]
    pub const fn minimization_selected(&self) -> &crate::FindingProductionReplayCaptureOutcome {
        &self.minimization_selected
    }

    /// Returns the independent replay of the original reproduction.
    #[must_use]
    pub const fn verification_original(&self) -> &crate::FindingProductionReplayCaptureOutcome {
        &self.verification_original
    }

    /// Returns the independent replay of the selected minimized reproduction.
    #[must_use]
    pub const fn verification_selected(&self) -> &crate::FindingProductionReplayCaptureOutcome {
        &self.verification_selected
    }

    pub(crate) fn capture_inputs(
        &self,
    ) -> Result<[crate::FindingReplayCaptureInput; 4], crate::FindingProductionReplayCaptureError>
    {
        Ok([
            replay_capture_input(&self.minimization_original)?,
            replay_capture_input(&self.minimization_selected)?,
            replay_capture_input(&self.verification_original)?,
            replay_capture_input(&self.verification_selected)?,
        ])
    }
}

fn replay_capture_input(
    outcome: &crate::FindingProductionReplayCaptureOutcome,
) -> Result<crate::FindingReplayCaptureInput, crate::FindingProductionReplayCaptureError> {
    Ok(match outcome {
        crate::FindingProductionReplayCaptureOutcome::Complete(capture) => {
            crate::FindingReplayCaptureInput::Complete(Box::new(capture.prepare_objects()?))
        }
        crate::FindingProductionReplayCaptureOutcome::Incomplete(reason) => {
            crate::FindingReplayCaptureInput::Incomplete(match reason {
                crate::FindingProductionReplayIncomplete::MissingEventLogPrefix => {
                    FindingReplayCaptureIncomplete::MissingEventLogPrefix
                }
                crate::FindingProductionReplayIncomplete::MissingTerminalFingerprints => {
                    FindingReplayCaptureIncomplete::MissingTerminalFingerprints
                }
                crate::FindingProductionReplayIncomplete::MissingSignalArtifactStore => {
                    FindingReplayCaptureIncomplete::MissingSignalArtifactStore
                }
                crate::FindingProductionReplayIncomplete::MissingWorldArtifactStore => {
                    FindingReplayCaptureIncomplete::MissingWorldArtifactStore
                }
                crate::FindingProductionReplayIncomplete::PublicationLimitExceeded => {
                    FindingReplayCaptureIncomplete::PublicationLimitExceeded
                }
            })
        }
    })
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
        ContentId::for_bytes(ObjectKind::Policy, 5, b"test finding retention policy");
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

    /// Returns the verified Crucible artifact behind [`Self::original`].
    #[must_use]
    pub const fn original_artifact(&self) -> &crucible::ReproductionArtifact {
        &self.original_artifact
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

    /// Returns the verified Crucible artifact behind [`Self::minimized`].
    #[must_use]
    pub const fn minimized_artifact(&self) -> &crucible::ReproductionArtifact {
        &self.minimized_artifact
    }

    /// Returns the number of unique typed records retained from both replay passes.
    #[must_use]
    pub const fn replay_record_count(&self) -> usize {
        self.replay_records.record_count
    }

    /// Returns aggregate canonical body bytes retained from both replay passes.
    #[must_use]
    pub const fn replay_record_bytes(&self) -> u64 {
        self.replay_records.canonical_bytes
    }

    /// Returns the finding-candidate root record.
    #[must_use]
    pub const fn bundle(&self) -> &FindingCandidateBundle {
        &self.bundle
    }

    /// Returns the four transient production replay outcomes, when captured.
    #[must_use]
    pub const fn production_replays(&self) -> Option<&PreparedFindingProductionReplays> {
        self.production_replays.as_ref()
    }

    pub(crate) fn production_replay_capture_bindings(
        &self,
    ) -> Result<[(ReproductionArtifactId, FindingSignature); 4], CampaignCodecError> {
        let original = self.original.id()?;
        let minimized = self.minimized.id()?;
        let selected_index = self
            .minimized
            .minimization()
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "finding production replay minimization is unavailable",
            })?
            .attempts()
            .iter()
            .position(|attempt| attempt.accepted())
            .map_or(0, |index| index + 1);
        let signatures = self.bundle.signature_minimization();
        let signature_at = |pass: &[Option<FindingSignature>], index, reason| {
            pass.get(index)
                .and_then(Option::as_ref)
                .cloned()
                .ok_or(CampaignCodecError::InvalidValue { reason })
        };

        Ok([
            (
                original,
                signature_at(
                    signatures.minimization_pass(),
                    0,
                    "finding production replay minimization original signature is unavailable",
                )?,
            ),
            (
                minimized,
                signature_at(
                    signatures.minimization_pass(),
                    selected_index,
                    "finding production replay minimization selected signature is unavailable",
                )?,
            ),
            (
                original,
                signature_at(
                    signatures.verification_pass(),
                    0,
                    "finding production replay verification original signature is unavailable",
                )?,
            ),
            (
                minimized,
                signature_at(
                    signatures.verification_pass(),
                    selected_index,
                    "finding production replay verification selected signature is unavailable",
                )?,
            ),
        ])
    }

    pub(crate) fn production_replay_capture_inputs(
        &self,
    ) -> Result<
        Option<[crate::FindingReplayCaptureInput; 4]>,
        crate::FindingProductionReplayCaptureError,
    > {
        self.production_replays
            .as_ref()
            .map(PreparedFindingProductionReplays::capture_inputs)
            .transpose()
    }

    pub(crate) fn bind_production_replay_captures(
        &mut self,
        replay_captures: FindingReplayCaptureSet,
    ) -> Result<(), CampaignCodecError> {
        if self.production_replays.is_none() || self.bundle.replay_captures().is_some() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding production replay captures cannot be rebound",
            });
        }
        let core = crucible_campaign::FindingCandidateCore::new(
            self.bundle.observation(),
            self.bundle.signature().clone(),
            self.bundle.reproduction(),
            self.bundle.minimized(),
            self.bundle.signature_minimization().clone(),
            self.bundle.exact_pins().clone(),
        );
        self.bundle = match self.bundle.exact_retention_evidence() {
            Some(evidence) => {
                FindingCandidateBundle::new_with_replay_captures_and_authenticated_exact_retention(
                    core,
                    self.bundle.triage_evidence(),
                    replay_captures,
                    self.bundle.exact_retention(),
                    evidence.clone(),
                )?
            }
            None => FindingCandidateBundle::new_with_replay_captures_and_exact_retention(
                core,
                self.bundle.triage_evidence(),
                replay_captures,
                self.bundle.exact_retention(),
            )?,
        };
        self.production_replays = None;
        Ok(())
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
        // Replay records are read from their store one at a time.
        let records = &self.replay_records;
        records.try_for_each(&records.ids.domains, |domain| {
            store.publish_choice_domain_record(domain).map(drop)
        })?;
        records.try_for_each(&records.ids.declarations, |declaration| {
            store.publish_selectable_record(declaration).map(drop)
        })?;
        records.try_for_each(&records.ids.opportunities, |opportunity| {
            store
                .publish_choice_opportunity_record(opportunity)
                .map(drop)
        })?;
        records.try_for_each(&records.ids.selections, |selection| {
            store.publish_selection_record(selection).map(drop)
        })?;
        records.try_for_each(&records.ids.configurations, |configuration| {
            store.publish_configuration(configuration).map(drop)
        })?;
        records.try_for_each(&records.ids.measurements, |measurements| {
            store.publish_measurement_record(measurements).map(drop)
        })?;
        records.try_for_each(&records.ids.properties, |properties| {
            store.publish_property_record(properties).map(drop)
        })?;
        records.try_for_each(&records.ids.coverage, |coverage| {
            store.publish_coverage_record(coverage).map(drop)
        })?;
        store.publish_configuration(&self.original_configuration)?;
        store.publish_reproduction_record(&self.original, self.original_artifact.schedule())?;
        store.publish_configuration(&self.minimized_configuration)?;
        store.publish_reproduction_record(&self.minimized, self.minimized_artifact.schedule())?;
        if let Some(triage_replays) = &self.triage_replays {
            triage_replays.publish(store)?;
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
        // Replay records are read from their store one at a time.
        let records = &self.replay_records;
        records.try_for_each(&records.ids.domains, |domain| {
            store.publish_executor_choice_domain(domain).map(drop)
        })?;
        records.try_for_each(&records.ids.declarations, |declaration| {
            store.publish_executor_selectable(declaration).map(drop)
        })?;
        records.try_for_each(&records.ids.opportunities, |opportunity| {
            store
                .publish_executor_choice_opportunity(opportunity)
                .map(drop)
        })?;
        records.try_for_each(&records.ids.selections, |selection| {
            store.publish_executor_selection(selection).map(drop)
        })?;
        records.try_for_each(&records.ids.configurations, |configuration| {
            store
                .publish_executor_configuration(configuration)
                .map(drop)
        })?;
        records.try_for_each(&records.ids.measurements, |measurements| {
            store
                .publish_executor_measurement_set(measurements)
                .map(drop)
        })?;
        records.try_for_each(&records.ids.properties, |properties| {
            store
                .publish_executor_property_verdict_set(properties)
                .map(drop)
        })?;
        records.try_for_each(&records.ids.coverage, |coverage| {
            store
                .publish_executor_coverage_projection(coverage)
                .map(drop)
        })?;
        let original_configuration =
            store.publish_executor_configuration(&self.original_configuration)?;
        if original_configuration != self.original_configuration.id()? {
            return Err(CampaignRepositoryError::Integrity {
                reason: "prepared-finding-original-configuration-publication-mismatch",
            });
        }
        publish_executor_payload_segments(store, self.original_artifact.schedule())?;
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
        publish_executor_payload_segments(store, self.minimized_artifact.schedule())?;
        let minimized = store.publish_executor_reproduction(&self.minimized)?;
        if minimized != self.minimized.id()? {
            return Err(CampaignRepositoryError::Integrity {
                reason: "prepared-finding-minimized-publication-mismatch",
            });
        }
        if let Some(triage_replays) = &self.triage_replays {
            triage_replays.publish_for_executor(store)?;
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
        production,
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
    let production_replays =
        prepare_finding_production_replays(production, original_id, minimized_id, finding)?;
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
        original_artifact: finding.artifact.clone(),
        minimized_configuration,
        minimized,
        minimized_artifact: minimization.minimized.artifact.clone(),
        replay_records,
        minimization_replays: minimization_pass,
        verification_replays: verification_pass,
        triage_replays,
        production_replays,
        bundle,
    })
}

fn prepare_finding_production_replays(
    production: finding_replay::RetainedFindingProductionReplayEvidence,
    original: ReproductionArtifactId,
    minimized: ReproductionArtifactId,
    finding: &FindingReproductionArtifact,
) -> Result<Option<PreparedFindingProductionReplays>, CrucibleArtifactError> {
    let Some((
        minimization_original,
        minimization_selected,
        verification_original,
        verification_selected,
    )) = production.into_parts()?
    else {
        return Ok(None);
    };
    let limits = crate::FindingProductionReplayCaptureLimits::for_finding(finding);
    let bind = |reproduction, replay: finding_replay::RetainedFindingProductionReplay| {
        Ok::<_, CrucibleArtifactError>(match replay.capture {
            crate::FindingProductionReplayCaptureOutcome::Complete(material) => {
                crate::FindingProductionReplayCaptureOutcome::Complete(
                    material.as_ref().clone().bind(
                        reproduction,
                        replay.observed_signature,
                        limits,
                    )?,
                )
            }
            crate::FindingProductionReplayCaptureOutcome::Incomplete(reason) => {
                crate::FindingProductionReplayCaptureOutcome::Incomplete(reason)
            }
        })
    };

    Ok(Some(PreparedFindingProductionReplays {
        minimization_original: bind(original, minimization_original)?,
        minimization_selected: bind(minimized, minimization_selected)?,
        verification_original: bind(original, verification_original)?,
        verification_selected: bind(minimized, verification_selected)?,
        limits,
    }))
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
    /// Store that receives each distinct replay record as it is retained.
    pub(crate) record_store: crate::ReplayRecordStore,
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
        record_store,
    } = preparation;
    let observation = result
        .observation()
        .observation()
        .id()
        .map_err(CrucibleArtifactError::from)?;
    let mut transcript = CrucibleFindingReplayTranscript::with_record_store(record_store);
    let mut replay_measurements = BoundedReplayMeasurementEvidence::new(&result)?;

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
                        production_replay,
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
                        let retained = match triage_evidence {
                            Some(triage_evidence) => {
                                AutomaticFindingReplayOutcome::observed_with_triage(
                                    *evidence,
                                    Vec::new(),
                                    *triage_evidence,
                                )
                            }
                            None => AutomaticFindingReplayOutcome::observed(*evidence, Vec::new()),
                        };
                        Ok(match production_replay {
                            Some(capture) => retained.with_production_replay(capture),
                            None => retained,
                        })
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
    let (replay_measurements, replay_segments) = replay_measurements.finish();
    result
        .attach_finding(prepared, replay_measurements, replay_segments)
        .map_err(AutomaticFindingPreparationError::PreparedResult)
}

/// Accumulates finding replay leaves and their segments under the
/// prepared-result record and byte bounds.
///
/// Segments are referenced, not encoded, by the prepared result, so only the
/// leaves count toward its byte bound.
struct BoundedReplayMeasurementEvidence<'a> {
    existing: BTreeMap<ContentId, &'a crate::CrucibleMeasurementReplayEvidence>,
    additional: BTreeMap<ContentId, crate::CrucibleMeasurementReplayEvidence>,
    segments: crate::AttemptLogSegmentSources,
    records: usize,
    canonical_bytes: usize,
}

impl<'a> BoundedReplayMeasurementEvidence<'a> {
    fn new(
        result: &'a PreparedSemanticAttemptResult,
    ) -> Result<Self, PreparedSemanticResultCodecError> {
        let mut accumulator = Self {
            existing: BTreeMap::new(),
            additional: BTreeMap::new(),
            segments: crate::AttemptLogSegmentSources::default(),
            records: 0,
            canonical_bytes: 0,
        };
        for leaf in result.measurement_replay_evidence() {
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
        evidence: Vec<crate::CrucibleMeasurementEvidenceBundle>,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        for bundle in evidence {
            let (leaf, segments) = bundle.into_parts();
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
            self.segments.extend(segments);
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

    fn finish(
        self,
    ) -> (
        Vec<crate::CrucibleMeasurementReplayEvidence>,
        crate::AttemptLogSegmentSources,
    ) {
        (self.additional.into_values().collect(), self.segments)
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
            crucible_reproduction_payload(&finding.artifact)?,
        )?;
        self.publish_reproduction_record(&artifact, schedule)
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
        let decoded_original = decode_crucible_reproduction(
            &stored_original,
            &RepositoryReproductionSegments {
                repository: &self.repository,
                reproduction: original,
            },
            "original finding reproduction",
        )?;
        let original_scenario = run.original.artifact.scenario_form();
        let original_scenario_record = encode_crucible_scenario_artifact(original_scenario)?;
        let original_configuration_record = encode_crucible_configuration_artifact(
            &original_scenario_record,
            run.original.artifact.schedule(),
        )?;
        if decoded_original != run.original.artifact
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
            CRUCIBLE_MINIMIZATION_POLICY_SCHEMA_V4,
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
            crucible_reproduction_payload(&minimized.artifact)?,
            minimization,
        )?;
        self.publish_reproduction_record(&artifact, schedule)
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
