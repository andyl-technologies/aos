//! Strict Crucible execution-model payloads carried by campaign artifacts.
//!
//! The campaign repository treats scenario and configuration payloads as
//! opaque, language-neutral byte strings. This module owns the following
//! nested payload schemas:
//!
//! ```text
//! CrucibleScenarioPayloadV1      = ScenarioDefForm compact binary V5
//! CrucibleScenarioPayloadV2      = ScenarioDefForm compact binary V6
//! CrucibleScenarioPayloadV3      = ScenarioDefForm compact binary V7
//! CrucibleConfigurationPayloadV2 = Schedule compact binary V2
//! CrucibleReproductionPayloadV2  = ReproductionArtifact compact binary V6
//! CrucibleReproductionPayloadV3  = ReproductionArtifact compact binary V7
//! ```
//!
//! Decoding re-derives both semantic identities before a live session or QEMU
//! process can consume the values.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

mod finding_replay;
mod prepared_result;

pub use finding_replay::{
    AutomaticFindingReplayOutcome, CrucibleFindingReplayEvidence, CrucibleFindingReplayTranscript,
    FindingProductionReplayMaterialOutcome, FindingReplayIncompatibility,
};
use finding_replay::{
    PreparedFindingReplayRecords, RecordedFindingReplay, validate_recorded_replay_configuration,
};
use prepared_result::MAX_PREPARED_RESULT_RECORDS;
pub(crate) use prepared_result::PreparedSemanticResultVersion;
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
    CoverageProjection, FindingCandidateBundle, FindingCandidateBundleId, FindingExactPins,
    FindingMinimizationAttempt, FindingMinimizationEvidence, FindingReplayCaptureIncomplete,
    FindingReplayCaptureSet, FindingReplaySignature, FindingSignature,
    FindingSignatureMinimizationEvidence, FindingTriageEvidenceSet, FindingTriageReplayEvidence,
    MeasurementSet, ObservationId, PropertyVerdictSet, ReproductionArtifact,
    ReproductionArtifactId, ResolvedSelection, ScenarioArtifact, ScenarioArtifactId, ScenarioDefId,
    SelectableDeclaration, Selection, SelectionId, SelectionOrigin,
};
use crucible_cas::content_store::ContentId;

/// Payload schema for a compact canonical Crucible scenario definition.
pub const CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V1: u32 = 1;
/// Payload schema for a scenario form with measurement-definition identity.
pub const CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V2: u32 = 2;
/// Payload schema for a scenario form with typed selectable declarations.
pub const CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V3: u32 = 3;
/// Payload schema for a compact canonical Crucible configuration schedule.
pub const CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V2: u32 = 2;
/// Payload schema for a compact canonical Crucible reproduction artifact.
pub const CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V1: u32 = 1;
/// Payload schema for a reproduction artifact carrying scenario form v6.
pub const CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V2: u32 = 2;
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
const CRUCIBLE_MINIMIZATION_POLICY_SCHEMA_V2: u32 = 2;
const CRUCIBLE_MINIMIZATION_POLICY_MAGIC_V2: &[u8] = b"crucible.finding-minimization-policy.v2\0";
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

    /// Encodes the four role-specific captures for chunked publication.
    ///
    /// # Errors
    ///
    /// Returns an error when a complete capture no longer validates or exceeds
    /// its scenario-derived canonical encoding bound.
    pub(crate) fn capture_inputs(
        &self,
    ) -> Result<[crate::FindingReplayCaptureInput; 4], crate::FindingProductionReplayCaptureError>
    {
        Ok([
            replay_capture_input(&self.minimization_original, self.limits)?,
            replay_capture_input(&self.minimization_selected, self.limits)?,
            replay_capture_input(&self.verification_original, self.limits)?,
            replay_capture_input(&self.verification_selected, self.limits)?,
        ])
    }
}

fn replay_capture_input(
    outcome: &crate::FindingProductionReplayCaptureOutcome,
    limits: crate::FindingProductionReplayCaptureLimits,
) -> Result<crate::FindingReplayCaptureInput, crate::FindingProductionReplayCaptureError> {
    Ok(match outcome {
        crate::FindingProductionReplayCaptureOutcome::Complete(capture) => {
            let bytes = capture.to_canonical_bytes(limits)?;
            let content_hash = crucible::ContentHash::from_bytes(&bytes);

            crate::FindingReplayCaptureInput::Complete {
                bytes,
                content_hash,
            }
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedFindingTriageReplayRecords {
    minimization_original: FindingTriageReplayEvidence,
    minimization_selected: FindingTriageReplayEvidence,
    verification_original: FindingTriageReplayEvidence,
    verification_selected: FindingTriageReplayEvidence,
}

impl PreparedFindingTriageReplayRecords {
    fn evidence_set(&self) -> Result<FindingTriageEvidenceSet, CampaignCodecError> {
        Ok(FindingTriageEvidenceSet::new(
            self.minimization_original.id()?,
            self.minimization_selected.id()?,
            self.verification_original.id()?,
            self.verification_selected.id()?,
        ))
    }

    fn records(&self) -> [&FindingTriageReplayEvidence; 4] {
        [
            &self.minimization_original,
            &self.minimization_selected,
            &self.verification_original,
            &self.verification_selected,
        ]
    }
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

    /// Returns the four production replay captures when the producer supports them.
    #[must_use]
    pub const fn production_replays(&self) -> Option<&PreparedFindingProductionReplays> {
        self.production_replays.as_ref()
    }

    /// Returns each durable capture's exact reproduction and observed signature.
    pub(crate) fn production_replay_capture_bindings(
        &self,
    ) -> Result<[(ReproductionArtifactId, &FindingSignature); 4], CampaignCodecError> {
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
        let minimization_original = finding_replay_signature_at(
            signatures.minimization_pass(),
            0,
            "finding production replay minimization original signature is unavailable",
        )?;
        let minimization_selected = finding_replay_signature_at(
            signatures.minimization_pass(),
            selected_index,
            "finding production replay minimization selected signature is unavailable",
        )?;
        let verification_original = finding_replay_signature_at(
            signatures.verification_pass(),
            0,
            "finding production replay verification original signature is unavailable",
        )?;
        let verification_selected = finding_replay_signature_at(
            signatures.verification_pass(),
            selected_index,
            "finding production replay verification selected signature is unavailable",
        )?;

        Ok([
            (original, minimization_original),
            (minimized, minimization_selected),
            (original, verification_original),
            (minimized, verification_selected),
        ])
    }

    /// Encodes the four transient production outcomes for chunked publication.
    ///
    /// # Errors
    ///
    /// Returns an error when a complete capture no longer validates or exceeds
    /// its scenario-derived canonical encoding bound.
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

    /// Replaces transient production captures with their durable manifest roots.
    ///
    /// The caller invokes this only after every complete capture manifest has
    /// been written under repository GC exclusion. Rebuilding the candidate
    /// changes its identity, so the returned state must enter the operational
    /// Publishing state before that exclusion is released.
    ///
    /// # Errors
    ///
    /// Returns an error when no transient capture set is present, the bundle
    /// was already bound, or the version-three bundle is invalid.
    pub(crate) fn bind_production_replay_captures(
        &mut self,
        replay_captures: FindingReplayCaptureSet,
    ) -> Result<(), CampaignCodecError> {
        if self.production_replays.is_none() || self.bundle.replay_captures().is_some() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding production replay captures cannot be rebound",
            });
        }

        let bundle = FindingCandidateBundle::new_with_replay_captures(
            self.bundle.observation(),
            self.bundle.signature().clone(),
            self.bundle.reproduction(),
            self.bundle.minimized(),
            self.bundle.signature_minimization().clone(),
            self.bundle.exact_pins().clone(),
            self.bundle.triage_evidence(),
            replay_captures,
        )?;

        self.bundle = bundle;
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
        let bundle = store.publish_executor_finding_candidate(&self.bundle)?;
        if bundle != self.id()? {
            return Err(CampaignRepositoryError::Integrity {
                reason: "prepared-finding-bundle-publication-mismatch",
            });
        }
        Ok(bundle)
    }
}

fn finding_replay_signature_at<'a>(
    pass: &'a [Option<FindingSignature>],
    index: usize,
    reason: &'static str,
) -> Result<&'a FindingSignature, CampaignCodecError> {
    pass.get(index)
        .and_then(Option::as_ref)
        .ok_or(CampaignCodecError::InvalidValue { reason })
}

/// Prepares a signature-preserving minimized finding without repository writes.
///
/// `transcript` must contain the actual typed evidence recorded by the caller's
/// execution-model replay oracle. Each pass begins with the original
/// reproduction and continues one-to-one with the
/// deterministic minimizer's candidate order. This function replays that order
/// only through Crucible's pure schedule reducer; it never fabricates, executes,
/// or infers a signature. Both supplied signature passes must independently
/// select the same exact run. Unique retained records across both passes are
/// bounded separately from reducer work.
///
/// # Errors
///
/// Returns [`CrucibleArtifactError`] when the finding, signature, pass lengths,
/// pass observations, deterministic run, or constructed campaign records are
/// inconsistent.
pub fn prepare_signature_preserving_minimized_finding_candidate(
    signature: FindingSignature,
    observation: ObservationId,
    finding: &FindingReproductionArtifact,
    exact_pins: FindingExactPins,
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
    let bundle = match &triage_replays {
        Some(triage_replays) => FindingCandidateBundle::new_with_triage_evidence(
            observation,
            signature,
            original_id,
            minimized_id,
            signature_minimization,
            exact_pins,
            triage_replays.evidence_set()?,
        )?,
        None => FindingCandidateBundle::new(
            observation,
            signature,
            original_id,
            minimized_id,
            signature_minimization,
            exact_pins,
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

fn prepare_finding_triage_replay_records(
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

/// Runs both minimization passes and attaches their finding to one observation.
///
/// The supplied prepared result is the exact semantic result that will enter
/// the durable executor journal. The oracle returns both its typed finding
/// replay and the raw measurement leaves needed to reauthenticate that replay
/// after restart. Both passes use Crucible's fixed candidate and copy-work
/// bounds, and no repository writes occur during this operation.
///
/// # Errors
///
/// Returns [`AutomaticFindingPreparationError::Artifact`] when either replay
/// pass fails or does not preserve the target signature. Returns
/// [`AutomaticFindingPreparationError::PreparedResult`] when the prepared
/// finding does not belong to the observation or its combined raw measurement
/// evidence is incomplete or inconsistent.
// crucible-lint: allow rust-allow -- the finding basis remains explicit at the execution boundary.
#[allow(clippy::too_many_arguments)]
pub fn prepare_automatic_signature_preserving_finding<F>(
    result: PreparedSemanticAttemptResult,
    signature: FindingSignature,
    finding: &FindingReproductionArtifact,
    exact_pins: FindingExactPins,
    seed: crucible::Seed,
    mut signature_oracle: F,
) -> Result<PreparedSemanticAttemptResult, AutomaticFindingPreparationError>
where
    F: FnMut(
        &FindingReproductionArtifact,
    ) -> Result<
        (
            CrucibleFindingReplayEvidence,
            Vec<crate::CrucibleMeasurementReplayEvidence>,
        ),
        EngineError,
    >,
{
    prepare_automatic_signature_preserving_finding_with_outcomes(
        result,
        signature,
        finding,
        exact_pins,
        seed,
        |candidate| {
            let (evidence, measurement_replay_evidence) = signature_oracle(candidate)?;
            Ok(AutomaticFindingReplayOutcome::observed(
                evidence,
                measurement_replay_evidence,
            ))
        },
    )
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
// crucible-lint: allow rust-allow -- the finding basis remains explicit at the execution boundary.
#[allow(clippy::too_many_arguments)]
pub fn prepare_automatic_signature_preserving_finding_with_outcomes<F>(
    result: PreparedSemanticAttemptResult,
    signature: FindingSignature,
    finding: &FindingReproductionArtifact,
    exact_pins: FindingExactPins,
    seed: crucible::Seed,
    mut signature_oracle: F,
) -> Result<PreparedSemanticAttemptResult, AutomaticFindingPreparationError>
where
    F: FnMut(&FindingReproductionArtifact) -> Result<AutomaticFindingReplayOutcome, EngineError>,
{
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
                        let replay = match triage_evidence {
                            Some(triage_evidence) => {
                                AutomaticFindingReplayOutcome::observed_with_triage(
                                    *evidence,
                                    Vec::new(),
                                    *triage_evidence,
                                )
                            }
                            None => AutomaticFindingReplayOutcome::observed(
                                *evidence,
                                Vec::new(),
                            ),
                        };
                        Ok(match production_replay {
                            Some(production_replay) => {
                                replay.with_production_replay(production_replay)
                            }
                            None => replay,
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

    let prepared = prepare_signature_preserving_minimized_finding_candidate(
        signature,
        observation,
        finding,
        exact_pins,
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
    pub fn import_configuration_with_selections(
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
            scenario_record.scenario(),
            scenario_record.id()?,
            configuration_record.configuration(),
            stored_configuration,
            fingerprint,
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
            .minimize(MinimizationConfig::new(run.seed), failure_oracle)
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

        let policy = encode_crucible_minimization_policy(verified.seed);
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
            CRUCIBLE_MINIMIZATION_POLICY_SCHEMA_V2,
            policy,
            attempts,
            CampaignHash::from_bytes(minimized.replay.state.bytes),
        )?;
        let fingerprint = CampaignHash::from_bytes(minimized.finding_fingerprint.bytes);
        let artifact = ReproductionArtifact::new_minimized(
            scenario_record.scenario(),
            scenario_record.id()?,
            configuration_record.configuration(),
            stored_configuration,
            fingerprint,
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

    /// Minimizes and publishes one signature-preserving finding candidate.
    ///
    /// The failure oracle returns the complete typed evidence and stable
    /// campaign signature for a replayed candidate. Candidates preserve the
    /// finding only when that stable replay projection equals `signature`;
    /// matching the payload fingerprint alone is insufficient. Both complete
    /// passes finish before the first write. Their unique evidence records and
    /// raw signatures are retained in the published bundle closure. This
    /// executor-side operation does not advance a campaign ref.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleArtifactError`] when the original fingerprint differs
    /// from the stable signature, replay or deterministic minimization fails,
    /// immutable artifact verification, signature-evidence construction, or
    /// bundle publication fails.
    pub fn publish_signature_preserving_minimized_finding_candidate<F>(
        &self,
        signature: FindingSignature,
        observation: ObservationId,
        finding: &FindingReproductionArtifact,
        exact_pins: FindingExactPins,
        seed: crucible::Seed,
        mut signature_oracle: F,
    ) -> Result<FindingCandidateBundleId, CrucibleArtifactError>
    where
        F: FnMut(
            &FindingReproductionArtifact,
        ) -> Result<CrucibleFindingReplayEvidence, EngineError>,
    {
        let mut transcript = CrucibleFindingReplayTranscript::new();
        minimize_signature_preserving_finding(
            finding,
            &signature,
            seed,
            FindingReplayPass::Minimization,
            &mut transcript,
            &mut signature_oracle,
        )?;
        minimize_signature_preserving_finding(
            finding,
            &signature,
            seed,
            FindingReplayPass::Verification,
            &mut transcript,
            &mut signature_oracle,
        )?;
        let prepared = prepare_signature_preserving_minimized_finding_candidate(
            signature,
            observation,
            finding,
            exact_pins,
            seed,
            transcript,
        )?;
        prepared.publish(self)
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

fn prepare_original_reproduction(
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
        scenario_record.scenario(),
        scenario_record.id()?,
        configuration_record.configuration(),
        configuration_record.id()?,
        CampaignHash::from_bytes(finding.finding_fingerprint.bytes),
        CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3,
        finding.artifact.to_compact_binary(),
    )?;
    Ok((scenario_record, configuration_record, reproduction))
}

fn prepare_minimized_reproduction(
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
        CRUCIBLE_MINIMIZATION_POLICY_SCHEMA_V2,
        encode_crucible_minimization_policy(run.seed),
        attempts,
        CampaignHash::from_bytes(minimized.replay.state.bytes),
    )?;
    let reproduction = ReproductionArtifact::new_minimized(
        scenario_record.scenario(),
        scenario_record.id()?,
        configuration_record.configuration(),
        configuration_record.id()?,
        CampaignHash::from_bytes(minimized.finding_fingerprint.bytes),
        CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3,
        minimized.artifact.to_compact_binary(),
        minimization,
    )?;
    Ok((configuration_record, reproduction))
}

fn replay_recorded_signature_pass(
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
        .minimize(MinimizationConfig::new(seed), |candidate| {
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
        })
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

fn validate_replay_incompatibility_passes(
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
enum FindingReplayPass {
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

fn minimize_signature_preserving_finding<F>(
    finding: &FindingReproductionArtifact,
    signature: &FindingSignature,
    seed: crucible::Seed,
    pass: FindingReplayPass,
    transcript: &mut CrucibleFindingReplayTranscript,
    mut signature_oracle: F,
) -> Result<MinimizationRun, CrucibleArtifactError>
where
    F: FnMut(&FindingReproductionArtifact) -> Result<CrucibleFindingReplayEvidence, EngineError>,
{
    minimize_signature_preserving_finding_with_outcomes(
        finding,
        signature,
        seed,
        pass,
        transcript,
        |candidate| {
            signature_oracle(candidate)
                .map(|evidence| AutomaticFindingReplayOutcome::observed(evidence, Vec::new()))
        },
    )
}

fn minimize_signature_preserving_finding_with_outcomes<F>(
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
        .minimize(MinimizationConfig::new(seed), |candidate| {
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
        })
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

fn encode_crucible_minimization_policy(seed: crucible::Seed) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CRUCIBLE_MINIMIZATION_POLICY_MAGIC_V2.len() + 44);
    bytes.extend_from_slice(CRUCIBLE_MINIMIZATION_POLICY_MAGIC_V2);
    bytes.extend_from_slice(&seed.bytes());
    bytes.extend_from_slice(&CRUCIBLE_MINIMIZATION_CANDIDATES.to_be_bytes());
    bytes.extend_from_slice(&CRUCIBLE_MINIMIZATION_CANDIDATE_WORK_BYTES.to_be_bytes());
    bytes
}

/// Required replay stage in signature-preserving finding preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingRequiredReproductionStage {
    /// The original reproduction failed at the start of the minimization pass.
    MinimizationOriginal,
    /// The original reproduction failed at the start of the independent verification pass.
    VerificationOriginal,
    /// The independently selected minimized reproduction disagreed with the first pass.
    SelectedVerification,
}

impl std::fmt::Display for FindingRequiredReproductionStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::MinimizationOriginal => "minimization-original replay",
            Self::VerificationOriginal => "verification-original replay",
            Self::SelectedVerification => "selected-reproduction verification",
        };
        formatter.write_str(name)
    }
}

/// Failure to translate a campaign artifact into the Crucible execution model.
#[derive(Debug, thiserror::Error)]
pub enum CrucibleArtifactError {
    /// A required original or selected replay did not preserve the finding signature.
    #[error("required finding reproduction failed during {stage}")]
    FindingRequiredReproductionMismatch {
        /// Exact preparation stage that failed to reproduce the target signature.
        stage: FindingRequiredReproductionStage,
    },
    /// Production replay content could not be authenticated or bound.
    #[error(transparent)]
    FindingProductionReplay(#[from] crate::FindingProductionReplayCaptureError),
    /// The artifact names a payload schema this adapter cannot execute.
    #[error("unsupported {artifact} payload schema {actual}; expected {expected}")]
    UnsupportedPayloadSchema {
        /// Stable artifact class used for diagnostics.
        artifact: &'static str,
        /// Unsupported schema supplied by the artifact.
        actual: u32,
        /// Exact schema implemented by this adapter.
        expected: u32,
    },
    /// Configuration payload bytes do not carry the required Schedule version.
    #[error("Crucible configuration payload requires Schedule compact binary V2")]
    UnsupportedScheduleEncoding,
    /// Compact Crucible bytes were malformed or semantically invalid.
    #[error("invalid Crucible {artifact} payload: {source}")]
    InvalidPayload {
        /// Stable artifact class used for diagnostics.
        artifact: &'static str,
        /// Crucible compact-codec validation failure.
        #[source]
        source: Box<crucible::EngineError>,
    },
    /// The decoded semantic identity differs from the campaign binding.
    #[error("Crucible {artifact} payload semantic identity does not match its campaign artifact")]
    SemanticIdentityMismatch {
        /// Stable artifact class used for diagnostics.
        artifact: &'static str,
    },
    /// A configuration names a different exact scenario artifact.
    #[error("Crucible configuration artifact names a different exact scenario artifact")]
    ScenarioArtifactMismatch,
    /// A structurally valid schedule contains selections that were not resolved.
    #[error("Crucible configuration contains an unresolved campaign selection decision")]
    UnresolvedSelectionDecision,
    /// Authenticated campaign selection closure could not be resolved.
    #[error(transparent)]
    SelectionRepository(#[from] CampaignRepositoryError),
    /// Immutable artifact publication failed after semantic verification.
    #[error(transparent)]
    RepositoryPublication(CampaignRepositoryError),
    /// A model-sampled value has no pure model verifier in this executor.
    #[error("Crucible configuration contains a model selection without a registered verifier")]
    UnverifiedModelSelection,
    /// A configuration exceeds the bounded selection-resolution contract.
    #[error("Crucible configuration exceeds the campaign selection resolution limit")]
    SelectionResolutionLimit,
    /// Selected-continuation decoding exceeds its admitted logical memory budget.
    #[error("Crucible selected-continuation decoding exceeds `{resource}`")]
    ResourceLimit {
        /// Stable resource category that refused the decoded representation.
        resource: &'static str,
    },
    /// A derived schedule prefix was inconsistent with its source schedule.
    #[error(transparent)]
    SelectionPrefix(#[from] crucible::ScheduleError),
    /// Campaign envelope construction rejected a newly encoded artifact.
    #[error(transparent)]
    Campaign(#[from] CampaignCodecError),
    /// A promoted signal-fault selection did not match its standardized records.
    #[error(transparent)]
    SignalFaultSelection(#[from] crucible::SignalFaultSelectableError),
    /// A standardized signal-fault selection was not followed by its exact prefix.
    #[error("Crucible configuration signal-fault branch differs from its authenticated prefix")]
    SignalFaultScheduleMismatch,
    /// A raw signal-fault override was not certified by a standardized selection.
    #[error("Crucible configuration contains an unbound signal-fault override")]
    UnboundSignalFaultOverride,
}

/// Encodes one validated Crucible scenario form as a campaign artifact.
///
/// # Errors
///
/// Returns [`CrucibleArtifactError`] when the bounded campaign artifact cannot
/// be constructed.
pub fn encode_crucible_scenario_artifact(
    scenario: &ScenarioDefForm,
) -> Result<ScenarioArtifact, CrucibleArtifactError> {
    ScenarioArtifact::new(
        campaign_scenario_id(scenario.id()),
        CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V3,
        scenario.to_compact_binary(),
    )
    .map_err(Into::into)
}

/// Strictly decodes and authenticates one Crucible scenario artifact.
///
/// # Errors
///
/// Returns [`CrucibleArtifactError`] for an unsupported payload schema,
/// malformed compact bytes, or a semantic identity mismatch.
pub fn decode_crucible_scenario_artifact(
    artifact: &ScenarioArtifact,
) -> Result<ScenarioDefForm, CrucibleArtifactError> {
    match artifact.payload_schema() {
        CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V1
            if artifact
                .payload()
                .starts_with(b"crucible.scenario-def-form.v5\0") => {}
        CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V2
            if artifact
                .payload()
                .starts_with(b"crucible.scenario-def-form.v6\0") => {}
        CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V3
            if artifact
                .payload()
                .starts_with(b"crucible.scenario-def-form.v7\0") => {}
        actual => {
            return Err(CrucibleArtifactError::UnsupportedPayloadSchema {
                artifact: "scenario",
                actual,
                expected: CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V3,
            });
        }
    }
    let scenario = ScenarioDefForm::from_compact_binary(artifact.payload()).map_err(|source| {
        CrucibleArtifactError::InvalidPayload {
            artifact: "scenario",
            source: Box::new(source),
        }
    })?;
    if campaign_scenario_id(scenario.id()) != artifact.scenario() {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "scenario",
        });
    }
    Ok(scenario)
}

/// Encodes one Crucible schedule as an exact campaign configuration artifact.
///
/// The supplied scenario artifact is decoded again so callers cannot pair a
/// valid schedule with unverified or drifted scenario bytes.
///
/// # Errors
///
/// Returns [`CrucibleArtifactError`] when scenario authentication or bounded
/// campaign artifact construction fails.
pub fn encode_crucible_configuration_artifact(
    scenario_artifact: &ScenarioArtifact,
    schedule: &Schedule,
) -> Result<ConfigurationArtifact, CrucibleArtifactError> {
    let scenario = decode_crucible_scenario_artifact(scenario_artifact)?;
    let configuration = Configuration {
        def: scenario.scenario_def(),
        schedule: schedule.clone(),
    };
    ConfigurationArtifact::new(
        scenario_artifact.scenario(),
        scenario_artifact.id()?,
        campaign_configuration_id(configuration.id()),
        CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V2,
        schedule.to_compact_binary(),
    )
    .map_err(Into::into)
}

/// Strictly decodes and authenticates one Crucible configuration artifact.
///
/// # Errors
///
/// Returns [`CrucibleArtifactError`] for unsupported or malformed payloads,
/// scenario-reference drift, or a re-derived semantic identity mismatch.
pub fn decode_crucible_configuration_artifact(
    scenario: &ScenarioDefForm,
    scenario_artifact: &ScenarioArtifact,
    artifact: &ConfigurationArtifact,
) -> Result<Configuration, CrucibleArtifactError> {
    let configuration =
        decode_crucible_configuration_artifact_structural(scenario, scenario_artifact, artifact)?;
    if configuration
        .schedule
        .decisions()
        .iter()
        .any(|decision| matches!(decision, Decision::Selection(_)))
    {
        return Err(CrucibleArtifactError::UnresolvedSelectionDecision);
    }
    Ok(configuration)
}

/// Strictly decodes a configuration and resolves every embedded selection.
///
/// Each selection must equal its authenticated repository record. Branch
/// provenance is recomputed from the exact schedule prefix and opportunity.
/// Model-sampled selections are accepted only when the authenticated records
/// reconstruct Crucible's standardized app-random uniform model; every other
/// model remains fail-closed until its pure verifier is implemented.
///
/// # Errors
///
/// Returns [`CrucibleArtifactError`] for the structural failures documented by
/// [`decode_crucible_configuration_artifact`], missing or inconsistent
/// selection records, invalid prefix provenance, or unverified model sampling.
pub fn decode_crucible_configuration_artifact_with_selections(
    scenario: &ScenarioDefForm,
    scenario_artifact: &ScenarioArtifact,
    artifact: &ConfigurationArtifact,
    store: &CampaignExecutorStore,
) -> Result<Configuration, CrucibleArtifactError> {
    decode_crucible_configuration_artifact_with_resolver(
        scenario,
        scenario_artifact,
        artifact,
        store,
    )
    .map(|(configuration, _)| configuration)
}

/// Decodes a configuration through the full repository selection verifier.
pub(crate) fn decode_crucible_configuration_artifact_from_repository(
    scenario: &ScenarioDefForm,
    scenario_artifact: &ScenarioArtifact,
    artifact: &ConfigurationArtifact,
    repository: &CampaignRepository,
) -> Result<Configuration, CrucibleArtifactError> {
    decode_crucible_configuration_artifact_with_resolver(
        scenario,
        scenario_artifact,
        artifact,
        repository,
    )
    .map(|(configuration, _)| configuration)
}

/// Strictly decodes a configuration and retains authenticated signal-fault replay.
///
/// This performs the same complete selection validation as
/// [`decode_crucible_configuration_artifact_with_selections`]. In addition, it
/// reconstructs every standardized promoted signal-fault branch, requires its
/// selection and optional override to occur at the exact target prefix, and
/// returns the bounded ordered plan consumed by the production lifecycle.
///
/// # Errors
///
/// Returns [`CrucibleArtifactError`] for malformed artifacts, unresolved or
/// inconsistent selection records, uncovered signal-fault overrides, or an
/// invalid replay plan.
pub fn decode_crucible_configuration_artifact_with_signal_fault_replay(
    scenario: &ScenarioDefForm,
    scenario_artifact: &ScenarioArtifact,
    artifact: &ConfigurationArtifact,
    store: &CampaignExecutorStore,
) -> Result<(Configuration, SignalFaultCampaignReplayPlan), CrucibleArtifactError> {
    decode_crucible_configuration_artifact_with_resolver(
        scenario,
        scenario_artifact,
        artifact,
        store,
    )
}

/// Decodes an unpublished observation child for one private finding replay.
///
/// The current observation may own selections that have not entered the
/// repository. This verifier resolves those values from the already checked
/// candidate and resolves inherited selections through the executor store. It
/// returns the exact resolved selection closure alongside the signal-fault plan
/// so private replay evidence can retain every starting decision.
pub(crate) fn decode_crucible_configuration_artifact_with_owned_candidate(
    scenario: &ScenarioDefForm,
    scenario_artifact: &ScenarioArtifact,
    artifact: &ConfigurationArtifact,
    store: &CampaignExecutorStore,
    owned: &crucible_campaign::ObservationCandidate,
) -> Result<
    (
        Configuration,
        SignalFaultCampaignReplayPlan,
        Vec<ResolvedSelection>,
    ),
    CrucibleArtifactError,
> {
    let configuration =
        decode_crucible_configuration_artifact_structural(scenario, scenario_artifact, artifact)?;
    let mut retained = Vec::new();
    let replay = resolve_selection_decisions(&configuration, artifact, None, |ids, _| {
        retained = store
            .resolve_selections_with_owned_candidate(ids, owned)
            .map_err(CrucibleArtifactError::SelectionRepository)?;
        Ok(retained.clone())
    })?;
    Ok((configuration, replay, retained))
}

fn decode_crucible_configuration_artifact_with_resolver(
    scenario: &ScenarioDefForm,
    scenario_artifact: &ScenarioArtifact,
    artifact: &ConfigurationArtifact,
    resolver: &impl ConfigurationSelectionResolver,
) -> Result<(Configuration, SignalFaultCampaignReplayPlan), CrucibleArtifactError> {
    let configuration =
        decode_crucible_configuration_artifact_structural(scenario, scenario_artifact, artifact)?;
    let replay = resolve_selection_decisions(&configuration, artifact, None, |ids, _| {
        resolver
            .resolve_configuration_selections(ids)
            .map_err(Into::into)
    })?;
    Ok((configuration, replay))
}

pub(crate) fn decode_crucible_configuration_artifact_with_signal_fault_replay_guarded(
    scenario: &ScenarioDefForm,
    scenario_artifact: &ScenarioArtifact,
    artifact: &ConfigurationArtifact,
    store: &CampaignExecutorStore,
    retained_memory_guard: Option<&mut RetainedConfigurationMemoryGuard<'_>>,
) -> Result<(Configuration, SignalFaultCampaignReplayPlan), CrucibleArtifactError> {
    let configuration =
        decode_crucible_configuration_artifact_structural(scenario, scenario_artifact, artifact)?;
    let replay = resolve_selection_decisions(
        &configuration,
        artifact,
        retained_memory_guard,
        |ids, selection_resolution_limit| match selection_resolution_limit {
            Some(maximum_canonical_bytes) => store
                .resolve_selections_with_canonical_byte_limit(ids, maximum_canonical_bytes)
                .map_err(|error| match error {
                    CampaignRepositoryError::SelectionResolutionBudgetExceeded { .. } => {
                        CrucibleArtifactError::ResourceLimit {
                            resource: "selected-origin-decoded-resident-bytes",
                        }
                    }
                    error => CrucibleArtifactError::SelectionRepository(error),
                }),
            None => store.resolve_selections(ids).map_err(Into::into),
        },
    )?;
    Ok((configuration, replay))
}

trait ConfigurationSelectionResolver {
    fn resolve_configuration_selections(
        &self,
        ids: &[SelectionId],
    ) -> Result<Vec<ResolvedSelection>, CampaignRepositoryError>;
}

impl ConfigurationSelectionResolver for CampaignExecutorStore {
    fn resolve_configuration_selections(
        &self,
        ids: &[SelectionId],
    ) -> Result<Vec<ResolvedSelection>, CampaignRepositoryError> {
        self.resolve_selections(ids)
    }
}

impl ConfigurationSelectionResolver for CampaignRepository {
    fn resolve_configuration_selections(
        &self,
        ids: &[SelectionId],
    ) -> Result<Vec<ResolvedSelection>, CampaignRepositoryError> {
        self.resolve_distinct_selections(ids)
    }
}

fn decode_crucible_configuration_artifact_structural(
    scenario: &ScenarioDefForm,
    scenario_artifact: &ScenarioArtifact,
    artifact: &ConfigurationArtifact,
) -> Result<Configuration, CrucibleArtifactError> {
    let authenticated_scenario = decode_crucible_scenario_artifact(scenario_artifact)?;
    if &authenticated_scenario != scenario || artifact.scenario() != scenario_artifact.scenario() {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "configuration scenario",
        });
    }
    if artifact.scenario_artifact() != scenario_artifact.id()? {
        return Err(CrucibleArtifactError::ScenarioArtifactMismatch);
    }
    require_schema(
        "configuration",
        artifact.payload_schema(),
        CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V2,
    )?;
    if !artifact.payload().starts_with(CRUCIBLE_SCHEDULE_V2_MAGIC) {
        return Err(CrucibleArtifactError::UnsupportedScheduleEncoding);
    }
    let schedule = Schedule::from_compact_binary(artifact.payload()).map_err(|source| {
        CrucibleArtifactError::InvalidPayload {
            artifact: "configuration",
            source: Box::new(source),
        }
    })?;
    let configuration = Configuration {
        def: scenario.scenario_def(),
        schedule,
    };
    if campaign_configuration_id(configuration.id()) != artifact.configuration() {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "configuration",
        });
    }
    Ok(configuration)
}

fn resolve_selection_decisions<R>(
    configuration: &Configuration,
    artifact: &ConfigurationArtifact,
    retained_memory_guard: Option<&mut RetainedConfigurationMemoryGuard<'_>>,
    resolve: R,
) -> Result<SignalFaultCampaignReplayPlan, CrucibleArtifactError>
where
    R: FnOnce(
        &[SelectionId],
        Option<usize>,
    ) -> Result<Vec<ResolvedSelection>, CrucibleArtifactError>,
{
    let mut selections = Vec::new();
    let mut campaign_branch_count = 0usize;
    for (index, decision) in configuration.schedule.decisions().iter().enumerate() {
        let Decision::Selection(decision) = decision else {
            continue;
        };
        let selection = decision.selection()?;
        selections.push((index, selection));
        if selections.len() > MAX_CONFIGURATION_SELECTION_DECISIONS {
            return Err(CrucibleArtifactError::SelectionResolutionLimit);
        }
        if matches!(
            selections.last().map(|(_, selection)| selection.origin()),
            Some(SelectionOrigin::CampaignBranch { .. })
        ) {
            campaign_branch_count = campaign_branch_count
                .checked_add(1)
                .ok_or(CrucibleArtifactError::SelectionResolutionLimit)?;
        }
    }
    let branch_prefix_bytes = artifact
        .payload()
        .len()
        .checked_mul(campaign_branch_count)
        .ok_or(CrucibleArtifactError::SelectionResolutionLimit)?;
    if branch_prefix_bytes > MAX_CONFIGURATION_BRANCH_PREFIX_BYTES {
        return Err(CrucibleArtifactError::SelectionResolutionLimit);
    }
    let selection_resolution_limit = retained_memory_guard
        .map(|guard| guard(configuration, campaign_branch_count))
        .transpose()?;
    if selections.is_empty() {
        if configuration.schedule.decisions().iter().any(|decision| {
            matches!(decision, Decision::Override(override_decision) if override_decision.point.key.starts_with("signal-fault/"))
        }) {
            return Err(CrucibleArtifactError::UnboundSignalFaultOverride);
        }
        return Ok(SignalFaultCampaignReplayPlan::empty(configuration.clone()));
    }

    let selection_ids = selections
        .iter()
        .map(|(_, selection)| selection.id())
        .collect::<Result<Vec<_>, _>>()?;
    let resolved = resolve(&selection_ids, selection_resolution_limit)?;
    let mut signal_fault_branches = Vec::new();
    let mut covered_signal_fault_overrides = BTreeSet::new();
    for ((index, selection), resolved) in selections.into_iter().zip(resolved) {
        if resolved.selection() != &selection
            || resolved.opportunity().scenario() != artifact.scenario()
        {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "configuration selection",
            });
        }
        match selection.origin() {
            SelectionOrigin::Default | SelectionOrigin::LockedReplay => {
                selection.validate_replay(resolved.opportunity(), resolved.domain())?;
            }
            SelectionOrigin::CampaignBranch { .. } => {
                let parent = Configuration {
                    def: configuration.def.clone(),
                    schedule: configuration.schedule.prefix(index)?,
                };
                selection.validate_branch_replay(
                    resolved.opportunity(),
                    resolved.domain(),
                    resolved
                        .opportunity()
                        .branch_point_id(campaign_configuration_id(parent.id())),
                )?;
                if matches!(
                    resolved.opportunity().source(),
                    crucible_campaign::ChoiceSource::Environment { adapter, .. }
                        if adapter == crucible::SIGNAL_FAULT_CAMPAIGN_ADAPTER
                ) {
                    let selectable = SignalFaultSelectable::from_records(
                        &parent,
                        resolved.declaration(),
                        resolved.opportunity(),
                        resolved.domain(),
                    )?;
                    let branch = selectable.resolve_branch(&selection)?;
                    let end = index
                        .checked_add(branch.decisions().len())
                        .ok_or(CrucibleArtifactError::SelectionResolutionLimit)?;
                    if end > configuration.schedule.len()
                        || configuration.schedule.decisions()[index..end] != *branch.decisions()
                    {
                        return Err(CrucibleArtifactError::SignalFaultScheduleMismatch);
                    }
                    if branch.decisions().len() == 2 {
                        covered_signal_fault_overrides.insert(index + 1);
                    }
                    signal_fault_branches.push(branch);
                }
            }
            SelectionOrigin::ModelSample(_) => {
                crucible::validate_app_random_model_selection(
                    &selection,
                    resolved.declaration(),
                    resolved.opportunity(),
                    resolved.domain(),
                )
                .map_err(|_| CrucibleArtifactError::UnverifiedModelSelection)?;
            }
        }
    }
    if configuration
        .schedule
        .decisions()
        .iter()
        .enumerate()
        .any(|(index, decision)| {
            matches!(decision, Decision::Override(override_decision) if override_decision.point.key.starts_with("signal-fault/"))
                && !covered_signal_fault_overrides.contains(&index)
        })
    {
        return Err(CrucibleArtifactError::UnboundSignalFaultOverride);
    }
    SignalFaultCampaignReplayPlan::new(configuration.clone(), signal_fault_branches)
        .map_err(Into::into)
}

fn require_schema(
    artifact: &'static str,
    actual: u32,
    expected: u32,
) -> Result<(), CrucibleArtifactError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CrucibleArtifactError::UnsupportedPayloadSchema {
            artifact,
            actual,
            expected,
        })
    }
}

fn campaign_scenario_id(id: crucible::ContentHash) -> ScenarioDefId {
    ScenarioDefId::from_hash(CampaignHash::from_bytes(id.bytes))
}

fn campaign_configuration_id(id: crucible::ContentHash) -> ConfigurationId {
    ConfigurationId::from_hash(CampaignHash::from_bytes(id.bytes))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#[allow(clippy::expect_used)]
mod tests;
