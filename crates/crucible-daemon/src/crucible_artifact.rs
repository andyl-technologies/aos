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

use std::collections::BTreeSet;
use std::sync::Arc;

mod finding_replay;
mod prepared_result;

pub use finding_replay::{CrucibleFindingReplayEvidence, CrucibleFindingReplayTranscript};
use finding_replay::{
    PreparedFindingReplayRecords, RecordedFindingReplay, validate_recorded_replay_configuration,
};
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
    FindingMinimizationAttempt, FindingMinimizationEvidence, FindingReplaySignature,
    FindingSignature, FindingSignatureMinimizationEvidence, MeasurementSet, ObservationId,
    PropertyVerdictSet, ReproductionArtifact, ReproductionArtifactId, ResolvedSelection,
    ScenarioArtifact, ScenarioArtifactId, ScenarioDefId, SelectableDeclaration, Selection,
    SelectionId, SelectionOrigin,
};

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
    bundle: FindingCandidateBundle,
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
        let bundle = store.publish_executor_finding_candidate(&self.bundle)?;
        if bundle != self.id()? {
            return Err(CampaignRepositoryError::Integrity {
                reason: "prepared-finding-bundle-publication-mismatch",
            });
        }
        Ok(bundle)
    }
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
    } = transcript;
    let minimization =
        replay_recorded_signature_pass(finding, &signature, seed, &minimization_pass)?;
    let verified = replay_recorded_signature_pass(finding, &signature, seed, &verification_pass)?;
    if verified != minimization {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding minimization replay passes",
        });
    }

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
        .map(|replay| replay.signature.clone())
        .collect();
    let verification_signatures = verification_pass
        .iter()
        .map(|replay| replay.signature.clone())
        .collect();
    let signature_minimization = FindingSignatureMinimizationEvidence::new(
        &signature,
        minimization_evidence,
        minimization_signatures,
        verification_signatures,
    )?;
    let replay_records = records.finish();
    let bundle = FindingCandidateBundle::new(
        observation,
        signature,
        original_id,
        minimized.id()?,
        signature_minimization,
        exact_pins,
    )?;

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
        bundle,
    })
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
        .and_then(|replay| replay.signature.as_ref())
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
                .signature
                .as_ref()
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

#[derive(Clone, Copy)]
enum FindingReplayPass {
    Minimization,
    Verification,
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
    let target_fingerprint = finding.finding_fingerprint;
    if CampaignHash::from_bytes(target_fingerprint.bytes) != signature.fingerprint() {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding signature",
        });
    }

    let target_signature = FindingReplaySignature::from_observed(signature);
    let mut transcript_error = None;
    let run = finding
        .minimize(MinimizationConfig::new(seed), |candidate| {
            let observed = signature_oracle(candidate)?;
            let preserves_signature = observed
                .signature()
                .map(FindingReplaySignature::from_observed)
                .as_ref()
                == Some(&target_signature);
            let result = match pass {
                FindingReplayPass::Minimization => {
                    transcript.record_minimization(candidate, observed)
                }
                FindingReplayPass::Verification => {
                    transcript.record_verification(candidate, observed)
                }
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
            transcript_error.unwrap_or(CrucibleArtifactError::InvalidPayload {
                artifact: "signature-preserving finding minimization",
                source: Box::new(source),
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

/// Failure to translate a campaign artifact into the Crucible execution model.
#[derive(Debug, thiserror::Error)]
pub enum CrucibleArtifactError {
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
mod tests {
    use std::collections::BTreeMap;

    use std::collections::BTreeSet;
    use std::sync::Arc;

    use crucible::model::{MeasurementDefinitions, MeasurementTerminalState};
    use crucible::{
        ContentHash, Decision, DeliveryOrderDecision, FindingDiscoveryPath, SelectionDecision,
        VirtualTime,
    };
    use crucible_campaign::{
        AlternativeId, AssignmentId, AttemptResourceLimits, BooleanDomain, BudgetGrant,
        CampaignCommandId, CampaignControlAction, CampaignLineage, CampaignMode, CampaignName,
        CampaignPolicy, CampaignRepository, CampaignSeed, ChoiceClassContext, ChoiceCoordinate,
        ChoiceDiscovery, ChoiceDomain, ChoiceOpportunity, ChoiceSource, ChoiceValue,
        ControlRequest, CoverageProjection, DaemonEpoch, DiscreteAlternative, DiscreteDomain,
        ExecutionRetentionIntent, ExecutorService, ExplorerPolicy, FairnessPolicy,
        FindingCandidateBundleId, FindingKind, FindingTarget, MeasurementSet, Observation,
        ObservationCandidate, ProgressiveWideningPolicy, PropertyVerdictSet, PuctPolicy,
        RetentionPolicy, SelectableDeclaration, Selection, SelectionOrigin, StopCondition,
        StopOutcome, SubmitAttemptDisposition, SubmitAttemptRequest,
    };
    use crucible_cas::content_store::{
        ContentId, DirectoryBlobBackend, MemoryBlobBackend, MemoryRefBackend, ObjectKind,
    };

    use super::*;
    use crate::{
        AllowAllAttemptAdmission, AssignmentLedger, AttemptExecutionKey, AttemptExecutionProduct,
        AttemptResultStageOutcome, AttemptRuntimeState, AttemptWorkResult,
        AttemptWorkerReconcileOutcome, CompletedFindingCandidate, CompletionOutcome,
        CrucibleMeasurementPublication, CrucibleMeasurementReplayEvidence, ExactCheckpointStore,
        ExecutorCapacity, LocalExecutorError, LocalExecutorSupervisor,
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES, MemoryAssignmentLedger,
        PreparedAttemptWorkResult, evaluate_crucible_measurement_publication,
        incorporate_and_acknowledge_finding_candidate, prepare_attempt_result,
        publish_prepared_attempt_result, reconcile_published_attempt_result,
        stage_prepared_attempt_result,
    };

    fn empty_measurement_publication(
        scenario: ScenarioDefId,
        configuration: ConfigurationId,
    ) -> CrucibleMeasurementPublication {
        evaluate_crucible_measurement_publication(
            scenario,
            configuration,
            &MeasurementDefinitions::empty(),
            Vec::new(),
            MeasurementTerminalState {
                scenario_ready_at: None,
                at: VirtualTime { ticks: 0 },
                node_icounts: BTreeMap::new(),
                scheduler_quiescent: true,
            },
            MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
        )
        .expect("empty measurement publication")
    }

    fn observation_with_measurements(
        candidate: &ObservationCandidate,
        measurements: MeasurementSet,
    ) -> ObservationCandidate {
        let retained = candidate.observation();
        assert!(retained.produced_selections().is_empty());
        let observation = Observation::new(
            retained.attempt(),
            retained.child(),
            retained.child_content(),
            retained.path(),
            retained.stop().clone(),
            measurements.id().expect("replacement measurement ID"),
            retained.properties(),
            retained.coverage(),
            retained.discovered_choices().clone(),
        )
        .expect("observation with replacement measurements");
        ObservationCandidate::new(
            candidate.child().clone(),
            measurements,
            candidate.properties().clone(),
            candidate.coverage().clone(),
            candidate.discovered_choices().to_vec(),
            observation,
        )
        .expect("candidate with replacement measurements")
    }

    fn measurement_with_evidence(
        template: &MeasurementSet,
        evidence: &CrucibleMeasurementReplayEvidence,
        definitions: CampaignHash,
    ) -> MeasurementSet {
        let retained = template.evaluation().expect("measurement evaluation");
        MeasurementSet::from_evaluation(
            definitions,
            retained.payload_schema(),
            retained.evaluation(),
            retained.payload().to_vec(),
            BTreeSet::from([evidence.id().expect("measurement evidence ID")]),
        )
        .expect("measurement with replacement evidence")
    }

    fn selection_decision(scenario: ScenarioDefId) -> Decision {
        let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("Boolean domain"));
        let declaration = SelectableDeclaration::new(
            "product.test.daemon-selection",
            ChoiceSource::Scheduler {
                producer: String::from("daemon-test"),
            },
            domain.clone(),
            ChoiceValue::Boolean(false),
            ChoiceClassContext::new(BTreeSet::new()).expect("class context"),
            BTreeSet::new(),
            true,
        )
        .expect("selectable declaration");
        let opportunity = ChoiceOpportunity::new(
            scenario,
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::derive("test", b"daemon-scheduler"),
                producer: CampaignHash::derive("test", b"daemon-producer"),
            },
            "daemon-selection",
            None,
        )
        .expect("choice opportunity");
        let selection = Selection::new(
            &opportunity,
            &domain,
            ChoiceValue::Boolean(false),
            SelectionOrigin::Default,
        )
        .expect("default selection");
        Decision::Selection(SelectionDecision::new(&selection))
    }

    fn signal_fault_selectable(
        parent: &Configuration,
        label: &[u8],
        frontier: u64,
    ) -> SignalFaultSelectable {
        let choice = crucible::model::BindingSearchChoice {
            id: crucible::model::SearchChoiceId::from_content_hash(ContentHash::from_bytes(label)),
            candidates_digest: ContentHash::from_canonical_material(
                "crucible.test.artifact-signal-candidates",
                &label
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            ),
            candidate_count: 2,
            selected_index: None,
            overridden: false,
        };
        SignalFaultSelectable::from_frontier(&crucible::SearchRuntimeFrontier {
            configuration: parent.clone(),
            at: VirtualTime { ticks: frontier },
            choices: crucible::SearchFrontierChoices::from_decisions(
                choice
                    .override_decisions(parent.id())
                    .into_iter()
                    .map(Decision::Override),
            ),
        })
        .expect("signal-fault selectable fixture")
    }

    fn publish_signal_selection(
        repository: &CampaignRepository,
        selectable: &SignalFaultSelectable,
        selection: &Selection,
    ) {
        repository
            .publish_choice_domain(selectable.domain())
            .expect("publish signal-fault domain");
        repository
            .publish_selectable(selectable.declaration())
            .expect("publish signal-fault declaration");
        repository
            .publish_choice_opportunity(selectable.opportunity())
            .expect("publish signal-fault opportunity");
        repository
            .publish_selection(selection)
            .expect("publish signal-fault selection");
    }

    #[test]
    fn crucible_payloads_round_trip_and_rederive_semantic_ids() {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let schedule = Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: Vec::new(),
        }));
        let scenario_artifact =
            encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
        let configuration_artifact =
            encode_crucible_configuration_artifact(&scenario_artifact, &schedule)
                .expect("configuration artifact");
        assert_eq!(
            configuration_artifact.payload_schema(),
            CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V2
        );

        assert_eq!(
            decode_crucible_scenario_artifact(&scenario_artifact).expect("decoded scenario"),
            scenario
        );
        let configuration = decode_crucible_configuration_artifact(
            &scenario,
            &scenario_artifact,
            &configuration_artifact,
        )
        .expect("decoded configuration");
        assert_eq!(configuration.schedule, schedule);
        assert_eq!(
            configuration_artifact.configuration(),
            campaign_configuration_id(configuration.id())
        );
    }

    #[test]
    fn verifier_backed_store_imports_complete_lineage_artifacts() {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let schedule = Schedule::empty();
        let repository = Arc::new(CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new("crucible-artifact-import", u64::MAX)),
            Arc::new(MemoryRefBackend::new()),
        ));
        let store = CrucibleCampaignArtifactStore::new(Arc::clone(&repository));

        let scenario_id = store.import_scenario(&scenario).expect("import scenario");
        let configuration_id = store
            .import_configuration(&scenario, &schedule)
            .expect("import configuration");
        let stored_scenario = repository
            .load_scenario_artifact(scenario_id)
            .expect("load scenario");
        let stored_configuration = repository
            .load_configuration_artifact(configuration_id)
            .expect("load configuration");

        assert_eq!(
            decode_crucible_scenario_artifact(&stored_scenario).expect("verify stored scenario"),
            scenario
        );
        assert_eq!(
            decode_crucible_configuration_artifact(
                &scenario,
                &stored_scenario,
                &stored_configuration,
            )
            .expect("verify stored configuration")
            .schedule,
            schedule
        );
    }

    #[test]
    fn resolved_app_random_model_sample_is_verified_before_execution() {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let scenario_artifact =
            encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
        let selectable = crucible::AppRandomSelectable::new(
            &scenario.scenario_def(),
            crucible::NodeId {
                name: String::from("node-a"),
            },
            crucible::RngStreamId::for_node("guest/backoff"),
            11,
            16,
        )
        .expect("app-random selectable");
        let selection = selectable
            .sampled_selection(0x1234_5678_9abc_def0)
            .expect("sampled selection");
        let schedule =
            Schedule::empty().appended(Decision::Selection(SelectionDecision::new(&selection)));
        let artifact = encode_crucible_configuration_artifact(&scenario_artifact, &schedule)
            .expect("configuration artifact");

        let repository = Arc::new(CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new(
                "crucible-app-random-selection",
                u64::MAX,
            )),
            Arc::new(MemoryRefBackend::new()),
        ));
        repository
            .publish_choice_domain(selectable.domain())
            .expect("publish app-random domain");
        repository
            .publish_selectable(selectable.declaration())
            .expect("publish app-random declaration");
        repository
            .publish_choice_opportunity(selectable.opportunity())
            .expect("publish app-random opportunity");
        repository
            .publish_selection(&selection)
            .expect("publish app-random selection");
        let store = CampaignExecutorStore::new(Arc::clone(&repository));

        let decoded = decode_crucible_configuration_artifact_with_selections(
            &scenario,
            &scenario_artifact,
            &artifact,
            &store,
        )
        .expect("standardized model sample should pass executor verification");
        assert_eq!(decoded.schedule, schedule);
    }

    #[test]
    fn selected_decode_refuses_a_large_domain_that_exceeds_its_remaining_budget() {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let scenario_artifact =
            encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
        let selected = AlternativeId::from_hash(CampaignHash::derive(
            "crucible.test.large-selected-domain.v1",
            &0_u32.to_be_bytes(),
        ));
        let alternatives = (0_u32..512)
            .map(|index| {
                let id = AlternativeId::from_hash(CampaignHash::derive(
                    "crucible.test.large-selected-domain.v1",
                    &index.to_be_bytes(),
                ));
                let alternative =
                    DiscreteAlternative::new(id, "x".repeat(1024), None).expect("alternative");
                (id, alternative)
            })
            .collect();
        let domain = ChoiceDomain::Discrete(
            DiscreteDomain::new(1, alternatives).expect("large discrete domain"),
        );
        let declaration = SelectableDeclaration::new(
            "product.test.large-selected-domain",
            ChoiceSource::Scheduler {
                producer: String::from("large-domain-test"),
            },
            domain.clone(),
            ChoiceValue::Discrete(selected),
            ChoiceClassContext::new(BTreeSet::new()).expect("class context"),
            BTreeSet::new(),
            true,
        )
        .expect("selectable declaration");
        let opportunity = ChoiceOpportunity::new(
            campaign_scenario_id(scenario.scenario_def().id()),
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::derive("test", b"large-domain-scheduler"),
                producer: CampaignHash::derive("test", b"large-domain-producer"),
            },
            "large-selected-domain",
            None,
        )
        .expect("choice opportunity");
        let selection = Selection::new(
            &opportunity,
            &domain,
            ChoiceValue::Discrete(selected),
            SelectionOrigin::Default,
        )
        .expect("default selection");
        let schedule =
            Schedule::empty().appended(Decision::Selection(SelectionDecision::new(&selection)));
        let artifact = encode_crucible_configuration_artifact(&scenario_artifact, &schedule)
            .expect("configuration artifact");
        let repository = Arc::new(CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new("large-selected-domain", u64::MAX)),
            Arc::new(MemoryRefBackend::new()),
        ));
        repository
            .publish_choice_domain(&domain)
            .expect("publish domain");
        repository
            .publish_selectable(&declaration)
            .expect("publish declaration");
        repository
            .publish_choice_opportunity(&opportunity)
            .expect("publish opportunity");
        repository
            .publish_selection(&selection)
            .expect("publish selection");
        let store = CampaignExecutorStore::new(repository);
        let mut guard = |_configuration: &Configuration, _branches: usize| Ok(64 * 1024);

        let error = decode_crucible_configuration_artifact_with_signal_fault_replay_guarded(
            &scenario,
            &scenario_artifact,
            &artifact,
            &store,
            Some(&mut guard),
        )
        .expect_err("large resolution closure must fit the selected decode budget");

        assert!(matches!(
            error,
            CrucibleArtifactError::ResourceLimit {
                resource: "selected-origin-decoded-resident-bytes"
            }
        ));
    }

    #[test]
    fn nested_signal_fault_selections_resolve_to_one_exact_ordered_plan() {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let scenario_artifact =
            encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
        let parent = Configuration::genesis(scenario.scenario_def());
        let first_selectable = signal_fault_selectable(&parent, b"first-signal-choice", 17);
        let first_selection = first_selectable
            .branch_selection(&parent, 0)
            .expect("first candidate selection");
        let first = first_selectable
            .resolve_branch(&first_selection)
            .expect("first branch");
        let second_selectable =
            signal_fault_selectable(first.selected(), b"second-signal-choice", 29);
        let second_selection = second_selectable
            .branch_selection(first.selected(), 2)
            .expect("second unmodified selection");
        let second = second_selectable
            .resolve_branch(&second_selection)
            .expect("second branch");
        let artifact =
            encode_crucible_configuration_artifact(&scenario_artifact, &second.selected().schedule)
                .expect("nested signal configuration");

        let repository = Arc::new(CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new(
                "crucible-nested-signal-selections",
                u64::MAX,
            )),
            Arc::new(MemoryRefBackend::new()),
        ));
        publish_signal_selection(&repository, &first_selectable, &first_selection);
        publish_signal_selection(&repository, &second_selectable, &second_selection);
        let store = CampaignExecutorStore::new(Arc::clone(&repository));

        let (decoded, replay) = decode_crucible_configuration_artifact_with_signal_fault_replay(
            &scenario,
            &scenario_artifact,
            &artifact,
            &store,
        )
        .expect("nested signal choices should authenticate");
        assert_eq!(decoded, *second.selected());
        assert_eq!(replay.target(), second.selected());
        assert_eq!(replay.branches(), &[first.clone(), second]);
        let restarted_store = CampaignExecutorStore::new(Arc::clone(&repository));
        let (_, restarted_replay) =
            decode_crucible_configuration_artifact_with_signal_fault_replay(
                &scenario,
                &scenario_artifact,
                &artifact,
                &restarted_store,
            )
            .expect("restart should reconstruct the same immutable replay plan");
        assert_eq!(restarted_replay, replay);

        let missing_override = Schedule::empty().appended(first.decisions()[0].clone());
        let missing_override =
            encode_crucible_configuration_artifact(&scenario_artifact, &missing_override)
                .expect("missing-override artifact");
        assert!(matches!(
            decode_crucible_configuration_artifact_with_signal_fault_replay(
                &scenario,
                &scenario_artifact,
                &missing_override,
                &store,
            ),
            Err(CrucibleArtifactError::SignalFaultScheduleMismatch)
        ));

        let raw_override = Schedule::empty().appended(first.decisions()[1].clone());
        let raw_override =
            encode_crucible_configuration_artifact(&scenario_artifact, &raw_override)
                .expect("raw-override artifact");
        assert!(matches!(
            decode_crucible_configuration_artifact_with_signal_fault_replay(
                &scenario,
                &scenario_artifact,
                &raw_override,
                &store,
            ),
            Err(CrucibleArtifactError::UnboundSignalFaultOverride)
        ));
    }

    #[test]
    fn verifier_backed_store_replays_finding_before_reproduction_publication() {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let configuration = Configuration {
            def: scenario.scenario_def(),
            schedule: Schedule::empty(),
        };
        let finding = FindingReproductionArtifact::capture(
            FindingDiscoveryPath::StateSpaceSearch,
            ContentHash::from_bytes(b"stable-failure-fingerprint"),
            &scenario,
            &configuration,
        )
        .expect("capture finding reproduction");
        let repository = Arc::new(CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new(
                "crucible-reproduction-import",
                u64::MAX,
            )),
            Arc::new(MemoryRefBackend::new()),
        ));
        let store = CrucibleCampaignArtifactStore::new(Arc::clone(&repository));

        let id = store
            .import_reproduction(&finding)
            .expect("import verified reproduction");
        let stored = repository
            .load_reproduction_artifact(id)
            .expect("load stored reproduction");
        assert_eq!(
            stored.finding_fingerprint(),
            CampaignHash::from_bytes(finding.finding_fingerprint.bytes)
        );
        assert_eq!(
            crucible::ReproductionArtifact::from_compact_binary(stored.payload())
                .expect("decode stored reproduction")
                .replay()
                .expect("replay stored reproduction"),
            finding.replay
        );

        let run = finding
            .minimize(
                MinimizationConfig::new(crucible::Seed::from_u64(0x5151)),
                |_| Ok(Some(finding.finding_fingerprint)),
            )
            .expect("verify deterministic minimization");
        let mislabeled = repository
            .publish_reproduction_artifact(
                stored.scenario(),
                stored.scenario_artifact(),
                stored.configuration(),
                stored.configuration_artifact(),
                stored.finding_fingerprint(),
                CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3 + 1,
                stored.payload().to_vec(),
            )
            .expect("publish structurally valid mislabeled reproduction");
        assert!(matches!(
            store.import_minimized_reproduction(mislabeled, &run, |_| {
                Ok(Some(finding.finding_fingerprint))
            }),
            Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "minimization original"
            })
        ));
        let minimized = store
            .import_minimized_reproduction(id, &run, |_| Ok(Some(finding.finding_fingerprint)))
            .expect("import minimized reproduction");
        let minimized = repository
            .load_reproduction_artifact(minimized)
            .expect("load minimized reproduction");
        assert_eq!(minimized.schema_version(), 2);
        let minimization = minimized
            .minimization()
            .expect("retained minimization evidence");
        assert_eq!(minimization.original(), id);
        assert_eq!(
            minimization.policy_schema(),
            CRUCIBLE_MINIMIZATION_POLICY_SCHEMA_V2
        );
        assert!(
            minimization
                .policy()
                .starts_with(CRUCIBLE_MINIMIZATION_POLICY_MAGIC_V2)
        );
    }

    fn replay_evidence(
        candidate: &FindingReproductionArtifact,
        signature: FindingSignature,
    ) -> CrucibleFindingReplayEvidence {
        let scenario = encode_crucible_scenario_artifact(candidate.artifact.scenario_form())
            .expect("encode replay scenario");
        let configuration =
            encode_crucible_configuration_artifact(&scenario, candidate.artifact.schedule())
                .expect("encode replay configuration");
        CrucibleFindingReplayEvidence::new(
            Some(signature),
            configuration,
            MeasurementSet::new(BTreeMap::new()).expect("empty replay measurements"),
            PropertyVerdictSet::new(BTreeMap::new()).expect("empty replay properties"),
            CoverageProjection::new(BTreeSet::new(), BTreeSet::new())
                .expect("empty replay coverage"),
            Vec::new(),
            Vec::new(),
        )
        .expect("typed replay evidence")
    }

    #[test]
    fn finding_candidate_preparation_deduplicates_bounded_replay_records_without_writes() {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let schedule = Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: Vec::new(),
        }));
        let configuration = Configuration {
            def: scenario.scenario_def(),
            schedule,
        };
        let fingerprint = ContentHash::from_bytes(b"prepared-finding-fingerprint");
        let finding = FindingReproductionArtifact::capture(
            FindingDiscoveryPath::StateSpaceSearch,
            fingerprint,
            &scenario,
            &configuration,
        )
        .expect("capture finding reproduction");
        let signature = FindingSignature::new(
            FindingKind::Divergence,
            CampaignHash::from_bytes(fingerprint.bytes),
            None,
            String::from("qemu.replay-divergence"),
            None,
            BTreeSet::new(),
        )
        .expect("stable finding signature");
        let seed = crucible::Seed::from_u64(0x5eed);
        let mut transcript = CrucibleFindingReplayTranscript::new();
        let first = minimize_signature_preserving_finding(
            &finding,
            &signature,
            seed,
            FindingReplayPass::Minimization,
            &mut transcript,
            |candidate| Ok(replay_evidence(candidate, signature.clone())),
        )
        .expect("first replay pass");
        let second = minimize_signature_preserving_finding(
            &finding,
            &signature,
            seed,
            FindingReplayPass::Verification,
            &mut transcript,
            |candidate| Ok(replay_evidence(candidate, signature.clone())),
        )
        .expect("second replay pass");
        assert_eq!(first, second);
        assert!(first.shrank());
        assert_eq!(transcript.minimization_pass.len(), first.attempts.len() + 1);
        assert_eq!(transcript.verification_pass.len(), first.attempts.len() + 1);

        let observation_content =
            ContentId::for_bytes(ObjectKind::Observation, 1, b"prepared-finding-observation");
        let observation = ObservationId::parse(&format!(
            "crucible.campaign.observation@{observation_content}"
        ))
        .expect("observation ID");
        let repository = Arc::new(CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new(
                "prepared-finding-no-write",
                u64::MAX,
            )),
            Arc::new(MemoryRefBackend::new()),
        ));
        let mut truncated = transcript.clone();
        truncated.verification_pass.pop();
        assert!(matches!(
            prepare_signature_preserving_minimized_finding_candidate(
                signature.clone(),
                observation,
                &finding,
                FindingExactPins::default(),
                seed,
                truncated,
            ),
            Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "finding minimization replay observation count"
            })
        ));

        let prepared = prepare_signature_preserving_minimized_finding_candidate(
            signature,
            observation,
            &finding,
            FindingExactPins::default(),
            seed,
            transcript,
        )
        .expect("prepare finding candidate");
        assert_eq!(prepared.replay_record_count(), 5);
        assert!(prepared.replay_record_bytes() > 0);
        assert!(
            repository
                .load_scenario_artifact(prepared.scenario().id().expect("scenario ID"))
                .is_err()
        );
        assert!(
            repository
                .load_reproduction_artifact(prepared.original().id().expect("original ID"))
                .is_err()
        );
    }

    #[test]
    fn finding_replay_retains_nonempty_configuration_target_and_causal_evidence() {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let schedule = Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: Vec::new(),
        }));
        let configuration = Configuration {
            def: scenario.scenario_def(),
            schedule,
        };
        let fingerprint = ContentHash::from_bytes(b"owned-replay-evidence-fingerprint");
        let finding = FindingReproductionArtifact::capture(
            FindingDiscoveryPath::StateSpaceSearch,
            fingerprint,
            &scenario,
            &configuration,
        )
        .expect("capture finding reproduction");
        let scenario_record =
            encode_crucible_scenario_artifact(&scenario).expect("scenario record");
        let original_configuration =
            encode_crucible_configuration_artifact(&scenario_record, finding.artifact.schedule())
                .expect("original configuration");
        let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("empty properties");
        let property_id = properties.id().expect("property ID");
        let signature = FindingSignature::new(
            FindingKind::Divergence,
            CampaignHash::from_bytes(fingerprint.bytes),
            None,
            String::from("qemu.replay-divergence"),
            Some(FindingTarget::Configuration(
                original_configuration.id().expect("configuration ID"),
            )),
            BTreeSet::from([property_id.content_id()]),
        )
        .expect("targeted finding signature");
        let seed = crucible::Seed::from_u64(0xe71d);
        let mut transcript = CrucibleFindingReplayTranscript::new();
        for pass in [
            FindingReplayPass::Minimization,
            FindingReplayPass::Verification,
        ] {
            minimize_signature_preserving_finding(
                &finding,
                &signature,
                seed,
                pass,
                &mut transcript,
                |candidate| {
                    let scenario =
                        encode_crucible_scenario_artifact(candidate.artifact.scenario_form())
                            .expect("candidate scenario");
                    let candidate_configuration = encode_crucible_configuration_artifact(
                        &scenario,
                        candidate.artifact.schedule(),
                    )
                    .expect("candidate configuration");
                    let candidate_signature = FindingSignature::new(
                        FindingKind::Divergence,
                        CampaignHash::from_bytes(fingerprint.bytes),
                        None,
                        String::from("qemu.replay-divergence"),
                        Some(FindingTarget::Configuration(
                            candidate_configuration
                                .id()
                                .expect("candidate configuration ID"),
                        )),
                        BTreeSet::from([property_id.content_id()]),
                    )
                    .expect("candidate signature");
                    Ok(CrucibleFindingReplayEvidence::new(
                        Some(candidate_signature),
                        candidate_configuration,
                        MeasurementSet::new(BTreeMap::new()).expect("measurements"),
                        properties.clone(),
                        CoverageProjection::new(BTreeSet::new(), BTreeSet::new())
                            .expect("coverage"),
                        Vec::new(),
                        Vec::new(),
                    )
                    .expect("candidate replay evidence"))
                },
            )
            .expect("targeted replay pass");
        }
        let observation_content =
            ContentId::for_bytes(ObjectKind::Observation, 1, b"targeted-finding-observation");
        let observation = ObservationId::parse(&format!(
            "crucible.campaign.observation@{observation_content}"
        ))
        .expect("observation ID");
        let prepared = prepare_signature_preserving_minimized_finding_candidate(
            signature.clone(),
            observation,
            &finding,
            FindingExactPins::default(),
            seed,
            transcript,
        )
        .expect("prepare targeted finding");
        let retained = prepared
            .bundle()
            .signature_minimization()
            .minimization_pass();
        assert!(retained.iter().flatten().all(|observed| {
            observed.target().is_some() && !observed.causal_evidence().is_empty()
        }));
        assert!(prepared.replay_records.configurations.iter().any(|record| {
            record.id().ok() == Some(original_configuration.id().expect("configuration ID"))
        }));
        assert!(
            prepared
                .replay_records
                .properties
                .iter()
                .any(|record| record.id().ok() == Some(property_id))
        );
    }

    #[test]
    fn prepared_finding_publishes_and_authenticates_an_admitted_observation_closure() {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let schedule = Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: Vec::new(),
        }));
        let scenario_record =
            encode_crucible_scenario_artifact(&scenario).expect("scenario record");
        let genesis = encode_crucible_configuration_artifact(&scenario_record, &Schedule::empty())
            .expect("genesis configuration");
        let child = encode_crucible_configuration_artifact(&scenario_record, &schedule)
            .expect("finding configuration");

        let repository = Arc::new(CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new(
                "prepared-finding-publication",
                u64::MAX,
            )),
            Arc::new(MemoryRefBackend::new()),
        ));
        repository
            .publish_scenario_artifact(
                scenario_record.scenario(),
                scenario_record.payload_schema(),
                scenario_record.payload().to_vec(),
            )
            .expect("publish scenario");
        repository
            .publish_configuration_artifact(
                genesis.scenario(),
                genesis.scenario_artifact(),
                genesis.configuration(),
                genesis.payload_schema(),
                genesis.payload().to_vec(),
            )
            .expect("publish genesis");
        let lineage = CampaignLineage::new(
            scenario_record.scenario(),
            scenario_record.id().expect("scenario ID"),
            genesis.configuration(),
            genesis.id().expect("genesis ID"),
            "crucible-test",
            "qemu-test",
            BTreeMap::from([(String::from("control"), 1)]),
            scenario_record.payload_schema(),
            1,
        )
        .expect("campaign lineage");
        let widening = ProgressiveWideningPolicy::new(
            crucible_campaign::ExactRational::new(1, 1).expect("widening numerator"),
            crucible_campaign::ExactRational::new(1, 2).expect("widening exponent"),
            1,
            100,
            1,
        )
        .expect("widening policy");
        let policy = CampaignPolicy::new(
            lineage.scenario(),
            CampaignSeed::from_bytes([7; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                widening: Some(widening),
                puct: PuctPolicy::new(1_000_000, 1, 0),
            },
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness policy"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        )
        .expect("campaign policy");
        let created = repository
            .create("prepared-finding", &lineage, &policy, &BTreeMap::new())
            .expect("create campaign");
        let resumed = repository
            .apply_control(
                "prepared-finding",
                &ControlRequest {
                    command: CampaignCommandId::from_hash(CampaignHash::derive(
                        "test",
                        b"resume-prepared-finding",
                    )),
                    expected_snapshot: created.snapshot_id(),
                    action: CampaignControlAction::Resume,
                },
            )
            .expect("resume campaign");
        let funded = repository
            .apply_control(
                "prepared-finding",
                &ControlRequest {
                    command: CampaignCommandId::from_hash(CampaignHash::derive(
                        "test",
                        b"fund-prepared-finding",
                    )),
                    expected_snapshot: resumed.new_snapshot,
                    action: CampaignControlAction::GrantBudget(
                        BudgetGrant::new(0, 1).expect("attempt grant"),
                    ),
                },
            )
            .expect("fund campaign");
        let attempt = repository
            .admit_initial_discovery_if_ready("prepared-finding")
            .expect("admit initial discovery")
            .expect("discovery attempt");
        assert_ne!(funded.new_snapshot, created.snapshot_id());
        let attempt_record = repository.load_attempt(attempt).expect("load attempt");

        let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
        let declaration = SelectableDeclaration::new(
            "product.test.prepared-finding-choice",
            ChoiceSource::Scheduler {
                producer: String::from("prepared-finding-test"),
            },
            domain.clone(),
            ChoiceValue::Boolean(false),
            ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
            BTreeSet::new(),
            true,
        )
        .expect("selectable declaration");
        let opportunity = ChoiceOpportunity::new(
            lineage.scenario(),
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::derive("test", b"prepared-finding-scheduler"),
                producer: CampaignHash::derive("test", b"prepared-finding-producer"),
            },
            "prepared-finding-choice",
            None,
        )
        .expect("choice opportunity");
        let discovery =
            ChoiceDiscovery::new(declaration, domain, opportunity.clone()).expect("discovery");
        let measurements = MeasurementSet::new(BTreeMap::new()).expect("measurements");
        let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
        let coverage =
            CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage projection");
        let observation = Observation::new(
            attempt,
            child.configuration(),
            child.id().expect("child ID"),
            attempt_record.path(),
            StopOutcome::Reached(StopCondition::NextChoice),
            measurements.id().expect("measurement ID"),
            properties.id().expect("property ID"),
            coverage.id().expect("coverage ID"),
            BTreeSet::from([opportunity.id().expect("opportunity ID")]),
        )
        .expect("observation");
        let observation_candidate = ObservationCandidate::new(
            child.clone(),
            measurements,
            properties.clone(),
            coverage,
            vec![discovery],
            observation,
        )
        .expect("observation candidate");
        let executor_store = CampaignExecutorStore::new(Arc::clone(&repository));
        let observation = observation_candidate
            .observation()
            .id()
            .expect("observation ID");

        let fingerprint = ContentHash::from_bytes(b"published-finding-fingerprint");
        let finding = FindingReproductionArtifact::capture(
            FindingDiscoveryPath::StateSpaceSearch,
            fingerprint,
            &scenario,
            &Configuration {
                def: scenario.scenario_def(),
                schedule,
            },
        )
        .expect("capture finding reproduction");
        let property = properties.id().expect("causal property record");
        let signature = FindingSignature::new(
            FindingKind::Divergence,
            CampaignHash::from_bytes(fingerprint.bytes),
            None,
            String::from("qemu.replay-divergence"),
            Some(FindingTarget::Configuration(
                child.id().expect("finding target"),
            )),
            BTreeSet::from([property.content_id()]),
        )
        .expect("finding signature");
        let seed = crucible::Seed::from_u64(0xface);
        let mut transcript = CrucibleFindingReplayTranscript::new();
        for pass in [
            FindingReplayPass::Minimization,
            FindingReplayPass::Verification,
        ] {
            minimize_signature_preserving_finding(
                &finding,
                &signature,
                seed,
                pass,
                &mut transcript,
                |candidate| {
                    let candidate_scenario =
                        encode_crucible_scenario_artifact(candidate.artifact.scenario_form())
                            .expect("candidate scenario");
                    let candidate_configuration = encode_crucible_configuration_artifact(
                        &candidate_scenario,
                        candidate.artifact.schedule(),
                    )
                    .expect("candidate configuration");
                    let observed = if candidate.artifact.schedule() == finding.artifact.schedule() {
                        signature.clone()
                    } else {
                        FindingSignature::new(
                            FindingKind::Divergence,
                            CampaignHash::derive("test", b"reduced-candidate-divergence"),
                            None,
                            String::from("qemu.different-replay-divergence"),
                            Some(FindingTarget::Configuration(
                                candidate_configuration.id().expect("candidate target"),
                            )),
                            BTreeSet::from([property.content_id()]),
                        )
                        .expect("rejected candidate signature")
                    };
                    Ok(CrucibleFindingReplayEvidence::new(
                        Some(observed),
                        candidate_configuration,
                        MeasurementSet::new(BTreeMap::new()).expect("replay measurements"),
                        properties.clone(),
                        CoverageProjection::new(BTreeSet::new(), BTreeSet::new())
                            .expect("replay coverage"),
                        Vec::new(),
                        Vec::new(),
                    )
                    .expect("replay evidence"))
                },
            )
            .expect("finding replay pass");
        }
        let prepared = prepare_signature_preserving_minimized_finding_candidate(
            signature.clone(),
            observation,
            &finding,
            FindingExactPins::default(),
            seed,
            transcript,
        )
        .expect("prepare finding candidate");
        assert!(
            prepared
                .minimized()
                .minimization()
                .expect("minimization evidence")
                .attempts()
                .iter()
                .any(|attempt| !attempt.accepted()),
            "the reduced empty schedule must be rejected by the concrete target"
        );

        let observation_publication =
            empty_measurement_publication(scenario_record.scenario(), child.configuration());
        let (observation_evidence, _, observation_measurements) =
            observation_publication.into_parts();
        let observation_candidate_v2 =
            observation_with_measurements(&observation_candidate, observation_measurements);
        let observation_v2 = observation_candidate_v2
            .observation()
            .id()
            .expect("v2 observation ID");
        let mut measurement_evidence = BTreeMap::from([(
            observation_evidence.id().expect("observation evidence ID"),
            observation_evidence,
        )]);
        let mut v2_transcript = CrucibleFindingReplayTranscript::new();
        for pass in [
            FindingReplayPass::Minimization,
            FindingReplayPass::Verification,
        ] {
            minimize_signature_preserving_finding(
                &finding,
                &signature,
                seed,
                pass,
                &mut v2_transcript,
                |candidate| {
                    let candidate_scenario =
                        encode_crucible_scenario_artifact(candidate.artifact.scenario_form())
                            .expect("v2 candidate scenario");
                    let candidate_configuration = encode_crucible_configuration_artifact(
                        &candidate_scenario,
                        candidate.artifact.schedule(),
                    )
                    .expect("v2 candidate configuration");
                    let observed = if candidate.artifact.schedule() == finding.artifact.schedule() {
                        signature.clone()
                    } else {
                        FindingSignature::new(
                            FindingKind::Divergence,
                            CampaignHash::derive("test", b"v2-reduced-candidate-divergence"),
                            None,
                            String::from("qemu.different-v2-replay-divergence"),
                            Some(FindingTarget::Configuration(
                                candidate_configuration.id().expect("v2 candidate target"),
                            )),
                            BTreeSet::from([property.content_id()]),
                        )
                        .expect("v2 rejected candidate signature")
                    };
                    let publication = empty_measurement_publication(
                        candidate_scenario.scenario(),
                        candidate_configuration.configuration(),
                    );
                    let (evidence, _, measurements) = publication.into_parts();
                    measurement_evidence
                        .insert(evidence.id().expect("v2 replay evidence ID"), evidence);
                    Ok(CrucibleFindingReplayEvidence::new(
                        Some(observed),
                        candidate_configuration,
                        measurements,
                        properties.clone(),
                        CoverageProjection::new(BTreeSet::new(), BTreeSet::new())
                            .expect("v2 replay coverage"),
                        Vec::new(),
                        Vec::new(),
                    )
                    .expect("v2 replay evidence"))
                },
            )
            .expect("v2 finding replay pass");
        }
        let prepared_v2 = prepare_signature_preserving_minimized_finding_candidate(
            signature.clone(),
            observation_v2,
            &finding,
            FindingExactPins::default(),
            seed,
            v2_transcript,
        )
        .expect("prepare v2 finding candidate");
        let measurement_evidence = measurement_evidence.into_values().collect::<Vec<_>>();
        assert!(measurement_evidence.len() >= 2);
        assert!(
            measurement_evidence
                .iter()
                .any(|evidence| evidence.configuration() != child.configuration())
        );
        let v2_result = PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
            observation_candidate_v2.clone(),
            measurement_evidence.clone(),
            Some(prepared_v2.clone()),
        )
        .expect("bind v2 prepared semantic result");
        v2_result
            .verify_measurement_publications(&scenario)
            .expect("verify every authenticated v2 measurement owner");

        let measurement_records = prepared_v2
            .replay_records
            .measurements
            .iter()
            .map(|measurement| {
                (
                    measurement.id().expect("replay measurement ID"),
                    measurement,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let shared_evidence = measurement_evidence
            .iter()
            .map(|evidence| evidence.id().expect("shared evidence ID"))
            .find(|evidence| {
                prepared_v2.minimization_replays.iter().any(|replay| {
                    measurement_records
                        .get(&replay.measurements)
                        .and_then(|measurement| measurement.evaluation())
                        .is_some_and(|evaluation| evaluation.evidence().contains(evidence))
                }) && prepared_v2.verification_replays.iter().any(|replay| {
                    measurement_records
                        .get(&replay.measurements)
                        .and_then(|measurement| measurement.evaluation())
                        .is_some_and(|evaluation| evaluation.evidence().contains(evidence))
                })
            })
            .expect("one raw leaf shared by both replay passes");
        let verification_replay = prepared_v2
            .verification_replays
            .iter()
            .position(|replay| {
                measurement_records
                    .get(&replay.measurements)
                    .and_then(|measurement| measurement.evaluation())
                    .is_some_and(|evaluation| evaluation.evidence().contains(&shared_evidence))
            })
            .expect("verification owner of shared raw leaf");
        let original_measurement = measurement_records
            .get(&prepared_v2.verification_replays[verification_replay].measurements)
            .copied()
            .expect("shared replay measurement");
        let retained = original_measurement
            .evaluation()
            .expect("shared replay evaluation");
        let mut tampered_payload = retained.payload().to_vec();
        tampered_payload.push(b' ');
        let tampered_measurement = MeasurementSet::from_evaluation(
            retained.definitions(),
            retained.payload_schema(),
            retained.evaluation(),
            tampered_payload,
            retained.evidence().clone(),
        )
        .expect("structurally valid tampered replay measurement");
        let tampered_measurement_id = tampered_measurement
            .id()
            .expect("tampered replay measurement ID");
        let mut tampered_finding = prepared_v2.clone();
        tampered_finding
            .replay_records
            .measurements
            .push(tampered_measurement);
        tampered_finding.verification_replays[verification_replay].measurements =
            tampered_measurement_id;
        let tampered_result = PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
            observation_candidate_v2.clone(),
            measurement_evidence.clone(),
            Some(tampered_finding),
        )
        .expect("retain structurally owned shared evidence");
        assert!(matches!(
            tampered_result.verify_measurement_publications(&scenario),
            Err(PreparedSemanticResultCodecError::Measurement(_))
        ));

        let v2_bytes = v2_result
            .canonical_bytes()
            .expect("encode v2 prepared result");
        assert_eq!(
            PreparedSemanticAttemptResult::from_canonical_bytes(&v2_bytes)
                .expect("decode v2 prepared result"),
            v2_result
        );

        let mut unordered_evidence = measurement_evidence.clone();
        unordered_evidence.reverse();
        assert!(matches!(
            PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
                observation_candidate_v2.clone(),
                unordered_evidence,
                Some(prepared_v2.clone()),
            ),
            Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "measurement replay evidence order"
            })
        ));

        let unused_publication = empty_measurement_publication(
            scenario_record.scenario(),
            ConfigurationId::from_hash(CampaignHash::derive(
                "test",
                b"unused-replay-measurement-configuration",
            )),
        );
        let (unused_evidence, _, unused_measurements) = unused_publication.into_parts();
        let mut evidence_with_extra = measurement_evidence
            .iter()
            .cloned()
            .map(|evidence| (evidence.id().expect("retained evidence ID"), evidence))
            .collect::<BTreeMap<_, _>>();
        evidence_with_extra.insert(
            unused_evidence.id().expect("unused evidence ID"),
            unused_evidence.clone(),
        );
        assert!(matches!(
            PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
                observation_candidate_v2.clone(),
                evidence_with_extra.values().cloned().collect(),
                Some(prepared_v2.clone()),
            ),
            Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "unowned measurement replay evidence"
            })
        ));
        let mut finding_with_unused_measurement = prepared_v2.clone();
        finding_with_unused_measurement
            .replay_records
            .measurements
            .push(unused_measurements);
        assert!(matches!(
            PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
                observation_candidate_v2.clone(),
                evidence_with_extra.into_values().collect(),
                Some(finding_with_unused_measurement),
            ),
            Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "unreferenced finding replay measurement record"
            })
        ));

        for (wrong_scenario, wrong_configuration, wrong_definitions) in [
            (
                ScenarioDefId::from_hash(CampaignHash::derive("test", b"wrong-scenario")),
                child.configuration(),
                None,
            ),
            (
                scenario_record.scenario(),
                ConfigurationId::from_hash(CampaignHash::derive("test", b"wrong-configuration")),
                None,
            ),
            (
                scenario_record.scenario(),
                child.configuration(),
                Some(CampaignHash::derive("test", b"wrong-definitions")),
            ),
        ] {
            let wrong_publication =
                empty_measurement_publication(wrong_scenario, wrong_configuration);
            let (wrong_evidence, _, _) = wrong_publication.into_parts();
            let definitions = wrong_definitions.unwrap_or_else(|| {
                observation_candidate_v2
                    .measurements()
                    .evaluation()
                    .expect("v2 measurement evaluation")
                    .definitions()
            });
            let wrong_measurements = measurement_with_evidence(
                observation_candidate_v2.measurements(),
                &wrong_evidence,
                definitions,
            );
            let wrong_candidate =
                observation_with_measurements(&observation_candidate_v2, wrong_measurements);
            assert!(matches!(
                PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
                    wrong_candidate,
                    vec![wrong_evidence],
                    None,
                ),
                Err(PreparedSemanticResultCodecError::Inconsistent {
                    component: "measurement replay evidence binding"
                })
            ));
        }

        let smuggled_v1 = prepared_result::encode_v1_without_measurement_evidence_for_test(
            &observation_candidate_v2,
            None,
        )
        .expect("encode invalid legacy v1 payload");
        assert!(matches!(
            PreparedSemanticAttemptResult::from_canonical_bytes(&smuggled_v1),
            Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "missing measurement replay evidence"
            })
        ));

        let expected = prepared.id().expect("prepared candidate ID");
        let expected_bundle = prepared.bundle().clone();
        let durable_result = PreparedSemanticAttemptResult::new(
            observation_candidate.clone(),
            Some(prepared.clone()),
        )
        .expect("bind prepared semantic result");
        let durable_bytes = durable_result
            .canonical_bytes()
            .expect("encode prepared semantic result");
        let decoded = PreparedSemanticAttemptResult::from_canonical_bytes(&durable_bytes)
            .expect("decode prepared semantic result");
        assert_eq!(decoded, durable_result);
        let mut trailing = durable_bytes.clone();
        trailing.push(0);
        assert!(matches!(
            PreparedSemanticAttemptResult::from_canonical_bytes(&trailing),
            Err(PreparedSemanticResultCodecError::TrailingBytes)
        ));

        let unrelated_observation = Observation::new(
            attempt,
            genesis.configuration(),
            genesis.id().expect("unrelated observation child"),
            attempt_record.path(),
            StopOutcome::Reached(StopCondition::NextChoice),
            observation_candidate
                .measurements()
                .id()
                .expect("unrelated observation measurements"),
            observation_candidate
                .properties()
                .id()
                .expect("unrelated observation properties"),
            observation_candidate
                .coverage()
                .id()
                .expect("unrelated observation coverage"),
            BTreeSet::from([opportunity.id().expect("unrelated observation choice")]),
        )
        .expect("unrelated observation");
        let unrelated_candidate = ObservationCandidate::new(
            genesis.clone(),
            observation_candidate.measurements().clone(),
            observation_candidate.properties().clone(),
            observation_candidate.coverage().clone(),
            observation_candidate.discovered_choices().to_vec(),
            unrelated_observation,
        )
        .expect("unrelated observation candidate");
        let mut mismatched_finding = prepared.clone();
        mismatched_finding.bundle = FindingCandidateBundle::new(
            unrelated_candidate
                .observation()
                .id()
                .expect("unrelated observation ID"),
            signature.clone(),
            prepared.bundle().reproduction(),
            prepared.bundle().minimized(),
            prepared.bundle().signature_minimization().clone(),
            prepared.bundle().exact_pins().clone(),
        )
        .expect("finding rebound to unrelated observation ID");
        assert!(matches!(
            PreparedSemanticAttemptResult::new(unrelated_candidate, Some(mismatched_finding)),
            Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "finding observation reproduction basis"
            })
        ));

        let mut inconsistent_finding = prepared.clone();
        let unrelated_schedule =
            finding
                .artifact
                .schedule()
                .clone()
                .appended(Decision::DeliveryOrder(DeliveryOrderDecision {
                    at: VirtualTime { ticks: 2 },
                    order: Vec::new(),
                }));
        let unrelated_configuration =
            encode_crucible_configuration_artifact(&scenario_record, &unrelated_schedule)
                .expect("unrelated replay configuration")
                .id()
                .expect("unrelated replay configuration ID");
        inconsistent_finding.minimization_replays[0].configuration = unrelated_configuration;
        let inconsistent = PreparedSemanticAttemptResult::new(
            observation_candidate.clone(),
            Some(inconsistent_finding),
        )
        .expect("observation binding remains valid");
        assert!(matches!(
            inconsistent.canonical_bytes_with_limit(1),
            Err(PreparedSemanticResultCodecError::LimitExceeded)
        ));
        assert!(matches!(
            inconsistent.canonical_bytes(),
            Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "finding replay record index"
            })
        ));

        let epoch = DaemonEpoch::from_bytes([0x57; 16]).expect("daemon epoch");
        let request = SubmitAttemptRequest::new(
            AssignmentId::from_bytes([0x58; 16]).expect("assignment"),
            epoch,
            lineage.id().expect("lineage ID"),
            attempt,
            AttemptResourceLimits::new(1, 4096, 4096, 64).expect("attempt resources"),
            ExecutionRetentionIntent::RetainOnFailure,
        )
        .expect("submit request");
        let mut supervisor = LocalExecutorSupervisor::new(
            MemoryAssignmentLedger::default(),
            AllowAllAttemptAdmission,
            epoch,
            ExecutorCapacity::new(1, 1, 4096, 4096, 64).expect("executor capacity"),
        );
        let response = supervisor
            .submit_attempt(&request)
            .expect("admit finding attempt");
        let SubmitAttemptDisposition::Accepted { execution } = response.disposition() else {
            panic!("finding attempt should be accepted")
        };
        let queued = supervisor.next_queued().expect("queued finding attempt");
        let checkpoint_directory = tempfile::tempdir().expect("checkpoint directory");
        let checkpoints = ExactCheckpointStore::new(
            Arc::new(DirectoryBlobBackend::new(
                "prepared-finding-checkpoints",
                checkpoint_directory.path(),
            )),
            1024 * 1024,
        )
        .expect("checkpoint store");
        let work = AttemptWorkResult::<()>::new(
            queued,
            Ok(AttemptExecutionProduct::observation_with_finding(
                observation_candidate,
                prepared,
            )),
        );
        let prepared = prepare_attempt_result(&executor_store, &checkpoints, work)
            .expect("prepare paired worker result");
        let PreparedAttemptWorkResult::Observation(prepared) = prepared else {
            panic!("finding worker returned an exact checkpoint")
        };
        assert_eq!(prepared.observation(), observation);
        assert_eq!(prepared.finding_candidate(), Some(expected));

        let staged = stage_prepared_attempt_result(&mut supervisor, *prepared)
            .expect("stage paired publication");
        let AttemptResultStageOutcome::Publish(staged) = staged else {
            panic!("current finding result should publish")
        };
        let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
        assert!(matches!(
            supervisor
                .ledger()
                .load_attempt(key)
                .expect("load staged finding pair"),
            Some(AttemptRuntimeState::Publishing {
                observation: retained_observation,
                finding_candidate: Some(retained_candidate),
                ..
            }) if retained_observation == observation && retained_candidate == expected
        ));
        assert_eq!(
            supervisor
                .stage_observation_and_finding_candidate_publication(
                    staged.queued(),
                    observation,
                    expected,
                )
                .expect("retry exact staged pair"),
            crate::ObservationPublicationOutcome::AlreadyStaged
        );
        let wrong_candidate_content =
            ContentId::for_bytes(ObjectKind::Finding, 1, b"wrong staged finding candidate");
        let wrong_candidate = FindingCandidateBundleId::parse(&format!(
            "crucible.campaign.finding-candidate-bundle@{wrong_candidate_content}"
        ))
        .expect("wrong finding candidate ID");
        assert!(matches!(
            supervisor.stage_and_reconcile_completion_with_finding_candidate(
                staged.queued(),
                observation,
                Some(wrong_candidate),
            ),
            Err(LocalExecutorError::ConflictingCompletion)
        ));

        let published = publish_prepared_attempt_result(&executor_store, staged)
            .expect("publish paired finding result");
        assert_eq!(published.finding_candidate(), Some(expected));
        let reconciled = reconcile_published_attempt_result::<_, _, ()>(&mut supervisor, published)
            .expect("reconcile paired finding result");
        assert_eq!(
            reconciled,
            AttemptWorkerReconcileOutcome::Reconciled {
                observation,
                completion: CompletionOutcome::Completed,
            }
        );

        let loaded = repository
            .load_finding_candidate_bundle(expected)
            .expect("load and authenticate finding closure");
        assert_eq!(loaded, expected_bundle);
        assert_eq!(loaded.observation(), observation);
        assert_eq!(loaded.signature().target(), signature.target());
        assert_eq!(
            loaded.signature().causal_evidence(),
            signature.causal_evidence()
        );

        let campaign = CampaignName::new("prepared-finding").expect("campaign name");
        let observation_parent = repository
            .head(campaign.as_str())
            .expect("current finding campaign head")
            .snapshot_id();
        let observation_record = repository
            .load_observation(observation)
            .expect("load paired observation");
        let incorporated_observation = repository
            .publish_observation(campaign.as_str(), observation_parent, &observation_record)
            .expect("incorporate paired observation");
        let mut ledger = supervisor.into_ledger();
        let handoff = incorporate_and_acknowledge_finding_candidate(
            &repository,
            &mut ledger,
            &campaign,
            incorporated_observation.new_snapshot,
            key,
            execution,
            observation,
            expected,
        )
        .expect("incorporate and acknowledge exact finding pair");
        let crate::FindingCandidateRetentionOutcome::Released(acknowledgement) =
            handoff.acknowledgement()
        else {
            panic!("exact finding pair should release its operational root")
        };
        assert_eq!(acknowledgement.bundle(), expected);
        assert!(matches!(
            ledger
                .load_attempt(key)
                .expect("load acknowledged finding pair"),
            Some(AttemptRuntimeState::Completed {
                observation: retained_observation,
                finding_candidate: CompletedFindingCandidate::Acknowledged(retained_candidate),
                ..
            }) if retained_observation == observation && retained_candidate == expected
        ));
    }

    #[test]
    fn finding_candidate_publication_waits_for_both_replay_passes() {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let schedule = Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: Vec::new(),
        }));
        let configuration = Configuration {
            def: scenario.scenario_def(),
            schedule,
        };
        let fingerprint = ContentHash::from_bytes(b"two-pass-finding-fingerprint");
        let finding = FindingReproductionArtifact::capture(
            FindingDiscoveryPath::StateSpaceSearch,
            fingerprint,
            &scenario,
            &configuration,
        )
        .expect("capture finding reproduction");
        let signature = FindingSignature::new(
            FindingKind::Divergence,
            CampaignHash::from_bytes(fingerprint.bytes),
            None,
            String::from("qemu.replay-divergence"),
            None,
            BTreeSet::new(),
        )
        .expect("stable finding signature");
        let seed = crucible::Seed::from_u64(0x7777);
        let mut probe = CrucibleFindingReplayTranscript::new();
        let first = minimize_signature_preserving_finding(
            &finding,
            &signature,
            seed,
            FindingReplayPass::Minimization,
            &mut probe,
            |candidate| Ok(replay_evidence(candidate, signature.clone())),
        )
        .expect("first replay pass");
        let (_, original_configuration, original) =
            prepare_original_reproduction(&finding).expect("prepare original reproduction");
        let observation_content =
            ContentId::for_bytes(ObjectKind::Observation, 1, b"two-pass-finding-observation");
        let observation = ObservationId::parse(&format!(
            "crucible.campaign.observation@{observation_content}"
        ))
        .expect("observation ID");
        let repository = Arc::new(CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new(
                "two-pass-finding-no-partial-write",
                u64::MAX,
            )),
            Arc::new(MemoryRefBackend::new()),
        ));
        let store = CrucibleCampaignArtifactStore::new(Arc::clone(&repository));
        let mut calls = 0;

        let error = store
            .publish_signature_preserving_minimized_finding_candidate(
                signature.clone(),
                observation,
                &finding,
                FindingExactPins::default(),
                seed,
                |candidate| {
                    if calls == first.attempts.len() + 1 {
                        return Err(crucible::ReproductionArtifact::from_compact_binary(
                            b"invalid replay artifact",
                        )
                        .expect_err("invalid replay artifact"));
                    }
                    calls += 1;
                    Ok(replay_evidence(candidate, signature.clone()))
                },
            )
            .expect_err("second replay pass must fail");

        assert!(matches!(
            error,
            CrucibleArtifactError::InvalidPayload {
                artifact: "signature-preserving finding minimization",
                ..
            }
        ));
        assert_eq!(calls, first.attempts.len() + 1);
        assert!(
            repository
                .load_configuration_artifact(
                    original_configuration
                        .id()
                        .expect("original configuration ID"),
                )
                .is_err()
        );
        assert!(
            repository
                .load_reproduction_artifact(original.id().expect("original reproduction ID"))
                .is_err()
        );
    }

    #[test]
    fn crucible_payloads_reject_schema_and_identity_drift() {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let valid = encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
        let unsupported = ScenarioArtifact::new(
            valid.scenario(),
            CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V3 + 1,
            valid.payload().to_vec(),
        )
        .expect("unsupported artifact remains structurally valid");
        assert!(matches!(
            decode_crucible_scenario_artifact(&unsupported),
            Err(CrucibleArtifactError::UnsupportedPayloadSchema { .. })
        ));
        let mislabeled_legacy = ScenarioArtifact::new(
            valid.scenario(),
            CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V1,
            valid.payload().to_vec(),
        )
        .expect("mislabeled artifact remains structurally valid");
        assert!(matches!(
            decode_crucible_scenario_artifact(&mislabeled_legacy),
            Err(CrucibleArtifactError::UnsupportedPayloadSchema {
                actual: CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V1,
                expected: CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V3,
                ..
            })
        ));

        let drifted = ScenarioArtifact::new(
            ScenarioDefId::from_hash(CampaignHash::from_bytes([0x5a; 32])),
            CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V3,
            valid.payload().to_vec(),
        )
        .expect("drifted identity artifact remains structurally valid");
        assert!(matches!(
            decode_crucible_scenario_artifact(&drifted),
            Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "scenario"
            })
        ));

        let configuration = encode_crucible_configuration_artifact(&valid, &Schedule::empty())
            .expect("configuration artifact");
        let legacy_configuration = ConfigurationArtifact::new(
            configuration.scenario(),
            configuration.scenario_artifact(),
            configuration.configuration(),
            1,
            configuration.payload().to_vec(),
        )
        .expect("legacy configuration remains structurally valid");
        assert!(matches!(
            decode_crucible_configuration_artifact(&scenario, &valid, &legacy_configuration),
            Err(CrucibleArtifactError::UnsupportedPayloadSchema {
                artifact: "configuration",
                actual: 1,
                expected: CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V2,
            })
        ));

        let selection_schedule = Schedule::empty().appended(selection_decision(valid.scenario()));
        let unresolved = encode_crucible_configuration_artifact(&valid, &selection_schedule)
            .expect("selection configuration");
        assert!(matches!(
            decode_crucible_configuration_artifact(&scenario, &valid, &unresolved),
            Err(CrucibleArtifactError::UnresolvedSelectionDecision)
        ));

        let mut legacy_payload = configuration.payload().to_vec();
        legacy_payload[..b"crucible.schedule.v2\0".len()]
            .copy_from_slice(b"crucible.schedule.v1\0");
        let legacy_nested_schedule = ConfigurationArtifact::new(
            configuration.scenario(),
            configuration.scenario_artifact(),
            configuration.configuration(),
            CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V2,
            legacy_payload,
        )
        .expect("legacy nested schedule remains structurally valid");
        assert!(matches!(
            decode_crucible_configuration_artifact(&scenario, &valid, &legacy_nested_schedule),
            Err(CrucibleArtifactError::UnsupportedScheduleEncoding)
        ));
    }
}
