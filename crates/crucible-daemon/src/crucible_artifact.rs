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
mod tests;
