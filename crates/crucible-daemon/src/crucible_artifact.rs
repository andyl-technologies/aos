//! Strict Crucible execution-model payloads carried by campaign artifacts.
//!
//! The campaign repository treats scenario and configuration payloads as
//! opaque, language-neutral byte strings. This module owns the following
//! nested payload schemas:
//!
//! ```text
//! CrucibleScenarioPayloadV1      = ScenarioDefForm compact binary V5
//! CrucibleConfigurationPayloadV2 = Schedule compact binary V2
//! ```
//!
//! Decoding re-derives both semantic identities before a live session or QEMU
//! process can consume the values.

use std::sync::Arc;

use crucible::{Configuration, Decision, FindingReproductionArtifact, ScenarioDefForm, Schedule};
use crucible_campaign::{
    CampaignCodecError, CampaignExecutorStore, CampaignHash, CampaignRepository,
    CampaignRepositoryError, CandidateGeneratorSpec, CandidateGeneratorSpecId,
    ConfigurationArtifact, ConfigurationArtifactId, ConfigurationId, ReproductionArtifact,
    ReproductionArtifactId, ScenarioArtifact, ScenarioArtifactId, ScenarioDefId, SelectionOrigin,
};

/// Payload schema for a compact canonical Crucible scenario definition.
pub const CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V1: u32 = 1;
/// Payload schema for a compact canonical Crucible configuration schedule.
pub const CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V2: u32 = 2;
/// Payload schema for a compact canonical Crucible reproduction artifact.
pub const CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V1: u32 = 1;
/// Maximum bytes accepted from one pre-bind Crucible artifact import file.
///
/// This matches the campaign artifact payload ceiling. Import callers should
/// enforce it while reading, before retaining or decoding the complete body.
pub const MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES: usize = 32 * 1024 * 1024;
const CRUCIBLE_SCHEDULE_V2_MAGIC: &[u8] = b"crucible.schedule.v2\0";
const MAX_CONFIGURATION_SELECTION_DECISIONS: usize = 4_096;
const MAX_CONFIGURATION_BRANCH_PREFIX_BYTES: usize = 256 * 1024 * 1024;

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

impl CrucibleCampaignArtifactStore {
    /// Creates a narrow artifact-import capability over one repository.
    #[must_use]
    pub const fn new(repository: Arc<CampaignRepository>) -> Self {
        Self { repository }
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
            scenario_record.scenario(),
            scenario_record.id()?,
            configuration_record.configuration(),
            stored_configuration,
            fingerprint,
            CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V1,
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
    /// A derived schedule prefix was inconsistent with its source schedule.
    #[error(transparent)]
    SelectionPrefix(#[from] crucible::ScheduleError),
    /// Campaign envelope construction rejected a newly encoded artifact.
    #[error(transparent)]
    Campaign(#[from] CampaignCodecError),
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
        CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V1,
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
    require_schema(
        "scenario",
        artifact.payload_schema(),
        CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V1,
    )?;
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
    let configuration =
        decode_crucible_configuration_artifact_structural(scenario, scenario_artifact, artifact)?;
    validate_selection_decisions(&configuration, artifact, store)?;
    Ok(configuration)
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

fn validate_selection_decisions(
    configuration: &Configuration,
    artifact: &ConfigurationArtifact,
    store: &CampaignExecutorStore,
) -> Result<(), CrucibleArtifactError> {
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
    if selections.is_empty() {
        return Ok(());
    }

    let selection_ids = selections
        .iter()
        .map(|(_, selection)| selection.id())
        .collect::<Result<Vec<_>, _>>()?;
    let resolved = store.resolve_selections(&selection_ids)?;
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
    Ok(())
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
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use crucible::{
        ContentHash, Decision, DeliveryOrderDecision, FindingDiscoveryPath, SelectionDecision,
        VirtualTime,
    };
    use crucible_campaign::{
        BooleanDomain, CampaignRepository, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain,
        ChoiceOpportunity, ChoiceSource, ChoiceValue, SelectableDeclaration, Selection,
        SelectionOrigin,
    };
    use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};

    use super::*;

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
        let store = CampaignExecutorStore::new(repository);

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
    }

    #[test]
    fn crucible_payloads_reject_schema_and_identity_drift() {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let valid = encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
        let unsupported = ScenarioArtifact::new(valid.scenario(), 2, valid.payload().to_vec())
            .expect("unsupported artifact remains structurally valid");
        assert!(matches!(
            decode_crucible_scenario_artifact(&unsupported),
            Err(CrucibleArtifactError::UnsupportedPayloadSchema { .. })
        ));

        let drifted = ScenarioArtifact::new(
            ScenarioDefId::from_hash(CampaignHash::from_bytes([0x5a; 32])),
            CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V1,
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
