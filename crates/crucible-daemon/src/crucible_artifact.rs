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

use crucible::{Configuration, Decision, ScenarioDefForm, Schedule};
use crucible_campaign::{
    CampaignCodecError, CampaignExecutorStore, CampaignHash, CampaignRepositoryError,
    ConfigurationArtifact, ConfigurationId, ScenarioArtifact, ScenarioDefId, SelectionOrigin,
};

/// Payload schema for a compact canonical Crucible scenario definition.
pub const CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V1: u32 = 1;
/// Payload schema for a compact canonical Crucible configuration schedule.
pub const CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V2: u32 = 2;
const CRUCIBLE_SCHEDULE_V2_MAGIC: &[u8] = b"crucible.schedule.v2\0";
const MAX_CONFIGURATION_SELECTION_DECISIONS: usize = 4_096;
const MAX_CONFIGURATION_BRANCH_PREFIX_BYTES: usize = 256 * 1024 * 1024;

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
/// provenance is recomputed from the exact schedule prefix and opportunity;
/// model-sampled selections remain fail-closed until a pure model verifier is
/// registered with the executor.
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
                return Err(CrucibleArtifactError::UnverifiedModelSelection);
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

    use crucible::{Decision, DeliveryOrderDecision, SelectionDecision, VirtualTime};
    use crucible_campaign::{
        BooleanDomain, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain, ChoiceOpportunity,
        ChoiceSource, ChoiceValue, SelectableDeclaration, Selection, SelectionOrigin,
    };

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
