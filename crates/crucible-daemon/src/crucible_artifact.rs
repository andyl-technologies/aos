//! Strict Crucible execution-model payloads carried by campaign artifacts.
//!
//! The campaign repository treats scenario and configuration payloads as
//! opaque, language-neutral byte strings. This module owns payload schema 1:
//!
//! ```text
//! CrucibleScenarioPayloadV1      = ScenarioDefForm compact binary V5
//! CrucibleConfigurationPayloadV1 = Schedule compact binary V1
//! ```
//!
//! Decoding re-derives both semantic identities before a live session or QEMU
//! process can consume the values.

use crucible::{Configuration, ScenarioDefForm, Schedule};
use crucible_campaign::{
    CampaignCodecError, CampaignHash, ConfigurationArtifact, ConfigurationId, ScenarioArtifact,
    ScenarioDefId,
};

/// Payload schema for a compact canonical Crucible scenario definition.
pub const CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V1: u32 = 1;
/// Payload schema for a compact canonical Crucible configuration schedule.
pub const CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V1: u32 = 1;

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
        CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V1,
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
        CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V1,
    )?;
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
    use crucible::{Decision, DeliveryOrderDecision, VirtualTime};

    use super::*;

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
    }
}
