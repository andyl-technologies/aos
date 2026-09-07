//! Exact scenario and configuration payloads retained by a campaign lineage.
//!
//! These records bind Crucible's semantic scenario/configuration identities to
//! the exact canonical execution-model bytes needed for replay. The campaign
//! layer does not reinterpret those bytes; the owning execution-model adapter
//! verifies the semantic identity before publication.

use std::collections::BTreeSet;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::{
    CampaignCodecError, ConfigurationArtifactId, ConfigurationId, ScenarioArtifactId, ScenarioDefId,
};

const ARTIFACT_SCHEMA_VERSION: u32 = 1;
const MAX_EXECUTION_MODEL_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

/// Exact canonical scenario-definition payload bound to its semantic identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioArtifact {
    schema_version: u32,
    scenario: ScenarioDefId,
    payload_schema: u32,
    payload: Vec<u8>,
}

impl ScenarioArtifact {
    /// Builds a bounded exact scenario artifact after execution-model verification.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a zero payload schema, an empty
    /// payload, or a payload above 32 MiB.
    pub fn new(
        scenario: ScenarioDefId,
        payload_schema: u32,
        payload: Vec<u8>,
    ) -> Result<Self, CampaignCodecError> {
        validate_payload(payload_schema, &payload)?;
        Ok(Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            scenario,
            payload_schema,
            payload,
        })
    }

    /// Returns the semantic scenario identity verified by the execution model.
    #[must_use]
    pub const fn scenario(&self) -> ScenarioDefId {
        self.scenario
    }

    /// Returns the execution-model payload schema.
    #[must_use]
    pub const fn payload_schema(&self) -> u32 {
        self.payload_schema
    }

    /// Returns the exact canonical execution-model bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the exact stored record identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<ScenarioArtifactId, CampaignCodecError> {
        let envelope = crate::ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ScenarioArtifact,
            BTreeSet::new(),
            codec::encode(self),
        )?;
        ScenarioArtifactId::from_content_id(envelope.content_id())
    }

    /// Returns strict canonical record-body bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical record-body bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, invalid, or
    /// oversized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_EXECUTION_MODEL_PAYLOAD_BYTES + 1024 {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "scenario-artifact-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }
}

impl Canonical for ScenarioArtifact {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.scenario.encode(encoder);
        self.payload_schema.encode(encoder);
        self.payload.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_artifact_schema(u32::decode(decoder)?)?;
        Self::new(
            ScenarioDefId::decode(decoder)?,
            u32::decode(decoder)?,
            decoder.sequence_bounded(
                MAX_EXECUTION_MODEL_PAYLOAD_BYTES,
                "scenario-artifact-payload-bytes",
                u8::decode,
            )?,
        )
    }
}

/// Exact canonical configuration payload bound to scenario and configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigurationArtifact {
    schema_version: u32,
    scenario: ScenarioDefId,
    scenario_artifact: ScenarioArtifactId,
    configuration: ConfigurationId,
    payload_schema: u32,
    payload: Vec<u8>,
}

impl ConfigurationArtifact {
    /// Builds a bounded exact configuration artifact after model verification.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a zero payload schema, an empty
    /// payload, or a payload above 32 MiB.
    pub fn new(
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        payload_schema: u32,
        payload: Vec<u8>,
    ) -> Result<Self, CampaignCodecError> {
        validate_payload(payload_schema, &payload)?;
        Ok(Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            scenario,
            scenario_artifact,
            configuration,
            payload_schema,
            payload,
        })
    }

    /// Returns the semantic scenario identity.
    #[must_use]
    pub const fn scenario(&self) -> ScenarioDefId {
        self.scenario
    }

    /// Returns the exact scenario artifact this configuration uses.
    #[must_use]
    pub const fn scenario_artifact(&self) -> ScenarioArtifactId {
        self.scenario_artifact
    }

    /// Returns the semantic configuration identity verified by the model.
    #[must_use]
    pub const fn configuration(&self) -> ConfigurationId {
        self.configuration
    }

    /// Returns the execution-model payload schema.
    #[must_use]
    pub const fn payload_schema(&self) -> u32 {
        self.payload_schema
    }

    /// Returns the exact canonical execution-model bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(crate) fn content_children(
        &self,
    ) -> [(&'static str, crucible_cas::content_store::ContentId); 1] {
        [("scenario", self.scenario_artifact.content_id())]
    }

    /// Returns the exact stored record identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<ConfigurationArtifactId, CampaignCodecError> {
        let envelope = crate::ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ConfigurationArtifact,
            crate::object::content_children(self.content_children())?,
            codec::encode(self),
        )?;
        ConfigurationArtifactId::from_content_id(envelope.content_id())
    }

    /// Returns strict canonical record-body bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical record-body bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, invalid, or
    /// oversized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_EXECUTION_MODEL_PAYLOAD_BYTES + 1024 {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "configuration-artifact-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }
}

impl Canonical for ConfigurationArtifact {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.scenario.encode(encoder);
        self.scenario_artifact.encode(encoder);
        self.configuration.encode(encoder);
        self.payload_schema.encode(encoder);
        self.payload.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_artifact_schema(u32::decode(decoder)?)?;
        Self::new(
            ScenarioDefId::decode(decoder)?,
            ScenarioArtifactId::decode(decoder)?,
            ConfigurationId::decode(decoder)?,
            u32::decode(decoder)?,
            decoder.sequence_bounded(
                MAX_EXECUTION_MODEL_PAYLOAD_BYTES,
                "configuration-artifact-payload-bytes",
                u8::decode,
            )?,
        )
    }
}

fn validate_payload(schema: u32, payload: &[u8]) -> Result<(), CampaignCodecError> {
    if schema == 0 || payload.is_empty() {
        return Err(CampaignCodecError::InvalidValue {
            reason: "execution-model artifact has zero schema or empty payload",
        });
    }
    if payload.len() > MAX_EXECUTION_MODEL_PAYLOAD_BYTES {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "execution-model-artifact-payload-bytes",
        });
    }
    Ok(())
}

fn require_artifact_schema(actual: u32) -> Result<(), CampaignCodecError> {
    if actual == ARTIFACT_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported execution-model-artifact schema version",
        })
    }
}
