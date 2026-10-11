//! Versioned portable node scenarios and their campaign artifact identities.
//!
//! This format is separate from the legacy execution-model payload. A scenario
//! contains durable implementation choices and immutable policy bytes; live
//! authority is supplied by the local factory after native resources are owned.
//!
//! ```json
//! {"format":"crucible.node-scenario","version":1,"world":{},
//!  "descriptors":[],"compatibility":[],"owners":[],"requirements":{},
//!  "content":[]}
//! ```

use crucible::node_admission::{
    AdmissionEvidence, AdmissionLimits, AdmissionRequest, AdmittedGraph, EvidenceError,
    ScenarioRequirements, admit_graph,
};
use crucible_campaign::{
    CampaignCodecError, CampaignHash, ConfigurationArtifact, ConfigurationId, ScenarioArtifact,
    ScenarioDefId,
};
use crucible_node_contract::{
    BindingCompatibility, ContentRef, ContractError, NodeBinding, NodeDescriptor, OwnerBinding,
    U64, Validate, WorldBinding, canonical,
};
use serde::{Deserialize, Serialize};

/// Selects the independent campaign payload edition for node-contract scenarios.
pub const NODE_SCENARIO_PAYLOAD_SCHEMA: u32 = 25;
/// Bounds a complete authored/resolved scenario before JSON allocation.
pub const MAX_NODE_SCENARIO_BYTES: usize = 16 * 1024 * 1024;

/// Retains one immutable content object, authenticated by its CNP reference.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioContent {
    /// Commits to the complete bytes and selected media type.
    pub reference: ContentRef,
    /// Contains exact bytes as an unpadded base64url portable byte string.
    #[serde(with = "portable_bytes")]
    pub bytes: Vec<u8>,
}

/// Defines a complete node graph without conferring live native authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeScenario {
    /// Identifies this independent format, `crucible.node-scenario`.
    pub format: String,
    /// Selects format edition one.
    pub version: u16,
    /// Commits to the complete durable world and initialization policy.
    pub world: WorldBinding,
    /// Enumerates complete logical descriptors in strictly increasing ID order.
    pub descriptors: Vec<NodeDescriptor>,
    /// Selects each node's complete implementation, capabilities, and guarantees.
    pub compatibility: Vec<BindingCompatibility>,
    /// Enumerates every execution and capture owner in increasing ID order.
    pub owners: Vec<OwnerBinding>,
    /// Declares required guarantees and explicit weaker-contract acceptance.
    pub requirements: ScenarioRequirements,
    /// Retains all scenario-owned immutable policy/model/initialization bytes.
    pub content: Vec<ScenarioContent>,
}

/// Selects finite execution limits independently of native realization identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRunConfiguration {
    /// Identifies this independent format, `crucible.node-run-configuration`.
    pub format: String,
    /// Selects format edition one.
    pub version: u16,
    /// Gives the requested final physical time in picoseconds.
    pub horizon_ps: U64,
    /// Bounds completed dispatch rounds, including stalled-boundary settlements.
    pub maximum_rounds: U64,
}

/// Reports strict format, identity, immutable-content, or graph admission refusal.
#[derive(Debug, thiserror::Error)]
pub enum NodeScenarioError {
    /// The portable format or local schema is invalid.
    #[error(transparent)]
    Contract(#[from] ContractError),
    /// Campaign artifact construction or planned identity verification failed.
    #[error(transparent)]
    Campaign(#[from] CampaignCodecError),
    /// Complete graph admission refused the installed/live realization.
    #[error(transparent)]
    Admission(#[from] crucible::node_admission::AdmissionError),
    /// The independent scenario format or artifact relation is unsupported.
    #[error("node scenario refused: {0}")]
    Refused(&'static str),
    /// Typed portable serialization failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl NodeScenario {
    /// Parses a bounded strict JSON scenario without enabling a provider.
    ///
    /// # Errors
    /// Refuses unknown fields, duplicate keys, unsupported editions, invalid
    /// portable records, unsorted rosters, or unauthenticated content bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, NodeScenarioError> {
        let value = canonical::parse_json(bytes, MAX_NODE_SCENARIO_BYTES)?;
        let scenario: Self = serde_json::from_value(value)?;
        scenario.validate_format()?;
        Ok(scenario)
    }

    /// Encodes validated portable bytes without changing legacy artifact formats.
    ///
    /// # Errors
    /// Refuses an unsupported or invalid graph/content roster or oversized bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, NodeScenarioError> {
        self.validate_format()?;
        bounded_canonical(self)
    }

    /// Constructs the independent campaign artifact from its exact payload.
    ///
    /// # Errors
    /// Refuses invalid format/content, excessive bytes, or artifact construction.
    pub fn artifact(&self) -> Result<ScenarioArtifact, NodeScenarioError> {
        let payload = self.canonical_bytes()?;
        let identity =
            ScenarioDefId::from_hash(CampaignHash::derive("crucible.node-scenario.v1", &payload));
        Ok(ScenarioArtifact::new(
            identity,
            NODE_SCENARIO_PAYLOAD_SCHEMA,
            payload,
        )?)
    }

    /// Admits a complete local realization under host-installed evidence policy.
    ///
    /// `bindings` must come from resources already owned by the local factory.
    /// Their durable projection must exactly match the authored selection. The
    /// evidence implementation must authenticate those actual live resources.
    ///
    /// # Errors
    /// Refuses a changed durable selection, invalid content, or any closed graph
    /// admission failure. Parsing a scenario alone never qualifies its providers.
    pub fn admit(
        &self,
        bindings: &[NodeBinding],
        evidence: &dyn AdmissionEvidence,
        limits: AdmissionLimits,
    ) -> Result<AdmittedGraph, NodeScenarioError> {
        self.validate_format()?;
        if bindings.len() != self.compatibility.len()
            || bindings
                .iter()
                .zip(&self.compatibility)
                .any(|(actual, selected)| &actual.compatibility != selected)
        {
            return Err(NodeScenarioError::Refused(
                "live realization changed durable selection",
            ));
        }
        Ok(admit_graph(
            AdmissionRequest {
                world: &self.world,
                descriptors: &self.descriptors,
                bindings,
                owners: &self.owners,
                requirements: &self.requirements,
            },
            evidence,
            limits,
        )?)
    }

    /// Reads authenticated embedded content under the caller's allocation bound.
    ///
    /// # Errors
    /// Refuses absent content or a byte ceiling below the complete object's size.
    pub fn content_bytes(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        let object = self
            .content
            .iter()
            .find(|object| &object.reference == reference)
            .ok_or_else(|| EvidenceError {
                message: "scenario content is unavailable".into(),
            })?;
        if object.bytes.len() > maximum_bytes {
            return Err(EvidenceError {
                message: "scenario content exceeds fetch ceiling".into(),
            });
        }
        Ok(object.bytes.clone())
    }

    fn validate_format(&self) -> Result<(), NodeScenarioError> {
        if self.format != "crucible.node-scenario" || self.version != 1 {
            return Err(NodeScenarioError::Refused("unsupported scenario format"));
        }
        self.world.validate()?;
        if self.descriptors.is_empty()
            || self.descriptors.len() > 1024
            || self.compatibility.len() != self.descriptors.len()
            || self.owners.len() > 2048
            || self.content.len() > 16_384
        {
            return Err(NodeScenarioError::Refused(
                "scenario roster exceeds finite limits",
            ));
        }
        for descriptor in &self.descriptors {
            descriptor.validate()?;
        }
        for binding in &self.compatibility {
            binding.validate()?;
        }
        for owner in &self.owners {
            owner.validate()?;
        }
        if self
            .descriptors
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
            || self
                .compatibility
                .windows(2)
                .any(|pair| pair[0].node_id >= pair[1].node_id)
            || self
                .owners
                .windows(2)
                .any(|pair| pair[0].owner.id >= pair[1].owner.id)
            || self
                .descriptors
                .iter()
                .zip(&self.compatibility)
                .any(|(descriptor, binding)| descriptor.id != binding.node_id)
        {
            return Err(NodeScenarioError::Refused(
                "scenario rosters are not complete and sorted",
            ));
        }
        let mut total = 0usize;
        for object in &self.content {
            if object.bytes.len() > 4 * 1024 * 1024 {
                return Err(NodeScenarioError::Refused(
                    "immutable object exceeds content ceiling",
                ));
            }
            total = total
                .checked_add(object.bytes.len())
                .ok_or(NodeScenarioError::Refused(
                    "content byte accounting overflow",
                ))?;
            if total > MAX_NODE_SCENARIO_BYTES {
                return Err(NodeScenarioError::Refused(
                    "content roster exceeds total ceiling",
                ));
            }
            let measured = canonical::content_ref(&object.bytes, &object.reference.media_type)?;
            if measured != object.reference {
                return Err(NodeScenarioError::Refused(
                    "embedded content differs from its reference",
                ));
            }
        }
        if self.content.windows(2).any(|pair| {
            (
                &pair[0].reference.hash.domain,
                &pair[0].reference.hash.digest,
            ) >= (
                &pair[1].reference.hash.domain,
                &pair[1].reference.hash.digest,
            )
        }) {
            return Err(NodeScenarioError::Refused(
                "immutable content roster is not strictly sorted",
            ));
        }
        Ok(())
    }
}

impl NodeRunConfiguration {
    /// Parses bounded strict JSON execution limits for a node scenario.
    ///
    /// # Errors
    /// Refuses malformed/unknown fields, unsupported versions, or zero bounds.
    pub fn from_json(bytes: &[u8]) -> Result<Self, NodeScenarioError> {
        let value = canonical::parse_json(bytes, 4096)?;
        let configuration: Self = serde_json::from_value(value)?;
        configuration.validate_format()?;
        Ok(configuration)
    }

    /// Constructs configuration bytes bound to the exact node scenario artifact.
    ///
    /// # Errors
    /// Refuses invalid execution bounds, invalid scenario payloads, or artifact
    /// construction failure. No legacy configuration is converted implicitly.
    pub fn artifact(
        &self,
        scenario: &NodeScenario,
    ) -> Result<ConfigurationArtifact, NodeScenarioError> {
        self.validate_format()?;
        let scenario = scenario.artifact()?;
        let payload = bounded_canonical(self)?;
        let identity = ConfigurationId::from_hash(CampaignHash::derive(
            "crucible.node-run-configuration.v1",
            &payload,
        ));
        Ok(ConfigurationArtifact::new(
            scenario.scenario(),
            scenario.id()?,
            identity,
            NODE_SCENARIO_PAYLOAD_SCHEMA,
            payload,
        )?)
    }

    fn validate_format(&self) -> Result<(), NodeScenarioError> {
        if self.format != "crucible.node-run-configuration"
            || self.version != 1
            || self.horizon_ps.get() == 0
            || self.maximum_rounds.get() == 0
            || self.maximum_rounds.get() > 65_536
        {
            return Err(NodeScenarioError::Refused(
                "unsupported or unbounded run configuration",
            ));
        }
        Ok(())
    }
}

fn bounded_canonical(value: &impl Serialize) -> Result<Vec<u8>, NodeScenarioError> {
    let bytes = canonical::canonical_json(&serde_json::to_value(value)?)?;
    if bytes.len() > MAX_NODE_SCENARIO_BYTES {
        return Err(NodeScenarioError::Refused(
            "scenario payload exceeds byte ceiling",
        ));
    }
    Ok(bytes)
}

mod portable_bytes {
    //! Uses the portable byte-string codec without exposing internal allocations.

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        crucible_node_contract::Bytes::new(bytes.to_vec()).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        Ok(crucible_node_contract::Bytes::deserialize(deserializer)?.into_vec())
    }
}
