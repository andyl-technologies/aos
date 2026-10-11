//! Portable descriptors records and their local schema invariants.

use super::*;

/// Binds a complete portable schema definition.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaRef {
    /// Names the schema.
    pub id: Id,
    /// Selects the positive schema edition.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub version: Version,
    /// Contains the complete verified schema and semantic specification.
    pub definition: ContentRef,
    /// Carries negotiated schema extensions.
    pub extensions: Extensions,
}

/// Declares an indivisible owner and its exact public membership.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerRef {
    /// Identifies the execution or capture owner.
    pub id: Id,
    /// Lists every public node controlled by this owner.
    pub participant_ids: IdSet,
    /// Lists every authoritative mutable state domain.
    pub state_domain_ids: IdSet,
}

/// Defines one unidirectional logical port lane.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneDescriptor {
    /// Identifies the lane within its port.
    pub id: Id,
    /// Selects input or output semantics.
    pub direction: Direction,
    /// Binds the complete portable payload schema.
    pub payload_schema: SchemaRef,
    /// Limits the bytes in one payload.
    pub maximum_payload_bytes: U64,
    /// Limits queued lane events.
    pub maximum_pending_events: U64,
    /// Carries identity-bearing lane extensions.
    pub extensions: Extensions,
}

/// Defines a logical interface and its selected features.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortDescriptor {
    /// Identifies the stable node-local port.
    pub id: Id,
    /// Lists lanes in strictly ascending ID order.
    pub lanes: Vec<LaneDescriptor>,
    /// Identifies the exact semantic interface family and version.
    pub interface_id: Id,
    /// Lists the selected realized features.
    pub features: IdSet,
    /// Binds ordering, flow-control, failure, and state semantics.
    pub configuration_ref: ContentRef,
    /// Carries identity-bearing port extensions.
    pub extensions: Extensions,
}

/// Describes immutable logical node identity independently of custody.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeDescriptor {
    /// Selects the baseline descriptor schema, version 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the semantic node.
    pub id: Id,
    /// Lists orthogonal role labels without implying capabilities.
    pub roles: IdSet,
    /// Binds the selected immutable model definition.
    pub model_ref: ContentRef,
    /// Binds all resolved semantic parameters.
    pub configuration_ref: ContentRef,
    /// Binds initialization inputs, policy, and provenance.
    pub initialization_ref: ContentRef,
    /// Lists ports in strictly ascending ID order.
    pub ports: Vec<PortDescriptor>,
    /// Carries identity-bearing descriptor extensions.
    pub extensions: Extensions,
}

/// Defines an admitted directed logical connection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionDescriptor {
    /// Selects the baseline connection schema, version 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the connection.
    pub id: Id,
    /// Selects the source output lane.
    pub producer: Endpoint,
    /// Selects the destination input lane.
    pub consumer: Endpoint,
    /// Names the exact compatible semantic interface.
    pub interface_id: Id,
    /// Lists admitted connection features.
    pub features: IdSet,
    /// Binds the exact connection payload schema.
    pub payload_schema: SchemaRef,
    /// Specifies literal minimum modeled latency, including zero.
    pub minimum_latency_ps: U64,
    /// Binds arbitration, conversion, fault, flow-control, and causal policy.
    pub policy_ref: ContentRef,
    /// Identifies the authoritative owner of connection state.
    pub capture_owner_id: Id,
    /// Carries identity-bearing connection extensions.
    pub extensions: Extensions,
}

impl Validate for SchemaRef {
    fn validate(&self) -> Result<(), ContractError> {
        self.definition.validate()?;
        if self.version == 0 {
            return Err(invalid("version", "zero schema/facet edition is forbidden"));
        }
        Ok(())
    }
}

impl Validate for OwnerRef {
    fn validate(&self) -> Result<(), ContractError> {
        validate_ids(&self.participant_ids, "participant_ids")?;
        validate_ids(&self.state_domain_ids, "state_domain_ids")?;
        Ok(())
    }
}

impl Validate for LaneDescriptor {
    fn validate(&self) -> Result<(), ContractError> {
        self.payload_schema.validate()?;
        Ok(())
    }
}

impl Validate for PortDescriptor {
    fn validate(&self) -> Result<(), ContractError> {
        validate_sorted(&self.lanes, |value| value.id.clone(), "lanes")?;
        for value in &self.lanes {
            value.validate()?;
        }
        validate_ids(&self.features, "features")?;
        self.configuration_ref.validate()?;
        Ok(())
    }
}

impl Validate for NodeDescriptor {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        validate_ids(&self.roles, "roles")?;
        self.model_ref.validate()?;
        self.configuration_ref.validate()?;
        self.initialization_ref.validate()?;
        validate_sorted(&self.ports, |value| value.id.clone(), "ports")?;
        for value in &self.ports {
            value.validate()?;
        }
        Ok(())
    }
}

impl NodeDescriptor {
    /// Validates and computes the complete durable CNP/1 identity.
    ///
    /// # Errors
    /// Rejects local schema violations and canonical serialization failures.
    pub fn identity(&self) -> Result<HashRef, ContractError> {
        self.validate()?;
        canonical::json_hash("cnp.node-descriptor.v1", self)
    }
}

impl Validate for ConnectionDescriptor {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        validate_ids(&self.features, "features")?;
        self.payload_schema.validate()?;
        self.policy_ref.validate()?;
        Ok(())
    }
}
