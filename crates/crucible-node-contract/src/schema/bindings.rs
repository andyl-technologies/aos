//! Portable bindings records and their local schema invariants.

use super::*;

/// Identifies an executable, adapter, patch set, or model input by bytes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    /// Identifies the artifact within the implementation.
    pub id: Id,
    /// Names its implementation role.
    pub role: Id,
    /// Commits to exact artifact bytes.
    pub content: ContentRef,
    /// Carries identity-bearing artifact extensions.
    pub extensions: Extensions,
}

/// Binds all artifacts and formats affecting implementation compatibility.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationIdentity {
    /// Selects the baseline implementation schema, version 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the selected implementation family.
    pub implementation_id: Id,
    /// Lists exact implementation artifacts by ID.
    pub artifacts: Vec<ArtifactIdentity>,
    /// Lists model-definition content sorted by domain and digest.
    pub model_definitions: Vec<ContentRef>,
    /// Lists complete state or protocol schemas by ID and version.
    pub formats: Vec<SchemaRef>,
    /// Carries identity-bearing implementation extensions.
    pub extensions: Extensions,
}

/// Commits to durable node compatibility independently of live authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingCompatibility {
    /// Selects the baseline binding schema, version 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the descriptor node.
    pub node_id: Id,
    /// Commits to the complete immutable descriptor.
    pub descriptor_hash: HashRef,
    /// Binds the selected artifacts and formats.
    pub implementation: ImplementationIdentity,
    /// Binds the full selected machine, device, or model profile.
    pub profile_ref: ContentRef,
    /// Binds all resolved compatibility parameters.
    pub configuration_ref: ContentRef,
    /// Binds timing, scheduling, and selected facets.
    pub operating_contract: OperatingContract,
    /// Declares indivisible execution membership and domains.
    pub execution_owner: OwnerRef,
    /// Declares authoritative capture membership and domains.
    pub capture_owner: OwnerRef,
    /// Binds the realized capability profile.
    pub capabilities_ref: ContentRef,
    /// Binds the orthogonal guarantee profile.
    pub guarantees_ref: ContentRef,
    /// Lists the exact implementation and profile qualification basis.
    pub qualification_refs: Vec<ContentRef>,
    /// Carries durable identity-bearing extension parameters.
    pub extensions: Extensions,
}

/// Records live custody claims requiring authenticated host admission.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveAuthority {
    /// Selects the baseline authority schema, version 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the admitted session.
    pub session_id: Id,
    /// Identifies the fresh live owner incarnation.
    pub incarnation_id: Id,
    /// Identifies the admitted realization.
    pub realization_id: Id,
    /// Identifies the selected activation, or explicit null before activation.
    #[serde(deserialize_with = "required_nullable")]
    pub activation_id: Option<Id>,
    /// Identifies the world generation; zero is initially uncommitted.
    pub world_generation: U64,
    /// Identifies the positive live owner generation.
    pub owner_generation: U64,
    /// Identifies the authenticated input custody epoch.
    pub input_epoch: Id,
    /// Binds the host admission record; syntax alone confers no authority.
    pub host_receipt: ContentRef,
    /// Carries negotiated operational extensions.
    pub extensions: Extensions,
}

/// Combines durable compatibility and separately authenticated live custody.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeBinding {
    /// Contains the sole durable node-binding hash projection.
    pub compatibility: BindingCompatibility,
    /// Contains separately authenticated live authority.
    pub authority: LiveAuthority,
    /// Carries operational extensions excluded from durable compatibility.
    pub extensions: Extensions,
}

/// Names a node and its durable admitted binding identity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeBindingRef {
    /// Identifies the semantic node.
    pub node_id: Id,
    /// Commits to its complete durable compatibility projection.
    pub binding_hash: HashRef,
    /// Carries identity-bearing reference extensions.
    pub extensions: Extensions,
}

/// Commits to the complete roster and constraints of one owner.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerBinding {
    /// Selects the baseline owner schema, version 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Declares participants and authoritative state domains.
    pub owner: OwnerRef,
    /// Selects execution, capture, or both roles.
    pub owner_roles: IdSet,
    /// Lists every participant binding by node ID.
    pub node_bindings: Vec<NodeBindingRef>,
    /// Binds indivisible ownership constraints.
    pub ownership_ref: ContentRef,
    /// Carries identity-bearing owner extensions.
    pub extensions: Extensions,
}

/// Commits to the complete immutable graph and coordinator contract.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldBinding {
    /// Selects the baseline world schema, version 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Binds the complete scenario identity.
    pub scenario_ref: ContentRef,
    /// Lists every admitted node binding by node ID.
    pub node_bindings: Vec<NodeBindingRef>,
    /// Lists admitted connections by ID.
    pub connections: Vec<ConnectionDescriptor>,
    /// Binds unique state domains and all owner dependencies.
    pub ownership_ref: ContentRef,
    /// Binds timing, preservation, arbitration, and compatibility schemas.
    pub coordinator_contract_ref: ContentRef,
    /// Names the admitted ordering profile, superdense-v1.
    pub ordering_profile: String,
    /// Binds initialization policy and provenance.
    pub initialization_ref: ContentRef,
    /// Carries identity-bearing world extensions.
    pub extensions: Extensions,
}

impl Validate for ArtifactIdentity {
    fn validate(&self) -> Result<(), ContractError> {
        self.content.validate()?;
        Ok(())
    }
}

impl Validate for ImplementationIdentity {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        validate_sorted(&self.artifacts, |value| value.id.clone(), "artifacts")?;
        for value in &self.artifacts {
            value.validate()?;
        }
        validate_sorted(
            &self.model_definitions,
            |value| (value.hash.domain.clone(), value.hash.digest.clone()),
            "model_definitions",
        )?;
        for value in &self.model_definitions {
            value.validate()?;
        }
        validate_sorted(
            &self.formats,
            |value| (value.id.clone(), value.version),
            "formats",
        )?;
        for value in &self.formats {
            value.validate()?;
        }
        Ok(())
    }
}

impl Validate for BindingCompatibility {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.descriptor_hash.validate()?;
        self.implementation.validate()?;
        self.profile_ref.validate()?;
        self.configuration_ref.validate()?;
        self.operating_contract.validate()?;
        self.execution_owner.validate()?;
        self.capture_owner.validate()?;
        self.capabilities_ref.validate()?;
        self.guarantees_ref.validate()?;
        validate_sorted(
            &self.qualification_refs,
            |value| (value.hash.domain.clone(), value.hash.digest.clone()),
            "qualification_refs",
        )?;
        for value in &self.qualification_refs {
            value.validate()?;
        }
        if self.descriptor_hash.domain != "cnp.node-descriptor.v1" {
            return Err(invalid(
                "descriptor_hash",
                "wrong descriptor identity domain",
            ));
        }
        if !self.execution_owner.participant_ids.contains(&self.node_id)
            || !self.capture_owner.participant_ids.contains(&self.node_id)
        {
            return Err(invalid(
                "node_id",
                "node missing from execution or capture owner roster",
            ));
        }
        Ok(())
    }
}

impl BindingCompatibility {
    /// Validates and computes the complete durable CNP/1 identity.
    ///
    /// # Errors
    /// Rejects local schema violations and canonical serialization failures.
    pub fn identity(&self) -> Result<HashRef, ContractError> {
        self.validate()?;
        canonical::json_hash("cnp.node-binding.v1", self)
    }
}

impl Validate for LiveAuthority {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.host_receipt.validate()?;
        if self.owner_generation.get() == 0 {
            return Err(invalid(
                "owner_generation",
                "live owner generation must be positive",
            ));
        }
        Ok(())
    }
}

impl Validate for NodeBinding {
    fn validate(&self) -> Result<(), ContractError> {
        self.compatibility.validate()?;
        self.authority.validate()?;
        Ok(())
    }
}

impl NodeBinding {
    /// Computes durable compatibility identity without live authority or wrapper extensions.
    ///
    /// # Errors
    /// Rejects invalid compatibility records or canonical serialization failures.
    pub fn identity(&self) -> Result<HashRef, ContractError> {
        self.compatibility.identity()
    }
}

impl Validate for NodeBindingRef {
    fn validate(&self) -> Result<(), ContractError> {
        self.binding_hash.validate()?;
        if self.binding_hash.domain != "cnp.node-binding.v1" {
            return Err(invalid(
                "binding_hash",
                "wrong node-binding identity domain",
            ));
        }
        Ok(())
    }
}

impl Validate for OwnerBinding {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.owner.validate()?;
        validate_ids(&self.owner_roles, "owner_roles")?;
        validate_sorted(
            &self.node_bindings,
            |value| value.node_id.clone(),
            "node_bindings",
        )?;
        for value in &self.node_bindings {
            value.validate()?;
        }
        self.ownership_ref.validate()?;
        if self.owner_roles.is_empty()
            || self
                .owner_roles
                .iter()
                .any(|role| !matches!(role.as_str(), "execution" | "capture"))
        {
            return Err(invalid(
                "owner_roles",
                "expected execution, capture, or both",
            ));
        }
        let participants: Vec<_> = self
            .node_bindings
            .iter()
            .map(|binding| binding.node_id.clone())
            .collect();
        if participants != self.owner.participant_ids {
            return Err(invalid(
                "node_bindings",
                "binding roster must equal owner participants",
            ));
        }
        Ok(())
    }
}

impl OwnerBinding {
    /// Validates and computes the complete durable CNP/1 identity.
    ///
    /// # Errors
    /// Rejects local schema violations and canonical serialization failures.
    pub fn identity(&self) -> Result<HashRef, ContractError> {
        self.validate()?;
        canonical::json_hash("cnp.owner-binding.v1", self)
    }
}

impl Validate for WorldBinding {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.scenario_ref.validate()?;
        validate_sorted(
            &self.node_bindings,
            |value| value.node_id.clone(),
            "node_bindings",
        )?;
        for value in &self.node_bindings {
            value.validate()?;
        }
        validate_sorted(&self.connections, |value| value.id.clone(), "connections")?;
        for value in &self.connections {
            value.validate()?;
        }
        self.ownership_ref.validate()?;
        self.coordinator_contract_ref.validate()?;
        self.initialization_ref.validate()?;
        if self.ordering_profile != "superdense-v1" {
            return Err(invalid("ordering_profile", "unsupported ordering profile"));
        }
        Ok(())
    }
}

impl WorldBinding {
    /// Validates and computes the complete durable CNP/1 identity.
    ///
    /// # Errors
    /// Rejects local schema violations and canonical serialization failures.
    pub fn identity(&self) -> Result<HashRef, ContractError> {
        self.validate()?;
        canonical::json_hash("cnp.world-binding.v1", self)
    }
}
