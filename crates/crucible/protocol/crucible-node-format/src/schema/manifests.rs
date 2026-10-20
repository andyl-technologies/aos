//! Portable manifests records and their local schema invariants.

use super::*;

/// Advertises a selected provider profile with complete schema content.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeManifest {
    /// Selects the baseline node-manifest schema, version 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the advertised profile.
    pub profile_id: Id,
    /// Lists orthogonal supported role labels.
    pub roles: IdSet,
    /// Binds the complete profile configuration schema.
    pub configuration_schema: SchemaRef,
    /// Binds allowed mode, device, and facet combinations.
    pub allowed_combinations_ref: ContentRef,
    /// Binds complete realized-port templates.
    pub port_templates_ref: ContentRef,
    /// Lists supported state formats by ID and version.
    pub state_formats: Vec<SchemaRef>,
    /// Lists supported operation facets by ID and version.
    pub operation_facets: Vec<FacetSelection>,
    /// Carries manifest extensions.
    pub extensions: Extensions,
}

/// Advertises an implementation with explicitly qualified profile support.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderManifest {
    /// Selects the baseline provider-manifest schema, version 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the provider.
    pub provider_id: Id,
    /// Binds all implementation artifacts and formats.
    pub implementation: ImplementationIdentity,
    /// Lists admitted protocol version identifiers.
    pub protocol_versions: IdSet,
    /// Lists supported profiles by profile ID.
    pub supported_profiles: Vec<NodeManifest>,
    /// Lists explicitly supported extension identifiers.
    pub extensions_supported: IdSet,
    /// Lists exact profile qualification evidence.
    pub qualification_refs: Vec<ContentRef>,
    /// Carries provider manifest extensions.
    pub extensions: Extensions,
}

/// Describes the complete realized graph before host admission.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealizationManifest {
    /// Selects the baseline realization schema, version 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the proposed realization.
    pub realization_id: Id,
    /// Binds the provider manifest content.
    pub provider_manifest: ContentRef,
    /// Lists realized descriptors by node ID.
    pub descriptors: Vec<NodeDescriptor>,
    /// Lists proposed bindings by semantic node ID.
    pub bindings: Vec<NodeBinding>,
    /// Lists every execution and capture owner by owner ID.
    pub owners: Vec<OwnerRef>,
    /// Lists complete owner bindings by owner ID.
    pub owner_bindings: Vec<OwnerBinding>,
    /// Carries realization extensions.
    pub extensions: Extensions,
}

/// Bounds provider resources without interpreting zero as unlimited.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// Limits actual hardware execution budget in nanoseconds.
    pub cpu_budget_ns: U64,
    /// Limits resident and reserved memory bytes.
    pub memory_bytes: U64,
    /// Limits writable storage bytes.
    pub writable_bytes: U64,
    /// Limits owned process count.
    pub processes: U64,
    /// Limits owned file descriptor count.
    pub descriptors: U64,
    /// Limits pending event count.
    pub pending_events: U64,
    /// Limits portable content bytes.
    pub content_bytes: U64,
    /// Limits accepted operation count.
    pub maximum_operations: U64,
    /// Carries separately admitted resource-limit extensions.
    pub extensions: Extensions,
}

impl Validate for NodeManifest {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        validate_ids(&self.roles, "roles")?;
        self.configuration_schema.validate()?;
        self.allowed_combinations_ref.validate()?;
        self.port_templates_ref.validate()?;
        validate_sorted(
            &self.state_formats,
            |value| (value.id.clone(), value.version),
            "state_formats",
        )?;
        for value in &self.state_formats {
            value.validate()?;
        }
        validate_sorted(
            &self.operation_facets,
            |value| (value.id.clone(), value.version),
            "operation_facets",
        )?;
        for value in &self.operation_facets {
            value.validate()?;
        }
        Ok(())
    }
}

impl Validate for ProviderManifest {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.implementation.validate()?;
        validate_ids(&self.protocol_versions, "protocol_versions")?;
        validate_sorted(
            &self.supported_profiles,
            |value| value.profile_id.clone(),
            "supported_profiles",
        )?;
        for value in &self.supported_profiles {
            value.validate()?;
        }
        validate_ids(&self.extensions_supported, "extensions_supported")?;
        validate_sorted(
            &self.qualification_refs,
            |value| (value.hash.domain.clone(), value.hash.digest.clone()),
            "qualification_refs",
        )?;
        for value in &self.qualification_refs {
            value.validate()?;
        }
        Ok(())
    }
}

impl Validate for RealizationManifest {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.provider_manifest.validate()?;
        validate_sorted(&self.descriptors, |value| value.id.clone(), "descriptors")?;
        for value in &self.descriptors {
            value.validate()?;
        }
        validate_sorted(
            &self.bindings,
            |value| value.compatibility.node_id.clone(),
            "bindings",
        )?;
        for value in &self.bindings {
            value.validate()?;
        }
        validate_sorted(&self.owners, |value| value.id.clone(), "owners")?;
        for value in &self.owners {
            value.validate()?;
        }
        validate_sorted(
            &self.owner_bindings,
            |value| value.owner.id.clone(),
            "owner_bindings",
        )?;
        for value in &self.owner_bindings {
            value.validate()?;
        }
        Ok(())
    }
}

impl Validate for ResourceLimits {
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}
