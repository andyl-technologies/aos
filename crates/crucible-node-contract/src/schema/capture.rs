//! Portable capture schemas and local integrity checks.
//!
//! ```json
//! { "schema_version": 1, "extensions": {} }
//! ```
//!
//! Complete objects require every field defined by RFC-0025; reference content
//! and live custody are verified separately by host admission.

use super::*;

/// Selects the authoritative preservation representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureRepresentation {
    /// Preserves complete portable restart content.
    Durable,
    /// Preserves authenticated live custody without implying durable restart.
    RetainedSource,
}

/// Commits to the complete world continuation boundary and authoritative domains.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureManifest {
    /// Selects baseline capture-manifest schema 1.
    pub schema_version: Version,
    /// Identifies this complete capture.
    pub capture_id: Id,
    /// Commits to complete world compatibility.
    pub world_binding_hash: HashRef,
    /// Binds the scenario identity.
    pub scenario_ref: ContentRef,
    /// Names the selected complete preservation contract.
    pub preservation_contract: Id,
    /// Locates the unchanged coherent capture boundary.
    pub cut: Position,
    /// Preserves the coordinator event ordinal.
    pub event_ordinal: U64,
    /// Names the admitted ordering profile, superdense-v1.
    pub ordering_profile: String,
    /// Binds capture guarantees and nondeterminism limitations.
    pub guarantees_ref: ContentRef,
    /// Binds the complete coordinator continuation state.
    pub coordinator_state_ref: ContentRef,
    /// Lists every authoritative capture owner by owner ID.
    pub owners: Vec<CapturedOwner>,
    /// Lists all immutable dependencies by domain and digest.
    pub immutable_refs: Vec<ContentRef>,
    /// Binds capture provenance and input history.
    pub provenance_ref: ContentRef,
    /// Carries identity-bearing capture extensions.
    pub extensions: Extensions,
}

/// Preserves one authoritative owner using durable bytes or an authenticated live lease.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedOwner {
    /// Identifies the authoritative capture owner.
    pub capture_owner_id: Id,
    /// Lists all public participants in this capture.
    pub participant_ids: IdSet,
    /// Lists exact authoritative mutable domain coverage.
    pub state_domain_ids: IdSet,
    /// Lists participant binding hashes by domain and digest.
    pub binding_hashes: Vec<HashRef>,
    /// Binds complete versioned native state semantics.
    pub state_schema: SchemaRef,
    /// Selects durable content or retained-source lease.
    pub representation: CaptureRepresentation,
    /// Binds durable state, or explicit null for a retained source.
    #[serde(deserialize_with = "required_nullable")]
    pub state_ref: Option<ContentRef>,
    /// Binds authenticated retained custody and expiry, or explicit null for durable state.
    #[serde(deserialize_with = "required_nullable")]
    pub retained_source_ref: Option<ContentRef>,
    /// Lists required owner dependencies.
    pub dependencies: IdSet,
    /// Binds unchanged-cut and complete-domain proof.
    pub capture_receipt: ContentRef,
    /// Carries owner capture extensions.
    pub extensions: Extensions,
}

impl Validate for CaptureManifest {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.world_binding_hash.validate()?;
        if self.world_binding_hash.domain != "cnp.world-binding.v1" {
            return Err(invalid("world_binding_hash", "wrong world identity domain"));
        }
        self.scenario_ref.validate()?;
        self.cut.validate()?;
        if self.ordering_profile != "superdense-v1" {
            return Err(invalid("ordering_profile", "unsupported ordering profile"));
        }
        self.guarantees_ref.validate()?;
        self.coordinator_state_ref.validate()?;
        validate_sorted(
            &self.owners,
            |value| value.capture_owner_id.clone(),
            "owners",
        )?;
        for value in &self.owners {
            value.validate()?;
        }
        validate_sorted(
            &self.immutable_refs,
            |value| (value.hash.domain.clone(), value.hash.digest.clone()),
            "immutable_refs",
        )?;
        for value in &self.immutable_refs {
            value.validate()?;
        }
        self.provenance_ref.validate()?;
        Ok(())
    }
}

impl Validate for CapturedOwner {
    fn validate(&self) -> Result<(), ContractError> {
        validate_ids(&self.participant_ids, "participant_ids")?;
        validate_ids(&self.state_domain_ids, "state_domain_ids")?;
        validate_sorted(
            &self.binding_hashes,
            |value| (value.domain.clone(), value.digest.clone()),
            "binding_hashes",
        )?;
        for value in &self.binding_hashes {
            value.validate()?;
        }
        if self
            .binding_hashes
            .iter()
            .any(|hash| hash.domain != "cnp.node-binding.v1")
        {
            return Err(invalid(
                "binding_hashes",
                "wrong node-binding identity domain",
            ));
        }
        self.state_schema.validate()?;
        if let Some(value) = &self.state_ref {
            value.validate()?;
        }
        if let Some(value) = &self.retained_source_ref {
            value.validate()?;
        }
        validate_ids(&self.dependencies, "dependencies")?;
        self.capture_receipt.validate()?;
        match self.representation {
            CaptureRepresentation::Durable
                if self.state_ref.is_some() && self.retained_source_ref.is_none() => {}
            CaptureRepresentation::RetainedSource
                if self.state_ref.is_none() && self.retained_source_ref.is_some() => {}
            _ => {
                return Err(invalid(
                    "representation",
                    "exactly one matching state representation must be nonnull",
                ));
            }
        }
        Ok(())
    }
}
