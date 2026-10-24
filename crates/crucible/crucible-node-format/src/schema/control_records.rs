//! Complete baseline control receipt payload records.

use super::*;

/// Selects terminal owned-resource custody after cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupDisposition {
    /// Requires proven native termination and release.
    Released,
    /// Requires authenticated nonnull supervisor custody.
    Quarantined,
    /// Retains declared live custody without claiming release.
    Retained,
}

/// Binds accepted input batches and complete pending custody.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputCustodyRecord {
    /// Selects baseline control-record schema 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the receiving execution owner.
    pub execution_owner_id: Id,
    /// Identifies the admitted owner generation.
    pub owner_generation: U64,
    /// Identifies the input custody epoch.
    pub input_epoch: Id,
    /// Records accepted input progress.
    pub input_watermark: U64,
    /// Lists accepted complete input-batch identities.
    pub batch_hashes: Vec<HashRef>,
    /// Binds complete pending input state.
    pub pending_inventory: ContentRef,
    /// Binds complete qualified native proof content.
    pub evidence_refs: Vec<ContentRef>,
    /// Carries record extensions.
    pub extensions: Extensions,
}

impl Validate for InputCustodyRecord {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        validate_sorted(
            &self.batch_hashes,
            |value| (value.domain.clone(), value.digest.clone()),
            "batch_hashes",
        )?;
        for value in &self.batch_hashes {
            value.validate()?;
        }
        self.pending_inventory.validate()?;
        validate_sorted(
            &self.evidence_refs,
            |value| (value.hash.domain.clone(), value.hash.digest.clone()),
            "evidence_refs",
        )?;
        for value in &self.evidence_refs {
            value.validate()?;
        }
        if self
            .batch_hashes
            .iter()
            .any(|hash| hash.domain != "cnp.input-batch.v1")
        {
            return Err(invalid("batch_hashes", "wrong input batch identity domain"));
        }
        Ok(())
    }
}

/// Records actual physical gate closure beneath prepared custody.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosedGateRecord {
    /// Selects baseline control-record schema 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the physically closed gate.
    pub gate_id: Id,
    /// Identifies authenticated prepared custody.
    pub prepared_token: Id,
    /// Lists every contained owner.
    pub owner_ids: IdSet,
    /// Must be true for this receipt kind.
    pub gate_closed: bool,
    /// Binds actual contained native activity.
    pub physical_status_ref: ContentRef,
    /// Binds complete qualified native proof content.
    pub evidence_refs: Vec<ContentRef>,
    /// Carries record extensions.
    pub extensions: Extensions,
}

impl Validate for ClosedGateRecord {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        validate_ids(&self.owner_ids, "owner_ids")?;
        if !self.gate_closed {
            return Err(invalid("gate_closed", "closed-gate receipt requires true"));
        }
        self.physical_status_ref.validate()?;
        validate_sorted(
            &self.evidence_refs,
            |value| (value.hash.domain.clone(), value.hash.digest.clone()),
            "evidence_refs",
        )?;
        for value in &self.evidence_refs {
            value.validate()?;
        }
        Ok(())
    }
}

/// Records complete owner readiness beneath a physically closed gate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationReadyRecord {
    /// Selects baseline control-record schema 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the proposed activation.
    pub activation_id: Id,
    /// Identifies the proposed world generation.
    pub world_generation: U64,
    /// Identifies the closed gate.
    pub gate_id: Id,
    /// Identifies prepared custody.
    pub prepared_token: Id,
    /// Commits to complete world compatibility.
    pub world_binding_hash: HashRef,
    /// Lists every prepared owner.
    pub owner_ids: IdSet,
    /// Must be true; readiness does not open the gate.
    pub gate_closed: bool,
    /// Binds complete qualified native proof content.
    pub evidence_refs: Vec<ContentRef>,
    /// Carries record extensions.
    pub extensions: Extensions,
}

impl Validate for ActivationReadyRecord {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.world_binding_hash.validate()?;
        if self.world_binding_hash.domain != "cnp.world-binding.v1" {
            return Err(invalid("world_binding_hash", "wrong world identity domain"));
        }
        validate_ids(&self.owner_ids, "owner_ids")?;
        if !self.gate_closed {
            return Err(invalid("gate_closed", "closed-gate receipt requires true"));
        }
        validate_sorted(
            &self.evidence_refs,
            |value| (value.hash.domain.clone(), value.hash.digest.clone()),
            "evidence_refs",
        )?;
        for value in &self.evidence_refs {
            value.validate()?;
        }
        Ok(())
    }
}

/// Records unchanged modeled state and complete progress counters.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnchangedCutRecord {
    /// Selects baseline control-record schema 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Locates the unchanged modeled boundary.
    pub cut: Position,
    /// Records the unchanged coordinator ordinal.
    pub event_ordinal: U64,
    /// Commits to modeled state before capture preparation.
    pub before_state_digest: HashRef,
    /// Commits to the identical modeled state after preparation.
    pub after_state_digest: HashRef,
    /// Binds complete pre-capture retirement and native event counters.
    pub before_progress_ref: ContentRef,
    /// Binds complete post-capture retirement and native event counters.
    pub after_progress_ref: ContentRef,
    /// Lists every owner covered by the proof.
    pub owner_ids: IdSet,
    /// Binds complete qualified native proof content.
    pub evidence_refs: Vec<ContentRef>,
    /// Carries record extensions.
    pub extensions: Extensions,
}

impl Validate for UnchangedCutRecord {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.cut.validate()?;
        self.before_state_digest.validate()?;
        self.after_state_digest.validate()?;
        self.before_progress_ref.validate()?;
        self.after_progress_ref.validate()?;
        validate_ids(&self.owner_ids, "owner_ids")?;
        validate_sorted(
            &self.evidence_refs,
            |value| (value.hash.domain.clone(), value.hash.digest.clone()),
            "evidence_refs",
        )?;
        for value in &self.evidence_refs {
            value.validate()?;
        }
        if self.before_state_digest != self.after_state_digest {
            return Err(invalid("state_digest", "unchanged-cut digests disagree"));
        }
        Ok(())
    }
}

/// Records terminal resource disposition with explicit supervision custody.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupRecord {
    /// Selects baseline control-record schema 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Lists every owner covered by cleanup.
    pub owner_ids: IdSet,
    /// Enumerates all processes, mappings, files, descriptors, and external authority.
    pub resource_inventory_ref: ContentRef,
    /// Selects proven release, supervised quarantine, or retention.
    pub disposition: CleanupDisposition,
    /// Binds authenticated supervisor custody, required for quarantine.
    #[serde(deserialize_with = "required_nullable")]
    pub supervisor_receipt: Option<ContentRef>,
    /// Binds complete qualified native proof content.
    pub evidence_refs: Vec<ContentRef>,
    /// Carries record extensions.
    pub extensions: Extensions,
}

impl Validate for CleanupRecord {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        validate_ids(&self.owner_ids, "owner_ids")?;
        self.resource_inventory_ref.validate()?;
        if let Some(value) = &self.supervisor_receipt {
            value.validate()?;
        }
        validate_sorted(
            &self.evidence_refs,
            |value| (value.hash.domain.clone(), value.hash.digest.clone()),
            "evidence_refs",
        )?;
        for value in &self.evidence_refs {
            value.validate()?;
        }
        if self.disposition == CleanupDisposition::Quarantined && self.supervisor_receipt.is_none()
        {
            return Err(invalid(
                "supervisor_receipt",
                "quarantine requires authenticated supervisor custody",
            ));
        }
        Ok(())
    }
}

/// Records host admission of exact artifacts, qualifications, and resource limits.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRecord {
    /// Selects baseline control-record schema 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the admitted realization.
    pub realization_id: Id,
    /// Lists admitted durable node-binding identities.
    pub binding_hashes: Vec<HashRef>,
    /// Commits to the admitted complete world.
    pub world_binding_hash: HashRef,
    /// Lists exact measured artifacts by ID.
    pub measured_artifacts: Vec<ArtifactIdentity>,
    /// Binds exact implementation and profile qualification.
    pub qualification_refs: Vec<ContentRef>,
    /// Records installed resource ceilings.
    pub resource_limits: ResourceLimits,
    /// Binds complete qualified native proof content.
    pub evidence_refs: Vec<ContentRef>,
    /// Carries record extensions.
    pub extensions: Extensions,
}

impl Validate for AdmissionRecord {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        validate_sorted(
            &self.binding_hashes,
            |value| (value.domain.clone(), value.digest.clone()),
            "binding_hashes",
        )?;
        for value in &self.binding_hashes {
            value.validate()?;
        }
        self.world_binding_hash.validate()?;
        if self.world_binding_hash.domain != "cnp.world-binding.v1" {
            return Err(invalid("world_binding_hash", "wrong world identity domain"));
        }
        validate_sorted(
            &self.measured_artifacts,
            |value| value.id.clone(),
            "measured_artifacts",
        )?;
        for value in &self.measured_artifacts {
            value.validate()?;
        }
        validate_sorted(
            &self.qualification_refs,
            |value| (value.hash.domain.clone(), value.hash.digest.clone()),
            "qualification_refs",
        )?;
        for value in &self.qualification_refs {
            value.validate()?;
        }
        self.resource_limits.validate()?;
        validate_sorted(
            &self.evidence_refs,
            |value| (value.hash.domain.clone(), value.hash.digest.clone()),
            "evidence_refs",
        )?;
        for value in &self.evidence_refs {
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
        Ok(())
    }
}
