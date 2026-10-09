//! Portable receipts schemas and local integrity checks.
//!
//! ```json
//! { "schema_version": 1, "extensions": {} }
//! ```
//!
//! Complete objects require every field defined by RFC-0025; reference content
//! and live custody are verified separately by host admission.

use super::*;

/// States actual physical stop or containment status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhysicalStop {
    /// Has physically paused all admitted activity.
    Paused,
    /// Has preserved an unresolved input boundary.
    InputBlocked,
    /// Has closed observation while autonomous activity may continue.
    ObservationClosed,
    /// Has failed under proven containment.
    FailedContained,
}

/// Selects a complete baseline control receipt record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlReceiptKind {
    /// Records accepted input custody.
    InputCustody,
    /// Records a physically closed activation gate.
    ClosedGate,
    /// Records prepared owner readiness beneath a closed gate.
    ActivationReady,
    /// Records unchanged modeled state and progress.
    UnchangedCut,
    /// Records terminal resource disposition and supervision.
    Cleanup,
    /// Records authenticated host admission.
    Admission,
}

/// Distinguishes provider claims from host-authenticated authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptIssuer {
    /// Contains a provider-issued claim.
    Provider,
    /// Contains an authenticated host record.
    Host,
}

/// Records physical stop status and independently justified production closure.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopReceipt {
    /// Selects baseline stop-receipt schema 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the admitted session.
    pub session_id: Id,
    /// Identifies the live provider incarnation.
    pub incarnation_id: Id,
    /// Commits to complete owner compatibility.
    pub owner_binding_hash: HashRef,
    /// Commits to world compatibility.
    pub world_binding_hash: HashRef,
    /// Identifies the admitted activation.
    pub activation_id: Id,
    /// Identifies the world generation.
    pub world_generation: U64,
    /// Identifies the execution owner.
    pub execution_owner_id: Id,
    /// Identifies the owner generation.
    pub owner_generation: U64,
    /// Identifies the originating operation.
    pub operation_id: Id,
    /// Retains grant identity, or explicit null for a nongrant operation.
    #[serde(deserialize_with = "required_nullable")]
    pub grant_id: Option<Id>,
    /// Lists every controlled public participant.
    pub participant_ids: IdSet,
    /// Names the selected timing mode.
    pub mode: OperatingMode,
    /// Names the admitted ordering profile, superdense-v1.
    pub ordering_profile: String,
    /// Locates execution progress; null requires an autonomous observation contract.
    #[serde(deserialize_with = "required_nullable")]
    pub reached: Option<Position>,
    /// Locates independently justified production closure.
    pub production_prefix: Position,
    /// Selects inclusive or exclusive closure.
    pub prefix_kind: ClosureKind,
    /// Lists each output lane bound by endpoint.
    pub output_lower_bounds: Vec<PortBound>,
    /// States actual physical containment without inferring semantic closure.
    pub physical_stop: PhysicalStop,
    /// Identifies the qualified stop cause.
    pub cause: Id,
    /// Binds actual input stream custody.
    pub input_custody: ContentRef,
    /// Binds complete pending state.
    pub pending_inventory: ContentRef,
    /// Binds staged or committed observations.
    pub observation_batch: ContentRef,
    /// Binds physical stop measurements and uncertainty.
    pub physical_measurement_ref: ContentRef,
    /// Binds selected native proof content.
    pub evidence_refs: Vec<ContentRef>,
    /// Carries stop-receipt extensions.
    pub extensions: Extensions,
}

/// Binds qualified lookahead to exactly one logical output lane.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortBound {
    /// Identifies the precise output lane.
    pub endpoint: Endpoint,
    /// Contains its qualified lower bound or explicit unknown.
    pub bound: Bound,
    /// Carries per-port bound extensions.
    pub extensions: Extensions,
}

/// Describes a world activation transaction without granting provider authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationManifest {
    /// Selects baseline activation-manifest schema 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Identifies the host transaction.
    pub transaction_id: Id,
    /// Identifies the proposed activation.
    pub activation_id: Id,
    /// Identifies the proposed committed generation.
    pub world_generation: U64,
    /// Identifies the closed activation gate.
    pub gate_id: Id,
    /// Commits to the full world compatibility.
    pub world_binding_hash: HashRef,
    /// Lists all ready owners by owner ID.
    pub owners: Vec<PreparedOwner>,
    /// Binds prepared coordinator state.
    pub coordinator_state_ref: ContentRef,
    /// Carries activation extensions.
    pub extensions: Extensions,
}

/// Records one prepared owner beneath a closed activation gate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedOwner {
    /// Identifies the prepared owner.
    pub owner_id: Id,
    /// Identifies the fresh live incarnation.
    pub incarnation_id: Id,
    /// Identifies the prepared positive owner generation.
    pub owner_generation: U64,
    /// Identifies authenticated prepared custody.
    pub prepared_token: Id,
    /// Lists admitted node binding hashes by domain and digest.
    pub binding_hashes: Vec<HashRef>,
    /// Binds exact ready-state evidence.
    pub ready_receipt: ContentRef,
    /// Carries preparation extensions.
    pub extensions: Extensions,
}

/// Separates provider claims from host-authenticated control records.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlReceipt {
    /// Selects baseline control-receipt schema 1.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Selects the complete record schema.
    pub kind: ControlReceiptKind,
    /// Identifies the admitted session.
    pub session_id: Id,
    /// Identifies the live provider incarnation.
    pub incarnation_id: Id,
    /// Identifies the original request.
    pub request_id: Id,
    /// Identifies operation scope, or explicit null for an unscoped control record.
    #[serde(deserialize_with = "required_nullable")]
    pub operation_id: Option<Id>,
    /// Lists every affected owner.
    pub owner_ids: IdSet,
    /// Identifies the selected world generation.
    pub world_generation: U64,
    /// Binds the complete kind-specific facts and evidence.
    pub record_ref: ContentRef,
    /// Distinguishes provider claims from host-authenticated records.
    pub issuer: ReceiptIssuer,
    /// Carries control-receipt extensions.
    pub extensions: Extensions,
}

impl Validate for StopReceipt {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.owner_binding_hash.validate()?;
        if self.owner_binding_hash.domain != "cnp.owner-binding.v1" {
            return Err(invalid("owner_binding_hash", "wrong owner identity domain"));
        }
        self.world_binding_hash.validate()?;
        if self.world_binding_hash.domain != "cnp.world-binding.v1" {
            return Err(invalid("world_binding_hash", "wrong world identity domain"));
        }
        validate_ids(&self.participant_ids, "participant_ids")?;
        if self.ordering_profile != "superdense-v1" {
            return Err(invalid("ordering_profile", "unsupported ordering profile"));
        }
        if let Some(value) = &self.reached {
            value.validate()?;
        }
        self.production_prefix.validate()?;
        validate_sorted(
            &self.output_lower_bounds,
            |value| value.endpoint.clone(),
            "output_lower_bounds",
        )?;
        for value in &self.output_lower_bounds {
            value.validate()?;
        }
        self.input_custody.validate()?;
        self.pending_inventory.validate()?;
        self.observation_batch.validate()?;
        self.physical_measurement_ref.validate()?;
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

impl Validate for PortBound {
    fn validate(&self) -> Result<(), ContractError> {
        self.endpoint.validate()?;
        self.bound.validate()?;
        Ok(())
    }
}

impl Validate for ActivationManifest {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.world_binding_hash.validate()?;
        if self.world_binding_hash.domain != "cnp.world-binding.v1" {
            return Err(invalid("world_binding_hash", "wrong world identity domain"));
        }
        validate_sorted(&self.owners, |value| value.owner_id.clone(), "owners")?;
        for value in &self.owners {
            value.validate()?;
        }
        self.coordinator_state_ref.validate()?;
        Ok(())
    }
}

impl Validate for PreparedOwner {
    fn validate(&self) -> Result<(), ContractError> {
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
        self.ready_receipt.validate()?;
        Ok(())
    }
}

impl Validate for ControlReceipt {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        validate_ids(&self.owner_ids, "owner_ids")?;
        self.record_ref.validate()?;
        Ok(())
    }
}
