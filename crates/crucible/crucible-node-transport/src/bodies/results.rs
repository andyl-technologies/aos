//! Closed CNP/1 results and local bound checks.

use super::*;

/// Represents the baseline `DiscoverResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverResult {
    /// Carries the normative `provider_manifest` contract field.
    pub provider_manifest: ProviderManifest,
    /// Carries the normative `profiles` contract field.
    pub profiles: Vec<NodeManifest>,
    /// Carries the normative `facet_schemas` contract field.
    pub facet_schemas: Vec<SchemaRef>,
    /// Carries the normative `complete` contract field.
    pub complete: bool,
    /// Identifies another discovery page, or explicit null at completion.
    pub next_cursor: Nullable<Id>,
}

impl Validate for DiscoverResult {
    fn validate(&self) -> Result<(), ContractError> {
        self.provider_manifest.validate()?;
        sorted(
            &self.profiles,
            |value| (value.profile_id.clone(), 0),
            "profiles",
        )?;
        for value in &self.profiles {
            value.validate()?;
        }
        sorted(
            &self.facet_schemas,
            |value| (value.id.clone(), value.version),
            "facet_schemas",
        )?;
        for value in &self.facet_schemas {
            value.validate()?;
        }
        if self.complete && self.next_cursor.0.is_some() {
            return Err(invalid(
                "next_cursor",
                "complete discovery has no continuation cursor",
            ));
        }
        Ok(())
    }
}

/// Represents the baseline `RealizeResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealizeResult {
    /// Carries the normative `realization_manifest` contract field.
    pub realization_manifest: RealizationManifest,
    /// Carries the normative `prepared_token` contract field.
    pub prepared_token: Id,
    /// Carries the normative `closed_gate_receipt` contract field.
    pub closed_gate_receipt: ContentRef,
}

impl Validate for RealizeResult {
    fn validate(&self) -> Result<(), ContractError> {
        self.realization_manifest.validate()?;
        self.closed_gate_receipt.validate()?;
        Ok(())
    }
}

/// Represents the baseline `AdmitResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmitResult {
    /// Carries the normative `accepted_binding_hashes` contract field.
    pub accepted_binding_hashes: Vec<HashRef>,
    /// Carries the normative `admission_id` contract field.
    pub admission_id: Id,
}

impl Validate for AdmitResult {
    fn validate(&self) -> Result<(), ContractError> {
        sorted(
            &self.accepted_binding_hashes,
            |value| (value.domain.clone(), value.digest.clone()),
            "accepted_binding_hashes",
        )?;
        for value in &self.accepted_binding_hashes {
            value.validate()?;
        }
        for hash in &self.accepted_binding_hashes {
            domain(hash, "cnp.node-binding.v1")?;
        }
        Ok(())
    }
}

/// Represents the baseline `ActivateResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateResult {
    /// Must be true; staging never opens the execution gate.
    pub staged: bool,
    /// Carries the normative `gate_id` contract field.
    pub gate_id: Id,
    /// Carries the normative `staged_owner_ids` contract field.
    pub staged_owner_ids: IdSet,
    /// Carries the normative `activation_receipt` contract field.
    pub activation_receipt: ContentRef,
}

impl Validate for ActivateResult {
    fn validate(&self) -> Result<(), ContractError> {
        ids(&self.staged_owner_ids, "staged_owner_ids")?;
        self.activation_receipt.validate()?;
        if !self.staged {
            return Err(invalid(
                "staged",
                "successful activation staging requires true",
            ));
        }
        Ok(())
    }
}

/// Represents the baseline `InputResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputResult {
    /// Carries the normative `accepted_event_ids` contract field.
    pub accepted_event_ids: IdSet,
    /// Carries the normative `input_watermark` contract field.
    pub input_watermark: U64,
    /// Binds authenticated durable custody of accepted inputs.
    pub custody_receipt: ContentRef,
    /// Carries the normative `inventory_hash` contract field.
    pub inventory_hash: HashRef,
}

impl Validate for InputResult {
    fn validate(&self) -> Result<(), ContractError> {
        ids(&self.accepted_event_ids, "accepted_event_ids")?;
        self.custody_receipt.validate()?;
        self.inventory_hash.validate()?;
        Ok(())
    }
}

/// Represents the baseline `ObserveResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserveResult {
    /// Carries the normative `observations` contract field.
    pub observations: Vec<ObservationBatch>,
    /// Carries the normative `next_sequence` contract field.
    pub next_sequence: U64,
    /// Carries the normative `complete` contract field.
    pub complete: bool,
    /// Carries the normative `inventory_hash` contract field.
    pub inventory_hash: HashRef,
}

impl Validate for ObserveResult {
    fn validate(&self) -> Result<(), ContractError> {
        count(&self.observations, "observations")?;
        for value in &self.observations {
            value.validate()?;
        }
        self.inventory_hash.validate()?;
        Ok(())
    }
}

/// Represents the baseline `BeginAccepted` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginAccepted {
    /// Carries the normative `operation_id` contract field.
    pub operation_id: Id,
    /// Carries the normative `kind` contract field.
    pub kind: BeginKind,
}

impl Validate for BeginAccepted {
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

/// Represents the baseline `PollResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollResult {
    /// Carries the normative `operation_id` contract field.
    pub operation_id: Id,
    /// Carries the normative `operation_state` contract field.
    pub operation_state: OperationState,
    /// Retains the original terminal response, or explicit null before completion.
    pub outcome: Nullable<Map<String, Value>>,
    /// Carries the normative `observations` contract field.
    pub observations: Vec<ObservationBatch>,
    /// Carries the normative `next_observation_sequence` contract field.
    pub next_observation_sequence: U64,
}

impl Validate for PollResult {
    fn validate(&self) -> Result<(), ContractError> {
        count(&self.observations, "observations")?;
        for value in &self.observations {
            value.validate()?;
        }
        if self.operation_state == OperationState::Completed && self.outcome.0.is_none() {
            return Err(invalid(
                "outcome",
                "completed operation requires original terminal outcome",
            ));
        }
        if let Some(outcome) = &self.outcome.0 {
            let response = decode_response_shape(outcome)?;
            if response.is_accepted() || response.operation_state() != self.operation_state {
                return Err(invalid(
                    "outcome",
                    "poll outcome must retain original terminal operation state",
                ));
            }
        }
        Ok(())
    }
}

/// Represents the baseline `CancelResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelResult {
    /// Carries the normative `cancel_requested` contract field.
    pub cancel_requested: bool,
    /// Carries the normative `operation_state` contract field.
    pub operation_state: OperationState,
}

impl Validate for CancelResult {
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

/// Represents the baseline `QuantumCloseResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuantumCloseResult {
    /// Carries the normative `grant_id` contract field.
    pub grant_id: Id,
    /// Carries the normative `quantum_index` contract field.
    pub quantum_index: U64,
    /// Carries the normative `cut` contract field.
    pub cut: Position,
    /// Commits to the exact admitted timing policy.
    pub policy_hash: HashRef,
    /// Identifies the admitted activation.
    pub activation_id: Id,
    /// Identifies the admitted world generation.
    pub world_generation: U64,
    /// Identifies the positive admitted owner generation.
    pub owner_generation: U64,
    /// Carries the normative `input_epoch` contract field.
    pub input_epoch: Id,
    /// Carries the normative `stop_receipt` contract field.
    pub stop_receipt: ContentRef,
    /// Carries the normative `committed_batch` contract field.
    pub committed_batch: ContentRef,
    /// Carries the normative `pending_inventory` contract field.
    pub pending_inventory: ContentRef,
    /// Carries the normative `next_allowed_quantum` contract field.
    pub next_allowed_quantum: Nullable<U64>,
}

impl Validate for QuantumCloseResult {
    fn validate(&self) -> Result<(), ContractError> {
        self.cut.validate()?;
        self.policy_hash.validate()?;
        if self.owner_generation.get() == 0 {
            return Err(invalid("owner_generation", "generation must be positive"));
        }
        self.stop_receipt.validate()?;
        self.committed_batch.validate()?;
        self.pending_inventory.validate()?;
        Ok(())
    }
}

/// Represents the baseline `WorldActivateResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldActivateResult {
    /// Carries the normative `armed_owner_ids` contract field.
    pub armed_owner_ids: IdSet,
    /// Carries the normative `gate_id` contract field.
    pub gate_id: Id,
    /// Carries the normative `activation_receipt` contract field.
    pub activation_receipt: ContentRef,
}

impl Validate for WorldActivateResult {
    fn validate(&self) -> Result<(), ContractError> {
        ids(&self.armed_owner_ids, "armed_owner_ids")?;
        self.activation_receipt.validate()?;
        Ok(())
    }
}

/// Represents the baseline `AbortResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortResult {
    /// Carries the normative `transaction_id` contract field.
    pub transaction_id: Id,
    /// Carries the normative `owner_ids` contract field.
    pub owner_ids: IdSet,
    /// Carries the normative `cleanup_receipt` contract field.
    pub cleanup_receipt: ContentRef,
    /// Carries the normative `effect` contract field.
    pub effect: EffectCertainty,
}

impl Validate for AbortResult {
    fn validate(&self) -> Result<(), ContractError> {
        ids(&self.owner_ids, "owner_ids")?;
        self.cleanup_receipt.validate()?;
        Ok(())
    }
}

/// Represents the baseline `RetireResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetireResult {
    /// Carries the normative `retired_request_ids` contract field.
    pub retired_request_ids: IdSet,
    /// Carries the normative `retired_operation_ids` contract field.
    pub retired_operation_ids: IdSet,
}

impl Validate for RetireResult {
    fn validate(&self) -> Result<(), ContractError> {
        ids(&self.retired_request_ids, "retired_request_ids")?;
        ids(&self.retired_operation_ids, "retired_operation_ids")?;
        Ok(())
    }
}

/// Represents the baseline `BlobBeginResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobBeginResult {
    /// Carries the normative `transfer_id` contract field.
    pub transfer_id: Id,
    /// Carries the normative `next_offset` contract field.
    pub next_offset: U64,
    /// Carries the normative `maximum_chunk_bytes` contract field.
    pub maximum_chunk_bytes: U64,
}

impl Validate for BlobBeginResult {
    fn validate(&self) -> Result<(), ContractError> {
        if self.maximum_chunk_bytes.get() == 0 || self.maximum_chunk_bytes.get() > 1_048_576 {
            return Err(invalid("maximum_chunk_bytes", "invalid chunk ceiling"));
        }
        Ok(())
    }
}

/// Represents the baseline `BlobChunkResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobChunkResult {
    /// Carries the normative `transfer_id` contract field.
    pub transfer_id: Id,
    /// Carries the normative `next_offset` contract field.
    pub next_offset: U64,
}

impl Validate for BlobChunkResult {
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

/// Represents the baseline `BlobFinishResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobFinishResult {
    /// Carries the normative `transfer_id` contract field.
    pub transfer_id: Id,
    /// Carries the normative `content` contract field.
    pub content: ContentRef,
}

impl Validate for BlobFinishResult {
    fn validate(&self) -> Result<(), ContractError> {
        self.content.validate()?;
        Ok(())
    }
}

/// Represents the baseline `ReleaseResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseResult {
    /// Carries the normative `realization_id` contract field.
    pub realization_id: Id,
    /// Carries the normative `owner_ids` contract field.
    pub owner_ids: IdSet,
    /// Carries the normative `cleanup_receipt` contract field.
    pub cleanup_receipt: ContentRef,
    /// Reports actual proved resource release.
    pub released: bool,
}

impl Validate for ReleaseResult {
    fn validate(&self) -> Result<(), ContractError> {
        ids(&self.owner_ids, "owner_ids")?;
        self.cleanup_receipt.validate()?;
        Ok(())
    }
}
