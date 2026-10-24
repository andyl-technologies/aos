//! Closed CNP/1 operations and local bound checks.

use super::*;

/// Represents the baseline `GrantContext` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantContext {
    /// Carries the normative `grant_id` contract field.
    pub grant_id: Id,
    /// Carries the normative `participant_ids` contract field.
    pub participant_ids: IdSet,
    /// Carries the normative `realization_id` contract field.
    pub realization_id: Id,
    /// Identifies the admitted activation.
    pub activation_id: Id,
    /// Identifies the admitted world generation.
    pub world_generation: U64,
    /// Identifies the positive admitted owner generation.
    pub owner_generation: U64,
    /// Carries the normative `input_epoch` contract field.
    pub input_epoch: Id,
    /// Carries the normative `mode` contract field.
    pub mode: OperatingMode,
    /// Carries the normative `ordering_profile` contract field.
    pub ordering_profile: String,
}

impl Validate for GrantContext {
    fn validate(&self) -> Result<(), ContractError> {
        ids(&self.participant_ids, "participant_ids")?;
        if self.owner_generation.get() == 0 {
            return Err(invalid("owner_generation", "generation must be positive"));
        }
        if self.ordering_profile != "superdense-v1" {
            return Err(invalid("ordering_profile", "unsupported ordering profile"));
        }
        Ok(())
    }
}

/// Represents the baseline `ExactRunArguments` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactRunArguments {
    /// Carries the normative `grant_id` contract field.
    pub grant_id: Id,
    /// Carries the normative `participant_ids` contract field.
    pub participant_ids: IdSet,
    /// Carries the normative `realization_id` contract field.
    pub realization_id: Id,
    /// Identifies the admitted activation.
    pub activation_id: Id,
    /// Identifies the admitted world generation.
    pub world_generation: U64,
    /// Identifies the positive admitted owner generation.
    pub owner_generation: U64,
    /// Carries the normative `input_epoch` contract field.
    pub input_epoch: Id,
    /// Carries the normative `mode` contract field.
    pub mode: OperatingMode,
    /// Carries the normative `ordering_profile` contract field.
    pub ordering_profile: String,
    /// Carries the normative `start` contract field.
    pub start: Position,
    /// Carries the normative `limit` contract field.
    pub limit: Position,
    /// Carries the normative `boundary_policy` contract field.
    pub boundary_policy: BoundaryPolicy,
    /// Carries the normative `input_authorization` contract field.
    pub input_authorization: ContentRef,
    /// Carries the normative `input_watermark` contract field.
    pub input_watermark: U64,
}

impl Validate for ExactRunArguments {
    fn validate(&self) -> Result<(), ContractError> {
        ids(&self.participant_ids, "participant_ids")?;
        if self.owner_generation.get() == 0 {
            return Err(invalid("owner_generation", "generation must be positive"));
        }
        if self.ordering_profile != "superdense-v1" {
            return Err(invalid("ordering_profile", "unsupported ordering profile"));
        }
        self.start.validate()?;
        self.limit.validate()?;
        self.input_authorization.validate()?;
        if self.mode != OperatingMode::Exact || self.start > self.limit {
            return Err(invalid(
                "grant",
                "exact grant requires exact mode and start <= limit",
            ));
        }
        Ok(())
    }
}

/// Represents the baseline `QuantumBeginArguments` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuantumBeginArguments {
    /// Carries the normative `grant_id` contract field.
    pub grant_id: Id,
    /// Carries the normative `participant_ids` contract field.
    pub participant_ids: IdSet,
    /// Carries the normative `realization_id` contract field.
    pub realization_id: Id,
    /// Identifies the admitted activation.
    pub activation_id: Id,
    /// Identifies the admitted world generation.
    pub world_generation: U64,
    /// Identifies the positive admitted owner generation.
    pub owner_generation: U64,
    /// Carries the normative `input_epoch` contract field.
    pub input_epoch: Id,
    /// Carries the normative `mode` contract field.
    pub mode: OperatingMode,
    /// Carries the normative `ordering_profile` contract field.
    pub ordering_profile: String,
    /// Carries the normative `quantum_index` contract field.
    pub quantum_index: U64,
    /// Carries the normative `from_ps` contract field.
    pub from_ps: Tick,
    /// Carries the normative `until_ps` contract field.
    pub until_ps: Tick,
    /// Carries the normative `input_batch` contract field.
    pub input_batch: ContentRef,
    /// Carries the normative `input_watermark` contract field.
    pub input_watermark: U64,
    /// Commits to the exact admitted timing policy.
    pub policy_hash: HashRef,
    /// Carries the normative `wall_budget_ns` contract field.
    pub wall_budget_ns: U64,
}

impl Validate for QuantumBeginArguments {
    fn validate(&self) -> Result<(), ContractError> {
        ids(&self.participant_ids, "participant_ids")?;
        if self.owner_generation.get() == 0 {
            return Err(invalid("owner_generation", "generation must be positive"));
        }
        if self.ordering_profile != "superdense-v1" {
            return Err(invalid("ordering_profile", "unsupported ordering profile"));
        }
        self.input_batch.validate()?;
        self.policy_hash.validate()?;
        if self.mode != OperatingMode::Quantized || self.from_ps >= self.until_ps {
            return Err(invalid(
                "grant",
                "quantum requires quantized mode and from < until",
            ));
        }
        Ok(())
    }
}

/// Represents the baseline `PauseArguments` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PauseArguments {
    /// Carries the normative `participant_ids` contract field.
    pub participant_ids: IdSet,
    /// Carries the normative `reason` contract field.
    pub reason: Id,
}

impl Validate for PauseArguments {
    fn validate(&self) -> Result<(), ContractError> {
        ids(&self.participant_ids, "participant_ids")?;
        Ok(())
    }
}

/// Represents the baseline `CaptureArguments` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureArguments {
    /// Carries the normative `capture_id` contract field.
    pub capture_id: Id,
    /// Carries the normative `participant_ids` contract field.
    pub participant_ids: IdSet,
    /// Carries the normative `cut_id` contract field.
    pub cut_id: Id,
    /// Carries the normative `cut` contract field.
    pub cut: Position,
    /// Carries the normative `event_ordinal` contract field.
    pub event_ordinal: U64,
    /// Carries the normative `ordering_profile` contract field.
    pub ordering_profile: String,
    /// Carries the normative `preservation_contract` contract field.
    pub preservation_contract: Id,
}

impl Validate for CaptureArguments {
    fn validate(&self) -> Result<(), ContractError> {
        ids(&self.participant_ids, "participant_ids")?;
        self.cut.validate()?;
        if self.ordering_profile != "superdense-v1" {
            return Err(invalid("ordering_profile", "unsupported ordering profile"));
        }
        Ok(())
    }
}

/// Represents the baseline `PrepareRestoreArguments` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRestoreArguments {
    /// Carries the normative `transaction_id` contract field.
    pub transaction_id: Id,
    /// Carries the normative `capture_manifest` contract field.
    pub capture_manifest: ContentRef,
    /// Carries the normative `expected_world_binding_hash` contract field.
    pub expected_world_binding_hash: HashRef,
    /// Carries the normative `expected_owner_binding_hash` contract field.
    pub expected_owner_binding_hash: HashRef,
    /// Carries the normative `destination_owner_ids` contract field.
    pub destination_owner_ids: IdSet,
}

impl Validate for PrepareRestoreArguments {
    fn validate(&self) -> Result<(), ContractError> {
        self.capture_manifest.validate()?;
        self.expected_world_binding_hash.validate()?;
        domain(&self.expected_world_binding_hash, "cnp.world-binding.v1")?;
        self.expected_owner_binding_hash.validate()?;
        domain(&self.expected_owner_binding_hash, "cnp.owner-binding.v1")?;
        ids(&self.destination_owner_ids, "destination_owner_ids")?;
        Ok(())
    }
}

/// Represents the baseline `ShutdownArguments` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownArguments {
    /// Carries the normative `participant_ids` contract field.
    pub participant_ids: IdSet,
    /// Carries the normative `reason` contract field.
    pub reason: Id,
}

impl Validate for ShutdownArguments {
    fn validate(&self) -> Result<(), ContractError> {
        ids(&self.participant_ids, "participant_ids")?;
        Ok(())
    }
}

/// Represents the baseline `ExactRunResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactRunResult {
    /// Carries the normative `grant_id` contract field.
    pub grant_id: Id,
    /// Carries the normative `reached` contract field.
    pub reached: Position,
    /// Carries the normative `stop_reason` contract field.
    pub stop_reason: StopReason,
    /// Carries the normative `stop_receipt` contract field.
    pub stop_receipt: ContentRef,
    /// Carries the normative `observation_batch` contract field.
    pub observation_batch: ContentRef,
    /// Carries the normative `pending_inventory` contract field.
    pub pending_inventory: ContentRef,
    /// Carries the normative `next_attention` contract field.
    pub next_attention: Bound,
}

impl Validate for ExactRunResult {
    fn validate(&self) -> Result<(), ContractError> {
        self.reached.validate()?;
        self.stop_receipt.validate()?;
        self.observation_batch.validate()?;
        self.pending_inventory.validate()?;
        self.next_attention.validate()?;
        Ok(())
    }
}

/// Represents the baseline `QuantumBeginResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuantumBeginResult {
    /// Carries the normative `grant_id` contract field.
    pub grant_id: Id,
    /// Carries the normative `quantum_index` contract field.
    pub quantum_index: U64,
    /// Carries the normative `stop_receipt` contract field.
    pub stop_receipt: ContentRef,
    /// Carries the normative `observation_batch` contract field.
    pub observation_batch: ContentRef,
    /// Carries the normative `pending_inventory` contract field.
    pub pending_inventory: ContentRef,
    /// Carries the normative `budget_outcome` contract field.
    pub budget_outcome: BudgetOutcome,
    /// Carries the normative `physical_measurement_ref` contract field.
    pub physical_measurement_ref: ContentRef,
}

impl Validate for QuantumBeginResult {
    fn validate(&self) -> Result<(), ContractError> {
        self.stop_receipt.validate()?;
        self.observation_batch.validate()?;
        self.pending_inventory.validate()?;
        self.physical_measurement_ref.validate()?;
        Ok(())
    }
}

/// Represents the baseline `PauseResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PauseResult {
    /// Carries the normative `stop_receipt` contract field.
    pub stop_receipt: ContentRef,
    /// Carries the normative `physical_paused` contract field.
    pub physical_paused: bool,
    /// Carries the normative `reached` contract field.
    pub reached: Nullable<Position>,
    /// Carries the normative `pending_inventory` contract field.
    pub pending_inventory: ContentRef,
}

impl Validate for PauseResult {
    fn validate(&self) -> Result<(), ContractError> {
        self.stop_receipt.validate()?;
        if let Some(value) = &self.reached.0 {
            value.validate()?;
        }
        self.pending_inventory.validate()?;
        Ok(())
    }
}

/// Represents the baseline `CaptureResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureResult {
    /// Carries the normative `capture_manifest` contract field.
    pub capture_manifest: ContentRef,
    /// Carries the normative `owner_state_refs` contract field.
    pub owner_state_refs: Vec<ContentRef>,
    /// Carries the normative `unchanged_cut_receipt` contract field.
    pub unchanged_cut_receipt: ContentRef,
}

impl Validate for CaptureResult {
    fn validate(&self) -> Result<(), ContractError> {
        self.capture_manifest.validate()?;
        sorted(
            &self.owner_state_refs,
            |value| (value.hash.domain.clone(), value.hash.digest.clone()),
            "owner_state_refs",
        )?;
        for value in &self.owner_state_refs {
            value.validate()?;
        }
        self.unchanged_cut_receipt.validate()?;
        Ok(())
    }
}

/// Represents the baseline `PrepareRestoreResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRestoreResult {
    /// Carries the normative `transaction_id` contract field.
    pub transaction_id: Id,
    /// Carries the normative `prepared_token` contract field.
    pub prepared_token: Id,
    /// Commits to complete world compatibility.
    pub world_binding_hash: HashRef,
    /// Carries the normative `owner_binding_hash` contract field.
    pub owner_binding_hash: HashRef,
    /// Carries the normative `staged_owner_ids` contract field.
    pub staged_owner_ids: IdSet,
    /// Carries the normative `closed_gate_receipt` contract field.
    pub closed_gate_receipt: ContentRef,
    /// Carries the normative `validated_manifest` contract field.
    pub validated_manifest: ContentRef,
}

impl Validate for PrepareRestoreResult {
    fn validate(&self) -> Result<(), ContractError> {
        self.world_binding_hash.validate()?;
        domain(&self.world_binding_hash, "cnp.world-binding.v1")?;
        self.owner_binding_hash.validate()?;
        domain(&self.owner_binding_hash, "cnp.owner-binding.v1")?;
        ids(&self.staged_owner_ids, "staged_owner_ids")?;
        self.closed_gate_receipt.validate()?;
        self.validated_manifest.validate()?;
        Ok(())
    }
}

/// Represents the baseline `ShutdownResult` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownResult {
    /// Carries the normative `observation_batch` contract field.
    pub observation_batch: ContentRef,
    /// Carries the normative `pending_inventory` contract field.
    pub pending_inventory: ContentRef,
    /// Carries the normative `stopped` contract field.
    pub stopped: bool,
    /// Carries the normative `reaped` contract field.
    pub reaped: bool,
    /// Carries the normative `cleanup_receipt` contract field.
    pub cleanup_receipt: ContentRef,
}

impl Validate for ShutdownResult {
    fn validate(&self) -> Result<(), ContractError> {
        self.observation_batch.validate()?;
        self.pending_inventory.validate()?;
        self.cleanup_receipt.validate()?;
        if self.reaped && !self.stopped {
            return Err(invalid("reaped", "reaped owner must be stopped"));
        }
        Ok(())
    }
}
