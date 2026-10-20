//! Closed CNP/1 requests and local bound checks.

use super::*;

/// Represents the baseline `DiscoverRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverRequest {
    /// Carries the normative `profile_ids` contract field.
    pub profile_ids: IdSet,
    /// Carries the normative `cursor` contract field.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "optional_nonnull"
    )]
    pub cursor: Option<Id>,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for DiscoverRequest {
    fn validate(&self) -> Result<(), ContractError> {
        ids(&self.profile_ids, "profile_ids")?;
        Ok(())
    }
}

/// Represents the baseline `RealizeRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealizeRequest {
    /// Carries the normative `realization_id` contract field.
    pub realization_id: Id,
    /// Carries the normative `configuration` contract field.
    pub configuration: ContentRef,
    /// Carries the normative `requested_node_ids` contract field.
    pub requested_node_ids: IdSet,
    /// Carries the normative `resource_limits` contract field.
    pub resource_limits: ResourceLimits,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for RealizeRequest {
    fn validate(&self) -> Result<(), ContractError> {
        self.configuration.validate()?;
        ids(&self.requested_node_ids, "requested_node_ids")?;
        self.resource_limits.validate()?;
        Ok(())
    }
}

/// Represents the baseline `AdmitRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmitRequest {
    /// Carries the normative `bindings` contract field.
    pub bindings: Vec<NodeBinding>,
    /// Commits to complete world compatibility.
    pub world_binding_hash: HashRef,
    /// Carries the normative `admission_receipt` contract field.
    pub admission_receipt: ContentRef,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for AdmitRequest {
    fn validate(&self) -> Result<(), ContractError> {
        sorted(
            &self.bindings,
            |value| (value.compatibility.node_id.clone(), 0),
            "bindings",
        )?;
        for value in &self.bindings {
            value.validate()?;
        }
        self.world_binding_hash.validate()?;
        domain(&self.world_binding_hash, "cnp.world-binding.v1")?;
        self.admission_receipt.validate()?;
        Ok(())
    }
}

/// Represents the baseline `ActivateRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateRequest {
    /// Carries the normative `admission_id` contract field.
    pub admission_id: Id,
    /// Identifies the admitted activation.
    pub activation_id: Id,
    /// Identifies the admitted world generation.
    pub world_generation: U64,
    /// Carries the normative `prepared_token` contract field.
    pub prepared_token: Id,
    /// Commits to complete world compatibility.
    pub world_binding_hash: HashRef,
    /// Carries the normative `gate_id` contract field.
    pub gate_id: Id,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for ActivateRequest {
    fn validate(&self) -> Result<(), ContractError> {
        self.world_binding_hash.validate()?;
        domain(&self.world_binding_hash, "cnp.world-binding.v1")?;
        Ok(())
    }
}

/// Represents the baseline `InputRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputRequest {
    /// Commits to the selected complete owner or node binding.
    pub binding_hash: HashRef,
    /// Identifies the positive admitted owner generation.
    pub owner_generation: U64,
    /// Carries the normative `batch_id` contract field.
    pub batch_id: Id,
    /// Carries the normative `batch_sequence` contract field.
    pub batch_sequence: U64,
    /// Carries the normative `input_epoch` contract field.
    pub input_epoch: Id,
    /// Preserves the admitted delivered event order.
    pub events: Vec<Event>,
    /// Carries the normative `batch_hash` contract field.
    pub batch_hash: HashRef,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for InputRequest {
    fn validate(&self) -> Result<(), ContractError> {
        self.binding_hash.validate()?;
        if self.owner_generation.get() == 0 {
            return Err(invalid("owner_generation", "generation must be positive"));
        }
        count(&self.events, "events")?;
        for value in &self.events {
            value.validate()?;
        }
        self.batch_hash.validate()?;
        domain(&self.binding_hash, "cnp.owner-binding.v1")?;
        domain(&self.batch_hash, "cnp.input-batch.v1")?;
        if self.batch_sequence.get() == 0 {
            return Err(invalid("batch_sequence", "input batches begin at one"));
        }
        let mut sequences = std::collections::BTreeSet::new();
        for event in &self.events {
            if event.stage != EventStage::Delivery {
                return Err(invalid("events", "publication is not delivered input"));
            }
            if !sequences.insert((&event.source.node_id, event.source_sequence)) {
                return Err(invalid("events", "producer sequence repeats"));
            }
        }
        Ok(())
    }
}

/// Represents the baseline `ObserveRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserveRequest {
    /// Commits to the selected complete owner or node binding.
    pub binding_hash: HashRef,
    /// Identifies the positive admitted owner generation.
    pub owner_generation: U64,
    /// Carries the normative `after_observation_sequence` contract field.
    pub after_observation_sequence: U64,
    /// Limits requested observations without authorizing allocation.
    pub maximum_items: U64,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for ObserveRequest {
    fn validate(&self) -> Result<(), ContractError> {
        self.binding_hash.validate()?;
        if self.owner_generation.get() == 0 {
            return Err(invalid("owner_generation", "generation must be positive"));
        }
        if !matches!(
            self.binding_hash.domain.as_str(),
            "cnp.node-binding.v1" | "cnp.owner-binding.v1"
        ) {
            return Err(invalid("binding_hash", "wrong observation binding domain"));
        }
        if self.maximum_items.get() > MAX_ARRAY_ELEMENTS as u64 {
            return Err(invalid(
                "maximum_items",
                "require positive bounded observation allowance",
            ));
        }
        Ok(())
    }
}

/// Represents the baseline `BeginRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginRequest {
    /// Carries the normative `kind` contract field.
    pub kind: BeginKind,
    /// Commits to the selected complete owner or node binding.
    pub binding_hash: HashRef,
    /// Identifies the positive admitted owner generation.
    pub owner_generation: U64,
    /// Identifies the admitted activation.
    pub activation_id: Nullable<Id>,
    /// Identifies the admitted world generation.
    pub world_generation: U64,
    /// Contains the closed argument schema selected by kind.
    pub arguments: Map<String, Value>,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for BeginRequest {
    fn validate(&self) -> Result<(), ContractError> {
        self.binding_hash.validate()?;
        if self.owner_generation.get() == 0 {
            return Err(invalid("owner_generation", "generation must be positive"));
        }
        domain(&self.binding_hash, "cnp.owner-binding.v1")?;
        self.decoded_arguments()?.validate()?;
        Ok(())
    }
}

/// Represents the baseline `PollRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollRequest {
    /// Carries the normative `after_observation_sequence` contract field.
    pub after_observation_sequence: U64,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for PollRequest {
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

/// Represents the baseline `CancelRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRequest {
    /// Carries the normative `reason` contract field.
    pub reason: Id,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for CancelRequest {
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

/// Represents the baseline `QuantumCloseRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuantumCloseRequest {
    /// Carries the normative `grant_id` contract field.
    pub grant_id: Id,
    /// Identifies the admitted activation.
    pub activation_id: Id,
    /// Identifies the admitted world generation.
    pub world_generation: U64,
    /// Identifies the positive admitted owner generation.
    pub owner_generation: U64,
    /// Carries the normative `input_epoch` contract field.
    pub input_epoch: Id,
    /// Carries the normative `quantum_index` contract field.
    pub quantum_index: U64,
    /// Carries the normative `participant_ids` contract field.
    pub participant_ids: IdSet,
    /// Carries the normative `cut` contract field.
    pub cut: Position,
    /// Commits to the exact admitted timing policy.
    pub policy_hash: HashRef,
    /// Carries the normative `observation_batch_hash` contract field.
    pub observation_batch_hash: HashRef,
    /// Carries the normative `input_watermark` contract field.
    pub input_watermark: U64,
    /// Carries the normative `deadline_disposition` contract field.
    pub deadline_disposition: BudgetOutcome,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for QuantumCloseRequest {
    fn validate(&self) -> Result<(), ContractError> {
        if self.owner_generation.get() == 0 {
            return Err(invalid("owner_generation", "generation must be positive"));
        }
        ids(&self.participant_ids, "participant_ids")?;
        self.cut.validate()?;
        self.policy_hash.validate()?;
        self.observation_batch_hash.validate()?;
        Ok(())
    }
}

/// Represents the baseline `WorldActivateRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldActivateRequest {
    /// Carries the normative `transaction_id` contract field.
    pub transaction_id: Id,
    /// Identifies the admitted activation.
    pub activation_id: Id,
    /// Identifies the admitted world generation.
    pub world_generation: U64,
    /// Carries the normative `prepared_token` contract field.
    pub prepared_token: Id,
    /// Commits to complete world compatibility.
    pub world_binding_hash: HashRef,
    /// Carries the normative `gate_id` contract field.
    pub gate_id: Id,
    /// Carries the normative `activation_manifest` contract field.
    pub activation_manifest: ContentRef,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for WorldActivateRequest {
    fn validate(&self) -> Result<(), ContractError> {
        self.world_binding_hash.validate()?;
        domain(&self.world_binding_hash, "cnp.world-binding.v1")?;
        self.activation_manifest.validate()?;
        Ok(())
    }
}

/// Represents the baseline `AbortRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortRequest {
    /// Carries the normative `transaction_id` contract field.
    pub transaction_id: Id,
    /// Carries the normative `reason` contract field.
    pub reason: Id,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for AbortRequest {
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

/// Represents the baseline `RetireRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetireRequest {
    /// Carries the normative `request_ids` contract field.
    pub request_ids: IdSet,
    /// Carries the normative `operation_ids` contract field.
    pub operation_ids: IdSet,
    /// Carries the normative `disposition` contract field.
    pub disposition: RetirementDisposition,
    /// Binds authenticated durable custody; null is legal only for inert abandonment.
    pub custody_receipt: Nullable<ContentRef>,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for RetireRequest {
    fn validate(&self) -> Result<(), ContractError> {
        ids(&self.request_ids, "request_ids")?;
        ids(&self.operation_ids, "operation_ids")?;
        if let Some(value) = &self.custody_receipt.0 {
            value.validate()?;
        }
        match self.disposition {
            RetirementDisposition::Consumed if self.custody_receipt.0.is_some() => {}
            RetirementDisposition::AbandonedInertTransfer
                if self.custody_receipt.0.is_none() && self.operation_ids.is_empty() => {}
            _ => {
                return Err(invalid(
                    "custody_receipt",
                    "retirement disposition disagrees with custody",
                ));
            }
        }
        Ok(())
    }
}

/// Represents the baseline `BlobBeginRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobBeginRequest {
    /// Carries the normative `transfer_id` contract field.
    pub transfer_id: Id,
    /// Carries the normative `content` contract field.
    pub content: ContentRef,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for BlobBeginRequest {
    fn validate(&self) -> Result<(), ContractError> {
        self.content.validate()?;
        Ok(())
    }
}

/// Represents the baseline `BlobChunkRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobChunkRequest {
    /// Carries the normative `transfer_id` contract field.
    pub transfer_id: Id,
    /// Carries the normative `offset` contract field.
    pub offset: U64,
    /// Carries the normative `bytes` contract field.
    pub bytes: Bytes,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for BlobChunkRequest {
    fn validate(&self) -> Result<(), ContractError> {
        if self.bytes.as_slice().is_empty() || self.bytes.as_slice().len() > 1_048_576 {
            return Err(invalid("bytes", "require a nonempty bounded blob chunk"));
        }
        self.offset.checked_add(U64::new(
            u64::try_from(self.bytes.as_slice().len()).map_err(|_| ContractError::Overflow)?,
        ))?;
        Ok(())
    }
}

/// Represents the baseline `BlobFinishRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobFinishRequest {
    /// Carries the normative `transfer_id` contract field.
    pub transfer_id: Id,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for BlobFinishRequest {
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

/// Represents the baseline `ReleaseRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRequest {
    /// Carries the normative `realization_id` contract field.
    pub realization_id: Id,
    /// Carries explicitly negotiated method extensions.
    pub extensions: Extensions,
}

impl Validate for ReleaseRequest {
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}
