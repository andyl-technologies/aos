//! Checks closed native17 results fields and their actual retained backing.

use super::*;

historical_struct!(DiscoverResult {
    provider_manifest: ProviderManifest,
    profiles: Vec<NodeManifest>,
    facet_schemas: Vec<SchemaRef>,
    complete: bool,
    next_cursor: Nullable<Id>,
});

historical_struct!(RealizeResult {
    realization_manifest: RealizationManifest,
    prepared_token: Id,
    closed_gate_receipt: ContentRef,
});

historical_struct!(AdmitResult {
    accepted_binding_hashes: Vec<HashRef>,
    admission_id: Id,
});

historical_struct!(ActivateResult {
    staged: bool,
    gate_id: Id,
    staged_owner_ids: IdSet,
    activation_receipt: ContentRef,
});

impl ObserveMetadata for ActivateResult {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            staged,
            gate_id,
            staged_owner_ids,
            activation_receipt,
        } = self;
        observer.observe(staged)?;
        observer.observe(gate_id)?;
        observer.observe(staged_owner_ids)?;
        observer.observe(activation_receipt)?;
        Ok(())
    }
}

historical_struct!(ObserveResult {
    observations: Vec<ObservationBatch>,
    next_sequence: U64,
    complete: bool,
    inventory_hash: HashRef,
});

historical_struct!(BeginAccepted {
    operation_id: Id,
    kind: BeginKind,
});

historical_struct!(PollResult {
    operation_id: Id,
    operation_state: OperationState,
    outcome: Nullable<Map<String, Value>>,
    observations: Vec<ObservationBatch>,
    next_observation_sequence: U64,
});

historical_struct!(CancelResult {
    cancel_requested: bool,
    operation_state: OperationState,
});

impl ObserveMetadata for CancelResult {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            cancel_requested,
            operation_state,
        } = self;
        observer.observe(cancel_requested)?;
        observer.observe(operation_state)?;
        Ok(())
    }
}

historical_struct!(QuantumCloseResult {
    grant_id: Id,
    quantum_index: U64,
    cut: Position,
    policy_hash: HashRef,
    activation_id: Id,
    world_generation: U64,
    owner_generation: U64,
    input_epoch: Id,
    stop_receipt: ContentRef,
    committed_batch: ContentRef,
    pending_inventory: ContentRef,
    next_allowed_quantum: Nullable<U64>,
});

impl ObserveMetadata for QuantumCloseResult {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            grant_id,
            quantum_index,
            cut,
            policy_hash,
            activation_id,
            world_generation,
            owner_generation,
            input_epoch,
            stop_receipt,
            committed_batch,
            pending_inventory,
            next_allowed_quantum,
        } = self;
        observer.observe(grant_id)?;
        observer.observe(quantum_index)?;
        observer.observe(cut)?;
        observer.observe(policy_hash)?;
        observer.observe(activation_id)?;
        observer.observe(world_generation)?;
        observer.observe(owner_generation)?;
        observer.observe(input_epoch)?;
        observer.observe(stop_receipt)?;
        observer.observe(committed_batch)?;
        observer.observe(pending_inventory)?;
        observer.observe(next_allowed_quantum)?;
        Ok(())
    }
}

historical_struct!(WorldActivateResult {
    armed_owner_ids: IdSet,
    gate_id: Id,
    activation_receipt: ContentRef,
});

historical_struct!(AbortResult {
    transaction_id: Id,
    owner_ids: IdSet,
    cleanup_receipt: ContentRef,
    effect: EffectCertainty,
});

impl ObserveMetadata for AbortResult {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            transaction_id,
            owner_ids,
            cleanup_receipt,
            effect,
        } = self;
        observer.observe(transaction_id)?;
        observer.observe(owner_ids)?;
        observer.observe(cleanup_receipt)?;
        observer.observe(effect)?;
        Ok(())
    }
}

historical_struct!(RetireResult {
    retired_request_ids: IdSet,
    retired_operation_ids: IdSet,
});

impl ObserveMetadata for RetireResult {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            retired_request_ids,
            retired_operation_ids,
        } = self;
        observer.observe(retired_request_ids)?;
        observer.observe(retired_operation_ids)?;
        Ok(())
    }
}

historical_struct!(BlobBeginResult {
    transfer_id: Id,
    next_offset: U64,
    maximum_chunk_bytes: U64,
});

impl ObserveMetadata for BlobBeginResult {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            transfer_id,
            next_offset,
            maximum_chunk_bytes,
        } = self;
        observer.observe(transfer_id)?;
        observer.observe(next_offset)?;
        observer.observe(maximum_chunk_bytes)?;
        Ok(())
    }
}

historical_struct!(BlobChunkResult {
    transfer_id: Id,
    next_offset: U64,
});

impl ObserveMetadata for BlobChunkResult {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            transfer_id,
            next_offset,
        } = self;
        observer.observe(transfer_id)?;
        observer.observe(next_offset)?;
        Ok(())
    }
}

historical_struct!(BlobFinishResult {
    transfer_id: Id,
    content: ContentRef,
});

impl ObserveMetadata for BlobFinishResult {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            transfer_id,
            content,
        } = self;
        observer.observe(transfer_id)?;
        observer.observe(content)?;
        Ok(())
    }
}

historical_struct!(ReleaseResult {
    realization_id: Id,
    owner_ids: IdSet,
    cleanup_receipt: ContentRef,
    released: bool,
});

impl ObserveMetadata for ReleaseResult {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            realization_id,
            owner_ids,
            cleanup_receipt,
            released,
        } = self;
        observer.observe(realization_id)?;
        observer.observe(owner_ids)?;
        observer.observe(cleanup_receipt)?;
        observer.observe(released)?;
        Ok(())
    }
}

historical_struct!(ExactRunResult {
    grant_id: Id,
    reached: Position,
    stop_reason: StopReason,
    stop_receipt: ContentRef,
    observation_batch: ContentRef,
    pending_inventory: ContentRef,
    next_attention: Bound,
});

impl ObserveMetadata for ExactRunResult {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            grant_id,
            reached,
            stop_reason,
            stop_receipt,
            observation_batch,
            pending_inventory,
            next_attention,
        } = self;
        observer.observe(grant_id)?;
        observer.observe(reached)?;
        observer.observe(stop_reason)?;
        observer.observe(stop_receipt)?;
        observer.observe(observation_batch)?;
        observer.observe(pending_inventory)?;
        observer.observe(next_attention)?;
        Ok(())
    }
}

historical_struct!(QuantumBeginResult {
    grant_id: Id,
    quantum_index: U64,
    stop_receipt: ContentRef,
    observation_batch: ContentRef,
    pending_inventory: ContentRef,
    budget_outcome: BudgetOutcome,
    physical_measurement_ref: ContentRef,
});

impl ObserveMetadata for QuantumBeginResult {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            grant_id,
            quantum_index,
            stop_receipt,
            observation_batch,
            pending_inventory,
            budget_outcome,
            physical_measurement_ref,
        } = self;
        observer.observe(grant_id)?;
        observer.observe(quantum_index)?;
        observer.observe(stop_receipt)?;
        observer.observe(observation_batch)?;
        observer.observe(pending_inventory)?;
        observer.observe(budget_outcome)?;
        observer.observe(physical_measurement_ref)?;
        Ok(())
    }
}

historical_struct!(PauseResult {
    stop_receipt: ContentRef,
    physical_paused: bool,
    reached: Nullable<Position>,
    pending_inventory: ContentRef,
});

impl ObserveMetadata for PauseResult {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            stop_receipt,
            physical_paused,
            reached,
            pending_inventory,
        } = self;
        observer.observe(stop_receipt)?;
        observer.observe(physical_paused)?;
        observer.observe(reached)?;
        observer.observe(pending_inventory)?;
        Ok(())
    }
}

historical_struct!(CaptureResult {
    capture_manifest: ContentRef,
    owner_state_refs: Vec<ContentRef>,
    unchanged_cut_receipt: ContentRef,
});

historical_struct!(PrepareRestoreResult {
    transaction_id: Id,
    prepared_token: Id,
    world_binding_hash: HashRef,
    owner_binding_hash: HashRef,
    staged_owner_ids: IdSet,
    closed_gate_receipt: ContentRef,
    validated_manifest: ContentRef,
});

impl ObserveMetadata for PrepareRestoreResult {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            transaction_id,
            prepared_token,
            world_binding_hash,
            owner_binding_hash,
            staged_owner_ids,
            closed_gate_receipt,
            validated_manifest,
        } = self;
        observer.observe(transaction_id)?;
        observer.observe(prepared_token)?;
        observer.observe(world_binding_hash)?;
        observer.observe(owner_binding_hash)?;
        observer.observe(staged_owner_ids)?;
        observer.observe(closed_gate_receipt)?;
        observer.observe(validated_manifest)?;
        Ok(())
    }
}

historical_struct!(ShutdownResult {
    observation_batch: ContentRef,
    pending_inventory: ContentRef,
    stopped: bool,
    reaped: bool,
    cleanup_receipt: ContentRef,
});

impl ObserveMetadata for ShutdownResult {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            observation_batch,
            pending_inventory,
            stopped,
            reaped,
            cleanup_receipt,
        } = self;
        observer.observe(observation_batch)?;
        observer.observe(pending_inventory)?;
        observer.observe(stopped)?;
        observer.observe(reaped)?;
        observer.observe(cleanup_receipt)?;
        Ok(())
    }
}

#[path = "results/native17_build.rs"]
mod native17_build;
