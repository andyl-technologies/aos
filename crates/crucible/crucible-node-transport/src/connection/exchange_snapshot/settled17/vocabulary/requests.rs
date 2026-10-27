//! Checks closed native17 requests fields and their actual retained backing.

use super::*;

impl HistoricalType for DiscoverRequest {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let profile_ids = ledger.read::<IdSet>(fields.named("profile_ids")?, build)?;
        let pending = fields.pair()?.ok_or_else(invalid)?;
        let (cursor, pending) = if plain_string(pending.0)? == "cursor" {
            if pending.1 == b"null" {
                return Err(invalid());
            }
            (
                ledger.read::<Option<Id>>(pending.1, build)?,
                fields.pair()?.ok_or_else(invalid)?,
            )
        } else {
            (build.then_some(None), pending)
        };
        if plain_string(pending.0)? != "extensions" {
            return Err(invalid());
        }
        let extensions = ledger.read::<Extensions>(pending.1, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            profile_ids: profile_ids.ok_or_else(invalid)?,
            cursor: cursor.ok_or_else(invalid)?,
            extensions: extensions.ok_or_else(invalid)?,
        }))
    }
}

impl ObserveMetadata for DiscoverRequest {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            profile_ids,
            cursor,
            extensions,
        } = self;
        observer.observe(profile_ids)?;
        observer.observe(cursor)?;
        observer.observe(extensions)?;
        Ok(())
    }
}

historical_struct!(AdmitRequest {
    bindings: Vec<NodeBinding>,
    world_binding_hash: HashRef,
    admission_receipt: ContentRef,
    extensions: Extensions,
});

impl ObserveMetadata for AdmitRequest {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            bindings,
            world_binding_hash,
            admission_receipt,
            extensions,
        } = self;
        observer.observe(bindings)?;
        observer.observe(world_binding_hash)?;
        observer.observe(admission_receipt)?;
        observer.observe(extensions)?;
        Ok(())
    }
}

impl ObserveMetadata for ActivateRequest {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            admission_id,
            activation_id,
            world_generation,
            prepared_token,
            world_binding_hash,
            gate_id,
            extensions,
        } = self;
        observer.observe(admission_id)?;
        observer.observe(activation_id)?;
        observer.observe(world_generation)?;
        observer.observe(prepared_token)?;
        observer.observe(world_binding_hash)?;
        observer.observe(gate_id)?;
        observer.observe(extensions)?;
        Ok(())
    }
}

historical_struct!(InputRequest {
    binding_hash: HashRef,
    owner_generation: U64,
    batch_id: Id,
    batch_sequence: U64,
    input_epoch: Id,
    events: Vec<Event>,
    batch_hash: HashRef,
    extensions: Extensions,
});

historical_struct!(ObserveRequest {
    binding_hash: HashRef,
    owner_generation: U64,
    after_observation_sequence: U64,
    maximum_items: U64,
    extensions: Extensions,
});

impl ObserveMetadata for ObserveRequest {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            binding_hash,
            owner_generation,
            after_observation_sequence,
            maximum_items,
            extensions,
        } = self;
        observer.observe(binding_hash)?;
        observer.observe(owner_generation)?;
        observer.observe(after_observation_sequence)?;
        observer.observe(maximum_items)?;
        observer.observe(extensions)?;
        Ok(())
    }
}

historical_struct!(PollRequest {
    after_observation_sequence: U64,
    extensions: Extensions,
});

impl ObserveMetadata for PollRequest {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            after_observation_sequence,
            extensions,
        } = self;
        observer.observe(after_observation_sequence)?;
        observer.observe(extensions)?;
        Ok(())
    }
}

historical_struct!(CancelRequest {
    reason: Id,
    extensions: Extensions,
});

impl ObserveMetadata for CancelRequest {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self { reason, extensions } = self;
        observer.observe(reason)?;
        observer.observe(extensions)?;
        Ok(())
    }
}

historical_struct!(QuantumCloseRequest {
    grant_id: Id,
    activation_id: Id,
    world_generation: U64,
    owner_generation: U64,
    input_epoch: Id,
    quantum_index: U64,
    participant_ids: IdSet,
    cut: Position,
    policy_hash: HashRef,
    observation_batch_hash: HashRef,
    input_watermark: U64,
    deadline_disposition: BudgetOutcome,
    extensions: Extensions,
});

impl ObserveMetadata for QuantumCloseRequest {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            grant_id,
            activation_id,
            world_generation,
            owner_generation,
            input_epoch,
            quantum_index,
            participant_ids,
            cut,
            policy_hash,
            observation_batch_hash,
            input_watermark,
            deadline_disposition,
            extensions,
        } = self;
        observer.observe(grant_id)?;
        observer.observe(activation_id)?;
        observer.observe(world_generation)?;
        observer.observe(owner_generation)?;
        observer.observe(input_epoch)?;
        observer.observe(quantum_index)?;
        observer.observe(participant_ids)?;
        observer.observe(cut)?;
        observer.observe(policy_hash)?;
        observer.observe(observation_batch_hash)?;
        observer.observe(input_watermark)?;
        observer.observe(deadline_disposition)?;
        observer.observe(extensions)?;
        Ok(())
    }
}

impl ObserveMetadata for WorldActivateRequest {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            transaction_id,
            activation_id,
            world_generation,
            prepared_token,
            world_binding_hash,
            gate_id,
            activation_manifest,
            extensions,
        } = self;
        observer.observe(transaction_id)?;
        observer.observe(activation_id)?;
        observer.observe(world_generation)?;
        observer.observe(prepared_token)?;
        observer.observe(world_binding_hash)?;
        observer.observe(gate_id)?;
        observer.observe(activation_manifest)?;
        observer.observe(extensions)?;
        Ok(())
    }
}

historical_struct!(AbortRequest {
    transaction_id: Id,
    reason: Id,
    extensions: Extensions,
});

impl ObserveMetadata for AbortRequest {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            transaction_id,
            reason,
            extensions,
        } = self;
        observer.observe(transaction_id)?;
        observer.observe(reason)?;
        observer.observe(extensions)?;
        Ok(())
    }
}

historical_struct!(RetireRequest {
    request_ids: IdSet,
    operation_ids: IdSet,
    disposition: RetirementDisposition,
    custody_receipt: Nullable<ContentRef>,
    extensions: Extensions,
});

impl ObserveMetadata for RetireRequest {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            request_ids,
            operation_ids,
            disposition,
            custody_receipt,
            extensions,
        } = self;
        observer.observe(request_ids)?;
        observer.observe(operation_ids)?;
        observer.observe(disposition)?;
        observer.observe(custody_receipt)?;
        observer.observe(extensions)?;
        Ok(())
    }
}

historical_struct!(BlobBeginRequest {
    transfer_id: Id,
    content: ContentRef,
    extensions: Extensions,
});

impl ObserveMetadata for BlobBeginRequest {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            transfer_id,
            content,
            extensions,
        } = self;
        observer.observe(transfer_id)?;
        observer.observe(content)?;
        observer.observe(extensions)?;
        Ok(())
    }
}

historical_struct!(BlobChunkRequest {
    transfer_id: Id,
    offset: U64,
    bytes: Bytes,
    extensions: Extensions,
});

impl ObserveMetadata for BlobChunkRequest {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            transfer_id,
            offset,
            bytes,
            extensions,
        } = self;
        observer.observe(transfer_id)?;
        observer.observe(offset)?;
        observer.observe(bytes)?;
        observer.observe(extensions)?;
        Ok(())
    }
}

historical_struct!(BlobFinishRequest {
    transfer_id: Id,
    extensions: Extensions,
});

impl ObserveMetadata for BlobFinishRequest {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            transfer_id,
            extensions,
        } = self;
        observer.observe(transfer_id)?;
        observer.observe(extensions)?;
        Ok(())
    }
}

historical_struct!(ReleaseRequest {
    realization_id: Id,
    extensions: Extensions,
});

impl ObserveMetadata for ReleaseRequest {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            realization_id,
            extensions,
        } = self;
        observer.observe(realization_id)?;
        observer.observe(extensions)?;
        Ok(())
    }
}

#[path = "requests/native17_build.rs"]
mod native17_build;
