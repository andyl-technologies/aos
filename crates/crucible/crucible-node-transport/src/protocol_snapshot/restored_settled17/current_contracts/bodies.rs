//! Reads the defining bodies DTO fields in their actual emitted order.

use super::*;

impl CurrentContract17 for InputRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let binding_hash_raw = fields.named("binding_hash")?;
        let owner_generation_raw = fields.named("owner_generation")?;
        let batch_id_raw = fields.named("batch_id")?;
        let batch_sequence_raw = fields.named("batch_sequence")?;
        let input_epoch_raw = fields.named("input_epoch")?;
        let events_raw = fields.named("events")?;
        let batch_hash_raw = fields.named("batch_hash")?;
        let extensions_raw = fields.named("extensions")?;
        fields.finish()?;

        let binding_hash =
            <Plain17<HashRef> as CurrentField17>::read(binding_hash_raw, ledger, build)?;
        let owner_generation =
            <Plain17<U64> as CurrentField17>::read(owner_generation_raw, ledger, build)?;
        let batch_id = <Plain17<Id> as CurrentField17>::read(batch_id_raw, ledger, build)?;
        let batch_sequence =
            <Plain17<U64> as CurrentField17>::read(batch_sequence_raw, ledger, build)?;
        let input_epoch = <Plain17<Id> as CurrentField17>::read(input_epoch_raw, ledger, build)?;
        let events = <Plain17<Vec<Event>> as CurrentField17>::read(events_raw, ledger, build)?;
        let batch_hash = <Plain17<HashRef> as CurrentField17>::read(batch_hash_raw, ledger, build)?;
        let extensions =
            <Plain17<Extensions> as CurrentField17>::read(extensions_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            binding_hash: binding_hash.ok_or_else(invalid)?,
            owner_generation: owner_generation.ok_or_else(invalid)?,
            batch_id: batch_id.ok_or_else(invalid)?,
            batch_sequence: batch_sequence.ok_or_else(invalid)?,
            input_epoch: input_epoch.ok_or_else(invalid)?,
            events: events.ok_or_else(invalid)?,
            batch_hash: batch_hash.ok_or_else(invalid)?,
            extensions: extensions.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            binding_hash,
            owner_generation,
            batch_id,
            batch_sequence,
            input_epoch,
            events,
            batch_hash,
            extensions,
        } = self;
        <Plain17<HashRef> as CurrentField17>::observe(binding_hash, observer)?;
        <Plain17<U64> as CurrentField17>::observe(owner_generation, observer)?;
        <Plain17<Id> as CurrentField17>::observe(batch_id, observer)?;
        <Plain17<U64> as CurrentField17>::observe(batch_sequence, observer)?;
        <Plain17<Id> as CurrentField17>::observe(input_epoch, observer)?;
        <Plain17<Vec<Event>> as CurrentField17>::observe(events, observer)?;
        <Plain17<HashRef> as CurrentField17>::observe(batch_hash, observer)?;
        <Plain17<Extensions> as CurrentField17>::observe(extensions, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for BeginRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let kind_raw = fields.named("kind")?;
        let binding_hash_raw = fields.named("binding_hash")?;
        let owner_generation_raw = fields.named("owner_generation")?;
        let activation_id_raw = fields.named("activation_id")?;
        let world_generation_raw = fields.named("world_generation")?;
        let arguments_raw = fields.named("arguments")?;
        let extensions_raw = fields.named("extensions")?;
        fields.finish()?;

        let kind = <Plain17<BeginKind> as CurrentField17>::read(kind_raw, ledger, build)?;
        let binding_hash =
            <Plain17<HashRef> as CurrentField17>::read(binding_hash_raw, ledger, build)?;
        let owner_generation =
            <Plain17<U64> as CurrentField17>::read(owner_generation_raw, ledger, build)?;
        let activation_id =
            <Plain17<Nullable<Id>> as CurrentField17>::read(activation_id_raw, ledger, build)?;
        let world_generation =
            <Plain17<U64> as CurrentField17>::read(world_generation_raw, ledger, build)?;
        let arguments =
            <Plain17<Map<String, Value>> as CurrentField17>::read(arguments_raw, ledger, build)?;
        let extensions =
            <Plain17<Extensions> as CurrentField17>::read(extensions_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            kind: kind.ok_or_else(invalid)?,
            binding_hash: binding_hash.ok_or_else(invalid)?,
            owner_generation: owner_generation.ok_or_else(invalid)?,
            activation_id: activation_id.ok_or_else(invalid)?,
            world_generation: world_generation.ok_or_else(invalid)?,
            arguments: arguments.ok_or_else(invalid)?,
            extensions: extensions.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            kind,
            binding_hash,
            owner_generation,
            activation_id,
            world_generation,
            arguments,
            extensions,
        } = self;
        <Plain17<BeginKind> as CurrentField17>::observe(kind, observer)?;
        <Plain17<HashRef> as CurrentField17>::observe(binding_hash, observer)?;
        <Plain17<U64> as CurrentField17>::observe(owner_generation, observer)?;
        <Plain17<Nullable<Id>> as CurrentField17>::observe(activation_id, observer)?;
        <Plain17<U64> as CurrentField17>::observe(world_generation, observer)?;
        <Plain17<Map<String, Value>> as CurrentField17>::observe(arguments, observer)?;
        <Plain17<Extensions> as CurrentField17>::observe(extensions, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PollRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let after_observation_sequence_raw = fields.named("after_observation_sequence")?;
        let extensions_raw = fields.named("extensions")?;
        fields.finish()?;

        let after_observation_sequence =
            <Plain17<U64> as CurrentField17>::read(after_observation_sequence_raw, ledger, build)?;
        let extensions =
            <Plain17<Extensions> as CurrentField17>::read(extensions_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            after_observation_sequence: after_observation_sequence.ok_or_else(invalid)?,
            extensions: extensions.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            after_observation_sequence,
            extensions,
        } = self;
        <Plain17<U64> as CurrentField17>::observe(after_observation_sequence, observer)?;
        <Plain17<Extensions> as CurrentField17>::observe(extensions, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for RetireRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let request_ids_raw = fields.named("request_ids")?;
        let operation_ids_raw = fields.named("operation_ids")?;
        let disposition_raw = fields.named("disposition")?;
        let custody_receipt_raw = fields.named("custody_receipt")?;
        let extensions_raw = fields.named("extensions")?;
        fields.finish()?;

        let request_ids = <Plain17<IdSet> as CurrentField17>::read(request_ids_raw, ledger, build)?;
        let operation_ids =
            <Plain17<IdSet> as CurrentField17>::read(operation_ids_raw, ledger, build)?;
        let disposition = <Inline17<RetirementDisposition> as CurrentField17>::read(
            disposition_raw,
            ledger,
            build,
        )?;
        let custody_receipt = <Plain17<Nullable<ContentRef>> as CurrentField17>::read(
            custody_receipt_raw,
            ledger,
            build,
        )?;
        let extensions =
            <Plain17<Extensions> as CurrentField17>::read(extensions_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            request_ids: request_ids.ok_or_else(invalid)?,
            operation_ids: operation_ids.ok_or_else(invalid)?,
            disposition: disposition.ok_or_else(invalid)?,
            custody_receipt: custody_receipt.ok_or_else(invalid)?,
            extensions: extensions.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            request_ids,
            operation_ids,
            disposition,
            custody_receipt,
            extensions,
        } = self;
        <Plain17<IdSet> as CurrentField17>::observe(request_ids, observer)?;
        <Plain17<IdSet> as CurrentField17>::observe(operation_ids, observer)?;
        <Inline17<RetirementDisposition> as CurrentField17>::observe(disposition, observer)?;
        <Plain17<Nullable<ContentRef>> as CurrentField17>::observe(custody_receipt, observer)?;
        <Plain17<Extensions> as CurrentField17>::observe(extensions, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for ObserveRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let binding_hash_raw = fields.named("binding_hash")?;
        let owner_generation_raw = fields.named("owner_generation")?;
        let after_observation_sequence_raw = fields.named("after_observation_sequence")?;
        let maximum_items_raw = fields.named("maximum_items")?;
        let extensions_raw = fields.named("extensions")?;
        fields.finish()?;

        let binding_hash =
            <Plain17<HashRef> as CurrentField17>::read(binding_hash_raw, ledger, build)?;
        let owner_generation =
            <Plain17<U64> as CurrentField17>::read(owner_generation_raw, ledger, build)?;
        let after_observation_sequence =
            <Plain17<U64> as CurrentField17>::read(after_observation_sequence_raw, ledger, build)?;
        let maximum_items =
            <Plain17<U64> as CurrentField17>::read(maximum_items_raw, ledger, build)?;
        let extensions =
            <Plain17<Extensions> as CurrentField17>::read(extensions_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            binding_hash: binding_hash.ok_or_else(invalid)?,
            owner_generation: owner_generation.ok_or_else(invalid)?,
            after_observation_sequence: after_observation_sequence.ok_or_else(invalid)?,
            maximum_items: maximum_items.ok_or_else(invalid)?,
            extensions: extensions.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            binding_hash,
            owner_generation,
            after_observation_sequence,
            maximum_items,
            extensions,
        } = self;
        <Plain17<HashRef> as CurrentField17>::observe(binding_hash, observer)?;
        <Plain17<U64> as CurrentField17>::observe(owner_generation, observer)?;
        <Plain17<U64> as CurrentField17>::observe(after_observation_sequence, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_items, observer)?;
        <Plain17<Extensions> as CurrentField17>::observe(extensions, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for BlobBeginRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let transfer_id_raw = fields.named("transfer_id")?;
        let content_raw = fields.named("content")?;
        let extensions_raw = fields.named("extensions")?;
        fields.finish()?;

        let transfer_id = <Plain17<Id> as CurrentField17>::read(transfer_id_raw, ledger, build)?;
        let content = <Plain17<ContentRef> as CurrentField17>::read(content_raw, ledger, build)?;
        let extensions =
            <Plain17<Extensions> as CurrentField17>::read(extensions_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            transfer_id: transfer_id.ok_or_else(invalid)?,
            content: content.ok_or_else(invalid)?,
            extensions: extensions.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            transfer_id,
            content,
            extensions,
        } = self;
        <Plain17<Id> as CurrentField17>::observe(transfer_id, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(content, observer)?;
        <Plain17<Extensions> as CurrentField17>::observe(extensions, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for BlobChunkRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let transfer_id_raw = fields.named("transfer_id")?;
        let offset_raw = fields.named("offset")?;
        let bytes_raw = fields.named("bytes")?;
        let extensions_raw = fields.named("extensions")?;
        fields.finish()?;

        let transfer_id = <Plain17<Id> as CurrentField17>::read(transfer_id_raw, ledger, build)?;
        let offset = <Plain17<U64> as CurrentField17>::read(offset_raw, ledger, build)?;
        let bytes = <Plain17<Bytes> as CurrentField17>::read(bytes_raw, ledger, build)?;
        let extensions =
            <Plain17<Extensions> as CurrentField17>::read(extensions_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            transfer_id: transfer_id.ok_or_else(invalid)?,
            offset: offset.ok_or_else(invalid)?,
            bytes: bytes.ok_or_else(invalid)?,
            extensions: extensions.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            transfer_id,
            offset,
            bytes,
            extensions,
        } = self;
        <Plain17<Id> as CurrentField17>::observe(transfer_id, observer)?;
        <Plain17<U64> as CurrentField17>::observe(offset, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(bytes, observer)?;
        <Plain17<Extensions> as CurrentField17>::observe(extensions, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for BlobFinishRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let transfer_id_raw = fields.named("transfer_id")?;
        let extensions_raw = fields.named("extensions")?;
        fields.finish()?;

        let transfer_id = <Plain17<Id> as CurrentField17>::read(transfer_id_raw, ledger, build)?;
        let extensions =
            <Plain17<Extensions> as CurrentField17>::read(extensions_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            transfer_id: transfer_id.ok_or_else(invalid)?,
            extensions: extensions.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            transfer_id,
            extensions,
        } = self;
        <Plain17<Id> as CurrentField17>::observe(transfer_id, observer)?;
        <Plain17<Extensions> as CurrentField17>::observe(extensions, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for ExactRunArguments {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let grant_id_raw = fields.named("grant_id")?;
        let participant_ids_raw = fields.named("participant_ids")?;
        let realization_id_raw = fields.named("realization_id")?;
        let activation_id_raw = fields.named("activation_id")?;
        let world_generation_raw = fields.named("world_generation")?;
        let owner_generation_raw = fields.named("owner_generation")?;
        let input_epoch_raw = fields.named("input_epoch")?;
        let mode_raw = fields.named("mode")?;
        let ordering_profile_raw = fields.named("ordering_profile")?;
        let start_raw = fields.named("start")?;
        let limit_raw = fields.named("limit")?;
        let boundary_policy_raw = fields.named("boundary_policy")?;
        let input_authorization_raw = fields.named("input_authorization")?;
        let input_watermark_raw = fields.named("input_watermark")?;
        fields.finish()?;

        let grant_id = <Plain17<Id> as CurrentField17>::read(grant_id_raw, ledger, build)?;
        let participant_ids =
            <Plain17<IdSet> as CurrentField17>::read(participant_ids_raw, ledger, build)?;
        let realization_id =
            <Plain17<Id> as CurrentField17>::read(realization_id_raw, ledger, build)?;
        let activation_id =
            <Plain17<Id> as CurrentField17>::read(activation_id_raw, ledger, build)?;
        let world_generation =
            <Plain17<U64> as CurrentField17>::read(world_generation_raw, ledger, build)?;
        let owner_generation =
            <Plain17<U64> as CurrentField17>::read(owner_generation_raw, ledger, build)?;
        let input_epoch = <Plain17<Id> as CurrentField17>::read(input_epoch_raw, ledger, build)?;
        let mode = <Plain17<OperatingMode> as CurrentField17>::read(mode_raw, ledger, build)?;
        let ordering_profile =
            <Plain17<String> as CurrentField17>::read(ordering_profile_raw, ledger, build)?;
        let start = <Plain17<Position> as CurrentField17>::read(start_raw, ledger, build)?;
        let limit = <Plain17<Position> as CurrentField17>::read(limit_raw, ledger, build)?;
        let boundary_policy =
            <Inline17<BoundaryPolicy> as CurrentField17>::read(boundary_policy_raw, ledger, build)?;
        let input_authorization =
            <Plain17<ContentRef> as CurrentField17>::read(input_authorization_raw, ledger, build)?;
        let input_watermark =
            <Plain17<U64> as CurrentField17>::read(input_watermark_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            grant_id: grant_id.ok_or_else(invalid)?,
            participant_ids: participant_ids.ok_or_else(invalid)?,
            realization_id: realization_id.ok_or_else(invalid)?,
            activation_id: activation_id.ok_or_else(invalid)?,
            world_generation: world_generation.ok_or_else(invalid)?,
            owner_generation: owner_generation.ok_or_else(invalid)?,
            input_epoch: input_epoch.ok_or_else(invalid)?,
            mode: mode.ok_or_else(invalid)?,
            ordering_profile: ordering_profile.ok_or_else(invalid)?,
            start: start.ok_or_else(invalid)?,
            limit: limit.ok_or_else(invalid)?,
            boundary_policy: boundary_policy.ok_or_else(invalid)?,
            input_authorization: input_authorization.ok_or_else(invalid)?,
            input_watermark: input_watermark.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            grant_id,
            participant_ids,
            realization_id,
            activation_id,
            world_generation,
            owner_generation,
            input_epoch,
            mode,
            ordering_profile,
            start,
            limit,
            boundary_policy,
            input_authorization,
            input_watermark,
        } = self;
        <Plain17<Id> as CurrentField17>::observe(grant_id, observer)?;
        <Plain17<IdSet> as CurrentField17>::observe(participant_ids, observer)?;
        <Plain17<Id> as CurrentField17>::observe(realization_id, observer)?;
        <Plain17<Id> as CurrentField17>::observe(activation_id, observer)?;
        <Plain17<U64> as CurrentField17>::observe(world_generation, observer)?;
        <Plain17<U64> as CurrentField17>::observe(owner_generation, observer)?;
        <Plain17<Id> as CurrentField17>::observe(input_epoch, observer)?;
        <Plain17<OperatingMode> as CurrentField17>::observe(mode, observer)?;
        <Plain17<String> as CurrentField17>::observe(ordering_profile, observer)?;
        <Plain17<Position> as CurrentField17>::observe(start, observer)?;
        <Plain17<Position> as CurrentField17>::observe(limit, observer)?;
        <Inline17<BoundaryPolicy> as CurrentField17>::observe(boundary_policy, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(input_authorization, observer)?;
        <Plain17<U64> as CurrentField17>::observe(input_watermark, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for CaptureArguments {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let capture_id_raw = fields.named("capture_id")?;
        let participant_ids_raw = fields.named("participant_ids")?;
        let cut_id_raw = fields.named("cut_id")?;
        let cut_raw = fields.named("cut")?;
        let event_ordinal_raw = fields.named("event_ordinal")?;
        let ordering_profile_raw = fields.named("ordering_profile")?;
        let preservation_contract_raw = fields.named("preservation_contract")?;
        fields.finish()?;

        let capture_id = <Plain17<Id> as CurrentField17>::read(capture_id_raw, ledger, build)?;
        let participant_ids =
            <Plain17<IdSet> as CurrentField17>::read(participant_ids_raw, ledger, build)?;
        let cut_id = <Plain17<Id> as CurrentField17>::read(cut_id_raw, ledger, build)?;
        let cut = <Plain17<Position> as CurrentField17>::read(cut_raw, ledger, build)?;
        let event_ordinal =
            <Plain17<U64> as CurrentField17>::read(event_ordinal_raw, ledger, build)?;
        let ordering_profile =
            <Plain17<String> as CurrentField17>::read(ordering_profile_raw, ledger, build)?;
        let preservation_contract =
            <Plain17<Id> as CurrentField17>::read(preservation_contract_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            capture_id: capture_id.ok_or_else(invalid)?,
            participant_ids: participant_ids.ok_or_else(invalid)?,
            cut_id: cut_id.ok_or_else(invalid)?,
            cut: cut.ok_or_else(invalid)?,
            event_ordinal: event_ordinal.ok_or_else(invalid)?,
            ordering_profile: ordering_profile.ok_or_else(invalid)?,
            preservation_contract: preservation_contract.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            capture_id,
            participant_ids,
            cut_id,
            cut,
            event_ordinal,
            ordering_profile,
            preservation_contract,
        } = self;
        <Plain17<Id> as CurrentField17>::observe(capture_id, observer)?;
        <Plain17<IdSet> as CurrentField17>::observe(participant_ids, observer)?;
        <Plain17<Id> as CurrentField17>::observe(cut_id, observer)?;
        <Plain17<Position> as CurrentField17>::observe(cut, observer)?;
        <Plain17<U64> as CurrentField17>::observe(event_ordinal, observer)?;
        <Plain17<String> as CurrentField17>::observe(ordering_profile, observer)?;
        <Plain17<Id> as CurrentField17>::observe(preservation_contract, observer)?;
        Ok(())
    }
}
