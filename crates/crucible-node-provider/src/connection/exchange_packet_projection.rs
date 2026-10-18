//! Bounds an ordinary Observe proof prefix before its owning reply exists.
//!
//! The closed native producer supplies full original/terminal field counters
//! and one to three content extents. This uses the real ordinary Blob grammar;
//! it constructs no future Envelope, reference, Capture owner or payload. The
//! actual owning counter must fit every component before the builder runs.

use super::*;
use continuation::{ContentExtent, ProjectedBody, copy_storage};

#[path = "exchange_packet_startup.rs"]
mod startup;
pub(crate) use startup::{
    original_packet_prefix_startup_counter_scratch_data,
    quote_original_packet_baseline_prefix_startup_storage_data,
    quote_original_packet_prefix_startup_storage_data,
    quote_original_restored_input17_prefix_startup_storage_data,
};

// The class is private to the defining closed constructors. An array size or
// matching scalar quote cannot select another request family.
#[derive(Clone, Copy, Eq, PartialEq)]
enum PrefixClass {
    Observe,
    RestoredInput17,
}

impl PrefixClass {
    const fn method_data(self) -> Method {
        match self {
            Self::Observe => Method::Observe,
            Self::RestoredInput17 => Method::Input,
        }
    }
}

pub(crate) struct OriginalPacketPrefixProjectionInput<'a> {
    pub(crate) terminal: &'a OriginalSerializationStorageData,
    pub(crate) original: &'a OriginalSerializationStorageData,
    pub(crate) objects: &'a [OriginalContinuationContentExtent<'a>],
    pub(crate) maximum_requested_bytes: usize,
}

/// Contains prospective storage bounds, without allocation or transport rights.
pub(crate) struct OriginalPacketPrefixProjectionStorageData<const OBJECTS: usize = 3> {
    pub(crate) exchange: OriginalPacketPrefixStorageData,
    pub(crate) source_owner_requested_bytes: usize,
    /// Is present only for the closed native initial lifecycle grammar.
    pub(crate) native_source_backing_bytes: Option<usize>,
    pub(crate) declared_counter_scratch_bytes: usize,
    terminal: OriginalSerializationStorageData,
    original: OriginalSerializationStorageData,
    objects: [Option<ContentExtent>; OBJECTS],
    class: PrefixClass,
    maximum_requested_bytes: usize,
}

impl<const OBJECTS: usize> OriginalPacketPrefixProjectionStorageData<OBJECTS> {
    /// Counts the completed record using this same closed outgoing grammar.
    pub(crate) fn completed_record_encoding_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<super::super::OriginalPacketCompletedRecordEncodingData, ProviderError> {
        connection.protocol_owner.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        let chunk = allowance(connection.authority.limits().blob_chunk_bytes.get())?.min(4096);
        if chunk == 0 {
            return Err(credit());
        }
        let mut nodes = self.terminal.serialized_value_nodes;
        let mut records = self.terminal.serialized_capacity_records;
        let transfer = add("packet-transfer-".len(), 20)?;
        let mut count = 1usize;
        for object in self.objects.iter().flatten() {
            for (method, body) in [
                (Method::BlobBegin, ProjectedBody::Begin(transfer, object)),
                (Method::BlobFinish, ProjectedBody::Finish(transfer)),
            ] {
                let frame = continuation::projected_packet_frame(
                    &connection.authority,
                    method,
                    body,
                    self.maximum_requested_bytes,
                )?;
                nodes = add(nodes, frame.serialized_value_nodes)?;
                records = add(records, frame.serialized_capacity_records)?;
                count = add(count, 1)?;
            }
            let mut remaining = object.payload;
            while remaining > 0 {
                let bytes = remaining.min(chunk);
                let encoded = mul(bytes.div_ceil(3), 4)?;
                let frame = continuation::projected_packet_frame(
                    &connection.authority,
                    Method::BlobChunk,
                    ProjectedBody::Chunk(transfer, encoded),
                    self.maximum_requested_bytes,
                )?;
                nodes = add(nodes, frame.serialized_value_nodes)?;
                records = add(records, frame.serialized_capacity_records)?;
                count = add(count, 1)?;
                remaining -= bytes;
            }
        }
        if count != self.exchange.frames {
            return Err(refused());
        }
        connection.quote_original_packet_completed_record_encoding_data(
            &self.exchange,
            nodes,
            records,
            self.maximum_requested_bytes,
        )
    }

    pub(crate) fn requested_bytes(&self) -> Result<usize, ProviderError> {
        sum(&[
            self.exchange.requested_bytes()?,
            self.source_owner_requested_bytes,
            self.declared_counter_scratch_bytes,
        ])
    }

    /// Recounts current owners before any actual frame/canonical plan is built.
    pub(crate) fn authenticate_actual_inputs<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        first: u64,
        request: &Envelope,
        body: &Map<String, Value>,
        evidence: &Vec<(ContentRef, Vec<u8>)>,
    ) -> Result<OriginalPacketPrefixStorageData, ProviderError> {
        connection.protocol_owner.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        if connection.role != EndpointRole::Provider
            || request.method != self.class.method_data()
            || evidence.len() != self.objects.iter().flatten().count()
        {
            return Err(refused());
        }
        if self.class == PrefixClass::RestoredInput17 {
            super::restored_input17::authenticate_actual_inputs_data(
                connection, request, body, evidence,
            )?;
        }
        // Source backing is independent of plan backing. Large spare payload,
        // reference, body or evidence-vector capacity must refuse here rather
        // than only at the later actual plan reconciliation.
        let mut source = MetadataObserver::new();
        source.observe(body)?;
        source.vector::<(ContentRef, Vec<u8>)>(evidence.capacity())?;
        for ((reference, bytes), extent) in evidence.iter().zip(self.objects.iter().flatten()) {
            if bytes.len() > extent.payload
                || reference.media_type.len() > extent.media
                || reference.hash.algorithm != "blake3-256"
                || reference.hash.domain != "cnp.blob.v1"
                || reference.hash.digest.len() != 64
                || reference.length.get() != u64::try_from(bytes.len()).map_err(|_| credit())?
            {
                return Err(credit());
            }
            source.observe(reference)?;
            source.vector::<u8>(bytes.capacity())?;
            source.observe(&bytes.len())?;
        }
        if requested_facts(&source.finish())? > self.source_owner_requested_bytes {
            return Err(credit());
        }
        let mut fields = MetadataObserver::new();
        fields.observe(request)?;
        let original = actual_serialization_storage_data(
            request,
            fields.finish(),
            self.maximum_requested_bytes,
        )?;
        continuation::within(&original, &self.original)?;
        let terminal = frame_projection(
            &connection.authority,
            Some(request),
            first,
            self.class.method_data(),
            Body::Response(body),
            self.maximum_requested_bytes,
        )?;
        continuation::within(&terminal, &self.terminal)?;
        // This owning requote uses CURRENT authority, exact full references,
        // payload lengths and original. A foreign/stale smaller header bound
        // cannot allocate a multiplied larger plan before being checked.
        let actual = match self.class {
            PrefixClass::Observe => connection.quote_original_packet_prefix_storage_data(
                first,
                request,
                body,
                evidence,
                self.maximum_requested_bytes,
            )?,
            PrefixClass::RestoredInput17 => connection
                .quote_original_restored_input17_prefix_storage_data(
                    first,
                    request,
                    body,
                    evidence,
                    self.maximum_requested_bytes,
                )?,
        };
        within_exchange(&actual, &self.exchange)?;
        Ok(actual)
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn quote_original_packet_prefix_projection_storage_data(
        &self,
        first: u64,
        original_observe: &Envelope,
        input: OriginalPacketPrefixProjectionInput<'_>,
    ) -> Result<OriginalPacketPrefixProjectionStorageData, ProviderError> {
        self.quote_original_packet_prefix_projection_storage_inner_data::<3>(
            first,
            original_observe,
            input,
            PrefixClass::Observe,
        )
    }

    /// Quotes the same actual selected Input17 connection before its reply exists.
    ///
    /// # Errors
    /// Refuses another full selected header, noncurrent connection, changed
    /// original correlation/literal cut, five-role extent roster or byte limit.
    pub(crate) fn quote_original_restored_input17_prefix_projection_storage_data(
        &self,
        first: u64,
        original: &Envelope,
        input: OriginalPacketPrefixProjectionInput<'_>,
    ) -> Result<OriginalPacketPrefixProjectionStorageData<5>, ProviderError> {
        super::restored_input17::authenticate_original_data(self, original)?;
        if input.objects.len() != 5
            || input
                .objects
                .iter()
                .any(|object| object.media_type != "application/json")
        {
            return Err(refused());
        }
        self.quote_original_packet_prefix_projection_storage_inner_data::<5>(
            first,
            original,
            input,
            PrefixClass::RestoredInput17,
        )
    }

    fn quote_original_packet_prefix_projection_storage_inner_data<const OBJECTS: usize>(
        &self,
        first: u64,
        original_observe: &Envelope,
        input: OriginalPacketPrefixProjectionInput<'_>,
        class: PrefixClass,
    ) -> Result<OriginalPacketPrefixProjectionStorageData<OBJECTS>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Provider
            || !matches!(
                self.native5_codec.as_deref(),
                Some(Native5CodecOwner::NativePacket(_))
            )
            || original_observe.method != class.method_data()
            || input.objects.is_empty()
            || input.objects.len() > OBJECTS
        {
            return Err(refused());
        }
        let maximum_frame = allowance(self.authority.limits().frame_bytes.get())?;
        let chunk = allowance(self.authority.limits().blob_chunk_bytes.get())?.min(4096);
        if maximum_frame == 0 || chunk == 0 || input.terminal.maximum_encoded_bytes > maximum_frame
        {
            return Err(credit());
        }
        let mut objects = [None; OBJECTS];
        let mut payload = 0usize;
        let mut frames = 1usize;
        for (index, object) in input.objects.iter().enumerate() {
            if object.maximum_payload_bytes > 65_536
                || object.media_type.is_empty()
                || object.media_type.len() > 128
                || !object
                    .media_type
                    .bytes()
                    .all(|byte| (0x20..=0x7e).contains(&byte))
            {
                return Err(credit());
            }
            payload = add(payload, object.maximum_payload_bytes)?;
            frames = add(
                frames,
                add(2, object.maximum_payload_bytes.div_ceil(chunk))?,
            )?;
            objects[index] = Some(ContentExtent {
                payload: object.maximum_payload_bytes,
                media: object.media_type.len(),
            });
        }
        if payload > 4 * 1024 * 1024 {
            return Err(credit());
        }
        let requests = frames.checked_sub(1).ok_or_else(credit)?;
        self.guard.preflight_original_packet_prefix_data(
            original_observe,
            first,
            frames,
            requests,
        )?;
        let mut original_fields = MetadataObserver::new();
        original_fields.observe(original_observe)?;
        let actual_original = actual_serialization_storage_data(
            original_observe,
            original_fields.finish(),
            input.maximum_requested_bytes,
        )?;
        continuation::within(&actual_original, input.original)?;
        let mut data = OriginalPacketPrefixStorageData {
            native_retained_backing_bytes: None,
            frames,
            requests,
            evidence_payload_bytes: payload,
            outgoing_framed_bytes: 0,
            incoming_framed_bytes: mul(requests, add(maximum_frame, 4)?)?,
            new_transport_credit_bytes: 0,
            original_plan_requested_bytes: mul(frames, size_of::<Envelope>())?,
            acknowledgement_index_requested_bytes:
                super::super::super::restore_input_quote::tree_storage(
                    1,
                    input.objects.len(),
                    size_of::<Id>() + size_of::<ContentRef>(),
                    align_of::<Id>().max(align_of::<ContentRef>()),
                )?,
            canonical_requested_bytes: 0,
            record_slots_requested_bytes: sum(&[
                mul(frames, size_of::<Vec<u8>>())?,
                mul(frames, size_of::<Option<usize>>())?,
                mul(requests, size_of::<ReceivedFrame>())?,
                size_of::<ExchangeRecord>(),
            ])?,
            outgoing_guard_requested_bytes: super::super::super::restore_input_quote::tree_storage(
                2,
                frames,
                size_of::<Id>() + size_of::<Envelope>(),
                align_of::<Id>().max(align_of::<Envelope>()),
            )?,
            response_iterator_requested_bytes: mul(
                add(requests, 1)?,
                std::mem::size_of_val(&self.guard.pending_requests())
                    .max(std::mem::size_of_val(&self.guard.incoming_requests())),
            )?,
            successful_ack_cache_requested_bytes: 0,
            one_open_ack_requested_bytes: acknowledgements::open_ack_storage(maximum_frame)?,
            containment_requested_bytes: add(
                current_containment(self)?,
                mul(add(mul(2, requests)?, 8)?, size_of::<Envelope>())?,
            )?,
            construction_transient_requested_bytes: input.original.requested_total()?,
            preparation_transient_requested_bytes: 0,
            declared_quote_scratch_bytes: Self::original_packet_prefix_quote_scratch_bytes_data(),
            original_literal_required_bytes: mul(requests, add(maximum_frame, 4)?)?,
            original_slots_required: add(frames, requests)?,
        };
        if class == PrefixClass::RestoredInput17 {
            data.declared_quote_scratch_bytes = add(
                data.declared_quote_scratch_bytes,
                super::restored_input17::counter_scratch_data(),
            )?;
            data.construction_transient_requested_bytes = add(
                data.construction_transient_requested_bytes,
                super::restored_input17::validation_transient_storage_data(),
            )?;
        }
        let mut source_owner = sum(&[
            input.terminal.dom_and_canonical_scratch_bytes,
            payload,
            mul(
                add(mul(2, input.objects.len())?, 4)?,
                size_of::<(ContentRef, Vec<u8>)>(),
            )?,
            size_of::<crate::reference_packet::control::PacketControlReply>(),
        ])?;
        // Ordinary preparation retains its frame loop's complete work sum. Do
        // not substitute the continuation planner's sequential phase maximum.
        charge_frame(
            &mut data,
            copy_storage(input.terminal),
            false,
            maximum_frame,
        )?;
        let transfer = add("packet-transfer-".len(), 20)?;
        for object in objects.iter().flatten() {
            let reference =
                continuation::reference_projection(object, input.maximum_requested_bytes)?;
            source_owner = add(source_owner, reference.dom_and_canonical_scratch_bytes)?;
            data.acknowledgement_index_requested_bytes = add(
                data.acknowledgement_index_requested_bytes,
                add(reference.dom_and_canonical_scratch_bytes, growth(transfer)?)?,
            )?;
            for (method, body) in [
                (Method::BlobBegin, ProjectedBody::Begin(transfer, object)),
                (Method::BlobFinish, ProjectedBody::Finish(transfer)),
            ] {
                charge_frame(
                    &mut data,
                    continuation::projected_packet_frame(
                        &self.authority,
                        method,
                        body,
                        input.maximum_requested_bytes,
                    )?,
                    true,
                    maximum_frame,
                )?;
            }
            let mut remaining = object.payload;
            while remaining > 0 {
                let bytes = remaining.min(chunk);
                let encoded = mul(bytes.div_ceil(3), 4)?;
                data.construction_transient_requested_bytes = add(
                    data.construction_transient_requested_bytes,
                    sum(&[bytes, encoded, growth(transfer)?])?,
                )?;
                charge_frame(
                    &mut data,
                    continuation::projected_packet_frame(
                        &self.authority,
                        Method::BlobChunk,
                        ProjectedBody::Chunk(transfer, encoded),
                        input.maximum_requested_bytes,
                    )?,
                    true,
                    maximum_frame,
                )?;
                remaining -= bytes;
            }
        }
        let outgoing_bodies = data
            .outgoing_framed_bytes
            .checked_sub(mul(frames, 4)?)
            .ok_or_else(credit)?;
        data.new_transport_credit_bytes = add(
            mul(outgoing_bodies, 3)?,
            mul(mul(requests, maximum_frame)?, 2)?,
        )?;
        data.preflight_transport_credit_data(0)?;
        self.original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| refused())?
            .preflight_framed_suffix(
                frames,
                data.outgoing_framed_bytes,
                requests,
                data.incoming_framed_bytes,
            )?;
        let result = OriginalPacketPrefixProjectionStorageData {
            exchange: data,
            source_owner_requested_bytes: source_owner,
            native_source_backing_bytes: None,
            declared_counter_scratch_bytes: sum(&[
                size_of::<&Self>(),
                size_of::<OriginalPacketPrefixProjectionStorageData<OBJECTS>>(),
                size_of::<OriginalPacketPrefixProjectionInput<'static>>(),
                size_of::<MetadataObserver<'static>>(),
                size_of::<RetainedProtocolMetadataFacts>(),
                mul(3, size_of::<OriginalSerializationStorageData>())?,
            ])?,
            terminal: copy_storage(input.terminal),
            original: copy_storage(input.original),
            objects,
            class,
            maximum_requested_bytes: input.maximum_requested_bytes,
        };
        if result.requested_bytes()? > input.maximum_requested_bytes {
            return Err(credit());
        }
        self.authenticate_native5_source_codec()?;
        Ok(result)
    }
}

fn within_exchange(
    actual: &OriginalPacketPrefixStorageData,
    bound: &OriginalPacketPrefixStorageData,
) -> Result<(), ProviderError> {
    for (actual, bound) in [
        (actual.frames, bound.frames),
        (actual.requests, bound.requests),
        (actual.evidence_payload_bytes, bound.evidence_payload_bytes),
        (actual.outgoing_framed_bytes, bound.outgoing_framed_bytes),
        (actual.incoming_framed_bytes, bound.incoming_framed_bytes),
        (
            actual.new_transport_credit_bytes,
            bound.new_transport_credit_bytes,
        ),
        (
            actual.original_plan_requested_bytes,
            bound.original_plan_requested_bytes,
        ),
        (
            actual.acknowledgement_index_requested_bytes,
            bound.acknowledgement_index_requested_bytes,
        ),
        (
            actual.canonical_requested_bytes,
            bound.canonical_requested_bytes,
        ),
        (
            actual.record_slots_requested_bytes,
            bound.record_slots_requested_bytes,
        ),
        (
            actual.outgoing_guard_requested_bytes,
            bound.outgoing_guard_requested_bytes,
        ),
        (
            actual.response_iterator_requested_bytes,
            bound.response_iterator_requested_bytes,
        ),
        (
            actual.successful_ack_cache_requested_bytes,
            bound.successful_ack_cache_requested_bytes,
        ),
        (
            actual.one_open_ack_requested_bytes,
            bound.one_open_ack_requested_bytes,
        ),
        (
            actual.containment_requested_bytes,
            bound.containment_requested_bytes,
        ),
        (
            actual.construction_transient_requested_bytes,
            bound.construction_transient_requested_bytes,
        ),
        (
            actual.preparation_transient_requested_bytes,
            bound.preparation_transient_requested_bytes,
        ),
        (
            actual.declared_quote_scratch_bytes,
            bound.declared_quote_scratch_bytes,
        ),
        (
            actual.original_literal_required_bytes,
            bound.original_literal_required_bytes,
        ),
        (
            actual.original_slots_required,
            bound.original_slots_required,
        ),
    ] {
        if actual > bound {
            return Err(credit());
        }
    }
    Ok(())
}

#[path = "exchange_native_observe_prepare.rs"]
mod native_observe_prepare;
#[cfg(test)]
pub(super) use native_observe_prepare::for_test as native_observe_preparation_for_test;
pub(crate) use native_observe_prepare::{
    OriginalNativeObservePreparationStorageData,
    original_native_observe_preparation_counter_scratch_data,
    quote_original_native_observe_prefix_startup_storage_data,
};
#[cfg(test)]
pub(super) use startup::native_observe_projection_for_test;
