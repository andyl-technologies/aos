//! Quotes the actual multiwindow Capture and confirmation proof planners.
//!
//! Prospective terminal fields come from the native producer's closed counter;
//! no future Envelope, ContentRef or payload is fabricated. Actual supplied
//! owners are counted again before frame construction and every prepared window
//! is reconciled. These requested layouts grant no Source or transport credit.

use super::*;
use crate::bodies::{BlobChunkRequest, MethodResult, ResponseShape};
use std::collections::VecDeque;

/// Distinguishes the two existing planners without changing their wire shapes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OriginalContinuationPrefixKind {
    Capture,
    AfterConfirmation,
}

/// Names an actual schema's future encoded payload and printable media type.
///
/// The source-selected native producer derives the length from its complete
/// bounded encoder. This is data, not a reference, an observed capacity or an
/// allowance to allocate or read that many bytes.
pub(crate) struct OriginalContinuationContentExtent<'a> {
    pub(crate) maximum_payload_bytes: usize,
    pub(crate) media_type: &'a str,
}

/// Borrows the real native producer's future complete terminal-frame counter.
///
/// `terminal` covers the complete response Envelope, including its independent
/// body/extensions and maximum future sequence/identifier grammar. All its
/// components are checked against the actual terminal before any frame exists.
pub(crate) struct OriginalContinuationPrefixStorageInput<'a> {
    pub(crate) kind: OriginalContinuationPrefixKind,
    pub(crate) terminal: &'a OriginalSerializationStorageData,
    /// Bounds the separately cloned incoming original during reply construction.
    pub(crate) original: &'a OriginalSerializationStorageData,
    pub(crate) objects: &'a [OriginalContinuationContentExtent<'a>],
    pub(crate) maximum_requested_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ContentExtent {
    pub(super) payload: usize,
    pub(super) media: usize,
}

struct ContinuationShape<'a> {
    kind: OriginalContinuationPrefixKind,
    terminal: &'a OriginalSerializationStorageData,
    original: &'a OriginalSerializationStorageData,
    objects: &'a [Option<ContentExtent>; 3],
    maximum_requested_bytes: usize,
    containment_base_requested_bytes: usize,
}

/// Names simultaneous owners of the existing multiwindow proof plans.
///
/// Existing raw literal and descriptor requirements remain subextents of their
/// independently retained banks. `requested_bytes` sums newly owned backing
/// and named construction/decoder transients, never wire bytes as heap credit.
pub(crate) struct OriginalContinuationPrefixStorageData {
    pub(crate) exchange: OriginalPacketPrefixStorageData,
    pub(crate) kind: OriginalContinuationPrefixKind,
    pub(crate) windows: usize,
    pub(crate) simultaneous_requests: usize,
    pub(crate) chunk_bytes: usize,
    pub(crate) source_owner_requested_bytes: usize,
    pub(crate) windows_requested_bytes: usize,
    pub(crate) flat_plan_requested_bytes: usize,
    pub(crate) authority_clone_requested_bytes: usize,
    pub(crate) declared_planner_scratch_bytes: usize,
    terminal: OriginalSerializationStorageData,
    original: OriginalSerializationStorageData,
    objects: [Option<ContentExtent>; 3],
    maximum_requested_bytes: usize,
    containment_base_requested_bytes: usize,
}

impl OriginalContinuationPrefixStorageData {
    pub(crate) fn maximum_payload_bytes_data(&self, index: usize) -> Result<usize, ProviderError> {
        self.objects
            .get(index)
            .copied()
            .flatten()
            .map(|extent| extent.payload)
            .ok_or_else(refused)
    }

    pub(crate) fn requested_bytes(&self) -> Result<usize, ProviderError> {
        sum(&[
            self.exchange.requested_bytes()?,
            self.source_owner_requested_bytes,
            self.windows_requested_bytes,
            self.flat_plan_requested_bytes,
            self.authority_clone_requested_bytes,
            self.declared_planner_scratch_bytes,
        ])
    }

    /// Checks the existing no-refund 512 MiB transport counter separately.
    pub(crate) fn preflight_transport_credit_data(&self) -> Result<(), ProviderError> {
        if self.exchange.new_transport_credit_bytes
            > crate::reference_packet::continuation_transport::MAXIMUM_CAPTURE_TRANSPORT_BYTES
        {
            return Err(credit());
        }
        Ok(())
    }

    pub(crate) fn reconcile_window_population_data(
        &self,
        pending_windows: usize,
        completed_windows: usize,
        active_window: bool,
        originals: usize,
    ) -> Result<(), ProviderError> {
        if add(
            add(pending_windows, completed_windows)?,
            usize::from(active_window),
        )? > self.windows
            || originals > self.exchange.frames
        {
            return Err(credit());
        }
        Ok(())
    }

    /// Recounts supplied complete owners before the existing planner allocates.
    ///
    /// Reference/hash and source-result semantics remain the planner's existing
    /// independent checks. Changed fields may fit the same storage bound; equal
    /// storage data never establishes source identity or capture authority.
    pub(crate) fn authenticate_actual_inputs<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        response: &Envelope,
        objects: &[(&ContentRef, &[u8])],
    ) -> Result<(), ProviderError> {
        authenticate_connection(connection)?;
        self.authenticate_current_shape_data(connection)?;
        let expected_method = match self.kind {
            OriginalContinuationPrefixKind::Capture => Method::Begin,
            OriginalContinuationPrefixKind::AfterConfirmation => Method::Poll,
        };
        if response.message != MessageKind::Response
            || response.method != expected_method
            || objects.len() != self.objects.iter().flatten().count()
            || allowance(connection.authority.limits().blob_chunk_bytes.get())?.min(4096)
                != self.chunk_bytes
            || allowance(connection.authority.limits().requests.get())?.min(32)
                != self.simultaneous_requests
        {
            return Err(refused());
        }
        let original = connection
            .guard
            .incoming_requests()
            .next()
            .ok_or_else(refused)?;
        self.authenticate_response_original_clone_data(connection, original)?;
        if original.method != expected_method
            || (expected_method == Method::Begin
                && original.body.get("kind").and_then(Value::as_str) != Some("capture"))
            || response.request_id != original.request_id
            || response.session_id != original.session_id
            || response.incarnation_id != original.incarnation_id
            || response.node_id != original.node_id
            || response.execution_owner_id != original.execution_owner_id
            || response.capture_owner_id != original.capture_owner_id
            || response.operation_id != original.operation_id
        {
            return Err(refused());
        }
        connection.guard.preflight_original_packet_prefix_data(
            original,
            response.sequence.get(),
            1,
            0,
        )?;
        self.authenticate_terminal_storage_data(response)?;
        let mut observer = MetadataObserver::new();
        observer.observe(response)?;
        if requested_facts(&observer.finish())? > self.source_owner_requested_bytes {
            return Err(credit());
        }
        let mut frames = 1usize;
        for ((reference, bytes), extent) in objects.iter().zip(self.objects.iter().flatten()) {
            reference.validate()?;
            if bytes.len() > extent.payload
                || reference.media_type.len() > extent.media
                || reference.length.get() != u64::try_from(bytes.len()).map_err(|_| credit())?
            {
                return Err(credit());
            }
            frames = add(frames, add(2, bytes.len().div_ceil(self.chunk_bytes))?)?;
        }
        if frames > self.exchange.frames {
            return Err(credit());
        }
        connection
            .guard
            .preflight_confirmation_sequences(frames, frames - 1)?;
        self.preflight_transport_credit_data()?;
        // This is the actual same bank's remaining per-direction/lifetime
        // allowance, not the prospective scalar report or a renewed budget.
        connection
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| refused())?
            .preflight_framed_suffix(
                self.exchange.frames,
                self.exchange.outgoing_framed_bytes,
                self.exchange.requests,
                self.exchange.incoming_framed_bytes,
            )?;
        Ok(())
    }

    /// Reprojects the saved maximum shape on the actual current authority.
    ///
    /// Changing incoming Observe to Capture/Poll does not renew or replace the
    /// admitted incident baseline. Its independently projected future original
    /// term must cover the actual current sole guard before frames are built.
    pub(crate) fn authenticate_current_shape_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        authenticate_connection(connection)?;
        if current_containment(connection)? > self.containment_base_requested_bytes {
            return Err(credit());
        }
        let current = connection.quote_continuation_shape_data(ContinuationShape {
            kind: self.kind,
            terminal: &self.terminal,
            original: &self.original,
            objects: &self.objects,
            maximum_requested_bytes: self.maximum_requested_bytes,
            containment_base_requested_bytes: self.containment_base_requested_bytes,
        })?;
        if current.exchange != self.exchange
            || current.kind != self.kind
            || current.windows != self.windows
            || current.simultaneous_requests != self.simultaneous_requests
            || current.chunk_bytes != self.chunk_bytes
            || current.source_owner_requested_bytes != self.source_owner_requested_bytes
            || current.windows_requested_bytes != self.windows_requested_bytes
            || current.flat_plan_requested_bytes != self.flat_plan_requested_bytes
            || current.authority_clone_requested_bytes != self.authority_clone_requested_bytes
            || current.declared_planner_scratch_bytes != self.declared_planner_scratch_bytes
        {
            return Err(credit());
        }
        Ok(())
    }

    /// Checks actual moved source backing independently of future plan buffers.
    pub(crate) fn authenticate_source_owner_storage_data(
        &self,
        facts: &RetainedProtocolMetadataFacts,
    ) -> Result<(), ProviderError> {
        if requested_facts(facts)? > self.source_owner_requested_bytes {
            return Err(credit());
        }
        Ok(())
    }

    /// Checks actual current original clone storage before reply construction.
    ///
    /// Source ticket, semantic currency and callback/effect permission remain
    /// independent. This authenticates the same actor's sole retained original
    /// and its projected clone extent, without allocating that clone.
    pub(crate) fn authenticate_response_original_clone_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        authenticate_connection(connection)?;
        let mut originals = connection.guard.incoming_requests();
        if originals.next() != Some(original) || originals.next().is_some() {
            return Err(refused());
        }
        // The raw Envelope contains U64 and Value, never custom Bytes. Its
        // already-owned Value vector banks do not imply base64 formatter work.
        let actual = actual_serialization_storage_data(
            original,
            Default::default(),
            self.maximum_requested_bytes,
        )?;
        within_clone(&actual, &self.original)
    }

    /// Recounts actual raw terminal fields without issuing any live permission.
    pub(crate) fn authenticate_terminal_storage_data(
        &self,
        response: &Envelope,
    ) -> Result<(), ProviderError> {
        let actual = actual_serialization_storage_data(
            response,
            Default::default(),
            self.maximum_requested_bytes,
        )?;
        within(&actual, &self.terminal)
    }

    /// Compares actual current owner backing with the admitted named heap sum.
    ///
    /// Callers add every source/window/record child to one actual observer.
    /// Shared actor/bank payloads belong to the outer SDK graph and are not
    /// rewalked here. Partial failure peaks were admitted before publication.
    pub(crate) fn reconcile_owner_metadata_data(
        &self,
        facts: &RetainedProtocolMetadataFacts,
    ) -> Result<(), ProviderError> {
        if requested_facts(facts)?
            > sum(&[
                self.exchange.original_plan_requested_bytes,
                self.exchange.acknowledgement_index_requested_bytes,
                self.exchange.canonical_requested_bytes,
                self.exchange.record_slots_requested_bytes,
                self.exchange.successful_ack_cache_requested_bytes,
                self.source_owner_requested_bytes,
                self.windows_requested_bytes,
            ])?
        {
            return Err(credit());
        }
        Ok(())
    }
}

impl<S: ProviderStream> Connection<S> {
    /// Projects future closed Capture/confirmation transfers from current Observe.
    ///
    /// This counts all future originals without constructing them. The actual
    /// native producer must conjoin this with the current Observe prefix and
    /// both future incoming originals, SDK/native owners and whole allowance.
    /// Actual preparation rechecks the current owner, full terminal shape and
    /// independent remaining raw banks before constructing any proof frame.
    pub(crate) fn quote_original_continuation_prefix_storage_data(
        &self,
        first_observe_response: u64,
        original_observe: &Envelope,
        input: OriginalContinuationPrefixStorageInput<'_>,
    ) -> Result<OriginalContinuationPrefixStorageData, ProviderError> {
        authenticate_connection(self)?;
        if original_observe.method != Method::Observe {
            return Err(refused());
        }
        self.guard.preflight_original_packet_prefix_data(
            original_observe,
            first_observe_response,
            1,
            0,
        )?;
        let expected = match input.kind {
            OriginalContinuationPrefixKind::Capture => 3,
            OriginalContinuationPrefixKind::AfterConfirmation => 1,
        };
        if input.objects.len() != expected {
            return Err(credit());
        }
        let mut objects = [None; 3];
        for (index, object) in input.objects.iter().enumerate() {
            if object.media_type.is_empty()
                || object.media_type.len() > 128
                || !object
                    .media_type
                    .bytes()
                    .all(|byte| (0x20..=0x7e).contains(&byte))
            {
                return Err(credit());
            }
            objects[index] = Some(ContentExtent {
                payload: object.maximum_payload_bytes,
                media: object.media_type.len(),
            });
        }
        // A future sole Capture/Poll replaces the current Observe. Account its
        // independent guard key/tree/incident clone now, before it exists.
        let future_original = sum(&[
            input.original.dom_and_canonical_scratch_bytes,
            growth(128)?,
            super::super::super::restore_input_quote::tree_storage(
                1,
                1,
                size_of::<Id>() + size_of::<Envelope>(),
                align_of::<Id>().max(align_of::<Envelope>()),
            )?,
            mul(2, size_of::<Envelope>())?,
        ])?;
        let containment_base_requested_bytes = add(current_containment(self)?, future_original)?;
        self.quote_continuation_shape_data(ContinuationShape {
            kind: input.kind,
            terminal: input.terminal,
            original: input.original,
            objects: &objects,
            maximum_requested_bytes: input.maximum_requested_bytes,
            containment_base_requested_bytes,
        })
    }

    /// Counts the same planner at its actual sole Capture/Poll boundary.
    ///
    /// The original is already retained by this actual guard. Unlike the
    /// prospective Observe entry, this derives containment from that current
    /// original and creates no saved future-original or authority surrogate.
    pub(crate) fn quote_original_current_continuation_prefix_storage_data(
        &self,
        actual_original: &Envelope,
        input: OriginalContinuationPrefixStorageInput<'_>,
    ) -> Result<OriginalContinuationPrefixStorageData, ProviderError> {
        authenticate_connection(self)?;
        let mut originals = self.guard.incoming_requests();
        if originals.next() != Some(actual_original)
            || originals.next().is_some()
            || actual_original.message != MessageKind::Request
            || match input.kind {
                OriginalContinuationPrefixKind::Capture => {
                    actual_original.method != Method::Begin
                        || actual_original.body.get("kind").and_then(Value::as_str)
                            != Some("capture")
                }
                OriginalContinuationPrefixKind::AfterConfirmation => {
                    actual_original.method != Method::Poll
                }
            }
        {
            return Err(refused());
        }
        let expected = match input.kind {
            OriginalContinuationPrefixKind::Capture => 3,
            OriginalContinuationPrefixKind::AfterConfirmation => 1,
        };
        if input.objects.len() != expected {
            return Err(credit());
        }
        let actual = actual_serialization_storage_data(
            actual_original,
            Default::default(),
            input.maximum_requested_bytes,
        )?;
        within_clone(&actual, input.original)?;
        let mut objects = [None; 3];
        for (index, object) in input.objects.iter().enumerate() {
            if object.media_type.is_empty()
                || object.media_type.len() > 128
                || !object
                    .media_type
                    .bytes()
                    .all(|byte| (0x20..=0x7e).contains(&byte))
            {
                return Err(credit());
            }
            objects[index] = Some(ContentExtent {
                payload: object.maximum_payload_bytes,
                media: object.media_type.len(),
            });
        }
        self.quote_continuation_shape_data(ContinuationShape {
            kind: input.kind,
            terminal: input.terminal,
            original: input.original,
            objects: &objects,
            maximum_requested_bytes: input.maximum_requested_bytes,
            containment_base_requested_bytes: current_containment(self)?,
        })
    }

    fn quote_continuation_shape_data(
        &self,
        input: ContinuationShape<'_>,
    ) -> Result<OriginalContinuationPrefixStorageData, ProviderError> {
        authenticate_connection(self)?;
        let maximum_frame = allowance(self.authority.limits().frame_bytes.get())?;
        let chunk = allowance(self.authority.limits().blob_chunk_bytes.get())?.min(4096);
        let simultaneous = allowance(self.authority.limits().requests.get())?.min(32);
        let object_count = match input.kind {
            OriginalContinuationPrefixKind::Capture => 3,
            OriginalContinuationPrefixKind::AfterConfirmation => 1,
        };
        if chunk == 0
            || simultaneous == 0
            || maximum_frame > 65_536
            || input.objects.iter().flatten().count() != object_count
            || input.terminal.maximum_encoded_bytes > maximum_frame
        {
            return Err(credit());
        }
        let mut frames = 1usize;
        let mut payload = 0usize;
        let extents = *input.objects;
        for (index, object) in input.objects.iter().flatten().enumerate() {
            let maximum = match (input.kind, index) {
                (OriginalContinuationPrefixKind::Capture, 1) => 8192,
                (OriginalContinuationPrefixKind::Capture, _) => 8 * 1024 * 1024,
                // The actual after maximum is the separately selected source
                // reservation. The planner has no independent payload cap.
                (OriginalContinuationPrefixKind::AfterConfirmation, _) => usize::MAX,
            };
            if object.payload > maximum || object.media == 0 || object.media > 128 {
                return Err(credit());
            }
            frames = add(frames, add(2, object.payload.div_ceil(chunk))?)?;
            payload = add(payload, object.payload)?;
        }
        if frames > 4096 {
            return Err(credit());
        }
        let requests = frames - 1;
        let windows = add(requests.div_ceil(simultaneous), 1)?;
        let window_slots = add(mul(requests.div_ceil(simultaneous), simultaneous)?, 2)?;
        let mut data = OriginalPacketPrefixStorageData {
            native_retained_backing_bytes: None,
            frames,
            requests,
            evidence_payload_bytes: payload,
            outgoing_framed_bytes: 0,
            incoming_framed_bytes: mul(requests, add(maximum_frame, 4)?)?,
            new_transport_credit_bytes: 0,
            original_plan_requested_bytes: mul(window_slots, size_of::<Envelope>())?,
            acknowledgement_index_requested_bytes:
                super::super::super::restore_input_quote::tree_storage(
                    1,
                    object_count,
                    size_of::<Id>() + size_of::<ContentRef>(),
                    align_of::<Id>().max(align_of::<ContentRef>()),
                )?,
            canonical_requested_bytes: 0,
            record_slots_requested_bytes: sum(&[
                mul(frames, size_of::<Vec<u8>>())?,
                mul(frames, size_of::<Option<usize>>())?,
                mul(requests, size_of::<ReceivedFrame>())?,
                mul(windows, size_of::<ExchangeRecord>())?,
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
                input.containment_base_requested_bytes,
                mul(add(mul(2, requests)?, 8)?, size_of::<Envelope>())?,
            )?,
            construction_transient_requested_bytes: 0,
            preparation_transient_requested_bytes: 0,
            declared_quote_scratch_bytes: Self::original_packet_prefix_quote_scratch_bytes_data(),
            original_literal_required_bytes: mul(requests, add(maximum_frame, 4)?)?,
            original_slots_required: add(frames, requests)?,
        };
        let mut source_requested = input.terminal.dom_and_canonical_scratch_bytes;
        if input.kind == OriginalContinuationPrefixKind::Capture {
            source_requested = add(source_requested, payload)?;
        }
        let mut source_reference_fields = 0usize;
        for object in input.objects.iter().flatten() {
            let reference = reference_projection(object, input.maximum_requested_bytes)?;
            // The actual source keeps one independent fullref; its map key
            // and begin body clone receive their own backing below.
            source_reference_fields = add(
                source_reference_fields,
                reference.dom_and_canonical_scratch_bytes,
            )?;
            data.acknowledgement_index_requested_bytes = add(
                data.acknowledgement_index_requested_bytes,
                add(reference.dom_and_canonical_scratch_bytes, growth(128)?)?,
            )?;
            let prefix = match input.kind {
                OriginalContinuationPrefixKind::Capture => "packet-capture-transfer-",
                OriginalContinuationPrefixKind::AfterConfirmation => "packet-after-transfer-",
            };
            let transfer = add(prefix.len(), 20)?;
            charge_continuation_frame(
                &mut data,
                projected_frame(
                    &self.authority,
                    input.kind,
                    Method::BlobBegin,
                    ProjectedBody::Begin(transfer, object),
                    input.maximum_requested_bytes,
                )?,
                true,
                maximum_frame,
            )?;
            let mut remaining = object.payload;
            while remaining > 0 {
                let bytes = remaining.min(chunk);
                let encoded = mul(bytes.div_ceil(3), 4)?;
                data.construction_transient_requested_bytes =
                    data.construction_transient_requested_bytes.max(sum(&[
                        bytes,
                        encoded,
                        growth(transfer)?,
                        size_of::<BlobChunkRequest>(),
                    ])?);
                charge_continuation_frame(
                    &mut data,
                    projected_frame(
                        &self.authority,
                        input.kind,
                        Method::BlobChunk,
                        ProjectedBody::Chunk(transfer, encoded),
                        input.maximum_requested_bytes,
                    )?,
                    true,
                    maximum_frame,
                )?;
                remaining -= bytes;
            }
            charge_continuation_frame(
                &mut data,
                projected_frame(
                    &self.authority,
                    input.kind,
                    Method::BlobFinish,
                    ProjectedBody::Finish(transfer),
                    input.maximum_requested_bytes,
                )?,
                true,
                maximum_frame,
            )?;
        }
        // Source, completed response clone and one sequential validator DOM
        // are separate owners; retained frame/guard/canonical sums stay whole.
        charge_continuation_frame(
            &mut data,
            copy_storage(input.terminal),
            false,
            maximum_frame,
        )?;
        data.construction_transient_requested_bytes = data
            .construction_transient_requested_bytes
            .max(mul(input.terminal.requested_total()?, 4)?)
            .max(add(
                input.original.requested_total()?,
                input.terminal.requested_total()?,
            )?);
        data.new_transport_credit_bytes = add(
            mul(
                data.outgoing_framed_bytes
                    .checked_sub(mul(frames, 4)?)
                    .ok_or_else(credit)?,
                3,
            )?,
            mul(mul(requests, maximum_frame)?, 2)?,
        )?;
        self.guard
            .preflight_confirmation_sequences(frames, requests)?;
        let authority_clone_requested_bytes =
            if input.kind == OriginalContinuationPrefixKind::AfterConfirmation {
                let mut observer = MetadataObserver::new();
                self.authority
                    .observe_prospective_clone_metadata(&mut observer)?;
                requested_facts(&observer.finish())?
            } else {
                0
            };
        let result = OriginalContinuationPrefixStorageData {
            exchange: data,
            kind: input.kind,
            windows,
            simultaneous_requests: simultaneous,
            chunk_bytes: chunk,
            source_owner_requested_bytes: add(source_requested, source_reference_fields)?,
            windows_requested_bytes: mul(add(mul(windows, 4)?, 4)?, size_of::<Vec<Envelope>>())?,
            flat_plan_requested_bytes: mul(frames, size_of::<Envelope>())?,
            authority_clone_requested_bytes,
            declared_planner_scratch_bytes: sum(&[
                crate::reference_packet::continuation_transport::original_continuation_prefix_layout_data::<S>(input.kind)?,
                mul(2, size_of::<OriginalContinuationPrefixStorageData>())?,
                size_of::<ContinuationShape<'static>>(),
                size_of::<OriginalContinuationPrefixStorageInput<'static>>(),
                size_of::<VecDeque<Vec<Envelope>>>(),
                size_of::<Projection>(),
                size_of::<MetadataObserver<'static>>(),
                size_of::<RetainedProtocolMetadataFacts>(),
                size_of::<blake3::Hasher>(),
                20,
                64,
                "blake3-256".len(),
                "cnp.blob.v1".len(),
            ])?,
            terminal: copy_storage(input.terminal),
            original: copy_storage(input.original),
            objects: extents,
            maximum_requested_bytes: input.maximum_requested_bytes,
            containment_base_requested_bytes: input.containment_base_requested_bytes,
        };
        if result.requested_bytes()? > input.maximum_requested_bytes {
            return Err(credit());
        }
        result.preflight_transport_credit_data()?;
        Ok(result)
    }
}

fn authenticate_connection<S: ProviderStream>(
    connection: &Connection<S>,
) -> Result<(), ProviderError> {
    connection.protocol_owner.ensure_current()?;
    connection.authenticate_native5_source_codec()?;
    if connection.role != EndpointRole::Provider
        || !matches!(
            connection.native5_codec.as_deref(),
            Some(Native5CodecOwner::NativePacket(_))
        )
    {
        return Err(refused());
    }
    Ok(())
}

pub(super) fn copy_storage(
    value: &OriginalSerializationStorageData,
) -> OriginalSerializationStorageData {
    OriginalSerializationStorageData {
        dom_and_canonical_scratch_bytes: value.dom_and_canonical_scratch_bytes,
        retained_value_backing_bytes: value.retained_value_backing_bytes,
        projected_parser_requested_bytes: value.projected_parser_requested_bytes,
        canonical_output_requested_bytes: value.canonical_output_requested_bytes,
        serializer_temporary_requested_bytes: value.serializer_temporary_requested_bytes,
        declared_counter_scratch_bytes: value.declared_counter_scratch_bytes,
        maximum_encoded_bytes: value.maximum_encoded_bytes,
        sequence_elements: value.sequence_elements,
        sequence_containers: value.sequence_containers,
        serialized_value_nodes: value.serialized_value_nodes,
        serialized_capacity_records: value.serialized_capacity_records,
    }
}

// Raw Number uses an inline integer/float representation under the pinned
// serde_json default feature set. Clone allocates its DOM children, not a
// serializer/parser/output bank. Valid 1.0/1e0 Phase spelling must therefore
// not inherit the generic arbitrary-f64 encoded132 upper bound as clone work.
fn within_clone(
    actual: &OriginalSerializationStorageData,
    bound: &OriginalSerializationStorageData,
) -> Result<(), ProviderError> {
    if actual.dom_and_canonical_scratch_bytes > bound.dom_and_canonical_scratch_bytes
        || actual.retained_value_backing_bytes > bound.retained_value_backing_bytes
        || actual.sequence_elements > bound.sequence_elements
        || actual.sequence_containers > bound.sequence_containers
    {
        return Err(credit());
    }
    Ok(())
}

pub(super) fn within(
    actual: &OriginalSerializationStorageData,
    bound: &OriginalSerializationStorageData,
) -> Result<(), ProviderError> {
    for (actual, bound) in [
        (
            actual.dom_and_canonical_scratch_bytes,
            bound.dom_and_canonical_scratch_bytes,
        ),
        (
            actual.retained_value_backing_bytes,
            bound.retained_value_backing_bytes,
        ),
        (
            actual.projected_parser_requested_bytes,
            bound.projected_parser_requested_bytes,
        ),
        (
            actual.canonical_output_requested_bytes,
            bound.canonical_output_requested_bytes,
        ),
        (
            actual.serializer_temporary_requested_bytes,
            bound.serializer_temporary_requested_bytes,
        ),
        (
            actual.declared_counter_scratch_bytes,
            bound.declared_counter_scratch_bytes,
        ),
        (actual.maximum_encoded_bytes, bound.maximum_encoded_bytes),
        (actual.sequence_elements, bound.sequence_elements),
        (actual.sequence_containers, bound.sequence_containers),
        (actual.serialized_value_nodes, bound.serialized_value_nodes),
        (
            actual.serialized_capacity_records,
            bound.serialized_capacity_records,
        ),
    ] {
        if actual > bound {
            return Err(credit());
        }
    }
    Ok(())
}

// Every validator/parser temporary drops at its loop's semicolon. Previously
// completed originals/canonical/cache owners remain in their independent sums;
// those live children are never included in this sequential-phase maximum.
fn charge_continuation_frame(
    data: &mut OriginalPacketPrefixStorageData,
    frame: OriginalSerializationStorageData,
    request: bool,
    maximum_frame: usize,
) -> Result<(), ProviderError> {
    let preceding = data.preparation_transient_requested_bytes;
    charge_frame(data, frame, request, maximum_frame)?;
    let next = data
        .preparation_transient_requested_bytes
        .checked_sub(preceding)
        .ok_or_else(credit)?;
    data.preparation_transient_requested_bytes = preceding.max(next);
    Ok(())
}

pub(super) enum ProjectedBody<'a> {
    Begin(usize, &'a ContentExtent),
    Chunk(usize, usize),
    Finish(usize),
}

fn reference_fields(out: &mut Projection, object: &ContentExtent) -> Result<(), ProviderError> {
    out.add_object()?;
    out.add_field("hash")?;
    out.add_object()?;
    out.add_field("algorithm")?;
    out.add_string("blake3-256")?;
    out.add_field("domain")?;
    out.add_string("cnp.blob.v1")?;
    out.add_field("digest")?;
    out.add_unescaped_ascii_extent(64)?;
    out.add_field("length")?;
    let length = u64::try_from(object.payload).map_err(|_| credit())?;
    // The DATA counter projects U64's decimal JSON string directly. Its
    // ordinary serializer creates a temporary String before a native debit.
    out.add_unescaped_ascii_extent(length.checked_ilog10().unwrap_or(0) as usize + 1)?;
    out.add_field("media_type")?;
    // The contract permits quotes and backslashes in its printable ASCII.
    // Actual preparation bounds its byte length, so preserve worst escaping.
    out.add_string_extent(object.media)
}

pub(super) fn reference_projection(
    object: &ContentExtent,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut out = Projection::new(maximum)?;
    reference_fields(&mut out, object)?;
    out.finish(maximum)
}

fn projected_frame(
    authority: &ConnectionAuthority,
    kind: OriginalContinuationPrefixKind,
    method: Method,
    body: ProjectedBody<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let prefix = match kind {
        OriginalContinuationPrefixKind::Capture => "packet-capture-proof-",
        OriginalContinuationPrefixKind::AfterConfirmation => "packet-after-proof-",
    };
    projected_blob_frame(
        authority,
        kind == OriginalContinuationPrefixKind::AfterConfirmation,
        prefix,
        method,
        body,
        maximum,
    )
}

/// Counts the actual ordinary unscoped packet proof grammar without an owner.
pub(super) fn projected_packet_frame(
    authority: &ConnectionAuthority,
    method: Method,
    body: ProjectedBody<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    projected_blob_frame(authority, false, "packet-proof-", method, body, maximum)
}

fn projected_blob_frame(
    authority: &ConnectionAuthority,
    after_confirmation: bool,
    request_prefix: &str,
    method: Method,
    body: ProjectedBody<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    projected_blob_frame_scope(
        (authority.session_id(), authority.incarnation_id()),
        after_confirmation,
        request_prefix,
        method,
        body,
        maximum,
    )
}

/// Uses actual launch identities without constructing registration authority.
pub(super) fn projected_packet_startup_frame(
    session: &Id,
    incarnation: &Id,
    method: Method,
    body: ProjectedBody<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    projected_blob_frame_scope(
        (session, incarnation),
        false,
        "packet-proof-",
        method,
        body,
        maximum,
    )
}

fn projected_blob_frame_scope(
    scope: (&Id, &Id),
    after_confirmation: bool,
    request_prefix: &str,
    method: Method,
    body: ProjectedBody<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let (session, incarnation) = scope;
    let mut out = Projection::new(maximum)?;
    out.add_object()?;
    for (key, value) in [("protocol", "CNP/1"), ("message", "request")] {
        out.add_field(key)?;
        out.add_string(value)?;
    }
    out.add_field("session_id")?;
    out.add_value(session)?;
    out.add_field("incarnation_id")?;
    out.add_value(incarnation)?;
    for key in [
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "operation_id",
    ] {
        out.add_field(key)?;
        if after_confirmation && key != "execution_owner_id" {
            out.add_string_extent(128)?;
        } else {
            out.add_value(&Option::<Id>::None)?;
        }
    }
    out.add_field("request_id")?;
    out.add_unescaped_ascii_extent(add(request_prefix.len(), 20)?)?;
    out.add_field("sequence")?;
    out.add_unescaped_ascii_extent(20)?;
    out.add_field("method")?;
    out.add_value(&method)?;
    out.add_field("body")?;
    out.add_object()?;
    match body {
        ProjectedBody::Begin(transfer, object) => {
            out.add_field("transfer_id")?;
            out.add_unescaped_ascii_extent(transfer)?;
            out.add_field("content")?;
            reference_fields(&mut out, object)?;
        }
        ProjectedBody::Chunk(transfer, bytes) => {
            out.add_field("transfer_id")?;
            out.add_unescaped_ascii_extent(transfer)?;
            out.add_field("offset")?;
            out.add_unescaped_ascii_extent(20)?;
            out.add_field("bytes")?;
            out.add_unescaped_ascii_extent(bytes)?;
        }
        ProjectedBody::Finish(transfer) => {
            out.add_field("transfer_id")?;
            out.add_unescaped_ascii_extent(transfer)?;
        }
    }
    out.add_field("extensions")?;
    out.add_object()?;
    out.add_field("extensions")?;
    out.add_object()?;
    out.finish(maximum)
}

impl ExchangeRecord {
    /// Visits independently owned record children, excluding the shared bank.
    pub(crate) fn observe_original_continuation_storage_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        authenticate_connection(connection)?;
        let (actor, bank) = self.original_actor.as_ref().ok_or_else(refused)?;
        if !Rc::ptr_eq(actor, &connection.protocol_owner)
            || connection
                .original_frames
                .as_ref()
                .is_none_or(|actual| !Rc::ptr_eq(actual, bank))
        {
            return Err(refused());
        }
        observer.observe(&self.originals)?;
        observer.observe(&self.canonical)?;
        observer.observe(&self.original_slots)?;
        observer.vector::<ReceivedFrame>(self.acknowledgements.capacity())?;
        for received in &self.acknowledgements {
            observer.observe(&received.envelope)?;
            let ReceivedBody::Response(response) = &received.body else {
                return Err(refused());
            };
            observer.boxed_value(response.as_ref())?;
            match &response.shape {
                ResponseShape::Accepted {
                    result, extensions, ..
                }
                | ResponseShape::Completed {
                    result, extensions, ..
                } => {
                    observer.observe(result)?;
                    observer.observe(extensions)?;
                }
                ResponseShape::Error {
                    error, extensions, ..
                } => {
                    observer.observe(error)?;
                    observer.observe(extensions)?;
                }
            }
            match response.result.as_ref() {
                None => {}
                Some(MethodResult::BlobBegin(value)) => observer.observe(&value.transfer_id)?,
                Some(MethodResult::BlobChunk(value)) => observer.observe(&value.transfer_id)?,
                Some(MethodResult::BlobFinish(value)) => {
                    observer.observe(&value.transfer_id)?;
                    observer.observe(&value.content)?;
                }
                Some(_) => return Err(refused()),
            }
        }
        Ok(())
    }
}

impl<S: ProviderStream> PreparedExchange<S> {
    pub(crate) fn observe_original_continuation_storage_data(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.record
            .observe_original_continuation_storage_data(&self.connection, observer)
    }

    pub(crate) fn observe_original_continuation_prior_record_data(
        &self,
        record: &ExchangeRecord,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        record.observe_original_continuation_storage_data(&self.connection, observer)
    }

    /// Reconciles an actually retained same-actor window before registration.
    pub(crate) fn reconcile_original_continuation_window_storage_data(
        &self,
        data: &OriginalContinuationPrefixStorageData,
    ) -> Result<(), ProviderError> {
        if !matches!(self.phase, Phase::Unprepared | Phase::Prepared)
            || self.record.sent != 0
            || !self.record.acknowledgements.is_empty()
            || self.record.originals.len() > data.simultaneous_requests + 1
            || self
                .record
                .originals
                .iter()
                .filter(|frame| frame.message == MessageKind::Request)
                .count()
                > data.simultaneous_requests
        {
            return Err(refused());
        }
        let mut observer = MetadataObserver::new();
        self.observe_original_continuation_storage_data(&mut observer)?;
        data.reconcile_owner_metadata_data(&observer.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_numeric_phase_spelling_keeps_the_actual_inline_clone_layout()
    -> Result<(), Box<dyn std::error::Error>> {
        let maximum = 1024 * 1024;
        let mut projection = Projection::new(maximum)?;
        projection.add_object()?;
        projection.add_field("phase")?;
        projection.add_value(&crucible_node_contract::Phase::Publication)?;
        let projected = projection.finish(maximum)?;
        let raw = serde_json::json!({"phase":1.0});
        let actual = actual_serialization_storage_data(&raw, Default::default(), maximum)?;
        assert!(actual.maximum_encoded_bytes > projected.maximum_encoded_bytes);
        within_clone(&actual, &projected)?;
        let changed = serde_json::json!({"phase":1.0, "new_child":"x".repeat(4096)});
        let changed = actual_serialization_storage_data(&changed, Default::default(), maximum)?;
        assert!(within_clone(&changed, &projected).is_err());
        Ok(())
    }

    #[test]
    fn continuation_storage_preserves_and_checks_actual_serialization_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let actual = actual_serialization_storage_data(
            &serde_json::json!({"objects": ["snapshot", "control"]}),
            Default::default(),
            1024 * 1024,
        )?;
        let copied = copy_storage(&actual);
        assert!(actual.serialized_value_nodes > 0);
        assert!(actual.serialized_capacity_records > 0);
        assert_eq!(copied.serialized_value_nodes, actual.serialized_value_nodes);
        assert_eq!(
            copied.serialized_capacity_records,
            actual.serialized_capacity_records,
        );
        within(&actual, &copied)?;

        let mut fewer_values = copy_storage(&actual);
        fewer_values.serialized_value_nodes -= 1;
        assert!(within(&actual, &fewer_values).is_err());

        let mut fewer_records = copy_storage(&actual);
        fewer_records.serialized_capacity_records -= 1;
        assert!(within(&actual, &fewer_records).is_err());
        Ok(())
    }

    #[test]
    fn direct_decimal_extent_matches_actual_u64_counter_at_every_digit_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let same = |left: &OriginalSerializationStorageData,
                    right: &OriginalSerializationStorageData| {
            assert_eq!(left.maximum_encoded_bytes, right.maximum_encoded_bytes);
            assert_eq!(
                left.retained_value_backing_bytes,
                right.retained_value_backing_bytes
            );
            assert_eq!(
                left.dom_and_canonical_scratch_bytes,
                right.dom_and_canonical_scratch_bytes
            );
            assert_eq!(
                left.projected_parser_requested_bytes,
                right.projected_parser_requested_bytes
            );
            assert_eq!(
                left.canonical_output_requested_bytes,
                right.canonical_output_requested_bytes
            );
            assert_eq!(left.serialized_value_nodes, right.serialized_value_nodes);
            assert_eq!(
                left.serialized_capacity_records,
                right.serialized_capacity_records
            );
        };
        for power in 0..=19 {
            let base = 10u64.pow(power);
            for value in [
                base.saturating_sub(1),
                base,
                base.saturating_add(1),
                u64::MAX,
            ] {
                let mut actual = Projection::new(1024 * 1024)?;
                actual.add_value(&U64::new(value))?;
                let actual = actual.finish(1024 * 1024)?;
                let mut direct = Projection::new(1024 * 1024)?;
                direct
                    .add_unescaped_ascii_extent(value.checked_ilog10().unwrap_or(0) as usize + 1)?;
                let direct = direct.finish(1024 * 1024)?;
                same(&actual, &direct);
            }
        }
        Ok(())
    }
}
