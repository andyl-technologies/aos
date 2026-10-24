//! Shares the actual original startup prefix frame loop.
//!
//! Transport expands the same source body with actual compiled private headers
//! and the original selected-17 adjustment statements at their original slots.
//! The original-only DATA entry uses genuine committed header facts and no
//! restored-input fields, token, archive, zero substitute or authority.

use super::*;
use crate::profile::handshake::Limits;

/// Shares the closed startup frame body with its actual upper constructor.
///
/// The finite expression slots preserve genuine private layout/counter queries;
/// the adjustment block stays at the original selected-class point. This macro
/// carries no runtime callback, native dispatch or deserialization surface.
#[macro_export]
macro_rules! original_packet_prefix_startup_body {
    (
        scope = $scope:ident, limits = $limits:ident,
        maximum_extensions = $maximum_extensions:ident, input = $input:ident,
        allow_empty_baseline = $allow_empty_baseline:ident, class = $class:ident,
        objects = $objects:ident, data = $data:ident,
        envelope_bytes = $envelope_bytes:expr, envelope_alignment = $envelope_alignment:expr,
        received_frame_bytes = $received_frame_bytes:expr, exchange_record_bytes = $exchange_record_bytes:expr,
        response_iterator_bytes = $response_iterator_bytes:expr, reply_bytes = $reply_bytes:expr,
        incident_bytes = $incident_bytes:expr, body_header_bytes = $body_header_bytes:expr,
        ack = $ack:expr, quote_scratch = $quote_scratch:expr,
        startup_scratch = $startup_scratch:expr, adjustments = $adjustments:block $(,)?
    ) => {{
        use $crate::profile::reference_packet::service::native_startup::packet_prefix as prefix;
        use $crate::profile::reference_packet::service::native_startup::packet_prefix::frames::ProjectedBody;
        use $crate::profile::reference_packet::service::native_startup::report_ack::open_ack_storage;
        use $crate::profile::requested_storage::tree_storage_data as tree_storage;
        use $crate::profile::envelope::Method;
        use ::crucible_node_format::{ContentRef, Id};
        use ::std::mem::{align_of, size_of};


        let (session, incarnation) = $scope;
        if (!$allow_empty_baseline && !$class.is_capture17_upload_data() && $input.objects.is_empty())
            || $input.objects.len() > $objects
        {
            return Err(prefix::refused());
        }
        let maximum_frame = prefix::allowance($limits.frame_bytes.get())?;
        let chunk = prefix::allowance($limits.blob_chunk_bytes.get())?.min(4096);
        if maximum_frame == 0 || chunk == 0 {
            return Err(prefix::credit());
        }
        let mut objects = [None; $objects];
        let mut payload = 0usize;
        let mut frames = 1usize;
        for (index, object) in $input.objects.iter().enumerate() {
            if object.maximum_payload_bytes > 65_536
                || object.media_type.is_empty()
                || object.media_type.len() > 128
                || !object
                    .media_type
                    .bytes()
                    .all(|byte| (0x20..=0x7e).contains(&byte))
            {
                return Err(prefix::credit());
            }
            payload = prefix::add(payload, object.maximum_payload_bytes)?;
            frames = prefix::add(
                frames,
                prefix::add(2, object.maximum_payload_bytes.div_ceil(chunk))?,
            )?;
            objects[index] = Some(prefix::frames::ContentExtent {
                payload: object.maximum_payload_bytes,
                media: object.media_type.len(),
            });
        }
        if payload > 4 * 1024 * 1024 {
            return Err(prefix::credit());
        }
        let requests = frames.checked_sub(1).ok_or_else(prefix::credit)?;
        let mut $data = prefix::OriginalPacketPrefixStorageData {
            native_retained_backing_bytes: None,
            frames,
            requests,
            evidence_payload_bytes: payload,
            outgoing_framed_bytes: 0,
            incoming_framed_bytes: prefix::mul(requests, prefix::add(maximum_frame, 4)?)?,
            new_transport_credit_bytes: 0,
            original_plan_requested_bytes: prefix::mul(frames, $envelope_bytes)?,
            acknowledgement_index_requested_bytes:
                tree_storage(
                    1,
                    $input.objects.len(),
                    size_of::<Id>() + size_of::<ContentRef>(),
                    align_of::<Id>().max(align_of::<ContentRef>()),
                )?,
            canonical_requested_bytes: 0,
            record_slots_requested_bytes: prefix::sum(&[
                prefix::mul(frames, size_of::<Vec<u8>>())?,
                prefix::mul(frames, size_of::<Option<usize>>())?,
                prefix::mul(requests, $received_frame_bytes)?,
                $exchange_record_bytes,
            ])?,
            outgoing_guard_requested_bytes: tree_storage(
                2,
                frames,
                size_of::<Id>() + $envelope_bytes,
                align_of::<Id>().max($envelope_alignment),
            )?,
            response_iterator_requested_bytes: prefix::mul(
                prefix::add(requests, 1)?,
                $response_iterator_bytes,
            )?,
            successful_ack_cache_requested_bytes: 0,
            one_open_ack_requested_bytes: if requests == 0 {
                0 // No provider proof request exists, so no ACK reader runs.
            } else {
                open_ack_storage(maximum_frame, $ack)?
            },
            containment_requested_bytes: prefix::add(
                prefix::startup_containment($maximum_extensions, $input.original, $envelope_bytes, $envelope_alignment, $incident_bytes)?,
                prefix::mul(prefix::add(prefix::mul(2, requests)?, 8)?, $envelope_bytes)?,
            )?,
            construction_transient_requested_bytes: $input.original.requested_total()?,
            preparation_transient_requested_bytes: 0,
            declared_quote_scratch_bytes: $quote_scratch,
            original_literal_required_bytes: prefix::mul(requests, prefix::add(maximum_frame, 4)?)?,
            original_slots_required: prefix::add(frames, requests)?,
        };
        $adjustments
        if $allow_empty_baseline
            || $class == prefix::PrefixClass::RestoredObserve17
            || $class.is_capture17_upload_data()
        {
            // The legacy containment projection mixes the original DOM and
            // canonical work. Replace that one named component by backing only;
            // all other actual guard/authority/map/root banks remain unchanged.
            let containment_backing = $data
                .containment_requested_bytes
                .checked_sub($input.original.dom_and_canonical_scratch_bytes)
                .and_then(|bytes| bytes.checked_add($input.original.retained_value_backing_bytes))
                .ok_or_else(prefix::credit)?;
            $data.native_retained_backing_bytes = Some(prefix::sum(&[
                $data.original_plan_requested_bytes,
                $data.acknowledgement_index_requested_bytes,
                $data.record_slots_requested_bytes,
                $data.outgoing_guard_requested_bytes,
                $data.response_iterator_requested_bytes,
                containment_backing,
            ])?);
        }
        let mut native_source_backing = prefix::sum(&[
            $input.terminal.retained_value_backing_bytes,
            payload,
            prefix::mul(
                prefix::add(prefix::mul(2, $input.objects.len())?, 4)?,
                size_of::<(ContentRef, Vec<u8>)>(),
            )?,
            $reply_bytes,
        ])?;
        let mut source_owner = prefix::sum(&[
            $input.terminal.dom_and_canonical_scratch_bytes,
            payload,
            prefix::mul(
                prefix::add(prefix::mul(2, $input.objects.len())?, 4)?,
                size_of::<(ContentRef, Vec<u8>)>(),
            )?,
            $reply_bytes,
        ])?;
        // Ordinary preparation retains its frame loop's complete work sum. Do
        // not substitute the continuation planner's sequential phase maximum.
        prefix::charge_frame(&mut $data, prefix::frames::copy_storage($input.terminal), false, 65_536, $body_header_bytes, $ack)?;
        let transfer = prefix::add("packet-transfer-".len(), 20)?;
        for object in objects.iter().flatten() {
            let reference = prefix::frames::reference_projection(object, $input.maximum_requested_bytes)?;
            source_owner = prefix::add(source_owner, reference.dom_and_canonical_scratch_bytes)?;
            native_source_backing = prefix::add(
                native_source_backing,
                reference.retained_value_backing_bytes,
            )?;
            if let Some(retained) = $data.native_retained_backing_bytes.as_mut() {
                *retained = prefix::add(
                    *retained,
                    prefix::add(reference.retained_value_backing_bytes, prefix::growth(transfer)?)?,
                )?;
            }

            $data.acknowledgement_index_requested_bytes = prefix::add(
                $data.acknowledgement_index_requested_bytes,
                prefix::add(reference.dom_and_canonical_scratch_bytes, prefix::growth(transfer)?)?,
            )?;
            for (method, body) in [
                (Method::BlobBegin, ProjectedBody::Begin(transfer, object)),
                (Method::BlobFinish, ProjectedBody::Finish(transfer)),
            ] {
                prefix::charge_frame(
                    &mut $data,
                    prefix::frames::projected_packet_startup_frame(
                        session,
                        incarnation,
                        method,
                        body,
                        $input.maximum_requested_bytes,
                    )?,
                    true,
                    65_536, $body_header_bytes, $ack)?;
            }
            let mut remaining = object.payload;
            while remaining > 0 {
                let bytes = remaining.min(chunk);
                let encoded = prefix::mul(bytes.div_ceil(3), 4)?;
                $data.construction_transient_requested_bytes = prefix::add(
                    $data.construction_transient_requested_bytes,
                    prefix::sum(&[bytes, encoded, prefix::growth(transfer)?])?,
                )?;
                prefix::charge_frame(
                    &mut $data,
                    prefix::frames::projected_packet_startup_frame(
                        session,
                        incarnation,
                        Method::BlobChunk,
                        ProjectedBody::Chunk(transfer, encoded),
                        $input.maximum_requested_bytes,
                    )?,
                    true,
                    65_536, $body_header_bytes, $ack)?;
                remaining -= bytes;
            }
        }
        let outgoing_bodies = $data
            .outgoing_framed_bytes
            .checked_sub(prefix::mul(frames, 4)?)
            .ok_or_else(prefix::credit)?;
        $data.new_transport_credit_bytes = prefix::add(
            prefix::mul(outgoing_bodies, 3)?,
            prefix::mul(prefix::mul(requests, maximum_frame)?, 2)?,
        )?;
        let result = prefix::OriginalPacketPrefixProjectionStorageData {
            exchange: $data,
            source_owner_requested_bytes: source_owner,
            native_source_backing_bytes: ($allow_empty_baseline
                || $class == prefix::PrefixClass::RestoredObserve17
                || $class.is_capture17_upload_data())
            .then_some(native_source_backing),
            declared_counter_scratch_bytes: $startup_scratch,
            terminal: prefix::frames::copy_storage($input.terminal),
            original: prefix::frames::copy_storage($input.original),
            objects,
            class: $class,
            maximum_requested_bytes: $input.maximum_requested_bytes,
        };
        if result.requested_bytes()? > $input.maximum_requested_bytes {
            return Err(prefix::credit());
        }
        Ok(result)

    }};
}

/// Carries original upper compiled headers and defining fixed-counter outputs.
///
/// These measurements grant no backing, allocation, frame allowance or native
/// authority. A selected parent must remeasure and bind the actual originals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketPrefixFixedLayoutData {
    /// Names the actual compiled Envelope header.
    pub envelope_bytes: usize,
    /// Names its actual alignment.
    pub envelope_alignment: usize,
    /// Names the actual retained ReceivedFrame header.
    pub received_frame_bytes: usize,
    /// Names the actual original ExchangeRecord header.
    pub exchange_record_bytes: usize,
    /// Names the actual borrowed BTree response-iterator header.
    pub response_iterator_bytes: usize,
    /// Names the actual PacketControlReply header.
    pub reply_bytes: usize,
    /// Names the actual ConnectionIncident header.
    pub incident_bytes: usize,
    /// Names the maximum actual request/response body header.
    pub body_header_bytes: usize,
    /// Names the actual original fixed quote-counter getter output.
    pub quote_counter_scratch_bytes: usize,
    /// Names the actual original fixed startup-counter getter output.
    pub startup_counter_scratch_bytes: usize,
}

/// Counts the actual original Observe or baseline prefix from borrowed operands.
///
/// This is the original internal parts calculation. Callers independently
/// validate limits and the baseline zero/two-evidence selector before using
/// the DATA. It grants no dispatch, provenance, allocation or transport credit.
///
/// # Errors
/// Preserves the original cardinality, media, frame, layout and arithmetic refusals.
pub fn quote_original_parts(
    scope: (&Id, &Id),
    limits: Limits,
    maximum_extensions: usize,
    input: OriginalPacketPrefixProjectionInput<'_>,
    allow_empty_baseline: bool,
    fixed: &PacketPrefixFixedLayoutData,
    ack: &super::super::report_ack::AckFixedLayoutData,
) -> Result<OriginalPacketPrefixProjectionStorageData, ProviderError> {
    const OBJECTS: usize = 3;
    let class = PrefixClass::Observe;
    crate::original_packet_prefix_startup_body!(
        scope = scope,
        limits = limits,
        maximum_extensions = maximum_extensions,
        input = input,
        allow_empty_baseline = allow_empty_baseline,
        class = class,
        objects = OBJECTS,
        data = data,
        envelope_bytes = fixed.envelope_bytes,
        envelope_alignment = fixed.envelope_alignment,
        received_frame_bytes = fixed.received_frame_bytes,
        exchange_record_bytes = fixed.exchange_record_bytes,
        response_iterator_bytes = fixed.response_iterator_bytes,
        reply_bytes = fixed.reply_bytes,
        incident_bytes = fixed.incident_bytes,
        body_header_bytes = fixed.body_header_bytes,
        ack = ack,
        quote_scratch = fixed.quote_counter_scratch_bytes,
        startup_scratch = fixed.startup_counter_scratch_bytes,
        adjustments = {},
    )
}

/// Counts the existing original Observe prefix from actual nonsecret fields.
///
/// # Errors
/// Preserves original limit validation, absent-binding, cardinality, media,
/// frame and checked-storage refusals in their original order.
pub fn quote_original_data(
    launch: &crate::profile::reference_packet::service::PacketNative5LaunchValidationFields<'_>,
    input: OriginalPacketPrefixProjectionInput<'_>,
    fixed: &PacketPrefixFixedLayoutData,
    ack: &super::super::report_ack::AckFixedLayoutData,
) -> Result<OriginalPacketPrefixProjectionStorageData, ProviderError> {
    crucible_node_format::Validate::validate(launch.limits)?;
    let binding = launch
        .selection
        .realization
        .bindings
        .first()
        .ok_or_else(refused)?;
    quote_original_parts(
        (
            &binding.authority.session_id,
            &binding.authority.incarnation_id,
        ),
        *launch.limits,
        launch.selection.provider.extensions_supported.len(),
        input,
        false,
        fixed,
        ack,
    )
}

/// Counts the existing zero/two-evidence baseline from actual nonsecret fields.
///
/// # Errors
/// Preserves original limit validation, baseline cardinality, absent-binding,
/// media, frame and checked-storage refusals in their original order.
pub fn quote_baseline_data(
    launch: &crate::profile::reference_packet::service::PacketNative5LaunchValidationFields<'_>,
    input: OriginalPacketPrefixProjectionInput<'_>,
    fixed: &PacketPrefixFixedLayoutData,
    ack: &super::super::report_ack::AckFixedLayoutData,
) -> Result<OriginalPacketPrefixProjectionStorageData, ProviderError> {
    crucible_node_format::Validate::validate(launch.limits)?;
    if !matches!(input.objects.len(), 0 | 2) {
        return Err(refused());
    }
    let binding = launch
        .selection
        .realization
        .bindings
        .first()
        .ok_or_else(refused)?;
    quote_original_parts(
        (
            &binding.authority.session_id,
            &binding.authority.incarnation_id,
        ),
        *launch.limits,
        launch.selection.provider.extensions_supported.len(),
        input,
        true,
        fixed,
        ack,
    )
}
