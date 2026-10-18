//! Counts prospective report prefix storage from an installed launch before birth.
//!
//! This is closed requested-layout data. It does not create a connection or
//! admit a hypothetical maximum-shaped suffix to any wire or frame bank. The
//! live counter and actual builder must independently enforce unchanged limits.

use super::*;
use crate::reference_packet::service::PacketNative5SourceLaunch;

pub(crate) fn quote_original_packet_prefix_startup_storage_data(
    launch: &PacketNative5SourceLaunch,
    input: OriginalPacketPrefixProjectionInput<'_>,
) -> Result<OriginalPacketPrefixProjectionStorageData, ProviderError> {
    crucible_node_contract::Validate::validate(&launch.limits)?;
    let binding = launch
        .selection
        .realization
        .bindings
        .first()
        .ok_or_else(refused)?;
    quote_startup_parts(
        (
            &binding.authority.session_id,
            &binding.authority.incarnation_id,
        ),
        launch.limits,
        launch.selection.provider.extensions_supported.len(),
        input,
        false,
    )
}

/// Counts the same closed initial Discover/Realize/Admit proof grammar.
///
/// Only the baseline constructor projection calls this data function. Empty
/// evidence means the actual Discover/Admit response has no ACK receive phase;
/// Realize independently names both actual proof objects. This issues no scope.
pub(crate) fn quote_original_packet_baseline_prefix_startup_storage_data(
    launch: &PacketNative5SourceLaunch,
    input: OriginalPacketPrefixProjectionInput<'_>,
) -> Result<OriginalPacketPrefixProjectionStorageData, ProviderError> {
    crucible_node_contract::Validate::validate(&launch.limits)?;
    if !matches!(input.objects.len(), 0 | 2) {
        return Err(refused());
    }
    let binding = launch
        .selection
        .realization
        .bindings
        .first()
        .ok_or_else(refused)?;
    quote_startup_parts(
        (
            &binding.authority.session_id,
            &binding.authority.incarnation_id,
        ),
        launch.limits,
        launch.selection.provider.extensions_supported.len(),
        input,
        true,
    )
}

fn quote_startup_parts(
    scope: (&Id, &Id),
    limits: crate::handshake::Limits,
    maximum_extensions: usize,
    input: OriginalPacketPrefixProjectionInput<'_>,
    allow_empty_baseline: bool,
) -> Result<OriginalPacketPrefixProjectionStorageData, ProviderError> {
    quote_startup_parts_for::<3>(
        scope,
        limits,
        maximum_extensions,
        input,
        allow_empty_baseline,
        PrefixClass::Observe,
    )
}

fn quote_startup_parts_for<const OBJECTS: usize>(
    scope: (&Id, &Id),
    limits: crate::handshake::Limits,
    maximum_extensions: usize,
    input: OriginalPacketPrefixProjectionInput<'_>,
    allow_empty_baseline: bool,
    class: PrefixClass,
) -> Result<OriginalPacketPrefixProjectionStorageData<OBJECTS>, ProviderError> {
    let (session, incarnation) = scope;
    if (!allow_empty_baseline && input.objects.is_empty()) || input.objects.len() > OBJECTS {
        return Err(refused());
    }
    let maximum_frame = allowance(limits.frame_bytes.get())?;
    let chunk = allowance(limits.blob_chunk_bytes.get())?.min(4096);
    if maximum_frame == 0 || chunk == 0 {
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
            crate::connection::restore_input_quote::tree_storage(
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
        outgoing_guard_requested_bytes: crate::connection::restore_input_quote::tree_storage(
            2,
            frames,
            size_of::<Id>() + size_of::<Envelope>(),
            align_of::<Id>().max(align_of::<Envelope>()),
        )?,
        response_iterator_requested_bytes: mul(
            add(requests, 1)?,
            size_of::<std::collections::btree_map::Values<'static, Id, Envelope>>(),
        )?,
        successful_ack_cache_requested_bytes: 0,
        one_open_ack_requested_bytes: if requests == 0 {
            0 // No provider proof request exists, so no ACK reader runs.
        } else {
            acknowledgements::open_ack_storage(maximum_frame)?
        },
        containment_requested_bytes: add(
            startup_containment(maximum_extensions, input.original)?,
            mul(add(mul(2, requests)?, 8)?, size_of::<Envelope>())?,
        )?,
        construction_transient_requested_bytes: input.original.requested_total()?,
        preparation_transient_requested_bytes: 0,
        declared_quote_scratch_bytes: Connection::<crate::client::DeadlineStream>::original_packet_prefix_quote_scratch_bytes_data(),
        original_literal_required_bytes: mul(requests, add(maximum_frame, 4)?)?,
        original_slots_required: add(frames, requests)?,
    };
    if class == PrefixClass::RestoredInput17 {
        data.declared_quote_scratch_bytes = add(
            data.declared_quote_scratch_bytes,
            super::super::restored_input17::counter_scratch_data(),
        )?;
        data.construction_transient_requested_bytes = add(
            data.construction_transient_requested_bytes,
            super::super::restored_input17::validation_transient_storage_data(),
        )?;
    }
    if allow_empty_baseline {
        // The legacy containment projection mixes the original DOM and
        // canonical work. Replace that one named component by backing only;
        // all other actual guard/authority/map/root banks remain unchanged.
        let containment_backing = data
            .containment_requested_bytes
            .checked_sub(input.original.dom_and_canonical_scratch_bytes)
            .and_then(|bytes| bytes.checked_add(input.original.retained_value_backing_bytes))
            .ok_or_else(credit)?;
        data.native_retained_backing_bytes = Some(sum(&[
            data.original_plan_requested_bytes,
            data.acknowledgement_index_requested_bytes,
            data.record_slots_requested_bytes,
            data.outgoing_guard_requested_bytes,
            data.response_iterator_requested_bytes,
            containment_backing,
        ])?);
    }
    let mut native_source_backing = sum(&[
        input.terminal.retained_value_backing_bytes,
        payload,
        mul(
            add(mul(2, input.objects.len())?, 4)?,
            size_of::<(ContentRef, Vec<u8>)>(),
        )?,
        size_of::<crate::reference_packet::control::PacketControlReply>(),
    ])?;
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
    charge_frame(&mut data, copy_storage(input.terminal), false, 65_536)?;
    let transfer = add("packet-transfer-".len(), 20)?;
    for object in objects.iter().flatten() {
        let reference = continuation::reference_projection(object, input.maximum_requested_bytes)?;
        source_owner = add(source_owner, reference.dom_and_canonical_scratch_bytes)?;
        native_source_backing = add(
            native_source_backing,
            reference.retained_value_backing_bytes,
        )?;
        if let Some(retained) = data.native_retained_backing_bytes.as_mut() {
            *retained = add(
                *retained,
                add(reference.retained_value_backing_bytes, growth(transfer)?)?,
            )?;
        }

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
                continuation::projected_packet_startup_frame(
                    session,
                    incarnation,
                    method,
                    body,
                    input.maximum_requested_bytes,
                )?,
                true,
                65_536,
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
                continuation::projected_packet_startup_frame(
                    session,
                    incarnation,
                    Method::BlobChunk,
                    ProjectedBody::Chunk(transfer, encoded),
                    input.maximum_requested_bytes,
                )?,
                true,
                65_536,
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
    let result = OriginalPacketPrefixProjectionStorageData {
        exchange: data,
        source_owner_requested_bytes: source_owner,
        native_source_backing_bytes: allow_empty_baseline.then_some(native_source_backing),
        declared_counter_scratch_bytes: startup_counter_additional_scratch_data_for::<OBJECTS>(),
        terminal: copy_storage(input.terminal),
        original: copy_storage(input.original),
        objects,
        class,
        maximum_requested_bytes: input.maximum_requested_bytes,
    };
    if result.requested_bytes()? > input.maximum_requested_bytes {
        return Err(credit());
    }
    Ok(result)
}

/// Bounds containment with the normative sole incoming report query.
fn startup_containment(
    extensions: usize,
    original: &OriginalSerializationStorageData,
) -> Result<usize, ProviderError> {
    // Fresh13 maps its Query and PrepareBinding keys to one selected feature.
    // The closed installed mapping has at most two keys per advertised feature;
    // charge both Id-bounded names even when that feature is not selected.
    // The independent confirmation key retains its own additional entry.
    let mapped_keys = mul(2, extensions)?;
    let tree = crate::connection::restore_input_quote::tree_storage(
        4,
        add(mapped_keys, 1)?,
        size_of::<Id>() + size_of::<Envelope>(),
        align_of::<Id>().max(align_of::<Envelope>()),
    )?;
    sum(&[
        original.dom_and_canonical_scratch_bytes,
        // Guard and authority retain independently cloned session/incarnation
        // IDs plus connection ID; the incoming map independently clones its key.
        mul(6, 128)?,
        mul(mapped_keys, 128)?,
        tree,
        mul(10, size_of::<Envelope>())?,
        size_of::<ConnectionIncident>(),
    ])
}

/// Names fixed counter/header scratch before any prospective quote is built.
///
/// This excludes compiler frames, recursive serde frames, allocator overhead
/// and native caller-specific counters. No allocation or allowance is issued.
pub(crate) const fn original_packet_prefix_startup_counter_scratch_data() -> usize {
    Connection::<crate::client::DeadlineStream>::original_packet_prefix_quote_scratch_bytes_data()
        + startup_counter_additional_scratch_data()
}

const fn startup_counter_additional_scratch_data() -> usize {
    startup_counter_additional_scratch_data_for::<3>()
}

const fn startup_counter_additional_scratch_data_for<const OBJECTS: usize>() -> usize {
    size_of::<[usize; 4]>()
        + size_of::<Option<&mut usize>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<OriginalPacketPrefixProjectionStorageData<OBJECTS>>()
        + size_of::<OriginalPacketPrefixProjectionInput<'static>>()
        + size_of::<[Option<ContentExtent>; OBJECTS]>()
        + size_of::<(&Id, &Id)>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + 3 * size_of::<OriginalSerializationStorageData>()
}

#[cfg(test)]
#[path = "exchange_packet_startup_tests.rs"]
mod tests;

#[cfg(test)]
pub(in crate::connection) fn native_observe_projection_for_test(
    scope: (&Id, &Id),
    limits: crate::handshake::Limits,
    input: OriginalPacketPrefixProjectionInput<'_>,
) -> Result<OriginalPacketPrefixProjectionStorageData, ProviderError> {
    quote_startup_parts(scope, limits, 0, input, false)
}

/// Projects the distinct five-evidence Input17 producer without allocating it.
///
/// This closed constructor admits no request. Actual publication independently
/// authenticates its Source action scope and exact five-role completed reply.
///
/// # Errors
/// Refuses another full selected schema, non-Reactive launch, a changed five
/// role roster, unchanged object/frame ceilings or arithmetic/storage overflow.
pub(crate) fn quote_original_restored_input17_prefix_startup_storage_data(
    launch: &PacketNative5SourceLaunch,
    input: OriginalPacketPrefixProjectionInput<'_>,
) -> Result<OriginalPacketPrefixProjectionStorageData<5>, ProviderError> {
    super::super::restored_input17::authenticate_launch_data(launch)?;
    if input.objects.len() != 5
        || input
            .objects
            .iter()
            .any(|object| object.media_type != "application/json")
    {
        return Err(refused());
    }
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    quote_startup_parts_for::<5>(
        (
            &binding.authority.session_id,
            &binding.authority.incarnation_id,
        ),
        launch.limits,
        launch.selection.provider.extensions_supported.len(),
        input,
        false,
        PrefixClass::RestoredInput17,
    )
}
