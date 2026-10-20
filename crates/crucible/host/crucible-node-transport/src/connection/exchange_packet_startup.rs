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
    crucible_node_format::Validate::validate(&launch.limits)?;
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
    crucible_node_format::Validate::validate(&launch.limits)?;
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
    crucible_source_birth_data::original_packet_prefix_startup_body!(
        scope = scope, limits = limits, maximum_extensions = maximum_extensions,
        input = input, allow_empty_baseline = allow_empty_baseline, class = class,
        objects = OBJECTS, data = data,
        envelope_bytes = size_of::<Envelope>(), envelope_alignment = align_of::<Envelope>(),
        received_frame_bytes = size_of::<ReceivedFrame>(), exchange_record_bytes = size_of::<ExchangeRecord>(),
        response_iterator_bytes = size_of::<std::collections::btree_map::Values<'static, Id, Envelope>>(),
        reply_bytes = size_of::<crate::reference_packet::control::PacketControlReply>(),
        incident_bytes = size_of::<ConnectionIncident>(),
        body_header_bytes = size_of::<ResponseBody>().max(size_of::<RequestBody>()),
        ack = &acknowledgements::ACK_FIXED_LAYOUT,
        quote_scratch = Connection::<crate::client::DeadlineStream>::original_packet_prefix_quote_scratch_bytes_data(),
        startup_scratch = startup_counter_additional_scratch_data_for::<OBJECTS>(),
        adjustments = {
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
    if class == PrefixClass::RestoredObserve17 {
        data.declared_quote_scratch_bytes = add(
            data.declared_quote_scratch_bytes,
            super::super::restored_observation17::counter_scratch_data(),
        )?;
        data.construction_transient_requested_bytes = add(
            data.construction_transient_requested_bytes,
            super::super::restored_observation17::validation_transient_storage_data(),
        )?;
    }
    if class.is_capture17_upload_data() {
        data.declared_quote_scratch_bytes = add(
            data.declared_quote_scratch_bytes,
            super::super::capture17_upload::counter_scratch_data(),
        )?;
    }
        },
    )
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
        + 3 * size_of::<usize>()
}

// Preserves the original test-only shorthand using the production containment walk.
#[cfg(test)]
fn startup_containment(
    maximum_extensions: usize,
    original: &OriginalSerializationStorageData,
) -> Result<usize, ProviderError> {
    crucible_source_birth_data::profile::reference_packet::service::native_startup::packet_prefix::startup_containment(
        maximum_extensions,
        original,
        size_of::<Envelope>(),
        align_of::<Envelope>(),
        size_of::<ConnectionIncident>(),
    )
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

/// Quotes the closed selected Observe17 two-object producer before allocation.
///
/// # Errors
/// Refuses incomplete selected schemas, a non-Reactive launch, a changed two
/// object/JSON roster or any original frame, cardinality or storage ceiling.
pub(crate) fn quote_original_restored_observation17_prefix_startup_storage_data(
    launch: &PacketNative5SourceLaunch,
    input: OriginalPacketPrefixProjectionInput<'_>,
) -> Result<OriginalPacketPrefixProjectionStorageData<2>, ProviderError> {
    super::super::restored_input17::authenticate_launch_data(launch)?;
    if input.objects.len() != 2
        || input.objects.iter().any(|object| {
            object.media_type != "application/json" || object.maximum_payload_bytes == 0
        })
    {
        return Err(refused());
    }
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    quote_startup_parts_for::<2>(
        (
            &binding.authority.session_id,
            &binding.authority.incarnation_id,
        ),
        launch.limits,
        launch.selection.provider.extensions_supported.len(),
        input,
        false,
        PrefixClass::RestoredObserve17,
    )
}

/// Projects only the closed zero-evidence Capture upload response class.
///
/// This DATA producer neither authenticates a current native child nor creates
/// a Source signature, upload once owner or retained output allowance.
///
/// # Errors
/// Refuses another method, nonempty evidence, invalid limits or finite overflow.
pub(crate) fn quote_original_capture17_upload_prefix_startup_storage_data(
    launch: &PacketNative5SourceLaunch,
    method: Method,
    input: OriginalPacketPrefixProjectionInput<'_>,
) -> Result<OriginalPacketPrefixProjectionStorageData<0>, ProviderError> {
    crucible_node_format::Validate::validate(&launch.limits)?;
    if !matches!(
        method,
        Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
    ) || !input.objects.is_empty()
    {
        return Err(refused());
    }
    let binding = launch
        .selection
        .realization
        .bindings
        .first()
        .ok_or_else(refused)?;
    quote_startup_parts_for::<0>(
        (
            &binding.authority.session_id,
            &binding.authority.incarnation_id,
        ),
        launch.limits,
        launch.selection.provider.extensions_supported.len(),
        input,
        false,
        PrefixClass::CaptureUpload17(method),
    )
}

/// Reports actual private headers and fixed getters for the original prefix.
///
/// These are compiled layout measurements, not requested final rows, live
/// owner observations, allocation grants or native provenance.
pub fn original_packet_prefix_fixed_layout_data() -> crucible_source_birth_data::profile::reference_packet::service::native_startup::packet_prefix::startup::PacketPrefixFixedLayoutData{
    use crucible_source_birth_data::profile::reference_packet::service::native_startup::packet_prefix::startup::PacketPrefixFixedLayoutData;
    PacketPrefixFixedLayoutData {
        envelope_bytes: size_of::<Envelope>(),
        envelope_alignment: align_of::<Envelope>(),
        received_frame_bytes: size_of::<ReceivedFrame>(),
        exchange_record_bytes: size_of::<ExchangeRecord>(),
        response_iterator_bytes: size_of::<std::collections::btree_map::Values<'static, Id, Envelope>>(),
        reply_bytes: size_of::<crate::reference_packet::control::PacketControlReply>(),
        incident_bytes: size_of::<ConnectionIncident>(),
        body_header_bytes: size_of::<ResponseBody>().max(size_of::<RequestBody>()),
        quote_counter_scratch_bytes: Connection::<crate::client::DeadlineStream>::original_packet_prefix_quote_scratch_bytes_data(),
        startup_counter_scratch_bytes: startup_counter_additional_scratch_data(),
    }
}

/// Names the actual fixed result/control family of the compiled layout getter.
pub const fn original_packet_prefix_fixed_layout_counter_scratch_data() -> usize {
    2 * size_of::<crucible_source_birth_data::profile::reference_packet::service::native_startup::packet_prefix::startup::PacketPrefixFixedLayoutData>()
        + 2 * size_of::<usize>()
}

#[cfg(test)]
#[path = "exchange_packet_startup_original.rs"]
mod original;
