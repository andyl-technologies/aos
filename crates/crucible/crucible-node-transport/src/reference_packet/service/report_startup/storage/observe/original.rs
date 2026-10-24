//! Retains the complete pre-cut report shape and fixed-counter oracle.

use super::super::super::*;

#[path = "original/observe.rs"]
pub(super) mod observe;
#[path = "original/raw_record.rs"]
pub(super) mod raw_record;

/// Names actual fixed counter headers and compiled definition-generation storage.
///
/// This nonallocating getter is called before the storage producer. Overflow
/// returns an unadmittable demand, never a smaller default. Compiler/recursive
/// traversal frames and physical allocator overhead remain separate obligations.
pub(super) fn counter_scratch_data() -> usize {
    let result = schema_generation::requested_data().and_then(|schemas| {
        let terms: [usize; 48] = [
            size_of::<[usize; 48]>(),
            size_of::<&[usize]>(),
            size_of::<std::slice::Iter<'static, usize>>(),
            size_of::<Result<usize, ProviderError>>(),
            size_of::<[&str; 5]>(),
            size_of::<[&str; 6]>(),
            size_of::<[&str; 10]>(),
            size_of::<&[&str]>(),
            size_of::<std::slice::Iter<'static, &'static str>>(),
            size_of::<&&str>(),
            size_of::<&str>(),
            schemas,
            crate::reference_packet::control::original_observe_dispatch_scratch_data(),
            crate::reference_packet::endpoint::original_capture_report_quote_layout_data(),
            crate::reference_packet::endpoint::original_fresh_report_startup_publication_counter_scratch_data(),
            size_of::<PacketNativeReportStartupStorageData>(),
            size_of::<observe::OriginalObserveStartupShapes>(),
            size_of::<observe::OriginalObserveStartupShapes>(),
            size_of::<Result<observe::OriginalObserveStartupShapes, ProviderError>>(),
            size_of::<Result<OriginalSerializationStorageData, ProviderError>>(),
            size_of::<Result<PacketNativeReportStartupStorageData, ProviderError>>(),
            size_of::<&PacketNative5SourceLaunch>(),
            size_of::<PacketNativeReportStartupPurpose>(),
            size_of::<&PacketConnectedSourceProgram>(),
            size_of::<&crate::reference_packet::PacketProgramDefinition>(),
            size_of::<&mut OriginalSerializationStorageProjection>(),
            size_of::<&crate::reference_packet::PacketEvent>(),
            size_of::<std::slice::Iter<'static, crate::reference_packet::PacketEvent>>(),
            size_of::<std::ops::Range<usize>>(),
            size_of::<crucible_node_format::Position>(),
            size_of::<Result<(), ProviderError>>(),
            size_of::<OriginalSerializationStorageProjection>(),
            size_of::<OriginalSerializationStorageData>(),
            size_of::<MetadataObserver<'static>>(),
            size_of::<RetainedProtocolMetadataFacts>(),

            crate::reference_packet::service::ack_emitter::original_native_report_startup_scope_layout_data(),
            crate::connection::original_packet_prefix_startup_counter_scratch_data(),
            crate::connection::OriginalPacketPrefixStorageData::native_original_observe_prepared_lifetime_counter_scratch_data(),
            // The independent ACK arm retains its actual typed query and both
            // counter windows, using this direct three-term sum view.
            size_of::<[usize; 3]>(),
            size_of::<Result<usize, ProviderError>>(),
            size_of::<usize>(),
            crate::connection::original_report_query_receive_counter_scratch_data(),
            crate::reference_packet::service::fresh_restore_allocation::fresh_restore_allocation_startup_counter_scratch_data(),
            crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::requested_serialization_scratch_bytes(),
            crate::connection::NativeCaptureSdkStateQuote::requested_scratch_bytes(),
            crate::protocol_snapshot::owned11::correspondence::closed_envelope_comparison_scratch_data(),
            size_of::<[u8; 20]>(),
            layout::counter_scratch_data(),
        ];
        sum(&terms)
    });
    match result {
        Ok(bytes) => bytes,
        Err(_) => usize::MAX,
    }
}

/// Reads every old component without substituting the shared implementation.
pub(super) fn shape_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
    initial: bool,
) -> Result<[[usize; 11]; 6], ProviderError> {
    let shapes = if initial {
        observe::project_initial(launch, maximum)?
    } else {
        observe::project(launch, maximum)?
    };
    Ok([
        super::report_data(&shapes.original),
        super::report_data(&shapes.terminal),
        super::report_data(&shapes.receipt),
        super::report_data(&shapes.wrapper),
        super::report_data(&shapes.report),
        super::report_data(&shapes.raw),
    ])
}
