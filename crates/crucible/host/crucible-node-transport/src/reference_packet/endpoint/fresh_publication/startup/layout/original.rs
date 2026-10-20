//! Preserves the full original Fresh startup quoter and counter for controls.
//!
//! Only function names/visibility change. It keeps the original private layout
//! expressions rather than obtaining expected values from the new supplier.

use super::super::*;

/// Counts the closed actual publisher from the installed original launch.
///
/// The caller first admits the static counter window and independently checks
/// the full selected launch/schema tuple. This function neither constructs a
/// native owner nor authenticates a Source grant. The later live quote keeps
/// all unchanged frame/history/wire ceilings and recounts actual capacities.
pub(super) fn quote(
    launch: &PacketNative5SourceLaunch,
    maximum_requested_bytes: usize,
) -> Result<PacketNativeFreshPublicationStartupStorageData, ProviderError> {
    let shapes = fresh_restore_allocation_startup_shapes(launch, maximum_requested_bytes)?;
    let inventory = initial_inventory(&launch.program, maximum_requested_bytes)?;
    let objects = [OriginalContinuationContentExtent {
        maximum_payload_bytes: PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
        media_type: PACKET_FRESH_RESTORE_ALLOCATION_MEDIA,
    }];
    let prefix = crate::connection::quote_original_packet_prefix_startup_storage_data(
        launch,
        OriginalPacketPrefixProjectionInput {
            original: &shapes.original,
            terminal: &shapes.terminal,
            objects: &objects,
            maximum_requested_bytes,
        },
    )?;

    let reference_children = sum(&[
        "blake3-256".len(),
        "cnp.blob.v1".len(),
        64,
        PACKET_FRESH_RESTORE_ALLOCATION_MEDIA.len(),
    ])?;
    let inventory_hash_children = sum(&[
        "blake3-256".len(),
        64,
        "source-owned.packet-connected-inventory/4".len(),
    ])?;
    let retained = sum(&[
        crate::reference_packet::endpoint::fresh_restore::original_fresh_report_owner_layout_data(),
        // The real owner retains both the raw query Envelope and the decoded
        // Observe request. Ordinary planner containment clones are additional.
        mul(2, shapes.original.dom_and_canonical_scratch_bytes)?,
        shapes.query_typed_requested_bytes,
        size_of::<ReceivedFrame>(),
        size_of::<RequestBody>(),
        shapes.report_typed_requested_bytes,
        shapes.receipt_typed_requested_bytes,
        PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
        inventory.maximum_encoded_bytes,
        shapes.terminal.dom_and_canonical_scratch_bytes,
        size_of::<ObserveResult>(),
        size_of::<crate::reference_packet::control::PacketControlReply>(),
        size_of::<(ContentRef, Vec<u8>)>(),
        PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
        mul(2, inventory_hash_children)?,
        mul(3, reference_children)?,
        prefix.exchange.requested_bytes()?,
        prefix.source_owner_requested_bytes,
    ])?;
    let scratch = counter_scratch_data();
    let initial_receive = crate::connection::original_report_query_receive_storage_data(
        launch,
        crate::reference_packet::service::report_startup::PacketNativeReportStartupPurpose::FreshCompletedAdmit13,
    )?.requested_bytes()?;
    // The restricted receive has returned before publication starts. Its raw
    // parser/error work cannot overlap this complete encoding phase. Returned
    // raw/typed query owners remain independently retained above, including
    // failures; the live publication quote uses this same encoding sum.
    let transient = sum(&[
        inventory.requested_total()?,
        shapes.report_authentication_transient_requested_bytes,
        shapes.report.requested_total()?,
        shapes.receipt.requested_total()?,
        shapes.terminal.requested_total()?,
        shapes.original.requested_total()?,
        shapes.terminal.dom_and_canonical_scratch_bytes,
        shapes.receipt.dom_and_canonical_scratch_bytes,
        prefix.exchange.requested_bytes()?,
        prefix.declared_counter_scratch_bytes,
        scratch,
    ])?;
    let data = PacketNativeFreshPublicationStartupStorageData {
        retained_growth_bytes: retained,
        maximum_simultaneous_transient_bytes: initial_receive.max(transient),
        declared_counter_scratch_bytes: scratch,
    };
    if sum(&[
        data.retained_growth_bytes,
        data.maximum_simultaneous_transient_bytes,
        data.declared_counter_scratch_bytes,
    ])? > maximum_requested_bytes
    {
        return Err(exhausted());
    }
    Ok(data)
}

/// Names fixed real counter/header layouts before any projection or schema work.
///
/// The enclosing report-startup producer separately includes initial raw query
/// parsing and fixed schema generation. This getter excludes recursive/compiler
/// frames and allocator overhead. Overflow is an unadmittable demand.
pub(super) fn counter_scratch_data() -> usize {
    let terms = [
        original_fresh_report_publication_counter_scratch_data(),
        crate::connection::original_packet_prefix_startup_counter_scratch_data(),
        size_of::<PacketNativeFreshPublicationStartupStorageData>(),
        size_of::<Projection>(),
        2 * size_of::<OriginalSerializationStorageData>(),
        size_of::<FreshRestoreAllocationStartupShapes>(),
        size_of::<crate::connection::OriginalPacketPrefixProjectionStorageData>(),
        size_of::<[OriginalContinuationContentExtent<'static>; 1]>(),
        size_of::<[usize; 24]>(),
        size_of::<std::slice::Iter<'static, usize>>(),
        size_of::<std::slice::Iter<'static, crate::reference_packet::PacketEvent>>(),
        size_of::<[u8; 20]>(),
    ];
    terms
        .iter()
        .try_fold(std::mem::size_of_val(&terms), |total, term| {
            total.checked_add(*term)
        })
        .unwrap_or(usize::MAX)
}
