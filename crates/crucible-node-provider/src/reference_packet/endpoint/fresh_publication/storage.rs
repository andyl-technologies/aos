//! Counts the real Fresh publication before allocating its report or prefix.
//!
//! Current census facts are rechecked, not retagged as future storage. The new
//! report, inventory encoding, cached terminal and ordinary proof planner are
//! independently named. Conservative complete phase sums preserve raw R and the
//! original B/F/J limits; equal bounds create no startup permission.

use super::*;
use crate::connection::{
    OriginalContinuationContentExtent, OriginalPacketPrefixProjectionInput,
    OriginalPacketPrefixProjectionStorageData,
};
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, actual_serialization_storage_data,
    original_serialization_formatter_temporary_storage_data,
};
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};

pub(super) struct NativeFreshPublicationPlan {
    pub(super) shapes: FreshRestoreAllocationStartupShapes,
    pub(super) inventory: OriginalSerializationStorageData,
    pub(super) prefix: OriginalPacketPrefixProjectionStorageData,
    pub(super) row: PacketNativeReportStartupAllocationRow,
    pub(super) declared_full_scratch: usize,
}

pub(super) fn quote(
    endpoint: &PacketEndpoint<DeadlineStream>,
) -> Result<NativeFreshPublicationPlan, ProviderError> {
    endpoint.ensure_complete_origin()?;
    if !endpoint.held
        || endpoint.records.len() >= EXCHANGES
        || endpoint.records.len() >= endpoint.records.capacity()
    {
        return Err(refused());
    }
    let Some(Transport::Connected(connection)) = endpoint.transport.as_ref() else {
        return Err(refused());
    };
    let attempt = endpoint
        .fresh_restore_attempt
        .as_ref()
        .ok_or_else(refused)?
        .try_borrow()
        .map_err(|_| refused())?;
    attempt.authenticate_current(connection)?;
    attempt
        .startup
        .authenticate_complete_native_baseline(connection)?;
    if !attempt.publication.is_unstarted() {
        return Err(refused());
    }
    let current = attempt.current.as_ref().ok_or_else(refused)?;
    authenticate_current_census(endpoint, current)?;
    let scratch = original_fresh_report_publication_counter_scratch_data();
    attempt.startup.authenticate_compiled_headers(
        connection,
        scratch,
        super::super::fresh_restore::original_fresh_report_owner_layout_data(),
    )?;
    let policy = &connection.original_native_owned11_admission()?.policy;
    let view = endpoint.native.borrow_original_fresh_report_data(policy)?;
    let fields = view.inventory_formatter_fields_data()?;
    let retained_fields = view.inventory_fields_data();
    if fields.vector_capacity_bytes > retained_fields.vector_capacity_bytes
        || fields.vector_banks > retained_fields.vector_banks
    {
        return Err(refused());
    }
    // A real Bytes formatter allocates before entering the shared counter.
    // Authenticate this exact actual-vector-bank term first, without Serialize.
    let formatter = original_serialization_formatter_temporary_storage_data(&fields)?;
    let counter_row = PacketNativeReportStartupAllocationRow {
        raw_report_capacity: quantity(PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY)?,
        retained_growth_bytes: quantity(std::mem::size_of::<NativeFreshReportPublication>())?,
        maximum_simultaneous_transient_bytes: quantity(add(formatter, scratch)?)?,
        declared_counter_scratch_bytes: quantity(scratch)?,
    };
    attempt
        .startup
        .authenticate_actual_data(connection, &counter_row)?;
    let maximum = attempt.startup.maximum_requested_bytes()?;
    let inventory = actual_serialization_storage_data(&view.inventory_data(), fields, maximum)?;
    let shapes = fresh_restore_allocation_host_shapes(view.selection_data(), maximum)?;
    let frame = attempt.input.frame.as_ref().ok_or_else(refused)?;
    let mut original_fields = MetadataObserver::new();
    original_fields.observe(&frame.envelope)?;
    let original =
        actual_serialization_storage_data(&frame.envelope, original_fields.finish(), maximum)?;
    let objects = [OriginalContinuationContentExtent {
        maximum_payload_bytes: PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
        media_type: PACKET_FRESH_RESTORE_ALLOCATION_MEDIA,
    }];
    let prefix = connection.quote_original_packet_prefix_projection_storage_data(
        endpoint.next_sequence,
        &frame.envelope,
        OriginalPacketPrefixProjectionInput {
            original: &original,
            terminal: &shapes.terminal,
            objects: &objects,
            maximum_requested_bytes: maximum,
        },
    )?;
    prefix
        .exchange
        .preflight_transport_credit_data(endpoint.transport_credit)?;
    let prepare = attempt
        .prepare
        .original_fixed_prepare_storage_data(connection)?;
    let declared_full_scratch = add(scratch, prepare.declared_counter_scratch_bytes())?;
    // The prefix's complete requested sum also includes its temporary phases.
    // Keeping that complete amount in growth is a conservative retained upper,
    // never a claim that all those buffers survive or an allocator measurement.
    let retained = sum(&[
        std::mem::size_of::<NativeFreshReportPublication>(),
        shapes.report_typed_requested_bytes,
        shapes.receipt_typed_requested_bytes,
        PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
        inventory.maximum_encoded_bytes,
        shapes.terminal.dom_and_canonical_scratch_bytes,
        std::mem::size_of::<ObserveResult>(),
        std::mem::size_of::<super::super::super::control::PacketControlReply>(),
        std::mem::size_of::<(ContentRef, Vec<u8>)>(),
        PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
        // Typed inventory hash plus the independently retained Observe result.
        2 * ("blake3-256".len() + 64 + "source-owned.packet-connected-inventory/4".len()),
        // Native reference, typed receipt and evidence each retain full refs.
        3 * ("blake3-256".len()
            + "cnp.blob.v1".len()
            + 64
            + PACKET_FRESH_RESTORE_ALLOCATION_MEDIA.len()),
        prefix.exchange.requested_bytes()?,
        prefix.source_owner_requested_bytes,
    ])?;
    let transient = sum(&[
        inventory.requested_total()?,
        shapes.report_authentication_transient_requested_bytes,
        shapes.report.requested_total()?,
        shapes.receipt.requested_total()?,
        shapes.terminal.requested_total()?,
        original.requested_total()?,
        // completed(result) first owns its result map, then serializes the full
        // response; the typed receipt is independently serialized into it.
        shapes.terminal.dom_and_canonical_scratch_bytes,
        shapes.receipt.dom_and_canonical_scratch_bytes,
        prefix.exchange.requested_bytes()?,
        prefix.declared_counter_scratch_bytes,
        scratch,
    ])?;
    let row = PacketNativeReportStartupAllocationRow {
        raw_report_capacity: quantity(PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY)?,
        retained_growth_bytes: quantity(retained)?,
        maximum_simultaneous_transient_bytes: quantity(transient)?,
        declared_counter_scratch_bytes: quantity(scratch)?,
    };
    attempt.startup.authenticate_actual_data(connection, &row)?;
    drop(view);
    attempt.authenticate_current(connection)?;
    authenticate_current_census(endpoint, current)?;
    Ok(NativeFreshPublicationPlan {
        shapes,
        inventory,
        prefix,
        row,
        declared_full_scratch,
    })
}

fn authenticate_current_census(
    endpoint: &PacketEndpoint<DeadlineStream>,
    current: &NativeFreshCurrentCensus,
) -> Result<(), ProviderError> {
    let banks = endpoint
        .complete
        .as_ref()
        .ok_or_else(refused)?
        .original_fresh_report_bank_data()?;
    let retained = sum(&[
        std::mem::size_of::<super::super::super::service::PacketSourceService>(),
        banks[0].allocated_bytes,
        banks[1].allocated_bytes,
        requested_metadata_backing_storage_data(&current.facts)?,
    ])?;
    if current.banks != banks
        || current.retained_requested_bytes != retained
        || current.shared_roots != current.facts.shared_backing_views
        || current.shared_edges < current.shared_roots
        || current.declared_counter_scratch_bytes
            != super::super::fresh_restore::original_fresh_current_counter_scratch_data()
    {
        return Err(refused());
    }
    Ok(())
}
fn add(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_add(b).ok_or_else(exhausted)
}
fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values
        .iter()
        .try_fold(0usize, |total, value| add(total, *value))
}
