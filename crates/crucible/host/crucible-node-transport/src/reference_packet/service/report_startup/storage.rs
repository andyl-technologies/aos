//! Projects startup publication owners from the immutable installed launch.
//!
//! Core preadmits the declared fixed counter/schema window before this producer
//! runs. The returned data contains no native owner or allocation permission.
//! The real native consumer must join the original private birth and reconcile
//! actual component demands before constructing any report or proof exchange.

use super::super::{PacketConnectedSourceProgram, PacketNative5SourceLaunch};
use super::*;
use crate::connection::{OriginalPacketPrefixLifetimeDataExt, OriginalPacketPrefixProjectionInput};
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection,
};
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
use std::mem::size_of;

#[cfg(test)]
use crate::connection::OriginalContinuationContentExtent;
#[cfg(test)]
use crucible_node_format::{ContentRef, Id};

mod layout;
mod observe;
mod raw_record;
mod schema_generation;

const MAXIMUM_COMPILED_PROJECTION_BYTES: usize = 512 * 1024 * 1024;

pub use crucible_source_birth_data::profile::reference_packet::service::native_startup::original_report::PacketNativeReportStartupStorageData;

/// Counts one selected publisher from the actual immutable pre-child launch.
///
/// The caller must first admit [`original_report_startup_counter_scratch_data`].
/// This window covers the fixed schema helpers invoked for full definition
/// comparison. Those helpers allocate; this API makes no allocation-free claim.
/// Initial raw query decoding is counted separately from already-owning original
/// clones, and the live caller must use the matching pretyped receive guard.
///
/// # Errors
/// Refuses absent or mismatched selections, incomplete profile/schema tuples,
/// unsupported closed model shapes, overflow or a demand above the unchanged
/// implementation ceiling. Successful data creates no construction right.
pub fn original_report_startup_storage_data(
    launch: &PacketNative5SourceLaunch,
    purpose: PacketNativeReportStartupPurpose,
) -> Result<PacketNativeReportStartupStorageData, ProviderError> {
    authenticate_tuple(launch, purpose)?;
    let maximum = MAXIMUM_COMPILED_PROJECTION_BYTES;
    let receive = crate::connection::original_report_query_receive_storage_data(launch, purpose)?;
    let data = match purpose {
        PacketNativeReportStartupPurpose::OriginalObserve12 => {
            let shapes = observe::project(launch, maximum)?;
            original(
                launch,
                &shapes,
                receive.requested_bytes()?,
                crate::connection::OriginalPacketPrefixStorageData::native_observe_returned_query_storage_data(&receive)?,
            )?
        }
        PacketNativeReportStartupPurpose::FreshCompletedAdmit13 => {
            let fresh =
                crate::reference_packet::endpoint::original_fresh_report_startup_publication_data(
                    launch, maximum,
                )?;
            if fresh.declared_counter_scratch_bytes > original_report_startup_counter_scratch_data()
            {
                return Err(exhausted());
            }
            PacketNativeReportStartupStorageData {
                retained_growth_bytes: fresh.retained_growth_bytes,
                maximum_simultaneous_transient_bytes: fresh.maximum_simultaneous_transient_bytes,
                // Core admits this static window before either the full schema
                // comparisons or the concrete Fresh publisher counter runs.
                declared_counter_scratch_bytes: original_report_startup_counter_scratch_data(),
            }
        }
    };
    if sum(&[
        data.retained_growth_bytes,
        data.maximum_simultaneous_transient_bytes,
        data.declared_counter_scratch_bytes,
    ])? > maximum
    {
        return Err(exhausted());
    }
    Ok(data)
}

/// Quotes the actual Source14 first-report producer before private boot.
///
/// Core's same-Source original startup claim is the only selected caller. The
/// real native Source14 report scope independently requires the untouched model
/// census before its live quote. Old generic and invocation producers stay broad.
/// This DATA creates no boot, initial-state, currentness or construction right.
///
/// # Errors
/// Refuses the old full tuple guards, checked overflow or the same compiled cap.
pub fn original_initial_report_startup_storage_data(
    launch: &PacketNative5SourceLaunch,
    purpose: PacketNativeReportStartupPurpose,
) -> Result<PacketNativeReportStartupStorageData, ProviderError> {
    if purpose != PacketNativeReportStartupPurpose::OriginalObserve12 {
        return original_report_startup_storage_data(launch, purpose);
    }
    authenticate_tuple(launch, purpose)?;
    let maximum = MAXIMUM_COMPILED_PROJECTION_BYTES;
    let receive = crate::connection::original_report_query_receive_storage_data(launch, purpose)?;
    let shapes = observe::project_initial(launch, maximum)?;
    let data = original(
        launch, &shapes, receive.requested_bytes()?,
        crate::connection::OriginalPacketPrefixStorageData::native_observe_returned_query_storage_data(&receive)?,
    )?;
    if sum(&[
        data.retained_growth_bytes,
        data.maximum_simultaneous_transient_bytes,
        data.declared_counter_scratch_bytes,
    ])? > maximum
    {
        return Err(exhausted());
    }
    Ok(data)
}

fn original(
    launch: &PacketNative5SourceLaunch,
    shapes: &observe::OriginalObserveStartupShapes,
    initial_receive: usize,
    typed_query_requested_bytes: usize,
) -> Result<PacketNativeReportStartupStorageData, ProviderError> {
    crucible_source_birth_data::source_birth_original_report_body! {
        shapes = shapes,
        initial_receive = initial_receive,
        typed_query_requested_bytes = typed_query_requested_bytes,
        maximum = MAXIMUM_COMPILED_PROJECTION_BYTES,
        objects = objects,
        prefix = prefix,
        preparation = preparation,
        prefix_lifetime = prefix_lifetime,
        prefix_stage = crate::connection::quote_original_native_observe_prefix_startup_storage_data(
            launch,
            OriginalPacketPrefixProjectionInput {
                terminal: &shapes.terminal,
                original: &shapes.original,
                objects: &objects,
                maximum_requested_bytes: MAXIMUM_COMPILED_PROJECTION_BYTES,
            },
        ),
        lifetime_stage = prefix
            .exchange
            .native_original_observe_prepared_lifetime_storage_data(
                &preparation,
                usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| exhausted())?,
                MAXIMUM_COMPILED_PROJECTION_BYTES,
            ),
        cache_layout = layout::cache_tree_layout_data(),
        layout = layout::project(),
        capture_owner = layout::capture_owner_bytes_data(),
        owner_binding = owner_binding,
        observation = {
            let [owner_binding] = launch.selection.realization.owner_bindings.as_slice() else {
                return Err(refused());
            };
            let mut identity_fields = MetadataObserver::new();
            identity_fields.observe(owner_binding)?;
        },
        owner_facts = identity_fields.finish(),
        counter = layout::counter_output_data(),
    }
}

fn authenticate_tuple(
    launch: &PacketNative5SourceLaunch,
    purpose: PacketNativeReportStartupPurpose,
) -> Result<(), ProviderError> {
    use crate::reference_packet::service::{capture_allocation::*, fresh_restore_allocation::*};
    if !matches!(
        launch.capture_profile,
        super::super::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
    ) || launch.protocol_metadata_limits.is_none()
        || launch.native_codec_metadata_extent
            != Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
        || launch.ack_emitter_selection
            != Some(super::super::PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
        || launch.selection.realization.bindings.len() != 1
        || launch.selection.realization.owner_bindings.len() != 1
    {
        return Err(refused());
    }
    let provider = &launch.selection.provider;
    let has_feature = |feature: &str| {
        provider
            .extensions_supported
            .iter()
            .any(|id| id.as_str() == feature)
    };
    match purpose {
        PacketNativeReportStartupPurpose::OriginalObserve12 => {
            if launch.capture_allocation_selection
                != Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
                || !has_feature(PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE)
            {
                return Err(refused());
            }
            for schema in [
                capture_allocation_schema()?,
                capture_allocation_record_schema()?,
            ] {
                if !provider.implementation.formats.contains(&schema)
                    || !launch.selection.realization.bindings[0]
                        .compatibility
                        .implementation
                        .formats
                        .contains(&schema)
                {
                    return Err(refused());
                }
            }
        }
        PacketNativeReportStartupPurpose::FreshCompletedAdmit13 => {
            if launch.fresh_restore_allocation_selection != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
                || launch.complete_restore_selection != Some(super::super::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                || launch.restore_input_emitter_selection != Some(super::super::complete_restore::PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
                || !has_feature(PACKET_FRESH_RESTORE_ALLOCATION_FEATURE)
            { return Err(refused()); }
            for kind in [
                PacketNativeFreshRestoreAllocationSchema::Query,
                PacketNativeFreshRestoreAllocationSchema::Report,
                PacketNativeFreshRestoreAllocationSchema::Proof,
                PacketNativeFreshRestoreAllocationSchema::Receipt,
                PacketNativeFreshRestoreAllocationSchema::PrepareBinding,
            ] {
                let schema = fresh_restore_allocation_schema(kind)?;
                if !provider.implementation.formats.contains(&schema)
                    || !launch.selection.realization.bindings[0]
                        .compatibility
                        .implementation
                        .formats
                        .contains(&schema)
                {
                    return Err(refused());
                }
            }
        }
    }
    Ok(())
}

/// Names actual fixed counter headers and compiled definition-generation storage.
///
/// This nonallocating getter is called before the storage producer. Overflow
/// returns an unadmittable demand, never a smaller default. Compiler/recursive
/// traversal frames and physical allocator overhead remain separate obligations.
pub fn original_report_startup_counter_scratch_data() -> usize {
    let result = schema_generation::requested_data().and_then(|schemas| {
        let terms: [usize; 50] = [
            size_of::<[usize; 50]>(),
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
            super::super::fresh_restore_allocation::fresh_restore_allocation_startup_counter_scratch_data(),
            crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::requested_serialization_scratch_bytes(),
            crate::connection::NativeCaptureSdkStateQuote::requested_scratch_bytes(),
            crate::protocol_snapshot::owned11::correspondence::closed_envelope_comparison_scratch_data(),
            size_of::<[u8; 20]>(),
            layout::counter_scratch_data(),
            observe::counter_scratch_data(),
            crucible_source_birth_data::profile::reference_packet::service::native_startup::original_report::AGGREGATION_COUNTER_SCRATCH_DATA,
        ];
        sum(&terms)
    });
    match result {
        Ok(bytes) => bytes,
        Err(_) => usize::MAX,
    }
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |total, next| {
        total.checked_add(*next).ok_or_else(exhausted)
    })
}
fn mul(count: usize, slot: usize) -> Result<usize, ProviderError> {
    count.checked_mul(slot).ok_or_else(exhausted)
}
fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("compiled native report startup storage")
}
fn refused() -> ProviderError {
    ProviderError::Correlation("compiled native report startup tuple")
}

/// Returns the finite compiled Fresh definition-generation and comparison phase.
pub(crate) fn original_fresh_schema_generation_storage_data() -> Result<usize, ProviderError> {
    schema_generation::fresh_requested_data()
}

mod invocation;

pub use invocation::{
    original_invocation_report_startup_counter_scratch_data,
    original_invocation_report_startup_storage_data,
};

#[cfg(test)]
#[path = "storage/aggregation/original.rs"]
mod aggregation_original;

#[cfg(test)]
#[path = "storage/aggregation/tests.rs"]
mod aggregation_tests;
