//! Projects startup publication owners from the immutable installed launch.
//!
//! Core preadmits the declared fixed counter/schema window before this producer
//! runs. The returned data contains no native owner or allocation permission.
//! The real native consumer must join the original private birth and reconcile
//! actual component demands before constructing any report or proof exchange.

use super::super::{PacketConnectedSourceProgram, PacketNative5SourceLaunch};
use super::*;
use crate::connection::{OriginalContinuationContentExtent, OriginalPacketPrefixProjectionInput};
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection,
};
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
use crucible_node_contract::{ContentRef, Id};
use serde_json::Value;
use std::mem::size_of;

mod observe;
mod raw_record;
mod schema_generation;

const MAXIMUM_COMPILED_PROJECTION_BYTES: usize = 512 * 1024 * 1024;

/// Describes separately bounded requested storage for one compiled publisher.
///
/// Values describe a closed prospective shape. They prove no Source admission,
/// native currentness, actual capacities or physical allocator peak.
pub struct PacketNativeReportStartupStorageData {
    retained_growth_bytes: usize,
    maximum_simultaneous_transient_bytes: usize,
    declared_counter_scratch_bytes: usize,
}

impl PacketNativeReportStartupStorageData {
    /// Returns the exact required raw report capacity shared by both families.
    pub const fn raw_report_capacity(&self) -> usize {
        PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY
    }

    /// Returns the bound for every independent new retained owner.
    pub const fn retained_growth_bytes(&self) -> usize {
        self.retained_growth_bytes
    }

    /// Returns a conservative sum covering the complete simultaneous phase.
    pub const fn maximum_simultaneous_transient_bytes(&self) -> usize {
        self.maximum_simultaneous_transient_bytes
    }

    /// Returns the declared counter and fixed compiled schema-generation window.
    pub const fn declared_counter_scratch_bytes(&self) -> usize {
        self.declared_counter_scratch_bytes
    }
}

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
            original(launch, &shapes, receive.requested_bytes()?)?
        }
        PacketNativeReportStartupPurpose::FreshCompletedAdmit13 => {
            // The dedicated fresh handler must supply its real partial-owner
            // layout before this purpose can issue a construction allowance.
            // The original active report cannot stand in for inactive owners.
            return Err(ProviderError::Correlation(
                "fresh report startup owner layout pending",
            ));
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

fn original(
    launch: &PacketNative5SourceLaunch,
    shapes: &observe::OriginalObserveStartupShapes,
    initial_receive: usize,
) -> Result<PacketNativeReportStartupStorageData, ProviderError> {
    use crate::reference_packet::service::capture_allocation::*;
    let raw = shapes.raw.maximum_encoded_bytes.min(65_536);
    // The existing producer rejects larger encoded records. Its complete
    // pre-rejection DOM/canonical work remains charged below at the full shape.
    let objects = [
        OriginalContinuationContentExtent {
            maximum_payload_bytes: raw,
            media_type: "application/json",
        },
        OriginalContinuationContentExtent {
            maximum_payload_bytes: shapes.wrapper.maximum_encoded_bytes,
            media_type: "application/json",
        },
        OriginalContinuationContentExtent {
            maximum_payload_bytes: PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
            media_type: PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA,
        },
    ];
    let prefix = crate::connection::quote_original_packet_prefix_startup_storage_data(
        launch,
        OriginalPacketPrefixProjectionInput {
            terminal: &shapes.terminal,
            original: &shapes.original,
            objects: &objects,
            maximum_requested_bytes: MAXIMUM_COMPILED_PROJECTION_BYTES,
        },
    )?;
    let mut trees = MetadataObserver::new();
    // Independent content keys for raw, receipt5, wrapper12 and report12;
    // the immutable original cache owns one additional Id/hash/reply row.
    trees.tree::<ContentRef, Vec<u8>>(4)?;
    trees.tree::<Id, (
        crucible_node_contract::HashRef,
        crate::reference_packet::control::PacketControlReply,
    )>(1)?;
    let new_tree_backing =
        crate::retained_metadata::requested_metadata_backing_storage_data(&trees.finish())?;
    let content_bytes = sum(&[
        raw,
        shapes.receipt.maximum_encoded_bytes,
        shapes.wrapper.maximum_encoded_bytes,
        PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
    ])?;
    let cache_bytes = sum(&[
        raw,
        shapes.wrapper.maximum_encoded_bytes,
        PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
        shapes.terminal.dom_and_canonical_scratch_bytes,
        mul(3, size_of::<(ContentRef, Vec<u8>)>())?,
    ])?;
    let reference_children = |media: &str| {
        sum(&[
            "blake3-256".len(),
            "cnp.blob.v1".len(),
            2 * blake3::OUT_LEN,
            media.len(),
        ])
    };
    let content_references = sum(&[
        mul(3, reference_children("application/json")?)?,
        reference_children(PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA)?,
    ])?;
    let completed_owner = sum(&[
        size_of::<crate::reference_packet::service::PacketSourceService>(),
        shapes.original.dom_and_canonical_scratch_bytes,
        size_of::<PacketNativeCaptureAllocationReport>(),
        shapes.report.dom_and_canonical_scratch_bytes,
        PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
        reference_children(PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA)?,
    ])?;
    let retained = sum(&[
        prefix.exchange.requested_bytes()?, // Includes temporary terms conservatively.
        prefix.source_owner_requested_bytes,
        content_bytes,
        content_references,
        cache_bytes,
        completed_owner,
        new_tree_backing,
        // The selected policy additionally retains two independent full schema
        // definition references. These are new publication-class fields; the
        // baseline native service/model/SDK birth remains a separate action.
        mul(2, size_of::<ContentRef>())?,
        mul(2, reference_children("application/json")?)?,
    ])?;
    let transient = sum(&[
        initial_receive,
        shapes.original.requested_total()?,
        shapes.raw.requested_total()?,
        shapes.receipt.requested_total()?,
        shapes.wrapper.requested_total()?,
        shapes.report.requested_total()?,
        shapes.terminal.requested_total()?,
        // The receipt constructor owns a complete original clone and independent
        // scope strings. Charging its full DOM shape plus actual typed header
        // dominates those scalar children without manufacturing a receipt DTO.
        size_of::<crate::reference_packet::control::PacketNative5Record>(),
        shapes.receipt.dom_and_canonical_scratch_bytes,
        size_of::<crucible_node_contract::ObservationBatch>(),
        size_of::<crate::bodies::ObserveResult>(),
        shapes.terminal.dom_and_canonical_scratch_bytes,
        // Each of the four new content references is independently generated,
        // verified and cloned into a content key/evidence/typed wrapper owner.
        mul(4, content_references)?,
        size_of::<blake3::Hasher>(),
    ])?;
    Ok(PacketNativeReportStartupStorageData {
        retained_growth_bytes: retained,
        maximum_simultaneous_transient_bytes: transient,
        declared_counter_scratch_bytes: original_report_startup_counter_scratch_data(),
    })
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
    let result = schema_generation::requested_data().and_then(|schemas| sum(&[
        schemas,
        size_of::<crate::reference_packet::service::PacketSourceService>(),
        size_of::<PacketNativeReportStartupStorageData>(),
        size_of::<observe::OriginalObserveStartupShapes>(),
        size_of::<OriginalSerializationStorageProjection>(),
        size_of::<OriginalSerializationStorageData>(),
        size_of::<MetadataObserver<'static>>(),
        size_of::<RetainedProtocolMetadataFacts>(),

        crate::reference_packet::service::ack_emitter::original_native_report_startup_scope_layout_data(),
        crate::connection::original_packet_prefix_startup_counter_scratch_data(),
        crate::connection::original_report_query_receive_counter_scratch_data(),
        super::super::fresh_restore_allocation::fresh_restore_allocation_startup_counter_scratch_data(),
        crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::requested_serialization_scratch_bytes(),
        size_of::<[u8; 20]>(),
    ]));
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
