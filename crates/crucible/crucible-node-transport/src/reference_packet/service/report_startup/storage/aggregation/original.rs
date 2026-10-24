//! Preserves complete independent old aggregation and defining counter bodies.

use super::*;
use crate::connection::OriginalContinuationContentExtent;
use crucible_node_format::{ContentRef, Id};

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

pub(super) fn quote(
    launch: &PacketNative5SourceLaunch,
    shapes: &observe::OriginalObserveStartupShapes,
    initial_receive: usize,
    typed_query_requested_bytes: usize,
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
    let (prefix, preparation) =
        crate::connection::quote_original_native_observe_prefix_startup_storage_data(
            launch,
            OriginalPacketPrefixProjectionInput {
                terminal: &shapes.terminal,
                original: &shapes.original,
                objects: &objects,
                maximum_requested_bytes: MAXIMUM_COMPILED_PROJECTION_BYTES,
            },
        )?;
    // authenticate_tuple selected the actual OriginalObserve12 constructor.
    // Its incoming query returns before reply/control/prefix construction. Keep
    // every original/failed owner below; the complete old prefix peak is merely
    // partitioned so returning work is not also described as permanent growth.
    let prefix_lifetime = prefix
        .exchange
        .native_original_observe_prepared_lifetime_storage_data(
            &preparation,
            usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| exhausted())?,
            MAXIMUM_COMPILED_PROJECTION_BYTES,
        )?;
    let mut trees = MetadataObserver::new();
    // Independent content keys for raw, receipt5, wrapper12 and report12;
    // the immutable original cache owns one additional Id/hash/reply row.
    trees.tree::<ContentRef, Vec<u8>>(4)?;
    trees.tree::<Id, (
        crucible_node_format::HashRef,
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
    let layout = layout::project();
    let cache_bytes = sum(&[
        raw,
        shapes.wrapper.maximum_encoded_bytes,
        PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
        shapes.terminal.dom_and_canonical_scratch_bytes,
        mul(3, layout.content_entry_bytes)?,
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
        layout::capture_owner_bytes_data(),
        shapes.original.dom_and_canonical_scratch_bytes,
        layout.capture_report_bytes,
        shapes.report.dom_and_canonical_scratch_bytes,
        PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
        reference_children(PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA)?,
    ])?;
    let [owner_binding] = launch.selection.realization.owner_bindings.as_slice() else {
        return Err(refused());
    };
    let mut identity_fields = MetadataObserver::new();
    identity_fields.observe(owner_binding)?;
    let identity =
        crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
            owner_binding,
            identity_fields.finish(),
            MAXIMUM_COMPILED_PROJECTION_BYTES,
        )?;
    // The real selected dispatcher hashes this same immutable binding while
    // comparing the request, producing receipt5 and building ObservationBatch.
    let binding_identity_transient = sum(&[
        mul(3, identity.requested_total()?)?,
        mul(
            3,
            "blake3-256".len() + "cnp.owner-binding.v1".len() + 2 * blake3::OUT_LEN,
        )?,
    ])?;
    let retained = sum(&[
        prefix_lifetime.retained_requested_bytes,
        prefix.source_owner_requested_bytes,
        content_bytes,
        content_references,
        cache_bytes,
        completed_owner,
        new_tree_backing,
        // Independent policy definition refs belong to this publication class.
        mul(2, layout.content_ref_bytes)?,
        mul(2, reference_children("application/json")?)?,
    ])?;
    let encoding = sum(&[
        // Endpoint::step holds the SAME returned Box<RequestBody> and its
        // Observe hash/children until selected_report returns. This actual
        // restricted query row, including the unchanged SDK observer's possible
        // empty Extensions root, survives receive and overlaps all encoding;
        // only its returning raw/parser work belongs in the other max arm.
        typed_query_requested_bytes,
        binding_identity_transient,
        prefix_lifetime.encoding_work_requested_bytes()?,
        prefix.declared_counter_scratch_bytes,
        shapes.original.requested_total()?,
        shapes.raw.requested_total()?,
        shapes.receipt.requested_total()?,
        shapes.wrapper.requested_total()?,
        shapes.report.requested_total()?,
        shapes.terminal.requested_total()?,
        // The receipt constructor owns a complete original clone and independent
        // scope strings. Charging its full DOM shape plus actual typed header
        // dominates those scalar children without manufacturing a receipt DTO.
        layout.produced_receipt_bytes,
        128, // Id::new grammar bound of the independently retained activation witness.
        shapes.receipt.dom_and_canonical_scratch_bytes,
        layout.observation_batch_bytes,
        layout.observe_result_bytes,
        shapes.terminal.dom_and_canonical_scratch_bytes,
        // Each of the four new content references is independently generated,
        // verified and cloned into a content key/evidence/typed wrapper owner.
        mul(4, content_references)?,
        layout.hasher_bytes,
    ])?;
    // ACK receipt starts only after the actual transform/dispatch/prepare
    // stack returns. The returned typed Observe query survives through publish;
    // preserve it and both defining counter windows in this distinct arm.
    let acknowledgement = sum(&[
        typed_query_requested_bytes,
        prefix_lifetime.acknowledgement_work_requested_bytes()?,
        prefix.declared_counter_scratch_bytes,
    ])?;
    Ok(PacketNativeReportStartupStorageData {
        retained_growth_bytes: retained,
        // The full untrusted query is still funded at the negotiated raw cap.
        // It cannot overlap later encoding: receive_original_report_query has
        // returned before publish_original_capture_allocation_observe begins.
        // Original/containment remain funded above; the returned typed Box and
        // Observe children are explicitly carried in encoding, not maxed away.
        maximum_simultaneous_transient_bytes: initial_receive.max(encoding).max(acknowledgement),
        declared_counter_scratch_bytes: layout::counter_output_data(),
    })
}

pub(super) fn counter_scratch_data() -> usize {
    let result = schema_generation::requested_data().and_then(|schemas| {
        let terms: [usize; 49] = [
            size_of::<[usize; 49]>(),
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
            super::super::super::fresh_restore_allocation::fresh_restore_allocation_startup_counter_scratch_data(),
            crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::requested_serialization_scratch_bytes(),
            crate::connection::NativeCaptureSdkStateQuote::requested_scratch_bytes(),
            crate::protocol_snapshot::owned11::correspondence::closed_envelope_comparison_scratch_data(),
            size_of::<[u8; 20]>(),
            layout::counter_scratch_data(),
            observe::counter_scratch_data(),
        ];
        sum(&terms)
    });
    match result {
        Ok(bytes) => bytes,
        Err(_) => usize::MAX,
    }
}
