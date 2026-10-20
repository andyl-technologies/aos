//! Projects the fourth native12 owner from its actual current child owners.
//!
//! This counter is evaluated before a Report or completed native owner exists.
//! Actual Observe/SDK/currency views are borrowed; only the closed future report,
//! reference, compact byte bank and Capture grammar contribute prospective terms.
//! No result grants an allocation, Capture cut, Source ticket or full-class right.

use super::*;
use crate::connection::NativeCaptureSdkCompletedQuote;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use crate::reference_packet::control::{
    NativeCaptureReportProjectionData, NativeProjectedCaptureRequestData,
    PacketLiveCaptureControlCurrency,
};
use crate::reference_packet::serialization_storage::{
    NativeSerializationStorageData, actual_serialization_storage_data,
};
use crate::reference_packet::service::{
    OriginalNativeCaptureContext, PacketNative5ProtocolMetadataBirthFacts,
    capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA,
};
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};

pub(crate) struct NativeCaptureCandidateOwnerData {
    pub(crate) maximum_encoded_bytes: usize,
    pub(crate) maximum_record_rows: usize,
    pub(crate) maximum_alias_rows: usize,
    pub(crate) maximum_observed_nodes: usize,
    pub(crate) frame_bank_views: usize,
    pub(crate) includes_capture_original: bool,
    pub(crate) requested_owner_fields_bytes: usize,
    pub(crate) requested_observe_owner_fields_bytes: usize,
    pub(crate) typed_report_requested_bytes: usize,
    pub(crate) raw_report_requested_bytes: usize,
    pub(crate) serialization_requested_bytes: usize,
    pub(crate) declared_counter_scratch_bytes: usize,
    pub(crate) capture_original_maximum_encoded_bytes: usize,
    pub(crate) capture_original_capacity_records: usize,
    pub(crate) capture_original_observed_nodes: usize,
    pub(crate) maximum_serialized_value_nodes: usize,
    pub(crate) maximum_serialized_capacity_records: usize,
    pub(crate) capture_original_serialized_value_nodes: usize,
    pub(crate) capture_original_serialized_capacity_records: usize,
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native fourth-owner prospective storage")
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |sum, next| {
        sum.checked_add(*next).ok_or_else(exhausted)
    })
}

fn project_reference(
    projection: &mut OriginalSerializationStorageProjection,
) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in ["hash", "length", "media_type"] {
        projection.add_field(key)?;
    }
    projection.add_object()?;
    for key in ["algorithm", "domain", "digest"] {
        projection.add_field(key)?;
    }
    projection.add_string("blake3-256")?;
    projection.add_string("cnp.blob.v1")?;
    projection.add_unescaped_ascii_extent(2 * blake3::OUT_LEN)?;
    projection.add_unescaped_ascii_extent(20)?;
    projection.add_string(PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA)
}

// Each component remains an independently evaluated bounded visitor. Summing
// their output terms intentionally retains every declared local counter/header
// rather than pretending that combining data also combines stack lifetimes.
fn encoding_sum(parts: &[&NativeSerializationStorageData]) -> Result<usize, ProviderError> {
    parts.iter().try_fold(0usize, |bytes, part| {
        bytes
            .checked_add(part.maximum_encoded_bytes)
            .ok_or_else(exhausted)
    })
}

pub(super) fn quote_original_candidate_owner(
    connection: &Connection<crate::client::DeadlineStream>,
    blobs: &BlobReceiver,
    context: &OriginalNativeCaptureContext<'_>,
    native: &PacketControl,
    original: &Envelope,
    sdk: &NativeCaptureSdkCompletedQuote,
    currency: &PacketLiveCaptureControlCurrency,
    report: &NativeCaptureReportProjectionData,
    capture: &NativeProjectedCaptureRequestData,
    metadata: &PacketNative5ProtocolMetadataBirthFacts,
    maximum: usize,
) -> Result<NativeCaptureCandidateOwnerData, ProviderError> {
    currency.authenticate_before_observe(native)?;
    sdk.authenticate_current(connection, blobs, context)?;
    let declared_scratch_bytes = sum(&[
        BorrowedCompactBytes::requested_serialization_scratch_bytes(),
        crate::retained_metadata::original_metadata_observer_layout_bytes(),
        crate::retained_metadata::original_metadata_observer_layout_bytes(),
        std::mem::size_of::<NativeCaptureCandidateOwnerData>(),
        2 * std::mem::size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>(),
        std::mem::size_of::<
            crate::protocol_snapshot::compact_bytes::CompactBytesSerializationLayoutData,
        >(),
    ])?;
    if declared_scratch_bytes > maximum {
        return Err(exhausted());
    }

    let mut observer = MetadataObserver::new();
    observer.observe(original)?;
    sdk.observe_owned12_metadata(connection, blobs, context, &mut observer)?;
    currency.observe_before_observe_currency_data(native, &mut observer)?;
    let actual = observer.finish();
    let current_backing = requested_metadata_backing_storage_data(&actual)?;
    if sum(&[declared_scratch_bytes, current_backing])? > maximum {
        return Err(exhausted());
    }
    let sdk_view = sdk.borrowed_owned12_protocol_view(connection, blobs, context)?;
    let currency_view = currency.borrowed_before_observe_currency_data(native)?;
    let actual_view =
        actual_serialization_storage_data(&(original, sdk_view, currency_view), actual, maximum)?;
    let maximum_raw_report_bytes = report.encoding.maximum_encoded_bytes;
    if maximum_raw_report_bytes
        > super::super::service::capture_allocation::MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES
    {
        return Err(exhausted());
    }
    let compact = BorrowedCompactBytes::serialization_layout_data(maximum_raw_report_bytes)?;
    let mut layout = OriginalSerializationStorageProjection::new(maximum)?;
    layout.add_array_extent(11)?;
    layout.add_string("source-private.native-capture-allocation-owner/12")?;
    layout.add_value(&std::process::id())?;
    layout.add_string("same-original-thread")?;
    layout.add_string("complete-original-observe")?;
    project_reference(&mut layout)?;
    layout.add_array_extent(2)?;
    // Raw capacity is an actual usize on the eventual owner. Its numeric
    // formatter is bounded here; actual postreserve capacity is reconciled.
    layout.add_value(&usize::MAX)?;
    layout.add_array_extent(3)?;
    layout.add_string("source-private.compact-bytes/7")?;
    layout.add_value(&compact.maximum_raw_bytes)?;
    layout.add_array_extent(compact.chunk_count)?;
    if compact.full_chunks != 0 {
        let full_chunk_extent = compact
            .maximum_base64_bytes
            .checked_sub(compact.final_encoded_chunk_bytes)
            .ok_or_else(exhausted)?
            / compact.full_chunks;
        for _ in 0..compact.full_chunks {
            layout.add_unescaped_ascii_extent(full_chunk_extent)?;
        }
    }
    if compact.final_encoded_chunk_bytes != 0 {
        layout.add_unescaped_ascii_extent(compact.final_encoded_chunk_bytes)?;
    }
    let layout = layout.finish(maximum)?;

    // Closed actual Envelope observer: seven string/Id roots, body/extension
    // maps, twenty body entries, one participant Vec and its Id strings. Each
    // nullable header and JSON Value wrapper is included in the node count.
    // These count bounds are reconciled against the genuine incoming original.
    let capture_original_capacity_records = sum(&[48, capture.participant_count])?;
    let capture_original_observed_nodes = capture
        .participant_count
        .checked_mul(2)
        .and_then(|nodes| nodes.checked_add(82))
        .ok_or_else(exhausted)?;
    let mut birth_observer = MetadataObserver::new();
    birth_observer.observe(metadata)?;
    let birth = birth_observer.finish();
    // Report: ten fields; scope17 plus three HashRef child triples and one
    // Position triple; two protocol triples; growth4/transients5. The metadata
    // child's root is already one of the ten Report fields.
    let report_nodes = sum(&[
        1,
        10,
        17,
        9,
        3,
        3,
        3,
        4,
        5,
        birth.observed_nodes.checked_sub(1).ok_or_else(exhausted)?,
    ])?;
    let maximum_capacity_records = sum(&[
        actual.capacity_records,
        report.owned_string_rows,
        birth.capacity_records,
        4,
        1,
        capture_original_capacity_records,
    ])?;
    let maximum_observed_nodes = sum(&[
        actual.observed_nodes,
        report_nodes,
        7,
        // The actual266 typed byte-bank observer records capacity plus one
        // scalar length visit; byte verification remains separately bounded.
        1,
        2,
        capture_original_observed_nodes,
    ])?;
    if maximum_capacity_records > 131_072 || maximum_observed_nodes > 131_072 {
        return Err(exhausted());
    }
    let typed_report_requested_bytes = sum(&[
        report.typed_report_layout_bytes,
        report.owned_string_requested_bytes,
    ])?;
    let reference_strings = sum(&[
        "blake3-256".len(),
        "cnp.blob.v1".len(),
        2 * blake3::OUT_LEN,
        PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA.len(),
    ])?;
    // Completed SDK/currency fields move the same actual Rc handles; they do
    // not allocate replacement codec/bank/Control payloads. Those existing
    // roots remain in the baseline unique walk. The incoming Observe itself
    // moves into the preparation capsule; its already observed backing is not
    // copied. New report/ref/raw banks and the future Capture clone are growth.
    let requested_observe_owner_fields_bytes = sum(&[
        typed_report_requested_bytes,
        reference_strings,
        super::super::service::capture_allocation::MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES,
        capture_allocation::original_capture_report_owner_layout_data(),
    ])?;
    let requested_backing_bytes = sum(&[
        requested_observe_owner_fields_bytes,
        capture.envelope.dom_and_canonical_scratch_bytes,
    ])?;
    let serialization_requested_bytes = sum(&[
        actual_view.requested_total()?,
        report.encoding.requested_total()?,
        capture.envelope.requested_total()?,
        layout.requested_total()?,
    ])?;
    if sum(&[
        requested_backing_bytes,
        serialization_requested_bytes,
        declared_scratch_bytes,
    ])? > maximum
    {
        return Err(exhausted());
    }
    currency.authenticate_before_observe(native)?;
    sdk.authenticate_current(connection, blobs, context)?;
    Ok(NativeCaptureCandidateOwnerData {
        maximum_encoded_bytes: encoding_sum(&[
            &actual_view,
            &report.encoding,
            &capture.envelope,
            &layout,
        ])?,
        maximum_record_rows: maximum_capacity_records,
        maximum_alias_rows: actual.shared_backing_views,
        maximum_observed_nodes,
        // SDK225's full completed-owner renderer has exactly one direct full
        // FrameBank leaf. All its other shared metadata edges remain in actual.
        frame_bank_views: 1,
        includes_capture_original: true,
        requested_owner_fields_bytes: requested_backing_bytes,
        requested_observe_owner_fields_bytes,
        typed_report_requested_bytes,
        raw_report_requested_bytes: super::super::service::capture_allocation::MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES,
        serialization_requested_bytes,
        declared_counter_scratch_bytes: declared_scratch_bytes,
        capture_original_maximum_encoded_bytes: capture.envelope.maximum_encoded_bytes,
        capture_original_capacity_records,
        capture_original_observed_nodes,
        maximum_serialized_value_nodes: sum(&[
            actual_view.serialized_value_nodes,
            report.encoding.serialized_value_nodes,
            capture.envelope.serialized_value_nodes,
            layout.serialized_value_nodes,
        ])?,
        maximum_serialized_capacity_records: sum(&[
            actual_view.serialized_capacity_records,
            report.encoding.serialized_capacity_records,
            capture.envelope.serialized_capacity_records,
            layout.serialized_capacity_records,
        ])?,
        capture_original_serialized_value_nodes: capture.envelope.serialized_value_nodes,
        capture_original_serialized_capacity_records: capture.envelope.serialized_capacity_records,
    })
}
