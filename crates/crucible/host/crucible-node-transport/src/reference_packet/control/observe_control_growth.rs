//! Bounds the actual selected Observe cache and next Capture registration.
//!
//! The stopped Control supplies the unchanged children. New cache/content rows
//! follow the same producer and registration grammars as dispatch_prepared,
//! retain_original_stopped_observe_evidence and reserve_original_capture. These
//! projections construct no reply, reference, request or allocation permission.

use super::*;
use crate::reference_packet::serialization_storage::{
    NativeControlCaptureEncodingData, NativeSerializationStorageData,
};
use crate::reference_packet::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA;
use crate::retained_metadata::{
    MetadataObserver, requested_metadata_backing_storage_data,
    serialization_storage::OriginalSerializationStorageProjection,
};
use std::mem::size_of;

type Projection = OriginalSerializationStorageProjection;

pub(crate) struct NativeObserveControlGrowthInput<'a> {
    pub(crate) original: &'a Envelope,
    pub(crate) currency: &'a restore_fresh::PacketLiveCaptureControlCurrency,
    pub(crate) current: &'a NativeControlCaptureEncodingData,
    pub(crate) raw: &'a NativeSerializationStorageData,
    pub(crate) publication: &'a NativeObservePublicationProjectionData,
    pub(crate) report: &'a NativeCaptureReportProjectionData,
    pub(crate) capture: &'a NativeProjectedCaptureRequestData,
    pub(crate) maximum: usize,
}

pub(crate) struct NativeObserveControlGrowthData {
    pub(crate) publication_retained_bytes: usize,
    pub(crate) registration_retained_bytes: usize,
    pub(crate) maximum_control_encoded_bytes: usize,
    pub(crate) control_encoding: NativeSerializationStorageData,
    pub(crate) model_control_requested_bytes: usize,
    pub(crate) registration_transient_bytes: usize,
    pub(crate) serialized_value_nodes: usize,
    pub(crate) serialized_capacity_records: usize,
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("native Observe and Capture Control growth")
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |total, next| {
        total.checked_add(*next).ok_or_else(credit)
    })
}

fn multiply(count: usize, bytes: usize) -> Result<usize, ProviderError> {
    count.checked_mul(bytes).ok_or_else(credit)
}

fn object(projection: &mut Projection, fields: &[&str]) -> Result<(), ProviderError> {
    projection.add_object()?;
    for field in fields {
        projection.add_field(field)?;
    }
    Ok(())
}

fn hash(projection: &mut Projection, domain: &str) -> Result<(), ProviderError> {
    object(projection, &["algorithm", "domain", "digest"])?;
    projection.add_string("blake3-256")?;
    projection.add_string(domain)?;
    projection.add_unescaped_ascii_extent(2 * blake3::OUT_LEN)
}

fn reference(projection: &mut Projection, media: &str) -> Result<(), ProviderError> {
    object(projection, &["hash", "length", "media_type"])?;
    hash(projection, "cnp.blob.v1")?;
    projection.add_unescaped_ascii_extent(20)?;
    projection.add_string(media)
}

fn byte_array(projection: &mut Projection, length: usize) -> Result<(), ProviderError> {
    // Control's actual &[u8]/Vec<u8> serializers use integer arrays. Each byte
    // has inline Number storage and at most three digits. This is not compact
    // protocol encoding and cannot be charged as its shorter base64 shape.
    projection.add_array_extent(length)?;
    for _ in 0..length {
        projection.add_value(&u8::MAX)?;
    }
    Ok(())
}

fn evidence(projection: &mut Projection, extent: usize, media: &str) -> Result<(), ProviderError> {
    projection.add_array_extent(2)?;
    reference(projection, media)?;
    byte_array(projection, extent)
}

pub(super) fn unknown_capture(projection: &mut Projection) -> Result<(), ProviderError> {
    object(
        projection,
        &["status", "operation_state", "error", "extensions"],
    )?;
    projection.add_string("error")?;
    projection.add_value(&OperationState::Unknown)?;
    object(
        projection,
        &["code", "message", "effect", "retryable", "details"],
    )?;
    projection.add_string("OUTCOME_UNKNOWN")?;
    projection.add_string("original native Capture remains unresolved")?;
    projection.add_value(&EffectCertainty::Unknown)?;
    projection.add_value(&false)?;
    projection.add_object()?;
    projection.add_object()
}

fn reference_backing(media: &str) -> Result<usize, ProviderError> {
    sum(&[
        "blake3-256".len(),
        "cnp.blob.v1".len(),
        2 * blake3::OUT_LEN,
        media.len(),
    ])
}

impl PacketControl {
    pub(crate) fn quote_original_observe_control_growth(
        &self,
        input: NativeObserveControlGrowthInput<'_>,
    ) -> Result<NativeObserveControlGrowthData, ProviderError> {
        let NativeObserveControlGrowthInput {
            original,
            currency,
            current,
            raw,
            publication,
            report,
            capture,
            maximum,
        } = input;
        currency.authenticate_before_observe(self)?;
        let request = original.request_id.0.as_ref().ok_or_else(credit)?;
        if original.method != Method::Observe
            || self.originals.contains_key(request)
            || raw.maximum_encoded_bytes > 65_536
            || report.encoding.maximum_encoded_bytes
                > super::super::service::capture_allocation::MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES
        {
            return Err(credit());
        }
        let payloads = [
            (raw.maximum_encoded_bytes, "application/json"),
            (
                publication.native_receipt.maximum_encoded_bytes,
                "application/json",
            ),
            (
                publication.wrapper_record.maximum_encoded_bytes,
                "application/json",
            ),
            (
                report.encoding.maximum_encoded_bytes,
                PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA,
            ),
        ];
        let proof_payloads = [payloads[0], payloads[2], payloads[3]];
        let mut projection = Projection::new(maximum)?;
        object(
            &mut projection,
            &[
                "originals",
                "content",
                "begins",
                "begin_requests",
                "current_operation",
                "content_bytes",
            ],
        )?;
        projection.add_array_extent(2)?;
        object(
            &mut projection,
            &["request", "identity", "response_body", "evidence"],
        )?;
        projection.add_value(request)?;
        hash(&mut projection, "cnp.request.v1")?;
        object(
            &mut projection,
            &["status", "operation_state", "result", "extensions"],
        )?;
        projection.add_string("completed")?;
        projection.add_value(&OperationState::Completed)?;
        self.project_original_observe_result(&mut projection, original)?;
        projection.add_object()?;
        projection.add_array_extent(proof_payloads.len())?;
        for (extent, media) in proof_payloads {
            evidence(&mut projection, extent, media)?;
        }
        object(
            &mut projection,
            &["request", "identity", "response_body", "evidence"],
        )?;
        projection.add_unescaped_ascii_extent(128)?;
        hash(&mut projection, "cnp.request.v1")?;
        unknown_capture(&mut projection)?;
        projection.add_array_extent(0)?;
        projection.add_array_extent(payloads.len())?;
        for (extent, media) in payloads {
            evidence(&mut projection, extent, media)?;
        }
        projection.add_object()?;
        projection.add_field_extent(128)?;
        self.project_original_capture_body(&mut projection)?;
        projection.add_object()?;
        projection.add_field_extent(128)?;
        projection.add_unescaped_ascii_extent(128)?;
        projection.add_unescaped_ascii_extent(128)?;
        projection.add_value(&usize::MAX)?;
        let delta = projection.finish(maximum)?;

        let mut cache_tree = MetadataObserver::new();
        cache_tree.tree::<Id, (HashRef, PacketControlReply)>(1)?;
        cache_tree.tree::<ContentRef, Vec<u8>>(4)?;
        let publication_trees = requested_metadata_backing_storage_data(&cache_tree.finish())?;
        let content_bytes = payloads.iter().try_fold(0usize, |total, (bytes, _)| {
            total.checked_add(*bytes).ok_or_else(credit)
        })?;
        // Raw and wrapper output Vecs may have spare canonical writer backing;
        // the report producer instead reserves its exact closed16KiB bank.
        // Control content copies use initialized lengths, whereas the moved
        // evidence cache retains these actual producer output allocations.
        let evidence_bytes = sum(&[
            raw.canonical_output_requested_bytes,
            publication.wrapper_record.canonical_output_requested_bytes,
            super::super::service::capture_allocation::MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES,
        ])?;
        let references = payloads.iter().chain(proof_payloads.iter()).try_fold(
            0usize,
            |total, (_, media)| {
                total
                    .checked_add(reference_backing(media)?)
                    .ok_or_else(credit)
            },
        )?;
        let publication_retained_bytes = sum(&[
            publication_trees,
            content_bytes,
            evidence_bytes,
            references,
            request.as_str().len(),
            "blake3-256".len() + "cnp.request.v1".len() + 2 * blake3::OUT_LEN,
            publication.terminal.dom_and_canonical_scratch_bytes,
            multiply(3, size_of::<(ContentRef, Vec<u8>)>())?,
        ])?;
        let mut registration_tree = MetadataObserver::new();
        registration_tree.tree::<Id, (HashRef, PacketControlReply)>(1)?;
        registration_tree.tree::<Id, BeginRequest>(1)?;
        registration_tree.tree::<Id, Id>(1)?;
        let registration_trees =
            requested_metadata_backing_storage_data(&registration_tree.finish())?;
        let mut unknown = Projection::new(maximum)?;
        unknown_capture(&mut unknown)?;
        let unknown = unknown.finish(maximum)?;
        let registration_retained_bytes = sum(&[
            registration_trees,
            multiply(5, 128)?, // original key, operation/key/value and current_operation
            "blake3-256".len() + "cnp.request.v1".len() + 2 * blake3::OUT_LEN,
            unknown.dom_and_canonical_scratch_bytes,
            multiply(2, capture.begin_requested_bytes)?, // map entry and retained reservation
            capture.arguments_requested_bytes,
            capture.envelope.dom_and_canonical_scratch_bytes,
            size_of::<PacketOriginalCaptureReservation>(),
        ])?;
        let registration_transient_bytes = sum(&[
            capture.envelope.requested_total()?,
            capture.body.requested_total()?,
            capture.arguments_requested_bytes,
            capture.begin_requested_bytes,
            unknown.requested_total()?,
            size_of::<blake3::Hasher>(),
        ])?;
        // Current children remain unchanged. The extra closed rows dominate
        // every inserted object/array/key and the larger scalar counters. Both
        // independent DOMs and parser/output banks coexist in the actual
        // capture_control_state path and are included by requested_total.
        let maximum_control_encoded_bytes =
            sum(&[current.maximum_encoded_bytes, delta.maximum_encoded_bytes])?;
        let control_encoding = crate::reference_packet::serialization_storage::closed_event_serialization_storage_data(
            maximum_control_encoded_bytes,
            sum(&[current.serialized_value_nodes, delta.serialized_value_nodes])?,
            sum(&[current.serialized_capacity_records, delta.serialized_capacity_records])?,
            // The independently measured current model/Control phase covers
            // custom Bytes temporaries. New rows serialize integer byte arrays
            // and closed strings; they introduce no additional custom encoder.
            current.requested_bytes,
            maximum,
        )?;
        let model_control_requested_bytes = sum(&[
            current.requested_bytes,
            delta.requested_total()?,
            multiply(2, delta.dom_and_canonical_scratch_bytes)?,
            delta.projected_parser_requested_bytes,
            multiply(
                self.originals.len().checked_add(2).ok_or_else(credit)?,
                size_of::<(&Id, &HashRef, &Map<String, Value>, &[(ContentRef, Vec<u8>)])>(),
            )?,
            multiply(
                self.content.len().checked_add(4).ok_or_else(credit)?,
                size_of::<(&ContentRef, &[u8])>(),
            )?,
            registration_transient_bytes,
            multiply(
                4,
                "blake3-256".len() + "cnp.blob.v1".len() + 2 * blake3::OUT_LEN,
            )?,
        ])?;
        if sum(&[
            publication_retained_bytes,
            registration_retained_bytes,
            model_control_requested_bytes,
        ])? > maximum
        {
            return Err(credit());
        }
        currency.authenticate_before_observe(self)?;
        Ok(NativeObserveControlGrowthData {
            publication_retained_bytes,
            registration_retained_bytes,
            maximum_control_encoded_bytes,
            control_encoding,
            model_control_requested_bytes,
            registration_transient_bytes,
            serialized_value_nodes: sum(&[
                current.serialized_value_nodes,
                delta.serialized_value_nodes,
            ])?,
            serialized_capacity_records: sum(&[
                current.serialized_capacity_records,
                delta.serialized_capacity_records,
            ])?,
        })
    }
}
