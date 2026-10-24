//! Projects the original content-reference and Blob frame grammar as DATA.
//!
//! These borrowed extents create no reference, payload, registration or native
//! authority. Live authority authentication remains in Transport.

use super::*;
use crate::profile::envelope::Method;
use crate::profile::serialization_storage::OriginalSerializationStorageProjection as Projection;

/// Names an actual schema's future encoded payload and printable media type.
pub struct OriginalContinuationContentExtent<'a> {
    /// Names the actual schema encoder's maximum payload extent.
    pub maximum_payload_bytes: usize,
    /// Borrows the actual schema media type.
    pub media_type: &'a str,
}

/// Names projected content scalar extents, never a reference or owned payload.
#[derive(Clone, Copy, Debug)]
pub struct ContentExtent {
    /// Counts projected payload bytes.
    pub payload: usize,
    /// Counts projected printable media-type bytes.
    pub media: usize,
}

/// Names one actual closed Blob request body shape.
pub enum ProjectedBody<'a> {
    /// Names a BlobBegin transfer identifier and content shape.
    Begin(usize, &'a ContentExtent),
    /// Names a BlobChunk transfer identifier and encoded payload extent.
    Chunk(usize, usize),
    /// Names a BlobFinish transfer identifier.
    Finish(usize),
}

/// Copies the eleven original serializer-report components.
pub fn copy_storage(value: &OriginalSerializationStorageData) -> OriginalSerializationStorageData {
    OriginalSerializationStorageData {
        dom_and_canonical_scratch_bytes: value.dom_and_canonical_scratch_bytes,
        retained_value_backing_bytes: value.retained_value_backing_bytes,
        projected_parser_requested_bytes: value.projected_parser_requested_bytes,
        canonical_output_requested_bytes: value.canonical_output_requested_bytes,
        serializer_temporary_requested_bytes: value.serializer_temporary_requested_bytes,
        declared_counter_scratch_bytes: value.declared_counter_scratch_bytes,
        maximum_encoded_bytes: value.maximum_encoded_bytes,
        sequence_elements: value.sequence_elements,
        sequence_containers: value.sequence_containers,
        serialized_value_nodes: value.serialized_value_nodes,
        serialized_capacity_records: value.serialized_capacity_records,
    }
}

/// Projects the actual closed content-reference field grammar.
///
/// # Errors
/// Preserves original serializer, extent and checked-storage refusals.
pub fn reference_fields(out: &mut Projection, object: &ContentExtent) -> Result<(), ProviderError> {
    out.add_object()?;
    out.add_field("hash")?;
    out.add_object()?;
    out.add_field("algorithm")?;
    out.add_string("blake3-256")?;
    out.add_field("domain")?;
    out.add_string("cnp.blob.v1")?;
    out.add_field("digest")?;
    out.add_unescaped_ascii_extent(64)?;
    out.add_field("length")?;
    let length = u64::try_from(object.payload).map_err(|_| credit())?;
    // The DATA counter projects U64's decimal JSON string directly. Its
    // ordinary serializer creates a temporary String before a native debit.
    out.add_unescaped_ascii_extent(length.checked_ilog10().unwrap_or(0) as usize + 1)?;
    out.add_field("media_type")?;
    // The contract permits quotes and backslashes in its printable ASCII.
    // Actual preparation bounds its byte length, so preserve worst escaping.
    out.add_string_extent(object.media)
}

/// Projects one original content-reference shape.
///
/// # Errors
/// Preserves original serializer, extent and checked-storage refusals.
pub fn reference_projection(
    object: &ContentExtent,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut out = Projection::new(maximum)?;
    reference_fields(&mut out, object)?;
    out.finish(maximum)
}

/// Projects one ordinary unscoped packet proof frame.
///
/// # Errors
/// Preserves original serializer, extent and checked-storage refusals.
pub fn projected_packet_startup_frame(
    session: &Id,
    incarnation: &Id,
    method: Method,
    body: ProjectedBody<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    projected_blob_frame_scope(
        (session, incarnation),
        false,
        "packet-proof-",
        method,
        body,
        maximum,
    )
}

/// Projects the shared closed Blob frame grammar from original scope identities.
///
/// # Errors
/// Preserves original serializer, extent and checked-storage refusals.
pub fn projected_blob_frame_scope(
    scope: (&Id, &Id),
    after_confirmation: bool,
    request_prefix: &str,
    method: Method,
    body: ProjectedBody<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let (session, incarnation) = scope;
    let mut out = Projection::new(maximum)?;
    out.add_object()?;
    for (key, value) in [("protocol", "CNP/1"), ("message", "request")] {
        out.add_field(key)?;
        out.add_string(value)?;
    }
    out.add_field("session_id")?;
    out.add_value(session)?;
    out.add_field("incarnation_id")?;
    out.add_value(incarnation)?;
    for key in [
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "operation_id",
    ] {
        out.add_field(key)?;
        if after_confirmation && key != "execution_owner_id" {
            out.add_string_extent(128)?;
        } else {
            out.add_value(&Option::<Id>::None)?;
        }
    }
    out.add_field("request_id")?;
    out.add_unescaped_ascii_extent(add(request_prefix.len(), 20)?)?;
    out.add_field("sequence")?;
    out.add_unescaped_ascii_extent(20)?;
    out.add_field("method")?;
    out.add_value(&method)?;
    out.add_field("body")?;
    out.add_object()?;
    match body {
        ProjectedBody::Begin(transfer, object) => {
            out.add_field("transfer_id")?;
            out.add_unescaped_ascii_extent(transfer)?;
            out.add_field("content")?;
            reference_fields(&mut out, object)?;
        }
        ProjectedBody::Chunk(transfer, bytes) => {
            out.add_field("transfer_id")?;
            out.add_unescaped_ascii_extent(transfer)?;
            out.add_field("offset")?;
            out.add_unescaped_ascii_extent(20)?;
            out.add_field("bytes")?;
            out.add_unescaped_ascii_extent(bytes)?;
        }
        ProjectedBody::Finish(transfer) => {
            out.add_field("transfer_id")?;
            out.add_unescaped_ascii_extent(transfer)?;
        }
    }
    out.add_field("extensions")?;
    out.add_object()?;
    out.add_field("extensions")?;
    out.add_object()?;
    out.finish(maximum)
}
