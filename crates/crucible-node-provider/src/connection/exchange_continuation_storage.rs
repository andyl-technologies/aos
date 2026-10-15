//! Counts only ordinary Blob prefix grammar from original launch/registration data.
//!
//! These exact shared helper bodies contain no selected Capture or confirmation
//! planner, controller callback, native owner constructor or allocation grant.

use super::*;

/// Names an actual schema's future encoded payload and printable media type.
///
/// The source-selected native producer derives the length from its complete
/// bounded encoder. This is data, not a reference, an observed capacity or an
/// allowance to allocate or read that many bytes.
pub(crate) struct OriginalContinuationContentExtent<'a> {
    pub(crate) maximum_payload_bytes: usize,
    pub(crate) media_type: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ContentExtent {
    pub(super) payload: usize,
    pub(super) media: usize,
}

pub(super) fn copy_storage(
    value: &OriginalSerializationStorageData,
) -> OriginalSerializationStorageData {
    OriginalSerializationStorageData {
        dom_and_canonical_scratch_bytes: value.dom_and_canonical_scratch_bytes,
        projected_parser_requested_bytes: value.projected_parser_requested_bytes,
        canonical_output_requested_bytes: value.canonical_output_requested_bytes,
        serializer_temporary_requested_bytes: value.serializer_temporary_requested_bytes,
        declared_counter_scratch_bytes: value.declared_counter_scratch_bytes,
        maximum_encoded_bytes: value.maximum_encoded_bytes,
        sequence_elements: value.sequence_elements,
        sequence_containers: value.sequence_containers,
    }
}

pub(super) fn within(
    actual: &OriginalSerializationStorageData,
    bound: &OriginalSerializationStorageData,
) -> Result<(), ProviderError> {
    for (actual, bound) in [
        (
            actual.dom_and_canonical_scratch_bytes,
            bound.dom_and_canonical_scratch_bytes,
        ),
        (
            actual.projected_parser_requested_bytes,
            bound.projected_parser_requested_bytes,
        ),
        (
            actual.canonical_output_requested_bytes,
            bound.canonical_output_requested_bytes,
        ),
        (
            actual.serializer_temporary_requested_bytes,
            bound.serializer_temporary_requested_bytes,
        ),
        (
            actual.declared_counter_scratch_bytes,
            bound.declared_counter_scratch_bytes,
        ),
        (actual.maximum_encoded_bytes, bound.maximum_encoded_bytes),
        (actual.sequence_elements, bound.sequence_elements),
        (actual.sequence_containers, bound.sequence_containers),
    ] {
        if actual > bound {
            return Err(credit());
        }
    }
    Ok(())
}

pub(super) enum ProjectedBody<'a> {
    Begin(usize, &'a ContentExtent),
    Chunk(usize, usize),
    Finish(usize),
}

fn reference_fields(out: &mut Projection, object: &ContentExtent) -> Result<(), ProviderError> {
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
    out.add_value(&U64::new(
        u64::try_from(object.payload).map_err(|_| credit())?,
    ))?;
    out.add_field("media_type")?;
    // The contract permits quotes and backslashes in its printable ASCII.
    // Actual preparation bounds its byte length, so preserve worst escaping.
    out.add_string_extent(object.media)
}

pub(super) fn reference_projection(
    object: &ContentExtent,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut out = Projection::new(maximum)?;
    reference_fields(&mut out, object)?;
    out.finish(maximum)
}

/// Counts the actual ordinary unscoped packet proof grammar without an owner.
pub(super) fn projected_packet_frame(
    authority: &ConnectionAuthority,
    method: Method,
    body: ProjectedBody<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    projected_blob_frame(authority, false, "packet-proof-", method, body, maximum)
}

fn projected_blob_frame(
    authority: &ConnectionAuthority,
    after_confirmation: bool,
    request_prefix: &str,
    method: Method,
    body: ProjectedBody<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    projected_blob_frame_scope(
        (authority.session_id(), authority.incarnation_id()),
        after_confirmation,
        request_prefix,
        method,
        body,
        maximum,
    )
}

/// Uses actual launch identities without constructing registration authority.
pub(super) fn projected_packet_startup_frame(
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

fn projected_blob_frame_scope(
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
    out.add_value(&U64::new(u64::MAX))?;
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
            out.add_value(&U64::new(u64::MAX))?;
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
