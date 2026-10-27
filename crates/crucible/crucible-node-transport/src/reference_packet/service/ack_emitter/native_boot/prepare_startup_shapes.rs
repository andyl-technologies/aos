//! Projects the complete closed fixed Prepare request and response grammar.
//!
//! No future Id, reference, DTO or permit is constructed. Arbitrary request
//! extension data is separately capped by its actual16KiB contract. Raw/error
//! receive accounting retains the full negotiated ceiling independently.

use super::*;
use crate::reference_packet::service::fresh_restore_allocation::*;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection as Projection;

pub(super) struct PrepareStartupShapes {
    pub(super) body_bytes: usize,
    pub(super) original_bytes: usize,
    pub(super) response_bytes: usize,
}

pub(super) fn project() -> Result<PrepareStartupShapes, ProviderError> {
    let mut body = Projection::new(usize::MAX)?;
    begin_body(&mut body)?;
    let body_bytes = body.finish(usize::MAX)?.maximum_encoded_bytes;

    let mut original = Projection::new(usize::MAX)?;
    envelope(&mut original, false)?;
    original.add_field("body")?;
    begin_body(&mut original)?;
    original.add_field("extensions")?;
    original.add_object()?;
    original.add_field(PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION)?;
    original.add_field(PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION)?;
    // Their actual Value bytes are counted separately below. No placeholder
    // Value is serialized in place of either source-signed full object.
    original.add_field(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)?;
    fresh_binding(&mut original)?;
    let fixed = original.finish(usize::MAX)?.maximum_encoded_bytes;
    let original_bytes = sum(&[
        fixed,
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES,
    ])?;

    let mut response = Projection::new(usize::MAX)?;
    envelope(&mut response, true)?;
    response.add_field("body")?;
    response.add_object()?;
    for key in ["status", "operation_state"] {
        response.add_field(key)?;
        response.add_string("completed")?;
    }
    response.add_field("result")?;
    result(&mut response)?;
    response.add_field("extensions")?;
    response.add_object()?;
    response.add_field("extensions")?;
    response.add_object()?;
    response.add_field(PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION)?;
    receipt(&mut response)?;
    let response_bytes = response.finish(usize::MAX)?.maximum_encoded_bytes;
    Ok(PrepareStartupShapes {
        body_bytes,
        original_bytes,
        response_bytes,
    })
}

fn envelope(out: &mut Projection, response: bool) -> Result<(), ProviderError> {
    out.add_object()?;
    for (key, value) in [
        ("protocol", "CNP/1"),
        ("message", if response { "response" } else { "request" }),
        ("method", "begin"),
    ] {
        out.add_field(key)?;
        out.add_string(value)?;
    }
    // The actual writer leaves capture-owner and operation null. Counting
    // both Id alternatives is conservative and authorizes neither alternative.
    for key in [
        "session_id",
        "incarnation_id",
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "request_id",
        "operation_id",
    ] {
        out.add_field(key)?;
        identifier(out)?;
    }
    out.add_field("sequence")?;
    unsigned(out)
}

fn begin_body(out: &mut Projection) -> Result<(), ProviderError> {
    out.add_object()?;
    out.add_field("kind")?;
    out.add_string("prepare_restore")?;
    out.add_field("binding_hash")?;
    hash(out, "cnp.owner-binding.v1")?;
    for key in ["owner_generation", "world_generation"] {
        out.add_field(key)?;
        unsigned(out)?;
    }
    out.add_field("activation_id")?;
    identifier(out)?;
    out.add_field("arguments")?;
    out.add_object()?;
    out.add_field("transaction_id")?;
    identifier(out)?;
    out.add_field("capture_manifest")?;
    content(out, None)?;
    out.add_field("expected_world_binding_hash")?;
    hash(out, "cnp.world-binding.v1")?;
    out.add_field("expected_owner_binding_hash")?;
    hash(out, "cnp.owner-binding.v1")?;
    out.add_field("destination_owner_ids")?;
    out.add_array_extent(1)?;
    identifier(out)?;
    out.add_field("extensions")?;
    out.add_object()
}

fn fresh_binding(out: &mut Projection) -> Result<(), ProviderError> {
    out.add_object()?;
    out.add_field("schema")?;
    out.add_string(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)?;
    for key in ["assigned_query", "completed_query_response"] {
        out.add_field(key)?;
        out.add_unescaped_ascii_extent(43)?;
    }
    out.add_field("allocation")?;
    content(out, Some(PACKET_FRESH_RESTORE_ALLOCATION_MEDIA))
}

fn result(out: &mut Projection) -> Result<(), ProviderError> {
    out.add_object()?;
    for key in ["transaction_id", "prepared_token"] {
        out.add_field(key)?;
        identifier(out)?;
    }
    out.add_field("world_binding_hash")?;
    hash(out, "cnp.world-binding.v1")?;
    out.add_field("owner_binding_hash")?;
    hash(out, "cnp.owner-binding.v1")?;
    out.add_field("staged_owner_ids")?;
    out.add_array_extent(1)?;
    identifier(out)?;
    for key in ["closed_gate_receipt", "validated_manifest"] {
        out.add_field(key)?;
        content(out, None)?;
    }
    Ok(())
}

fn receipt(out: &mut Projection) -> Result<(), ProviderError> {
    out.add_object()?;
    out.add_field("schema")?;
    out.add_string(PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION)?;
    out.add_field("algorithm")?;
    out.add_string(PACKET_COMPLETE_RESTORE_ALGORITHM)?;
    for key in [
        "prepare_digest",
        "context_digest",
        "input_roster",
        "transfer_token",
        "assigned_response",
        "mac",
    ] {
        out.add_field(key)?;
        out.add_unescaped_ascii_extent(43)?;
    }
    for key in ["generation", "native_sequence"] {
        out.add_field(key)?;
        unsigned(out)?;
    }
    Ok(())
}

fn content(out: &mut Projection, media: Option<&str>) -> Result<(), ProviderError> {
    out.add_object()?;
    out.add_field("hash")?;
    hash(out, "cnp.blob.v1")?;
    out.add_field("length")?;
    unsigned(out)?;
    out.add_field("media_type")?;
    match media {
        Some(media) => out.add_string(media),
        None => out.add_string_extent(128),
    }
}

fn hash(out: &mut Projection, domain: &str) -> Result<(), ProviderError> {
    out.add_object()?;
    out.add_field("algorithm")?;
    out.add_string("blake3-256")?;
    out.add_field("domain")?;
    out.add_string(domain)?;
    out.add_field("digest")?;
    out.add_unescaped_ascii_extent(64)
}

fn identifier(out: &mut Projection) -> Result<(), ProviderError> {
    // Id's actual closed alphabet excludes quotes, backslashes and controls.
    out.add_unescaped_ascii_extent(128)
}

fn unsigned(out: &mut Projection) -> Result<(), ProviderError> {
    // U64's actual formatter emits a quoted at-most20-digit decimal string.
    out.add_unescaped_ascii_extent(20)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bodies::{OperationState, PrepareRestoreResult, ResponseShape};
    use crate::envelope::{Envelope, MessageKind, Method, Nullable};
    use crucible_node_format::Extensions;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn maximum_typed_prepare_response_and_receipt_fit_the_closed_field_projection() -> TestResult {
        let shapes = project()?;
        let id = Id::new("a".repeat(128))?;
        let media = "\"\\".repeat(64);
        let reference = canonical::content_ref(b"{}", &media)?;
        let result = PrepareRestoreResult {
            transaction_id: id.clone(),
            prepared_token: id.clone(),
            world_binding_hash: canonical::hash("cnp.world-binding.v1", b"world")?,
            owner_binding_hash: canonical::hash("cnp.owner-binding.v1", b"owner")?,
            staged_owner_ids: vec![id.clone()],
            closed_gate_receipt: reference.clone(),
            validated_manifest: reference,
        };
        let value = serde_json::to_value(result)?;
        let body = ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: value.as_object().ok_or("result object")?.clone(),
            extensions: Extensions::new(),
        };
        let body = serde_json::to_value(body)?;
        let receipt = PacketCompleteRestorePrepareReceipt {
            schema: PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION.into(),
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
            prepare_digest: Bytes::new(vec![255; 32]),
            context_digest: Bytes::new(vec![255; 32]),
            input_roster: Bytes::new(vec![255; 32]),
            transfer_token: Bytes::new(vec![255; 32]),
            generation: u64::MAX.into(),
            native_sequence: u64::MAX.into(),
            assigned_response: Bytes::new(vec![255; 32]),
            mac: Bytes::new(vec![255; 32]),
        };
        assert!(
            serde_json::to_vec(&receipt)?.len() <= MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES
        );
        let original = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Response,
            session_id: Nullable(Some(id.clone())),
            incarnation_id: Nullable(Some(id.clone())),
            node_id: Nullable(Some(id.clone())),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(Some(id.clone())),
            request_id: Nullable(Some(id.clone())),
            operation_id: Nullable(Some(id)),
            sequence: u64::MAX.into(),
            method: Method::Begin,
            body: body.as_object().ok_or("response object")?.clone(),
            extensions: [(
                PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION.into(),
                serde_json::to_value(receipt)?,
            )]
            .into(),
        };
        let encoded = serde_json::to_vec(&original)?;
        assert!(encoded.len() <= shapes.response_bytes);
        let copy = original.clone();
        let mut observer = MetadataObserver::new();
        observer.observe(&copy)?;
        let actual =
            crate::retained_metadata::requested_storage::requested_metadata_backing_storage_data(
                &observer.finish(),
            )?;
        let bound = original_json_value_storage_extent_data(shapes.response_bytes)?;
        assert!(actual <= bound.value_dom_requested_bytes);
        Ok(())
    }
}
