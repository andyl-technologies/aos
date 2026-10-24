//! Checks both actual upload journals, signed contexts and complete payloads.
//!
//! Payload verification streams the exact normative CNP hash framing over the
//! actual retained Chunk bodies. It never allocates a second complete uploaded
//! object, fabricates a Blob completion, or interprets DATA as a native lease.

use super::*;
use crate::reference_packet::service::native_startup::{
    PacketRestoredSettledCaptureUploadGeometryData,
    original_restored_settled_capture_auxiliary_geometry_for_limits_data,
};
use crate::reference_packet::service::restored_settled_capture::upload::*;

pub(super) fn authenticate_uploads_data(
    capture: &Map<String, Value>,
    root: &Map<String, Value>,
    request: &PacketRestoredSettledCaptureRequest,
    limits: &crate::handshake::Limits,
    prefix_frontier: U64,
) -> Result<U64, ProviderError> {
    let maxima = tuple(field(capture, "maximum_auxiliary_originals")?, 2)?;
    let maxima = [
        usize::try_from(number(&maxima[0])?).map_err(|_| invalid())?,
        usize::try_from(number(&maxima[1])?).map_err(|_| invalid())?,
    ];
    let maximum = maxima[0]
        .checked_add(maxima[1])
        .and_then(|n| n.checked_add(2))
        .ok_or_else(invalid)?;
    let geometry = original_restored_settled_capture_auxiliary_geometry_for_limits_data(
        limits,
        &request.history_prefix,
        &request.runtime_object,
        maximum,
    )?;
    if geometry.maximum_auxiliary_originals_data() != maxima {
        return Err(invalid());
    }
    let uploads = tuple(field(capture, "auxiliary_uploads")?, 2)?;
    let mut frontier = prefix_frontier;
    for (ordinal, history) in uploads.iter().enumerate() {
        frontier =
            authenticate_upload_data(history, root, request, ordinal, &geometry, limits, frontier)?;
    }
    Ok(frontier)
}

fn authenticate_upload_data(
    history: &Value,
    root: &Map<String, Value>,
    capture: &PacketRestoredSettledCaptureRequest,
    ordinal: usize,
    geometry: &PacketRestoredSettledCaptureUploadGeometryData,
    limits: &crate::handshake::Limits,
    mut frontier: U64,
) -> Result<U64, ProviderError> {
    let history = history.as_object().ok_or_else(invalid)?;
    let request: PacketRestoredSettledCaptureUploadRequest = read(field(history, "request")?)?;
    let context: PacketRestoredSettledCaptureUploadContext = read(field(history, "context")?)?;
    let artifact: PacketRestoredSettledCaptureUploadArtifact = read(field(history, "artifact")?)?;
    request.validate_data()?;
    context.validate_data()?;
    artifact.validate_data()?;
    let expected_ordinal = match ordinal {
        0 => PacketRestoredSettledCaptureUploadOrdinal::HistoryPrefix,
        1 => PacketRestoredSettledCaptureUploadOrdinal::RuntimeObject,
        _ => return Err(invalid()),
    };
    let completed = field(history, "completed")?
        .as_array()
        .ok_or_else(invalid)?;
    if !field(history, "pending")?.is_null()
        || field(history, "finished")?.as_bool() != Some(true)
        || request.capture != *capture
        || request.ordinal != expected_ordinal
        || context.request != request
        || artifact.request != request
        || artifact.proof.context_digest.as_slice()
            != restored_settled_capture_upload_context_digest_data(&context)?
        || completed.len() != geometry.maximum_auxiliary_originals_data()[ordinal]
        || usize::try_from(number(field(history, "maximum_originals")?)?).map_err(|_| invalid())?
            != completed.len()
        || read::<U64>(field(history, "next_offset")?)? != request.content.length
    {
        return Err(invalid());
    }
    let maximum_frame = usize::try_from(limits.frame_bytes.get()).map_err(|_| invalid())?;
    let maximum_chunk: U64 = read(field(history, "maximum_chunk")?)?;
    if maximum_chunk.get() == 0 {
        return Err(invalid());
    }
    let mut offset = 0usize;
    let length = usize::try_from(request.content.length.get()).map_err(|_| invalid())?;
    let mut payload_hash = payload_hasher_data(&request.content)?;
    for (index, original_history) in completed.iter().enumerate() {
        let original_history = original_history.as_object().ok_or_else(invalid)?;
        let pair = pair_data(original_history, "frontier", root)?;
        if pair.original.sequence != frontier
            || pair.original.capture_owner_id.0.as_ref() != Some(&capture.capture_owner)
            || pair.original.operation_id.0.is_some()
        {
            return Err(invalid());
        }
        let body = object(field(original_history, "body")?, &["kind", "data"])?;
        if field(body, "data")? != &Value::Object(pair.original.body.clone()) {
            return Err(invalid());
        }
        if index == 0 {
            text(field(body, "kind")?, "begin")?;
            let request_body: BlobBeginRequest = read(field(body, "data")?)?;
            let Some(MethodResult::BlobBegin(result)) = pair.response.result.as_ref() else {
                return Err(invalid());
            };
            let assigned = restored_settled_capture_upload_assigned_request_digest_data(
                &pair.original,
                maximum_frame,
            )?;
            let extension = object(field(original_history, "extension")?, &["request"])?;
            if !field(original_history, "continuation")?.is_null()
                || pair.original.method != Method::BlobBegin
                || pair
                    .original
                    .extensions
                    .get(RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE)
                    != Some(&value_data(&artifact)?)
                || field(extension, "request")? != &value_data(&request)?
                || context.assigned_request.as_slice() != assigned
                || request_body.transfer_id != request.transfer_id
                || request_body.content != request.content
                || !request_body.extensions.is_empty()
                || result.transfer_id != request.transfer_id
                || result.next_offset != U64::new(0)
                || result.maximum_chunk_bytes != maximum_chunk
            {
                return Err(invalid());
            }
        } else {
            let continuation: PacketRestoredSettledCaptureUploadContinuation =
                read(field(original_history, "continuation")?)?;
            authenticate_restored_settled_capture_upload_continuation_data(
                &pair.original,
                &context,
                &continuation,
            )?;
            if field(original_history, "extension")? != &value_data(&continuation)? {
                return Err(invalid());
            }
            if index + 1 == completed.len() {
                text(field(body, "kind")?, "finish")?;
                let request_body: BlobFinishRequest = read(field(body, "data")?)?;
                let Some(MethodResult::BlobFinish(result)) = pair.response.result.as_ref() else {
                    return Err(invalid());
                };
                if pair.original.method != Method::BlobFinish
                    || offset != length
                    || request_body.transfer_id != request.transfer_id
                    || result.transfer_id != request.transfer_id
                    || result.content != request.content
                {
                    return Err(invalid());
                }
            } else {
                text(field(body, "kind")?, "chunk")?;
                let request_body: BlobChunkRequest = read(field(body, "data")?)?;
                let Some(MethodResult::BlobChunk(result)) = pair.response.result.as_ref() else {
                    return Err(invalid());
                };
                let chunk = request_body.bytes.as_slice();
                let expected = geometry.expected_chunk_length_data(ordinal, offset)?;
                let next = offset.checked_add(chunk.len()).ok_or_else(invalid)?;
                if pair.original.method != Method::BlobChunk
                    || request_body.transfer_id != request.transfer_id
                    || request_body.offset.get() != u64::try_from(offset).map_err(|_| invalid())?
                    || chunk.len() != expected
                    || u64::try_from(chunk.len()).map_err(|_| invalid())? > maximum_chunk.get()
                    || next > length
                    || result.transfer_id != request.transfer_id
                    || result.next_offset.get() != u64::try_from(next).map_err(|_| invalid())?
                {
                    return Err(invalid());
                }
                payload_hash.update(chunk);
                offset = next;
            }
        }
        frontier = pair.frontier;
    }
    if offset != length || payload_hash.finalize().to_hex().as_str() != request.content.hash.digest
    {
        return Err(invalid());
    }
    Ok(frontier)
}

fn payload_hasher_data(reference: &ContentRef) -> Result<blake3::Hasher, ProviderError> {
    reference.validate()?;
    if reference.hash.algorithm != "blake3-256" || reference.hash.domain != "cnp.blob.v1" {
        return Err(invalid());
    }
    // Exactly canonical::hash's framing, streamed over the retained Chunk bytes.
    let domain = reference.hash.domain.as_bytes();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(
        &u32::try_from(domain.len())
            .map_err(|_| invalid())?
            .to_be_bytes(),
    );
    hasher.update(domain);
    hasher.update(&reference.length.get().to_be_bytes());
    Ok(hasher)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_chunk_stream_has_exact_normative_blob_identity() {
        let payload = b"actual retained chunks preserve byte ordering";
        let reference = canonical::content_ref(payload, "application/json").unwrap();
        let mut stream = payload_hasher_data(&reference).unwrap();
        for chunk in payload.chunks(7) {
            stream.update(chunk);
        }
        assert_eq!(stream.finalize().to_hex().as_str(), reference.hash.digest);

        let mut reordered = payload_hasher_data(&reference).unwrap();
        for chunk in payload.chunks(7).rev() {
            reordered.update(chunk);
        }
        assert_ne!(
            reordered.finalize().to_hex().as_str(),
            reference.hash.digest
        );
    }
}
