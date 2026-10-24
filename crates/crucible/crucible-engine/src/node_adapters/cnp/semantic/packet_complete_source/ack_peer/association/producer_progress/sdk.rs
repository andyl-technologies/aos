//! Retains bounded upload originals and validates every actual method reply.

use super::*;

pub(super) fn upload_data(
    attempt: &mut ProducerProgressAttempt,
    controller: &mut CnpController,
    association: &OriginalAckPeerAssociation,
    authorization: bool,
    recheck: &mut dyn FnMut() -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    let payload = if authorization {
        attempt.authorization.as_ref()
    } else {
        attempt.consumption.as_ref()
    }
    .ok_or(RuntimeError::OwnerUnavailable)?;
    payload
        .reference
        .verify(&payload.bytes)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let emitter = association
        .emitter
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    let transfer = request_id_data(
        attempt.slot,
        if authorization {
            "grant"
        } else {
            "consumption"
        },
        0,
    )?;
    let chunk = attempt
        .row
        .provider
        .maximum_upload_chunk_bytes_data()
        .map_err(|_| RuntimeError::ResourceLimit)?;
    if payload.bytes.len() > 8192 || chunk == 0 {
        return Err(RuntimeError::ResourceLimit);
    }
    attempt
        .upload_bodies
        .push(UploadBody::Begin(BlobBeginRequest {
            transfer_id: transfer.clone(),
            content: payload.reference.clone(),
            extensions: Extensions::new(),
        }));
    let first = attempt.upload_bodies.len() - 1;
    for (index, bytes) in payload.bytes.chunks(chunk).enumerate() {
        let offset = index
            .checked_mul(chunk)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(RuntimeError::ResourceLimit)?;
        attempt
            .upload_bodies
            .push(UploadBody::Chunk(BlobChunkRequest {
                transfer_id: transfer.clone(),
                offset: U64::new(offset),
                bytes: Bytes::new(bytes.to_vec()),
                extensions: Extensions::new(),
            }));
    }
    attempt
        .upload_bodies
        .push(UploadBody::Finish(BlobFinishRequest {
            transfer_id: transfer,
            extensions: Extensions::new(),
        }));
    for index in first..attempt.upload_bodies.len() {
        if attempt.uploads.len() >= attempt.row.provider.maximum_originals_data() {
            return Err(RuntimeError::ResourceLimit);
        }
        attempt.uploads.push(None);
        let id = request_id_data(attempt.slot, "blob", index)?;
        attempt.request_ids.push(id);
        recheck()?;
        let mut marker = controller
            .prepare_original_restored_suffix_into(
                emitter,
                attempt
                    .request_ids
                    .last()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .clone(),
                None,
                attempt.upload_bodies[index].body_data(),
                Extensions::new(),
                attempt
                    .uploads
                    .last_mut()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        marker
            .original_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        recheck()?;
        marker
            .publish_data(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        drop(marker);
        let (_, _, reply) = attempt
            .uploads
            .last()
            .and_then(Option::as_ref)
            .ok_or(RuntimeError::OwnerUnavailable)?
            .completed_pair_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        authenticate_upload_reply_data(
            &attempt.upload_bodies[index],
            reply,
            &payload.reference,
            chunk,
        )?;
    }
    Ok(())
}

fn authenticate_upload_reply_data(
    body: &UploadBody,
    reply: &ResponseBody,
    content: &ContentRef,
    chunk: usize,
) -> Result<(), RuntimeError> {
    if !matches!(&reply.shape, ResponseShape::Completed { extensions, .. } if extensions.is_empty())
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let valid = match (body, &reply.result) {
        (UploadBody::Begin(request), Some(MethodResult::BlobBegin(result))) => {
            result.transfer_id == request.transfer_id
                && result.next_offset.get() == 0
                && usize::try_from(result.maximum_chunk_bytes.get())
                    .is_ok_and(|maximum| maximum >= chunk)
        }
        (UploadBody::Chunk(request), Some(MethodResult::BlobChunk(result))) => {
            result.transfer_id == request.transfer_id
                && u64::try_from(request.bytes.as_slice().len())
                    .ok()
                    .and_then(|length| request.offset.get().checked_add(length))
                    == Some(result.next_offset.get())
        }
        (UploadBody::Finish(request), Some(MethodResult::BlobFinish(result))) => {
            result.transfer_id == request.transfer_id && &result.content == content
        }
        _ => false,
    };
    if !valid {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

pub(super) fn request_id_data(slot: usize, phase: &str, index: usize) -> Result<Id, RuntimeError> {
    use std::fmt::Write;
    let mut text = String::new();
    text.try_reserve_exact(128)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    write!(&mut text, "restored-producer-{slot}-{phase}-{index}")
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    Id::new(text).map_err(|_| RuntimeError::InvalidReceipt)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "closed reply DATA controls use no live claim or native authority"
)]
mod tests {
    use super::*;

    #[test]
    fn producer_upload_finish_requires_method_and_complete_full_reference() {
        let reference = canonical::content_ref(b"complete", "application/json").unwrap();
        let transfer = Id::new("actual-transfer").unwrap();
        let body = UploadBody::Finish(BlobFinishRequest {
            transfer_id: transfer.clone(),
            extensions: Extensions::new(),
        });
        let mut reply = ResponseBody {
            shape: ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result: serde_json::Map::new(),
                extensions: Extensions::new(),
            },
            result: Some(MethodResult::BlobFinish(BlobFinishResult {
                transfer_id: transfer,
                content: reference.clone(),
            })),
        };
        authenticate_upload_reply_data(&body, &reply, &reference, 1).unwrap();
        let mut different = reference.clone();
        different.media_type = "application/octet-stream".into();
        assert!(authenticate_upload_reply_data(&body, &reply, &different, 1).is_err());
        reply.result = None;
        assert!(authenticate_upload_reply_data(&body, &reply, &reference, 1).is_err());
    }

    #[test]
    fn producer_ids_bind_both_operation_slot_and_phase_without_replacement() {
        let first = request_id_data(0, "begin", 0).unwrap();
        assert_eq!(first, request_id_data(0, "begin", 0).unwrap());
        assert_ne!(first, request_id_data(1, "begin", 0).unwrap());
        assert_ne!(first, request_id_data(0, "poll", 0).unwrap());
        assert_ne!(
            request_id_data(0, "blob", 0).unwrap(),
            request_id_data(0, "blob", 1).unwrap()
        );
        assert!(
            request_id_data(usize::MAX, "consumption", usize::MAX)
                .unwrap()
                .as_str()
                .len()
                <= 128
        );
    }
}
