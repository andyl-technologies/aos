//! Sends only the two independently admitted, Source-signed Capture auxiliaries.
//!
//! The parent owns the real ticket/claim, SourceRead and separately admitted SDK
//! row before calling. SDK owns every assigned/raw/typed/failed transport slot.
//! This helper never uses generic Blob or old suffix upload permission.

use super::signing::CaptureSigningOwners;
use crate::node_contract::RuntimeError;
use crucible_node_format::{Bytes, ContentRef, Extensions, Id, U64};
use crucible_node_transport::{
    bodies::{BlobBeginRequest, BlobChunkRequest, BlobFinishRequest, MethodResult},
    client::{
        OriginalCanonicalBlobAckEmitter, PreparedOriginalRestoredSettledCapture,
        RestoredSettledCaptureAuxiliaryBody,
    },
    reference_packet::service::{
        native_startup::PacketRestoredSettledCaptureUploadGeometryData,
        restored_settled_capture::upload::{
            PacketRestoredSettledCaptureUploadOrdinal, PacketRestoredSettledCaptureUploadRequest,
        },
    },
};
use std::{fmt::Write, mem::size_of};

pub(super) fn upload_data(
    prepared: &mut PreparedOriginalRestoredSettledCapture<'_>,
    signatures: &mut CaptureSigningOwners,
    emitter: &OriginalCanonicalBlobAckEmitter,
    key: &[u8; 32],
    request: &PacketRestoredSettledCaptureUploadRequest,
    payload: (&ContentRef, &[u8]),
    geometry: &PacketRestoredSettledCaptureUploadGeometryData,
    sdk: &crucible_node_transport::client::OriginalRestoredSettledCaptureConstructionData,
    request_ids: &mut Vec<Id>,
    bodies: &mut Vec<RestoredSettledCaptureAuxiliaryBody>,
    recheck: &mut dyn FnMut() -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    let ordinal = match request.ordinal {
        PacketRestoredSettledCaptureUploadOrdinal::HistoryPrefix => 0,
        PacketRestoredSettledCaptureUploadOrdinal::RuntimeObject => 1,
    };
    let originals = geometry.maximum_auxiliary_originals_data()[ordinal];
    if request.content != *payload.0 || originals < 2 {
        return Err(RuntimeError::InvalidReceipt);
    }
    if request_ids
        .len()
        .checked_add(originals)
        .is_none_or(|needed| needed > request_ids.capacity())
        || bodies
            .len()
            .checked_add(originals)
            .is_none_or(|needed| needed > bodies.capacity())
    {
        return Err(RuntimeError::ResourceLimit);
    }
    payload
        .0
        .verify(payload.1)
        .map_err(|_| RuntimeError::InvalidReceipt)?;

    let first = request_ids.len();
    request_ids.push(request_id_data(
        &request.capture.capture.capture_id,
        ordinal,
        0,
    )?);
    bodies.push(RestoredSettledCaptureAuxiliaryBody::Begin(
        BlobBeginRequest {
            transfer_id: request.transfer_id.clone(),
            content: payload.0.clone(),
            extensions: Extensions::new(),
        },
    ));
    let Some(RestoredSettledCaptureAuxiliaryBody::Begin(body)) = bodies.last() else {
        return Err(RuntimeError::OwnerUnavailable);
    };
    recheck()?;
    let mut begin = prepared
        .begin_auxiliary_data(
            emitter,
            request_ids[first].clone(),
            request.clone(),
            body.clone(),
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    signatures.seal_upload_data(
        &mut begin,
        emitter,
        key,
        request,
        sdk,
        sdk.maximum_frame_bytes_data(),
    )?;
    recheck()?;
    begin
        .publish_data(emitter)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    drop(begin);
    let (_, _, reply) = prepared
        .auxiliary_completed_pair_data(request.ordinal)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if !matches!(reply.result.as_ref(), Some(MethodResult::BlobBegin(result))
        if result.transfer_id == request.transfer_id && result.next_offset == U64::new(0)
            && usize::try_from(result.maximum_chunk_bytes.get()).is_ok_and(|maximum|
                maximum >= geometry.maximum_chunk_bytes_data()))
    {
        return Err(RuntimeError::InvalidReceipt);
    }

    let mut offset = 0usize;
    let mut index = 1usize;
    while offset < payload.1.len() {
        let length = geometry
            .expected_chunk_length_data(ordinal, offset)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let end = offset
            .checked_add(length)
            .ok_or(RuntimeError::ResourceLimit)?;
        let bytes = payload
            .1
            .get(offset..end)
            .ok_or(RuntimeError::InvalidReceipt)?;
        if index
            .checked_add(1)
            .is_none_or(|needed| needed >= originals)
        {
            return Err(RuntimeError::ResourceLimit);
        }
        request_ids.push(request_id_data(
            &request.capture.capture.capture_id,
            ordinal,
            index,
        )?);
        // Keep the Source body before any SDK guard can reject its incoming
        // copy. The SDK and Source byte banks are independently precredited.
        bodies.push(RestoredSettledCaptureAuxiliaryBody::Chunk(
            BlobChunkRequest {
                transfer_id: request.transfer_id.clone(),
                offset: U64::new(u64::try_from(offset).map_err(|_| RuntimeError::ResourceLimit)?),
                bytes: Bytes::new(bytes.to_vec()),
                extensions: Extensions::new(),
            },
        ));
        let Some(RestoredSettledCaptureAuxiliaryBody::Chunk(body)) = bodies.last() else {
            return Err(RuntimeError::OwnerUnavailable);
        };
        recheck()?;
        let mut chunk = prepared
            .continue_auxiliary_data(
                emitter,
                request.ordinal,
                request_ids
                    .last()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .clone(),
                RestoredSettledCaptureAuxiliaryBody::Chunk(body.clone()),
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        // Continuations carry the exact retained signed Begin context digest;
        // they neither create another Source proof nor acquire generic upload.
        recheck()?;
        chunk
            .publish_data(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        drop(chunk);
        let (_, _, reply) = prepared
            .auxiliary_completed_pair_data(request.ordinal)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if !matches!(reply.result.as_ref(), Some(MethodResult::BlobChunk(result))
            if result.transfer_id == request.transfer_id
                && usize::try_from(result.next_offset.get()) == Ok(end))
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        offset = end;
        index = index.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
    }
    if index.checked_add(1) != Some(originals) {
        return Err(RuntimeError::InvalidReceipt);
    }
    request_ids.push(request_id_data(
        &request.capture.capture.capture_id,
        ordinal,
        index,
    )?);
    bodies.push(RestoredSettledCaptureAuxiliaryBody::Finish(
        BlobFinishRequest {
            transfer_id: request.transfer_id.clone(),
            extensions: Extensions::new(),
        },
    ));
    let Some(RestoredSettledCaptureAuxiliaryBody::Finish(body)) = bodies.last() else {
        return Err(RuntimeError::OwnerUnavailable);
    };
    recheck()?;
    let mut finish = prepared
        .continue_auxiliary_data(
            emitter,
            request.ordinal,
            request_ids
                .last()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .clone(),
            RestoredSettledCaptureAuxiliaryBody::Finish(body.clone()),
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    recheck()?;
    finish
        .publish_data(emitter)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    drop(finish);
    let (_, _, reply) = prepared
        .auxiliary_completed_pair_data(request.ordinal)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if !matches!(reply.result.as_ref(), Some(MethodResult::BlobFinish(result))
        if result.transfer_id == request.transfer_id && result.content == *payload.0)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    if request_ids.len() - first != originals {
        return Err(RuntimeError::InvalidReceipt);
    }
    recheck()
}

/// Creates only routing DATA in the actual per-Controller request namespace.
fn request_id_data(capture: &Id, ordinal: usize, index: usize) -> Result<Id, RuntimeError> {
    let mut hash = blake3::Hasher::new_derive_key("source.restored-capture17-request-id/1");
    hash.update(capture.as_str().as_bytes());
    let ordinal = u64::try_from(ordinal).map_err(|_| RuntimeError::ResourceLimit)?;
    let index = u64::try_from(index).map_err(|_| RuntimeError::ResourceLimit)?;
    hash.update(&ordinal.to_le_bytes());
    hash.update(&index.to_le_bytes());
    let mut text = String::new();
    text.try_reserve_exact(128)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    write!(&mut text, "source-capture17-{}", hash.finalize().to_hex())
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    Id::new(text).map_err(|_| RuntimeError::InvalidReceipt)
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<blake3::Hasher>()
        + size_of::<String>()
        + size_of::<Id>()
        + size_of::<Option<&Id>>()
        + size_of::<Result<Id, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<&mut PreparedOriginalRestoredSettledCapture<'static>>()
        + size_of::<&PacketRestoredSettledCaptureUploadRequest>()
        + size_of::<&PacketRestoredSettledCaptureUploadGeometryData>()
        + size_of::<(&ContentRef, &[u8])>()
        + size_of::<&mut Vec<Id>>()
        + size_of::<&mut Vec<RestoredSettledCaptureAuxiliaryBody>>()
        + size_of::<Option<&RestoredSettledCaptureAuxiliaryBody>>()
        + size_of::<RestoredSettledCaptureAuxiliaryBody>()
        + size_of::<&BlobBeginRequest>()
        + size_of::<&BlobChunkRequest>()
        + size_of::<&BlobFinishRequest>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<&mut dyn FnMut() -> Result<(), RuntimeError>>()
        + size_of::<[usize; 6]>()
        + size_of::<[u8; 8]>()
        + CaptureSigningOwners::counter_scratch_data()
}

/// Counts all actual Source typed-body banks independently of SDK custody.
pub(super) fn bodies_retained_storage_data(
    bodies: &[RestoredSettledCaptureAuxiliaryBody],
    maximum: usize,
) -> Result<usize, RuntimeError> {
    use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
        sum_with_error, value_storage_with_error,
    };
    use crate::node_contract::NodeRuntime;

    let mut total = 0usize;
    for body in bodies {
        let (transfer, content, bytes, extensions) = match body {
            RestoredSettledCaptureAuxiliaryBody::Begin(body) => {
                let BlobBeginRequest {
                    transfer_id,
                    content,
                    extensions,
                } = body;
                (transfer_id, Some(content), 0, extensions)
            }
            RestoredSettledCaptureAuxiliaryBody::Chunk(body) => {
                let BlobChunkRequest {
                    transfer_id,
                    offset: _,
                    bytes,
                    extensions,
                } = body;
                (transfer_id, None, bytes.allocation_capacity(), extensions)
            }
            RestoredSettledCaptureAuxiliaryBody::Finish(body) => {
                let BlobFinishRequest {
                    transfer_id,
                    extensions,
                } = body;
                (transfer_id, None, 0, extensions)
            }
        };
        let tree = NodeRuntime::capture_protocol_tree_storage(
            1,
            extensions.len(),
            size_of::<(String, serde_json::Value)>(),
            std::mem::align_of::<(String, serde_json::Value)>(),
            maximum,
        )?;
        total = sum_with_error::<RuntimeError, _>(
            [
                total,
                transfer.allocated_capacity(),
                bytes,
                tree,
                content
                    .map(NodeRuntime::capture_reference_storage)
                    .transpose()?
                    .unwrap_or(0),
            ],
            maximum,
        )?;
        for (key, value) in extensions {
            total = sum_with_error::<RuntimeError, _>(
                [
                    total,
                    key.capacity(),
                    value_storage_with_error::<RuntimeError>(value, 0, maximum)?,
                ],
                maximum,
            )?;
        }
    }
    Ok(total)
}
