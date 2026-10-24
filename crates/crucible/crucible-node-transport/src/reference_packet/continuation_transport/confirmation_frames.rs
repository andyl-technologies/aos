//! Plans the fourth after-body transfer before a correlated confirmation reply.
//!
//! This distinct planner leaves the existing Begin/Capture three-body grammar
//! unchanged. Its caller retains the actual opaque after owner, installed source
//! selection and the complete original Capture terminal beside this plan.

use super::frames::CapturePlan;
use super::*;
use crate::handshake::ConnectionAuthority;
use crate::reference_packet::service::confirmation::{
    PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION, PacketNativeAfterConfirmationReceipt,
};
use crucible_node_format::{Bytes, Extensions, U64};
use serde::Serialize;
use serde_json::{Map, Value};

pub(super) fn confirmation_plan(
    authority: &crate::handshake::ConnectionAuthority,
    response: &Envelope,
    receipt: &PacketNativeAfterConfirmationReceipt,
    after: (&ContentRef, &[u8]),
    maximum_after_bytes: usize,
) -> Result<CapturePlan, ProviderError> {
    if response.message != MessageKind::Response
        || response.method != Method::Poll
        || response.operation_id.0.is_none()
        || response.request_id.0.is_none()
        || response.capture_owner_id.0.is_none()
        || response.execution_owner_id.0.is_some()
        || response.session_id.0.as_ref() != Some(authority.session_id())
        || response.incarnation_id.0.as_ref() != Some(authority.incarnation_id())
        || response.extensions.len() != 1
    {
        return Err(ProviderError::Correlation(
            "after confirmation response scope",
        ));
    }
    let _value = response
        .extensions
        .get(PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION)
        .ok_or(ProviderError::Correlation(
            "after confirmation receipt absent",
        ))?;
    receipt.validate_data()?;
    if &receipt.native_after_ref != after.0 || after.1.len() > maximum_after_bytes {
        return Err(ProviderError::ResourceExhausted(
            "after confirmation actual body credit",
        ));
    }
    after.0.verify(after.1)?;
    let shape = crate::bodies::decode_response_shape(&response.body)?;
    if !matches!(
        shape,
        ResponseShape::Completed {
            operation_state: OperationState::Completed,
            ..
        }
    ) {
        return Err(ProviderError::Correlation(
            "after confirmation Poll not completed",
        ));
    }
    let maximum_frame = usize::try_from(authority.limits().frame_bytes.get())
        .map_err(|_| ProviderError::ResourceExhausted("after confirmation frame bound"))?;
    if maximum_frame > 65_536 {
        return Err(ProviderError::ResourceExhausted(
            "after confirmation frame ceiling",
        ));
    }
    crate::connection::serialized_credit(response, maximum_frame)?;
    let chunk = usize::try_from(authority.limits().blob_chunk_bytes.get())
        .map_err(|_| ProviderError::ResourceExhausted("after confirmation chunk bound"))?
        .min(4096);
    let simultaneous = usize::try_from(authority.limits().requests.get())
        .map_err(|_| ProviderError::ResourceExhausted("after confirmation request bound"))?
        .min(MAXIMUM_CAPTURE_WINDOW_REQUESTS);
    if chunk == 0 || simultaneous == 0 {
        return Err(ProviderError::ResourceExhausted(
            "after confirmation positive bounds",
        ));
    }
    let count = after
        .1
        .len()
        .div_ceil(chunk)
        .checked_add(3)
        .filter(|n| *n <= 4096)
        .ok_or(ProviderError::ResourceExhausted(
            "after confirmation frame population",
        ))?;
    let next_sequence = response.sequence.get().checked_add(count as u64).ok_or(
        ProviderError::ResourceExhausted("after confirmation sequence"),
    )?;
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(count)
        .map_err(|_| ProviderError::ResourceExhausted("after confirmation original frame slots"))?;
    let mut charged_bytes = 0;
    let mut sequence = response.sequence.get();
    let transfer = Id::new(format!("packet-after-transfer-{sequence}"))?;
    let contents = BTreeMap::from([(transfer.clone(), after.0.clone())]);
    append_confirmation_request(
        &mut frames,
        &mut charged_bytes,
        maximum_frame,
        authority,
        response,
        &mut sequence,
        Method::BlobBegin,
        object(BlobBeginRequest {
            transfer_id: transfer.clone(),
            content: after.0.clone(),
            extensions: Extensions::new(),
        })?,
    )?;
    for (index, bytes) in after.1.chunks(chunk).enumerate() {
        append_confirmation_request(
            &mut frames,
            &mut charged_bytes,
            maximum_frame,
            authority,
            response,
            &mut sequence,
            Method::BlobChunk,
            object(BlobChunkRequest {
                transfer_id: transfer.clone(),
                offset: U64::new((index * chunk) as u64),
                bytes: Bytes::new(bytes.to_vec()),
                extensions: Extensions::new(),
            })?,
        )?;
    }
    append_confirmation_request(
        &mut frames,
        &mut charged_bytes,
        maximum_frame,
        authority,
        response,
        &mut sequence,
        Method::BlobFinish,
        object(BlobFinishRequest {
            transfer_id: transfer,
            extensions: Extensions::new(),
        })?,
    )?;
    let mut completion = response.clone();
    completion.sequence = U64::new(sequence);
    append(&mut frames, &mut charged_bytes, maximum_frame, completion)?;
    sequence += 1;
    if sequence != next_sequence {
        return Err(ProviderError::Conflict(
            "after confirmation exact sequence count",
        ));
    }
    let window_count = (count - 1).div_ceil(simultaneous) + 1;
    let mut windows = VecDeque::new();
    windows
        .try_reserve_exact(window_count)
        .map_err(|_| ProviderError::ResourceExhausted("capture window slots"))?;
    let mut window = Vec::new();
    window
        .try_reserve_exact(simultaneous + 1)
        .map_err(|_| ProviderError::ResourceExhausted("capture window frame slots"))?;
    let mut requests = 0usize;
    for frame in frames {
        // Keep the terminal response in its own original window. Its issuance
        // therefore witnesses completion of all actual preceding Blob replies.
        if frame.message == MessageKind::Response && !window.is_empty() {
            windows.push_back(window);
            window = Vec::new();
            window
                .try_reserve_exact(1)
                .map_err(|_| ProviderError::ResourceExhausted("capture terminal response slot"))?;
            requests = 0;
        }
        if frame.message == MessageKind::Request && requests == simultaneous {
            windows.push_back(window);
            window = Vec::new();
            window
                .try_reserve_exact(simultaneous)
                .map_err(|_| ProviderError::ResourceExhausted("capture window frame slots"))?;
            requests = 0;
        }
        requests += usize::from(frame.message == MessageKind::Request);
        window.push(frame);
    }
    if !window.is_empty() {
        windows.push_back(window);
    }
    Ok(CapturePlan {
        windows,
        contents,
        chunk: chunk as u64,
        charged_bytes,
        next_sequence,
    })
}

fn append(
    frames: &mut Vec<Envelope>,
    charge: &mut usize,
    maximum_frame: usize,
    frame: Envelope,
) -> Result<(), ProviderError> {
    let encoded = crate::connection::serialized_credit(&frame, maximum_frame)?;
    let replies = if frame.message == MessageKind::Request {
        maximum_frame * 2
    } else {
        0
    };
    *charge = encoded
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add(replies))
        .and_then(|bytes| charge.checked_add(bytes))
        .filter(|bytes| *bytes <= MAXIMUM_CAPTURE_TRANSPORT_BYTES)
        .ok_or(ProviderError::ResourceExhausted(
            "capture whole encoded transport credit",
        ))?;
    frames.push(frame);
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Couples one original frame to its same whole-prefix charge and sequence.
fn append_confirmation_request(
    frames: &mut Vec<Envelope>,
    charge: &mut usize,
    maximum_frame: usize,
    authority: &ConnectionAuthority,
    poll_response: &Envelope,
    sequence: &mut u64,
    method: Method,
    body: Map<String, Value>,
) -> Result<(), ProviderError> {
    let frame = Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(authority.session_id().clone())),
        incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
        node_id: poll_response.node_id.clone(),
        execution_owner_id: poll_response.execution_owner_id.clone(),
        capture_owner_id: poll_response.capture_owner_id.clone(),
        operation_id: poll_response.operation_id.clone(),
        request_id: Nullable(Some(Id::new(format!("packet-after-proof-{sequence}"))?)),
        sequence: U64::new(*sequence),
        method,
        body,
        extensions: Extensions::new(),
    };
    append(frames, charge, maximum_frame, frame)?;
    *sequence = sequence
        .checked_add(1)
        .ok_or(ProviderError::ResourceExhausted(
            "capture original sequence overflow",
        ))?;
    Ok(())
}

fn object(value: impl Serialize) -> Result<Map<String, Value>, ProviderError> {
    match serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)? {
        Value::Object(value) => Ok(value),
        _ => Err(ProviderError::Frame("capture frame body must be object")),
    }
}

/// Counts exact outgoing canonical extents before copying any after payload.
///
/// Empty Bytes encode as an empty URL-safe base64 string. Its exact unpadded
/// character growth therefore equals the actual chunk envelope growth; all
/// scope fields, IDs, offsets and sequences are constructed by the same planner.
pub(crate) fn outgoing_confirmation_extent(
    authority: &ConnectionAuthority,
    response: &Envelope,
    after: &ContentRef,
    length: usize,
) -> Result<usize, ProviderError> {
    let exhausted = || ProviderError::ResourceExhausted("confirmation exact outgoing extent");
    let maximum = usize::try_from(authority.limits().frame_bytes.get()).map_err(|_| exhausted())?;
    let chunk = usize::try_from(authority.limits().blob_chunk_bytes.get())
        .map_err(|_| exhausted())?
        .min(4096);
    if chunk == 0 {
        return Err(exhausted());
    }
    let mut sequence = response.sequence.get();
    let transfer = Id::new(format!("packet-after-transfer-{sequence}"))?;
    let mut total = 0usize;
    let mut count_frame = |method, body, payload: usize| -> Result<(), ProviderError> {
        let frame = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(authority.session_id().clone())),
            incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
            node_id: response.node_id.clone(),
            execution_owner_id: response.execution_owner_id.clone(),
            capture_owner_id: response.capture_owner_id.clone(),
            operation_id: response.operation_id.clone(),
            request_id: Nullable(Some(Id::new(format!("packet-after-proof-{sequence}"))?)),
            sequence: U64::new(sequence),
            method,
            body,
            extensions: Extensions::new(),
        };
        let encoded_payload = (payload / 3)
            .checked_mul(4)
            .and_then(|n| {
                n.checked_add(match payload % 3 {
                    0 => 0,
                    1 => 2,
                    _ => 3,
                })
            })
            .ok_or_else(exhausted)?;
        let encoded = crate::connection::serialized_credit(&frame, maximum)?
            .checked_add(encoded_payload)
            .filter(|n| *n <= maximum)
            .ok_or_else(exhausted)?;
        total = total
            .checked_add(encoded)
            .and_then(|n| n.checked_add(4))
            .ok_or_else(exhausted)?;
        sequence = sequence.checked_add(1).ok_or_else(exhausted)?;
        Ok(())
    };
    count_frame(
        Method::BlobBegin,
        object(BlobBeginRequest {
            transfer_id: transfer.clone(),
            content: after.clone(),
            extensions: Extensions::new(),
        })?,
        0,
    )?;
    for offset in (0..length).step_by(chunk) {
        count_frame(
            Method::BlobChunk,
            object(BlobChunkRequest {
                transfer_id: transfer.clone(),
                offset: U64::new(offset as u64),
                bytes: Bytes::new(Vec::new()),
                extensions: Extensions::new(),
            })?,
            (length - offset).min(chunk),
        )?;
    }
    count_frame(
        Method::BlobFinish,
        object(BlobFinishRequest {
            transfer_id: transfer,
            extensions: Extensions::new(),
        })?,
        0,
    )?;
    let mut completion = response.clone();
    completion.sequence = U64::new(sequence);
    total
        .checked_add(crate::connection::serialized_credit(&completion, maximum)?)
        .and_then(|n| n.checked_add(4))
        .ok_or_else(exhausted)
}
