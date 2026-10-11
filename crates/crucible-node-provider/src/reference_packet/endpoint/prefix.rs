//! Prebuilds exact full source reply/proof rows and their transfer acknowledgements.

use std::collections::BTreeMap;

use crucible_node_contract::{Bytes, ContentRef, Extensions, Id, U64};
use serde::Serialize;
use serde_json::{Map, Value};

use super::{super::control::PacketControlReply, Transport};
use crate::{ProviderError, bodies::*, connection::*, envelope::*, handshake::ConnectionAuthority};

pub(super) struct Acknowledgements {
    contents: BTreeMap<Id, ContentRef>,
    chunk: u64,
}

impl Acknowledgements {
    pub(super) fn validate(
        &self,
        original: &Envelope,
        received: &ReceivedFrame,
    ) -> Result<(), ProviderError> {
        let ReceivedBody::Response(response) = &received.body else {
            return Err(ProviderError::Correlation("packet proof requires response"));
        };
        if !matches!(response.shape, ResponseShape::Completed { .. }) {
            return Err(ProviderError::Correlation(
                "packet original proof not completed",
            ));
        }
        let agrees = match (
            decode_request(original.method, &original.body)?,
            &response.result,
        ) {
            (RequestBody::BlobBegin(request), Some(MethodResult::BlobBegin(result))) => {
                result.next_offset == U64::new(0)
                    && result.maximum_chunk_bytes.get()
                        >= self.chunk.min(request.content.length.get())
            }
            (RequestBody::BlobChunk(_), Some(MethodResult::BlobChunk(_))) => true,
            (RequestBody::BlobFinish(request), Some(MethodResult::BlobFinish(result))) => {
                self.contents.get(&request.transfer_id) == Some(&result.content)
            }
            _ => false,
        };
        if !agrees {
            return Err(ProviderError::Correlation(
                "packet original proof acknowledgement changed",
            ));
        }
        Ok(())
    }
}

pub(super) fn completed(result: impl Serialize) -> Result<Map<String, Value>, ProviderError> {
    object(ResponseShape::Completed {
        operation_state: OperationState::Completed,
        result: object(result)?,
        extensions: Extensions::new(),
    })
}

fn object(value: impl Serialize) -> Result<Map<String, Value>, ProviderError> {
    match serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)? {
        Value::Object(value) => Ok(value),
        _ => Err(ProviderError::Frame("packet source body must be object")),
    }
}

pub(super) fn prepare<S: ProviderStream>(
    transport: &mut Option<Transport<S>>,
    next_sequence: &mut u64,
    retained_credit: &mut usize,
    authority: &ConnectionAuthority,
    request: &Envelope,
    reply: &PacketControlReply,
) -> Result<(), ProviderError> {
    let (frames, acknowledgements, next) = frames(*next_sequence, authority, request, reply)?;
    // Retain complete outgoing envelopes/canonical/correlation copies plus the
    // worst negotiated incoming acknowledgement extents for this whole prefix.
    // This encoded-storage account is separate from native content/pin credit;
    // remote parsing still obeys its own finite array/depth/allocator limits.
    let mut outgoing = 0usize;
    for frame in &frames {
        outgoing = outgoing
            .checked_add(crate::connection::serialized_credit(frame, 65_536)?)
            .ok_or(ProviderError::ResourceExhausted(
                "packet whole transport credit",
            ))?;
    }
    let maximum_frame = usize::try_from(authority.limits().frame_bytes.get())
        .map_err(|_| ProviderError::ResourceExhausted("packet acknowledgement ceiling"))?;
    let charge = frames
        .len()
        .saturating_sub(1)
        .checked_mul(maximum_frame)
        .and_then(|acks| acks.checked_mul(2))
        .and_then(|acks| {
            outgoing
                .checked_mul(3)
                .and_then(|sent| sent.checked_add(acks))
        })
        .and_then(|new| retained_credit.checked_add(new))
        .filter(|total| *total <= 32 * 1024 * 1024)
        .ok_or(ProviderError::ResourceExhausted(
            "packet whole transport credit",
        ))?;
    let Some(Transport::Connected(connection)) = transport.take() else {
        return Err(ProviderError::Conflict(
            "packet source connection already reserved",
        ));
    };
    // Install the entire original capsule before trusted schema or supervision
    // callbacks. Unwind cannot remove it from the surrounding native owner.
    *transport = Some(Transport::Prepared(
        connection.unprepared_exchange(frames),
        acknowledgements,
    ));
    *retained_credit = charge;
    let Some(Transport::Prepared(exchange, _)) = transport.as_mut() else {
        return Err(ProviderError::Conflict(
            "packet original preparation disappeared",
        ));
    };
    exchange.prepare_in_place()?;
    *next_sequence = next;
    Ok(())
}

fn frames(
    first: u64,
    authority: &ConnectionAuthority,
    request: &Envelope,
    reply: &PacketControlReply,
) -> Result<(Vec<Envelope>, Acknowledgements, u64), ProviderError> {
    let chunk = usize::try_from(authority.limits().blob_chunk_bytes.get())
        .map_err(|_| ProviderError::ResourceExhausted("packet source chunk allowance"))?
        .min(4096);
    if chunk == 0 || reply.evidence.len() > 256 {
        return Err(ProviderError::ResourceExhausted("packet proof population"));
    }
    crate::connection::serialized_credit(&reply.body, 65_536)?;
    let mut count = 1usize;
    let mut bytes = 0usize;
    for (root, body) in &reply.evidence {
        if body.len() > 65_536 {
            return Err(ProviderError::ResourceExhausted("packet proof body"));
        }
        root.verify(body)?;
        bytes = bytes
            .checked_add(body.len())
            .filter(|n| *n <= 4 * 1024 * 1024)
            .ok_or(ProviderError::ResourceExhausted("packet proof whole bytes"))?;
        count = count.checked_add(2 + body.len().div_ceil(chunk)).ok_or(
            ProviderError::ResourceExhausted("packet proof frame population"),
        )?;
    }
    let requests = usize::try_from(authority.limits().requests.get())
        .map_err(|_| ProviderError::ResourceExhausted("packet proof request allowance"))?;
    if count > requests.saturating_add(1) {
        return Err(ProviderError::ResourceExhausted(
            "packet proof simultaneous correlations",
        ));
    }
    let count_u64 = u64::try_from(count)
        .map_err(|_| ProviderError::ResourceExhausted("packet proof sequence population"))?;
    let next = first
        .checked_add(count_u64)
        .ok_or(ProviderError::ResourceExhausted(
            "packet proof sequence overflow",
        ))?;
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(count)
        .map_err(|_| ProviderError::ResourceExhausted("packet proof frame slots"))?;
    let mut response = request.clone();
    response.message = MessageKind::Response;
    response.sequence = U64::new(first);
    response.body = reply.body.clone();
    frames.push(response);
    let mut sequence = first + 1;
    let mut contents = BTreeMap::new();
    for (root, body) in &reply.evidence {
        let transfer = Id::new(format!("packet-transfer-{sequence}"))?;
        contents.insert(transfer.clone(), root.clone());
        push(
            &mut frames,
            authority,
            &mut sequence,
            Method::BlobBegin,
            object(BlobBeginRequest {
                transfer_id: transfer.clone(),
                content: root.clone(),
                extensions: Extensions::new(),
            })?,
        )?;
        for (index, payload) in body.chunks(chunk).enumerate() {
            let offset = u64::try_from(index * chunk)
                .map_err(|_| ProviderError::ResourceExhausted("packet proof chunk offset"))?;
            push(
                &mut frames,
                authority,
                &mut sequence,
                Method::BlobChunk,
                object(BlobChunkRequest {
                    transfer_id: transfer.clone(),
                    offset: U64::new(offset),
                    bytes: Bytes::new(payload.to_vec()),
                    extensions: Extensions::new(),
                })?,
            )?;
        }
        push(
            &mut frames,
            authority,
            &mut sequence,
            Method::BlobFinish,
            object(BlobFinishRequest {
                transfer_id: transfer,
                extensions: Extensions::new(),
            })?,
        )?;
    }
    Ok((
        frames,
        Acknowledgements {
            contents,
            chunk: chunk as u64,
        },
        next,
    ))
}

fn push(
    frames: &mut Vec<Envelope>,
    authority: &ConnectionAuthority,
    sequence: &mut u64,
    method: Method,
    body: Map<String, Value>,
) -> Result<(), ProviderError> {
    let request = Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(authority.session_id().clone())),
        incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(None),
        request_id: Nullable(Some(Id::new(format!("packet-proof-{sequence}"))?)),
        sequence: U64::new(*sequence),
        method,
        body,
        extensions: Extensions::new(),
    };
    *sequence = sequence
        .checked_add(1)
        .ok_or(ProviderError::ResourceExhausted(
            "packet proof sequence overflow",
        ))?;
    frames.push(request);
    Ok(())
}
