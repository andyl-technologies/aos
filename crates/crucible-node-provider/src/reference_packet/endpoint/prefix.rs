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
    prepare_inner(
        transport,
        next_sequence,
        retained_credit,
        PrefixInput {
            authority,
            request,
            reply,
            storage: None,
        },
    )
}

/// Uses the checked native producer's prospective storage data before building.
///
/// The caller conjoins the data with its real simultaneous allocation allowance
/// first. This function reconciles actual initialized capacities; it grants no
/// allowance and retains the old transport and raw-frame limits.
pub(super) fn prepare_with_storage_data<S: ProviderStream>(
    transport: &mut Option<Transport<S>>,
    next_sequence: &mut u64,
    retained_credit: &mut usize,
    authority: &ConnectionAuthority,
    request: &Envelope,
    reply: &PacketControlReply,
    storage: &OriginalPacketPrefixStorageData,
) -> Result<(), ProviderError> {
    prepare_inner(
        transport,
        next_sequence,
        retained_credit,
        PrefixInput {
            authority,
            request,
            reply,
            storage: Some(storage),
        },
    )
}

/// Recounts an actual reply under a preconstruction upper before any frames.
pub(super) fn prepare_with_projection_storage_data<S: ProviderStream>(
    transport: &mut Option<Transport<S>>,
    next_sequence: &mut u64,
    retained_credit: &mut usize,
    authority: &ConnectionAuthority,
    request: &Envelope,
    reply: &PacketControlReply,
    projection: &OriginalPacketPrefixProjectionStorageData,
) -> Result<(), ProviderError> {
    let Some(Transport::Connected(connection)) = transport.as_ref() else {
        return Err(ProviderError::Conflict(
            "packet prospective prefix original connection absent",
        ));
    };
    connection.authenticate_original_packet_prefix_builder_authority_data(authority)?;
    let actual = projection.authenticate_actual_inputs(
        connection,
        *next_sequence,
        request,
        &reply.body,
        &reply.evidence,
    )?;
    // Existing242 independently requotes these exact actual inputs again before
    // frames. The prospective upper itself is never passed as an exact quote.
    prepare_with_storage_data(
        transport,
        next_sequence,
        retained_credit,
        authority,
        request,
        reply,
        &actual,
    )
}

struct PrefixInput<'a> {
    authority: &'a ConnectionAuthority,
    request: &'a Envelope,
    reply: &'a PacketControlReply,
    storage: Option<&'a OriginalPacketPrefixStorageData>,
}

fn prepare_inner<S: ProviderStream>(
    transport: &mut Option<Transport<S>>,
    next_sequence: &mut u64,
    retained_credit: &mut usize,
    input: PrefixInput<'_>,
) -> Result<(), ProviderError> {
    let PrefixInput {
        authority,
        request,
        reply,
        storage,
    } = input;
    if let Some(storage) = storage {
        let Some(Transport::Connected(connection)) = transport.as_ref() else {
            return Err(ProviderError::Conflict(
                "packet prefix original unavailable before storage recheck",
            ));
        };
        connection.authenticate_original_packet_prefix_builder_authority_data(authority)?;
        connection.authenticate_requoted_original_packet_prefix_storage_data(
            *next_sequence,
            request,
            &reply.body,
            &reply.evidence,
            storage,
        )?;
        storage.preflight_transport_credit_data(*retained_credit)?;
    }
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
        .filter(|total| *total <= super::MAXIMUM_PACKET_TRANSPORT_BYTES)
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
    let Some(Transport::Prepared(exchange, acknowledgements)) = transport.as_mut() else {
        return Err(ProviderError::Conflict(
            "packet original preparation disappeared",
        ));
    };
    if let Some(storage) = storage {
        storage.reconcile_acknowledgement_index_data(&acknowledgements.contents)?;
        exchange.reconcile_original_packet_prefix_storage_data(storage)?;
    }
    exchange.prepare_in_place()?;
    if let Some(storage) = storage {
        storage.reconcile_acknowledgement_index_data(&acknowledgements.contents)?;
        exchange.reconcile_original_packet_prefix_storage_data(storage)?;
    }
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
    // Input4 contexts select requests and must not be echoed into replies.
    response.extensions = Extensions::new();
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

#[cfg(test)]
mod restored_response_tests {
    use super::*;
    use crate::connection::original_restored_response_data;

    #[test]
    fn real_evidence_prefix_finds_response_before_blob_suffix_and_refuses_duplicates() {
        let (_, short_authority) = crate::handshake::tests::authority();
        let mut original = crate::envelope::tests::request();
        original.method = Method::Observe;
        original.extensions.clear();
        original.session_id = Nullable(Some(short_authority.session_id().clone()));
        original.incarnation_id = Nullable(Some(short_authority.incarnation_id().clone()));
        let bytes = br#"{"model":"evidence fixture"}"#.to_vec();
        let root =
            crucible_node_contract::canonical::content_ref(&bytes, "application/json").unwrap();
        let reply = PacketControlReply {
            body: completed(serde_json::json!({"data_only": true})).unwrap(),
            evidence: vec![(root, bytes)],
        };
        // The small general fixture negotiates two requests. A nonempty proof
        // needs Begin, Chunk and Finish, so its unchanged limit must refuse.
        assert!(matches!(
            frames(10, &short_authority, &original, &reply),
            Err(ProviderError::ResourceExhausted(
                "packet proof simultaneous correlations"
            ))
        ));

        // Use the existing real negotiation fixture with sixteen requests and
        // bind the original to that same authority. Production limits stay intact.
        let (_, authority) =
            crate::handshake::tests::authority_with_scope("restored-response-prefix");
        original.session_id = Nullable(Some(authority.session_id().clone()));
        original.incarnation_id = Nullable(Some(authority.incarnation_id().clone()));
        let (mut prefix, _, _) = frames(10, &authority, &original, &reply).unwrap();
        assert_eq!(prefix.first().unwrap().message, MessageKind::Response);
        assert_eq!(prefix.last().unwrap().method, Method::BlobFinish);
        let (index, terminal) = original_restored_response_data(&original, &prefix).unwrap();
        assert_eq!(index, 0);
        assert_eq!(terminal, &prefix[0]);
        let saved = terminal.clone();
        prefix.push(saved);
        assert!(original_restored_response_data(&original, &prefix).is_err());
        prefix.pop();
        prefix[0].method = Method::Poll;
        assert!(original_restored_response_data(&original, &prefix).is_err());
        prefix.remove(0);
        assert!(original_restored_response_data(&original, &prefix).is_err());
    }
}
