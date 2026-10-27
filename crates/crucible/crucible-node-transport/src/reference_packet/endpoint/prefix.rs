//! Prebuilds exact full source reply/proof rows and their transfer acknowledgements.

use std::collections::BTreeMap;

use crucible_node_format::{Bytes, ContentRef, Extensions, Id, U64};
use serde::Serialize;
use serde_json::{Map, Value};

use super::{super::control::PacketControlReply, Transport};
use crate::{ProviderError, bodies::*, connection::*, envelope::*, handshake::ConnectionAuthority};

pub(super) struct Acknowledgements {
    contents: BTreeMap<Id, ContentRef>,
    chunk: u64,
    restored_input17: bool,
    restored_observation17: bool,
}

impl Acknowledgements {
    pub(super) fn validate(
        &self,
        original: &Envelope,
        received: &ReceivedFrame,
    ) -> Result<(), ProviderError> {
        if self.restored_input17 && self.restored_observation17 {
            return Err(ProviderError::Correlation(
                "two selected proof prefix classes",
            ));
        }
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
            (RequestBody::BlobChunk(request), Some(MethodResult::BlobChunk(result))) => {
                !(self.restored_input17 || self.restored_observation17)
                    || request.offset.get().checked_add(
                        u64::try_from(request.bytes.as_slice().len()).map_err(|_| {
                            ProviderError::ResourceExhausted("selected17 chunk ACK offset")
                        })?,
                    ) == Some(result.next_offset.get())
            }
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
    match serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)? {
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
            restored_input17: false,
            restored_observation17: false,
            capture17_upload: false,
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
            restored_input17: false,
            restored_observation17: false,
            capture17_upload: false,
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
    let actual =
        projection.authenticate_actual_inputs(connection, *next_sequence, request, reply)?;
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

/// Builds one selected Input17 terminal and its exact five-evidence suffix.
///
/// The action owner has already authenticated and funded its genuine native
/// occurrence. This wrapper independently reconciles actual owners and literal
/// capacity before installing the ordinary prepared failure-retaining capsule.
///
/// # Errors
/// Refuses another selected schema, current owner, five-role reply, actual
/// component/credit upper, literal cut or the ordinary unchanged frame limits.
pub(super) fn prepare_with_restored_input17_projection_storage_data<S: ProviderStream>(
    transport: &mut Option<Transport<S>>,
    next_sequence: &mut u64,
    retained_credit: &mut usize,
    authority: &ConnectionAuthority,
    request: &Envelope,
    reply: &PacketControlReply,
    projection: &OriginalPacketPrefixProjectionStorageData<5>,
) -> Result<(), ProviderError> {
    let Some(Transport::Connected(connection)) = transport.as_ref() else {
        return Err(ProviderError::Conflict("Input17 prefix connection absent"));
    };
    connection.authenticate_original_packet_prefix_builder_authority_data(authority)?;
    let actual =
        projection.authenticate_actual_inputs(connection, *next_sequence, request, reply)?;
    prepare_inner(
        transport,
        next_sequence,
        retained_credit,
        PrefixInput {
            authority,
            request,
            reply,
            storage: Some(&actual),
            restored_input17: true,
            restored_observation17: false,
            capture17_upload: false,
        },
    )
}

/// Builds the exact selected Observe17 terminal and two immutable proofs.
///
/// The defining native action has already spent its own source-authenticated
/// row. This builder reconciles the same actual reply, connection and literal
/// banks before installing the ordinary failure-retaining prepared capsule.
///
/// # Errors
/// Refuses another selected class/owner, wrong two-role reply, changed quote,
/// insufficient literal/transport capacity or any ordinary preparation failure.
pub(super) fn prepare_with_restored_observation17_projection_storage_data<S: ProviderStream>(
    transport: &mut Option<Transport<S>>,
    next_sequence: &mut u64,
    retained_credit: &mut usize,
    authority: &ConnectionAuthority,
    request: &Envelope,
    reply: &PacketControlReply,
    projection: &OriginalPacketPrefixProjectionStorageData<2>,
) -> Result<(), ProviderError> {
    let Some(Transport::Connected(connection)) = transport.as_ref() else {
        return Err(ProviderError::Conflict(
            "Observe17 prefix connection absent",
        ));
    };
    connection.authenticate_original_packet_prefix_builder_authority_data(authority)?;
    let actual =
        projection.authenticate_actual_inputs(connection, *next_sequence, request, reply)?;
    prepare_inner(
        transport,
        next_sequence,
        retained_credit,
        PrefixInput {
            authority,
            request,
            reply,
            storage: Some(&actual),
            restored_input17: false,
            restored_observation17: true,
            capture17_upload: false,
        },
    )
}

/// Prepares one actual completed Blob response without a proof-object suffix.
///
/// The defining native upload scope separately authenticates Source/current
/// custody, spends its independent row and supplies its real primitive result.
/// This builder verifies only the selected current transport and exact quote.
///
/// # Errors
/// Refuses another selected class, evidence, actual reply or finite bank/cut.
pub(super) fn prepare_with_capture17_upload_projection_storage_data<S: ProviderStream>(
    transport: &mut Option<Transport<S>>,
    next_sequence: &mut u64,
    retained_credit: &mut usize,
    authority: &ConnectionAuthority,
    request: &Envelope,
    reply: &PacketControlReply,
    projection: &OriginalPacketPrefixProjectionStorageData<0>,
) -> Result<(), ProviderError> {
    let Some(Transport::Connected(connection)) = transport.as_ref() else {
        return Err(ProviderError::Conflict(
            "Capture upload reply connection absent",
        ));
    };
    connection.authenticate_original_packet_prefix_builder_authority_data(authority)?;
    let actual =
        projection.authenticate_actual_inputs(connection, *next_sequence, request, reply)?;
    prepare_inner(
        transport,
        next_sequence,
        retained_credit,
        PrefixInput {
            authority,
            request,
            reply,
            storage: Some(&actual),
            restored_input17: false,
            restored_observation17: false,
            capture17_upload: true,
        },
    )
}

struct PrefixInput<'a> {
    authority: &'a ConnectionAuthority,
    request: &'a Envelope,
    reply: &'a PacketControlReply,
    storage: Option<&'a OriginalPacketPrefixStorageData>,
    restored_input17: bool,
    restored_observation17: bool,
    capture17_upload: bool,
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
        restored_input17,
        restored_observation17,
        capture17_upload,
    } = input;
    if let Some(storage) = storage {
        let Some(Transport::Connected(connection)) = transport.as_ref() else {
            return Err(ProviderError::Conflict(
                "packet prefix original unavailable before storage recheck",
            ));
        };
        connection.authenticate_original_packet_prefix_builder_authority_data(authority)?;
        if capture17_upload {
            if restored_input17 || restored_observation17 {
                return Err(ProviderError::Correlation(
                    "two selected reply prefix classes",
                ));
            }
            connection.authenticate_requoted_original_capture17_upload_prefix_storage_data(
                *next_sequence,
                request,
                &reply.body,
                &reply.evidence,
                storage,
            )?;
        } else if restored_observation17 {
            if restored_input17 {
                return Err(ProviderError::Correlation(
                    "two selected proof prefix classes",
                ));
            }
            connection.authenticate_requoted_original_restored_observation17_prefix_storage_data(
                *next_sequence,
                request,
                &reply.body,
                &reply.evidence,
                storage,
            )?;
        } else if restored_input17 {
            connection.authenticate_requoted_original_restored_input17_prefix_storage_data(
                *next_sequence,
                request,
                &reply.body,
                &reply.evidence,
                storage,
            )?;
        } else {
            connection.authenticate_requoted_original_packet_prefix_storage_data(
                *next_sequence,
                request,
                &reply.body,
                &reply.evidence,
                storage,
            )?;
        }
        storage.preflight_transport_credit_data(*retained_credit)?;
    }
    let (frames, mut acknowledgements, next) = frames(*next_sequence, authority, request, reply)?;
    acknowledgements.restored_input17 = restored_input17;
    acknowledgements.restored_observation17 = restored_observation17;
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
            restored_input17: false,
            restored_observation17: false,
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
            crucible_node_format::canonical::content_ref(&bytes, "application/json").unwrap();
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

#[cfg(test)]
mod input17_transport_tests {
    use super::*;
    use crucible_node_format::canonical;

    #[test]
    fn five_bank_terminal_prefix_requires_every_exact_chunk_offset_ack() {
        let (_, authority) =
            crate::handshake::tests::authority_with_scope("input17-five-bank-prefix");
        let mut original = crate::envelope::tests::request();
        original.method = Method::Input;
        original.session_id = Nullable(Some(authority.session_id().clone()));
        original.incarnation_id = Nullable(Some(authority.incarnation_id().clone()));
        original.extensions.clear();
        original.body = object(InputRequest {
            binding_hash: canonical::hash("cnp.owner-binding.v1", b"transport-test").unwrap(),
            owner_generation: U64::new(1),
            batch_id: Id::new("transport-test-batch").unwrap(),
            batch_sequence: U64::new(1),
            input_epoch: Id::new("transport-test-epoch").unwrap(),
            events: Vec::new(),
            batch_hash: canonical::hash("cnp.input-batch.v1", b"transport-test").unwrap(),
            extensions: Extensions::new(),
        })
        .unwrap();
        // This exercises the ordinary builder/ACK machinery using transport
        // test banks. It supplies no new17 selected Source or native grant.
        let evidence = (0..5)
            .map(|role| {
                let bytes =
                    canonical::canonical_json(&serde_json::json!({"transport_role":role})).unwrap();
                (
                    canonical::content_ref(&bytes, "application/json").unwrap(),
                    bytes,
                )
            })
            .collect::<Vec<_>>();
        let reply = PacketControlReply {
            body: completed(InputResult {
                accepted_event_ids: Vec::new(),
                input_watermark: U64::new(1),
                custody_receipt: evidence[2].0.clone(),
                inventory_hash: evidence[0].0.hash.clone(),
            })
            .unwrap(),
            evidence,
        };
        let (planned, mut acknowledgements, next) =
            frames(10, &authority, &original, &reply).unwrap();
        acknowledgements.restored_input17 = true;
        assert_eq!(planned.len(), 16);
        assert_eq!(next, 26);
        assert_eq!(planned[0].message, MessageKind::Response);
        let mut accepted = 0;
        let mut checked_changed_chunk = false;
        for sent in &planned[1..] {
            let request = decode_request(sent.method, &sent.body).unwrap();
            let result = match &request {
                RequestBody::BlobBegin(request) => object(BlobBeginResult {
                    transfer_id: request.transfer_id.clone(),
                    next_offset: U64::new(0),
                    maximum_chunk_bytes: U64::new(acknowledgements.chunk),
                })
                .unwrap(),
                RequestBody::BlobChunk(request) => object(BlobChunkResult {
                    transfer_id: request.transfer_id.clone(),
                    next_offset: U64::new(
                        request.offset.get() + request.bytes.as_slice().len() as u64,
                    ),
                })
                .unwrap(),
                RequestBody::BlobFinish(request) => object(BlobFinishResult {
                    transfer_id: request.transfer_id.clone(),
                    content: acknowledgements.contents[&request.transfer_id].clone(),
                })
                .unwrap(),
                _ => panic!("unexpected transport request"),
            };
            let body = completed(result).unwrap();
            let mut envelope = sent.clone();
            envelope.message = MessageKind::Response;
            envelope.body = body.clone();
            let mut received = ReceivedFrame {
                envelope,
                body: ReceivedBody::Response(Box::new(decode_response(&request, &body).unwrap())),
            };
            acknowledgements.validate(sent, &received).unwrap();
            accepted += 1;
            if !checked_changed_chunk && sent.method == Method::BlobChunk {
                let ReceivedBody::Response(response) = &mut received.body else {
                    unreachable!()
                };
                let Some(MethodResult::BlobChunk(result)) = &mut response.result else {
                    unreachable!()
                };
                result.next_offset = U64::new(result.next_offset.get() + 1);
                assert!(acknowledgements.validate(sent, &received).is_err());
                checked_changed_chunk = true;
            }
        }
        assert_eq!(accepted, 15);
        assert!(checked_changed_chunk);
    }

    #[test]
    fn two_actual_observe17_proofs_require_every_exact_ack_and_one_class() {
        let (_, authority) =
            crate::handshake::tests::authority_with_scope("observe17-two-proof-acks");
        let mut original = crate::envelope::tests::request();
        original.method = Method::Observe;
        original.session_id = Nullable(Some(authority.session_id().clone()));
        original.incarnation_id = Nullable(Some(authority.incarnation_id().clone()));
        let evidence = ["model", "restored"]
            .into_iter()
            .map(|role| {
                let bytes = crucible_node_format::canonical::canonical_json(
                    &serde_json::json!({"transport_test_role":role}),
                )
                .unwrap();
                (
                    crucible_node_format::canonical::content_ref(&bytes, "application/json")
                        .unwrap(),
                    bytes,
                )
            })
            .collect::<Vec<_>>();
        let reply = PacketControlReply {
            body: completed(serde_json::json!({"transport_data_only":true})).unwrap(),
            evidence,
        };
        // This is the actual ordinary frame/ACK producer, with DATA-only proof
        // banks. Native/Source action permission remains a separate prerequisite.
        let (planned, mut acknowledgements, next) =
            frames(10, &authority, &original, &reply).unwrap();
        acknowledgements.restored_observation17 = true;
        assert_eq!(planned.len(), 7);
        assert_eq!(next, 17);
        let mut checked = 0;
        for sent in &planned[1..] {
            let request = decode_request(sent.method, &sent.body).unwrap();
            let result = match &request {
                RequestBody::BlobBegin(request) => object(BlobBeginResult {
                    transfer_id: request.transfer_id.clone(),
                    next_offset: U64::new(0),
                    maximum_chunk_bytes: U64::new(acknowledgements.chunk),
                })
                .unwrap(),
                RequestBody::BlobChunk(request) => object(BlobChunkResult {
                    transfer_id: request.transfer_id.clone(),
                    next_offset: U64::new(
                        request.offset.get() + request.bytes.as_slice().len() as u64,
                    ),
                })
                .unwrap(),
                RequestBody::BlobFinish(request) => object(BlobFinishResult {
                    transfer_id: request.transfer_id.clone(),
                    content: acknowledgements.contents[&request.transfer_id].clone(),
                })
                .unwrap(),
                _ => panic!("unexpected proof request"),
            };
            let body = completed(result).unwrap();
            let mut envelope = sent.clone();
            envelope.message = MessageKind::Response;
            envelope.body = body.clone();
            let mut received = ReceivedFrame {
                envelope,
                body: ReceivedBody::Response(Box::new(decode_response(&request, &body).unwrap())),
            };
            acknowledgements.validate(sent, &received).unwrap();
            acknowledgements.restored_input17 = true;
            assert!(acknowledgements.validate(sent, &received).is_err());
            acknowledgements.restored_input17 = false;
            if let ReceivedBody::Response(body) = &mut received.body
                && let Some(MethodResult::BlobChunk(result)) = &mut body.result
            {
                result.next_offset = U64::new(result.next_offset.get() + 1);
                assert!(acknowledgements.validate(sent, &received).is_err());
            }
            checked += 1;
        }
        assert_eq!(checked, 6);
    }
}

/// Names the actual selected upload response builder's ephemeral fixed views.
///
/// The zero-evidence class adds no field to retained ACK or wire state.
pub(crate) const fn native_capture17_upload_prefix_counter_scratch_data() -> usize {
    std::mem::size_of::<PrefixInput<'static>>()
        + std::mem::size_of::<&OriginalPacketPrefixProjectionStorageData<0>>()
        + std::mem::size_of::<OriginalPacketPrefixStorageData>()
        + std::mem::size_of::<Result<OriginalPacketPrefixStorageData, ProviderError>>()
        + std::mem::size_of::<Result<(), ProviderError>>()
}
