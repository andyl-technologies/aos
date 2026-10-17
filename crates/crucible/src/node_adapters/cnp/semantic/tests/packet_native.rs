//! Actual finite packet process preparation under its closed nonexecuting gate.

#![cfg(test)]

use super::*;

fn completed(value: impl Serialize) -> Map<String, Value> {
    object(ResponseShape::Completed {
        operation_state: OperationState::Completed,
        result: object(value),
        extensions: Extensions::new(),
    })
}

pub(super) fn serve(socket: &std::path::Path, bootstrap: Bootstrap) {
    let listener = UnixListener::bind(socket).unwrap();
    println!("GENERIC_PACKET_BOUND");
    std::io::stdout().flush().unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = FrameReader::new(stream.try_clone().unwrap(), FRAME).unwrap();
    let hello: Envelope = serde_json::from_value(reader.read().unwrap().unwrap()).unwrap();
    let RequestBody::Hello(request) = decode_request(hello.method, &hello.body).unwrap() else {
        panic!("not Hello")
    };
    assert_eq!(request.admission_token.as_slice(), &[7; 32]);
    let result = HelloResult {
        version: "CNP/1".into(),
        session_id: id("packet-session"),
        incarnation_id: id("packet-incarnation"),
        controller_nonce: request.controller_nonce,
        provider_nonce: Bytes::new(vec![5; 32]),
        selected_features: bootstrap.features(),
        limits: bootstrap.limits(),
        resume_token: Nullable(None),
        provider_identity: bootstrap.manifest.clone(),
        resumed_operations: vec![],
    };
    let mut sequence = 1;
    respond(&mut stream, &hello, completed(result), &mut sequence);
    let mut originals = BTreeMap::<Id, (HashRef, Map<String, Value>)>::new();
    let mut operation = None;
    let mut effects = 0u64;
    while let Some(value) = reader.read().unwrap() {
        let request: Envelope = serde_json::from_value(value).unwrap();
        request.validate().unwrap();
        let request_id = request.request_id.0.as_ref().unwrap();
        let hash = request.request_hash(RequestOrigin::Controller).unwrap();
        if let Some((original, body)) = originals.get(request_id) {
            assert_eq!(&hash, original);
            respond(&mut stream, &request, body.clone(), &mut sequence);
            continue;
        }
        assert!(
            originals.len() < 64,
            "finite native request custody reserved before callback"
        );
        assert!(bytes(&request).len() <= FRAME);
        let (body, receipt) = match decode_request(request.method, &request.body).unwrap() {
            RequestBody::Discover(_) => (
                completed(DiscoverResult {
                    provider_manifest: bootstrap.manifest.clone(),
                    profiles: bootstrap.manifest.supported_profiles.clone(),
                    facet_schemas: bootstrap.manifest.implementation.formats.clone(),
                    complete: true,
                    next_cursor: Nullable(None),
                }),
                None,
            ),
            RequestBody::Realize(realize) => {
                assert_eq!(realize.realization_id, bootstrap.realization.realization_id);
                assert_eq!(realize.requested_node_ids, vec![id("packet")]);
                assert!(operation.is_none());
                let receipt = bytes(json!({
                    "schema":"source-owned.packet-closed-gate.v1",
                    "original_pid":std::process::id(),
                    "model":reference(bootstrap.definition.as_slice()),
                    "realization":bootstrap.realization.realization_id,
                    "native_callbacks":"0", "gate_closed":true,
                    "input_inventory":[], "output_inventory":[],
                    "pending_timers":[{"publication_ps":"5","microstep":"1","remaining":"1"}]
                }));
                let root = reference(&receipt);
                (
                    completed(RealizeResult {
                        realization_manifest: bootstrap.realization.clone(),
                        prepared_token: id("packet-original-prepared-token"),
                        closed_gate_receipt: root.clone(),
                    }),
                    Some((root, receipt)),
                )
            }
            RequestBody::Begin(begin) => {
                assert!(operation.is_none());
                assert_eq!(begin, bootstrap.begin());
                // Register complete original before creating the one packet effect.
                operation = Some(request.operation_id.0.clone().unwrap());
                effects += 1;
                (
                    object(ResponseShape::Accepted {
                        operation_state: OperationState::Running,
                        result: object(BeginAccepted {
                            operation_id: operation.clone().unwrap(),
                            kind: BeginKind::ExactRun,
                        }),
                        extensions: Extensions::new(),
                    }),
                    None,
                )
            }
            RequestBody::Poll(_) => {
                assert_eq!(request.operation_id.0, operation);
                let receipt = bytes(PacketReceipt {
                    schema: "packet-relay-native/1".into(),
                    operation: operation.clone().unwrap(),
                    port: id("wire_tx"),
                    payload: Bytes::new(b"actual\0packet\xff".to_vec()),
                    position: Position::new(Tick::new(5), U64::new(1), Phase::Publication),
                    native_effects: U64::new(effects),
                });
                assert!(
                    receipt.len() <= 4096,
                    "complete native response credit precedes copy/send"
                );
                let root = reference(&receipt);
                let outcome = completed(ExactRunResult {
                    grant_id: operation.clone().unwrap(),
                    reached: bootstrap.limit,
                    stop_reason: crucible_node_provider::bodies::StopReason::Ceiling,
                    stop_receipt: root.clone(),
                    observation_batch: root.clone(),
                    pending_inventory: root.clone(),
                    next_attention: Bound {
                        kind: BoundKind::Unknown,
                        position: None,
                        evidence: None,
                    },
                });
                (
                    completed(PollResult {
                        operation_id: operation.clone().unwrap(),
                        operation_state: OperationState::Completed,
                        outcome: Nullable(Some(outcome)),
                        observations: vec![],
                        next_observation_sequence: U64::new(1),
                    }),
                    Some((root, receipt)),
                )
            }
            _ => panic!("unsupported packet fixture method"),
        };
        originals.insert(request_id.clone(), (hash, body.clone()));
        respond(&mut stream, &request, body, &mut sequence);
        if let Some((reference, receipt)) = receipt {
            transfer(
                &mut stream,
                &mut reader,
                &reference,
                &receipt,
                &mut sequence,
            );
        }
    }
}

fn respond(
    stream: &mut UnixStream,
    request: &Envelope,
    body: Map<String, Value>,
    sequence: &mut u64,
) {
    let mut response = request.clone();
    response.message = MessageKind::Response;
    response.incarnation_id = Nullable(Some(id("packet-incarnation")));
    response.sequence = U64::new(*sequence);
    *sequence += 1;
    response.body = body;
    write_frame(stream, &serde_json::to_value(response).unwrap(), FRAME).unwrap();
}

fn transfer(
    stream: &mut UnixStream,
    reader: &mut FrameReader<UnixStream>,
    reference: &ContentRef,
    bytes: &[u8],
    sequence: &mut u64,
) {
    let transfer = id(&format!("native-proof-{}", reference.hash.digest));
    for (index, method, body) in [
        (
            0,
            Method::BlobBegin,
            object(BlobBeginRequest {
                transfer_id: transfer.clone(),
                content: reference.clone(),
                extensions: Extensions::new(),
            }),
        ),
        (
            1,
            Method::BlobChunk,
            object(BlobChunkRequest {
                transfer_id: transfer.clone(),
                offset: U64::new(0),
                bytes: Bytes::new(bytes.to_vec()),
                extensions: Extensions::new(),
            }),
        ),
        (
            2,
            Method::BlobFinish,
            object(BlobFinishRequest {
                transfer_id: transfer,
                extensions: Extensions::new(),
            }),
        ),
    ] {
        let request = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(id("packet-session"))),
            incarnation_id: Nullable(Some(id("packet-incarnation"))),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            operation_id: Nullable(None),
            request_id: Nullable(Some(id(&format!("native-proof-{index}")))),
            sequence: U64::new(*sequence),
            method,
            body,
            extensions: Extensions::new(),
        };
        *sequence += 1;
        write_frame(stream, &serde_json::to_value(&request).unwrap(), FRAME).unwrap();
        let response: Envelope = serde_json::from_value(reader.read().unwrap().unwrap()).unwrap();
        request.matches_response(&response).unwrap();
        assert!(matches!(
            decode_response(
                &decode_request(method, &request.body).unwrap(),
                &response.body
            )
            .unwrap()
            .shape,
            ResponseShape::Completed { .. }
        ));
    }
}
