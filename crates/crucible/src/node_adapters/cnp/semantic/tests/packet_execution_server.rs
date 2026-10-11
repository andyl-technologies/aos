//! Actual closed source endpoint carrying complete native proofs over CNP blobs.

#![cfg(test)]

use super::*;

fn completed(result: impl Serialize) -> Map<String, Value> {
    object(ResponseShape::Completed {
        operation_state: OperationState::Completed,
        result: object(result),
        extensions: Extensions::new(),
    })
}

pub(super) fn serve(socket: &std::path::Path, bootstrap: NativeBootstrap) {
    if bootstrap.owning_endpoint {
        super::owning_endpoint::serve(socket, bootstrap);
        return;
    }
    let listener = UnixListener::bind(socket).unwrap();
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
    let mut sequence = 1;
    respond(
        &mut stream,
        &hello,
        completed(HelloResult {
            version: "CNP/1".into(),
            session_id: id("packet-session"),
            incarnation_id: id("packet-incarnation"),
            controller_nonce: request.controller_nonce,
            provider_nonce: Bytes::new(vec![5; 32]),
            selected_features: bootstrap.protocol.features(),
            limits: bootstrap.protocol.limits(),
            resume_token: Nullable(None),
            provider_identity: bootstrap.protocol.manifest.clone(),
            resumed_operations: vec![],
        }),
        &mut sequence,
    );
    let native_socket = UnixDatagram::unbound().unwrap();
    native_socket.connect(&bootstrap.effects).unwrap();
    let program = PacketProgram::new(bootstrap.events, native_socket).unwrap();
    let mut control = if bootstrap.immediate {
        PacketControl::new_immediate(bootstrap.selection, program).unwrap()
    } else {
        PacketControl::new(bootstrap.selection, program).unwrap()
    };
    let mut uploads = BTreeMap::<Id, (ContentRef, Vec<u8>)>::new();
    let mut blob_originals = BTreeMap::<Id, (HashRef, Map<String, Value>)>::new();
    let mut sent = std::collections::BTreeSet::<ContentRef>::new();
    let mut reserved_upload_bytes = 0usize;
    while let Some(value) = reader.read().unwrap() {
        let request: Envelope = serde_json::from_value(value).unwrap();
        request.validate().unwrap();
        let request_id = request.request_id.0.as_ref().unwrap();
        let identity = request.request_hash(RequestOrigin::Controller).unwrap();
        if let Some((original, response)) = blob_originals.get(request_id) {
            assert_eq!(original, &identity);
            respond(&mut stream, &request, response.clone(), &mut sequence);
            continue;
        }
        let blob = match decode_request(request.method, &request.body).unwrap() {
            RequestBody::BlobBegin(begin) => {
                assert!(uploads.len() < 128);
                let bytes = usize::try_from(begin.content.length.get()).unwrap();
                assert!(bytes <= FRAME);
                reserved_upload_bytes = reserved_upload_bytes.checked_add(bytes).unwrap();
                assert!(reserved_upload_bytes <= 4 * 1024 * 1024);
                assert!(
                    uploads
                        .insert(
                            begin.transfer_id.clone(),
                            (begin.content, Vec::with_capacity(bytes))
                        )
                        .is_none()
                );
                Some(completed(BlobBeginResult {
                    transfer_id: begin.transfer_id,
                    next_offset: U64::new(0),
                    maximum_chunk_bytes: U64::new(4096),
                }))
            }
            RequestBody::BlobChunk(chunk) => {
                let (reference, original) = uploads.get_mut(&chunk.transfer_id).unwrap();
                assert!(chunk.bytes.as_slice().len() <= 4096);
                assert_eq!(chunk.offset.get(), original.len() as u64);
                assert!(
                    original
                        .len()
                        .checked_add(chunk.bytes.as_slice().len())
                        .unwrap()
                        <= reference.length.get() as usize
                );
                original.extend_from_slice(chunk.bytes.as_slice());
                Some(completed(BlobChunkResult {
                    transfer_id: chunk.transfer_id,
                    next_offset: U64::new(original.len() as u64),
                }))
            }
            RequestBody::BlobFinish(finish) => {
                let (reference, bytes) = uploads.get(&finish.transfer_id).unwrap();
                reference.verify(bytes).unwrap();
                control.install_content(reference.clone(), bytes).unwrap();
                Some(completed(BlobFinishResult {
                    transfer_id: finish.transfer_id,
                    content: reference.clone(),
                }))
            }
            _ => None,
        };
        if let Some(response) = blob {
            assert!(blob_originals.len() < 256);
            blob_originals.insert(request_id.clone(), (identity, response.clone()));
            respond(&mut stream, &request, response, &mut sequence);
            continue;
        }
        if bootstrap.refuse_reply_preflight == Some(request.method) {
            let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                control
                    .dispatch_with_preflight(&request, &mut |_| {
                        if bootstrap.panic_reply_preflight {
                            panic!("original reply preparation test unwind");
                        }
                        Err(ProviderError::ResourceExhausted(
                            "source-local prepared reply test credit",
                        ))
                    })
                    .map(|_| ())
            }));
            if bootstrap.panic_reply_preflight {
                assert!(attempted.is_err());
            } else {
                assert!(attempted.unwrap().is_err());
            }
            // Observe the actual unchanged native owner and original Unknown,
            // not its prospective proof, before fencing the same child.
            let unknown = &control.original(request_id).unwrap().body;
            assert!(matches!(
                decode_response(
                    &decode_request(request.method, &request.body).unwrap(),
                    unknown
                )
                .unwrap()
                .shape,
                ResponseShape::Error {
                    operation_state: OperationState::Unknown,
                    ..
                }
            ));
            let mut changed_transport = request.clone();
            changed_transport.request_id = Nullable(Some(id("after-preparation-fence")));
            changed_transport.sequence = U64::new(request.sequence.get() + 1);
            assert!(control.dispatch(&changed_transport).is_err());
            let retained = PacketNativeRecord {
                schema: "source-owned.packet-native/2".into(),
                native_pid: U64::new(u64::from(std::process::id())),
                original: request.clone(),
                inventory: control.inventory(),
                grant: None,
            };
            std::fs::write(
                &bootstrap.retained_native,
                canonical::canonical_json(&serde_json::to_value(&retained).unwrap()).unwrap(),
            )
            .unwrap();
            stream.shutdown(std::net::Shutdown::Both).unwrap();
            loop {
                std::thread::park();
            }
        }
        let response = control.dispatch(&request).unwrap();
        if (bootstrap.lose_completed_response
            && ((!bootstrap.immediate && request.method == Method::Poll)
                || (bootstrap.immediate && request.method == Method::Begin)))
            || (bootstrap.lose_world_activate_response && request.method == Method::WorldActivate)
        {
            let (_, native) = response.evidence.first().unwrap();
            assert!(native.len() <= FRAME);
            std::fs::write(&bootstrap.retained_native, native).unwrap();
            stream.shutdown(std::net::Shutdown::Both).unwrap();
            // Keep the actual dispatcher, original completed grant and output
            // bytes owned until the parent authentically contains this process.
            loop {
                std::thread::park();
            }
        }
        respond(&mut stream, &request, response.body.clone(), &mut sequence);
        for (root, body) in &response.evidence {
            if sent.insert(root.clone()) {
                transfer(&mut stream, &mut reader, root, body, &mut sequence);
            }
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
    root: &ContentRef,
    bytes: &[u8],
    sequence: &mut u64,
) {
    let transfer = id(&format!("native-proof-{}", root.hash.digest));
    let mut requests = vec![(
        Method::BlobBegin,
        object(BlobBeginRequest {
            transfer_id: transfer.clone(),
            content: root.clone(),
            extensions: Extensions::new(),
        }),
    )];
    for (index, chunk) in bytes.chunks(4096).enumerate() {
        requests.push((
            Method::BlobChunk,
            object(BlobChunkRequest {
                transfer_id: transfer.clone(),
                offset: U64::new((index * 4096) as u64),
                bytes: Bytes::new(chunk.to_vec()),
                extensions: Extensions::new(),
            }),
        ));
    }
    requests.push((
        Method::BlobFinish,
        object(BlobFinishRequest {
            transfer_id: transfer,
            extensions: Extensions::new(),
        }),
    ));
    for (index, (method, body)) in requests.into_iter().enumerate() {
        let request = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(id("packet-session"))),
            incarnation_id: Nullable(Some(id("packet-incarnation"))),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            operation_id: Nullable(None),
            request_id: Nullable(Some(id(&format!(
                "native-proof-{}-{index}",
                root.hash.digest
            )))),
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
