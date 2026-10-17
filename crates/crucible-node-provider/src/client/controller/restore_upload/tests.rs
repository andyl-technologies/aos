//! Checks actual role/ACK data without a native grant or socket operation.

use super::*;

fn held() -> OriginalCompleteRestoreInputUpload {
    OriginalCompleteRestoreInputUpload {
        controller: Weak::new(),
        prepare_id: blake3::Hash::from_bytes([0; 32]),
        prepare_sequence: U64::new(0),
        response_sequence: U64::new(0),
        receipt_token: blake3::Hash::from_bytes([0; 32]),
        references: std::array::from_fn(|_| None),
        transfers: std::array::from_fn(|_| None),
        offsets: [0; 6],
        frames: Vec::new(),
        active: 0,
        phase: UploadPhase::Allocating,
        cut: None,
    }
}

fn original(method: Method) -> Envelope {
    let present = || Nullable(Some(Id::new("actual/scope").unwrap()));
    Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: present(),
        incarnation_id: present(),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(None),
        request_id: present(),
        sequence: U64::new(7),
        method,
        body: Default::default(),
        extensions: Default::default(),
    }
}

fn chunk_frame() -> UploadFrame {
    UploadFrame {
        role: 0,
        method: Method::BlobChunk,
        offset: 3,
        length: 2,
        request_id: Id::new("actual/scope").unwrap(),
        original: Some(original(Method::BlobChunk)),
        received: None,
        attempted: true,
        complete: false,
    }
}

fn chunk_ack() -> ReceivedFrame {
    let mut envelope = original(Method::BlobChunk);
    envelope.message = MessageKind::Response;
    envelope.sequence = U64::new(9);
    ReceivedFrame {
        envelope,
        body: ReceivedBody::Response(Box::new(ResponseBody {
            shape: ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result: Default::default(),
                extensions: Default::default(),
            },
            result: Some(MethodResult::BlobChunk(BlobChunkResult {
                transfer_id: Id::new("transfer/0").unwrap(),
                next_offset: U64::new(5),
            })),
        })),
    }
}

#[test]
fn equal_content_keeps_six_distinct_roles_and_original_request_ids() {
    let reference = canonical::content_ref(b"abcde", "application/json").unwrap();
    let value = serde_json::to_value(&reference).unwrap();
    let references = [inputs::Reference::borrow(&value).unwrap(); 6];
    let mut held = held();
    let requests = 6 * (5usize.div_ceil(2) + 2);
    held.frames.try_reserve_exact(requests).unwrap();

    populate_plan(&mut held, &references, "actual-prepare", 2).unwrap();

    assert_eq!(held.frames.len(), requests);
    assert_eq!(
        held.references
            .iter()
            .filter(|r| r.as_ref() == Some(&reference))
            .count(),
        6
    );
    let transfers = held
        .transfers
        .iter()
        .map(|r| r.as_ref().unwrap().as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let requests = held
        .frames
        .iter()
        .map(|r| r.request_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(transfers.len(), 6);
    assert_eq!(requests.len(), held.frames.len());
    let request_count = requests.len();
    drop(requests);
    assert!(
        held.frames
            .iter()
            .all(|r| !r.attempted && !r.complete && r.original.is_none() && r.received.is_none())
    );
    assert!(populate_plan(&mut held, &references, "replacement", 2).is_err());
    assert_eq!(held.frames.len(), request_count);
}

#[test]
fn plan_requires_full_preallocated_population_without_late_vec_growth() {
    let reference = canonical::content_ref(b"abcde", "application/json").unwrap();
    let value = serde_json::to_value(&reference).unwrap();
    let references = [inputs::Reference::borrow(&value).unwrap(); 6];
    let count = 6 * (5usize.div_ceil(2) + 2);
    let mut exact = held();
    exact.frames.try_reserve_exact(count).unwrap();
    populate_plan(&mut exact, &references, "actual", 2).unwrap();
    let capacity = exact.frames.capacity();
    assert_eq!(exact.frames.len(), count);
    assert_eq!(exact.frames.capacity(), capacity);

    let mut short = held();
    short.frames.try_reserve_exact(count - 1).unwrap();
    let capacity = short.frames.capacity();
    assert!(populate_plan(&mut short, &references, "actual", 2).is_err());
    assert_eq!(short.frames.capacity(), capacity);
    assert_eq!(short.frames.len(), capacity);
    assert!(short.references.iter().any(Option::is_some));
    assert!(populate_plan(&mut short, &references, "replacement", 2).is_err());
}

#[test]
fn chunk_ack_requires_exact_progress_transfer_and_correlation() {
    let frame = chunk_frame();
    let transfer = Id::new("transfer/0").unwrap();
    let reference = canonical::content_ref(b"abcde", "application/json").unwrap();
    let mut ack = chunk_ack();
    authenticate_ack(&frame, &ack, &transfer, &reference, 2).unwrap();
    let ReceivedBody::Response(body) = &mut ack.body else {
        panic!("fixture");
    };
    let Some(MethodResult::BlobChunk(result)) = &mut body.result else {
        panic!("fixture");
    };
    result.next_offset = U64::new(4);
    assert!(authenticate_ack(&frame, &ack, &transfer, &reference, 2).is_err());
    ack = chunk_ack();
    ack.envelope.request_id = Nullable(Some(Id::new("foreign/request").unwrap()));
    assert!(authenticate_ack(&frame, &ack, &transfer, &reference, 2).is_err());
    ack = chunk_ack();
    assert!(
        authenticate_ack(
            &frame,
            &ack,
            &Id::new("foreign/transfer").unwrap(),
            &reference,
            2
        )
        .is_err()
    );
    assert!(frame.attempted && !frame.complete);
}

#[test]
fn wrong_finish_full_reference_or_extra_extension_cannot_complete_role() {
    let reference = canonical::content_ref(b"abcde", "application/json").unwrap();
    let transfer = Id::new("transfer/0").unwrap();
    let mut frame = chunk_frame();
    frame.method = Method::BlobFinish;
    frame.offset = 5;
    frame.length = 0;
    frame.original = Some(original(Method::BlobFinish));
    let mut ack = chunk_ack();
    ack.envelope.method = Method::BlobFinish;
    ack.body = ReceivedBody::Response(Box::new(ResponseBody {
        shape: ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: Default::default(),
            extensions: Default::default(),
        },
        result: Some(MethodResult::BlobFinish(BlobFinishResult {
            transfer_id: transfer.clone(),
            content: reference.clone(),
        })),
    }));
    authenticate_ack(&frame, &ack, &transfer, &reference, 2).unwrap();
    let mut changed = reference.clone();
    changed.media_type.push('x');
    assert!(authenticate_ack(&frame, &ack, &transfer, &changed, 2).is_err());
    ack.envelope
        .extensions
        .insert("foreign".into(), Value::Null);
    assert!(authenticate_ack(&frame, &ack, &transfer, &reference, 2).is_err());
}

#[test]
fn six_body_verification_preserves_role_order_and_complete_reference() {
    let bytes = [[1u8], [2], [3], [4], [5], [6]];
    let values: [Value; 6] = std::array::from_fn(|i| {
        serde_json::to_value(canonical::content_ref(&bytes[i], "application/json").unwrap())
            .unwrap()
    });
    let mut response = original(Method::Begin);
    response.message = MessageKind::Response;
    let original = original(Method::Begin);
    let data = PrepareInputs {
        original: &original,
        response: &response,
        request_id: original.request_id.0.as_ref().unwrap(),
        token: "inert-data-only",
        references: std::array::from_fn(|i| inputs::Reference::borrow(&values[i]).unwrap()),
    };
    let mut bodies = std::array::from_fn(|i| bytes[i].as_slice());
    data.verify_bodies(&bodies).unwrap();
    bodies.swap(0, 1);
    assert!(data.verify_bodies(&bodies).is_err());
    bodies.swap(0, 1);
    bodies[5] = b"changed";
    assert!(data.verify_bodies(&bodies).is_err());
}

#[test]
fn borrowed_input_reference_refuses_noncanonical_or_unknown_fields() {
    let reference = canonical::content_ref(b"x", "application/json").unwrap();
    let value = serde_json::to_value(&reference).unwrap();
    let borrowed = inputs::Reference::borrow(&value).unwrap();
    assert_eq!(borrowed.owned(), reference);
    let mut changed = value.clone();
    changed["length"] = Value::String("01".into());
    assert!(inputs::Reference::borrow(&changed).is_err());
    changed = value.clone();
    changed["hash"]["digest"] = Value::String("A".repeat(64));
    assert!(inputs::Reference::borrow(&changed).is_err());
    changed = value.clone();
    changed
        .as_object_mut()
        .unwrap()
        .insert("unknown".into(), Value::Null);
    assert!(inputs::Reference::borrow(&changed).is_err());
}
