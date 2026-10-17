//! Exercises whole-prefix transport custody without native qualification.

use super::*;

fn originals(authority: &ConnectionAuthority) -> Vec<Envelope> {
    let first = frame(authority);
    let mut second = first.clone();
    second.request_id = Nullable(Some(Id::new("request-2").unwrap()));
    second.sequence = U64::new(3);
    vec![first, second]
}

fn reply(original: &Envelope, sequence: u64) -> Envelope {
    let mut reply = original.clone();
    reply.message = MessageKind::Response;
    reply.sequence = U64::new(sequence);
    reply.body = json!({
        "status":"completed", "operation_state":"completed", "extensions":{},
        "result": {"operation_id": original.operation_id.0,
                   "operation_state":"running", "outcome":null,
                   "observations":[], "next_observation_sequence":"0"}
    })
    .as_object()
    .unwrap()
    .clone();
    reply
}

fn connection(
    stream: UnixStream,
    authority: ConnectionAuthority,
    supervisor: Rc<Supervisor>,
) -> Connection<UnixStream> {
    Connection::new(
        stream,
        authority,
        supervisor,
        Rc::new(CoreSchemas),
        EndpointRole::Controller,
    )
    .unwrap()
}

#[test]
fn whole_prefix_is_inert_and_retains_literal_frames_and_received_replies() {
    let (_handshake, authority) = crate::handshake::tests::authority();
    let originals = originals(&authority);
    let (stream, mut peer) = pair();
    let supervisor = Rc::new(Supervisor::default());
    let mut exchange = connection(stream, authority, supervisor)
        .prepare_exchange(originals.clone())
        .unwrap_or_else(|_| panic!("valid prefix"));
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut [0]).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    peer.set_nonblocking(false).unwrap();
    for (index, original) in originals.iter().enumerate() {
        write_frame(
            &mut peer,
            &serde_json::to_value(reply(original, 2 + index as u64)).unwrap(),
            4096,
        )
        .unwrap();
    }

    let mut validated = 0;
    exchange
        .publish(&mut |original, received| {
            original.matches_response(&received.envelope)?;
            validated += 1;
            Ok(())
        })
        .unwrap();
    assert!(exchange.publish(&mut |_, _| Ok(())).is_err());
    let (connection, record) = exchange.into_parts();
    assert_eq!(record.originals(), originals);
    assert_eq!(record.sent(), 2);
    assert_eq!(record.acknowledgements().len(), 2);
    assert_eq!(validated, 2);
    assert_eq!(connection.guard.pending_requests().count(), 0);
    for (index, original) in originals.iter().enumerate() {
        let mut expected = Vec::new();
        write_frame(
            &mut expected,
            &serde_json::to_value(original).unwrap(),
            4096,
        )
        .unwrap();
        let mut actual = vec![0; expected.len()];
        peer.read_exact(&mut actual).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(record.canonical_frames()[index], expected[4..]);
    }
}

#[test]
fn source_refusal_retains_acknowledged_prefix_and_unsent_original_suffix() {
    let (_handshake, authority) = crate::handshake::tests::authority();
    let originals = originals(&authority);
    let (stream, mut peer) = pair();
    let supervisor = Rc::new(Supervisor::default());
    let mut exchange = connection(stream, authority, supervisor.clone())
        .prepare_exchange(originals.clone())
        .unwrap_or_else(|_| panic!("valid prefix"));
    write_frame(
        &mut peer,
        &serde_json::to_value(reply(&originals[0], 2)).unwrap(),
        4096,
    )
    .unwrap();

    assert!(
        exchange
            .publish(&mut |_, _| Err(ProviderError::Correlation("source transfer refusal")))
            .is_err()
    );
    assert!(exchange.publish(&mut |_, _| Ok(())).is_err());
    let (mut connection, record) = exchange.into_parts();
    assert_eq!(record.originals(), originals);
    assert_eq!(record.sent(), 1);
    assert_eq!(record.acknowledgements().len(), 1);
    assert!(connection.receive().is_err());
    assert_eq!(supervisor.0.borrow().len(), 1);
    assert_eq!(
        supervisor.0.borrow()[0].outgoing,
        vec![originals[1].clone()]
    );
}

#[test]
fn validator_unwind_fences_connection_but_preserves_received_original() {
    let (_handshake, authority) = crate::handshake::tests::authority();
    let original = frame(&authority);
    let (stream, mut peer) = pair();
    let supervisor = Rc::new(Supervisor::default());
    let mut exchange = connection(stream, authority, supervisor.clone())
        .prepare_exchange(vec![original.clone()])
        .unwrap_or_else(|_| panic!("valid prefix"));
    write_frame(
        &mut peer,
        &serde_json::to_value(reply(&original, 2)).unwrap(),
        4096,
    )
    .unwrap();

    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = exchange.publish(&mut |_, _| panic!("source validator failure"));
    }));
    assert!(unwind.is_err());
    assert!(exchange.publish(&mut |_, _| Ok(())).is_err());
    let (mut connection, record) = exchange.into_parts();
    assert_eq!(record.originals(), [original]);
    assert_eq!(record.acknowledgements().len(), 1);
    assert_eq!(record.sent(), 1);
    assert!(connection.receive().is_err());
    assert_eq!(supervisor.0.borrow().len(), 1);
}

#[test]
fn future_response_cannot_discharge_an_earlier_original() {
    let (_handshake, authority) = crate::handshake::tests::authority();
    let originals = originals(&authority);
    let (stream, mut peer) = pair();
    let supervisor = Rc::new(Supervisor::default());
    let mut exchange = connection(stream, authority, supervisor.clone())
        .prepare_exchange(originals.clone())
        .unwrap_or_else(|_| panic!("valid prefix"));
    write_frame(
        &mut peer,
        &serde_json::to_value(reply(&originals[1], 2)).unwrap(),
        4096,
    )
    .unwrap();

    assert!(exchange.publish(&mut |_, _| Ok(())).is_err());
    let (_, record) = exchange.into_parts();
    assert_eq!(record.sent(), 1);
    assert_eq!(record.originals(), originals);
    assert_eq!(
        record.acknowledgements()[0].envelope.request_id,
        record.originals()[1].request_id
    );
    assert_eq!(
        supervisor.0.borrow()[0].outgoing,
        vec![originals[0].clone()]
    );
}

#[test]
fn count_credit_refuses_whole_prefix_before_writes_or_schema_calls() {
    struct Schemas(std::cell::Cell<usize>);
    impl BodySchemaVerifier for Schemas {
        fn verify(
            &self,
            _: &ConnectionAuthority,
            _: &Envelope,
            _: &ReceivedBody,
        ) -> Result<(), ProviderError> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
    }
    let (_handshake, authority) = crate::handshake::tests::authority();
    let mut originals = originals(&authority);
    let mut third = originals[1].clone();
    third.sequence = U64::new(4);
    third.request_id = Nullable(Some(Id::new("request-3").unwrap()));
    originals.push(third);
    let (stream, mut peer) = pair();
    let schemas = Rc::new(Schemas(std::cell::Cell::new(0)));
    let connection = Connection::new(
        stream,
        authority,
        Rc::new(Supervisor::default()),
        schemas.clone(),
        EndpointRole::Controller,
    )
    .unwrap();

    let failure = match connection.prepare_exchange(originals.clone()) {
        Ok(_) => panic!("overwide prefix accepted"),
        Err(failure) => failure,
    };
    assert!(matches!(
        failure.error(),
        ProviderError::ResourceExhausted("prepared exchange frame count")
    ));
    assert_eq!(failure.record().originals(), originals);
    assert_eq!(failure.record().sent(), 0);
    assert_eq!(schemas.0.get(), 0);
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
}

#[test]
fn partial_write_retains_complete_buffers_and_never_republishes() {
    let (_handshake, authority) = crate::handshake::tests::authority();
    let originals = originals(&authority);
    let supervisor = Rc::new(Supervisor::default());
    let connection = Connection::new(
        PartialWrite {
            input: Cursor::new(Vec::new()),
            remaining: 7,
            fenced: false,
        },
        authority,
        supervisor.clone(),
        Rc::new(CoreSchemas),
        EndpointRole::Controller,
    )
    .unwrap();
    let mut exchange = connection
        .prepare_exchange(originals.clone())
        .unwrap_or_else(|_| panic!("valid prefix"));

    assert!(exchange.publish(&mut |_, _| Ok(())).is_err());
    assert!(exchange.publish(&mut |_, _| Ok(())).is_err());
    let (_, record) = exchange.into_parts();
    assert_eq!(record.originals(), originals);
    assert_eq!(record.canonical_frames().len(), 2);
    assert_eq!(record.sent(), 0);
    assert!(record.acknowledgements().is_empty());
    assert_eq!(supervisor.0.borrow()[0].outgoing, originals);
}

#[test]
fn preparation_unwind_keeps_the_complete_capsule_outside_schema_callback() {
    struct PanicSchema;
    impl BodySchemaVerifier for PanicSchema {
        fn verify(
            &self,
            _: &ConnectionAuthority,
            _: &Envelope,
            _: &ReceivedBody,
        ) -> Result<(), ProviderError> {
            panic!("installed source schema panicked")
        }
    }
    let (_handshake, authority) = crate::handshake::tests::authority();
    let originals = originals(&authority);
    let (stream, mut peer) = pair();
    let supervisor = Rc::new(Supervisor::default());
    let connection = Connection::new(
        stream,
        authority,
        supervisor.clone(),
        Rc::new(PanicSchema),
        EndpointRole::Controller,
    )
    .unwrap();
    let mut exchange = connection.unprepared_exchange(originals.clone());
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = exchange.prepare_in_place();
    }));

    assert!(unwind.is_err());
    assert_eq!(exchange.record().originals(), originals);
    assert_eq!(exchange.record().sent(), 0);
    assert!(exchange.prepare_in_place().is_err());
    assert!(exchange.publish(&mut |_, _| Ok(())).is_err());
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut [0]).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    let (_, record, _) = exchange
        .abort(ProviderError::Conflict("original held after schema unwind"))
        .into_parts();
    assert_eq!(record.originals(), originals);
    assert_eq!(supervisor.0.borrow().len(), 1);
}
