//! Exercises actual compact publication, literal prefixes and failed ACK custody.

use super::*;
use crate::bodies::{EffectCertainty, ErrorRecord, OperationState, ResponseShape};
use crate::envelope::Nullable;
use crate::transport::original_frames::OriginalFrameReservation;
use crate::transport::write_frame;
use crucible_node_format::{Extensions, U64};
use serde_json::json;
use std::{cell::RefCell, io::Cursor};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn oversized_legacy_reply_refuses_before_typed_codec_or_correlation_copy() -> TestResult {
    struct CountingSchemas(std::cell::Cell<usize>);

    impl BodySchemaVerifier for CountingSchemas {
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

    let (_lease, authority) = crate::handshake::tests::authority();
    let request = frame(&authority);
    let maximum = usize::try_from(authority.limits().frame_bytes.get())?;
    let schemas = Rc::new(CountingSchemas(std::cell::Cell::new(0)));
    let supervisor = Rc::new(Supervisor::default());
    let mut connection = Connection::new(
        Stream {
            input: Cursor::new(Vec::new()),
            output: Vec::new(),
            remaining: usize::MAX,
            fenced: false,
        },
        authority,
        supervisor.clone(),
        schemas.clone(),
        EndpointRole::Controller,
    )?;
    connection.guard.receive(&request)?;
    let mut response = request.clone();
    response.message = MessageKind::Response;
    response.body = json!({
        "status": "error", "operation_state": "not_started",
        "error": {"code": "RESOURCE_EXHAUSTED", "message": "original refusal",
                  "effect": "not_started", "retryable": true,
                  "details": {"original": "x".repeat(maximum)}},
        "extensions": {}
    })
    .as_object()
    .unwrap()
    .clone();
    // This is otherwise a valid old response. A larger historical negotiated
    // ceiling can admit it; today's compact send must reject it before codecs.
    connection.validate_body(&response, false)?;
    assert_eq!(schemas.0.get(), 1);
    schemas.0.set(0);
    let before = serde_json::to_value(connection.guard.protocol_view())?;

    let result = connection.send_compact(&response);

    assert!(matches!(result, Err(ProviderError::ResourceExhausted(_))));
    assert_eq!(schemas.0.get(), 0);
    assert_eq!(
        serde_json::to_value(connection.guard.protocol_view())?,
        before
    );
    assert!(connection.reader.stream_mut().output.is_empty());
    assert!(!connection.reader.stream_mut().fenced);
    assert!(supervisor.0.borrow().is_empty());
    Ok(())
}

#[derive(Default)]
struct Supervisor(RefCell<Vec<ConnectionIncident>>);

impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, incident: ConnectionIncident) {
        self.0.borrow_mut().push(incident);
    }
}

struct Schemas;

impl BodySchemaVerifier for Schemas {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        _: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        Ok(())
    }
}

struct Stream {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    remaining: usize,
    fenced: bool,
}

impl Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(bytes)
    }
}

impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        let written = bytes.len().min(self.remaining);
        self.output.extend_from_slice(&bytes[..written]);
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        panic!("CNP frame publication does not flush the stream");
    }
}

impl ProviderStream for Stream {
    fn fence(&mut self) -> std::io::Result<()> {
        self.fenced = true;
        Ok(())
    }
}

fn frame(authority: &ConnectionAuthority) -> Envelope {
    let mut envelope = crate::envelope::tests::request();
    envelope.session_id = Nullable(Some(authority.session_id().clone()));
    envelope.incarnation_id = Nullable(Some(authority.incarnation_id().clone()));
    envelope.sequence = U64::new(2);
    envelope
}

fn framed(envelope: &Envelope) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &serde_json::to_value(envelope).unwrap(), 4096).unwrap();
    bytes
}

fn empty_connection(authority: ConnectionAuthority) -> Result<Connection<Stream>, ProviderError> {
    Connection::new(
        Stream {
            input: Cursor::new(Vec::new()),
            output: Vec::new(),
            remaining: usize::MAX,
            fenced: false,
        },
        authority,
        Rc::new(Supervisor::default()),
        Rc::new(Schemas),
        EndpointRole::Controller,
    )
}

#[test]
fn compact_idle_boundary_preserves_each_unresolved_correlation_population() -> TestResult {
    for owner in ["outgoing", "incoming", "writing", "failed"] {
        let (_lease, authority) = crate::handshake::tests::authority();
        let request = frame(&authority);
        let mut connection = empty_connection(authority)?;
        match owner {
            "outgoing" => connection.guard.register_request(request)?,
            "incoming" => connection.guard.receive(&request)?,
            "writing" => {
                connection.guard.receive(&request)?;
                let mut response = request;
                response.message = MessageKind::Response;
                connection.guard.register_outgoing(response)?;
            }
            "failed" => connection.guard.fence(),
            _ => unreachable!(),
        }
        let before = serde_json::to_value(connection.guard.protocol_view())?;

        let result = connection.authenticate_compact_exchange_idle();

        assert!(
            matches!(result, Err(ProviderError::Conflict(_))),
            "{owner}: {result:?}"
        );
        assert_eq!(
            serde_json::to_value(connection.guard.protocol_view())?,
            before
        );
        assert!(connection.reader.stream_mut().output.is_empty());
    }
    Ok(())
}

#[test]
fn compact_idle_boundary_accepts_retired_history_and_keeps_negotiated_credit() -> TestResult {
    let (_lease, authority) = crate::handshake::tests::authority();
    let request = frame(&authority);
    let mut connection = empty_connection(authority)?;
    let before = serde_json::to_value(connection.guard.protocol_view())?;
    connection.authenticate_compact_exchange_idle()?;
    connection.guard.receive(&request)?;
    let mut response = request;
    response.message = MessageKind::Response;
    connection.guard.register_outgoing(response.clone())?;
    connection.guard.confirm_response_sent(&response)?;
    let retired = serde_json::to_value(connection.guard.protocol_view())?;
    assert!(!connection.guard.unused());

    connection.authenticate_compact_exchange_idle()?;

    assert_eq!(
        serde_json::to_value(connection.guard.protocol_view())?,
        retired
    );
    assert_eq!(before[5], retired[5]);
    Ok(())
}

#[test]
fn borrowed_send_preserves_wire_literal_and_correlation_with_either_bank() -> TestResult {
    for with_bank in [false, true] {
        for remaining in [7, usize::MAX] {
            let (_lease, authority) = crate::handshake::tests::authority();
            let mut request = frame(&authority);
            request.protocol.reserve(65_536);
            let original_capacity = request.protocol.capacity();
            let expected = framed(&request);
            let supervisor = Rc::new(Supervisor::default());
            let mut connection = Connection::new(
                Stream {
                    input: Cursor::new(Vec::new()),
                    output: Vec::new(),
                    remaining,
                    fenced: false,
                },
                authority,
                supervisor.clone(),
                Rc::new(Schemas),
                EndpointRole::Controller,
            )?;
            if with_bank {
                connection
                    .install_native5_frame_bank(OriginalFrameReservation::reserve(16_384, 8)?)?;
            }

            let result = connection.send_compact(&request);

            assert_eq!(result.is_ok(), remaining == usize::MAX);
            let sent = expected.len().min(remaining);
            assert_eq!(connection.reader.stream_mut().output, expected[..sent]);
            assert_eq!(request.protocol.capacity(), original_capacity);
            assert_eq!(
                connection.guard.pending_requests().collect::<Vec<_>>(),
                vec![&request]
            );
            if with_bank {
                let bank = connection.original_frames.as_ref().unwrap().borrow();
                let literal = bank.frames().next().unwrap();
                assert_eq!(literal.bytes, expected);
                assert_eq!(literal.transferred, sent);
                assert_eq!(literal.complete, remaining == usize::MAX);
            }
            if result.is_err() {
                assert!(connection.fenced);
                assert!(connection.reader.stream_mut().fenced);
                assert_eq!(supervisor.0.borrow()[0].outgoing, vec![request.clone()]);
                assert!(connection.send_compact(&request).is_err());
                assert_eq!(supervisor.0.borrow().len(), 1);
            }
        }
    }
    Ok(())
}

#[test]
fn partial_compact_ack_preserves_received_and_writing_response_owners() -> TestResult {
    for remaining in [7, usize::MAX] {
        let (_lease, authority) = crate::handshake::tests::authority();
        let mut request = frame(&authority);
        request.method = Method::BlobFinish;
        request.operation_id = Nullable(None);
        request.execution_owner_id = Nullable(None);
        request.body =
            serde_json::from_value(json!({"transfer_id":"transfer-1", "extensions":{}}))?;
        let supervisor = Rc::new(Supervisor::default());
        let mut connection = Connection::new(
            Stream {
                input: Cursor::new(framed(&request)),
                output: Vec::new(),
                remaining,
                fenced: false,
            },
            authority,
            supervisor.clone(),
            Rc::new(Schemas),
            EndpointRole::Controller,
        )?;
        connection.install_native5_frame_bank(OriginalFrameReservation::reserve(16_384, 8)?)?;
        assert_eq!(connection.receive()?.unwrap().envelope, request);
        let mut response = request.clone();
        response.message = MessageKind::Response;
        response.body = serde_json::from_value(serde_json::to_value(ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            error: ErrorRecord {
                code: "RESOURCE_EXHAUSTED".into(),
                message: "retained refusal".into(),
                effect: EffectCertainty::NotStarted,
                retryable: true,
                details: serde_json::Map::new(),
            },
            extensions: Extensions::new(),
        })?)?;

        let result = connection.send_compact(&response);

        assert_eq!(result.is_ok(), remaining == usize::MAX);
        let bank = connection.original_frames.as_ref().unwrap().borrow();
        let literal = bank.frames().last().unwrap();
        let expected = framed(&response);
        assert_eq!(literal.bytes, expected);
        assert_eq!(literal.transferred, expected.len().min(remaining));
        assert_eq!(literal.complete, remaining == usize::MAX);
        let correlations = serde_json::to_value(connection.guard.protocol_view())?;
        let received = correlations[7].as_object().unwrap();
        let writing = correlations[8].as_object().unwrap();
        if remaining == usize::MAX {
            assert!(received.is_empty());
            assert!(writing.is_empty());
            assert!(supervisor.0.borrow().is_empty());
        } else {
            assert_eq!(
                received.values().next(),
                Some(&serde_json::to_value(&request)?)
            );
            assert_eq!(
                writing.values().next(),
                Some(&serde_json::to_value(&response)?)
            );
            assert_eq!(supervisor.0.borrow()[0].incoming, vec![request]);
            assert_eq!(supervisor.0.borrow()[0].failure, ConnectionFailure::Write);
        }
    }
    Ok(())
}

#[test]
fn compact_send_keeps_closed_body_and_native18_refusals_before_publication() -> TestResult {
    let (_lease, authority) = crate::handshake::tests::authority();
    let mut request = frame(&authority);
    let mut connection = Connection::new(
        Stream {
            input: Cursor::new(Vec::new()),
            output: Vec::new(),
            remaining: usize::MAX,
            fenced: false,
        },
        authority,
        Rc::new(Supervisor::default()),
        Rc::new(Schemas),
        EndpointRole::Controller,
    )?;
    request.body.insert("unknown".into(), json!(true));
    assert!(connection.send_compact(&request).is_err());
    request.method = Method::NativeImport18Bootstrap;
    assert!(connection.send_compact(&request).is_err());

    assert!(connection.reader.stream_mut().output.is_empty());
    assert!(connection.guard.unused());
    Ok(())
}
