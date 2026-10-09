//! Exercises authenticated stream failure with model-only installation evidence.

#![allow(clippy::unwrap_used)]

use std::cell::RefCell;
use std::io::{Cursor, Error, ErrorKind};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crucible_node_contract::U64;
use serde_json::{Value, json};

use super::*;
use crate::envelope::{Nullable, tests::request};
use crate::transport::write_frame;

#[derive(Default)]
struct Supervisor(RefCell<Vec<ConnectionIncident>>);

impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, incident: ConnectionIncident) {
        self.0.borrow_mut().push(incident);
    }
}

struct CoreSchemas;

impl BodySchemaVerifier for CoreSchemas {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        envelope: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        if !envelope.extensions.is_empty()
            || envelope
                .body
                .get("extensions")
                .is_some_and(|value| value != &json!({}))
        {
            return Err(ProviderError::Correlation("unregistered test extension"));
        }
        Ok(())
    }
}

fn frame(authority: &ConnectionAuthority) -> Envelope {
    let mut frame = request();
    frame.session_id = Nullable(Some(authority.session_id().clone()));
    frame.incarnation_id = Nullable(Some(authority.incarnation_id().clone()));
    frame.sequence = U64::new(2);
    frame
}

fn pair() -> (UnixStream, UnixStream) {
    let (controller, provider) = UnixStream::pair().unwrap();
    for stream in [&controller, &provider] {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    (controller, provider)
}

#[test]
fn invalid_response_body_keeps_original_request_custody() {
    let (_handshake, authority) = crate::handshake::tests::authority();
    let original = frame(&authority);
    let (stream, mut peer) = pair();
    let supervisor = Rc::new(Supervisor::default());
    let mut connection = Connection::new(
        stream,
        authority,
        supervisor.clone(),
        Rc::new(CoreSchemas),
        EndpointRole::Controller,
    )
    .unwrap();
    connection.send(original.clone()).unwrap();

    let mut response = original.clone();
    response.message = MessageKind::Response;
    response.body = json!({"foreign": "not a baseline response"})
        .as_object()
        .unwrap()
        .clone();
    write_frame(&mut peer, &serde_json::to_value(response).unwrap(), 4096).unwrap();

    assert!(connection.receive().is_err());
    assert_eq!(supervisor.0.borrow().len(), 1);
    let incidents = supervisor.0.borrow();
    assert_eq!(incidents[0].outgoing, vec![original]);
    assert!(incidents[0].transport_fenced);
    drop(incidents);
    drop(connection);
    assert_eq!(supervisor.0.borrow().len(), 1);
}

#[test]
fn eof_fences_the_stream_without_claiming_original_operation_stopped() {
    let (_handshake, authority) = crate::handshake::tests::authority();
    let original = frame(&authority);
    let (stream, peer) = pair();
    let supervisor = Rc::new(Supervisor::default());
    let mut connection = Connection::new(
        stream,
        authority,
        supervisor.clone(),
        Rc::new(CoreSchemas),
        EndpointRole::Controller,
    )
    .unwrap();
    connection.send(original.clone()).unwrap();
    peer.shutdown(std::net::Shutdown::Write).unwrap();

    assert!(connection.receive().unwrap().is_none());
    let incidents = supervisor.0.borrow();
    assert_eq!(incidents[0].failure, ConnectionFailure::Read);
    assert_eq!(incidents[0].outgoing, vec![original]);
}

#[test]
fn revoked_authority_prevents_new_frames_and_transfers_original_custody() {
    let (mut handshake, authority) = crate::handshake::tests::authority();
    let original = frame(&authority);
    let (stream, _peer) = pair();
    let supervisor = Rc::new(Supervisor::default());
    let mut connection = Connection::new(
        stream,
        authority,
        supervisor.clone(),
        Rc::new(CoreSchemas),
        EndpointRole::Controller,
    )
    .unwrap();
    connection.send(original.clone()).unwrap();
    handshake.contain();

    assert!(connection.send(original.clone()).is_err());
    let incidents = supervisor.0.borrow();
    assert_eq!(incidents[0].failure, ConnectionFailure::Authority);
    assert_eq!(incidents[0].outgoing, vec![original]);
}

#[test]
fn provider_requests_cannot_inject_controller_execution_commands() {
    let (_handshake, authority) = crate::handshake::tests::authority();
    let forbidden = frame(&authority);
    let (stream, mut peer) = pair();
    let supervisor = Rc::new(Supervisor::default());
    let mut connection = Connection::new(
        stream,
        authority,
        supervisor.clone(),
        Rc::new(CoreSchemas),
        EndpointRole::Controller,
    )
    .unwrap();
    write_frame(&mut peer, &serde_json::to_value(forbidden).unwrap(), 4096).unwrap();

    assert!(connection.receive().is_err());
    assert!(supervisor.0.borrow()[0].incoming.is_empty());
}

#[test]
fn accepted_provider_content_requests_survive_borrower_drop() {
    let (_handshake, authority) = crate::handshake::tests::authority();
    let mut request = frame(&authority);
    request.method = Method::BlobFinish;
    request.operation_id = Nullable(None);
    request.execution_owner_id = Nullable(None);
    request.body = json!({"transfer_id":"transfer-1", "extensions":{}})
        .as_object()
        .unwrap()
        .clone();
    let (stream, mut peer) = pair();
    let supervisor = Rc::new(Supervisor::default());
    let mut connection = Connection::new(
        stream,
        authority,
        supervisor.clone(),
        Rc::new(CoreSchemas),
        EndpointRole::Controller,
    )
    .unwrap();
    write_frame(&mut peer, &serde_json::to_value(&request).unwrap(), 4096).unwrap();

    assert!(matches!(
        connection.receive().unwrap().unwrap().body,
        ReceivedBody::Request(_)
    ));
    drop(connection);
    assert_eq!(supervisor.0.borrow()[0].incoming, vec![request]);
}

struct PartialWrite {
    input: Cursor<Vec<u8>>,
    remaining: usize,
    fenced: bool,
}

impl Read for PartialWrite {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(bytes)
    }
}

impl Write for PartialWrite {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(Error::new(ErrorKind::BrokenPipe, "scripted partial write"));
        }
        let written = bytes.len().min(self.remaining);
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ProviderStream for PartialWrite {
    fn fence(&mut self) -> std::io::Result<()> {
        self.fenced = true;
        Ok(())
    }
}

#[test]
fn partial_outgoing_write_retains_the_original_request_and_cannot_retry() {
    let (_handshake, authority) = crate::handshake::tests::authority();
    let original = frame(&authority);
    let stream = PartialWrite {
        input: Cursor::new(Vec::new()),
        remaining: 7,
        fenced: false,
    };
    let supervisor = Rc::new(Supervisor::default());
    let mut connection = Connection::new(
        stream,
        authority,
        supervisor.clone(),
        Rc::new(CoreSchemas),
        EndpointRole::Controller,
    )
    .unwrap();

    assert!(connection.send(original.clone()).is_err());
    assert!(connection.send(original.clone()).is_err());
    assert_eq!(supervisor.0.borrow().len(), 1);
    let incidents = supervisor.0.borrow();
    assert_eq!(incidents[0].failure, ConnectionFailure::Write);
    assert_eq!(incidents[0].outgoing, vec![original]);
    assert!(incidents[0].transport_fenced);
}

#[test]
fn local_schema_refusal_does_not_consume_sequence_or_stream_credit() {
    let (_handshake, authority) = crate::handshake::tests::authority();
    let valid = frame(&authority);
    let mut invalid = valid.clone();
    invalid.body.insert("foreign".into(), Value::Bool(true));
    let (stream, _peer) = pair();
    let supervisor = Rc::new(Supervisor::default());
    let mut connection = Connection::new(
        stream,
        authority,
        supervisor.clone(),
        Rc::new(CoreSchemas),
        EndpointRole::Controller,
    )
    .unwrap();

    assert!(connection.send(invalid).is_err());
    assert!(supervisor.0.borrow().is_empty());
    connection.send(valid).unwrap();
    assert_eq!(connection.guard.pending_requests().count(), 1);
}

#[test]
fn a_valid_poll_body_cannot_substitute_another_original_operation() {
    let (_handshake, authority) = crate::handshake::tests::authority();
    let original = frame(&authority);
    let (stream, mut peer) = pair();
    let supervisor = Rc::new(Supervisor::default());
    let mut connection = Connection::new(stream, authority, supervisor.clone(), Rc::new(CoreSchemas), EndpointRole::Controller).unwrap();
    connection.send(original.clone()).unwrap();

    let mut response = original.clone();
    response.message = MessageKind::Response;
    response.body = json!({
        "status":"completed", "operation_state":"completed", "extensions":{},
        "result": {"operation_id":"foreign-operation", "operation_state":"running", "outcome":null,
                   "observations":[], "next_observation_sequence":"0"}
    }).as_object().unwrap().clone();
    write_frame(&mut peer, &serde_json::to_value(response).unwrap(), 4096).unwrap();

    assert!(connection.receive().is_err());
    assert_eq!(supervisor.0.borrow()[0].outgoing, vec![original]);
}
