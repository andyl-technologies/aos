//! Exercises the actual borrowed guard without native effect permissions.

use super::*;
use crate::{bodies::*, envelope::Nullable, handshake::Handshake};
use crucible_node_format::{Extensions, U64};
use std::{cell::RefCell, io::Cursor};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Fixture = (Handshake, PreparedExchange<Memory>, Rc<Supervisor>);

#[derive(Default)]
struct Memory {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    fenced: bool,
}

impl Read for Memory {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(bytes)
    }
}

impl Write for Memory {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ProviderStream for Memory {
    fn fence(&mut self) -> std::io::Result<()> {
        self.fenced = true;
        Ok(())
    }
}

#[derive(Default)]
struct Supervisor(RefCell<Vec<ConnectionIncident>>);

impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, incident: ConnectionIncident) {
        self.0.borrow_mut().push(incident);
    }
}

struct Uninstalled;

impl BodySchemaVerifier for Uninstalled {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        _: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "fixture callback must be replaced",
        ))
    }
}

fn object(
    value: &impl serde::Serialize,
) -> Result<serde_json::Map<String, serde_json::Value>, ProviderError> {
    match serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)? {
        serde_json::Value::Object(value) => Ok(value),
        _ => Err(ProviderError::Frame("fixture expected object")),
    }
}

fn fixture(mutate: impl FnOnce(&mut Envelope)) -> Result<Fixture, Box<dyn std::error::Error>> {
    let (handshake, authority, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let policy = crate::reference_packet::service::prepared_blob_proof_codec_for_test(
        selection,
        coordinator,
    )?;
    let transfer = Id::new("packet-transfer-2")?;
    let original = Envelope {
        protocol: "CNP/1".to_owned(),
        message: MessageKind::Request,
        session_id: Nullable(Some(authority.session_id().clone())),
        incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        request_id: Nullable(Some(Id::new("packet-proof-2")?)),
        operation_id: Nullable(None),
        sequence: U64::new(2),
        method: Method::BlobBegin,
        body: object(&BlobBeginRequest {
            transfer_id: transfer.clone(),
            content: canonical::content_ref(b"actual proof", "application/json")?,
            extensions: Extensions::new(),
        })?,
        extensions: Extensions::new(),
    };
    let mut response = original.clone();
    response.message = MessageKind::Response;
    response.body = object(&ResponseShape::Completed {
        operation_state: OperationState::Completed,
        result: object(&BlobBeginResult {
            transfer_id: transfer,
            next_offset: U64::new(0),
            maximum_chunk_bytes: U64::new(4096),
        })?,
        extensions: Extensions::new(),
    })?;
    mutate(&mut response);
    let bytes = canonical::canonical_json(&serde_json::to_value(&response)?)?;
    let mut input = Vec::new();
    input.extend_from_slice(&u32::try_from(bytes.len())?.to_be_bytes());
    input.extend_from_slice(&bytes);
    let supervisor = Rc::new(Supervisor::default());
    let mut connection = Connection::new(
        Memory {
            input: Cursor::new(input),
            ..Memory::default()
        },
        authority,
        supervisor.clone(),
        Rc::new(Uninstalled),
        EndpointRole::Provider,
    )?;
    let mut bank =
        Some(crate::transport::original_frames::OriginalFrameReservation::reserve(262_144, 8)?);
    connection.install_native5_native_codec(&mut bank, policy)?;
    let mut exchange = connection.unprepared_exchange(vec![original]);
    exchange.prepare_in_place()?;
    Ok((handshake, exchange, supervisor))
}

#[test]
fn same_prepared_native_blob_proof_uses_the_guard_and_retains_complete_literals() -> TestResult {
    let (_handshake, mut exchange, supervisor) = fixture(|_| {})?;

    exchange.publish(&mut |_, received| {
        if matches!(&received.body, ReceivedBody::Response(body) if matches!(body.result, Some(MethodResult::BlobBegin(_)))) {
            Ok(())
        } else {
            Err(ProviderError::Frame("fixture expected typed BlobBegin response"))
        }
    })?;

    assert_eq!(exchange.record.sent, 1);
    assert_eq!(exchange.record.acknowledgements.len(), 1);
    assert_eq!(exchange.connection.guard.pending_requests().count(), 0);
    assert!(supervisor.0.borrow().is_empty());
    let bank = exchange
        .connection
        .original_frames
        .as_ref()
        .ok_or("fixture bank absent")?
        .borrow();
    assert_eq!(bank.frames().count(), 2);
    assert!(
        bank.frames()
            .all(|frame| frame.complete && frame.transferred == frame.bytes.len())
    );
    Ok(())
}

#[test]
fn foreign_request_method_scope_and_request_kind_refuse_before_typed_body_decode() -> TestResult {
    for change in 0..5 {
        let other_request = Id::new("another-proof")?;
        let other_node = Id::new("another-node")?;
        let (_handshake, mut exchange, supervisor) = fixture(|response| {
            match change {
                0 => response.request_id = Nullable(Some(other_request)),
                1 => response.method = Method::BlobFinish,
                2 => response.message = MessageKind::Request,
                3 => response.sequence = U64::new(3),
                _ => response.node_id = Nullable(Some(other_node)),
            }
            response.body = serde_json::Map::new();
        })?;

        let result =
            exchange.publish(&mut |_, _| Err(ProviderError::Frame("validator must not run")));

        assert!(matches!(result, Err(ProviderError::Correlation(_))));
        assert_eq!(exchange.record.sent, 1);
        assert!(exchange.record.acknowledgements.is_empty());
        assert_eq!(supervisor.0.borrow().len(), 1);
        assert_eq!(supervisor.0.borrow()[0].outgoing, exchange.record.originals);
        let bank = exchange
            .connection
            .original_frames
            .as_ref()
            .ok_or("fixture bank absent")?
            .borrow();
        assert_eq!(bank.frames().count(), 2);
        assert!(bank.frames().all(|frame| frame.complete));
    }
    Ok(())
}

#[test]
fn another_actual_actor_cannot_read_using_the_equal_prepared_original() -> TestResult {
    let (_first_handshake, mut first, _) = fixture(|_| {})?;
    let (_second_handshake, mut second, _) = fixture(|_| {})?;
    first
        .connection
        .publish_original_send(&first.record.canonical[0], first.record.original_slots[0])?;
    first.record.sent = 1;
    assert_eq!(first.record.originals, second.record.originals);

    assert!(
        second
            .connection
            .receive_original_prepared_blob_proof(&first.record, 0)
            .is_err()
    );

    assert_eq!(second.connection.reader.stream_ref().input.position(), 0);
    assert!(second.connection.reader.stream_ref().output.is_empty());
    assert_eq!(second.connection.guard.pending_requests().count(), 1);
    Ok(())
}

#[test]
fn replaced_actual_schema_owner_refuses_before_the_guard_reads_any_bytes() -> TestResult {
    let (_handshake, mut exchange, _) = fixture(|_| {})?;
    exchange.connection.schemas = Rc::new(Uninstalled);

    assert!(exchange.publish(&mut |_, _| Ok(())).is_err());

    assert_eq!(exchange.connection.reader.stream_ref().input.position(), 0);
    assert_eq!(exchange.connection.guard.pending_requests().count(), 1);
    Ok(())
}

#[test]
fn generic_receive_still_accepts_an_independent_valid_incoming_request() -> TestResult {
    let (_handshake, mut exchange, _) = fixture(|response| {
        response.message = MessageKind::Request;
        response.method = Method::BlobFinish;
        response.body = serde_json::Map::from_iter([
            (
                "transfer_id".to_owned(),
                serde_json::Value::String("independent-transfer".to_owned()),
            ),
            (
                "extensions".to_owned(),
                serde_json::Value::Object(serde_json::Map::new()),
            ),
        ]);
    })?;

    let received = exchange
        .connection
        .receive()?
        .ok_or("fixture reply absent")?;

    assert!(
        matches!(received.body, ReceivedBody::Request(body) if matches!(*body, RequestBody::BlobFinish(_)))
    );
    assert_eq!(exchange.connection.guard.incoming_requests().count(), 1);
    assert_eq!(exchange.connection.guard.pending_requests().count(), 1);
    Ok(())
}
