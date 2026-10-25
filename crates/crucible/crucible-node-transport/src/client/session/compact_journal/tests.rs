//! Exercises real SDK socket traffic and compact failure custody under a model lease.
//!
//! These tests perform actual stream I/O, hashing and content transfer. The
//! registrar and schema verifier are inert fixtures; no Source, Child, Hello
//! measurement, native preservation or allocation permission is claimed.

use super::*;
use crate::{
    bodies::*,
    connection::{BodySchemaVerifier, ConnectionIncident, ConnectionSupervisor, ReceivedBody},
    envelope::{Method, Nullable},
    handshake::{ConnectionAuthority, Handshake},
    transport::{FrameReader, write_frame},
};
use crucible_node_format::{Bytes, Extensions, U64, canonical};
use serde_json::{Value, json};
use std::{io::Read, os::unix::net::UnixStream, rc::Rc, time::Duration};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CONTENT_BYTES: usize = 262_144;
const BANK_BYTES: usize = 9 * CONTENT_BYTES;

struct Supervisor;

impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, _: ConnectionIncident) {}
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

fn fixture(
    bank_limit: usize,
) -> (
    Handshake,
    ClientSession,
    CompactClientCustody,
    UnixStream,
    Envelope,
) {
    let (handshake, authority) = crate::handshake::tests::controller_authority(true).unwrap();
    let (session, peer) =
        ClientSession::controller_fixture(authority.clone(), Rc::new(Supervisor), Rc::new(Schemas))
            .unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let custody = CompactClientCustody::new(
        8,
        ClientContent::new(CONTENT_BYTES, 8, 4096).unwrap(),
        bank_limit,
    )
    .unwrap();
    let request = Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(authority.session_id().clone())),
        incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        request_id: Nullable(Some(Id::new("compact-control").unwrap())),
        operation_id: Nullable(None),
        sequence: U64::new(2),
        method: Method::Discover,
        body: super::super::object(DiscoverRequest {
            profile_ids: vec![Id::new("cnp.reference-packet/1").unwrap()],
            cursor: None,
            extensions: Extensions::new(),
        })
        .unwrap(),
        extensions: Extensions::new(),
    };
    (handshake, session, custody, peer, request)
}

fn read(reader: &mut FrameReader<UnixStream>) -> Envelope {
    serde_json::from_value(reader.read().unwrap().unwrap()).unwrap()
}

fn write(peer: &mut UnixStream, envelope: &Envelope) {
    write_frame(peer, &serde_json::to_value(envelope).unwrap(), 65_536).unwrap();
}

fn response(request: &Envelope, details: Value, sequence: u64) -> Envelope {
    let mut response = request.clone();
    response.message = MessageKind::Response;
    response.sequence = U64::new(sequence);
    response.body = super::super::object(ResponseShape::Error {
        operation_state: OperationState::NotStarted,
        error: ErrorRecord {
            code: "RESOURCE_EXHAUSTED".into(),
            message: "original bounded refusal".into(),
            effect: EffectCertainty::NotStarted,
            retryable: true,
            details: details.as_object().unwrap().clone(),
        },
        extensions: Extensions::new(),
    })
    .unwrap();
    response
}

#[test]
fn failed_send_keeps_compact_original_and_caller_spare_capacity() -> TestResult {
    let (_lease, mut session, mut custody, peer, mut request) = fixture(BANK_BYTES);
    request.protocol.reserve(1_048_576);
    let caller_capacity = request.protocol.capacity();
    let original = request.clone();
    let id = request.request_id.0.clone().unwrap();
    drop(peer);

    let result = session.exchange_compact(&mut custody, &mut request, Duration::from_secs(2));

    assert!(matches!(result, Err(ProviderError::Io(_))), "{result:?}");
    let retained = custody.original(RequestOrigin::Controller, &id).unwrap();
    assert_eq!(retained.materialize_request()?, original);
    assert_eq!(
        retained.identity(),
        &original.request_hash(RequestOrigin::Controller)?
    );
    assert!(!retained.has_response());
    assert!(custody.pending_envelope().is_none());
    assert_eq!(request.protocol.capacity(), caller_capacity);
    assert_eq!(request, original);
    assert_eq!(
        custody.retained_journal_bytes(),
        super::super::envelope_bytes(&original)?
    );
    assert!(retained.retained_bank_bytes() <= 9 * custody.retained_journal_bytes());
    assert!(
        custody.retained_metadata_facts()?.vector_capacity_bytes >= retained.retained_bank_bytes()
    );
    Ok(())
}

#[test]
fn cached_response_emits_no_new_frame_and_changed_original_is_refused() -> TestResult {
    let (_lease, mut session, mut custody, mut peer, mut request) = fixture(BANK_BYTES);
    let (done, wait) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let original = read(&mut reader);
        let response = response(
            &original,
            json!({"nested": [{"retained": [0, false, "雪"]}]}),
            2,
        );
        write(&mut peer, &response);
        wait.recv_timeout(Duration::from_secs(5)).unwrap();
        peer.set_nonblocking(true).unwrap();
        assert!(
            matches!(peer.read(&mut [0]), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        (original, response)
    });

    let first = session.exchange_compact(&mut custody, &mut request, Duration::from_secs(2))?;
    let charged = custody.retained_journal_bytes();
    let second = session.exchange_compact(&mut custody, &mut request, Duration::from_secs(2))?;
    done.send(())?;
    let (original, response) = server.join().unwrap();

    assert_eq!(first, response);
    assert_eq!(second, first);
    assert_eq!(custody.retained_journal_bytes(), charged);
    let retained = custody
        .original(
            RequestOrigin::Controller,
            original.request_id.0.as_ref().unwrap(),
        )
        .unwrap();
    let legacy = crate::client::ClientOriginal {
        identity: original.request_hash(RequestOrigin::Controller)?,
        request: original.clone(),
        response: Some(response),
    };
    assert_eq!(
        serde_json::to_value(retained)?,
        serde_json::to_value(legacy)?
    );
    assert_eq!(retained.materialize_request()?, original);
    assert!(retained.retained_bank_bytes() <= 9 * charged);

    request.body.insert("cursor".into(), json!("changed"));
    assert!(matches!(
        session.exchange_compact(&mut custody, &mut request, Duration::from_secs(2)),
        Err(ProviderError::Conflict(_))
    ));
    assert_eq!(custody.retained_journal_bytes(), charged);
    assert_eq!(custody.originals().count(), 1);
    Ok(())
}

#[test]
fn response_compaction_failure_preserves_received_envelope_and_pending_fence() -> TestResult {
    let (_lease, mut session, mut custody, mut peer, mut request) = fixture(BANK_BYTES);
    custody.maximum_envelope_bank_bytes =
        CompactJson::from_envelope(&request, usize::MAX)?.retained_bytes();
    let limit = custody.maximum_envelope_bank_bytes;
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let original = read(&mut reader);
        let response = response(&original, json!({"original": "x".repeat(4096)}), 2);
        write(&mut peer, &response);
        response
    });

    let result = session.exchange_compact(&mut custody, &mut request, Duration::from_secs(2));
    let response = server.join().unwrap();

    assert!(
        matches!(result, Err(ProviderError::ResourceExhausted(_))),
        "{result:?}"
    );
    assert_eq!(
        custody.pending_envelope(),
        Some((RequestOrigin::Controller, &response))
    );
    assert!(!custody.originals().next().unwrap().has_response());
    assert_eq!(custody.maximum_envelope_bank_bytes, limit);
    let before = serde_json::to_value(custody.pending_envelope().unwrap().1)?;
    assert!(
        session
            .exchange_compact(&mut custody, &mut request, Duration::from_secs(2))
            .is_err()
    );
    assert_eq!(
        serde_json::to_value(custody.pending_envelope().unwrap().1)?,
        before
    );
    let facts = custody.retained_metadata_facts()?;
    assert!(facts.string_capacity_bytes >= 4096);
    Ok(())
}

#[test]
fn request_compaction_refusal_leaves_original_with_caller_before_publication() -> TestResult {
    let (_lease, mut session, mut custody, mut peer, mut request) = fixture(1);
    let original = request.clone();

    assert!(matches!(
        session.exchange_compact(&mut custody, &mut request, Duration::from_secs(2)),
        Err(ProviderError::ResourceExhausted(_))
    ));

    assert_eq!(request, original);
    assert_eq!(custody.originals().count(), 0);
    assert_eq!(custody.retained_journal_bytes(), 0);
    assert!(custody.pending_envelope().is_none());
    assert_eq!(peer.read(&mut [0])?, 0);
    Ok(())
}

#[test]
fn actual_content_transfer_keeps_namespaces_distinct_and_recovers_original_ack() -> TestResult {
    let (_lease, mut session, mut custody, mut peer, mut request) = fixture(BANK_BYTES);
    let payload = b"actual compact SDK content".to_vec();
    let reference = canonical::content_ref(&payload, "application/octet-stream")?;
    let expected_reference = reference.clone();
    let original_id = request.request_id.0.clone().unwrap();
    let same_id = original_id.clone();
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let original = read(&mut reader);
        let transfer = Id::new("compact-transfer").unwrap();
        let bodies = [
            (
                Method::BlobBegin,
                same_id,
                super::super::object(BlobBeginRequest {
                    transfer_id: transfer.clone(),
                    content: reference,
                    extensions: Extensions::new(),
                })
                .unwrap(),
            ),
            (
                Method::BlobChunk,
                Id::new("compact-chunk").unwrap(),
                super::super::object(BlobChunkRequest {
                    transfer_id: transfer.clone(),
                    offset: U64::new(0),
                    bytes: Bytes::new(payload),
                    extensions: Extensions::new(),
                })
                .unwrap(),
            ),
            (
                Method::BlobFinish,
                Id::new("compact-finish").unwrap(),
                super::super::object(BlobFinishRequest {
                    transfer_id: transfer,
                    extensions: Extensions::new(),
                })
                .unwrap(),
            ),
        ];
        let mut originals = Vec::new();
        let mut acknowledgements = Vec::new();
        for (index, (method, id, body)) in bodies.into_iter().enumerate() {
            let mut incoming = original.clone();
            incoming.method = method;
            incoming.request_id = Nullable(Some(id));
            incoming.sequence = U64::new(index as u64 + 2);
            incoming.body = body;
            write(&mut peer, &incoming);
            originals.push(incoming);
            acknowledgements.push(read(&mut reader));
        }
        let mut duplicate = originals[2].clone();
        duplicate.sequence = U64::new(5);
        write(&mut peer, &duplicate);
        let repeated_ack = read(&mut reader);
        let response = response(&original, json!({}), 6);
        write(&mut peer, &response);
        (originals, acknowledgements, repeated_ack, response)
    });

    let received = session.exchange_compact(&mut custody, &mut request, Duration::from_secs(2))?;
    let (originals, acknowledgements, repeated_ack, response) = server.join().unwrap();

    assert_eq!(received, response);
    assert_eq!(
        custody.content().get(&expected_reference)?,
        b"actual compact SDK content"
    );
    assert_eq!(
        custody
            .originals_by_origin(RequestOrigin::Controller)
            .count(),
        1
    );
    assert_eq!(
        custody.originals_by_origin(RequestOrigin::Provider).count(),
        3
    );
    assert_ne!(
        custody
            .original(RequestOrigin::Controller, &original_id)
            .unwrap()
            .identity(),
        custody
            .original(RequestOrigin::Provider, &original_id)
            .unwrap()
            .identity()
    );
    for (original, acknowledgement) in originals.iter().zip(&acknowledgements) {
        let retained = custody
            .original(
                RequestOrigin::Provider,
                original.request_id.0.as_ref().unwrap(),
            )
            .unwrap();
        assert_eq!(retained.materialize_request()?, *original);
        assert_eq!(
            retained.materialize_response()?.as_ref(),
            Some(acknowledgement)
        );
    }
    let mut expected_ack = acknowledgements[2].clone();
    expected_ack.sequence = repeated_ack.sequence;
    assert_eq!(repeated_ack, expected_ack);
    assert!(custody.pending_envelope().is_none());
    let bank_bytes: usize = custody
        .originals()
        .map(CompactClientOriginal::retained_bank_bytes)
        .sum();
    assert!(bank_bytes <= 9 * custody.retained_journal_bytes());
    assert!(custody.retained_metadata_facts()?.vector_capacity_bytes >= bank_bytes);
    Ok(())
}

#[test]
fn defining_envelope_serializer_preserves_every_field_and_number_bits() -> TestResult {
    let (_lease, _session, _custody, _peer, mut request) = fixture(BANK_BYTES);
    request.body = serde_json::from_value(
        json!({"values": [-0.0, 1.0, u64::MAX, i64::MIN], "nested": {"雪": [null, {}]}}),
    )?;
    request
        .extensions
        .insert("extension".into(), json!({"": [0, false]}));
    let expected = serde_json::to_value(&request)?;
    let via_value = CompactJson::from_value(&expected, usize::MAX)?;
    let direct = CompactJson::from_envelope(&request, usize::MAX)?;

    assert_eq!(direct.to_value()?, expected);
    assert_eq!(direct.retained_bytes(), via_value.retained_bytes());
    assert_eq!(
        serde_json::to_vec(&direct.as_serializable())?,
        serde_json::to_vec(&request)?
    );
    assert!(direct.retained_bytes() <= 9 * canonical::canonical_json(&expected)?.len());
    let restored = direct.to_value()?;
    for index in [0, 1] {
        assert!(
            restored["body"]["values"][index]
                .as_number()
                .unwrap()
                .is_f64()
        );
        assert_eq!(
            restored["body"]["values"][index]
                .as_f64()
                .unwrap()
                .to_bits(),
            expected["body"]["values"][index]
                .as_f64()
                .unwrap()
                .to_bits()
        );
    }
    assert!(CompactJson::from_envelope(&request, direct.retained_bytes() - 1).is_err());
    Ok(())
}

#[test]
fn unsupported_notification_keeps_complete_frame_and_fences_stream() -> TestResult {
    let (_lease, mut session, mut custody, mut peer, mut request) = fixture(BANK_BYTES);
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let original = read(&mut reader);
        let mut event = original.clone();
        event.message = MessageKind::Event;
        event.method = Method::ProviderFault;
        event.request_id = Nullable(None);
        event.sequence = U64::new(2);
        let notification = NotificationBody {
            operation_state: OperationState::NotStarted,
            last_observation_sequence: U64::new(0),
            details: json!({"failed_prefix": ["x".repeat(4096), {"nested": false}]})
                .as_object()
                .unwrap()
                .clone(),
            extensions: Extensions::new(),
        };
        event.body = super::super::object(&notification).unwrap();
        write(&mut peer, &event);

        // Fencing closes the real socket even while the retained frame survives.
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        (event, notification)
    });

    let result = session.exchange_compact(&mut custody, &mut request, Duration::from_secs(2));
    let (event, notification) = server.join().unwrap();

    assert!(
        matches!(result, Err(ProviderError::Correlation(_))),
        "{result:?}"
    );
    let retained = custody.unexpected_frame().unwrap();
    assert_eq!(retained.envelope, event);
    let ReceivedBody::Notification(body) = &retained.body else {
        panic!("notification typed backing was lost");
    };
    assert_eq!(body.as_ref(), &notification);
    assert!(custody.retained_metadata_facts().is_err());
    assert!(custody.pending_envelope().is_none());
    assert!(!custody.originals().next().unwrap().has_response());
    let charged = custody.retained_journal_bytes();

    assert!(
        session
            .exchange_compact(&mut custody, &mut request, Duration::from_secs(2))
            .is_err()
    );
    assert_eq!(custody.unexpected_frame().unwrap().envelope, event);
    assert_eq!(custody.retained_journal_bytes(), charged);
    assert_eq!(custody.originals().count(), 1);
    Ok(())
}
