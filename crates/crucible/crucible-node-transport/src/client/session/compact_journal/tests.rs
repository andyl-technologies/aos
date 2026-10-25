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

mod identity;

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
    assert!(journal_backing(&custody)? <= custody.journal_retained_storage_data(usize::MAX)?);
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
    assert!(journal_backing(&custody)? <= custody.journal_retained_storage_data(usize::MAX)?);
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
    let materialized = direct.materialize_envelope()?;
    assert_eq!(materialized, request);
    for index in [0, 1] {
        assert!(
            materialized.body["values"][index]
                .as_number()
                .unwrap()
                .is_f64()
        );
        assert_eq!(
            materialized.body["values"][index]
                .as_f64()
                .unwrap()
                .to_bits(),
            request.body["values"][index].as_f64().unwrap().to_bits()
        );
    }
    Ok(())
}

#[test]
fn compact_materialization_preserves_scalar_contracts_and_marker_key_data() -> TestResult {
    let (_lease, _session, _custody, _peer, mut request) = fixture(BANK_BYTES);
    request.node_id = Nullable(Some(Id::new("materialized-node")?));
    request.execution_owner_id = Nullable(Some(Id::new("materialized-execution")?));
    request.capture_owner_id = Nullable(Some(Id::new("materialized-capture")?));
    request.operation_id = Nullable(Some(Id::new("materialized-operation")?));
    request.sequence = U64::new(u64::MAX);
    request.body.insert(
        "marker_data".into(),
        json!({"$serde_json::private::RawValue": "ordinary DATA, not JSON syntax"}),
    );
    request.extensions.insert(
        "marker_data".into(),
        json!({"$serde_json::private::Number": {"nested": [true, false, "雪"]}}),
    );
    let mut spare = String::with_capacity(1_048_576);
    spare.push_str("owned once");
    request.body.insert("spare".into(), Value::String(spare));

    for message in [
        MessageKind::Request,
        MessageKind::Response,
        MessageKind::Event,
    ] {
        request.message = message;
        let bank = CompactJson::from_envelope(&request, usize::MAX)?;
        let capacity = bank.retained_bytes();
        let materialized = bank.materialize_envelope()?;

        assert_eq!(materialized, request);
        assert_eq!(
            serde_json::to_vec(&materialized)?,
            serde_json::to_vec(&request)?
        );
        assert_eq!(bank.retained_bytes(), capacity);
        assert_eq!(request.body["spare"].as_str(), Some("owned once"));
        let Value::String(original) = &request.body["spare"] else {
            panic!("original String changed");
        };
        assert_eq!(original.capacity(), 1_048_576);
    }
    Ok(())
}

#[test]
fn compact_materialization_checks_defining_fields_at_maximum_depth() -> TestResult {
    let (_lease, _session, _custody, _peer, mut request) = fixture(BANK_BYTES);
    let mut nested = Value::Null;
    for _ in 0..62 {
        nested = Value::Array(vec![nested]);
    }
    request.body.insert("nested".into(), nested);
    let bank = CompactJson::from_envelope(&request, usize::MAX)?;

    assert_eq!(bank.materialize_envelope()?, request);
    // Value banks are a different private constructor format: object fields
    // follow map order instead of the concrete Envelope serializer's order.
    let sorted = CompactJson::from_value(&serde_json::to_value(&request)?, usize::MAX)?;
    assert!(sorted.materialize_envelope().is_err());
    for value in [
        Value::Null,
        json!([]),
        json!({}),
        json!({"protocol": "CNP/1"}),
    ] {
        let bank = CompactJson::from_value(&value, usize::MAX)?;
        assert!(bank.materialize_envelope().is_err());
    }
    Ok(())
}

#[test]
fn envelope_preflight_matches_jcs_escaping_and_number_normalization() -> TestResult {
    let (_lease, _session, _custody, _peer, mut request) = fixture(BANK_BYTES);
    let mut text: String = (0..=127).map(char::from).collect();
    for code in [
        0x80, 0x85, 0xff, 0x100, 0x2028, 0xd7ff, 0xe000, 0xffff, 0x10000, 0x10ffff,
    ] {
        text.push(char::from_u32(code).unwrap());
    }
    request.body.insert(text.clone(), Value::String(text));
    request
        .body
        .insert("𐀀".into(), json!({"\u{e000}": [null, true, false, {}, []]}));
    let mut numbers = vec![
        json!(u64::MAX),
        json!(i64::MIN),
        json!(9_007_199_254_740_993_u64),
    ];
    for value in [-0.0, 0.0, 1.0, 1e20, 1e-7, f64::MAX, f64::from_bits(1)] {
        numbers.push(json!(value));
    }
    let mut bits = 0xd85e_56ae_5ff3_2a91_u64;
    for _ in 0..1024 {
        bits ^= bits << 13;
        bits ^= bits >> 7;
        bits ^= bits << 17;
        if let Some(number) = serde_json::Number::from_f64(f64::from_bits(bits)) {
            numbers.push(Value::Number(number));
        }
    }
    request.body.insert("numbers".into(), Value::Array(numbers));
    let expected = canonical::canonical_json(&serde_json::to_value(&request)?)?.len();
    let bank = CompactJson::from_envelope(&request, usize::MAX)?.retained_bytes();

    assert_eq!(
        CompactJson::envelope_extents(&request, bank, expected)?,
        (bank, expected)
    );
    assert!(CompactJson::envelope_extents(&request, bank - 1, expected).is_err());
    assert!(CompactJson::envelope_extents(&request, bank, expected - 1).is_err());
    Ok(())
}

#[test]
fn outgoing_preflight_refuses_unbounded_work_before_identity_validation() -> TestResult {
    for deep in [false, true] {
        let (_lease, mut session, mut custody, mut peer, mut request) = fixture(BANK_BYTES);
        // The defining hash would report this protocol error first. The size or
        // depth refusal proves the bounded preflight runs before that supplier.
        request.protocol = "not-CNP/1".into();
        let mut value = if deep {
            Value::Null
        } else {
            json!("x".repeat(CONTENT_BYTES))
        };
        if deep {
            for _ in 0..128 {
                value = Value::Array(vec![value]);
            }
        }
        request.body.insert("outside_local_bounds".into(), value);
        let original = request.clone();

        let result = session.exchange_compact(&mut custody, &mut request, Duration::from_secs(2));

        assert!(
            matches!(result, Err(ProviderError::ResourceExhausted(_))),
            "{result:?}"
        );
        assert_eq!(request, original);
        assert_eq!(custody.originals().count(), 0);
        assert_eq!(custody.retained_journal_bytes(), 0);
        assert!(custody.pending_envelope().is_none());
        assert_eq!(peer.read(&mut [0])?, 0);
    }
    Ok(())
}

#[test]
fn retry_preflight_allows_sequence_width_without_renewing_full_credit() -> TestResult {
    let (_lease, _session, _custody, _peer, request) = fixture(BANK_BYTES);
    let canonical = super::super::envelope_bytes(&request)?;
    let bank = CompactJson::from_envelope(&request, usize::MAX)?.retained_bytes();
    for origin in [RequestOrigin::Controller, RequestOrigin::Provider] {
        let content = ClientContent::new(canonical, 8, 1)?;
        let mut custody = CompactClientCustody::new(8, content, bank)?;
        custody.retain_request(origin, &request, 0)?;
        assert_eq!(custody.retained_journal_bytes(), canonical);
        let mut retry = request.clone();
        retry.sequence = U64::new(u64::MAX);

        custody.retain_request(origin, &retry, 0)?;

        assert_eq!(custody.retained_journal_bytes(), canonical);
        assert_eq!(custody.originals().count(), 1);
        let original = custody
            .original(origin, request.request_id.0.as_ref().unwrap())
            .unwrap();
        assert_eq!(original.materialize_request()?, request);
        assert_eq!(original.retained_bank_bytes(), bank);
        assert!(!original.has_response());
    }
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
    let facts = custody.retained_metadata_facts()?;
    assert!(facts.string_capacity_bytes >= 2 * 4096);
    assert!(facts.boxed_value_bytes >= std::mem::size_of::<NotificationBody>());
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

fn journal_backing(custody: &CompactClientCustody) -> Result<usize, ProviderError> {
    let mut observer = crate::retained_metadata::MetadataObserver::new();
    observer.observe(&custody.controller)?;
    observer.observe(&custody.provider)?;
    crate::retained_metadata::requested_metadata_backing_storage_data(&observer.finish())
}

#[test]
fn full_journal_projection_keeps_both_namespaces_and_unresolved_prefixes() -> TestResult {
    let (_lease, _session, mut custody, _peer, template) = fixture(BANK_BYTES);
    let quote = custody.journal_retained_storage_data(usize::MAX)?;
    let ceilings = (custody.maximum_requests, custody.maximum_bytes);

    // This fills the actual SDK owner as DATA. Existing socket controls cover
    // wire admission; these deliberately generic bodies issue no Source rights.
    for (origin, prefix) in [
        (RequestOrigin::Controller, "c"),
        (RequestOrigin::Provider, "p"),
    ] {
        for index in 0..custody.maximum_requests {
            let mut request = template.clone();
            request.request_id = Nullable(Some(Id::new(format!(
                "{prefix}{index}-{}",
                "x".repeat(120)
            ))?));
            request.body = serde_json::from_value(json!({"nested": [{"": [0, -0.0, true]}]}))?;
            custody.retain_request(origin, &request, 0)?;
            if index % 2 == 0 {
                let response = response(&request, json!({"complete": [false, {}]}), 2);
                custody.hold(origin, response)?;
                custody.complete_response(request.request_id.0.as_ref().unwrap())?;
            }
            assert!(journal_backing(&custody)? <= quote);
        }
    }

    assert_eq!(custody.controller.len(), ceilings.0);
    assert_eq!(custody.provider.len(), ceilings.0);
    assert_eq!(
        custody
            .originals()
            .filter(|entry| !entry.has_response())
            .count(),
        ceilings.0
    );
    assert_eq!(custody.journal_retained_storage_data(quote)?, quote);
    assert!(custody.journal_retained_storage_data(quote - 1).is_err());
    assert_eq!((custody.maximum_requests, custody.maximum_bytes), ceilings);
    assert_eq!(
        custody.content().original_completed_objects_data().count(),
        0
    );
    Ok(())
}

#[test]
fn bootstrap_failed_data_census_counts_typed_banks_without_eligibility() -> TestResult {
    use crate::connection::ReceivedFrame;
    use crate::reference_packet::service::{
        complete_restore::import18::bootstrap_ack::*,
        native_startup::PacketNativeStartupAllocationRow,
    };

    let (_lease, _session, mut custody, _peer, envelope) = fixture(BANK_BYTES);
    let row = PacketNativeStartupAllocationRow {
        retained_requested_bytes: U64::new(0),
        maximum_simultaneous_transient_bytes: U64::new(0),
        declared_counter_scratch_bytes: U64::new(0),
    };
    let spare_bytes = || {
        let mut bytes = Vec::with_capacity(131_072);
        bytes.extend_from_slice(&[0; 32]);
        Bytes::new(bytes)
    };
    let spare_schema = || {
        let mut schema = String::with_capacity(8192);
        schema.push_str("invalid failed-prefix DATA");
        schema
    };
    let request = PacketNativeImport18BootstrapRequest {
        schema: spare_schema(),
        recipe_identity: spare_bytes(),
        initial_funding: row,
    };
    let result = PacketNativeImport18BootstrapResult {
        schema: spare_schema(),
        state: PacketNativeImport18BootstrapAckState::BootstrapOnly,
        recipe_identity: spare_bytes(),
        initial_funding: row,
    };
    assert!(request.validate_data().is_err());
    let bodies = [
        PacketNativeImport18BootstrapReceivedBody::Request(request),
        PacketNativeImport18BootstrapReceivedBody::Response(
            PacketNativeImport18BootstrapResponseBody {
                shape: ResponseShape::Completed {
                    operation_state: OperationState::Completed,
                    result: serde_json::from_value(json!({"independent": "x".repeat(4096)}))?,
                    extensions: Extensions::new(),
                },
                result: Some(result),
            },
        ),
        PacketNativeImport18BootstrapReceivedBody::Response(
            PacketNativeImport18BootstrapResponseBody {
                shape: ResponseShape::Accepted {
                    operation_state: OperationState::NotStarted,
                    result: serde_json::from_value(json!({"ineligible_prefix": "x".repeat(4096)}))?,
                    extensions: Extensions::new(),
                },
                result: None,
            },
        ),
        PacketNativeImport18BootstrapReceivedBody::Response(
            PacketNativeImport18BootstrapResponseBody {
                shape: ResponseShape::Error {
                    operation_state: OperationState::NotStarted,
                    error: ErrorRecord {
                        code: "REFUSED".into(),
                        message: "actual saved refusal".into(),
                        effect: EffectCertainty::Unknown,
                        retryable: false,
                        details: serde_json::from_value(json!({"independent": "x".repeat(4096)}))?,
                    },
                    extensions: Extensions::new(),
                },
                result: None,
            },
        ),
    ];

    // These are unvalidated retained DTOs, not a native bootstrap exchange or
    // allocation grant. Ineligibility cannot make their real backing disappear.
    for body in bodies {
        let owns_recipe = !matches!(&body, PacketNativeImport18BootstrapReceivedBody::Response(value) if value.result.is_none());
        custody.unexpected = Some(ReceivedFrame {
            envelope: envelope.clone(),
            body: ReceivedBody::NativeImport18Bootstrap(Box::new(body)),
        });
        let facts = custody.retained_metadata_facts()?;

        assert!(
            facts.boxed_value_bytes
                >= std::mem::size_of::<PacketNativeImport18BootstrapReceivedBody>()
        );
        if owns_recipe {
            assert!(facts.vector_capacity_bytes >= 131_072);
            assert!(facts.string_capacity_bytes >= 8192);
        } else {
            assert!(facts.string_capacity_bytes >= 4096);
        }
    }
    Ok(())
}
