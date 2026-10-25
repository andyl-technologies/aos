//! Exercises the actual opaque SDK owner with a modeled registrar and real I/O.
//!
//! These controls authenticate ownership, protocol bytes and retained failure
//! prefixes. They establish no Source18 admission, native effect or R/T/S grant.

use super::*;
use crate::client::ClientContent;
use crate::connection::{
    BodySchemaVerifier, ConnectionIncident, ConnectionSupervisor, ReceivedBody,
};
use crate::handshake::{ConnectionAuthority, Handshake};
use crate::transport::{FrameReader, write_frame};
use crucible_node_format::Bytes;
use serde_json::json;
use std::{io::Read, os::unix::net::UnixStream, rc::Rc};

type TestResult = Result<(), Box<dyn std::error::Error>>;

mod identity;
mod retained;

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

fn fixture(maximum: usize) -> (Handshake, Option<CnpController>, UnixStream, ContentRef) {
    let (lease, authority) = crate::handshake::tests::controller_authority(true).unwrap();
    let (session, peer) =
        ClientSession::controller_fixture(authority, Rc::new(Supervisor), Rc::new(Schemas))
            .unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut content = ClientContent::new(262_144, 8, 4096).unwrap();
    let reference =
        canonical::content_ref(b"original content", "application/octet-stream").unwrap();
    content
        .install(reference.clone(), b"original content".to_vec())
        .unwrap();
    let custody = ClientCustody::new(maximum, content).unwrap();
    let route = ControllerRoute {
        node: id("node"),
        execution_owner: id("owner"),
    };
    let controller = CnpController::new(session, custody, route, Duration::from_secs(2)).unwrap();
    (lease, Some(controller), peer, reference)
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn body(value: impl Serialize) -> serde_json::Map<String, Value> {
    let Value::Object(object) = serde_json::to_value(value).unwrap() else {
        panic!("test object")
    };
    object
}

fn discover() -> DiscoverRequest {
    DiscoverRequest {
        profile_ids: vec![id("cnp.reference-packet/1")],
        cursor: None,
        extensions: Extensions::new(),
    }
}

fn read(reader: &mut FrameReader<UnixStream>) -> Envelope {
    serde_json::from_value(reader.read().unwrap().unwrap()).unwrap()
}

fn write(peer: &mut UnixStream, envelope: &Envelope) {
    write_frame(peer, &serde_json::to_value(envelope).unwrap(), 65_536).unwrap();
}

fn response(original: &Envelope, shape: ResponseShape, sequence: u64) -> Envelope {
    let mut response = original.clone();
    response.message = MessageKind::Response;
    response.sequence = U64::new(sequence);
    response.body = body(shape);
    response
}

fn refusal(original: &Envelope, sequence: u64) -> Envelope {
    response(
        original,
        ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            error: ErrorRecord {
                code: "UNSUPPORTED_FEATURE".into(),
                message: "modeled refusal".into(),
                effect: EffectCertainty::NotStarted,
                retryable: false,
                details: serde_json::Map::new(),
            },
            extensions: Extensions::new(),
        },
        sequence,
    )
}

fn completed(original: &Envelope, reference: &ContentRef, sequence: u64) -> Envelope {
    response(
        original,
        ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: body(BlobFinishResult {
                transfer_id: id("controller-transfer"),
                content: reference.clone(),
            }),
            extensions: Extensions::new(),
        },
        sequence,
    )
}

fn prefix(controller: &CnpController) -> Vec<u8> {
    serde_json::to_vec(&controller.custody.originals().collect::<Vec<_>>()).unwrap()
}

fn blob(
    original: &Envelope,
    reference: &ContentRef,
    bytes: &[u8],
    index: usize,
    sequence: u64,
) -> Envelope {
    let mut request = original.clone();
    request.message = MessageKind::Request;
    request.sequence = U64::new(sequence);
    request.request_id = Nullable(Some(id([
        "provider-begin",
        "provider-chunk",
        "provider-finish",
    ][index])));
    request.method = [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish][index];
    request.body = match index {
        0 => body(BlobBeginRequest {
            transfer_id: id("provider-transfer"),
            content: reference.clone(),
            extensions: Extensions::new(),
        }),
        1 => body(BlobChunkRequest {
            transfer_id: id("provider-transfer"),
            offset: U64::new(0),
            bytes: Bytes::new(bytes.to_vec()),
            extensions: Extensions::new(),
        }),
        2 => body(BlobFinishRequest {
            transfer_id: id("provider-transfer"),
            extensions: Extensions::new(),
        }),
        _ => panic!("test blob index"),
    };
    request
}

#[test]
fn opaque_owner_preserves_original_actor_content_credit_and_cached_reply() -> TestResult {
    let (_lease, mut original, mut peer, installed) = fixture(8);
    let reference = canonical::content_ref(b"runtime content", "application/octet-stream")?;
    let peer_reference = reference.clone();
    let (done, wait) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let first = read(&mut reader);
        write(&mut peer, &refusal(&first, 2));
        let second = read(&mut reader);
        assert_eq!(second.sequence, U64::new(3));
        write(&mut peer, &completed(&second, &peer_reference, 3));
        for index in 0..3 {
            let request = blob(
                &second,
                &peer_reference,
                b"runtime content",
                index,
                index as u64 + 4,
            );
            write(&mut peer, &request);
            let acknowledgement = read(&mut reader);
            request.matches_response(&acknowledgement).unwrap();
        }
        wait.recv_timeout(Duration::from_secs(5)).unwrap();
        peer.set_nonblocking(true).unwrap();
        assert!(
            matches!(peer.read(&mut [0]), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    });
    let controller = original.as_mut().unwrap();
    let unspent_journal =
        controller.original_compact_runtime_journal_retained_storage_data(usize::MAX)?;
    let first = controller.call(id("legacy"), None, Method::Discover, false, discover())?;
    let before = prefix(controller);
    let pointer = controller.content(&installed)?.as_ptr();
    let actor = Rc::downgrade(&controller.protocol_owner);
    let [maximum, used] = controller.custody.runtime_journal_bytes_data();
    let journal = controller.original_compact_runtime_journal_retained_storage_data(usize::MAX)?;
    assert_eq!(unspent_journal - journal, 9 * used);
    assert_eq!(
        controller.original_compact_runtime_journal_retained_storage_data(journal)?,
        journal
    );
    assert!(
        controller
            .original_compact_runtime_journal_retained_storage_data(journal - 1)
            .is_err()
    );
    let mut output = None;

    CompactRuntimeController::retain_into(&mut original, &mut output)?;

    assert!(original.is_none());
    let runtime = output.as_mut().unwrap();
    assert!(std::rc::Weak::ptr_eq(
        &actor,
        &Rc::downgrade(&runtime.original.protocol_owner)
    ));
    assert_eq!(runtime.content(&installed)?.as_ptr(), pointer);
    assert_eq!(runtime.journal_byte_reservations_data(), [maximum, used, 0]);
    assert_eq!(runtime.journal.retained_storage_data(usize::MAX)?, journal);
    assert_eq!(prefix(&runtime.original), before);

    let reply = runtime.call(
        id("runtime"),
        None,
        Method::BlobFinish,
        false,
        BlobFinishRequest {
            transfer_id: id("controller-transfer"),
            extensions: Extensions::new(),
        },
    )?;

    assert!(matches!(reply.shape, ResponseShape::Completed { .. }));
    assert_eq!(runtime.content(&reference)?, b"runtime content");
    assert_eq!(runtime.content(&installed)?.as_ptr(), pointer);
    assert_eq!(prefix(&runtime.original), before);
    assert_eq!(
        runtime.legacy_originals(RequestOrigin::Controller).count(),
        1
    );
    assert_eq!(
        runtime.compact_originals(RequestOrigin::Controller).count(),
        1
    );
    assert_eq!(
        runtime.compact_originals(RequestOrigin::Provider).count(),
        3
    );
    let [ceiling, prefix_used, suffix_used] = runtime.journal_byte_reservations_data();
    assert_eq!([ceiling, prefix_used], [maximum, used]);
    assert!(prefix_used + suffix_used <= ceiling);
    let charged = runtime.journal_byte_reservations_data();

    let cached = runtime.call(id("legacy"), None, Method::Discover, false, discover())?;

    assert_eq!(cached, first);
    assert_eq!(runtime.journal_byte_reservations_data(), charged);
    assert_eq!(prefix(&runtime.original), before);
    done.send(())?;
    server.join().unwrap();
    Ok(())
}

#[test]
fn original_journal_quote_remains_data_after_fencing_without_authorizing_handoff() -> TestResult {
    let (_lease, mut original, _peer, _) = fixture(256);
    let controller = original.as_mut().unwrap();
    let quote = controller.original_compact_runtime_journal_retained_storage_data(usize::MAX)?;
    let debit = controller.custody.runtime_journal_bytes_data();

    controller.fence();

    assert_eq!(
        controller.original_compact_runtime_journal_retained_storage_data(quote)?,
        quote
    );
    assert_eq!(controller.custody.runtime_journal_bytes_data(), debit);
    assert!(CnpController::original_compact_runtime_journal_retained_counter_scratch_data() > 0);
    let mut output = None;
    assert!(CompactRuntimeController::retain_into(&mut original, &mut output).is_err());
    assert!(original.is_some());
    assert!(output.is_none());
    Ok(())
}

#[test]
fn refusal_preserves_input_and_occupied_output_slots() -> TestResult {
    let (_lease, mut original, mut peer, _) = fixture(8);
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        read(&mut reader);
        peer.read(&mut [0]).unwrap()
    });
    let controller = original.as_mut().unwrap();
    // The actual write retains an unanswered original and unresolved guard.
    let response = controller.call(id("unsettled"), None, Method::Discover, false, discover());
    assert!(response.is_err());
    let before = prefix(controller);
    let mut output = None;

    assert!(CompactRuntimeController::retain_into(&mut original, &mut output).is_err());

    assert!(output.is_none());
    assert_eq!(prefix(original.as_ref().unwrap()), before);
    original.as_mut().unwrap().fence();
    assert_eq!(server.join().unwrap(), 0);

    let (_lease, mut replacement, _peer, _) = fixture(8);
    CompactRuntimeController::retain_into(&mut replacement, &mut output)?;
    let (_other_lease, mut other, _other_peer, _) = fixture(8);
    let actor = Rc::downgrade(&other.as_ref().unwrap().protocol_owner);
    let occupied = output.as_ref().unwrap() as *const CompactRuntimeController;

    assert!(CompactRuntimeController::retain_into(&mut other, &mut output).is_err());

    assert!(std::rc::Weak::ptr_eq(
        &actor,
        &Rc::downgrade(&other.as_ref().unwrap().protocol_owner)
    ));
    assert_eq!(
        output.as_ref().unwrap() as *const CompactRuntimeController,
        occupied
    );
    Ok(())
}

#[test]
fn content_wait_retains_notification_and_fences_later_calls() -> TestResult {
    let (_lease, mut original, mut peer, _) = fixture(8);
    let reference = canonical::content_ref(b"promised", "application/octet-stream")?;
    let mut output = None;
    CompactRuntimeController::retain_into(&mut original, &mut output)?;
    let runtime = output.as_mut().unwrap();
    let before = prefix(&runtime.original);
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let original = read(&mut reader);
        write(&mut peer, &completed(&original, &reference, 2));
        let mut event = original;
        event.message = MessageKind::Event;
        event.method = Method::ProviderFault;
        event.request_id = Nullable(None);
        event.sequence = U64::new(3);
        let notification = NotificationBody {
            operation_state: OperationState::NotStarted,
            last_observation_sequence: U64::new(0),
            details: json!({"original_details": "x".repeat(1024)})
                .as_object()
                .unwrap()
                .clone(),
            extensions: Extensions::new(),
        };
        event.body = body(&notification);
        write(&mut peer, &event);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        (event, notification)
    });

    assert!(
        runtime
            .call(
                id("runtime"),
                None,
                Method::BlobFinish,
                false,
                BlobFinishRequest {
                    transfer_id: id("controller-transfer"),
                    extensions: Extensions::new()
                }
            )
            .is_err()
    );

    let (event, notification) = server.join().unwrap();
    let retained = runtime.unexpected_frame().unwrap();
    assert_eq!(retained.envelope, event);
    let ReceivedBody::Notification(body) = &retained.body else {
        panic!("typed notification custody")
    };
    assert_eq!(body.as_ref(), &notification);
    assert!(runtime.pending_envelope().is_none());
    assert_eq!(prefix(&runtime.original), before);
    assert!(
        runtime
            .compact_originals(RequestOrigin::Controller)
            .next()
            .unwrap()
            .has_response()
    );
    let mut observer = crate::retained_metadata::MetadataObserver::new();
    runtime.journal.observe_runtime_metadata(&mut observer)?;
    let facts = observer.finish();
    assert!(facts.string_capacity_bytes >= 2 * 1024);
    let used = runtime.journal_byte_reservations_data();

    assert!(
        runtime
            .call(id("later"), None, Method::Discover, false, discover())
            .is_err()
    );

    assert_eq!(runtime.journal_byte_reservations_data(), used);
    assert_eq!(runtime.unexpected_frame().unwrap().envelope, event);
    Ok(())
}

#[test]
fn promised_content_cannot_renew_the_exhausted_provider_namespace() -> TestResult {
    let (_lease, mut original, mut peer, _) = fixture(3);
    let old_reference = canonical::content_ref(b"old", "application/octet-stream")?;
    let new_reference = canonical::content_ref(b"new", "application/octet-stream")?;
    let peer_reference = new_reference.clone();
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let first = read(&mut reader);
        for index in 0..3 {
            let request = blob(&first, &old_reference, b"old", index, index as u64 + 2);
            write(&mut peer, &request);
            read(&mut reader);
        }
        write(&mut peer, &refusal(&first, 5));
        let next = read(&mut reader);
        write(&mut peer, &completed(&next, &peer_reference, 6));
        let mut incoming = blob(&next, &peer_reference, b"new", 0, 7);
        incoming.request_id = Nullable(Some(id("overflow-provider")));
        write(&mut peer, &incoming);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        incoming
    });
    original
        .as_mut()
        .unwrap()
        .call(id("legacy"), None, Method::Discover, false, discover())?;
    let before = prefix(original.as_ref().unwrap());
    let mut output = None;
    CompactRuntimeController::retain_into(&mut original, &mut output)?;
    let runtime = output.as_mut().unwrap();

    assert!(
        runtime
            .call(
                id("runtime"),
                None,
                Method::BlobFinish,
                false,
                BlobFinishRequest {
                    transfer_id: id("controller-transfer"),
                    extensions: Extensions::new()
                }
            )
            .is_err()
    );

    let expected = server.join().unwrap();
    assert_eq!(
        runtime.pending_envelope(),
        Some((RequestOrigin::Provider, &expected))
    );
    assert_eq!(
        runtime.compact_originals(RequestOrigin::Provider).count(),
        0
    );
    assert_eq!(runtime.legacy_originals(RequestOrigin::Provider).count(), 3);
    assert_eq!(prefix(&runtime.original), before);
    assert!(runtime.content(&new_reference).is_err());
    Ok(())
}
