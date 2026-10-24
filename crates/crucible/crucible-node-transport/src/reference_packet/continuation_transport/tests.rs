//! Exercises original Unix-stream prefix custody using model-only source installation.

#![allow(clippy::unwrap_used)]

use std::{
    cell::RefCell,
    io::{Read, Write},
    os::unix::net::UnixStream,
    rc::Rc,
    thread,
    time::Duration,
};

use crucible_node_format::{Extensions, U64, canonical};
use serde_json::json;

use super::*;
use crate::{handshake::ConnectionAuthority, transport::write_frame};

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
        original: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        if !original.extensions.is_empty() {
            return Err(ProviderError::Correlation("test extension"));
        }
        Ok(())
    }
}

fn object(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    value.as_object().unwrap().clone()
}

fn request(authority: &ConnectionAuthority) -> Envelope {
    Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(authority.session_id().clone())),
        incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
        node_id: Nullable(Some(Id::new("node").unwrap())),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(Some(Id::new("owner").unwrap())),
        operation_id: Nullable(Some(Id::new("capture-operation").unwrap())),
        request_id: Nullable(Some(Id::new("capture-request").unwrap())),
        sequence: U64::new(2),
        method: Method::Begin,
        body: object(
            json!({"kind":"capture", "binding_hash":{"algorithm":"blake3-256","digest":"a".repeat(64),"domain":"cnp.owner-binding.v1"},
            "owner_generation":"1","activation_id":"activation","world_generation":"1",
            "arguments":{"capture_id":"capture","participant_ids":["node"],"cut_id":"cut",
                "cut":{"time_ps":"6","microstep":"1","phase":1},"event_ordinal":"1",
                "ordering_profile":"superdense-v1","preservation_contract":"source-owned.packet-complete-original-lineage/5"},"extensions":{}}),
        ),
        extensions: Extensions::new(),
    }
}

struct CaptureBodies {
    response: Envelope,
    snapshot: (ContentRef, Vec<u8>),
    anchor: (ContentRef, Vec<u8>),
}

fn source(request: &Envelope) -> CaptureBodies {
    let snapshot = vec![7; 1300];
    let anchor = b"anchor5".to_vec();
    let snapshot_ref = canonical::content_ref(&snapshot, "application/octet-stream").unwrap();
    let anchor_ref = canonical::content_ref(&anchor, "application/octet-stream").unwrap();
    let mut response = request.clone();
    response.message = MessageKind::Response;
    response.body = object(
        json!({"status":"completed","operation_state":"completed","extensions":{},
        "result":{"capture_manifest":snapshot_ref,"owner_state_refs":[],"unchanged_cut_receipt":anchor_ref}}),
    );
    CaptureBodies {
        response,
        snapshot: (snapshot_ref, snapshot),
        anchor: (anchor_ref, anchor),
    }
}

fn fixture() -> (
    crate::handshake::Handshake,
    PacketCapturePrefix<UnixStream>,
    UnixStream,
    Rc<Supervisor>,
    Envelope,
) {
    let (handshake, authority) = crate::handshake::tests::authority();
    let (stream, mut peer) = UnixStream::pair().unwrap();
    for stream in [&stream, &peer] {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    let original = request(&authority);
    write_frame(&mut peer, &serde_json::to_value(&original).unwrap(), 4096).unwrap();
    let supervisor = Rc::new(Supervisor::default());
    let mut connection = Connection::new(
        stream,
        authority,
        supervisor.clone(),
        Rc::new(Schemas),
        EndpointRole::Provider,
    )
    .unwrap();
    assert_eq!(connection.receive().unwrap().unwrap().envelope, original);
    (
        handshake,
        PacketCapturePrefix::new(connection),
        peer,
        supervisor,
        original,
    )
}

fn read_frame(stream: &mut UnixStream) -> Envelope {
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let mut body = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn reply(
    original: &Envelope,
    sequence: u64,
    contents: &mut BTreeMap<Id, ContentRef>,
    corrupt: bool,
) -> Envelope {
    let result = match decode_request(original.method, &original.body).unwrap() {
        RequestBody::BlobBegin(begin) => {
            contents.insert(begin.transfer_id.clone(), begin.content);
            serde_json::to_value(BlobBeginResult {
                transfer_id: begin.transfer_id,
                next_offset: U64::new(0),
                maximum_chunk_bytes: U64::new(512),
            })
            .unwrap()
        }
        RequestBody::BlobChunk(chunk) => serde_json::to_value(BlobChunkResult {
            transfer_id: chunk.transfer_id,
            next_offset: U64::new(
                chunk.offset.get() + chunk.bytes.as_slice().len() as u64 + u64::from(corrupt),
            ),
        })
        .unwrap(),
        RequestBody::BlobFinish(finish) => serde_json::to_value(BlobFinishResult {
            content: if corrupt {
                canonical::content_ref(b"foreign-full-reference", "application/octet-stream")
                    .unwrap()
            } else {
                contents[&finish.transfer_id].clone()
            },
            transfer_id: finish.transfer_id,
        })
        .unwrap(),
        _ => panic!("unexpected original transfer"),
    };
    let mut response = original.clone();
    response.message = MessageKind::Response;
    response.sequence = U64::new(sequence);
    response.body = object(
        json!({"status":"completed","operation_state":"completed","result":result,"extensions":{}}),
    );
    response
}

#[test]
fn complete_original_prefix_crosses_windows_without_resetting_sequences() {
    let (_handshake, mut prefix, mut peer, supervisor, original) = fixture();
    let CaptureBodies {
        response,
        snapshot,
        anchor,
    } = source(&original);
    prefix.prepare(response.clone(), snapshot, anchor).unwrap();
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut [0]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    peer.set_nonblocking(false).unwrap();
    let worker = thread::spawn(move || {
        let mut contents = BTreeMap::new();
        let mut originals = Vec::new();
        for sequence in 3..11 {
            let original = read_frame(&mut peer);
            let response = reply(&original, sequence, &mut contents, false);
            write_frame(&mut peer, &serde_json::to_value(response).unwrap(), 4096).unwrap();
            originals.push(original);
        }
        let mut expected = response;
        expected.sequence = U64::new(10);
        assert_eq!(read_frame(&mut peer), expected);
        originals
    });
    prefix.publish().unwrap();
    let originals = worker.join().unwrap();
    assert!(prefix.is_complete());
    assert_eq!(prefix.records().len(), 5);
    assert_eq!(prefix.next_sequence(), 11);
    assert_eq!(
        prefix
            .records()
            .iter()
            .map(|r| r.acknowledgements().len())
            .sum::<usize>(),
        8
    );
    assert_eq!(
        prefix
            .records()
            .iter()
            .flat_map(|r| r.originals())
            .filter(|r| r.message == MessageKind::Request)
            .cloned()
            .collect::<Vec<_>>(),
        originals
    );
    assert!(prefix.publish().is_err());
    let original_connection = prefix.take_completed_connection().unwrap();
    assert!(prefix.take_completed_connection().is_err());
    assert!(supervisor.0.borrow().is_empty());
    drop(original_connection);
    assert_eq!(supervisor.0.borrow().len(), 1);
}

#[test]
fn changed_ack_retains_completed_and_active_original_windows_without_retry() {
    let (_handshake, mut prefix, mut peer, supervisor, original) = fixture();
    let CaptureBodies {
        response,
        snapshot,
        anchor,
    } = source(&original);
    prefix.prepare(response, snapshot, anchor).unwrap();
    let worker = thread::spawn(move || {
        let mut contents = BTreeMap::new();
        for sequence in 3..6 {
            let original = read_frame(&mut peer);
            let response = reply(&original, sequence, &mut contents, sequence == 5);
            write_frame(&mut peer, &serde_json::to_value(response).unwrap(), 4096).unwrap();
        }
        peer.flush().unwrap();
    });
    assert!(prefix.publish().is_err());
    worker.join().unwrap();
    assert_eq!(prefix.records().len(), 1);
    let active = prefix.incomplete_window().unwrap();
    assert_eq!(active.sent(), 1);
    assert_eq!(supervisor.0.borrow()[0].outgoing.len(), 2);
    assert_eq!(active.acknowledgements().len(), 0);
    assert_eq!(active.originals().len(), 2);
    assert!(!prefix.is_complete());
    assert!(prefix.publish().is_err());
    assert!(prefix.take_completed_connection().is_err());
    assert_eq!(supervisor.0.borrow().len(), 1);
}

#[test]
fn changed_full_finish_reference_is_retained_before_source_refusal() {
    let (_handshake, mut prefix, mut peer, supervisor, original) = fixture();
    let CaptureBodies {
        response,
        snapshot,
        anchor,
    } = source(&original);
    prefix.prepare(response, snapshot, anchor).unwrap();
    let worker = thread::spawn(move || {
        let mut contents = BTreeMap::new();
        for sequence in 3..8 {
            let original = read_frame(&mut peer);
            let response = reply(&original, sequence, &mut contents, sequence == 7);
            write_frame(&mut peer, &serde_json::to_value(response).unwrap(), 4096).unwrap();
        }
    });
    assert!(prefix.publish().is_err());
    worker.join().unwrap();
    assert_eq!(prefix.records().len(), 2);
    let active = prefix.incomplete_window().unwrap();
    assert_eq!(active.sent(), 1);
    assert_eq!(active.acknowledgements().len(), 1);
    assert_eq!(active.originals().len(), 2);
    assert!(!prefix.is_complete());
    assert!(prefix.publish().is_err());
    assert!(prefix.take_completed_connection().is_err());
    assert_eq!(supervisor.0.borrow().len(), 1);
}

#[test]
fn oversized_source_bodies_refuse_before_any_original_publication() {
    for snapshot_oversized in [false, true] {
        let (_handshake, mut prefix, mut peer, _supervisor, original) = fixture();
        let mut bodies = source(&original);
        let body = if snapshot_oversized {
            &mut bodies.snapshot
        } else {
            &mut bodies.anchor
        };
        body.1 = vec![
            7;
            if snapshot_oversized {
                MAXIMUM_CAPTURE_SNAPSHOT_BYTES + 1
            } else {
                MAXIMUM_CAPTURE_ANCHOR_BYTES + 1
            }
        ];
        body.0 = canonical::content_ref(&body.1, "application/octet-stream").unwrap();
        bodies.response.body = object(
            json!({"status":"completed","operation_state":"completed","extensions":{},
            "result":{"capture_manifest":bodies.snapshot.0,"owner_state_refs":[],"unchanged_cut_receipt":bodies.anchor.0}}),
        );
        assert!(matches!(
            prefix.prepare(bodies.response, bodies.snapshot, bodies.anchor),
            Err(ProviderError::ResourceExhausted(
                "capture snapshot/anchor closure"
            ))
        ));
        assert!(prefix.records().is_empty());
        assert!(prefix.incomplete_window().is_none());
        assert!(prefix.publish().is_err());
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn final_anchor_ack_refusal_keeps_completed_capture_response_unsent() {
    let (_handshake, mut prefix, mut peer, _supervisor, original) = fixture();
    let CaptureBodies {
        response,
        snapshot,
        anchor,
    } = source(&original);
    prefix.prepare(response, snapshot, anchor).unwrap();
    let worker = thread::spawn(move || {
        let mut contents = BTreeMap::new();
        for sequence in 3..11 {
            let original = read_frame(&mut peer);
            assert_eq!(original.message, MessageKind::Request);
            let response = reply(&original, sequence, &mut contents, sequence == 10);
            write_frame(&mut peer, &serde_json::to_value(response).unwrap(), 4096).unwrap();
        }
        peer
    });

    assert!(prefix.publish().is_err());
    let mut peer = worker.join().unwrap();
    assert_eq!(prefix.records().len(), 3);
    let current = prefix.incomplete_window().unwrap();
    assert_eq!(current.sent(), 2);
    assert_eq!(current.acknowledgements().len(), 2);
    assert!(
        prefix
            .records()
            .iter()
            .flat_map(ExchangeRecord::originals)
            .chain(current.originals())
            .all(|frame| frame.message == MessageKind::Request)
    );
    let terminal = prefix.windows.back().unwrap();
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0].message, MessageKind::Response);
    assert_eq!(terminal[0].sequence, U64::new(10));
    assert!(!prefix.is_complete());
    assert!(prefix.publish().is_err());
    assert!(prefix.take_completed_connection().is_err());

    peer.set_nonblocking(true).unwrap();
    match peer.read(&mut [0]) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("completed Capture response escaped after refused final ACK: {other:?}"),
    }
}
