//! Checks the owning Capture route and opposite-direction prefix on real Unix I/O.
//!
//! The Hello verifier and peer are inert models. These controls authenticate SDK
//! originals and framing only; they issue no native capture, source settlement,
//! Accepted result or preservation permission.

// crucible-lint: allow panic-shortcut -- Capture transport fixtures deliberately panic on broken invariants.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{
    client::ClientContent,
    connection::*,
    handshake::Handshake,
    protocol_snapshot::{ProtocolCaptureCut, ProtocolSnapshotReservation},
    transport::original_frames::OriginalFrameReservation,
};
use std::{io::Read, os::unix::net::UnixStream, rc::Rc};

struct Supervisor;
impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, _: ConnectionIncident) {}
}
struct Schemas;
impl BodySchemaVerifier for Schemas {
    fn verify(
        &self,
        _: &crate::handshake::ConnectionAuthority,
        _: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        Ok(())
    }
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn controller() -> (Handshake, CnpController, UnixStream) {
    let (handshake, authority) = crate::handshake::tests::controller_authority(true).unwrap();
    let (session, peer) =
        ClientSession::controller_fixture(authority, Rc::new(Supervisor), Rc::new(Schemas))
            .unwrap();
    let custody = ClientCustody::new(8, ClientContent::new(2 * 65_536, 8, 4096).unwrap()).unwrap();
    let route = ControllerRoute {
        node: id("model-node"),
        execution_owner: id("model-owner"),
    };
    let mut controller =
        CnpController::new(session, custody, route, Duration::from_secs(2)).unwrap();
    controller
        .install_native5_frame_bank(OriginalFrameReservation::reserve(262144, 8).unwrap())
        .unwrap();
    (handshake, controller, peer)
}

fn capture() -> BeginRequest {
    BeginRequest {
        kind: BeginKind::Capture,
        binding_hash: canonical::json_hash(
            "cnp.owner-binding.v1",
            &serde_json::json!({"model":true}),
        )
        .unwrap(),
        owner_generation: U64::new(1),
        activation_id: Nullable(Some(id("activation"))),
        world_generation: U64::new(1),
        arguments: serde_json::to_value(CaptureArguments {
            capture_id: id("capture"),
            participant_ids: vec![id("model-node")],
            cut_id: id("cut"),
            cut: crucible_node_format::Position::new(
                U64::new(12),
                U64::new(0),
                crucible_node_format::Phase::BoundaryControl,
            ),
            event_ordinal: U64::new(0),
            ordering_profile: "superdense-v1".into(),
            preservation_contract: id("model-complete-contract"),
        })
        .unwrap()
        .as_object()
        .unwrap()
        .clone(),
        extensions: Extensions::new(),
    }
}

fn body(value: impl Serialize) -> serde_json::Map<String, Value> {
    serde_json::to_value(value)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

#[test]
fn native5_original_controller_capture_keeps_owner_and_blob_prefix_journals() {
    let (_handshake, mut controller, peer) = controller();
    let authority = controller.authority().clone();
    let reference =
        canonical::content_ref(b"exact original prefix", "application/octet-stream").unwrap();
    let prefix_reference = reference.clone();
    let worker = std::thread::spawn(move || {
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut endpoint = Connection::new(
            peer,
            authority,
            Rc::new(Supervisor),
            Rc::new(Schemas),
            EndpointRole::Provider,
        )
        .unwrap();
        endpoint
            .install_native5_frame_bank(OriginalFrameReservation::reserve(262144, 8).unwrap())
            .unwrap();
        let original = endpoint.receive().unwrap().unwrap().envelope;
        assert_eq!(original.capture_owner_id.0, Some(id("capture-owner")));
        assert_eq!(original.node_id.0, Some(id("model-node")));
        assert!(original.execution_owner_id.0.is_none());
        assert!(original.extensions.is_empty());
        let requests = [
            (
                Method::BlobBegin,
                body(BlobBeginRequest {
                    transfer_id: id("prefix-transfer"),
                    content: prefix_reference,
                    extensions: Extensions::new(),
                }),
            ),
            (
                Method::BlobChunk,
                body(BlobChunkRequest {
                    transfer_id: id("prefix-transfer"),
                    offset: U64::new(0),
                    bytes: crucible_node_format::Bytes::new(b"exact original prefix".to_vec()),
                    extensions: Extensions::new(),
                }),
            ),
            (
                Method::BlobFinish,
                body(BlobFinishRequest {
                    transfer_id: id("prefix-transfer"),
                    extensions: Extensions::new(),
                }),
            ),
        ];
        for (index, (method, body)) in requests.into_iter().enumerate() {
            let mut request = original.clone();
            request.method = method;
            request.body = body;
            request.request_id = Nullable(Some(id(&format!("prefix-request-{index}"))));
            request.sequence = U64::new(index as u64 + 2);
            request.node_id = Nullable(None);
            request.execution_owner_id = Nullable(None);
            request.capture_owner_id = Nullable(None);
            request.operation_id = Nullable(None);
            endpoint.send(request.clone()).unwrap();
            let response = endpoint.receive().unwrap().unwrap().envelope;
            request.matches_response(&response).unwrap();
        }
        let mut response = original.clone();
        response.message = MessageKind::Response;
        response.sequence = U64::new(5);
        response.body = body(ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            error: ErrorRecord {
                code: "UNSUPPORTED_FEATURE".into(),
                message: "inert peer grants no preservation".into(),
                effect: EffectCertainty::NotStarted,
                retryable: false,
                details: serde_json::Map::new(),
            },
            extensions: Extensions::new(),
        });
        endpoint.send(response).unwrap();
        original
    });

    let result = controller
        .call_original_capture(
            id("capture-request"),
            id("capture-operation"),
            id("capture-owner"),
            capture(),
        )
        .unwrap();
    let received_original = worker.join().unwrap();
    assert!(matches!(result.shape, ResponseShape::Error { .. }));
    let retained = controller.original(&id("capture-request")).unwrap();
    assert_eq!(retained.request, received_original);
    assert!(retained.response.is_some());
    assert_eq!(
        controller
            .originals_by_origin(RequestOrigin::Provider)
            .count(),
        3
    );
    assert_eq!(
        controller.content(&reference).unwrap(),
        b"exact original prefix"
    );
    let mut reserve = ProtocolSnapshotReservation::reserve_complete(1_048_576, 262144, 8).unwrap();
    controller
        .capture_original_protocol_state(&mut reserve, ProtocolCaptureCut::HostSettled)
        .unwrap();
    let snapshot = controller
        .take_original_protocol_snapshot(&mut Some(reserve), ProtocolCaptureCut::HostSettled)
        .unwrap();
    assert!(controller.owns_original_protocol_snapshot(&snapshot));
    assert_eq!(snapshot.literal_frames().unwrap().count(), 8);
}

#[test]
fn native5_original_controller_non_capture_refuses_before_original_or_wire() {
    let (_handshake, mut controller, mut peer) = controller();
    let mut request = capture();
    request.kind = BeginKind::Shutdown;
    request.arguments = body(ShutdownArguments {
        participant_ids: vec![id("model-node")],
        reason: id("fixture"),
    });
    assert!(
        controller
            .call_original_capture(id("refused"), id("operation"), id("capture-owner"), request)
            .is_err()
    );
    assert_eq!(controller.originals().count(), 0);
    peer.set_nonblocking(true).unwrap();
    let mut byte = [0];
    assert!(
        matches!(peer.read(&mut byte), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn native5_original_controller_capture_credit_precedes_argument_decode() {
    let (_handshake, mut controller, mut peer) = controller();
    let mut request = capture();
    request.arguments.insert(
        "oversized-unknown-field".into(),
        Value::String("x".repeat(70_000)),
    );
    let result = controller.call_original_capture(
        id("oversized"),
        id("operation"),
        id("capture-owner"),
        request,
    );

    assert!(matches!(
        result,
        Err(ProviderError::ResourceExhausted(
            "generic whole-frame precredit"
        ))
    ));
    assert_eq!(controller.originals().count(), 0);
    peer.set_nonblocking(true).unwrap();
    let mut byte = [0];
    assert!(
        matches!(peer.read(&mut byte), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn native5_original_custody_facts_refuse_unsealed_baseline_bank_without_mutation() {
    let (_handshake, controller, _peer) = controller();
    let before = controller.custody.protocol_view();
    let bytes = serde_json::to_vec(&before).unwrap();
    drop(before);
    assert!(controller.original_native5_custody_facts().is_err());
    assert_eq!(
        serde_json::to_vec(&controller.custody.protocol_view()).unwrap(),
        bytes
    );
    let facts = controller.custody.original_native5_custody_facts(64);
    assert_eq!(facts.maximum_requests_per_namespace, 8);
    assert_eq!(facts.controller_originals, 0);
    assert_eq!(facts.provider_originals, 0);
    assert_eq!(facts.retained_journal_bytes, 0);
    assert_eq!(facts.maximum_journal_bytes, 2 * 65_536);
    assert_eq!(facts.negotiated_journal_entries, 64);
}

#[test]
fn native5_confirmation_refuses_legacy_codec_before_custody_or_unix_io() {
    let (_handshake, mut controller, mut peer) = controller();
    let before = serde_json::to_vec(&controller.custody.protocol_view()).unwrap();
    let reference = canonical::content_ref(b"inert snapshot", "application/json").unwrap();
    let context =
        crate::reference_packet::service::confirmation::PacketNativeAfterConfirmationRequest {
            schema: "source-owned.packet-native-after-confirmation-request/5".into(),
            capture_request_id: id("capture-request"),
            capture_request_hash: canonical::hash("cnp.request.v1", b"inert request").unwrap(),
            capture_operation_id: id("capture-operation"),
            capture_terminal_hash: canonical::hash(
                "source-owned.packet-native-capture-terminal/5",
                b"inert terminal",
            )
            .unwrap(),
            capture_terminal_sequence: U64::new(2),
            native_snapshot_ref: reference,
            native_control_ref: canonical::content_ref(b"inert control", "application/json")
                .unwrap(),
            native_anchor_ref: canonical::content_ref(b"inert anchor", "application/json").unwrap(),
        };

    assert!(matches!(
        controller.call_original_native_after_confirmation(
            id("confirmation"),
            id("capture-owner"),
            context
        ),
        Err(ProviderError::Correlation(
            "native5 actual immutable source codec is absent"
        ))
    ));
    assert_eq!(
        serde_json::to_vec(&controller.custody.protocol_view()).unwrap(),
        before
    );
    peer.set_nonblocking(true).unwrap();
    let mut byte = [0; 1];
    assert_eq!(
        peer.read(&mut byte).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn canonical_ack_lease_refuses_unselected_original_controller_before_wire() {
    let (_handshake, controller, mut peer) = controller();
    let original_count = controller.originals().count();
    assert!(
        controller
            .retain_original_canonical_blob_ack_emitter()
            .is_err()
    );
    assert_eq!(controller.originals().count(), original_count);
    peer.set_nonblocking(true).unwrap();
    let mut byte = [0];
    assert!(
        matches!(peer.read(&mut byte), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}
