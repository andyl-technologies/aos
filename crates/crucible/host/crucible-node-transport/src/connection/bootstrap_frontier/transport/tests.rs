//! Exercises actual Unix originals with inert model negotiation and MAC DATA.
//!
//! These tests issue no Source recipe, initial escrow or completion permission.

use super::*;
use crate::envelope::Nullable;
use crate::handshake::*;
use crate::reference_packet::control::PacketControlSelection;
use crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::*;
use crate::reference_packet::service::complete_restore::import18::*;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use crate::reference_service::InstalledContent;
use crate::transport::original_frames::OriginalFrameReservation;
use crucible_node_format::{
    Bytes, ContentRef, Extensions, IdSet, ProviderManifest, SchemaRef, U64,
};
use std::io::Read;
use std::os::unix::net::UnixStream;

struct Supervisor;

impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, _: ConnectionIncident) {}
}

struct Uninstalled;

impl BodySchemaVerifier for Uninstalled {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        _: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        Err(refused())
    }
}

struct ModelVerifier;
impl TrustedHandshakeVerifier for ModelVerifier {
    fn authenticate_exchange(
        &mut self,
        _: &Id,
        _: &TrustedInstallation,
        _: &HelloRequest,
        _: &HelloResult,
    ) -> Result<(), ProviderError> {
        Ok(())
    }
    fn verify_contract_selection(
        &mut self,
        _: &ProviderManifest,
        _: &IdSet,
        _: &[SchemaRef],
        _: &ContentRef,
    ) -> Result<(), ProviderError> {
        Ok(())
    }
    fn resume_custody(
        &mut self,
        _: &Id,
        _: &Id,
        _: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        Ok(Vec::new())
    }
    fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
        Ok(())
    }
}

fn id(text: &str) -> Id {
    Id::new(text).unwrap()
}

fn scope() -> (Handshake, Connection<UnixStream>, UnixStream) {
    scope_with_declaration_fault(None)
}

fn scope_with_declaration_fault(
    fault: Option<usize>,
) -> (Handshake, Connection<UnixStream>, UnixStream) {
    let (_, _, _, installed) =
        crate::reference_packet::coordinator::original_native5_controller_scope();
    let mut coordinator: PacketNative5CoordinatorInstallation =
        serde_json::from_slice(installed.bytes.as_slice()).unwrap();
    let selection = &mut coordinator.participants[0];
    for schema in [
        native_import18_schema_data().unwrap(),
        native_import18_stage_schema_data().unwrap(),
        native_import18_restored_record_schema_data().unwrap(),
    ] {
        selection.provider.implementation.formats.push(schema);
    }
    selection
        .provider
        .implementation
        .formats
        .sort_by(|a, b| a.id.cmp(&b.id));
    for feature in native_import18_declared_features_data() {
        selection.provider.extensions_supported.push(id(feature));
    }
    selection.provider.extensions_supported.sort();
    selection.provider.extensions_supported.dedup();
    if let Some(which @ 0..=2) = fault {
        let absent = native_import18_declared_features_data()[which];
        selection
            .provider
            .implementation
            .formats
            .retain(|schema| schema.id.as_str() != absent);
    }
    selection.realization.bindings[0]
        .compatibility
        .implementation = selection.provider.implementation.clone();
    let manifest =
        canonical::canonical_json(&serde_json::to_value(&selection.provider).unwrap()).unwrap();
    selection.realization.provider_manifest =
        canonical::content_ref(&manifest, "application/json").unwrap();
    selection.realization.owner_bindings[0].node_bindings[0].binding_hash =
        selection.realization.bindings[0].identity().unwrap();
    coordinator.template["nodes"][0]["binding"] =
        serde_json::to_value(&selection.realization.bindings[0]).unwrap();
    coordinator.template["owner_bindings"][0] =
        serde_json::to_value(&selection.realization.owner_bindings[0]).unwrap();
    let mut world: crucible_node_format::WorldBinding =
        serde_json::from_value(coordinator.template["world"].clone()).unwrap();
    world.node_bindings[0].binding_hash = selection.realization.bindings[0].identity().unwrap();
    let world_identity = world.identity().unwrap();
    coordinator.template["world"] = serde_json::to_value(&world).unwrap();
    coordinator.template["activation"]["world_binding_hash"] =
        serde_json::to_value(&world_identity).unwrap();
    for participant in &mut coordinator.participants {
        participant.world = world_identity.clone();
    }
    let selection: PacketControlSelection = coordinator.participants[0].clone();
    let binding = &selection.realization.bindings[0];
    let session = binding.authority.session_id.clone();
    let incarnation = binding.authority.incarnation_id.clone();
    let mut features = vec![
        id("cnp.core/1"),
        id("cnp.control-evidence/1"),
        id(crate::reference_packet::input::PACKET_INPUT_FEATURE),
        id(crate::reference_packet::continuation_contracts::PACKET_COMPLETE_LINEAGE_FEATURE),
    ];
    features.extend(native_import18_declared_features_data().map(id));
    features.sort();
    if fault == Some(3) {
        features.retain(|feature| feature.as_str() != NATIVE_IMPORT18_BOOTSTRAP_FEATURE);
    }
    let limits = Limits {
        frame_bytes: U64::new(65536),
        nesting: U64::new(64),
        requests: U64::new(8),
        journal_entries: U64::new(64),
        blob_chunk_bytes: U64::new(4096),
    };
    let mut keys = std::collections::BTreeMap::new();
    let input = crate::reference_packet::input::PACKET_INPUT_FEATURE;
    keys.insert(input.into(), id(input));
    keys.insert(
        NATIVE_IMPORT18_EXTENSION.into(),
        id(NATIVE_IMPORT18_EXTENSION),
    );
    for phase in [
        PacketNativeImport18Phase::Prepare,
        PacketNativeImport18Phase::Commit,
    ] {
        for key in [
            phase.request_extension(),
            phase.proof_extension(),
            phase.receipt_extension(),
        ] {
            keys.insert(key.into(), id(NATIVE_IMPORT18_EXTENSION));
        }
    }
    for key in [
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF,
        NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT,
    ] {
        keys.insert(key.into(), id(NATIVE_IMPORT18_BOOTSTRAP_FEATURE));
    }
    match fault {
        Some(3) => {
            keys.remove(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF);
            keys.remove(NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT);
        }
        Some(4) => {
            keys.remove(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF);
        }
        Some(5) => {
            keys.remove(NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT);
        }
        _ => {}
    }
    let mut handshake = Handshake::new(
        TrustedInstallation {
            session_id: session.clone(),
            incarnation_id: incarnation.clone(),
            measured_implementation: selection.provider.implementation.clone(),
            launch_receipt: selection.admission_receipt.clone(),
            admission_token: [7; 32],
        },
        NegotiationPolicy {
            supported_features: features.clone(),
            required_features: features.clone(),
            provider_limits: limits,
            required_schemas: Vec::new(),
            required_guarantees: binding.compatibility.guarantees_ref.clone(),
            envelope_extension_features: keys,
        },
    )
    .unwrap();
    let hello = HelloRequest {
        versions: vec!["CNP/1".into()],
        session_id: session.clone(),
        controller_nonce: Bytes::new(vec![3; 32]),
        required_features: features.clone(),
        optional_features: Vec::new(),
        limits,
        admission_token: Bytes::new(vec![7; 32]),
        resume_session: None,
        extensions: Extensions::new(),
    };
    let result = HelloResult {
        version: "CNP/1".into(),
        session_id: session,
        incarnation_id: incarnation,
        controller_nonce: hello.controller_nonce.clone(),
        provider_nonce: Bytes::new(vec![5; 32]),
        selected_features: features,
        limits,
        resume_token: Nullable(None),
        provider_identity: selection.provider.clone(),
        resumed_operations: Vec::new(),
    };
    let authority = handshake
        .admit_exchange(
            &hello,
            &result,
            id("bootstrap-model-connection"),
            &mut ModelVerifier,
        )
        .unwrap();
    let bytes = canonical::canonical_json(&serde_json::to_value(coordinator).unwrap()).unwrap();
    let installed = InstalledContent {
        reference: canonical::content_ref(&bytes, "application/json").unwrap(),
        bytes: Bytes::new(bytes),
    };
    let (stream, peer) = UnixStream::pair().unwrap();
    let mut connection = Connection::new(
        stream,
        authority,
        Rc::new(Supervisor),
        Rc::new(Uninstalled),
        EndpointRole::Controller,
    )
    .unwrap();
    connection
        .install_native5_controller_codec(
            &mut Some(OriginalFrameReservation::reserve(262144, 8).unwrap()),
            selection,
            installed,
        )
        .unwrap();
    (handshake, connection, peer)
}

fn proposal(
    connection: &Connection<UnixStream>,
) -> (
    Envelope,
    PacketNativeImport18BootstrapRequest,
    PacketNativeImport18BootstrapAckProof,
) {
    let request = PacketNativeImport18BootstrapRequest {
        schema: NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA.into(),
        recipe_identity: Bytes::new(vec![1; 32]),
        initial_funding: PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(1),
            maximum_simultaneous_transient_bytes: U64::new(2),
            declared_counter_scratch_bytes: U64::new(3),
        },
    };
    let mut original = crate::envelope::tests::request();
    original.method = Method::NativeImport18Bootstrap;
    original.sequence = U64::new(2);
    original.session_id = Nullable(Some(connection.authority.session_id().clone()));
    original.incarnation_id = Nullable(Some(connection.authority.incarnation_id().clone()));
    original.node_id = Nullable(None);
    original.execution_owner_id = Nullable(None);
    original.capture_owner_id = Nullable(None);
    original.operation_id = Nullable(None);
    original.body = serde_json::to_value(&request)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    original.extensions.clear();
    // Structurally valid bytes deliberately carry no Source authentication claim.
    let proof = PacketNativeImport18BootstrapAckProof {
        schema: NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
        algorithm: "blake3-keyed-canonical/1".into(),
        context_digest: Bytes::new(vec![2; 32]),
        mac: Bytes::new(vec![3; 32]),
    };
    (original, request, proof)
}

fn seal(
    connection: &mut Connection<UnixStream>,
) -> (
    Envelope,
    PacketNativeImport18BootstrapRequest,
    PacketNativeImport18BootstrapAckProof,
    Vec<u8>,
    Option<usize>,
) {
    let (mut original, request, proof) = proposal(connection);
    let mut slot = None;
    connection
        .reserve_original_bootstrap_data(&original, &request, 65536, &mut slot)
        .unwrap();
    original.extensions.insert(
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
        serde_json::to_value(&proof).unwrap(),
    );
    let bytes = canonical::canonical_json(&serde_json::to_value(&original).unwrap()).unwrap();
    connection
        .seal_original_bootstrap_data(&original, &request, &proof, &bytes, slot)
        .unwrap();
    (original, request, proof, bytes, slot)
}

fn response(
    original: &Envelope,
    request: &PacketNativeImport18BootstrapRequest,
) -> serde_json::Value {
    let mut response = original.clone();
    response.message = MessageKind::Response;
    response.body = serde_json::json!({"status":"completed", "operation_state":"completed", "extensions":{}, "result": {
        "schema": NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA, "state":"bootstrap_only", "recipe_identity":request.recipe_identity, "initial_funding":request.initial_funding,
    }}).as_object().unwrap().clone();
    response.extensions.clear();
    response.extensions.insert(NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.into(), serde_json::json!({
        "schema": NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT, "algorithm":"blake3-keyed-canonical/1", "state":"bootstrap_only",
        "context_digest": Bytes::new(vec![2;32]), "assigned_response": Bytes::new(vec![3;32]), "mac":Bytes::new(vec![4;32]),
    }));
    serde_json::to_value(response).unwrap()
}

#[test]
fn dedicated_bootstrap_moves_the_actual_pending_request_after_retained_decoding() {
    let (_lease, mut connection, mut peer) = scope();
    let (original, request, proof, bytes, slot) = seal(&mut connection);
    let pending_pointer = connection
        .guard
        .pending_requests()
        .next()
        .unwrap()
        .request_id
        .0
        .as_ref()
        .unwrap()
        .as_str()
        .as_ptr();

    connection
        .publish_original_bootstrap_data(&original, &request, &proof, &bytes, slot)
        .unwrap();
    let mut header = [0; 4];
    peer.read_exact(&mut header).unwrap();
    let mut received = vec![0; u32::from_be_bytes(header) as usize];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(received, bytes);
    let raw_value = response(&original, &request);
    crate::transport::write_frame(&mut peer, &raw_value, 65536).unwrap();
    let mut raw = None;
    connection
        .receive_original_bootstrap_raw_into_data(&original, 65536, &mut raw)
        .unwrap();
    assert!(
        connection
            .receive_original_bootstrap_raw_into_data(&original, 65536, &mut raw)
            .is_err()
    );
    assert!(!connection.fenced);
    let raw = raw.unwrap();
    let quote = native_import18_bootstrap_response_decode_quote_data(usize::MAX).unwrap();
    let mut decoded = None;
    let mut retained_request = None;
    connection
        .decode_original_bootstrap_raw_into_data(
            &original,
            &raw,
            &quote,
            usize::MAX,
            (&mut decoded, &mut retained_request),
        )
        .unwrap();

    assert!(
        connection
            .decode_original_bootstrap_raw_into_data(
                &original,
                &raw,
                &quote,
                usize::MAX,
                (&mut decoded, &mut retained_request)
            )
            .is_err()
    );
    assert!(!connection.fenced);
    assert!(connection.guard.pending_requests().next().is_none());
    assert_eq!(retained_request.as_ref().unwrap(), &original);
    assert_eq!(
        retained_request
            .as_ref()
            .unwrap()
            .request_id
            .0
            .as_ref()
            .unwrap()
            .as_str()
            .as_ptr(),
        pending_pointer
    );
    assert!(decoded.as_ref().unwrap().borrowed_history_data().decoded);
    assert_eq!(raw.value, raw_value);
    assert!(
        connection
            .guard
            .original_bootstrap_received_data(
                retained_request.as_ref().unwrap(),
                decoded
                    .as_ref()
                    .unwrap()
                    .borrowed_history_data()
                    .envelope
                    .unwrap()
            )
            .is_ok()
    );
}

#[test]
fn reservation_refuses_foreign_headers_and_closed_body_without_io_or_new_slots() {
    for fault in 0..14 {
        let (_lease, mut connection, mut peer) = scope();
        let (mut original, request, _) = proposal(&connection);
        let mut maximum = 65536;
        match fault {
            0 => original.sequence = U64::new(3),
            1 => original.message = MessageKind::Response,
            2 => original.method = Method::Admit,
            3 => original.session_id = Nullable(Some(id("foreign-session"))),
            4 => original.incarnation_id = Nullable(Some(id("foreign-incarnation"))),
            5 => original.request_id = Nullable(None),
            6 => original.node_id = Nullable(Some(id("native-node"))),
            7 => original.execution_owner_id = Nullable(Some(id("native-owner"))),
            8 => original.capture_owner_id = Nullable(Some(id("native-capture"))),
            9 => original.operation_id = Nullable(Some(id("native-operation"))),
            10 => {
                original
                    .body
                    .insert("unknown".into(), serde_json::json!({}));
            }
            11 => {
                original.body.get_mut("initial_funding").unwrap()["retained_requested_bytes"] =
                    serde_json::json!("01");
            }
            12 => maximum = 0,
            13 => maximum = 65537,
            _ => unreachable!(),
        }
        let mut slot = None;

        assert!(
            connection
                .reserve_original_bootstrap_data(&original, &request, maximum, &mut slot)
                .is_err(),
            "fault {fault}"
        );
        assert!(slot.is_none());
        assert!(
            connection
                .original_frames
                .as_ref()
                .unwrap()
                .borrow()
                .frames()
                .next()
                .is_none()
        );
        assert!(connection.guard.unused());
        assert!(!connection.fenced);
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn occupied_reservation_preserves_the_original_slot_and_unsigned_frontier() {
    let (_lease, mut connection, mut peer) = scope();
    let (original, request, _) = proposal(&connection);
    let mut slot = None;
    connection
        .reserve_original_bootstrap_data(&original, &request, 65536, &mut slot)
        .unwrap();
    let saved = slot;

    assert!(
        connection
            .reserve_original_bootstrap_data(&original, &request, 65536, &mut slot)
            .is_err()
    );
    assert_eq!(slot, saved);
    assert_eq!(
        connection
            .original_frames
            .as_ref()
            .unwrap()
            .borrow()
            .frames()
            .count(),
        1
    );
    assert!(connection.guard.unused());
    assert!(!connection.fenced);
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut [0]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn changed_seal_keeps_the_reserved_original_and_fences_before_publication() {
    for fault in 0..6 {
        let (mut lease, mut connection, mut peer) = scope();
        let (mut original, request, proof) = proposal(&connection);
        let mut slot = None;
        connection
            .reserve_original_bootstrap_data(&original, &request, 65536, &mut slot)
            .unwrap();
        original.extensions.insert(
            NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
            serde_json::to_value(&proof).unwrap(),
        );
        let mut bytes =
            canonical::canonical_json(&serde_json::to_value(&original).unwrap()).unwrap();
        let reserved = slot;
        match fault {
            0 => {
                original
                    .extensions
                    .get_mut(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF)
                    .unwrap()["mac"] = serde_json::to_value(Bytes::new(vec![9; 32])).unwrap();
            }
            1 => {
                original.body["initial_funding"]["declared_counter_scratch_bytes"] =
                    serde_json::json!("4");
            }
            2 => bytes[0] = b' ',
            3 => slot = None,
            4 => connection.role = EndpointRole::Provider,
            5 => lease.contain(),
            _ => unreachable!(),
        }

        assert!(
            connection
                .seal_original_bootstrap_data(&original, &request, &proof, &bytes, slot)
                .is_err(),
            "fault {fault}"
        );
        assert!(connection.fenced);
        assert!(connection.guard.pending_requests().next().is_none());
        let bank = connection.original_frames.as_ref().unwrap().borrow();
        let frame = bank.frame(reserved.unwrap()).unwrap();
        assert!(frame.bytes.is_empty());
        assert_eq!(frame.transferred, 0);
        assert!(!frame.complete);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
}

#[test]
fn broken_pipe_retains_sealed_literal_and_actual_pending_original_without_retry() {
    let (_lease, mut connection, peer) = scope();
    let (original, request, proof, bytes, slot) = seal(&mut connection);
    let pointer = connection
        .guard
        .pending_requests()
        .next()
        .unwrap()
        .request_id
        .0
        .as_ref()
        .unwrap()
        .as_str()
        .as_ptr();
    drop(peer);

    assert!(
        connection
            .publish_original_bootstrap_data(&original, &request, &proof, &bytes, slot)
            .is_err()
    );
    assert!(connection.fenced);
    assert!(
        connection
            .publish_original_bootstrap_data(&original, &request, &proof, &bytes, slot)
            .is_err()
    );
    let pending = connection.guard.pending_requests().next().unwrap();
    assert_eq!(pending, &original);
    assert_eq!(
        pending.request_id.0.as_ref().unwrap().as_str().as_ptr(),
        pointer
    );
    let bank = connection.original_frames.as_ref().unwrap().borrow();
    let frame = bank.frame(slot.unwrap()).unwrap();
    assert_eq!(&frame.bytes[4..], bytes);
    assert_eq!(frame.transferred, 0);
    assert!(!frame.complete);
    assert_eq!(bank.frames().count(), 1);
}

fn published() -> (
    Handshake,
    Connection<UnixStream>,
    UnixStream,
    Envelope,
    PacketNativeImport18BootstrapRequest,
) {
    let (lease, mut connection, mut peer) = scope();
    let (original, request, proof, bytes, slot) = seal(&mut connection);
    connection
        .publish_original_bootstrap_data(&original, &request, &proof, &bytes, slot)
        .unwrap();
    let mut header = [0; 4];
    peer.read_exact(&mut header).unwrap();
    let mut received = vec![0; u32::from_be_bytes(header) as usize];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(received, bytes);
    (lease, connection, peer, original, request)
}

#[test]
fn partial_response_retains_literal_prefix_and_pending_original_after_read_failure() {
    use std::io::Write;
    let (_lease, mut connection, mut peer, original, request) = published();
    let bytes = canonical::canonical_json(&response(&original, &request)).unwrap();
    let header = u32::try_from(bytes.len()).unwrap().to_be_bytes();
    peer.write_all(&header).unwrap();
    peer.write_all(&bytes[..17]).unwrap();
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    let mut raw = None;

    assert!(
        connection
            .receive_original_bootstrap_raw_into_data(&original, 65536, &mut raw)
            .is_err()
    );
    assert!(raw.is_none());
    assert!(connection.fenced);
    assert_eq!(connection.guard.pending_requests().next(), Some(&original));
    let bank = connection.original_frames.as_ref().unwrap().borrow();
    let frame = bank.frames().last().unwrap();
    assert_eq!(frame.direction, FrameDirection::Incoming);
    assert_eq!(&frame.bytes[..4], &header);
    assert_eq!(&frame.bytes[4..], &bytes[..17]);
    assert_eq!(frame.transferred, 21);
    assert!(!frame.complete);
}

#[test]
fn failed_result_correspondence_retains_raw_and_decoded_prefix_before_sdk_settlement() {
    let (_lease, mut connection, mut peer, original, request) = published();
    let mut value = response(&original, &request);
    value["body"]["result"]["recipe_identity"] =
        serde_json::to_value(Bytes::new(vec![9; 32])).unwrap();
    crate::transport::write_frame(&mut peer, &value, 65536).unwrap();
    let mut raw = None;
    connection
        .receive_original_bootstrap_raw_into_data(&original, 65536, &mut raw)
        .unwrap();
    let quote = native_import18_bootstrap_response_decode_quote_data(usize::MAX).unwrap();
    let mut decoded = None;
    let mut retained = None;

    assert!(
        connection
            .decode_original_bootstrap_raw_into_data(
                &original,
                raw.as_ref().unwrap(),
                &quote,
                usize::MAX,
                (&mut decoded, &mut retained)
            )
            .is_err()
    );
    assert_eq!(raw.as_ref().unwrap().value, value);
    let history = decoded.as_ref().unwrap().borrowed_history_data();
    assert!(history.failed);
    assert!(!history.decoded);
    assert!(history.envelope.is_some());
    assert!(history.request.is_some());
    assert!(history.body.is_some());
    assert!(history.result.is_some());
    assert!(history.receipt.is_none());
    assert!(retained.is_none());
    assert_eq!(connection.guard.pending_requests().next(), Some(&original));
    assert!(connection.fenced);
}

#[test]
fn completed_publication_refuses_a_second_write_without_replaying_bytes() {
    let (_lease, mut connection, mut peer) = scope();
    let (original, request, proof, bytes, slot) = seal(&mut connection);
    connection
        .publish_original_bootstrap_data(&original, &request, &proof, &bytes, slot)
        .unwrap();
    let mut literal = vec![0; bytes.len() + 4];
    peer.read_exact(&mut literal).unwrap();

    assert!(
        connection
            .publish_original_bootstrap_data(&original, &request, &proof, &bytes, slot)
            .is_err()
    );
    assert!(connection.fenced);
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    let bank = connection.original_frames.as_ref().unwrap().borrow();
    let frame = bank.frame(slot.unwrap()).unwrap();
    assert_eq!(frame.bytes, literal);
    assert_eq!(frame.transferred, literal.len());
    assert!(frame.complete);
    assert_eq!(bank.frames().count(), 1);
    assert_eq!(connection.guard.pending_requests().next(), Some(&original));
}

#[test]
fn generic_send_still_refuses_bootstrap_before_io() {
    let (_lease, mut connection, mut peer) = scope();
    let (mut original, _, proof) = proposal(&connection);
    original.extensions.insert(
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
        serde_json::to_value(proof).unwrap(),
    );

    assert!(connection.send(original).is_err());
    assert!(!connection.fenced);
    assert!(connection.guard.pending_requests().next().is_none());
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut [0]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(
        connection
            .original_frames
            .as_ref()
            .unwrap()
            .borrow()
            .frames()
            .next()
            .is_none()
    );
}

#[test]
fn dedicated_bootstrap_requires_all_three_full_contracts_and_both_negotiated_keys() {
    for fault in 0..6 {
        let (_lease, mut connection, mut peer) = scope_with_declaration_fault(Some(fault));
        let (original, request, _) = proposal(&connection);
        let mut slot = None;

        assert!(
            connection
                .reserve_original_bootstrap_data(&original, &request, 65536, &mut slot)
                .is_err(),
            "fault {fault}"
        );
        assert!(slot.is_none());
        assert!(connection.guard.unused());
        assert!(!connection.fenced);
        assert!(
            connection
                .original_frames
                .as_ref()
                .unwrap()
                .borrow()
                .frames()
                .next()
                .is_none()
        );
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn generic_receive_preserves_bootstrap_original_without_granting_a_generic_body() {
    let (_lease, mut connection, mut peer, original, request) = published();
    crate::transport::write_frame(&mut peer, &response(&original, &request), 65536).unwrap();

    assert!(connection.receive().is_err());
    assert!(connection.fenced);
    assert_eq!(connection.guard.pending_requests().next(), Some(&original));
    let bank = connection.original_frames.as_ref().unwrap().borrow();
    let frame = bank.frames().last().unwrap();
    assert_eq!(frame.direction, FrameDirection::Incoming);
    assert!(frame.complete);
    assert_eq!(frame.transferred, frame.bytes.len());
}
