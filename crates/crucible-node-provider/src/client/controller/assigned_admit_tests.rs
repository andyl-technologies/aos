//! Exercises assigned originals on actual Unix I/O under a modeled registrar.
//!
//! The coordinator and source codec are coherent immutable SDK values, but the
//! Hello verifier, proof contents and reply peer are explicit models. These
//! controls grant no native marker, private Child, semantic Capture or Ready.

// These fixture assertions deliberately panic on broken invariants.
#![allow(clippy::unwrap_used)]
// Explicit drops release the wrapper's unique controller borrow for assertions.
#![allow(clippy::drop_non_drop)]

use super::*;
use crate::{
    client::{ClientContent, ClientCustody, ClientSession},
    connection::{BodySchemaVerifier, ConnectionIncident, ConnectionSupervisor, ReceivedBody},
    handshake::{ConnectionAuthority, Handshake},
    reference_packet::control::PacketControlSelection,
    transport::{FrameReader, write_frame},
};
use crucible_node_contract::Bytes;
use std::{io::Read, os::unix::net::UnixStream, rc::Rc};

struct Supervisor;
impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, _: ConnectionIncident) {}
}
struct BeforeInstallation;
impl BodySchemaVerifier for BeforeInstallation {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        _: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "fixture requires immutable source codec",
        ))
    }
}

fn uninstalled_fixture() -> (
    Handshake,
    CnpController,
    UnixStream,
    PacketControlSelection,
    crate::reference_service::InstalledContent,
) {
    let (handshake, authority, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let (session, peer) = ClientSession::controller_fixture(
        authority,
        Rc::new(Supervisor),
        Rc::new(BeforeInstallation),
    )
    .unwrap();
    let custody =
        ClientCustody::new(64, ClientContent::new(8 * 1024 * 1024, 64, 4096).unwrap()).unwrap();
    let route = ControllerRoute {
        node: selection.realization.bindings[0]
            .compatibility
            .node_id
            .clone(),
        execution_owner: selection.realization.owner_bindings[0].owner.id.clone(),
    };
    let controller =
        CnpController::new(session, custody, route, Duration::from_secs(2)).unwrap();
    (handshake, controller, peer, selection, coordinator)
}

fn fixture() -> (Handshake, CnpController, UnixStream, PacketControlSelection) {
    let (handshake, mut controller, peer, selection, coordinator) = uninstalled_fixture();
    let mut bank = Some(
        crate::transport::original_frames::OriginalFrameReservation::reserve(262144, 64).unwrap(),
    );
    controller
        .install_native5_source_ack_emitter_codec_with_metadata_extent(
            &mut bank,
            selection.clone(),
            coordinator,
            crate::reference_packet::service::PacketNative5CaptureProfile::OriginalArrays6,
            crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
        )
        .unwrap();
    assert!(bank.is_none());
    assert_eq!(
        controller.original_native5_codec_metadata_extent().unwrap(),
        Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
    );
    (handshake, controller, peer, selection)
}

fn request(selection: &PacketControlSelection) -> AdmitRequest {
    AdmitRequest {
        bindings: selection.realization.bindings.clone(),
        world_binding_hash: selection.world.clone(),
        admission_receipt: selection.admission_receipt.clone(),
        extensions: Extensions::new(),
    }
}

fn proof() -> PacketCanonicalAckAdmissionProof {
    // Syntax-only proof; the fixture peer cannot issue a verified native token.
    PacketCanonicalAckAdmissionProof {
        schema: PACKET_CANONICAL_ACK_ADMISSION_FEATURE.into(),
        algorithm:
            crate::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM
                .into(),
        context_digest: Bytes::new(vec![3; 32]),
        mac: Bytes::new(vec![5; 32]),
    }
}

fn assert_no_wire(peer: &mut UnixStream) {
    peer.set_nonblocking(true).unwrap();
    let mut byte = [0];
    assert!(
        matches!(peer.read(&mut byte), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    peer.set_nonblocking(false).unwrap();
}

#[test]
fn original_canonical_ack_lease_authenticates_exact_controller_and_refuses_foreign_revoked() {
    let (handshake, controller, mut peer, _) = fixture();
    let lease = controller
        .retain_original_canonical_blob_ack_emitter()
        .unwrap();
    lease.authenticate_original(&controller).unwrap();
    assert_eq!(
        lease.maximum_framed_response_bytes(&controller).unwrap(),
        1824
    );
    let (_other_handshake, other, _, _) = fixture();
    assert!(lease.authenticate_original(&other).is_err());
    assert_no_wire(&mut peer);

    drop(handshake);
    assert!(lease.authenticate_original(&controller).is_err());
    assert!(
        controller
            .retain_original_canonical_blob_ack_emitter()
            .is_err()
    );
    assert_no_wire(&mut peer);
}

#[test]
fn original_assigned_admit_drop_and_signer_unwind_retain_id_cut_buffer_and_slot() {
    let (_handshake, mut controller, mut peer, selection) = fixture();
    let lease = controller
        .retain_original_canonical_blob_ack_emitter()
        .unwrap();
    let id = Id::new("assigned-before-source-signature").unwrap();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let assigned = controller
            .prepare_original_canonical_ack_admit(&lease, id.clone(), request(&selection))
            .unwrap();
        assigned.authenticate_original_emitter(&lease).unwrap();
        assert_eq!(assigned.original().unwrap().sequence, U64::new(2));
        assert_eq!(
            assigned.original().unwrap().request_id.0.as_ref(),
            Some(&id)
        );
        panic!("modeled source signing callback refuses after assignment");
    }));
    assert!(outcome.is_err());
    let state = controller.original_ack_admit.as_ref().unwrap();
    let cut = state.cut;
    let capacity = state.bytes.capacity();
    let pointer = state.bytes.as_ptr();
    let slot = state.literal_slot;
    assert!(slot.is_some());
    assert!(state.bytes.is_empty());
    assert_eq!(controller.originals().count(), 0);
    assert!(
        controller
            .prepare_original_canonical_ack_admit(
                &lease,
                Id::new("replacement").unwrap(),
                request(&selection)
            )
            .is_err()
    );
    assert!(
        controller
            .call(
                Id::new("intervening").unwrap(),
                None,
                Method::Poll,
                true,
                PollRequest {
                    after_observation_sequence: U64::new(0),
                    extensions: Extensions::new()
                }
            )
            .is_err()
    );
    {
        let resumed = controller
            .resume_original_canonical_ack_admit(&lease)
            .unwrap();
        assert_eq!(resumed.original().unwrap().sequence, U64::new(2));
        assert_eq!(resumed.original().unwrap().request_id.0.as_ref(), Some(&id));
    }
    let state = controller.original_ack_admit.as_ref().unwrap();
    assert_eq!(state.cut, cut);
    assert_eq!(state.bytes.capacity(), capacity);
    assert_eq!(state.bytes.as_ptr(), pointer);
    assert_eq!(state.literal_slot, slot);
    assert_no_wire(&mut peer);
}

#[test]
fn original_assigned_admit_invalid_proof_and_double_seal_preserve_original_without_io() {
    let (_handshake, mut controller, mut peer, selection) = fixture();
    let lease = controller
        .retain_original_canonical_blob_ack_emitter()
        .unwrap();
    let mut assigned = controller
        .prepare_original_canonical_ack_admit(
            &lease,
            Id::new("seal-once").unwrap(),
            request(&selection),
        )
        .unwrap();
    let original = assigned.original().unwrap().clone();
    let mut invalid = proof();
    invalid.mac = Bytes::new(vec![5; 31]);
    assert!(assigned.seal(&lease, invalid).is_err());
    assert_eq!(assigned.original().unwrap(), &original);
    assigned.seal(&lease, proof()).unwrap();
    let sealed = assigned.original().unwrap().clone();
    assert_eq!(sealed.sequence, original.sequence);
    assert_eq!(sealed.body, original.body);
    assert_eq!(sealed.extensions.len(), 1);
    assert!(assigned.seal(&lease, proof()).is_err());
    assert_eq!(assigned.original().unwrap(), &sealed);
    drop(assigned);
    let state = controller.original_ack_admit.as_ref().unwrap();
    let bytes = state.bytes.clone();
    let slot = state.literal_slot;
    let resumed = controller
        .resume_original_canonical_ack_admit(&lease)
        .unwrap();
    assert_eq!(resumed.original().unwrap(), &sealed);
    drop(resumed);
    let state = controller.original_ack_admit.as_ref().unwrap();
    assert_eq!(state.bytes, bytes);
    assert_eq!(state.literal_slot, slot);
    assert_no_wire(&mut peer);
}

#[test]
fn original_assigned_admit_actual_unix_publication_uses_exact_sequence_once_without_reset() {
    let (_handshake, mut controller, mut peer, selection) = fixture();
    let lease = controller
        .retain_original_canonical_blob_ack_emitter()
        .unwrap();
    let mut assigned = controller
        .prepare_original_canonical_ack_admit(
            &lease,
            Id::new("publish-once").unwrap(),
            request(&selection),
        )
        .unwrap();
    assert_eq!(assigned.original().unwrap().sequence, U64::new(2));
    assigned.seal(&lease, proof()).unwrap();
    let expected = assigned.original().unwrap().clone();
    drop(assigned);
    let cut = controller.original_ack_admit.as_ref().unwrap().cut;
    let worker = std::thread::spawn(move || {
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let value = reader.read().unwrap().unwrap();
        let original =
            Envelope::decode(&canonical::canonical_json(&value).unwrap(), 65_536).unwrap();
        assert_eq!(original.sequence, U64::new(2));
        let RequestBody::Admit(request) = decode_request(original.method, &original.body).unwrap()
        else {
            panic!("original method changed");
        };
        let mut hashes = request
            .bindings
            .iter()
            .map(crucible_node_contract::NodeBinding::identity)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        hashes.sort();
        let result = crate::bodies::AdmitResult {
            accepted_binding_hashes: hashes,
            admission_id: Id::new("modeled-admit-reply").unwrap(),
        };
        let mut response = original.clone();
        response.message = MessageKind::Response;
        response.sequence = U64::new(2);
        response.extensions.clear();
        response.body = serde_json::to_value(ResponseShape::Completed {
            operation_state: crate::bodies::OperationState::Completed,
            result: serde_json::to_value(result)
                .unwrap()
                .as_object()
                .unwrap()
                .clone(),
            extensions: Extensions::new(),
        })
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
        write_frame(&mut peer, &serde_json::to_value(&response).unwrap(), 65_536).unwrap();
        original
    });
    let mut completed = None;
    {
        let mut resumed = controller
            .resume_original_canonical_ack_admit(&lease)
            .unwrap();
        resumed.publish_into(&lease, &mut completed).unwrap();
        assert!(completed.is_some());
        assert_eq!(resumed.original().unwrap(), &expected);
        let mut second = None;
        assert!(resumed.publish_into(&lease, &mut second).is_err());
        assert!(second.is_none());
    }
    assert_eq!(worker.join().unwrap(), expected);
    let retained = controller
        .original(&Id::new("publish-once").unwrap())
        .unwrap();
    assert_eq!(retained.request, expected);
    assert!(retained.response.is_some());
    assert_eq!(controller.original_ack_admit.as_ref().unwrap().cut, cut);
    assert!(
        controller
            .resume_original_canonical_ack_admit(&lease)
            .is_err()
    );
}

#[test]
fn original_selected_codec_extent_keeps_legacy_limit_and_wrong_source_bank_untouched() {
    let (_handshake, mut controller, mut peer, selection, coordinator) = uninstalled_fixture();
    let mut bank = Some(
        crate::transport::original_frames::OriginalFrameReservation::reserve(262144, 64).unwrap(),
    );
    let capacity = bank.as_ref().unwrap().allocated_bytes();
    let refused = controller.install_native5_source_ack_emitter_codec(
        &mut bank,
        selection.clone(),
        coordinator.clone(),
        crate::reference_packet::service::PacketNative5CaptureProfile::OriginalArrays6,
    );
    assert!(matches!(refused, Err(ProviderError::ResourceExhausted(_))));
    assert_eq!(
        bank.as_ref().unwrap().allocated_bytes(),
        capacity
    );
    assert!(
        controller
            .retain_original_canonical_blob_ack_emitter()
            .is_err()
    );
    assert_no_wire(&mut peer);

    let mut wrong = selection;
    wrong.admission_receipt = crucible_node_contract::canonical::content_ref(b"foreign admission", "application/json").unwrap();
    assert!(
        controller
            .install_native5_source_ack_emitter_codec_with_metadata_extent(
                &mut bank,
                wrong,
                coordinator,
                crate::reference_packet::service::PacketNative5CaptureProfile::OriginalArrays6,
                crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
            )
            .is_err()
    );
    assert_eq!(
        bank.as_ref().unwrap().allocated_bytes(),
        capacity
    );
    assert!(
        controller
            .retain_original_canonical_blob_ack_emitter()
            .is_err()
    );
    assert_no_wire(&mut peer);
}
