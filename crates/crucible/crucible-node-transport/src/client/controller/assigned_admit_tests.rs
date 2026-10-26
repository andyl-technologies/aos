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
use crucible_node_format::Bytes;
use std::{io::Read, os::unix::net::UnixStream, rc::Rc};

struct Supervisor {
    original: crate::connection::OriginalSupervisorState,
    incidents: std::cell::RefCell<Vec<ConnectionIncident>>,
}
impl Supervisor {
    fn new() -> Self {
        Self {
            original: crate::connection::OriginalSupervisorState::new(),
            incidents: std::cell::RefCell::new(Vec::with_capacity(4)),
        }
    }
}
impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, incident: ConnectionIncident) {
        let _callback = self.original.begin_quarantine_callback().unwrap();
        self.incidents.borrow_mut().push(incident);
    }
    fn with_original_protocol_state(
        &self,
        inspect: &mut dyn FnMut(
            crate::connection::OriginalSupervisorProtocolView<'_>,
        ) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        self.original
            .with_original_incidents(&self.incidents, inspect)
    }
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
        Rc::new(Supervisor::new()),
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
    let controller = CnpController::new(session, custody, route, Duration::from_secs(2)).unwrap();
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
            .map(crucible_node_format::NodeBinding::identity)
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

// Uses an actual paired Unix stream and a syntax-only modeled proof/reply peer.
fn complete_modeled_assigned_admit(
    controller: &mut CnpController,
    peer: UnixStream,
    selection: &PacketControlSelection,
) {
    complete_modeled_assigned_admit_with_proofs(controller, peer, selection, false);
}

fn complete_modeled_assigned_admit_with_proofs(
    controller: &mut CnpController,
    mut peer: UnixStream,
    selection: &PacketControlSelection,
    with_provider_proofs: bool,
) {
    let lease = controller
        .retain_original_canonical_blob_ack_emitter()
        .unwrap();
    let mut assigned = controller
        .prepare_original_canonical_ack_admit(
            &lease,
            Id::new("publish-once").unwrap(),
            request(selection),
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
            .map(crucible_node_format::NodeBinding::identity)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        hashes.sort();
        let result = crate::bodies::AdmitResult {
            accepted_binding_hashes: hashes,
            admission_id: Id::new("modeled-admit-reply").unwrap(),
        };
        if with_provider_proofs {
            let content = canonical::content_ref(b"", "application/octet-stream").unwrap();
            let transfer_id = Id::new("intervening-empty-transfer").unwrap();
            let begin = crate::bodies::BlobBeginRequest {
                transfer_id: transfer_id.clone(),
                content,
                extensions: Extensions::new(),
            };
            let finish = crate::bodies::BlobFinishRequest {
                transfer_id,
                extensions: Extensions::new(),
            };
            for (sequence, name, body) in [
                (2, "intervening-begin", RequestBody::BlobBegin(begin)),
                (3, "intervening-finish", RequestBody::BlobFinish(finish)),
            ] {
                let mut proof_request = original.clone();
                proof_request.sequence = U64::new(sequence);
                proof_request.request_id.0 = Some(Id::new(name).unwrap());
                proof_request.extensions.clear();
                proof_request.method = match &body {
                    RequestBody::BlobBegin(_) => Method::BlobBegin,
                    RequestBody::BlobFinish(_) => Method::BlobFinish,
                    _ => unreachable!("closed fixture proof roster"),
                };
                proof_request.body = match &body {
                    RequestBody::BlobBegin(value) => serde_json::to_value(value).unwrap(),
                    RequestBody::BlobFinish(value) => serde_json::to_value(value).unwrap(),
                    _ => unreachable!("closed fixture proof roster"),
                }
                .as_object()
                .unwrap()
                .clone();
                write_frame(
                    &mut peer,
                    &serde_json::to_value(&proof_request).unwrap(),
                    65_536,
                )
                .unwrap();
                let ack_value = reader.read().unwrap().unwrap();
                let ack = Envelope::decode(&canonical::canonical_json(&ack_value).unwrap(), 65_536)
                    .unwrap();
                assert_eq!(ack.message, MessageKind::Response);
                assert_eq!(ack.request_id, proof_request.request_id);
                assert_eq!(ack.sequence, U64::new(sequence + 1));
                decode_response(&body, &ack.body).unwrap();
            }
        }
        let mut response = original.clone();
        response.message = MessageKind::Response;
        response.sequence = U64::new(if with_provider_proofs { 4 } else { 2 });
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
    assert_eq!(bank.as_ref().unwrap().allocated_bytes(), capacity);
    assert!(
        controller
            .retain_original_canonical_blob_ack_emitter()
            .is_err()
    );
    assert_no_wire(&mut peer);

    let mut wrong = selection;
    wrong.admission_receipt =
        crucible_node_format::canonical::content_ref(b"foreign admission", "application/json")
            .unwrap();
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
    assert_eq!(bank.as_ref().unwrap().allocated_bytes(), capacity);
    assert!(
        controller
            .retain_original_canonical_blob_ack_emitter()
            .is_err()
    );
    assert_no_wire(&mut peer);
}

#[test]
fn owned11_full_host_data_roundtrip_preserves_complete_originals_and_capacities() {
    owned11_model_host_roundtrip(false);
}

#[test]
fn owned11_completed_assigned_unix_originals_roundtrip_and_old_seven_refuses() {
    owned11_model_host_roundtrip(true);
}

#[test]
fn owned11_completed_assigned_with_intervening_provider_proofs_keeps_all_literals() {
    owned11_model_host_roundtrip_with_proofs(true, true);
}

fn owned11_model_host_roundtrip(with_completed_assigned: bool) {
    owned11_model_host_roundtrip_with_proofs(with_completed_assigned, false);
}

fn owned11_model_host_roundtrip_with_proofs(
    with_completed_assigned: bool,
    with_provider_proofs: bool,
) {
    use crate::protocol_snapshot::owned11::{
        aliases::HistoricalAliasSummary,
        json_value::HistoricalJsonLimits,
        outer::{OwnedProtocol11DataLimits, ValidatedOwnedProtocol11},
    };
    use crate::protocol_snapshot::{ProtocolCaptureCut, ProtocolSnapshotReservation};
    let (_handshake, mut controller, peer, selection, coordinator) = uninstalled_fixture();
    controller.session.seed_owned11_model_hello().unwrap();
    let profile = crate::reference_packet::service::PacketNative5CaptureProfile::OwnedProtocol11 {
        native_before_protocol_bytes: U64::new(2 * 1024 * 1024),
        native_after_protocol_bytes: U64::new(2 * 1024 * 1024),
        host_protocol_bytes: U64::new(16 * 1024 * 1024),
    };
    let mut bank = Some(
        crate::transport::original_frames::OriginalFrameReservation::reserve(262144, 64).unwrap(),
    );
    controller
        .install_native5_source_ack_emitter_codec_with_metadata_extent(
            &mut bank,
            selection.clone(),
            coordinator,
            profile.clone(),
            crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
        )
        .unwrap();
    if with_completed_assigned {
        if with_provider_proofs {
            complete_modeled_assigned_admit_with_proofs(&mut controller, peer, &selection, true);
        } else {
            complete_modeled_assigned_admit(&mut controller, peer, &selection);
        }
        let mut old_seven =
            ProtocolSnapshotReservation::reserve_complete_compact(16 * 1024 * 1024, 262144, 64)
                .unwrap();
        let prior = old_seven.original_allocation_facts().unwrap();
        assert!(
            controller
                .capture_original_protocol_state(&mut old_seven, ProtocolCaptureCut::HostSettled,)
                .is_err()
        );
        assert_eq!(old_seven.original_allocation_facts().unwrap(), prior);
    }
    let supervisor = controller.retain_original_protocol_supervisor().unwrap();
    let before = controller.original_owned11_metadata_facts().unwrap();
    let mut reservation = Some(
        ProtocolSnapshotReservation::reserve_complete_owned11(16 * 1024 * 1024, 262144, 64, 16384)
            .unwrap(),
    );
    controller
        .capture_original_protocol_state_with_supervisor(
            reservation.as_mut().unwrap(),
            ProtocolCaptureCut::HostSettled,
            &supervisor,
        )
        .unwrap();
    let mut captured = None;
    controller
        .take_original_protocol_snapshot_into(
            &mut reservation,
            &mut captured,
            ProtocolCaptureCut::HostSettled,
        )
        .unwrap();
    let captured = captured.unwrap();
    assert!(reservation.is_none());
    let mut scratch = vec![HistoricalAliasSummary::default(); 16384];
    let limits = OwnedProtocol11DataLimits {
        json: HistoricalJsonLimits {
            maximum_input_bytes: 16 * 1024 * 1024,
            maximum_nodes: 512 * 1024,
            maximum_depth: 64,
            maximum_owned_backing_bytes: 32 * 1024 * 1024,
            maximum_tree_entries: 65536,
        },
        content: crate::client::compact_metadata8::CompactMetadata8Limits {
            content: crate::client::compact_cursor::CompactContentLimits {
                max_input_bytes: 16 * 1024 * 1024,
                max_rows: 8192,
                max_groups: 8192,
                max_first_group_capacity_bytes: 16 * 1024 * 1024,
            },
            maximum_metadata_capacity_bytes: 4 * 1024 * 1024,
        },
        maximum_metadata_rows: 16384,
        maximum_literal_backing_bytes: 1024 * 1024,
    };
    let mut plan =
        ValidatedOwnedProtocol11::validate(captured.bytes(), limits, &mut scratch).unwrap();
    assert!(plan.allocation_demand().alias_groups > 0);
    let mut completed = None;
    plan.reconstruct_complete_into(&mut completed).unwrap();
    let restored = completed.unwrap();
    assert_eq!(restored.node, controller.route.node);
    assert_eq!(restored.execution_owner, controller.route.execution_owner);
    assert_eq!(restored.profile, profile);
    assert_eq!(
        restored.session.sequence,
        U64::new(if with_provider_proofs {
            5
        } else if with_completed_assigned {
            3
        } else {
            2
        })
    );
    assert_eq!(
        restored
            .session
            .connection
            .codec
            .selection
            .realization
            .bindings[0]
            .compatibility
            .node_id,
        controller.route.node
    );
    assert_eq!(restored.session.hello.frames().count(), 2);
    let restored_supervisor = restored.supervisor.as_ref().unwrap();
    assert!(restored_supervisor.incidents.is_empty());
    assert_eq!(restored_supervisor.incidents.capacity(), 4);
    assert!(restored_supervisor.inspection_in_progress);
    assert!(!restored_supervisor.callback_in_progress);
    let reader = restored.session.connection.reader.unwrap();
    assert!(!reader.failed);
    assert_eq!(
        reader.last_original_slot,
        if with_provider_proofs {
            Some(5)
        } else if with_completed_assigned {
            Some(1)
        } else {
            None
        }
    );
    assert_eq!(
        restored.session.connection.frames.frames().count(),
        if with_provider_proofs {
            6
        } else if with_completed_assigned {
            2
        } else {
            0
        }
    );
    if with_completed_assigned {
        let original = controller.original_ack_admit.as_ref().unwrap();
        let assigned = restored.assigned.as_ref().unwrap();
        assert_eq!(assigned.original(), &original.original);
        assert_eq!(assigned.canonical_bytes(), original.bytes.as_slice());
        assert_eq!(assigned.canonical_capacity(), original.bytes.capacity());
        assert_eq!(assigned.response(), original.response.as_ref().unwrap());
        assert_eq!(assigned.literal_slot(), original.literal_slot.unwrap());
    } else {
        assert!(restored.assigned.is_none());
    }
    if with_provider_proofs {
        // Compatibility data still parses, but it cannot enter the complete class.
        let mut old = captured.bytes().to_vec();
        let new_tag = b"\"source-private.connection-with-reader/11\"";
        let old_tag = b"\"source-private.connection/11\"";
        let tag_start = old
            .windows(new_tag.len())
            .position(|bytes| bytes == new_tag)
            .unwrap();
        old.splice(
            tag_start..tag_start + new_tag.len(),
            old_tag.iter().copied(),
        );
        let mut reader_field = vec![b','];
        reader_field.extend(serde_json::to_vec(&reader).unwrap());
        let reader_start = old
            .windows(reader_field.len())
            .position(|bytes| bytes == reader_field)
            .unwrap();
        old.drain(reader_start..reader_start + reader_field.len());
        let mut old_scratch = vec![HistoricalAliasSummary::default(); 16384];
        let mut old_plan =
            ValidatedOwnedProtocol11::validate(&old, limits, &mut old_scratch).unwrap();
        assert!(old_plan.require_complete_reader_state().is_err());
        let mut refused = None;
        assert!(old_plan.reconstruct_complete_into(&mut refused).is_err());
        assert!(refused.is_none());
        old_plan.reconstruct_into(&mut refused).unwrap();
        let historical = refused.unwrap();
        assert!(historical.session.connection.reader.is_none());
        assert!(historical.require_complete_reader_state().is_err());
    }
    if with_provider_proofs {
        // Missing new retained-owner coverage is historical data, never a full target.
        // Preserve the declaration order of every nested typed object. A Value
        // round trip sorts those keys and would test malformed history instead.
        let mut older = captured.bytes().to_vec();
        let current_tag = b"\"source-private.controller-restorable-complete/11\"";
        let older_tag = b"\"source-private.controller-complete/11\"";
        let tag_starts = older
            .windows(current_tag.len())
            .enumerate()
            .filter_map(|(index, bytes)| (bytes == current_tag).then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(tag_starts.len(), 1);
        let tag_start = tag_starts[0];
        assert_eq!(older[tag_start - 1], b'[');
        let controller_end = {
            let mut controller = serde_json::Deserializer::from_slice(&older[tag_start - 1..])
                .into_iter::<serde::de::IgnoredAny>();
            controller.next().unwrap().unwrap();
            tag_start - 1 + controller.byte_offset()
        };
        assert_eq!(&older[controller_end - 6..controller_end], b",null]");
        older.drain(controller_end - 6..controller_end - 1);
        older.splice(
            tag_start..tag_start + current_tag.len(),
            older_tag.iter().copied(),
        );
        let mut older_scratch = vec![HistoricalAliasSummary::default(); 16384];
        let mut older_plan =
            ValidatedOwnedProtocol11::validate(&older, limits, &mut older_scratch).unwrap();
        assert!(older_plan.complete_schema_identity().is_err());
        let mut partial = None;
        assert!(older_plan.reconstruct_complete_into(&mut partial).is_err());
        assert!(partial.is_none());
        older_plan.reconstruct_into(&mut partial).unwrap();
        assert!(partial.unwrap().require_complete_reader_state().is_err());

        let reference =
            crucible_node_format::canonical::content_ref(captured.bytes(), "application/json")
                .unwrap();
        let wrong = crucible_node_format::canonical::content_ref(
            b"wrong archived host",
            "application/json",
        )
        .unwrap();
        let mut seal_scratch = vec![HistoricalAliasSummary::default(); 16384];
        let mut seal_plan =
            ValidatedOwnedProtocol11::validate(captured.bytes(), limits, &mut seal_scratch)
                .unwrap();
        let mut encoded = Some(Vec::with_capacity(
            seal_plan.sealed_encoded_body_bytes() + 17,
        ));
        let original_pointer = encoded.as_ref().unwrap().as_ptr();
        let original_capacity = encoded.as_ref().unwrap().capacity();
        let mut sealed = None;
        assert!(
            seal_plan
                .reconstruct_sealed_into(&wrong, &mut encoded, &mut sealed)
                .is_err()
        );
        assert!(sealed.is_none());
        assert_eq!(encoded.as_ref().unwrap().as_ptr(), original_pointer);
        assert_eq!(encoded.as_ref().unwrap().capacity(), original_capacity);
        assert!(encoded.as_ref().unwrap().is_empty());
        seal_plan
            .reconstruct_sealed_into(&reference, &mut encoded, &mut sealed)
            .unwrap();
        assert!(encoded.is_none());
        let sealed = sealed.unwrap();
        assert_eq!(sealed.encoded_body().as_ptr(), original_pointer);
        assert_eq!(sealed.encoded_capacity(), original_capacity);
        assert_eq!(sealed.encoded_body(), captured.bytes());
        assert_eq!(sealed.body_reference(), &reference);
        assert_eq!(
            sealed
                .historical()
                .unwrap()
                .assigned
                .as_ref()
                .unwrap()
                .canonical_bytes(),
            restored.assigned.as_ref().unwrap().canonical_bytes()
        );

        let mut independent_scratch = vec![HistoricalAliasSummary::default(); 16384];
        let mut independent_plan =
            ValidatedOwnedProtocol11::validate(captured.bytes(), limits, &mut independent_scratch)
                .unwrap();
        let mut insufficient = Some(Vec::with_capacity(1));
        let mut independent = None;
        assert!(
            independent_plan
                .reconstruct_sealed_into(&reference, &mut insufficient, &mut independent)
                .is_err()
        );
        assert!(independent.is_none());
        assert!(insufficient.is_some());
        let mut independent_bytes = Some(Vec::with_capacity(
            independent_plan.sealed_encoded_body_bytes(),
        ));
        independent_plan
            .reconstruct_sealed_into(&reference, &mut independent_bytes, &mut independent)
            .unwrap();
        let independent = independent.unwrap();
        assert_ne!(
            sealed.encoded_body().as_ptr(),
            independent.encoded_body().as_ptr()
        );
        assert_eq!(sealed.encoded_body(), independent.encoded_body());
        assert_eq!(
            sealed.historical().unwrap().node,
            independent.historical().unwrap().node
        );
        if let (Some(first), Some(second)) = (
            &sealed.historical().unwrap().session.authority.extensions,
            &independent
                .historical()
                .unwrap()
                .session
                .authority
                .extensions,
        ) {
            assert!(!std::sync::Arc::ptr_eq(first, second));
        }
    }
    assert_eq!(
        controller.original_owned11_metadata_facts().unwrap(),
        before
    );
    // Data restoration leaves the actual current actor and all original banks intact.
    assert!(controller.owns_original_protocol_snapshot(&captured));
}

#[path = "assigned_admit_tests/capacities.rs"]
mod capacities;
