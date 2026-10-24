//! Exercises the ordinary retained-terminal and dependency-ordered Blob suffix.
//!
//! The socket/codec fixture has modeled installation and inert proof bytes. It
//! grants no Source claim, native child, restoration, simulated effect or Ready.

// crucible-lint: allow panic-shortcut -- retained proof, real I/O and unchanged cuts are observations.
use super::*;
use crate::client::{ClientContent, ClientCustody};
use crate::connection::{BodySchemaVerifier, ReceivedBody};
use crate::handshake::ConnectionAuthority;
use crate::transport::{FrameReader, write_frame};
use crucible_node_format::{ObservationBatch, Visibility};
use std::{os::unix::net::UnixStream, rc::Rc, time::Duration};

struct BeforeInstallation;

impl BodySchemaVerifier for BeforeInstallation {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        _: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "fixture requires original immutable codec",
        ))
    }
}

fn fixture() -> (crate::handshake::Handshake, CnpController, UnixStream) {
    fixture_with_receiver(1024 * 1024, 64)
}

fn fixture_with_receiver(
    maximum_content_bytes: usize,
    maximum_requests: usize,
) -> (crate::handshake::Handshake, CnpController, UnixStream) {
    let (handshake, authority, selection, coordinator) =
        crate::reference_packet::coordinator::original_native5_controller_scope();
    let (supervisor, _owner) = crate::connection::OriginalRetainedSupervisor::reserve().unwrap();
    let (session, peer) =
        ClientSession::controller_fixture(authority, supervisor, Rc::new(BeforeInstallation))
            .unwrap();
    let custody = ClientCustody::new(
        maximum_requests,
        ClientContent::new(maximum_content_bytes, 256, 4096).unwrap(),
    )
    .unwrap();
    let mut controller = CnpController::new(
        session,
        custody,
        ControllerRoute {
            node: selection.realization.bindings[0]
                .compatibility
                .node_id
                .clone(),
            execution_owner: selection.realization.owner_bindings[0].owner.id.clone(),
        },
        Duration::from_secs(30),
    )
    .unwrap();
    let mut bank = Some(
        crate::transport::original_frames::OriginalFrameReservation::reserve(1024 * 1024, 64)
            .unwrap(),
    );
    controller
        .install_native5_source_codec(&mut bank, selection, coordinator)
        .unwrap();
    (handshake, controller, peer)
}

fn publishing(controller: &mut CnpController, root: ContentRef) {
    let scope = crate::reference_packet::service::complete_restore::activation::tests::request()
        .unwrap()
        .scope;
    let observation = ObservationBatch {
        schema_version: 1,
        execution_owner_id: scope.target.owner.clone(),
        owner_binding_hash: scope.target.binding_hash.clone(),
        world_binding_hash: scope.target.world.clone(),
        activation_id: scope.target.activation.clone(),
        world_generation: scope.target.generation,
        owner_generation: scope.target.owner_generation,
        operation_id: Id::new("retained-observe").unwrap(),
        grant_id: None,
        first_sequence: U64::new(0),
        last_sequence: U64::new(0),
        events: Vec::new(),
        visibility: Visibility::Staged,
        measurement_ref: root,
        extensions: Extensions::new(),
    };
    let decoded = ResponseBody {
        shape: ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: serde_json::Map::new(),
            extensions: Extensions::new(),
        },
        result: Some(MethodResult::Observe(ObserveResult {
            observations: vec![observation],
            next_sequence: U64::new(1),
            complete: true,
            inventory_hash: scope.target.world.clone(),
        })),
    };
    let request = PacketRestorationObservationRequest {
        schema: PACKET_RESTORATION_OBSERVE_FEATURE.into(),
        scope,
        world_original: canonical::content_ref(b"saved-world-original", "application/json")
            .unwrap(),
        world_terminal: canonical::content_ref(b"saved-world-terminal", "application/json")
            .unwrap(),
        maximum_items: U64::new(1),
        native_allocation: PacketRestorationActivationAllocationRow {
            retained_requested_bytes: U64::new(1),
            maximum_simultaneous_transient_bytes: U64::new(2),
            declared_counter_scratch_bytes: U64::new(3),
        },
    };
    let mut terminal = crate::envelope::tests::request();
    terminal.message = MessageKind::Response;
    terminal.method = Method::Observe;
    controller.original_installed_restoration_observation =
        Some(AssignedOriginalInstalledRestorationObservation {
            body: ObserveRequest {
                binding_hash: request.scope.target.binding_hash.clone(),
                owner_generation: request.scope.target.owner_generation,
                after_observation_sequence: U64::new(0),
                maximum_items: U64::new(1),
                extensions: Extensions::new(),
            },
            request,
            unsigned_request: None,
            original: None,
            bytes: Vec::new(),
            literal_slot: None,
            cut: controller.session.protocol_original_deadline(),
            state: ObservationState::Publishing,
            response: Some(terminal),
            decoded: Some(decoded),
            completed_frontier: None,
        });
}

fn blob_frames(
    controller: &CnpController,
    reference: &ContentRef,
    bytes: &[u8],
    first: u64,
) -> Vec<Envelope> {
    let transfer = Id::new(format!("packet-transfer-{first}")).unwrap();
    let mut bodies = vec![(
        Method::BlobBegin,
        serde_json::to_value(BlobBeginRequest {
            transfer_id: transfer.clone(),
            content: reference.clone(),
            extensions: Extensions::new(),
        })
        .unwrap(),
    )];
    for (index, bytes) in bytes.chunks(4096).enumerate() {
        bodies.push((
            Method::BlobChunk,
            serde_json::to_value(BlobChunkRequest {
                transfer_id: transfer.clone(),
                offset: U64::new((index * 4096) as u64),
                bytes: Bytes::new(bytes.to_vec()),
                extensions: Extensions::new(),
            })
            .unwrap(),
        ));
    }
    bodies.push((
        Method::BlobFinish,
        serde_json::to_value(BlobFinishRequest {
            transfer_id: transfer,
            extensions: Extensions::new(),
        })
        .unwrap(),
    ));
    bodies
        .into_iter()
        .enumerate()
        .map(|(index, (method, body))| {
            let sequence = first + index as u64;
            Envelope {
                protocol: "CNP/1".into(),
                message: MessageKind::Request,
                session_id: Nullable(Some(controller.authority().session_id().clone())),
                incarnation_id: Nullable(Some(controller.authority().incarnation_id().clone())),
                node_id: Nullable(None),
                execution_owner_id: Nullable(None),
                capture_owner_id: Nullable(None),
                operation_id: Nullable(None),
                request_id: Nullable(Some(Id::new(format!("packet-proof-{sequence}")).unwrap())),
                sequence: U64::new(sequence),
                method,
                body: body.as_object().unwrap().clone(),
                extensions: Extensions::new(),
            }
        })
        .collect()
}

fn acknowledge_frames(mut peer: UnixStream, frames: Vec<Envelope>) -> Vec<Envelope> {
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
    frames
        .into_iter()
        .map(|original| {
            write_frame(&mut peer, &serde_json::to_value(&original).unwrap(), 65_536).unwrap();
            let acknowledgement = reader.read().unwrap().unwrap();
            let acknowledgement: Envelope = serde_json::from_value(acknowledgement).unwrap();
            original.matches_response(&acknowledgement).unwrap();
            assert_eq!(acknowledgement.sequence, original.sequence);
            acknowledgement
        })
        .collect()
}

#[test]
fn dependency_before_root_multichunk_suffix_completes_only_after_every_acknowledgement() {
    let (_handshake, mut controller, peer) = fixture();
    let dependency_bytes =
        canonical::canonical_json(&serde_json::json!({"dependency":"d".repeat(9000)})).unwrap();
    let dependency = canonical::content_ref(&dependency_bytes, "application/json").unwrap();
    let root_bytes = canonical::canonical_json(
        &serde_json::json!({"underlying":dependency,"padding":"r".repeat(5000)}),
    )
    .unwrap();
    let root = canonical::content_ref(&root_bytes, "application/json").unwrap();
    publishing(&mut controller, root.clone());
    let cut = controller.session.protocol_original_deadline();
    let mut frames = blob_frames(&controller, &dependency, &dependency_bytes, 2);
    let root_first = 2 + frames.len() as u64;
    frames.extend(blob_frames(&controller, &root, &root_bytes, root_first));
    let frontier = U64::new(2 + frames.len() as u64);
    let originals = frames.clone();
    let producer = std::thread::spawn(move || acknowledge_frames(peer, frames));

    assert!(controller.content(&dependency).is_err());
    assert!(controller.content(&root).is_err());
    controller
        .complete_original_installed_observation_content_data()
        .unwrap();
    let acknowledgements = producer.join().unwrap();

    assert_eq!(controller.content(&dependency).unwrap(), dependency_bytes);
    assert_eq!(controller.content(&root).unwrap(), root_bytes);
    assert_eq!(
        controller
            .originals_by_origin(RequestOrigin::Provider)
            .count(),
        originals.len()
    );
    for (original, acknowledgement) in originals.iter().zip(&acknowledgements) {
        let retained = controller
            .originals_by_origin(RequestOrigin::Provider)
            .find(|row| row.request.request_id == original.request_id)
            .unwrap();
        assert_eq!(&retained.request, original);
        assert_eq!(retained.response.as_ref(), Some(acknowledgement));
    }
    let state = controller
        .original_installed_restoration_observation
        .as_ref()
        .unwrap();
    assert!(state.state == ObservationState::Complete);
    assert_eq!(state.completed_frontier, Some(frontier));
    assert_eq!(state.cut, cut);
    assert_eq!(controller.session.protocol_original_deadline(), cut);
    assert!(
        controller
            .complete_original_installed_observation_content_data()
            .is_err()
    );
}

#[test]
fn disconnect_after_acknowledged_begin_and_chunk_retains_partial_custody_and_original_cut() {
    let (_handshake, mut controller, peer) = fixture();
    let bytes =
        canonical::canonical_json(&serde_json::json!({"incomplete":"p".repeat(9000)})).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    publishing(&mut controller, reference.clone());
    let cut = controller.session.protocol_original_deadline();
    let terminal = controller
        .original_installed_restoration_observation
        .as_ref()
        .unwrap()
        .response
        .clone();
    let decoded = controller
        .original_installed_restoration_observation
        .as_ref()
        .unwrap()
        .decoded
        .clone();
    let originals = blob_frames(&controller, &reference, &bytes, 2)
        .into_iter()
        .take(2)
        .collect::<Vec<_>>();
    let frames = originals.clone();
    let producer = std::thread::spawn(move || acknowledge_frames(peer, frames));

    assert!(
        controller
            .complete_original_installed_observation_content_data()
            .is_err()
    );
    let acknowledgements = producer.join().unwrap();

    let state = controller
        .original_installed_restoration_observation
        .as_ref()
        .unwrap();
    assert!(state.state == ObservationState::Publishing);
    assert_eq!(state.response, terminal);
    assert_eq!(state.decoded, decoded);
    assert!(state.completed_frontier.is_none());
    assert_eq!(state.cut, cut);
    assert_eq!(controller.session.protocol_original_deadline(), cut);
    assert!(controller.content(&reference).is_err());
    assert!(
        controller
            .ensure_no_pending_original_installed_restoration_observation()
            .is_err()
    );
    assert_eq!(
        controller
            .originals_by_origin(RequestOrigin::Provider)
            .count(),
        2
    );
    for (original, acknowledgement) in originals.iter().zip(&acknowledgements) {
        let retained = controller
            .originals_by_origin(RequestOrigin::Provider)
            .find(|row| row.request.request_id == original.request_id)
            .unwrap();
        assert_eq!(&retained.request, original);
        assert_eq!(retained.response.as_ref(), Some(acknowledgement));
    }
    let content = serde_json::to_value(controller.custody.content().protocol_view()).unwrap();
    let transfers = content[4].as_array().unwrap();
    assert_eq!(transfers.len(), 1);
    assert_eq!(transfers[0][1], serde_json::to_value(&reference).unwrap());
    assert_eq!(transfers[0][2].as_array().unwrap().len(), 4096);
    assert_eq!(transfers[0][4], serde_json::json!(false));
    assert!(content[5].as_array().unwrap().is_empty());
}

#[test]
fn actual_large_content_ceiling_is_funded_by_finite_chunk_origins_with_exact_boundary() {
    let (_handshake, controller, _peer) = fixture_with_receiver(256 * 1024 * 1024, 256);
    let row = controller
        .original_observation_receive_storage_data(512 * 1024 * 1024)
        .unwrap();
    let total = row
        .retained
        .checked_add(row.transient)
        .unwrap()
        .checked_add(row.scratch)
        .unwrap();
    assert!(total < 512 * 1024 * 1024);
    let exact = controller
        .original_observation_receive_storage_data(total)
        .unwrap();
    assert_eq!(
        (exact.retained, exact.transient, exact.scratch),
        (row.retained, row.transient, row.scratch)
    );
    assert!(
        controller
            .original_observation_receive_storage_data(total - 1)
            .is_err()
    );

    // A numeric reservation is not requested byte backing. With the same finite
    // original/chunk ceilings, enlarging only that quota supplies no row credit.
    let (_other_handshake, small, _other_peer) = fixture_with_receiver(2 * 1024 * 1024, 256);
    let small = small
        .original_observation_receive_storage_data(512 * 1024 * 1024)
        .unwrap();
    assert_eq!(
        (small.retained, small.transient, small.scratch),
        (row.retained, row.transient, row.scratch)
    );
}

#[test]
fn oversized_observation_roster_refuses_before_read_and_preserves_both_typed_roots() {
    let (_handshake, mut controller, mut peer) = fixture();
    let reference = canonical::content_ref(b"never read", "application/json").unwrap();
    publishing(&mut controller, reference);
    let state = controller
        .original_installed_restoration_observation
        .as_mut()
        .unwrap();
    let Some(MethodResult::Observe(result)) = state.decoded.as_mut().unwrap().result.as_mut()
    else {
        panic!("Observe fixture");
    };
    result.observations.push(result.observations[0].clone());
    assert!(
        controller
            .complete_original_installed_observation_content_data()
            .is_err()
    );
    let state = controller
        .original_installed_restoration_observation
        .as_ref()
        .unwrap();
    assert!(state.state == ObservationState::Publishing);
    assert!(state.completed_frontier.is_none());
    let Some(MethodResult::Observe(result)) = state.decoded.as_ref().unwrap().result.as_ref()
    else {
        panic!("retained Observe");
    };
    assert_eq!(result.observations.len(), 2);
    peer.set_nonblocking(true).unwrap();
    let mut byte = [0];
    use std::io::Read;
    assert!(
        matches!(peer.read(&mut byte),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn controller_content_growth_prices_actual_local_custody_and_its_own_counter() {
    let (_handshake, controller, _peer) = fixture_with_receiver(4096, 8);
    let before = controller.original_native5_custody_facts().unwrap();
    let quote = controller
        .original_content_internal_growth_storage_data(usize::MAX)
        .unwrap();
    let direct = controller
        .custody
        .content()
        .original_internal_growth_storage_data(usize::MAX)
        .unwrap();

    assert_eq!(
        quote.retained_requested_bytes_data(),
        direct.retained_requested_bytes_data()
    );
    assert_eq!(
        quote.maximum_simultaneous_transient_bytes_data(),
        direct.maximum_simultaneous_transient_bytes_data()
    );
    assert!(quote.counter_scratch_bytes_data() > direct.counter_scratch_bytes_data());
    assert_eq!(
        quote.counter_scratch_bytes_data(),
        CnpController::original_content_internal_growth_counter_scratch_data()
    );
    let peak = quote.retained_requested_bytes_data()
        + quote.maximum_simultaneous_transient_bytes_data()
        + quote.counter_scratch_bytes_data();
    assert_eq!(
        controller
            .original_content_internal_growth_storage_data(peak)
            .unwrap(),
        quote
    );
    assert!(
        controller
            .original_content_internal_growth_storage_data(peak - 1)
            .is_err()
    );
    assert_eq!(controller.original_native5_custody_facts().unwrap(), before);
}

#[test]
fn controller_content_growth_preserves_fenced_partial_and_external_spare_capacity() {
    let (_handshake, mut controller, _peer) = fixture_with_receiver(4096, 8);
    let before = controller.original_native5_custody_facts().unwrap();
    let quote = controller
        .original_content_internal_growth_storage_data(usize::MAX)
        .unwrap();
    let mut bytes = Vec::with_capacity(1_048_576);
    bytes.extend_from_slice(b"external original");
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    controller
        .custody
        .content_mut()
        .install(reference.clone(), bytes)
        .unwrap();
    let pending = canonical::content_ref(b"incomplete transfer", "application/json").unwrap();
    let transfer_id = Id::new("controller-content-growth-partial").unwrap();
    controller
        .custody
        .content_mut()
        .begin(&BlobBeginRequest {
            transfer_id: transfer_id.clone(),
            content: pending.clone(),
            extensions: Extensions::new(),
        })
        .unwrap();
    controller
        .custody
        .content_mut()
        .chunk(&BlobChunkRequest {
            transfer_id,
            offset: U64::new(0),
            bytes: Bytes::new(b"incomplete".to_vec()),
            extensions: Extensions::new(),
        })
        .unwrap();
    controller.fence();

    assert!(controller.fenced);
    assert_eq!(
        controller
            .original_content_internal_growth_storage_data(usize::MAX)
            .unwrap(),
        quote
    );
    assert_eq!(
        controller.custody.content().get(&reference).unwrap(),
        b"external original"
    );
    assert!(controller.custody.content().get(&pending).is_err());
    assert!(controller.original_native5_custody_facts().is_err());
    assert_eq!(
        controller
            .custody
            .original_native5_custody_facts(before.negotiated_journal_entries),
        before
    );
}
