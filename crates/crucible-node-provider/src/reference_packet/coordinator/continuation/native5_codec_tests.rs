//! Real Unix codec installation with inert complete coordinator/Hello fixtures.
//!
//! These controls preserve actual framing and private marker fields. They issue
//! no source process, semantic settlement, capture/adoption or Ready authority.

use super::*;
use crate::{
    connection::*,
    envelope::*,
    handshake::*,
    protocol_snapshot::{ProtocolCaptureCut, ProtocolSnapshotReservation},
    reference_service::InstalledContent,
    transport::original_frames::OriginalFrameReservation,
};
use std::{os::unix::net::UnixStream, rc::Rc};

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
        Err(ProviderError::Correlation(
            "fixture mutable schema must be replaced",
        ))
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

fn scope(
    feature: bool,
) -> (
    Handshake,
    ConnectionAuthority,
    PacketControlSelection,
    InstalledContent,
) {
    let coordinator = five();
    let selection = coordinator.participants[0].clone();
    let binding = &selection.realization.bindings[0];
    let session = binding.authority.session_id.clone();
    let incarnation = binding.authority.incarnation_id.clone();
    let mut features = vec![
        id("cnp.core/1"),
        id(crate::reference_packet::input::PACKET_INPUT_FEATURE),
    ];
    if feature {
        features.push(id(contracts::PACKET_COMPLETE_LINEAGE_FEATURE));
    }
    features.sort();
    let limits = Limits {
        frame_bytes: U64::new(65536),
        nesting: U64::new(64),
        requests: U64::new(8),
        journal_entries: U64::new(64),
        blob_chunk_bytes: U64::new(4096),
    };
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
            envelope_extension_features: std::collections::BTreeMap::from([(
                crate::reference_packet::input::PACKET_INPUT_FEATURE.into(),
                id(crate::reference_packet::input::PACKET_INPUT_FEATURE),
            )]),
        },
    )
    .unwrap();
    let request = HelloRequest {
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
    let response = HelloResult {
        version: "CNP/1".into(),
        session_id: session,
        incarnation_id: incarnation,
        controller_nonce: request.controller_nonce.clone(),
        provider_nonce: Bytes::new(vec![5; 32]),
        selected_features: features,
        limits,
        resume_token: Nullable(None),
        provider_identity: selection.provider.clone(),
        resumed_operations: Vec::new(),
    };
    let authority = handshake
        .admit_exchange(
            &request,
            &response,
            id("codec-fixture-connection"),
            &mut ModelVerifier,
        )
        .unwrap();
    let bytes = canonical::canonical_json(&serde_json::to_value(coordinator).unwrap()).unwrap();
    let installed = InstalledContent {
        reference: canonical::content_ref(&bytes, "application/json").unwrap(),
        bytes: Bytes::new(bytes),
    };
    (handshake, authority, selection, installed)
}

#[test]
fn native5_original_immutable_codec_installs_and_captures_actual_pending_frame() {
    let (_handshake, authority, selection, coordinator) = scope(true);
    let (host, native) = UnixStream::pair().unwrap();
    let mut controller = Connection::new(
        host,
        authority.clone(),
        Rc::new(Supervisor),
        Rc::new(Uninstalled),
        EndpointRole::Controller,
    )
    .unwrap();
    let mut provider = Connection::new(
        native,
        authority,
        Rc::new(Supervisor),
        Rc::new(Uninstalled),
        EndpointRole::Provider,
    )
    .unwrap();
    let policy = crate::reference_packet::service::controlled_native5_policy(
        selection.clone(),
        coordinator.clone(),
    )
    .unwrap();
    let mut host_bank = Some(OriginalFrameReservation::reserve(262144, 8).unwrap());
    let mut native_bank = Some(OriginalFrameReservation::reserve(262144, 8).unwrap());
    controller
        .install_native5_controller_codec(&mut host_bank, selection.clone(), coordinator)
        .unwrap();
    provider
        .install_native5_native_codec(&mut native_bank, policy)
        .unwrap();
    assert!(host_bank.is_none() && native_bank.is_none());
    controller.authenticate_native5_source_codec().unwrap();
    provider.authenticate_native5_source_codec().unwrap();
    assert!(controller.install_packet_schema().is_err());
    assert!(provider.install_packet_schema().is_err());
    assert!(
        controller
            .install_connected_packet_schema(
                &selection.realization.bindings[0],
                &selection.realization.owner_bindings[0],
            )
            .is_err()
    );
    assert!(
        provider
            .install_connected_packet_schema(
                &selection.realization.bindings[0],
                &selection.realization.owner_bindings[0],
            )
            .is_err()
    );
    controller.authenticate_native5_source_codec().unwrap();
    provider.authenticate_native5_source_codec().unwrap();
    let initial = controller.original_native5_storage_facts().unwrap();
    assert_eq!(initial.maximum_history_bytes, 262144);
    assert_eq!(initial.maximum_frames_per_direction, 8);
    assert_eq!(initial.byte_capacity, 262144);
    assert_eq!(initial.descriptor_capacity, 16);
    assert_eq!(
        initial.allocated_bytes,
        initial.byte_capacity + initial.descriptor_bytes
    );
    assert_eq!(initial.incoming_frames, 0);
    assert_eq!(initial.outgoing_frames, 0);
    assert!(initial.all_io_complete);

    let mut request = crate::envelope::tests::request();
    request.session_id = Nullable(Some(
        provider.provider_authority().unwrap().session_id().clone(),
    ));
    request.incarnation_id = Nullable(Some(
        provider
            .provider_authority()
            .unwrap()
            .incarnation_id()
            .clone(),
    ));
    request.node_id = Nullable(Some(selection.realization.descriptors[0].id.clone()));
    request.execution_owner_id = Nullable(None);
    request.capture_owner_id = Nullable(Some(id("fixture-capture-owner")));
    request.method = Method::Begin;
    request.sequence = U64::new(2);
    request.body = serde_json::json!({"kind":"capture", "binding_hash":selection.realization.owner_bindings[0].identity().unwrap(), "owner_generation":"1", "activation_id":"fixture-activation", "world_generation":"1", "arguments":{"capture_id":"fixture-capture", "participant_ids":[selection.realization.descriptors[0].id.clone()], "cut_id":"fixture-cut", "cut":Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl), "event_ordinal":"0", "ordering_profile":"superdense-v1", "preservation_contract":contracts::PACKET_COMPLETE_LINEAGE_PROFILE}, "extensions":{}}).as_object().unwrap().clone();
    controller.send(request.clone()).unwrap();
    assert_eq!(provider.receive().unwrap().unwrap().envelope, request);
    let sent = controller.original_native5_storage_facts().unwrap();
    let received = provider.original_native5_storage_facts().unwrap();
    assert_eq!(sent.outgoing_frames, 1);
    assert_eq!(received.incoming_frames, 1);
    assert!(sent.retained_bytes > 4 && sent.all_io_complete);
    assert_eq!(sent.retained_bytes, received.retained_bytes);
    assert_eq!(sent.allocated_bytes, initial.allocated_bytes);

    let deadline =
        crate::client::ExchangeDeadline::start(std::time::Duration::from_secs(2)).unwrap();
    let mut reserve =
        ProtocolSnapshotReservation::reserve_complete(4 * 1024 * 1024, 262144, 8).unwrap();
    provider
        .capture_native_protocol_state(
            &mut reserve,
            ProtocolCaptureCut::NativeIncomingCapture,
            &deadline,
        )
        .unwrap();
    let snapshot = provider
        .take_native_protocol_snapshot(
            &mut Some(reserve),
            ProtocolCaptureCut::NativeIncomingCapture,
        )
        .unwrap();
    let data: Value = serde_json::from_slice(snapshot.bytes()).unwrap();
    assert_eq!(data["native5_codec"][0], "native-packet/5");
    assert_eq!(snapshot.literal_frames().unwrap().count(), 1);
    assert_eq!(data["correlations"][6].as_object().unwrap().len(), 1);
    let mut target = OriginalFrameReservation::reserve(262144, 8).unwrap();
    assert!(snapshot.prepare_historical_frame_data(&mut target).is_err());
    assert_eq!(target.frames().count(), 0);
}

#[test]
fn native5_original_immutable_codec_refusal_keeps_original_bank() {
    let (_handshake, authority, selection, coordinator) = scope(false);
    let (host, _peer) = UnixStream::pair().unwrap();
    let mut controller = Connection::new(
        host,
        authority,
        Rc::new(Supervisor),
        Rc::new(Uninstalled),
        EndpointRole::Controller,
    )
    .unwrap();
    let mut bank = Some(OriginalFrameReservation::reserve(262144, 8).unwrap());
    let allocation = bank.as_ref().unwrap().allocated_bytes();
    assert!(
        controller
            .install_native5_controller_codec(&mut bank, selection, coordinator)
            .is_err()
    );
    assert_eq!(bank.as_ref().unwrap().allocated_bytes(), allocation);
    assert_eq!(bank.as_ref().unwrap().frames().count(), 0);
}
