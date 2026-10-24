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
impl crate::blob::BlobSupervisor for Supervisor {
    fn quarantine(&self, _: crate::blob::BlobQuarantine) {}
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
    scope_named(feature, None, 0)
}

pub(super) fn original_native5_controller_scope() -> (
    Handshake,
    ConnectionAuthority,
    PacketControlSelection,
    InstalledContent,
) {
    // The raw-census caller constructs a controller requiring negotiated evidence.
    scope_named_with_limits_and_evidence(true, None, 0, None, true)
}

fn scope_named(
    feature: bool,
    suffix: Option<&str>,
    participant: usize,
) -> (
    Handshake,
    ConnectionAuthority,
    PacketControlSelection,
    InstalledContent,
) {
    scope_named_with_limits(feature, suffix, participant, None)
}

fn rename_scope(coordinator: &mut PacketNative5CoordinatorInstallation, suffix: &str) {
    let identities: Vec<_> = coordinator
        .participants
        .iter()
        .map(|peer| &peer.realization.bindings[0].authority)
        .chain(std::iter::once(&coordinator.host.binding.authority))
        .flat_map(|authority| {
            [
                authority.session_id.as_str().to_owned(),
                authority.incarnation_id.as_str().to_owned(),
            ]
        })
        .collect();
    fn map_template(value: &mut Value, identities: &[String], suffix: &str) {
        match value {
            Value::String(id) if identities.contains(id) => *id = format!("{id}-{suffix}"),
            Value::Array(rows) => rows
                .iter_mut()
                .for_each(|row| map_template(row, identities, suffix)),
            Value::Object(fields) => fields
                .values_mut()
                .for_each(|field| map_template(field, identities, suffix)),
            _ => {}
        }
    }
    map_template(&mut coordinator.template, &identities, suffix);
    map_template(&mut coordinator.host.initial_node, &identities, suffix);
    for (index, peer) in coordinator.participants.iter_mut().enumerate() {
        let binding = &mut peer.realization.bindings[0];
        binding.authority.session_id = id(&format!("{}-{suffix}", binding.authority.session_id));
        binding.authority.incarnation_id =
            id(&format!("{}-{suffix}", binding.authority.incarnation_id));
        coordinator.template["nodes"][index]["binding"] = serde_json::to_value(binding).unwrap();
    }
    let binding = &mut coordinator.host.binding;
    binding.authority.session_id = id(&format!("{}-{suffix}", binding.authority.session_id));
    binding.authority.incarnation_id =
        id(&format!("{}-{suffix}", binding.authority.incarnation_id));
    coordinator.host.initial_node["binding"] = serde_json::to_value(&*binding).unwrap();
    coordinator.template["nodes"][3]["binding"] = serde_json::to_value(binding).unwrap();
}

fn scope_named_with_limits(
    feature: bool,
    suffix: Option<&str>,
    participant: usize,
    override_limits: Option<Limits>,
) -> (
    Handshake,
    ConnectionAuthority,
    PacketControlSelection,
    InstalledContent,
) {
    scope_named_with_limits_and_evidence(feature, suffix, participant, override_limits, false)
}

fn scope_named_with_limits_and_evidence(
    feature: bool,
    suffix: Option<&str>,
    participant: usize,
    override_limits: Option<Limits>,
    control_evidence: bool,
) -> (
    Handshake,
    ConnectionAuthority,
    PacketControlSelection,
    InstalledContent,
) {
    let mut coordinator = five();
    if let Some(suffix) = suffix {
        let identities: Vec<_> = coordinator
            .participants
            .iter()
            .map(|peer| &peer.realization.bindings[0].authority)
            .chain(std::iter::once(&coordinator.host.binding.authority))
            .flat_map(|authority| {
                [
                    authority.session_id.as_str().to_owned(),
                    authority.incarnation_id.as_str().to_owned(),
                ]
            })
            .collect();
        fn map_template(value: &mut Value, identities: &[String], suffix: &str) {
            match value {
                Value::String(id) if identities.contains(id) => *id = format!("{id}-{suffix}"),
                Value::Array(rows) => rows
                    .iter_mut()
                    .for_each(|row| map_template(row, identities, suffix)),
                Value::Object(fields) => fields
                    .values_mut()
                    .for_each(|field| map_template(field, identities, suffix)),
                _ => {}
            }
        }
        map_template(&mut coordinator.template, &identities, suffix);
        map_template(&mut coordinator.host.initial_node, &identities, suffix);
        for (index, peer) in coordinator.participants.iter_mut().enumerate() {
            let binding = &mut peer.realization.bindings[0];
            binding.authority.session_id =
                id(&format!("{}-{suffix}", binding.authority.session_id));
            binding.authority.incarnation_id =
                id(&format!("{}-{suffix}", binding.authority.incarnation_id));
            coordinator.template["nodes"][index]["binding"] =
                serde_json::to_value(binding).unwrap();
        }
        let binding = &mut coordinator.host.binding;
        binding.authority.session_id = id(&format!("{}-{suffix}", binding.authority.session_id));
        binding.authority.incarnation_id =
            id(&format!("{}-{suffix}", binding.authority.incarnation_id));
        coordinator.host.initial_node["binding"] = serde_json::to_value(&*binding).unwrap();
        coordinator.template["nodes"][3]["binding"] = serde_json::to_value(binding).unwrap();
    }
    let selection = coordinator.participants[participant].clone();
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
    if control_evidence {
        let evidence = id("cnp.control-evidence/1");
        assert!(selection.provider.extensions_supported.contains(&evidence));
        features.push(evidence);
    }
    features.sort();
    let limits = override_limits.unwrap_or(Limits {
        frame_bytes: U64::new(65536),
        nesting: U64::new(64),
        requests: U64::new(8),
        journal_entries: U64::new(64),
        blob_chunk_bytes: U64::new(4096),
    });
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
            id(&format!(
                "codec-fixture-connection-{}",
                suffix.unwrap_or("original")
            )),
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
    original_pending_capture_control(false);
}

#[test]
fn native5_prepared_suffix_after_capacity_is_readonly_and_retains_same_originals() {
    original_pending_capture_control(true);
}

fn original_pending_capture_control(prepared_suffix: bool) {
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
    let blob_authority = provider.provider_authority().unwrap().clone();
    let blob_limits = crate::blob::BlobLimits {
        reserved_bytes: 65536,
        content_bytes: 65536,
        chunk_bytes: 4096,
        transfers_per_origin: 8,
        tombstones_per_origin: 8,
        chunks_per_transfer: 16,
        operation_pins: 8,
    };
    let blobs = crate::blob::BlobReceiver::new(
        blob_authority.session_id().clone(),
        blob_authority.incarnation_id().clone(),
        blob_limits,
        Rc::new(Supervisor),
    )
    .unwrap();
    provider.bind_native5_blob_receiver(&blobs).unwrap();

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
    let after = ProtocolSnapshotReservation::reserve_complete(4 * 1024 * 1024, 262144, 8).unwrap();
    let original_bank = provider.original_native5_storage_facts().unwrap();
    let original_copy = after.original_allocation_facts().unwrap();
    let admitted = provider
        .preflight_native5_after_protocol_capacity(&after, &blobs)
        .unwrap();
    assert!(admitted.maximum_literal_encoded_bytes >= 4 * 262144);
    assert!(admitted.maximum_after_encoded_bytes <= admitted.reserved_after_encoded_bytes);
    assert_eq!(
        provider.original_native5_storage_facts().unwrap(),
        original_bank
    );
    assert_eq!(after.original_allocation_facts().unwrap(), original_copy);
    let small = ProtocolSnapshotReservation::reserve_complete(65536, 262144, 8).unwrap();
    assert!(
        provider
            .preflight_native5_after_protocol_capacity(&small, &blobs)
            .is_err()
    );
    assert_eq!(small.original_allocation_facts().unwrap().encoded_length, 0);
    let foreign_blobs = crate::blob::BlobReceiver::new(
        blob_authority.session_id().clone(),
        blob_authority.incarnation_id().clone(),
        blob_limits,
        Rc::new(Supervisor),
    )
    .unwrap();
    assert!(
        provider
            .preflight_native5_after_protocol_capacity(&after, &foreign_blobs)
            .is_err()
    );
    assert_eq!(
        provider.original_native5_storage_facts().unwrap(),
        original_bank
    );
    if prepared_suffix {
        let mut prospective = request.clone();
        prospective.node_id = Nullable(None);
        prospective.execution_owner_id = Nullable(None);
        prospective.capture_owner_id = Nullable(None);
        prospective.operation_id = Nullable(None);
        prospective.request_id = Nullable(Some(id("after-preflight-request")));
        prospective.sequence = U64::new(2);
        prospective.method = Method::BlobBegin;
        prospective.body = serde_json::json!({
            "transfer_id":"after-preflight-transfer",
            "content": canonical::content_ref(b"abc", "application/octet-stream").unwrap(),
            "extensions":{},
        })
        .as_object()
        .unwrap()
        .clone();
        let exchange = provider
            .prepare_exchange(vec![prospective.clone()])
            .unwrap_or_else(|failure| panic!("{}", failure.error()));
        let admitted = exchange
            .preflight_native5_after_protocol_capacity(&after, &blobs)
            .unwrap();
        assert!(admitted.maximum_after_encoded_bytes <= admitted.reserved_after_encoded_bytes);
        assert_eq!(exchange.record().sent(), 0);
        assert_eq!(exchange.record().originals(), &[prospective]);
        assert!(
            exchange
                .preflight_native5_after_protocol_capacity(&small, &blobs)
                .is_err()
        );
        assert!(
            exchange
                .preflight_native5_after_protocol_capacity(&after, &foreign_blobs)
                .is_err()
        );
        assert_eq!(exchange.record().sent(), 0);
        assert_eq!(after.original_allocation_facts().unwrap(), original_copy);
        let held = exchange.abort(ProviderError::Frame("preflight fixture containment"));
        assert_eq!(held.record().sent(), 0);
        assert_eq!(held.record().originals().len(), 1);
        return;
    }
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
    assert_eq!(data["correlations"][0], "source-private.correlations/6");
    assert_eq!(data["correlations"][7].as_object().unwrap().len(), 1);
    let mut target = OriginalFrameReservation::reserve(262144, 8).unwrap();
    assert!(snapshot.prepare_historical_frame_data(&mut target).is_err());
    assert_eq!(target.frames().count(), 0);
    assert!(
        provider
            .authenticate_native5_capture_antecedent(&snapshot)
            .is_err()
    );
    let mut response = request;
    response.message = MessageKind::Response;
    response.body = serde_json::json!({"status":"error","operation_state":"not_started",
        "error":{"code":"UNSUPPORTED_FEATURE","message":"antecedent fixture refusal",
            "effect":"not_started","retryable":false,"details":{}},"extensions":{}})
    .as_object()
    .unwrap()
    .clone();
    let mut exchange = provider
        .prepare_exchange(vec![response.clone()])
        .unwrap_or_else(|failure| {
            panic!("actual terminal preparation refused: {}", failure.error())
        });
    assert_eq!(exchange.record().sent(), 0);
    exchange.publish(&mut |_, _| Ok(())).unwrap();
    let (provider, record) = exchange.into_parts();
    controller.receive().unwrap().unwrap();
    {
        let sent = record.original_sent_frame(&provider, 0).unwrap();
        assert_eq!(sent.original(), &response);
        assert_eq!(&sent.literal().bytes[4..], sent.canonical_body());
        assert!(sent.literal().complete);
        assert_eq!(sent.literal().transferred, sent.literal().bytes.len());
        assert_eq!(record.sent(), record.originals().len());
    }
    assert!(record.original_sent_frame(&controller, 0).is_err());
    assert!(record.original_sent_frame(&provider, 1).is_err());
    let facts = provider
        .authenticate_native5_capture_antecedent(&snapshot)
        .unwrap();
    assert_eq!(facts.snapshot_bytes, snapshot.bytes().len());
    assert_eq!(facts.captured.incoming_frames, 1);
    assert_eq!(facts.captured.outgoing_frames, 0);
    assert_eq!(facts.current.incoming_frames, 1);
    assert_eq!(facts.current.outgoing_frames, 1);
    assert!(facts.current.all_io_complete);
    assert!(
        controller
            .authenticate_native5_capture_antecedent(&snapshot)
            .is_err()
    );
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

#[test]
fn native5_original_fresh_codec_mapping_keeps_actual_policies_and_refuses_other_source() {
    use std::io::Write;

    let (_original_handshake, authority, selection, coordinator) = scope(true);
    let (stream, mut peer) = UnixStream::pair().unwrap();
    let mut original = Connection::new(
        stream,
        authority.clone(),
        Rc::new(Supervisor),
        Rc::new(Uninstalled),
        EndpointRole::Controller,
    )
    .unwrap();
    let mut bank = Some(OriginalFrameReservation::reserve(262144, 8).unwrap());
    original
        .install_native5_controller_codec(&mut bank, selection, coordinator)
        .unwrap();

    let mut request = crate::envelope::tests::request();
    request.session_id = Nullable(Some(authority.session_id().clone()));
    request.incarnation_id = Nullable(Some(authority.incarnation_id().clone()));
    request.sequence = U64::new(2);
    original.send(request.clone()).unwrap();
    let mut response = request;
    response.message = MessageKind::Response;
    response.body =
        serde_json::json!({"status":"completed", "operation_state":"completed", "extensions":{},
        "result":{"operation_id":"operation-1", "operation_state":"running", "outcome":null,
        "observations":[], "next_observation_sequence":"0"}})
        .as_object()
        .unwrap()
        .clone();
    let raw = serde_json::to_vec(&response).unwrap();
    peer.write_all(&(raw.len() as u32).to_be_bytes()).unwrap();
    peer.write_all(&raw).unwrap();
    original.receive().unwrap().unwrap();
    let deadline =
        crate::client::ExchangeDeadline::start(std::time::Duration::from_secs(2)).unwrap();
    let mut reservation =
        ProtocolSnapshotReservation::reserve_complete(4 * 1024 * 1024, 262144, 8).unwrap();
    original
        .capture_native_protocol_state(&mut reservation, ProtocolCaptureCut::HostSettled, &deadline)
        .unwrap();
    let snapshot = original
        .take_native_protocol_snapshot(&mut Some(reservation), ProtocolCaptureCut::HostSettled)
        .unwrap();
    assert_eq!(snapshot.literal_frames().unwrap().count(), 2);

    let (_target_handshake, target_authority, target_selection, target_coordinator) =
        scope_named(true, Some("fresh"), 0);
    let (stream, _target_peer) = UnixStream::pair().unwrap();
    let mut target = Connection::new(
        stream,
        target_authority,
        Rc::new(Supervisor),
        Rc::new(Uninstalled),
        EndpointRole::Controller,
    )
    .unwrap();
    let mut target_bank = Some(OriginalFrameReservation::reserve(262144, 8).unwrap());
    target
        .install_native5_controller_codec(&mut target_bank, target_selection, target_coordinator)
        .unwrap();
    let before = target.original_native5_storage_facts().unwrap();
    let mapping = target.prepare_fresh_protocol_mapping(&snapshot).unwrap();
    mapping.validate_original(&snapshot).unwrap();
    target
        .authenticate_fresh_native5_protocol_mapping(&snapshot, &mapping)
        .unwrap();
    let (_copy_handshake, copy_authority, copy_selection, copy_coordinator) =
        scope_named(true, Some("fresh"), 0);
    let (copy_stream, _copy_peer) = UnixStream::pair().unwrap();
    let mut copy = Connection::new(
        copy_stream,
        copy_authority,
        Rc::new(Supervisor),
        Rc::new(Uninstalled),
        EndpointRole::Controller,
    )
    .unwrap();
    let mut copy_bank = Some(OriginalFrameReservation::reserve(262144, 8).unwrap());
    copy.install_native5_controller_codec(&mut copy_bank, copy_selection, copy_coordinator)
        .unwrap();
    assert!(
        copy.authenticate_fresh_native5_protocol_mapping(&snapshot, &mapping)
            .is_err()
    );
    copy.authenticate_native5_source_codec().unwrap();
    assert_eq!(
        copy.original_native5_storage_facts()
            .unwrap()
            .retained_bytes,
        0
    );
    let policies = serde_json::to_value(mapping.original_native5_codec_views().unwrap()).unwrap();
    assert_eq!(policies[0][0], "controller-packet/5");
    assert_eq!(policies[1][0], "controller-packet/5");
    assert_ne!(
        policies[0][1][0]["realization"]["bindings"][0]["authority"]["session_id"],
        policies[1][1][0]["realization"]["bindings"][0]["authority"]["session_id"]
    );
    assert_eq!(target.original_native5_storage_facts().unwrap(), before);

    let (_other_handshake, other_authority, other_selection, other_coordinator) =
        scope_named(true, Some("other"), 1);
    let (stream, _other_peer) = UnixStream::pair().unwrap();
    let mut other = Connection::new(
        stream,
        other_authority,
        Rc::new(Supervisor),
        Rc::new(Uninstalled),
        EndpointRole::Controller,
    )
    .unwrap();
    let mut other_bank = Some(OriginalFrameReservation::reserve(262144, 8).unwrap());
    other
        .install_native5_controller_codec(&mut other_bank, other_selection, other_coordinator)
        .unwrap();
    let other_before = other.original_native5_storage_facts().unwrap();
    assert!(other.prepare_fresh_protocol_mapping(&snapshot).is_err());
    assert_eq!(
        other.original_native5_storage_facts().unwrap(),
        other_before
    );
    assert_eq!(snapshot.literal_frames().unwrap().count(), 2);
}

#[path = "native5_endpoint_recovery_tests.rs"]
mod endpoint_recovery_tests;

#[path = "native5_birth_tests.rs"]
mod birth_tests;

#[path = "native5_policy_dynamic_tests.rs"]
mod policy_dynamic_tests;

#[test]
fn native5_compact_snapshot_requires_same_installed_profile_and_exact_bound() {
    use crate::reference_packet::service::PacketNative5CaptureProfile;
    let (_handshake, authority, selection, mut coordinator) = scope(true);
    let mut owned_coordinator = coordinator.bytes.into_vec();
    let required = owned_coordinator.capacity() + 256;
    owned_coordinator.try_reserve_exact(required).unwrap();
    let coordinator_capacity = owned_coordinator.capacity();
    let coordinator_body = owned_coordinator.clone();
    coordinator.bytes = Bytes::new(owned_coordinator);
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
    let profile = PacketNative5CaptureProfile::CompactBytes7 {
        native_before_protocol_bytes: U64::new(65536),
        native_after_protocol_bytes: U64::new(131072),
        host_protocol_bytes: U64::new(262144),
    };
    controller
        .install_native5_controller_codec_with_profile(
            &mut bank,
            selection,
            coordinator,
            profile.clone(),
        )
        .unwrap();
    assert_eq!(
        controller.original_native5_capture_profile().unwrap(),
        &profile
    );
    let original = controller.original_native5_storage_facts().unwrap();
    let deadline =
        crate::client::ExchangeDeadline::start(std::time::Duration::from_secs(2)).unwrap();

    let mut legacy = ProtocolSnapshotReservation::reserve_complete(262144, 262144, 8).unwrap();
    assert!(
        controller
            .capture_native_protocol_state(&mut legacy, ProtocolCaptureCut::HostSettled, &deadline)
            .is_err()
    );
    assert_eq!(
        legacy.original_allocation_facts().unwrap().encoded_length,
        0
    );
    let mut mismatched =
        ProtocolSnapshotReservation::reserve_complete_compact(131072, 262144, 8).unwrap();
    assert!(
        controller
            .capture_native_protocol_state(
                &mut mismatched,
                ProtocolCaptureCut::HostSettled,
                &deadline
            )
            .is_err()
    );
    assert_eq!(
        mismatched
            .original_allocation_facts()
            .unwrap()
            .encoded_length,
        0
    );
    assert_eq!(
        controller.original_native5_storage_facts().unwrap(),
        original
    );

    let mut compact =
        ProtocolSnapshotReservation::reserve_complete_compact(262144, 262144, 8).unwrap();
    controller
        .capture_native_protocol_state(&mut compact, ProtocolCaptureCut::HostSettled, &deadline)
        .unwrap();
    let snapshot = controller
        .take_native_protocol_snapshot(&mut Some(compact), ProtocolCaptureCut::HostSettled)
        .unwrap();
    assert!(snapshot.uses_compact_encoding().unwrap());
    let value: Value = serde_json::from_slice(snapshot.bytes()).unwrap();
    assert_eq!(value[0], "source-private.native-cnp/7");
    assert_eq!(value[2]["frames"][6][0], "source-private.compact-bytes/7");
    assert_eq!(value[2]["frames"][4], original.byte_capacity);
    let codec = &value[2]["native5_codec"];
    assert_eq!(codec[0], "controller-packet-compact/7");
    assert_eq!(codec[1][1][1], coordinator_capacity);
    let encoded = serde_json::to_vec(&codec[1][1][2]).unwrap();
    let plan = crate::protocol_snapshot::compact_bytes::ValidatedCompactBytes::validate(
        &encoded,
        encoded.len(),
        coordinator_body.len(),
    )
    .unwrap();
    let mut recovered_coordinator = Vec::with_capacity(coordinator_capacity);
    let pointer = recovered_coordinator.as_ptr();
    plan.fill_preowned(&mut recovered_coordinator).unwrap();
    assert_eq!(recovered_coordinator, coordinator_body);
    assert_eq!(recovered_coordinator.capacity(), coordinator_capacity);
    assert_eq!(recovered_coordinator.as_ptr(), pointer);

    assert_eq!(
        snapshot
            .original_allocation_facts()
            .unwrap()
            .maximum_encoded_bytes,
        262144
    );

    let facts = snapshot.original_allocation_facts().unwrap();
    let pointer = snapshot.bytes().as_ptr();
    let (owner, mut archive) = snapshot.into_original_payload();
    let retained_metadata = owner.original_retained_metadata_facts().unwrap();
    assert!(retained_metadata.string_capacity_bytes > 0);
    assert!(retained_metadata.vector_capacity_bytes > 0);
    assert!(retained_metadata.shared_backing_views >= 4);
    assert_eq!(
        owner.original_retained_metadata_facts().unwrap(),
        retained_metadata
    );
    assert_eq!(archive.as_ptr(), pointer);
    assert_eq!(archive.capacity(), facts.encoded_capacity);
    assert_eq!(owner.original_allocation_facts().unwrap(), facts);
    owner.validate_original_payload(&archive).unwrap();
    serde_json::to_vec(&owner.original_association_view().unwrap()).unwrap();
    owner.original_physical_cut_expired().unwrap();

    let copy = archive.clone();
    assert_ne!(copy.as_ptr(), archive.as_ptr());
    owner.validate_original_payload(&copy).unwrap();
    // Matching bytes do not credit the copy's distinct live allocation.
    assert_eq!(copy.len(), facts.encoded_length);
    assert_eq!(archive.capacity(), facts.encoded_capacity);
    let mut changed = copy;
    changed[0] ^= 1;
    assert!(owner.validate_original_payload(&changed).is_err());
    let additional = archive.capacity() + 1;
    archive.try_reserve_exact(additional).unwrap();
    assert!(archive.capacity() > facts.encoded_capacity);
    owner.validate_original_payload(&archive).unwrap();
    assert_eq!(owner.original_allocation_facts().unwrap(), facts);
    // The archive must charge this actual capacity, not immutable issuance facts.
    assert!(archive.capacity() + changed.capacity() > facts.encoded_capacity);
}

#[test]
fn native5_controller_current_codec_refuses_revocation_foreign_scope_and_changed_features() {
    let (handshake, authority, selection, coordinator) = scope(true);
    let (host, _peer) = UnixStream::pair().unwrap();
    let mut controller = Connection::new(
        host,
        authority.clone(),
        Rc::new(Supervisor),
        Rc::new(Uninstalled),
        EndpointRole::Controller,
    )
    .unwrap();
    let mut bank = Some(OriginalFrameReservation::reserve(262144, 8).unwrap());
    controller
        .install_native5_controller_codec(&mut bank, selection, coordinator)
        .unwrap();
    let codec = controller.retained_native5_codec_owner().unwrap().clone();
    let mut original = crate::envelope::tests::request();
    original.session_id = Nullable(Some(authority.session_id().clone()));
    original.incarnation_id = Nullable(Some(authority.incarnation_id().clone()));
    original.method = Method::Discover;
    original.body = serde_json::json!({"profile_ids":[],"extensions":{}})
        .as_object()
        .unwrap()
        .clone();
    original.extensions.clear();
    let body = ReceivedBody::Request(Box::new(
        crate::bodies::decode_request(original.method, &original.body).unwrap(),
    ));
    codec.verify(&authority, &original, &body).unwrap();
    let (_foreign_owner, foreign, _, _) = scope_named(true, Some("foreign-controller"), 0);
    assert!(codec.verify(&foreign, &original, &body).is_err());
    let (_legacy_owner, legacy, _, _) = scope(false);
    assert!(codec.verify(&legacy, &original, &body).is_err());
    let (_limit_owner, limited, _, _) = scope_named_with_limits(
        true,
        None,
        0,
        Some(Limits {
            frame_bytes: U64::new(65536),
            requests: U64::new(8),
            journal_entries: U64::new(64),
            nesting: U64::new(64),
            blob_chunk_bytes: U64::new(8192),
        }),
    );
    assert!(codec.verify(&limited, &original, &body).is_err());
    codec.verify(&authority, &original, &body).unwrap();
    drop(handshake);
    for _ in 0..2 {
        assert!(codec.verify(&authority, &original, &body).is_err());
        assert!(controller.authenticate_native5_source_codec().is_err());
    }
}

#[allow(clippy::unwrap_used)]
pub(super) fn original_canonical_ack_controller_scope() -> (
    Handshake,
    ConnectionAuthority,
    PacketControlSelection,
    InstalledContent,
) {
    original_canonical_ack_controller_scope_with_identity_suffix(None)
}

#[allow(clippy::unwrap_used)]
pub(super) fn original_canonical_ack_controller_scope_with_identity_suffix(
    suffix: Option<&str>,
) -> (
    Handshake,
    ConnectionAuthority,
    PacketControlSelection,
    InstalledContent,
) {
    let participant = 0;
    let mut coordinator = five_with_ack_emitter(
        Some(&crate::reference_packet::service::PacketNative5ConfirmationSelection::AfterProtocolPoll5),
        Some(&crate::reference_packet::service::PacketNative5AckEmitterSelection::CanonicalSdkBlob5),
    );
    if let Some(suffix) = suffix {
        rename_scope(&mut coordinator, suffix);
    }
    let selection = coordinator.participants[participant].clone();
    let binding = &selection.realization.bindings[0];
    let session = binding.authority.session_id.clone();
    let incarnation = binding.authority.incarnation_id.clone();
    let mut features = vec![
        id("cnp.core/1"),
        id(crate::reference_packet::input::PACKET_INPUT_FEATURE),
    ];
    features.push(id(contracts::PACKET_COMPLETE_LINEAGE_FEATURE));
    features.extend([
        id("cnp.control-evidence/1"),
        id(crate::reference_packet::service::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE),
        id(crate::reference_packet::service::ack_emitter::PACKET_NATIVE_CANONICAL_ACK_FEATURE),
        id(crate::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE),
    ]);
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
            ), (
                crate::reference_packet::service::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION.into(),
                id(crate::reference_packet::service::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE),
            ), (
                crate::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE.into(),
                id(crate::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE),
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
            id(&format!("codec-fixture-connection-{}", "selected-ack")),
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
