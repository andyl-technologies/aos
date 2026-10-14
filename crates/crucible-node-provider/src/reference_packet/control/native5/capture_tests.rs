//! Tests same-owner native Capture journals with an explicitly modeled activation.
//!
//! Genuine Unix model ownership is retained. These component controls model the
//! active lifecycle directly; they do not qualify a child, transport prefix,
//! common admission, installed capture or fresh restoration.

#![allow(clippy::unwrap_used)]

use super::tests::{fixture, producer, request};
use super::*;
use crate::envelope::MessageKind;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn modeled_active_control() -> PacketControl {
    modeled_active_control_with_profile(None)
}

fn modeled_active_control_with_profile(
    profile: Option<crate::reference_packet::service::PacketNative5CaptureProfile>,
) -> PacketControl {
    let coordinator = fixture::five();
    let mut native = PacketControl::new_complete_producer(
        coordinator.participants[0].clone(),
        producer(),
        coordinator.clone(),
    )
    .unwrap();
    native
        .bind_complete_original_storage(
            crate::reference_packet::service::PacketNative5StorageLimits {
                snapshot_bytes: U64::new(4 * 1024 * 1024),
                control_snapshot_bytes: U64::new(1024 * 1024),
                protocol_snapshot_bytes: U64::new(32 * 1024 * 1024),
                frame_bank_bytes: U64::new(8 * 1024 * 1024),
                frames_per_direction: U64::new(4096),
                hello_bytes: U64::new(1024 * 1024),
                settlement_bytes: U64::new(32 * 1024 * 1024),
            },
            crate::handshake::Limits {
                frame_bytes: U64::new(65536),
                requests: U64::new(256),
                journal_entries: U64::new(4096),
                nesting: U64::new(64),
                blob_chunk_bytes: U64::new(4096),
            },
        )
        .unwrap();
    if let Some(profile) = profile {
        native
            .bind_complete_original_capture_profile(profile)
            .unwrap();
    }
    native.program.open_gate().unwrap();
    native.active = Some(WorldActivateRequest {
        transaction_id: native.selection.transaction.clone(),
        activation_id: id("modeled-native5-activation"),
        world_generation: U64::new(1),
        prepared_token: native.selection.prepared_token.clone(),
        world_binding_hash: native.selection.world.clone(),
        gate_id: native.selection.gate.clone(),
        activation_manifest: canonical::content_ref(
            b"modeled-test-activation",
            "application/octet-stream",
        )
        .unwrap(),
        extensions: Extensions::new(),
    });
    native
}

fn capture_request(native: &PacketControl) -> Envelope {
    let owner = &native.selection.realization.owner_bindings[0];
    let active = native.active.as_ref().unwrap();
    let arguments = CaptureArguments {
        capture_id: id("component-capture"),
        participant_ids: owner.owner.participant_ids.clone(),
        cut_id: id("component-cut"),
        cut: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
        event_ordinal: U64::new(0),
        ordering_profile: "superdense-v1".into(),
        preservation_contract: id("source-owned.packet-complete-original-lineage/5"),
    };
    let begin = BeginRequest {
        kind: BeginKind::Capture,
        binding_hash: owner.identity().unwrap(),
        owner_generation: native.selection.realization.bindings[0]
            .authority
            .owner_generation,
        activation_id: Nullable(Some(active.activation_id.clone())),
        world_generation: active.world_generation,
        arguments: object(arguments).unwrap(),
        extensions: Extensions::new(),
    };
    let mut envelope = request(native);
    envelope.message = MessageKind::Request;
    envelope.method = Method::Begin;
    envelope.request_id = Nullable(Some(id("component-capture-request")));
    envelope.operation_id = Nullable(Some(id("component-capture-operation")));
    envelope.capture_owner_id = Nullable(Some(
        native.selection.realization.bindings[0]
            .compatibility
            .capture_owner
            .id
            .clone(),
    ));
    envelope.body = object(begin).unwrap();
    envelope
}

#[test]
fn capture_retains_pending_original_and_complete_coordinator_before_settlement() {
    let mut native = modeled_active_control();
    let original = capture_request(&native);
    let before = native.program.inventory_hash().unwrap();
    let reservation = native.reserve_original_capture(&original).unwrap();
    let component = native
        .capture_reserved_control(&reservation, 8 * 1024 * 1024)
        .unwrap();
    let decoded = decode_packet_control_snapshot(
        component.snapshot().bytes(),
        component.snapshot().reference(),
        8 * 1024 * 1024,
    )
    .unwrap();
    assert_eq!(decoded.administrative_cut(), reservation.arguments().cut);
    let body = canonical::parse_json(component.snapshot().bytes(), 8 * 1024 * 1024).unwrap();
    assert_eq!(
        body["control"]["complete_coordinator"]["schema"],
        "source-owned.packet-complete-coordinator-installation/5"
    );
    assert_eq!(
        body["control"]["originals"][0]["response_body"]["operation_state"],
        "unknown"
    );
    assert_eq!(before, native.program.inventory_hash().unwrap());

    let complete = canonical::content_ref(
        b"component-only-whole-snapshot-placeholder",
        "application/octet-stream",
    )
    .unwrap();
    let prospective = native
        .original_capture_reply(&reservation, &component, &complete)
        .unwrap();
    let mut forged = PacketControlReply {
        body: prospective.body.clone(),
        evidence: Vec::new(),
    };
    forged.body.insert("extra".into(), Value::Bool(true));
    assert!(
        native
            .settle_original_capture(&reservation, &component, &complete, &forged)
            .is_err()
    );
    let retained = native
        .originals
        .get(original.request_id.0.as_ref().unwrap())
        .unwrap();
    assert_eq!(retained.1.body["operation_state"], "unknown");
    assert!(native.current_operation.is_some());

    native
        .settle_original_capture(&reservation, &component, &complete, &prospective)
        .unwrap();
    let retained = native
        .originals
        .get(original.request_id.0.as_ref().unwrap())
        .unwrap();
    assert_eq!(retained.1.body, prospective.body);
    assert!(native.current_operation.is_none());
    assert!(
        native
            .settle_original_capture(&reservation, &component, &complete, &prospective)
            .is_err()
    );
    assert_eq!(before, native.program.inventory_hash().unwrap());
}

#[test]
fn capture_refuses_foreign_activation_and_equal_shaped_control_without_enrollment() {
    let mut native = modeled_active_control();
    let original = capture_request(&native);
    for field in ["activation_id", "world_generation"] {
        let mut wrong = original.clone();
        wrong.body.insert(
            field.into(),
            if field == "activation_id" {
                Value::String("foreign-activation".into())
            } else {
                Value::String("2".into())
            },
        );
        assert!(native.reserve_original_capture(&wrong).is_err());
        assert!(native.originals.is_empty());
        assert!(native.current_operation.is_none());
    }
    let reservation = native.reserve_original_capture(&original).unwrap();
    let component = native
        .capture_reserved_control(&reservation, 8 * 1024 * 1024)
        .unwrap();
    let mut equal = modeled_active_control();
    let equal_original = capture_request(&equal);
    let equal_reservation = equal.reserve_original_capture(&equal_original).unwrap();
    let complete =
        canonical::content_ref(b"component-placeholder", "application/octet-stream").unwrap();
    assert!(
        equal
            .original_capture_reply(&equal_reservation, &component, &complete)
            .is_err()
    );
    assert!(
        native
            .original_capture_reply(&equal_reservation, &component, &complete)
            .is_err()
    );
    assert_eq!(
        native
            .originals
            .get(original.request_id.0.as_ref().unwrap())
            .unwrap()
            .1
            .body["operation_state"],
        "unknown"
    );
    assert!(native.current_operation.is_some());
}

#[test]
fn capture_preflight_preserves_originals_on_credit_refusal_and_bounds_pending_state() {
    let mut native = modeled_active_control();
    let request = capture_request(&native);
    let model = native.program.inventory_hash().unwrap();
    let maximum = 8 * 1024 * 1024;

    assert!(native.preflight_original_capture(&request, 1024).is_err());
    assert!(native.originals.is_empty());
    assert!(native.begins.is_empty());
    assert!(native.begin_requests.is_empty());
    assert!(native.current_operation.is_none());
    assert_eq!(native.program.inventory_hash().unwrap(), model);

    let bound = native
        .preflight_original_capture(&request, maximum)
        .unwrap();
    assert!(native.originals.is_empty());
    assert!(native.begins.is_empty());
    assert!(native.begin_requests.is_empty());
    assert!(native.current_operation.is_none());
    assert_eq!(native.program.inventory_hash().unwrap(), model);

    let reservation = native.reserve_original_capture(&request).unwrap();
    let component = native
        .capture_reserved_control(&reservation, maximum)
        .unwrap();
    assert!(component.snapshot().bytes().len() <= bound);
    assert_eq!(native.program.inventory_hash().unwrap(), model);
    assert!(
        native
            .preflight_original_capture(&request, maximum)
            .is_err()
    );
}

#[test]
fn original_endpoint_storage_tuple_cannot_be_reselected_after_refusal() {
    let coordinator = fixture::five();
    let mut native = PacketControl::new_complete_producer(
        coordinator.participants[0].clone(),
        producer(),
        coordinator,
    )
    .unwrap();
    super::tests::bind_storage(&mut native);
    let selected = super::tests::modeled_storage_selection();
    let before = native.program.inventory_hash().unwrap();
    native
        .authenticate_complete_storage(&selected.storage, selected.limits)
        .unwrap();

    let mut other_storage = selected.storage.clone();
    other_storage.protocol_snapshot_bytes =
        U64::new(other_storage.protocol_snapshot_bytes.get() + 1);
    other_storage.validate(&selected.limits).unwrap();
    assert!(
        native
            .authenticate_complete_storage(&other_storage, selected.limits)
            .is_err()
    );

    let mut other_limits = selected.limits;
    other_limits.journal_entries = U64::new(other_limits.journal_entries.get() + 1);
    selected.storage.validate(&other_limits).unwrap();
    assert!(
        native
            .authenticate_complete_storage(&selected.storage, other_limits)
            .is_err()
    );

    native
        .authenticate_complete_storage(&selected.storage, selected.limits)
        .unwrap();
    assert_eq!(native.program.inventory_hash().unwrap(), before);
    assert!(native.originals.is_empty());
    assert!(native.begins.is_empty());
    assert!(native.active.is_none());
    assert!(!native.realized);
    assert_eq!(native.complete_storage.as_ref(), Some(&selected));
}

#[test]
fn control_snapshot_retains_closed_compact_profile_and_rejects_unbound_data() {
    use crate::reference_packet::service::PacketNative5CaptureProfile;

    let profile = PacketNative5CaptureProfile::CompactBytes7 {
        native_before_protocol_bytes: U64::new(1024 * 1024),
        native_after_protocol_bytes: U64::new(2 * 1024 * 1024),
        host_protocol_bytes: U64::new(32 * 1024 * 1024),
    };
    let native = modeled_active_control_with_profile(Some(profile.clone()));
    let cut = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
    let snapshot = native.capture_control_state(cut, 8 * 1024 * 1024).unwrap();
    decode_packet_control_snapshot(snapshot.bytes(), snapshot.reference(), 8 * 1024 * 1024)
        .unwrap();
    let mut value = canonical::parse_json(snapshot.bytes(), 8 * 1024 * 1024).unwrap();
    assert_eq!(
        value["control"]["complete_capture_profile"],
        serde_json::to_value(profile).unwrap()
    );

    value["control"]["complete_storage"] = Value::Null;
    let bytes = canonical::canonical_json(&value).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    assert!(decode_packet_control_snapshot(&bytes, &reference, 8 * 1024 * 1024).is_err());
}
