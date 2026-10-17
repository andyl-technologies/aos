//! Tests real local model ownership under inert complete-selection declarations.
//!
//! UnixDatagram pairs below are genuine. These controls exercise constructors,
//! unopened native gates and source-issued record closure, never installed
//! preservation, native child capture, full transport or restored capability.

// crucible-lint: allow panic-shortcut -- Assertion panics are the control verdict.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::envelope::MessageKind;
use crate::reference_packet::{
    PacketEvent,
    connected::{PacketConnectedDefinition, PacketInputConnection},
};
use std::os::unix::net::UnixDatagram;

#[path = "fixture.rs"]
pub(super) mod fixture;

fn id(name: &str) -> Id {
    Id::new(name).unwrap()
}

pub(super) fn modeled_storage_selection() -> PacketNative5StorageSelection {
    PacketNative5StorageSelection {
        storage: PacketNative5StorageLimits {
            snapshot_bytes: U64::new(65_536),
            control_snapshot_bytes: U64::new(65_536),
            protocol_snapshot_bytes: U64::new(1024 * 1024),
            frame_bank_bytes: U64::new(1024 * 1024),
            frames_per_direction: U64::new(64),
            hello_bytes: U64::new(2 * 65_536 + 8),
            settlement_bytes: U64::new(1024 * 1024),
        },
        limits: Limits {
            frame_bytes: U64::new(65_536),
            nesting: U64::new(64),
            requests: U64::new(32),
            journal_entries: U64::new(64),
            blob_chunk_bytes: U64::new(4096),
        },
    }
}

pub(super) fn bind_storage(control: &mut PacketControl) {
    // This fixture binds data only; it allocates no endpoint or client bank.
    let selected = modeled_storage_selection();
    control
        .bind_complete_original_storage(selected.storage, selected.limits)
        .unwrap();
}

pub(super) fn producer() -> PacketProgram {
    let (socket, _peer) = UnixDatagram::pair().unwrap();
    PacketProgram::new(
        vec![
            PacketEvent {
                id: id("private-callback-0"),
                evaluation: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                completion: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                payload: None,
            },
            PacketEvent {
                id: id("packet-callback-0"),
                evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
                completion: Position::new(U64::new(5), U64::new(1), Phase::Publication),
                payload: Some(Bytes::new(b"original-producer".to_vec())),
            },
        ],
        socket,
    )
    .unwrap()
}

pub(super) fn reactive(
    coordinator: &PacketNative5CoordinatorInstallation,
    member: usize,
) -> PacketConnectedProgram {
    let world: WorldBinding =
        serde_json::from_value(coordinator.template["world"].clone()).unwrap();
    let node = &coordinator.participants[member].realization.descriptors[0].id;
    let incoming = world
        .connections
        .iter()
        .filter(|connection| &connection.consumer.node_id == node)
        .map(|connection| PacketInputConnection {
            id: connection.id.clone(),
            policy: connection.policy_ref.clone(),
            producer: connection.producer.clone(),
            consumer: connection.consumer.clone(),
            delay_ps: connection.minimum_latency_ps,
        })
        .collect();
    let output = world
        .connections
        .iter()
        .find(|connection| &connection.producer.node_id == node)
        .map(|connection| connection.producer.clone());
    let (socket, _peer) = UnixDatagram::pair().unwrap();
    PacketConnectedProgram::new(
        PacketConnectedDefinition {
            schema: "source-owned.packet-connected-program/4".into(),
            connections: incoming,
            output,
        },
        socket,
    )
    .unwrap()
}

pub(super) fn request(control: &PacketControl) -> Envelope {
    let binding = &control.selection.realization.bindings[0];
    Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(binding.authority.session_id.clone())),
        incarnation_id: Nullable(Some(binding.authority.incarnation_id.clone())),
        node_id: Nullable(Some(binding.compatibility.node_id.clone())),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        request_id: Nullable(Some(id("native5-original-read"))),
        operation_id: Nullable(None),
        sequence: U64::new(3),
        method: Method::Discover,
        body: serde_json::from_value(
            serde_json::json!({"cursor":null,"maximum_items":"1","profile_ids":[],"extensions":{}}),
        )
        .unwrap(),
        extensions: Extensions::new(),
    }
}

#[test]
fn complete_native_boot_uses_actual_producer_and_reactive_models() {
    let coordinator = fixture::five();
    let mut control = PacketControl::new_complete_producer(
        coordinator.participants[0].clone(),
        producer(),
        coordinator.clone(),
    )
    .unwrap();
    assert!(control.inventory().unwrap().gate_closed);
    assert!(control.active.is_none());
    assert!(control.begins.is_empty());
    assert!(control.connected_coordinator.is_none());
    bind_storage(&mut control);
    let original = request(&control);
    let before = control.program.inventory_hash().unwrap();
    let proof = control.proof(&original, None).unwrap();
    let evidence = control.record_evidence(proof).unwrap();
    assert_eq!(evidence.len(), 2);
    let raw: PacketNativeRecord = decode_record(&evidence[0].1).unwrap();
    assert_eq!(raw.schema, "source-owned.packet-native/2");
    assert_eq!(raw.original, original);
    let wrapper: PacketNative5Record = decode_record(&evidence[1].1).unwrap();
    assert_eq!(wrapper.native_record, evidence[0].0);
    assert_eq!(wrapper.original, original);
    assert_eq!(wrapper.native_pid, U64::new(u64::from(std::process::id())));
    assert_eq!(before, control.program.inventory_hash().unwrap());

    for member in [1, 2] {
        let mut control = PacketControl::new_complete_reactive(
            coordinator.participants[member].clone(),
            reactive(&coordinator, member),
            coordinator.clone(),
        )
        .unwrap();
        bind_storage(&mut control);
        let original = request(&control);
        let proof = control.proof(&original, None).unwrap();
        let evidence = control.record_evidence(proof).unwrap();
        let raw: PacketConnectedNativeRecord = decode_record(&evidence[0].1).unwrap();
        let wrapper: PacketNative5Record = decode_record(&evidence[1].1).unwrap();
        assert_eq!(raw.schema, "source-owned.packet-native/4");
        assert_eq!(raw.original, original);
        assert!(raw.inventory.gate_closed);
        assert!(raw.inventory.stages.is_empty());
        assert!(raw.inventory.commits.is_empty());
        assert_eq!(wrapper.native_record, evidence[0].0);
        assert!(control.active.is_none());
    }
}

#[test]
fn complete_native_refuses_open_gate_and_changed_selected_model() {
    let coordinator = fixture::five();
    let mut opened = producer();
    opened.open_gate().unwrap();
    assert!(
        PacketControl::new_complete_producer(
            coordinator.participants[0].clone(),
            opened,
            coordinator.clone()
        )
        .is_err()
    );
    let foreign = reactive(&coordinator, 2);
    assert!(
        PacketControl::new_complete_reactive(
            coordinator.participants[1].clone(),
            foreign,
            coordinator.clone()
        )
        .is_err()
    );
    let mut changed = coordinator.clone();
    changed.schema = "source-owned.packet-connected-coordinator-installation/4".into();
    assert!(
        PacketControl::new_complete_producer(
            coordinator.participants[0].clone(),
            producer(),
            changed
        )
        .is_err()
    );
}

#[test]
fn complete_live_receipt_rejects_foreign_original_and_preserves_underlying_bytes() {
    let coordinator = fixture::five();
    let mut control = PacketControl::new_complete_producer(
        coordinator.participants[0].clone(),
        producer(),
        coordinator,
    )
    .unwrap();
    bind_storage(&mut control);
    let original = request(&control);
    let proof = control.proof(&original, None).unwrap();
    let evidence = control.record_evidence(proof).unwrap();
    let raw = evidence[0].1.clone();
    let mut changed = original.clone();
    changed.request_id = Nullable(Some(id("equal-shape-foreign-request")));
    assert!(
        control
            .retain_complete_record(&changed, evidence[0].0.clone())
            .is_err()
    );
    assert_eq!(control.content.get(&evidence[0].0).unwrap(), &raw);
    control.capture_creator = control.capture_creator.wrapping_add(1);
    assert!(
        control
            .retain_complete_record(&original, evidence[0].0.clone())
            .is_err()
    );
    assert!(control.record_evidence(evidence[1].clone()).is_err());
    assert!(control.originals.is_empty());
    assert!(control.begins.is_empty());
    assert!(control.inventory().unwrap().gate_closed);
}

#[test]
fn live_record_codec_keeps_actual_typed_producer_and_reactive_originals() {
    let coordinator = fixture::five();
    for member in 0..3 {
        let selected = coordinator.participants[member].clone();
        let mut control = if member == 0 {
            PacketControl::new_complete_producer(selected.clone(), producer(), coordinator.clone())
                .unwrap()
        } else {
            PacketControl::new_complete_reactive(
                selected.clone(),
                reactive(&coordinator, member),
                coordinator.clone(),
            )
            .unwrap()
        };
        bind_storage(&mut control);
        let original = request(&control);
        let proof = control.proof(&original, None).unwrap();
        let evidence = control.record_evidence(proof).unwrap();
        let receipt: PacketNative5Record = decode_record(&evidence[1].1).unwrap();
        let checked = receipt
            .verify_original_record_data(&selected, std::process::id(), &original, &evidence[0].1)
            .unwrap();
        match checked {
            PacketNative5UnderlyingRecord::Producer(record) => {
                assert_eq!(member, 0);
                assert_eq!(record.original, original);
                assert_eq!(encode(&record).unwrap(), evidence[0].1);
            }
            PacketNative5UnderlyingRecord::Reactive(record) => {
                assert_ne!(member, 0);
                assert_eq!(record.original, original);
                assert_eq!(encode(record.as_ref()).unwrap(), evidence[0].1);
            }
        }
        assert!(control.active.is_none());
        assert!(control.begins.is_empty());
        assert!(control.inventory().unwrap().gate_closed);
    }
}

#[test]
fn live_record_codec_refuses_full_tuple_and_raw_byte_substitution() {
    let coordinator = fixture::five();
    let selected = coordinator.participants[1].clone();
    let mut control = PacketControl::new_complete_reactive(
        selected.clone(),
        reactive(&coordinator, 1),
        coordinator,
    )
    .unwrap();
    bind_storage(&mut control);
    let original = request(&control);
    let proof = control.proof(&original, None).unwrap();
    let evidence = control.record_evidence(proof).unwrap();
    let receipt: PacketNative5Record = decode_record(&evidence[1].1).unwrap();
    let raw = &evidence[0].1;
    let before = control.program.inventory_hash().unwrap();
    let verify = |candidate: &PacketNative5Record, body: &[u8], pid| {
        candidate.verify_original_record_data(&selected, pid, &original, body)
    };

    let mut foreign = receipt.clone();
    foreign.owner = id("foreign-owner-same-native-record");
    assert!(verify(&foreign, raw, std::process::id()).is_err());
    let mut foreign = receipt.clone();
    foreign.input_epoch = id("foreign-input-epoch");
    assert!(verify(&foreign, raw, std::process::id()).is_err());
    let mut foreign = receipt.clone();
    foreign.native_record.media_type = "application/octet-stream".into();
    assert!(verify(&foreign, raw, std::process::id()).is_err());
    let mut foreign = receipt.clone();
    foreign.native_pid = U64::new(u64::from(std::process::id()) + 1);
    assert!(verify(&foreign, raw, std::process::id().wrapping_add(1)).is_err());
    let mut foreign = receipt.clone();
    foreign.original.request_id = Nullable(Some(id("different-original-journal-row")));
    assert!(verify(&foreign, raw, std::process::id()).is_err());

    let mut changed = raw.clone();
    changed[0] = b'[';
    assert!(verify(&receipt, &changed, std::process::id()).is_err());
    let mut record: PacketConnectedNativeRecord = decode_record(raw).unwrap();
    record.schema = "source-owned.packet-native/2".into();
    let changed = encode(&record).unwrap();
    let mut foreign = receipt.clone();
    foreign.native_record = reference(&changed).unwrap();
    assert!(verify(&foreign, &changed, std::process::id()).is_err());

    assert_eq!(control.program.inventory_hash().unwrap(), before);
    assert_eq!(control.content.get(&evidence[0].0).unwrap(), raw);
    assert!(control.originals.is_empty());
    assert!(control.begins.is_empty());
}

#[test]
fn selected_storage_is_required_before_dispatch_or_preparation() {
    let coordinator = fixture::five();
    let mut control = PacketControl::new_complete_producer(
        coordinator.participants[0].clone(),
        producer(),
        coordinator,
    )
    .unwrap();
    let original = request(&control);
    let before = control.program.inventory_hash().unwrap();
    let mut called = false;
    assert!(
        control
            .dispatch_with_preflight(&original, &mut |_| {
                called = true;
                Ok(())
            })
            .is_err()
    );
    assert!(!called);
    assert!(control.originals.is_empty());
    assert!(control.content.is_empty());
    assert_eq!(control.content_bytes, 0);
    assert!(!control.fenced);
    assert!(!control.native_effect_attempted);
    assert_eq!(control.program.inventory_hash().unwrap(), before);

    bind_storage(&mut control);
    assert_eq!(
        control.complete_storage.as_ref(),
        Some(&modeled_storage_selection())
    );
}

#[test]
fn selected_storage_refuses_invalid_birth_and_rebinding() {
    let coordinator = fixture::five();
    let mut control = PacketControl::new_complete_producer(
        coordinator.participants[0].clone(),
        producer(),
        coordinator,
    )
    .unwrap();
    let mut invalid = modeled_storage_selection();
    invalid.storage.frames_per_direction = U64::new(1);
    assert!(
        control
            .bind_complete_original_storage(invalid.storage, invalid.limits)
            .is_err()
    );
    assert!(control.complete_storage.is_none());
    assert!(control.originals.is_empty());
    assert!(control.content.is_empty());

    bind_storage(&mut control);
    let original = control.complete_storage.clone();
    let mut replacement = modeled_storage_selection();
    replacement.limits.requests = U64::new(31);
    assert!(
        control
            .bind_complete_original_storage(replacement.storage, replacement.limits)
            .is_err()
    );
    assert_eq!(control.complete_storage, original);
}

#[test]
fn live_record_codec_refuses_incomplete_selected_storage() {
    let coordinator = fixture::five();
    let selected = coordinator.participants[0].clone();
    let mut control =
        PacketControl::new_complete_producer(selected.clone(), producer(), coordinator).unwrap();
    bind_storage(&mut control);
    let original = request(&control);
    let proof = control.proof(&original, None).unwrap();
    let evidence = control.record_evidence(proof).unwrap();
    let receipt: PacketNative5Record = decode_record(&evidence[1].1).unwrap();
    assert_eq!(receipt.storage_selection, modeled_storage_selection());
    let mut changed = receipt;
    changed.storage_selection.storage.frames_per_direction = U64::new(1);
    assert!(
        changed
            .verify_original_record_data(&selected, std::process::id(), &original, &evidence[0].1)
            .is_err()
    );
    assert_eq!(control.complete_storage, Some(modeled_storage_selection()));
}

#[test]
fn complete_capture_profile_is_original_birth_data() {
    let coordinator = fixture::five();
    let selected = coordinator.participants[0].clone();
    let mut control =
        PacketControl::new_complete_producer(selected.clone(), producer(), coordinator).unwrap();
    let profile = PacketNative5CaptureProfile::CompactBytes7 {
        native_before_protocol_bytes: U64::new(1024 * 1024),
        native_after_protocol_bytes: U64::new(2 * 1024 * 1024),
        host_protocol_bytes: U64::new(3 * 1024 * 1024),
    };

    assert!(
        control
            .bind_complete_original_capture_profile(profile.clone())
            .is_err()
    );
    assert!(control.complete_capture_profile.is_none());
    bind_storage(&mut control);
    control
        .bind_complete_original_capture_profile(profile.clone())
        .unwrap();
    assert!(
        control
            .bind_complete_original_capture_profile(profile.clone())
            .is_err()
    );
    assert_eq!(control.complete_capture_profile.as_ref(), Some(&profile));
    control
        .authenticate_complete_capture_profile(&profile)
        .unwrap();
    assert!(
        control
            .authenticate_complete_capture_profile(&PacketNative5CaptureProfile::OriginalArrays6,)
            .is_err()
    );

    let original = request(&control);
    let proof = control.proof(&original, None).unwrap();
    let evidence = control.record_evidence(proof).unwrap();
    let receipt: PacketNative5Record = decode_record(&evidence[1].1).unwrap();
    assert_eq!(receipt.capture_profile, profile);
    receipt
        .verify_original_record_data(&selected, std::process::id(), &original, &evidence[0].1)
        .unwrap();
}

#[test]
fn complete_capture_profile_refuses_invalid_and_dispatched_birth() {
    let coordinator = fixture::five();
    let mut control = PacketControl::new_complete_producer(
        coordinator.participants[0].clone(),
        producer(),
        coordinator,
    )
    .unwrap();
    bind_storage(&mut control);
    let invalid = PacketNative5CaptureProfile::CompactBytes7 {
        native_before_protocol_bytes: U64::new(0),
        native_after_protocol_bytes: U64::new(1024),
        host_protocol_bytes: U64::new(1024),
    };
    assert!(
        control
            .bind_complete_original_capture_profile(invalid)
            .is_err()
    );
    assert!(control.complete_capture_profile.is_none());

    let original = request(&control);
    let proof = control.proof(&original, None).unwrap();
    let evidence = control.record_evidence(proof).unwrap();
    let value: Value = serde_json::from_slice(&evidence[1].1).unwrap();
    assert!(value.get("capture_profile").is_none());
    let receipt: PacketNative5Record = decode_record(&evidence[1].1).unwrap();
    assert_eq!(
        receipt.capture_profile,
        PacketNative5CaptureProfile::OriginalArrays6
    );

    control.realized = true;
    assert!(
        control
            .bind_complete_original_capture_profile(PacketNative5CaptureProfile::OriginalArrays6,)
            .is_err()
    );
    assert!(control.complete_capture_profile.is_none());
}

#[test]
fn generic_admit_proof_extension_refuses_before_original_or_callback() {
    let coordinator = fixture::five();
    let mut control = PacketControl::new_complete_producer(
        coordinator.participants[0].clone(),
        producer(),
        coordinator,
    )
    .unwrap();
    bind_storage(&mut control);
    control.realized = true;
    let mut original = request(&control);
    original.method = Method::Admit;
    original.body = serde_json::to_value(AdmitRequest {
        bindings: control.selection.realization.bindings.clone(),
        world_binding_hash: control.selection.world.clone(),
        admission_receipt: control.selection.admission_receipt.clone(),
        extensions: Extensions::new(),
    })
    .unwrap()
    .as_object()
    .unwrap()
    .clone();
    original.extensions.insert(
        crate::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE.into(),
        serde_json::json!({"schema":"source-owned.packet-canonical-ack-admission/5","algorithm":"blake3-keyed-canonical/1","context_digest":Bytes::new(vec![0;32]),"mac":Bytes::new(vec![0;32])}),
    );
    let before = control.program.inventory_hash().unwrap();
    let mut callbacks = 0;
    for _ in 0..2 {
        assert!(
            control
                .dispatch_with_preflight(&original, &mut |_| {
                    callbacks += 1;
                    Ok(())
                })
                .is_err()
        );
        assert!(control.originals.is_empty());
        assert!(!control.admitted);
        assert!(!control.fenced);
    }
    assert_eq!(callbacks, 0);
    assert_eq!(control.program.inventory_hash().unwrap(), before);
}

#[test]
fn generic_admit_no_extension_retains_original_baseline_result() {
    let coordinator = fixture::five();
    let mut control = PacketControl::new_complete_producer(
        coordinator.participants[0].clone(),
        producer(),
        coordinator,
    )
    .unwrap();
    bind_storage(&mut control);
    control.realized = true;
    let mut original = request(&control);
    original.method = Method::Admit;
    original.body = serde_json::to_value(AdmitRequest {
        bindings: control.selection.realization.bindings.clone(),
        world_binding_hash: control.selection.world.clone(),
        admission_receipt: control.selection.admission_receipt.clone(),
        extensions: Extensions::new(),
    })
    .unwrap()
    .as_object()
    .unwrap()
    .clone();
    let mut callbacks = 0;
    control
        .dispatch_with_preflight(&original, &mut |_| {
            callbacks += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(callbacks, 1);
    assert!(control.admitted);
    let retained = control
        .originals
        .get(original.request_id.0.as_ref().unwrap())
        .unwrap();
    assert_eq!(
        retained.0,
        original.request_hash(RequestOrigin::Controller).unwrap()
    );
    assert!(matches!(
        decode_response(
            &decode_request(Method::Admit, &original.body).unwrap(),
            &retained.1.body
        )
        .unwrap()
        .result,
        Some(MethodResult::Admit(_))
    ));
}

#[test]
fn generic_signed_admit_cached_original_refuses_before_preparation() {
    let coordinator = fixture::five();
    let mut control = PacketControl::new_complete_producer(
        coordinator.participants[0].clone(),
        producer(),
        coordinator,
    )
    .unwrap();
    bind_storage(&mut control);
    control.realized = true;
    let mut original = request(&control);
    original.method = Method::Admit;
    original.body = serde_json::to_value(AdmitRequest {
        bindings: control.selection.realization.bindings.clone(),
        world_binding_hash: control.selection.world.clone(),
        admission_receipt: control.selection.admission_receipt.clone(),
        extensions: Extensions::new(),
    })
    .unwrap()
    .as_object()
    .unwrap()
    .clone();
    control
        .dispatch_with_preflight(&original, &mut |_| Ok(()))
        .unwrap();
    original.extensions.insert(
        crate::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE.into(),
        serde_json::json!({"schema":"source-owned.packet-canonical-ack-admission/5","algorithm":"blake3-keyed-canonical/1","context_digest":Bytes::new(vec![0;32]),"mac":Bytes::new(vec![0;32])}),
    );
    let id = original.request_id.0.as_ref().unwrap();
    // The completed baseline result is real. This private fixture substitutes
    // only its stored request hash to model the exact signed original cache
    // that successful selected handoff creates; it mints no verified token.
    let signed_hash = original.request_hash(RequestOrigin::Controller).unwrap();
    control.originals.get_mut(id).unwrap().0 = signed_hash.clone();
    let body = control.originals[id].1.body.clone();
    let inventory = control.program.inventory_hash().unwrap();
    let evidence_count = control.originals[id].1.evidence.len();
    let mut callbacks = 0;
    for _ in 0..2 {
        assert!(
            control
                .dispatch_with_preflight(&original, &mut |_| {
                    callbacks += 1;
                    Ok(())
                })
                .is_err()
        );
        assert!(control.dispatch(&original).is_err());
    }
    assert_eq!(callbacks, 0);
    assert_eq!(control.originals.len(), 1);
    assert_eq!(control.originals[id].0, signed_hash);
    assert_eq!(control.originals[id].1.body, body);
    assert_eq!(control.originals[id].1.evidence.len(), evidence_count);
    assert_eq!(control.program.inventory_hash().unwrap(), inventory);
    assert!(control.admitted);
    assert!(!control.fenced);
}

#[test]
fn actual_birth_phase_selection_survives_realize_and_admit_for_all_three_models() {
    let coordinator = fixture::five();
    for member in 0..3 {
        let mut control = if member == 0 {
            PacketControl::new_complete_producer(
                coordinator.participants[member].clone(),
                producer(),
                coordinator.clone(),
            )
            .unwrap()
        } else {
            PacketControl::new_complete_reactive(
                coordinator.participants[member].clone(),
                reactive(&coordinator, member),
                coordinator.clone(),
            )
            .unwrap()
        };
        bind_storage(&mut control);
        assert!(std::ptr::eq(
            control
                .original_native_birth_selection_data(0, false)
                .unwrap(),
            &control.selection,
        ));
        assert!(
            control
                .original_native_birth_selection_data(2, false)
                .is_err()
        );

        let mut discover = request(&control);
        discover.request_id = Nullable(Some(id("actual-birth-discover")));
        discover.body = object(crate::bodies::DiscoverRequest {
            profile_ids: Default::default(),
            cursor: None,
            extensions: Extensions::new(),
        })
        .unwrap();
        control.dispatch(&discover).unwrap();
        assert!(
            control
                .original_native_birth_selection_data(0, true)
                .is_ok()
        );
        assert!(
            control
                .original_native_birth_selection_data(1, false)
                .is_ok()
        );
        assert!(
            control
                .original_native_birth_selection_data(1, true)
                .is_err()
        );

        let mut realize = discover.clone();
        realize.method = Method::Realize;
        realize.request_id = Nullable(Some(id("actual-birth-realize")));
        realize.sequence = U64::new(4);
        realize.body = object(&control.selection.realize).unwrap();
        let reply = control.dispatch(&realize).unwrap();
        assert_eq!(
            reply.body.get("status").and_then(Value::as_str),
            Some("completed")
        );
        assert!(control.realized);
        // The constructor predicate remains strict. Reusing it here caused
        // the actual Realize publication to fail before the next Admit read.
        assert!(control.endpoint_scope().is_err());
        assert!(
            control
                .original_native_birth_selection_data(1, true)
                .is_ok()
        );
        assert!(
            control
                .original_native_birth_selection_data(2, false)
                .is_ok()
        );
        assert!(
            control
                .original_native_birth_selection_data(1, false)
                .is_err()
        );

        let mut admit = realize.clone();
        admit.method = Method::Admit;
        admit.request_id = Nullable(Some(id("actual-birth-admit")));
        admit.sequence = U64::new(5);
        admit.body = object(AdmitRequest {
            bindings: control.selection.realization.bindings.clone(),
            world_binding_hash: control.selection.world.clone(),
            admission_receipt: control.selection.admission_receipt.clone(),
            extensions: Extensions::new(),
        })
        .unwrap();
        let reply = control.dispatch(&admit).unwrap();
        assert_eq!(
            reply.body.get("status").and_then(Value::as_str),
            Some("completed")
        );
        assert!(control.admitted);
        assert!(
            control
                .original_native_birth_selection_data(2, true)
                .is_ok()
        );
        assert!(
            control
                .original_native_birth_selection_data(2, false)
                .is_err()
        );
        assert!(
            control
                .original_native_birth_selection_data(3, true)
                .is_err()
        );
        assert_eq!(control.originals.len(), 3);

        control.program.open_gate().unwrap();
        assert!(
            control
                .original_native_birth_selection_data(2, true)
                .is_err()
        );
    }
}

#[test]
fn failed_actual_realize_preparation_keeps_partial_control_and_refuses_birth_scope() {
    let coordinator = fixture::five();
    let mut control = PacketControl::new_complete_producer(
        coordinator.participants[0].clone(),
        producer(),
        coordinator,
    )
    .unwrap();
    bind_storage(&mut control);
    let mut realize = request(&control);
    realize.method = Method::Realize;
    realize.request_id = Nullable(Some(id("failed-birth-realize")));
    realize.body = object(&control.selection.realize).unwrap();

    let result = control.dispatch_with_preflight(&realize, &mut |_| {
        Err(ProviderError::ResourceExhausted(
            "actual birth prefix refusal",
        ))
    });
    assert!(result.is_err());
    assert!(control.realized);
    assert!(control.fenced);
    assert!(
        control
            .originals
            .contains_key(realize.request_id.0.as_ref().unwrap())
    );
    assert!(
        control
            .original_native_birth_selection_data(1, true)
            .is_err()
    );
}
