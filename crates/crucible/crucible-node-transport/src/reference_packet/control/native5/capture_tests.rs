//! Tests same-owner native Capture journals with an explicitly modeled activation.
//!
//! Genuine Unix model ownership is retained. These component controls model the
//! active lifecycle directly; they do not qualify a child, transport prefix,
//! common admission, installed capture or fresh restoration.

// crucible-lint: allow panic-shortcut -- Assertion panics are the control verdict.
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
fn native17_current_capture_writer_preserves_actual_registration_owner() {
    let mut native = modeled_active_control();
    let original = capture_request(&native);
    let registration = native.reserve_original_capture(&original).unwrap();

    // This is the actual noncloneable native5 reservation, used only to check
    // owning serialization and metadata. It supplies no Capture17 Source proof.
    crate::reference_packet::service::native_startup::NativeRestoredSettledCaptureAttempt::check_registration_writer_fixture_data(registration)
        .unwrap();
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

#[test]
fn complete_control_edition5_roundtrips_actual_original_without_capture_selection() {
    let native = modeled_active_control();
    let before = native.program.inventory_hash().unwrap();
    let cut = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
    let snapshot = native.capture_control_state(cut, 8 * 1024 * 1024).unwrap();
    let original_bytes = snapshot.bytes().to_vec();
    let decoded =
        decode_packet_control_snapshot(snapshot.bytes(), snapshot.reference(), 8 * 1024 * 1024)
            .unwrap();

    assert_eq!(decoded.capture_allocation_selection(), None);
    assert_eq!(decoded.administrative_cut(), cut);
    assert_eq!(decoded.local_cursor(), cut);
    assert_eq!(snapshot.bytes(), original_bytes);
    assert_eq!(native.program.inventory_hash().unwrap(), before);
    let value = canonical::parse_json(snapshot.bytes(), 8 * 1024 * 1024).unwrap();
    assert_eq!(
        value["schema"],
        "source-owned.packet-native-control-state/5"
    );
    assert!(
        value["control"]
            .get("complete_capture_allocation_selection")
            .is_none()
    );
}

#[test]
fn complete_control_decoder_refuses_cross_edition_selection_and_missing_original_tuple() {
    use crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection;

    let native = modeled_active_control();
    let cut = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
    let snapshot = native.capture_control_state(cut, 8 * 1024 * 1024).unwrap();
    let original = canonical::parse_json(snapshot.bytes(), 8 * 1024 * 1024).unwrap();
    let selected =
        serde_json::to_value(PacketNative5CaptureAllocationSelection::OriginalObserve12).unwrap();
    let encode_and_decode = |value: &Value| {
        let bytes = canonical::canonical_json(value).unwrap();
        let reference = canonical::content_ref(&bytes, "application/json").unwrap();
        decode_packet_control_snapshot(&bytes, &reference, 8 * 1024 * 1024)
    };

    // These all run the actual complete decoder, not a standalone key scanner.
    for selection in [Value::Null, selected.clone()] {
        let mut wrong_old = original.clone();
        wrong_old["control"]["complete_capture_allocation_selection"] = selection;
        assert!(matches!(
            encode_and_decode(&wrong_old),
            Err(ProviderError::Correlation(
                "packet complete Control edition/selection differs"
            ))
        ));
    }
    let mut missing_new = original.clone();
    missing_new["schema"] = "source-owned.packet-native-control-state/6".into();
    assert!(matches!(
        encode_and_decode(&missing_new),
        Err(ProviderError::Correlation(
            "packet complete Control edition/selection differs"
        ))
    ));
    missing_new["control"]["complete_capture_allocation_selection"] = Value::Null;
    assert!(matches!(
        encode_and_decode(&missing_new),
        Err(ProviderError::Correlation(
            "packet complete Control edition/selection differs"
        ))
    ));

    // Correctly spelling a selected family cannot supply its original owning
    // profile, metadata, coordinator declarations or full definition roster.
    missing_new["control"]["complete_capture_allocation_selection"] = selected;
    assert!(matches!(
        encode_and_decode(&missing_new),
        Err(ProviderError::Correlation(
            "captured native allocation family lacks original tuple"
        ))
    ));
    assert!(
        decode_packet_control_snapshot(snapshot.bytes(), snapshot.reference(), 8 * 1024 * 1024,)
            .is_ok()
    );
}

// These controls exercise the live producer component with the modeled lifecycle
// used by this module. They install no selected policy, Source grant or endpoint
// codec, and do not claim a selected full-native publication positive.
fn modeled_stopped_observe_producer() -> (
    PacketControl,
    Envelope,
    super::super::restore_fresh::PacketLiveCaptureControlCurrency,
) {
    let mut native = modeled_active_control();
    native.realized = true;
    native.admitted = true;
    let mut original = request(&native);
    original.method = Method::Observe;
    original.body = object(ObserveRequest {
        binding_hash: native.selection.realization.owner_bindings[0]
            .identity()
            .unwrap(),
        owner_generation: native.selection.realization.bindings[0]
            .authority
            .owner_generation,
        after_observation_sequence: U64::new(0),
        maximum_items: U64::new(1),
        extensions: Extensions::new(),
    })
    .unwrap();
    let mut roots = crate::retained_metadata::NativeCaptureMetadataRoots::new();
    let mut observer = crate::retained_metadata::MetadataObserver::new();
    let currency = native
        .observe_original_live_capture_metadata(&mut roots, &mut observer)
        .unwrap();
    roots.finish().unwrap();
    native.originals.insert(
        original.request_id.0.as_ref().unwrap().clone(),
        (
            original
                .request_hash(crate::envelope::RequestOrigin::Controller)
                .unwrap(),
            PacketControlReply {
                body: Map::new(),
                evidence: Vec::new(),
            },
        ),
    );
    (native, original, currency)
}

#[test]
fn stopped_observe_producer_preserves_legacy_receipt_and_all_evidence_bytes() {
    let (mut native, original, currency) = modeled_stopped_observe_producer();
    let admitted = native
        .program
        .quote_original_stopped_observe_record(&original, 16 * 1024 * 1024)
        .unwrap();
    assert!(native.complete_capture_allocation_selection.is_none());

    let produced = native
        .retain_original_stopped_observe_evidence(&original, &currency, &admitted)
        .unwrap();
    let evidence = &produced.evidence;
    let legacy_receipt = native
        .retain_complete_record(&original, evidence[0].0.clone())
        .unwrap();
    let legacy_evidence = native.record_evidence(legacy_receipt).unwrap();

    assert_eq!(evidence, &legacy_evidence);
    assert_eq!(evidence.len(), 2);
    let receipt: PacketNative5Record = decode_record(&evidence[1].1).unwrap();
    assert_eq!(receipt.original, original);
    assert_eq!(receipt.native_record, evidence[0].0);
    for (reference, bytes) in evidence {
        reference.verify(bytes).unwrap();
        assert_eq!(
            canonical::canonical_json(&canonical::parse_json(bytes, FRAME).unwrap()).unwrap(),
            *bytes
        );
    }
}

#[test]
fn actual_stopped_observe_reply_matches_ordinary_body_receipt_and_evidence() {
    let (mut selected, original, currency) = modeled_stopped_observe_producer();
    let (mut ordinary, ordinary_original, _) = modeled_stopped_observe_producer();
    assert_eq!(original, ordinary_original);
    let RequestBody::Observe(observe) = decode_request(original.method, &original.body).unwrap()
    else {
        panic!("fixture must decode as Observe");
    };
    let admitted = selected
        .program
        .quote_original_stopped_observe_record(&original, 16 * 1024 * 1024)
        .unwrap();
    let mut witness = None;

    let actual = selected
        .observe(
            &original,
            observe.clone(),
            Some((&currency, &admitted, &mut witness)),
        )
        .unwrap();
    let expected = ordinary.observe(&ordinary_original, observe, None).unwrap();

    assert_eq!(actual.evidence, expected.evidence);
    assert_eq!(
        canonical::canonical_json(&Value::Object(actual.body.clone())).unwrap(),
        canonical::canonical_json(&Value::Object(expected.body.clone())).unwrap()
    );
    let decoded = crate::bodies::decode_response(
        &RequestBody::Observe(decode_observe_request(&original)),
        &actual.body,
    )
    .unwrap();
    assert!(matches!(decoded.result, Some(MethodResult::Observe(_))));
    let witness = witness.unwrap();
    let incoming_hash = canonical::json_hash(crate::reference_packet::service::capture_allocation::NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN, &original).unwrap();
    let scope = witness
        .original_allocation_scope(&currency, incoming_hash.clone(), 3, 41)
        .unwrap();
    assert_eq!(scope.observe_hash, incoming_hash);
    assert_eq!(
        scope.observe_request,
        *original.request_id.0.as_ref().unwrap()
    );
    assert_eq!(scope.model_cursor, currency.cursor());
    assert_eq!(scope.endpoint_records_before.get(), 3);
    let (_, _, foreign_currency) = modeled_stopped_observe_producer();
    assert!(
        witness
            .original_allocation_scope(&foreign_currency, scope.observe_hash, 3, 41)
            .is_err()
    );
}

fn decode_observe_request(original: &Envelope) -> ObserveRequest {
    let RequestBody::Observe(observe) = decode_request(original.method, &original.body).unwrap()
    else {
        panic!("fixture must decode as Observe");
    };
    observe
}

#[test]
fn stopped_observe_producer_refuses_foreign_currency_and_changed_original() {
    let (mut native, original, currency) = modeled_stopped_observe_producer();
    let admitted = native
        .program
        .quote_original_stopped_observe_record(&original, 16 * 1024 * 1024)
        .unwrap();
    let (mut foreign, _, _) = modeled_stopped_observe_producer();
    let foreign_content = foreign.content.len();

    assert!(
        foreign
            .retain_original_stopped_observe_evidence(&original, &currency, &admitted,)
            .is_err()
    );
    assert_eq!(foreign.content.len(), foreign_content);

    let content_before = native.content.len();
    let mut changed = original.clone();
    changed.method = Method::Input;
    assert!(
        native
            .retain_original_stopped_observe_evidence(&changed, &currency, &admitted,)
            .is_err()
    );
    changed.method = Method::Observe;
    changed
        .body
        .insert("changed".into(), Value::String("x".repeat(65536)));
    assert!(
        native
            .retain_original_stopped_observe_evidence(&changed, &currency, &admitted,)
            .is_err()
    );
    assert_eq!(native.content.len(), content_before);
}

#[test]
fn produced_observe_receipt_wraps_exact_bytes_and_refuses_foreign_or_changed_association() {
    let (mut native, original, currency) = modeled_stopped_observe_producer();
    let admitted = native
        .program
        .quote_original_stopped_observe_record(&original, 16 * 1024 * 1024)
        .unwrap();
    let produced = native
        .retain_original_stopped_observe_evidence(&original, &currency, &admitted)
        .unwrap();
    let (_, _, foreign_currency) = modeled_stopped_observe_producer();
    // This is an inert wrapper/reference data control. Neither the deliberately
    // non-report body nor this modeled Control is a complete report/Source grant.
    let report = canonical::content_ref(
        br#"{"component":"reference-data"}"#,
        crate::reference_packet::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA,
    ).unwrap();
    let actual = produced
        .receipt
        .borrowed_allocation_record_view(&original, &currency, &report)
        .unwrap();
    let native_receipt: PacketNative5Record = decode_record(&produced.evidence[1].1).unwrap();
    let expected = serde_json::json!({
        "schema": crate::reference_packet::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD,
        "native": native_receipt,
        "allocation": report,
    });

    assert_eq!(
        canonical::canonical_json(&serde_json::to_value(actual).unwrap()).unwrap(),
        canonical::canonical_json(&expected).unwrap()
    );
    assert!(
        produced
            .receipt
            .borrowed_allocation_record_view(&original, &foreign_currency, &report)
            .is_err()
    );
    let mut changed = original.clone();
    changed.sequence = changed.sequence.checked_add(U64::new(1)).unwrap();
    assert!(
        produced
            .receipt
            .borrowed_allocation_record_view(&changed, &currency, &report)
            .is_err()
    );
}

#[test]
fn selected_dispatch_retains_actual_produced_reply_before_transform_refusal_or_unwind() {
    // This exercises the private dispatcher branch with its real stopped
    // producer. The modeled activation does not install a report policy or
    // qualify a successful endpoint/Source publication.
    for unwind in [false, true] {
        let (mut native, original, currency) = modeled_stopped_observe_producer();
        let id = original.request_id.0.as_ref().unwrap().clone();
        native.originals.remove(&id);
        let admitted = native
            .program
            .quote_original_stopped_observe_record(&original, 16 * 1024 * 1024)
            .unwrap();
        let before = native.program.inventory_hash().unwrap();
        let mut original_banks = Vec::new();
        let mut transform = |reply: &mut PacketControlReply,
                             _: &ProducedOriginalObserveReceipt|
         -> Result<(), ProviderError> {
            assert_eq!(reply.evidence.len(), 2);
            original_banks = reply
                .evidence
                .iter()
                .map(|(_, bytes)| (bytes.as_ptr() as usize, bytes.len(), bytes.capacity()))
                .collect();
            reply
                .body
                .insert("partial_preparation".into(), Value::Bool(true));
            if unwind {
                panic!("modeled selected publication interruption");
            }
            Err(ProviderError::Conflict(
                "modeled selected publication refusal",
            ))
        };
        let mut selected = OriginalObserveAllocationPreparation {
            currency: &currency,
            raw_record: &admitted,
            transform_and_prepare: &mut transform,
        };
        let mut preparation = ReplyPreparation {
            callback: None,
            attempted: false,
        };

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            native
                .dispatch_prepared(&original, &mut preparation, None, Some(&mut selected))
                .map(|_| ())
        }));
        if unwind {
            assert!(outcome.is_err());
        } else {
            assert!(outcome.unwrap().is_err());
        }
        drop(selected);
        drop(transform);

        assert!(native.fenced);
        assert!(preparation.attempted);
        assert_eq!(before, native.program.inventory_hash().unwrap());
        let cached = &native.originals.get(&id).unwrap().1;
        assert_eq!(
            cached.body.get("partial_preparation"),
            Some(&Value::Bool(true))
        );
        assert_eq!(cached.evidence.len(), 2);
        let retained_banks: Vec<_> = cached
            .evidence
            .iter()
            .map(|(_, bytes)| (bytes.as_ptr() as usize, bytes.len(), bytes.capacity()))
            .collect();
        assert_eq!(retained_banks, original_banks);
        for (reference, bytes) in &cached.evidence {
            reference.verify(bytes).unwrap();
            assert_eq!(native.content.get(reference).unwrap(), bytes);
        }
    }
}

#[test]
fn produced_receipt_encodes_into_same_retained_wrapper_bank_without_reparse() {
    // The reference is inert component data. This tests the actual private
    // stopped producer and writer used by the publisher, not a completed
    // Report, native SDK owner, policy admission or full publication.
    let (mut native, original, currency) = modeled_stopped_observe_producer();
    let admitted = native
        .program
        .quote_original_stopped_observe_record(&original, 16 * 1024 * 1024)
        .unwrap();
    let produced = native
        .retain_original_stopped_observe_evidence(&original, &currency, &admitted)
        .unwrap();
    let report = canonical::content_ref(
        br#"{"component":"wrapper-encoding-data"}"#,
        crate::reference_packet::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA,
    ).unwrap();
    let wrapper = produced
        .receipt
        .borrowed_allocation_record_view(&original, &currency, &report)
        .unwrap();
    let storage =
        crate::reference_packet::serialization_storage::actual_serialization_storage_data(
            &wrapper,
            Default::default(),
            16 * 1024 * 1024,
        )
        .unwrap();
    let mut bank = Vec::with_capacity(storage.maximum_encoded_bytes);
    let original_bank = (bank.as_ptr(), bank.capacity());

    crate::reference_packet::serialization_storage::encode_original_precharged_serialization_into(
        &wrapper, &storage, &mut bank,
    )
    .unwrap();

    let receipt: PacketNative5Record = decode_record(&produced.evidence[1].1).unwrap();
    let expected = serde_json::json!({
        "schema": crate::reference_packet::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD,
        "native": receipt,
        "allocation": report,
    });
    assert_eq!(bank, canonical::canonical_json(&expected).unwrap());
    assert_eq!(original_bank, (bank.as_ptr(), bank.capacity()));
    let (_, _, foreign) = modeled_stopped_observe_producer();
    assert!(
        produced
            .receipt
            .borrowed_allocation_record_view(&original, &foreign, &report,)
            .is_err()
    );
    let mut changed = original.clone();
    changed.sequence = changed.sequence.checked_add(U64::new(1)).unwrap();
    assert!(
        produced
            .receipt
            .borrowed_allocation_record_view(&changed, &currency, &report,)
            .is_err()
    );
    assert_eq!(original_bank, (bank.as_ptr(), bank.capacity()));
}

#[test]
fn owned_selected_dispatch_reaches_transform_and_releases_only_after_installation() {
    // This exercises the actual private dispatcher with the modeled activation.
    // The third body is inert component data, not a Report or publication right.
    let (mut native, original, currency) = modeled_stopped_observe_producer();
    let id = original.request_id.0.as_ref().unwrap().clone();
    native.originals.remove(&id);
    let admitted = native
        .program
        .quote_original_stopped_observe_record(&original, 16 * 1024 * 1024)
        .unwrap();
    let before = native.program.inventory_hash().unwrap();
    let third = b"owned-dispatch-component".to_vec();
    let reference = canonical::content_ref(&third, "application/octet-stream").unwrap();
    let mut calls = 0;
    let mut banks = Vec::new();
    let mut transform = |reply: &mut PacketControlReply,
                         _: &ProducedOriginalObserveReceipt|
     -> Result<(), ProviderError> {
        calls += 1;
        assert_eq!(reply.evidence.len(), 2);
        banks = reply
            .evidence
            .iter()
            .map(|(_, bytes)| (bytes.as_ptr() as usize, bytes.len(), bytes.capacity()))
            .collect();
        reply.evidence.push((reference.clone(), third.clone()));
        Ok(())
    };
    let mut selected = OriginalObserveAllocationPreparation {
        currency: &currency,
        raw_record: &admitted,
        transform_and_prepare: &mut transform,
    };
    let mut preparation = ReplyPreparation {
        callback: None,
        attempted: false,
    };

    native
        .dispatch_prepared(&original, &mut preparation, None, Some(&mut selected))
        .unwrap();
    drop(selected);
    drop(transform);

    assert_eq!(calls, 1);
    assert!(preparation.attempted);
    assert!(!native.fenced);
    currency.authenticate_completed_observe(&native).unwrap();
    assert_eq!(before, native.program.inventory_hash().unwrap());
    let cached = &native.originals.get(&id).unwrap().1;
    let retained_banks: Vec<_> = cached.evidence[..2]
        .iter()
        .map(|(_, bytes)| (bytes.as_ptr() as usize, bytes.len(), bytes.capacity()))
        .collect();
    assert_eq!(retained_banks, banks);
    assert_eq!(cached.evidence.len(), 3);
    for (reference, bytes) in &cached.evidence {
        reference.verify(bytes).unwrap();
        assert_eq!(native.content.get(reference).unwrap(), bytes);
    }
}

#[test]
fn owned_dispatch_preserves_ordinary_fence_refusal_and_sticky_drop() {
    let (mut native, original, currency) = modeled_stopped_observe_producer();
    let admitted = native
        .program
        .quote_original_stopped_observe_record(&original, 16 * 1024 * 1024)
        .unwrap();
    let produced = native
        .retain_original_stopped_observe_evidence(&original, &currency, &admitted)
        .unwrap();
    let id = original.request_id.0.as_ref().unwrap();
    native.originals.get_mut(id).unwrap().1.evidence = produced.evidence;
    let before = native.program.inventory_hash().unwrap();

    {
        let dispatch = OriginalObserveDispatch::begin(
            &mut native,
            &currency,
            &original,
            Some(&produced.receipt),
        )
        .unwrap();
        currency
            .authenticate_owned_observe_dispatch(&dispatch)
            .unwrap();
        assert!(
            currency
                .authenticate_completed_observe(dispatch.control_data())
                .is_err()
        );
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        assert!(
            dispatch
                .control_data()
                .observe_live_capture_children(&mut observer)
                .is_err()
        );
        assert_eq!(observer.finish().observed_nodes, 0);
        // Dropping an unfinished owned phase must never reopen the Control.
    }

    assert!(native.fenced);
    assert_eq!(before, native.program.inventory_hash().unwrap());
    assert_eq!(native.originals.get(id).unwrap().1.evidence.len(), 2);
}

#[test]
fn owned_dispatch_refuses_changed_original_and_foreign_currency_without_losing_cache() {
    for foreign in [false, true] {
        let (mut native, original, currency) = modeled_stopped_observe_producer();
        let admitted = native
            .program
            .quote_original_stopped_observe_record(&original, 16 * 1024 * 1024)
            .unwrap();
        let produced = native
            .retain_original_stopped_observe_evidence(&original, &currency, &admitted)
            .unwrap();
        let id = original.request_id.0.as_ref().unwrap().clone();
        native.originals.get_mut(&id).unwrap().1.evidence = produced.evidence;
        let banks: Vec<_> = native
            .originals
            .get(&id)
            .unwrap()
            .1
            .evidence
            .iter()
            .map(|(_, bytes)| (bytes.as_ptr() as usize, bytes.len(), bytes.capacity()))
            .collect();
        let (_, _, other_currency) = modeled_stopped_observe_producer();
        let mut changed = original.clone();
        changed.sequence = changed.sequence.checked_add(U64::new(1)).unwrap();
        let selected_currency = if foreign { &other_currency } else { &currency };
        let selected_original = if foreign { &original } else { &changed };

        assert!(
            OriginalObserveDispatch::begin(
                &mut native,
                selected_currency,
                selected_original,
                Some(&produced.receipt),
            )
            .is_err()
        );

        assert!(native.fenced);
        let retained: Vec<_> = native
            .originals
            .get(&id)
            .unwrap()
            .1
            .evidence
            .iter()
            .map(|(_, bytes)| (bytes.as_ptr() as usize, bytes.len(), bytes.capacity()))
            .collect();
        assert_eq!(retained, banks);
    }
}

#[test]
fn decoded_control_census_checks_actual_backing_without_mutating_its_live_source() {
    let native = modeled_active_control();
    let before = native.program.inventory_hash().unwrap();
    let cut = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
    let snapshot = native.capture_control_state(cut, 8 * 1024 * 1024).unwrap();
    let decoded =
        decode_packet_control_snapshot(snapshot.bytes(), snapshot.reference(), 8 * 1024 * 1024)
            .unwrap();

    let requested = decoded.retained_requested_storage_data(usize::MAX).unwrap();
    assert!(requested > std::mem::size_of_val(&decoded));
    assert_eq!(
        decoded.retained_requested_storage_data(requested).unwrap(),
        requested
    );
    assert!(
        decoded
            .retained_requested_storage_data(requested - 1)
            .is_err()
    );
    assert!(PacketDecodedControlSnapshot::retained_metadata_counter_scratch_data() > 0);
    assert_eq!(decoded.administrative_cut(), cut);
    assert_eq!(native.program.inventory_hash().unwrap(), before);
    snapshot.reference().verify(snapshot.bytes()).unwrap();
}

#[test]
fn capture_future_control_provenance_binds_the_actual_decoded_body_and_full_reference() {
    let native = modeled_active_control();
    let cut = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
    let snapshot = native.capture_control_state(cut, 8 * 1024 * 1024).unwrap();
    let decoded = decode_packet_control_snapshot_for_capture_future_data(
        snapshot.bytes(),
        snapshot.reference(),
        8 * 1024 * 1024,
    )
    .unwrap();

    decoded
        .authenticate_body_data(snapshot.reference(), snapshot.bytes())
        .unwrap();
    let requested = decoded.retained_requested_storage_data(usize::MAX).unwrap();
    assert_eq!(
        decoded.retained_requested_storage_data(requested).unwrap(),
        requested
    );
    assert!(
        decoded
            .retained_requested_storage_data(requested - 1)
            .is_err()
    );
    assert!(requested >= PacketDecodedCaptureFutureControlData::header_requested_bytes_data());
    assert_eq!(decoded.control_data().administrative_cut(), cut);

    let mut other_reference = snapshot.reference().clone();
    other_reference.media_type = "application/example".into();
    assert!(
        decoded
            .authenticate_body_data(&other_reference, snapshot.bytes())
            .is_err()
    );
    assert!(
        decoded
            .authenticate_body_data(snapshot.reference(), b"{}")
            .is_err()
    );
    let mut changed = snapshot.bytes().to_vec();
    changed[0] ^= 1;
    assert!(
        decoded
            .authenticate_body_data(snapshot.reference(), &changed)
            .is_err()
    );
    assert_eq!(decoded.control_data().administrative_cut(), cut);
    assert_eq!(
        decoded.retained_requested_storage_data(requested).unwrap(),
        requested
    );
}
