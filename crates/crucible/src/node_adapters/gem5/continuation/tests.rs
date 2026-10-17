//! Adversarial codec tests; no fixture constructs native or archive authority.

// crucible-lint: allow panic-shortcut -- These continuation tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crucible_node_contract::{HashRef, Phase};

use super::*;

#[path = "reconciliation_tests.rs"]
mod reconciliation;

fn fixture() -> (Wire, RuntimeSnapshot, Vec<InputPayload>) {
    let owner = OwnerIdentity {
        owner: Id::new("owner").unwrap(),
        incarnation: Id::new("original").unwrap(),
        generation: 1.into(),
    };
    let cut = Position::new(100.into(), 0.into(), Phase::BoundaryControl);
    let source = RuntimeSnapshot {
        terminal: None,
        condition_stop: None,
        schema_version: 1,
        source_activation: SavedRuntimeActivation {
            generation: 1.into(),
            activation_id: Id::new("source").unwrap(),
            world_binding_hash: HashRef {
                algorithm: "blake3-256".to_owned(),
                domain: "model-only".to_owned(),
                digest: "a".repeat(64),
            },
            owners: vec![owner.clone()],
            boundary: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
        },
        capture_cut: cut,
        capture_ordinal: 7.into(),
        owners: Vec::new(),
        operations: Vec::new(),
        inputs: Vec::new(),
    };
    let bytes = b"model-only consistency body, not qualification".to_vec();
    let reference = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
    let wire = Wire {
        schema_version: 2,
        source_activation: source.source_activation.clone(),
        common_cut: cut,
        native_boundary: Gem5Boundary {
            tick: 150.into(),
            logical_position: Position::new(150.into(), 0.into(), Phase::BoundaryControl),
            ordinal: 0.into(),
            tick_ordinal: 0.into(),
            has_next_event: false,
            next_tick: 0.into(),
            next_priority: 0,
            inventory: serde_json::json!({"native_tick":"150","complete":false}),
        },
        guest_isa: "aarch64".to_owned(),
        source_layout_root: "/historical/removed/source".to_owned(),
        source_supplementary_files_root: "/historical/removed/images/ckpt_model_files".to_owned(),
        maximum_microsteps: 1_000_000.into(),
        node: Id::new("node").unwrap(),
        owners: vec![owner],
        capture: Id::new("capture").unwrap(),
        closure: reference.clone(),
        operations: Vec::new(),
        native_prefixes: Vec::new(),
        native_pending: None,
        native_acknowledged: None,
        output_sequence: 0.into(),
        artifacts: vec![
            SavedArtifact {
                role: Id::new("image").unwrap(),
                name: "image/ckpt_model.dmtcp".to_owned(),
                content: reference.clone(),
            },
            SavedArtifact {
                role: Id::new("image").unwrap(),
                name: "image/ckpt_model_files/fd-info.txt".to_owned(),
                content: reference.clone(),
            },
        ],
    };
    (wire, source, vec![InputPayload { reference, bytes }])
}

fn bytes(wire: &Wire) -> Vec<u8> {
    canonical::canonical_json(&serde_json::to_value(wire).unwrap()).unwrap()
}

fn decode(
    wire: &Wire,
    source: &RuntimeSnapshot,
    evidence: &[InputPayload],
) -> Result<Gem5ContinuationRecord, OperationFailure> {
    decode_gem5_continuation(
        &bytes(wire),
        source,
        &wire.node,
        wire.maximum_microsteps,
        evidence,
        16 * 1024 * 1024,
    )
}

#[test]
fn latent_native_frontier_is_preserved_without_relabeling_the_common_cut() {
    let (wire, source, evidence) = fixture();
    let record = decode(&wire, &source, &evidence).unwrap();
    assert_eq!(record.common_cut(), source.capture_cut);
    assert_eq!(record.native_boundary().logical_position.time_ps.get(), 150);
    assert_eq!(record.source_layout_root(), "/historical/removed/source");
    assert_eq!(
        record.source_supplementary_files_root(),
        "/historical/removed/images/ckpt_model_files"
    );
}

#[test]
fn legacy_codec_cannot_guess_the_missing_original_checkpoint_root() {
    let (wire, source, evidence) = fixture();
    let mut legacy = serde_json::to_value(&wire).unwrap();
    legacy["schema_version"] = serde_json::json!(1);
    legacy
        .as_object_mut()
        .unwrap()
        .remove("source_supplementary_files_root");
    let encoded = canonical::canonical_json(&legacy).unwrap();

    assert!(
        decode_gem5_continuation(
            &encoded,
            &source,
            &wire.node,
            wire.maximum_microsteps,
            &evidence,
            16 * 1024 * 1024,
        )
        .is_err()
    );
}

#[test]
fn original_checkpoint_root_must_match_the_complete_preserved_roster() {
    let (mut wire, source, evidence) = fixture();
    wire.source_supplementary_files_root = "/historical/removed/images/foreign_files".to_owned();
    assert!(decode(&wire, &source, &evidence).is_err());

    wire.source_supplementary_files_root = "/historical/removed/images/ckpt_model_files".to_owned();
    wire.artifacts
        .retain(|artifact| artifact.name.ends_with(".dmtcp"));
    assert!(decode(&wire, &source, &evidence).is_err());
}

#[test]
fn missing_or_repeated_evidence_and_foreign_world_fail_closed() {
    let (mut wire, source, evidence) = fixture();
    assert!(decode(&wire, &source, &[]).is_err());
    assert!(decode(&wire, &source, &[evidence[0].clone(), evidence[0].clone()]).is_err());
    wire.source_activation.activation_id = Id::new("other").unwrap();
    assert!(decode(&wire, &source, &evidence).is_err());
}

#[test]
fn omitted_nullable_field_and_unknown_extension_are_refused() {
    let (wire, source, evidence) = fixture();
    for mutation in ["omit", "unknown"] {
        let mut value = serde_json::to_value(&wire).unwrap();
        if mutation == "omit" {
            value.as_object_mut().unwrap().remove("native_pending");
        } else {
            value["unqualified_extension"] = serde_json::json!(true);
        }
        let encoded = canonical::canonical_json(&value).unwrap();
        assert!(
            decode_gem5_continuation(
                &encoded,
                &source,
                &wire.node,
                wire.maximum_microsteps,
                &evidence,
                16 * 1024 * 1024
            )
            .is_err()
        );
    }
}

#[test]
fn untracked_native_ack_and_parent_traversal_cannot_survive_decoding() {
    let (mut wire, source, evidence) = fixture();
    wire.native_acknowledged = Some(Id::new("missing-prefix").unwrap());
    assert!(decode(&wire, &source, &evidence).is_err());
    wire.native_acknowledged = None;
    wire.artifacts.push(SavedArtifact {
        role: Id::new("image").unwrap(),
        name: "image/../foreign".to_owned(),
        content: evidence[0].reference.clone(),
    });
    assert!(decode(&wire, &source, &evidence).is_err());
}

#[test]
fn decoder_refuses_unbounded_installed_credit_before_processing_evidence() {
    let (wire, source, evidence) = fixture();
    assert!(
        decode_gem5_continuation(
            &bytes(&wire),
            &source,
            &wire.node,
            wire.maximum_microsteps,
            &evidence,
            usize::MAX
        )
        .is_err()
    );
}

fn stopped_record() -> (Gem5ContinuationRecord, ContentRef, Vec<u8>, usize) {
    let (wire, source, mut evidence) = fixture();
    let original_closure = b"model-only original closure, never native authority".to_vec();
    let closure = canonical::content_ref(&original_closure, "application/octet-stream").unwrap();
    let body = canonical::canonical_json(&serde_json::json!({
        "schema":"crucible.gem5.common-observation.v1",
        "boundary":wire.native_boundary,
        "closure":closure,
        "owners":wire.owners,
        "activation_id":source.source_activation.activation_id,
    }))
    .unwrap();
    let reference = canonical::content_ref(&body, "application/json").unwrap();
    let credit = body.len() + original_closure.len();
    evidence.push(InputPayload {
        reference: closure,
        bytes: original_closure,
    });
    evidence.push(InputPayload {
        reference: reference.clone(),
        bytes: body.clone(),
    });
    (
        decode(&wire, &source, &evidence).unwrap(),
        reference,
        body,
        credit,
    )
}

#[test]
fn stopped_proof_keeps_original_bytes_across_later_frontiers_and_repeat_reattachment() {
    let (mut record, reference, original, credit) = stopped_record();
    record.wire.native_boundary.logical_position.time_ps = 200.into();
    let mut ledger = super::super::ledger::OperationLedger::new(1, 1, credit).unwrap();
    super::super::observations::retain_historical_observations(&mut ledger, &record).unwrap();
    super::super::observations::retain_historical_observations(&mut ledger, &record).unwrap();
    assert_eq!(ledger.standalone().len(), 2);
    assert_eq!(
        ledger
            .standalone()
            .find(|object| object.reference == reference)
            .unwrap()
            .bytes,
        original
    );
    assert!(ledger.can_run_prefix(1).is_err());
}

#[test]
fn stopped_proof_requires_original_closure_and_bounded_credit_before_copying() {
    let (mut record, reference, _, credit) = stopped_record();
    let mut ledger = super::super::ledger::OperationLedger::new(1, 1, credit - 1).unwrap();
    assert!(
        super::super::observations::retain_historical_observations(&mut ledger, &record).is_err()
    );
    assert_eq!(ledger.standalone().len(), 0);

    let body = &record.evidence[&reference].bytes;
    let value = canonical::parse_json(body, 16 * 1024 * 1024).unwrap();
    let closure: ContentRef = serde_json::from_value(value["closure"].clone()).unwrap();
    record.evidence.remove(&closure);
    let mut ledger = super::super::ledger::OperationLedger::new(1, 1, credit).unwrap();
    assert!(
        super::super::observations::retain_historical_observations(&mut ledger, &record).is_err()
    );
    assert_eq!(ledger.standalone().len(), 0);
}

#[test]
fn stopped_proof_cannot_move_into_another_native_owner() {
    let (mut record, _, _, credit) = stopped_record();
    record.wire.owners[0].owner = Id::new("foreign-native-owner").unwrap();
    let mut ledger = super::super::ledger::OperationLedger::new(1, 1, credit).unwrap();
    assert!(
        super::super::observations::retain_historical_observations(&mut ledger, &record).is_err()
    );
    assert_eq!(ledger.standalone().len(), 0);
}
