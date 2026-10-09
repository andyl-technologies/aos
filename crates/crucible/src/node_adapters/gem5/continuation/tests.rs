//! Adversarial codec tests; no fixture constructs native or archive authority.

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
        schema_version: 1,
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
        artifacts: Vec::new(),
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
