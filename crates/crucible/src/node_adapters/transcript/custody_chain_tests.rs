//! Data-only replay custody-chain counterexamples; these mint no live authority.

// crucible-lint: allow panic-shortcut -- These custody chain tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)] // Test fixture invariants deliberately panic.

use super::*;

fn check_chain(
    saved: &NativeInputAcknowledgement,
    original: &NativeInputAcknowledgement,
    objects: &[InputPayload],
) -> Result<bool, OperationFailure> {
    validate_reminted_input_ack(
        saved,
        original,
        objects,
        &mut BTreeSet::new(),
        &object(b"{\"source_transcript\":true}").reference,
    )
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn object(bytes: &[u8]) -> InputPayload {
    InputPayload {
        reference: canonical::content_ref(bytes, "application/json").unwrap(),
        bytes: bytes.to_vec(),
    }
}

fn owner(generation: u64) -> OwnerIdentity {
    OwnerIdentity {
        owner: id("owner/replay"),
        incarnation: id(&format!("incarnation/{generation}")),
        generation: generation.into(),
    }
}

fn original() -> NativeInputAcknowledgement {
    NativeInputAcknowledgement {
        stage_operation: id("original/stage"),
        batch: id("original/batch"),
        node: id("node/replay"),
        owners: vec![owner(1)],
        cutoff: Position::new(
            50.into(),
            0.into(),
            crucible_node_contract::Phase::BoundaryControl,
        ),
        inventory: object(b"[]").reference,
        proof_ref: object(b"{\"physical_original\":true}").reference,
    }
}

fn restore_receipt(
    source: &NativeInputAcknowledgement,
    generation: u64,
) -> (NativeInputAcknowledgement, InputPayload) {
    let fresh_owner = owner(generation);
    let target = SavedRuntimeActivation {
        generation: generation.into(),
        activation_id: id(&format!("activation/{generation}")),
        world_binding_hash: object(b"{\"world\":\"unchanged\"}").reference.hash,
        owners: vec![fresh_owner.clone()],
        boundary: source.cutoff,
    };
    let receipt = ReplayInputCustody {
        schema: "crucible.transcript-replay.input-custody.v1".into(),
        source_state: object(b"{\"saved_replay_state\":true}").reference,
        source_ack: source.clone(),
        target,
        node: source.node.clone(),
        owners: vec![fresh_owner.clone()],
        batch: source.batch.clone(),
        stage_operation: source.stage_operation.clone(),
        inventory: source.inventory.clone(),
        cutoff: source.cutoff,
    };
    let bytes = encode(&receipt).unwrap();
    let body = object(&bytes);
    let mut fresh = source.clone();
    fresh.owners = vec![fresh_owner];
    fresh.proof_ref = body.reference.clone();
    (fresh, body)
}

#[test]
fn original_proof_cannot_be_retagged_as_fresh_owner_custody() {
    let original = original();
    assert!(check_chain(&original, &original, &[]).unwrap());

    let mut forged = original.clone();
    forged.owners = vec![owner(2)];

    assert!(!check_chain(&forged, &original, &[]).unwrap());
    assert_eq!(original.owners, vec![owner(1)]);
}

#[test]
fn every_restored_generation_requires_its_original_exact_custody_body() {
    let original = original();
    let (first, first_body) = restore_receipt(&original, 2);
    let (second, second_body) = restore_receipt(&first, 3);
    let bodies = [first_body.clone(), second_body.clone()];

    assert!(check_chain(&second, &original, &bodies).unwrap());
    assert!(!check_chain(&second, &original, &[second_body]).unwrap());
    assert!(!check_chain(&second, &original, &[first_body]).unwrap());

    let mut changed_inventory = second;
    changed_inventory.inventory = object(b"[\"counterfactual\"]").reference;
    assert!(!check_chain(&changed_inventory, &original, &bodies).unwrap());
}

#[test]
fn saved_receipt_cannot_claim_an_owner_outside_its_target_roster() {
    let original = original();
    let (mut fresh, body) = restore_receipt(&original, 2);
    let mut receipt: ReplayInputCustody = serde_json::from_slice(&body.bytes).unwrap();
    receipt.target.owners.clear();
    let changed = object(&encode(&receipt).unwrap());
    fresh.proof_ref = changed.reference.clone();

    assert!(!check_chain(&fresh, &original, &[changed]).unwrap());
}

#[test]
fn initial_model_admission_requires_exact_original_transcript_and_acknowledgement() {
    let original = original();
    let (mut fresh, base) = restore_receipt(&original, 2);
    let mut receipt: ReplayInputCustody = serde_json::from_slice(&base.bytes).unwrap();
    receipt.schema = "crucible.transcript-replay.input-admission.v1".into();
    receipt.source_state = object(b"{\"source_transcript\":true}").reference;
    let body = object(&encode(&receipt).unwrap());
    fresh.proof_ref = body.reference.clone();
    assert!(check_chain(&fresh, &original, &[body]).unwrap());

    receipt.source_state = object(b"{\"foreign_transcript\":true}").reference;
    let changed = object(&encode(&receipt).unwrap());
    fresh.proof_ref = changed.reference.clone();
    assert!(!check_chain(&fresh, &original, &[changed]).unwrap());
}
