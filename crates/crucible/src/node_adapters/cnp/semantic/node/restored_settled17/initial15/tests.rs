//! Exercises historical field comparisons without constructing a live owner.

use super::*;
use crate::node_contract::{
    ActivationRecord, EffectKnowledge, OperationOutcome, OperationRequest,
    OriginalLineageOwnerMapping, ProgressEvidence, SavedRuntimeActivation, Submission,
};
use crucible_node_contract::{Phase, Position, Tick, U64, canonical};

fn reference(bytes: &[u8]) -> ContentRef {
    canonical::content_ref(bytes, "application/json").unwrap()
}

fn owners() -> (OwnerIdentity, OwnerIdentity) {
    let old = OwnerIdentity {
        owner: Id::new("same-logical-owner").unwrap(),
        incarnation: Id::new("old-native-incarnation").unwrap(),
        generation: U64::new(1),
    };
    let fresh = OwnerIdentity {
        incarnation: Id::new("fresh-native-incarnation").unwrap(),
        generation: U64::new(2),
        ..old.clone()
    };
    (old, fresh)
}

fn target(owner: &OwnerIdentity) -> ActivationRecord {
    ActivationRecord {
        generation: U64::new(2),
        activation_id: Id::new("fresh-world").unwrap(),
        world_binding_hash: reference(b"actual world DATA").hash,
        owners: vec![owner.clone()],
        boundary: Position::new(Tick::new(4), U64::new(0), Phase::Delivery),
    }
}

#[test]
fn operation_owner_substitution_preserves_every_other_result_and_effect_field() {
    // These are comparison DTOs only. The empty World preparation below cannot
    // pass the separate strict Node/Source/native constructors or issue a grant.
    let (old, fresh) = owners();
    let node = Id::new("same-logical-node").unwrap();
    let operation = Id::new("original-operation").unwrap();
    let route = NodeRoute {
        node: node.clone(),
        owners: vec![fresh.clone()],
    };
    let outcome = OperationOutcome {
        operation: operation.clone(),
        node: node.clone(),
        owners: vec![old.clone()],
        progress: ProgressEvidence::Paused {
            reached: None,
            stop_receipt: reference(b"original stop evidence"),
        },
        retained_outputs: vec![Id::new("original-output").unwrap()],
        scheduling: None,
    };
    let saved = SavedRuntimeOperation {
        operation: operation.clone(),
        route: NodeRoute {
            node,
            owners: vec![old],
        },
        request: OperationRequest::Pause,
        input_batch: None,
        result: SavedRuntimeResult::Complete(outcome.clone()),
        close_submission: Some(Submission::Accepted),
        submission_effects: Some(EffectKnowledge::CommittedPrefix(vec![operation.clone()])),
        scheduling_commit: None,
    };
    let mut fresh_outcome = outcome;
    fresh_outcome.owners = vec![fresh.clone()];
    let current = SavedRuntimeOperation {
        route: route.clone(),
        result: SavedRuntimeResult::Complete(fresh_outcome.clone()),
        ..saved.clone()
    };
    let admission = AdmissionRecord17 {
        operation,
        route: route.clone(),
        request: saved.request.clone(),
        activation: record::WorldRecord17 {
            record: SavedRuntimeActivation::from(&target(&fresh)),
            nodes: Vec::new(),
            preparation: None,
        },
        inputs: None,
    };

    assert!(authenticate_operation_data(&saved, &current, &admission, &route).is_ok());

    let mut changed = current.clone();
    changed.close_submission = None;
    assert!(authenticate_operation_data(&saved, &changed, &admission, &route).is_err());

    let mut changed = current.clone();
    changed.submission_effects = Some(EffectKnowledge::Unknown);
    assert!(authenticate_operation_data(&saved, &changed, &admission, &route).is_err());

    let mut changed = current.clone();
    changed.request = OperationRequest::Observe;
    assert!(authenticate_operation_data(&saved, &changed, &admission, &route).is_err());

    let mut changed = current.clone();
    changed.result = SavedRuntimeResult::Acknowledged(fresh_outcome.clone());
    assert!(authenticate_operation_data(&saved, &changed, &admission, &route).is_err());

    fresh_outcome
        .retained_outputs
        .push(Id::new("replacement-output").unwrap());
    let changed = SavedRuntimeOperation {
        result: SavedRuntimeResult::Complete(fresh_outcome),
        ..current
    };
    assert!(authenticate_operation_data(&saved, &changed, &admission, &route).is_err());
}

#[test]
fn fresh_input_ack_must_match_the_actual_roster_not_only_its_proof_label() {
    let (old, fresh) = owners();
    let node = Id::new("same-logical-node").unwrap();
    let route = NodeRoute {
        node: node.clone(),
        owners: vec![fresh.clone()],
    };
    let cutoff = Position::new(Tick::new(4), U64::new(0), Phase::Delivery);
    let old_ack = NativeInputAcknowledgement {
        node: node.clone(),
        stage_operation: Id::new("original-stage").unwrap(),
        batch: Id::new("original-batch").unwrap(),
        owners: vec![old.clone()],
        cutoff,
        inventory: reference(b"original empty ordered inventory"),
        proof_ref: reference(b"original native ACK"),
    };
    let fresh_ack = NativeInputAcknowledgement {
        owners: vec![fresh.clone()],
        proof_ref: reference(b"actual fresh all-owner proof"),
        ..old_ack.clone()
    };
    let saved = OriginalLineageInputRecord {
        node: node.clone(),
        stage_operation: old_ack.stage_operation.clone(),
        batch: old_ack.batch.clone(),
        owners: vec![old.clone()],
        cutoff,
        inventory: old_ack.inventory.clone(),
        deliveries: Vec::new(),
        payloads: Vec::new(),
        provenance: None,
        lineage: None,
        acknowledgement: Some(old_ack),
        failure: None,
        committed: true,
        coordinator_committed: true,
    };
    let current = OriginalLineageInputRecord {
        owners: vec![fresh.clone()],
        acknowledgement: Some(fresh_ack.clone()),
        ..saved.clone()
    };
    let batch = BatchRecord17 {
        activation: record::WorldRecord17 {
            record: SavedRuntimeActivation::from(&target(&fresh)),
            nodes: Vec::new(),
            preparation: None,
        },
        node,
        stage_operation: saved.stage_operation.clone(),
        batch: saved.batch.clone(),
        owners: route.owners.clone(),
        cutoff,
        inventory: saved.inventory.clone(),
        deliveries: Vec::new(),
        payloads: Vec::new(),
    };
    let mut restoration = OriginalLineageNativeScope {
        coordinator_schema: 7,
        source_record: reference(b"original Runtime7"),
        source_capture: SavedRuntimeActivation::from(&target(&old)),
        target: target(&fresh),
        owners: vec![OriginalLineageOwnerMapping {
            source: old,
            target: fresh,
        }],
        first_scopes: Vec::new(),
        journals: Vec::new(),
        input_acknowledgements: vec![fresh_ack.clone()],
        proof: fresh_ack.proof_ref.clone(),
    };

    assert!(authenticate_input_data(&saved, &current, &batch, &route, &restoration).is_ok());

    restoration.input_acknowledgements.clear();
    assert!(authenticate_input_data(&saved, &current, &batch, &route, &restoration).is_err());

    restoration.input_acknowledgements = vec![fresh_ack.clone(), fresh_ack.clone()];
    assert!(authenticate_input_data(&saved, &current, &batch, &route, &restoration).is_err());

    restoration.input_acknowledgements = vec![fresh_ack];
    let mut changed = current.clone();
    changed.coordinator_committed = false;
    assert!(authenticate_input_data(&saved, &changed, &batch, &route, &restoration).is_err());

    let mut changed = current;
    changed.payloads.push(reference(b"replacement payload"));
    assert!(authenticate_input_data(&saved, &changed, &batch, &route, &restoration).is_err());
}
