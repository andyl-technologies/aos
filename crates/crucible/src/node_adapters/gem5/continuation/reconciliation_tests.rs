//! Data-only adversarial cache checks; these records grant no native authority.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crucible_node_contract::Endpoint;
use crucible_node_provider::gem5::{Gem5ConsolePublication, Gem5ExactRange, Gem5Run};

use crate::node_scheduling::{
    NativeOutputBound, NativeProducerBound, NativePublication, NativeSchedulingObservation,
};

use super::*;

fn held_publication() -> (Wire, RuntimeSnapshot, Vec<InputPayload>) {
    let (mut wire, mut source, mut evidence) = fixture();
    let start = source.capture_cut;
    let limit = Position::new(150.into(), 1.into(), Phase::BoundaryControl);
    let operation = Id::new("original-common-operation").unwrap();
    let scope = PrefixScope {
        activation: source.source_activation.clone(),
        route: NodeRoute {
            node: wire.node.clone(),
            owners: wire.owners.clone(),
        },
    };
    let digest = canonical::json_hash("crucible.gem5.original-prefix.v1", &serde_json::json!({"operation":operation,"owners":scope.route.owners,"activation":scope.activation.activation_id,"prefix":0})).unwrap();
    let prefix_id = Id::new(format!("gem5-prefix/{}", digest.digest)).unwrap();
    let mut before = wire.native_boundary.clone();
    before.tick = 100.into();
    before.logical_position = start;
    before.has_next_event = true;
    before.next_tick = 150.into();
    let mut after = wire.native_boundary.clone();
    after.logical_position = limit;
    after.ordinal = 1.into();
    after.tick_ordinal = 1.into();
    let output = b"12345678".to_vec();
    let prefix = Gem5Completion {
        kind: "completed".to_owned(),
        operation: prefix_id.clone(),
        original: Gem5Run {
            kind: "run".to_owned(),
            operation: prefix_id.clone(),
            exclusive_tick: limit.time_ps,
            maximum_events: 1024.into(),
            exact_range: Some(Gem5ExactRange {
                start,
                limit,
                maximum_microsteps: wire.maximum_microsteps,
            }),
        },
        before,
        after: after.clone(),
        processed_events: 1.into(),
        reason: "output".to_owned(),
        output: output.clone(),
        publications: vec![Gem5ConsolePublication {
            output_id: 1.into(),
            tick: 150.into(),
            event_ordinal: 1.into(),
            tick_ordinal: 1.into(),
            guest_pid: 100.into(),
            context_id: 0.into(),
            guest_fd: 1,
            causal_parent: 0.into(),
            payload: output.clone(),
        }],
        exit_cause: None,
        exit_code: None,
    };
    let prefix_bytes = canonical::canonical_json(&serde_json::to_value(&prefix).unwrap()).unwrap();
    let prefix_ref = canonical::content_ref(&prefix_bytes, "application/json").unwrap();
    let payload = canonical::content_ref(&output, "application/octet-stream").unwrap();
    let publication = NativePublication {
        publication_id: Id::new("gem5/output/1").unwrap(),
        endpoint: Endpoint {
            node_id: wire.node.clone(),
            port_id: Id::new("console").unwrap(),
            lane_id: Id::new("stdout").unwrap(),
        },
        native_sequence: 1.into(),
        publication: Position::new(150.into(), 1.into(), Phase::Publication),
        evaluation: Some(Position::new(150.into(), 0.into(), Phase::Reaction)),
        causal_parents: Vec::new(),
        payload: payload.clone(),
        payload_bytes: output.clone(),
    };
    let outcome = OperationOutcome {
        operation: operation.clone(),
        node: wire.node.clone(),
        owners: wire.owners.clone(),
        progress: ProgressEvidence::Exact {
            reached: limit,
            stop: StopReason::HorizonPark,
        },
        retained_outputs: vec![publication.publication_id.clone()],
        scheduling: Some(NativeSchedulingObservation {
            node: wire.node.clone(),
            owners: wire.owners.clone(),
            reached: limit,
            closed_prefix: limit,
            bounds: vec![NativeProducerBound {
                producer: wire.node.clone(),
                bound: NativeOutputBound::At(publication.publication),
                proof_ref: prefix_ref.clone(),
            }],
            publications: vec![publication],
            input_progress: None,
            external_inputs: Vec::new(),
            proof_ref: prefix_ref.clone(),
        }),
    };
    let saved = SavedRuntimeOperation {
        operation,
        route: scope.route.clone(),
        request: OperationRequest::ExactRun {
            start,
            limit,
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
        },
        input_batch: None,
        result: SavedRuntimeResult::Complete(outcome),
        close_submission: None,
        submission_effects: None,
        scheduling_commit: None,
    };
    source.operations.push(saved.clone());
    wire.operations.push(SavedNativeOperation {
        original: saved,
        prefixes: vec![prefix_ref.clone()],
        prefix_scopes: vec![scope],
    });
    wire.native_prefixes = vec![prefix_ref.clone()];
    wire.native_pending = Some(prefix_id);
    wire.native_boundary = after;
    wire.output_sequence = 1.into();
    evidence.push(InputPayload {
        reference: prefix_ref,
        bytes: prefix_bytes,
    });
    evidence.push(InputPayload {
        reference: payload,
        bytes: output,
    });
    (wire, source, evidence)
}

fn change_cached(
    wire: &mut Wire,
    source: &mut RuntimeSnapshot,
    mutate: impl FnOnce(&mut OperationOutcome),
) {
    let SavedRuntimeResult::Complete(outcome) = &mut wire.operations[0].original.result else {
        panic!("model fixture must have cached completion")
    };
    mutate(outcome);
    source.operations[0] = wire.operations[0].original.clone();
}

#[test]
fn prepared_native_publication_beyond_exclusive_ceiling_keeps_original_birth() {
    let (wire, source, evidence) = held_publication();
    let record = decode(&wire, &source, &evidence).unwrap();
    let SavedRuntimeResult::Complete(outcome) = &record.wire.operations[0].original.result else {
        panic!()
    };
    let publication = &outcome.scheduling.as_ref().unwrap().publications[0];
    assert!(publication.evaluation.unwrap() < record.native_boundary().logical_position);
    assert!(publication.publication > record.native_boundary().logical_position);
}

#[test]
fn authenticated_hashes_cannot_replace_native_cached_byte_and_birth_consistency() {
    for mutation in [
        "bytes",
        "evaluation",
        "publication",
        "sequence",
        "stop",
        "proof",
        "bound",
    ] {
        let (mut wire, mut source, evidence) = held_publication();
        let foreign_ref = evidence[0].reference.clone();
        change_cached(&mut wire, &mut source, |outcome| {
            let scheduling = outcome.scheduling.as_mut().unwrap();
            match mutation {
                "bytes" => scheduling.publications[0].payload_bytes[0] ^= 1,
                "evaluation" => scheduling.publications[0].evaluation = Some(scheduling.reached),
                "publication" => scheduling.publications[0].publication = scheduling.reached,
                "sequence" => scheduling.publications[0].native_sequence = 2.into(),
                "stop" => {
                    outcome.progress = ProgressEvidence::Exact {
                        reached: scheduling.reached,
                        stop: StopReason::Lifecycle,
                    }
                }
                "proof" => scheduling.proof_ref = foreign_ref,
                "bound" => {
                    scheduling.bounds[0].bound = NativeOutputBound::AfterInstant(U64::new(u64::MAX))
                }
                _ => unreachable!(),
            }
        });
        assert!(decode(&wire, &source, &evidence).is_err(), "{mutation}");
    }
}

#[test]
fn original_fifo_cursor_missing_payload_and_invented_ack_are_refused() {
    let (mut wire, source, evidence) = held_publication();
    wire.output_sequence = 2.into();
    assert!(decode(&wire, &source, &evidence).is_err());
    wire.output_sequence = 1.into();
    assert!(decode(&wire, &source, &evidence[..2]).is_err());
    wire.native_acknowledged = wire.native_pending.take();
    assert!(decode(&wire, &source, &evidence).is_err());
}

#[test]
fn publication_terminal_cannot_be_hidden_as_pending_budget_progress() {
    let (mut wire, mut source, evidence) = held_publication();
    wire.operations[0].original.result = SavedRuntimeResult::Pending;
    source.operations[0] = wire.operations[0].original.clone();
    wire.native_acknowledged = wire.native_pending.take();
    assert!(decode(&wire, &source, &evidence).is_err());
}

#[test]
fn acknowledged_budget_progress_remains_pending_only_before_original_ceiling() {
    let (mut wire, mut source, mut evidence) = held_publication();
    let limit = Position::new(200.into(), 0.into(), Phase::BoundaryControl);
    let progress = Position::new(150.into(), 2.into(), Phase::Reaction);
    let prefix_reference = wire.operations[0].prefixes[0].clone();
    let prefix_object = evidence
        .iter_mut()
        .find(|object| object.reference == prefix_reference)
        .unwrap();
    let mut prefix: Gem5Completion = serde_json::from_slice(&prefix_object.bytes).unwrap();
    prefix.original.exclusive_tick = limit.time_ps;
    prefix.original.maximum_events = 1.into();
    prefix.original.exact_range.as_mut().unwrap().limit = limit;
    prefix.after.logical_position = progress;
    prefix.after.has_next_event = true;
    prefix.after.next_tick = 150.into();
    prefix.reason = "event_budget".to_owned();
    prefix.output.clear();
    prefix.publications.clear();
    let new_bytes = canonical::canonical_json(&serde_json::to_value(&prefix).unwrap()).unwrap();
    let new_ref = canonical::content_ref(&new_bytes, "application/json").unwrap();
    *prefix_object = InputPayload {
        reference: new_ref.clone(),
        bytes: new_bytes,
    };
    evidence.truncate(2);
    wire.operations[0].prefixes = vec![new_ref.clone()];
    wire.operations[0].original.result = SavedRuntimeResult::Pending;
    let OperationRequest::ExactRun {
        limit: saved_limit, ..
    } = &mut wire.operations[0].original.request
    else {
        panic!()
    };
    *saved_limit = limit;
    source.operations[0] = wire.operations[0].original.clone();
    wire.native_prefixes = vec![new_ref];
    wire.native_acknowledged = wire.native_pending.take();
    wire.native_boundary = prefix.after.clone();
    wire.output_sequence = 0.into();
    assert!(decode(&wire, &source, &evidence).is_ok());

    prefix.after.logical_position = limit;
    let new_bytes = canonical::canonical_json(&serde_json::to_value(&prefix).unwrap()).unwrap();
    let new_ref = canonical::content_ref(&new_bytes, "application/json").unwrap();
    evidence[1] = InputPayload {
        reference: new_ref.clone(),
        bytes: new_bytes,
    };
    wire.operations[0].prefixes = vec![new_ref.clone()];
    wire.native_prefixes = vec![new_ref];
    wire.native_boundary = prefix.after;
    assert!(decode(&wire, &source, &evidence).is_err());
}
