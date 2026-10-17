//! Checks retired-input association without granting native continuation authority.
//!
//! These synthetic records isolate original ACK, used-batch and terminal-frontier
//! mismatches. Complete signed body/native readers remain separately mandatory.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Synthetic association controls panic on malformed authored fixtures or accepted foreign scope.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible::node_contract::SavedRuntimeInput;
use crucible_node_contract::{Id, canonical};
use serde_json::json;

fn fixture() -> (Vec<SavedRuntimeOperation>, SavedRuntimeInput, Vec<Id>) {
    let proof = canonical::content_ref(b"synthetic association", "application/json").unwrap();
    let owners = json!([{"owner":"owner/block", "incarnation":"original", "generation":"1"}]);
    let cutoff = json!({"time_ps":"11", "microstep":"0", "phase":0});
    let inventory = proof.clone();
    let acknowledgement = json!({
        "stage_operation":"stage/original", "batch":"batch/original", "node":"block",
        "owners":owners, "cutoff":cutoff, "inventory":inventory, "proof_ref":proof
    });
    let delivery = json!({
        "connection_id":"connection/original", "connection_policy_ref":proof,
        "external_root":null, "provenance_ref":proof, "publication_id":"publication/original",
        "producer":"source", "consumer":"block",
        "producer_endpoint":{"node_id":"source", "port_id":"data", "lane_id":"output"},
        "consumer_endpoint":{"node_id":"block", "port_id":"data", "lane_id":"input"},
        "source_sequence":"3", "native_sequence":"2", "evaluation":null,
        "causal_parents":[],
        "publication":{"time_ps":"10", "microstep":"0", "phase":1},
        "delivery":{"time_ps":"10", "microstep":"0", "phase":2}, "payload":proof
    });
    let input = serde_json::from_value(json!({
        "node":"block", "stage_operation":"stage/original", "batch":"batch/original",
        "owners":owners, "cutoff":cutoff, "inventory":inventory,
        "deliveries":[delivery], "payloads":[], "acknowledgement":acknowledgement,
        "failure":null, "committed":true, "coordinator_committed":true
    }))
    .unwrap();
    let observation = json!({
        "node":"block", "owners":owners, "reached":cutoff, "closed_prefix":cutoff,
        "publications":[], "bounds":[], "external_inputs":[], "proof_ref":proof,
        "input_progress":{"batch":"batch/original", "proof_ref":proof,
            "consumed":[{"producer":"source", "source_sequence":"3"}]}
    });
    let operation = serde_json::from_value(json!({
        "operation":"consume/original", "route":{"node":"block", "owners":owners},
        "request":{"ExactRun":{"start":{"time_ps":"10", "microstep":"0", "phase":0},
            "limit":cutoff, "boundary_policy":"HorizonPark"}},
        "input_batch":"batch/original", "close_submission":null, "submission_effects":null,
        "scheduling_commit":{"node":"block", "operation":"consume/original", "retained_outputs":[]},
        "result":{"kind":"acknowledged", "value":{
            "node":"block", "operation":"consume/original", "owners":owners,
            "progress":{"Exact":{"reached":cutoff, "stop":"HorizonPark"}},
            "retained_outputs":[], "scheduling":observation}}
    }))
    .unwrap();

    (
        vec![operation],
        input,
        vec![Id::new("batch/original").unwrap()],
    )
}

#[test]
fn retired_frontier_requires_original_ack_and_used_batch() {
    let (operations, input, used) = fixture();
    assert_eq!(
        authenticate_input_frontier(&operations, &input, &used).unwrap(),
        1
    );
    assert!(authenticate_input_frontier(&operations, &input, &[]).is_err());

    let mut changed = input.clone();
    changed.acknowledgement.as_mut().unwrap().owners[0].generation = 2.into();
    assert!(authenticate_input_frontier(&operations, &changed, &used).is_err());
    changed = input.clone();
    changed.coordinator_committed = false;
    assert!(authenticate_input_frontier(&operations, &changed, &used).is_err());
    changed = input;
    changed.acknowledgement = None;
    assert!(authenticate_input_frontier(&operations, &changed, &used).is_err());
}

#[test]
fn retired_frontier_requires_exact_operation_batch_commit_and_consumption() {
    let (operations, input, used) = fixture();
    let mut changed = operations.clone();
    changed[0].input_batch = Some(Id::new("batch/foreign").unwrap());
    assert!(authenticate_input_frontier(&changed, &input, &used).is_err());
    changed = operations.clone();
    changed[0].scheduling_commit = None;
    assert!(authenticate_input_frontier(&changed, &input, &used).is_err());

    changed = operations;
    let SavedRuntimeResult::Acknowledged(outcome) = &mut changed[0].result else {
        unreachable!()
    };
    outcome
        .scheduling
        .as_mut()
        .unwrap()
        .input_progress
        .as_mut()
        .unwrap()
        .consumed[0]
        .producer = Id::new("foreign-producer").unwrap();
    assert!(authenticate_input_frontier(&changed, &input, &used).is_err());
}
