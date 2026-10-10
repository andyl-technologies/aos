//! Exercises runtime association and refusal with explicitly synthetic native custody.
//!
//! These models do not qualify a source installation, native class or readiness.

// crucible-lint: allow panic-shortcut -- These association models panic on invalid synthetic fixture setup and violated ledger invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::node_scheduling::{
    InputPayload, NativePublication, NativeSchedulingObservation, RuntimeInputBatch,
    event::Delivery,
};
use crucible_node_contract::{Endpoint, Event, EventStage, Extensions, canonical};

fn fixture() -> (
    NodeRuntime,
    Vec<Rc<RefCell<NativeState>>>,
    OperationToken,
    RuntimeInputBatch,
) {
    let (mut runtime, states) = runtime(OperatingMode::Quantized);
    let activation = activate(&mut runtime);
    let token = quantum(&mut runtime, &activation);
    let original = runtime.operations[&id("quantum")].admission.clone();
    let payload = InputPayload {
        // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
        reference: canonical::content_ref(b"original bytes", "application/octet-stream").unwrap(),
        bytes: b"original bytes".to_vec(),
    };
    let publication = Position::new(1000.into(), 0.into(), Phase::Publication);
    let endpoint = Endpoint {
        node_id: id("a"),
        port_id: id("data"),
        lane_id: id("output"),
    };
    let event = Event {
        schema_version: 1,
        id: id("checksum-1"),
        source: endpoint.clone(),
        destination: Endpoint {
            node_id: id("a"),
            port_id: id("data"),
            lane_id: id("input"),
        },
        position: publication,
        stage: EventStage::Publication,
        publication_position: publication,
        delivery_position: None,
        source_sequence: 7.into(),
        causal_parent_ids: vec![],
        payload: payload.reference.clone(),
        provenance_ref: payload.reference.clone(),
        extensions: Extensions::new(),
    };
    // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
    let bytes = canonical::canonical_json(&serde_json::to_value(&event).unwrap()).unwrap();
    let published = InputPayload {
        // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
        reference: canonical::content_ref(&bytes, "application/json").unwrap(),
        bytes,
    };
    let owner = original.token().route().owners[0].clone();
    let mut objects = vec![payload.clone(), published.clone()];
    objects.sort_by(|a, b| a.reference.cmp(&b.reference));
    let rows = objects
        .iter()
        .map(|object| OriginalLineageRow {
            object: object.reference.clone(),
            dependencies: if object.reference == published.reference {
                vec![payload.reference.clone()]
            } else {
                vec![]
            },
        })
        .collect();
    let claim = OriginalPublicationClaim {
        event: event.clone(),
        published: published.reference,
        origin: OriginalPublicationOrigin {
            owner_binding_hash: hash("cnp.owner-binding.v1"),
            execution_owner_id: owner.owner,
            session_id: id("original-session"),
            world_binding_hash: activation.record().world_binding_hash.clone(),
            activation_id: activation.record().activation_id.clone(),
            world_generation: activation.record().generation,
            incarnation_id: owner.incarnation,
            owner_generation: owner.generation,
            operation_id: id("quantum"),
            grant_id: id("window"),
            observation_batch: payload.reference.clone(),
            stop_receipt: payload.reference.clone(),
            measurement: payload.reference.clone(),
        },
        objects,
        rows,
    };
    let native = NativePublication {
        publication_id: event.id.clone(),
        endpoint: endpoint.clone(),
        native_sequence: event.source_sequence,
        publication,
        evaluation: None,
        causal_parents: vec![],
        payload: payload.reference.clone(),
        payload_bytes: payload.bytes.clone(),
    };
    states[0].borrow_mut().lineage_claim = Some(claim);
    states[0].borrow_mut().retained_outputs = vec![event.id.clone()];
    states[0].borrow_mut().terminal_scheduling = Some(NativeSchedulingObservation {
        node: id("a"),
        owners: token.route().owners.clone(),
        reached: position(1000),
        closed_prefix: publication,
        bounds: vec![],
        publications: vec![native],
        external_inputs: vec![],
        input_progress: None,
        proof_ref: payload.reference.clone(),
    });
    states[1].borrow_mut().lineage_required = true;
    // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
    runtime.close_quantum(&token).unwrap();
    assert!(matches!(poll(&mut runtime, &token), Poll::Ready(Ok(_))));
    let delivery = Delivery {
        connection_id: Some(id("edge")),
        connection_policy_ref: Some(payload.reference.clone()),
        external_root: None,
        provenance_ref: payload.reference.clone(),
        publication_id: event.id,
        producer: id("a"),
        consumer: id("b"),
        producer_endpoint: endpoint,
        consumer_endpoint: Endpoint {
            node_id: id("b"),
            port_id: id("data"),
            lane_id: id("input"),
        },
        source_sequence: 900.into(),
        native_sequence: 7.into(),
        evaluation: None,
        causal_parents: vec![],
        publication,
        delivery: Position::new(1001.into(), 0.into(), Phase::Delivery),
        payload: payload.reference.clone(),
    };
    let inventory = canonical::content_ref(
        // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
        &canonical::canonical_json(&serde_json::to_value(vec![delivery.clone()]).unwrap()).unwrap(),
        "application/json",
    )
    // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
    .unwrap();
    let batch = RuntimeInputBatch {
        activation,
        node: id("b"),
        stage_operation: id("stage"),
        batch: id("input"),
        owners: token.route().owners.clone(),
        cutoff: position(2000),
        inventory,
        deliveries: vec![delivery],
        payloads: vec![payload],
    };
    (runtime, states, token, batch)
}

#[test]
fn original_lineage_preserves_native_fifo_and_ordered_duplicate_occurrences() {
    let (mut runtime, states, _, mut batch) = fixture();
    let mut duplicate = batch.deliveries[0].clone();
    duplicate.source_sequence = 901.into();
    batch.deliveries.push(duplicate);
    let lineage = runtime
        .prepare_original_input_lineage(&batch)
        // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
        .unwrap()
        // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
        .unwrap();
    assert_eq!(lineage.original().deliveries(), batch.deliveries());
    assert_eq!(lineage.publications().len(), 2);
    let retained = lineage.retained_copy();
    assert_eq!(
        lineage.publications().as_ptr(),
        retained.publications().as_ptr()
    );
    assert_eq!(
        lineage.original().payloads().as_ptr(),
        retained.original().payloads().as_ptr()
    );
    assert!(
        lineage
            .publications()
            .iter()
            .all(|claim| claim.event.source_sequence == 7.into())
    );
    assert_eq!(states[0].borrow().lineage_reads, 2);
    assert_eq!(states[0].borrow().lineage_validations, 4);
    assert_eq!(states[1].borrow().begin_calls, 0);
}

#[test]
fn original_lineage_survives_actual_cached_ack_without_native_redispatch() {
    let (mut runtime, states, token, batch) = fixture();
    let before = runtime
        .prepare_original_input_lineage(&batch)
        // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
        .unwrap()
        // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
        .unwrap();
    // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
    runtime.acknowledge(&token, &[id("checksum-1")]).unwrap();
    let after = runtime
        .prepare_original_input_lineage(&batch)
        // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
        .unwrap()
        // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
        .unwrap();
    assert_eq!(before.publications(), after.publications());
    assert_eq!(states[0].borrow().begin_calls, 1);
    assert_eq!(states[0].borrow().close_calls, 1);
    assert_eq!(states[0].borrow().ack_calls, 1);
}

#[test]
fn original_lineage_changed_native_tuple_refuses_before_source_callback() {
    for variant in 0..4 {
        let (mut runtime, states, _, mut batch) = fixture();
        match variant {
            0 => batch.deliveries[0].publication_id = id("foreign"),
            1 => batch.deliveries[0].native_sequence = 900.into(),
            2 => batch.deliveries[0].producer_endpoint.lane_id = id("foreign"),
            _ => batch.deliveries[0].publication.time_ps = 999.into(),
        }
        assert!(runtime.prepare_original_input_lineage(&batch).is_err());
        assert_eq!(states[0].borrow().lineage_reads, 0);
        assert_eq!(states[1].borrow().begin_calls, 0);
    }
}

#[test]
fn original_lineage_source_refusal_or_changed_epoch_never_authorizes_consumer() {
    for invalid_source in [true, false] {
        let (mut runtime, states, _, batch) = fixture();
        if invalid_source {
            states[0].borrow_mut().lineage_invalid = true;
        } else {
            states[0]
                .borrow_mut()
                .lineage_claim
                .as_mut()
                // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
                .unwrap()
                .origin
                .activation_id = id("foreign");
        }
        assert!(runtime.prepare_original_input_lineage(&batch).is_err());
        assert_eq!(states[1].borrow().begin_calls, 0);
    }
}

#[test]
fn original_lineage_missing_row_and_cyclic_original_closure_refuse() {
    for cyclic in [false, true] {
        let (mut runtime, states, _, batch) = fixture();
        let mut state = states[0].borrow_mut();
        // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
        let claim = state.lineage_claim.as_mut().unwrap();
        if cyclic {
            let other = claim.published.clone();
            claim
                .rows
                .iter_mut()
                .find(|row| row.object == claim.origin.measurement)
                // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
                .unwrap()
                .dependencies = vec![other];
        } else {
            claim.rows.pop();
        }
        drop(state);
        assert!(runtime.prepare_original_input_lineage(&batch).is_err());
        assert_eq!(states[1].borrow().begin_calls, 0);
    }
}

#[test]
fn original_lineage_capture_refuses_before_any_legacy_snapshot_omission() {
    let (mut runtime, states, _, batch) = fixture();
    let lineage = runtime
        .prepare_original_input_lineage(&batch)
        // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
        .unwrap()
        // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
        .unwrap();
    runtime.input_batches.insert(
        id("stage"),
        inputs::RetainedInput {
            batch,
            provenance: None,
            lineage: Some(lineage),
            acknowledgement: None,
            failure: None,
            committed: false,
            commit: None,
        },
    );
    assert!(matches!(
        runtime.runtime_snapshot(position(2000), 1.into(), 1024 * 1024),
        Err(RuntimeError::UnsupportedFacet)
    ));
    assert_eq!(states[0].borrow().native_capture_calls, 0);
}

#[test]
fn original_lineage_transitive_inventory_exhaustion_refuses_before_consumer() {
    let (mut runtime, states, _, batch) = fixture();
    let mut state = states[0].borrow_mut();
    // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
    let claim = state.lineage_claim.as_mut().unwrap();
    let mut dependency = claim.origin.measurement.clone();
    for ordinal in 0..365 {
        let bytes = format!("original selected role {ordinal}").into_bytes();
        // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
        let reference = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
        claim.objects.push(InputPayload {
            reference: reference.clone(),
            bytes,
        });
        claim.rows.push(OriginalLineageRow {
            object: reference.clone(),
            dependencies: vec![dependency],
        });
        dependency = reference;
    }
    claim
        .rows
        .iter_mut()
        .find(|row| row.object == claim.published)
        // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
        .unwrap()
        .dependencies = vec![dependency];
    claim.objects.sort_by(|a, b| a.reference.cmp(&b.reference));
    claim.rows.sort_by(|a, b| a.object.cmp(&b.object));
    assert!(
        claim
            .rows
            .iter()
            .map(|row| row.dependencies.len())
            .sum::<usize>()
            < 4096
    );
    drop(state);

    assert!(matches!(
        runtime.prepare_original_input_lineage(&batch),
        Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))
    ));
    assert_eq!(states[1].borrow().begin_calls, 0);
}
