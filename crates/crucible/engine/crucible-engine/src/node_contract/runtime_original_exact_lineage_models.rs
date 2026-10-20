//! Exercises actual exact runtime tokens with explicitly modeled native ancestry.
//!
//! The core dispatch and terminal custody are actual; native peers and codecs are modeled.
//! No source installation, native class, Ready or connected-world claim is inferred.

// crucible-lint: allow panic-shortcut -- These association models panic on invalid synthetic fixture setup and violated ledger invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::node_contract::runtime::inputs::RetainedInput;
use crate::node_scheduling::{
    InputPayload, NativePublication, NativeSchedulingObservation, RuntimeInputBatch,
    event::Delivery,
};
use crucible_node_format::{Endpoint, Event, EventStage, Extensions, canonical};

fn exact_fixture(
    ancestry: bool,
) -> (
    NodeRuntime,
    Vec<Rc<RefCell<NativeState>>>,
    OperationToken,
    RuntimeInputBatch,
) {
    let (mut runtime, states) = runtime(OperatingMode::Exact);
    let activation = activate(&mut runtime);
    let token = exact(&mut runtime, &activation, "exact-lineage");
    let original = runtime.operations[&id("exact-lineage")].admission.clone();
    let payload = InputPayload {
        // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
        reference: canonical::content_ref(b"original bytes", "application/octet-stream").unwrap(),
        bytes: b"original bytes".to_vec(),
    };
    let publication = Position::new(5.into(), 1.into(), Phase::Publication);
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
        causal_parent_ids: if ancestry {
            vec![id("model-reaction")]
        } else {
            vec![]
        },
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
            operation_id: id("exact-lineage"),
            grant_id: id("exact-lineage"),
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
        evaluation: ancestry.then_some(Position::new(5.into(), 0.into(), Phase::Reaction)),
        causal_parents: if ancestry {
            vec![Position::new(5.into(), 0.into(), Phase::Reaction)]
        } else {
            vec![]
        },
        payload: payload.reference.clone(),
        payload_bytes: payload.bytes.clone(),
    };
    states[0].borrow_mut().lineage_claim = Some(claim);
    states[0].borrow_mut().retained_outputs = vec![event.id.clone()];
    states[0].borrow_mut().terminal_scheduling = Some(NativeSchedulingObservation {
        node: id("a"),
        owners: token.route().owners.clone(),
        reached: position(9),
        closed_prefix: position(9),
        bounds: vec![],
        publications: vec![native],
        external_inputs: vec![],
        input_progress: None,
        proof_ref: payload.reference.clone(),
    });
    states[1].borrow_mut().lineage_required = true;
    // crucible-lint: allow panic-shortcut -- finite synthetic source fixtures panic to identify the exact custody transition.
    let observed = poll(&mut runtime, &token);
    assert!(matches!(observed, Poll::Ready(Ok(_))), "{observed:?}");
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
        evaluation: ancestry.then_some(Position::new(5.into(), 0.into(), Phase::Reaction)),
        causal_parents: if ancestry {
            vec![Position::new(5.into(), 0.into(), Phase::Reaction)]
        } else {
            vec![]
        },
        publication,
        delivery: Position::new(6.into(), 0.into(), Phase::Delivery),
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
        cutoff: position(20),
        inventory,
        deliveries: vec![delivery],
        payloads: vec![payload],
    };
    (runtime, states, token, batch)
}

#[test]
fn exact_original_lineage_requires_the_additional_closed_source_codec() {
    let (mut runtime, states, _, batch) = exact_fixture(true);
    assert!(runtime.prepare_original_input_lineage(&batch).is_err());
    assert_eq!(states[0].borrow().exact_lineage_validations, 1);
    assert_eq!(states[1].borrow().begin_calls, 0);

    states[0].borrow_mut().exact_lineage_supported = true;
    let lineage = runtime
        .prepare_original_input_lineage(&batch)
        .unwrap()
        .unwrap();
    assert_eq!(
        lineage.publications()[0].event.causal_parent_ids,
        vec![id("model-reaction")]
    );
    assert_eq!(states[0].borrow().exact_lineage_validations, 3);
    assert_eq!(states[0].borrow().begin_calls, 1);
    assert_eq!(states[1].borrow().begin_calls, 0);
}

#[test]
fn exact_original_lineage_binds_native_parent_positions_and_common_operation() {
    for variant in 0..4 {
        let (mut runtime, states, _, mut batch) = exact_fixture(true);
        states[0].borrow_mut().exact_lineage_supported = true;
        match variant {
            0 => batch.deliveries[0].causal_parents[0].microstep = 1.into(),
            1 => batch.deliveries[0].evaluation = None,
            2 => {
                states[0]
                    .borrow_mut()
                    .lineage_claim
                    .as_mut()
                    .unwrap()
                    .origin
                    .grant_id = id("foreign")
            }
            _ => {
                states[0]
                    .borrow_mut()
                    .lineage_claim
                    .as_mut()
                    .unwrap()
                    .event
                    .causal_parent_ids = vec![id("foreign")]
            }
        }
        assert!(runtime.prepare_original_input_lineage(&batch).is_err());
        assert_eq!(states[1].borrow().begin_calls, 0);
        if variant < 2 {
            assert_eq!(states[0].borrow().lineage_reads, 0);
        }
    }
}

#[test]
fn exact_lineage_provenance_retains_original_roots_and_deduplicates_body_bytes() {
    let (mut runtime, states, _, mut batch) = exact_fixture(true);
    states[0].borrow_mut().exact_lineage_supported = true;
    let mut duplicate = batch.deliveries[0].clone();
    duplicate.source_sequence = 901.into();
    batch.deliveries.push(duplicate);
    let lineage = runtime
        .prepare_original_input_lineage(&batch)
        .unwrap()
        .unwrap();
    let provenance = runtime
        .provenance_from_original_lineage(&batch, &lineage)
        .unwrap();
    assert!(provenance.activation().same_authority(batch.activation()));
    assert_eq!(
        provenance.roots(),
        &[batch.deliveries[0].provenance_ref.clone()]
    );
    assert_eq!(provenance.objects(), lineage.publications()[0].objects);
    assert_eq!(provenance.inventory(), batch.inventory());
    batch.stage_operation = id("foreign-stage");
    assert!(
        runtime
            .provenance_from_original_lineage(&batch, &lineage)
            .is_err()
    );
}

#[test]
fn ordinary_staging_keeps_lineage_without_provenance_refusal() {
    let (mut runtime, states, token, batch) = exact_fixture(true);
    states[0].borrow_mut().exact_lineage_supported = true;
    runtime.acknowledge(&token, &[id("checksum-1")]).unwrap();
    assert!(matches!(
        runtime.stage_inputs(batch),
        Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))
    ));
    assert_eq!(
        runtime.original_error_site,
        Some("input/lineage-without-provenance")
    );
    assert!(runtime.input_batches.is_empty());
    assert_eq!(states[1].borrow().begin_calls, 0);
}

#[test]
fn exact_lineage_provenance_precharges_complete_retained_inventory() {
    let (mut runtime, states, _, batch) = exact_fixture(true);
    states[0].borrow_mut().exact_lineage_supported = true;
    {
        let mut state = states[0].borrow_mut();
        let claim = state.lineage_claim.as_mut().unwrap();
        let mut dependencies = vec![];
        for index in 0..4094 {
            let bytes = format!("model-original-source-leaf-{index}").into_bytes();
            let reference = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
            dependencies.push(reference.clone());
            claim.objects.push(InputPayload {
                reference: reference.clone(),
                bytes,
            });
            claim.rows.push(OriginalLineageRow {
                object: reference,
                dependencies: vec![],
            });
        }
        let published = claim
            .rows
            .iter_mut()
            .find(|row| row.object == claim.published)
            .unwrap();
        published.dependencies.extend(dependencies);
        published.dependencies.sort();
        claim
            .objects
            .sort_by(|left, right| left.reference.cmp(&right.reference));
        claim
            .rows
            .sort_by(|left, right| left.object.cmp(&right.object));
    }
    let lineage = runtime
        .prepare_original_input_lineage(&batch)
        .unwrap()
        .unwrap();
    let provenance = runtime
        .provenance_from_original_lineage(&batch, &lineage)
        .unwrap();
    assert_eq!(provenance.objects().len(), 4096);
    runtime.input_batches.insert(
        id("prior-retained-original"),
        RetainedInput {
            batch: batch.retained_copy(),
            provenance: Some(provenance),
            lineage: Some(lineage.retained_copy()),
            acknowledgement: None,
            failure: None,
            committed: false,
            commit: None,
        },
    );
    assert!(matches!(
        runtime.provenance_from_original_lineage(&batch, &lineage),
        Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))
    ));
    assert_eq!(states[1].borrow().begin_calls, 0);
}

pub(super) fn preservation_record() -> (
    NodeRuntime,
    OriginalInputLineage,
    OriginalLineageRuntimeRecord,
) {
    let (mut runtime, states, _, batch) = exact_fixture(true);
    states[0].borrow_mut().exact_lineage_supported = true;
    let lineage = runtime
        .prepare_original_input_lineage(&batch)
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap()
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap();
    let legacy = runtime
        .runtime_snapshot(position(2000), 1.into(), 1024 * 1024)
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap();
    let saved = lineage
        .saved_reference_view(OriginalInputLineageLimits::default())
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap();
    let mut objects: Vec<_> = lineage.publications()[0]
        .objects
        .iter()
        .map(|object| object.reference.clone())
        .collect();
    objects.sort();
    objects.dedup();
    let input = OriginalLineageInputRecord {
        node: batch.node().clone(),
        stage_operation: batch.stage_operation().clone(),
        batch: batch.batch().clone(),
        owners: batch.owners().to_vec(),
        cutoff: batch.cutoff(),
        inventory: batch.inventory().clone(),
        deliveries: batch.deliveries().to_vec(),
        payloads: batch
            .payloads()
            .iter()
            .map(|object| object.reference.clone())
            .collect(),
        provenance: Some(OriginalLineageProvenanceRecord {
            schema_version: 1,
            node: batch.node().clone(),
            stage_operation: batch.stage_operation().clone(),
            batch: batch.batch().clone(),
            inventory: batch.inventory().clone(),
            roots: vec![lineage.publications()[0].origin.measurement.clone()],
            objects,
        }),
        lineage: Some(saved),
        acknowledgement: None,
        failure: None,
        committed: false,
        coordinator_committed: false,
    };
    let record = OriginalLineageRuntimeRecord {
        schema_version: 7,
        source_activation: legacy.source_activation,
        capture_cut: legacy.capture_cut,
        capture_ordinal: legacy.capture_ordinal,
        owners: legacy.owners,
        operations: legacy.operations,
        inputs: vec![input],
    };
    (runtime, lineage, record)
}
