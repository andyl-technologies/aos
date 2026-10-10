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

pub(in crate::node_contract::runtime) fn preservation_record() -> (
    NodeRuntime,
    OriginalInputLineage,
    OriginalLineageRuntimeRecord,
) {
    let (mut runtime, _, _, batch) = fixture();
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

#[test]
fn original_lineage_reference_record_preserves_raw_scope_without_body_arrays() {
    let (_, lineage, mut record) = preservation_record();
    record.source_activation.generation = 2.into();
    record.source_activation.activation_id = id("fresh-current-activation");
    record.inputs[0].owners[0].incarnation = id("fresh-current-consumer");
    record
        .validate_metadata(OriginalInputLineageLimits::default(), 1024 * 1024)
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap();

    // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
    let bytes = serde_json::to_vec(&record).unwrap();
    // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
    let decoded: OriginalLineageRuntimeRecord = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded, record);
    assert_eq!(
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        decoded.inputs[0].lineage.as_ref().unwrap().source,
        *lineage.source_scope()
    );
    assert_ne!(
        decoded.source_activation.activation_id,
        decoded.inputs[0]
            .lineage
            .as_ref()
            // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
            .unwrap()
            .source
            .source_activation
            .activation_id
    );
    // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
    let value = serde_json::to_value(&decoded).unwrap();
    assert!(
        value["inputs"][0]["provenance"]["objects"][0]
            .get("bytes")
            .is_none()
    );
    assert!(
        value["inputs"][0]["lineage"]["publications"][0]["objects"][0]
            .get("bytes")
            .is_none()
    );
}

#[test]
fn original_lineage_reference_record_refuses_credit_rows_and_missing_nullable() {
    let (_, lineage, record) = preservation_record();
    let limits = OriginalInputLineageLimits {
        maximum_bytes: 1,
        ..Default::default()
    };
    assert!(matches!(
        lineage.saved_reference_view(limits),
        Err(RuntimeError::ResourceLimit)
    ));
    assert!(matches!(
        record.validate_metadata(limits, 1024 * 1024),
        Err(RuntimeError::ResourceLimit)
    ));
    assert!(matches!(
        record.validate_metadata(OriginalInputLineageLimits::default(), 1),
        Err(RuntimeError::ResourceLimit)
    ));

    let mut changed = record.clone();
    // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
    changed.inputs[0].lineage.as_mut().unwrap().publications[0]
        .rows
        .pop();
    assert!(
        changed
            .validate_metadata(OriginalInputLineageLimits::default(), 1024 * 1024)
            .is_err()
    );
    // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
    let mut value = serde_json::to_value(&record).unwrap();
    value["inputs"][0]
        .as_object_mut()
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap()
        .remove("lineage");
    assert!(serde_json::from_value::<OriginalLineageRuntimeRecord>(value).is_err());
    // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
    let mut value = serde_json::to_value(&record).unwrap();
    value
        .as_object_mut()
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap()
        .insert("unknown_native_permission".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<OriginalLineageRuntimeRecord>(value).is_err());
}

#[test]
fn original_lineage_runtime7_default_native_verifier_cannot_promote_parsed_data() {
    struct LegacyVerifier {
        legacy_calls: usize,
    }
    impl NativeRuntimeContinuationVerifier for LegacyVerifier {
        fn verify_runtime_continuation(
            &mut self,
            _: &RuntimeSnapshot,
            _: &crate::node_scheduling::SchedulingSnapshot,
            _: &ActivationRecord,
        ) -> Result<NativeRuntimeContinuationEvidence, RuntimeError> {
            self.legacy_calls += 1;
            Err(RuntimeError::InvalidReceipt)
        }
    }
    let (runtime, _, record) = preservation_record();
    // The default hook rejects before inspecting either inert saved document.
    let scheduling = crate::node_scheduling::SchedulingSnapshot {
        schema_version: 1,
        original_epochs: None,
        ordering_profile: "cnp.superdense.v1".into(),
        world_binding_hash: record.source_activation.world_binding_hash.clone(),
        source_activation_id: record.source_activation.activation_id.clone(),
        source_generation: record.source_activation.generation,
        source_boundary: record.source_activation.boundary,
        capture_cut: record.capture_cut,
        capture_ordinal: record.capture_ordinal,
        source_owners: vec![],
        maximum_microsteps: 64.into(),
        positions: vec![],
        producers: vec![],
        native_sequences: vec![],
        external_closed_prefixes: vec![],
        payload_objects: vec![],
        pending_deliveries: vec![],
        used_operations: vec![],
        reservations: vec![],
        input_batches: vec![],
        used_input_batches: vec![],
    };
    let mut verifier = LegacyVerifier { legacy_calls: 0 };
    assert!(matches!(
        verifier.verify_original_lineage_continuation(
            &record,
            &scheduling,
            runtime.barrier.record(),
        ),
        Err(RuntimeError::UnsupportedFacet)
    ));
    assert_eq!(verifier.legacy_calls, 0);
}

#[test]
fn original_lineage_reference_bodies_keep_fifo_ids_and_exact_media_roles() {
    let (_, lineage, record) = preservation_record();
    let bodies: BTreeMap<_, _> = lineage
        .publications()
        .iter()
        .flat_map(|claim| &claim.objects)
        .map(|object| (object.reference.clone(), object.bytes.as_slice()))
        .collect();
    record
        .check_original_bodies(|reference| bodies.get(reference).copied())
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap();

    let mut changed = record.clone();
    changed.inputs[0].deliveries[0].native_sequence = 8.into();
    assert!(
        changed
            .check_original_bodies(|reference| bodies.get(reference).copied())
            .is_err()
    );
    let mut changed = record.clone();
    changed.inputs[0].deliveries[0].publication_id = id("counterfactual-id");
    assert!(
        changed
            .check_original_bodies(|reference| bodies.get(reference).copied())
            .is_err()
    );
    let mut changed = record.clone();
    // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
    changed.inputs[0].lineage.as_mut().unwrap().publications[0]
        .origin
        .session_id = id("changed-session");
    // The data/body checker cannot authenticate a native session label. The
    // mandatory original source policy must reject this distinct original scope.
    changed
        .check_original_bodies(|reference| bodies.get(reference).copied())
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap();
    // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
    changed.inputs[0].lineage.as_mut().unwrap().publications[0]
        .origin
        .activation_id = id("changed-world-activation");
    assert!(
        changed
            .validate_metadata(OriginalInputLineageLimits::default(), 1024 * 1024)
            .is_err()
    );

    // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
    let published = &record.inputs[0].lineage.as_ref().unwrap().publications[0].published;
    assert!(
        record
            .check_original_bodies(|reference| {
                if reference == published {
                    None
                } else {
                    bodies.get(reference).copied()
                }
            })
            .is_err()
    );
    assert!(
        record
            .check_original_bodies(|reference| {
                if reference == published {
                    Some(b"changed raw original body".as_slice())
                } else {
                    bodies.get(reference).copied()
                }
            })
            .is_err()
    );
}

#[test]
fn original_lineage_runtime_export_keeps_cached_operations_and_unknown_input() {
    let (mut runtime, lineage, historical) = preservation_record();
    let batch = lineage.original().retained_copy();
    let source = &lineage.publications()[0];
    let provenance = InputProvenanceClosure::from_validated(
        &batch,
        vec![source.origin.measurement.clone()],
        source.objects.clone(),
    );
    let failure = OperationFailure {
        effects: EffectKnowledge::MayHaveProgressed,
        reason: "original native input transport uncertainty".into(),
    };
    runtime.input_batches.insert(
        batch.stage_operation().clone(),
        inputs::RetainedInput {
            batch,
            provenance: Some(provenance),
            lineage: Some(lineage.retained_copy()),
            acknowledgement: None,
            failure: Some(failure.clone()),
            committed: false,
            commit: None,
        },
    );

    let record = runtime
        .original_lineage_runtime_snapshot(
            position(2000),
            1.into(),
            OriginalInputLineageLimits::default(),
            1024 * 1024,
        )
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap();
    assert_eq!(record.operations, historical.operations);
    assert_eq!(record.owners, historical.owners);
    assert_eq!(record.inputs[0].failure, Some(failure));
    assert_eq!(
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        record.inputs[0].lineage.as_ref().unwrap().source,
        *lineage.source_scope()
    );
    let retained: Vec<_> = runtime.original_lineage_capture_objects().collect();
    record
        .check_original_bodies(|reference| {
            retained
                .iter()
                .find(|object| &object.reference == reference)
                .map(|object| object.bytes.as_slice())
        })
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap();
    assert!(matches!(
        runtime.runtime_snapshot(position(2000), 1.into(), 1024 * 1024),
        Err(RuntimeError::UnsupportedFacet)
    ));
    assert!(matches!(
        runtime.original_lineage_runtime_snapshot(
            position(2000),
            1.into(),
            OriginalInputLineageLimits {
                maximum_objects: 1,
                ..Default::default()
            },
            1024 * 1024,
        ),
        Err(RuntimeError::ResourceLimit)
    ));
    assert_eq!(
        runtime.input_batches[&id("stage")].failure,
        record.inputs[0].failure
    );
}

#[path = "runtime_original_input_lineage/restoration_models.rs"]
mod restoration_models;

#[test]
fn original_lineage_whole_metadata_credit_precedes_every_copy_attempt() {
    use super::super::original_input_lineage::snapshot_credit;

    let (mut runtime, _, _, batch) = fixture();
    let lineage = runtime
        .prepare_original_input_lineage(&batch)
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap()
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap();
    let provenance = InputProvenanceClosure::from_validated(
        &batch,
        vec![lineage.publications()[0].origin.measurement.clone()],
        lineage.publications()[0].objects.clone(),
    );
    runtime.input_batches.insert(
        batch.batch().clone(),
        super::super::inputs::RetainedInput {
            batch,
            provenance: Some(provenance),
            lineage: Some(lineage),
            acknowledgement: None,
            failure: None,
            committed: false,
            commit: None,
        },
    );
    let limits = OriginalInputLineageLimits::default();
    let record = runtime
        .original_lineage_runtime_snapshot(position(2000), 1.into(), limits, 1024 * 1024)
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap();
    // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
    let encoded = serde_json::to_vec(&record).unwrap();
    let view = snapshot_credit::SnapshotView {
        runtime: &runtime,
        cut: position(2000),
        ordinal: 1.into(),
    };
    // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
    assert_eq!(serde_json::to_vec(&view).unwrap(), encoded);

    // Each old per-operation check fits, while their complete containing record
    // does not. Counting must reject before the first metadata-copy reservation.
    let insufficient = encoded.len() - 1;
    let per_operation = insufficient / runtime.operations.len().max(1);
    for operation in runtime.operations.values() {
        assert!(
            serde_json::to_vec(&operation.admission.request)
                // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
                .unwrap()
                .len()
                <= per_operation
        );
        if let RetainedResult::Complete(outcome) | RetainedResult::Acknowledged(outcome) =
            &operation.result
        {
            // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
            assert!(serde_json::to_vec(outcome).unwrap().len() <= per_operation);
        }
    }
    let before = snapshot_credit::metadata_copy_attempts();
    assert!(matches!(
        runtime.original_lineage_runtime_snapshot(position(2000), 1.into(), limits, insufficient),
        Err(RuntimeError::ResourceLimit)
    ));
    assert_eq!(snapshot_credit::metadata_copy_attempts(), before);
    assert_eq!(
        runtime
            .original_lineage_runtime_snapshot(position(2000), 1.into(), limits, encoded.len())
            // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
            .unwrap(),
        record
    );
    assert_eq!(snapshot_credit::metadata_copy_attempts(), before + 1);
}

/// Creates synthetic first-epoch facts separately from genuine runtime tokens.
fn conditional_fixture() -> (
    NodeRuntime,
    Vec<Rc<RefCell<NativeState>>>,
    RuntimeInputBatch,
    SavedOriginalInputScope,
) {
    let (runtime, states, _, batch) = fixture();
    let mut first = SavedRuntimeActivation::from(batch.activation().record());
    first.activation_id = id("synthetic/first-activation");
    first.world_binding_hash = hash("cnp.synthetic-first-world.v1");
    for owner in &mut first.owners {
        owner.incarnation = id("synthetic/first-incarnation");
    }
    let first_owners = batch
        .owners()
        .iter()
        .map(|current| {
            // crucible-lint: allow panic-shortcut -- The finite synthetic first roster deliberately retains every current logical owner.
            first
                .owners
                .iter()
                .find(|owner| owner.owner == current.owner)
                // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
                .unwrap()
                .clone()
        })
        .collect();
    let scope = SavedOriginalInputScope {
        source_activation: first.clone(),
        node: batch.node().clone(),
        stage_operation: batch.stage_operation().clone(),
        batch: batch.batch().clone(),
        owners: first_owners,
        cutoff: batch.cutoff(),
        inventory: batch.inventory().clone(),
    };
    let mut source = states[0].borrow_mut();
    // crucible-lint: allow panic-shortcut -- The original synthetic producer deliberately retains its exact terminal claim.
    let origin = &mut source.lineage_claim.as_mut().unwrap().origin;
    origin.world_binding_hash = first.world_binding_hash;
    origin.activation_id = first.activation_id;
    origin.world_generation = first.generation;
    // crucible-lint: allow panic-shortcut -- The first roster deliberately includes the original producer owner.
    let owner = first
        .owners
        .iter()
        .find(|owner| owner.owner == origin.execution_owner_id)
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap();
    origin.incarnation_id = owner.incarnation.clone();
    origin.owner_generation = owner.generation;
    drop(source);
    (runtime, states, batch, scope)
}

#[test]
fn conditional_lineage_requires_both_actual_source_and_target_validators() {
    let (mut runtime, states, batch, scope) = conditional_fixture();
    // Historical labels alone cannot cross the strict native epoch gate.
    assert!(runtime.prepare_original_input_lineage(&batch).is_err());
    states[1].borrow_mut().conditional_lineage_scope = Some(scope.clone());
    // Consumer scope validation alone cannot grant a source target association.
    assert!(runtime.prepare_original_input_lineage(&batch).is_err());
    assert_eq!(states[0].borrow().conditional_target_validations, 1);
    assert_eq!(states[1].borrow().begin_calls, 0);

    states[0].borrow_mut().conditional_target_supported = true;
    // crucible-lint: allow panic-shortcut -- This explicitly synthetic target predicate permits the tested exact original association.
    let lineage = runtime
        .prepare_original_input_lineage(&batch)
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap()
        // crucible-lint: allow panic-shortcut -- Synthetic preservation setup and exact ledger assertions deliberately panic at the first invalid original fixture.
        .unwrap();
    assert_eq!(lineage.source_scope(), &scope);
    assert_eq!(
        lineage.original().activation().record(),
        batch.activation().record()
    );
    assert_ne!(
        lineage.source_scope().source_activation.activation_id,
        lineage.original().activation().record().activation_id
    );
    assert_eq!(states[0].borrow().conditional_target_validations, 3);
    assert_eq!(states[1].borrow().begin_calls, 0);
}

#[test]
fn conditional_lineage_foreign_current_inventory_refuses_before_source_read() {
    for changed in ["node", "stage", "inventory", "owner", "world_roster"] {
        let (mut runtime, states, batch, mut scope) = conditional_fixture();
        match changed {
            "node" => scope.node = id("foreign/node"),
            "stage" => scope.stage_operation = id("foreign/stage"),
            "inventory" => scope.inventory = blob(),
            "owner" => scope.owners.clear(),
            _ => scope.source_activation.owners.clear(),
        }
        states[1].borrow_mut().conditional_lineage_scope = Some(scope);
        assert!(runtime.prepare_original_input_lineage(&batch).is_err());
        assert_eq!(states[0].borrow().lineage_reads, 0);
        assert_eq!(states[0].borrow().conditional_target_validations, 0);
        assert_eq!(states[1].borrow().begin_calls, 0);
    }
}

#[path = "runtime_original_input_observation_models.rs"]
mod stage_projection;
