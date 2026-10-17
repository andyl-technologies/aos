//! Data-only manifest geometry, original role, and pre-read credit counterexamples.

use std::cell::Cell;

use super::*;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn reference(bytes: &[u8], media: &str) -> ContentRef {
    canonical::content_ref(bytes, media).unwrap()
}

fn empty() -> (InputLineageInventory, InputBatch) {
    let batch = InputBatch {
        schema_version: 1,
        execution_owner_id: id("owner/consumer"),
        input_epoch: id("input/epoch"),
        batch_id: id("batch/original"),
        batch_sequence: U64::new(1),
        events: Vec::new(),
        extensions: Extensions::new(),
    };
    let inventory = InputLineageInventory {
        schema_version: 1,
        execution_owner_id: batch.execution_owner_id.clone(),
        owner_generation: U64::new(1),
        input_epoch: batch.input_epoch.clone(),
        batch_id: batch.batch_id.clone(),
        batch_sequence: batch.batch_sequence,
        entries: Vec::new(),
        dependencies: Vec::new(),
    };
    (inventory, batch)
}

#[test]
fn empty_original_cut_has_no_hidden_dependency_or_enclosing_batch_cycle() {
    let (inventory, batch) = empty();
    inventory
        .validate_bodies(&batch, U64::new(1), |_| {
            panic!("no original body is required")
        })
        .unwrap();
    let bytes = canonical::canonical_json(&serde_json::to_value(&inventory).unwrap()).unwrap();
    assert_eq!(
        canonical::decode::<InputLineageInventory>(&bytes, 65_536).unwrap(),
        inventory
    );
}

#[test]
fn changed_original_scope_refuses_before_reading_any_body() {
    let (original, batch) = empty();
    for variant in 0..5 {
        let mut changed = original.clone();
        match variant {
            0 => changed.execution_owner_id = id("foreign/owner"),
            1 => changed.batch_id = id("foreign/batch"),
            2 => changed.input_epoch = id("foreign/epoch"),
            3 => changed.batch_sequence = U64::new(2),
            _ => changed.owner_generation = U64::new(2),
        }
        assert!(
            changed
                .validate_bodies(&batch, U64::new(1), |_| panic!(
                    "scope preflight must refuse"
                ))
                .is_err()
        );
    }
}

#[test]
fn declared_extent_exhaustion_refuses_before_resolver_callback() {
    let (mut inventory, batch) = empty();
    let mut body = reference(b"not allocated", "application/octet-stream");
    body.length = U64::new(64 * 1024 * 1024 + 1);
    inventory.dependencies.push(InputLineageRow {
        object: body,
        dependencies: Vec::new(),
    });
    let reads = Cell::new(0);
    assert!(
        inventory
            .validate_bodies(&batch, U64::new(1), |_| {
                reads.set(reads.get() + 1);
                Ok(&[])
            })
            .is_err()
    );
    assert_eq!(reads.get(), 0);
}

#[test]
fn extra_unscoped_object_refuses_before_original_body_reads() {
    let (mut inventory, batch) = empty();
    inventory.dependencies.push(InputLineageRow {
        object: reference(b"outside", "application/octet-stream"),
        dependencies: Vec::new(),
    });
    assert!(
        inventory
            .validate_bodies(&batch, U64::new(1), |_| panic!(
                "unscoped inventory must refuse"
            ))
            .is_err()
    );
}

#[test]
fn cycles_and_missing_rows_remain_explicit_refusals() {
    let first = reference(b"first", "application/json");
    let second = reference(b"second", "application/json");
    let roots = BTreeSet::from([first.clone()]);
    let mut cycle = vec![
        InputLineageRow {
            object: first.clone(),
            dependencies: vec![second.clone()],
        },
        InputLineageRow {
            object: second,
            dependencies: vec![first],
        },
    ];
    cycle.sort_by(|a, b| a.object.cmp(&b.object));
    assert!(validate_graph(&roots, &cycle).is_err());
    cycle.pop();
    assert!(validate_graph(&roots, &cycle).is_err());
}

#[test]
fn same_physical_bytes_under_two_original_roles_remain_separate_rows() {
    let proof = reference(b"unchanged original", "application/json");
    let payload = reference(b"unchanged original", "application/octet-stream");
    assert_eq!(proof.hash, payload.hash);
    let roots = BTreeSet::from([proof.clone()]);
    let mut rows = vec![
        InputLineageRow {
            object: proof.clone(),
            dependencies: vec![payload.clone()],
        },
        InputLineageRow {
            object: payload.clone(),
            dependencies: Vec::new(),
        },
    ];
    rows.sort_by(|a, b| a.object.cmp(&b.object));
    validate_graph(&roots, &rows).unwrap();
    assert_ne!(
        locate(&rows, &proof).unwrap(),
        locate(&rows, &payload).unwrap()
    );
    let undeclared_alias = reference(b"unchanged original", "text/plain");
    assert!(locate(&rows, &undeclared_alias).is_err());
}

#[test]
fn same_digest_extent_conflict_and_unknown_edition_refuse_before_read() {
    let (mut inventory, batch) = empty();
    let first = reference(b"same", "application/json");
    let mut other = reference(b"same", "application/octet-stream");
    other.length = U64::new(other.length.get() + 1);
    inventory.dependencies = vec![
        InputLineageRow {
            object: first,
            dependencies: Vec::new(),
        },
        InputLineageRow {
            object: other,
            dependencies: Vec::new(),
        },
    ];
    inventory
        .dependencies
        .sort_by(|a, b| a.object.cmp(&b.object));
    assert!(
        inventory
            .validate_bodies(&batch, U64::new(1), |_| panic!("declared roles disagree"))
            .is_err()
    );
    let (mut inventory, batch) = empty();
    inventory.schema_version = 2;
    assert!(
        inventory
            .validate_bodies(&batch, U64::new(1), |_| panic!("unknown edition"))
            .is_err()
    );
}

struct OriginalBodies {
    inventory: InputLineageInventory,
    batch: InputBatch,
    bodies: BTreeMap<ContentRef, Vec<u8>>,
    stop: StopReceipt,
}

fn stored_json<T: Serialize>(value: &T, bodies: &mut BTreeMap<ContentRef, Vec<u8>>) -> ContentRef {
    let bytes = canonical::canonical_json(&serde_json::to_value(value).unwrap()).unwrap();
    let object = reference(&bytes, "application/json");
    bodies.insert(object.clone(), bytes);
    object
}

fn original_bodies() -> OriginalBodies {
    let (mut inventory, mut batch) = empty();
    let mut bodies = BTreeMap::new();
    let measurement = reference(b"original source measurement", "application/octet-stream");
    let payload = reference(b"identical checksum bytes", "application/octet-stream");
    bodies.insert(measurement.clone(), b"original source measurement".to_vec());
    bodies.insert(payload.clone(), b"identical checksum bytes".to_vec());
    let source = Endpoint {
        node_id: id("producer/a"),
        port_id: id("data"),
        lane_id: id("output"),
    };
    let publication = Position::new(10.into(), 0.into(), Phase::Publication);
    let original = Event {
        schema_version: 1,
        id: id("checksum-1"),
        source: source.clone(),
        destination: source.clone(),
        position: publication,
        stage: EventStage::Publication,
        publication_position: publication,
        delivery_position: None,
        source_sequence: 1.into(),
        causal_parent_ids: Vec::new(),
        payload: payload.clone(),
        provenance_ref: measurement.clone(),
        extensions: Extensions::new(),
    };
    let mut delivered = original.clone();
    delivered.destination = Endpoint {
        node_id: id("consumer/b"),
        port_id: id("data"),
        lane_id: id("input"),
    };
    delivered.position = Position::new(11.into(), 0.into(), Phase::Delivery);
    delivered.delivery_position = Some(delivered.position);
    delivered.stage = EventStage::Delivery;
    let published_ref = stored_json(&original, &mut bodies);
    let delivered_ref = stored_json(&delivered, &mut bodies);
    let owner_binding_hash = HashRef {
        algorithm: "blake3-256".into(),
        domain: "cnp.owner-binding.v1".into(),
        digest: "1".repeat(64),
    };
    let world_binding_hash = HashRef {
        algorithm: "blake3-256".into(),
        domain: "cnp.world-binding.v1".into(),
        digest: "2".repeat(64),
    };
    let observation = ObservationBatch {
        schema_version: 1,
        execution_owner_id: id("owner/a"),
        owner_binding_hash: owner_binding_hash.clone(),
        world_binding_hash: world_binding_hash.clone(),
        activation_id: id("activation/a"),
        world_generation: 1.into(),
        owner_generation: 1.into(),
        operation_id: id("operation/a"),
        grant_id: Some(id("grant/a")),
        first_sequence: 1.into(),
        last_sequence: 1.into(),
        events: vec![original],
        visibility: Visibility::Staged,
        measurement_ref: measurement.clone(),
        extensions: Extensions::new(),
    };
    let observation_ref = stored_json(&observation, &mut bodies);
    let stop = StopReceipt {
        schema_version: 1,
        session_id: id("session/a"),
        incarnation_id: id("incarnation/a"),
        owner_binding_hash,
        world_binding_hash,
        activation_id: observation.activation_id.clone(),
        world_generation: 1.into(),
        execution_owner_id: observation.execution_owner_id.clone(),
        owner_generation: 1.into(),
        operation_id: observation.operation_id.clone(),
        grant_id: observation.grant_id.clone(),
        participant_ids: vec![source.node_id],
        mode: OperatingMode::Quantized,
        ordering_profile: "superdense-v1".into(),
        reached: Some(Position::new(10.into(), 0.into(), Phase::BoundaryControl)),
        production_prefix: publication,
        prefix_kind: ClosureKind::Through,
        output_lower_bounds: Vec::new(),
        physical_stop: PhysicalStop::ObservationClosed,
        cause: id("quantum-complete"),
        input_custody: measurement.clone(),
        pending_inventory: measurement.clone(),
        observation_batch: observation_ref.clone(),
        physical_measurement_ref: measurement.clone(),
        evidence_refs: Vec::new(),
        extensions: Extensions::new(),
    };
    let stop_ref = stored_json(&stop, &mut bodies);
    inventory.entries.push(InputLineageEntry {
        delivered: delivered_ref.clone(),
        published: published_ref.clone(),
        producer: InputLineageProducer {
            owner_binding_hash: observation.owner_binding_hash.clone(),
            execution_owner_id: observation.execution_owner_id.clone(),
            session_id: stop.session_id.clone(),
            world_binding_hash: observation.world_binding_hash.clone(),
            activation_id: observation.activation_id.clone(),
            world_generation: observation.world_generation,
            incarnation_id: stop.incarnation_id.clone(),
            owner_generation: observation.owner_generation,
            operation_id: observation.operation_id.clone(),
            grant_id: stop.grant_id.clone().unwrap(),
            observation_batch: observation_ref.clone(),
            stop_receipt: stop_ref.clone(),
            measurement: measurement.clone(),
        },
    });
    let event_dependencies: Vec<_> = BTreeSet::from([payload.clone(), measurement.clone()])
        .into_iter()
        .collect();
    for object in bodies.keys() {
        let dependencies = if object == &delivered_ref || object == &published_ref {
            event_dependencies.clone()
        } else if object == &observation_ref {
            vec![measurement.clone()]
        } else if object == &stop_ref {
            BTreeSet::from([measurement.clone(), observation_ref.clone()])
                .into_iter()
                .collect()
        } else {
            Vec::new()
        };
        inventory.dependencies.push(InputLineageRow {
            object: object.clone(),
            dependencies,
        });
    }
    batch.events.push(delivered);
    OriginalBodies {
        inventory,
        batch,
        bodies,
        stop,
    }
}

#[test]
fn original_event_observation_stop_and_control_scope_are_paired_exactly() {
    // This is a body-codec fixture, not a native source enrollment or consumption proof.
    let original = original_bodies();
    original
        .inventory
        .validate_bodies(&original.batch, 1.into(), |object| {
            Ok(original.bodies.get(object).unwrap())
        })
        .unwrap();

    for variant in 0..5 {
        let mut changed = original.inventory.clone();
        let producer = &mut changed.entries[0].producer;
        match variant {
            0 => producer.session_id = id("foreign/session"),
            1 => producer.activation_id = id("foreign/activation"),
            2 => producer.world_generation = 2.into(),
            3 => producer.incarnation_id = id("foreign/incarnation"),
            _ => producer.execution_owner_id = id("foreign/owner"),
        }
        assert!(
            changed
                .validate_bodies(&original.batch, 1.into(), |object| {
                    Ok(original.bodies.get(object).unwrap())
                })
                .is_err()
        );
    }
}

#[test]
fn original_event_rows_cannot_omit_payload_or_invent_an_empty_leaf() {
    let mut original = original_bodies();
    let delivered = original.inventory.entries[0].delivered.clone();
    let row = original
        .inventory
        .dependencies
        .iter_mut()
        .find(|row| row.object == delivered)
        .unwrap();
    row.dependencies.clear();
    assert!(
        original
            .inventory
            .validate_bodies(&original.batch, 1.into(), |object| {
                Ok(original.bodies.get(object).unwrap())
            })
            .is_err()
    );
}

#[test]
fn internally_valid_foreign_stop_cannot_replace_original_world_or_activation() {
    let mut original = original_bodies();
    original.stop.activation_id = id("foreign/activation");
    original.stop.validate().unwrap();
    let prior = original.inventory.entries[0].producer.stop_receipt.clone();
    let changed = stored_json(&original.stop, &mut original.bodies);
    original.inventory.entries[0].producer.stop_receipt = changed.clone();
    original
        .inventory
        .dependencies
        .iter_mut()
        .find(|row| row.object == prior)
        .unwrap()
        .object = changed;
    original
        .inventory
        .dependencies
        .sort_by(|a, b| a.object.cmp(&b.object));
    assert!(
        original
            .inventory
            .validate_bodies(&original.batch, 1.into(), |object| {
                Ok(original.bodies.get(object).unwrap())
            })
            .is_err()
    );
}
