//! Exact original public batch associations; fixtures do not qualify a provider.

// crucible-lint: allow panic-shortcut -- A mismatch invalidates the retained original batch fixture.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use crucible_node_contract::{Endpoint, EventStage, Id, Phase, Position, U64};

use super::*;
use crate::reference_lineage::{LineageCustodyQueue, tests::stage};

fn batch() -> InputBatch {
    let original = stage(0, &[b"same", b"", b"same"]);
    InputBatch {
        schema_version: 1,
        execution_owner_id: original.grant.owner_id,
        input_epoch: Id::new("original-input-epoch").unwrap(),
        batch_id: original.grant.input_batch_id,
        batch_sequence: U64::new(0),
        events: original
            .entries
            .iter()
            .enumerate()
            .map(|(index, entry)| Event {
                schema_version: 1,
                // Different producers may legitimately use the same local ID.
                id: Id::new("checksum-0").unwrap(),
                source: Endpoint {
                    node_id: Id::new(format!("producer-{index}")).unwrap(),
                    port_id: Id::new("out").unwrap(),
                    lane_id: Id::new("bytes").unwrap(),
                },
                destination: Endpoint {
                    node_id: Id::new("consumer").unwrap(),
                    port_id: Id::new("in").unwrap(),
                    lane_id: Id::new("bytes").unwrap(),
                },
                position: Position {
                    time_ps: U64::new(2),
                    microstep: U64::new(0),
                    phase: Phase::Delivery,
                },
                stage: EventStage::Delivery,
                publication_position: Position {
                    time_ps: U64::new(1),
                    microstep: U64::new(0),
                    phase: Phase::Publication,
                },
                delivery_position: Some(Position {
                    time_ps: U64::new(2),
                    microstep: U64::new(0),
                    phase: Phase::Delivery,
                }),
                source_sequence: U64::new(0),
                causal_parent_ids: vec![],
                payload: entry.payload.clone(),
                provenance_ref: canonical::content_ref(
                    format!("original producer proof {index}").as_bytes(),
                    "application/json",
                )
                .unwrap(),
                extensions: Default::default(),
            })
            .collect(),
        extensions: Default::default(),
    }
}

fn bytes(batch: &InputBatch) -> Vec<u8> {
    canonical::canonical_json(&serde_json::to_value(batch).unwrap()).unwrap()
}

#[test]
fn original_payload_roles_and_batch_scope_are_exact() {
    let original = batch();
    let staged = stage(0, &[b"same", b"", b"same"]);
    validate_original_batch(&original, &staged).unwrap();

    let mut changed = original.clone();
    changed.events[0].payload.media_type = "application/json".into();
    assert!(validate_original_batch(&changed, &staged).is_err());
    assert_eq!(
        changed.events[0].payload.hash,
        original.events[0].payload.hash
    );

    let mut changed = original.clone();
    changed.execution_owner_id = Id::new("other-owner").unwrap();
    assert!(validate_original_batch(&changed, &staged).is_err());
    let mut changed = original.clone();
    changed.batch_id = Id::new("other-batch").unwrap();
    assert!(validate_original_batch(&changed, &staged).is_err());
}

#[test]
fn input_builder_retains_ordered_empty_entries_and_refuses_before_execution() {
    let original = batch();
    let raw = bytes(&original);
    let reference = canonical::content_ref(&raw, "application/json").unwrap();
    let grant = stage(0, &[]).grant;
    let stage = crate::reference_lineage::LineageStage::from_input_batch(
        grant.clone(),
        reference.clone(),
        &raw,
        &[b"same", b"", b"same"],
    )
    .unwrap();
    assert_eq!(stage.input, b"samesame");
    assert_eq!(stage.entries.len(), 3);
    assert_eq!(stage.entries[1].byte_start, stage.entries[1].byte_end);
    assert_eq!(stage.entries[1].event_index.get(), 1);
    assert_eq!(stage.original_batch, reference);

    for payloads in [
        vec![b"same".as_slice()],
        vec![b"same".as_slice(), b"same", b""],
        vec![b"other".as_slice(), b"", b"same"],
    ] {
        assert!(
            crate::reference_lineage::LineageStage::from_input_batch(
                grant.clone(),
                reference.clone(),
                &raw,
                &payloads,
            )
            .is_err()
        );
    }
    let mut changed = grant;
    changed.input_batch_id = Id::new("replacement-batch").unwrap();
    assert!(
        crate::reference_lineage::LineageStage::from_input_batch(
            changed,
            reference,
            &raw,
            &[b"same", b"", b"same"],
        )
        .is_err()
    );
}

#[test]
fn source_relation_credit_binds_exact_original_input_before_native_effects() {
    let original = batch();
    let raw = bytes(&original);
    let staged = crate::reference_lineage::LineageStage::from_input_batch(
        stage(0, &[]).grant,
        canonical::content_ref(&raw, "application/json").unwrap(),
        &raw,
        &[b"same", b"", b"same"],
    )
    .unwrap();
    crate::reference_lineage::ConsumptionRelationCredit::reserve(&staged, &raw).unwrap();

    let mut changed = original.clone();
    changed.events.swap(0, 2);
    assert!(
        crate::reference_lineage::ConsumptionRelationCredit::reserve(&staged, &bytes(&changed),)
            .is_err()
    );
    let mut noncanonical = raw.clone();
    noncanonical.push(b' ');
    assert!(
        crate::reference_lineage::ConsumptionRelationCredit::reserve(&staged, &noncanonical,)
            .is_err()
    );
    assert!(
        crate::reference_lineage::ConsumptionRelationCredit::reserve(
            &staged,
            &vec![0; MAX_FRAME_BYTES + 1],
        )
        .is_err()
    );
}

#[test]
#[ignore = "requires the source-built distinct CRUCIBLE_REFERENCE_LINEAGE_DEVICE"]
fn actual_native_batch_association_retains_scoped_equal_ids_and_zero_entries() {
    static SEQUENCE: AtomicU64 = AtomicU64::new(1);
    let root = std::env::temp_dir().join(format!(
        "native-lineage-association-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let queue = LineageCustodyQueue::new().unwrap();
    let mut staged = stage(0, &[b"same", b"", b"same"]);
    let original = batch();
    let raw = bytes(&original);
    staged = crate::reference_lineage::LineageStage::from_input_batch(
        staged.grant,
        canonical::content_ref(&raw, "application/json").unwrap(),
        &raw,
        &[b"same", b"", b"same"],
    )
    .unwrap();
    let mut native = NativeLineageDevice::spawn(
        Path::new(&std::env::var_os("CRUCIBLE_REFERENCE_LINEAGE_DEVICE").unwrap()),
        &root,
        staged.grant.owner_id.clone(),
        staged.grant.incarnation_id.clone(),
        staged.grant.generation,
        Duration::from_secs(2),
        queue,
    )
    .unwrap();
    let relation_credit =
        crate::reference_lineage::ConsumptionRelationCredit::reserve(&staged, &raw).unwrap();
    let mut other_stage = staged.clone();
    other_stage.grant.window_id = Id::new("other-original-window").unwrap();
    let wrong_relation_credit =
        crate::reference_lineage::ConsumptionRelationCredit::reserve(&other_stage, &raw).unwrap();
    native.stage(staged.clone()).unwrap();
    native.activate().unwrap();

    // A parsed or locally recomputed receipt has no accepted native Close yet.
    let mut model =
        crate::reference_lineage::execution::NativeWindow::prepare(staged.clone(), 0, None)
            .unwrap();
    model.activate(&mut 0).unwrap();
    assert!(
        native
            .associate_consumption(&model.close().unwrap(), &raw)
            .is_err()
    );
    let closed = native.close().unwrap();
    let command_count = native.commands().len();
    let association = native.associate_consumption(&closed, &raw).unwrap();
    assert_ne!(association.origin().child_pid(), 0);
    assert_ne!(association.origin().start_ticks().get(), 0);
    assert_eq!(association.origin().owner(), &staged.grant.owner_id);
    assert_eq!(
        association.origin().incarnation(),
        &staged.grant.incarnation_id
    );
    assert_eq!(association.origin().generation(), staged.grant.generation);
    assert_eq!(
        association.origin().initialization().knowledge(),
        NativeCommandKnowledge::Accepted
    );
    let original_pid = association.origin().child_pid();
    let original_start = association.origin().start_ticks();
    assert_eq!(association.original_bytes(), raw);
    assert_eq!(association.original(), &original);
    assert_eq!(association.complete_prefix().get(), 3);
    assert_eq!(association.zero_byte_consumed(0), Some(false));
    assert_eq!(association.zero_byte_consumed(1), Some(true));
    assert_eq!(association.zero_byte_consumed(3), None);
    assert_eq!(
        association.event(0).unwrap().id,
        association.event(2).unwrap().id
    );
    assert_ne!(
        association.event(0).unwrap().source,
        association.event(2).unwrap().source,
    );
    assert_eq!(association.receipt(), &closed);
    assert!(association.predecessor().is_none());
    assert!(!association.window().acknowledged());
    assert_eq!(
        association.close_command().knowledge(),
        NativeCommandKnowledge::Accepted
    );
    let wire = association.close_command().response_wire_bytes();
    assert_eq!(
        u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize,
        wire.len() - 4
    );
    assert!(
        crate::reference_lineage::NativeConsumptionRelation::collect(
            &association,
            wrong_relation_credit,
        )
        .is_err()
    );
    assert_eq!(native.commands().len(), command_count);
    assert!(!native.windows()[0].acknowledged());
    let relation =
        crate::reference_lineage::NativeConsumptionRelation::collect(&association, relation_credit)
            .unwrap();
    let relation_body = relation
        .evidence()
        .iter()
        .find(|object| object.reference() == relation.reference())
        .unwrap();
    let record = canonical::parse_json(relation_body.bytes(), MAX_FRAME_BYTES).unwrap();
    assert_eq!(record["complete_consumed_prefix"], "3");
    assert_eq!(record["entries"][1]["zero_byte_consumed"], true);
    assert_eq!(
        record["entries"][0]["event_id"],
        record["entries"][2]["event_id"]
    );
    assert_ne!(
        record["entries"][0]["producer"],
        record["entries"][2]["producer"]
    );
    let original_body = relation
        .evidence()
        .iter()
        .find(|object| object.reference() == &staged.original_batch)
        .unwrap();
    assert_eq!(original_body.bytes(), raw);
    for field in ["initialize_response_wire", "close_response_wire"] {
        let reference: ContentRef = serde_json::from_value(record[field].clone()).unwrap();
        let object = relation
            .evidence()
            .iter()
            .find(|object| object.reference() == &reference)
            .unwrap();
        let wire = object.bytes();
        assert_eq!(
            u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize,
            wire.len() - 4
        );
        reference.verify(wire).unwrap();
    }
    assert_eq!(native.commands().len(), command_count);
    assert!(!native.windows()[0].acknowledged());

    for changed in [
        {
            let mut changed = original.clone();
            changed.events.swap(0, 2);
            changed
        },
        {
            let mut changed = original.clone();
            changed.events[0].id = Id::new("replaced-original-id").unwrap();
            changed
        },
        {
            let mut changed = original.clone();
            changed.events[0].source.node_id = Id::new("foreign-producer").unwrap();
            changed
        },
    ] {
        assert!(
            native
                .associate_consumption(&closed, &bytes(&changed))
                .is_err()
        );
        assert_eq!(native.commands().len(), command_count);
        assert!(!native.windows()[0].acknowledged());
        assert_eq!(native.windows()[0].closure(), Some(&closed));
    }
    native.acknowledge_publication(&closed).unwrap();

    let mut next_stage = stage(1, &[b""]);
    let mut next_batch = original.clone();
    next_batch.batch_id = next_stage.grant.input_batch_id.clone();
    next_batch.batch_sequence = U64::new(1);
    next_batch.events = vec![original.events[1].clone()];
    let next_raw = bytes(&next_batch);
    next_stage.original_batch = canonical::content_ref(&next_raw, "application/json").unwrap();
    native.stage(next_stage).unwrap();
    native.activate().unwrap();
    let next_closed = native.close().unwrap();
    let next_association = native
        .associate_consumption(&next_closed, &next_raw)
        .unwrap();
    assert_eq!(next_association.complete_prefix().get(), 1);
    assert_eq!(next_association.zero_byte_consumed(0), Some(true));
    assert_eq!(
        next_association.predecessor().unwrap().closure(),
        Some(&closed)
    );
    assert!(next_association.predecessor().unwrap().acknowledged());
    assert_eq!(
        next_closed.previous_closed,
        Some(closed.identity().unwrap())
    );
    native.acknowledge_publication(&next_closed).unwrap();

    let deadline =
        crate::operational_time::OperationalDeadline::after(Duration::from_secs(5)).unwrap();
    while !native.poll_quarantine().unwrap() {
        assert!(!deadline.is_expired());
        std::thread::sleep(Duration::from_millis(1));
    }
    let association = native.associate_consumption(&closed, &raw).unwrap();
    assert_eq!(association.origin().child_pid(), original_pid);
    assert_eq!(association.origin().start_ticks(), original_start);
    assert!(association.window().acknowledged());
    assert_eq!(association.receipt(), &closed);
    fs::remove_dir_all(root).unwrap();
}
