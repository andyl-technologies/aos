//! Adversarial causal, reservation, equality and publication regression tests.

// crucible-lint: allow panic-shortcut -- These node scheduling tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::node_contract::{
    ActivationRecord, OwnerIdentity, PhysicalState, QuantumClosureEvidence,
};
use crate::node_scheduling::SavedPermission;
use crate::node_scheduling::event::{ProducerSequences, direct_delivery, reaction_publication};
use crucible_node_contract::{ContentRef, EventKey, HashRef};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn reference() -> ContentRef {
    ContentRef {
        hash: HashRef {
            algorithm: "blake3-256".into(),
            domain: "cnp.blob.v1".into(),
            digest: "0".repeat(64),
        },
        length: U64::new(0),
        media_type: "application/octet-stream".into(),
    }
}

fn position(time: u64, microstep: u64, phase: Phase) -> Position {
    Position::new(U64::new(time), U64::new(microstep), phase)
}

fn exact(ceiling: ExactCeiling) -> ExecutionPolicy {
    ExecutionPolicy::Exact {
        schema_version: 1,
        execution_proof_ref: reference(),
        ceiling,
        boundary_settlement_ref: Some(reference()),
    }
}

fn fixture(policy: ExecutionPolicy, resolution: u64, latency: Option<u64>) -> CausalScheduler {
    let activation = WorldActivation {
        nodes: std::rc::Rc::from([]),
        preparation: None,
        authority: Rc::new(()),
        record: ActivationRecord {
            generation: U64::new(1),
            activation_id: id("activation/1"),
            world_binding_hash: HashRef {
                algorithm: "blake3-256".into(),
                domain: "cnp.world-binding.v1".into(),
                digest: "1".repeat(64),
            },
            owners: vec![
                OwnerIdentity {
                    owner: id("owner/A"),
                    incarnation: id("incarnation/A"),
                    generation: U64::new(1),
                },
                OwnerIdentity {
                    owner: id("owner/Z"),
                    incarnation: id("incarnation/Z"),
                    generation: U64::new(1),
                },
            ],
            boundary: position(0, 0, Phase::BoundaryControl),
        },
    };
    let grid = QuantumGrid::new(U64::new(resolution), U64::new(0)).unwrap();
    let inputs = latency
        .map(|latency| {
            vec![InputPath {
                producer: id("Z"),
                latency_ps: U64::new(latency),
                external: false,
                external_endpoint: None,
            }]
        })
        .unwrap_or_default();
    let mut sequences = ProducerSequences::default();
    sequences.restore_next(id("A"), Some(U64::new(0)));
    sequences.restore_next(id("Z"), Some(U64::new(0)));
    CausalScheduler {
        activation: activation.clone(),
        node_routes: activation
            .record()
            .owners
            .iter()
            .map(|identity| {
                (
                    if identity.owner == id("owner/A") {
                        id("A")
                    } else {
                        id("Z")
                    },
                    vec![identity.clone()],
                )
            })
            .collect(),
        input_batches: BTreeMap::new(),
        used_input_batches: BTreeSet::new(),
        node_owners: BTreeMap::from([(id("A"), id("owner/A")), (id("Z"), id("owner/Z"))]),
        owners: BTreeMap::from([
            (
                id("owner/A"),
                OwnerSchedule {
                    grid,
                    policy: policy.clone(),
                    cursor: position(0, 0, Phase::BoundaryControl),
                    inputs,
                    reserved: None,
                },
            ),
            (
                id("owner/Z"),
                OwnerSchedule {
                    grid,
                    policy,
                    cursor: position(0, 0, Phase::BoundaryControl),
                    inputs: Vec::new(),
                    reserved: None,
                },
            ),
        ]),
        bounds: BTreeMap::from([
            (id("A"), OutputBound::Unknown),
            (id("Z"), OutputBound::Unknown),
        ]),
        pending: BTreeMap::new(),
        operations: BTreeMap::new(),
        used_operations: BTreeSet::new(),
        sequences,
        routing: BTreeMap::new(),
        output_endpoints: BTreeMap::new(),
        external_roots: BTreeMap::new(),
        external_closed_prefixes: BTreeMap::new(),
        closed_prefixes: BTreeMap::from([
            (id("A"), position(0, 0, Phase::BoundaryControl)),
            (id("Z"), position(0, 0, Phase::BoundaryControl)),
        ]),
        native_sequences: BTreeMap::new(),
        payloads: BTreeMap::new(),
        maximum_pending_payload_bytes: U64::new(1_048_576),
        maximum_microsteps: U64::new(4),
    }
}

fn observe(scheduler: &mut CausalScheduler, bound: OutputBound) {
    let activation = scheduler.activation.clone();
    scheduler
        .observe_bound(&activation, &id("Z"), bound)
        .unwrap();
}

fn exact_receipt(
    scheduler: &CausalScheduler,
    grant: &ExecutionAdmission,
    reached: Position,
    stop: StopReason,
) -> SchedulingReceipt {
    SchedulingReceipt::new(
        scheduler.activation.clone(),
        grant.node().clone(),
        grant.operation().clone(),
        ProgressEvidence::Exact { reached, stop },
        Vec::new(),
        None,
    )
}

#[test]
fn empty_queue_does_not_prove_future_input_absence() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 50, Some(1000));

    assert!(matches!(
        scheduler.admit_exact(&id("A"), id("run/1"), U64::new(10_000)),
        Err(SchedulingError::InputBlocked(_))
    ));
    assert!(scheduler.operations.is_empty());
    assert!(scheduler.used_operations.is_empty());
}

#[test]
fn faster_consumer_cannot_outrun_slow_producer() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 50, Some(1000));
    observe(
        &mut scheduler,
        OutputBound::At(position(0, 0, Phase::Publication)),
    );

    let grant = scheduler
        .admit_exact(&id("A"), id("run/1"), U64::new(10_000))
        .unwrap();

    assert_eq!(grant.limit(), position(950, 0, Phase::BoundaryControl));
}

#[test]
fn incommensurate_arrival_uses_strict_predecessor() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 100, Some(200));
    observe(
        &mut scheduler,
        OutputBound::At(position(1050, 0, Phase::Publication)),
    );

    let grant = scheduler
        .admit_exact(&id("A"), id("run/1"), U64::new(10_000))
        .unwrap();

    assert_eq!(grant.limit().time_ps, U64::new(1200));
}

#[test]
fn qualified_input_park_excludes_every_position_at_arrival() {
    let mut scheduler = fixture(
        exact(ExactCeiling::InputBlocked {
            proof_ref: reference(),
        }),
        50,
        Some(200),
    );
    observe(
        &mut scheduler,
        OutputBound::At(position(1050, 3, Phase::Publication)),
    );

    let grant = scheduler
        .admit_exact(&id("A"), id("run/1"), U64::new(10_000))
        .unwrap();

    assert_eq!(grant.limit(), position(1250, 0, Phase::BoundaryControl));
    assert!(position(1250, 0, Phase::Reaction) > grant.limit());
}

#[test]
fn arithmetic_failure_does_not_consume_operation_or_owner() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, Some(10));
    observe(
        &mut scheduler,
        OutputBound::At(position(u64::MAX, 0, Phase::Publication)),
    );

    assert!(matches!(
        scheduler.admit_exact(&id("A"), id("run/1"), U64::new(100)),
        Err(SchedulingError::Contract(_))
    ));
    assert!(scheduler.used_operations.is_empty());
    assert_eq!(scheduler.owners[&id("owner/A")].reserved, None);
}

#[test]
fn source_bound_cannot_regress_after_authorizing_consumers() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, Some(10));
    observe(&mut scheduler, OutputBound::AfterInstant(U64::new(100)));
    let activation = scheduler.activation.clone();

    assert!(matches!(
        scheduler.observe_bound(
            &activation,
            &id("Z"),
            OutputBound::At(position(100, 3, Phase::Publication))
        ),
        Err(SchedulingError::CausalRegression)
    ));
    assert_eq!(
        scheduler.bounds[&id("Z")],
        OutputBound::AfterInstant(U64::new(100))
    );
}

#[test]
fn shared_owner_facets_cannot_get_concurrent_grants() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 50, None);
    scheduler.node_owners.insert(id("A/irq"), id("owner/A"));
    let grant = scheduler
        .admit_exact(&id("A"), id("run/1"), U64::new(100))
        .unwrap();
    drop(grant);

    assert!(matches!(
        scheduler.admit_exact(&id("A/irq"), id("run/2"), U64::new(100)),
        Err(SchedulingError::OwnerBusy)
    ));
}

#[test]
fn input_exposed_by_another_facet_constrains_the_whole_owner() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 50, None);
    scheduler.node_owners.insert(id("A/irq"), id("owner/A"));
    scheduler
        .add_path(&id("Z"), &id("A/irq"), U64::new(1000), false)
        .unwrap();

    assert!(matches!(
        scheduler.admit_exact(&id("A"), id("run/1"), U64::new(10_000)),
        Err(SchedulingError::InputBlocked(_))
    ));
    observe(
        &mut scheduler,
        OutputBound::At(position(0, 0, Phase::Publication)),
    );
    assert_eq!(
        scheduler
            .admit_exact(&id("A"), id("run/1"), U64::new(10_000))
            .unwrap()
            .limit()
            .time_ps,
        U64::new(950)
    );
}

#[test]
fn native_input_park_permission_is_not_inferred_for_an_earlier_horizon() {
    let mut scheduler = fixture(
        exact(ExactCeiling::InputBlocked {
            proof_ref: reference(),
        }),
        50,
        Some(1000),
    );
    observe(
        &mut scheduler,
        OutputBound::At(position(0, 0, Phase::Publication)),
    );
    let grant = scheduler
        .admit_exact(&id("A"), id("run/1"), U64::new(500))
        .unwrap();

    assert!(matches!(
        grant.request(),
        OperationRequest::ExactRun {
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
            ..
        }
    ));
    let receipt = exact_receipt(&scheduler, &grant, grant.limit(), StopReason::InputBlocked);
    assert!(matches!(
        scheduler.accept_receipt(receipt),
        Err(SchedulingError::InvalidReceipt)
    ));
}

#[test]
fn abandoning_unique_undispatched_grant_keeps_identity_used() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 50, None);
    let grant = scheduler
        .admit_exact(&id("A"), id("run/1"), U64::new(100))
        .unwrap();
    scheduler.abandon_undispatched(grant).unwrap();

    assert!(matches!(
        scheduler.admit_exact(&id("A"), id("run/1"), U64::new(200)),
        Err(SchedulingError::DuplicateOperation)
    ));
    assert!(
        scheduler
            .admit_exact(&id("A"), id("run/2"), U64::new(100))
            .is_ok()
    );
}

#[test]
fn overrun_and_unclassified_receipts_retain_owner() {
    for (reached, stop) in [
        (
            position(101, 0, Phase::BoundaryControl),
            StopReason::HorizonPark,
        ),
        (position(100, 0, Phase::BoundaryControl), StopReason::Output),
        (
            position(50, 0, Phase::BoundaryControl),
            StopReason::Unclassified,
        ),
    ] {
        let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, None);
        let grant = scheduler
            .admit_exact(&id("A"), id("run/1"), U64::new(100))
            .unwrap();
        let receipt = exact_receipt(&scheduler, &grant, reached, stop);

        assert!(matches!(
            scheduler.accept_receipt(receipt),
            Err(SchedulingError::InvalidReceipt)
        ));
        assert_eq!(
            scheduler.position(&id("A")).unwrap(),
            position(0, 0, Phase::BoundaryControl)
        );
        assert!(scheduler.owners[&id("owner/A")].reserved.is_some());
    }
}

#[test]
fn authentic_horizon_completion_updates_all_owner_facets() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, None);
    scheduler.node_owners.insert(id("A/irq"), id("owner/A"));
    let grant = scheduler
        .admit_exact(&id("A"), id("run/1"), U64::new(100))
        .unwrap();
    let receipt = exact_receipt(&scheduler, &grant, grant.limit(), StopReason::HorizonPark);
    scheduler.accept_receipt(receipt).unwrap();

    assert_eq!(scheduler.position(&id("A/irq")).unwrap(), grant.limit());
    assert_eq!(scheduler.owners[&id("owner/A")].reserved, None);
}

#[test]
fn same_record_with_foreign_local_authority_is_refused() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, None);
    let grant = scheduler
        .admit_exact(&id("A"), id("run/1"), U64::new(100))
        .unwrap();
    let mut receipt = exact_receipt(&scheduler, &grant, grant.limit(), StopReason::HorizonPark);
    receipt.activation.authority = Rc::new(());

    assert!(matches!(
        scheduler.accept_receipt(receipt),
        Err(SchedulingError::ForeignActivation)
    ));
    assert!(scheduler.owners[&id("owner/A")].reserved.is_some());
}

#[test]
fn id_only_outputs_never_publish_or_release_reservation() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, None);
    let grant = scheduler
        .admit_exact(&id("A"), id("run/1"), U64::new(100))
        .unwrap();
    let mut receipt = exact_receipt(
        &scheduler,
        &grant,
        position(50, 0, Phase::Reaction),
        StopReason::Output,
    );
    receipt.retained_outputs.push(id("output/1"));

    assert!(matches!(
        scheduler.accept_receipt(receipt),
        Err(SchedulingError::MissingOutputCoordinates)
    ));
    assert!(scheduler.owners[&id("owner/A")].reserved.is_some());
    assert!(scheduler.pending.is_empty());
}

#[test]
fn settlement_does_not_turn_into_physical_time_execution() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, None);

    assert!(matches!(
        scheduler.admit_boundary_settlement(
            &id("A"),
            id("settle/1"),
            position(1, 0, Phase::Reaction)
        ),
        Err(SchedulingError::NoSafeProgress)
    ));
    assert!(matches!(
        scheduler.admit_boundary_settlement(
            &id("A"),
            id("settle/1"),
            position(0, 4, Phase::Reaction)
        ),
        Err(SchedulingError::SameTimeNonconvergence)
    ));
    assert!(scheduler.used_operations.is_empty());
}

#[test]
fn unresolved_same_microstep_delivery_blocks_reaction() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, Some(0));
    observe(
        &mut scheduler,
        OutputBound::At(position(0, 0, Phase::Publication)),
    );

    assert!(matches!(
        scheduler.admit_boundary_settlement(
            &id("A"),
            id("settle/1"),
            position(0, 0, Phase::Reaction)
        ),
        Err(SchedulingError::InputBlocked(_))
    ));
    let grant = scheduler
        .admit_boundary_settlement(&id("A"), id("settle/1"), position(0, 0, Phase::Delivery))
        .unwrap();
    assert!(matches!(
        grant.request(),
        OperationRequest::BoundarySettle { .. }
    ));
}

fn quantum() -> ExecutionPolicy {
    ExecutionPolicy::Quantized {
        schema_version: 1,
        quantum_ps: U64::new(100),
        phase_ps: U64::new(0),
        host_budget_ns: U64::new(1000),
        window_proof_ref: reference(),
    }
}

#[test]
fn same_boundary_microstep_output_blocks_quantum_start() {
    let mut scheduler = fixture(quantum(), 100, Some(0));
    observe(
        &mut scheduler,
        OutputBound::At(position(0, 3, Phase::Publication)),
    );

    assert!(matches!(
        scheduler.admit_quantum(&id("A"), id("run/1"), id("window/1"), id("batch/1")),
        Err(SchedulingError::InputBlocked(_))
    ));
}

#[test]
fn closing_one_quantum_does_not_close_next_input_batch() {
    let mut scheduler = fixture(quantum(), 100, Some(0));
    observe(&mut scheduler, OutputBound::AfterInstant(U64::new(0)));
    stage_empty_quantum(&mut scheduler, "batch/1");
    let grant = scheduler
        .admit_quantum(&id("A"), id("run/1"), id("window/1"), id("batch/1"))
        .unwrap();
    let receipt = SchedulingReceipt::new(
        scheduler.activation.clone(),
        id("A"),
        id("run/1"),
        ProgressEvidence::Quantized {
            window: id("window/1"),
            publication: grant.limit(),
            physical: PhysicalState::Suspended,
            closure: Box::new(QuantumClosureEvidence {
                input_batch: id("batch/1"),
                close_receipt: reference(),
                output_inventory: reference(),
                pending_inventory: reference(),
                clock_evidence: reference(),
            }),
        },
        Vec::new(),
        Some(empty_quantum_observation(
            &scheduler,
            "batch/1",
            position(100, 0, Phase::BoundaryControl),
        )),
    );
    scheduler.accept_receipt(receipt).unwrap();

    assert_eq!(scheduler.position(&id("A")).unwrap().time_ps, U64::new(100));
    assert!(matches!(
        scheduler.admit_quantum(&id("A"), id("run/2"), id("window/2"), id("batch/2")),
        Err(SchedulingError::InputBlocked(_))
    ));
}

#[test]
fn reverse_lexical_reaction_follows_its_parent() {
    let cause = position(100, 0, Phase::Delivery);
    let evaluation = position(100, 0, Phase::Reaction);
    let publication =
        reaction_publication(&[cause], evaluation, U64::new(100), U64::new(4)).unwrap();
    let delivery = direct_delivery(publication, U64::new(0), None).unwrap();
    let cause_key = EventKey {
        position: cause,
        consumer_node_id: id("B"),
        producer_node_id: id("Z"),
        source_sequence: U64::new(0),
    };
    let effect_key = EventKey {
        position: delivery,
        consumer_node_id: id("A"),
        producer_node_id: id("B"),
        source_sequence: U64::new(0),
    };

    assert!(effect_key > cause_key);
    assert_eq!(publication.microstep, U64::new(1));
    assert_eq!(delivery.microstep, publication.microstep);
}

#[test]
fn native_alarm_and_feedback_obey_finite_microstep_closure() {
    let alarm = position(200, 0, Phase::Reaction);
    let first = reaction_publication(&[], alarm, U64::new(200), U64::new(4)).unwrap();
    assert_eq!(first, position(200, 1, Phase::Publication));

    let mut reaction = alarm;
    for microstep in 1..4 {
        let output = reaction_publication(&[], reaction, U64::new(200), U64::new(4)).unwrap();
        assert_eq!(output.microstep, U64::new(microstep));
        reaction = Position {
            phase: Phase::Reaction,
            ..output
        };
    }
    assert!(matches!(
        reaction_publication(&[], reaction, U64::new(200), U64::new(4)),
        Err(SchedulingError::SameTimeNonconvergence)
    ));
}

#[test]
fn grid_sampling_preserves_same_time_causal_membership() {
    let grid = QuantumGrid::new(U64::new(100), U64::new(0)).unwrap();
    let publication = position(100, 2, Phase::Publication);

    assert_eq!(
        direct_delivery(publication, U64::new(0), Some(grid)).unwrap(),
        position(100, 2, Phase::Delivery)
    );
    assert_eq!(
        direct_delivery(publication, U64::new(1), Some(grid)).unwrap(),
        position(200, 0, Phase::Delivery)
    );
}

#[test]
fn final_sequence_survives_capture_and_never_wraps() {
    let mut sequences: ProducerSequences =
        serde_json::from_str("{\"Z\":\"18446744073709551615\"}").unwrap();
    assert_eq!(sequences.allocate(&id("Z")).unwrap(), U64::new(u64::MAX));
    let saved = serde_json::to_vec(&sequences).unwrap();
    let mut restored: ProducerSequences = serde_json::from_slice(&saved).unwrap();

    assert!(matches!(
        restored.allocate(&id("Z")),
        Err(SchedulingError::SequenceExhausted)
    ));
}

#[test]
fn fanout_sequence_exhaustion_is_atomic() {
    let mut sequences: ProducerSequences =
        serde_json::from_str("{\"Z\":\"18446744073709551615\"}").unwrap();
    let before = sequences.clone();

    assert!(matches!(
        sequences.allocate_fanout(&id("Z"), 2),
        Err(SchedulingError::SequenceExhausted)
    ));
    assert_eq!(sequences, before);
    assert_eq!(
        sequences.allocate_fanout(&id("Z"), 1).unwrap(),
        vec![U64::new(u64::MAX)]
    );
}

#[test]
fn explicit_nullable_policy_field_cannot_be_omitted() {
    let mut value = serde_json::to_value(exact(ExactCeiling::StrictPredecessor)).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("boundary_settlement_ref");

    assert!(serde_json::from_value::<ExecutionPolicy>(value).is_err());
}

#[test]
fn snapshot_retains_phase_bounds_sequences_and_used_operations() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, None);
    let grant = scheduler
        .admit_boundary_settlement(&id("A"), id("settle/1"), position(0, 1, Phase::Reaction))
        .unwrap();
    let receipt = exact_receipt(&scheduler, &grant, grant.limit(), StopReason::HorizonPark);
    scheduler.accept_receipt(receipt).unwrap();
    observe(&mut scheduler, OutputBound::AfterInstant(U64::new(0)));
    scheduler.sequences.restore_next(id("A"), None);
    let snapshot = scheduler
        .snapshot(position(0, 1, Phase::Reaction), U64::new(9))
        .unwrap();
    let encoded = serde_json::to_vec(&snapshot).unwrap();
    let decoded = serde_json::from_slice(&encoded).unwrap();
    super::snapshot_impl::validate_structure(&decoded).unwrap();
    let mut reconstructed = fixture(exact(ExactCeiling::StrictPredecessor), 1, None);
    reconstructed.load_snapshot(decoded).unwrap();

    assert_eq!(
        reconstructed.position(&id("A")).unwrap(),
        position(0, 1, Phase::Reaction)
    );
    assert_eq!(
        reconstructed.bounds[&id("Z")],
        OutputBound::AfterInstant(U64::new(0))
    );
    assert_eq!(reconstructed.sequences.next(&id("A")), None);
    assert!(matches!(
        reconstructed.admit_exact(&id("A"), id("settle/1"), U64::new(100)),
        Err(SchedulingError::DuplicateOperation)
    ));
    assert_eq!(snapshot.capture_ordinal, U64::new(9));
}

#[test]
fn snapshot_preserves_unresolved_original_quantum_without_relabeling_it_closed() {
    let mut scheduler = fixture(quantum(), 100, None);
    stage_empty_quantum(&mut scheduler, "batch/1");
    let grant = scheduler
        .admit_quantum(&id("A"), id("run/1"), id("window/1"), id("batch/1"))
        .unwrap();
    let snapshot = scheduler
        .snapshot(position(0, 0, Phase::BoundaryControl), U64::new(1))
        .unwrap();

    assert_eq!(snapshot.reservations.len(), 1);
    assert_eq!(snapshot.reservations[0].operation, *grant.operation());
    assert!(
        matches!(&snapshot.reservations[0].permission, crate::node_scheduling::SavedPermission::Quantum { window, start, end, input_batch, .. }
        if window == &id("window/1") && start == &grant.start() && end == &grant.limit() && input_batch == &id("batch/1"))
    );
    assert_eq!(snapshot.positions[0].position, grant.start());
}

#[test]
fn snapshot_rejects_legacy_order_omitted_sequence_and_duplicate_roster() {
    let scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, None);
    let mut snapshot = scheduler
        .snapshot(position(0, 0, Phase::BoundaryControl), U64::new(1))
        .unwrap();
    snapshot.ordering_profile = "legacy-positive-latency".into();
    assert!(matches!(
        super::snapshot_impl::validate_structure(&snapshot),
        Err(SchedulingError::InvalidSnapshot)
    ));
    snapshot.ordering_profile = "superdense-v1".into();
    snapshot
        .source_owners
        .push(snapshot.source_owners[0].clone());
    assert!(matches!(
        super::snapshot_impl::validate_structure(&snapshot),
        Err(SchedulingError::InvalidSnapshot)
    ));

    let snapshot = scheduler
        .snapshot(position(0, 0, Phase::BoundaryControl), U64::new(1))
        .unwrap();
    let mut value = serde_json::to_value(snapshot).unwrap();
    value["producers"][0]
        .as_object_mut()
        .unwrap()
        .remove("next_sequence");
    assert!(serde_json::from_value::<crate::node_scheduling::SchedulingSnapshot>(value).is_err());
}

#[test]
fn operation_capacity_refusal_does_not_create_unserializable_continuation() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, None);
    for index in 0..crucible_node_contract::MAX_ARRAY_ELEMENTS {
        scheduler
            .used_operations
            .insert(id(&format!("previous/{index}")));
    }

    assert!(matches!(
        scheduler.admit_exact(&id("A"), id("run/new"), U64::new(100)),
        Err(SchedulingError::CapacityExceeded)
    ));
    assert!(scheduler.operations.is_empty());
    assert_eq!(scheduler.owners[&id("owner/A")].reserved, None);
}

fn stage_empty_quantum(scheduler: &mut CausalScheduler, name: &str) {
    let cutoff = position(
        scheduler.position(&id("A")).unwrap().time_ps.get() + 1,
        0,
        Phase::BoundaryControl,
    );
    let batch = scheduler
        .prepare_input_batch(&id("A"), id(&format!("stage/{name}")), id(name), cutoff)
        .unwrap();
    let ack = crate::node_scheduling::NativeInputAcknowledgement {
        stage_operation: batch.stage_operation.clone(),
        batch: batch.batch.clone(),
        node: batch.node.clone(),
        owners: batch.owners.clone(),
        cutoff: batch.cutoff,
        inventory: batch.inventory.clone(),
        proof_ref: reference(),
    };
    scheduler
        .accept_input_acknowledgement(crate::node_scheduling::ValidatedInputAcknowledgement::new(
            scheduler.activation.clone(),
            ack,
        ))
        .unwrap();
}

fn empty_quantum_observation(
    scheduler: &CausalScheduler,
    batch: &str,
    reached: Position,
) -> crate::node_scheduling::NativeSchedulingObservation {
    crate::node_scheduling::NativeSchedulingObservation {
        node: id("A"),
        owners: scheduler.node_routes[&id("A")].clone(),
        reached,
        closed_prefix: reached,
        bounds: vec![crate::node_scheduling::NativeProducerBound {
            producer: id("A"),
            bound: crate::node_scheduling::NativeOutputBound::At(position(
                reached.time_ps.get(),
                0,
                Phase::Publication,
            )),
            proof_ref: reference(),
        }],
        publications: Vec::new(),
        external_inputs: Vec::new(),
        input_progress: Some(crate::node_scheduling::NativeInputProgress {
            batch: id(batch),
            consumed: Vec::new(),
            proof_ref: reference(),
        }),
        proof_ref: reference(),
    }
}

fn routed_fixture() -> (CausalScheduler, Endpoint) {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, Some(1));
    let (graph, _) = crate::node_admission::test_fixture_with_content();
    let mut connection = graph.world().connections[0].clone();
    connection.producer.node_id = id("Z");
    connection.consumer.node_id = id("A");
    let endpoint = connection.producer.clone();
    let policy = graph.connection_policy(&connection.id).unwrap().clone();
    scheduler
        .output_endpoints
        .insert(endpoint.clone(), policy.maximum_payload_bytes);
    scheduler.maximum_pending_payload_bytes = policy.maximum_pending_bytes;
    scheduler.routing.insert(
        connection.id.clone(),
        RoutingConnection {
            descriptor: connection,
            policy,
        },
    );
    (scheduler, endpoint)
}

fn publication_observation(
    scheduler: &CausalScheduler,
    endpoint: &Endpoint,
    bytes: &[u8],
) -> crate::node_scheduling::NativeSchedulingObservation {
    use crate::node_scheduling::{
        NativeOutputBound, NativeProducerBound, NativePublication, NativeSchedulingObservation,
    };
    NativeSchedulingObservation {
        node: id("Z"),
        owners: scheduler.node_routes[&id("Z")].clone(),
        reached: position(100, 0, Phase::BoundaryControl),
        closed_prefix: position(100, 0, Phase::BoundaryControl),
        bounds: vec![NativeProducerBound {
            producer: id("Z"),
            bound: NativeOutputBound::AfterInstant(U64::new(100)),
            proof_ref: reference(),
        }],
        publications: vec![NativePublication {
            publication_id: id("output/1"),
            endpoint: endpoint.clone(),
            native_sequence: U64::new(7),
            publication: position(10, 1, Phase::Publication),
            evaluation: Some(position(10, 0, Phase::Reaction)),
            causal_parents: Vec::new(),
            payload: crucible_node_contract::canonical::content_ref(
                bytes,
                "application/octet-stream",
            )
            .unwrap(),
            payload_bytes: bytes.to_vec(),
        }],
        external_inputs: Vec::new(),
        input_progress: None,
        proof_ref: reference(),
    }
}

fn publish_original(
    scheduler: &mut CausalScheduler,
    observation: crate::node_scheduling::NativeSchedulingObservation,
) {
    scheduler
        .admit_exact(&id("Z"), id("run/output"), U64::new(100))
        .unwrap();
    let receipt = SchedulingReceipt::new(
        scheduler.activation.clone(),
        id("Z"),
        id("run/output"),
        ProgressEvidence::Exact {
            reached: observation.reached,
            stop: StopReason::HorizonPark,
        },
        vec![id("output/1")],
        Some(observation),
    );
    scheduler.accept_receipt(receipt).unwrap();
}

#[test]
fn authenticated_output_retains_readable_bytes_fifo_and_closure_after_roundtrip() {
    let (mut scheduler, endpoint) = routed_fixture();
    let observation = publication_observation(&scheduler, &endpoint, b"hello");
    publish_original(&mut scheduler, observation);
    let snapshot = scheduler
        .snapshot(position(100, 0, Phase::BoundaryControl), U64::new(1))
        .unwrap();
    super::snapshot_impl::validate_structure(&snapshot).unwrap();
    let encoded = serde_json::to_vec(&snapshot).unwrap();
    let decoded = serde_json::from_slice(&encoded).unwrap();
    let (mut restored, _) = routed_fixture();
    restored.load_snapshot(decoded).unwrap();

    assert_eq!(restored.pending, scheduler.pending);
    assert_eq!(restored.payloads, scheduler.payloads);
    assert_eq!(restored.closed_prefixes, scheduler.closed_prefixes);
    assert_eq!(restored.native_sequences, scheduler.native_sequences);
    assert_eq!(restored.sequences, scheduler.sequences);
    assert_eq!(
        restored.pending.values().next().unwrap().native_sequence,
        U64::new(7)
    );
    assert_eq!(restored.payloads.values().next().unwrap(), b"hello");
}

#[test]
fn frozen_input_staging_does_not_consume_until_authenticated_semantic_receipt() {
    use crate::node_scheduling::{
        NativeInputAcknowledgement, NativeInputProgress, NativeOutputBound, NativeProducerBound,
        NativeSchedulingObservation, ValidatedInputAcknowledgement,
    };
    let (mut scheduler, endpoint) = routed_fixture();
    let observation = publication_observation(&scheduler, &endpoint, b"hello");
    publish_original(&mut scheduler, observation);
    let original = scheduler.pending.values().next().unwrap().clone();
    let batch = scheduler
        .prepare_input_batch(
            &id("A"),
            id("stage/1"),
            id("batch/1"),
            position(100, 0, Phase::BoundaryControl),
        )
        .unwrap();
    assert_eq!(batch.deliveries(), std::slice::from_ref(&original));
    assert_eq!(scheduler.pending.len(), 1);
    let ack = NativeInputAcknowledgement {
        stage_operation: batch.stage_operation.clone(),
        batch: batch.batch.clone(),
        node: batch.node.clone(),
        owners: batch.owners.clone(),
        cutoff: batch.cutoff,
        inventory: batch.inventory.clone(),
        proof_ref: reference(),
    };
    scheduler
        .accept_input_acknowledgement(ValidatedInputAcknowledgement::new(
            scheduler.activation.clone(),
            ack,
        ))
        .unwrap();
    assert_eq!(scheduler.pending.len(), 1);
    let grant = scheduler
        .admit_exact(&id("A"), id("run/input"), U64::new(100))
        .unwrap();
    assert_eq!(grant.input_batch(), Some(&id("batch/1")));
    assert_eq!(scheduler.pending.len(), 1);
    let observation = NativeSchedulingObservation {
        node: id("A"),
        owners: scheduler.node_routes[&id("A")].clone(),
        reached: grant.limit(),
        closed_prefix: grant.limit(),
        bounds: vec![NativeProducerBound {
            producer: id("A"),
            bound: NativeOutputBound::AfterInstant(U64::new(100)),
            proof_ref: reference(),
        }],
        publications: Vec::new(),
        external_inputs: Vec::new(),
        input_progress: Some(NativeInputProgress {
            batch: id("batch/1"),
            consumed: vec![super::inputs_impl::input_identity(&original)],
            proof_ref: reference(),
        }),
        proof_ref: reference(),
    };
    let receipt = SchedulingReceipt::new(
        scheduler.activation.clone(),
        id("A"),
        id("run/input"),
        ProgressEvidence::Exact {
            reached: grant.limit(),
            stop: StopReason::HorizonPark,
        },
        Vec::new(),
        Some(observation),
    );
    scheduler.accept_receipt(receipt).unwrap();

    assert!(scheduler.pending.is_empty());
    assert!(scheduler.input_batches.is_empty());
    assert!(scheduler.payloads.is_empty());
    assert!(scheduler.used_input_batches.contains(&id("batch/1")));
}

#[test]
fn arbitrary_quantum_batch_identity_cannot_authorize_native_execution() {
    let mut scheduler = fixture(quantum(), 100, None);
    assert!(matches!(
        scheduler.admit_quantum(&id("A"), id("run/1"), id("window/1"), id("fabricated")),
        Err(SchedulingError::MissingObservation)
    ));
    assert!(scheduler.operations.is_empty());
}

#[test]
fn receipt_and_bound_refuse_exhausted_same_time_positions_atomically() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, None);
    scheduler
        .admit_exact(&id("A"), id("run/1"), U64::new(100))
        .unwrap();
    let invalid = position(50, scheduler.maximum_microsteps.get(), Phase::Reaction);
    let receipt = SchedulingReceipt::new(
        scheduler.activation.clone(),
        id("A"),
        id("run/1"),
        ProgressEvidence::Exact {
            reached: invalid,
            stop: StopReason::Output,
        },
        Vec::new(),
        None,
    );
    assert!(matches!(
        scheduler.accept_receipt(receipt),
        Err(SchedulingError::SameTimeNonconvergence)
    ));
    assert_eq!(
        scheduler.position(&id("A")).unwrap(),
        position(0, 0, Phase::BoundaryControl)
    );
    assert!(scheduler.operations.contains_key(&id("run/1")));
    assert!(matches!(
        scheduler.observe_bound(
            &scheduler.activation.clone(),
            &id("Z"),
            OutputBound::At(position(
                50,
                scheduler.maximum_microsteps.get(),
                Phase::Publication
            ))
        ),
        Err(SchedulingError::SameTimeNonconvergence)
    ));
    assert_eq!(scheduler.bounds[&id("Z")], OutputBound::Unknown);
}

#[test]
fn invalid_native_payload_does_not_commit_any_prefix_or_sequence() {
    let (mut scheduler, endpoint) = routed_fixture();
    let mut observation = publication_observation(&scheduler, &endpoint, b"hello");
    observation.publications[0].payload_bytes = b"other".to_vec();
    scheduler
        .admit_exact(&id("Z"), id("run/output"), U64::new(100))
        .unwrap();
    let receipt = SchedulingReceipt::new(
        scheduler.activation.clone(),
        id("Z"),
        id("run/output"),
        ProgressEvidence::Exact {
            reached: observation.reached,
            stop: StopReason::HorizonPark,
        },
        vec![id("output/1")],
        Some(observation),
    );

    assert!(matches!(
        scheduler.accept_receipt(receipt),
        Err(SchedulingError::InvalidPublication)
    ));
    assert!(scheduler.pending.is_empty());
    assert!(scheduler.payloads.is_empty());
    assert!(scheduler.native_sequences.is_empty());
    assert_eq!(scheduler.bounds[&id("Z")], OutputBound::Unknown);
    assert_eq!(
        scheduler.closed_prefixes[&id("Z")],
        position(0, 0, Phase::BoundaryControl)
    );
    assert_eq!(scheduler.sequences.next(&id("Z")), Some(U64::new(0)));
    assert!(scheduler.operations.contains_key(&id("run/output")));
}

#[test]
fn snapshot_preserves_frozen_input_inventory_without_resampling() {
    let (mut scheduler, endpoint) = routed_fixture();
    let observation = publication_observation(&scheduler, &endpoint, b"hello");
    publish_original(&mut scheduler, observation);
    let batch = scheduler
        .prepare_input_batch(
            &id("A"),
            id("stage/original"),
            id("batch/original"),
            position(100, 0, Phase::BoundaryControl),
        )
        .unwrap();
    let snapshot = scheduler
        .snapshot(position(100, 0, Phase::BoundaryControl), U64::new(1))
        .unwrap();
    super::snapshot_impl::validate_structure(&snapshot).unwrap();
    let (mut restored, _) = routed_fixture();
    restored.load_snapshot(snapshot).unwrap();
    let retained = &restored.input_batches[&id("owner/A")];

    assert_eq!(retained.batch.batch(), batch.batch());
    assert_eq!(retained.batch.stage_operation(), batch.stage_operation());
    assert_eq!(retained.batch.inventory(), batch.inventory());
    assert_eq!(retained.batch.deliveries(), batch.deliveries());
    assert_eq!(retained.batch.payloads(), batch.payloads());
    assert!(retained.acknowledgement.is_none());
    assert!(restored.used_input_batches.contains(batch.batch()));
    assert!(matches!(
        restored.admit_exact(&id("A"), id("run/new"), U64::new(100)),
        Err(SchedulingError::MissingObservation) | Err(SchedulingError::NoSafeProgress)
    ));
}

fn external_fixture() -> (CausalScheduler, Endpoint) {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, None);
    let endpoint = Endpoint {
        node_id: id("A"),
        port_id: id("data"),
        lane_id: id("input"),
    };
    scheduler.external_roots.insert(
        endpoint.clone(),
        ExternalRootPolicy {
            maximum_payload_bytes: U64::new(64),
            maximum_pending_bytes: U64::new(128),
            grid: None,
        },
    );
    scheduler.maximum_pending_payload_bytes = U64::new(128);
    scheduler
        .owners
        .get_mut(&id("owner/A"))
        .unwrap()
        .inputs
        .push(InputPath {
            producer: id("A"),
            latency_ps: U64::new(0),
            external: true,
            external_endpoint: Some(endpoint.clone()),
        });
    (scheduler, endpoint)
}

fn external_observation(
    scheduler: &CausalScheduler,
    endpoint: &Endpoint,
    closed: u64,
) -> crate::node_scheduling::NativeSchedulingObservation {
    use crate::node_scheduling::{
        NativeExternalInput, NativeExternalInputInventory, NativeOutputBound, NativeProducerBound,
        NativeSchedulingObservation,
    };
    let bytes = b"root";
    NativeSchedulingObservation {
        node: id("A"),
        owners: scheduler.node_routes[&id("A")].clone(),
        reached: position(0, 0, Phase::BoundaryControl),
        closed_prefix: position(0, 0, Phase::BoundaryControl),
        bounds: vec![NativeProducerBound {
            producer: id("A"),
            bound: NativeOutputBound::Unknown,
            proof_ref: reference(),
        }],
        publications: Vec::new(),
        input_progress: None,
        external_inputs: vec![NativeExternalInputInventory {
            endpoint: endpoint.clone(),
            closed_before: position(closed, 0, Phase::BoundaryControl),
            inputs: vec![NativeExternalInput {
                event_id: id("root/1"),
                native_sequence: U64::new(0),
                publication: position(10, 0, Phase::Publication),
                payload: crucible_node_contract::canonical::content_ref(
                    bytes,
                    "application/octet-stream",
                )
                .unwrap(),
                payload_bytes: bytes.to_vec(),
                provenance_ref: reference(),
            }],
            proof_ref: reference(),
        }],
        proof_ref: reference(),
    }
}

#[test]
fn authentic_external_prefix_closes_input_without_assuming_empty_queues() {
    use crate::node_scheduling::ValidatedSchedulingObservation;
    let (mut scheduler, endpoint) = external_fixture();
    assert!(matches!(
        scheduler.admit_exact(&id("A"), id("run/unknown"), U64::new(100)),
        Err(SchedulingError::InputBlocked(_))
    ));
    let raw = external_observation(&scheduler, &endpoint, 101);
    scheduler
        .accept_boundary_observation(ValidatedSchedulingObservation::new(
            scheduler.activation.clone(),
            raw.clone(),
        ))
        .unwrap();
    let original = scheduler.pending.values().next().unwrap().clone();
    scheduler
        .accept_boundary_observation(ValidatedSchedulingObservation::new(
            scheduler.activation.clone(),
            raw,
        ))
        .unwrap();

    assert_eq!(scheduler.pending.len(), 1);
    assert_eq!(scheduler.pending.values().next(), Some(&original));
    assert_eq!(scheduler.sequences.next(&id("A")), Some(U64::new(1)));
    assert_eq!(original.external_root, Some(endpoint.clone()));
    assert_eq!(original.connection_id, None);
    assert_eq!(
        scheduler.external_closed_prefixes[&endpoint],
        position(101, 0, Phase::BoundaryControl)
    );
    let snapshot = scheduler
        .snapshot(position(0, 0, Phase::BoundaryControl), U64::new(1))
        .unwrap();
    super::snapshot_impl::validate_structure(&snapshot).unwrap();
    let (mut restored, _) = external_fixture();
    restored.load_snapshot(snapshot).unwrap();
    assert_eq!(
        restored.external_closed_prefixes,
        scheduler.external_closed_prefixes
    );
    assert_eq!(restored.pending, scheduler.pending);
    assert_eq!(restored.payloads, scheduler.payloads);
}

#[test]
fn external_prefix_regression_or_changed_retained_fifo_cannot_mutate_custody() {
    use crate::node_scheduling::ValidatedSchedulingObservation;
    let (mut scheduler, endpoint) = external_fixture();
    let raw = external_observation(&scheduler, &endpoint, 101);
    scheduler
        .accept_boundary_observation(ValidatedSchedulingObservation::new(
            scheduler.activation.clone(),
            raw.clone(),
        ))
        .unwrap();
    let before = scheduler
        .snapshot(position(0, 0, Phase::BoundaryControl), U64::new(1))
        .unwrap();
    let mut changed = raw.clone();
    changed.external_inputs[0].inputs[0].event_id = id("replacement");
    assert!(matches!(
        scheduler.accept_boundary_observation(ValidatedSchedulingObservation::new(
            scheduler.activation.clone(),
            changed
        )),
        Err(SchedulingError::InvalidReceipt)
    ));
    let mut forgotten = raw.clone();
    forgotten.external_inputs[0].inputs.clear();
    assert!(matches!(
        scheduler.accept_boundary_observation(ValidatedSchedulingObservation::new(
            scheduler.activation.clone(),
            forgotten
        )),
        Err(SchedulingError::InvalidReceipt)
    ));
    let mut regressed = raw;
    regressed.external_inputs[0].closed_before = position(100, 0, Phase::BoundaryControl);
    assert!(matches!(
        scheduler.accept_boundary_observation(ValidatedSchedulingObservation::new(
            scheduler.activation.clone(),
            regressed
        )),
        Err(SchedulingError::CausalRegression)
    ));
    assert_eq!(
        scheduler
            .snapshot(position(0, 0, Phase::BoundaryControl), U64::new(1))
            .unwrap(),
        before
    );
}

#[test]
fn saved_source_validation_checks_admitted_profile_without_reminting_custody() {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let owners: Vec<_> = graph
        .node_ids()
        .map(|node| {
            let binding = graph.binding(node).unwrap();
            OwnerIdentity {
                owner: binding.compatibility.execution_owner.id.clone(),
                incarnation: binding.authority.incarnation_id.clone(),
                generation: binding.authority.owner_generation,
            }
        })
        .collect();
    let activation = WorldActivation {
        nodes: std::rc::Rc::from([]),
        preparation: None,
        authority: Rc::new(()),
        record: ActivationRecord {
            world_binding_hash: graph.world_binding_hash().clone(),
            activation_id: id("source/activation"),
            generation: U64::new(u64::MAX),
            owners,
            boundary: position(0, 0, Phase::BoundaryControl),
        },
    };
    let mut scheduler = CausalScheduler::new(&graph, activation).unwrap();
    let node = graph.node_ids().next().unwrap().clone();
    let original = scheduler
        .admit_exact(&node, id("original/run"), U64::new(100))
        .unwrap();
    let snapshot = scheduler
        .snapshot(position(0, 0, Phase::BoundaryControl), U64::new(1))
        .unwrap();

    // Even an exhausted world generation can be valid source evidence. It
    // cannot authorize fresh execution, and original custody stays reserved.
    validate_saved_source(&graph, &snapshot).unwrap();
    assert_eq!(snapshot.reservations.len(), 1);
    assert_eq!(snapshot.reservations[0].operation, *original.operation());
    let mut wrong_profile = snapshot.clone();
    wrong_profile.maximum_microsteps = wrong_profile
        .maximum_microsteps
        .checked_add(U64::new(1))
        .unwrap();
    assert!(matches!(
        validate_saved_source(&graph, &wrong_profile),
        Err(SchedulingError::InvalidSnapshot)
    ));
    let mut widened = snapshot.clone();
    if let SavedPermission::ExactRun { start, .. } = &mut widened.reservations[0].permission {
        *start = position(1, 0, Phase::BoundaryControl);
    }
    assert!(matches!(
        validate_saved_source(&graph, &widened),
        Err(SchedulingError::InvalidSnapshot)
    ));
    let mut historical = snapshot;
    historical.source_owners[0].incarnation = id("historical/incarnation");
    validate_saved_source(&graph, &historical).unwrap();
    let mut wrong_owner = historical;
    wrong_owner.source_owners[0].generation = U64::new(0);
    assert!(matches!(
        validate_saved_source(&graph, &wrong_owner),
        Err(SchedulingError::InvalidSnapshot)
    ));
    assert!(matches!(
        scheduler.admit_exact(&node, id("another/run"), U64::new(100)),
        Err(SchedulingError::OwnerBusy)
    ));
}

#[test]
fn exact_previews_retain_closure_checks_without_reserving_native_operations() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 50, Some(1000));
    assert!(matches!(
        scheduler.preview_exact_limit(&id("A"), U64::new(10_000)),
        Err(SchedulingError::InputBlocked(_))
    ));
    assert!(matches!(
        scheduler.preview_exact_input_cut(&id("A"), U64::new(10_000)),
        Err(SchedulingError::InputBlocked(_))
    ));

    observe(
        &mut scheduler,
        OutputBound::At(position(0, 0, Phase::Publication)),
    );
    let preview = scheduler
        .preview_exact_limit(&id("A"), U64::new(10_000))
        .unwrap();
    assert_eq!(preview, position(950, 0, Phase::BoundaryControl));
    let cut = scheduler
        .preview_exact_input_cut(&id("A"), U64::new(10_000))
        .unwrap();
    assert_eq!(cut.time_ps, U64::new(1000));
    assert!(scheduler.operations.is_empty());
    assert!(scheduler.used_operations.is_empty());
    assert!(scheduler.input_batches.is_empty());

    let grant = scheduler
        .admit_exact(&id("A"), id("original-run"), U64::new(10_000))
        .unwrap();
    assert_eq!(grant.limit(), preview);
    assert_eq!(scheduler.operations.len(), 1);
}

#[path = "tests/quantized_parents.rs"]
mod quantized_parents;

#[path = "tests/complete_future_bound.rs"]
mod complete_future_bound;

#[path = "tests/future_birth.rs"]
mod future_birth;

#[path = "tests/terminal.rs"]
mod terminal;
