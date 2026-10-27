//! Checks original global operation identities in saved source DATA.

use super::*;
use crate::node_contract::{ActivationRecord, OwnerIdentity};
use crucible_node_format::Phase;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn source_scheduler() -> (AdmittedGraph, CausalScheduler, Vec<Id>) {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let nodes: Vec<_> = graph.node_ids().cloned().collect();
    assert_eq!(nodes.len(), 2);
    let mut owners: Vec<_> = nodes
        .iter()
        .map(|node| {
            let binding = graph.binding(node).unwrap();
            OwnerIdentity {
                owner: binding.compatibility.execution_owner.id.clone(),
                incarnation: binding.authority.incarnation_id.clone(),
                generation: binding.authority.owner_generation,
            }
        })
        .collect();
    owners.sort_by(|left, right| left.owner.cmp(&right.owner));
    let activation = WorldActivation {
        nodes: std::rc::Rc::from([]),
        preparation: None,
        authority: std::rc::Rc::new(()),
        record: ActivationRecord {
            world_binding_hash: graph.world_binding_hash().clone(),
            activation_id: id("original/source"),
            generation: 1.into(),
            owners,
            boundary: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
        },
    };
    let scheduler = CausalScheduler::new(&graph, activation).unwrap();
    (graph, scheduler, nodes)
}

fn save(scheduler: &CausalScheduler) -> SchedulingSnapshot {
    scheduler
        .snapshot(
            Position::new(0.into(), 0.into(), Phase::BoundaryControl),
            1.into(),
        )
        .unwrap()
}

fn two_input_cuts() -> (AdmittedGraph, CausalScheduler) {
    let (graph, mut scheduler, nodes) = source_scheduler();
    for (index, node) in nodes.iter().enumerate() {
        scheduler
            .prepare_input_batch(
                node,
                id(&format!("stage/{index}")),
                id(&format!("batch/{index}")),
                Position::new(1.into(), 0.into(), Phase::BoundaryControl),
            )
            .unwrap();
    }
    (graph, scheduler)
}

#[test]
fn saved_input_staging_keeps_globally_distinct_operation_identities() {
    let (graph, scheduler) = two_input_cuts();
    let original = save(&scheduler);
    validate_saved_source(&graph, &original).unwrap();
    assert_ne!(
        original.input_batches[0].owner,
        original.input_batches[1].owner
    );

    let mut aliased = original.clone();
    aliased.input_batches[1].stage_operation = aliased.input_batches[0].stage_operation.clone();

    assert!(matches!(
        validate_saved_source(&graph, &aliased),
        Err(SchedulingError::InvalidSnapshot)
    ));
    assert_eq!(save(&scheduler), original);
}

#[test]
fn saved_execution_cannot_reuse_an_original_input_stage_operation() {
    let (graph, mut scheduler, nodes) = source_scheduler();
    scheduler
        .prepare_input_batch(
            &nodes[0],
            id("original/stage"),
            id("original/batch"),
            Position::new(1.into(), 0.into(), Phase::BoundaryControl),
        )
        .unwrap();
    scheduler
        .admit_exact(&nodes[1], id("original/run"), 100.into())
        .unwrap();
    let original = save(&scheduler);
    validate_saved_source(&graph, &original).unwrap();

    let mut aliased = original.clone();
    aliased.reservations[0].operation = aliased.input_batches[0].stage_operation.clone();

    assert!(matches!(
        validate_saved_source(&graph, &aliased),
        Err(SchedulingError::InvalidSnapshot)
    ));
    assert_eq!(save(&scheduler), original);
}

#[test]
fn saved_input_batch_cannot_reuse_another_original_batch_identity() {
    let (graph, scheduler) = two_input_cuts();
    let original = save(&scheduler);
    validate_saved_source(&graph, &original).unwrap();

    let mut aliased = original.clone();
    aliased.input_batches[1].batch = aliased.input_batches[0].batch.clone();

    assert!(matches!(
        validate_saved_source(&graph, &aliased),
        Err(SchedulingError::InvalidSnapshot)
    ));
    assert_eq!(save(&scheduler), original);
}
