//! Exercises real scheduler reservation growth and refused constructor bounds.

use super::*;
use crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter;

fn observed(scheduler: &CausalScheduler) -> usize {
    let mut counter = RetainedRuntimeCounter::new(usize::MAX);
    scheduler
        .charge_original_retained_storage(&mut counter)
        .unwrap();
    counter.bytes()
}

#[test]
fn actual_two_grants_keep_used_identities_and_constructor_growth_within_quote() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, None);
    let node = id("A");
    for (name, horizon) in [("restored/run/one", 100), ("restored/run/two", 200)] {
        let operation = id(name);
        let before = observed(&scheduler);
        let (retained, _) = scheduler
            .original_restored_producer_grant_construction_data(&node, &operation, usize::MAX)
            .unwrap();

        let grant = scheduler
            .admit_exact(&node, operation.clone(), U64::new(horizon))
            .unwrap();
        let after = observed(&scheduler);
        assert!(after.saturating_sub(before) <= retained);
        assert!(
            scheduler
                .original_restored_producer_grant_construction_data(
                    &node,
                    &id("another"),
                    usize::MAX,
                )
                .is_err()
        );
        let receipt = exact_receipt(&scheduler, &grant, grant.limit(), StopReason::HorizonPark);
        scheduler.accept_receipt(receipt).unwrap();

        assert_eq!(scheduler.position(&node).unwrap(), grant.limit());
        assert!(
            scheduler
                .original_restored_producer_grant_construction_data(&node, &operation, usize::MAX,)
                .is_err()
        );
    }
    assert_eq!(scheduler.used_operations.len(), 2);
}

#[test]
fn constructor_exact_and_one_short_refuse_before_reservation_or_used_id_append() {
    let scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, None);
    let node = id("A");
    let operation = id("restored/run/one");
    let initial = observed(&scheduler);
    let (retained, transient) = scheduler
        .original_restored_producer_grant_construction_data(&node, &operation, usize::MAX)
        .unwrap();
    let axis_maximum = retained.max(transient);

    assert_eq!(
        scheduler
            .original_restored_producer_grant_construction_data(&node, &operation, axis_maximum,)
            .unwrap(),
        (retained, transient)
    );
    assert!(scheduler.original_restored_producer_grant_construction_data(
        &node, &operation, axis_maximum - 1,
    ).is_err());

    assert_eq!(observed(&scheduler), initial);
    assert!(scheduler.used_operations.is_empty());
    assert!(scheduler.operations.is_empty());
    assert!(scheduler.owners[&id("owner/A")].reserved.is_none());
}

#[test]
fn real_refusal_keeps_grant_identity_without_authorizing_another_attempt() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, None);
    let node = id("A");
    let operation = id("restored/failed");
    let grant = scheduler
        .admit_exact(&node, operation.clone(), U64::new(100))
        .unwrap();
    scheduler.reconcile_no_effect(&grant).unwrap();

    assert!(
        scheduler
            .original_restored_producer_grant_construction_data(&node, &operation, usize::MAX,)
            .is_err()
    );
    assert!(scheduler.used_operations.contains(&operation));
    assert!(scheduler.owners[&id("owner/A")].reserved.is_none());
    assert_eq!(
        scheduler.position(&node).unwrap(),
        position(0, 0, Phase::BoundaryControl)
    );
}
