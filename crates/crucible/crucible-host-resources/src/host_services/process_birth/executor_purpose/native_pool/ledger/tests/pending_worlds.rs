//! Exercises exact ledger and real lease retention without authentic Main issuance.

// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

use super::*;
use crate::host_services::HostServiceAllocator;
use crate::host_supervision::{HostOperationBudgets, HostOperationClass, HostOperationSupervisor};

fn original() -> Arc<HostOperationGuard> {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap())
}

fn identity(value: u8) -> NativeWorldIdentity {
    NativeWorldIdentity {
        owner: [value; 32],
        selection: [value; 32],
    }
}

#[test]
fn pending_body_keeps_its_debt_and_lease_while_an_independent_world_returns() {
    let original = original();
    let allocator = HostServiceAllocator::new(1, 26, 1).unwrap();
    let mut ledger = PoolLedger::new(ceiling(), 2, 8, 3).unwrap();
    let initial = ledger.used;
    let (first, _, _) = ledger
        .assign(identity(1), &requests()[..1], 16, &original)
        .unwrap();
    ledger
        .bind_window(first, allocator.reserve_resources(0, 12, 0).unwrap())
        .unwrap();
    ledger.take_consumer(first).unwrap();
    let (index, assignment) = ledger.take_node(first, requests()[0].node).unwrap();
    let prepared = ledger
        .prepare_node_return(first, assignment, index)
        .unwrap();
    ledger.commit_node_return(prepared);
    let first_body = ledger.used;

    assert_eq!(first_body.metadata_bytes, initial.metadata_bytes + 16);
    assert_eq!(
        first_body.resident_peak_bytes,
        initial.resident_peak_bytes + 16
    );
    assert_eq!(first_body.file_descriptors, initial.file_descriptors);
    assert!(matches!(
        ledger.prepare_world_return(first).unwrap(),
        WorldReturnPreparation::PendingBody
    ));
    assert_eq!(ledger.used, first_body);
    assert!(ledger.verify_never_born(first).is_err());

    let (second, _, _) = ledger
        .assign(identity(2), &requests()[1..], 24, &original)
        .unwrap();
    ledger
        .bind_window(second, allocator.reserve_resources(0, 14, 0).unwrap())
        .unwrap();
    ledger.take_consumer(second).unwrap();
    assert!(allocator.reserve_resources(0, 1, 0).is_err());
    let (index, assignment) = ledger.take_node(second, requests()[1].node).unwrap();
    let prepared = ledger
        .prepare_node_return(second, assignment, index)
        .unwrap();
    ledger.commit_node_return(prepared);
    ledger.close_consumer(second).unwrap();
    let (index, remaining, windows, tables) = ready_return(&ledger, second);
    assert_eq!((windows, tables), (0, 0));
    assert_eq!(remaining, first_body);
    ledger.commit_world_return(index, second, remaining);

    let second_window = allocator.reserve_resources(0, 14, 0).unwrap();
    assert!(allocator.reserve_resources(0, 1, 0).is_err());
    assert!(ledger.prepare_world_return(second).is_err());
    assert!(matches!(
        ledger.prepare_world_return(first).unwrap(),
        WorldReturnPreparation::PendingBody
    ));
    assert_eq!(ledger.used, first_body);
    ledger.close_consumer(first).unwrap();
    let (index, remaining, windows, tables) = ready_return(&ledger, first);
    assert_eq!((windows, tables), (0, 0));
    assert_eq!(remaining, initial);
    ledger.commit_world_return(index, first, remaining);
    drop(second_window);

    let all_windows = allocator.reserve_resources(0, 26, 0).unwrap();
    assert_eq!(ledger.used, initial);
    assert!(ledger.close_consumer(first).is_err());
    assert!(ledger.prepare_world_return(first).is_err());
    drop(all_windows);
}

#[test]
fn pending_body_does_not_mask_issued_members_stale_epochs_or_corruption() {
    let (mut ledger, epoch) = selected_ledger();
    ledger.take_consumer(epoch).unwrap();
    let charged = ledger.used;
    assert!(ledger.prepare_world_return(epoch + 1).is_err());
    let (index, assignment) = ledger.take_node(epoch, requests()[0].node).unwrap();
    assert!(ledger.prepare_world_return(epoch).is_err());
    assert_eq!(ledger.used, charged);
    let prepared = ledger
        .prepare_node_return(epoch, assignment, index)
        .unwrap();
    ledger.commit_node_return(prepared);
    assert!(matches!(
        ledger.prepare_world_return(epoch).unwrap(),
        WorldReturnPreparation::PendingBody
    ));

    let index = ledger.nodes.iter().position(Option::is_some).unwrap();
    ledger.nodes[index].as_mut().unwrap().windows_issued[0] = true;
    assert!(ledger.prepare_world_return(epoch).is_err());
    ledger.nodes[index].as_mut().unwrap().windows_issued[0] = false;
    let retained = ledger.used;
    ledger.used.metadata_bytes = 0;
    assert!(ledger.prepare_world_return(epoch).is_err());
    ledger.used = retained;
    let world = ledger
        .worlds
        .iter_mut()
        .flatten()
        .find(|world| world.epoch == epoch)
        .unwrap();
    let window = world.window.take().unwrap();
    assert!(ledger.prepare_world_return(epoch).is_err());
    ledger.bind_window(epoch, window).unwrap();

    assert_eq!(ledger.used, retained);
    assert!(matches!(
        ledger.prepare_world_return(epoch).unwrap(),
        WorldReturnPreparation::PendingBody
    ));
    assert!(ledger.verify_never_born(epoch).is_err());
}

#[test]
fn pending_body_cannot_hide_lost_never_born_rows() {
    let (mut ledger, epoch) = selected_ledger();
    ledger.take_consumer(epoch).unwrap();
    let charged = ledger.used;
    let first = ledger.nodes[0].take();
    let second = ledger.nodes[1].take();

    assert!(ledger.prepare_world_return(epoch).is_err());
    assert_eq!(ledger.used, charged);
    assert!(ledger.verify_never_born(epoch).is_err());

    ledger.nodes[0] = first;
    ledger.nodes[1] = second;
    assert!(matches!(
        ledger.prepare_world_return(epoch).unwrap(),
        WorldReturnPreparation::PendingBody
    ));
    assert_eq!(ledger.used, charged);
}

#[test]
fn actual_assignment_refusal_changes_neither_rows_debt_nor_epochs() {
    let (mut ledger, epoch) = selected_ledger();
    let original = original();
    let used = ledger.used;
    let next_world = ledger.next_world;
    let next_assignment = ledger.next_assignment;
    let world_count = ledger.worlds.iter().flatten().count();
    let node_count = ledger.nodes.iter().flatten().count();
    let held_original = Arc::clone(&ledger.worlds.iter().flatten().next().unwrap()._original);

    assert!(
        ledger
            .assign(identity(3), &requests()[..1], 16, &original)
            .is_err()
    );
    assert_eq!(ledger.used, used);
    assert_eq!(ledger.next_world, next_world);
    assert_eq!(ledger.next_assignment, next_assignment);
    assert_eq!(ledger.worlds.iter().flatten().count(), world_count);
    assert_eq!(ledger.nodes.iter().flatten().count(), node_count);
    assert!(Arc::ptr_eq(
        &ledger.worlds.iter().flatten().next().unwrap()._original,
        &held_original
    ));

    ledger.take_consumer(epoch).unwrap();
    ledger.close_consumer(epoch).unwrap();
    let (index, remaining, _, _) = ready_return(&ledger, epoch);
    ledger.commit_world_return(index, epoch, remaining);
    let (next, _, _) = ledger
        .assign(identity(3), &requests()[..1], 16, &original)
        .unwrap();
    assert_eq!(next, next_world + 1);
    assert_eq!(ledger.next_assignment, next_assignment + 1);
}

#[test]
fn epoch_exhaustion_is_refused_before_any_publication() {
    let mut ledger = PoolLedger::new(ceiling(), 2, 8, 3).unwrap();
    let original = original();
    let used = ledger.used;
    ledger.next_assignment = u64::MAX;

    assert!(
        ledger
            .assign(identity(1), &requests()[..1], 16, &original)
            .is_err()
    );
    assert_eq!(ledger.used, used);
    assert_eq!(ledger.next_world, 0);
    assert_eq!(ledger.next_assignment, u64::MAX);
    assert!(ledger.nodes.iter().all(Option::is_none));
    assert!(ledger.worlds.iter().all(Option::is_none));
}

#[test]
fn committed_window_refusal_preserves_the_original_world_and_actual_lease() {
    let original = original();
    let allocator = HostServiceAllocator::new(1, 24, 1).unwrap();
    let mut ledger = PoolLedger::new(ceiling(), 2, 8, 3).unwrap();
    let (epoch, _, _) = ledger
        .assign(identity(1), &requests()[..1], 16, &original)
        .unwrap();
    ledger
        .bind_window(epoch, allocator.reserve_resources(0, 12, 0).unwrap())
        .unwrap();
    let charged = ledger.used;

    let refused_window = allocator.reserve_resources(0, 12, 0).unwrap();
    assert!(ledger.bind_window(epoch, refused_window).is_err());
    assert_eq!(ledger.used, charged);
    let held = ledger.worlds.iter().flatten().next().unwrap();
    assert!(Arc::ptr_eq(&held._original, &original));
    assert!(held.window.is_some());
    assert_eq!(Arc::strong_count(&original), 2);
    let temporary = allocator.reserve_resources(0, 12, 0).unwrap();
    assert!(allocator.reserve_resources(0, 1, 0).is_err());
    drop(temporary);

    ledger.take_consumer(epoch).unwrap();
    assert!(matches!(
        ledger.prepare_world_return(epoch).unwrap(),
        WorldReturnPreparation::PendingBody
    ));
    ledger.close_consumer(epoch).unwrap();
    let (index, remaining, _, _) = ready_return(&ledger, epoch);
    ledger.commit_world_return(index, epoch, remaining);
    assert_eq!(Arc::strong_count(&original), 1);
    let returned = allocator.reserve_resources(0, 24, 0).unwrap();
    drop(returned);
}
