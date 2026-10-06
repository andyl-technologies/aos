//! Resource admission and generation-bound transition behavior.

// crucible-lint: allow panic-shortcut -- test fixtures panic to localize invalid resource-ledger admission assumptions.
#![allow(clippy::unwrap_used)]

use super::*;

fn target(owner: u8) -> HostRamTarget {
    HostRamTarget {
        daemon_epoch: [1; 32],
        owner_id: [owner; 32],
        node_id: [3; 32],
        owner_generation: 1,
        arena_generation: 1,
        retained_template: false,
    }
}

fn resources(resident: u64) -> HostResourceVector {
    HostResourceVector {
        resident_peak_bytes: resident,
        backing_peak_bytes: 100,
        metadata_bytes: 10,
        staging_bytes: 10,
        paging_io_slots: 2,
        cpu_slots: 1,
        task_slots: 2,
        file_descriptors: 4,
    }
}

#[test]
fn transient_peak_is_reserved_before_apply_and_released_after_convergence() {
    let mut ledger = HostResourceLedger::new(HostResourceVector {
        resident_peak_bytes: 400,
        backing_peak_bytes: 400,
        metadata_bytes: 100,
        staging_bytes: 100,
        paging_io_slots: 20,
        cpu_slots: 10,
        task_slots: 20,
        file_descriptors: 40,
    });
    ledger.admit(target(1), resources(100)).unwrap();
    let transition = ledger
        .begin_transition(target(1), 0, resources(50), resources(150))
        .unwrap();

    assert_eq!(ledger.reserved().resident_peak_bytes, 150);
    assert!(matches!(
        ledger.release(target(1)),
        Err(HostRamPolicyError::TransitionPending)
    ));
    assert!(matches!(
        ledger.begin_transition(target(1), 1, resources(20), resources(150)),
        Err(HostRamPolicyError::TransitionPending)
    ));
    ledger.finish_transition(transition).unwrap();
    assert_eq!(ledger.reserved().resident_peak_bytes, 50);
    ledger.release(target(1)).unwrap();
    assert_eq!(ledger.reserved(), HostResourceVector::default());
}

#[test]
fn refused_capacity_and_stale_completions_do_not_change_accounting() {
    let mut ledger = HostResourceLedger::new(resources(100));
    ledger.admit(target(1), resources(100)).unwrap();

    assert!(
        ledger
            .begin_transition(target(1), 0, resources(200), resources(200))
            .is_err()
    );
    assert_eq!(
        ledger.owner_reservation(target(1)),
        Some((0, resources(100)))
    );
    let transition = ledger
        .begin_transition(target(1), 0, resources(50), resources(100))
        .unwrap();
    let mut stale = transition;
    stale.target.arena_generation = 2;
    assert!(ledger.finish_transition(stale).is_err());
    assert_eq!(ledger.reserved(), resources(100));
}

#[test]
fn a_soft_target_does_not_replace_the_sound_execution_peak() {
    let policy = HostRamPolicy {
        mode: HostRamMode::Managed,
        resident_target_bytes: 10,
        eviction_preference: 80,
        writeback_bytes_per_second: 100,
        maximum_paging_io_in_flight: 1,
        prefetch_on_increase: false,
        latency: HostOperationBudgets::default(),
    };
    let capabilities = HostRamCapabilities {
        logical_ram_bytes: 100,
        compulsory_resident_bytes: 10,
        minimum_execution_peak_bytes: 100,
        maximum_paging_io_slots: 1,
        dynamic_residency: true,
        disk_oriented: true,
        resident_required: false,
    };

    assert_eq!(
        policy.validate(capabilities, resources(20), false),
        Err(HostRamPolicyError::CapacityRefused)
    );
    assert!(policy.validate(capabilities, resources(110), false).is_ok());
    let resident = HostRamPolicy {
        mode: HostRamMode::ResidentRequired,
        ..policy
    };
    assert_eq!(
        resident.validate(capabilities, resources(110), false),
        Err(HostRamPolicyError::Unsupported)
    );
}

#[test]
fn io_capacity_is_independent_from_resident_bytes() {
    let mut ledger = HostResourceLedger::new(resources(1000));
    ledger.admit(target(1), resources(1)).unwrap();

    assert_eq!(
        ledger.admit(target(2), resources(1)),
        Err(HostRamPolicyError::CapacityRefused)
    );
    assert_eq!(ledger.reserved().paging_io_slots, 2);
}

#[test]
fn initial_inventory_repartition_retains_complete_totals_and_revision() {
    let initial = resources(100);
    let actual = HostResourceVector {
        metadata_bytes: 30,
        staging_bytes: 20,
        ..initial
    };
    let mut ledger = HostResourceLedger::new(actual);
    ledger.admit(target(1), initial).unwrap();

    ledger
        .repartition_before_execution(target(1), initial, actual)
        .unwrap();

    assert_eq!(ledger.owner_reservation(target(1)), Some((0, actual)));
    assert_eq!(ledger.capacity(), actual);
    assert_eq!(
        ledger.reserved().resident_peak_bytes,
        initial.resident_peak_bytes
    );
    assert!(
        ledger
            .repartition_before_execution(target(1), initial, actual)
            .is_err()
    );
    let excessive = HostResourceVector {
        metadata_bytes: 81,
        ..actual
    };
    assert!(
        ledger
            .repartition_before_execution(target(1), actual, excessive)
            .is_err()
    );
    assert_eq!(ledger.owner_reservation(target(1)), Some((0, actual)));
    let changed_peak = HostResourceVector {
        resident_peak_bytes: 101,
        ..actual
    };
    assert!(
        ledger
            .repartition_before_execution(target(1), actual, changed_peak)
            .is_err()
    );
}

#[test]
fn proven_cleanup_discharges_pending_peak_without_claiming_convergence() {
    let mut ledger = HostResourceLedger::new(resources(150));
    ledger.admit(target(1), resources(100)).unwrap();
    let transition = ledger
        .begin_transition(target(1), 0, resources(50), resources(150))
        .unwrap();

    assert_eq!(
        ledger.release(target(1)),
        Err(HostRamPolicyError::TransitionPending)
    );
    ledger.release_after_cleanup(target(1)).unwrap();

    assert_eq!(ledger.reserved(), HostResourceVector::default());
    assert!(ledger.finish_transition(transition).is_err());
    assert_eq!(
        ledger.release_after_cleanup(target(1)),
        Err(HostRamPolicyError::NotCurrent)
    );
}
