//! Checks that absent custody never authenticates a Target return.
//!
//! These are negative local witness controls, not Main/Source issuance tests.

use super::*;

#[test]
fn absent_roster_never_becomes_a_returned_target_even_for_old_or_future_epochs() {
    for epoch in [0, 1, u64::MAX] {
        let mut loan = QemuForkTargetConstructionLoan {
            attempt: NativeAccountAttempt {
                roster: Weak::new(),
                index: 0,
                generation: 1,
            },
            epoch,
            process_generation: 2,
            returned: false,
            failed_permit: None,
        };
        assert!(loan.try_finish().is_err());
        assert!(!loan.is_physically_returned());
        assert_eq!(loan.process_generation(), 2);
        assert!(loan.try_finish().is_err());
        assert!(!loan.is_physically_returned());
    }
}

#[test]
fn completed_saved_cleanup_is_observed_without_admitting_a_second_operation() {
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationState, HostOperationSupervisor,
    };
    // This is an actual component supervisor/control. It creates no Main,
    // NativeAccountAttempt, Target loan, physical close receipt or role credit.
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let preparation = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let mut cleanup = TargetCleanup::new(preparation);
    let original = cleanup.guard().unwrap();
    let operation_id = original.status().unwrap().operation_id;
    drop(original);
    cleanup.complete_for_return().unwrap();
    assert!(cleanup.completed);
    cleanup.complete_for_return().unwrap();
    let operations = supervisor.operation_statuses().unwrap();
    let saved = operations
        .iter()
        .filter(|status| status.class == HostOperationClass::Cleanup)
        .collect::<Vec<_>>();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].operation_id, operation_id);
    assert_eq!(saved[0].state, HostOperationState::Completed);
}

#[test]
fn nominal_cleanup_joins_actual_child_service_without_substituting_its_roster() {
    use crate::qmp::checkpoint_paged_source_support::ImmutableBacking;
    use crate::ram_control::RamCleanupOriginal;
    use crate::ram_source::{QemuRamBacking, QemuRamSourceService};
    use crucible_host_resources::host_services::HostServiceAllocator;
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor, HostSupervisionError,
    };
    use crucible_qemu_protocol::ram_page::RamPageBinding;
    use std::os::unix::net::UnixStream;

    // These are real component operation tables and a real socket worker.
    // The local cleanup mechanism below issues no Native Target or Main grant.
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let child_supervisor = supervisor
        .new_budget_owner(HostOperationBudgets::default())
        .unwrap();
    let preparation = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let mut cleanup = Arc::new(TargetCleanup::new(preparation));
    let original = TargetCleanupLoan(Arc::clone(&cleanup))
        .retained_original()
        .unwrap();
    assert!(matches!(
        RamCleanupOriginal::direct(original.original(), &child_supervisor).verify(),
        Err(HostSupervisionError::InvalidBudget)
    ));
    let backing = Arc::new(ImmutableBacking::new(2).unwrap());
    let binding = RamPageBinding {
        session: [1; 16],
        owner_incarnation: [2; 16],
        source_generation: 1,
        root_digest: *backing.root_record().digest().as_bytes(),
    };
    let (socket, _peer) = UnixStream::pair().unwrap();
    let mut service = QemuRamSourceService::start_component(
        socket,
        backing,
        binding,
        child_supervisor,
        HostServiceAllocator::new(1, 4, 8 * 1024 * 1024).unwrap(),
        None,
    )
    .unwrap();

    let (joined, status) = service.stop(Some(RamCleanupOriginal::target(&original)));

    assert!(joined);
    status.unwrap();
    assert!(Arc::get_mut(&mut cleanup).is_none());
    drop(service);
    drop(original);
    // The step borrower cannot complete the issuer. Only returning both of
    // its actual aliases restores the issuer's unique completion boundary.
    let cleanup = Arc::get_mut(&mut cleanup).unwrap();
    assert!(!cleanup.completed);
    cleanup.complete_for_return().unwrap();
    assert!(cleanup.completed);
}

#[test]
fn cached_nominal_cleanup_rejects_another_actual_entry_and_never_renews_after_expiry() {
    use crucible_host_resources::host_supervision::{
        HostOperationBudget, HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    use std::time::Duration;

    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let preparation = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let first = Arc::new(TargetCleanup::new(Arc::clone(&preparation)));
    let second = Arc::new(TargetCleanup::new(preparation));
    let original = TargetCleanupLoan(Arc::clone(&first))
        .retained_original()
        .unwrap();
    let other = TargetCleanupLoan(second).retained_original().unwrap();
    let mismatched = TargetCleanupOriginal {
        original: Arc::clone(&other.original),
        lender: TargetCleanupLoan(Arc::clone(&first)),
    };
    assert!(mismatched.checked_original().is_err());
    let saved = original.original().status().unwrap().operation_id;
    let (revision, mut budgets) = supervisor.budgets().unwrap();
    budgets.classes[HostOperationClass::Cleanup as usize] =
        HostOperationBudget::finite(Duration::from_nanos(1));
    supervisor.update_budgets(revision, budgets).unwrap();

    let again = TargetCleanupLoan(first).retained_original().unwrap();

    assert!(std::ptr::eq(original.original(), again.original()));
    assert!(
        crate::ram_control::RamCleanupOriginal::target(&again)
            .wait_slice()
            .is_err()
    );
    let entries = supervisor.operation_statuses().unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.operation_id == saved)
            .count(),
        1
    );
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.class == HostOperationClass::Cleanup)
            .count(),
        2
    );
}
