//! Checks actual lower original/event/body credit; no native receiver is modeled as accepting.

use super::*;
use crucible_host_resources::host_services::HostServiceAllocator;
use crucible_host_resources::host_supervision::{HostOperationBudgets, HostOperationState};
use crucible_host_resources::test_support::{AllocationIdentity, TestAllocationObserver};
use std::time::Duration;

fn target() -> HostRamTarget {
    HostRamTarget {
        daemon_epoch: [1; 32],
        owner_id: [2; 32],
        node_id: [3; 32],
        owner_generation: 1,
        arena_generation: 1,
        retained_template: false,
    }
}

fn supervisor() -> HostOperationSupervisor {
    HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )
    .unwrap()
}

fn event() -> OwnedFd {
    rustix::event::eventfd(
        0,
        rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
    )
    .unwrap()
}

fn observed_loan() -> (
    CheckpointOriginalLoan,
    HostServiceAllocator,
    AllocationIdentity,
) {
    let supervisor = supervisor();
    let account = HostServiceAllocator::new(1, 2, 16384).unwrap();
    let event = event();
    let mut owner =
        CheckpointOriginal::allocate_registered_owner(&supervisor, &account, target()).unwrap();
    let (layout, _) = Layout::new::<[AtomicUsize; 2]>()
        .extend(Layout::new::<LoanBody>())
        .unwrap();
    let (entered, allocation, counts) =
        TestAllocationObserver::capture_layout_and_count(layout.pad_to_align(), || {
            owner.enter(&event)
        });
    entered.unwrap();
    assert!(!counts.overflow);
    let loan = owner.loan(target()).unwrap();

    // This is actual parent-observed retirement, while the separate transport
    // borrower still owns the already entered original and its subscriber.
    owner.retire_after_reap();
    (loan, account, allocation.unwrap())
}

#[test]
fn final_checkpoint_loan_frees_actual_allocation_before_original_credit() {
    let (loan, account, allocation) = observed_loan();
    let (last, counts) = TestAllocationObserver::count(|| loan.clone());
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(loan.same_owner(&last));
    drop(loan);
    assert!(account.reserve_resources(0, 0, 16384).is_err());

    let ((), observations) = TestAllocationObserver::observe_controls(
        [&account, &account],
        None,
        [Some(allocation), None, None],
        || drop(last),
    );

    let observed = observations[0].unwrap();
    let bytes = observed.before.original_bytes[0].unwrap();
    assert!(bytes >= CheckpointOriginalLoan::allocation_bytes().unwrap());
    assert_eq!(observed.after.original_bytes, [Some(bytes); 2]);
    assert!(account.reserve_resources(0, 0, 16384).is_ok());
}

#[test]
fn checkpoint_loan_unwind_keeps_credit_through_actual_allocation_free() {
    let (loan, account, allocation) = observed_loan();

    let (result, observations) = TestAllocationObserver::observe_controls(
        [&account, &account],
        None,
        [Some(allocation), None, None],
        || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _loan = loan;
                panic!("intentional checkpoint loan unwind");
            }))
        },
    );

    assert!(result.is_err());
    let observed = observations[0].unwrap();
    let bytes = observed.before.original_bytes[0].unwrap();
    assert!(bytes >= CheckpointOriginalLoan::allocation_bytes().unwrap());
    assert_eq!(observed.after.original_bytes, [Some(bytes); 2]);
    assert!(account.reserve_resources(0, 0, 16384).is_ok());
}

#[test]
fn entered_original_basis_and_operation_identity_stay_fixed_across_rechecks() {
    let supervisor = supervisor();
    let account = HostServiceAllocator::new(1, 2, 16384).unwrap();
    let event = event();
    let mut owner =
        CheckpointOriginal::allocate_registered_owner(&supervisor, &account, target()).unwrap();
    owner.enter(&event).unwrap();
    let body = owner.body.as_ref().unwrap();
    let first = body.basis.unwrap();

    owner.check(target()).unwrap();
    owner.check(target()).unwrap();

    assert_eq!(body.basis.unwrap(), first);
    assert_eq!(&first[..8], b"CRUCPAU1");
    assert_eq!(
        body.original
            .as_ref()
            .unwrap()
            .guard()
            .status()
            .unwrap()
            .class,
        HostOperationClass::Quiescence
    );
    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
}

#[test]
fn insufficient_same_account_refuses_before_operation_or_subscriber_birth() {
    let supervisor = supervisor();
    let account = HostServiceAllocator::new(1, 1, 1).unwrap();

    let error =
        CheckpointOriginal::allocate_registered_owner(&supervisor, &account, target()).unwrap_err();

    assert_eq!(
        error.source,
        CheckpointOriginalCause::Account(HostServiceError::CapacityExhausted)
    );
    assert!(supervisor.operation_statuses().unwrap().is_empty());
    assert!(account.reserve_resources(0, 1, 1).is_ok());
}

#[test]
fn canceled_actual_original_refuses_without_replacement_and_retains_body_credit() {
    let supervisor = supervisor();
    let account = HostServiceAllocator::new(1, 1, 16384).unwrap();
    let event = event();
    supervisor.cancel().unwrap();

    let mut owner =
        CheckpointOriginal::allocate_registered_owner(&supervisor, &account, target()).unwrap();
    let error = owner.enter(&event).unwrap_err();

    assert!(matches!(
        error.source,
        CheckpointOriginalCause::Original(HostSupervisionError::Terminal {
            state: HostOperationState::Canceled
        })
    ));
    assert_eq!(owner.enter(&event).unwrap_err(), error);
    assert!(account.reserve_resources(0, 1, 16384).is_err());
    owner.retire_after_reap();
    assert!(account.reserve_resources(0, 1, 16384).is_ok());
}

#[test]
fn same_event_cancellation_retains_original_and_credit_until_observed_retirement() {
    let supervisor = supervisor();
    let account = HostServiceAllocator::new(1, 2, 16384).unwrap();
    let event = event();
    let mut owner =
        CheckpointOriginal::allocate_registered_owner(&supervisor, &account, target()).unwrap();
    owner.enter(&event).unwrap();

    assert_eq!(rustix::io::write(&event, &1_u64.to_ne_bytes()).unwrap(), 8);
    let refusal = owner.check(target()).unwrap_err();

    assert!(matches!(
        refusal.source,
        CheckpointOriginalCause::Original(HostSupervisionError::Terminal {
            state: HostOperationState::Canceled
        })
    ));
    assert!(account.reserve_resources(0, 1, 1).is_err());
    assert!(owner.body.is_some());
    owner.retire_after_reap();
    assert!(owner.body.is_none());
    assert!(account.reserve_resources(0, 1, 16384).is_ok());
}

#[test]
fn receiver_unavailability_preserves_first_cause_and_later_original_postcut() {
    let supervisor = supervisor();
    let account = HostServiceAllocator::new(1, 2, 16384).unwrap();
    let event = event();
    let mut owner =
        CheckpointOriginal::allocate_registered_owner(&supervisor, &account, target()).unwrap();
    owner.enter(&event).unwrap();
    let basis = owner.body.as_ref().unwrap().basis.unwrap();
    let refusal = owner
        .prepare_receiving(&registration(&account, Arc::new(UnavailableRegistrar)))
        .unwrap_err();

    supervisor.cancel().unwrap();
    let retry = owner
        .prepare_receiving(&registration(&account, Arc::new(UnavailableRegistrar)))
        .unwrap_err();

    assert_eq!(
        refusal.source,
        CheckpointOriginalCause::NativeReceiverUnavailable
    );
    assert_eq!(retry.source, refusal.source);
    assert!(retry.original_after.is_some());
    let body = owner.body.as_ref().unwrap();
    assert_eq!(body.first_refusal, Some(refusal));
    assert_eq!(body.basis.unwrap(), basis);
    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
    assert_eq!(owner.receiver_custody, ReceiverCustody::Receiving);
    assert!(account.reserve_resources(0, 1, 1).is_err());
    owner.retire_after_reap();
    assert!(account.reserve_resources(0, 1, 16384).is_ok());
}

#[test]
fn changed_registered_target_cannot_borrow_the_same_original() {
    let supervisor = supervisor();
    let account = HostServiceAllocator::new(1, 2, 16384).unwrap();
    let event = event();
    let mut owner =
        CheckpointOriginal::allocate_registered_owner(&supervisor, &account, target()).unwrap();
    owner.enter(&event).unwrap();
    let mut changed = target();
    changed.owner_generation = 2;

    assert_eq!(
        owner.check(changed).unwrap_err().source,
        CheckpointOriginalCause::Original(HostSupervisionError::InvalidBudget)
    );
    assert!(owner.check(target()).is_ok());
}

#[test]
fn subscriber_refusal_keeps_entered_identity_even_after_capacity_returns() {
    let supervisor = supervisor();
    let account = HostServiceAllocator::new(1, 1, 16384).unwrap();
    let event = event();
    let competing_descriptor = account.reserve_resources(0, 1, 1).unwrap();
    let mut owner =
        CheckpointOriginal::allocate_registered_owner(&supervisor, &account, target()).unwrap();

    let first = owner.enter(&event).unwrap_err();
    let entered = owner
        .body
        .as_ref()
        .unwrap()
        .original
        .as_ref()
        .unwrap()
        .guard();
    let operation_id = entered.status().unwrap().operation_id;
    let first_status = entered.status().unwrap();
    let remaining = first_status.effective_deadline.as_ref().unwrap().remaining;

    assert_eq!(
        first.source,
        CheckpointOriginalCause::Account(HostServiceError::CapacityExhausted)
    );
    assert_eq!(first.original_after, None);
    let retained = CheckpointOriginalError {
        source: first.source,
        original_after: Some(HostSupervisionError::Unavailable),
    };
    // Subscriber admission never completed. Its independent retry postcut
    // reports that absence without replacing the initiating account refusal.
    assert_eq!(owner.enter(&event).unwrap_err(), retained);
    drop(competing_descriptor);
    assert_eq!(owner.enter(&event).unwrap_err(), retained);
    assert_eq!(owner.check(target()).unwrap_err(), retained);
    assert_eq!(owner.body.as_ref().unwrap().first_refusal, Some(first));

    let entered = owner
        .body
        .as_ref()
        .unwrap()
        .original
        .as_ref()
        .unwrap()
        .guard();
    assert_eq!(entered.status().unwrap().operation_id, operation_id);
    assert!(entered.serialize_original_quiescence_basis().is_err());
    assert!(
        entered
            .status()
            .unwrap()
            .effective_deadline
            .as_ref()
            .unwrap()
            .remaining
            <= remaining
    );
    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
    assert!(owner.body.as_ref().unwrap().basis.is_none());
    assert!(account.reserve_resources(0, 1, 16384).is_err());
    owner.retire_after_reap();
    assert!(account.reserve_resources(0, 1, 16384).is_ok());
}

#[test]
fn retained_subscriber_refusal_keeps_first_cause_and_later_raw_postcut() {
    let supervisor = supervisor();
    let account = HostServiceAllocator::new(1, 1, 16384).unwrap();
    let event = event();
    let _competing_descriptor = account.reserve_resources(0, 1, 1).unwrap();
    let mut owner =
        CheckpointOriginal::allocate_registered_owner(&supervisor, &account, target()).unwrap();
    let first = owner.enter(&event).unwrap_err();
    let id = owner
        .body
        .as_ref()
        .unwrap()
        .original
        .as_ref()
        .unwrap()
        .guard()
        .status()
        .unwrap()
        .operation_id;

    supervisor.cancel().unwrap();
    let retry = owner.enter(&event).unwrap_err();

    assert_eq!(retry.source, first.source);
    assert!(retry.original_after.is_some());
    assert_eq!(owner.body.as_ref().unwrap().first_refusal, Some(first));
    assert_eq!(
        owner
            .body
            .as_ref()
            .unwrap()
            .original
            .as_ref()
            .unwrap()
            .guard()
            .status()
            .unwrap()
            .operation_id,
        id
    );
    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
}

#[test]
fn native_alias_is_born_once_and_owned_until_retirement() {
    use std::os::fd::AsRawFd;

    let supervisor = supervisor();
    let account = HostServiceAllocator::new(1, 2, 16384).unwrap();
    let event = event();
    let mut owner =
        CheckpointOriginal::allocate_registered_owner(&supervisor, &account, target()).unwrap();
    owner.enter(&event).unwrap();

    owner.check(target()).unwrap();
    let first_alias = owner
        .body
        .as_ref()
        .unwrap()
        .native_transfer
        .as_ref()
        .unwrap()
        .cancellation
        .as_raw_fd();
    let first_basis = owner.body.as_ref().unwrap().basis.unwrap();
    owner.check(target()).unwrap();

    assert_eq!(
        owner
            .body
            .as_ref()
            .unwrap()
            .native_transfer
            .as_ref()
            .unwrap()
            .cancellation
            .as_raw_fd(),
        first_alias
    );
    assert_eq!(owner.body.as_ref().unwrap().basis.unwrap(), first_basis);
    assert!(account.reserve_resources(0, 1, 1).is_err());
    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
    owner.retire_after_reap();
    assert!(owner.body.is_none());
    assert!(account.reserve_resources(0, 2, 16384).is_ok());
}

#[test]
fn native_alias_admission_refusal_never_restarts_or_duplicates_after_capacity_returns() {
    let supervisor = supervisor();
    let account = HostServiceAllocator::new(1, 2, 16384).unwrap();
    let event = event();
    let mut owner =
        CheckpointOriginal::allocate_registered_owner(&supervisor, &account, target()).unwrap();
    let competing = account.reserve_resources(0, 1, 1).unwrap();

    let first = owner.enter(&event).unwrap_err();
    let id = owner
        .body
        .as_ref()
        .unwrap()
        .original
        .as_ref()
        .unwrap()
        .guard()
        .status()
        .unwrap()
        .operation_id;
    drop(competing);
    let retry = owner.enter(&event).unwrap_err();

    assert_eq!(
        first.source,
        CheckpointOriginalCause::Account(HostServiceError::CapacityExhausted)
    );
    assert_eq!(retry, first);
    assert!(owner.body.as_ref().unwrap().native_transfer.is_none());
    assert!(owner.body.as_ref().unwrap().basis.is_none());
    assert_eq!(
        owner
            .body
            .as_ref()
            .unwrap()
            .original
            .as_ref()
            .unwrap()
            .guard()
            .status()
            .unwrap()
            .operation_id,
        id
    );
    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
    assert!(account.reserve_resources(0, 1, 1).is_ok());
}

#[test]
fn canceled_original_retains_native_alias_and_its_descriptor_credit_until_reap() {
    let supervisor = supervisor();
    let account = HostServiceAllocator::new(1, 2, 16384).unwrap();
    let event = event();
    let mut owner =
        CheckpointOriginal::allocate_registered_owner(&supervisor, &account, target()).unwrap();
    owner.enter(&event).unwrap();
    owner.check(target()).unwrap();

    assert_eq!(rustix::io::write(&event, &1_u64.to_ne_bytes()).unwrap(), 8);
    assert!(owner.check(target()).is_err());

    assert!(owner.body.as_ref().unwrap().native_transfer.is_some());
    assert!(account.reserve_resources(0, 1, 1).is_err());
    owner.retire_after_reap();
    assert!(account.reserve_resources(0, 2, 16384).is_ok());
}

#[test]
fn receiving_refusal_drop_cannot_refund_unreaped_child_custody() {
    let supervisor = supervisor();
    let account = HostServiceAllocator::new(1, 2, 16384).unwrap();
    let event = event();
    let mut owner =
        CheckpointOriginal::allocate_registered_owner(&supervisor, &account, target()).unwrap();
    owner.enter(&event).unwrap();
    owner
        .prepare_receiving(&registration(&account, Arc::new(UnavailableRegistrar)))
        .unwrap_err();

    drop(owner);

    assert!(account.reserve_resources(0, 1, 16384).is_err());
}

#[test]
fn receiving_retry_cannot_replace_basis_or_alias_after_refusal() {
    use std::os::fd::AsRawFd;

    let supervisor = supervisor();
    let account = HostServiceAllocator::new(1, 2, 16384).unwrap();
    let replacement = event();
    let event = event();
    let mut owner =
        CheckpointOriginal::allocate_registered_owner(&supervisor, &account, target()).unwrap();
    owner.enter(&event).unwrap();
    let body = owner.body.as_ref().unwrap();
    let basis = body.basis.unwrap();
    let alias = body
        .native_transfer
        .as_ref()
        .unwrap()
        .cancellation
        .as_raw_fd();
    let first = owner
        .prepare_receiving(&registration(&account, Arc::new(UnavailableRegistrar)))
        .unwrap_err();

    assert_eq!(owner.enter(&replacement).unwrap_err(), first);
    assert_eq!(
        owner
            .prepare_receiving(&registration(&account, Arc::new(UnavailableRegistrar)))
            .unwrap_err(),
        first
    );

    let body = owner.body.as_ref().unwrap();
    assert_eq!(body.basis.unwrap(), basis);
    assert_eq!(
        body.native_transfer
            .as_ref()
            .unwrap()
            .cancellation
            .as_raw_fd(),
        alias
    );
    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
    owner.retire_after_reap();
    assert!(account.reserve_resources(0, 1, 16384).is_ok());
}

struct UnavailableRegistrar;

impl crate::ram_control::RamControlRegistrar for UnavailableRegistrar {
    fn register(
        &self,
        _target: HostRamTarget,
        _policy: crucible_host_resources::ram_policy::HostRamPolicy,
        _resources: crucible_host_resources::ram_policy::HostResourceVector,
        _supervisor: HostOperationSupervisor,
        _client: Option<crate::ram_control::RamControlClient>,
    ) -> Result<(), RamControlError> {
        Err(RamControlError::AuthorityMismatch)
    }
}

fn registration(
    account: &HostServiceAllocator,
    registrar: Arc<dyn crate::ram_control::RamControlRegistrar>,
) -> crate::ram_control::RamControlRegistration {
    use crucible_host_resources::ram_policy::{HostRamMode, HostRamPolicy, HostResourceVector};
    crate::ram_control::RamControlRegistration {
        target: target(),
        initial_policy: HostRamPolicy {
            mode: HostRamMode::ResidentRequired,
            resident_target_bytes: 4096,
            eviction_preference: 0,
            writeback_bytes_per_second: 4096,
            maximum_paging_io_in_flight: 1,
            prefetch_on_increase: false,
            latency: HostOperationBudgets::default(),
        },
        resources: HostResourceVector::default(),
        spill_quota_bytes: 0,
        host_services: account.clone(),
        registrar,
    }
}

mod arm;
mod external;
