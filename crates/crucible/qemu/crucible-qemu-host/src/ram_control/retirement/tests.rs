//! Exercises actual registrar effects and the saved Cleanup's independent post.
//!
//! The registrar is a component owner; no native RAM issuer is modeled.

use super::*;
use crucible_host_resources::host_supervision::{HostOperationBudget, HostOperationBudgets};
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Registrar {
    supervisor: HostOperationSupervisor,
    calls: AtomicUsize,
    returned: RamControlRetirementDisposition,
    fail: bool,
}

impl RamControlRegistrar for Registrar {
    fn register(
        &self,
        _: HostRamTarget,
        _: HostRamPolicy,
        _: HostResourceVector,
        _: HostOperationSupervisor,
        _: Option<RamControlClient>,
    ) -> Result<(), RamControlError> {
        Err(RamControlError::AuthorityMismatch)
    }

    fn prepare_retirement_after_cleanup(&self, _: HostRamTarget) -> RamControlRetirementOutcome {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let (revision, mut budgets) = self.supervisor.budgets().unwrap();
        budgets.classes[HostOperationClass::Cleanup as usize] =
            HostOperationBudget::finite(Duration::from_nanos(1));
        self.supervisor.update_budgets(revision, budgets).unwrap();
        RamControlRetirementOutcome {
            disposition: self.returned,
            failure: self.fail.then_some(RamControlError::AuthorityMismatch),
        }
    }
}

fn registration(
    returned: RamControlRetirementDisposition,
    fail: bool,
) -> Result<(RamControlRegistration, Arc<Registrar>, HostOperationGuard), Box<dyn std::error::Error>>
{
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    let registrar = Arc::new(Registrar {
        supervisor,
        calls: AtomicUsize::new(0),
        returned,
        fail,
    });
    let policy = HostRamPolicy {
        mode: HostRamMode::Managed,
        resident_target_bytes: 4096,
        eviction_preference: 50,
        writeback_bytes_per_second: 4096,
        maximum_paging_io_in_flight: 1,
        prefetch_on_increase: false,
        latency: HostOperationBudgets::default(),
    };
    let registration = RamControlRegistration {
        target: HostRamTarget {
            daemon_epoch: [1; 32],
            owner_id: [2; 32],
            node_id: [3; 32],
            owner_generation: 1,
            arena_generation: 1,
            retained_template: false,
        },
        initial_policy: policy,
        resources: HostResourceVector::default(),
        spill_quota_bytes: 4096,
        host_services: HostServiceAllocator::new(1, 4, 4096)?,
        registrar: registrar.clone(),
    };
    Ok((registration, registrar, original))
}

#[test]
fn actual_controller_return_and_independent_post_failure_do_not_repeat_the_effect()
-> Result<(), Box<dyn std::error::Error>> {
    let (registration, registrar, original) =
        registration(RamControlRetirementDisposition::Returned, true)?;
    let id = original.status()?.operation_id;
    let custody = crate::QemuRamLaunchCustody::new(&registration);
    let mut progress = RamControlRetirementProgress::for_launch(&custody)?;

    let ((returned, status), allocations) =
        crucible_host_resources::test_support::TestAllocationObserver::count(|| {
            progress.return_controller(
                &registration,
                Some(RamCleanupOriginal::direct(&original, &registrar.supervisor)),
            )
        });
    assert_eq!(allocations.allocations, 0);
    assert_eq!(allocations.reallocations, 0);
    assert!(!allocations.overflow);

    assert!(returned);
    let first = status.unwrap_err();
    assert!(matches!(
        first.first.as_ref().and_then(|cause| cause
            .source()
            .and_then(|source| source.source())
            .and_then(|source| source.downcast_ref::<RamControlError>())),
        Some(RamControlError::AuthorityMismatch)
    ));
    assert!(first.before.is_none());
    assert!(
        matches!(first.after, Some(HostSupervisionError::DeadlineExpired { operation_id, .. }) if operation_id == id)
    );
    let ((returned, status), allocations) =
        crucible_host_resources::test_support::TestAllocationObserver::count(|| {
            progress.return_controller(
                &registration,
                Some(RamCleanupOriginal::direct(&original, &registrar.supervisor)),
            )
        });
    assert_eq!(allocations.allocations, 0);
    assert_eq!(allocations.reallocations, 0);
    assert!(!allocations.overflow);
    assert!(returned);
    status?;
    assert_eq!(registrar.calls.load(Ordering::Acquire), 1);
    assert_eq!(progress.history, first);
    Ok(())
}

#[test]
fn unknown_controller_disposition_keeps_same_owner_and_never_replays_the_provider()
-> Result<(), Box<dyn std::error::Error>> {
    let (registration, registrar, original) =
        registration(RamControlRetirementDisposition::Unknown, true)?;
    let custody = crate::QemuRamLaunchCustody::new(&registration);
    let mut progress = RamControlRetirementProgress::for_launch(&custody)?;

    let ((returned, status), allocations) =
        crucible_host_resources::test_support::TestAllocationObserver::count(|| {
            progress.return_controller(
                &registration,
                Some(RamCleanupOriginal::direct(&original, &registrar.supervisor)),
            )
        });
    assert_eq!(allocations.allocations, 0);
    assert_eq!(allocations.reallocations, 0);
    assert!(!allocations.overflow);
    assert!(!returned);
    let first = status.unwrap_err();
    assert!(first.first.is_some());
    assert!(first.after.is_some());
    assert!(first.uncertain);
    let ((returned, status), allocations) =
        crucible_host_resources::test_support::TestAllocationObserver::count(|| {
            progress.return_controller(
                &registration,
                Some(RamCleanupOriginal::direct(&original, &registrar.supervisor)),
            )
        });
    assert_eq!(allocations.allocations, 0);
    assert_eq!(allocations.reallocations, 0);
    assert!(!allocations.overflow);
    assert!(!returned);
    assert_eq!(status.unwrap_err(), first);
    assert_eq!(registrar.calls.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn unprepared_or_foreign_progress_never_enters_the_actual_provider()
-> Result<(), Box<dyn std::error::Error>> {
    let (registration, registrar, original) =
        registration(RamControlRetirementDisposition::Returned, true)?;
    let mut unprepared = RamControlRetirementProgress::new();
    let ((returned, status), allocations) =
        crucible_host_resources::test_support::TestAllocationObserver::count(|| {
            unprepared.return_controller(&registration, None)
        });
    assert!(!returned);
    assert_eq!(
        status.unwrap_err(),
        RamControlRetirementProgress::unavailable()
    );
    assert_eq!(allocations.allocations, 0);
    assert_eq!(allocations.reallocations, 0);
    assert!(!allocations.overflow);
    assert_eq!(registrar.calls.load(Ordering::Acquire), 0);

    let custody = crate::QemuRamLaunchCustody::new(&registration);
    let mut progress = RamControlRetirementProgress::for_launch(&custody)?;
    let other = Arc::new(Registrar {
        supervisor: registrar.supervisor.clone(),
        calls: AtomicUsize::new(0),
        returned: RamControlRetirementDisposition::Returned,
        fail: false,
    });
    for change_registrar in [false, true] {
        let mut foreign = registration.clone();
        if change_registrar {
            foreign.registrar = other.clone();
        } else {
            foreign.target.owner_generation += 1;
        }

        let ((returned, status), allocations) =
            crucible_host_resources::test_support::TestAllocationObserver::count(|| {
                progress.return_controller(
                    &foreign,
                    Some(RamCleanupOriginal::direct(&original, &registrar.supervisor)),
                )
            });
        assert!(!returned);
        assert_eq!(
            status.unwrap_err(),
            RamControlRetirementProgress::unavailable()
        );
        assert_eq!(allocations.allocations, 0);
        assert_eq!(allocations.reallocations, 0);
        assert!(!allocations.overflow);
    }
    assert_eq!(registrar.calls.load(Ordering::Acquire), 0);
    assert_eq!(other.calls.load(Ordering::Acquire), 0);

    let (returned, _) = progress.return_controller(
        &registration,
        Some(RamCleanupOriginal::direct(&original, &registrar.supervisor)),
    );
    assert!(returned);
    assert_eq!(registrar.calls.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn one_launch_permits_only_one_canonical_controller_progress()
-> Result<(), Box<dyn std::error::Error>> {
    let (registration, registrar, _) =
        registration(RamControlRetirementDisposition::Returned, true)?;
    let custody = crate::QemuRamLaunchCustody::new(&registration);
    let mut progress = RamControlRetirementProgress::for_launch(&custody)?;

    let (refused, allocations) =
        crucible_host_resources::test_support::TestAllocationObserver::count(|| {
            RamControlRetirementProgress::for_launch(&custody)
        });
    assert!(matches!(refused, Err(RamControlError::AuthorityMismatch)));
    assert_eq!(allocations.allocations, 0);
    assert_eq!(allocations.reallocations, 0);
    assert!(!allocations.overflow);
    assert!(progress.bind(&custody.cleanup));
    assert_eq!(registrar.calls.load(Ordering::Acquire), 0);
    Ok(())
}
