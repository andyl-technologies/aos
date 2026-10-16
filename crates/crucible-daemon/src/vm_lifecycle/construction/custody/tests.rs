//! Component controls for custody storage and same-owner cleanup retry.
#![cfg(test)]

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct RetainedLauncher {
    calls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    refuse_once: AtomicBool,
    custody: Option<Box<ProductionVmConstructionCustody>>,
}

impl Drop for RetainedLauncher {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl crucible_api::ProductionVmCleanupOwner for RetainedLauncher {
    type Failure = crucible::SchedulerError;

    fn retry_cleanup(&mut self) -> Result<(), crucible::SchedulerError> {
        ProductionVmNodeLauncher::finish(self).map_err(|error| {
            crucible::SchedulerError::BoundaryViolation {
                message: error.to_string(),
            }
        })
    }
}

impl ProductionVmNodeLauncher for RetainedLauncher {
    fn take_construction_custody(&mut self) -> Option<Box<ProductionVmConstructionCustody>> {
        self.custody.take()
    }

    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        Err(LifecycleApiError::ConstructionCustodyUnavailable)
    }

    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        Err(LifecycleApiError::ConstructionCustodyUnavailable)
    }

    fn launch_fresh(
        &mut self,
        _: ProductionVmNodeLaunchRequest<'_>,
        _: &Path,
        _: &Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(LifecycleApiError::ConstructionCustodyUnavailable)
    }

    fn launch_restored(
        &mut self,
        _: ProductionVmNodeLaunchRequest<'_>,
        _: ProductionVmExactNodeRestoreAdmission,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(LifecycleApiError::ConstructionCustodyUnavailable)
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        Err(LifecycleApiError::ConstructionCustodyUnavailable)
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.refuse_once.swap(false, Ordering::SeqCst) {
            Err(LifecycleApiError::ConstructionCustodyUnavailable)
        } else {
            Ok(())
        }
    }
}

fn launcher(
    custody: Option<Box<ProductionVmConstructionCustody>>,
) -> (
    Box<dyn ProductionVmNodeLauncher>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    (
        Box::new(RetainedLauncher {
            calls: Arc::clone(&calls),
            drops: Arc::clone(&drops),
            refuse_once: AtomicBool::new(true),
            custody,
        }),
        calls,
        drops,
    )
}

#[test]
fn absent_storage_keeps_same_launcher_and_first_cause_through_retry() {
    let (launcher, calls, drops) = launcher(None);
    let failure = with_inputs(launcher, None, None, None, Vec::new()).unwrap_err();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 0);

    assert!(failure.retry_cleanup().is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(
        failure.first(),
        Some(&LifecycleApiError::ConstructionCustodyUnavailable)
    );

    failure.retry_cleanup().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(
        failure.first(),
        Some(&LifecycleApiError::ConstructionCustodyUnavailable)
    );
    drop(failure);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn rejected_assembly_returns_the_same_partial_owner_without_new_storage() {
    let (launcher, calls, drops) = launcher(Some(Box::new(ProductionVmConstructionCustody::new())));
    let mut custody = with_inputs(launcher, None, None, None, Vec::new()).unwrap();
    let address = (&*custody as *const ProductionVmConstructionCustody) as usize;
    let first = custody.complete_with(Err).unwrap_err();
    let failure = custody.into_failure(first.clone());
    let custody = failure.into_custody().unwrap();
    assert_eq!(
        (&*custody as *const ProductionVmConstructionCustody) as usize,
        address
    );

    assert!(custody.retry_cleanup().is_err());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    custody.retry_cleanup().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(custody.first.as_ref(), Some(&first));
    custody.retry_cleanup().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(custody);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn returned_lifecycle_moves_into_the_same_empty_carrier() {
    let source = crucible::crash_restart_scenario().unwrap().scenario;
    let mut lifecycle =
        crate::vm_lifecycle::runtime::tests::production_loop_without_backends(&source);
    let carrier = Box::new(ProductionVmConstructionCustody {
        first: None,
        phase: Mutex::new(Phase::Empty),
        physically_closed: AtomicBool::new(false),
        #[cfg(target_os = "linux")]
        reservation: None,
    });
    let address = std::ptr::from_ref(&*carrier);
    lifecycle.construction_custody = Some(carrier);

    let carrier = lifecycle
        .into_construction_custody()
        .unwrap_or_else(|_| panic!("original empty carrier must retain its returned lifecycle"));

    assert_eq!(std::ptr::from_ref(&*carrier), address);
    assert!(carrier.first.is_none());
    assert!(matches!(
        &*carrier.phase.lock().unwrap(),
        Phase::Complete(_)
    ));
}

#[test]
fn missing_retirement_carrier_returns_the_same_lifecycle_and_resources() {
    struct DropWitness(Arc<AtomicUsize>);

    impl Drop for DropWitness {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let source = crucible::crash_restart_scenario().unwrap().scenario;
    let mut lifecycle =
        crate::vm_lifecycle::runtime::tests::production_loop_without_backends(&source);
    let drops = Arc::new(AtomicUsize::new(0));
    lifecycle
        .retained_hot_fork_disk_owners
        .push(Box::new(DropWitness(Arc::clone(&drops))));

    let lifecycle = match lifecycle.into_construction_custody() {
        Ok(_) => panic!("absent carrier must not be fabricated"),
        Err(lifecycle) => lifecycle,
    };

    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert!(lifecycle.construction_custody.is_none());
    drop(lifecycle);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
