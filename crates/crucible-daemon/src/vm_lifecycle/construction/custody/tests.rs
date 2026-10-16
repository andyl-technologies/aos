//! Component controls for custody storage and same-owner cleanup retry.
#![cfg(test)]

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct RetainedLauncher {
    calls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    refuse_once: AtomicBool,
    custody: Option<Box<ProductionVmConstructionCustody>>,
    raw_failure: Option<crate::QemuAttemptResourceGuardCleanupFailure>,
    retained_failure: Option<ProductionVmConstructionFailure>,
}

impl Drop for RetainedLauncher {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl crucible_api::ProductionVmCleanupOwner for RetainedLauncher {
    type Failure = crate::ProductionVmConstructionCleanupError;

    fn retry_cleanup(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        ProductionVmNodeLauncher::finish(self)
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

    fn finish(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(failure) = self.retained_failure.as_ref() {
            return failure.retry_cleanup();
        }
        if let Some(failure) = self.raw_failure.take() {
            return Err(failure.into());
        }
        if self.refuse_once.swap(false, Ordering::SeqCst) {
            Err((LifecycleApiError::ConstructionCustodyUnavailable).into())
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
            raw_failure: None,
            retained_failure: None,
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

#[derive(Debug)]
struct OwnedComponentCause {
    file: File,
    name: &'static str,
}

impl fmt::Display for OwnedComponentCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name)
    }
}

impl Error for OwnedComponentCause {}

struct CauseProbe {
    descriptor: std::os::fd::RawFd,
    identity: (u64, u64),
    address: *const OwnedComponentCause,
}

impl CauseProbe {
    fn is_open(&self) -> bool {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(format!("/proc/self/fd/{}", self.descriptor))
            .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == self.identity)
    }

    fn assert_same_leaf(&self, failure: &crate::QemuAttemptResourceGuardCleanupFailure) {
        let crucible_qemu::QemuVmRealizationError::ModelCopy { source } = failure.error() else {
            panic!("the actual owned component leaf was erased");
        };
        let actual = source.downcast_ref::<OwnedComponentCause>().unwrap();
        assert!(std::ptr::eq(actual, self.address));
        assert!(self.is_open());
        assert!(
            !failure.was_quarantined(),
            "a refusal did not transfer this owner"
        );
    }
}

fn raw_launcher(
    name: &'static str,
    custody: Option<Box<ProductionVmConstructionCustody>>,
) -> (
    Box<dyn ProductionVmNodeLauncher>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    CauseProbe,
) {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let cause = Box::new(OwnedComponentCause {
        file: tempfile::tempfile().unwrap(),
        name,
    });
    let metadata = cause.file.metadata().unwrap();
    let probe = CauseProbe {
        descriptor: cause.file.as_raw_fd(),
        identity: (metadata.dev(), metadata.ino()),
        address: std::ptr::from_ref(&*cause),
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let launcher = Box::new(RetainedLauncher {
        calls: Arc::clone(&calls),
        drops: Arc::clone(&drops),
        refuse_once: AtomicBool::new(false),
        custody,
        raw_failure: Some(crate::QemuAttemptResourceGuardCleanupFailure::retained(
            crucible_qemu::QemuVmRealizationError::ModelCopy { source: cause },
        )),
        retained_failure: None,
    });
    (launcher, calls, drops, probe)
}

#[test]
fn rejected_two_body_cleanup_keeps_both_leaves_through_actual_queued_destruction() {
    // Local launchers own real files but refuse all execution operations. This
    // exercises existing carrier/cell custody, not Main or native admission.
    let (existing_launcher, existing_calls, existing_drops, existing_cause) =
        raw_launcher("existing carrier", None);
    let mut existing = Box::new(ProductionVmConstructionCustody::new());
    existing.first = Some(LifecycleApiError::ConstructionCustodyUnavailable);
    existing.partial_mut().unwrap().node_launcher = Some(existing_launcher);
    let (incoming_launcher, incoming_calls, incoming_drops, incoming_cause) =
        raw_launcher("incoming partial", Some(existing));
    let failure = with_inputs(incoming_launcher, None, None, None, Vec::new()).unwrap_err();
    let wrapper_calls = Arc::new(AtomicUsize::new(0));
    let wrapper_drops = Arc::new(AtomicUsize::new(0));
    let wrapper = Box::new(RetainedLauncher {
        calls: Arc::clone(&wrapper_calls),
        drops: Arc::clone(&wrapper_drops),
        refuse_once: AtomicBool::new(false),
        custody: None,
        raw_failure: None,
        retained_failure: Some(failure),
    });

    let history = crate::lifecycle_cleanup::component_owner_history_for_test(wrapper, || {
        assert_eq!(incoming_calls.load(Ordering::SeqCst), 1);
        assert_eq!(existing_calls.load(Ordering::SeqCst), 1);
        assert_eq!(incoming_drops.load(Ordering::SeqCst), 0);
        assert_eq!(existing_drops.load(Ordering::SeqCst), 0);
        assert!(incoming_cause.is_open());
        assert!(existing_cause.is_open());
    });

    assert_eq!(wrapper_calls.load(Ordering::SeqCst), 2);
    assert_eq!(wrapper_drops.load(Ordering::SeqCst), 1);
    assert_eq!(incoming_calls.load(Ordering::SeqCst), 2);
    assert_eq!(existing_calls.load(Ordering::SeqCst), 2);
    assert_eq!(incoming_drops.load(Ordering::SeqCst), 1);
    assert_eq!(existing_drops.load(Ordering::SeqCst), 1);
    let ProductionVmConstructionCleanupError::GuardPair {
        first:
            Some(ProductionVmCleanupEarlierFailure::Scheduler(SchedulerError::BoundaryViolation {
                message,
            })),
        first_guard,
        second_guard,
    } = &history
    else {
        panic!("both independently owned bodies must retain their actual leaves: {history:?}");
    };
    assert_eq!(message, "retained lifecycle cleanup cell was poisoned");
    incoming_cause.assert_same_leaf(first_guard);
    existing_cause.assert_same_leaf(second_guard);
    drop(history);
    assert!(!incoming_cause.is_open());
    assert!(!existing_cause.is_open());
}

struct BoxedLoopOwner(Arc<AtomicUsize>);

impl Drop for BoxedLoopOwner {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn boxed_retirement_lifecycle() -> (Box<ProductionVmLifecycleLoop>, Arc<AtomicUsize>) {
    let source = crucible::crash_restart_scenario().unwrap().scenario;
    let mut lifecycle =
        Box::new(crate::vm_lifecycle::runtime::tests::production_loop_without_backends(&source));
    let drops = Arc::new(AtomicUsize::new(0));
    lifecycle
        .retained_hot_fork_disk_owners
        .push(Box::new(BoxedLoopOwner(Arc::clone(&drops))));
    (lifecycle, drops)
}

fn empty_retirement_carrier() -> Box<ProductionVmConstructionCustody> {
    Box::new(ProductionVmConstructionCustody {
        first: None,
        phase: Mutex::new(Phase::Empty),
        physically_closed: AtomicBool::new(false),
        #[cfg(target_os = "linux")]
        reservation: None,
    })
}

#[test]
fn boxed_retirement_refusal_keeps_same_allocation_carrier_and_contained_owner() {
    enum CarrierState {
        Missing,
        Occupied,
        Poisoned,
    }

    for state in [
        CarrierState::Missing,
        CarrierState::Occupied,
        CarrierState::Poisoned,
    ] {
        let (mut lifecycle, drops) = boxed_retirement_lifecycle();
        let (launcher, calls, launcher_drops) = launcher(None);
        lifecycle.node_launcher = launcher;
        let carrier = match state {
            CarrierState::Missing => None,
            CarrierState::Occupied => Some(Box::new(ProductionVmConstructionCustody::new())),
            CarrierState::Poisoned => {
                let carrier = empty_retirement_carrier();
                let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _phase = carrier.phase.lock().unwrap();
                    panic!("poison the actual carrier phase");
                }));
                assert!(poisoned.is_err());
                Some(carrier)
            }
        };
        let carrier_address = carrier.as_deref().map(std::ptr::from_ref);
        lifecycle.construction_custody = carrier;
        let lifecycle_address = std::ptr::from_ref(&*lifecycle);
        let owner_address = std::ptr::from_ref(&*lifecycle.retained_hot_fork_disk_owners[0]);

        let lifecycle = match lifecycle.into_construction_custody_from_box() {
            Ok(_) => panic!("unusable original storage cannot accept the Loop"),
            Err(lifecycle) => lifecycle,
        };

        assert_eq!(std::ptr::from_ref(&*lifecycle), lifecycle_address);
        assert_eq!(
            lifecycle
                .construction_custody
                .as_deref()
                .map(std::ptr::from_ref),
            carrier_address,
        );
        assert!(std::ptr::addr_eq(
            std::ptr::from_ref(&*lifecycle.retained_hot_fork_disk_owners[0]),
            owner_address,
        ));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(launcher_drops.load(Ordering::SeqCst), 0);
        drop(lifecycle);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(launcher_drops.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn boxed_retirement_moves_loop_and_owners_into_the_original_carrier() {
    let (mut lifecycle, drops) = boxed_retirement_lifecycle();
    let (launcher, calls, launcher_drops) = launcher(None);
    lifecycle.node_launcher = launcher;
    let carrier = empty_retirement_carrier();
    let carrier_address = std::ptr::from_ref(&*carrier);
    let owner_address = std::ptr::from_ref(&*lifecycle.retained_hot_fork_disk_owners[0]);
    lifecycle.construction_custody = Some(carrier);

    let carrier = lifecycle
        .into_construction_custody_from_box()
        .unwrap_or_else(|_| panic!("original empty carrier must retain the boxed Loop"));

    assert_eq!(std::ptr::from_ref(&*carrier), carrier_address);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    let phase = carrier.phase.lock().unwrap();
    let Phase::Complete(lifecycle) = &*phase else {
        panic!("the original carrier must own the complete Loop");
    };
    assert!(lifecycle.construction_custody.is_none());
    assert!(std::ptr::addr_eq(
        std::ptr::from_ref(&*lifecycle.retained_hot_fork_disk_owners[0]),
        owner_address,
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(launcher_drops.load(Ordering::SeqCst), 0);
    drop(phase);
    drop(carrier);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(launcher_drops.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
