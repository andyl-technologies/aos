//! QEMU attempt resource ownership and cleanup regression tests.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::ProductionVmNodeLauncher;
use crucible_engine::ContentHash;
use crucible_campaign::ExactCheckpointId;

use crucible_store::content_store::{ContentId, ObjectKind};

use super::*;

#[derive(Debug, Default)]
struct HostCounters {
    begins: AtomicUsize,
    fork_targets_owned: AtomicUsize,
    checks: AtomicUsize,
    signals: AtomicUsize,
    finishes: AtomicUsize,
    quarantines: AtomicUsize,
    selected_roots: Mutex<Vec<ContentHash>>,
}

struct FakeHostFactory {
    installed: AttemptResourceLimits,
    counters: Arc<HostCounters>,
    signal_error: bool,
    signal_panics: bool,
    finish_error: bool,
}

impl QemuAttemptHostResourceFactory for FakeHostFactory {
    type Owner = FakeHostOwner;

    fn begin(
        &mut self,
        _resources: AttemptResourceLimits,
    ) -> Result<Self::Owner, QemuVmRealizationError> {
        self.begin_with_root(None)
    }
}

impl FakeHostFactory {
    fn begin_with_root(
        &mut self,
        exact_checkpoint_root: Option<ContentHash>,
    ) -> Result<FakeHostOwner, QemuVmRealizationError> {
        self.counters.begins.fetch_add(1, Ordering::SeqCst);
        let (cgroup_procs, _cgroup_peer) =
            UnixStream::pair().expect("cgroup process contract descriptors");
        let (cancellation_event, _cancellation_peer) =
            UnixStream::pair().expect("cancellation process contract descriptors");
        if let Some(root) = exact_checkpoint_root {
            self.counters
                .selected_roots
                .lock()
                .expect("selected-root fixture lock")
                .push(root);
        }
        let process_contract = QemuChildProcessContract::from_unvalidated_test_descriptors(
            cgroup_procs.into(),
            cancellation_event.into(),
            self.installed.maximum_vcpus(),
            self.installed.maximum_resident_bytes(),
            self.installed.maximum_disk_bytes(),
        );
        Ok(FakeHostOwner {
            installed: self.installed,
            process_contract,
            counters: Arc::clone(&self.counters),
            signal_error: self.signal_error,
            signal_panics: self.signal_panics,
            finish_error: self.finish_error,
            terminal: false,
        })
    }
}

struct RetrySelectedHostFactory {
    host: FakeHostFactory,
    fail_next_selected_begin: bool,
}

impl QemuAttemptHostResourceFactory for RetrySelectedHostFactory {
    type Owner = FakeHostOwner;

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
    ) -> Result<Self::Owner, QemuVmRealizationError> {
        self.host.begin(resources)
    }
}

impl QemuAttemptSelectedHostResourceFactory for RetrySelectedHostFactory {
    fn begin_selected(
        &mut self,
        _resources: AttemptResourceLimits,
        selected_checkpoint: Option<SelectedExactCheckpointRoot>,
    ) -> Result<
        (Self::Owner, Option<SelectedExactCheckpointRoot>),
        QemuAttemptResourceGuardBeginFailure,
    > {
        if self.fail_next_selected_begin {
            self.fail_next_selected_begin = false;
            return Err(
                QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                    QemuVmRealizationError::ExecutorUnavailable {
                        operation: "begin exact test host resources",
                        message: String::from("injected clean resource-allocation failure"),
                    },
                    selected_checkpoint,
                ),
            );
        }

        let exact_root = selected_checkpoint
            .as_ref()
            .map(SelectedExactCheckpointRoot::process_contract_root);
        match self.host.begin_with_root(exact_root) {
            Ok(owner) => Ok((owner, selected_checkpoint)),
            Err(error) => Err(
                QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                    error,
                    selected_checkpoint,
                ),
            ),
        }
    }
}

impl QemuAttemptSelectedHostResourceFactory for FakeHostFactory {
    fn begin_selected(
        &mut self,
        resources: AttemptResourceLimits,
        selected_checkpoint: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Result<
        (Self::Owner, Option<SelectedExactCheckpointRoot>),
        QemuAttemptResourceGuardBeginFailure,
    > {
        if selected_checkpoint.is_some() {
            return Err(
                QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                    QemuVmRealizationError::Executor {
                        operation: "begin fake host resources",
                        message: String::from("fake host cannot preseal an exact checkpoint root"),
                    },
                    selected_checkpoint,
                ),
            );
        }
        self.begin(resources)
            .map(|owner| (owner, None))
            .map_err(QemuAttemptResourceGuardBeginFailure::after_checkpoint_claim)
    }
}

struct FakeHostOwner {
    installed: AttemptResourceLimits,
    process_contract: QemuChildProcessContract,
    counters: Arc<HostCounters>,
    signal_error: bool,
    signal_panics: bool,
    finish_error: bool,
    terminal: bool,
}

impl QemuAttemptHostResourceOwner for FakeHostOwner {
    #[cfg(target_os = "linux")]
    fn fork_target_is_owned(&self) -> bool {
        self.counters.fork_targets_owned.load(Ordering::Acquire) != 0
    }

    type CancellationSignal = FakeCancellationSignal;

    #[cfg(feature = "private-measurement-domain")]
    fn finish_with_original_registry(
        &mut self,
        _registry: &crate::HostOperationalRegistry,
    ) -> Result<(), QemuVmRealizationError> {
        if !self.finish_error {
            return self.finish();
        }
        self.counters.finishes.fetch_add(1, Ordering::SeqCst);
        use crucible_host_resources::host_supervision::{
            HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
        };
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)
            .expect("finite mechanism supervisor");
        let original = supervisor
            .begin(HostOperationClass::Preparation)
            .expect("same mechanism original");
        supervisor
            .cancel()
            .expect("actual independent post refusal");
        let post = original.wait_slice().expect_err("same original canceled");
        Err(QemuVmRealizationError::ModelCopy {
            source: Box::new(
                crucible_qemu_host::OriginalActorAccountError::NativeControlBoundary {
                    source: crucible_qemu_host::LinuxQemuNativeResourceError::Retired,
                    original: Some(post),
                },
            ),
        })
    }

    fn resource_limits(&self) -> AttemptResourceLimits {
        self.installed
    }

    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        Ok(&self.process_contract)
    }

    fn prepare_generation_run_directory(
        &mut self,
        _requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        Err(QemuVmRealizationError::Executor {
            operation: "prepare fake QEMU run directory",
            message: String::from("fake host does not provision run directories"),
        })
    }

    fn cancellation_signal(&self) -> Result<Self::CancellationSignal, QemuVmRealizationError> {
        Ok(FakeCancellationSignal {
            counters: Arc::clone(&self.counters),
            fail: self.signal_error,
            panic: self.signal_panics,
        })
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        self.counters.checks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn retain_failed_launch_child(&mut self, _child: QemuNodeChild) {}

    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.terminal {
            return Ok(());
        }
        self.counters.finishes.fetch_add(1, Ordering::SeqCst);
        if self.finish_error {
            return Err(QemuVmRealizationError::ExecutorUnavailable {
                operation: "finish fake host resources",
                message: String::from("reap is unavailable"),
            });
        }
        self.terminal = true;
        Ok(())
    }

    fn quarantine(&mut self) {
        if !self.terminal {
            self.counters.quarantines.fetch_add(1, Ordering::SeqCst);
            self.terminal = true;
        }
    }
}

impl QemuHotForkChildProcessOwner for FakeHostOwner {
    type Authority = ();

    fn retain_hot_fork_child(
        &mut self,
        _basis: QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        Ok(())
    }
}

#[derive(Debug)]
struct FakeCancellationSignal {
    counters: Arc<HostCounters>,
    fail: bool,
    panic: bool,
}

impl QemuAttemptCancellationSignal for FakeCancellationSignal {
    fn signal(&self) -> Result<(), QemuVmRealizationError> {
        self.counters.signals.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panic, "injected cancellation signal panic");
        if self.fail {
            Err(QemuVmRealizationError::Executor {
                operation: "signal fake process cancellation",
                message: String::from("sticky signal failed"),
            })
        } else {
            Ok(())
        }
    }
}

fn resources(quanta: u64) -> AttemptResourceLimits {
    AttemptResourceLimits::new(2, 64 * 1024 * 1024, 128 * 1024 * 1024, quanta)
        .expect("attempt resources")
}

fn selected_checkpoint(label: &[u8]) -> (ExactCheckpointId, SelectedExactCheckpointRoot) {
    let checkpoint =
        ExactCheckpointId::try_from(ContentId::for_bytes(ObjectKind::ExactManifest, 6, label))
            .expect("build selected exact checkpoint ID");
    let selected = SelectedExactCheckpointRoot::from_test_checkpoint(checkpoint);
    (checkpoint, selected)
}

fn factory(
    installed: AttemptResourceLimits,
    counters: Arc<HostCounters>,
) -> ComposedQemuAttemptResourceGuardFactory<FakeHostFactory> {
    ComposedQemuAttemptResourceGuardFactory::new(FakeHostFactory {
        installed,
        counters,
        signal_error: false,
        signal_panics: false,
        finish_error: false,
    })
}

#[test]
fn composed_guard_retains_hot_fork_process_authority_without_splitting_host_resources() {
    fn require_complete_owner<T>()
    where
        T: QemuAttemptResourceGuard + QemuHotForkChildProcessOwner<Authority = ()>,
    {
    }

    require_complete_owner::<ComposedQemuAttemptResourceGuard<FakeHostOwner>>();
}

#[test]
fn fixed_workers_share_one_host_allocator_without_sharing_attempt_owners() {
    let resources = resources(2);
    let counters = Arc::new(HostCounters::default());
    let shared = SharedQemuAttemptHostResourceFactory::new(FakeHostFactory {
        installed: resources,
        counters: Arc::clone(&counters),
        signal_error: false,
        signal_panics: false,
        finish_error: false,
    });
    let mut first = ComposedQemuAttemptResourceGuardFactory::new(shared.clone());
    let mut second = ComposedQemuAttemptResourceGuardFactory::new(shared.clone());
    assert_eq!(shared.strong_count(), 3);

    let first = thread::spawn(move || {
        let mut guard = first
            .begin(resources, ExecutionCancellation::default(), None)
            .expect("first shared guard");
        guard.finish().expect("finish first shared guard");
    });
    let second = thread::spawn(move || {
        let mut guard = second
            .begin(resources, ExecutionCancellation::default(), None)
            .expect("second shared guard");
        guard.finish().expect("finish second shared guard");
    });
    first.join().expect("first worker");
    second.join().expect("second worker");

    assert_eq!(counters.begins.load(Ordering::SeqCst), 2);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 2);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn clean_selected_resource_failure_returns_the_one_shot_claim_for_retry() {
    let resources = resources(2);
    let counters = Arc::new(HostCounters::default());
    let mut factory = ComposedQemuAttemptResourceGuardFactory::new(RetrySelectedHostFactory {
        host: FakeHostFactory {
            installed: resources,
            counters: Arc::clone(&counters),
            signal_error: false,
            signal_panics: false,
            finish_error: false,
        },
        fail_next_selected_begin: true,
    });
    let (checkpoint, selected) = selected_checkpoint(b"retry selected exact checkpoint");

    let failure = match factory.begin(resources, ExecutionCancellation::default(), Some(selected)) {
        Ok(_) => panic!("injected first allocation failure unexpectedly succeeded"),
        Err(failure) => failure,
    };
    let (error, selected) = failure.into_parts();
    assert!(matches!(
        error.first_error(),
        QemuVmRealizationError::ExecutorUnavailable { .. }
    ));
    assert!(!error.was_quarantined());
    assert!(error.cleanup_error().is_none());
    let selected = selected.expect("clean failure retains selected-root authority");
    assert!(selected.authorizes(checkpoint));

    let mut guard = factory
        .begin(resources, ExecutionCancellation::default(), Some(selected))
        .expect("retry installs the exact presealed resource guard");
    guard.finish().expect("finish retried exact guard");

    assert_eq!(counters.begins.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn selected_resource_cleanup_failure_spends_the_claim_and_quarantines() {
    let requested = resources(2);
    let installed = resources(3);
    let counters = Arc::new(HostCounters::default());
    let mut factory = ComposedQemuAttemptResourceGuardFactory::new(RetrySelectedHostFactory {
        host: FakeHostFactory {
            installed,
            counters: Arc::clone(&counters),
            signal_error: false,
            signal_panics: false,
            finish_error: true,
        },
        fail_next_selected_begin: false,
    });
    let (_, selected) = selected_checkpoint(b"quarantined selected exact checkpoint");

    let failure = match factory.begin(requested, ExecutionCancellation::default(), Some(selected)) {
        Ok(_) => panic!("mismatched resource installation unexpectedly succeeded"),
        Err(failure) => failure,
    };
    let (error, selected) = failure.into_parts();

    assert!(matches!(
        error.first_error(),
        QemuVmRealizationError::Executor {
            operation: "install QEMU host resources",
            ..
        }
    ));
    assert!(error.was_quarantined());
    assert!(matches!(
        error.cleanup_error(),
        Some(QemuVmRealizationError::ExecutorUnavailable {
            operation: "finish fake host resources",
            ..
        })
    ));
    assert!(
        selected.is_none(),
        "quarantined ownership must consume the selected-root claim"
    );
    assert_eq!(counters.begins.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
}

#[test]
fn replay_targets_share_one_selected_guard_and_quantum_ceiling() {
    let resources = resources(2);
    let counters = Arc::new(HostCounters::default());
    let mut factory = ComposedQemuAttemptResourceGuardFactory::new(RetrySelectedHostFactory {
        host: FakeHostFactory {
            installed: resources,
            counters: Arc::clone(&counters),
            signal_error: false,
            signal_panics: false,
            finish_error: false,
        },
        fail_next_selected_begin: false,
    });
    let (_, selected) = selected_checkpoint(b"aggregate replay exact checkpoint");
    let selected_root = selected.process_contract_root();
    let mut guard = factory
        .begin(resources, ExecutionCancellation::default(), Some(selected))
        .expect("install one aggregate replay guard");

    let first_contract = guard
        .child_process_contract()
        .expect("first replay target contract")
        as *const QemuChildProcessContract;
    guard
        .charge_execution_quantum()
        .expect("charge first replay target");
    let second_contract = guard
        .child_process_contract()
        .expect("second replay target contract")
        as *const QemuChildProcessContract;
    guard
        .charge_execution_quantum()
        .expect("charge second replay target");

    assert_eq!(first_contract, second_contract);
    assert!(matches!(
        guard.charge_execution_quantum(),
        Err(QemuVmRealizationError::Executor {
            operation: "charge QEMU execution quantum",
            ..
        })
    ));
    guard.finish().expect("finish aggregate replay guard");

    assert_eq!(
        counters
            .selected_roots
            .lock()
            .expect("selected-root fixture lock")
            .as_slice(),
        &[selected_root]
    );
    assert_eq!(counters.begins.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn cancellation_signals_process_synchronously_and_unregisters_on_finish() {
    let resources = resources(2);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    let cancellation = ExecutionCancellation::default();
    let mut guard = factory
        .begin(resources, cancellation.clone(), None)
        .expect("composed resource guard");

    cancellation.cancel_for_test();
    assert_eq!(counters.signals.load(Ordering::SeqCst), 1);
    assert!(matches!(
        guard.check_operational_boundary(),
        Err(QemuVmRealizationError::Canceled { .. })
    ));
    guard.finish().expect("finish composed guard");

    cancellation.cancel_for_test();
    assert_eq!(counters.signals.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

// These exercise host composition only. FakeHostFactory has no Main, Source
// issuer or native Target permit; none of these controls claims native birth.
#[cfg(target_os = "linux")]
#[test]
fn retained_target_composition_keeps_mismatched_host_without_cleanup() {
    let admitted = resources(2);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources(3), Arc::clone(&counters));
    let mut host = Some(factory.host.begin_with_root(None).expect("component host"));
    let original = host.as_ref().expect("retained host") as *const FakeHostOwner;

    let outcome = ComposedQemuAttemptResourceGuard::from_retained_target_host(
        &mut host,
        admitted,
        ExecutionCancellation::default(),
    );

    assert!(matches!(
        outcome,
        Err(QemuVmRealizationError::ExecutorUnavailable { .. })
    ));
    assert!(std::ptr::eq(
        host.as_ref().expect("same retained host"),
        original
    ));
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
    host.as_mut()
        .expect("same retained host")
        .finish()
        .expect("actual cleanup");
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn retained_target_hook_refusal_keeps_both_actual_owners_separate() {
    let admitted = resources(2);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(admitted, Arc::clone(&counters));
    let cancellation = ExecutionCancellation::default();
    let mut first = factory
        .begin(admitted, cancellation.clone(), None)
        .expect("first component owner with actual hook");
    let mut second_host = Some(
        factory
            .host
            .begin_with_root(None)
            .expect("second component host"),
    );

    let refused = ComposedQemuAttemptResourceGuard::from_retained_target_host(
        &mut second_host,
        admitted,
        cancellation.clone(),
    );

    assert!(matches!(
        refused,
        Err(QemuVmRealizationError::Executor { .. })
    ));
    assert!(second_host.is_some());
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
    cancellation.cancel_for_test();
    assert_eq!(counters.signals.load(Ordering::SeqCst), 1);
    second_host
        .as_mut()
        .expect("same second host")
        .finish()
        .expect("second host cleanup");
    first.finish().expect("first host cleanup");
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 2);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn retained_target_post_refusal_returns_actual_guard_before_cleanup() {
    let admitted = resources(2);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(admitted, Arc::clone(&counters));
    let mut host = Some(factory.host.begin_with_root(None).expect("component host"));
    let cancellation = ExecutionCancellation::default();
    cancellation.cancel_for_test();

    let (mut guard, first_post) = ComposedQemuAttemptResourceGuard::from_retained_target_host(
        &mut host,
        admitted,
        cancellation,
    )
    .expect("guard is retained independently of its post refusal");

    assert!(host.is_none());
    assert!(matches!(
        first_post,
        Some(QemuVmRealizationError::Canceled { .. })
    ));
    assert_eq!(counters.signals.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
    guard.finish().expect("same guard cleanup");
    guard.finish().expect("idempotent physical cleanup");
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn retained_target_healthy_composition_keeps_one_actual_host_and_hook() {
    let admitted = resources(2);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(admitted, Arc::clone(&counters));
    let mut host = Some(factory.host.begin_with_root(None).expect("component host"));
    let cancellation = ExecutionCancellation::default();

    let (mut guard, first_post) = ComposedQemuAttemptResourceGuard::from_retained_target_host(
        &mut host,
        admitted,
        cancellation.clone(),
    )
    .expect("actual component guard");

    assert!(host.is_none());
    assert!(first_post.is_none());
    assert_eq!(counters.begins.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
    guard.finish().expect("same actual guard cleanup");
    cancellation.cancel_for_test();
    assert_eq!(counters.signals.load(Ordering::SeqCst), 0);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn cancellation_that_wins_before_begin_signals_and_rolls_back() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    let cancellation = ExecutionCancellation::default();
    cancellation.cancel_for_test();

    let error = match factory.begin(resources, cancellation, None) {
        Ok(_) => panic!("pre-canceled guard unexpectedly installed"),
        Err(failure) => failure.into_parts().0,
    };
    assert!(matches!(
        error.first_error(),
        QemuVmRealizationError::Canceled { .. }
    ));
    assert_eq!(counters.signals.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn guard_charges_the_exact_quantum_ceiling() {
    let resources = resources(2);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, counters);
    let mut guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("composed resource guard");

    assert!(guard.charge_execution_quantum().is_ok());
    assert!(guard.charge_execution_quantum().is_ok());
    assert!(matches!(
        guard.charge_execution_quantum(),
        Err(QemuVmRealizationError::Executor { .. })
    ));
    guard.finish().expect("finish composed guard");
}

#[test]
fn production_lifecycle_launcher_charges_the_attempt_quantum_ceiling() {
    let resources = resources(2);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, counters);
    let storage = test_generation_storage(&["vm-a"]);
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("composed resource guard");
    let owner = QemuAttemptGenerationResourceOwner::new(guard, storage);
    let mut launcher = crate::QemuAttemptProductionVmNodeLauncher::new(owner);

    assert!(launcher.begin_execution_quantum().is_ok());
    assert!(launcher.check_operational_boundary().is_ok());
    assert!(launcher.begin_execution_quantum().is_ok());
    assert!(matches!(
        launcher.begin_execution_quantum(),
        Err(LifecycleApiError::AttemptOperational {
            class: SchedulerOperationalFailureClass::Terminal,
            ..
        })
    ));
    launcher.finish().expect("finish lifecycle launcher");
}

#[test]
fn production_lifecycle_launcher_preserves_cancellation_class() {
    let resources = resources(2);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, counters);
    let cancellation = ExecutionCancellation::default();
    let storage = test_generation_storage(&["vm-a"]);
    let guard = factory
        .begin(resources, cancellation.clone(), None)
        .expect("composed resource guard");
    let owner = QemuAttemptGenerationResourceOwner::new(guard, storage);
    let mut launcher = crate::QemuAttemptProductionVmNodeLauncher::new(owner);

    cancellation.cancel_for_test();
    assert!(matches!(
        launcher.check_operational_boundary(),
        Err(LifecycleApiError::AttemptOperational {
            class: SchedulerOperationalFailureClass::Canceled,
            ..
        })
    ));
    launcher.finish().expect("finish lifecycle launcher");
}

#[test]
fn mismatched_host_limits_are_released_before_rejection() {
    let requested = resources(1);
    let installed = AttemptResourceLimits::new(
        requested.maximum_vcpus() + 1,
        requested.maximum_resident_bytes(),
        requested.maximum_disk_bytes(),
        requested.maximum_execution_quanta(),
    )
    .expect("mismatched resources");
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(installed, Arc::clone(&counters));

    assert!(matches!(
        factory.begin(requested, ExecutionCancellation::default(), None),
        Err(QemuAttemptResourceGuardBeginFailure { .. })
    ));
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn one_execution_cannot_install_two_process_hooks() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let cancellation = ExecutionCancellation::default();
    let mut first_factory = factory(resources, Arc::clone(&counters));
    let mut second_factory = factory(resources, Arc::clone(&counters));
    let mut first = first_factory
        .begin(resources, cancellation.clone(), None)
        .expect("first resource guard");

    assert!(matches!(
        second_factory.begin(resources, cancellation, None),
        Err(QemuAttemptResourceGuardBeginFailure { .. })
    ));
    assert_eq!(counters.begins.load(Ordering::SeqCst), 2);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    first.finish().expect("finish first resource guard");
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 2);
}

#[test]
fn cancellation_signal_failure_is_a_terminal_operational_error() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut factory = ComposedQemuAttemptResourceGuardFactory::new(FakeHostFactory {
        installed: resources,
        counters: Arc::clone(&counters),
        signal_error: true,
        signal_panics: false,
        finish_error: false,
    });
    let cancellation = ExecutionCancellation::default();
    let mut guard = factory
        .begin(resources, cancellation.clone(), None)
        .expect("resource guard before cancellation");

    cancellation.cancel_for_test();
    assert!(matches!(
        guard.check_operational_boundary(),
        Err(QemuVmRealizationError::Executor { .. })
    ));
    guard.finish().expect("finish after signal failure");
    assert_eq!(counters.signals.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
}

#[test]
fn cancellation_signal_panic_is_contained_and_reported() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut factory = ComposedQemuAttemptResourceGuardFactory::new(FakeHostFactory {
        installed: resources,
        counters: Arc::clone(&counters),
        signal_error: false,
        signal_panics: true,
        finish_error: false,
    });
    let cancellation = ExecutionCancellation::default();
    let mut guard = factory
        .begin(resources, cancellation.clone(), None)
        .expect("resource guard before cancellation");

    cancellation.cancel_for_test();
    assert!(matches!(
        guard.check_operational_boundary(),
        Err(QemuVmRealizationError::Executor { .. })
    ));
    guard.finish().expect("finish after contained panic");
    assert_eq!(counters.signals.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
}

#[test]
fn failed_reap_quarantines_process_and_filesystem_authority_once() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut factory = ComposedQemuAttemptResourceGuardFactory::new(FakeHostFactory {
        installed: resources,
        counters: Arc::clone(&counters),
        signal_error: false,
        signal_panics: false,
        finish_error: true,
    });
    let mut guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("resource guard");

    let first = guard.finish().expect_err("actual cleanup refused");
    assert!(matches!(
        first.error(),
        QemuVmRealizationError::ExecutorUnavailable {
            operation: "finish fake host resources",
            ..
        }
    ));
    assert!(first.was_quarantined());
    assert!(first.reports_terminal_quarantine());
    for _ in 0..3 {
        let repeated = guard.finish().expect_err("quarantine remains retained");
        assert!(matches!(
            repeated.error(),
            QemuVmRealizationError::Canceled {
                operation: "repeat quarantined attempt host retirement"
            }
        ));
        assert!(repeated.was_quarantined());
        assert!(repeated.reports_terminal_quarantine());
    }
    assert!(guard.check_operational_boundary().is_err());
    assert!(guard.charge_execution_quantum().is_err());
    guard.quarantine();
    drop(guard);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
}

#[test]
fn explicit_quarantine_cannot_become_successful_finish() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut host = factory(resources, Arc::clone(&counters));
    let mut guard = host
        .begin(resources, ExecutionCancellation::default(), None)
        .unwrap();

    guard.quarantine();
    guard.quarantine();
    for _ in 0..3 {
        let repeated = guard.finish().expect_err("quarantine remains retained");
        assert!(matches!(
            repeated.error(),
            QemuVmRealizationError::Canceled {
                operation: "repeat quarantined attempt host retirement"
            }
        ));
        assert!(repeated.was_quarantined());
        assert!(repeated.reports_terminal_quarantine());
    }
    assert!(guard.check_operational_boundary().is_err());
    assert!(guard.charge_execution_quantum().is_err());
    drop(guard);

    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
}

#[test]
fn returned_generic_guard_stays_idempotent_and_cannot_reopen() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut host = factory(resources, Arc::clone(&counters));
    let mut guard = host
        .begin(resources, ExecutionCancellation::default(), None)
        .unwrap();

    guard.finish().unwrap();
    guard.quarantine();
    guard.finish().unwrap();
    assert!(guard.check_operational_boundary().is_err());
    assert!(guard.charge_execution_quantum().is_err());
    drop(guard);

    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn dropping_a_live_guard_transfers_all_host_resources_to_quarantine() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("resource guard");

    drop(guard);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
}

fn test_generation_storage(names: &[&str]) -> QemuAttemptGenerationStorage {
    let nodes = names
        .iter()
        .map(|name| NodeId {
            name: String::from(*name),
        })
        .collect::<Vec<_>>();
    QemuAttemptGenerationStorage::prepare(nodes.iter()).expect("selected generation storage")
}

fn generation(node: &str, generation: u64) -> ProductionVmNodeGeneration {
    ProductionVmNodeGeneration::new(
        NodeId {
            name: String::from(node),
        },
        generation,
    )
    .expect("valid process generation")
}

#[test]
fn generation_owner_releases_only_after_exact_monotone_leases_finish() {
    let resources = resources(4);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    let storage = test_generation_storage(&["vm-a", "vm-b"]);
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("composed resource guard");
    let mut owner = QemuAttemptGenerationResourceOwner::new(guard, storage);

    let mut first_a = owner
        .register_generation(generation("vm-a", 1))
        .expect("first vm-a generation");
    let mut first_b = owner
        .register_generation(generation("vm-b", 1))
        .expect("first vm-b generation");
    assert!(
        owner.register_generation(generation("vm-a", 1)).is_err(),
        "one generation identity cannot be reused"
    );
    let mut second_a = owner
        .register_generation(generation("vm-a", 2))
        .expect("one staged vm-a replacement");
    assert!(
        owner.register_generation(generation("vm-a", 3)).is_err(),
        "one scheduler node cannot retain a third generation"
    );
    assert!(
        owner.register_generation(generation("vm-c", 1)).is_err(),
        "distinct node retention stays bounded"
    );

    first_a.finish().expect("release reaped vm-a generation");
    first_b.finish().expect("release reaped vm-b generation");
    second_a
        .finish()
        .expect("release reaped replacement generation");
    owner.finish().expect("release aggregate attempt resources");
    owner.finish().expect("aggregate finish is idempotent");
    owner.quarantine_original_launch();
    owner.quarantine();
    owner
        .finish()
        .expect("post-return quarantine cannot reopen ownership");
    assert!(owner.check_operational_boundary().is_err());
    assert!(owner.register_generation(generation("vm-a", 3)).is_err());
    drop(owner);

    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn original_generation_quarantine_never_attests_aggregate_return() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("component resource guard");
    let mut owner =
        QemuAttemptGenerationResourceOwner::new(guard, test_generation_storage(&["vm-a"]));
    let mut lease = owner
        .register_generation(generation("vm-a", 1))
        .expect("actual finite generation lease");

    // This exercises retained component custody, not Main or native issuance.
    // The enclosing launch/park owner keeps its initiating typed cause.
    owner.quarantine_original_launch();
    assert!(matches!(
        owner.finish(),
        Err(crate::ProductionVmConstructionCleanupError::Authority(
            LifecycleApiError::CleanupRetained
        ))
    ));
    lease
        .finish()
        .expect("close the exact local generation body");
    owner.quarantine_original_launch();
    owner.quarantine();
    assert!(matches!(
        owner.finish(),
        Err(crate::ProductionVmConstructionCleanupError::Authority(
            LifecycleApiError::CleanupRetained
        ))
    ));
    assert!(owner.register_generation(generation("vm-a", 2)).is_err());
    assert!(owner.check_operational_boundary().is_err());
    drop(owner);

    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
}

#[test]
fn generation_quarantine_preserves_its_existing_failure_presentation() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("component resource guard");
    let mut owner =
        QemuAttemptGenerationResourceOwner::new(guard, test_generation_storage(&["vm-a"]));

    owner.quarantine();
    let first = owner.finish().expect_err("quarantine cannot attest return");
    let crate::ProductionVmConstructionCleanupError::Authority(first) = first else {
        panic!("local aggregate quarantine must remain an API status");
    };
    assert_eq!(
        first,
        LifecycleApiError::LoopFactory {
            message: String::from(
                "QEMU attempt aggregate resources were transferred to quarantine"
            ),
        }
    );
    owner.quarantine_original_launch();
    assert!(
        matches!(owner.finish(), Err(crate::ProductionVmConstructionCleanupError::Authority(ref repeated)) if repeated == &first)
    );
    drop(owner);

    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
}

#[test]
fn generation_guard_finish_failure_never_retries_or_attests_return() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    factory.host.finish_error = true;
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("component resource guard");
    let mut owner =
        QemuAttemptGenerationResourceOwner::new(guard, test_generation_storage(&["vm-a"]));

    let first = owner.finish().expect_err("actual component host refusal");
    let raw = first
        .guard_failure()
        .expect("actual guard leaf survives generation owner");
    assert!(matches!(
        raw.error(),
        QemuVmRealizationError::ExecutorUnavailable {
            operation: "finish fake host resources",
            ..
        }
    ));
    assert!(raw.was_quarantined());
    assert!(raw.reports_terminal_quarantine());
    owner.quarantine_original_launch();
    owner.quarantine();
    assert!(matches!(
        owner.finish(),
        Err(crate::ProductionVmConstructionCleanupError::Authority(
            LifecycleApiError::CleanupRetained
        ))
    ));
    assert!(owner.check_operational_boundary().is_err());
    drop(owner);

    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
}

#[test]
fn unselected_node_refusal_cannot_spend_a_selected_nodes_slot_or_fence() {
    let resources = resources(4);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    let storage = test_generation_storage(&["vm-a", "vm-b"]);
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("composed resource guard");
    let mut owner = QemuAttemptGenerationResourceOwner::new(guard, storage);

    assert!(
        owner
            .register_generation(generation("foreign", 100))
            .is_err()
    );
    let mut first = owner.register_generation(generation("vm-a", 1)).unwrap();
    let mut second = owner.register_generation(generation("vm-b", 1)).unwrap();
    assert!(
        owner
            .register_generation(generation("foreign", 101))
            .is_err()
    );
    first.finish().unwrap();
    second.finish().unwrap();
    assert!(owner.register_generation(generation("vm-a", 1)).is_err());
    let mut replacement = owner.register_generation(generation("vm-a", 2)).unwrap();
    replacement.finish().unwrap();
    owner.finish().unwrap();

    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn abandoned_generation_lease_permanently_quarantines_aggregate_guard() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    let storage = test_generation_storage(&["vm-a"]);
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("composed resource guard");
    let mut owner = QemuAttemptGenerationResourceOwner::new(guard, storage);

    let lease = owner
        .register_generation(generation("vm-a", 1))
        .expect("first vm-a generation");
    drop(lease);
    assert!(owner.finish().is_err());
    assert!(
        owner.finish().is_err(),
        "quarantine remains observable on exact retry"
    );

    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
}

#[test]
fn no_process_abort_preserves_the_exact_generation_for_retry() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    let storage = test_generation_storage(&["vm-a"]);
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("composed resource guard");
    let mut owner = QemuAttemptGenerationResourceOwner::new(guard, storage);

    let pending = owner
        .register_generation(generation("vm-a", 1))
        .expect("pending generation");
    pending
        .abort_without_process()
        .expect("abort generation before process ownership");

    let mut retried = owner
        .register_generation(generation("vm-a", 1))
        .expect("exact generation retry");
    retried.finish().expect("release reaped retry generation");
    owner.finish().expect("release aggregate attempt resources");

    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn aborting_a_replacement_restores_the_previous_generation_fence() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    let storage = test_generation_storage(&["vm-a"]);
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("composed resource guard");
    let mut owner = QemuAttemptGenerationResourceOwner::new(guard, storage);

    let mut first = owner
        .register_generation(generation("vm-a", 1))
        .expect("first generation");
    owner
        .register_generation(generation("vm-a", 2))
        .expect("pending replacement")
        .abort_without_process()
        .expect("abort pending replacement");

    assert!(
        owner.register_generation(generation("vm-a", 1)).is_err(),
        "the prior committed generation remains fenced"
    );
    let mut retried = owner
        .register_generation(generation("vm-a", 2))
        .expect("exact replacement retry");
    first.finish().expect("release reaped first generation");
    retried.finish().expect("release replacement retry");
    owner.finish().expect("release aggregate attempt resources");
}

#[test]
fn active_generation_prevents_aggregate_release_without_losing_lease_authority() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    let storage = test_generation_storage(&["vm-a"]);
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("composed resource guard");
    let mut owner = QemuAttemptGenerationResourceOwner::new(guard, storage);
    let mut lease = owner
        .register_generation(generation("vm-a", 1))
        .expect("first vm-a generation");

    assert!(owner.finish().is_err());
    lease
        .finish()
        .expect("the exact lease remains locally releasable for diagnostics");
    assert!(owner.finish().is_err());
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "private-measurement-domain")]
#[test]
fn original_composed_retirement_returns_first_control_and_post_original_unchanged() {
    use crucible_host_resources::host_supervision::{HostOperationState, HostSupervisionError};
    let limits = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut host = factory(limits, Arc::clone(&counters));
    host.host.finish_error = true;
    let mut guard = host
        .begin(limits, ExecutionCancellation::default(), None)
        .expect("actual composed guard mechanism");
    guard
        .retain_original_native_registry(crate::HostOperationalRegistry::default())
        .expect("actual composed registry forwarding");

    let first = guard.finish().expect_err("actual host control refused");

    let QemuVmRealizationError::ModelCopy { source } = first.error() else {
        panic!("actual first error must not be converted to string quarantine");
    };
    let actual = source
        .downcast_ref::<crucible_qemu_host::OriginalActorAccountError>()
        .expect("typed original control error remains accessible");
    assert!(matches!(
        actual,
        crucible_qemu_host::OriginalActorAccountError::NativeControlBoundary {
            source: crucible_qemu_host::LinuxQemuNativeResourceError::Retired,
            original: Some(HostSupervisionError::Terminal {
                state: HostOperationState::Canceled
            }),
        }
    ));
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
    drop(guard);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
    drop(first);
}

#[cfg(feature = "private-measurement-domain")]
#[test]
fn original_composed_retirement_cannot_retry_or_attest_terminal_containment() {
    let limits = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut host = factory(limits, Arc::clone(&counters));
    host.host.finish_error = true;
    let mut guard = host
        .begin(limits, ExecutionCancellation::default(), None)
        .expect("actual composed guard mechanism");
    guard
        .retain_original_native_registry(crate::HostOperationalRegistry::default())
        .expect("actual registry forwarding");
    let first = guard.finish().expect_err("first real finish refusal");

    assert!(matches!(
        guard.finish().as_ref().map_err(|failure| failure.error()),
        Err(QemuVmRealizationError::Canceled {
            operation: "repeat quarantined original native retirement"
        })
    ));
    guard.quarantine();
    assert!(matches!(
        guard.finish().as_ref().map_err(|failure| failure.error()),
        Err(QemuVmRealizationError::Canceled {
            operation: "repeat quarantined original native retirement"
        })
    ));
    drop(guard);

    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
    drop(first);
}

#[cfg(feature = "private-measurement-domain")]
#[test]
fn original_composed_retirement_keeps_healthy_finish_idempotent() {
    let limits = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut host = factory(limits, Arc::clone(&counters));
    let mut guard = host
        .begin(limits, ExecutionCancellation::default(), None)
        .expect("actual composed healthy guard");
    guard
        .retain_original_native_registry(crate::HostOperationalRegistry::default())
        .expect("actual registry forwarding");

    guard.finish().expect("actual healthy host finish");
    guard
        .finish()
        .expect("same completed facade remains idempotent");
    guard.quarantine();
    guard
        .finish()
        .expect("post-return quarantine cannot reopen the guard");
    assert!(guard.check_operational_boundary().is_err());
    drop(guard);

    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "private-measurement-domain")]
#[test]
fn original_explicit_quarantine_never_attests_return() {
    let limits = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut host = factory(limits, Arc::clone(&counters));
    let mut guard = host
        .begin(limits, ExecutionCancellation::default(), None)
        .unwrap();
    // The existing component registry selects the Original reporting path;
    // this control does not authenticate Main or issue native Source authority.
    guard
        .retain_original_native_registry(crate::HostOperationalRegistry::default())
        .unwrap();

    guard.quarantine();
    for _ in 0..3 {
        assert!(matches!(
            guard.finish().as_ref().map_err(|failure| failure.error()),
            Err(QemuVmRealizationError::Canceled {
                operation: "repeat quarantined original native retirement"
            })
        ));
    }
    guard.quarantine();
    assert!(guard.check_operational_boundary().is_err());
    drop(guard);

    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
}

#[test]
fn process_stage_contract_refuses_foreign_cancellation_before_callback() {
    let resources = resources(4);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    let cancellation = ExecutionCancellation::default();
    let storage = test_generation_storage(&["vm-a"]);
    let guard = factory
        .begin(resources, cancellation.clone(), None)
        .expect("resource guard");
    let mut owner = QemuAttemptGenerationResourceOwner::new(guard, storage);
    let mut called = false;
    let checks = counters.checks.load(Ordering::SeqCst);

    let refused = owner.with_process_stage_contract(&ExecutionCancellation::default(), |_| {
        called = true;
    });

    assert!(matches!(
        refused,
        Err(ProcessStageContractRefusal::NotCurrent)
    ));
    assert!(!called);
    assert_eq!(counters.checks.load(Ordering::SeqCst), checks);
    owner.finish().expect("finish unused generation owner");
}

#[test]
fn process_stage_contract_borrows_same_owner_and_refuses_later_cancellation() {
    let resources = resources(4);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    let cancellation = ExecutionCancellation::default();
    let storage = test_generation_storage(&["vm-a"]);
    let guard = factory
        .begin(resources, cancellation.clone(), None)
        .expect("resource guard");
    let mut owner = QemuAttemptGenerationResourceOwner::new(guard, storage);
    let checks = counters.checks.load(Ordering::SeqCst);

    let observed = owner
        .with_process_stage_contract(&cancellation, |_| 73)
        .expect("same owner contract");

    assert_eq!(observed, 73);
    assert_eq!(counters.checks.load(Ordering::SeqCst), checks + 1);
    cancellation.cancel();
    let mut called = false;
    let refused = owner.with_process_stage_contract(&cancellation, |_| {
        called = true;
    });
    assert!(matches!(
        refused,
        Err(ProcessStageContractRefusal::Owner(
            QemuVmRealizationError::Canceled { .. }
        ))
    ));
    assert!(!called);
    owner.finish().expect("finish cancelled generation owner");
}

#[test]
fn genuine_effective_linux_basis_preserves_original_nonresident_obligations()
-> Result<(), Box<dyn std::error::Error>> {
    let admitted = AttemptResourceLimits::new(1, 512 << 20, 1 << 30, 50000)?;
    let effective = super::effective_linux_limits(admitted, (1, 256 << 20, 1 << 30))?;
    assert_eq!(effective.maximum_resident_bytes(), 256 << 20);
    assert_eq!(
        effective.maximum_execution_quanta(),
        admitted.maximum_execution_quanta()
    );
    assert_eq!(effective.maximum_vcpus(), admitted.maximum_vcpus());
    assert_eq!(
        effective.maximum_disk_bytes(),
        admitted.maximum_disk_bytes()
    );

    for invalid in [
        (1, 0, 1 << 30),
        (1, (512 << 20) + 1, 1 << 30),
        (2, 256 << 20, 1 << 30),
        (1, 256 << 20, (1 << 30) - 1),
    ] {
        assert!(super::effective_linux_limits(admitted, invalid).is_err());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn erased_launcher_observes_the_actual_generic_guard_target_loan() {
    let resources = resources(2);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    let storage = test_generation_storage(&["vm-a"]);
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("actual generic guard fixture");
    let owner = QemuAttemptGenerationResourceOwner::new(guard, storage);
    let mut launcher: Box<dyn ProductionVmNodeLauncher> =
        Box::new(crate::QemuAttemptProductionVmNodeLauncher::new(owner));

    counters.fork_targets_owned.store(1, Ordering::Release);

    assert!(launcher.fork_target_is_owned());
    assert!(launcher.prepare_fork_target().is_err());
    assert_eq!(counters.begins.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);

    counters.fork_targets_owned.store(0, Ordering::Release);
    assert!(!launcher.fork_target_is_owned());
    launcher.finish().expect("actual generic guard fixture");
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
}

#[test]
fn canceled_begin_with_failed_rollback_keeps_both_actual_causes_and_one_quarantine() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut factory = ComposedQemuAttemptResourceGuardFactory::new(FakeHostFactory {
        installed: resources,
        counters: Arc::clone(&counters),
        signal_error: false,
        signal_panics: false,
        finish_error: true,
    });
    let cancellation = ExecutionCancellation::default();
    cancellation.cancel_for_test();

    let failure = match factory.begin(resources, cancellation, None) {
        Ok(_) => panic!("pre-canceled component guard unexpectedly installed"),
        Err(failure) => failure,
    };
    let (report, selected) = failure.into_parts();

    assert!(matches!(
        report.first_error(),
        QemuVmRealizationError::Canceled {
            operation: "QEMU attempt resource boundary"
        }
    ));
    assert!(matches!(
        report.cleanup_error(),
        Some(QemuVmRealizationError::ExecutorUnavailable {
            operation: "finish fake host resources",
            ..
        })
    ));
    assert!(report.was_quarantined());
    assert!(selected.is_none());
    assert_eq!(counters.signals.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
}

#[test]
fn inline_begin_report_moves_both_original_allocations_without_reboxing() {
    // Diagnostic transport only; this issues no Main, native owner or closure.
    let first_message = String::from("original resource installation refusal");
    let cleanup_message = String::from("independent host rollback refusal");
    let first_pointer = first_message.as_ptr();
    let cleanup_pointer = cleanup_message.as_ptr();
    let failure = QemuAttemptResourceGuardBeginFailure::rollback(
        QemuVmRealizationError::Executor {
            operation: "component first",
            message: first_message,
        },
        crate::crucible_qemu_session::QemuAttemptResourceGuardCleanupFailure::quarantined(
            QemuVmRealizationError::ExecutorUnavailable {
                operation: "component cleanup",
                message: cleanup_message,
            },
        ),
    );
    let (report, selected) = failure.into_parts();
    let moved = QemuAttemptResourceGuardBeginFailure::from_report(report, selected);
    let (report, selected) = moved.into_parts();

    let QemuVmRealizationError::Executor { message: first, .. } = report.first_error() else {
        panic!("typed first cause changed");
    };
    let Some(QemuVmRealizationError::ExecutorUnavailable {
        message: cleanup, ..
    }) = report.cleanup_error()
    else {
        panic!("typed cleanup cause changed");
    };
    assert_eq!(first.as_ptr(), first_pointer);
    assert_eq!(cleanup.as_ptr(), cleanup_pointer);
    assert!(report.was_quarantined());
    assert!(selected.is_none());
}

#[test]
fn absent_selected_claim_alone_does_not_invent_quarantine_history() {
    let failure = QemuAttemptResourceGuardBeginFailure::after_checkpoint_claim(
        QemuVmRealizationError::ExecutorUnavailable {
            operation: "component no selected root",
            message: String::from("unavailable"),
        },
    );
    let (report, selected) = failure.into_parts();

    assert!(selected.is_none());
    assert!(!report.was_quarantined());
    assert!(report.cleanup_error().is_none());
    assert!(matches!(
        report.first_error(),
        QemuVmRealizationError::ExecutorUnavailable {
            operation: "component no selected root",
            ..
        }
    ));
}

#[test]
fn retained_cleanup_marker_is_an_operational_terminal_refusal() {
    let error = attempt_operational_error(
        "component member cleanup",
        QemuVmRealizationError::CleanupRetained {
            operation: "finish hot-fork World member",
        },
    );
    assert!(matches!(
        error,
        LifecycleApiError::AttemptOperational {
            class: SchedulerOperationalFailureClass::Terminal,
            ..
        }
    ));
}
