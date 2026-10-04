//! QEMU attempt resource ownership and cleanup regression tests.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crucible::ContentHash;
use crucible_api::ProductionVmNodeLauncher;
use crucible_campaign::ExactCheckpointId;
use crucible_cas::content_store::{ContentId, ObjectKind};

use super::*;

#[derive(Debug, Default)]
struct HostCounters {
    begins: AtomicUsize,
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
    type CancellationSignal = FakeCancellationSignal;

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
        ExactCheckpointId::try_from(ContentId::for_bytes(ObjectKind::ExactManifest, 5, label))
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
        error,
        QemuVmRealizationError::ExecutorUnavailable { .. }
    ));
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
        error,
        QemuVmRealizationError::ReapQuarantined { .. }
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
    assert!(matches!(error, QemuVmRealizationError::Canceled { .. }));
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
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("composed resource guard");
    let owner =
        QemuAttemptGenerationResourceOwner::new(guard, 1).expect("generation resource owner");
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
    let guard = factory
        .begin(resources, cancellation.clone(), None)
        .expect("composed resource guard");
    let owner =
        QemuAttemptGenerationResourceOwner::new(guard, 1).expect("generation resource owner");
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

    assert!(matches!(
        guard.finish(),
        Err(QemuVmRealizationError::ReapQuarantined { .. })
    ));
    drop(guard);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
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
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("composed resource guard");
    let mut owner =
        QemuAttemptGenerationResourceOwner::new(guard, 2).expect("bounded generation owner");

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

    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn abandoned_generation_lease_permanently_quarantines_aggregate_guard() {
    let resources = resources(1);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("composed resource guard");
    let mut owner =
        QemuAttemptGenerationResourceOwner::new(guard, 1).expect("bounded generation owner");

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
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("composed resource guard");
    let mut owner =
        QemuAttemptGenerationResourceOwner::new(guard, 1).expect("bounded generation owner");

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
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("composed resource guard");
    let mut owner =
        QemuAttemptGenerationResourceOwner::new(guard, 1).expect("bounded generation owner");

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
    let guard = factory
        .begin(resources, ExecutionCancellation::default(), None)
        .expect("composed resource guard");
    let mut owner =
        QemuAttemptGenerationResourceOwner::new(guard, 1).expect("bounded generation owner");
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
