// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

#[derive(Debug, Default)]
struct HostCounters {
    begins: AtomicUsize,
    checks: AtomicUsize,
    signals: AtomicUsize,
    finishes: AtomicUsize,
    quarantines: AtomicUsize,
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
        self.counters.begins.fetch_add(1, Ordering::SeqCst);
        let (cgroup_procs, _cgroup_peer) =
            UnixStream::pair().expect("cgroup process contract descriptors");
        let (cancellation_event, _cancellation_peer) =
            UnixStream::pair().expect("cancellation process contract descriptors");
        Ok(FakeHostOwner {
            installed: self.installed,
            process_contract: QemuChildProcessContract::from_unvalidated_test_descriptors(
                cgroup_procs.into(),
                cancellation_event.into(),
                self.installed.maximum_vcpus(),
                self.installed.maximum_resident_bytes(),
                self.installed.maximum_disk_bytes(),
            ),
            counters: Arc::clone(&self.counters),
            signal_error: self.signal_error,
            signal_panics: self.signal_panics,
            finish_error: self.finish_error,
            terminal: false,
        })
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

    fn prepare_run_directory(
        &mut self,
        _command: &QemuLaunchCommand,
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
fn cancellation_signals_process_synchronously_and_unregisters_on_finish() {
    let resources = resources(2);
    let counters = Arc::new(HostCounters::default());
    let mut factory = factory(resources, Arc::clone(&counters));
    let cancellation = ExecutionCancellation::default();
    let mut guard = factory
        .begin(resources, cancellation.clone())
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

    let error = match factory.begin(resources, cancellation) {
        Ok(_) => panic!("pre-canceled guard unexpectedly installed"),
        Err(error) => error,
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
        .begin(resources, ExecutionCancellation::default())
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
        factory.begin(requested, ExecutionCancellation::default()),
        Err(QemuVmRealizationError::Executor { .. })
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
        .begin(resources, cancellation.clone())
        .expect("first resource guard");

    assert!(matches!(
        second_factory.begin(resources, cancellation),
        Err(QemuVmRealizationError::Executor { .. })
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
        .begin(resources, cancellation.clone())
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
        .begin(resources, cancellation.clone())
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
        .begin(resources, ExecutionCancellation::default())
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
        .begin(resources, ExecutionCancellation::default())
        .expect("resource guard");

    drop(guard);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
}
