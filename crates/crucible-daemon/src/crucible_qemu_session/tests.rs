//! Tests for attempt-scoped live-QEMU session ownership.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use crucible::{
    AdvanceOutcome, Backend, BackendError, BackendInput, Checkpoint, Configuration, ContentHash,
    Decision, EventLog, ExecutionFingerprint, ExecutionHorizon, Icount, RngDecision, RngStreamId,
    RuntimeState, ScenarioDef, SchedulerState,
};
use crucible_campaign::ExecutionRetentionIntent;
use crucible_qemu::{QemuLiveBackendShutdown, QemuRealizedNodeBackend};

use super::*;

#[derive(Default)]
struct FakeBackend;

impl Backend for FakeBackend {
    fn advance_to_horizon(
        &mut self,
        _horizon: ExecutionHorizon,
    ) -> Result<AdvanceOutcome, BackendError> {
        Ok(AdvanceOutcome::ReachedHorizon)
    }

    fn fingerprint(&mut self) -> Result<ExecutionFingerprint, BackendError> {
        Ok(ExecutionFingerprint {
            hash: ContentHash::from_canonical_material("crucible.test.live-session", "backend"),
        })
    }

    fn deliver_input(&mut self, _input: BackendInput) -> Result<(), BackendError> {
        Ok(())
    }

    fn snapshot(&mut self) -> Result<Checkpoint, BackendError> {
        Err(BackendError::NotImplemented {
            operation: "fake live-session snapshot",
        })
    }

    fn restore(&mut self, _checkpoint: &Checkpoint) -> Result<(), BackendError> {
        Err(BackendError::NotImplemented {
            operation: "fake live-session restore",
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        Ok(())
    }
}

impl QemuRealizedNodeBackend for FakeBackend {
    fn prepare_authoritative_observation_stream(&mut self) -> Result<(), BackendError> {
        Ok(())
    }

    fn advance_live_to_horizon(
        &mut self,
        horizon: ExecutionHorizon,
        _event_log: &mut EventLog,
    ) -> Result<AdvanceOutcome, BackendError> {
        Backend::advance_to_horizon(self, horizon)
    }

    fn seal_live_observation_boundary(
        &mut self,
        _event_log: &mut EventLog,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    fn shutdown_live_with_event_log(
        &mut self,
        _event_log: &mut EventLog,
    ) -> Result<(), BackendError> {
        Backend::shutdown(self)?;
        Ok(())
    }

    fn current_icount(&mut self) -> Result<Icount, BackendError> {
        Ok(Icount::default())
    }
}

struct FakeExecutor {
    backend: FakeBackend,
    event_log: EventLog,
    counters: TestCounters,
    active: bool,
    unreaped_failed_launch: bool,
    shutdown_error: bool,
    seal_boundary_changed: bool,
    shutdown_boundary_changed: bool,
    guarded_error: bool,
    failed_realization_reap_error: bool,
}

impl QemuVmRealizationExecutor for FakeExecutor {
    fn load_exact_snapshot(
        &mut self,
        _config: &Configuration,
        _snapshot: &QemuVmSnapshot,
        _authorization: QemuLoadvmCommandAuthorization,
        _admission: QemuLoadvmRealizationAdmission,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        unreachable!("ownership test does not realize QEMU")
    }

    fn load_exact_snapshot_for_replay_oracle_probe(
        &mut self,
        _config: &Configuration,
        _snapshot: &QemuVmSnapshot,
        _authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        unreachable!("ownership test does not realize QEMU")
    }

    fn load_baked_genesis(
        &mut self,
        _config: &Configuration,
        _admission: QemuBakedGenesisRestoreAdmission<'_>,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        unreachable!("ownership test does not realize QEMU")
    }

    fn replay_one_quantum(
        &mut self,
        _runtime: RuntimeState,
        _request: QemuVmReplayRequest,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        unreachable!("ownership test does not realize QEMU")
    }
}

impl QemuVmLiveRealizationExecutor for FakeExecutor {
    fn live_backend_is_active(&self) -> bool {
        self.active || self.unreaped_failed_launch
    }

    fn live_backend_mut(
        &mut self,
    ) -> Result<&mut dyn QemuLiveAttemptBackend, QemuVmRealizationError> {
        Ok(self)
    }

    fn seal_live_observation_boundary(&mut self) -> Result<bool, QemuVmRealizationError> {
        Ok(!self.seal_boundary_changed)
    }

    fn shutdown_live_backend(&mut self) -> Result<QemuLiveBackendShutdown, QemuVmRealizationError> {
        self.counters.shutdowns.fetch_add(1, Ordering::SeqCst);
        if self.shutdown_error {
            self.active = true;
            return Err(QemuVmRealizationError::ExecutorUnavailable {
                operation: "reap fake QEMU process",
                message: String::from("injected reap failure"),
            });
        }
        self.active = false;
        if self.shutdown_boundary_changed {
            Ok(QemuLiveBackendShutdown::changed_after_seal())
        } else {
            Ok(QemuLiveBackendShutdown::unchanged())
        }
    }
}

impl QemuLiveAttemptBackend for FakeExecutor {
    fn advance_to_horizon(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<AdvanceOutcome, BackendError> {
        QemuRealizedNodeBackend::advance_live_to_horizon(
            &mut self.backend,
            horizon,
            &mut self.event_log,
        )
    }

    fn fingerprint(&mut self) -> Result<ExecutionFingerprint, BackendError> {
        Backend::fingerprint(&mut self.backend)
    }

    fn deliver_input(&mut self, input: BackendInput) -> Result<(), BackendError> {
        Backend::deliver_input(&mut self.backend, input)
    }

    fn current_icount(&mut self) -> Result<Icount, BackendError> {
        QemuRealizedNodeBackend::current_icount(&mut self.backend)
    }

    fn event_log(&self) -> &EventLog {
        &self.event_log
    }
}

impl QemuGuardedLiveRealizationExecutor<TrackingGuard> for FakeExecutor {
    fn load_exact_snapshot_guarded(
        &mut self,
        _guard: &mut TrackingGuard,
        _config: &Configuration,
        _snapshot: &QemuVmSnapshot,
        _authorization: QemuLoadvmCommandAuthorization,
        _admission: QemuLoadvmRealizationAdmission,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        unreachable!("ownership test does not realize QEMU")
    }

    fn load_exact_snapshot_for_replay_oracle_probe_guarded(
        &mut self,
        _guard: &mut TrackingGuard,
        _config: &Configuration,
        _snapshot: &QemuVmSnapshot,
        _authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        unreachable!("ownership test does not realize QEMU")
    }

    fn load_baked_genesis_guarded(
        &mut self,
        _guard: &mut TrackingGuard,
        _config: &Configuration,
        _admission: QemuBakedGenesisRestoreAdmission<'_>,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        unreachable!("ownership test does not realize QEMU")
    }

    fn replay_one_quantum_guarded(
        &mut self,
        guard: &mut TrackingGuard,
        runtime: RuntimeState,
        _request: QemuVmReplayRequest,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        self.counters.guarded_calls.fetch_add(1, Ordering::SeqCst);
        if self.guarded_error {
            self.unreaped_failed_launch = true;
            return Err(QemuVmRealizationError::ExecutorUnavailable {
                operation: "install fake live backend",
                message: String::from("injected post-spawn failure"),
            });
        }
        self.active = true;
        guard.check_operational_boundary()?;
        Ok(runtime)
    }

    fn reap_failed_realization_guarded(
        &mut self,
        _guard: &mut TrackingGuard,
    ) -> Result<(), QemuVmRealizationError> {
        self.counters.failed_reaps.fetch_add(1, Ordering::SeqCst);
        self.counters.shutdowns.fetch_add(1, Ordering::SeqCst);
        if self.failed_realization_reap_error {
            return Err(QemuVmRealizationError::ExecutorUnavailable {
                operation: "reap failed fake realization",
                message: String::from("injected failed-realization reap failure"),
            });
        }
        self.active = false;
        self.unreaped_failed_launch = false;
        Ok(())
    }
}

struct UnusedDriver;

impl QemuLiveAttemptDriver for UnusedDriver {
    type Error = ();

    fn run_attempt(
        &mut self,
        _backend: &mut dyn QemuLiveAttemptExecution,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        _realization: QemuVmRealization,
    ) -> Result<QemuLiveAttemptResult, AttemptWorkerFailure<Self::Error>> {
        unreachable!("ownership test does not drive a modeled attempt")
    }
}

#[derive(Clone, Default)]
struct TestCounters {
    shutdowns: Arc<AtomicUsize>,
    finishes: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
    guarded_calls: Arc<AtomicUsize>,
    failed_reaps: Arc<AtomicUsize>,
    checks: Arc<AtomicUsize>,
    quanta: Arc<AtomicUsize>,
}

#[derive(Clone, Copy, Default)]
struct SessionBehavior {
    shutdown_error: bool,
    seal_boundary_changed: bool,
    shutdown_boundary_changed: bool,
    guarded_error: bool,
    failed_realization_reap_error: bool,
    replace_cancellation: bool,
    fail_on_check: Option<usize>,
}

struct TrackingGuardFactory {
    installed: AttemptResourceLimits,
    counters: TestCounters,
    replace_cancellation: bool,
    fail_on_check: Option<usize>,
}

impl QemuAttemptResourceGuardFactory for TrackingGuardFactory {
    type Guard = TrackingGuard;

    fn begin(
        &mut self,
        _resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
    ) -> Result<Self::Guard, QemuVmRealizationError> {
        Ok(TrackingGuard {
            installed: self.installed,
            cancellation: if self.replace_cancellation {
                ExecutionCancellation::default()
            } else {
                cancellation
            },
            counters: self.counters.clone(),
            fail_on_check: self.fail_on_check,
            quanta_remaining: self.installed.maximum_execution_quanta(),
            finished: false,
        })
    }
}

struct TrackingGuard {
    installed: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    counters: TestCounters,
    fail_on_check: Option<usize>,
    quanta_remaining: u64,
    finished: bool,
}

impl QemuAttemptOperationalBoundary for TrackingGuard {
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.installed
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        let check = self.counters.checks.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_on_check == Some(check) {
            return Err(QemuVmRealizationError::Canceled {
                operation: "guarded fake realization operation",
            });
        }
        Ok(())
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.quanta_remaining == 0 {
            return Err(QemuVmRealizationError::Executor {
                operation: "charge fake QEMU execution quantum",
                message: String::from("execution quantum ceiling exhausted"),
            });
        }
        self.quanta_remaining -= 1;
        self.counters.quanta.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl QemuAttemptResourceGuard for TrackingGuard {
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        if !self.finished {
            self.counters.finishes.fetch_add(1, Ordering::SeqCst);
            self.finished = true;
        }
        Ok(())
    }

    fn quarantine(&mut self) {
        if !self.finished {
            self.counters.quarantines.fetch_add(1, Ordering::SeqCst);
            self.finished = true;
        }
    }
}

#[test]
fn live_backend_spends_exactly_one_guard_quantum_before_each_advance() {
    let resources = AttemptResourceLimits::new(1, 4096, 8192, 2).expect("resource limits");
    let counters = TestCounters::default();
    let factory = session_factory(resources, counters.clone(), SessionBehavior::default());
    let (mut executor, _driver, mut guard_factory) = factory.into_parts();
    let mut guard = guard_factory
        .begin(resources, ExecutionCancellation::default())
        .expect("install tracking guard");
    let mut backend = ChargedQemuLiveAttemptBackend {
        backend: &mut executor,
        boundary: &mut guard,
        operational_failure: None,
    };
    let horizon = ExecutionHorizon {
        icount: Icount { retired: 1 },
    };

    assert_eq!(
        backend.advance_to_horizon(horizon),
        Ok(AdvanceOutcome::ReachedHorizon)
    );
    assert_eq!(
        backend.advance_to_horizon(horizon),
        Ok(AdvanceOutcome::ReachedHorizon)
    );
    assert!(matches!(
        backend.advance_to_horizon(horizon),
        Err(BackendError::Rejected { .. })
    ));
    assert!(matches!(
        backend.take_operational_failure(),
        Some(QemuVmRealizationError::Executor { .. })
    ));
    assert_eq!(counters.quanta.load(Ordering::SeqCst), 2);
}

#[test]
fn realization_replay_spends_quantum_before_the_guarded_executor_call() {
    let resources = AttemptResourceLimits::new(1, 4096, 8192, 1).expect("resource limits");
    let counters = TestCounters::default();
    let mut factory = session_factory(resources, counters.clone(), SessionBehavior::default());
    let context = execution_context(resources);
    let (runtime, request) = replay_fixture();
    let mut session = factory
        .begin_attempt(&context)
        .expect("begin exact session");

    let first = QemuVmRealizationExecutor::replay_one_quantum(
        &mut session,
        runtime.clone(),
        request.clone(),
    );
    assert!(first.is_ok());
    assert_eq!(counters.guarded_calls.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quanta.load(Ordering::SeqCst), 1);

    let second = QemuVmRealizationExecutor::replay_one_quantum(&mut session, runtime, request);
    assert!(matches!(
        second,
        Err(QemuVmRealizationError::Executor { .. })
    ));
    assert_eq!(counters.guarded_calls.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quanta.load(Ordering::SeqCst), 1);
}

#[test]
fn explicit_finish_reaps_backend_before_releasing_exact_resource_guard() {
    let resources = resource_limits(2);
    let counters = TestCounters::default();
    let mut factory = session_factory(resources, counters.clone(), SessionBehavior::default());
    let context = execution_context(resources);

    let session = factory
        .begin_attempt(&context)
        .expect("begin exact session");
    assert_eq!(session.resource_limits(), resources);
    session.finish().expect("finish exact session");

    assert_eq!(counters.shutdowns.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn dropped_session_reaps_backend_and_releases_resources_once() {
    let resources = resource_limits(1);
    let counters = TestCounters::default();
    let mut factory = session_factory(resources, counters.clone(), SessionBehavior::default());
    let context = execution_context(resources);

    {
        let _session = factory
            .begin_attempt(&context)
            .expect("begin exact session");
    }

    assert_eq!(counters.shutdowns.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn mismatched_guard_is_released_before_launch_authority_is_returned() {
    let requested = resource_limits(2);
    let installed = resource_limits(1);
    let counters = TestCounters::default();
    let mut factory = session_factory(installed, counters.clone(), SessionBehavior::default());
    let context = execution_context(requested);

    let result = factory.begin_attempt(&context);
    assert!(matches!(
        result,
        Err(QemuVmRealizationError::Executor { .. })
    ));
    assert_eq!(counters.shutdowns.load(Ordering::SeqCst), 0);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn guard_with_wrong_cancellation_incarnation_is_rejected_before_launch() {
    let resources = resource_limits(1);
    let counters = TestCounters::default();
    let mut factory = session_factory(
        resources,
        counters.clone(),
        SessionBehavior {
            replace_cancellation: true,
            ..SessionBehavior::default()
        },
    );
    let context = execution_context(resources);

    let result = factory.begin_attempt(&context);

    assert!(matches!(
        result,
        Err(QemuVmRealizationError::Executor { .. })
    ));
    assert_eq!(counters.shutdowns.load(Ordering::SeqCst), 0);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn guarded_realization_observes_cancellation_inside_the_executor_operation() {
    let resources = resource_limits(1);
    let counters = TestCounters::default();
    let mut factory = session_factory(
        resources,
        counters.clone(),
        SessionBehavior {
            fail_on_check: Some(2),
            ..SessionBehavior::default()
        },
    );
    let context = execution_context(resources);
    let (runtime, request) = replay_fixture();
    let mut session = factory
        .begin_attempt(&context)
        .expect("begin exact session");

    let result = QemuVmRealizationExecutor::replay_one_quantum(&mut session, runtime, request);

    assert!(matches!(
        result,
        Err(QemuVmRealizationError::Canceled { .. })
    ));
    drop(session);
    assert_eq!(counters.guarded_calls.load(Ordering::SeqCst), 1);
    assert_eq!(counters.failed_reaps.load(Ordering::SeqCst), 1);
    assert_eq!(counters.checks.load(Ordering::SeqCst), 3);
    assert_eq!(counters.shutdowns.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
}

#[test]
fn failed_reap_quarantines_resources_and_poisons_the_next_launch() {
    let resources = resource_limits(1);
    let counters = TestCounters::default();
    let mut factory = session_factory(
        resources,
        counters.clone(),
        SessionBehavior {
            shutdown_error: true,
            ..SessionBehavior::default()
        },
    );
    let context = execution_context(resources);
    let (runtime, request) = replay_fixture();
    let mut session = factory
        .begin_attempt(&context)
        .expect("begin exact session");
    QemuVmRealizationExecutor::replay_one_quantum(&mut session, runtime, request)
        .expect("install fake live backend");

    let result = session.finish();
    assert!(matches!(
        result,
        Err(QemuVmRealizationError::ReapQuarantined { .. })
    ));
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);

    let next = factory.begin_attempt(&context);
    assert!(matches!(
        next,
        Err(QemuVmRealizationError::ExecutorUnavailable { .. })
    ));
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
}

#[test]
fn final_observable_events_reject_the_candidate_after_reap_and_release() {
    let resources = resource_limits(1);
    let counters = TestCounters::default();
    let mut factory = session_factory(
        resources,
        counters.clone(),
        SessionBehavior {
            shutdown_boundary_changed: true,
            ..SessionBehavior::default()
        },
    );
    let context = execution_context(resources);
    let mut session = factory
        .begin_attempt(&context)
        .expect("begin exact session");
    let expected = session.executor.event_log.offset();
    assert!(
        session
            .seal_result_event_log(expected)
            .expect("seal exact candidate boundary")
    );

    let result = session.finish();

    assert!(matches!(
        result,
        Err(QemuVmRealizationError::Executor { .. })
    ));
    assert_eq!(counters.shutdowns.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
    factory
        .begin_attempt(&context)
        .expect("reaped executor remains reusable");
}

#[test]
fn exact_driver_event_log_boundary_is_accepted() {
    let resources = resource_limits(1);
    let counters = TestCounters::default();
    let mut factory = session_factory(resources, counters.clone(), SessionBehavior::default());
    let context = execution_context(resources);
    let mut session = factory
        .begin_attempt(&context)
        .expect("begin exact session");
    let expected = session.executor.event_log.offset();

    assert!(
        session
            .seal_result_event_log(expected)
            .expect("seal exact driver boundary")
    );
    session.finish().expect("finish exact session");
    assert_eq!(counters.shutdowns.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
}

#[test]
fn stale_driver_event_log_boundary_is_rejected() {
    let resources = resource_limits(1);
    let counters = TestCounters::default();
    let mut factory = session_factory(resources, counters, SessionBehavior::default());
    let context = execution_context(resources);
    let mut session = factory
        .begin_attempt(&context)
        .expect("begin exact session");
    let stale = crucible::EventLogOffset::new(
        ContentHash::from_canonical_material("crucible.test.live-session", "stale-log"),
        8,
        1,
    );

    assert!(
        !session
            .seal_result_event_log(stale)
            .expect("seal stale driver boundary")
    );
}

#[test]
fn seal_time_observable_event_rejects_the_driver_boundary() {
    let resources = resource_limits(1);
    let counters = TestCounters::default();
    let mut factory = session_factory(
        resources,
        counters,
        SessionBehavior {
            seal_boundary_changed: true,
            ..SessionBehavior::default()
        },
    );
    let context = execution_context(resources);
    let mut session = factory
        .begin_attempt(&context)
        .expect("begin exact session");
    let expected = session.executor.event_log.offset();

    assert!(
        !session
            .seal_result_event_log(expected)
            .expect("seal changed observation boundary")
    );
}

#[test]
fn post_spawn_realization_failure_requires_reap_attestation_before_release() {
    let resources = resource_limits(1);
    let counters = TestCounters::default();
    let mut factory = session_factory(
        resources,
        counters.clone(),
        SessionBehavior {
            guarded_error: true,
            failed_realization_reap_error: true,
            ..SessionBehavior::default()
        },
    );
    let context = execution_context(resources);
    let (runtime, request) = replay_fixture();
    let mut session = factory
        .begin_attempt(&context)
        .expect("begin exact session");

    let realization = QemuVmRealizationExecutor::replay_one_quantum(&mut session, runtime, request);
    assert!(matches!(
        realization,
        Err(QemuVmRealizationError::ExecutorUnavailable { .. })
    ));
    let finish = session.finish();
    assert!(matches!(
        finish,
        Err(QemuVmRealizationError::ReapQuarantined { .. })
    ));

    assert_eq!(counters.failed_reaps.load(Ordering::SeqCst), 2);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
    assert!(matches!(
        factory.begin_attempt(&context),
        Err(QemuVmRealizationError::ExecutorUnavailable { .. })
    ));
}

fn session_factory(
    installed: AttemptResourceLimits,
    counters: TestCounters,
    behavior: SessionBehavior,
) -> QemuLiveAttemptSessionFactory<FakeExecutor, UnusedDriver, TrackingGuardFactory> {
    QemuLiveAttemptSessionFactory::new(
        FakeExecutor {
            backend: FakeBackend,
            event_log: EventLog::new(),
            counters: counters.clone(),
            active: false,
            unreaped_failed_launch: false,
            shutdown_error: behavior.shutdown_error,
            seal_boundary_changed: behavior.seal_boundary_changed,
            shutdown_boundary_changed: behavior.shutdown_boundary_changed,
            guarded_error: behavior.guarded_error,
            failed_realization_reap_error: behavior.failed_realization_reap_error,
        },
        UnusedDriver,
        TrackingGuardFactory {
            installed,
            counters,
            replace_cancellation: behavior.replace_cancellation,
            fail_on_check: behavior.fail_on_check,
        },
    )
}

fn execution_context(resources: AttemptResourceLimits) -> AttemptExecutionContext {
    AttemptExecutionContext::new(
        resources,
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
    )
}

fn replay_fixture() -> (RuntimeState, QemuVmReplayRequest) {
    let from = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.live-session",
        "scenario=guarded-replay",
    ));
    let decision = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("guarded-replay"),
        value: 7,
    });
    let to = crucible::step(&from, decision.clone());
    let runtime = RuntimeState {
        id: ContentHash::from_canonical_material(
            "crucible.test.live-session",
            "runtime=guarded-replay",
        ),
        configuration: from.id(),
        node_blobs: BTreeMap::new(),
        node_icounts: BTreeMap::new(),
        scheduler: SchedulerState::from_schedule(&from.schedule),
        event_log: Default::default(),
    };
    (runtime, QemuVmReplayRequest { from, to, decision })
}

fn resource_limits(vcpus: u32) -> AttemptResourceLimits {
    AttemptResourceLimits::new(vcpus, 4096, 8192, 64).expect("resource limits")
}
