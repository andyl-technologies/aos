// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for precise failures.
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crucible::{Configuration, EventLog};
use crucible_campaign::{
    Attempt, AttemptResourceLimits, AttemptStart, BranchPath, CampaignHash, CampaignLineage,
    ConfigurationArtifact, ConfigurationId, ExecutionId, ExecutionRetentionIntent,
    ScenarioArtifact, ScenarioDefId, StopCondition,
};
use crucible_qemu::{QemuHotForkChildDiagnosticDrain, QemuVmRealizationError};

use super::*;
use crate::{
    AttemptExecutionKey, ExecutionCancellation, ExecutionCheckpointRequest,
    QemuAttemptOperationalBoundary, QemuHotForkChildExitPolicy, QemuHotForkLiveExecution,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("scripted pool failure")]
struct ScriptedError;

struct NeverLive;

impl QemuAttemptOperationalBoundary for NeverLive {
    fn resource_limits(&self) -> AttemptResourceLimits {
        panic!("scripted pool lifecycle never exposes a live child")
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        panic!("scripted pool lifecycle never exposes a live child")
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        panic!("scripted pool lifecycle never exposes a live child")
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        panic!("scripted pool lifecycle never exposes a live child")
    }
}

impl QemuHotForkLiveExecution for NeverLive {
    fn event_log_mut(&mut self) -> &mut EventLog {
        panic!("scripted pool lifecycle never exposes a live child")
    }

    fn drain_diagnostics(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticDrain, QemuVmRealizationError> {
        panic!("scripted pool lifecycle never exposes a live child")
    }
}

struct ScriptedLifecycle {
    runtime_basis: AttemptExecutionRuntimeBasis,
    source: u64,
    reconciled: bool,
    quarantined: Arc<Mutex<Vec<u64>>>,
}

impl QemuHotForkAttemptLifecycle for ScriptedLifecycle {
    type Live<'a> = NeverLive;
    type Error = ScriptedError;

    fn runtime_basis(&self) -> AttemptExecutionRuntimeBasis {
        self.runtime_basis
    }

    fn admit_child(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn live_child(&mut self) -> Result<Self::Live<'_>, Self::Error> {
        Err(ScriptedError)
    }

    fn stop_before_publication(
        &mut self,
        _exit_policy: QemuHotForkChildExitPolicy,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn reconcile_execution_disposition(
        &mut self,
        _disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        self.reconciled = true;
        Ok(AttemptExecutionReconciliationStep::Complete)
    }

    fn quarantine(&mut self) {
        self.quarantined
            .lock()
            .expect("quarantine observations")
            .push(self.source);
    }
}

#[derive(Clone, Copy)]
enum StartFailure {
    None,
    Retryable,
    Canceled,
    Terminal,
}

struct ScriptedFactory {
    key: QemuHotForkTemplateKey,
    source: u64,
    available: bool,
    failure: StartFailure,
    starts: Arc<Mutex<Vec<u64>>>,
    quarantined: Arc<Mutex<Vec<u64>>>,
}

impl QemuHotForkAttemptLifecycleFactory for ScriptedFactory {
    type Lifecycle = ScriptedLifecycle;
    type Error = ScriptedError;

    fn start(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        runtime_basis: AttemptExecutionRuntimeBasis,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.starts
            .lock()
            .expect("start observations")
            .push(self.source);
        match self.failure {
            StartFailure::None => {}
            StartFailure::Retryable => {
                return Err(AttemptWorkerFailure::Retryable(ScriptedError));
            }
            StartFailure::Canceled => {
                return Err(AttemptWorkerFailure::Canceled(ScriptedError));
            }
            StartFailure::Terminal => {
                return Err(AttemptWorkerFailure::Terminal(ScriptedError));
            }
        }
        if !self.available {
            return Err(AttemptWorkerFailure::Terminal(ScriptedError));
        }
        self.available = false;
        Ok(ScriptedLifecycle {
            runtime_basis,
            source: self.source,
            reconciled: false,
            quarantined: Arc::clone(&self.quarantined),
        })
    }

    fn recover(
        &mut self,
        lifecycle: Self::Lifecycle,
    ) -> Result<(), QemuHotForkAttemptLifecycleRecoveryError<Self::Lifecycle, Self::Error>> {
        if !lifecycle.reconciled || lifecycle.source != self.source {
            return Err(QemuHotForkAttemptLifecycleRecoveryError::new(
                lifecycle,
                AttemptWorkerFailure::Terminal(ScriptedError),
            ));
        }
        self.available = true;
        Ok(())
    }

    fn quarantine(&mut self, mut lifecycle: Self::Lifecycle) {
        lifecycle.quarantine();
    }
}

impl sealed::QemuHotForkKeyedLifecycleFactory for ScriptedFactory {}

impl QemuHotForkKeyedLifecycleFactory for ScriptedFactory {
    fn template_key(&self) -> QemuHotForkTemplateKey {
        self.key
    }

    fn template_available(&self) -> bool {
        self.available
    }
}

#[derive(Clone, Default)]
struct ScriptedQuarantine {
    retained: Arc<Mutex<Vec<u64>>>,
}

impl QemuHotForkLifecycleQuarantine<QemuHotForkTemplatePoolLifecycle<ScriptedLifecycle>>
    for ScriptedQuarantine
{
    fn retain_lifecycle(&mut self, lifecycle: QemuHotForkTemplatePoolLifecycle<ScriptedLifecycle>) {
        self.retained
            .lock()
            .expect("retained lifecycles")
            .push(lifecycle.lifecycle.source);
    }
}

#[test]
fn exact_key_selection_uses_duplicate_slots_in_stable_order() {
    let input = execution_input();
    let basis = execution_basis(&input);
    let context = execution_context(&input);
    let key = template_key(&input);
    let starts = Arc::new(Mutex::new(Vec::new()));
    let quarantined = Arc::new(Mutex::new(Vec::new()));
    let mut pool = QemuHotForkTemplatePool::new(
        3,
        scripted_factory(key, 1, Arc::clone(&starts), Arc::clone(&quarantined)),
        ScriptedQuarantine::default(),
    )
    .expect("bounded pool");
    assert_eq!(pool.first_slot().expect("first coordinate").slot_index(), 0);
    let duplicate_slot = pool
        .insert(scripted_factory(
            key,
            2,
            Arc::clone(&starts),
            Arc::clone(&quarantined),
        ))
        .expect("duplicate exact-key slot");
    assert_eq!(duplicate_slot.template_key(), key);
    assert_eq!(duplicate_slot.slot_index(), 1);
    let foreign_slot = pool
        .insert(scripted_factory(
            foreign_key(basis),
            3,
            Arc::clone(&starts),
            Arc::clone(&quarantined),
        ))
        .expect("second exact key");
    assert_eq!(foreign_slot.slot_index(), 0);

    let mut first = pool.start(&input, &context, basis).expect("first slot");
    let mut second = pool.start(&input, &context, basis).expect("second slot");
    assert_eq!(first.slot_index(), 0);
    assert_eq!(second.slot_index(), 1);
    assert!(matches!(
        pool.start(&input, &context, basis),
        Err(AttemptWorkerFailure::Retryable(
            QemuHotForkTemplatePoolError::AllTemplatesBusy { .. }
        ))
    ));
    assert_eq!(starts.lock().expect("starts").as_slice(), &[1, 2]);
    assert_eq!(pool.slot_count(), 3);
    assert_eq!(pool.key_count(), 2);
    assert_eq!(pool.available_slot_count(), 1);

    reconcile(&mut first);
    reconcile(&mut second);
    pool.recover(first).expect("recover first slot");
    pool.recover(second).expect("recover second slot");
    assert_eq!(pool.available_slot_count(), 3);

    let selected = pool
        .start(&input, &context, basis)
        .expect("stable first slot");
    assert_eq!(selected.slot_index(), 0);
    pool.quarantine(selected);
}

#[test]
fn missing_exact_key_fails_before_any_worker_start() {
    let input = execution_input();
    let basis = execution_basis(&input);
    let context = execution_context(&input);
    let starts = Arc::new(Mutex::new(Vec::new()));
    let mut pool = QemuHotForkTemplatePool::new(
        1,
        scripted_factory(
            foreign_key(basis),
            4,
            Arc::clone(&starts),
            Arc::new(Mutex::new(Vec::new())),
        ),
        ScriptedQuarantine::default(),
    )
    .expect("foreign-only pool");

    assert!(matches!(
        pool.start(&input, &context, basis),
        Err(AttemptWorkerFailure::Terminal(
            QemuHotForkTemplatePoolError::MissingTemplate { .. }
        ))
    ));
    assert!(starts.lock().expect("starts").is_empty());
}

#[test]
fn pool_capacity_failures_return_every_uninstalled_worker() {
    let input = execution_input();
    let key = template_key(&input);
    let starts = Arc::new(Mutex::new(Vec::new()));
    let quarantined = Arc::new(Mutex::new(Vec::new()));
    for (capacity, expected) in [
        (0, QemuHotForkTemplatePoolCapacityError::Zero),
        (
            MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS + 1,
            QemuHotForkTemplatePoolCapacityError::AboveMaximum {
                requested: MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS + 1,
            },
        ),
    ] {
        let result = QemuHotForkTemplatePool::new(
            capacity,
            scripted_factory(key, 5, Arc::clone(&starts), Arc::clone(&quarantined)),
            ScriptedQuarantine::default(),
        );
        let error = match result {
            Err(error) => error,
            Ok(_pool) => panic!("invalid capacity must retain the first worker"),
        };
        let (factory, error) = error.into_parts();
        assert_eq!(factory.source, 5);
        assert_eq!(error, expected);
    }

    let mut pool = QemuHotForkTemplatePool::new(
        1,
        scripted_factory(key, 6, Arc::clone(&starts), Arc::clone(&quarantined)),
        ScriptedQuarantine::default(),
    )
    .expect("single-slot pool");
    let error = pool
        .insert(scripted_factory(key, 7, starts, quarantined))
        .expect_err("full pool insertion");
    assert_eq!(error.into_factory().source, 7);
}

#[test]
fn static_maximum_admits_exactly_the_bounded_worker_count() {
    let input = execution_input();
    let key = template_key(&input);
    let starts = Arc::new(Mutex::new(Vec::new()));
    let quarantined = Arc::new(Mutex::new(Vec::new()));
    let mut pool = QemuHotForkTemplatePool::new(
        MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS,
        scripted_factory(key, 1, Arc::clone(&starts), Arc::clone(&quarantined)),
        ScriptedQuarantine::default(),
    )
    .expect("maximum-size pool");
    for source in 2..=MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS as u64 {
        pool.insert(scripted_factory(
            key,
            source,
            Arc::clone(&starts),
            Arc::clone(&quarantined),
        ))
        .expect("bounded source slot");
    }
    assert_eq!(pool.slot_count(), MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS);

    let rejected = MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS as u64 + 1;
    let error = pool
        .insert(scripted_factory(key, rejected, starts, quarantined))
        .expect_err("slot above the static maximum");
    assert_eq!(error.into_factory().source, rejected);
}

#[test]
fn idle_retirement_returns_authority_and_busy_retirement_is_read_only() {
    let input = execution_input();
    let basis = execution_basis(&input);
    let context = execution_context(&input);
    let key = template_key(&input);
    let mut pool = pool(key, 11, ScriptedQuarantine::default());
    let mut lifecycle = pool.start(&input, &context, basis).expect("busy slot");

    assert!(matches!(
        pool.retire_idle(QemuHotForkTemplatePoolSlot::new(key, 0)),
        Err(QemuHotForkTemplatePoolRetirementError::Busy {
            key: actual_key,
            slot: 0,
        }) if actual_key == key
    ));
    assert_eq!(pool.slot_count(), 1);
    reconcile(&mut lifecycle);
    pool.recover(lifecycle).expect("recover before retirement");

    let factory = pool
        .retire_idle(QemuHotForkTemplatePoolSlot::new(key, 0))
        .expect("idle retirement");
    assert_eq!(factory.source, 11);
    assert_eq!(pool.slot_count(), 0);
    assert_eq!(pool.key_count(), 0);
    assert!(matches!(
        pool.retire_idle(QemuHotForkTemplatePoolSlot::new(key, 0)),
        Err(QemuHotForkTemplatePoolRetirementError::MissingSlot {
            key: actual_key,
            slot: 0,
        }) if actual_key == key
    ));
}

#[test]
fn retiring_an_idle_sibling_preserves_busy_coordinates_and_reuses_only_the_hole() {
    let input = execution_input();
    let basis = execution_basis(&input);
    let context = execution_context(&input);
    let key = template_key(&input);
    let starts = Arc::new(Mutex::new(Vec::new()));
    let quarantined = Arc::new(Mutex::new(Vec::new()));
    let mut pool = QemuHotForkTemplatePool::new(
        2,
        scripted_factory(key, 12, Arc::clone(&starts), Arc::clone(&quarantined)),
        ScriptedQuarantine::default(),
    )
    .expect("two-slot pool");
    pool.insert(scripted_factory(
        key,
        13,
        Arc::clone(&starts),
        Arc::clone(&quarantined),
    ))
    .expect("idle sibling");

    let mut original = pool.start(&input, &context, basis).expect("slot zero");
    assert_eq!(original.slot_index(), 0);
    assert_eq!(
        pool.retire_idle(QemuHotForkTemplatePoolSlot::new(key, 1))
            .expect("idle sibling")
            .source,
        13
    );
    pool.insert(scripted_factory(key, 14, starts, quarantined))
        .expect("reuse tombstone");
    let mut replacement = pool.start(&input, &context, basis).expect("reused slot");
    assert_eq!(replacement.slot_index(), 1);
    assert_eq!(replacement.lifecycle.source, 14);

    reconcile(&mut original);
    reconcile(&mut replacement);
    pool.recover(original)
        .expect("original coordinate survives");
    pool.recover(replacement)
        .expect("replacement coordinate survives");
    assert_eq!(pool.available_slot_count(), 2);
}

#[test]
fn foreign_pool_recovery_retains_the_exact_lifecycle_for_quarantine() {
    let input = execution_input();
    let basis = execution_basis(&input);
    let context = execution_context(&input);
    let key = template_key(&input);
    let lifecycle_quarantine = Arc::new(Mutex::new(Vec::new()));
    let mut first = pool(key, 8, ScriptedQuarantine::default());
    let mut second = pool(
        key,
        9,
        ScriptedQuarantine {
            retained: Arc::clone(&lifecycle_quarantine),
        },
    );
    let mut lifecycle = first
        .start(&input, &context, basis)
        .expect("first pool start");
    reconcile(&mut lifecycle);

    let error = second
        .recover(lifecycle)
        .expect_err("foreign pool recovery");
    let (lifecycle, failure) = error.into_parts();
    assert!(matches!(
        failure,
        AttemptWorkerFailure::Terminal(QemuHotForkTemplatePoolError::ForeignLifecycle)
    ));
    second.quarantine(lifecycle);
    assert_eq!(
        lifecycle_quarantine
            .lock()
            .expect("lifecycle quarantine")
            .as_slice(),
        &[8]
    );
}

#[test]
fn selected_factory_failure_preserves_its_retry_class() {
    let input = execution_input();
    let basis = execution_basis(&input);
    let context = execution_context(&input);
    let key = template_key(&input);
    for (failure, expected) in [
        (StartFailure::Retryable, "retryable"),
        (StartFailure::Canceled, "canceled"),
        (StartFailure::Terminal, "terminal"),
    ] {
        let mut factory = scripted_factory(
            key,
            10,
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(Vec::new())),
        );
        factory.failure = failure;
        let mut pool = QemuHotForkTemplatePool::new(1, factory, ScriptedQuarantine::default())
            .expect("failure pool");
        let actual = match pool.start(&input, &context, basis) {
            Err(AttemptWorkerFailure::Retryable(_)) => "retryable",
            Err(AttemptWorkerFailure::Canceled(_)) => "canceled",
            Err(AttemptWorkerFailure::Terminal(_)) => "terminal",
            Ok(_) => "success",
        };
        assert_eq!(actual, expected);
    }
}

fn reconcile(lifecycle: &mut QemuHotForkTemplatePoolLifecycle<ScriptedLifecycle>) {
    assert_eq!(
        lifecycle
            .reconcile_execution_disposition(AttemptExecutionDisposition::Canceled)
            .expect("semantic reconciliation"),
        AttemptExecutionReconciliationStep::Complete
    );
}

fn pool(
    key: QemuHotForkTemplateKey,
    source: u64,
    quarantine: ScriptedQuarantine,
) -> QemuHotForkTemplatePool<ScriptedFactory, ScriptedQuarantine> {
    QemuHotForkTemplatePool::new(
        1,
        scripted_factory(
            key,
            source,
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(Vec::new())),
        ),
        quarantine,
    )
    .expect("scripted pool")
}

fn scripted_factory(
    key: QemuHotForkTemplateKey,
    source: u64,
    starts: Arc<Mutex<Vec<u64>>>,
    quarantined: Arc<Mutex<Vec<u64>>>,
) -> ScriptedFactory {
    ScriptedFactory {
        key,
        source,
        available: true,
        failure: StartFailure::None,
        starts,
        quarantined,
    }
}

fn template_key(input: &CrucibleAttemptExecution) -> QemuHotForkTemplateKey {
    let basis = execution_basis(input);
    QemuHotForkTemplateKey::new(basis.key().lineage(), input_configuration(input))
}

fn foreign_key(basis: AttemptExecutionRuntimeBasis) -> QemuHotForkTemplateKey {
    QemuHotForkTemplateKey::new(
        basis.key().lineage(),
        crucible::ContentHash::from_bytes(b"foreign-template-key"),
    )
}

fn input_configuration(input: &CrucibleAttemptExecution) -> crucible::ContentHash {
    match input.start() {
        crate::CrucibleResolvedAttemptStart::Discover { configuration } => configuration.id(),
        crate::CrucibleResolvedAttemptStart::Branch { parent, .. } => parent.id(),
    }
}

fn execution_input() -> CrucibleAttemptExecution {
    let scenario = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    let definition = scenario.scenario_def();
    let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(definition.id().bytes));
    let scenario_artifact =
        ScenarioArtifact::new(scenario_id, 1, b"scenario".to_vec()).expect("scenario artifact");
    let scenario_content = scenario_artifact.id().expect("scenario artifact id");
    let configuration = Configuration::genesis(definition);
    let configuration_id =
        ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes));
    let configuration_artifact = ConfigurationArtifact::new(
        scenario_id,
        scenario_content,
        configuration_id,
        1,
        b"configuration".to_vec(),
    )
    .expect("configuration artifact");
    let configuration_content = configuration_artifact
        .id()
        .expect("configuration artifact id");
    let lineage = CampaignLineage::new(
        scenario_id,
        scenario_content,
        configuration_id,
        configuration_content,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("campaign lineage");
    let path = BranchPath::new(Vec::new()).expect("genesis path");
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_content,
        },
        path.id().expect("path id"),
        StopCondition::Terminal,
    )
    .expect("attempt");
    CrucibleAttemptExecution::from_test_parts(
        lineage,
        scenario,
        attempt,
        path,
        crate::CrucibleResolvedAttemptStart::Discover { configuration },
    )
}

fn execution_basis(input: &CrucibleAttemptExecution) -> AttemptExecutionRuntimeBasis {
    AttemptExecutionRuntimeBasis::new(
        AttemptExecutionKey::new(
            input.lineage().id().expect("lineage id"),
            input.attempt().id().expect("attempt id"),
        ),
        ExecutionId::from_bytes([0x61; 16]).expect("execution"),
    )
}

fn execution_context(input: &CrucibleAttemptExecution) -> AttemptExecutionContext {
    let checkpoint = ExecutionCheckpointRequest::default();
    checkpoint.request_for_test();
    AttemptExecutionContext::new(
        AttemptResourceLimits::new(2, 64 * 1024 * 1024, 128 * 1024 * 1024, 8).expect("resources"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        checkpoint,
    )
    .with_runtime_basis(execution_basis(input))
}
