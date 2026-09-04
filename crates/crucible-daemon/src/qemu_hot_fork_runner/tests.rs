// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crucible::{Checkpoint, Configuration, ScenarioDef, VirtualTime};
use crucible_campaign::{
    Attempt, AttemptResourceLimits, AttemptStart, BranchPath, CampaignHash, CampaignLineage,
    ConfigurationArtifact, ConfigurationId, ExactCheckpointId, ExecutionId,
    ExecutionRetentionIntent, ScenarioArtifact, ScenarioDefId, StopCondition,
};
use crucible_cas::content_store::{BlobHandle, ContentId, ObjectKind};
use crucible_qemu::{
    QemuHotForkChildDiagnosticDrain, QemuHotForkHostContinuation, QemuNodeChannelError,
    QemuQmpVmStateControlChannel, QemuReplayOracleValidation, QemuVmRealizationError,
    QemuVmSnapshot,
};

use super::*;
use crate::{
    AttemptExecutionKey, CapturedExactCheckpoint, ExecutionCancellation, ExecutionCheckpointRequest,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("scripted hot-fork failure")]
struct ScriptedError;

struct ScriptedLive<'a> {
    calls: &'a Arc<Mutex<Vec<&'static str>>>,
    resources: AttemptResourceLimits,
    cancellation: &'a ExecutionCancellation,
}

impl QemuAttemptOperationalBoundary for ScriptedLive<'_> {
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        self.calls.lock().expect("calls").push("boundary");
        if self.cancellation.is_canceled() {
            Err(QemuVmRealizationError::Canceled {
                operation: "scripted hot-fork boundary",
            })
        } else {
            Ok(())
        }
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.calls.lock().expect("calls").push("quantum");
        Ok(())
    }
}

impl QemuHotForkLiveExecution for ScriptedLive<'_> {
    fn child_qmp_mut(
        &mut self,
    ) -> &mut QemuQmpVmStateControlChannel<std::os::unix::net::UnixStream> {
        panic!("scripted driver does not use raw child QMP")
    }

    fn host_continuation_mut(&mut self) -> &mut QemuHotForkHostContinuation {
        panic!("scripted driver does not use a host continuation")
    }

    fn drain_diagnostics(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticDrain, QemuVmRealizationError> {
        panic!("scripted driver does not use child diagnostics")
    }
}

struct ScriptedLifecycle {
    basis: AttemptExecutionRuntimeBasis,
    calls: Arc<Mutex<Vec<&'static str>>>,
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    fail_stop: bool,
    stopped: bool,
    reconciliation_steps: u8,
    disposition: Option<AttemptExecutionDisposition>,
}

impl QemuHotForkAttemptLifecycle for ScriptedLifecycle {
    type Live<'a>
        = ScriptedLive<'a>
    where
        Self: 'a;
    type Error = ScriptedError;

    fn runtime_basis(&self) -> AttemptExecutionRuntimeBasis {
        self.basis
    }

    fn admit_child(&mut self) -> Result<(), Self::Error> {
        self.calls.lock().expect("calls").push("admit");
        Ok(())
    }

    fn live_child(&mut self) -> Result<Self::Live<'_>, Self::Error> {
        Ok(ScriptedLive {
            calls: &self.calls,
            resources: self.resources,
            cancellation: &self.cancellation,
        })
    }

    fn stop_before_publication(
        &mut self,
        _exit_policy: QemuHotForkChildExitPolicy,
    ) -> Result<(), Self::Error> {
        self.calls.lock().expect("calls").push("stop");
        if self.fail_stop {
            return Err(ScriptedError);
        }
        self.stopped = true;
        Ok(())
    }

    fn reconcile_execution_disposition(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        self.calls.lock().expect("calls").push("reconcile");
        if !self.stopped
            || self
                .disposition
                .is_some_and(|retained| retained != disposition)
        {
            return Err(AttemptWorkerFailure::Terminal(ScriptedError));
        }
        self.disposition = Some(disposition);
        self.reconciliation_steps = self.reconciliation_steps.saturating_add(1);
        if self.reconciliation_steps == 1 {
            Ok(AttemptExecutionReconciliationStep::Progressed)
        } else {
            Ok(AttemptExecutionReconciliationStep::Complete)
        }
    }
}

struct ScriptedFactory {
    calls: Arc<Mutex<Vec<&'static str>>>,
    wrong_basis: bool,
    fail_stop: bool,
    fail_recover_once: bool,
}

impl ScriptedFactory {
    fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            wrong_basis: false,
            fail_stop: false,
            fail_recover_once: false,
        }
    }
}

impl QemuHotForkAttemptLifecycleFactory for ScriptedFactory {
    type Lifecycle = ScriptedLifecycle;
    type Error = ScriptedError;

    fn start(
        &mut self,
        _input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        runtime_basis: AttemptExecutionRuntimeBasis,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.calls.lock().expect("calls").push("start");
        let basis = if self.wrong_basis {
            AttemptExecutionRuntimeBasis::new(
                runtime_basis.key(),
                ExecutionId::from_bytes([0x99; 16]).expect("foreign execution"),
            )
        } else {
            runtime_basis
        };
        Ok(ScriptedLifecycle {
            basis,
            calls: Arc::clone(&self.calls),
            resources: context.resources(),
            cancellation: context.cancellation().clone(),
            fail_stop: self.fail_stop,
            stopped: false,
            reconciliation_steps: 0,
            disposition: None,
        })
    }

    fn recover(
        &mut self,
        lifecycle: Self::Lifecycle,
    ) -> Result<(), QemuHotForkAttemptLifecycleRecoveryError<Self::Lifecycle, Self::Error>> {
        self.calls.lock().expect("calls").push("recover");
        if self.fail_recover_once {
            self.fail_recover_once = false;
            Err(QemuHotForkAttemptLifecycleRecoveryError::new(
                lifecycle,
                AttemptWorkerFailure::Retryable(ScriptedError),
            ))
        } else {
            Ok(())
        }
    }

    fn quarantine(&mut self, _lifecycle: Self::Lifecycle) {
        self.calls.lock().expect("calls").push("quarantine");
    }
}

#[derive(Clone, Copy)]
enum DriverDisposition {
    Success,
    Retryable,
    Canceled,
    Terminal,
}

struct ScriptedDriver {
    disposition: DriverDisposition,
}

impl QemuHotForkAttemptDriver for ScriptedDriver {
    type Pending = ();
    type Error = ScriptedError;

    fn drive<L>(
        &mut self,
        live: &mut L,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Pending, AttemptWorkerFailure<Self::Error>>
    where
        L: QemuHotForkLiveExecution,
    {
        live.charge_execution_quantum()
            .map_err(|_error| AttemptWorkerFailure::Terminal(ScriptedError))?;
        match self.disposition {
            DriverDisposition::Success => Ok(()),
            DriverDisposition::Retryable => Err(AttemptWorkerFailure::Retryable(ScriptedError)),
            DriverDisposition::Canceled => Err(AttemptWorkerFailure::Canceled(ScriptedError)),
            DriverDisposition::Terminal => Err(AttemptWorkerFailure::Terminal(ScriptedError)),
        }
    }

    fn seal<L>(
        &mut self,
        _pending: Self::Pending,
        live: &mut L,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>>
    where
        L: QemuHotForkLiveExecution,
    {
        live.check_operational_boundary()
            .map_err(|_error| AttemptWorkerFailure::Terminal(ScriptedError))?;
        Ok(checkpoint_product())
    }
}

fn policy() -> QemuHotForkChildExitPolicy {
    QemuHotForkChildExitPolicy::new(std::time::Duration::from_millis(1), 5).expect("exit policy")
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
        ExecutionId::from_bytes([0x42; 16]).expect("execution"),
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

fn checkpoint_product() -> AttemptExecutionProduct {
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.hot-fork-runner",
        "sealed-product",
    ));
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        crucible::CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("checkpoint");
    let snapshot =
        QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun).expect("snapshot");
    AttemptExecutionProduct::exact_checkpoint(CapturedExactCheckpoint::new(
        snapshot,
        BlobHandle::from_bytes(vec![0x5a; 512]),
    ))
}

fn checkpoint_id() -> ExactCheckpointId {
    ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        4,
        b"hot-fork-runner-checkpoint",
    ))
    .expect("checkpoint id")
}

fn calls(
    runner: &QemuHotForkExecutionRunner<ScriptedFactory, ScriptedDriver>,
) -> Vec<&'static str> {
    runner.factory.calls.lock().expect("calls").clone()
}

#[test]
fn successful_result_waits_for_exact_semantic_disposition_before_recovery() {
    let input = execution_input();
    let context = execution_context(&input);
    let mut runner = QemuHotForkExecutionRunner::new(
        ScriptedFactory::new(),
        ScriptedDriver {
            disposition: DriverDisposition::Success,
        },
        policy(),
    );

    let outcome = runner.execute(&input, &context).expect("hot-fork result");
    assert_eq!(
        outcome.materialization(),
        CrucibleMaterializationTier::HotFork
    );
    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
    assert!(runner.has_pending_reconciliation());
    assert_eq!(
        calls(&runner),
        ["start", "admit", "quantum", "boundary", "stop"]
    );

    assert_eq!(
        runner
            .reconcile_execution(AttemptExecutionDisposition::ExactCheckpoint(checkpoint_id()))
            .expect("first reconciliation"),
        AttemptExecutionReconciliationStep::Progressed
    );
    assert_eq!(
        runner
            .reconcile_execution(AttemptExecutionDisposition::ExactCheckpoint(checkpoint_id()))
            .expect("final reconciliation"),
        AttemptExecutionReconciliationStep::Complete
    );
    assert!(!runner.has_pending_reconciliation());
    assert_eq!(
        calls(&runner),
        [
            "start",
            "admit",
            "quantum",
            "boundary",
            "stop",
            "reconcile",
            "reconcile",
            "recover",
        ]
    );
}

#[test]
fn retryable_driver_failure_is_quarantined_without_fabricating_publication() {
    let input = execution_input();
    let context = execution_context(&input);
    let mut runner = QemuHotForkExecutionRunner::new(
        ScriptedFactory::new(),
        ScriptedDriver {
            disposition: DriverDisposition::Retryable,
        },
        policy(),
    );

    assert!(matches!(
        runner.execute(&input, &context),
        Err(AttemptWorkerFailure::Retryable(
            QemuHotForkExecutionRunnerError::Driver(ScriptedError)
        ))
    ));
    assert!(!runner.has_pending_reconciliation());
    assert_eq!(
        calls(&runner),
        ["start", "admit", "quantum", "stop", "quarantine"]
    );
}

#[test]
fn cancellation_quarantines_without_fabricating_semantic_retirement() {
    let input = execution_input();
    let context = execution_context(&input);
    let mut runner = QemuHotForkExecutionRunner::new(
        ScriptedFactory::new(),
        ScriptedDriver {
            disposition: DriverDisposition::Canceled,
        },
        policy(),
    );

    assert!(matches!(
        runner.execute(&input, &context),
        Err(AttemptWorkerFailure::Canceled(
            QemuHotForkExecutionRunnerError::Driver(ScriptedError)
        ))
    ));
    assert!(!runner.has_pending_reconciliation());
    assert_eq!(calls(&runner).last(), Some(&"quarantine"));
}

#[test]
fn foreign_runtime_basis_is_quarantined_before_child_admission() {
    let input = execution_input();
    let context = execution_context(&input);
    let mut factory = ScriptedFactory::new();
    factory.wrong_basis = true;
    let mut runner = QemuHotForkExecutionRunner::new(
        factory,
        ScriptedDriver {
            disposition: DriverDisposition::Success,
        },
        policy(),
    );

    assert!(matches!(
        runner.execute(&input, &context),
        Err(AttemptWorkerFailure::Terminal(
            QemuHotForkExecutionRunnerError::RuntimeBasisMismatch
        ))
    ));
    assert_eq!(calls(&runner), ["start", "quarantine"]);
}

#[test]
fn missing_runtime_basis_and_exact_resume_fail_before_factory_access() {
    let input = execution_input();
    let resources =
        AttemptResourceLimits::new(2, 64 * 1024 * 1024, 128 * 1024 * 1024, 8).expect("resources");
    let context = AttemptExecutionContext::new(
        resources,
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
    );
    let mut runner = QemuHotForkExecutionRunner::new(
        ScriptedFactory::new(),
        ScriptedDriver {
            disposition: DriverDisposition::Success,
        },
        policy(),
    );
    assert!(matches!(
        runner.execute(&input, &context),
        Err(AttemptWorkerFailure::Terminal(
            QemuHotForkExecutionRunnerError::MissingRuntimeBasis
        ))
    ));
    assert!(calls(&runner).is_empty());

    let resumed = context
        .with_runtime_basis(execution_basis(&input))
        .with_resume_checkpoint(Some(checkpoint_id()));
    assert!(matches!(
        runner.execute(&input, &resumed),
        Err(AttemptWorkerFailure::Terminal(
            QemuHotForkExecutionRunnerError::ResumeCheckpointUnsupported(_)
        ))
    ));
    assert!(calls(&runner).is_empty());
}

#[test]
fn pending_publication_prevents_a_second_child_launch() {
    let input = execution_input();
    let context = execution_context(&input);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let factory = ScriptedFactory {
        calls: Arc::clone(&calls),
        wrong_basis: false,
        fail_stop: false,
        fail_recover_once: false,
    };
    let mut runner = QemuHotForkExecutionRunner::new(
        factory,
        ScriptedDriver {
            disposition: DriverDisposition::Success,
        },
        policy(),
    );
    runner.execute(&input, &context).expect("first result");
    assert!(matches!(
        runner.execute(&input, &context),
        Err(AttemptWorkerFailure::Terminal(
            QemuHotForkExecutionRunnerError::PriorReconciliationPending
        ))
    ));
    assert_eq!(
        calls
            .lock()
            .expect("calls")
            .iter()
            .filter(|call| **call == "start")
            .count(),
        1
    );
    drop(runner);
    assert_eq!(calls.lock().expect("calls").last(), Some(&"quarantine"));
}

#[test]
fn teardown_failure_quarantines_instead_of_returning_a_product() {
    let input = execution_input();
    let context = execution_context(&input);
    let mut factory = ScriptedFactory::new();
    factory.fail_stop = true;
    let mut runner = QemuHotForkExecutionRunner::new(
        factory,
        ScriptedDriver {
            disposition: DriverDisposition::Success,
        },
        policy(),
    );

    assert!(matches!(
        runner.execute(&input, &context),
        Err(AttemptWorkerFailure::Terminal(
            QemuHotForkExecutionRunnerError::Lifecycle(ScriptedError)
        ))
    ));
    assert_eq!(
        calls(&runner),
        [
            "start",
            "admit",
            "quantum",
            "boundary",
            "stop",
            "quarantine",
        ]
    );
}

#[test]
fn retryable_template_recovery_retains_the_exact_lifecycle_token() {
    let input = execution_input();
    let context = execution_context(&input);
    let mut factory = ScriptedFactory::new();
    factory.fail_recover_once = true;
    let mut runner = QemuHotForkExecutionRunner::new(
        factory,
        ScriptedDriver {
            disposition: DriverDisposition::Success,
        },
        policy(),
    );
    runner.execute(&input, &context).expect("hot-fork result");
    let disposition = AttemptExecutionDisposition::ExactCheckpoint(checkpoint_id());
    assert_eq!(
        runner
            .reconcile_execution(disposition)
            .expect("reconciliation progress"),
        AttemptExecutionReconciliationStep::Progressed
    );
    assert!(matches!(
        runner.reconcile_execution(disposition),
        Err(AttemptWorkerFailure::Retryable(
            QemuHotForkExecutionRunnerError::Factory(ScriptedError)
        ))
    ));
    assert!(runner.has_pending_reconciliation());
    assert_eq!(
        runner
            .reconcile_execution(disposition)
            .expect("recovery retry"),
        AttemptExecutionReconciliationStep::Complete
    );
    assert_eq!(
        calls(&runner)
            .iter()
            .filter(|call| **call == "recover")
            .count(),
        2
    );
}

#[test]
fn dropping_a_pending_runner_transfers_the_lifecycle_to_quarantine() {
    let input = execution_input();
    let context = execution_context(&input);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let factory = ScriptedFactory {
        calls: Arc::clone(&calls),
        wrong_basis: false,
        fail_stop: false,
        fail_recover_once: false,
    };
    let mut runner = QemuHotForkExecutionRunner::new(
        factory,
        ScriptedDriver {
            disposition: DriverDisposition::Success,
        },
        policy(),
    );
    runner.execute(&input, &context).expect("hot-fork result");
    drop(runner);
    assert_eq!(calls.lock().expect("calls").last(), Some(&"quarantine"));
}

#[test]
fn exit_policy_rejects_unbounded_or_busy_polling() {
    assert_eq!(
        QemuHotForkChildExitPolicy::new(std::time::Duration::ZERO, 1),
        Err(QemuHotForkChildExitPolicyError::IntervalTooShort)
    );
    assert_eq!(
        QemuHotForkChildExitPolicy::new(std::time::Duration::from_millis(1), 0),
        Err(QemuHotForkChildExitPolicyError::ZeroPolls)
    );
    assert_eq!(
        QemuHotForkChildExitPolicy::new(std::time::Duration::from_secs(2), 1),
        Err(QemuHotForkChildExitPolicyError::IntervalTooLong)
    );
    assert_eq!(
        QemuHotForkChildExitPolicy::new(std::time::Duration::from_secs(1), 3_601),
        Err(QemuHotForkChildExitPolicyError::WaitTooLong)
    );
}

#[test]
fn reconciliation_classification_retries_only_recoverable_owner_operations() {
    let release = classify_reconciliation_failure(QemuHotForkAttemptReconciliationError::Backend {
        operation: "release branch-private child resources",
        source: LinuxQemuHotForkReconciliationError::Source(QemuNodeChannelError::new(
            "release resource",
            "temporary source channel failure",
        )),
    });
    assert!(matches!(release, AttemptWorkerFailure::Retryable(_)));

    let drain = classify_reconciliation_failure(QemuHotForkAttemptReconciliationError::Backend {
        operation: "drain branch-private child diagnostics",
        source: LinuxQemuHotForkReconciliationError::Source(QemuNodeChannelError::new(
            "drain diagnostics",
            "complete diagnostic retention failed",
        )),
    });
    assert!(matches!(drain, AttemptWorkerFailure::Terminal(_)));
    assert!(matches!(
        classify_reconciliation_failure(QemuHotForkAttemptReconciliationError::ChildBasisMismatch),
        AttemptWorkerFailure::Terminal(_)
    ));
}

#[test]
fn terminal_driver_failure_is_quarantined_before_returning() {
    let input = execution_input();
    let context = execution_context(&input);
    let mut runner = QemuHotForkExecutionRunner::new(
        ScriptedFactory::new(),
        ScriptedDriver {
            disposition: DriverDisposition::Terminal,
        },
        policy(),
    );

    assert!(matches!(
        runner.execute(&input, &context),
        Err(AttemptWorkerFailure::Terminal(
            QemuHotForkExecutionRunnerError::Driver(ScriptedError)
        ))
    ));
    assert!(!runner.has_pending_reconciliation());
    assert_eq!(calls(&runner).last(), Some(&"quarantine"));
}
