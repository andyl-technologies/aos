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
use crucible_qemu::{
    QemuHotForkChildDiagnosticDrain, QemuHotForkHostContinuation, QemuQmpVmStateControlChannel,
};

use super::*;
use crate::{
    AttemptExecutionKey, ExecutionCancellation, ExecutionCheckpointRequest,
    QemuAttemptOperationalBoundary, QemuHotForkChildExitPolicy, QemuHotForkLiveExecution,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("scripted template failure")]
struct ScriptedError;

struct ScriptedTemplate {
    configuration: ContentHash,
    incarnation: u64,
}

impl sealed::QemuHotForkTemplateSource for ScriptedTemplate {}

impl QemuHotForkTemplateSource for ScriptedTemplate {
    fn configuration(&self) -> ContentHash {
        self.configuration
    }
}

#[derive(Default)]
struct ScriptedGuardState {
    begins: usize,
    finishes: usize,
    quarantines: usize,
}

struct ScriptedGuard {
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    state: Arc<Mutex<ScriptedGuardState>>,
    terminal: bool,
}

impl QemuAttemptOperationalBoundary for ScriptedGuard {
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.cancellation.is_canceled() {
            Err(QemuVmRealizationError::Canceled {
                operation: "scripted template guard",
            })
        } else {
            Ok(())
        }
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.check_operational_boundary()
    }
}

impl QemuAttemptResourceGuard for ScriptedGuard {
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        if !self.terminal {
            self.state.lock().expect("guard state").finishes += 1;
            self.terminal = true;
        }
        Ok(())
    }

    fn quarantine(&mut self) {
        if !self.terminal {
            self.state.lock().expect("guard state").quarantines += 1;
            self.terminal = true;
        }
    }
}

#[derive(Clone, Copy)]
enum GuardFailure {
    None,
    Unavailable,
    Canceled,
    Terminal,
}

struct ScriptedResourceFactory {
    state: Arc<Mutex<ScriptedGuardState>>,
    failure: GuardFailure,
}

impl QemuAttemptResourceGuardFactory for ScriptedResourceFactory {
    type Guard = ScriptedGuard;

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
    ) -> Result<Self::Guard, QemuVmRealizationError> {
        self.state.lock().expect("guard state").begins += 1;
        match self.failure {
            GuardFailure::None => Ok(ScriptedGuard {
                resources,
                cancellation,
                state: Arc::clone(&self.state),
                terminal: false,
            }),
            GuardFailure::Unavailable => Err(QemuVmRealizationError::ExecutorUnavailable {
                operation: "scripted resource admission",
                message: String::from("temporarily unavailable"),
            }),
            GuardFailure::Canceled => Err(QemuVmRealizationError::Canceled {
                operation: "scripted resource admission",
            }),
            GuardFailure::Terminal => Err(QemuVmRealizationError::Executor {
                operation: "scripted resource admission",
                message: String::from("stable failure"),
            }),
        }
    }
}

struct ScriptedLive<'a> {
    guard: &'a mut ScriptedGuard,
    event_log: &'a mut EventLog,
}

impl QemuAttemptOperationalBoundary for ScriptedLive<'_> {
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.guard.resource_limits()
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        self.guard.cancellation()
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        self.guard.check_operational_boundary()
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.guard.charge_execution_quantum()
    }
}

impl QemuHotForkLiveExecution for ScriptedLive<'_> {
    fn child_qmp_mut(
        &mut self,
    ) -> &mut QemuQmpVmStateControlChannel<std::os::unix::net::UnixStream> {
        panic!("scripted template lifecycle has no QMP channel")
    }

    fn host_continuation_mut(&mut self) -> &mut QemuHotForkHostContinuation {
        panic!("scripted template lifecycle has no host continuation")
    }

    fn event_log_mut(&mut self) -> &mut EventLog {
        self.event_log
    }

    fn drain_diagnostics(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticDrain, QemuVmRealizationError> {
        panic!("scripted template lifecycle has no diagnostics")
    }
}

struct ScriptedLifecycle {
    basis: AttemptExecutionRuntimeBasis,
    template: Option<ScriptedTemplate>,
    guard: ScriptedGuard,
    event_log: EventLog,
    stopped: bool,
    complete: bool,
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
        Ok(())
    }

    fn live_child(&mut self) -> Result<Self::Live<'_>, Self::Error> {
        Ok(ScriptedLive {
            guard: &mut self.guard,
            event_log: &mut self.event_log,
        })
    }

    fn stop_before_publication(
        &mut self,
        _exit_policy: QemuHotForkChildExitPolicy,
    ) -> Result<(), Self::Error> {
        self.stopped = true;
        Ok(())
    }

    fn reconcile_execution_disposition(
        &mut self,
        _disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        if !self.stopped {
            return Err(AttemptWorkerFailure::Terminal(ScriptedError));
        }
        self.guard
            .finish()
            .map_err(|_source| AttemptWorkerFailure::Terminal(ScriptedError))?;
        self.complete = true;
        Ok(AttemptExecutionReconciliationStep::Complete)
    }

    fn quarantine(&mut self) {
        self.guard.quarantine();
    }
}

struct ScriptedLauncher {
    fail_launch: bool,
}

impl QemuHotForkTemplateLauncher<ScriptedGuard> for ScriptedLauncher {
    type Template = ScriptedTemplate;
    type Lifecycle = ScriptedLifecycle;
    type Error = ScriptedError;

    fn launch(
        &mut self,
        template: Self::Template,
        target: ScriptedGuard,
        runtime_basis: AttemptExecutionRuntimeBasis,
        _input: &CrucibleAttemptExecution,
    ) -> Result<
        Self::Lifecycle,
        QemuHotForkTemplateLaunchFailure<Self::Template, ScriptedGuard, Self::Error>,
    > {
        if self.fail_launch {
            return Err(QemuHotForkTemplateLaunchFailure::new(
                template,
                target,
                ScriptedError,
            ));
        }
        Ok(ScriptedLifecycle {
            basis: runtime_basis,
            template: Some(template),
            guard: target,
            event_log: EventLog::new(),
            stopped: false,
            complete: false,
        })
    }

    fn recover(
        &mut self,
        mut lifecycle: Self::Lifecycle,
    ) -> Result<
        Self::Template,
        QemuHotForkTemplateSourceRecoveryFailure<Self::Lifecycle, Self::Error>,
    > {
        if !lifecycle.complete {
            return Err(QemuHotForkTemplateSourceRecoveryFailure::new(
                lifecycle,
                AttemptWorkerFailure::Terminal(ScriptedError),
            ));
        }
        Ok(lifecycle.template.take().expect("recovered template"))
    }
}

#[derive(Clone, Default)]
struct ScriptedQuarantine {
    templates: Arc<Mutex<Vec<u64>>>,
    lifecycles: Arc<Mutex<Vec<u64>>>,
}

impl QemuHotForkFactoryQuarantine<ScriptedTemplate, QemuHotForkPooledLifecycle<ScriptedLifecycle>>
    for ScriptedQuarantine
{
    fn retain_template(&mut self, template: QemuHotForkBoundTemplate<ScriptedTemplate>) {
        let (_key, template) = template.into_parts();
        self.templates
            .lock()
            .expect("quarantined templates")
            .push(template.incarnation);
    }

    fn retain_lifecycle(&mut self, lifecycle: QemuHotForkPooledLifecycle<ScriptedLifecycle>) {
        self.lifecycles
            .lock()
            .expect("quarantined lifecycles")
            .push(
                lifecycle
                    .lifecycle
                    .template
                    .as_ref()
                    .expect("lifecycle template")
                    .incarnation,
            );
    }
}

type ScriptedFactory =
    FixedQemuHotForkTemplateFactory<ScriptedResourceFactory, ScriptedLauncher, ScriptedQuarantine>;

#[test]
fn exact_template_is_recovered_only_after_semantic_reconciliation() {
    let input = execution_input();
    let basis = execution_basis(&input);
    let context = execution_context(&input);
    let state = Arc::new(Mutex::new(ScriptedGuardState::default()));
    let quarantine = ScriptedQuarantine::default();
    let mut factory = factory(
        &input,
        11,
        GuardFailure::None,
        false,
        Arc::clone(&state),
        quarantine,
    );

    let mut lifecycle = factory
        .start(&input, &context, basis)
        .expect("start exact lifecycle");
    assert!(!factory.template_available());
    lifecycle.admit_child().expect("admit child");
    lifecycle
        .stop_before_publication(exit_policy())
        .expect("stop child");
    assert_eq!(
        lifecycle
            .reconcile_execution_disposition(AttemptExecutionDisposition::Canceled)
            .expect("reconcile disposition"),
        AttemptExecutionReconciliationStep::Complete
    );
    factory.recover(lifecycle).expect("recover template");

    assert!(factory.template_available());
    let state = state.lock().expect("guard state");
    assert_eq!(state.begins, 1);
    assert_eq!(state.finishes, 1);
    assert_eq!(state.quarantines, 0);
}

#[test]
fn mismatched_template_key_fails_before_resource_admission() {
    let input = execution_input();
    let basis = execution_basis(&input);
    let context = execution_context(&input);
    let state = Arc::new(Mutex::new(ScriptedGuardState::default()));
    let quarantine = ScriptedQuarantine::default();
    let foreign = ContentHash::from_bytes(b"foreign-template");
    let mut factory = FixedQemuHotForkTemplateFactory::new(
        QemuHotForkTemplateKey::new(basis.key().lineage(), foreign),
        ScriptedTemplate {
            configuration: foreign,
            incarnation: 12,
        },
        ScriptedResourceFactory {
            state: Arc::clone(&state),
            failure: GuardFailure::None,
        },
        ScriptedLauncher { fail_launch: false },
        quarantine,
    )
    .expect("foreign-key factory");

    assert!(matches!(
        factory.start(&input, &context, basis),
        Err(AttemptWorkerFailure::Terminal(
            FixedQemuHotForkTemplateFactoryError::TemplateKeyMismatch { .. }
        ))
    ));
    assert!(factory.template_available());
    assert_eq!(state.lock().expect("guard state").begins, 0);
}

#[test]
fn resource_failures_preserve_the_source_and_retry_class() {
    let input = execution_input();
    let basis = execution_basis(&input);
    let context = execution_context(&input);
    for (failure, expected) in [
        (GuardFailure::Unavailable, "retryable"),
        (GuardFailure::Canceled, "canceled"),
        (GuardFailure::Terminal, "terminal"),
    ] {
        let state = Arc::new(Mutex::new(ScriptedGuardState::default()));
        let mut factory = factory(
            &input,
            13,
            failure,
            false,
            state,
            ScriptedQuarantine::default(),
        );
        let actual = match factory.start(&input, &context, basis) {
            Err(AttemptWorkerFailure::Retryable(_)) => "retryable",
            Err(AttemptWorkerFailure::Canceled(_)) => "canceled",
            Err(AttemptWorkerFailure::Terminal(_)) => "terminal",
            Ok(_) => "success",
        };
        assert_eq!(actual, expected);
        assert!(factory.template_available());
    }
}

#[test]
fn failed_launch_quarantines_target_and_removes_source_slot() {
    let input = execution_input();
    let basis = execution_basis(&input);
    let context = execution_context(&input);
    let state = Arc::new(Mutex::new(ScriptedGuardState::default()));
    let quarantine = ScriptedQuarantine::default();
    let retained = Arc::clone(&quarantine.templates);
    let mut factory = factory(
        &input,
        14,
        GuardFailure::None,
        true,
        Arc::clone(&state),
        quarantine,
    );

    assert!(matches!(
        factory.start(&input, &context, basis),
        Err(AttemptWorkerFailure::Terminal(
            FixedQemuHotForkTemplateFactoryError::Launch(ScriptedError)
        ))
    ));
    assert!(!factory.template_available());
    assert_eq!(
        retained.lock().expect("quarantined templates").as_slice(),
        &[14]
    );
    assert_eq!(state.lock().expect("guard state").quarantines, 1);
}

#[test]
fn foreign_factory_cannot_recover_a_template_incarnation() {
    let input = execution_input();
    let basis = execution_basis(&input);
    let context = execution_context(&input);
    let mut first = factory(
        &input,
        21,
        GuardFailure::None,
        false,
        Arc::new(Mutex::new(ScriptedGuardState::default())),
        ScriptedQuarantine::default(),
    );
    let second_quarantine = ScriptedQuarantine::default();
    let retained = Arc::clone(&second_quarantine.lifecycles);
    let mut second = factory(
        &input,
        22,
        GuardFailure::None,
        false,
        Arc::new(Mutex::new(ScriptedGuardState::default())),
        second_quarantine,
    );
    let lifecycle = first
        .start(&input, &context, basis)
        .expect("first lifecycle");

    let error = second.recover(lifecycle).expect_err("foreign recovery");
    let (lifecycle, failure) = error.into_parts();
    assert!(matches!(
        failure,
        AttemptWorkerFailure::Terminal(FixedQemuHotForkTemplateFactoryError::ForeignLifecycle)
    ));
    second.quarantine(lifecycle);
    assert_eq!(
        retained.lock().expect("quarantined lifecycle").as_slice(),
        &[21]
    );
}

#[test]
fn construction_mismatch_returns_the_prepared_source() {
    let input = execution_input();
    let basis = execution_basis(&input);
    let expected = template_configuration(&input);
    let source = ScriptedTemplate {
        configuration: expected,
        incarnation: 31,
    };
    let result = FixedQemuHotForkTemplateFactory::new(
        QemuHotForkTemplateKey::new(
            basis.key().lineage(),
            ContentHash::from_bytes(b"different-key"),
        ),
        source,
        ScriptedResourceFactory {
            state: Arc::new(Mutex::new(ScriptedGuardState::default())),
            failure: GuardFailure::None,
        },
        ScriptedLauncher { fail_launch: false },
        ScriptedQuarantine::default(),
    );
    let error = match result {
        Err(error) => error,
        Ok(_factory) => panic!("configuration mismatch must retain the source"),
    };
    let (source, diagnostic) = error.into_parts();
    assert_eq!(source.incarnation, 31);
    assert!(matches!(
        diagnostic,
        FixedQemuHotForkTemplateFactoryError::TemplateConfigurationMismatch { .. }
    ));
}

#[test]
fn dropping_an_idle_factory_transfers_exactly_one_source() {
    let input = execution_input();
    let quarantine = ScriptedQuarantine::default();
    let retained = Arc::clone(&quarantine.templates);
    let factory = factory(
        &input,
        41,
        GuardFailure::None,
        false,
        Arc::new(Mutex::new(ScriptedGuardState::default())),
        quarantine,
    );
    drop(factory);
    assert_eq!(
        retained.lock().expect("quarantined template").as_slice(),
        &[41]
    );
}

#[test]
fn process_lifetime_quarantine_never_drops_accepted_authority() {
    struct DropWitness(Arc<Mutex<bool>>);
    impl Drop for DropWitness {
        fn drop(&mut self) {
            *self.0.lock().expect("drop witness") = true;
        }
    }

    let dropped = Arc::new(Mutex::new(false));
    let quarantine = ProcessLifetimeQemuHotForkQuarantine::default();
    quarantine.retain_forever(DropWitness(Arc::clone(&dropped)));
    assert_eq!(quarantine.retained(), 1);
    drop(quarantine);
    assert!(!*dropped.lock().expect("drop witness"));
}

fn factory(
    input: &CrucibleAttemptExecution,
    incarnation: u64,
    failure: GuardFailure,
    fail_launch: bool,
    state: Arc<Mutex<ScriptedGuardState>>,
    quarantine: ScriptedQuarantine,
) -> ScriptedFactory {
    let basis = execution_basis(input);
    let configuration = template_configuration(input);
    FixedQemuHotForkTemplateFactory::new(
        QemuHotForkTemplateKey::new(basis.key().lineage(), configuration),
        ScriptedTemplate {
            configuration,
            incarnation,
        },
        ScriptedResourceFactory { state, failure },
        ScriptedLauncher { fail_launch },
        quarantine,
    )
    .expect("scripted fixed template factory")
}

fn template_configuration(input: &CrucibleAttemptExecution) -> ContentHash {
    match input.start() {
        CrucibleResolvedAttemptStart::Discover { configuration } => configuration.id(),
        CrucibleResolvedAttemptStart::Branch { parent, .. } => parent.id(),
    }
}

fn exit_policy() -> QemuHotForkChildExitPolicy {
    QemuHotForkChildExitPolicy::new(std::time::Duration::from_millis(1), 1).expect("exit policy")
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
        CrucibleResolvedAttemptStart::Discover { configuration },
    )
}

fn execution_basis(input: &CrucibleAttemptExecution) -> AttemptExecutionRuntimeBasis {
    AttemptExecutionRuntimeBasis::new(
        AttemptExecutionKey::new(
            input.lineage().id().expect("lineage id"),
            input.attempt().id().expect("attempt id"),
        ),
        ExecutionId::from_bytes([0x52; 16]).expect("execution"),
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
