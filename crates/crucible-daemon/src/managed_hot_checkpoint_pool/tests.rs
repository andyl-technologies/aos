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
    QemuVmRealizationError,
};

use super::*;
use crate::{
    AttemptExecutionDisposition, AttemptExecutionKey, AttemptExecutionReconciliationStep,
    ExecutionCancellation, ExecutionCheckpointRequest, HotCheckpointFallback,
    HotCheckpointFallbackTier, HotCheckpointHotnessSignals, HotCheckpointResourceProfile,
    HotCheckpointUsage, QemuAttemptOperationalBoundary, QemuHotForkAttemptLifecycle,
    QemuHotForkChildExitPolicy, QemuHotForkLiveExecution, QemuHotForkTemplateKey,
};
use crucible_cas::content_store::{ContentId, ObjectKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("scripted managed-pool failure")]
struct ScriptedError;

struct NeverLive;

impl QemuAttemptOperationalBoundary for NeverLive {
    fn resource_limits(&self) -> AttemptResourceLimits {
        panic!("scripted lifecycle never becomes live")
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        panic!("scripted lifecycle never becomes live")
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        panic!("scripted lifecycle never becomes live")
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        panic!("scripted lifecycle never becomes live")
    }
}

impl QemuHotForkLiveExecution for NeverLive {
    fn child_qmp_mut(
        &mut self,
    ) -> &mut QemuQmpVmStateControlChannel<std::os::unix::net::UnixStream> {
        panic!("scripted lifecycle never becomes live")
    }

    fn host_continuation_mut(&mut self) -> &mut QemuHotForkHostContinuation {
        panic!("scripted lifecycle never becomes live")
    }

    fn event_log_mut(&mut self) -> &mut EventLog {
        panic!("scripted lifecycle never becomes live")
    }

    fn drain_diagnostics(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticDrain, QemuVmRealizationError> {
        panic!("scripted lifecycle never becomes live")
    }
}

struct ScriptedLifecycle;

impl QemuHotForkAttemptLifecycle for ScriptedLifecycle {
    type Live<'a> = NeverLive;
    type Error = ScriptedError;

    fn runtime_basis(&self) -> AttemptExecutionRuntimeBasis {
        panic!("scripted start always fails")
    }

    fn admit_child(&mut self) -> Result<(), Self::Error> {
        panic!("scripted start always fails")
    }

    fn live_child(&mut self) -> Result<Self::Live<'_>, Self::Error> {
        panic!("scripted start always fails")
    }

    fn stop_before_publication(
        &mut self,
        _exit_policy: QemuHotForkChildExitPolicy,
    ) -> Result<(), Self::Error> {
        panic!("scripted start always fails")
    }

    fn reconcile_execution_disposition(
        &mut self,
        _disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        panic!("scripted start always fails")
    }

    fn quarantine(&mut self) {}
}

struct ScriptedFactory {
    key: QemuHotForkTemplateKey,
    source: u64,
    available: Arc<Mutex<bool>>,
    starts: Arc<Mutex<usize>>,
}

impl QemuHotForkAttemptLifecycleFactory for ScriptedFactory {
    type Lifecycle = ScriptedLifecycle;
    type Error = ScriptedError;

    fn start(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        _runtime_basis: AttemptExecutionRuntimeBasis,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        *self.starts.lock().expect("start count") += 1;
        Err(AttemptWorkerFailure::Retryable(ScriptedError))
    }

    fn recover(
        &mut self,
        lifecycle: Self::Lifecycle,
    ) -> Result<(), QemuHotForkAttemptLifecycleRecoveryError<Self::Lifecycle, Self::Error>> {
        Err(QemuHotForkAttemptLifecycleRecoveryError::new(
            lifecycle,
            AttemptWorkerFailure::Terminal(ScriptedError),
        ))
    }

    fn quarantine(&mut self, _lifecycle: Self::Lifecycle) {}
}

impl crate::qemu_hot_fork_pool::sealed::QemuHotForkKeyedLifecycleFactory for ScriptedFactory {}

impl QemuHotForkKeyedLifecycleFactory for ScriptedFactory {
    fn template_key(&self) -> QemuHotForkTemplateKey {
        self.key
    }

    fn template_available(&self) -> bool {
        *self.available.lock().expect("availability")
    }
}

#[derive(Default)]
struct ScriptedQuarantine;

impl QemuHotForkLifecycleQuarantine<QemuHotForkTemplatePoolLifecycle<ScriptedLifecycle>>
    for ScriptedQuarantine
{
    fn retain_lifecycle(
        &mut self,
        _lifecycle: QemuHotForkTemplatePoolLifecycle<ScriptedLifecycle>,
    ) {
    }
}

#[derive(Default)]
struct ScriptedDemotions {
    completed: Vec<u64>,
    plans: Vec<HotCheckpointPlannedDemotion>,
    validations: Vec<(QemuHotForkTemplateKey, HotCheckpointFallback)>,
    fail_validation_call: Option<usize>,
    fail_source: Option<u64>,
}

impl HotCheckpointTemplateDemotionSink<ScriptedFactory> for ScriptedDemotions {
    type Error = ScriptedError;

    fn validate_fallback(
        &mut self,
        key: QemuHotForkTemplateKey,
        fallback: HotCheckpointFallback,
    ) -> Result<(), Self::Error> {
        self.validations.push((key, fallback));
        if self.fail_validation_call == Some(self.validations.len()) {
            return Err(ScriptedError);
        }
        Ok(())
    }

    fn demote(
        &mut self,
        factory: ScriptedFactory,
        plan: HotCheckpointPlannedDemotion,
    ) -> Result<(), HotCheckpointTemplateDemotionFailure<ScriptedFactory, Self::Error>> {
        if self.fail_source == Some(factory.source) {
            return Err(HotCheckpointTemplateDemotionFailure::new(
                factory,
                ScriptedError,
            ));
        }
        self.completed.push(factory.source);
        self.plans.push(plan);
        Ok(())
    }
}

#[test]
fn admission_keeps_manager_and_pool_on_the_same_exact_coordinate() {
    let mut owner = owner(
        2,
        resources(20, 20, 2, 2, 20, 2),
        4,
        ScriptedDemotions::default(),
    );
    let (factory, _available, _starts) = factory(1, 10);
    let commit = owner
        .admit_template(factory, candidate(1, 10, unit_resources()))
        .expect("first admission");

    assert_eq!(owner.pool().slot_count(), 1);
    assert_eq!(owner.manager().usage().templates(), 1);
    assert_eq!(owner.pool().first_slot(), Some(commit.retained().slot()));
    assert_eq!(
        owner.manager().status(commit.retained().slot()),
        Some(commit.retained())
    );
}

#[test]
fn invalid_candidate_fallback_rejects_before_pool_or_manager_mutation() {
    let mut owner = owner(
        1,
        unit_resources(),
        1,
        ScriptedDemotions {
            fail_validation_call: Some(1),
            ..ScriptedDemotions::default()
        },
    );
    let (factory, _available, _starts) = factory(1, 7);

    let failure = owner
        .admit_template(factory, candidate(1, 1, unit_resources()))
        .expect_err("invalid fallback");
    let (candidate, stranded, error) = failure.into_parts();

    assert_eq!(candidate.expect("returned candidate").source, 7);
    assert!(stranded.is_none());
    assert!(matches!(
        error,
        ManagedHotCheckpointAdmissionError::FallbackValidation(ScriptedError)
    ));
    assert_eq!(owner.manager().usage(), HotCheckpointUsage::default());
    assert_eq!(owner.manager().retained().len(), 0);
    assert_eq!(owner.pool().slot_count(), 0);
    assert_eq!(owner.demotion_sink().validations.len(), 1);
    assert!(owner.demotion_sink().completed.is_empty());
}

#[test]
fn pressure_reaps_colder_source_before_installing_replacement() {
    let mut owner = owner(1, unit_resources(), 4, ScriptedDemotions::default());
    let (first, _available, _starts) = factory(1, 1);
    owner
        .admit_template(first, candidate(1, 1, unit_resources()))
        .expect("cold source");
    let (replacement, _available, _starts) = factory(2, 2);
    let commit = owner
        .admit_template(replacement, candidate(2, 2, unit_resources()))
        .expect("hotter replacement");

    assert_eq!(owner.demotion_sink().completed, vec![1]);
    assert_eq!(
        owner.demotion_sink().plans[0].fallback().tier(),
        HotCheckpointFallbackTier::Exact
    );
    assert_eq!(
        owner.demotion_sink().plans[0].reason(),
        HotCheckpointDemotionReason::CapacityPressure
    );
    assert_eq!(commit.demoted().len(), 1);
    assert_eq!(commit.demoted()[0].status().score().value(), 1);
    assert_eq!(owner.pool().slot_count(), 1);
    assert_eq!(owner.manager().usage().templates(), 1);
}

#[test]
fn busy_victim_rejects_before_any_authority_or_accounting_change() {
    let mut owner = owner(1, unit_resources(), 4, ScriptedDemotions::default());
    let (first, available, _starts) = factory(1, 1);
    let first_commit = owner
        .admit_template(first, candidate(1, 1, unit_resources()))
        .expect("first source");
    *available.lock().expect("mark busy") = false;
    let before = owner.manager().usage();
    let (replacement, _available, _starts) = factory(2, 2);
    let failure = owner
        .admit_template(replacement, candidate(2, 2, unit_resources()))
        .expect_err("busy victim");
    let (candidate, stranded, error) = failure.into_parts();

    assert_eq!(candidate.expect("returned candidate").source, 2);
    assert!(stranded.is_none());
    assert!(matches!(
        error,
        ManagedHotCheckpointAdmissionError::VictimBusy
    ));
    assert_eq!(owner.manager().usage(), before);
    assert_eq!(owner.pool().slot_count(), 1);
    assert_eq!(
        owner.manager().status(first_commit.retained().slot()),
        Some(first_commit.retained())
    );
    assert!(owner.demotion_sink().completed.is_empty());
}

#[test]
fn invalid_planned_victim_fallback_rejects_before_any_source_transfer() {
    let mut owner = owner(
        2,
        resources(10, 10, 2, 2, 20, 2),
        4,
        ScriptedDemotions {
            fail_validation_call: Some(5),
            ..ScriptedDemotions::default()
        },
    );
    let (first, _available, _starts) = factory(1, 1);
    owner
        .admit_template(first, candidate(1, 1, resources(5, 5, 1, 1, 10, 1)))
        .expect("first");
    let (second, _available, _starts) = factory(2, 2);
    owner
        .admit_template(second, candidate(2, 2, resources(5, 5, 1, 1, 10, 1)))
        .expect("second");
    let before_usage = owner.manager().usage();
    let before_slots = owner.pool().slot_count();
    let (replacement, _available, _starts) = factory(3, 3);

    let failure = owner
        .admit_template(replacement, candidate(3, 3, unit_resources()))
        .expect_err("second planned fallback is invalid");
    let (candidate, stranded, error) = failure.into_parts();

    assert_eq!(candidate.expect("returned candidate").source, 3);
    assert!(stranded.is_none());
    assert!(matches!(
        error,
        ManagedHotCheckpointAdmissionError::FallbackValidation(ScriptedError)
    ));
    assert_eq!(owner.manager().usage(), before_usage);
    assert_eq!(owner.pool().slot_count(), before_slots);
    assert!(owner.demotion_sink().completed.is_empty());
    assert_eq!(owner.demotion_sink().validations.len(), 5);
}

#[test]
fn partial_demotion_failure_restores_failed_source_and_accounts_completed_work() {
    let mut owner = owner(
        2,
        resources(10, 10, 2, 2, 20, 2),
        4,
        ScriptedDemotions {
            fail_source: Some(2),
            ..ScriptedDemotions::default()
        },
    );
    let (first, _available, _starts) = factory(1, 1);
    let first_slot = owner
        .admit_template(first, candidate(1, 1, resources(5, 5, 1, 1, 10, 1)))
        .expect("first")
        .retained()
        .slot();
    let (second, _available, _starts) = factory(2, 2);
    let second_slot = owner
        .admit_template(second, candidate(2, 2, resources(5, 5, 1, 1, 10, 1)))
        .expect("second")
        .retained()
        .slot();
    let (replacement, _available, _starts) = factory(3, 3);
    let failure = owner
        .admit_template(replacement, candidate(3, 3, unit_resources()))
        .expect_err("second demotion fails");
    let (candidate, stranded, error) = failure.into_parts();

    assert_eq!(candidate.expect("returned candidate").source, 3);
    assert!(stranded.is_none());
    let reconciliation = match error {
        ManagedHotCheckpointAdmissionError::Demotion {
            source: ScriptedError,
            reconciliation,
        } => reconciliation.expect("completed-demotion reconciliation"),
        other => panic!("unexpected admission error: {other:?}"),
    };
    assert_eq!(reconciliation.len(), 1);
    assert_eq!(reconciliation[0].status().slot(), first_slot);
    assert_eq!(owner.demotion_sink().completed, vec![1]);
    assert!(owner.manager().status(first_slot).is_none());
    assert!(owner.manager().status(second_slot).is_some());
    assert_eq!(owner.pool().slot_count(), 1);
    assert_eq!(owner.manager().usage().templates(), 1);
    assert_eq!(owner.pool().first_slot(), Some(second_slot));
}

#[test]
fn explicit_demotion_secures_fallback_before_releasing_accounting() {
    let mut owner = owner(1, unit_resources(), 1, ScriptedDemotions::default());
    let (factory, _available, _starts) = factory(1, 7);
    let slot = owner
        .admit_template(factory, candidate(1, 9, unit_resources()))
        .expect("retained source")
        .retained()
        .slot();

    let demoted = owner
        .demote_template(slot, HotCheckpointDemotionReason::OperatorRequest)
        .expect("orderly demotion");

    assert_eq!(demoted.status().slot(), slot);
    assert_eq!(
        demoted.reason(),
        HotCheckpointDemotionReason::OperatorRequest
    );
    assert_eq!(owner.demotion_sink().completed, vec![7]);
    assert_eq!(
        owner.demotion_sink().plans[0].fallback().tier(),
        HotCheckpointFallbackTier::Exact
    );
    assert_eq!(
        owner.demotion_sink().plans[0].reason(),
        HotCheckpointDemotionReason::OperatorRequest
    );
    assert_eq!(owner.pool().slot_count(), 0);
    assert_eq!(owner.manager().usage(), HotCheckpointUsage::default());
}

#[test]
fn invalid_explicit_fallback_leaves_source_and_accounting_owned() {
    let mut owner = owner(
        1,
        unit_resources(),
        1,
        ScriptedDemotions {
            fail_validation_call: Some(2),
            ..ScriptedDemotions::default()
        },
    );
    let (factory, _available, _starts) = factory(1, 7);
    let retained = owner
        .admit_template(factory, candidate(1, 9, unit_resources()))
        .expect("retained source")
        .retained();
    let before = owner.manager().usage();

    let failure = owner
        .demote_template(
            retained.slot(),
            HotCheckpointDemotionReason::OperatorRequest,
        )
        .expect_err("fallback preflight fails");
    let (stranded, error) = failure.into_parts();

    assert!(stranded.is_none());
    assert!(matches!(
        error,
        ManagedHotCheckpointDemotionError::FallbackValidation(ScriptedError)
    ));
    assert_eq!(owner.pool().first_slot(), Some(retained.slot()));
    assert_eq!(owner.manager().status(retained.slot()), Some(retained));
    assert_eq!(owner.manager().usage(), before);
    assert!(owner.demotion_sink().completed.is_empty());
    assert_eq!(owner.demotion_sink().validations.len(), 2);
}

#[test]
fn failed_explicit_demotion_restores_the_exact_source_coordinate() {
    let mut owner = owner(
        1,
        unit_resources(),
        1,
        ScriptedDemotions {
            fail_source: Some(7),
            ..ScriptedDemotions::default()
        },
    );
    let (factory, _available, _starts) = factory(1, 7);
    let retained = owner
        .admit_template(factory, candidate(1, 9, unit_resources()))
        .expect("retained source")
        .retained();
    let before = owner.manager().usage();

    let failure = owner
        .demote_template(
            retained.slot(),
            HotCheckpointDemotionReason::SourceInvalidated,
        )
        .expect_err("scripted sink failure");
    let (stranded, error) = failure.into_parts();

    assert!(stranded.is_none());
    assert!(matches!(
        error,
        ManagedHotCheckpointDemotionError::Demotion(ScriptedError)
    ));
    assert_eq!(owner.pool().first_slot(), Some(retained.slot()));
    assert_eq!(owner.manager().status(retained.slot()), Some(retained));
    assert_eq!(owner.manager().usage(), before);
}

#[test]
fn candidate_key_mismatch_is_write_free_and_returns_the_factory() {
    let mut owner = owner(1, unit_resources(), 1, ScriptedDemotions::default());
    let (factory, _available, _starts) = factory(1, 1);
    let failure = owner
        .admit_template(factory, candidate(2, 2, unit_resources()))
        .expect_err("foreign candidate key");
    let (candidate, stranded, error) = failure.into_parts();
    assert_eq!(candidate.expect("returned candidate").source, 1);
    assert!(stranded.is_none());
    assert!(matches!(
        error,
        ManagedHotCheckpointAdmissionError::CandidateKeyMismatch
    ));
    assert_eq!(owner.pool().slot_count(), 0);
    assert_eq!(owner.manager().usage().templates(), 0);
}

#[test]
fn failed_installed_rollback_reports_the_exact_retained_coordinate() {
    let key = key(1);
    let slot = QemuHotForkTemplatePoolSlot::new(key, 3);
    let failure =
        ManagedHotCheckpointAdmissionFailure::<ScriptedFactory, ScriptedError>::without_candidate(
            slot,
            ManagedHotCheckpointAdmissionError::InstalledRollback {
                source: HotCheckpointAdmissionCommitError::StalePlan {
                    planned: 1,
                    current: 2,
                },
                retirement: QemuHotForkTemplatePoolRetirementError::Busy { key, slot: 3 },
            },
        );

    assert_eq!(failure.internally_retained_slot(), Some(slot));
    let (candidate, stranded, error) = failure.into_parts();
    assert!(candidate.is_none());
    assert!(stranded.is_none());
    assert!(matches!(
        error,
        ManagedHotCheckpointAdmissionError::InstalledRollback { .. }
    ));
}

#[test]
fn every_start_attempt_consumes_the_managed_fork_rate_before_pool_work() {
    let input = execution_input();
    let basis = execution_basis(&input);
    let context = execution_context(&input);
    let key = template_key(&input);
    let mut owner = owner(1, unit_resources(), 1, ScriptedDemotions::default());
    let available = Arc::new(Mutex::new(true));
    let starts = Arc::new(Mutex::new(0));
    owner
        .admit_template(
            ScriptedFactory {
                key,
                source: 1,
                available,
                starts: Arc::clone(&starts),
            },
            HotCheckpointCandidate::new(key, unit_resources(), signals(1), exact_fallback(1)),
        )
        .expect("managed source");

    assert!(matches!(
        owner.start(&input, &context, basis),
        Err(AttemptWorkerFailure::Retryable(
            ManagedHotCheckpointStartError::Pool(_)
        ))
    ));
    assert!(matches!(
        owner.start(&input, &context, basis),
        Err(AttemptWorkerFailure::Retryable(
            ManagedHotCheckpointStartError::ForkRate(
                HotCheckpointForkRateError::RateLimited { .. }
            )
        ))
    ));
    assert_eq!(*starts.lock().expect("start count"), 1);
}

fn owner(
    maximum_templates: usize,
    maximum_resources: HotCheckpointResourceProfile,
    maximum_forks_per_window: u32,
    demotions: ScriptedDemotions,
) -> ManagedQemuHotForkTemplatePool<ScriptedFactory, ScriptedQuarantine, ScriptedDemotions> {
    let limits = HotCheckpointLimits::new(
        maximum_templates,
        maximum_resources,
        maximum_forks_per_window,
        u64::MAX,
    )
    .expect("limits");
    ManagedQemuHotForkTemplatePool::new(limits, ScriptedQuarantine, demotions)
        .expect("managed pool")
}

fn factory(byte: u8, source: u64) -> (ScriptedFactory, Arc<Mutex<bool>>, Arc<Mutex<usize>>) {
    let available = Arc::new(Mutex::new(true));
    let starts = Arc::new(Mutex::new(0));
    (
        ScriptedFactory {
            key: key(byte),
            source,
            available: Arc::clone(&available),
            starts: Arc::clone(&starts),
        },
        available,
        starts,
    )
}

fn candidate(
    byte: u8,
    score: u64,
    resources: HotCheckpointResourceProfile,
) -> HotCheckpointCandidate {
    HotCheckpointCandidate::new(key(byte), resources, signals(score), exact_fallback(byte))
}

fn exact_fallback(byte: u8) -> HotCheckpointFallback {
    HotCheckpointFallback::Exact(
        crucible_campaign::ExactCheckpointId::try_from(ContentId::for_bytes(
            ObjectKind::ExactManifest,
            4,
            &[byte],
        ))
        .expect("exact fallback"),
    )
}

fn signals(score: u64) -> HotCheckpointHotnessSignals {
    HotCheckpointHotnessSignals::new()
        .with_pending_attempts(score)
        .expect("score")
}

fn resources(
    template_bytes: u64,
    expected_private_dirty_bytes: u64,
    process_count: u32,
    virtual_cpu_count: u32,
    descriptor_count: u32,
    overlay_count: u32,
) -> HotCheckpointResourceProfile {
    HotCheckpointResourceProfile::new(
        template_bytes,
        expected_private_dirty_bytes,
        process_count,
        virtual_cpu_count,
        descriptor_count,
        overlay_count,
    )
    .expect("resources")
}

fn unit_resources() -> HotCheckpointResourceProfile {
    resources(10, 10, 1, 1, 10, 1)
}

fn key(byte: u8) -> QemuHotForkTemplateKey {
    QemuHotForkTemplateKey::new(
        crucible_campaign::CampaignLineageId::parse(&typed_id(
            "crucible.campaign.lineage",
            "campaign-fact",
            byte,
        ))
        .expect("lineage"),
        crucible::ContentHash::from_bytes(&[byte]),
    )
}

fn template_key(input: &CrucibleAttemptExecution) -> QemuHotForkTemplateKey {
    QemuHotForkTemplateKey::new(
        execution_basis(input).key().lineage(),
        match input.start() {
            crate::CrucibleResolvedAttemptStart::Discover { configuration } => configuration.id(),
            crate::CrucibleResolvedAttemptStart::Branch { parent, .. } => parent.id(),
        },
    )
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

fn typed_id(tag: &str, kind: &str, byte: u8) -> String {
    format!("{tag}@{kind}.1.{}", encode_hex(&[byte; 32]))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
