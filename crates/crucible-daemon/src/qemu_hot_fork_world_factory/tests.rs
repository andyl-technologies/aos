//! Scripted production whole-world composition regressions.

// crucible-lint: allow panic-shortcut -- fixture construction and assertions use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::fs::{File, OpenOptions};
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crucible::{
    Configuration, ContentHash, ScenarioDefForm, ScenarioSelectableLimits, ScenarioSelectables,
};
use crucible_api::vm_lifecycle::{
    hot_fork_adoption_count_for_test,
    prepared_multi_node_hot_fork_source_world_for_scenario_for_test,
    prepared_multi_node_hot_fork_source_world_for_test, reset_hot_fork_adoption_count_for_test,
};
use crucible_campaign::{
    AssignmentId, Attempt, AttemptResourceLimits, AttemptStart, BooleanDomain, BranchPath,
    BudgetGrant, CampaignCommandId, CampaignControlAction, CampaignExecutorStore, CampaignHash,
    CampaignLineage, CampaignMode, CampaignPolicy, CampaignRepository, CampaignSeed,
    ChoiceClassContext, ChoiceDomain, ChoiceSource, ChoiceValue, ConfigurationArtifact,
    ConfigurationId, ControlRequest, CoverageProjection, DaemonEpoch, ExactCheckpointId,
    ExactRational, ExecutionId, ExecutionRetentionIntent, ExecutorCompatibilityProfile,
    ExecutorService, ExplorerPolicy, FairnessPolicy, MeasurementSet, Observation,
    ObservationCandidate, ProgressiveWideningPolicy, PropertyVerdictSet, PuctPolicy,
    RetentionPolicy, ScenarioArtifact, ScenarioDefId, SelectableDeclaration, StopCondition,
    StopOutcome, SubmitAttemptDisposition, SubmitAttemptRequest,
};
use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ContentId, ImmutableBlobBackend, MemoryBlobBackend,
    MemoryRefBackend, ObjectKind, PlacementReceipt, PutReceipt, StoreError,
};
use crucible_protocol::SelectionRequest;
use crucible_protocol::selectable_catalog_plan::{
    SelectableCatalogPlan, SelectablePlanContinuation, SelectablePlanDeclaration,
    SelectablePlanLimits, SelectablePlanPendingRequest, SelectablePlanPhase,
    SelectablePlanPresence,
};
use crucible_qemu::{
    LinuxQemuHotForkChildProcessAuthority, QemuChildProcessContract, QemuHotForkChildProcessBasis,
    QemuHotForkChildProcessOwner, QemuLaunchResourceRequirements, QemuNodeChannelError,
    QemuPreparedRunDirectory, QemuTestHotForkOutcome, QemuVmRealizationError,
    linux_process_identity, scripted_hot_fork_source_for_test,
    scripted_hot_fork_source_with_state_for_test,
};
use rustix::process::{Pid, PidfdFlags, pidfd_open};

use super::*;
use crate::{
    AttemptExecutionKey, AttemptExecutionRuntimeBasis, AttemptResultStageOutcome,
    AttemptWorkerReconcileOutcome, CompletionOutcome, CrucibleExecutionModel,
    CrucibleExecutionRunner, CrucibleMaterializationTier, ExactCheckpointStore,
    ExecutionCancellation, ExecutionCheckpointRequest, ExecutorCapacity, LocalAttemptWorker,
    LocalExecutorSupervisor, MemoryAssignmentLedger, PreparedAttemptWorkResult,
    QemuAttemptOperationalBoundary, QemuAttemptResourceGuard, QemuFreshModeledDriver,
    QemuHotFirstExecutionRouter, RepositoryAttemptAdmission, RepositoryAttemptWorker,
    decode_crucible_configuration_artifact_with_selections, encode_crucible_configuration_artifact,
    encode_crucible_scenario_artifact, prepare_attempt_result, publish_prepared_attempt_result,
    reconcile_published_attempt_result, stage_prepared_attempt_result,
};

struct ScriptedWorldGuard {
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    process_contract: QemuChildProcessContract,
    run_root: tempfile::TempDir,
    finishes: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
    retained_child_processes: Arc<Mutex<Vec<u32>>>,
    _liveness: Arc<()>,
    terminal: bool,
}

impl QemuAttemptOperationalBoundary for ScriptedWorldGuard {
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        Ok(())
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        Ok(())
    }
}

impl QemuAttemptResourceGuard for ScriptedWorldGuard {
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        if !self.terminal {
            self.finishes.fetch_add(1, Ordering::SeqCst);
            self.terminal = true;
        }
        Ok(())
    }

    fn quarantine(&mut self) {
        if !self.terminal {
            self.quarantines.fetch_add(1, Ordering::SeqCst);
            self.terminal = true;
        }
    }
}

impl QemuAttemptProcessResourceGuard for ScriptedWorldGuard {
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        Ok(&self.process_contract)
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        let index = self
            .run_root
            .path()
            .read_dir()
            .map_err(test_realization_error)?
            .count();
        let generation = self.run_root.path().join(format!("generation-{index:03}"));
        std::fs::create_dir(&generation).map_err(test_realization_error)?;
        File::create(generation.join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME))
            .map_err(test_realization_error)?;
        if requirements.has_root_overlay() {
            File::create(generation.join(crucible_qemu::DEFAULT_ROOT_OVERLAY_FILE_NAME))
                .map_err(test_realization_error)?;
        }
        QemuPreparedRunDirectory::open_for_test_requirements(
            requirements,
            generation,
            &self.process_contract,
        )
        .map_err(test_realization_error)
    }

    fn retain_failed_launch_child(&mut self, _child: crucible_qemu::QemuNodeChild) {}
}

impl QemuHotForkChildProcessOwner for ScriptedWorldGuard {
    type Authority = LinuxQemuHotForkChildProcessAuthority;

    fn retain_hot_fork_child(
        &mut self,
        basis: QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        let process_id =
            Pid::from_raw(i32::try_from(basis.child_process_id()).map_err(|error| {
                QemuNodeChannelError::new("retain scripted child", error.to_string())
            })?)
            .ok_or_else(|| {
                QemuNodeChannelError::new("retain scripted child", "child PID must be positive")
            })?;
        let descriptor = pidfd_open(process_id, PidfdFlags::empty()).map_err(|error| {
            QemuNodeChannelError::new("open scripted child pidfd", error.to_string())
        })?;
        let identity = linux_process_identity(basis.child_process_id())
            .map_err(|error| {
                QemuNodeChannelError::new("authenticate scripted child", error.to_string())
            })?
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "authenticate scripted child",
                    "scripted child process is absent",
                )
            })?;
        self.retained_child_processes
            .lock()
            .map_err(|_error| {
                QemuNodeChannelError::new(
                    "record scripted child",
                    "scripted child registry is poisoned",
                )
            })?
            .push(basis.child_process_id());
        Ok(
            LinuxQemuHotForkChildProcessAuthority::from_unvalidated_test_parts(
                basis, identity, descriptor,
            ),
        )
    }
}

struct ScriptedWorldGuardFactory {
    observations: ScriptedWorldObservations,
}

#[derive(Clone)]
struct ScriptedWorldObservations {
    finishes: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
    retained_child_processes: Arc<Mutex<Vec<u32>>>,
    guard_liveness: Arc<Mutex<Option<Weak<()>>>>,
}

impl ScriptedWorldObservations {
    fn new() -> Self {
        Self {
            finishes: Arc::new(AtomicUsize::new(0)),
            quarantines: Arc::new(AtomicUsize::new(0)),
            retained_child_processes: Arc::new(Mutex::new(Vec::new())),
            guard_liveness: Arc::new(Mutex::new(None)),
        }
    }
}

impl QemuAttemptResourceGuardFactory for ScriptedWorldGuardFactory {
    type Guard = ScriptedWorldGuard;

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
    ) -> Result<Self::Guard, QemuVmRealizationError> {
        let cgroup = tempfile::tempdir().map_err(test_realization_error)?;
        let cgroup_directory: OwnedFd = File::open(cgroup.path())
            .map_err(test_realization_error)?
            .into();
        let cgroup_procs: OwnedFd = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(cgroup.path().join("cgroup.procs"))
            .map_err(test_realization_error)?
            .into();
        let cancellation_event = rustix::event::eventfd(
            0,
            rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
        )
        .map_err(test_realization_error)?;
        let process_contract = QemuChildProcessContract::from_unvalidated_hot_fork_test_descriptors(
            cgroup_directory,
            cgroup_procs,
            cancellation_event,
            resources.maximum_vcpus(),
            resources.maximum_resident_bytes(),
            resources.maximum_disk_bytes(),
        );
        let liveness = Arc::new(());
        *self
            .observations
            .guard_liveness
            .lock()
            .map_err(|_error| test_realization_error("guard liveness registry is poisoned"))? =
            Some(Arc::downgrade(&liveness));
        Ok(ScriptedWorldGuard {
            resources,
            cancellation,
            process_contract,
            run_root: tempfile::tempdir().map_err(test_realization_error)?,
            finishes: Arc::clone(&self.observations.finishes),
            quarantines: Arc::clone(&self.observations.quarantines),
            retained_child_processes: Arc::clone(&self.observations.retained_child_processes),
            _liveness: liveness,
            terminal: false,
        })
    }
}

struct TestDurableCheckpointBackend {
    memory: MemoryBlobBackend,
}

impl TestDurableCheckpointBackend {
    fn new() -> Self {
        Self {
            memory: MemoryBlobBackend::new("hot-world-checkpoints", 8 * 1024 * 1024),
        }
    }
}

impl ImmutableBlobBackend for TestDurableCheckpointBackend {
    fn name(&self) -> &str {
        "hot-world-checkpoints"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            durable: true,
            deferred_write: false,
            range_read: true,
            streaming_read: true,
            conditional_create: true,
            streaming_put: true,
            repair_inventory: false,
            planned_delete: false,
        }
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.memory.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.memory.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let receipt = self.memory.put_if_absent(id, source)?;
        Ok(PutReceipt {
            id: receipt.id,
            placements: vec![PlacementReceipt {
                backend: String::from(self.name()),
                durable: true,
                logical_length: source.logical_length(),
            }],
        })
    }
}

struct ScriptedPublishedObservationDriver {
    candidate: ObservationCandidate,
    drives: Arc<AtomicUsize>,
    seals: Arc<AtomicUsize>,
}

impl QemuFreshAttemptDriver for ScriptedPublishedObservationDriver {
    type Pending = ObservationCandidate;
    type Error = &'static str;

    fn drive(
        &mut self,
        _lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        materialization: crate::QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>> {
        let (events, _bytes, _terminal_quiescence, _terminal_verdict) =
            materialization.into_parts();
        assert!(events.is_empty());
        self.drives.fetch_add(1, Ordering::SeqCst);
        Ok(QemuFreshDriveOutcome::Observation(self.candidate.clone()))
    }

    fn seal(
        &mut self,
        candidate: Self::Pending,
        _final_events: Vec<crucible::SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        self.seals.fetch_add(1, Ordering::SeqCst);
        Ok(AttemptExecutionProduct::observation(candidate))
    }
}

struct NeverFallbackRunner {
    calls: Arc<AtomicUsize>,
}

impl CrucibleExecutionRunner for NeverFallbackRunner {
    type Error = &'static str;

    fn execute(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(AttemptWorkerFailure::Terminal(
            "fallback must not run for an exact retained source world",
        ))
    }
}

struct RecordingUnavailableSourceWorldProvider {
    checkouts: Arc<AtomicUsize>,
}

impl QemuHotForkSourceWorldProvider for RecordingUnavailableSourceWorldProvider {
    type Error = Infallible;

    fn checkout(
        &mut self,
        _scenario: ContentHash,
        _configuration: ContentHash,
    ) -> Result<Option<ProductionVmHotForkSourceWorld>, Self::Error> {
        self.checkouts.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }

    fn restore(&mut self, source: ProductionVmHotForkSourceWorld) {
        let _retained_for_process_lifetime = Box::leak(Box::new(source));
    }
}

struct RecordingFallbackRunner {
    candidate: ObservationCandidate,
    calls: Arc<AtomicUsize>,
    reconciliations: Arc<AtomicUsize>,
}

impl CrucibleExecutionRunner for RecordingFallbackRunner {
    type Error = Infallible;

    fn execute(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(CrucibleExecutionOutcome::new(
            AttemptExecutionProduct::observation(self.candidate.clone()),
            CrucibleMaterializationTier::ThinReplay,
        ))
    }

    fn reconcile_execution(
        &mut self,
        _disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        self.reconciliations.fetch_add(1, Ordering::SeqCst);
        Ok(AttemptExecutionReconciliationStep::Complete)
    }
}

fn test_realization_error(error: impl std::fmt::Display) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation: "construct scripted whole-world fixture",
        message: error.to_string(),
    }
}

fn guest_selectable_scenario() -> ScenarioDefForm {
    let scenario = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    let declaration = guest_selectable_declaration();
    let selectables = ScenarioSelectables::new(
        scenario.world(),
        ScenarioSelectableLimits::new(4, 8, 16, 32).expect("selectable limits"),
        vec![declaration],
    )
    .expect("scenario selectables");
    scenario
        .with_selectables(selectables)
        .expect("guest selectable scenario")
}

fn guest_selectable_declaration() -> SelectableDeclaration {
    SelectableDeclaration::new(
        "product.recovery",
        ChoiceSource::Guest {
            node: String::from("db-0"),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        ChoiceDomain::Boolean(BooleanDomain::new(1).expect("Boolean domain")),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
        BTreeSet::from([String::from("recovery")]),
        true,
    )
    .expect("guest selectable declaration")
}

fn pending_guest_selectable_plan() -> (SelectableCatalogPlan, SelectablePlanPendingRequest) {
    let declaration = guest_selectable_declaration();
    let expected = SelectablePlanDeclaration::new(
        declaration.name(),
        declaration.domain().canonical_bytes(),
        declaration.default().canonical_bytes(),
        declaration.semantic_tags().iter().cloned().collect(),
        SelectablePlanPresence::Required,
    )
    .expect("selectable plan declaration");
    let request = SelectionRequest::new(2, declaration.name(), "publication", None, 256)
        .expect("pending selectable request");
    let continuation = SelectablePlanContinuation::new(
        SelectablePlanPhase::Frozen,
        BTreeSet::from([String::from(declaration.name())]),
        Some(1),
        BTreeMap::new(),
        None,
        None,
    )
    .expect("pending selectable continuation");
    let plan = SelectableCatalogPlan::new(
        SelectablePlanLimits::new(4, 16, 32).expect("selectable plan limits"),
        vec![expected],
        continuation,
    )
    .expect("pending selectable catalog plan");
    let pending = SelectablePlanPendingRequest::new(request, 1, 0, 0x1000);
    (plan, pending)
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
        scenario_artifact.payload_schema(),
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

fn execution_basis(
    input: &CrucibleAttemptExecution,
    execution_byte: u8,
) -> AttemptExecutionRuntimeBasis {
    AttemptExecutionRuntimeBasis::new(
        AttemptExecutionKey::new(
            input.lineage().id().expect("lineage id"),
            input.attempt().id().expect("attempt id"),
        ),
        ExecutionId::from_bytes([execution_byte; 16]).expect("execution"),
    )
}

fn execution_context(
    input: &CrucibleAttemptExecution,
    execution_byte: u8,
) -> AttemptExecutionContext {
    AttemptExecutionContext::new(
        AttemptResourceLimits::new(8, 8 << 30, 8 << 30, 64).expect("resources"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
    )
    .with_runtime_basis(execution_basis(input, execution_byte))
}

fn factory(
    source_world: ProductionVmHotForkSourceWorld,
    run_state_root: PathBuf,
    observations: ScriptedWorldObservations,
) -> QemuProductionHotForkWorldLifecycleFactory<
    QemuSingleHotForkSourceWorldProvider,
    ScriptedWorldGuardFactory,
> {
    QemuProductionHotForkWorldLifecycleFactory::new(
        QemuSingleHotForkSourceWorldProvider::new(source_world),
        ScriptedWorldGuardFactory { observations },
        run_state_root,
        QemuShutdownPolicy::fast_test(),
        QemuAsyncDriverPolicy::fast_test(),
    )
}

fn repository_execution_fixture() -> (
    Arc<CampaignRepository>,
    CampaignExecutorStore,
    CampaignLineage,
    crucible_campaign::AttemptId,
    ObservationCandidate,
    ScenarioDefForm,
) {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "hot-world-publication",
            64 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let scenario = guest_selectable_scenario();
    let scenario_artifact =
        encode_crucible_scenario_artifact(&scenario).expect("encode scenario artifact");
    let scenario_content = repository
        .publish_scenario_artifact(
            scenario_artifact.scenario(),
            scenario_artifact.payload_schema(),
            scenario_artifact.payload().to_vec(),
        )
        .expect("publish scenario artifact");
    assert_eq!(
        scenario_content,
        scenario_artifact.id().expect("scenario artifact id")
    );

    let configuration = Configuration::genesis(scenario.scenario_def());
    let configuration_artifact =
        encode_crucible_configuration_artifact(&scenario_artifact, &configuration.schedule)
            .expect("encode configuration artifact");
    let configuration_content = repository
        .publish_configuration_artifact(
            configuration_artifact.scenario(),
            configuration_artifact.scenario_artifact(),
            configuration_artifact.configuration(),
            configuration_artifact.payload_schema(),
            configuration_artifact.payload().to_vec(),
        )
        .expect("publish configuration artifact");
    assert_eq!(
        configuration_content,
        configuration_artifact
            .id()
            .expect("configuration artifact id")
    );

    let lineage = CampaignLineage::new(
        scenario_artifact.scenario(),
        scenario_content,
        configuration_artifact.configuration(),
        configuration_content,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        scenario_artifact.payload_schema(),
        1,
    )
    .expect("campaign lineage");
    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1).expect("widening numerator"),
        ExactRational::new(1, 2).expect("widening exponent"),
        1,
        100,
        1,
    )
    .expect("widening policy");
    let policy = CampaignPolicy::new(
        scenario_artifact.scenario(),
        CampaignSeed::from_bytes([0x71; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness policy"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("campaign policy");
    let created = repository
        .create("hot-world-publication", &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    repository
        .apply_control(
            "hot-world-publication",
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.hot-world-publication.budget.v1",
                    b"budget",
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::GrantBudget(
                    BudgetGrant::new(0, 1).expect("attempt budget"),
                ),
            },
        )
        .expect("fund campaign");
    let funded = repository
        .head("hot-world-publication")
        .expect("funded head");
    repository
        .apply_control(
            "hot-world-publication",
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.hot-world-publication.resume.v1",
                    b"resume",
                )),
                expected_snapshot: funded.snapshot_id(),
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume campaign");
    let attempt_id = repository
        .admit_initial_discovery_if_ready("hot-world-publication")
        .expect("admit discovery")
        .expect("initial discovery attempt");
    let attempt = repository.load_attempt(attempt_id).expect("load attempt");

    let measurements = MeasurementSet::new(BTreeMap::new()).expect("measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
    let coverage =
        CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage projection");
    let observation = Observation::new(
        attempt_id,
        configuration_artifact.configuration(),
        configuration_content,
        attempt.path(),
        StopOutcome::TerminalSuccess,
        measurements.id().expect("measurement set id"),
        properties.id().expect("property verdict set id"),
        coverage.id().expect("coverage projection id"),
        BTreeSet::new(),
    )
    .expect("observation");
    let candidate = ObservationCandidate::new(
        configuration_artifact,
        measurements,
        properties,
        coverage,
        Vec::new(),
        observation,
    )
    .expect("observation candidate");
    let store = CampaignExecutorStore::new(Arc::clone(&repository));

    (repository, store, lineage, attempt_id, candidate, scenario)
}

fn reconcile_canceled_world(
    lifecycle: &mut QemuProductionHotForkWorldLifecycle<ScriptedWorldGuard>,
) {
    let mut reconciled = false;
    for _ in 0..64 {
        if lifecycle
            .reconcile_execution_disposition(AttemptExecutionDisposition::Canceled)
            .expect("reconcile world")
            == AttemptExecutionReconciliationStep::Complete
        {
            reconciled = true;
            break;
        }
    }
    assert!(reconciled);
}

#[test]
fn two_running_nodes_install_shutdown_reconcile_and_reuse_one_source_world() {
    let first =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let second =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let (nodes, source_world) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![first, second])
            .expect("prepared source world");
    assert_eq!(nodes.len(), 2);

    let input = execution_input();
    let context = execution_context(&input, 0x79);
    let run_state = tempfile::tempdir().expect("run state");
    let observations = ScriptedWorldObservations::new();
    let mut factory = factory(
        source_world,
        run_state.path().to_path_buf(),
        observations.clone(),
    );

    let mut lifecycle = match factory.try_start(&input, &context).expect("start world") {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("exact source world declined"),
    };
    assert!(!factory.sources().available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 0);
    assert!(lifecycle.start_materialization().is_ok());
    QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle).expect("shutdown adopted world");
    assert!(!factory.sources().available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 0);
    reconcile_canceled_world(&mut lifecycle);

    let competing_source_owner = lifecycle.source_world_owner_for_test();
    let lifecycle = factory
        .recover(lifecycle)
        .expect_err("a competing source owner must defer recovery");
    drop(competing_source_owner);
    assert!(factory.recover(lifecycle).is_ok());

    assert!(factory.sources().available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);

    let second_context = execution_context(&input, 0x7a);
    let mut second_lifecycle = match factory
        .try_start(&input, &second_context)
        .expect("reuse source world")
    {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("reprepared source world declined"),
    };
    assert!(second_lifecycle.start_materialization().is_ok());
    QemuFreshAttemptLifecycleOwner::shutdown(&mut second_lifecycle)
        .expect("shutdown second adopted world");
    reconcile_canceled_world(&mut second_lifecycle);
    assert!(factory.recover(second_lifecycle).is_ok());

    assert!(factory.sources().available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 2);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn second_child_indeterminate_failure_quarantines_first_child_and_complete_world() {
    let first =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let first_source_process = first.process_id();
    let second = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Indeterminate)
        .expect("second source");
    let second_source_process = second.process_id();
    let (_nodes, source_world) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![first, second])
            .expect("prepared source world");
    let input = execution_input();
    let context = execution_context(&input, 0x79);
    let run_state = tempfile::tempdir().expect("run state");
    let observations = ScriptedWorldObservations::new();
    let mut factory = factory(
        source_world,
        run_state.path().to_path_buf(),
        observations.clone(),
    );

    assert!(matches!(
        factory.try_start(&input, &context),
        Err(AttemptWorkerFailure::Retryable(
            QemuProductionHotForkWorldLifecycleFactoryError::Assembly(_)
        ))
    ));
    assert!(!factory.sources().available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 1);
    assert!(linux_process_identity(first_source_process).is_ok_and(|identity| identity.is_some()));
    assert!(linux_process_identity(second_source_process).is_ok_and(|identity| identity.is_some()));
    let retained_children = observations
        .retained_child_processes
        .lock()
        .expect("retained child registry");
    assert_eq!(retained_children.len(), 1);
    assert!(
        PathBuf::from("/proc")
            .join(retained_children[0].to_string())
            .exists()
    );
    let guard = observations
        .guard_liveness
        .lock()
        .expect("guard liveness registry")
        .as_ref()
        .and_then(Weak::upgrade);
    assert!(guard.is_some());
}

#[test]
fn second_adoption_failure_retains_first_adoption_and_complete_world() {
    let first =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let first_source_process = first.process_id();
    let second =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let second_source_process = second.process_id();
    let (nodes, mut source_world) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![first, second])
            .expect("prepared source world");
    source_world
        .replace_immutable_root_for_test(&nodes[1].0, ContentHash::from_bytes(b"mismatched-root"))
        .expect("replace second immutable root");
    let input = execution_input();
    let context = execution_context(&input, 0x79);
    let run_state = tempfile::tempdir().expect("run state");
    let observations = ScriptedWorldObservations::new();
    let mut factory = factory(
        source_world,
        run_state.path().to_path_buf(),
        observations.clone(),
    );

    reset_hot_fork_adoption_count_for_test();
    assert!(matches!(
        factory.try_start(&input, &context),
        Err(AttemptWorkerFailure::Terminal(
            QemuProductionHotForkWorldLifecycleFactoryError::Lifecycle(_)
        ))
    ));
    assert_eq!(hot_fork_adoption_count_for_test(), 1);
    assert!(!factory.sources().available());
    assert!(linux_process_identity(first_source_process).is_ok_and(|identity| identity.is_some()));
    assert!(linux_process_identity(second_source_process).is_ok_and(|identity| identity.is_some()));
    let retained_children = observations
        .retained_child_processes
        .lock()
        .expect("retained child registry");
    assert_eq!(retained_children.len(), 2);
    assert!(
        retained_children
            .iter()
            .all(|process| PathBuf::from("/proc").join(process.to_string()).exists())
    );
    let guard = observations
        .guard_liveness
        .lock()
        .expect("guard liveness registry")
        .as_ref()
        .and_then(Weak::upgrade);
    assert!(guard.is_some());
}

#[test]
fn poisoned_source_owner_cannot_be_recovered_on_retry() {
    let source = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("source");
    let (_nodes, source_world) = prepared_multi_node_hot_fork_source_world_for_test(vec![source])
        .expect("prepared source world");
    let input = execution_input();
    let context = execution_context(&input, 0x79);
    let run_state = tempfile::tempdir().expect("run state");
    let observations = ScriptedWorldObservations::new();
    let mut factory = factory(source_world, run_state.path().to_path_buf(), observations);
    let mut lifecycle = match factory.try_start(&input, &context).expect("start world") {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("exact source world declined"),
    };
    QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle).expect("shutdown adopted world");
    reconcile_canceled_world(&mut lifecycle);

    let source_owner = lifecycle.source_world_owner_for_test();
    let poisoner = std::thread::spawn(move || {
        let _source = source_owner.lock().expect("lock source owner");
        panic!("poison source owner");
    });
    assert!(poisoner.join().is_err());

    let lifecycle = factory
        .recover(lifecycle)
        .expect_err("poisoned source owner must fail recovery");
    let lifecycle = factory
        .recover(lifecycle)
        .expect_err("recovery retry must preserve source poison");
    assert!(!factory.sources().available());
    factory.quarantine(lifecycle);
}

#[test]
fn published_observation_reconciliation_makes_the_exact_source_world_reusable() {
    let (repository, store, lineage, attempt, _candidate, scenario) =
        repository_execution_fixture();
    let (selectable_plan, pending_request) = pending_guest_selectable_plan();
    let expected_discovery = crate::guest_selectable::resolve_guest_selectable(
        lineage.scenario(),
        &scenario,
        &crucible::NodeId {
            name: String::from("db-0"),
        },
        &pending_request,
    )
    .expect("resolve expected typed guest opportunity");
    let expected_opportunity = expected_discovery.opportunity().clone();
    let first = scripted_hot_fork_source_with_state_for_test(
        QemuTestHotForkOutcome::Forked,
        Vec::new(),
        Some((selectable_plan, pending_request)),
    )
    .expect("first source");
    let second =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let (_nodes, source_world) = prepared_multi_node_hot_fork_source_world_for_scenario_for_test(
        &scenario,
        vec![first, second],
    )
    .expect("prepared source world");
    let run_state = tempfile::tempdir().expect("run state");
    let observations = ScriptedWorldObservations::new();
    let fallback_calls = Arc::new(AtomicUsize::new(0));
    let hot_fork = QemuHotForkWorldExecutionRunner::new(
        factory(
            source_world,
            run_state.path().to_path_buf(),
            observations.clone(),
        ),
        QemuFreshModeledDriver::new(),
    );
    let router = QemuHotFirstExecutionRouter::new(
        hot_fork,
        NeverFallbackRunner {
            calls: Arc::clone(&fallback_calls),
        },
    );
    let model = CrucibleExecutionModel::new(store.clone(), router);
    let mut worker = RepositoryAttemptWorker::new(store.clone(), model);

    let profile = ExecutorCompatibilityProfile::new(
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        lineage.scenario_schema(),
        1,
    )
    .expect("compatibility profile");
    let epoch = DaemonEpoch::from_bytes([0x72; 16]).expect("daemon epoch");
    let resources = AttemptResourceLimits::new(8, 8 << 30, 8 << 30, 64).expect("attempt resources");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x73; 16]).expect("assignment"),
        epoch,
        lineage.id().expect("lineage id"),
        attempt,
        resources,
        ExecutionRetentionIntent::Discard,
    )
    .expect("submit request");
    let admission = RepositoryAttemptAdmission::new(Arc::clone(&repository), profile);
    let mut supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        admission,
        epoch,
        ExecutorCapacity::new(1, 8, 8 << 30, 8 << 30, 64).expect("executor capacity"),
    );
    let submitted =
        ExecutorService::submit_attempt(&mut supervisor, &request).expect("submit exact discovery");
    assert!(matches!(
        submitted.disposition(),
        SubmitAttemptDisposition::Accepted { .. }
    ));
    let queued = supervisor.next_queued().expect("queued execution");

    let work = worker.execute(queued);
    let checkpoints = ExactCheckpointStore::new(
        Arc::new(TestDurableCheckpointBackend::new()),
        8 * 1024 * 1024,
    )
    .expect("checkpoint store");
    let prepared = prepare_attempt_result(&store, &checkpoints, work).expect("prepare result");
    let PreparedAttemptWorkResult::Observation(prepared) = prepared else {
        panic!("driver returned an unexpected checkpoint")
    };
    let observation = prepared.observation();

    assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        worker.model().last_materialization(),
        Some(CrucibleMaterializationTier::HotFork)
    );
    assert!(
        !worker
            .model()
            .runner()
            .hot_fork()
            .lifecycle_factory()
            .sources()
            .available()
    );
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 0);

    let staged = stage_prepared_attempt_result(&mut supervisor, *prepared).expect("stage result");
    let AttemptResultStageOutcome::Publish(staged) = staged else {
        panic!("current execution must publish")
    };
    let published = publish_prepared_attempt_result(&store, staged).expect("publish result");
    let published_observation = repository
        .load_observation(observation)
        .expect("published observation");
    assert_eq!(
        published_observation
            .id()
            .expect("published observation id"),
        observation
    );
    let expected_opportunity_id = expected_opportunity.id().expect("expected opportunity id");
    assert_eq!(
        published_observation.discovered_choices(),
        &BTreeSet::from([expected_opportunity_id])
    );
    assert_eq!(
        repository
            .load_choice_opportunity(expected_opportunity_id)
            .expect("published typed opportunity"),
        expected_opportunity
    );
    let child_artifact = repository
        .load_configuration_artifact(published_observation.child_content())
        .expect("published child configuration artifact");
    let scenario_artifact = repository
        .load_scenario_artifact(lineage.scenario_content())
        .expect("published scenario artifact");
    let child_configuration = decode_crucible_configuration_artifact_with_selections(
        &scenario,
        &scenario_artifact,
        &child_artifact,
        &store,
    )
    .expect("decode published child configuration");
    assert_eq!(
        ConfigurationId::from_hash(CampaignHash::from_bytes(child_configuration.id().bytes)),
        published_observation.child()
    );
    assert_eq!(child_configuration.def.id(), scenario.scenario_def().id());
    assert_eq!(expected_opportunity.instance(), "publication");
    assert_eq!(
        expected_opportunity.source(),
        &ChoiceSource::Guest {
            node: String::from("db-0"),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        }
    );
    let reconciled = reconcile_published_attempt_result::<_, _, ()>(&mut supervisor, published)
        .expect("reconcile published result");
    assert_eq!(
        reconciled,
        AttemptWorkerReconcileOutcome::Reconciled {
            observation,
            completion: CompletionOutcome::Completed,
        }
    );

    let mut cleanup_complete = false;
    for _ in 0..64 {
        if LocalAttemptWorker::reconcile_execution(
            &mut worker,
            AttemptExecutionDisposition::Observation(observation),
        )
        .expect("reconcile hot-fork execution")
            == AttemptExecutionReconciliationStep::Complete
        {
            cleanup_complete = true;
            break;
        }
    }
    assert!(cleanup_complete);
    assert!(
        worker
            .model()
            .runner()
            .hot_fork()
            .lifecycle_factory()
            .sources()
            .available()
    );
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn target_world_resource_preflight_rejects_before_source_checkout_or_guard_installation() {
    let input = execution_input();
    let first =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let second =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let (_nodes, source_world) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![first, second])
            .expect("prepared source world");
    let observations = ScriptedWorldObservations::new();
    let run_state = tempfile::tempdir().expect("run state");
    let mut factory = factory(
        source_world,
        run_state.path().to_path_buf(),
        observations.clone(),
    );
    let resources = AttemptResourceLimits::new(1, 64 << 20, 64 << 20, 64)
        .expect("undersized attempt resources");
    let context = AttemptExecutionContext::new(
        resources,
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
    )
    .with_runtime_basis(execution_basis(&input, 0x80));

    let failure = match factory.try_start(&input, &context) {
        Err(failure) => failure,
        Ok(_) => panic!("aggregate World baseline must exceed the attempt ceiling"),
    };
    assert!(matches!(
        failure,
        AttemptWorkerFailure::Terminal(
            QemuProductionHotForkWorldLifecycleFactoryError::ScenarioResources(_)
        )
    ));
    assert!(factory.sources().available());
    assert!(
        observations
            .guard_liveness
            .lock()
            .expect("guard liveness")
            .is_none()
    );
    assert!(
        observations
            .retained_child_processes
            .lock()
            .expect("child process observations")
            .is_empty()
    );
}

#[test]
fn hot_first_router_falls_back_only_after_decline_and_bypasses_hot_fork_for_resume() {
    let (_repository, _store, _lineage, _attempt, candidate, _scenario) =
        repository_execution_fixture();
    let input = execution_input();
    let checkouts = Arc::new(AtomicUsize::new(0));
    let fallback_calls = Arc::new(AtomicUsize::new(0));
    let reconciliations = Arc::new(AtomicUsize::new(0));
    let observations = ScriptedWorldObservations::new();
    let run_state = tempfile::tempdir().expect("run state");
    let factory = QemuProductionHotForkWorldLifecycleFactory::new(
        RecordingUnavailableSourceWorldProvider {
            checkouts: Arc::clone(&checkouts),
        },
        ScriptedWorldGuardFactory { observations },
        run_state.path(),
        QemuShutdownPolicy::fast_test(),
        QemuAsyncDriverPolicy::fast_test(),
    );
    let unused_driver_calls = Arc::new(AtomicUsize::new(0));
    let unused_seals = Arc::new(AtomicUsize::new(0));
    let hot_fork = QemuHotForkWorldExecutionRunner::new(
        factory,
        ScriptedPublishedObservationDriver {
            candidate: candidate.clone(),
            drives: Arc::clone(&unused_driver_calls),
            seals: Arc::clone(&unused_seals),
        },
    );
    let fallback = RecordingFallbackRunner {
        candidate,
        calls: Arc::clone(&fallback_calls),
        reconciliations: Arc::clone(&reconciliations),
    };
    let mut router = QemuHotFirstExecutionRouter::new(hot_fork, fallback);

    let fresh = router
        .execute(&input, &execution_context(&input, 0x81))
        .expect("declined hot fork falls back");
    assert_eq!(
        fresh.materialization(),
        CrucibleMaterializationTier::ThinReplay
    );
    assert_eq!(checkouts.load(Ordering::SeqCst), 1);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);
    assert_eq!(unused_driver_calls.load(Ordering::SeqCst), 0);
    assert_eq!(unused_seals.load(Ordering::SeqCst), 0);
    assert_eq!(
        router
            .reconcile_execution(AttemptExecutionDisposition::Canceled)
            .expect("reconcile fallback"),
        AttemptExecutionReconciliationStep::Complete
    );

    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        4,
        b"hot-first-resume",
    ))
    .expect("checkpoint id");
    let resume_context = execution_context(&input, 0x82).with_resume_checkpoint(Some(checkpoint));
    let resumed = router
        .execute(&input, &resume_context)
        .expect("resume uses fallback directly");
    assert_eq!(
        resumed.materialization(),
        CrucibleMaterializationTier::ThinReplay
    );
    assert_eq!(checkouts.load(Ordering::SeqCst), 1);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        router
            .reconcile_execution(AttemptExecutionDisposition::ExactCheckpoint(checkpoint))
            .expect("reconcile resumed fallback"),
        AttemptExecutionReconciliationStep::Complete
    );
    assert_eq!(reconciliations.load(Ordering::SeqCst), 2);
}
