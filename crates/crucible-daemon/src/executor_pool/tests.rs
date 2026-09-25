//! Conformance tests for fixed local executor worker ownership.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]
// crucible-lint: allow clippy-disallowed-method -- the bounded host operation is operational only and cannot enter modeled state.
#![allow(clippy::disallowed_methods)]

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

use super::*;
use crate::executor_supervisor::AllowAllAttemptAdmission;
use crate::executor_worker::publish_prepared_semantic_attempt_result;
use crate::{
    AttemptAdmissionValidator, AttemptExecutionContext, AttemptExecutionDisposition,
    AttemptExecutionInput, AttemptExecutionKey, AttemptExecutionModel, AttemptExecutionOrigin,
    AttemptExecutionProduct, AttemptExecutionReconciliationStep, AttemptExecutionRuntimeBasis,
    AttemptRuntimeState, AttemptStateCas, AttemptWorkResult, AttemptWorkerFailure,
    CheckpointPromotionExecutionBasis, CheckpointPromotionRestartWork, CompletedFindingCandidate,
    DirectoryAssignmentLedger, ExactCheckpointStore, ExecutionCancellation, ExecutorCapacity,
    ExecutorLocalService, ExecutorLocalServiceError, ExecutorLoopbackEndpointConfig,
    ExecutorLoopbackServerConfig, LoopbackExecutorService, MemoryAssignmentLedger,
    PausedCheckpointPromotionRecoveryResolutionError, PreparedPausedCheckpointPromotion,
    PreparedPausedCheckpointPromotionRestart, PreparedSemanticAttemptResult,
    ProductionPausedCheckpointReplayFactory, ProductionPausedCheckpointReplaySession,
    RepositoryAttemptAdmission, RepositoryAttemptWorker, RepositoryAttemptWorkerError,
    UnixPeerExecutorIdentity, encode_crucible_configuration_artifact,
    encode_crucible_scenario_artifact, evaluate_crucible_measurement_publication,
    prepare_production_paused_checkpoint_promotion_restart, publish_next_objective_evaluation,
    resolve_production_paused_checkpoint_promotion_recovery,
};
use crucible::model::{
    Aggregation, BoundarySelector, CohortPolicy, MeasurementDefinition, MeasurementDefinitions,
    MeasurementId, MeasurementTerminalState, MetricDefinition, MetricId, MetricSource,
    MetricValueType, UnitId,
};
use crucible::{
    Configuration, Icount, Plan, Properties, ScenarioDefForm, Seed, VirtualTime, World,
};
use crucible_api::{
    AuthenticatedProductionCheckpointCodecFixture,
    build_authenticated_production_checkpoint_codec_fixture,
};
use crucible_campaign::{
    ActiveAttemptPolicy, ApplyCampaignCommandRequest, AssignmentId, Attempt, AttemptId,
    AttemptResourceLimits, AttemptStart, BooleanDomain, BranchBudget, BranchPath,
    BranchPathSegment, BranchRequest, BranchRequestCause, CampaignAuthorizationError,
    CampaignClient, CampaignCommandId, CampaignControlAction, CampaignExecutorDriver,
    CampaignExecutorStepOutcome, CampaignExecutorStore, CampaignHash, CampaignLineage,
    CampaignLineageId, CampaignMode, CampaignName, CampaignPolicy, CampaignPrincipal,
    CampaignPrincipalAuthorizer, CampaignRepository, CampaignSeed, CampaignServiceOperation,
    CancelAttemptExecutionRequest, CancelAttemptExecutionResponse, CandidateSource,
    CanonicalBeamPlanner, CheckpointAttemptExecutionRequest, CheckpointAttemptExecutionResponse,
    ChoiceClassContext, ChoiceCoordinate, ChoiceDomain, ChoiceOpportunity, ChoiceSource,
    ChoiceValue, ConfigurationArtifact, ConfigurationArtifactId, ConfigurationId, ControlRequest,
    CoverageProjection, DaemonEpoch, ExactCheckpointId, ExactRational, ExecutionId,
    ExecutionRetentionIntent, ExecutorCapabilitySet, ExecutorClient, ExecutorCompatibilityProfile,
    ExecutorControlService, ExecutorDescription, ExecutorMaterializationCapability,
    ExecutorRejection, ExecutorResumeService, ExecutorService, ExecutorStatusService,
    ExplorerPolicy, FairnessPolicy, GetAttemptExecutionDisposition, GetAttemptExecutionRequest,
    GetAttemptExecutionResponse, GetCampaignStatusRequest, InterventionLearningPolicy,
    MeasurementSet, Objective, ObjectiveGoal, Observation, ObservationCandidate, ObservationId,
    PinCampaignRequest, PinChange, PinRequest, PinRetention, PlannerProposalDisposition,
    PlanningBudget, PlanningScanPosition, ProgressiveWideningPolicy, PropertyVerdictSet, Proposal,
    PuctPolicy, PurePlannerEngine, RepositoryCampaignService, ResumeAttemptExecutionRequest,
    ResumeAttemptExecutionResponse, RetentionPolicy, SelectableDeclaration, Selection,
    SelectionOrigin, StopCondition, StopOutcome, SubmitAttemptDisposition, SubmitAttemptRequest,
    SubmitAttemptResponse, WorkerSlotId,
};
use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ContentId, ImmutableBlobBackend, MemoryBlobBackend,
    MemoryRefBackend, ObjectKind, PlacementReceipt, PutReceipt, StoreError,
};

struct TestDurableBackend {
    memory: MemoryBlobBackend,
}

struct RejectingPromotionBackend {
    memory: TestDurableBackend,
    reject_put: AtomicBool,
}

struct TransientExecutorReadBackend {
    memory: MemoryBlobBackend,
    fail_executor_read: AtomicBool,
    fail_content_read: Mutex<Option<ContentId>>,
    injected_failures: AtomicUsize,
}

impl TransientExecutorReadBackend {
    fn new(name: &'static str, maximum_bytes: u64) -> Self {
        Self {
            memory: MemoryBlobBackend::new(name, maximum_bytes),
            fail_executor_read: AtomicBool::new(false),
            fail_content_read: Mutex::new(None),
            injected_failures: AtomicUsize::new(0),
        }
    }

    fn fail_next_executor_read(&self) {
        self.fail_executor_read.store(true, Ordering::Release);
    }

    fn fail_next_read_of(&self, content: ContentId) {
        *self.fail_content_read.lock().expect("content read failure") = Some(content);
    }

    fn should_fail_content_read(&self, content: ContentId) -> bool {
        let mut failure = self.fail_content_read.lock().expect("content read failure");
        if failure.as_ref() == Some(&content) {
            *failure = None;
            self.injected_failures.fetch_add(1, Ordering::AcqRel);
            true
        } else {
            false
        }
    }

    fn should_fail_executor_read(&self) -> bool {
        let current = thread::current();
        let executor_thread = current
            .name()
            .is_some_and(|name| name.starts_with("crucible-executor-"));
        if executor_thread && self.fail_executor_read.swap(false, Ordering::AcqRel) {
            self.injected_failures.fetch_add(1, Ordering::AcqRel);
            true
        } else {
            false
        }
    }
}

impl ImmutableBlobBackend for TransientExecutorReadBackend {
    fn name(&self) -> &str {
        self.memory.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.memory.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        if self.should_fail_executor_read() {
            return Err(StoreError::Unavailable);
        }
        self.memory.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        if self.should_fail_content_read(id) || self.should_fail_executor_read() {
            return Err(StoreError::Unavailable);
        }
        self.memory.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.memory.put_if_absent(id, source)
    }
}

impl TestDurableBackend {
    fn new() -> Self {
        Self {
            memory: MemoryBlobBackend::new("executor-pool-checkpoints", 8 * 1024 * 1024),
        }
    }
}

impl RejectingPromotionBackend {
    fn new() -> Self {
        Self {
            memory: TestDurableBackend::new(),
            reject_put: AtomicBool::new(false),
        }
    }

    fn reject_publication(&self) {
        self.reject_put.store(true, Ordering::Release);
    }
}

impl ImmutableBlobBackend for RejectingPromotionBackend {
    fn name(&self) -> &str {
        "rejecting-promotion-backend"
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.memory.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.memory.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.memory.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        if self.reject_put.load(Ordering::Acquire) {
            Err(StoreError::Unauthorized)
        } else {
            self.memory.put_if_absent(id, source)
        }
    }
}

struct TerminalPromotionWorker;

impl LocalCheckpointPromotionWorker for TerminalPromotionWorker {
    type Error = &'static str;

    fn prepare(
        &mut self,
        _work: &mut CheckpointPromotionRestartWork,
        _cancellation: ExecutionCancellation,
    ) -> Result<PreparedPausedCheckpointPromotionRestart, AttemptWorkerFailure<Self::Error>> {
        Err(AttemptWorkerFailure::Terminal("terminal preparation"))
    }
}

struct CountingTerminalPromotionWorker {
    calls: Arc<AtomicUsize>,
}

impl LocalCheckpointPromotionWorker for CountingTerminalPromotionWorker {
    type Error = &'static str;

    fn prepare(
        &mut self,
        _work: &mut CheckpointPromotionRestartWork,
        _cancellation: ExecutionCancellation,
    ) -> Result<PreparedPausedCheckpointPromotionRestart, AttemptWorkerFailure<Self::Error>> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Err(AttemptWorkerFailure::Terminal("terminal preparation"))
    }
}

struct PreparedPromotionWorker {
    prepared: Option<PreparedPausedCheckpointPromotion>,
}

impl LocalCheckpointPromotionWorker for PreparedPromotionWorker {
    type Error = &'static str;

    fn prepare(
        &mut self,
        _work: &mut CheckpointPromotionRestartWork,
        _cancellation: ExecutionCancellation,
    ) -> Result<PreparedPausedCheckpointPromotionRestart, AttemptWorkerFailure<Self::Error>> {
        let prepared = self.prepared.take().expect("single promotion preparation");
        Ok(PreparedPausedCheckpointPromotionRestart::Stage(Box::new(
            prepared,
        )))
    }
}

impl ImmutableBlobBackend for TestDurableBackend {
    fn name(&self) -> &str {
        "executor-pool-checkpoints"
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

struct BlockingAdmission {
    state: Arc<(Mutex<(bool, bool)>, Condvar)>,
}

struct AllowCampaignControl;

impl CampaignPrincipalAuthorizer for AllowCampaignControl {
    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        Ok(())
    }
}

impl AttemptAdmissionValidator for BlockingAdmission {
    fn validate(&self, _request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection> {
        let (state, changed) = self.state.as_ref();
        let mut state = state.lock().map_err(|_| ExecutorRejection::Unauthorized)?;
        state.0 = true;
        changed.notify_all();
        while !state.1 {
            state = changed
                .wait(state)
                .map_err(|_| ExecutorRejection::Unauthorized)?;
        }
        Ok(())
    }
}

struct SequencedFailureWorker {
    calls: Arc<AtomicUsize>,
}

struct CountingProductionReplayFactory {
    calls: Arc<AtomicUsize>,
}

struct UnusedPromotionGuard {
    cancellation: ExecutionCancellation,
    resources: AttemptResourceLimits,
}

impl crate::QemuAttemptOperationalBoundary for UnusedPromotionGuard {
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), crucible_qemu::QemuVmRealizationError> {
        Ok(())
    }

    fn charge_execution_quantum(&mut self) -> Result<(), crucible_qemu::QemuVmRealizationError> {
        Ok(())
    }
}

impl crate::QemuAttemptResourceGuard for UnusedPromotionGuard {
    fn finish(&mut self) -> Result<(), crucible_qemu::QemuVmRealizationError> {
        Ok(())
    }

    fn quarantine(&mut self) {}
}

impl crate::QemuAttemptProcessResourceGuard for UnusedPromotionGuard {
    fn child_process_contract(
        &self,
    ) -> Result<&crucible_qemu::QemuChildProcessContract, crucible_qemu::QemuVmRealizationError>
    {
        Err(crucible_qemu::QemuVmRealizationError::Executor {
            operation: "use unreachable promotion guard",
            message: String::from("test factory never admits a QEMU target"),
        })
    }

    fn prepare_generation_run_directory(
        &mut self,
        _requirements: crucible_qemu::QemuLaunchResourceRequirements,
    ) -> Result<crucible_qemu::QemuPreparedRunDirectory, crucible_qemu::QemuVmRealizationError>
    {
        Err(crucible_qemu::QemuVmRealizationError::Executor {
            operation: "use unreachable promotion guard",
            message: String::from("test factory never admits a QEMU target"),
        })
    }

    fn retain_failed_launch_child(&mut self, _child: crucible_qemu::QemuNodeChild) {
        panic!("unreachable promotion guard cannot retain a child")
    }
}

impl ProductionPausedCheckpointReplayFactory for CountingProductionReplayFactory {
    type Guard = UnusedPromotionGuard;

    fn begin_replay(
        &mut self,
        _selected_checkpoint: crate::executor_supervisor::SelectedExactCheckpointRoot,
        cancellation: &ExecutionCancellation,
        resources: AttemptResourceLimits,
    ) -> Result<Self::Guard, crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure>
    {
        Ok(UnusedPromotionGuard {
            cancellation: cancellation.clone(),
            resources,
        })
    }

    fn begin_target(
        &mut self,
        _world: &World,
        _configuration: &Configuration,
        _target: crucible_api::ProductionVmReplayExactNodeRestoreAdmission,
        _guard: &mut Self::Guard,
    ) -> Result<ProductionPausedCheckpointReplaySession, crucible_qemu::QemuVmRealizationError>
    {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Err(crucible_qemu::QemuVmRealizationError::Executor {
            operation: "enter counted production replay target",
            message: String::from("counted test factory stops before QEMU launch"),
        })
    }

    fn replay_savepoint_capture(
        &mut self,
        _attempt: &crate::CrucibleAttemptExecution,
        _run_state_root: &std::path::Path,
        _cancellation: &ExecutionCancellation,
        _resources: AttemptResourceLimits,
    ) -> Result<crate::QemuSavepointReplayProof, crucible_qemu::QemuVmRealizationError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Err(crucible_qemu::QemuVmRealizationError::Executor {
            operation: "enter counted production attempt replay",
            message: String::from("counted test factory stops before QEMU launch"),
        })
    }
}

impl LocalAttemptWorker for SequencedFailureWorker {
    type Error = &'static str;

    fn execute(&mut self, queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel);
        let result = if call == 0 {
            Err(AttemptWorkerFailure::Retryable("retry once"))
        } else {
            Err(AttemptWorkerFailure::Terminal("stop"))
        };
        AttemptWorkResult::new(queued, result)
    }

    fn reconcile_execution(
        &mut self,
        _disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        panic!("a failed execution must reconcile its owner before returning")
    }
}

struct BlockingWorker {
    entered: Arc<AtomicUsize>,
}

#[derive(Default)]
struct DelayedCancellationState {
    entered: bool,
    canceled: bool,
    release: bool,
}

type SharedDelayedCancellationState = Arc<(Mutex<DelayedCancellationState>, Condvar)>;

struct DelayedCancellationWorker {
    state: SharedDelayedCancellationState,
}

impl LocalAttemptWorker for BlockingWorker {
    type Error = &'static str;

    fn execute(&mut self, queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        self.entered.store(1, Ordering::Release);
        while !queued.cancellation().is_canceled() {
            thread::sleep(Duration::from_millis(1));
        }
        AttemptWorkResult::new(
            queued,
            Err(AttemptWorkerFailure::Canceled("shutdown cancellation")),
        )
    }
}

impl LocalAttemptWorker for DelayedCancellationWorker {
    type Error = &'static str;

    fn execute(&mut self, queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        let (state, changed) = self.state.as_ref();
        {
            let mut state = state.lock().expect("delayed worker state");
            state.entered = true;
            changed.notify_all();
        }
        while !queued.cancellation().is_canceled() {
            thread::sleep(Duration::from_millis(1));
        }
        let mut state = state.lock().expect("delayed worker state");
        state.canceled = true;
        changed.notify_all();
        while !state.release {
            state = changed.wait(state).expect("delayed worker wake");
        }
        drop(state);
        AttemptWorkResult::new(
            queued,
            Err(AttemptWorkerFailure::Canceled(
                "delayed shutdown cancellation",
            )),
        )
    }
}

#[derive(Default)]
struct RecordingPausedCheckpointObserver {
    checkpoints: Mutex<Vec<ExactCheckpointId>>,
    promotions: Mutex<Vec<(ExactCheckpointId, ExactCheckpointId)>>,
}

impl PausedCheckpointObserver for RecordingPausedCheckpointObserver {
    fn checkpoint_paused(&self, checkpoint: ExactCheckpointId) -> Result<(), ()> {
        self.checkpoints
            .lock()
            .expect("paused-checkpoint observer lock")
            .push(checkpoint);
        Ok(())
    }

    fn checkpoint_promoted(
        &self,
        source: ExactCheckpointId,
        promoted: ExactCheckpointId,
    ) -> Result<(), ()> {
        self.promotions
            .lock()
            .expect("promoted-checkpoint observer lock")
            .push((source, promoted));
        Ok(())
    }
}

struct PanickingWorker;

impl LocalAttemptWorker for PanickingWorker {
    type Error = &'static str;

    fn execute(&mut self, _queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        panic!("intentional worker panic")
    }
}

struct AcceptedThenPanickingWorker(mpsc::Receiver<()>);

impl LocalAttemptWorker for AcceptedThenPanickingWorker {
    type Error = &'static str;

    fn execute(&mut self, _queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        // The listener must publish Accepted before this worker can close it.
        self.0
            .recv()
            .expect("client must release the accepted worker");
        panic!("intentional worker panic")
    }
}

struct CandidateModel {
    candidate: ObservationCandidate,
    calls: Arc<AtomicUsize>,
    runtime_bases: Arc<Mutex<Vec<AttemptExecutionRuntimeBasis>>>,
    reconciliations: Arc<Mutex<Vec<AttemptExecutionDisposition>>>,
}

struct CountingExecutorService<S> {
    inner: S,
    submits: Arc<AtomicUsize>,
    status_reads: Arc<AtomicUsize>,
}

impl<S: ExecutorService> ExecutorService for CountingExecutorService<S> {
    type Error = S::Error;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        self.submits.fetch_add(1, Ordering::AcqRel);
        self.inner.submit_attempt(request)
    }
}

impl<S: ExecutorStatusService> ExecutorStatusService for CountingExecutorService<S> {
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        self.status_reads.fetch_add(1, Ordering::AcqRel);
        self.inner.get_attempt_execution(request)
    }
}

impl<S: ExecutorControlService> ExecutorControlService for CountingExecutorService<S> {
    fn checkpoint_attempt_execution(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, Self::Error> {
        self.inner.checkpoint_attempt_execution(request)
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, Self::Error> {
        self.inner.cancel_attempt_execution(request)
    }
}

impl<S: ExecutorResumeService> ExecutorResumeService for CountingExecutorService<S> {
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        self.inner.resume_attempt_execution(request)
    }
}

impl AttemptExecutionModel for CandidateModel {
    type Error = std::convert::Infallible;

    fn execute(
        &mut self,
        _input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        assert!(!context.cancellation().is_canceled());
        self.runtime_bases
            .lock()
            .expect("runtime basis log")
            .push(context.runtime_basis().expect("worker runtime basis"));
        self.calls.fetch_add(1, Ordering::AcqRel);
        let result = PreparedSemanticAttemptResult::new(self.candidate.clone(), Vec::new(), None)
            .expect("prepare candidate result");
        Ok(AttemptExecutionProduct::prepared_semantic(result))
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        let mut reconciliations = self.reconciliations.lock().expect("reconciliation log");
        reconciliations.push(disposition);
        if reconciliations.len() == 1 {
            Ok(AttemptExecutionReconciliationStep::Progressed)
        } else {
            Ok(AttemptExecutionReconciliationStep::Complete)
        }
    }
}

#[test]
fn fixed_pool_requeues_once_then_stops_without_capacity_growth() {
    let epoch = DaemonEpoch::from_bytes([0x31; 16]).expect("epoch");
    let calls = Arc::new(AtomicUsize::new(0));
    let pool = pool(
        epoch,
        vec![SequencedFailureWorker {
            calls: Arc::clone(&calls),
        }],
    );
    let mut client = ExecutorClient::new(pool.service());
    assert!(matches!(
        client
            .submit_attempt(&request(epoch, 0x41))
            .expect("accepted request")
            .disposition(),
        SubmitAttemptDisposition::Accepted { .. }
    ));
    wait_until(Duration::from_secs(2), || {
        pool.service()
            .report()
            .is_ok_and(|report| report.active() == 0)
    });
    let report = pool.service().report().expect("pool report");
    assert_eq!(calls.load(Ordering::Acquire), 2);
    assert_eq!(report.executions(), 2);
    assert_eq!(report.retry_requeues(), 1);
    assert_eq!(report.terminal_stops(), 1);
    assert_eq!(report.active(), 0);
    assert_eq!(pool.shutdown_and_join().expect("clean shutdown"), report);
}

#[test]
fn operational_snapshots_are_read_only_and_revision_overflow_is_unavailable() {
    let epoch = DaemonEpoch::from_bytes([0x30; 16]).expect("epoch");
    let pool = pool(
        epoch,
        vec![SequencedFailureWorker {
            calls: Arc::new(AtomicUsize::new(0)),
        }],
    );
    let service = pool.service();

    let before = service.operational_snapshot().expect("first snapshot");
    thread::sleep(WORKER_RETRY_INTERVAL.saturating_mul(3));
    let after = service.operational_snapshot().expect("second snapshot");
    assert_eq!(after, before);

    service
        .shared
        .ownership_revision
        .store(u64::MAX, Ordering::Release);
    assert!(matches!(
        service.operational_snapshot(),
        Err(LocalExecutorPoolServiceError::ObservationRevisionExhausted)
    ));
    assert!(service.report().is_ok());

    pool.shutdown_and_join().expect("clean shutdown");
}

#[test]
fn promotion_report_records_terminal_preparation_from_real_process_path() {
    let checkpoints = checkpoint_store();
    let (shared, mut work, prepared, _) = promotion_process_fixture(Arc::clone(&checkpoints));
    let mut worker = TerminalPromotionWorker;

    promotion::process_promotion_work(
        &shared,
        &mut worker,
        &mut work,
        ExecutionCancellation::default(),
    );
    drop(prepared);

    let executor = shared.executor.lock().expect("executor report lock");
    let report = shared.report(executor.supervisor());
    assert_eq!(report.promotion_failures(), 1);
    assert_eq!(report.promotion_failure_phases().preparation_terminal(), 1);
    assert_eq!(
        report
            .promotion_failure_phases()
            .publication_terminal_reverted(),
        0
    );
    let failure = report
        .last_promotion_failure()
        .expect("terminal preparation retains its typed failure");
    assert_eq!(failure.phase(), LocalExecutorPromotionPhase::Preparation);
    assert_eq!(failure.detail(), "\"terminal preparation\"");
    assert!(!failure.detail_truncated());
    assert_eq!(
        report.last_promotion_activity().map(|(_, phase)| phase),
        Some(LocalExecutorPromotionPhase::Preparation)
    );
}

#[test]
fn stale_raw_promotion_is_discarded_before_worker_preparation() {
    let checkpoints = checkpoint_store();
    let fixture = crate::prepare_repository_promotion_fixture(&checkpoints);
    let crate::RepositoryPromotionFixture {
        prepared,
        key,
        state,
        daemon_epoch,
        capacity,
        ..
    } = fixture;
    let mut recovery_ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        recovery_ledger
            .compare_exchange_attempt(key, None, Some(state))
            .expect("seed raw promotion recovery"),
        AttemptStateCas::Advanced
    );
    let recovery_supervisor = LocalExecutorSupervisor::new(
        recovery_ledger,
        AllowAllAttemptAdmission,
        daemon_epoch,
        capacity,
    );
    let recovery = recovery_supervisor
        .paused_checkpoint_promotion_recovery(key)
        .expect("load raw promotion recovery")
        .expect("raw promotion recovery");

    let stale_state = AttemptRuntimeState::Canceled {
        execution_basis: state.execution_basis(),
        origin: state.origin(),
        daemon_epoch: state.daemon_epoch(),
        execution: state.execution(),
    };
    let mut ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, None, Some(stale_state))
            .expect("seed superseding terminal state"),
        AttemptStateCas::Advanced
    );
    let supervisor =
        LocalExecutorSupervisor::new(ledger, AllowAllAttemptAdmission, daemon_epoch, capacity);
    let resources = AttemptResourceLimits::new(1, 64 * 1024 * 1024, 0, 1_000)
        .expect("promotion fixture resource ceiling");
    let executor = LocalExecutorCapabilityService::new(
        supervisor,
        description_with_limits(daemon_epoch, 1, resources),
    )
    .expect("promotion fixture capability");
    let shared = SharedExecutor::new(executor, checkpoints, 1, 1, Vec::new(), None, None);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut worker = CountingTerminalPromotionWorker {
        calls: Arc::clone(&calls),
    };
    let mut work = CheckpointPromotionRestartWork::Paused(recovery);

    promotion::process_promotion_work(
        &shared,
        &mut worker,
        &mut work,
        ExecutionCancellation::default(),
    );
    drop(prepared);

    assert_eq!(calls.load(Ordering::Acquire), 0);
    let executor = shared.executor.lock().expect("executor report lock");
    let report = shared.report(executor.supervisor());
    assert_eq!(report.promotions_discarded(), 1);
    assert_eq!(report.promotion_failures(), 0);
    assert_eq!(report.promotion_failure_phases().preparation_terminal(), 0);
    assert!(report.last_promotion_failure().is_none());
    assert_eq!(
        report.last_promotion_activity().map(|(_, phase)| phase),
        Some(LocalExecutorPromotionPhase::Preflight)
    );
}

#[test]
fn promotion_report_records_terminal_publication_and_raw_reversion() {
    let backend = Arc::new(RejectingPromotionBackend::new());
    let checkpoints = Arc::new(
        ExactCheckpointStore::new(backend.clone(), 64 * 1024 * 1024)
            .expect("promotion checkpoint store"),
    );
    let (shared, mut work, prepared, raw) = promotion_process_fixture(Arc::clone(&checkpoints));
    backend.reject_publication();
    let mut worker = PreparedPromotionWorker {
        prepared: Some(prepared),
    };

    promotion::process_promotion_work(
        &shared,
        &mut worker,
        &mut work,
        ExecutionCancellation::default(),
    );

    let executor = shared.executor.lock().expect("executor report lock");
    let report = shared.report(executor.supervisor());
    assert_eq!(report.promotion_failures(), 1);
    assert_eq!(report.promotions_discarded(), 1);
    assert_eq!(report.promotion_failure_phases().preparation_terminal(), 0);
    assert_eq!(
        report
            .promotion_failure_phases()
            .publication_terminal_reverted(),
        1
    );
    let key = match work {
        CheckpointPromotionRestartWork::Paused(recovery) => recovery.key(),
        CheckpointPromotionRestartWork::Staged(_) => panic!("fixture began as a raw pause"),
    };
    let failure = report
        .last_promotion_failure()
        .expect("terminal publication retains its typed failure");
    assert_eq!(failure.key(), key);
    assert_eq!(failure.phase(), LocalExecutorPromotionPhase::Publication);
    assert!(!failure.detail().is_empty());
    assert_eq!(
        report.last_promotion_activity(),
        Some((key, LocalExecutorPromotionPhase::Publication))
    );
    assert_eq!(
        executor
            .supervisor()
            .paused_checkpoint_promotion_recovery(key)
            .expect("load reverted promotion")
            .expect("raw promotion remains eligible")
            .source(),
        raw
    );
}

#[test]
fn completed_promotion_worker_reclaims_its_live_claim() {
    let checkpoints = Arc::new(
        ExactCheckpointStore::new(Arc::new(TestDurableBackend::new()), 64 * 1024 * 1024)
            .expect("promotion checkpoint store"),
    );
    let (shared, mut work, prepared, _) = promotion_process_fixture(checkpoints);
    assert_eq!(
        promotion::reclaim_inactive_promotion_claims(&shared, &work),
        None,
        "a raw paused execution can still stage its promotion"
    );

    let mut worker = PreparedPromotionWorker {
        prepared: Some(prepared),
    };
    promotion::process_promotion_work(
        &shared,
        &mut worker,
        &mut work,
        ExecutionCancellation::default(),
    );
    let executor = shared.executor.lock().expect("completed promotion ledger");
    let report = shared.report(executor.supervisor());
    assert_eq!(report.promotions_reconciled(), 1);
    drop(executor);

    assert_eq!(
        promotion::reclaim_inactive_promotion_claims(&shared, &work),
        Some(1),
        "completed promotion releases its process-local claim"
    );
    assert_eq!(
        promotion::reclaim_inactive_promotion_claims(&shared, &work),
        Some(0),
        "reclamation is idempotent"
    );
}

#[test]
fn blocking_worker_does_not_block_service_and_shutdown_cancels_it() {
    let epoch = DaemonEpoch::from_bytes([0x32; 16]).expect("epoch");
    let entered = Arc::new(AtomicUsize::new(0));
    let pool = pool(
        epoch,
        vec![BlockingWorker {
            entered: Arc::clone(&entered),
        }],
    );
    let mut service = pool.service();
    let accepted = service
        .submit_attempt(&request(epoch, 0x42))
        .expect("accepted request");
    let SubmitAttemptDisposition::Accepted { .. } = accepted.disposition() else {
        panic!("request should be accepted")
    };
    wait_until(Duration::from_secs(2), || {
        entered.load(Ordering::Acquire) == 1
    });

    let started = Instant::now();
    let second = service
        .submit_attempt(&request(epoch, 0x43))
        .expect("bounded capacity response");
    assert!(matches!(
        second.disposition(),
        SubmitAttemptDisposition::Rejected { .. }
    ));
    assert!(started.elapsed() < Duration::from_millis(250));

    pool.request_shutdown();
    let report = pool.shutdown_and_join().expect("shutdown joins worker");
    assert_eq!(report.active(), 0);
    assert_eq!(report.terminal_stops(), 1);
}

#[test]
fn shutdown_drains_accepted_work_that_never_started() {
    let epoch = DaemonEpoch::from_bytes([0x36; 16]).expect("epoch");
    let entered = Arc::new(AtomicUsize::new(0));
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(2, 2, 4096, 8192, 64).expect("two-slot capacity"),
    );
    let capability =
        LocalExecutorCapabilityService::new(supervisor, description_with_slots(epoch, 2))
            .expect("two-slot capability");
    let pool = LocalExecutorWorkerPool::start(
        capability,
        store(),
        checkpoint_store(),
        vec![BlockingWorker {
            entered: Arc::clone(&entered),
        }],
    )
    .expect("one worker with two admitted slots");
    let mut service = pool.service();
    service
        .submit_attempt(&request(epoch, 0x47))
        .expect("first request");
    wait_until(Duration::from_secs(2), || {
        entered.load(Ordering::Acquire) == 1
    });
    assert!(matches!(
        service
            .submit_attempt(&request(epoch, 0x48))
            .expect("second queued request")
            .disposition(),
        SubmitAttemptDisposition::Accepted { .. }
    ));
    let before = service.report().expect("pre-shutdown report");
    assert_eq!(before.active(), 2);
    assert_eq!(before.queued(), 1);

    let report = pool.shutdown_and_join().expect("drained shutdown");
    assert_eq!(report.active(), 0);
    assert_eq!(report.queued(), 0);
    assert_eq!(report.executions(), 1);
    assert_eq!(report.terminal_stops(), 2);
}

#[test]
fn worker_panic_fails_closed_and_releases_exact_reservation() {
    let epoch = DaemonEpoch::from_bytes([0x33; 16]).expect("epoch");
    let pool = pool(epoch, vec![PanickingWorker]);
    let mut service = pool.service();
    service
        .submit_attempt(&request(epoch, 0x44))
        .expect("accepted request");
    wait_until(Duration::from_secs(2), || {
        matches!(
            service.submit_attempt(&request(epoch, 0x45)),
            Err(LocalExecutorPoolServiceError::WorkerPanicked)
        )
    });
    wait_until(Duration::from_secs(2), || {
        pool.service
            .shared
            .executor
            .lock()
            .is_ok_and(|executor| executor.supervisor().active_count() == 0)
    });
    assert!(matches!(
        pool.shutdown_and_join(),
        Err(LocalExecutorPoolShutdownError::WorkerPanicked)
    ));
}

#[test]
fn coupled_service_shutdown_interrupts_listener_and_joins_semantic_worker() {
    let epoch = DaemonEpoch::from_bytes([0x73; 16]).expect("epoch");
    let worker_state = Arc::new((
        Mutex::new(DelayedCancellationState::default()),
        Condvar::new(),
    ));
    let pool = pool(
        epoch,
        vec![DelayedCancellationWorker {
            state: Arc::clone(&worker_state),
        }],
    );
    let (directory, socket, listener, peer) = managed_executor_endpoint("coupled-shutdown");
    let service = ExecutorLocalService::from_managed_listener(
        listener,
        pool,
        peer,
        ExecutorLoopbackServerConfig::default(),
    )
    .expect("coupled local executor");
    let shutdown = service.shutdown_handle();
    let serving = thread::spawn(move || service.serve());

    let stream = UnixStream::connect(&socket).expect("connect executor client");
    let mut client = LoopbackExecutorService::new(stream).expect("executor client");
    assert!(matches!(
        client
            .submit_attempt(&request(epoch, 0x74))
            .expect("submit blocked execution")
            .disposition(),
        SubmitAttemptDisposition::Accepted { .. }
    ));
    wait_for_delayed_worker(&worker_state, |state| state.entered);

    shutdown.shutdown();
    wait_for_delayed_worker(&worker_state, |state| state.canceled);
    assert!(socket.exists());
    {
        let (state, changed) = worker_state.as_ref();
        let mut state = state.lock().expect("delayed worker state");
        state.release = true;
        changed.notify_all();
    }
    let report = serving
        .join()
        .expect("service thread")
        .expect("clean coupled shutdown");
    assert!(shutdown.is_shutdown());
    assert_eq!(report.listener().accepted_connections(), 1);
    assert_eq!(report.pool().executions(), 1);
    assert_eq!(report.pool().terminal_stops(), 1);
    assert_eq!(report.pool().active(), 0);
    assert!(!socket.exists());
    drop(directory);
}

#[test]
fn dropping_unserved_coupled_owner_retains_endpoint_until_semantic_join() {
    let epoch = DaemonEpoch::from_bytes([0x77; 16]).expect("epoch");
    let worker_state = Arc::new((
        Mutex::new(DelayedCancellationState::default()),
        Condvar::new(),
    ));
    let pool = pool(
        epoch,
        vec![DelayedCancellationWorker {
            state: Arc::clone(&worker_state),
        }],
    );
    let mut direct = pool.service();
    direct
        .submit_attempt(&request(epoch, 0x78))
        .expect("submit direct execution before binding");
    wait_for_delayed_worker(&worker_state, |state| state.entered);

    let (directory, socket, listener, peer) = managed_executor_endpoint("coupled-drop");
    let service = ExecutorLocalService::from_managed_listener(
        listener,
        pool,
        peer,
        ExecutorLoopbackServerConfig::default(),
    )
    .expect("coupled local executor");
    let dropping = thread::spawn(move || drop(service));

    wait_for_delayed_worker(&worker_state, |state| state.canceled);
    assert!(socket.exists());
    {
        let (state, changed) = worker_state.as_ref();
        let mut state = state.lock().expect("delayed worker state");
        state.release = true;
        changed.notify_all();
    }
    dropping.join().expect("coupled owner drop");
    assert!(!socket.exists());
    drop(directory);
}

#[test]
fn pending_service_cleanup_retains_endpoint_and_reservation_until_worker_exit() {
    for retained in [false, true] {
        let epoch = DaemonEpoch::from_bytes([0x79; 16]).expect("epoch");
        let worker_state = Arc::new((
            Mutex::new(DelayedCancellationState::default()),
            Condvar::new(),
        ));
        let pool = pool(
            epoch,
            vec![DelayedCancellationWorker {
                state: Arc::clone(&worker_state),
            }],
        );
        let mut direct = pool.service();
        direct
            .submit_attempt(&request(epoch, 0x7a))
            .expect("accepted attempt");
        wait_for_delayed_worker(&worker_state, |state| state.entered);
        let completion = pool.completion_handle();
        if retained {
            // Exercise the notification issued immediately before a worker
            // parks in quarantine without leaving a permanent test thread.
            pool.service.shared.fail_closed();
            pool.service.shared.completion.signal_retained();
        }
        let (directory, socket, listener, peer) = managed_executor_endpoint("pending-cleanup");
        let service = ExecutorLocalService::from_managed_listener(
            listener,
            pool,
            peer,
            ExecutorLoopbackServerConfig::default(),
        )
        .expect("service");
        let shutdown = service.shutdown_handle();
        let serving =
            thread::spawn(move || service.serve_with_shutdown_timeout(Duration::from_millis(25)));
        shutdown.shutdown();
        wait_for_delayed_worker(&worker_state, |state| state.canceled);
        let result = serving.join().expect("service thread");
        assert!(matches!(
            result,
            Err(ExecutorLocalServiceError::Pool(
                LocalExecutorPoolShutdownError::CleanupPending
            ))
        ));
        assert!(!completion.is_finished());
        assert_eq!(direct.report().expect("retained report").active(), 1);
        assert!(socket.exists());
        let endpoint = ExecutorLoopbackEndpointConfig::new(
            &socket,
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
            0o600,
        )
        .expect("endpoint");
        assert!(
            endpoint.bind().is_err(),
            "unfinished incarnation still owns endpoint"
        );
        {
            let (state, changed) = worker_state.as_ref();
            state.lock().expect("state").release = true;
            changed.notify_all();
        }
        wait_until(Duration::from_secs(2), || {
            completion.is_finished() && !socket.exists()
        });
        assert_eq!(direct.report().expect("reconciled report").active(), 0);
        drop(endpoint.bind().expect("endpoint reusable after cleanup"));
        drop(directory);
    }
}

#[test]
fn worker_completion_is_not_announced_before_model_drop_finishes() {
    struct DropBlockedWorker(SharedDelayedCancellationState);

    impl LocalAttemptWorker for DropBlockedWorker {
        type Error = ();

        fn execute(&mut self, queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
            AttemptWorkResult::new(queued, Err(AttemptWorkerFailure::Canceled(())))
        }
    }

    impl Drop for DropBlockedWorker {
        fn drop(&mut self) {
            let (state, changed) = self.0.as_ref();
            let mut state = state.lock().expect("drop state");
            state.entered = true;
            changed.notify_all();
            while !state.release {
                state = changed.wait(state).expect("drop release");
            }
        }
    }

    let state = Arc::new((
        Mutex::new(DelayedCancellationState::default()),
        Condvar::new(),
    ));
    let epoch = DaemonEpoch::from_bytes([0x7b; 16]).expect("epoch");
    let pool = pool(epoch, vec![DropBlockedWorker(Arc::clone(&state))]);
    let completion = pool.completion_handle();
    pool.request_shutdown();
    wait_for_delayed_worker(&state, |state| state.entered);
    assert!(!completion.is_finished());
    assert!(matches!(
        pool.shutdown_and_join_with_timeout(Duration::ZERO),
        Err(LocalExecutorPoolShutdownError::CleanupPending)
    ));
    {
        let (state, changed) = state.as_ref();
        state.lock().expect("state").release = true;
        changed.notify_all();
    }
    wait_until(Duration::from_secs(2), || completion.is_finished());
}

#[test]
fn terminal_worker_failure_closes_listener_and_precedes_listener_result() {
    let epoch = DaemonEpoch::from_bytes([0x75; 16]).expect("epoch");
    let (release_worker, worker_gate) = mpsc::channel();
    let pool = pool(epoch, vec![AcceptedThenPanickingWorker(worker_gate)]);
    let (directory, socket, listener, peer) = managed_executor_endpoint("coupled-panic");
    let service = ExecutorLocalService::from_managed_listener(
        listener,
        pool,
        peer,
        ExecutorLoopbackServerConfig::default(),
    )
    .expect("coupled local executor");
    let shutdown = service.shutdown_handle();
    let serving = thread::spawn(move || service.serve());

    let stream = UnixStream::connect(&socket).expect("connect executor client");
    let mut client = LoopbackExecutorService::new(stream).expect("executor client");
    assert!(matches!(
        client
            .submit_attempt(&request(epoch, 0x76))
            .expect("accept panicking execution")
            .disposition(),
        SubmitAttemptDisposition::Accepted { .. }
    ));
    release_worker.send(()).expect("release accepted worker");
    wait_until(Duration::from_secs(2), || shutdown.is_shutdown());

    assert!(matches!(
        serving.join().expect("service thread"),
        Err(ExecutorLocalServiceError::Pool(
            LocalExecutorPoolShutdownError::WorkerPanicked
        ))
    ));
    assert!(!socket.exists());
    drop(directory);
}

#[test]
fn worker_count_is_bounded_by_static_and_supervisor_capacity() {
    let epoch = DaemonEpoch::from_bytes([0x34; 16]).expect("epoch");
    let store = store();
    assert!(matches!(
        LocalExecutorWorkerPool::<MemoryAssignmentLedger, AllowAllAttemptAdmission>::start::<
            SequencedFailureWorker,
        >(
            capability(epoch),
            store.clone(),
            checkpoint_store(),
            Vec::new(),
        ),
        Err(LocalExecutorPoolConfigError::ZeroWorkers)
    ));
    let workers = (0..2)
        .map(|_| SequencedFailureWorker {
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .collect();
    assert!(matches!(
        LocalExecutorWorkerPool::start(capability(epoch), store, checkpoint_store(), workers),
        Err(LocalExecutorPoolConfigError::WorkerCountExceedsSlots)
    ));
}

#[test]
fn campaign_controls_remain_responsive_while_every_executor_slot_is_busy() {
    #[derive(Default)]
    struct BusyWorkerState {
        entered: usize,
        executions: Vec<ExecutionId>,
        cancellations_observed: usize,
        release: bool,
    }

    struct CountingBlockingWorker {
        state: Arc<(Mutex<BusyWorkerState>, Condvar)>,
    }

    impl LocalAttemptWorker for CountingBlockingWorker {
        type Error = &'static str;

        fn execute(&mut self, queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
            let cancellation_observer = queued
                .cancellation()
                .observer_for_test()
                .expect("install busy-worker cancellation observer");
            {
                let (state, changed) = self.state.as_ref();
                let mut state = state.lock().expect("busy worker state");
                state.entered += 1;
                state.executions.push(queued.execution());
                changed.notify_all();
            }
            assert!(
                cancellation_observer.wait_for_cancellation(Duration::from_secs(2)),
                "worker did not observe shutdown cancellation"
            );

            let (state, changed) = self.state.as_ref();
            let mut state = state.lock().expect("busy worker state");
            state.cancellations_observed += 1;
            changed.notify_all();
            let (state, timeout) = changed
                .wait_timeout_while(state, Duration::from_secs(2), |state| !state.release)
                .expect("busy worker release notification");
            assert!(!timeout.timed_out(), "worker release was not acknowledged");
            drop(state);

            AttemptWorkResult::new(
                queued,
                Err(AttemptWorkerFailure::Canceled("control-path shutdown")),
            )
        }
    }

    const CONTROL_BOUND: Duration = Duration::from_millis(250);

    let blobs = Arc::new(MemoryBlobBackend::new(
        "busy-campaign-control",
        64 * 1024 * 1024,
    ));
    let repository = Arc::new(CampaignRepository::new(
        blobs,
        Arc::new(MemoryRefBackend::new()),
    ));
    let campaign = "busy-campaign-control";
    let (lineage, _, _, admitted, _) = campaign_attempt_fixture(&repository, campaign);
    let running = repository
        .apply_control(
            campaign,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.busy-control.resume.v1",
                    b"resume",
                )),
                expected_snapshot: admitted.new_snapshot,
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume busy-control campaign");

    let epoch = DaemonEpoch::from_bytes([0xa0; 16]).expect("daemon epoch");
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(3, 3, 3072, 6144, 96).expect("three-slot capacity"),
    );
    let capability = LocalExecutorCapabilityService::new(
        supervisor,
        description_with_limits(
            epoch,
            3,
            AttemptResourceLimits::new(3, 3072, 6144, 96).expect("three-slot resource ceiling"),
        ),
    )
    .expect("three-slot capability");
    let worker_state = Arc::new((Mutex::new(BusyWorkerState::default()), Condvar::new()));
    let pool = LocalExecutorWorkerPool::start(
        capability,
        CampaignExecutorStore::new(Arc::clone(&repository)),
        checkpoint_store(),
        (0..2)
            .map(|_| CountingBlockingWorker {
                state: Arc::clone(&worker_state),
            })
            .collect(),
    )
    .expect("two-worker pool");
    let mut executor = pool.service();
    for byte in [0xa1, 0xa2, 0xa3] {
        assert!(matches!(
            executor
                .submit_attempt(&request(epoch, byte))
                .expect("submit blocking attempt")
                .disposition(),
            SubmitAttemptDisposition::Accepted { .. }
        ));
    }
    let (state, changed) = worker_state.as_ref();
    let state = changed
        .wait_timeout_while(
            state.lock().expect("busy worker state"),
            Duration::from_secs(2),
            |state| state.entered != 2,
        )
        .expect("worker entry notification")
        .0;
    assert_eq!(state.entered, 2, "both worker slots must be occupied");
    drop(state);
    let saturated = executor.report().expect("saturated pool report");
    assert_eq!(saturated.active(), 3);
    assert_eq!(saturated.queued(), 1);

    let principal = CampaignPrincipal::new("operator:lazy-frontier").expect("principal");
    let name = CampaignName::new(campaign).expect("campaign name");
    let client = CampaignClient::new(RepositoryCampaignService::new(
        repository.as_ref(),
        AllowCampaignControl,
    ));
    let pause_started = Instant::now();
    let paused = client
        .apply_campaign_command(
            &ApplyCampaignCommandRequest::new(
                principal.clone(),
                name.clone(),
                ControlRequest {
                    command: CampaignCommandId::from_hash(CampaignHash::derive(
                        "crucible.test.busy-control.pause.v1",
                        b"pause",
                    )),
                    expected_snapshot: running.new_snapshot,
                    action: CampaignControlAction::Pause(ActiveAttemptPolicy::Drain),
                },
            )
            .expect("pause request"),
        )
        .expect("pause while every executor slot is busy");
    assert!(
        pause_started.elapsed() < CONTROL_BOUND,
        "pause exceeded the bounded control path"
    );

    let status_started = Instant::now();
    let status = client
        .get_campaign_status(
            &GetCampaignStatusRequest::new(principal.clone(), name.clone(), paused.new_snapshot())
                .expect("status request"),
        )
        .expect("status while every executor slot is busy");
    assert_eq!(status.snapshot(), paused.new_snapshot());
    assert!(
        status_started.elapsed() < CONTROL_BOUND,
        "status exceeded the bounded control path"
    );

    let pin_started = Instant::now();
    let pinned = client
        .pin_campaign(
            &PinCampaignRequest::new(
                principal,
                name,
                PinRequest {
                    command: CampaignCommandId::from_hash(CampaignHash::derive(
                        "crucible.test.busy-control.pin.v1",
                        b"pin",
                    )),
                    expected_snapshot: paused.new_snapshot(),
                    change: PinChange::new(
                        lineage.genesis(),
                        Some(PinRetention::Thin),
                        "retain busy-control genesis",
                    )
                    .expect("pin change"),
                },
            )
            .expect("pin request"),
        )
        .expect("pin while every executor slot is busy");
    assert_ne!(pinned.new_snapshot(), paused.new_snapshot());
    assert!(
        pin_started.elapsed() < CONTROL_BOUND,
        "pin exceeded the bounded control path"
    );
    assert_eq!(
        executor
            .report()
            .expect("post-control pool report")
            .active(),
        3
    );

    let shutdown_started = Instant::now();
    pool.request_shutdown();
    assert!(
        shutdown_started.elapsed() < CONTROL_BOUND,
        "shutdown acknowledgement exceeded the bounded control path"
    );

    let rejected_started = Instant::now();
    assert!(matches!(
        executor.submit_attempt(&request(epoch, 0xa4)),
        Err(LocalExecutorPoolServiceError::ShuttingDown)
    ));
    assert!(
        rejected_started.elapsed() < CONTROL_BOUND,
        "post-shutdown admission rejection exceeded the bounded control path"
    );

    let (state, changed) = worker_state.as_ref();
    let mut state = changed
        .wait_timeout_while(
            state.lock().expect("busy worker state"),
            CONTROL_BOUND,
            |state| state.cancellations_observed != 2,
        )
        .expect("worker cancellation notification")
        .0;
    assert_eq!(
        state.cancellations_observed, 2,
        "shutdown must signal every executing worker"
    );
    let activity_during_exit = executor
        .shared
        .executor
        .lock()
        .expect("executor supervisor")
        .supervisor()
        .operational_activity_snapshot();
    for execution in &state.executions {
        let activity = activity_during_exit
            .iter()
            .find(|activity| activity.execution == *execution)
            .expect("executing reservation retained until worker exit");
        assert!(activity.worker_in_flight);
        assert!(activity.cancellation_requested);
    }
    state.release = true;
    changed.notify_all();
    drop(state);

    let (joined_tx, joined_rx) = mpsc::sync_channel(1);
    let joiner = thread::spawn(move || {
        joined_tx
            .send(pool.shutdown_and_join_with_timeout(CONTROL_BOUND))
            .expect("publish busy pool shutdown result");
    });
    let remaining = CONTROL_BOUND.saturating_sub(shutdown_started.elapsed());
    let report = joined_rx
        .recv_timeout(remaining)
        .expect("busy pool cleanup and joining exceeded the bounded shutdown path")
        .expect("bounded busy pool shutdown");
    joiner.join().expect("shutdown waiter");
    assert!(
        shutdown_started.elapsed() < CONTROL_BOUND,
        "worker cleanup and joining exceeded the bounded shutdown path"
    );
    assert_eq!(report.active(), 0);
    assert_eq!(report.queued(), 0);
    assert_eq!(report.executions(), 2, "queued work must not execute");
    assert_eq!(report.terminal_stops(), 3);
}

#[test]
fn repository_admission_does_not_hold_supervisor_actor_ownership() {
    let epoch = DaemonEpoch::from_bytes([0x35; 16]).expect("epoch");
    let state = Arc::new((Mutex::new((false, false)), Condvar::new()));
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        BlockingAdmission {
            state: Arc::clone(&state),
        },
        epoch,
        capacity(),
    );
    let capability =
        LocalExecutorCapabilityService::new(supervisor, description(epoch)).expect("capability");
    let pool = LocalExecutorWorkerPool::start(
        capability,
        store(),
        checkpoint_store(),
        vec![SequencedFailureWorker {
            calls: Arc::new(AtomicUsize::new(0)),
        }],
    )
    .expect("worker pool");
    let mut submitting = pool.service();
    let submit = thread::spawn(move || submitting.submit_attempt(&request(epoch, 0x46)));

    let (admission_state, changed) = state.as_ref();
    let mut admission_state = admission_state.lock().expect("admission state");
    while !admission_state.0 {
        admission_state = changed.wait(admission_state).expect("admission wake");
    }
    let started = Instant::now();
    assert_eq!(
        pool.service().report().expect("responsive report").active(),
        0
    );
    pool.request_shutdown();
    assert!(started.elapsed() < Duration::from_millis(250));
    admission_state.1 = true;
    changed.notify_all();
    drop(admission_state);

    assert!(matches!(
        submit.join().expect("submit thread"),
        Err(LocalExecutorPoolServiceError::ShuttingDown)
    ));
    let report = pool.shutdown_and_join().expect("clean shutdown");
    assert_eq!(report.active(), 0);
    assert_eq!(report.executions(), 0);
}

#[test]
fn campaign_driver_pool_flight_incorporates_one_execution_without_submit_polling() {
    let blobs = Arc::new(MemoryBlobBackend::new("executor-flight", 64 * 1024 * 1024));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let (lineage, _policy, request, admitted, candidate) =
        campaign_attempt_fixture(&repository, "executor-flight");
    let resume = ControlRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive(
            "crucible.test.executor-flight.resume.v1",
            b"resume",
        )),
        expected_snapshot: admitted.new_snapshot,
        action: CampaignControlAction::Resume,
    };
    repository
        .apply_control("executor-flight", &resume)
        .expect("resume campaign");

    let epoch = DaemonEpoch::from_bytes([0x81; 16]).expect("daemon epoch");
    let resources = AttemptResourceLimits::new(2, 512 * 1024 * 1024, 0, 50_000).expect("resources");
    let profile = ExecutorCompatibilityProfile::from_lineage(&lineage);
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        RepositoryAttemptAdmission::new(Arc::clone(&repository), profile.clone()),
        epoch,
        ExecutorCapacity::new(1, 2, 512 * 1024 * 1024, 0, 50_000).expect("capacity"),
    );
    let capabilities = ExecutorCapabilitySet::new(
        profile,
        "x86_64",
        BTreeSet::from([String::from("deterministic-tcg-v1")]),
        BTreeSet::from([ExecutorMaterializationCapability::ThinReplay]),
        1,
        resources,
        BTreeSet::from([CampaignHash::derive(
            "crucible.test.executor-flight.namespace.v1",
            b"local",
        )]),
    )
    .expect("capabilities");
    let description = ExecutorDescription::new(epoch, capabilities).expect("description");
    let capability =
        LocalExecutorCapabilityService::new(supervisor, description).expect("capability service");
    let calls = Arc::new(AtomicUsize::new(0));
    let runtime_bases = Arc::new(Mutex::new(Vec::new()));
    let reconciliations = Arc::new(Mutex::new(Vec::new()));
    let pool = LocalExecutorWorkerPool::start(
        capability,
        CampaignExecutorStore::new(Arc::clone(&repository)),
        checkpoint_store(),
        vec![RepositoryAttemptWorker::new(
            CampaignExecutorStore::new(Arc::clone(&repository)),
            CandidateModel {
                candidate: candidate.clone(),
                calls: Arc::clone(&calls),
                runtime_bases: Arc::clone(&runtime_bases),
                reconciliations: Arc::clone(&reconciliations),
            },
        )],
    )
    .expect("worker pool");
    let submits = Arc::new(AtomicUsize::new(0));
    let status_reads = Arc::new(AtomicUsize::new(0));
    let mut driver = CampaignExecutorDriver::new(
        Arc::clone(&repository),
        ExecutorClient::new(CountingExecutorService {
            inner: pool.service(),
            submits: Arc::clone(&submits),
            status_reads: Arc::clone(&status_reads),
        }),
        epoch,
        1,
        resources,
        ExecutionRetentionIntent::RetainOnFailure,
        10_000,
    )
    .expect("campaign executor driver");

    let first = driver
        .step("executor-flight", WorkerSlotId::new(0))
        .expect("submit attempt");
    let CampaignExecutorStepOutcome::Running {
        attempt,
        execution,
        newly_accepted: true,
    } = first
    else {
        panic!("first driver step did not admit the attempt")
    };
    assert_eq!(attempt, admitted.attempt);
    let deadline = Instant::now() + Duration::from_secs(2);
    let incorporated = loop {
        match driver
            .step("executor-flight", WorkerSlotId::new(0))
            .expect("poll execution")
        {
            CampaignExecutorStepOutcome::Running {
                newly_accepted: false,
                ..
            } => {
                assert!(Instant::now() < deadline, "execution did not complete");
                thread::sleep(Duration::from_millis(1));
            }
            CampaignExecutorStepOutcome::Incorporated(result) => break result,
            outcome => panic!("unexpected flight outcome: {outcome:?}"),
        }
    };
    assert_eq!(
        incorporated.observation_result().observation,
        candidate.observation().id().expect("observation id")
    );
    wait_until(Duration::from_secs(2), || {
        reconciliations
            .lock()
            .is_ok_and(|reconciliations| reconciliations.len() == 2)
    });
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert_eq!(
        runtime_bases.lock().expect("runtime bases").as_slice(),
        [AttemptExecutionRuntimeBasis::new(
            AttemptExecutionKey::new(lineage.id().expect("lineage id"), admitted.attempt),
            execution,
        )]
    );
    assert_eq!(
        reconciliations.lock().expect("reconciliations").as_slice(),
        [
            AttemptExecutionDisposition::Observation(incorporated.observation_result().observation,),
            AttemptExecutionDisposition::Observation(incorporated.observation_result().observation,),
        ]
    );
    assert_eq!(submits.load(Ordering::Acquire), 1);
    assert!(status_reads.load(Ordering::Acquire) >= 1);
    assert_eq!(driver.reservation_count(), 0);
    assert_eq!(
        repository
            .project_claimable_attempts("executor-flight", None, 10_000)
            .expect("post-flight projection")
            .attempts(),
        &[]
    );
    drop(driver);
    let report = pool.shutdown_and_join().expect("clean pool shutdown");
    assert_eq!(report.executions(), 1);
    assert_eq!(report.reconciled(), 1);
    assert_eq!(report.active(), 0);

    let restarted = CampaignRepository::new(blobs, refs);
    let head = restarted.head("executor-flight").expect("restart head");
    assert_eq!(head.snapshot_id(), incorporated.final_snapshot());
    assert_eq!(request.stop(), &StopCondition::NextChoice);
}

#[test]
fn complete_prepared_journal_recovers_without_rerunning_guest_work() {
    for prepublish_trace_leaf in [false, true] {
        recover_complete_prepared_journal(prepublish_trace_leaf, false, false);
    }
}

#[test]
fn retained_measurement_trace_publishes_the_named_beam_objective() {
    let blobs = Arc::new(TransientExecutorReadBackend::new(
        "beam-objective-publication",
        64 * 1024 * 1024,
    ));
    let repository = Arc::new(CampaignRepository::new(
        blobs.clone(),
        Arc::new(MemoryRefBackend::new()),
    ));
    let scenario = beam_objective_scenario();
    let metric = "beam-window.scheduler-events";
    let (lineage, policy, _request, _admitted, candidate) = campaign_attempt_fixture_with_policy(
        &repository,
        "beam-objective-publication",
        scenario.clone(),
        ExplorerPolicy::Beam {
            width: 1,
            novelty_reserve: 0,
        },
        BTreeMap::from([(
            metric.to_owned(),
            Objective::new(metric, ObjectiveGoal::Minimize, 1_000_000).expect("Beam objective"),
        )]),
        InterventionLearningPolicy::IncludeInGuidance,
        BranchBudget::new(1, 1).expect("single Beam candidate"),
    );
    let node = scenario
        .world()
        .vm_nodes()
        .first()
        .expect("Beam objective VM")
        .id
        .clone();
    let publication = evaluate_crucible_measurement_publication(
        lineage.scenario(),
        candidate.child().configuration(),
        scenario.measurements(),
        Vec::new(),
        MeasurementTerminalState {
            scenario_ready_at: None,
            at: VirtualTime { ticks: 4 },
            node_icounts: BTreeMap::from([(node, Icount { retired: 4 })]),
            scheduler_quiescent: true,
        },
        crate::MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    )
    .expect("production measurement publication");
    let (evidence, _evidence_bytes, measurements) = publication.into_parts();
    let evaluation = evidence
        .replay(
            lineage.scenario(),
            candidate.child().configuration(),
            scenario.measurements(),
        )
        .expect("replay retained measurement evidence");
    let retained = candidate.observation();
    let observation = Observation::new(
        retained.attempt(),
        Observation::outcome(
            retained.child(),
            retained.child_content(),
            retained.path(),
            retained.stop().clone(),
            measurements.id().expect("measurement ID"),
            retained.properties(),
            retained.coverage(),
        ),
        retained.discovered_choices().clone(),
    )
    .expect("observation with retained measurement trace");
    let expected = crate::evaluate_crucible_objectives(
        &measurements,
        &evaluation,
        &policy,
        &observation,
        candidate.properties(),
    )
    .expect("expected named objective");
    let evidence_id = evidence.id().expect("measurement evidence ID");
    assert_eq!(
        expected.components()[metric].value(),
        Some(&crucible_campaign::ObjectiveValue::Unsigned(0))
    );
    let observation = ObservationCandidate::new(
        candidate.child().clone(),
        measurements,
        candidate.properties().clone(),
        candidate.coverage().clone(),
        candidate.discovered_choices().to_vec(),
        observation,
    )
    .expect("candidate with retained measurement trace");
    let result = PreparedSemanticAttemptResult::new(observation.clone(), vec![evidence], None)
        .expect("prepared semantic observation");
    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    publish_prepared_semantic_attempt_result(
        &store,
        crate::automatic_finding_runner::test_finding_exact_retention_source().as_ref(),
        &result,
    )
    .expect("publish producer-owned measurement closure");
    let head = repository
        .head("beam-objective-publication")
        .expect("pre-observation head");
    repository
        .publish_observation(
            "beam-objective-publication",
            head.snapshot_id(),
            observation.observation(),
        )
        .expect("incorporate produced observation");

    let mut cursor = None;
    blobs.fail_next_read_of(evidence_id);
    assert!(matches!(
        publish_next_objective_evaluation(&repository, "beam-objective-publication", &mut cursor,),
        Err(crate::ObjectiveEvaluationDriverError::Repository(
            crucible_campaign::CampaignRepositoryError::Store(StoreError::Unavailable)
        ))
    ));
    assert_eq!(
        blobs.injected_failures.load(Ordering::Acquire),
        1,
        "the exact retained trace leaf must fail inside objective evaluation"
    );
    assert!(cursor.is_none());
    assert!(
        publish_next_objective_evaluation(&repository, "beam-objective-publication", &mut cursor,)
            .expect("publish objective from retained trace")
    );
    let stored = repository
        .load_objective_evaluation(expected.id().expect("expected objective ID"))
        .expect("load driver-published objective");
    assert_eq!(stored, expected);

    let discovery = observation
        .discovered_choices()
        .first()
        .expect("produced deeper choice");
    let parent = observation.child();
    let deeper_request = BranchRequest::new(
        BranchRequest::identity(
            discovery
                .opportunity()
                .branch_point_id(parent.configuration()),
            parent.id().expect("produced child artifact ID"),
            discovery.opportunity().id().expect("deeper opportunity ID"),
            discovery.domain().id().expect("deeper domain ID"),
        ),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(false)]))
            .expect("deeper finite source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(CampaignHash::derive(
            "crucible.test.beam-objective-publication.deeper.v1",
            b"deeper",
        ))),
        BranchBudget::new(1, 1).expect("deeper request budget"),
        StopCondition::NextChoice,
    )
    .expect("deeper request from retained observation");
    let head = repository
        .head("beam-objective-publication")
        .expect("evaluated Beam head");
    let requested = repository
        .submit_operator_branch_request(
            "beam-objective-publication",
            head.snapshot_id(),
            &deeper_request,
        )
        .expect("submit retained observation's deeper frontier");
    let basis = repository
        .publish_canonical_beam_planner_basis()
        .expect("publish canonical Beam basis");
    let invocation = repository
        .prepare_planner_invocation(
            "beam-objective-publication",
            requested.new_snapshot,
            basis.engine(),
            basis.artifact(),
            basis.initial_state(),
            None,
            100,
            PlanningBudget::new(2, 2, 100, 4 * 1024 * 1024, 10_000).expect("Beam planning budget"),
        )
        .expect("prepare objective-backed Beam invocation");
    let planner_request = repository
        .build_planner_request(
            requested.new_snapshot,
            invocation.id().expect("Beam invocation ID"),
        )
        .expect("build objective-backed Beam request");
    let output = CanonicalBeamPlanner
        .plan(&planner_request)
        .expect("rank retained objective with canonical Beam planner");
    let PlannerProposalDisposition::Issue {
        selected,
        proposals,
        ..
    } = output.proposal().disposition()
    else {
        panic!("retained objective must select its deeper frontier")
    };
    assert_eq!(
        *selected,
        PlanningScanPosition::new(
            deeper_request.branch_point(),
            deeper_request.id().expect("deeper request ID"),
        )
    );
    assert_eq!(proposals.len(), 1);
    assert_eq!(
        proposals[0].request(),
        deeper_request.id().expect("deeper request ID")
    );
}

#[test]
fn transient_recovery_input_unavailability_retries_without_guest_work() {
    recover_complete_prepared_journal(false, true, false);
}

#[test]
fn hidden_journal_recovery_commits_only_the_ledger_authorized_publication() {
    recover_complete_prepared_journal(false, false, true);
}

fn recover_complete_prepared_journal(
    prepublish_trace_leaf: bool,
    transient_recovery_input: bool,
    seed_hidden_journal: bool,
) {
    let blobs = Arc::new(TransientExecutorReadBackend::new(
        "prepared-recovery",
        64 * 1024 * 1024,
    ));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs));
    let (lineage, _, _, admitted, candidate) =
        campaign_attempt_fixture(&repository, "prepared-recovery");
    let scenario = minimal_campaign_scenario();
    let publication = evaluate_crucible_measurement_publication(
        candidate.child().scenario(),
        candidate.child().configuration(),
        scenario.measurements(),
        Vec::new(),
        MeasurementTerminalState {
            scenario_ready_at: None,
            at: VirtualTime { ticks: 0 },
            node_icounts: BTreeMap::new(),
            scheduler_quiescent: true,
        },
        crate::MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    )
    .expect("measurement publication");
    let (evidence, _, measurements) = publication.into_parts();
    let observation = candidate.observation();
    let observation = Observation::new(
        observation.attempt(),
        Observation::outcome(
            observation.child(),
            observation.child_content(),
            observation.path(),
            observation.stop().clone(),
            measurements.id().expect("measurement ID"),
            observation.properties(),
            observation.coverage(),
        ),
        observation.discovered_choices().clone(),
    )
    .expect("observation with raw measurement evidence");
    let candidate = ObservationCandidate::new(
        candidate.child().clone(),
        measurements,
        candidate.properties().clone(),
        candidate.coverage().clone(),
        candidate.discovered_choices().to_vec(),
        observation,
    )
    .expect("candidate with raw measurement evidence");
    let prepared = PreparedSemanticAttemptResult::new(candidate, vec![evidence.clone()], None)
        .expect("prepared semantic result");
    let expected_observation = prepared
        .observation()
        .observation()
        .id()
        .expect("observation ID");

    let epoch = DaemonEpoch::from_bytes([0x82; 16]).expect("daemon epoch");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x83; 16]).expect("assignment"),
        epoch,
        lineage.id().expect("lineage ID"),
        admitted.attempt,
        AttemptResourceLimits::new(1, 1024, 2048, 32).expect("resources"),
        ExecutionRetentionIntent::Discard,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .expect("submit request");
    let key = AttemptExecutionKey::for_request(&request);
    let producer_execution = ExecutionId::from_bytes([0x84; 16]).expect("producer execution");
    let ledger_root = TempDir::new().expect("assignment ledger");
    let mut ledger = DirectoryAssignmentLedger::open(ledger_root.path()).expect("open ledger");
    assert_eq!(
        ledger
            .compare_exchange_attempt(
                key,
                None,
                Some(AttemptRuntimeState::Publishing {
                    execution_basis: request.execution_basis_digest(),
                    origin: AttemptExecutionOrigin::Initial,
                    daemon_epoch: DaemonEpoch::from_bytes([0x80; 16]).expect("producer epoch"),
                    execution: producer_execution,
                    observation: expected_observation,
                    finding_candidate: None,
                }),
            )
            .expect("stage producer publication"),
        AttemptStateCas::Advanced
    );
    drop(ledger);
    let journals = TempDir::new().expect("prepared-result journals");
    let journal_namespace = crate::PreparedResultJournalNamespace::open(journals.path())
        .expect("open prepared-result journal namespace");
    let (journal, _) = if seed_hidden_journal {
        crate::DirectoryPreparedResultJournal::prepare_staged(
            &journal_namespace,
            key,
            producer_execution,
            crate::MAX_PREPARED_SEMANTIC_RESULT_BYTES,
            prepared,
        )
        .expect("seed hidden prepared result")
    } else {
        crate::DirectoryPreparedResultJournal::create(
            &journal_namespace,
            key,
            producer_execution,
            crate::MAX_PREPARED_SEMANTIC_RESULT_BYTES,
            prepared,
        )
        .expect("seed complete prepared result")
    };
    let journal_root = journal.root().to_path_buf();
    drop(journal);

    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    let evidence_id = evidence.id().expect("evidence ID");
    if prepublish_trace_leaf {
        store
            .publish_executor_trace_leaf(
                evidence_id,
                crate::CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V2,
                &evidence.canonical_bytes().expect("evidence bytes"),
            )
            .expect("prepublish trace leaf");
    }
    let observer: Arc<dyn PausedCheckpointObserver> =
        Arc::new(RecordingPausedCheckpointObserver::default());
    let profile = ExecutorCompatibilityProfile::from_lineage(&lineage);
    let supervisor = LocalExecutorSupervisor::new(
        DirectoryAssignmentLedger::open(ledger_root.path()).expect("reopen ledger"),
        RepositoryAttemptAdmission::new(Arc::clone(&repository), profile.clone()),
        epoch,
        capacity(),
    );
    let capabilities = ExecutorCapabilitySet::new(
        profile,
        "x86_64",
        BTreeSet::from([String::from("deterministic-tcg-v1")]),
        BTreeSet::from([ExecutorMaterializationCapability::ThinReplay]),
        1,
        AttemptResourceLimits::new(2, 4096, 8192, 64).expect("resource ceiling"),
        BTreeSet::from([CampaignHash::derive(
            "crucible.test.prepared-recovery-namespace.v1",
            b"local",
        )]),
    )
    .expect("capabilities");
    let description = ExecutorDescription::new(epoch, capabilities).expect("description");
    let capability =
        LocalExecutorCapabilityService::new(supervisor, description).expect("capability service");
    let pool = LocalExecutorWorkerPool::start_with_checkpoint_observer(
        capability,
        store,
        checkpoint_store(),
        vec![PanickingWorker],
        observer,
        Some(PreparedResultJournalConfig::new(
            journal_namespace,
            crate::MAX_PREPARED_SEMANTIC_RESULT_BYTES,
        )),
    )
    .expect("prepared-result recovery pool");
    let mut service = pool.service();
    if transient_recovery_input {
        blobs.fail_next_executor_read();
    }
    let accepted = service.submit_attempt(&request).expect("submit recovery");
    let SubmitAttemptDisposition::Accepted { execution } = accepted.disposition() else {
        panic!("recovery should receive a fresh supervisor execution")
    };
    assert_ne!(execution, producer_execution);
    let status_request = GetAttemptExecutionRequest::new(&request, execution).expect("status");
    wait_until(Duration::from_secs(2), || {
        let completed = service
            .get_attempt_execution(&status_request)
            .is_ok_and(|status| {
                matches!(
                    status.disposition(),
                    GetAttemptExecutionDisposition::Completed { observation }
                        if observation == expected_observation
                )
            });
        completed
            && service
                .report()
                .is_ok_and(|report| report.reconciled() == 1)
    });
    assert!(blobs.contains(evidence_id).expect("trace leaf presence"));
    assert!(!journal_root.exists());

    let report = service.report().expect("recovery report");
    assert_eq!(report.executions(), 0);
    assert_eq!(report.reconciled(), 1);
    assert_eq!(
        blobs.injected_failures.load(Ordering::Acquire),
        usize::from(transient_recovery_input)
    );
    if transient_recovery_input {
        assert!(report.publication_retries() >= 1);
    }
    pool.request_shutdown();
    assert_eq!(pool.shutdown_and_join().expect("clean shutdown"), report);
}

#[test]
fn stable_completed_journal_requires_matching_authenticated_roots_before_cleanup() {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "completed-prepared-cleanup",
            64 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let (lineage, _, _, admitted, candidate) =
        campaign_attempt_fixture(&repository, "completed-prepared-cleanup");
    let exact_observation = candidate.observation().id().expect("exact observation ID");
    let prepared = PreparedSemanticAttemptResult::new(candidate.clone(), Vec::new(), None)
        .expect("prepared result");
    let key = AttemptExecutionKey::new(lineage.id().expect("lineage ID"), admitted.attempt);
    let execution = ExecutionId::from_bytes([0xa1; 16]).expect("execution");
    let journals = TempDir::new().expect("prepared journals");
    let journal_namespace = crate::PreparedResultJournalNamespace::open(journals.path())
        .expect("open prepared-result journal namespace");
    let (journal, _) = crate::DirectoryPreparedResultJournal::create(
        &journal_namespace,
        key,
        execution,
        crate::MAX_PREPARED_SEMANTIC_RESULT_BYTES,
        prepared,
    )
    .expect("seed prepared journal");
    let journal_root = journal.root().to_path_buf();
    drop(journal);

    let wrong_content = ContentId::for_bytes(
        ObjectKind::Observation,
        crucible_campaign::CampaignRecordKind::Observation.schema_version(),
        b"wrong completion",
    );
    let wrong_observation =
        ObservationId::parse(&format!("crucible.campaign.observation@{wrong_content}"))
            .expect("wrong observation ID");
    let completed = |observation| AttemptRuntimeState::Completed {
        execution_basis: CampaignHash::derive("test", b"completed-cleanup-basis"),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: DaemonEpoch::from_bytes([0xa2; 16]).expect("daemon epoch"),
        execution,
        observation,
        finding_candidate: CompletedFindingCandidate::pending(None),
    };
    let mut ledger = MemoryAssignmentLedger::default();
    let mismatched = completed(wrong_observation);
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, None, Some(mismatched))
            .expect("seed completed ledger state"),
        AttemptStateCas::Advanced
    );
    let profile = ExecutorCompatibilityProfile::from_lineage(&lineage);
    let validator = RepositoryAttemptAdmission::new(Arc::clone(&repository), profile);
    let config = PreparedResultJournalConfig::new(
        journal_namespace,
        crate::MAX_PREPARED_SEMANTIC_RESULT_BYTES,
    );
    let gc_exclusion = repository
        .acquire_gc_exclusion_guard()
        .expect("exclude repository GC");

    assert!(matches!(
        reconcile_stable_prepared_result_journals(&ledger, &validator, &config, &gc_exclusion,),
        Err(LocalExecutorPoolConfigError::PreparedResultCompletionMismatch)
    ));
    assert!(journal_root.exists());

    let exact = completed(exact_observation);
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, Some(mismatched), Some(exact))
            .expect("repair completed ledger ID"),
        AttemptStateCas::Advanced
    );
    assert!(matches!(
        reconcile_stable_prepared_result_journals(&ledger, &validator, &config, &gc_exclusion,),
        Err(
            LocalExecutorPoolConfigError::PreparedResultCompletionValidation {
                reason: CompletionValidationFailure::UnavailableInput,
            }
        )
    ));
    assert!(journal_root.exists());

    CampaignExecutorStore::new(Arc::clone(&repository))
        .publish_observation_candidate(&candidate)
        .expect("publish exact completed closure");
    reconcile_stable_prepared_result_journals(&ledger, &validator, &config, &gc_exclusion)
        .expect("clean authenticated completed journal");
    assert!(!journal_root.exists());
}

#[test]
fn incomplete_prepared_journal_fails_closed_without_guest_execution() {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "incomplete-prepared-recovery",
            64 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let (lineage, _, _, admitted, candidate) =
        campaign_attempt_fixture(&repository, "incomplete-prepared-recovery");
    let prepared =
        PreparedSemanticAttemptResult::new(candidate, Vec::new(), None).expect("prepared result");
    let epoch = DaemonEpoch::from_bytes([0x85; 16]).expect("daemon epoch");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x86; 16]).expect("assignment"),
        epoch,
        lineage.id().expect("lineage ID"),
        admitted.attempt,
        AttemptResourceLimits::new(1, 1024, 2048, 32).expect("resources"),
        ExecutionRetentionIntent::Discard,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .expect("submit request");
    let journals = TempDir::new().expect("prepared-result journals");
    let journal_namespace = crate::PreparedResultJournalNamespace::open(journals.path())
        .expect("open prepared-result journal namespace");
    let (journal, _) = crate::DirectoryPreparedResultJournal::create(
        &journal_namespace,
        AttemptExecutionKey::for_request(&request),
        ExecutionId::from_bytes([0x87; 16]).expect("producer execution"),
        crate::MAX_PREPARED_SEMANTIC_RESULT_BYTES,
        prepared,
    )
    .expect("seed complete prepared result");
    let journal_root = journal.root().to_path_buf();
    drop(journal);
    let staged_root = journals.path().join(format!(
        ".staged-{}",
        journal_root
            .file_name()
            .and_then(|name| name.to_str())
            .expect("journal directory name")
    ));
    std::fs::rename(&journal_root, &staged_root).expect("interrupt journal publication");
    std::fs::remove_file(staged_root.join("state-v2")).expect("leave partial staged journal");

    let observer: Arc<dyn PausedCheckpointObserver> =
        Arc::new(RecordingPausedCheckpointObserver::default());
    let pool = LocalExecutorWorkerPool::start_with_checkpoint_observer(
        capability(epoch),
        CampaignExecutorStore::new(repository),
        checkpoint_store(),
        vec![PanickingWorker],
        observer,
        Some(PreparedResultJournalConfig::new(
            journal_namespace,
            crate::MAX_PREPARED_SEMANTIC_RESULT_BYTES,
        )),
    )
    .expect("prepared-result recovery pool");
    let mut service = pool.service();
    let accepted = service.submit_attempt(&request).expect("submit recovery");
    let SubmitAttemptDisposition::Accepted { execution } = accepted.disposition() else {
        panic!("recovery should receive a fresh supervisor execution")
    };
    let status_request = GetAttemptExecutionRequest::new(&request, execution).expect("status");
    wait_until(Duration::from_secs(2), || {
        service
            .get_attempt_execution(&status_request)
            .is_ok_and(|status| {
                status.disposition() == GetAttemptExecutionDisposition::TerminalFailure
            })
    });
    assert!(staged_root.exists());

    let report = service.report().expect("recovery report");
    assert_eq!(report.executions(), 0);
    assert_eq!(report.terminal_stops(), 1);
    assert_eq!(report.worker_panics(), 0);
    pool.request_shutdown();
    assert_eq!(pool.shutdown_and_join().expect("clean shutdown"), report);
}

#[test]
fn stable_journal_creation_failure_is_terminal_not_canceled() {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "stable-prepared-journal-failure",
            64 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let (lineage, _, _, admitted, candidate) =
        campaign_attempt_fixture(&repository, "stable-prepared-journal-failure");
    let epoch = DaemonEpoch::from_bytes([0xa3; 16]).expect("daemon epoch");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0xa4; 16]).expect("assignment"),
        epoch,
        lineage.id().expect("lineage ID"),
        admitted.attempt,
        AttemptResourceLimits::new(1, 1024, 2048, 32).expect("resources"),
        ExecutionRetentionIntent::Discard,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .expect("submit request");
    let profile = ExecutorCompatibilityProfile::from_lineage(&lineage);
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        RepositoryAttemptAdmission::new(Arc::clone(&repository), profile.clone()),
        epoch,
        capacity(),
    );
    let capabilities = ExecutorCapabilitySet::new(
        profile,
        "x86_64",
        BTreeSet::from([String::from("deterministic-tcg-v1")]),
        BTreeSet::from([ExecutorMaterializationCapability::ThinReplay]),
        1,
        AttemptResourceLimits::new(2, 4096, 8192, 64).expect("resource ceiling"),
        BTreeSet::from([CampaignHash::derive(
            "crucible.test.stable-journal-failure-namespace.v1",
            b"local",
        )]),
    )
    .expect("capabilities");
    let description = ExecutorDescription::new(epoch, capabilities).expect("description");
    let capability =
        LocalExecutorCapabilityService::new(supervisor, description).expect("capability service");
    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    let calls = Arc::new(AtomicUsize::new(0));
    let reconciliations = Arc::new(Mutex::new(Vec::new()));
    let observer: Arc<dyn PausedCheckpointObserver> =
        Arc::new(RecordingPausedCheckpointObserver::default());
    let journals = TempDir::new().expect("prepared journals");
    let journal_namespace = crate::PreparedResultJournalNamespace::open(journals.path())
        .expect("open prepared-result journal namespace");
    let pool = LocalExecutorWorkerPool::start_with_checkpoint_observer(
        capability,
        store.clone(),
        checkpoint_store(),
        vec![RepositoryAttemptWorker::new(
            store,
            CandidateModel {
                candidate,
                calls: Arc::clone(&calls),
                runtime_bases: Arc::new(Mutex::new(Vec::new())),
                reconciliations: Arc::clone(&reconciliations),
            },
        )],
        observer,
        Some(PreparedResultJournalConfig::new(journal_namespace, 1)),
    )
    .expect("prepared-result pool");
    let mut service = pool.service();
    let accepted = service.submit_attempt(&request).expect("submit attempt");
    let SubmitAttemptDisposition::Accepted { execution } = accepted.disposition() else {
        panic!("attempt should be accepted")
    };
    let status_request = GetAttemptExecutionRequest::new(&request, execution).expect("status");
    wait_until(Duration::from_secs(2), || {
        service
            .get_attempt_execution(&status_request)
            .is_ok_and(|status| {
                status.disposition() == GetAttemptExecutionDisposition::TerminalFailure
            })
    });
    wait_until(Duration::from_secs(2), || {
        reconciliations
            .lock()
            .is_ok_and(|reconciliations| reconciliations.len() == 2)
    });

    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert_eq!(
        reconciliations.lock().expect("reconciliations").as_slice(),
        [
            AttemptExecutionDisposition::Failed,
            AttemptExecutionDisposition::Failed,
        ]
    );
    let report = service.report().expect("pool report");
    assert_eq!(report.executions(), 1);
    assert_eq!(report.terminal_stops(), 1);
    pool.request_shutdown();
    assert_eq!(pool.shutdown_and_join().expect("clean shutdown"), report);
}

#[test]
fn repository_worker_rejects_branch_capture_before_model_execution() {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "branch-materialized-start-capture",
            64 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let (lineage, _policy, branch, admitted, candidate) =
        campaign_attempt_fixture(&repository, "branch-materialized-start-capture");
    let epoch = DaemonEpoch::from_bytes([0x93; 16]).expect("daemon epoch");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x94; 16]).expect("assignment"),
        epoch,
        lineage.id().expect("lineage id"),
        admitted.attempt,
        AttemptResourceLimits::new(1, 64 * 1024 * 1024, 0, 1_000).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .and_then(|assignment| {
        SubmitAttemptRequest::new_capture_materialized_start(assignment, branch.parent())
    })
    .expect("capture submit request");
    let mut supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(1, 1, 64 * 1024 * 1024, 0, 1_000).expect("capacity"),
    );
    supervisor
        .submit_attempt(&request)
        .expect("accept capture execution");
    let queued = supervisor.next_queued().expect("queued capture execution");
    assert!(queued.checkpoint_request().is_requested());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut worker = RepositoryAttemptWorker::new(
        CampaignExecutorStore::new(repository),
        CandidateModel {
            candidate,
            calls: Arc::clone(&calls),
            runtime_bases: Arc::new(Mutex::new(Vec::new())),
            reconciliations: Arc::new(Mutex::new(Vec::new())),
        },
    );

    let (_queued, result) = worker.execute(queued).into_parts();

    assert!(matches!(
        result,
        Err(AttemptWorkerFailure::Terminal(
            RepositoryAttemptWorkerError::IncompatibleResult {
                reason: "materialized-start capture requires a discovery attempt",
            }
        ))
    ));
    assert_eq!(calls.load(Ordering::Acquire), 0);
}

#[test]
fn raw_pause_restart_resolves_exact_materialized_start_capture() {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "capture-promotion-recovery",
            64 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let (lineage, attempt, configuration) =
        crucible_discovery_attempt_fixture(&repository, "capture-promotion-recovery");
    let epoch = DaemonEpoch::from_bytes([0x95; 16]).expect("daemon epoch");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x96; 16]).expect("assignment"),
        epoch,
        lineage.id().expect("lineage id"),
        attempt,
        AttemptResourceLimits::new(1, 64 * 1024 * 1024, 0, 1_000).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .and_then(|assignment| {
        SubmitAttemptRequest::new_capture_materialized_start(assignment, configuration)
    })
    .expect("capture submit request");
    let recovery = raw_pause_recovery_for_request(&request, 0x97);

    let resolved = resolve_production_paused_checkpoint_promotion_recovery(
        &CampaignExecutorStore::new(repository),
        &recovery,
        ExecutionCancellation::default(),
    )
    .expect("resolve exact materialized-start capture");

    assert!(resolved.matches_recovery(&recovery));
}

#[test]
fn raw_pause_restart_rejects_capture_for_another_configuration() {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "capture-promotion-wrong-configuration",
            64 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let (lineage, attempt, _configuration) =
        crucible_discovery_attempt_fixture(&repository, "capture-promotion-wrong-configuration");
    let wrong_configuration = ConfigurationArtifact::new(
        lineage.scenario(),
        lineage.scenario_content(),
        ConfigurationId::from_hash(CampaignHash::derive(
            "crucible.test.capture-promotion-wrong-configuration.v1",
            b"wrong",
        )),
        1,
        b"wrong".to_vec(),
    )
    .and_then(|artifact| artifact.id())
    .expect("wrong configuration artifact id");
    let epoch = DaemonEpoch::from_bytes([0x98; 16]).expect("daemon epoch");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x99; 16]).expect("assignment"),
        epoch,
        lineage.id().expect("lineage id"),
        attempt,
        AttemptResourceLimits::new(1, 64 * 1024 * 1024, 0, 1_000).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .and_then(|assignment| {
        SubmitAttemptRequest::new_capture_materialized_start(assignment, wrong_configuration)
    })
    .expect("capture submit request");
    let recovery = raw_pause_recovery_for_request(&request, 0x9a);

    assert!(matches!(
        resolve_production_paused_checkpoint_promotion_recovery(
            &CampaignExecutorStore::new(repository),
            &recovery,
            ExecutionCancellation::default(),
        ),
        Err(PausedCheckpointPromotionRecoveryResolutionError::CaptureStartMismatch)
    ));
}

#[test]
fn raw_pause_restart_rejects_capture_for_a_branch_attempt() {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "capture-promotion-branch",
            64 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let (lineage, _policy, branch, admitted, _candidate) =
        campaign_attempt_fixture(&repository, "capture-promotion-branch");
    let epoch = DaemonEpoch::from_bytes([0x9b; 16]).expect("daemon epoch");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x9c; 16]).expect("assignment"),
        epoch,
        lineage.id().expect("lineage id"),
        admitted.attempt,
        AttemptResourceLimits::new(1, 64 * 1024 * 1024, 0, 1_000).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .and_then(|assignment| {
        SubmitAttemptRequest::new_capture_materialized_start(assignment, branch.parent())
    })
    .expect("capture submit request");
    let recovery = raw_pause_recovery_for_request(&request, 0x9d);

    assert!(matches!(
        resolve_production_paused_checkpoint_promotion_recovery(
            &CampaignExecutorStore::new(repository),
            &recovery,
            ExecutionCancellation::default(),
        ),
        Err(PausedCheckpointPromotionRecoveryResolutionError::CaptureStartMismatch)
    ));
}

#[test]
fn raw_pause_restart_rejects_an_inconsistent_execution_basis_before_repository_reads() {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "raw-pause-recovery",
            64 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let (lineage, _policy, _branch, admitted, _candidate) =
        campaign_attempt_fixture(&repository, "raw-pause-recovery");
    let epoch = DaemonEpoch::from_bytes([0xa1; 16]).expect("daemon epoch");
    let resources = AttemptResourceLimits::new(1, 64 * 1024 * 1024, 0, 1_000).expect("resources");
    let retention = ExecutionRetentionIntent::RetainOnFailure;
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0xa2; 16]).expect("assignment"),
        epoch,
        lineage.id().expect("lineage id"),
        admitted.attempt,
        resources,
        retention,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .expect("submit request");
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let execution = ExecutionId::from_bytes([0xa3; 16]).expect("execution");
    let checkpoint = ExactCheckpointId::parse(&format!(
        "crucible.executor.exact-checkpoint-root@exact-manifest.5.{}",
        "a4".repeat(32)
    ))
    .expect("checkpoint");
    let state = AttemptRuntimeState::Paused {
        execution_basis: CampaignHash::derive(
            "crucible.test.inconsistent-promotion-basis.v1",
            b"different",
        ),
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch: epoch,
        execution,
        checkpoint,
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new(
            resources,
            retention,
            request.retention_policy(),
        )),
    };
    let mut ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, None, Some(state))
            .expect("seed raw pause"),
        AttemptStateCas::Advanced
    );
    let supervisor = LocalExecutorSupervisor::new(
        ledger,
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(1, 1, 64 * 1024 * 1024, 0, 1_000).expect("capacity"),
    );
    let mut work = Vec::new();
    supervisor
        .visit_checkpoint_promotion_restart_work(&mut |item| work.push(item))
        .expect("discover raw pause");
    let [CheckpointPromotionRestartWork::Paused(recovery)] = work.as_slice() else {
        panic!("expected one raw-pause recovery")
    };

    let store = CampaignExecutorStore::new(repository);
    assert!(matches!(
        resolve_production_paused_checkpoint_promotion_recovery(
            &store,
            recovery,
            ExecutionCancellation::default(),
        ),
        Err(PausedCheckpointPromotionRecoveryResolutionError::ExecutionBasisMismatch)
    ));
}

#[test]
fn production_restart_dispatch_replays_raw_roots_and_rejects_invalid_sources() {
    let temporary = tempfile::tempdir().expect("production promotion fixture root");
    let run_state_root = temporary.path().join("native-checkpoint");
    let raw_fixture = build_authenticated_production_checkpoint_codec_fixture(&run_state_root)
        .expect("build raw production fixture");
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "production-restart-dispatch",
            128 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let (lineage, attempt) = production_discovery_attempt_fixture(
        &repository,
        "production-restart-dispatch",
        &raw_fixture,
    );
    let epoch = DaemonEpoch::from_bytes([0xc1; 16]).expect("daemon epoch");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0xc2; 16]).expect("assignment"),
        epoch,
        lineage.id().expect("lineage id"),
        attempt,
        AttemptResourceLimits::new(1, 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024, 10_000)
            .expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .expect("submit request");
    let checkpoints = checkpoint_store();
    let prepared = checkpoints
        .prepare_production_closure(raw_fixture.closure().clone())
        .expect("prepare raw production checkpoint");
    let raw = checkpoints
        .publish_production_closure(&prepared)
        .expect("publish raw production checkpoint")
        .root();
    prepared
        .retire_native_source()
        .expect("retire redundant native checkpoint source");
    let store = CampaignExecutorStore::new(repository);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut factory = CountingProductionReplayFactory {
        calls: Arc::clone(&calls),
    };
    let raw_recovery = paused_recovery_for_checkpoint(
        &request,
        ExecutionId::from_bytes([0xc3; 16]).expect("raw execution"),
        raw,
    );
    let mut raw_work = CheckpointPromotionRestartWork::Paused(raw_recovery);
    let error = prepare_production_paused_checkpoint_promotion_restart(
        &store,
        &checkpoints,
        &mut raw_work,
        &run_state_root,
        ExecutionCancellation::default(),
        &mut factory,
    )
    .expect_err("counted production replay target must reject launch");
    assert!(
        matches!(
            &error,
            crate::PausedCheckpointPromotionRestartPreparationError::Preparation(error)
                if matches!(
                    error.as_ref(),
                    crate::PausedCheckpointPromotionPreparationError::Realization(
                        crucible_qemu::QemuVmRealizationError::Executor {
                            operation: "enter counted production replay target",
                            ..
                        }
                    )
                )
        ),
        "unexpected production restart error: {error:?}"
    );
    assert_eq!(calls.load(Ordering::Acquire), 1);

    let missing = ExactCheckpointId::parse(&format!(
        "crucible.executor.exact-checkpoint-root@exact-manifest.5.{}",
        "c5".repeat(32)
    ))
    .expect("missing checkpoint");
    let missing_recovery = paused_recovery_for_checkpoint(
        &request,
        ExecutionId::from_bytes([0xc6; 16]).expect("missing execution"),
        missing,
    );
    let mut missing_work = CheckpointPromotionRestartWork::Paused(missing_recovery);
    assert!(
        prepare_production_paused_checkpoint_promotion_restart(
            &store,
            &checkpoints,
            &mut missing_work,
            &run_state_root,
            ExecutionCancellation::default(),
            &mut factory,
        )
        .is_err()
    );
    assert_eq!(calls.load(Ordering::Acquire), 1);

    let foreign_repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "foreign-production-restart",
            64 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let (foreign_lineage, foreign_attempt, _) =
        crucible_discovery_attempt_fixture(&foreign_repository, "foreign-production-restart");
    let foreign_request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0xc7; 16]).expect("foreign assignment"),
        epoch,
        foreign_lineage.id().expect("foreign lineage"),
        foreign_attempt,
        request.resources(),
        request.retention(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .expect("foreign request");
    let foreign_recovery = paused_recovery_for_checkpoint(
        &foreign_request,
        ExecutionId::from_bytes([0xc8; 16]).expect("foreign execution"),
        raw,
    );
    let mut foreign_work = CheckpointPromotionRestartWork::Paused(foreign_recovery);
    assert!(
        prepare_production_paused_checkpoint_promotion_restart(
            &CampaignExecutorStore::new(foreign_repository),
            &checkpoints,
            &mut foreign_work,
            &run_state_root,
            ExecutionCancellation::default(),
            &mut factory,
        )
        .is_err()
    );
    assert_eq!(calls.load(Ordering::Acquire), 1);
}

fn crucible_discovery_attempt_fixture(
    repository: &CampaignRepository,
    name: &str,
) -> (CampaignLineage, AttemptId, ConfigurationArtifactId) {
    let world = World::from_nodes_and_links(Vec::new(), Vec::new()).expect("empty world");
    let scenario = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(7),
    )
    .expect("minimal scenario");
    let scenario_artifact =
        encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
    let scenario_content = repository
        .publish_scenario_artifact(
            scenario_artifact.scenario(),
            scenario_artifact.payload_schema(),
            scenario_artifact.payload().to_vec(),
        )
        .expect("publish scenario artifact");
    let configuration = Configuration::genesis(scenario.scenario_def());
    let configuration_artifact =
        encode_crucible_configuration_artifact(&scenario_artifact, &configuration.schedule)
            .expect("configuration artifact");
    let configuration_content = repository
        .publish_configuration_artifact(
            configuration_artifact.scenario(),
            scenario_content,
            configuration_artifact.configuration(),
            configuration_artifact.payload_schema(),
            configuration_artifact.payload().to_vec(),
        )
        .expect("publish configuration artifact");
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
    .expect("lineage");
    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1).expect("rational"),
        ExactRational::new(1, 2).expect("rational"),
        1,
        100,
        1,
    )
    .expect("widening");
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario_artifact.scenario(),
            CampaignSeed::from_bytes([7; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                widening: Some(widening),
                puct: PuctPolicy::new(1_000_000, 1, 0),
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )
    .expect("policy");
    let created = repository
        .create(name, &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    let granted = repository
        .apply_control(
            name,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.capture-promotion-budget.v1",
                    name.as_bytes(),
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::GrantBudget(
                    crucible_campaign::BudgetGrant::new(0, 1).expect("attempt grant"),
                ),
            },
        )
        .expect("grant campaign budget");
    repository
        .apply_control(
            name,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.capture-promotion-resume.v1",
                    name.as_bytes(),
                )),
                expected_snapshot: granted.new_snapshot,
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume campaign");
    let attempt = repository
        .admit_initial_discovery_if_ready(name)
        .expect("initial discovery admission")
        .expect("initial discovery attempt");

    (lineage, attempt, configuration_content)
}

fn production_discovery_attempt_fixture(
    repository: &CampaignRepository,
    name: &str,
    production: &AuthenticatedProductionCheckpointCodecFixture,
) -> (CampaignLineage, AttemptId) {
    let scenario_artifact =
        encode_crucible_scenario_artifact(production.source()).expect("scenario artifact");
    let scenario_content = repository
        .publish_scenario_artifact(
            scenario_artifact.scenario(),
            scenario_artifact.payload_schema(),
            scenario_artifact.payload().to_vec(),
        )
        .expect("publish scenario artifact");
    let configuration_artifact = encode_crucible_configuration_artifact(
        &scenario_artifact,
        &production.configuration().schedule,
    )
    .expect("configuration artifact");
    let configuration_content = repository
        .publish_configuration_artifact(
            configuration_artifact.scenario(),
            scenario_content,
            configuration_artifact.configuration(),
            configuration_artifact.payload_schema(),
            configuration_artifact.payload().to_vec(),
        )
        .expect("publish configuration artifact");
    let lineage = CampaignLineage::new(
        scenario_artifact.scenario(),
        scenario_content,
        configuration_artifact.configuration(),
        configuration_content,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        scenario_artifact.payload_schema(),
        4,
    )
    .expect("lineage");
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario_artifact.scenario(),
            CampaignSeed::from_bytes([7; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 1,
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )
    .expect("policy");
    let created = repository
        .create(name, &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    let granted = repository
        .apply_control(
            name,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.production-promotion-budget.v1",
                    name.as_bytes(),
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::GrantBudget(
                    crucible_campaign::BudgetGrant::new(0, 1).expect("attempt grant"),
                ),
            },
        )
        .expect("grant campaign budget");
    repository
        .apply_control(
            name,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.production-promotion-resume.v1",
                    name.as_bytes(),
                )),
                expected_snapshot: granted.new_snapshot,
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume campaign");
    let attempt = repository
        .admit_initial_discovery_if_ready(name)
        .expect("initial discovery admission")
        .expect("initial discovery attempt");

    (lineage, attempt)
}

fn paused_recovery_for_checkpoint(
    request: &SubmitAttemptRequest,
    execution: ExecutionId,
    checkpoint: ExactCheckpointId,
) -> crate::PausedCheckpointPromotionRecovery {
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution,
        checkpoint,
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new_for_start_mode(
            request.resources(),
            request.retention(),
            request.start_mode(),
            request.retention_policy(),
        )),
    };
    let mut ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, None, Some(state))
            .expect("seed paused promotion"),
        AttemptStateCas::Advanced
    );
    let supervisor = LocalExecutorSupervisor::new(
        ledger,
        AllowAllAttemptAdmission,
        request.daemon_epoch(),
        ExecutorCapacity::new(1, 1, 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024, 10_000)
            .expect("capacity"),
    );
    supervisor
        .paused_checkpoint_promotion_recovery(key)
        .expect("load paused recovery")
        .expect("paused recovery")
}

fn raw_pause_recovery_for_request(
    request: &SubmitAttemptRequest,
    identity_byte: u8,
) -> crate::PausedCheckpointPromotionRecovery {
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let execution = ExecutionId::from_bytes([identity_byte; 16]).expect("execution");
    let checkpoint = ExactCheckpointId::parse(&format!(
        "crucible.executor.exact-checkpoint-root@exact-manifest.5.{}",
        format!("{identity_byte:02x}").repeat(32)
    ))
    .expect("checkpoint");
    let state = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution,
        checkpoint,
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new_for_start_mode(
            request.resources(),
            request.retention(),
            request.start_mode(),
            request.retention_policy(),
        )),
    };
    let mut ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, None, Some(state))
            .expect("seed raw pause"),
        AttemptStateCas::Advanced
    );
    let supervisor = LocalExecutorSupervisor::new(
        ledger,
        AllowAllAttemptAdmission,
        request.daemon_epoch(),
        ExecutorCapacity::new(1, 1, 64 * 1024 * 1024, 0, 1_000).expect("capacity"),
    );
    let mut work = Vec::new();
    supervisor
        .visit_checkpoint_promotion_restart_work(&mut |item| work.push(item))
        .expect("discover raw pause");
    let Some(CheckpointPromotionRestartWork::Paused(recovery)) = work.pop() else {
        panic!("expected one raw-pause recovery")
    };
    assert!(work.is_empty());
    recovery
}

fn campaign_attempt_fixture(
    repository: &CampaignRepository,
    name: &str,
) -> (
    CampaignLineage,
    CampaignPolicy,
    BranchRequest,
    crucible_campaign::AttemptAdmissionResult,
    ObservationCandidate,
) {
    let scenario_form = minimal_campaign_scenario();
    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1).expect("rational"),
        ExactRational::new(1, 2).expect("rational"),
        1,
        100,
        1,
    )
    .expect("widening");

    campaign_attempt_fixture_with_policy(
        repository,
        name,
        scenario_form,
        ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        },
        BTreeMap::new(),
        InterventionLearningPolicy::Exclude,
        BranchBudget::new(2, 2).expect("branch budget"),
    )
}

fn campaign_attempt_fixture_with_policy(
    repository: &CampaignRepository,
    name: &str,
    scenario_form: ScenarioDefForm,
    explorer: ExplorerPolicy,
    objectives: BTreeMap<String, Objective>,
    intervention_learning: InterventionLearningPolicy,
    branch_budget: BranchBudget,
) -> (
    CampaignLineage,
    CampaignPolicy,
    BranchRequest,
    crucible_campaign::AttemptAdmissionResult,
    ObservationCandidate,
) {
    let scenario_artifact =
        encode_crucible_scenario_artifact(&scenario_form).expect("scenario artifact");
    let scenario = scenario_artifact.scenario();
    let scenario_content = repository
        .publish_scenario_artifact(
            scenario,
            scenario_artifact.payload_schema(),
            scenario_artifact.payload().to_vec(),
        )
        .expect("scenario artifact");
    let genesis_configuration = Configuration::genesis(scenario_form.scenario_def());
    let genesis_artifact =
        encode_crucible_configuration_artifact(&scenario_artifact, &genesis_configuration.schedule)
            .expect("genesis configuration artifact");
    let genesis = genesis_artifact.configuration();
    let genesis_content = repository
        .publish_configuration_artifact(
            scenario,
            scenario_content,
            genesis,
            genesis_artifact.payload_schema(),
            genesis_artifact.payload().to_vec(),
        )
        .expect("genesis artifact");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "crucible-v1",
        "qemu-build-v1",
        BTreeMap::from([(String::from("control"), 1)]),
        scenario_artifact.payload_schema(),
        1,
    )
    .expect("lineage");
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario,
            CampaignSeed::from_bytes([7; 32]),
            CampaignMode::Strict,
            explorer,
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            objectives,
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )
    .expect("policy");
    let policy = match intervention_learning {
        InterventionLearningPolicy::Exclude => policy,
        InterventionLearningPolicy::IncludeInGuidance => policy
            .with_intervention_learning_policy(intervention_learning)
            .expect("intervention-guided fixture policy"),
    };
    let created = repository
        .create(name, &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    repository
        .apply_control(
            name,
            &crucible_campaign::ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.executor-flight.budget.v1",
                    name.as_bytes(),
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::GrantBudget(
                    crucible_campaign::BudgetGrant::new(2, 2).expect("campaign allowance"),
                ),
            },
        )
        .expect("fund campaign");
    let created = repository.head(name).expect("funded head");

    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
    let declaration = SelectableDeclaration::new(
        "product.executor-flight",
        ChoiceSource::Workload {
            producer: String::from("executor-flight"),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::from([String::from("executor-flight")]))
            .expect("choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("declaration");
    repository
        .publish_choice_domain(&domain)
        .expect("publish domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish declaration");
    let opportunity = ChoiceOpportunity::new(
        scenario,
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("crucible.test.executor-flight.scheduler.v1", b"s"),
            producer: CampaignHash::derive("crucible.test.executor-flight.producer.v1", b"p"),
        },
        "executor-flight",
        None,
    )
    .expect("opportunity");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish opportunity");
    let discovered = repository
        .discover_operator_choice_opportunity(
            name,
            created.snapshot_id(),
            genesis_content,
            opportunity.id().expect("opportunity id"),
        )
        .expect("discover opportunity");
    let request = BranchRequest::new(
        BranchRequest::identity(
            opportunity.branch_point_id(genesis),
            genesis_content,
            opportunity.id().expect("opportunity id"),
            domain.id().expect("domain id"),
        ),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))
        .expect("finite source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(CampaignHash::derive(
            "crucible.test.executor-flight.branch.v1",
            b"branch",
        ))),
        branch_budget,
        StopCondition::NextChoice,
    )
    .expect("branch request");
    let requested = repository
        .submit_operator_branch_request(name, discovered.new_snapshot, &request)
        .expect("submit branch request");
    let request_head = repository.head(name).expect("request head");
    let proposal = Proposal::new(
        request.branch_point(),
        request.id().expect("request id"),
        request.domain(),
        ChoiceValue::Boolean(false),
        policy.id().expect("policy id"),
        None,
        1,
        request_head
            .snapshot()
            .planning_view()
            .id()
            .expect("planning view"),
    )
    .expect("proposal");
    let proposed = repository
        .issue_proposal(name, requested.new_snapshot, &proposal)
        .expect("issue proposal");
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        proposal.value().clone(),
        request.branch_point(),
    )
    .expect("selection");
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        panic!("campaign branch selection")
    };
    let path = BranchPath::new(vec![BranchPathSegment::new(request.branch_point(), edge)])
        .expect("branch path");
    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: request.parent(),
            selection: selection.id().expect("selection id"),
        },
        path.id().expect("path id"),
        request.stop().clone(),
    )
    .expect("attempt");
    let admitted = repository
        .admit_proposal(
            name,
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit proposal");

    let child = ConfigurationId::from_hash(CampaignHash::derive(
        "crucible.test.executor-flight.child.v1",
        name.as_bytes(),
    ));
    let child_artifact =
        ConfigurationArtifact::new(scenario, scenario_content, child, 1, b"child".to_vec())
            .expect("child artifact");
    let measurements = MeasurementSet::from_evaluation(
        CampaignHash::derive(
            "crucible.test.measurement-definitions.v1",
            b"executor flight",
        ),
        1,
        CampaignHash::derive(
            "crucible.test.measurement-evaluation.v1",
            b"executor flight",
        ),
        b"executor flight".to_vec(),
        BTreeSet::new(),
    )
    .expect("measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
    let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage");
    let observation = Observation::new(
        admitted.attempt,
        Observation::outcome(
            child,
            child_artifact.id().expect("child artifact id"),
            path.id().expect("path id"),
            StopOutcome::Reached(StopCondition::NextChoice),
            measurements.id().expect("measurement id"),
            properties.id().expect("properties id"),
            coverage.id().expect("coverage id"),
        ),
        BTreeSet::from([opportunity.id().expect("opportunity id")]),
    )
    .expect("observation");
    let candidate = ObservationCandidate::new(
        child_artifact,
        measurements,
        properties,
        coverage,
        vec![
            crucible_campaign::ChoiceDiscovery::new(declaration, domain, opportunity)
                .expect("choice discovery"),
        ],
        observation,
    )
    .expect("observation candidate");
    (lineage, policy, request, admitted, candidate)
}

fn minimal_campaign_scenario() -> ScenarioDefForm {
    let world = World::from_nodes_and_links(Vec::new(), Vec::new()).expect("empty world");
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(9),
    )
    .expect("minimal scenario")
}

fn beam_objective_scenario() -> ScenarioDefForm {
    let base = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let node = base
        .world()
        .vm_nodes()
        .first()
        .expect("happy-path VM")
        .id
        .clone();
    let measurements = MeasurementDefinitions::new(
        base.world(),
        base.plan(),
        base.properties(),
        vec![MeasurementDefinition {
            id: MeasurementId::parse("beam-window").expect("measurement ID"),
            begin: BoundarySelector::ScenarioGenesis,
            end: BoundarySelector::SchedulerQuiescence,
            timeout: None,
            cohort: CohortPolicy::All(vec![node]),
            metrics: vec![MetricDefinition {
                id: MetricId::parse("scheduler-events").expect("metric ID"),
                value_type: MetricValueType::UnsignedInteger,
                unit: UnitId::parse("events").expect("unit ID"),
                source: MetricSource::SchedulerEventCount,
                aggregation: Aggregation::Count,
            }],
        }],
    )
    .expect("Beam measurement definitions");

    ScenarioDefForm::from_components_with_measurements_and_app_random_draw_cap(
        base.world(),
        base.plan(),
        base.properties(),
        &measurements,
        base.seed(),
        base.app_random_draw_cap(),
    )
    .expect("Beam objective scenario")
}

fn pool<W>(
    epoch: DaemonEpoch,
    workers: Vec<W>,
) -> LocalExecutorWorkerPool<MemoryAssignmentLedger, AllowAllAttemptAdmission>
where
    W: LocalAttemptWorker + Send + 'static,
{
    LocalExecutorWorkerPool::start(capability(epoch), store(), checkpoint_store(), workers)
        .expect("worker pool")
}

fn managed_executor_endpoint(
    label: &str,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    crate::ManagedExecutorLoopbackListener,
    UnixPeerExecutorIdentity,
) {
    let directory = tempfile::tempdir().expect("endpoint directory");
    let socket = directory.path().join(format!("{label}.sock"));
    let user_id = rustix::process::geteuid().as_raw();
    let group_id = rustix::process::getegid().as_raw();
    let listener = ExecutorLoopbackEndpointConfig::new(&socket, user_id, group_id, 0o600)
        .expect("endpoint configuration")
        .bind()
        .expect("managed endpoint");
    (
        directory,
        socket,
        listener,
        UnixPeerExecutorIdentity::new(user_id, group_id),
    )
}

fn wait_for_delayed_worker(
    state: &SharedDelayedCancellationState,
    predicate: impl Fn(&DelayedCancellationState) -> bool,
) {
    let (state, changed) = state.as_ref();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut state = state.lock().expect("delayed worker state");
    while !predicate(&state) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "delayed worker timed out");
        let (next, timeout) = changed
            .wait_timeout(state, remaining)
            .expect("delayed worker wake");
        state = next;
        assert!(
            !timeout.timed_out() || predicate(&state),
            "delayed worker timed out"
        );
    }
}

fn checkpoint_store() -> Arc<ExactCheckpointStore> {
    Arc::new(
        ExactCheckpointStore::new(Arc::new(TestDurableBackend::new()), 1024 * 1024)
            .expect("durable exact-checkpoint store"),
    )
}

fn promotion_process_fixture(
    checkpoints: Arc<ExactCheckpointStore>,
) -> (
    SharedExecutor<MemoryAssignmentLedger, AllowAllAttemptAdmission>,
    CheckpointPromotionRestartWork,
    PreparedPausedCheckpointPromotion,
    ExactCheckpointId,
) {
    let fixture = crate::prepare_repository_promotion_fixture(&checkpoints);
    let crate::RepositoryPromotionFixture {
        prepared,
        key,
        state,
        daemon_epoch,
        capacity,
        ..
    } = fixture;
    let raw = prepared.source();
    let mut ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, None, Some(state))
            .expect("seed promotion process fixture"),
        AttemptStateCas::Advanced
    );
    let supervisor =
        LocalExecutorSupervisor::new(ledger, AllowAllAttemptAdmission, daemon_epoch, capacity);
    let recovery = supervisor
        .paused_checkpoint_promotion_recovery(key)
        .expect("load promotion process fixture")
        .expect("raw promotion process fixture");
    let resources = AttemptResourceLimits::new(1, 64 * 1024 * 1024, 0, 1_000)
        .expect("promotion fixture resource ceiling");
    let executor = LocalExecutorCapabilityService::new(
        supervisor,
        description_with_limits(daemon_epoch, 1, resources),
    )
    .expect("promotion fixture capability");
    let shared = SharedExecutor::new(executor, checkpoints, 1, 1, Vec::new(), None, None);

    (
        shared,
        CheckpointPromotionRestartWork::Paused(recovery),
        prepared,
        raw,
    )
}

fn capability(
    epoch: DaemonEpoch,
) -> LocalExecutorCapabilityService<MemoryAssignmentLedger, AllowAllAttemptAdmission> {
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        capacity(),
    );
    LocalExecutorCapabilityService::new(supervisor, description(epoch))
        .expect("matching capability service")
}

fn store() -> CampaignExecutorStore {
    CampaignExecutorStore::new(Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("executor-pool", u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    )))
}

fn capacity() -> ExecutorCapacity {
    ExecutorCapacity::new(1, 2, 4096, 8192, 64).expect("capacity")
}

fn description(epoch: DaemonEpoch) -> ExecutorDescription {
    description_with_slots(epoch, 1)
}

fn description_with_slots(epoch: DaemonEpoch, maximum_slots: u32) -> ExecutorDescription {
    description_with_limits(
        epoch,
        maximum_slots,
        AttemptResourceLimits::new(2, 4096, 8192, 64).expect("resource ceiling"),
    )
}

fn description_with_limits(
    epoch: DaemonEpoch,
    maximum_slots: u32,
    resource_ceiling: AttemptResourceLimits,
) -> ExecutorDescription {
    let compatibility = ExecutorCompatibilityProfile::new(
        "crucible-v1",
        "qemu-build-v1",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("compatibility");
    let capabilities = ExecutorCapabilitySet::new(
        compatibility,
        "x86_64",
        BTreeSet::from([String::from("deterministic-tcg-v1")]),
        BTreeSet::from([ExecutorMaterializationCapability::ThinReplay]),
        maximum_slots,
        resource_ceiling,
        BTreeSet::from([CampaignHash::derive(
            "crucible.test.executor-pool-namespace.v1",
            b"local",
        )]),
    )
    .expect("capabilities");
    ExecutorDescription::new(epoch, capabilities).expect("description")
}

fn request(epoch: DaemonEpoch, byte: u8) -> SubmitAttemptRequest {
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([byte; 16]).expect("assignment"),
        epoch,
        CampaignLineageId::parse(&typed_id(
            "crucible.campaign.lineage",
            "campaign-fact",
            crucible_campaign::CampaignRecordKind::Lineage.schema_version(),
            0x51,
        ))
        .expect("lineage"),
        AttemptId::parse(&typed_id(
            "crucible.campaign.attempt",
            "campaign-fact",
            crucible_campaign::CampaignRecordKind::Attempt.schema_version(),
            byte,
        ))
        .expect("attempt"),
        AttemptResourceLimits::new(1, 1024, 2048, 32).expect("resources"),
        ExecutionRetentionIntent::Discard,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .expect("request")
}

fn typed_id(tag: &str, kind: &str, schema_version: u32, byte: u8) -> String {
    format!(
        "{tag}@{kind}.{schema_version}.{}",
        format!("{byte:02x}").repeat(32)
    )
}

fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !condition() {
        assert!(Instant::now() < deadline, "condition timed out");
        thread::sleep(Duration::from_millis(1));
    }
}
