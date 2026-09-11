//! Shared workers, models, and backends for executor-pool tests.

use super::*;

pub(super) struct TestDurableBackend {
    pub(super) memory: MemoryBlobBackend,
}

pub(super) struct TestFindingCheckpointAuthenticator {
    pub(super) source: Arc<MemoryBlobBackend>,
}

impl FindingExactCheckpointAuthenticator for TestFindingCheckpointAuthenticator {
    fn authenticate_finding_exact_checkpoint(
        &self,
        _checkpoint: ExactCheckpointId,
        scenario: ScenarioDefId,
        _scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        _maximum_metadata_bytes: u64,
    ) -> Result<AuthenticatedFindingExactCheckpoint, FindingExactCheckpointAuthenticationError>
    {
        Ok(AuthenticatedFindingExactCheckpoint::new(
            scenario,
            configuration,
            0,
            1,
        ))
    }

    fn read_finding_exact_checkpoint_object(
        &self,
        object: ContentId,
    ) -> Result<BlobHandle, FindingExactCheckpointAuthenticationError> {
        self.source
            .read(object, None)
            .map_err(|_| FindingExactCheckpointAuthenticationError::AuthenticationFailed)
    }
}

pub(super) struct TransientExecutorReadBackend {
    pub(super) memory: MemoryBlobBackend,
    pub(super) fail_executor_read: AtomicBool,
    pub(super) fail_content_read: Mutex<Option<ContentId>>,
    pub(super) injected_failures: AtomicUsize,
}

impl TransientExecutorReadBackend {
    pub(super) fn new(name: &'static str, maximum_bytes: u64) -> Self {
        Self {
            memory: MemoryBlobBackend::new(name, maximum_bytes),
            fail_executor_read: AtomicBool::new(false),
            fail_content_read: Mutex::new(None),
            injected_failures: AtomicUsize::new(0),
        }
    }

    pub(super) fn fail_next_executor_read(&self) {
        self.fail_executor_read.store(true, Ordering::Release);
    }

    pub(super) fn fail_next_read_of(&self, content: ContentId) {
        *self.fail_content_read.lock().expect("content read failure") = Some(content);
    }

    pub(super) fn should_fail_content_read(&self, content: ContentId) -> bool {
        let mut failure = self.fail_content_read.lock().expect("content read failure");
        if failure.as_ref() == Some(&content) {
            *failure = None;
            self.injected_failures.fetch_add(1, Ordering::AcqRel);
            true
        } else {
            false
        }
    }

    pub(super) fn should_fail_executor_read(&self) -> bool {
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
    pub(super) fn new() -> Self {
        Self {
            memory: MemoryBlobBackend::new("executor-pool-checkpoints", 8 * 1024 * 1024),
        }
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

pub(super) struct BlockingAdmission {
    pub(super) state: Arc<(Mutex<(bool, bool)>, Condvar)>,
}

pub(super) struct AllowCampaignControl;

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

pub(super) struct AllowAllAttemptScopes;

impl AttemptAdmissionValidator for AllowAllAttemptScopes {
    fn validate(&self, _request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection> {
        Ok(())
    }

    fn validate_execution_scope(
        &self,
        _request: &SubmitAttemptRequest,
    ) -> Result<(), ExecutorRejection> {
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

pub(super) struct SequencedFailureWorker {
    pub(super) calls: Arc<AtomicUsize>,
}

pub(super) struct ExactStorePromotionWorker {
    pub(super) checkpoints: Arc<ExactCheckpointStore>,
    pub(super) calls: Arc<AtomicUsize>,
}

pub(super) struct BlockingCheckpointPromotionWorker {
    pub(super) entered: Arc<AtomicUsize>,
    pub(super) canceled: Arc<AtomicUsize>,
}

pub(super) struct CountingProductionReplayFactory {
    pub(super) calls: Arc<AtomicUsize>,
}

pub(super) struct UnusedPromotionGuard {
    pub(super) cancellation: ExecutionCancellation,
    pub(super) resources: AttemptResourceLimits,
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
    type Store = ProductionBakedGenesisReplayStore;
    type Launcher = ProductionBakedGenesisReplayLauncher;
    type Guard = UnusedPromotionGuard;

    fn begin_target(
        &mut self,
        _exact_root: ExactCheckpointId,
        _world: &World,
        _configuration: &Configuration,
        _target: &crucible_api::ProductionExactCheckpointReplayTarget,
        _cancellation: &ExecutionCancellation,
        _resources: AttemptResourceLimits,
    ) -> Result<
        ProductionPausedCheckpointReplaySession<Self::Store, Self::Launcher, Self::Guard>,
        crucible_qemu::QemuVmRealizationError,
    > {
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

impl LocalCheckpointPromotionWorker for ExactStorePromotionWorker {
    type Error = &'static str;

    fn prepare(
        &mut self,
        work: CheckpointPromotionRestartWork,
        _cancellation: ExecutionCancellation,
    ) -> Result<PreparedPausedCheckpointPromotionRestart, AttemptWorkerFailure<Self::Error>> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        match work {
            CheckpointPromotionRestartWork::Paused(recovery) => {
                let source = self.checkpoints.load(recovery.source()).map_err(|_| {
                    AttemptWorkerFailure::Terminal("load raw checkpoint promotion source")
                })?;
                let runtime_hash = source.snapshot().checkpoint().configuration;
                let check = QemuReplayOracleCheck::from_unvalidated_test_result(
                    source.snapshot().id(),
                    QemuReplayOracleValidation::Match { runtime_hash },
                );
                let promotion = self
                    .checkpoints
                    .prepare_replay_oracle_promotion(recovery.source(), check)
                    .map_err(|_| {
                        AttemptWorkerFailure::Terminal("prepare raw checkpoint promotion")
                    })?;
                Ok(PreparedPausedCheckpointPromotionRestart::Stage(Box::new(
                    PreparedPausedCheckpointPromotion::new(
                        recovery.key(),
                        recovery.execution(),
                        promotion,
                    ),
                )))
            }
            CheckpointPromotionRestartWork::Staged(recovery) => {
                let published =
                    recover_published_paused_checkpoint_promotion(&self.checkpoints, recovery)
                        .map_err(|_| {
                            AttemptWorkerFailure::Terminal(
                                "authenticate staged checkpoint promotion",
                            )
                        })?;
                Ok(PreparedPausedCheckpointPromotionRestart::Reconcile(
                    Box::new(published),
                ))
            }
        }
    }
}

impl LocalCheckpointPromotionWorker for BlockingCheckpointPromotionWorker {
    type Error = &'static str;

    fn prepare(
        &mut self,
        _work: CheckpointPromotionRestartWork,
        cancellation: ExecutionCancellation,
    ) -> Result<PreparedPausedCheckpointPromotionRestart, AttemptWorkerFailure<Self::Error>> {
        self.entered.store(1, Ordering::Release);
        while !cancellation.is_canceled() {
            thread::sleep(Duration::from_millis(1));
        }
        self.canceled.store(1, Ordering::Release);
        Err(AttemptWorkerFailure::Canceled("promotion shutdown"))
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

pub(super) struct BlockingWorker {
    pub(super) entered: Arc<AtomicUsize>,
}

#[derive(Default)]
pub(super) struct DelayedCancellationState {
    pub(super) entered: bool,
    pub(super) canceled: bool,
    pub(super) release: bool,
}

pub(super) type SharedDelayedCancellationState = Arc<(Mutex<DelayedCancellationState>, Condvar)>;

pub(super) struct DelayedCancellationWorker {
    pub(super) state: SharedDelayedCancellationState,
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

pub(super) struct CheckpointWorker {
    pub(super) entered: Arc<AtomicUsize>,
}

#[derive(Default)]
pub(super) struct RecordingPausedCheckpointObserver {
    pub(super) checkpoints: Mutex<Vec<ExactCheckpointId>>,
    pub(super) promotions: Mutex<Vec<(ExactCheckpointId, ExactCheckpointId)>>,
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

pub(super) struct UnsolicitedCheckpointWorker;

impl LocalAttemptWorker for UnsolicitedCheckpointWorker {
    type Error = &'static str;

    fn execute(&mut self, queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        AttemptWorkResult::new(
            queued,
            Ok(AttemptExecutionProduct::exact_checkpoint(
                crate::CapturedExactCheckpoint::new(
                    checkpoint_snapshot("unsolicited-checkpoint"),
                    BlobHandle::from_bytes(vec![0x6b; 512]),
                ),
            )),
        )
    }
}

impl LocalAttemptWorker for CheckpointWorker {
    type Error = &'static str;

    fn execute(&mut self, queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        self.entered.store(1, Ordering::Release);
        while !queued.checkpoint_request().is_requested() {
            if queued.cancellation().is_canceled() {
                return AttemptWorkResult::new(
                    queued,
                    Err(AttemptWorkerFailure::Canceled("checkpoint worker canceled")),
                );
            }
            thread::sleep(Duration::from_millis(1));
        }
        let (snapshot, scheduler) = checkpoint_capture("pool-checkpoint");
        AttemptWorkResult::new(
            queued,
            Ok(AttemptExecutionProduct::exact_checkpoint(
                crate::CapturedExactCheckpoint::new_with_scheduler(
                    snapshot,
                    scheduler,
                    BlobHandle::from_bytes(vec![0x5a; 512]),
                ),
            )),
        )
    }
}

pub(super) struct PanickingWorker;

impl LocalAttemptWorker for PanickingWorker {
    type Error = &'static str;

    fn execute(&mut self, _queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        panic!("intentional worker panic")
    }
}

pub(super) struct PanickingCleanupWorker {
    pub(super) cleanup: Option<crate::NativeCheckpointCleanup>,
}

pub(super) struct IdleCleanupWorker {
    pub(super) cleanup: Option<crate::NativeCheckpointCleanup>,
}

impl LocalAttemptWorker for IdleCleanupWorker {
    type Error = &'static str;

    fn execute(&mut self, _queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        unreachable!("idle cleanup worker receives no execution")
    }

    fn take_abandoned_native_checkpoint(&mut self) -> Option<crate::NativeCheckpointCleanup> {
        self.cleanup.take()
    }
}

impl LocalAttemptWorker for PanickingCleanupWorker {
    type Error = &'static str;

    fn execute(&mut self, _queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        panic!("intentional worker panic after native checkpoint capture")
    }

    fn take_abandoned_native_checkpoint(&mut self) -> Option<crate::NativeCheckpointCleanup> {
        self.cleanup.take()
    }
}

pub(super) struct CandidateModel {
    pub(super) candidate: ObservationCandidate,
    pub(super) calls: Arc<AtomicUsize>,
    pub(super) runtime_bases: Arc<Mutex<Vec<AttemptExecutionRuntimeBasis>>>,
    pub(super) reconciliations: Arc<Mutex<Vec<AttemptExecutionDisposition>>>,
}

pub(super) struct SuccessfulCleanupModel {
    pub(super) candidate: ObservationCandidate,
    pub(super) cleanup: Option<crate::NativeCheckpointCleanup>,
}

#[derive(Clone, Copy)]
pub(super) enum ReconciliationCleanupFailure {
    Retryable,
    Terminal,
}

pub(super) struct ReconciliationCleanupModel {
    pub(super) candidate: ObservationCandidate,
    pub(super) retirement: Option<crucible_api::ProductionExactCheckpointRetirement>,
    pub(super) cleanup: Option<crate::NativeCheckpointCleanup>,
    pub(super) failure: ReconciliationCleanupFailure,
    pub(super) calls: Arc<AtomicUsize>,
}

pub(super) struct ForeignCheckpointModel;

#[derive(Default)]
pub(super) struct StagedCheckpointState {
    pub(super) staged: bool,
    pub(super) release: bool,
}

pub(super) struct StagingCheckpointModel {
    pub(super) state: Arc<(Mutex<StagedCheckpointState>, Condvar)>,
}

impl AttemptExecutionModel for ForeignCheckpointModel {
    type Error = std::convert::Infallible;

    fn execute(
        &mut self,
        _input: &AttemptExecutionInput,
        _context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        Ok(AttemptExecutionProduct::exact_checkpoint(
            crate::CapturedExactCheckpoint::new(
                checkpoint_snapshot("foreign-checkpoint-scenario"),
                BlobHandle::from_bytes(vec![0x73; 512]),
            ),
        ))
    }
}

impl AttemptExecutionModel for StagingCheckpointModel {
    type Error = crate::CheckpointHandoffFailure;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        while !context.checkpoint_request().is_requested() {
            if context.cancellation().is_canceled() {
                return Err(AttemptWorkerFailure::Canceled(
                    crate::CheckpointHandoffFailure::Canceled,
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
        let scenario = crucible::ContentHash {
            bytes: input.lineage().scenario().as_hash().as_bytes(),
        };
        let capture = crate::CapturedExactCheckpoint::new(
            checkpoint_snapshot_for_scenario("staged-before-return", scenario),
            BlobHandle::from_bytes(vec![0x75; 512]),
        );
        let checkpoint = context.prepare_and_stage_checkpoint(&capture.into())?;

        let (state, changed) = self.state.as_ref();
        let mut state = state.lock().expect("checkpoint stage state");
        state.staged = true;
        changed.notify_all();
        while !state.release {
            state = changed.wait(state).expect("checkpoint stage wake");
        }
        drop(state);

        Ok(AttemptExecutionProduct::exact_checkpoint(checkpoint))
    }
}

pub(super) struct CountingExecutorService<S> {
    pub(super) inner: S,
    pub(super) submits: Arc<AtomicUsize>,
    pub(super) status_reads: Arc<AtomicUsize>,
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
        Ok(AttemptExecutionProduct::observation(self.candidate.clone()))
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

impl AttemptExecutionModel for SuccessfulCleanupModel {
    type Error = std::convert::Infallible;

    fn execute(
        &mut self,
        _input: &AttemptExecutionInput,
        _context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        Ok(AttemptExecutionProduct::observation(self.candidate.clone()))
    }

    fn take_abandoned_native_checkpoint(&mut self) -> Option<crate::NativeCheckpointCleanup> {
        self.cleanup.take()
    }
}

impl AttemptExecutionModel for ReconciliationCleanupModel {
    type Error = &'static str;

    fn execute(
        &mut self,
        _input: &AttemptExecutionInput,
        _context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        Ok(AttemptExecutionProduct::observation(self.candidate.clone()))
    }

    fn take_abandoned_native_checkpoint(&mut self) -> Option<crate::NativeCheckpointCleanup> {
        self.cleanup.take()
    }

    fn reconcile_execution(
        &mut self,
        _disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel);
        if call != 0 {
            return Ok(AttemptExecutionReconciliationStep::Complete);
        }
        self.cleanup = self
            .retirement
            .take()
            .map(crate::NativeCheckpointCleanup::Retire);
        match self.failure {
            ReconciliationCleanupFailure::Retryable => {
                Err(AttemptWorkerFailure::Retryable("retry reconciliation"))
            }
            ReconciliationCleanupFailure::Terminal => {
                Err(AttemptWorkerFailure::Terminal("terminal reconciliation"))
            }
        }
    }
}
