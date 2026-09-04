//! Conformance tests for fixed local executor worker ownership.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]
// crucible-lint: allow clippy-disallowed-method -- the bounded host operation is operational only and cannot enter modeled state.
#![allow(clippy::disallowed_methods)]

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crucible::{
    Checkpoint, CheckpointKind, Configuration, MaterializedState, ScenarioDef,
    SchedulerLivenessScenario, Shift, SimInstant, SingleScheduler, SingleSchedulerCheckpoint,
};
use crucible_campaign::{
    AssignmentId, Attempt, AttemptId, AttemptResourceLimits, AttemptStart, BooleanDomain,
    BranchBudget, BranchPath, BranchPathSegment, BranchRequest, BranchRequestCause,
    CampaignCommandId, CampaignControlAction, CampaignExecutorDriver, CampaignExecutorStepOutcome,
    CampaignExecutorStore, CampaignHash, CampaignLineage, CampaignLineageId, CampaignMode,
    CampaignPolicy, CampaignRepository, CampaignSeed, CancelAttemptExecutionRequest,
    CancelAttemptExecutionResponse, CandidateSource, CheckpointAttemptExecutionRequest,
    CheckpointAttemptExecutionResponse, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain,
    ChoiceOpportunity, ChoiceSource, ChoiceValue, ConfigurationArtifact, ConfigurationId,
    ControlRequest, CoverageProjection, DaemonEpoch, ExactCheckpointId, ExactRational, ExecutionId,
    ExecutionRetentionIntent, ExecutorCapabilitySet, ExecutorClient, ExecutorCompatibilityProfile,
    ExecutorControlService, ExecutorDescription, ExecutorMaterializationCapability,
    ExecutorRejection, ExecutorResumeService, ExecutorService, ExecutorStatusService,
    ExplorerPolicy, FairnessPolicy, GetAttemptExecutionDisposition, GetAttemptExecutionRequest,
    GetAttemptExecutionResponse, MeasurementSet, Observation, ObservationCandidate,
    ProgressiveWideningPolicy, PropertyVerdictSet, Proposal, PuctPolicy,
    ResumeAttemptExecutionRequest, ResumeAttemptExecutionResponse, RetentionPolicy, ScenarioDefId,
    SelectableDeclaration, Selection, SelectionOrigin, StopCondition, StopOutcome,
    SubmitAttemptDisposition, SubmitAttemptRequest, SubmitAttemptResponse, WorkerSlotId,
};
use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ContentId, ImmutableBlobBackend, MemoryBlobBackend,
    MemoryRefBackend, PlacementReceipt, PutReceipt, StoreError,
};
use crucible_qemu::{QemuReplayOracleCheck, QemuReplayOracleValidation, QemuVmSnapshot};

use super::*;
use crate::{
    AllowAllAttemptAdmission, AttemptAdmissionValidator, AttemptExecutionContext,
    AttemptExecutionDisposition, AttemptExecutionInput, AttemptExecutionKey, AttemptExecutionModel,
    AttemptExecutionProduct, AttemptExecutionReconciliationStep, AttemptExecutionRuntimeBasis,
    AttemptRuntimeState, AttemptStateCas, AttemptWorkResult, AttemptWorkerFailure,
    CheckpointPromotionExecutionBasis, CheckpointPromotionRestartWork, CheckpointRequestOutcome,
    ExactCheckpointStore, ExecutionCancellation, ExecutorCapacity, ExecutorLocalService,
    ExecutorLocalServiceError, ExecutorLoopbackEndpointConfig, ExecutorLoopbackServerConfig,
    LoopbackExecutorService, MemoryAssignmentLedger,
    PausedCheckpointPromotionRecoveryResolutionError, PausedCheckpointPromotionStageOutcome,
    PreparedPausedCheckpointPromotion, PreparedPausedCheckpointPromotionRestart,
    RepositoryAttemptAdmission, RepositoryAttemptWorker, RepositoryAttemptWorkerError,
    UnixPeerExecutorIdentity, recover_published_paused_checkpoint_promotion,
    resolve_production_paused_checkpoint_promotion_recovery,
    stage_prepared_paused_checkpoint_promotion,
};

struct TestDurableBackend {
    memory: MemoryBlobBackend,
}

impl TestDurableBackend {
    fn new() -> Self {
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

struct BlockingAdmission {
    state: Arc<(Mutex<(bool, bool)>, Condvar)>,
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

struct ExactStorePromotionWorker {
    checkpoints: Arc<ExactCheckpointStore>,
    calls: Arc<AtomicUsize>,
}

struct BlockingCheckpointPromotionWorker {
    entered: Arc<AtomicUsize>,
    canceled: Arc<AtomicUsize>,
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

struct CheckpointWorker {
    entered: Arc<AtomicUsize>,
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

struct UnsolicitedCheckpointWorker;

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

struct PanickingWorker;

impl LocalAttemptWorker for PanickingWorker {
    type Error = &'static str;

    fn execute(&mut self, _queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        panic!("intentional worker panic")
    }
}

struct CandidateModel {
    candidate: ObservationCandidate,
    calls: Arc<AtomicUsize>,
    runtime_bases: Arc<Mutex<Vec<AttemptExecutionRuntimeBasis>>>,
    reconciliations: Arc<Mutex<Vec<AttemptExecutionDisposition>>>,
}

struct ForeignCheckpointModel;

#[derive(Default)]
struct StagedCheckpointState {
    staged: bool,
    release: bool,
}

struct StagingCheckpointModel {
    state: Arc<(Mutex<StagedCheckpointState>, Condvar)>,
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
        let checkpoint = context.prepare_and_stage_checkpoint(capture.into())?;

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
fn checkpoint_capture_publishes_once_and_reconciles_paused_without_rerun() {
    let epoch = DaemonEpoch::from_bytes([0x37; 16]).expect("epoch");
    let entered = Arc::new(AtomicUsize::new(0));
    let observer = Arc::new(RecordingPausedCheckpointObserver::default());
    let checkpoint_observer: Arc<dyn PausedCheckpointObserver> = observer.clone();
    let pool = LocalExecutorWorkerPool::start_with_checkpoint_observer(
        capability(epoch),
        store(),
        checkpoint_store(),
        vec![CheckpointWorker {
            entered: Arc::clone(&entered),
        }],
        checkpoint_observer,
    )
    .expect("checkpoint-observing worker pool");
    let assignment = request(epoch, 0x49);
    let mut service = pool.service();
    let accepted = service
        .submit_attempt(&assignment)
        .expect("accept checkpointable execution");
    let SubmitAttemptDisposition::Accepted { execution } = accepted.disposition() else {
        panic!("checkpointable execution should be newly accepted")
    };
    wait_until(Duration::from_secs(2), || {
        entered.load(Ordering::Acquire) == 1
    });

    let checkpoint_request =
        CheckpointAttemptExecutionRequest::new(&assignment, execution).expect("checkpoint request");
    assert!(matches!(
        service
            .checkpoint_attempt_execution(&checkpoint_request)
            .expect("request exact checkpoint")
            .disposition(),
        crucible_campaign::CheckpointAttemptExecutionDisposition::Requested
    ));
    let status_request =
        GetAttemptExecutionRequest::new(&assignment, execution).expect("status request");
    wait_until(Duration::from_secs(2), || {
        service
            .get_attempt_execution(&status_request)
            .is_ok_and(|response| {
                matches!(
                    response.disposition(),
                    GetAttemptExecutionDisposition::Paused { .. }
                )
            })
    });
    let status = service
        .get_attempt_execution(&status_request)
        .expect("paused status");
    let GetAttemptExecutionDisposition::Paused { checkpoint } = status.disposition() else {
        panic!("execution should be paused")
    };
    let loaded = pool
        .service
        .shared
        .checkpoints
        .load(checkpoint)
        .expect("load published exact checkpoint");
    let (expected_snapshot, expected_scheduler) = checkpoint_capture("pool-checkpoint");
    assert_eq!(loaded.snapshot(), &expected_snapshot);
    assert_eq!(loaded.scheduler(), Some(&expected_scheduler));
    assert_eq!(loaded.vmstate_bytes(), 512);
    assert_eq!(
        observer
            .checkpoints
            .lock()
            .expect("paused-checkpoint observer lock")
            .as_slice(),
        &[checkpoint]
    );

    let report = service.report().expect("checkpoint pool report");
    assert_eq!(report.executions(), 1);
    assert_eq!(report.checkpoints_paused(), 1);
    assert_eq!(report.checkpoints_discarded(), 0);
    assert_eq!(report.active(), 0);
    assert_eq!(pool.shutdown_and_join().expect("clean shutdown"), report);
}

#[test]
fn newly_paused_checkpoint_is_enqueued_and_promoted_without_rerunning_attempt() {
    let epoch = DaemonEpoch::from_bytes([0x3a; 16]).expect("epoch");
    let entered = Arc::new(AtomicUsize::new(0));
    let promotion_calls = Arc::new(AtomicUsize::new(0));
    let observer = Arc::new(RecordingPausedCheckpointObserver::default());
    let checkpoint_observer: Arc<dyn PausedCheckpointObserver> = observer.clone();
    let checkpoints = checkpoint_store();
    let pool = LocalExecutorWorkerPool::start_with_checkpoint_promotions_and_observer(
        capability(epoch),
        store(),
        Arc::clone(&checkpoints),
        vec![CheckpointWorker {
            entered: Arc::clone(&entered),
        }],
        vec![ExactStorePromotionWorker {
            checkpoints,
            calls: Arc::clone(&promotion_calls),
        }],
        checkpoint_observer,
    )
    .expect("promotion-enabled checkpoint pool");
    let assignment = request(epoch, 0x4c);
    let mut service = pool.service();
    let accepted = service
        .submit_attempt(&assignment)
        .expect("accept checkpointable execution");
    let SubmitAttemptDisposition::Accepted { execution } = accepted.disposition() else {
        panic!("checkpointable execution should be newly accepted")
    };
    wait_until(Duration::from_secs(2), || {
        entered.load(Ordering::Acquire) == 1
    });

    let checkpoint_request =
        CheckpointAttemptExecutionRequest::new(&assignment, execution).expect("checkpoint request");
    service
        .checkpoint_attempt_execution(&checkpoint_request)
        .expect("request exact checkpoint");
    wait_until(Duration::from_secs(2), || {
        service
            .report()
            .is_ok_and(|report| report.promotions_reconciled() == 1)
    });

    let status_request =
        GetAttemptExecutionRequest::new(&assignment, execution).expect("status request");
    let status = service
        .get_attempt_execution(&status_request)
        .expect("promoted paused status");
    let GetAttemptExecutionDisposition::Paused { checkpoint } = status.disposition() else {
        panic!("execution should remain paused after promotion")
    };
    let loaded = pool
        .service
        .shared
        .checkpoints
        .load(checkpoint)
        .expect("load promoted exact checkpoint");
    assert!(matches!(
        loaded.snapshot().replay_oracle_validation(),
        QemuReplayOracleValidation::Match { .. }
    ));
    let promotions = observer
        .promotions
        .lock()
        .expect("promoted-checkpoint observer lock");
    let [(source, promoted)] = promotions.as_slice() else {
        panic!("promotion must notify the paused-root owner exactly once")
    };
    assert_eq!(*promoted, checkpoint);
    assert_ne!(source, promoted);
    assert_eq!(
        observer
            .checkpoints
            .lock()
            .expect("paused-checkpoint observer lock")
            .as_slice(),
        &[*source]
    );
    drop(promotions);
    assert_eq!(promotion_calls.load(Ordering::Acquire), 1);
    let report = service.report().expect("promoted checkpoint report");
    assert_eq!(report.executions(), 1);
    assert_eq!(report.checkpoints_paused(), 1);
    assert_eq!(report.promotions_reconciled(), 1);
    assert_eq!(report.active(), 0);
    pool.shutdown_and_join().expect("promotion pool shutdown");
}

#[test]
fn unsolicited_checkpoint_fails_closed_without_publication() {
    let epoch = DaemonEpoch::from_bytes([0x38; 16]).expect("epoch");
    let pool = pool(epoch, vec![UnsolicitedCheckpointWorker]);
    let assignment = request(epoch, 0x4a);
    let mut service = pool.service();
    let accepted = service
        .submit_attempt(&assignment)
        .expect("accept execution");
    let SubmitAttemptDisposition::Accepted { execution } = accepted.disposition() else {
        panic!("execution should be newly accepted")
    };
    let status_request =
        GetAttemptExecutionRequest::new(&assignment, execution).expect("status request");
    wait_until(Duration::from_secs(2), || {
        service
            .get_attempt_execution(&status_request)
            .is_ok_and(|response| {
                response.disposition() == GetAttemptExecutionDisposition::Canceled
            })
    });

    let report = service.report().expect("terminal pool report");
    assert_eq!(report.executions(), 1);
    assert_eq!(report.checkpoints_paused(), 0);
    assert_eq!(report.terminal_stops(), 1);
    assert_eq!(report.active(), 0);
    assert_eq!(pool.shutdown_and_join().expect("clean shutdown"), report);
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
    let pool = pool(epoch, vec![PanickingWorker]);
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
        incorporated.observation,
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
            AttemptExecutionDisposition::Observation(incorporated.observation),
            AttemptExecutionDisposition::Observation(incorporated.observation),
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
    assert_eq!(head.snapshot_id(), incorporated.new_snapshot);
    assert_eq!(request.stop(), &StopCondition::NextChoice);
}

#[test]
fn repository_worker_rejects_a_checkpoint_from_another_scenario() {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "foreign-checkpoint-scenario",
            64 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let (lineage, _policy, _branch, admitted, _candidate) =
        campaign_attempt_fixture(&repository, "foreign-checkpoint-scenario");
    let epoch = DaemonEpoch::from_bytes([0x91; 16]).expect("daemon epoch");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x92; 16]).expect("assignment"),
        epoch,
        lineage.id().expect("lineage id"),
        admitted.attempt,
        AttemptResourceLimits::new(1, 64 * 1024 * 1024, 0, 1_000).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("submit request");
    let mut supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(1, 1, 64 * 1024 * 1024, 0, 1_000).expect("capacity"),
    );
    let response = supervisor
        .submit_attempt(&request)
        .expect("accept execution");
    let SubmitAttemptDisposition::Accepted { execution } = response.disposition() else {
        panic!("execution should be accepted")
    };
    assert_eq!(
        supervisor
            .request_checkpoint(
                AttemptExecutionKey::new(request.lineage(), request.attempt()),
                execution,
            )
            .expect("request exact checkpoint"),
        CheckpointRequestOutcome::Requested
    );
    let queued = supervisor.next_queued().expect("queued execution");
    let mut worker = RepositoryAttemptWorker::new(
        CampaignExecutorStore::new(repository),
        ForeignCheckpointModel,
    );

    let (_queued, result) = worker.execute(queued).into_parts();

    assert!(matches!(
        result,
        Err(AttemptWorkerFailure::Terminal(
            RepositoryAttemptWorkerError::IncompatibleResult {
                reason: "exact checkpoint differs from assignment scenario",
            }
        ))
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
    )
    .expect("submit request");
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let execution = ExecutionId::from_bytes([0xa3; 16]).expect("execution");
    let checkpoint = ExactCheckpointId::parse(&format!(
        "crucible.executor.exact-checkpoint-root@exact-manifest.2.{}",
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
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new(resources, retention)),
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
            *recovery,
            ExecutionCancellation::default(),
        ),
        Err(PausedCheckpointPromotionRecoveryResolutionError::ExecutionBasisMismatch)
    ));
}

#[test]
fn fixed_promotion_worker_promotes_raw_restart_work_without_semantic_execution() {
    let checkpoints = checkpoint_store();
    let raw = checkpoints
        .prepare(
            &checkpoint_snapshot("promotion-worker-restart"),
            BlobHandle::from_bytes(vec![0x41; 512]),
        )
        .and_then(|prepared| checkpoints.publish(&prepared))
        .expect("publish raw restart checkpoint")
        .root();
    let source = checkpoints.load(raw).expect("load raw restart checkpoint");
    let runtime_hash = source.snapshot().checkpoint().configuration;
    let expected = checkpoints
        .prepare_replay_oracle_promotion(
            raw,
            QemuReplayOracleCheck::from_unvalidated_test_result(
                source.snapshot().id(),
                QemuReplayOracleValidation::Match { runtime_hash },
            ),
        )
        .expect("prepare expected promotion")
        .promoted();

    let epoch = DaemonEpoch::from_bytes([0xb1; 16]).expect("daemon epoch");
    let request = request(epoch, 0xb2);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let execution = ExecutionId::from_bytes([0xb3; 16]).expect("execution");
    let paused = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch: epoch,
        execution,
        checkpoint: raw,
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new(
            request.resources(),
            request.retention(),
        )),
    };
    let mut ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, None, Some(paused))
            .expect("seed paused restart"),
        AttemptStateCas::Advanced
    );
    let supervisor =
        LocalExecutorSupervisor::new(ledger, AllowAllAttemptAdmission, epoch, capacity());
    let executor = LocalExecutorCapabilityService::new(supervisor, description(epoch))
        .expect("promotion executor capability");
    let calls = Arc::new(AtomicUsize::new(0));
    let pool = LocalExecutorWorkerPool::start_with_checkpoint_promotions(
        executor,
        store(),
        Arc::clone(&checkpoints),
        vec![SequencedFailureWorker {
            calls: Arc::new(AtomicUsize::new(0)),
        }],
        vec![ExactStorePromotionWorker {
            checkpoints,
            calls: Arc::clone(&calls),
        }],
    )
    .expect("start promotion-enabled pool");
    let service = pool.service();

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let report = service.report().expect("promotion report");
        if report.promotions_reconciled() == 1 {
            assert_eq!(report.promotion_workers(), 1);
            assert_eq!(report.promotions_active(), 0);
            assert_eq!(report.promotions_queued(), 0);
            assert_eq!(report.executions(), 0);
            break;
        }
        assert!(Instant::now() < deadline, "promotion worker timed out");
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(calls.load(Ordering::Acquire), 1);
    let executor = service
        .shared
        .executor
        .lock()
        .expect("promotion supervisor");
    assert_eq!(
        executor
            .supervisor()
            .ledger()
            .load_attempt(key)
            .expect("load promoted attempt"),
        Some(AttemptRuntimeState::Paused {
            execution_basis: request.execution_basis_digest(),
            origin: crate::AttemptExecutionOrigin::Initial,
            daemon_epoch: epoch,
            execution,
            checkpoint: expected,
            promotion_basis: Some(CheckpointPromotionExecutionBasis::new(
                request.resources(),
                request.retention(),
            )),
        })
    );
    drop(executor);
    pool.shutdown_and_join().expect("promotion pool shutdown");
}

#[test]
fn shutdown_cancels_in_flight_promotion_and_retains_raw_restart_root() {
    let checkpoints = checkpoint_store();
    let raw = checkpoints
        .prepare(
            &checkpoint_snapshot("promotion-worker-cancel"),
            BlobHandle::from_bytes(vec![0x61; 512]),
        )
        .and_then(|prepared| checkpoints.publish(&prepared))
        .expect("publish cancelable promotion source")
        .root();
    let epoch = DaemonEpoch::from_bytes([0xd1; 16]).expect("daemon epoch");
    let request = request(epoch, 0xd2);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let execution = ExecutionId::from_bytes([0xd3; 16]).expect("execution");
    let paused = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch: epoch,
        execution,
        checkpoint: raw,
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new(
            request.resources(),
            request.retention(),
        )),
    };
    let mut ledger = MemoryAssignmentLedger::default();
    ledger
        .compare_exchange_attempt(key, None, Some(paused))
        .expect("seed cancelable promotion");
    let supervisor =
        LocalExecutorSupervisor::new(ledger, AllowAllAttemptAdmission, epoch, capacity());
    let executor = LocalExecutorCapabilityService::new(supervisor, description(epoch))
        .expect("cancelable promotion executor");
    let entered = Arc::new(AtomicUsize::new(0));
    let canceled = Arc::new(AtomicUsize::new(0));
    let pool = LocalExecutorWorkerPool::start_with_checkpoint_promotions(
        executor,
        store(),
        checkpoints,
        vec![SequencedFailureWorker {
            calls: Arc::new(AtomicUsize::new(0)),
        }],
        vec![BlockingCheckpointPromotionWorker {
            entered: Arc::clone(&entered),
            canceled: Arc::clone(&canceled),
        }],
    )
    .expect("start cancelable promotion pool");
    let service = pool.service();
    wait_until(Duration::from_secs(2), || {
        entered.load(Ordering::Acquire) == 1
    });

    pool.request_shutdown();
    let report = pool.shutdown_and_join().expect("join canceled promotion");
    assert_eq!(canceled.load(Ordering::Acquire), 1);
    assert_eq!(report.promotions_active(), 0);
    assert_eq!(report.promotions_reconciled(), 0);
    let executor = service
        .shared
        .executor
        .lock()
        .expect("canceled promotion supervisor");
    assert_eq!(
        executor
            .supervisor()
            .ledger()
            .load_attempt(key)
            .expect("load retained raw pause"),
        Some(paused)
    );
}

#[test]
fn incomplete_staged_restart_reverts_and_regenerates_without_attempt_execution() {
    let checkpoints = checkpoint_store();
    let raw = checkpoints
        .prepare(
            &checkpoint_snapshot("promotion-worker-incomplete"),
            BlobHandle::from_bytes(vec![0x51; 512]),
        )
        .and_then(|prepared| checkpoints.publish(&prepared))
        .expect("publish incomplete-promotion source")
        .root();
    let source = checkpoints
        .load(raw)
        .expect("load incomplete-promotion source");
    let runtime_hash = source.snapshot().checkpoint().configuration;
    let promotion = checkpoints
        .prepare_replay_oracle_promotion(
            raw,
            QemuReplayOracleCheck::from_unvalidated_test_result(
                source.snapshot().id(),
                QemuReplayOracleValidation::Match { runtime_hash },
            ),
        )
        .expect("prepare incomplete replacement");
    let expected = promotion.promoted();

    let epoch = DaemonEpoch::from_bytes([0xc1; 16]).expect("daemon epoch");
    let request = request(epoch, 0xc2);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let execution = ExecutionId::from_bytes([0xc3; 16]).expect("execution");
    let paused = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch: epoch,
        execution,
        checkpoint: raw,
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new(
            request.resources(),
            request.retention(),
        )),
    };
    let mut ledger = MemoryAssignmentLedger::default();
    ledger
        .compare_exchange_attempt(key, None, Some(paused))
        .expect("seed incomplete promotion");
    let mut supervisor =
        LocalExecutorSupervisor::new(ledger, AllowAllAttemptAdmission, epoch, capacity());
    let staged = match stage_prepared_paused_checkpoint_promotion(
        &mut supervisor,
        PreparedPausedCheckpointPromotion::new(key, execution, promotion),
    )
    .expect("stage incomplete replacement")
    {
        PausedCheckpointPromotionStageOutcome::Publish(staged) => staged,
        other => panic!("expected staged incomplete replacement, got {other:?}"),
    };
    drop(staged);

    let executor = LocalExecutorCapabilityService::new(supervisor, description(epoch))
        .expect("incomplete promotion executor");
    let calls = Arc::new(AtomicUsize::new(0));
    let pool = LocalExecutorWorkerPool::start_with_checkpoint_promotions(
        executor,
        store(),
        Arc::clone(&checkpoints),
        vec![SequencedFailureWorker {
            calls: Arc::new(AtomicUsize::new(0)),
        }],
        vec![ExactStorePromotionWorker {
            checkpoints,
            calls: Arc::clone(&calls),
        }],
    )
    .expect("restart incomplete promotion pool");
    let service = pool.service();
    wait_until(Duration::from_secs(2), || {
        service
            .report()
            .is_ok_and(|report| report.promotions_reconciled() == 1)
    });

    assert_eq!(calls.load(Ordering::Acquire), 2);
    let report = service.report().expect("regenerated promotion report");
    assert_eq!(report.promotions_discarded(), 1);
    assert_eq!(report.promotions_reconciled(), 1);
    assert_eq!(report.executions(), 0);
    let executor = service
        .shared
        .executor
        .lock()
        .expect("regenerated promotion supervisor");
    assert!(matches!(
        executor
            .supervisor()
            .ledger()
            .load_attempt(key)
            .expect("load regenerated promotion"),
        Some(AttemptRuntimeState::Paused { checkpoint, .. }) if checkpoint == expected
    ));
    drop(executor);
    pool.shutdown_and_join()
        .expect("regenerated promotion shutdown");
}

#[test]
fn pool_stages_the_exact_root_before_the_modeled_worker_returns() {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "checkpoint-handoff",
            64 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let (lineage, _policy, _branch, admitted, _candidate) =
        campaign_attempt_fixture(&repository, "checkpoint-handoff");
    let epoch = DaemonEpoch::from_bytes([0xa1; 16]).expect("daemon epoch");
    let assignment = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0xa2; 16]).expect("assignment"),
        epoch,
        lineage.id().expect("lineage id"),
        admitted.attempt,
        AttemptResourceLimits::new(1, 1024, 2048, 32).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("submit request");
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        capacity(),
    );
    let capability = LocalExecutorCapabilityService::new(supervisor, description(epoch))
        .expect("capability service");
    let state = Arc::new((Mutex::new(StagedCheckpointState::default()), Condvar::new()));
    let pool = LocalExecutorWorkerPool::start(
        capability,
        CampaignExecutorStore::new(Arc::clone(&repository)),
        checkpoint_store(),
        vec![RepositoryAttemptWorker::new(
            CampaignExecutorStore::new(repository),
            StagingCheckpointModel {
                state: Arc::clone(&state),
            },
        )],
    )
    .expect("checkpoint handoff pool");
    let mut service = pool.service();
    let accepted = service
        .submit_attempt(&assignment)
        .expect("accept checkpointable execution");
    let SubmitAttemptDisposition::Accepted { execution } = accepted.disposition() else {
        panic!("checkpointable execution should be accepted")
    };
    let checkpoint_request =
        CheckpointAttemptExecutionRequest::new(&assignment, execution).expect("checkpoint request");
    assert!(matches!(
        service
            .checkpoint_attempt_execution(&checkpoint_request)
            .expect("request checkpoint")
            .disposition(),
        crucible_campaign::CheckpointAttemptExecutionDisposition::Requested
            | crucible_campaign::CheckpointAttemptExecutionDisposition::AlreadyRequested
    ));

    let (stage_state, changed) = state.as_ref();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut stage_state = stage_state.lock().expect("checkpoint stage state");
    while !stage_state.staged {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "checkpoint handoff timed out");
        let (next, timeout) = changed
            .wait_timeout(stage_state, remaining)
            .expect("checkpoint stage wake");
        stage_state = next;
        assert!(
            !timeout.timed_out() || stage_state.staged,
            "checkpoint handoff timed out"
        );
    }
    let status_request =
        GetAttemptExecutionRequest::new(&assignment, execution).expect("status request");
    let status = service
        .get_attempt_execution(&status_request)
        .expect("publishing status");
    let GetAttemptExecutionDisposition::CheckpointPublishing { checkpoint } = status.disposition()
    else {
        panic!("exact root must be staged before the worker returns")
    };
    let publishing_report = service.report().expect("publishing pool report");
    assert_eq!(publishing_report.active(), 1);
    assert_eq!(publishing_report.checkpoints_paused(), 0);
    stage_state.release = true;
    changed.notify_all();
    drop(stage_state);

    wait_until(Duration::from_secs(2), || {
        service
            .get_attempt_execution(&status_request)
            .is_ok_and(|response| {
                response.disposition() == GetAttemptExecutionDisposition::Paused { checkpoint }
            })
    });
    assert_eq!(
        pool.service
            .shared
            .checkpoints
            .load(checkpoint)
            .expect("published checkpoint")
            .vmstate_bytes(),
        512
    );
    let report = service.report().expect("checkpoint pool report");
    assert_eq!(report.checkpoints_paused(), 1);
    assert_eq!(report.active(), 0);
    assert_eq!(pool.shutdown_and_join().expect("clean shutdown"), report);
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
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive(
        "crucible.test.executor-flight.scenario.v1",
        name.as_bytes(),
    ));
    let genesis = ConfigurationId::from_hash(CampaignHash::derive(
        "crucible.test.executor-flight.genesis.v1",
        name.as_bytes(),
    ));
    let scenario_content = repository
        .publish_scenario_artifact(scenario, 1, b"scenario".to_vec())
        .expect("scenario artifact");
    let genesis_content = repository
        .publish_configuration_artifact(scenario, scenario_content, genesis, 1, b"genesis".to_vec())
        .expect("genesis artifact");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "crucible-v1",
        "qemu-build-v1",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
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
        scenario,
        CampaignSeed::from_bytes([7; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("policy");
    let created = repository
        .create(name, &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");

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
        opportunity.branch_point_id(genesis),
        genesis_content,
        opportunity.id().expect("opportunity id"),
        domain.id().expect("domain id"),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))
        .expect("finite source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(CampaignHash::derive(
            "crucible.test.executor-flight.branch.v1",
            b"branch",
        ))),
        BranchBudget::new(2, 2).expect("branch budget"),
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
    let measurements = MeasurementSet::new(BTreeMap::new()).expect("measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
    let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage");
    let observation = Observation::new(
        admitted.attempt,
        child,
        child_artifact.id().expect("child artifact id"),
        path.id().expect("path id"),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements.id().expect("measurement id"),
        properties.id().expect("properties id"),
        coverage.id().expect("coverage id"),
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

fn checkpoint_snapshot(name: &str) -> QemuVmSnapshot {
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.executor-pool-checkpoint",
        name,
    ));
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        crucible::VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("checkpoint boundary");
    QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
        .expect("QEMU checkpoint snapshot")
}

fn checkpoint_snapshot_for_scenario(name: &str, scenario: crucible::ContentHash) -> QemuVmSnapshot {
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.executor-pool-checkpoint",
        name,
    ));
    let mut checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        crucible::VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("checkpoint boundary");
    checkpoint.scenario_ref = scenario;
    QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
        .expect("QEMU checkpoint snapshot")
}

fn checkpoint_capture(name: &str) -> (QemuVmSnapshot, SingleSchedulerCheckpoint) {
    let scenario =
        ScenarioDef::from_canonical_material("crucible.test.executor-pool-checkpoint", name);
    let configuration = Configuration::genesis(scenario.clone());
    let scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            name,
            Shift::new(0).expect("zero shift"),
            1,
            SimInstant { nanos: 1 },
            Vec::new(),
            Vec::new(),
        )
        .with_scenario_def(scenario),
    )
    .expect("checkpoint scheduler")
    .checkpoint()
    .expect("scheduler continuation");
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        scheduler.frontier(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("checkpoint boundary")
    .with_materialized_state(Some(MaterializedState::from_components(
        BTreeMap::new(),
        BTreeMap::new(),
        scheduler.scheduler_state().expect("scheduler projection"),
        scheduler.future_decision_rng_state().clone(),
        scheduler.event_log_offset(),
    )));
    let snapshot = QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
        .expect("QEMU checkpoint snapshot");
    (snapshot, scheduler)
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
        AttemptResourceLimits::new(2, 4096, 8192, 64).expect("resource ceiling"),
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
            0x51,
        ))
        .expect("lineage"),
        AttemptId::parse(&typed_id(
            "crucible.campaign.attempt",
            "campaign-fact",
            byte,
        ))
        .expect("attempt"),
        AttemptResourceLimits::new(1, 1024, 2048, 32).expect("resources"),
        ExecutionRetentionIntent::Discard,
    )
    .expect("request")
}

fn typed_id(tag: &str, kind: &str, byte: u8) -> String {
    format!("{tag}@{kind}.1.{}", format!("{byte:02x}").repeat(32))
}

fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !condition() {
        assert!(Instant::now() < deadline, "condition timed out");
        thread::sleep(Duration::from_millis(1));
    }
}
