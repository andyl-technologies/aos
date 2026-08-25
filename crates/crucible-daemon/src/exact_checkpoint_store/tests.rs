//! Exact-checkpoint store regressions.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, DecisionRngState, MaterializedState,
    RngStreamId, RngStreamPosition, ScenarioDef, SchedulerLivenessScenario, Shift, SimInstant,
    SingleScheduler,
};
use crucible_campaign::{
    AssignmentId, AttemptId, AttemptResourceLimits, CampaignLineageId,
    CheckpointAttemptExecutionRequest, DaemonEpoch, ExecutionRetentionIntent,
    ExecutorControlService, ExecutorResumeService, ExecutorService,
    ResumeAttemptExecutionDisposition, ResumeAttemptExecutionRequest, SubmitAttemptDisposition,
    SubmitAttemptRequest,
};
use crucible_cas::content_store::{
    BackendCapabilities, BlobSource, ByteRange, DirectoryBlobBackend, MemoryBlobBackend,
    PlacementReceipt,
};
use crucible_qemu::{QemuReplayOracleCheck, QemuReplayOracleValidation};

use super::*;
use crate::{
    AllowAllAttemptAdmission, AssignmentLedger, AttemptRuntimeState, CancellationOutcome,
    CheckpointCompletionOutcome, CheckpointPromotionCompletionOutcome, CheckpointResultAbortToken,
    CheckpointResultStageOutcome, ExecutorCapacity, LocalExecutorSupervisor,
    MemoryAssignmentLedger, PausedCheckpointPromotionStageOutcome, PreparedCheckpointResult,
    PreparedPausedCheckpointPromotion, abort_checkpoint_result, publish_staged_checkpoint_result,
    publish_staged_paused_checkpoint_promotion, reconcile_published_checkpoint_result,
    reconcile_published_paused_checkpoint_promotion, recover_published_paused_checkpoint_promotion,
    stage_prepared_checkpoint_result, stage_prepared_paused_checkpoint_promotion,
};

const STORE_LIMIT: u64 = 1024 * 1024;

struct TestDurableBackend {
    memory: MemoryBlobBackend,
}

impl TestDurableBackend {
    fn new() -> Self {
        Self {
            memory: MemoryBlobBackend::new("test-exact-checkpoints", 8 * STORE_LIMIT),
        }
    }

    fn object_count(&self) -> usize {
        self.memory.object_count().expect("count test objects")
    }
}

impl ImmutableBlobBackend for TestDurableBackend {
    fn name(&self) -> &str {
        "test-durable-exact-checkpoints"
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

struct OpenCountingSource {
    logical_length: u64,
    opens: Arc<AtomicUsize>,
}

impl BlobSource for OpenCountingSource {
    fn logical_length(&self) -> u64 {
        self.logical_length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Cursor::new(Vec::<u8>::new())))
    }
}

#[test]
fn prepare_is_write_free_and_publication_round_trips_streamed_vmstate() {
    let backend = Arc::new(TestDurableBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), STORE_LIMIT).expect("admit store");
    let snapshot = snapshot("round-trip");
    let vmstate_bytes = (0..131_071_u32)
        .map(|value| (value % 251) as u8)
        .collect::<Vec<_>>();

    let prepared = store
        .prepare(&snapshot, BlobHandle::from_bytes(vmstate_bytes.clone()))
        .expect("prepare exact checkpoint");

    assert_eq!(backend.object_count(), 0);
    assert_eq!(prepared.snapshot_identity(), snapshot.id());
    assert_eq!(
        prepared.configuration(),
        snapshot.checkpoint().configuration
    );
    assert_eq!(prepared.vmstate_bytes(), vmstate_bytes.len() as u64);
    assert_eq!(
        prepared.root().content_id().kind(),
        ObjectKind::ExactManifest
    );
    assert_eq!(
        prepared.root().content_id().schema_version(),
        LEGACY_EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION
    );
    assert_eq!(prepared.metadata_id().kind(), ObjectKind::DeviceState);
    assert_eq!(
        prepared.metadata_id().schema_version(),
        QEMU_VM_SNAPSHOT_METADATA_SCHEMA_VERSION
    );
    assert_eq!(prepared.vmstate_id().kind(), ObjectKind::DeviceState);
    assert_eq!(
        prepared.vmstate_id().schema_version(),
        QEMU_VMSTATE_SCHEMA_VERSION
    );

    let publication = store.publish(&prepared).expect("publish exact checkpoint");
    assert_eq!(publication.root(), prepared.root());
    assert_eq!(publication.metadata(), prepared.metadata_id());
    assert_eq!(publication.vmstate(), prepared.vmstate_id());
    assert_eq!(backend.object_count(), 3);

    let loaded = store
        .load(publication.root())
        .expect("load exact checkpoint");
    assert_eq!(loaded.root(), publication.root());
    assert_eq!(loaded.snapshot(), &snapshot);
    assert_eq!(loaded.vmstate_id(), publication.vmstate());
    let mut restored_vmstate = Vec::new();
    assert_eq!(
        loaded
            .copy_vmstate_to(&mut restored_vmstate)
            .expect("authenticate VMState"),
        vmstate_bytes.len() as u64
    );
    assert_eq!(restored_vmstate, vmstate_bytes);

    assert_eq!(
        store.publish(&prepared).expect("idempotent publish"),
        publication
    );
    assert_eq!(backend.object_count(), 3);
}

#[test]
fn complete_scheduler_continuation_round_trips_in_v3_root() {
    let backend = Arc::new(TestDurableBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), STORE_LIMIT).expect("admit store");
    let (snapshot, scheduler) = snapshot_with_scheduler("scheduler-round-trip");
    let capture = CapturedExactCheckpoint::new_with_scheduler(
        snapshot.clone(),
        scheduler.clone(),
        BlobHandle::from_bytes(vec![0x5a; 4_096]),
    );

    let prepared = store
        .prepare_capture(capture)
        .expect("prepare complete exact checkpoint");
    assert_eq!(backend.object_count(), 0);
    assert_eq!(
        prepared.root().content_id().schema_version(),
        SINGLE_NODE_EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION
    );
    assert_eq!(
        prepared
            .scheduler_id
            .expect("scheduler child")
            .schema_version(),
        SCHEDULER_CONTINUATION_SCHEMA_VERSION
    );

    let publication = store.publish(&prepared).expect("publish complete root");
    assert_eq!(publication.scheduler(), prepared.scheduler_id);
    assert_eq!(backend.object_count(), 4);

    let loaded = store.load(publication.root()).expect("load complete root");
    assert_eq!(loaded.snapshot(), &snapshot);
    assert_eq!(loaded.scheduler(), Some(&scheduler));
    assert_eq!(loaded.scheduler_id(), prepared.scheduler_id);
}

#[test]
fn mismatched_scheduler_continuation_is_rejected_before_writes() {
    let backend = Arc::new(TestDurableBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), STORE_LIMIT).expect("admit store");
    let (snapshot, _) = snapshot_with_scheduler("scheduler-basis-a");
    let (_, foreign_scheduler) = snapshot_with_scheduler("scheduler-basis-b");
    let capture = CapturedExactCheckpoint::new_with_scheduler(
        snapshot,
        foreign_scheduler,
        BlobHandle::from_bytes(vec![0x6b; 4_096]),
    );

    assert!(matches!(
        store.prepare_capture(capture),
        Err(ExactCheckpointStoreError::InvalidRoot {
            reason: "scheduler continuation does not match checkpoint projections"
        })
    ));
    assert_eq!(backend.object_count(), 0);
}

#[test]
fn scheduler_rng_and_event_segment_projections_are_exact() {
    let backend = Arc::new(TestDurableBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), STORE_LIMIT).expect("admit store");
    let (snapshot, scheduler) = snapshot_with_scheduler("scheduler-projection");
    let checkpoint = snapshot.checkpoint().clone();
    let materialized = checkpoint
        .state
        .as_ref()
        .expect("materialized state")
        .clone();

    let mut decision_rng = DecisionRngState::empty();
    decision_rng.positions.insert(
        RngStreamId::from_name("foreign-cursor"),
        RngStreamPosition::new(1),
    );
    let mismatched_rng = checkpoint.clone().with_materialized_state(Some(
        MaterializedState::from_components_with_event_log_segments(
            materialized.vm_snapshots.clone(),
            materialized.device_overlays.clone(),
            materialized.scheduler.clone(),
            decision_rng,
            materialized.event_log,
            materialized.event_log_segments.clone(),
        ),
    ));
    let mismatched_rng =
        QemuVmSnapshot::diskless(mismatched_rng, QemuReplayOracleValidation::NotRun)
            .expect("mismatched RNG snapshot");
    assert!(matches!(
        store.prepare_capture(CapturedExactCheckpoint::new_with_scheduler(
            mismatched_rng,
            scheduler.clone(),
            BlobHandle::from_bytes(vec![0x6c; 4_096]),
        )),
        Err(ExactCheckpointStoreError::InvalidRoot {
            reason: "scheduler continuation does not match checkpoint projections"
        })
    ));

    let mismatched_segments = checkpoint.with_materialized_state(Some(
        MaterializedState::from_components_with_event_log_segments(
            materialized.vm_snapshots.clone(),
            materialized.device_overlays.clone(),
            materialized.scheduler.clone(),
            materialized.decision_rng.clone(),
            materialized.event_log,
            [ContentHash::from_bytes(b"foreign-event-segment")],
        ),
    ));
    let mismatched_segments =
        QemuVmSnapshot::diskless(mismatched_segments, QemuReplayOracleValidation::NotRun)
            .expect("mismatched event-segment snapshot");
    assert!(matches!(
        store.prepare_capture(CapturedExactCheckpoint::new_with_scheduler(
            mismatched_segments,
            scheduler,
            BlobHandle::from_bytes(vec![0x6d; 4_096]),
        )),
        Err(ExactCheckpointStoreError::InvalidRoot {
            reason: "scheduler continuation does not match checkpoint projections"
        })
    ));
    assert_eq!(backend.object_count(), 0);
}

#[test]
fn replay_oracle_promotion_reuses_vmstate_and_publishes_a_new_exact_root() {
    let backend = Arc::new(TestDurableBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), STORE_LIMIT).expect("admit store");
    let (snapshot, scheduler) = snapshot_with_scheduler("oracle-promotion");
    let vmstate = vec![0x6d; 4096];
    let source = store
        .prepare_capture(CapturedExactCheckpoint::new_with_scheduler(
            snapshot.clone(),
            scheduler.clone(),
            BlobHandle::from_bytes(vmstate.clone()),
        ))
        .and_then(|prepared| store.publish(&prepared))
        .expect("publish unvalidated source");
    let loaded = store.load(source.root()).expect("load unvalidated source");
    let source_vmstate = loaded.vmstate_id();
    let source_scheduler = loaded.scheduler_id().expect("source scheduler child");
    let source_count = backend.object_count();
    let runtime_hash = crucible::ContentHash::from_canonical_material(
        "crucible.test.exact-checkpoint-store.runtime.v1",
        "oracle-promotion",
    );
    let check = QemuReplayOracleCheck::from_unvalidated_test_result(
        snapshot.id(),
        QemuReplayOracleValidation::Match { runtime_hash },
    );

    let promoted = store
        .prepare_replay_oracle_promotion(source.root(), check)
        .expect("prepare source-bound promotion");

    assert_eq!(backend.object_count(), source_count);
    assert_ne!(promoted.promoted(), source.root());
    assert_eq!(promoted.replacement().vmstate_id(), source_vmstate);
    let published = store
        .publish(promoted.replacement())
        .expect("publish promotion");
    store
        .authenticate_replay_oracle_promotion(source.root(), published.root())
        .expect("authenticate durable promotion pair");
    let reloaded = store.load(published.root()).expect("load promotion");
    assert_eq!(reloaded.vmstate_id(), source_vmstate);
    assert_eq!(reloaded.scheduler_id(), Some(source_scheduler));
    assert_eq!(reloaded.scheduler(), Some(&scheduler));
    let mut reloaded_vmstate = Vec::new();
    assert_eq!(
        reloaded
            .copy_vmstate_to(&mut reloaded_vmstate)
            .expect("copy promoted VMState"),
        vmstate.len() as u64
    );
    assert_eq!(reloaded_vmstate, vmstate);
    assert_eq!(
        reloaded.snapshot().replay_oracle_validation(),
        QemuReplayOracleValidation::Match { runtime_hash }
    );
}

#[test]
fn publication_phase_tokens_keep_capacity_and_root_ordering_exact() {
    let backend = Arc::new(TestDurableBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), STORE_LIMIT).expect("admit store");
    let epoch = DaemonEpoch::from_bytes([0x41; 16]).expect("daemon epoch");
    let mut supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(1, 2, 4096, 8192, 64).expect("capacity"),
    );
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x42; 16]).expect("assignment"),
        epoch,
        CampaignLineageId::parse(&typed_id(
            "crucible.campaign.lineage",
            "campaign-fact",
            1,
            0x43,
        ))
        .expect("lineage"),
        AttemptId::parse(&typed_id(
            "crucible.campaign.attempt",
            "campaign-fact",
            1,
            0x44,
        ))
        .expect("attempt"),
        AttemptResourceLimits::new(1, 2048, 4096, 32).expect("resources"),
        ExecutionRetentionIntent::RetainAlways,
    )
    .expect("request");
    let response = supervisor
        .submit_attempt(&request)
        .expect("accept execution");
    let execution = match response.disposition() {
        SubmitAttemptDisposition::Accepted { execution } => execution,
        other => panic!("expected accepted execution, got {other:?}"),
    };
    let queued = supervisor.next_queued().expect("take execution");
    supervisor
        .checkpoint_attempt_execution(
            &CheckpointAttemptExecutionRequest::new(&request, execution)
                .expect("checkpoint request"),
        )
        .expect("request checkpoint");

    let (phase_snapshot, phase_scheduler) = snapshot_with_scheduler("phase-ordering");
    let prepared = store
        .prepare_capture(CapturedExactCheckpoint::new_with_scheduler(
            phase_snapshot,
            phase_scheduler.clone(),
            BlobHandle::from_bytes(vec![0x55; 8192]),
        ))
        .expect("prepare checkpoint");
    let root = prepared.root();
    let staged = match stage_prepared_checkpoint_result(
        &mut supervisor,
        PreparedCheckpointResult::new(
            queued,
            PreparedAttemptCheckpoint::SingleNode(Box::new(prepared)),
        ),
    )
    .expect("stage root")
    {
        CheckpointResultStageOutcome::Publish(staged) => *staged,
        other => panic!("expected publish token, got {other:?}"),
    };
    assert_eq!(backend.object_count(), 0);
    assert_eq!(supervisor.active_count(), 1);
    let mut roots = Vec::new();
    supervisor
        .ledger()
        .visit_checkpoint_roots(&mut |checkpoint| roots.push(checkpoint))
        .expect("visit staged roots");
    assert_eq!(roots, vec![root]);

    let published = publish_staged_checkpoint_result(&store, staged).expect("publish checkpoint");
    assert_eq!(backend.object_count(), 4);
    let loaded = store.load(root).expect("load published root");
    assert_eq!(loaded.root(), root);
    assert_eq!(loaded.scheduler(), Some(&phase_scheduler));
    assert_eq!(supervisor.active_count(), 1);
    assert_eq!(
        reconcile_published_checkpoint_result(&mut supervisor, published)
            .expect("reconcile checkpoint"),
        CheckpointCompletionOutcome::Paused
    );
    assert_eq!(supervisor.active_count(), 0);

    let abort_request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x45; 16]).expect("abort assignment"),
        epoch,
        request.lineage(),
        AttemptId::parse(&typed_id(
            "crucible.campaign.attempt",
            "campaign-fact",
            1,
            0x46,
        ))
        .expect("abort attempt"),
        request.resources(),
        request.retention(),
    )
    .expect("abort request");
    let abort_response = supervisor
        .submit_attempt(&abort_request)
        .expect("accept abort execution");
    let abort_execution = match abort_response.disposition() {
        SubmitAttemptDisposition::Accepted { execution } => execution,
        other => panic!("expected accepted abort execution, got {other:?}"),
    };
    let abort_queued = supervisor.next_queued().expect("take abort execution");
    supervisor
        .checkpoint_attempt_execution(
            &CheckpointAttemptExecutionRequest::new(&abort_request, abort_execution)
                .expect("abort checkpoint request"),
        )
        .expect("request abort checkpoint");
    let abort_prepared = store
        .prepare(
            &snapshot("phase-abort"),
            BlobHandle::from_bytes(vec![0x66; 4096]),
        )
        .expect("prepare abort checkpoint");
    let abort_root = abort_prepared.root();
    let abort_staged = match stage_prepared_checkpoint_result(
        &mut supervisor,
        PreparedCheckpointResult::new(
            abort_queued,
            PreparedAttemptCheckpoint::SingleNode(Box::new(abort_prepared)),
        ),
    )
    .expect("stage abort root")
    {
        CheckpointResultStageOutcome::Publish(staged) => staged,
        other => panic!("expected abort publish token, got {other:?}"),
    };
    assert_eq!(
        abort_checkpoint_result(
            &mut supervisor,
            CheckpointResultAbortToken::Staged(abort_staged),
        )
        .expect("abort staged checkpoint"),
        CancellationOutcome::Canceled
    );
    assert_eq!(supervisor.active_count(), 0);
    let mut retained = Vec::new();
    supervisor
        .ledger()
        .visit_checkpoint_roots(&mut |checkpoint| retained.push(checkpoint))
        .expect("visit roots after abort");
    assert_eq!(retained, vec![root]);
    assert_ne!(abort_root, root);
}

#[test]
fn paused_raw_root_promotion_survives_restart_and_enables_exact_resume() {
    let backend = Arc::new(TestDurableBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), STORE_LIMIT).expect("admit store");
    let paused_epoch = DaemonEpoch::from_bytes([0x51; 16]).expect("paused daemon epoch");
    let resumed_epoch = DaemonEpoch::from_bytes([0x52; 16]).expect("resumed daemon epoch");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x53; 16]).expect("paused assignment"),
        paused_epoch,
        CampaignLineageId::parse(&typed_id(
            "crucible.campaign.lineage",
            "campaign-fact",
            1,
            0x54,
        ))
        .expect("lineage"),
        AttemptId::parse(&typed_id(
            "crucible.campaign.attempt",
            "campaign-fact",
            1,
            0x55,
        ))
        .expect("attempt"),
        AttemptResourceLimits::new(1, 2048, 4096, 32).expect("resources"),
        ExecutionRetentionIntent::RetainAlways,
    )
    .expect("paused request");
    let key = crate::AttemptExecutionKey::new(request.lineage(), request.attempt());
    let execution = crucible_campaign::ExecutionId::from_bytes([0x56; 16]).expect("execution");
    let raw = store
        .prepare(
            &snapshot("paused-promotion"),
            BlobHandle::from_bytes(vec![0x57; 4096]),
        )
        .and_then(|prepared| store.publish(&prepared))
        .expect("publish raw paused root")
        .root();
    let loaded = store.load(raw).expect("load raw paused root");
    let runtime_hash = loaded.snapshot().checkpoint().configuration;
    let check = || {
        QemuReplayOracleCheck::from_unvalidated_test_result(
            loaded.snapshot().id(),
            QemuReplayOracleValidation::Match { runtime_hash },
        )
    };

    let paused = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch: paused_epoch,
        execution,
        checkpoint: raw,
    };
    let mut ledger = MemoryAssignmentLedger::default();
    ledger
        .compare_exchange_attempt(key, None, Some(paused))
        .expect("seed paused state");
    let mut supervisor = LocalExecutorSupervisor::new(
        ledger,
        AllowAllAttemptAdmission,
        paused_epoch,
        ExecutorCapacity::new(1, 2, 4096, 8192, 64).expect("capacity"),
    );
    let stale_promotion = store
        .prepare_replay_oracle_promotion(raw, check())
        .expect("prepare stale replay-oracle promotion");
    let source_object_count = backend.object_count();
    let stale = stage_prepared_paused_checkpoint_promotion(
        &mut supervisor,
        PreparedPausedCheckpointPromotion::new(
            key,
            crucible_campaign::ExecutionId::from_bytes([0x59; 16]).expect("stale execution"),
            stale_promotion,
        ),
    )
    .expect("classify stale promotion");
    assert!(matches!(
        stale,
        PausedCheckpointPromotionStageOutcome::Finished {
            outcome: crate::CheckpointPromotionStageOutcome::NotCurrent,
            ..
        }
    ));
    assert_eq!(backend.object_count(), source_object_count);

    let promotion = store
        .prepare_replay_oracle_promotion(raw, check())
        .expect("prepare replay-oracle promotion");
    let promoted = promotion.promoted();
    let staged = match stage_prepared_paused_checkpoint_promotion(
        &mut supervisor,
        PreparedPausedCheckpointPromotion::new(key, execution, promotion),
    )
    .expect("stage promotion roots")
    {
        PausedCheckpointPromotionStageOutcome::Publish(staged) => *staged,
        other => panic!("expected promotion publish token, got {other:?}"),
    };
    let mut roots = Vec::new();
    supervisor
        .ledger()
        .visit_checkpoint_roots(&mut |checkpoint| roots.push(checkpoint))
        .expect("visit staged promotion roots");
    assert_eq!(roots, vec![promoted, raw]);
    let incomplete = supervisor
        .checkpoint_promotion_recovery(key)
        .expect("load incomplete staged promotion")
        .expect("incomplete staged promotion");
    assert!(matches!(
        recover_published_paused_checkpoint_promotion(&store, incomplete),
        Err(PrepareReplayOraclePromotionError::Checkpoint(
            ExactCheckpointStoreError::Store(StoreError::NotFound { .. })
        ))
    ));
    let _published =
        publish_staged_paused_checkpoint_promotion(&store, staged).expect("publish promoted root");

    let ledger = supervisor.into_ledger();
    let mut restarted = LocalExecutorSupervisor::new(
        ledger,
        AllowAllAttemptAdmission,
        resumed_epoch,
        ExecutorCapacity::new(1, 2, 4096, 8192, 64).expect("restart capacity"),
    );
    let recovery = restarted
        .checkpoint_promotion_recovery(key)
        .expect("load staged promotion")
        .expect("staged promotion");
    let published = recover_published_paused_checkpoint_promotion(&store, recovery)
        .expect("authenticate complete promoted root after restart");
    assert_eq!(
        reconcile_published_paused_checkpoint_promotion(&mut restarted, published)
            .expect("promote paused root"),
        CheckpointPromotionCompletionOutcome::Promoted
    );
    assert_eq!(
        restarted
            .ledger()
            .load_attempt(key)
            .expect("load promoted pause"),
        Some(AttemptRuntimeState::Paused {
            execution_basis: request.execution_basis_digest(),
            origin: crate::AttemptExecutionOrigin::Initial,
            daemon_epoch: paused_epoch,
            execution,
            checkpoint: promoted,
        })
    );

    let resumed_assignment = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x58; 16]).expect("resume assignment"),
        resumed_epoch,
        request.lineage(),
        request.attempt(),
        request.resources(),
        request.retention(),
    )
    .expect("resume assignment request");
    let resume = ResumeAttemptExecutionRequest::new(&resumed_assignment, execution, promoted)
        .expect("resume request");
    let response = restarted
        .resume_attempt_execution(&resume)
        .expect("resume promoted exact root");
    assert!(matches!(
        response.disposition(),
        ResumeAttemptExecutionDisposition::Accepted { .. }
    ));
}

#[test]
fn directory_publication_is_reloadable_after_store_restart() {
    let directory = tempfile::tempdir().expect("create exact-checkpoint store directory");
    let root_path = directory.path().join("objects");
    let (snapshot, scheduler) = snapshot_with_scheduler("directory-restart");
    let vmstate_bytes = vec![0xa5; 64 * 1024];

    let first_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "first-exact-checkpoint-store",
        &root_path,
    ));
    let first = ExactCheckpointStore::new(first_backend, STORE_LIMIT).expect("admit first store");
    let prepared = first
        .prepare_capture(CapturedExactCheckpoint::new_with_scheduler(
            snapshot.clone(),
            scheduler.clone(),
            BlobHandle::from_bytes(vmstate_bytes.clone()),
        ))
        .expect("prepare durable checkpoint");
    let root = first
        .publish(&prepared)
        .expect("publish durable checkpoint")
        .root();
    drop(first);

    let reopened_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "reopened-exact-checkpoint-store",
        root_path,
    ));
    let reopened = ExactCheckpointStore::new(reopened_backend, STORE_LIMIT).expect("reopen store");
    let loaded = reopened.load(root).expect("load after restart");
    let mut restored = Vec::new();
    loaded
        .copy_vmstate_to(&mut restored)
        .expect("authenticate restarted VMState");

    assert_eq!(loaded.snapshot(), &snapshot);
    assert_eq!(loaded.scheduler(), Some(&scheduler));
    assert_eq!(restored, vmstate_bytes);
}

#[test]
fn store_requires_durable_streaming_conditional_backend() {
    let memory: Arc<dyn ImmutableBlobBackend> =
        Arc::new(MemoryBlobBackend::new("non-durable", STORE_LIMIT));
    assert!(matches!(
        ExactCheckpointStore::new(memory, STORE_LIMIT),
        Err(ExactCheckpointStoreError::UnsupportedBackend {
            capability: "durable"
        })
    ));

    let backend: Arc<dyn ImmutableBlobBackend> = Arc::new(TestDurableBackend::new());
    assert!(matches!(
        ExactCheckpointStore::new(backend, 0),
        Err(ExactCheckpointStoreError::InvalidLimit)
    ));
}

#[test]
fn oversized_vmstate_is_rejected_before_open_or_store_write() {
    let backend = Arc::new(TestDurableBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), STORE_LIMIT).expect("admit store");
    let opens = Arc::new(AtomicUsize::new(0));
    let source = BlobHandle::new(Arc::new(OpenCountingSource {
        logical_length: STORE_LIMIT + 1,
        opens: opens.clone(),
    }));

    assert!(matches!(
        store.prepare(&snapshot("oversized"), source),
        Err(ExactCheckpointStoreError::ArtifactLimit {
            artifact: "qemu-vmstate",
            length,
            maximum: STORE_LIMIT,
        }) if length == STORE_LIMIT + 1
    ));
    assert_eq!(opens.load(Ordering::SeqCst), 0);
    assert_eq!(backend.object_count(), 0);
}

#[test]
fn load_fails_closed_when_a_root_child_is_missing() {
    let backend = Arc::new(TestDurableBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), STORE_LIMIT).expect("admit store");
    let prepared = store
        .prepare(
            &snapshot("missing-child"),
            BlobHandle::from_bytes(vec![7; 512]),
        )
        .expect("prepare root");
    backend
        .put_if_absent(prepared.root.content_id(), &prepared.root_source)
        .expect("publish only root");

    assert!(matches!(
        store.load(prepared.root()),
        Err(ExactCheckpointStoreError::Store(StoreError::NotFound { id }))
            if id == prepared.metadata_id()
    ));
    assert_eq!(backend.object_count(), 1);
}

#[test]
fn load_rejects_extraneous_root_children_before_child_reads() {
    let backend = Arc::new(TestDurableBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), STORE_LIMIT).expect("admit store");
    let prepared = store
        .prepare(
            &snapshot("extra-child"),
            BlobHandle::from_bytes(vec![9; 512]),
        )
        .expect("prepare root");
    let root_bytes = prepared
        .root_source
        .read_all(MAX_ROOT_BYTES)
        .expect("read prepared root");
    let root = ContentEnvelope::from_canonical_bytes(&root_bytes).expect("decode root");
    let extra_id = ContentId::for_bytes(ObjectKind::Trace, 1, b"smuggled");
    let mut children = root.children().clone();
    children.insert(ContentChild::new("extra", extra_id).expect("extra child"));
    let malformed = ContentEnvelope::new(
        EXACT_CHECKPOINT_ROOT_SCHEMA,
        SINGLE_NODE_EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
        children,
        root.body().to_vec(),
    )
    .expect("bounded malformed root");
    let malformed_id = ExactCheckpointId::try_from(malformed.content_id(ObjectKind::ExactManifest))
        .expect("typed malformed root");
    backend
        .put_if_absent(
            malformed_id.content_id(),
            &BlobHandle::from_bytes(malformed.canonical_bytes()),
        )
        .expect("publish malformed root");

    assert!(matches!(
        store.load(malformed_id),
        Err(ExactCheckpointStoreError::InvalidRoot {
            reason: "root contains an unknown child role"
        })
    ));
    assert_eq!(backend.object_count(), 1);
}

#[test]
fn root_binds_snapshot_semantics_not_only_child_shape() {
    let backend = Arc::new(TestDurableBackend::new());
    let store = ExactCheckpointStore::new(backend.clone(), STORE_LIMIT).expect("admit store");
    let original = store
        .prepare(&snapshot("basis-a"), BlobHandle::from_bytes(vec![1; 512]))
        .expect("prepare original");
    let replacement = store
        .prepare(&snapshot("basis-b"), BlobHandle::from_bytes(vec![1; 512]))
        .expect("prepare replacement");
    backend
        .put_if_absent(replacement.metadata_id, &replacement.metadata_source)
        .expect("publish replacement metadata");

    let original_bytes = original
        .root_source
        .read_all(MAX_ROOT_BYTES)
        .expect("read original root");
    let original_root = ContentEnvelope::from_canonical_bytes(&original_bytes).expect("root");
    let original_body = decode_root_body(original_root.schema_version(), original_root.body())
        .expect("decode original body");
    let forged_body = encode_root_body(
        original_body.snapshot_identity,
        original_body.configuration,
        replacement.metadata_source.logical_length(),
        None,
        replacement.vmstate_source.logical_length(),
    );
    let children = BTreeSet::from([
        ContentChild::new(SNAPSHOT_METADATA_ROLE, replacement.metadata_id)
            .expect("replacement metadata child"),
        ContentChild::new(QEMU_VMSTATE_ROLE, replacement.vmstate_id)
            .expect("replacement VMState child"),
    ]);
    let forged = ContentEnvelope::new(
        EXACT_CHECKPOINT_ROOT_SCHEMA,
        LEGACY_EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
        children,
        forged_body,
    )
    .expect("forge structurally valid root");
    let forged_id = ExactCheckpointId::try_from(forged.content_id(ObjectKind::ExactManifest))
        .expect("typed forged root");
    backend
        .put_if_absent(
            forged_id.content_id(),
            &BlobHandle::from_bytes(forged.canonical_bytes()),
        )
        .expect("publish forged root");

    let error = store
        .load(forged_id)
        .err()
        .expect("forged root must fail closed");
    assert!(
        matches!(
            error,
            ExactCheckpointStoreError::InvalidRoot {
                reason: "snapshot semantic basis mismatch"
            }
        ),
        "unexpected forged-root error: {error:?}"
    );
}

fn snapshot(name: &str) -> QemuVmSnapshot {
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.exact-checkpoint-store",
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
    .expect("build checkpoint");
    QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
        .expect("build snapshot")
}

fn snapshot_with_scheduler(name: &str) -> (QemuVmSnapshot, SingleSchedulerCheckpoint) {
    let scenario =
        ScenarioDef::from_canonical_material("crucible.test.exact-checkpoint-store", name);
    let configuration = Configuration::genesis(scenario.clone());
    let scheduler_scenario = SchedulerLivenessScenario::from_canonical_material(
        name,
        Shift::new(0).expect("zero shift"),
        1,
        SimInstant { nanos: 1 },
        Vec::new(),
        Vec::new(),
    )
    .with_scenario_def(scenario);
    let scheduler = SingleScheduler::new(scheduler_scenario).expect("build scheduler");
    let scheduler_checkpoint = scheduler.checkpoint().expect("capture scheduler");
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        scheduler_checkpoint.frontier(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("build checkpoint");
    let materialized = MaterializedState::from_components(
        BTreeMap::new(),
        BTreeMap::new(),
        scheduler_checkpoint
            .scheduler_state()
            .expect("scheduler projection"),
        scheduler_checkpoint.future_decision_rng_state().clone(),
        scheduler_checkpoint.event_log_offset(),
    );
    let checkpoint = checkpoint.with_materialized_state(Some(materialized));
    let snapshot = QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
        .expect("build snapshot");
    (snapshot, scheduler_checkpoint)
}

fn typed_id(tag: &str, kind: &str, version: u32, byte: u8) -> String {
    format!("{tag}@{kind}.{version}.{}", encode_hex(&[byte; 32]))
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
