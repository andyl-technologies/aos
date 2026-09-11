//! Packaged executor composition, endpoint, and lifecycle regression tests.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, ExecutionFingerprint,
    FingerprintSample, NodeId, Plan, Properties, QuantumOutcome, QuantumRequest,
    QuantumTerminalVerdict, ScenarioDef, ScenarioDefForm, SchedulerError, SchedulerEventLogEntry,
    Seed, VirtualTime, World,
};
use crucible_api::{ProductionFaultEvidenceSnapshot, ProductionVmNodeReplayLaunchProfile};
use crucible_campaign::{
    AssignmentId, AttemptId, AuthenticatedFindingExactCheckpoint, BudgetGrant, CampaignCommandId,
    CampaignControlAction, CampaignLineage, CampaignLineageId, CampaignMode,
    CampaignOperationalStatus, CampaignPolicy, CampaignSeed, CampaignWorldStatus, ConfigurationId,
    ControlRequest, CoverageProjection, ExactCheckpointId, ExactRational, ExecutionId,
    ExecutionRetentionIntent, ExecutorClient, ExplorerPolicy, FairnessPolicy,
    FindingCandidateBundle, FindingCandidateBundleId, FindingExactCheckpointAuthenticationError,
    FindingExactCheckpointAuthenticator, FindingExactPins, FindingKind,
    FindingMinimizationEvidence, FindingSignature, FindingSignatureMinimizationEvidence,
    FindingTarget, MeasurementSet, Observation, ObservationCandidate, PinChange, PinRequest,
    PinRetention, ProgressiveWideningPolicy, PropertyVerdictSet, PuctPolicy, RetentionPolicy,
    ScenarioDefId, StopOutcome, SubmitAttemptRequest,
};
use crucible_cas::content_envelope::{ContentChild, ContentEnvelope};
use crucible_cas::content_store::{
    BlobHandle, BlobStoreAdmin, ContentId, DirectoryBlobBackend, DirectoryRefBackend,
    ImmutableBlobBackend, MemoryBlobBackend, MemoryRefBackend, ObjectKind,
    PlannedDeleteDisposition,
};
use crucible_protocol::SelectionReply;
use crucible_qemu::{
    QemuChildProcessContract, QemuLaunchArtifactIdentityError, QemuLaunchResourceRequirements,
    QemuNodeChild, QemuNodeSelectablePendingRequest, QemuPreparedRunDirectory,
    QemuReplayOracleValidation, QemuVmSnapshot,
};

use super::*;
use crate::{
    AssignmentLedger, AttemptExecutionContext, AttemptExecutionKey, AttemptExecutionOrigin,
    AttemptExecutionRuntimeBasis, AttemptStateCas, AttemptWorkResult, AttemptWorkerFailure,
    CompletedFindingCandidate, DirectoryAssignmentLedger, DirectoryExactPinMaterializationStore,
    DirectoryPreparedResultJournal, EXACT_PIN_MATERIALIZATION_DIRECTORY, ExactCheckpointStore,
    ExactPinMaterializationSelection, ExactPinRetentionAdmin, HotCheckpointResourceProfile,
    LocalAttemptWorker, LoopbackExecutorService, QemuAttemptCancellationSignal,
    QemuFreshAttemptLifecycleFactory, QemuFreshAttemptLifecycleOwner, QueuedAttempt,
};

#[derive(Debug)]
struct UnusedHostFactory;

#[derive(Debug)]
struct UnusedHostOwner;

#[derive(Clone, Debug)]
struct UnusedCancellationSignal;

impl QemuAttemptCancellationSignal for UnusedCancellationSignal {
    fn signal(&self) -> Result<(), QemuVmRealizationError> {
        Ok(())
    }
}

impl QemuAttemptHostResourceFactory for UnusedHostFactory {
    type Owner = UnusedHostOwner;

    fn begin(
        &mut self,
        _resources: AttemptResourceLimits,
    ) -> Result<Self::Owner, QemuVmRealizationError> {
        Err(QemuVmRealizationError::Executor {
            operation: "begin unused packaged test host",
            message: String::from("test does not execute a guest"),
        })
    }
}

impl QemuAttemptHostResourceOwner for UnusedHostOwner {
    type CancellationSignal = UnusedCancellationSignal;

    fn resource_limits(&self) -> AttemptResourceLimits {
        resources()
    }

    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        Err(unused_host_error())
    }

    fn prepare_generation_run_directory(
        &mut self,
        _requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        Err(unused_host_error())
    }

    fn cancellation_signal(&self) -> Result<Self::CancellationSignal, QemuVmRealizationError> {
        Ok(UnusedCancellationSignal)
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        Err(unused_host_error())
    }

    fn retain_failed_launch_child(&mut self, _child: QemuNodeChild) {}

    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        Ok(())
    }

    fn quarantine(&mut self) {}
}

struct UnusedPromotionWorker;

impl LocalCheckpointPromotionWorker for UnusedPromotionWorker {
    type Error = ();

    fn prepare(
        &mut self,
        _work: crate::CheckpointPromotionRestartWork,
        _cancellation: crate::ExecutionCancellation,
    ) -> Result<crate::PreparedPausedCheckpointPromotionRestart, crate::AttemptWorkerFailure<()>>
    {
        Err(crate::AttemptWorkerFailure::Terminal(()))
    }
}

fn unused_host_error() -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation: "use unused packaged test host",
        message: String::from("test does not execute a guest"),
    }
}

fn resources() -> AttemptResourceLimits {
    AttemptResourceLimits::new(2, 512 * 1024 * 1024, 1024 * 1024 * 1024, 50_000)
        .expect("resource ceiling")
}

fn profile() -> ExecutorCompatibilityProfile {
    ExecutorCompatibilityProfile::new(
        "crucible-test",
        "qemu-test",
        std::collections::BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("compatibility profile")
}

fn config(directory: &tempfile::TempDir, worker_count: usize) -> PackagedQemuExecutorConfig {
    let metadata = std::fs::metadata(directory.path()).expect("temporary directory metadata");
    use std::os::unix::fs::MetadataExt;
    let endpoint = ExecutorLoopbackEndpointConfig::new(
        directory.path().join("executor.sock"),
        metadata.uid(),
        metadata.gid(),
        0o600,
    )
    .expect("executor endpoint");
    let host = LinuxQemuAttemptHostConfig::new(
        "/sys/fs/cgroup/crucible-packaged-test",
        "/var/lib/crucible-packaged-test",
        "packaged-test",
        1,
        2,
        metadata.uid().checked_add(1).expect("child user ID"),
        metadata.gid().checked_add(1).expect("child group ID"),
        32,
        1024,
        Duration::from_secs(1),
    )
    .expect("host configuration");
    PackagedQemuExecutorConfig::new(
        BTreeSet::from([CampaignName::new("packaged").expect("campaign name")]),
        endpoint,
        ExecutorLoopbackServerConfig::default(),
        directory.path().join("ledger"),
        1024 * 1024,
        DaemonEpoch::from_bytes([0x61; 16]).expect("daemon epoch"),
        ExecutorCapacity::new(2, 2, 512 * 1024 * 1024, 1024 * 1024 * 1024, 50_000)
            .expect("executor capacity"),
        worker_count,
        "x86_64",
        "deterministic-tcg-v1",
        CampaignHash::derive("crucible.test.packaged-executor-store.v1", b"local"),
        ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state"),
        host,
    )
    .expect("packaged executor config")
}

fn hot_fork_retention(
    directory: &tempfile::TempDir,
) -> DirectoryHotCheckpointFallbackRetentionStore {
    DirectoryHotCheckpointFallbackRetentionStore::open(directory.path().join("hot-fallbacks"))
        .expect("open test hot-fallback catalog")
}

#[test]
fn packaged_executor_serves_the_exact_composed_description_and_joins() {
    let directory = tempfile::tempdir().expect("packaged executor directory");
    let config = config(&directory, 2);
    let socket = config.endpoint().path().to_owned();
    let repository = repository_with_campaigns(&[("packaged", b"shared", "qemu-test")]);
    let status_repository = Arc::clone(&repository);
    let service = compose_packaged_qemu_executor(
        repository,
        Arc::new(crucible_cas::content_store::DirectoryBlobBackend::new(
            "packaged-executor-checkpoints",
            directory.path().join("shared-store"),
        )),
        profile(),
        scenario_artifact(),
        config,
        UnusedHostFactory,
    )
    .expect("compose packaged executor");
    let executor = AttachedPackagedQemuExecutor::start(service).expect("start packaged executor");

    let campaign = CampaignName::new("packaged").expect("campaign name");
    let snapshot = status_repository
        .head(campaign.as_str())
        .expect("campaign head")
        .snapshot_id();
    let status = executor
        .operational_status_provider()
        .operational_status(&campaign, snapshot);
    let CampaignOperationalStatus::Observed(evidence) = status else {
        panic!("packaged executor status must be observed");
    };
    assert_eq!(evidence.daemon_epoch().as_bytes(), [0x61; 16]);
    assert_eq!(evidence.worlds(), CampaignWorldStatus::default());
    assert_eq!(evidence.retained_checkpoint_roots(), 0);
    assert_eq!(evidence.materialized_checkpoints(), 0);

    let stream = UnixStream::connect(socket).expect("connect packaged executor");
    let service = LoopbackExecutorService::new(stream).expect("executor protocol");
    let mut client = ExecutorClient::new(service);
    let description = client.describe_executor().expect("describe executor");
    assert_eq!(description.daemon_epoch().as_bytes(), [0x61; 16]);
    assert_eq!(description.capabilities().maximum_slots(), 2);
    assert_eq!(description.capabilities().resource_ceiling(), resources());
    assert_eq!(
        description.capabilities().materialization(),
        &BTreeSet::from([ExecutorMaterializationCapability::ThinReplay])
    );

    drop(client);
    let report = executor
        .shutdown_and_join()
        .expect("join packaged executor");
    assert_eq!(report.pool().executions(), 0);
    assert_eq!(report.pool().active(), 0);
}

#[test]
fn packaged_startup_completes_pending_observation_and_finding_handoff() {
    let directory = tempfile::tempdir().expect("packaged restart directory");
    let mut config = config(&directory, 1);
    config.lifecycle = ProductionVmLifecycleConfig::new(
        "qemu",
        "plugin",
        "kernel",
        "root",
        directory.path().join("run-state"),
    );
    let repository = repository_with_campaigns(&[("packaged", b"shared", "qemu-test")]);
    let (key, candidate) = retain_packaged_pending_finding(&repository, config.ledger_root());

    let service = compose_packaged_qemu_executor(
        Arc::clone(&repository),
        Arc::new(DirectoryBlobBackend::new(
            "packaged-restart-checkpoints",
            directory.path().join("checkpoints"),
        )),
        profile(),
        scenario_artifact(),
        config.clone(),
        UnusedHostFactory,
    )
    .expect("packaged startup reconciles pending finding");
    let executor = AttachedPackagedQemuExecutor::start(service).expect("start packaged executor");
    executor
        .shutdown_and_join()
        .expect("join reconciled packaged executor");

    let campaign = CampaignName::new("packaged").expect("campaign name");
    let current = repository
        .head(campaign.as_str())
        .expect("reconciled packaged head")
        .snapshot_id();
    let publication = repository
        .incorporate_finding_candidate_bundle(campaign.as_str(), current, candidate)
        .expect("replay startup-incorporated finding");
    assert!(publication.replayed);
    repository
        .authenticate_current_finding_candidate_incorporation(
            &campaign,
            publication.finding,
            candidate,
        )
        .expect("startup finding remains authenticated");

    let ledger = DirectoryAssignmentLedger::open(config.ledger_root())
        .expect("reopen reconciled packaged ledger");
    assert!(matches!(
        ledger.load_attempt(key).expect("load packaged completion"),
        Some(AttemptRuntimeState::Completed {
            finding_candidate: CompletedFindingCandidate::Acknowledged(retained),
            ..
        }) if retained == candidate
    ));
}

struct CompleteRecoveryCheckpointAuthenticator {
    source: Arc<MemoryBlobBackend>,
}

impl FindingExactCheckpointAuthenticator for CompleteRecoveryCheckpointAuthenticator {
    fn authenticate_finding_exact_checkpoint(
        &self,
        _checkpoint: ExactCheckpointId,
        scenario: ScenarioDefId,
        _scenario_artifact: crucible_campaign::ScenarioArtifactId,
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

fn complete_recovery_checkpoint_source() -> (Arc<MemoryBlobBackend>, ExactCheckpointId) {
    let source = Arc::new(MemoryBlobBackend::new(
        "packaged-complete-recovery-checkpoint",
        64 * 1024 * 1024,
    ));
    let leaf_bytes = b"packaged complete recovery exact leaf".to_vec();
    let leaf = ContentId::for_bytes(ObjectKind::DeviceState, 5, &leaf_bytes);
    source
        .put_if_absent(leaf, &BlobHandle::from_bytes(leaf_bytes))
        .expect("publish recovery checkpoint leaf");
    let root = ContentEnvelope::new(
        "crucible.test.packaged-complete-recovery-root",
        4,
        BTreeSet::from([ContentChild::new("leaf", leaf).expect("root leaf")]),
        b"packaged complete recovery exact root".to_vec(),
    )
    .expect("recovery checkpoint root");
    let root_id = root.content_id(ObjectKind::ExactManifest);
    source
        .put_if_absent(root_id, &BlobHandle::from_bytes(root.canonical_bytes()))
        .expect("publish recovery checkpoint root");

    (
        source,
        ExactCheckpointId::parse(&format!(
            "crucible.executor.exact-checkpoint-root@{root_id}"
        ))
        .expect("recovery checkpoint ID"),
    )
}

#[derive(Clone, Copy)]
enum CompleteRecoveryCorruption {
    None,
    MissingDigest,
    MismatchedDigest,
    MissingJournal,
    MissingReplayCaptureChild,
}

fn seed_complete_packaged_recovery(
    corruption: CompleteRecoveryCorruption,
) -> (
    tempfile::TempDir,
    Arc<CampaignRepository>,
    PackagedQemuExecutorConfig,
    ExecutorCompatibilityProfile,
    crucible_campaign::ScenarioArtifactId,
    AttemptExecutionKey,
    FindingCandidateBundleId,
    std::path::PathBuf,
) {
    let directory = tempfile::tempdir().expect("complete recovery directory");
    let mut config = config(&directory, 1);
    config.lifecycle = ProductionVmLifecycleConfig::new(
        "qemu",
        "plugin",
        "kernel",
        "root",
        directory.path().join("run-state"),
    );
    let campaign_blobs = Arc::new(DirectoryBlobBackend::new(
        "packaged-complete-recovery-campaign",
        directory.path().join("campaign-store"),
    ));
    let repository = Arc::new(CampaignRepository::new(
        campaign_blobs.clone(),
        Arc::new(DirectoryRefBackend::new(
            directory.path().join("campaign-refs"),
        )),
    ));
    let (checkpoint_source, checkpoint) = complete_recovery_checkpoint_source();
    let fixture = crate::crucible_artifact::tests::prepared_finding_recovery_fixture(
        &repository,
        "packaged",
        checkpoint,
    );
    let profile = ExecutorCompatibilityProfile::from_lineage(&fixture.lineage);
    let scenario_artifact = fixture.lineage.scenario_content();
    let store = CampaignExecutorStore::with_finding_exact_checkpoint_authenticator(
        Arc::clone(&repository),
        Arc::new(CompleteRecoveryCheckpointAuthenticator {
            source: checkpoint_source,
        }),
    );
    crate::executor_worker::publish_prepared_semantic_attempt_result(&store, &fixture.result)
        .expect("publish complete V5 recovery result");
    if matches!(
        corruption,
        CompleteRecoveryCorruption::MissingReplayCaptureChild
    ) {
        let mut inventory = campaign_blobs
            .acquire_inventory_fence()
            .expect("acquire campaign inventory for recovery corruption");
        assert_eq!(
            inventory
                .delete_candidate(fixture.replay_capture_child)
                .expect("remove recovery replay capture child"),
            PlannedDeleteDisposition::Deleted
        );
    }

    let observation = fixture
        .observation
        .observation()
        .id()
        .expect("complete recovery observation ID");
    let candidate = fixture
        .result
        .finding()
        .expect("complete recovery finding")
        .id()
        .expect("complete recovery candidate ID");
    let retention_basis = repository
        .attempt_retention_policy_basis_at(
            repository
                .head("packaged")
                .expect("complete recovery source head")
                .snapshot_id(),
            fixture.attempt,
        )
        .expect("complete recovery request retention basis");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0xb1; 16]).expect("assignment"),
        DaemonEpoch::from_bytes([0x61; 16]).expect("daemon epoch"),
        fixture.lineage.id().expect("recovery lineage ID"),
        fixture.attempt,
        resources(),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("complete recovery request")
    .with_retention_policy_basis(retention_basis)
    .expect("bind complete recovery request policy");
    let key = AttemptExecutionKey::for_request(&request);
    let execution = ExecutionId::from_bytes([0xb2; 16]).expect("recovery execution");
    let journal_namespace = config
        .lifecycle
        .run_state_root()
        .join(PACKAGED_PREPARED_RESULT_NAMESPACE);
    std::fs::create_dir_all(&journal_namespace).expect("create recovery journal namespace");
    let (journal, _) = DirectoryPreparedResultJournal::create(
        &journal_namespace,
        key,
        execution,
        MAX_PREPARED_SEMANTIC_RESULT_BYTES,
        fixture.result,
    )
    .expect("create complete recovery journal");
    let journal_root = journal.root().to_path_buf();
    let journal_digest = journal.prepared_result_digest();
    drop(journal);
    if matches!(corruption, CompleteRecoveryCorruption::MissingJournal) {
        std::fs::remove_dir_all(&journal_root).expect("remove recovery journal");
    }
    let prepared_result_digest = match corruption {
        CompleteRecoveryCorruption::MissingDigest => None,
        CompleteRecoveryCorruption::MismatchedDigest => Some(CampaignHash::derive(
            "crucible.test.packaged-complete-recovery.wrong-digest.v1",
            b"wrong",
        )),
        CompleteRecoveryCorruption::None
        | CompleteRecoveryCorruption::MissingJournal
        | CompleteRecoveryCorruption::MissingReplayCaptureChild => Some(journal_digest),
    };
    let completed = AttemptRuntimeState::Completed {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution,
        observation,
        finding_candidate: CompletedFindingCandidate::Pending(candidate),
        prepared_result_digest,
    };
    let mut ledger = DirectoryAssignmentLedger::open(config.ledger_root())
        .expect("open complete recovery ledger");
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, None, Some(completed))
            .expect("seed complete recovery ledger"),
        AttemptStateCas::Advanced
    );

    (
        directory,
        repository,
        config,
        profile,
        scenario_artifact,
        key,
        candidate,
        journal_root,
    )
}

#[test]
fn packaged_startup_authenticates_complete_v5_recovery_before_ref_mutation() {
    let (_directory, repository, config, profile, scenario_artifact, key, candidate, journal_root) =
        seed_complete_packaged_recovery(CompleteRecoveryCorruption::None);
    let checkpoint_backend = Arc::new(DirectoryBlobBackend::new(
        "packaged-complete-recovery-checkpoints",
        config.lifecycle.run_state_root().join("checkpoint-store"),
    ));
    let service = compose_packaged_qemu_executor(
        Arc::clone(&repository),
        checkpoint_backend,
        profile,
        scenario_artifact,
        config.clone(),
        UnusedHostFactory,
    )
    .expect("authenticate complete V5 packaged recovery");
    let executor = AttachedPackagedQemuExecutor::start(service).expect("start recovered executor");
    executor
        .shutdown_and_join()
        .expect("join recovered executor");

    let ledger = DirectoryAssignmentLedger::open(config.ledger_root())
        .expect("reopen recovered assignment ledger");
    assert!(matches!(
        ledger.load_attempt(key).expect("load recovered completion"),
        Some(AttemptRuntimeState::Completed {
            finding_candidate: CompletedFindingCandidate::Acknowledged(retained),
            prepared_result_digest: Some(_),
            ..
        }) if retained == candidate
    ));
    assert!(!journal_root.exists());
    let campaign = CampaignName::new("packaged").expect("campaign name");
    let current = repository
        .head(campaign.as_str())
        .expect("recovered campaign head")
        .snapshot_id();
    let publication = repository
        .incorporate_finding_candidate_bundle(campaign.as_str(), current, candidate)
        .expect("cold replay complete recovered candidate");
    assert!(publication.replayed);
    repository
        .authenticate_current_finding_candidate_incorporation(
            &campaign,
            publication.finding,
            candidate,
        )
        .expect("complete recovered candidate remains authenticated");
}

#[test]
fn packaged_complete_v5_recovery_rejects_missing_or_mismatched_journal_binding() {
    for corruption in [
        CompleteRecoveryCorruption::MissingDigest,
        CompleteRecoveryCorruption::MismatchedDigest,
        CompleteRecoveryCorruption::MissingJournal,
    ] {
        let (_directory, repository, config, profile, scenario_artifact, key, candidate, _) =
            seed_complete_packaged_recovery(corruption);
        let head_before = repository
            .head("packaged")
            .expect("head before rejected recovery")
            .snapshot_id();
        let checkpoint_backend = Arc::new(DirectoryBlobBackend::new(
            "packaged-rejected-complete-recovery-checkpoints",
            config.lifecycle.run_state_root().join("checkpoint-store"),
        ));
        let error = match compose_packaged_qemu_executor(
            Arc::clone(&repository),
            checkpoint_backend,
            profile,
            scenario_artifact,
            config.clone(),
            UnusedHostFactory,
        ) {
            Ok(_) => panic!("unauthenticated complete V5 recovery must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            PackagedQemuExecutorError::FindingRestart(
                crate::FindingCandidateRestartError::RecoveryAuthentication
            )
        ));
        assert_eq!(
            repository
                .head("packaged")
                .expect("head after rejected recovery")
                .snapshot_id(),
            head_before
        );
        let ledger = DirectoryAssignmentLedger::open(config.ledger_root())
            .expect("reopen rejected recovery ledger");
        assert!(matches!(
            ledger.load_attempt(key).expect("load rejected completion"),
            Some(AttemptRuntimeState::Completed {
                finding_candidate: CompletedFindingCandidate::Pending(retained),
                ..
            }) if retained == candidate
        ));
    }
}

#[test]
fn packaged_complete_v5_recovery_rejects_missing_capture_child_before_ref_mutation() {
    let (_directory, repository, config, profile, scenario_artifact, key, candidate, _) =
        seed_complete_packaged_recovery(CompleteRecoveryCorruption::MissingReplayCaptureChild);
    let head_before = repository
        .head("packaged")
        .expect("head before rejected recovery")
        .snapshot_id();
    let checkpoint_backend = Arc::new(DirectoryBlobBackend::new(
        "packaged-missing-capture-recovery-checkpoints",
        config.lifecycle.run_state_root().join("checkpoint-store"),
    ));

    let error = match compose_packaged_qemu_executor(
        Arc::clone(&repository),
        checkpoint_backend,
        profile,
        scenario_artifact,
        config.clone(),
        UnusedHostFactory,
    ) {
        Ok(_) => panic!("recovery with a missing replay capture child must fail"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        PackagedQemuExecutorError::FindingRestart(
            crate::FindingCandidateRestartError::RecoveryAuthentication
        )
    ));
    assert_eq!(
        repository
            .head("packaged")
            .expect("head after rejected recovery")
            .snapshot_id(),
        head_before
    );
    let ledger = DirectoryAssignmentLedger::open(config.ledger_root())
        .expect("reopen rejected recovery ledger");
    assert!(matches!(
        ledger.load_attempt(key).expect("load rejected completion"),
        Some(AttemptRuntimeState::Completed {
            finding_candidate: CompletedFindingCandidate::Pending(retained),
            ..
        }) if retained == candidate
    ));
}

#[test]
fn packaged_executor_advertises_exact_restore_with_one_owner_per_worker() {
    let directory = tempfile::tempdir().expect("packaged executor directory");
    let config = config(&directory, 2);
    let socket = config.endpoint().path().to_owned();
    let repository = repository_with_campaigns(&[("packaged", b"shared", "qemu-test")]);
    let service = compose_packaged_qemu_executor_with_checkpoint_promotions(
        repository,
        Arc::new(crucible_cas::content_store::DirectoryBlobBackend::new(
            "packaged-executor-promoted-checkpoints",
            directory.path().join("shared-store"),
        )),
        PackagedCampaignBasis {
            profile: profile(),
            scenarios: BTreeSet::from([scenario_artifact()]),
            sources: BTreeMap::new(),
        },
        config,
        UnusedHostFactory,
        vec![UnusedPromotionWorker, UnusedPromotionWorker],
    )
    .expect("compose promotion-enabled packaged executor");
    let executor = AttachedPackagedQemuExecutor::start(service).expect("start packaged executor");

    let stream = UnixStream::connect(socket).expect("connect packaged executor");
    let service = LoopbackExecutorService::new(stream).expect("executor protocol");
    let mut client = ExecutorClient::new(service);
    let description = client.describe_executor().expect("describe executor");
    assert_eq!(
        description.capabilities().materialization(),
        &BTreeSet::from([
            ExecutorMaterializationCapability::ExactRestore,
            ExecutorMaterializationCapability::ThinReplay,
        ])
    );

    drop(client);
    let report = executor
        .shutdown_and_join()
        .expect("join promotion-enabled executor");
    assert_eq!(report.pool().promotion_workers(), 2);
    assert_eq!(report.pool().promotions_active(), 0);
    assert_eq!(report.pool().promotions_queued(), 0);
}

#[test]
fn packaged_executor_config_rejects_workers_beyond_slots() {
    let directory = tempfile::tempdir().expect("packaged executor directory");
    let error = PackagedQemuExecutorConfig::new(
        config(&directory, 1).campaigns.clone(),
        config(&directory, 1).endpoint.clone(),
        ExecutorLoopbackServerConfig::default(),
        directory.path().join("ledger-overflow"),
        1,
        DaemonEpoch::from_bytes([0x62; 16]).expect("daemon epoch"),
        ExecutorCapacity::new(1, 1, 1, 0, 1).expect("capacity"),
        2,
        "x86_64",
        "deterministic-tcg-v1",
        CampaignHash::derive("crucible.test.packaged-executor-store.v1", b"overflow"),
        ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state"),
        config(&directory, 1).host.clone(),
    )
    .expect_err("worker count should exceed slots");
    assert_eq!(error, PackagedQemuExecutorConfigError::WorkersExceedSlots);
}

#[test]
fn packaged_executor_boundary_diagnostics_are_explicit_and_bounded() {
    let directory = tempfile::tempdir().expect("packaged executor directory");
    let config = config(&directory, 1);
    assert_eq!(config.guest_selectable_boundary_diagnostics(), None);

    let diagnostics = GuestSelectableBoundaryDiagnosticConfig::new(17).expect("diagnostics");
    let config = config.with_guest_selectable_boundary_diagnostics(diagnostics);

    assert_eq!(
        config.guest_selectable_boundary_diagnostics(),
        Some(diagnostics)
    );
}

#[test]
fn packaged_executor_determinism_finding_verification_is_explicit() {
    let directory = tempfile::tempdir().expect("packaged executor directory");
    let config = config(&directory, 1);
    assert!(!config.verifies_determinism_findings());

    let config = config.with_determinism_finding_verification();

    assert!(config.verifies_determinism_findings());
}

#[test]
fn packaged_hot_fork_config_preserves_launch_authentication_source() {
    let directory = tempfile::tempdir().expect("authentication source directory");
    let lifecycle = ProductionVmLifecycleConfig::new(
        directory.path().join("missing-qemu"),
        directory.path().join("missing-plugin"),
        directory.path().join("kernel"),
        directory.path().join("root"),
        directory.path().join("run-state"),
    );
    let maximum_resources =
        HotCheckpointResourceProfile::new(1, 0, 1, 1, 1, 0).expect("hot-fork resource profile");
    let limits = HotCheckpointLimits::new(1, maximum_resources, 1, 1).expect("hot-fork limits");

    let error = PackagedQemuHotForkConfig::authenticate(
        &lifecycle,
        limits,
        HotCheckpointHotnessSignals::new(),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .expect_err("missing launch artifact must fail authentication");
    let source = std::error::Error::source(&error).expect("typed authentication source");

    assert!(
        source
            .downcast_ref::<QemuLaunchArtifactIdentityError>()
            .is_some()
    );
}

#[test]
fn packaged_executor_config_rejects_an_empty_campaign_set() {
    let directory = tempfile::tempdir().expect("packaged executor directory");
    let fixture = config(&directory, 1);
    let error = PackagedQemuExecutorConfig::new(
        BTreeSet::new(),
        fixture.endpoint.clone(),
        ExecutorLoopbackServerConfig::default(),
        directory.path().join("ledger-empty"),
        1,
        DaemonEpoch::from_bytes([0x63; 16]).expect("daemon epoch"),
        ExecutorCapacity::new(1, 1, 1, 0, 1).expect("capacity"),
        1,
        "x86_64",
        "deterministic-tcg-v1",
        CampaignHash::derive("crucible.test.packaged-executor-store.v1", b"empty"),
        ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state"),
        fixture.host.clone(),
    )
    .expect_err("empty campaign set must fail");
    assert_eq!(error, PackagedQemuExecutorConfigError::NoCampaigns);
}

fn scenario_artifact() -> ScenarioArtifactId {
    ScenarioArtifactId::parse(&format!(
        "crucible.campaign.scenario-artifact@{}",
        ContentId::for_bytes(ObjectKind::Scenario, 1, b"packaged-scenario").encode()
    ))
    .expect("scenario artifact ID")
}

fn repository_with_campaigns(campaigns: &[(&str, &[u8], &str)]) -> Arc<CampaignRepository> {
    repository_with_closure_schema(campaigns, crate::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION)
}

fn repository_with_closure_schema(
    campaigns: &[(&str, &[u8], &str)],
    closure_schema: u32,
) -> Arc<CampaignRepository> {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "packaged-campaign-basis",
            64 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    for (name, scenario_label, qemu_build) in campaigns {
        let scenario = ScenarioDefId::from_hash(CampaignHash::derive(
            "crucible.test.packaged-scenario.v1",
            scenario_label,
        ));
        let scenario_content = repository
            .publish_scenario_artifact(scenario, 1, scenario_label.to_vec())
            .expect("publish scenario artifact");
        let genesis = ConfigurationId::from_hash(CampaignHash::derive(
            "crucible.test.packaged-genesis.v1",
            name.as_bytes(),
        ));
        let genesis_content = repository
            .publish_configuration_artifact(
                scenario,
                scenario_content,
                genesis,
                1,
                name.as_bytes().to_vec(),
            )
            .expect("publish genesis artifact");
        let lineage = CampaignLineage::new(
            scenario,
            scenario_content,
            genesis,
            genesis_content,
            "crucible-test",
            *qemu_build,
            std::collections::BTreeMap::from([(String::from("control"), 1)]),
            1,
            closure_schema,
        )
        .expect("campaign lineage");
        let policy = packaged_policy(scenario);
        repository
            .create(name, &lineage, &policy, &std::collections::BTreeMap::new())
            .expect("create campaign");
    }
    repository
}

fn packaged_policy(scenario: ScenarioDefId) -> CampaignPolicy {
    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1).expect("widening coefficient"),
        ExactRational::new(1, 2).expect("widening exponent"),
        1,
        100,
        1,
    )
    .expect("widening policy");
    CampaignPolicy::new(
        scenario,
        CampaignSeed::from_bytes([7; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        },
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness policy"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("campaign policy")
}

fn retain_packaged_pending_finding(
    repository: &CampaignRepository,
    ledger_root: &Path,
) -> (AttemptExecutionKey, FindingCandidateBundleId) {
    const CAMPAIGN: &str = "packaged";

    let created = repository
        .head(CAMPAIGN)
        .expect("created packaged campaign");
    let lineage = repository
        .load_lineage(created.snapshot().lineage())
        .expect("load packaged lineage");
    let funded = repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.packaged-pending-finding.command.v1",
                    b"fund",
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::GrantBudget(
                    BudgetGrant::new(0, 1).expect("packaged attempt budget"),
                ),
            },
        )
        .expect("fund packaged campaign");
    repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.packaged-pending-finding.command.v1",
                    b"resume",
                )),
                expected_snapshot: funded.new_snapshot,
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume packaged campaign");
    let attempt = repository
        .admit_initial_discovery_if_ready(CAMPAIGN)
        .expect("admit packaged discovery")
        .expect("packaged discovery attempt");
    let source_snapshot = repository
        .head(CAMPAIGN)
        .expect("head with packaged discovery")
        .snapshot_id();
    let retention_basis = repository
        .attempt_retention_policy_basis_at(source_snapshot, attempt)
        .expect("packaged finding retention basis");
    let attempt_record = repository
        .load_attempt(attempt)
        .expect("load packaged attempt");
    let measurements = repository
        .publish_measurement_set(&MeasurementSet::new(BTreeMap::new()).expect("measurements"))
        .expect("publish measurements");
    let properties = repository
        .publish_property_verdict_set(
            &PropertyVerdictSet::new(BTreeMap::new()).expect("properties"),
        )
        .expect("publish properties");
    let coverage = repository
        .publish_coverage_projection(
            &CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage"),
        )
        .expect("publish coverage");
    let observation_record = Observation::new(
        attempt,
        lineage.genesis(),
        lineage.genesis_content(),
        attempt_record.path(),
        StopOutcome::TerminalSuccess,
        measurements,
        properties,
        coverage,
        BTreeSet::new(),
    )
    .expect("packaged pending observation");
    let observation = observation_record
        .id()
        .expect("packaged pending observation identity");
    let candidate = ObservationCandidate::new(
        repository
            .load_configuration_artifact(lineage.genesis_content())
            .expect("load packaged genesis artifact"),
        repository
            .load_measurement_set(measurements)
            .expect("load packaged measurements"),
        repository
            .load_property_verdict_set(properties)
            .expect("load packaged properties"),
        repository
            .load_coverage_projection(coverage)
            .expect("load packaged coverage"),
        Vec::new(),
        observation_record,
    )
    .expect("build packaged pending observation candidate");
    assert_eq!(
        repository
            .publish_observation_candidate(&candidate)
            .expect("store packaged pending observation body"),
        observation
    );

    let fingerprint = CampaignHash::derive(
        "crucible.test.packaged-pending-finding.fingerprint.v1",
        b"finding",
    );
    let reproduction_payload = b"packaged pending finding reproduction".to_vec();
    let original = repository
        .publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            lineage.genesis(),
            lineage.genesis_content(),
            fingerprint,
            1,
            reproduction_payload.clone(),
        )
        .expect("publish packaged original reproduction");
    let final_state =
        CampaignHash::derive("crucible.test.packaged-pending-finding.state.v1", b"final");
    let minimization = FindingMinimizationEvidence::new(
        original,
        1,
        b"packaged-pending-finding-policy".to_vec(),
        Vec::new(),
        final_state,
    )
    .expect("packaged minimization evidence");
    let minimized = repository
        .publish_minimized_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            lineage.genesis(),
            lineage.genesis_content(),
            fingerprint,
            1,
            reproduction_payload,
            minimization.clone(),
        )
        .expect("publish packaged minimized reproduction");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        String::from("qemu.packaged-restart-divergence"),
        Some(FindingTarget::Configuration(lineage.genesis_content())),
        BTreeSet::new(),
    )
    .expect("packaged finding signature");
    let signatures = FindingSignatureMinimizationEvidence::new(
        &signature,
        &minimization,
        vec![Some(signature.clone())],
        vec![Some(signature.clone())],
    )
    .expect("packaged signature minimization");
    let exact_retention = crucible_campaign::FindingExactRetention::new(
        retention_basis.snapshot(),
        retention_basis.policy(),
        retention_basis.admission(),
        0,
        crucible_campaign::FindingExactRetentionDisposition::Incomplete(
            crucible_campaign::FindingExactRetentionIncomplete::MissingSafeBoundaryCapture,
        ),
    )
    .expect("incomplete packaged exact retention");
    let bundle = FindingCandidateBundle::new_with_exact_retention(
        observation,
        signature,
        original,
        minimized,
        signatures,
        FindingExactPins::default(),
        None,
        None,
        exact_retention,
    )
    .expect("packaged finding candidate");
    let candidate = repository
        .publish_finding_candidate_bundle(&bundle)
        .expect("publish packaged finding candidate");

    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x67; 16]).expect("assignment"),
        DaemonEpoch::from_bytes([0x61; 16]).expect("daemon epoch"),
        lineage.id().expect("packaged lineage identity"),
        attempt,
        resources(),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("packaged pending request");
    let key = AttemptExecutionKey::for_request(&request);
    let completed = AttemptRuntimeState::Completed {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: ExecutionId::from_bytes([0x68; 16]).expect("execution"),
        observation,
        finding_candidate: CompletedFindingCandidate::Pending(candidate),
        prepared_result_digest: None,
    };
    let mut ledger = DirectoryAssignmentLedger::open(ledger_root).expect("open packaged ledger");
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, None, Some(completed))
            .expect("retain packaged pending finding"),
        AttemptStateCas::Advanced
    );

    (key, candidate)
}

struct ExactPinMaterializerFixture {
    repository: Arc<CampaignRepository>,
    checkpoints: Arc<ExactCheckpointStore>,
    campaign: CampaignName,
    configuration: ConfigurationId,
    checkpoint: ExactCheckpointId,
}

fn exact_pin_materializer_fixture(directory: &tempfile::TempDir) -> ExactPinMaterializerFixture {
    let backend = Arc::new(DirectoryBlobBackend::new(
        "packaged-exact-pin-store",
        directory.path().join("objects"),
    ));
    let repository = Arc::new(CampaignRepository::new(
        backend.clone(),
        Arc::new(MemoryRefBackend::new()),
    ));
    let scenario = ScenarioDef::from_canonical_material(
        "crucible.test.packaged-exact-pin-materializer",
        "scenario",
    );
    let configuration = Configuration::genesis(scenario.clone());
    let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes));
    let configuration_id =
        ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes));
    let scenario_artifact = repository
        .publish_scenario_artifact(scenario_id, 1, b"scenario".to_vec())
        .expect("publish scenario artifact");
    let configuration_artifact = repository
        .publish_configuration_artifact(
            scenario_id,
            scenario_artifact,
            configuration_id,
            1,
            b"configuration".to_vec(),
        )
        .expect("publish configuration artifact");
    let lineage = CampaignLineage::new(
        scenario_id,
        scenario_artifact,
        configuration_id,
        configuration_artifact,
        "crucible-test",
        "qemu-test",
        std::collections::BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("campaign lineage");
    let campaign = CampaignName::new("packaged-exact-pin").expect("campaign name");
    repository
        .create(
            campaign.as_str(),
            &lineage,
            &packaged_policy(scenario_id),
            &std::collections::BTreeMap::new(),
        )
        .expect("create campaign");

    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        VirtualTime::default(),
        std::collections::BTreeMap::new(),
        CheckpointKind::Fat,
        std::collections::BTreeMap::new(),
    )
    .expect("checkpoint");
    let snapshot = QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
        .expect("QEMU snapshot");
    let checkpoint_backend: Arc<dyn ImmutableBlobBackend> = backend;
    let checkpoints = Arc::new(
        ExactCheckpointStore::new(checkpoint_backend, 1024 * 1024).expect("exact checkpoint store"),
    );
    let prepared = checkpoints
        .prepare(&snapshot, BlobHandle::from_bytes(vec![0x5a; 4096]))
        .expect("prepare checkpoint");
    let checkpoint = checkpoints
        .publish(&prepared)
        .expect("publish checkpoint")
        .root();

    ExactPinMaterializerFixture {
        repository,
        checkpoints,
        campaign,
        configuration: configuration_id,
        checkpoint,
    }
}

fn apply_exact_pin(fixture: &ExactPinMaterializerFixture) {
    apply_exact_pin_command(fixture, b"pin", "retain packaged exact checkpoint");
}

fn apply_exact_pin_command(
    fixture: &ExactPinMaterializerFixture,
    command_material: &[u8],
    reason: &str,
) {
    let expected_snapshot = fixture
        .repository
        .head(fixture.campaign.as_str())
        .expect("campaign head")
        .snapshot_id();
    fixture
        .repository
        .apply_pin(
            fixture.campaign.as_str(),
            &PinRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.packaged-exact-pin.command.v1",
                    command_material,
                )),
                expected_snapshot,
                change: PinChange::new(fixture.configuration, Some(PinRetention::Exact), reason)
                    .expect("exact pin change"),
            },
        )
        .expect("apply exact pin");
}

#[test]
fn materializer_status_rejects_a_selection_for_a_superseded_pin_fact() {
    let directory = tempfile::tempdir().expect("packaged exact-pin directory");
    let fixture = exact_pin_materializer_fixture(&directory);
    apply_exact_pin(&fixture);

    let selection = ExactPinMaterializationSelection::prepare(
        &fixture.repository,
        &fixture.checkpoints,
        &fixture.campaign,
        fixture.configuration,
        fixture.checkpoint,
    )
    .expect("prepare exact-pin selection");
    let selection_root = directory.path().join(EXACT_PIN_MATERIALIZATION_DIRECTORY);
    let mut selections = DirectoryExactPinMaterializationStore::open(&selection_root)
        .expect("open exact-pin selections");
    selections
        .select(selection)
        .expect("store exact-pin selection");

    apply_exact_pin_command(&fixture, b"replacement-pin", "replace exact pin fact");
    let snapshot = fixture
        .repository
        .head(fixture.campaign.as_str())
        .expect("replacement pin head")
        .snapshot_id();
    let status = exact_pin_materializer::materialization_status(
        &fixture.repository,
        &fixture.campaign,
        snapshot,
        &mut selections,
    )
    .expect("read materialization status");

    assert!(status.selected_roots.is_empty());
}

#[test]
fn packaged_materializer_tracks_a_late_pin_and_promoted_replacement() {
    let directory = tempfile::tempdir().expect("packaged exact-pin directory");
    let fixture = exact_pin_materializer_fixture(&directory);
    let ledger = DirectoryAssignmentLedger::open(directory.path().join("ledger"))
        .expect("assignment ledger");
    let selection_root = directory.path().join(EXACT_PIN_MATERIALIZATION_DIRECTORY);
    let (prepared, observer) = prepare_packaged_exact_pin_materializer(
        Arc::clone(&fixture.repository),
        Arc::clone(&fixture.checkpoints),
        BTreeSet::from([fixture.campaign.clone()]),
        &ledger,
        &selection_root,
    )
    .expect("prepare exact-pin materializer");
    let terminal = Arc::new(AtomicBool::new(false));
    let terminal_signal = Arc::clone(&terminal);
    let owner = prepared
        .start(move || terminal_signal.store(true, Ordering::Release))
        .expect("start exact-pin materializer");

    observer
        .checkpoint_paused(fixture.checkpoint)
        .expect("publish paused checkpoint notification");
    owner.reconcile_now().expect("reconcile checkpoint catalog");
    apply_exact_pin(&fixture);
    owner.reconcile_now().expect("reconcile later exact pin");
    let snapshot = fixture
        .repository
        .head(fixture.campaign.as_str())
        .expect("pinned campaign head")
        .snapshot_id();
    let selected = owner
        .status_handle()
        .status(&fixture.campaign, snapshot)
        .expect("materializer status after pin");
    assert_eq!(
        selected.selected_roots,
        BTreeSet::from([fixture.checkpoint])
    );

    let source = fixture
        .checkpoints
        .load(fixture.checkpoint)
        .expect("load raw checkpoint");
    let replacement = fixture
        .checkpoints
        .prepare(source.snapshot(), BlobHandle::from_bytes(vec![0xa5; 4096]))
        .and_then(|prepared| fixture.checkpoints.publish(&prepared))
        .expect("publish replacement checkpoint")
        .root();
    assert_ne!(replacement, fixture.checkpoint);
    observer
        .checkpoint_promoted(fixture.checkpoint, replacement)
        .expect("publish promoted checkpoint notification");
    owner
        .reconcile_now()
        .expect("reconcile promoted checkpoint catalog");
    let selected = owner
        .status_handle()
        .status(&fixture.campaign, snapshot)
        .expect("materializer status after promotion");
    assert_eq!(selected.selected_roots, BTreeSet::from([replacement]));
    owner.join().expect("join exact-pin materializer");
    assert!(!terminal.load(Ordering::Acquire));

    let mut selections = DirectoryExactPinMaterializationStore::open(&selection_root)
        .expect("reopen exact-pin selections");
    let mut fence = selections
        .acquire_exact_pin_retention_fence()
        .expect("exact-pin fence");
    let selected = fence
        .selection(&fixture.campaign, fixture.configuration)
        .expect("read exact-pin selection")
        .expect("selected exact checkpoint");
    assert_eq!(selected.checkpoint(), replacement);
}

#[derive(Default)]
struct ControlledLifecycleBoundary {
    state: Mutex<(u8, u8)>,
    changed: Condvar,
    requested_fingerprint_nodes: Mutex<Vec<NodeId>>,
    fail_fingerprint_sample: AtomicBool,
    fail_effect_trace: AtomicBool,
}

impl ControlledLifecycleBoundary {
    fn arrive_and_wait(&self, phase: u8) {
        let mut state = self.state.lock().expect("controlled lifecycle state");
        state.0 = phase;
        self.changed.notify_all();
        while state.1 < phase {
            state = self.changed.wait(state).expect("controlled lifecycle wait");
        }
    }

    fn wait_for(&self, phase: u8) {
        let mut state = self.state.lock().expect("controlled lifecycle state");
        while state.0 < phase {
            state = self.changed.wait(state).expect("controlled lifecycle wait");
        }
    }

    fn release(&self, phase: u8) {
        let mut state = self.state.lock().expect("controlled lifecycle state");
        state.1 = phase;
        self.changed.notify_all();
    }
}

struct ControlledLifecycleFactory {
    boundary: Arc<ControlledLifecycleBoundary>,
    fail_shutdown: bool,
}

struct ControlledLifecycle {
    boundary: Arc<ControlledLifecycleBoundary>,
    fail_shutdown: bool,
}

impl QemuFreshAttemptLifecycleFactory for ControlledLifecycleFactory {
    type Lifecycle = ControlledLifecycle;
    type Error = ();

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &ScenarioDefForm,
        _start: &Configuration,
        _signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.boundary.arrive_and_wait(1);
        Ok(ControlledLifecycle {
            boundary: Arc::clone(&self.boundary),
            fail_shutdown: self.fail_shutdown,
        })
    }
}

impl QemuFreshAttemptLifecycleOwner for ControlledLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {
        panic!("controlled lifecycle does not drive a guest")
    }

    fn set_attempt_stop_frontier(
        &mut self,
        _frontier: Option<crucible::VirtualTime>,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        panic!("controlled lifecycle does not drive a guest")
    }

    fn completed_quanta(&self) -> u64 {
        0
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        panic!("controlled lifecycle does not drive a guest")
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        panic!("controlled lifecycle does not capture a checkpoint")
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        panic!("controlled lifecycle does not handle selections")
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &crucible::Configuration,
        _decision: crucible::SelectionDecision,
        _selected: &crucible::Configuration,
        _pending: &QemuNodeSelectablePendingRequest,
        _reply: &SelectionReply,
    ) -> Result<Vec<crucible::SchedulerEventLogEntry>, SchedulerError> {
        panic!("controlled lifecycle does not handle selections")
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &AttemptExecutionContext,
    ) -> Result<crate::CapturedAttemptCheckpoint, SchedulerError> {
        panic!("controlled lifecycle does not capture a checkpoint")
    }

    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, SchedulerError> {
        panic!("controlled lifecycle does not expose replay profiles")
    }

    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        panic!("controlled lifecycle does not expose fault evidence")
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        self.boundary
            .requested_fingerprint_nodes
            .lock()
            .expect("controlled fingerprint requests")
            .push(node);
        if self
            .boundary
            .fail_fingerprint_sample
            .load(Ordering::Acquire)
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("controlled fingerprint failure"),
            });
        }

        Ok(FingerprintSample {
            node: NodeId {
                name: String::from("inner-returned-node"),
            },
            at: VirtualTime { ticks: 73 },
            fingerprint: ExecutionFingerprint {
                hash: ContentHash::from_bytes(b"controlled-inner-fingerprint"),
            },
        })
    }

    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, SchedulerError> {
        if self.boundary.fail_effect_trace.load(Ordering::Acquire) {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("controlled effect-trace failure"),
            });
        }

        Ok(Some(b"controlled-inner-effect-trace".to_vec()))
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.boundary.arrive_and_wait(3);
        if self.fail_shutdown {
            Err(SchedulerError::BoundaryViolation {
                message: String::from("controlled cleanup failure"),
            })
        } else {
            Ok(Vec::new())
        }
    }
}

#[test]
fn packaged_status_lifecycle_delegates_execution_evidence_and_errors() {
    let boundary = Arc::new(ControlledLifecycleBoundary::default());
    boundary.release(1);
    let source = ScenarioDefForm::from_components(
        &World::from_nodes_and_links(Vec::new(), Vec::new()).expect("empty world"),
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(79),
    )
    .expect("delegation scenario");
    let scenario = source.scenario_def();
    let start = Configuration::genesis(scenario.clone());
    let context = AttemptExecutionContext::new(
        resources(),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
    );
    let mut factory = PackagedStatusLifecycleFactory {
        inner: ControlledLifecycleFactory {
            boundary: Arc::clone(&boundary),
            fail_shutdown: false,
        },
        lifecycles: PackagedWorldLifecycleTracker::new(),
    };
    let mut lifecycle = factory
        .start_fresh_lifecycle(
            &scenario,
            &source,
            &start,
            &crucible::SignalFaultCampaignReplayPlan::empty(start.clone()),
            &context,
        )
        .expect("start delegated lifecycle");

    let requested_node = NodeId {
        name: String::from("requested-node"),
    };
    let sample = lifecycle
        .sample_fingerprint(requested_node.clone())
        .expect("delegated fingerprint sample");
    assert_eq!(
        *boundary
            .requested_fingerprint_nodes
            .lock()
            .expect("controlled fingerprint requests"),
        vec![requested_node.clone()]
    );
    assert_eq!(sample.node.name, "inner-returned-node");
    assert_eq!(sample.at, VirtualTime { ticks: 73 });
    assert_eq!(
        sample.fingerprint.hash,
        ContentHash::from_bytes(b"controlled-inner-fingerprint")
    );
    assert_eq!(
        lifecycle
            .resolved_effect_trace()
            .expect("delegated effect trace"),
        Some(b"controlled-inner-effect-trace".to_vec())
    );

    boundary
        .fail_fingerprint_sample
        .store(true, Ordering::Release);
    let fingerprint_error = lifecycle
        .sample_fingerprint(requested_node)
        .expect_err("inner fingerprint failure must propagate");
    assert_eq!(
        fingerprint_error.to_string(),
        "controlled fingerprint failure"
    );

    boundary.fail_effect_trace.store(true, Ordering::Release);
    let effect_error = lifecycle
        .resolved_effect_trace()
        .expect_err("inner effect-trace failure must propagate");
    assert_eq!(effect_error.to_string(), "controlled effect-trace failure");
}

struct ControlledLifecycleWorker {
    lifecycles: PackagedWorldLifecycleTracker,
    boundary: Arc<ControlledLifecycleBoundary>,
    fail_shutdown: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("controlled attempt failed")]
struct ControlledAttemptError;

impl LocalAttemptWorker for ControlledLifecycleWorker {
    type Error = ControlledAttemptError;

    fn execute(&mut self, queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        let source = ScenarioDefForm::from_components(
            &World::from_nodes_and_links(Vec::new(), Vec::new()).expect("empty world"),
            &Plan::empty(),
            &Properties::empty(),
            Seed::from_u64(7),
        )
        .expect("controlled scenario");
        let scenario = source.scenario_def();
        let start = Configuration::genesis(scenario.clone());
        let context = AttemptExecutionContext::new(
            queued.request().resources(),
            queued.request().retention(),
            queued.cancellation().clone(),
            queued.checkpoint_request().clone(),
        )
        .with_runtime_basis(AttemptExecutionRuntimeBasis::new(
            AttemptExecutionKey::new(queued.request().lineage(), queued.request().attempt()),
            queued.execution(),
        ));
        let mut factory = PackagedStatusLifecycleFactory {
            inner: ControlledLifecycleFactory {
                boundary: Arc::clone(&self.boundary),
                fail_shutdown: self.fail_shutdown,
            },
            lifecycles: self.lifecycles.clone(),
        };
        let mut lifecycle = factory
            .start_fresh_lifecycle(
                &scenario,
                &source,
                &start,
                &crucible::SignalFaultCampaignReplayPlan::empty(start.clone()),
                &context,
            )
            .expect("start controlled lifecycle");

        self.boundary.arrive_and_wait(2);
        let cleanup = lifecycle.shutdown();
        assert_eq!(cleanup.is_err(), self.fail_shutdown);
        self.boundary.arrive_and_wait(4);

        AttemptWorkResult::new(
            queued,
            Err(AttemptWorkerFailure::Terminal(ControlledAttemptError)),
        )
    }
}

#[derive(Debug, thiserror::Error)]
#[error("outer model failure")]
struct DiagnosticOuterError(#[source] DiagnosticInnerError);

#[derive(Debug, thiserror::Error)]
#[error("inner model failure")]
struct DiagnosticInnerError(#[source] std::io::Error);

#[test]
fn packaged_attempt_failure_diagnostic_preserves_classification_and_bounded_source_chain() {
    let execution = ExecutionId::from_bytes([0x97; 16]).expect("execution");
    let failure = AttemptWorkerFailure::Terminal(crate::RepositoryAttemptWorkerError::Model {
        source: DiagnosticOuterError(DiagnosticInnerError(std::io::Error::other(
            "leaf execution failure",
        ))),
        checkpoint: None,
    });

    let diagnostic = packaged_attempt_failure_diagnostic(execution, &failure);

    assert_eq!(
        diagnostic,
        concat!(
            "packaged campaign execution 97979797979797979797979797979797 failed: ",
            "terminal execution failure: ",
            "attempt execution model failed\n",
            "  caused by [1]: attempt execution model failed\n",
            "  caused by [2]: outer model failure\n",
            "  caused by [3]: inner model failure\n",
            "  caused by [4]: leaf execution failure",
        )
    );

    let oversized = AttemptWorkerFailure::Terminal(crate::RepositoryAttemptWorkerError::Model {
        source: DiagnosticOuterError(DiagnosticInnerError(std::io::Error::other(
            "x".repeat(MAX_PACKAGED_ATTEMPT_FAILURE_DIAGNOSTIC_BYTES * 2),
        ))),
        checkpoint: None,
    });
    let diagnostic = packaged_attempt_failure_diagnostic(execution, &oversized);

    assert_eq!(
        diagnostic.len(),
        MAX_PACKAGED_ATTEMPT_FAILURE_DIAGNOSTIC_BYTES
    );
    assert!(diagnostic.ends_with("\n  ... diagnostic truncated"));
}

#[test]
fn packaged_attempt_failure_diagnostic_retains_prior_failure_after_cleanup_error() {
    let execution = ExecutionId::from_bytes([0x98; 16]).expect("execution");
    let resume_failure = crate::QemuProductionExactResumeExecutionRunnerError::<
        std::io::Error,
        std::io::Error,
    >::CleanupAfterRunner {
        failure: Box::new(
            crate::QemuProductionExactResumeExecutionRunnerError::Lifecycle(std::io::Error::other(
                "original resume failure",
            )),
        ),
        cleanup: SchedulerError::BoundaryViolation {
            message: String::from("resume cleanup failure"),
        },
    };
    let diagnostic = packaged_attempt_failure_diagnostic(
        execution,
        &AttemptWorkerFailure::Terminal(resume_failure),
    );

    assert!(diagnostic.contains("resume cleanup failure"));
    assert!(diagnostic.contains("caused by [2]: restore production campaign lifecycle"));
    assert!(diagnostic.contains("caused by [3]: original resume failure"));

    let hot_fork_failure = crate::QemuHotForkWorldExecutionRunnerError::<
        std::io::Error,
        std::io::Error,
    >::CleanupAfterRunner {
        failure: Box::new(crate::QemuHotForkWorldExecutionRunnerError::Factory(
            std::io::Error::other("original hot-fork failure"),
        )),
        cleanup: SchedulerError::BoundaryViolation {
            message: String::from("hot-fork cleanup failure"),
        },
    };
    let diagnostic = packaged_attempt_failure_diagnostic(
        execution,
        &AttemptWorkerFailure::Terminal(hot_fork_failure),
    );

    assert!(diagnostic.contains("hot-fork cleanup failure"));
    assert!(diagnostic.contains("caused by [2]: construct production hot-fork world lifecycle"));
    assert!(diagnostic.contains("caused by [3]: original hot-fork failure"));
}

fn controlled_submit_request(epoch: DaemonEpoch) -> SubmitAttemptRequest {
    let typed_id = |tag: &str, kind: &str, byte: u8| {
        format!("{tag}@{kind}.1.{}", format!("{byte:02x}").repeat(32))
    };
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x90; 16]).expect("assignment"),
        epoch,
        CampaignLineageId::parse(&typed_id(
            "crucible.campaign.lineage",
            "campaign-fact",
            0x91,
        ))
        .expect("lineage"),
        AttemptId::parse(&typed_id(
            "crucible.campaign.attempt",
            "campaign-fact",
            0x92,
        ))
        .expect("attempt"),
        resources(),
        ExecutionRetentionIntent::Discard,
    )
    .expect("submit request")
}

#[test]
fn packaged_lifecycle_wrappers_track_real_preparation_shutdown_and_sealing_boundaries() {
    let tracker = PackagedWorldLifecycleTracker::new();
    let boundary = Arc::new(ControlledLifecycleBoundary::default());
    let execution = ExecutionId::from_bytes([0x93; 16]).expect("execution");
    let epoch = DaemonEpoch::from_bytes([0x94; 16]).expect("daemon epoch");
    let queued = QueuedAttempt::from_test_parts(execution, controlled_submit_request(epoch));
    let mut worker = PackagedStatusAttemptWorker {
        inner: ControlledLifecycleWorker {
            lifecycles: tracker.clone(),
            boundary: Arc::clone(&boundary),
            fail_shutdown: false,
        },
        lifecycles: tracker.clone(),
    };
    let thread = thread::spawn(move || worker.execute(queued));
    let runtime = AttemptRuntimeState::Running {
        execution_basis: CampaignHash::derive("packaged-status-lifecycle-test", b"basis"),
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch: epoch,
        execution,
    };
    let activity = BTreeMap::from([(
        execution,
        LocalExecutionActivity {
            execution,
            worker_in_flight: true,
            cancellation_requested: false,
            completion_pending: false,
            cancellation_pending: false,
        },
    )]);

    boundary.wait_for(1);
    let phases = tracker.snapshot().expect("preparation snapshot").phases;
    assert_eq!(
        operational_phase(runtime, epoch, &activity, &phases),
        Ok(Some(OperationalPhase::Preparing))
    );
    boundary.release(1);

    boundary.wait_for(2);
    let phases = tracker.snapshot().expect("installed snapshot").phases;
    assert_eq!(
        operational_phase(runtime, epoch, &activity, &phases),
        Ok(Some(OperationalPhase::Running))
    );
    boundary.release(2);

    boundary.wait_for(3);
    let phases = tracker.snapshot().expect("teardown snapshot").phases;
    assert_eq!(
        operational_phase(runtime, epoch, &activity, &phases),
        Err(())
    );
    boundary.release(3);

    boundary.wait_for(4);
    let phases = tracker.snapshot().expect("post-shutdown snapshot").phases;
    assert_eq!(
        operational_phase(runtime, epoch, &activity, &phases),
        Ok(Some(OperationalPhase::Publishing))
    );
    boundary.release(4);

    let _result = thread.join().expect("controlled lifecycle worker");
    assert!(
        tracker
            .snapshot()
            .expect("completed worker snapshot")
            .phases
            .is_empty()
    );
}

#[test]
fn packaged_lifecycle_wrapper_invalidates_status_after_failed_cleanup() {
    let tracker = PackagedWorldLifecycleTracker::new();
    let boundary = Arc::new(ControlledLifecycleBoundary::default());
    let execution = ExecutionId::from_bytes([0x95; 16]).expect("execution");
    let epoch = DaemonEpoch::from_bytes([0x96; 16]).expect("daemon epoch");
    let queued = QueuedAttempt::from_test_parts(execution, controlled_submit_request(epoch));
    let mut worker = PackagedStatusAttemptWorker {
        inner: ControlledLifecycleWorker {
            lifecycles: tracker.clone(),
            boundary: Arc::clone(&boundary),
            fail_shutdown: true,
        },
        lifecycles: tracker.clone(),
    };
    let thread = thread::spawn(move || worker.execute(queued));

    for phase in 1..=3 {
        boundary.wait_for(phase);
        boundary.release(phase);
    }
    boundary.wait_for(4);
    assert!(tracker.snapshot().is_none());
    boundary.release(4);

    let _result = thread.join().expect("failed-cleanup lifecycle worker");
    assert!(tracker.snapshot().is_none());
}

#[test]
fn packaged_campaign_basis_is_order_independent_and_exact() {
    let repository = repository_with_campaigns(&[
        ("beta", b"shared", "qemu-test"),
        ("alpha", b"shared", "qemu-test"),
    ]);
    let campaigns = BTreeSet::from([
        CampaignName::new("beta").expect("beta campaign"),
        CampaignName::new("alpha").expect("alpha campaign"),
    ]);
    let basis = authenticate_packaged_campaigns(&repository, &campaigns, false)
        .expect("shared packaged campaign basis");
    let alpha = repository.head("alpha").expect("alpha head");
    let lineage = repository
        .load_lineage(alpha.snapshot().lineage())
        .expect("alpha lineage");
    assert_eq!(
        basis.scenarios,
        BTreeSet::from([lineage.scenario_content()])
    );
    assert!(basis.profile.admits(&lineage));
    assert!(basis.sources.is_empty());

    let incompatible = repository_with_campaigns(&[
        ("alpha", b"shared", "qemu-test"),
        ("beta", b"shared", "different-qemu"),
    ]);
    assert!(matches!(
        authenticate_packaged_campaigns(&incompatible, &campaigns, false),
        Err(PackagedQemuExecutorError::CampaignCompatibilityMismatch { campaign })
            if campaign.as_str() == "beta"
    ));

    let multiple_scenarios = repository_with_campaigns(&[
        ("alpha", b"alpha-scenario", "qemu-test"),
        ("beta", b"beta-scenario", "qemu-test"),
    ]);
    let basis = authenticate_packaged_campaigns(&multiple_scenarios, &campaigns, false)
        .expect("one packaged pool admits a bounded scenario catalog");
    assert_eq!(basis.scenarios.len(), 2);
    for campaign in ["alpha", "beta"] {
        let head = multiple_scenarios.head(campaign).expect("campaign head");
        let lineage = multiple_scenarios
            .load_lineage(head.snapshot().lineage())
            .expect("campaign lineage");
        assert!(basis.scenarios.contains(&lineage.scenario_content()));
    }
}

#[test]
fn valid_noncanonical_lineage_declines_genesis_hot_capture() {
    let source = admit_packaged_hot_fork_source_basis(Err(
        AuthenticatedQemuHotForkSourceBasisError::NonCanonicalGenesis,
    ))
    .expect("noncanonical source basis routes to a lower materialization tier");

    assert!(source.is_none());
}

#[test]
fn invalid_campaign_fails_before_operational_owner_mutation() {
    let directory = tempfile::tempdir().expect("packaged executor directory");
    let config = config(&directory, 1);
    let ledger = config.ledger_root().to_owned();
    let socket = config.endpoint().path().to_owned();
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(crucible_cas::content_store::MemoryBlobBackend::new(
            "missing-packaged-campaign",
            1024 * 1024,
        )),
        Arc::new(crucible_cas::content_store::MemoryRefBackend::new()),
    ));

    let checkpoint_backend = Arc::new(crucible_cas::content_store::MemoryBlobBackend::new(
        "invalid-campaign-checkpoints",
        1024 * 1024,
    ));
    let error = match prepare_packaged_qemu_executor(
        repository,
        checkpoint_backend,
        hot_fork_retention(&directory),
        config,
    ) {
        Ok(_) => panic!("missing campaign must fail before executor preparation"),
        Err(error) => error,
    };
    assert!(matches!(error, PackagedQemuExecutorError::Repository(_)));
    assert!(!ledger.exists());
    assert!(!socket.exists());
}

#[test]
fn unsupported_closure_version_fails_before_catalog_or_host_acquisition() {
    let directory = tempfile::tempdir().expect("packaged executor directory");
    let mut config = config(&directory, 1);
    config.campaigns = BTreeSet::from([CampaignName::new("legacy").expect("campaign name")]);
    let ledger = config.ledger_root().to_owned();
    let socket = config.endpoint().path().to_owned();
    // Deliberately not a decodable Crucible scenario: compatibility rejection
    // must precede even catalog decoding, let alone privileged host mutation.
    let repository = repository_with_closure_schema(&[("legacy", b"scenario", "qemu-test")], 2);
    let backend = Arc::new(MemoryBlobBackend::new("legacy-checkpoints", 1024 * 1024));
    let error = match prepare_packaged_qemu_executor(
        repository,
        backend,
        hot_fork_retention(&directory),
        config,
    ) {
        Ok(_) => panic!("legacy closure version must not be advertised by a version-four writer"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        PackagedQemuExecutorError::UnsupportedExactClosureSchema {
            actual: 2,
            supported: 4
        }
    ));
    assert!(!ledger.exists());
    assert!(!socket.exists());
}

#[test]
fn invalid_scenario_fails_before_operational_owner_mutation() {
    let directory = tempfile::tempdir().expect("packaged executor directory");
    let mut config = config(&directory, 1);
    config.campaigns = BTreeSet::from([CampaignName::new("invalid").expect("campaign name")]);
    let ledger = config.ledger_root().to_owned();
    let socket = config.endpoint().path().to_owned();
    let repository = repository_with_campaigns(&[("invalid", b"not-crucible", "qemu-test")]);

    let checkpoint_backend = Arc::new(crucible_cas::content_store::MemoryBlobBackend::new(
        "invalid-scenario-checkpoints",
        1024 * 1024,
    ));
    let error = match prepare_packaged_qemu_executor(
        repository,
        checkpoint_backend,
        hot_fork_retention(&directory),
        config,
    ) {
        Ok(_) => panic!("invalid scenario must fail before executor preparation"),
        Err(error) => error,
    };
    assert!(matches!(error, PackagedQemuExecutorError::Artifact(_)));
    assert!(!ledger.exists());
    assert!(!socket.exists());
}

#[test]
fn packaged_scenario_catalog_charges_an_exact_aggregate_byte_bound() {
    let mut charged = 0;
    charge_packaged_scenario_catalog_bytes(&mut charged, 5, 8)
        .expect("first scenario fits catalog");
    charge_packaged_scenario_catalog_bytes(&mut charged, 3, 8)
        .expect("exact catalog bound is admitted");
    assert_eq!(charged, 8);

    assert!(matches!(
        charge_packaged_scenario_catalog_bytes(&mut charged, 1, 8),
        Err(PackagedQemuExecutorError::ScenarioCatalogBytesExceeded { maximum: 8 })
    ));

    let mut overflow = usize::MAX;
    assert!(matches!(
        charge_packaged_scenario_catalog_bytes(&mut overflow, 1, usize::MAX),
        Err(PackagedQemuExecutorError::ScenarioCatalogBytesExceeded {
            maximum: usize::MAX
        })
    ));
}

#[test]
fn packaged_executor_completion_is_sticky_across_owner_panic() {
    let state = Arc::new((Mutex::new(false), Condvar::new()));
    let completion = PackagedQemuExecutorCompletion {
        state: Arc::clone(&state),
    };
    let owner = thread::spawn(move || {
        let _completion = PackagedQemuExecutorCompletionGuard(state);
        panic!("injected packaged executor owner panic");
    });

    assert!(owner.join().is_err());
    completion.wait();
}

#[test]
fn competing_packaged_startup_preserves_live_native_catalogs() {
    let directory = tempfile::tempdir().expect("packaged competing-start directory");
    let mut config = config(&directory, 1);
    config.lifecycle = ProductionVmLifecycleConfig::new(
        "qemu",
        "plugin",
        "kernel",
        "root",
        directory.path().join("run-state"),
    );
    let run_state_root = config.lifecycle.run_state_root();
    let workers = run_state_root.join("campaign-workers");
    let promotions = run_state_root.join("campaign-checkpoint-promotions");
    std::fs::create_dir_all(&workers).expect("live worker catalog");
    std::fs::write(workers.join("sentinel"), b"worker").expect("live worker sentinel");
    std::fs::create_dir_all(&promotions).expect("live promotion catalog");
    std::fs::write(promotions.join("sentinel"), b"promotion").expect("live promotion sentinel");
    let _live_ledger =
        DirectoryAssignmentLedger::open(&config.ledger_root).expect("live assignment ledger");

    let repository = repository_with_campaigns(&[("packaged", b"shared", "qemu-test")]);
    let result = compose_packaged_qemu_executor(
        repository,
        Arc::new(DirectoryBlobBackend::new(
            "packaged-competing-start-checkpoints",
            directory.path().join("shared-store"),
        )),
        profile(),
        scenario_artifact(),
        config,
        UnusedHostFactory,
    );
    let Err(PackagedQemuExecutorError::Ledger(_)) = result else {
        panic!("competing packaged startup must fail at ledger ownership");
    };

    assert_eq!(
        std::fs::read(workers.join("sentinel")).expect("retained worker sentinel"),
        b"worker"
    );
    assert_eq!(
        std::fs::read(promotions.join("sentinel")).expect("retained promotion sentinel"),
        b"promotion"
    );
}

#[test]
fn packaged_native_catalog_recovery_is_crash_safe_and_idempotent() {
    let directory = tempfile::tempdir().expect("packaged native catalog root");
    let workers = directory.path().join("campaign-workers");
    let promotions = directory.path().join("campaign-checkpoint-promotions");
    std::fs::create_dir_all(workers.join("worker-0/scenario")).expect("active worker catalog");
    std::fs::write(workers.join("worker-0/scenario/native"), b"worker")
        .expect("worker catalog sentinel");
    std::fs::create_dir_all(promotions.join("worker-0/scenario"))
        .expect("active promotion catalog");
    std::fs::write(promotions.join("worker-0/scenario/native"), b"promotion")
        .expect("promotion catalog sentinel");

    reconcile_packaged_native_catalogs(directory.path()).expect("retire active catalogs");
    for namespace in PACKAGED_NATIVE_NAMESPACES {
        assert!(!directory.path().join(namespace).exists());
        assert!(
            !directory
                .path()
                .join(format!(".retired-{namespace}"))
                .exists()
        );
    }

    reconcile_packaged_native_catalogs(directory.path()).expect("idempotent catalog recovery");
}

#[test]
fn packaged_native_catalog_recovery_finishes_a_renamed_generation() {
    let directory = tempfile::tempdir().expect("packaged native catalog root");
    let retired_workers = directory.path().join(".retired-campaign-workers");
    let promotions = directory.path().join("campaign-checkpoint-promotions");
    std::fs::create_dir_all(retired_workers.join("worker-0/scenario"))
        .expect("retired worker catalog");
    std::fs::create_dir_all(promotions.join("worker-0/scenario"))
        .expect("active promotion catalog");

    reconcile_packaged_native_catalogs(directory.path()).expect("finish catalog recovery");
    assert!(!retired_workers.exists());
    assert!(!promotions.exists());
}

#[test]
fn packaged_native_catalog_recovery_rejects_conflicting_generations() {
    let directory = tempfile::tempdir().expect("packaged native catalog root");
    let active = directory.path().join("campaign-workers");
    let retired = directory.path().join(".retired-campaign-workers");
    std::fs::create_dir(&active).expect("active worker catalog");
    std::fs::create_dir(&retired).expect("retired worker catalog");

    assert!(matches!(
        reconcile_packaged_native_catalogs(directory.path()),
        Err(PackagedNativeCatalogRecoveryError::ConflictingGeneration {
            namespace: "campaign-workers"
        })
    ));
    assert!(active.exists());
    assert!(retired.exists());
}

#[cfg(unix)]
#[test]
fn packaged_native_catalog_recovery_rejects_namespace_symlinks() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("packaged native catalog root");
    let target = directory.path().join("unrelated");
    std::fs::create_dir(&target).expect("unrelated directory");
    let workers = directory.path().join("campaign-workers");
    symlink(&target, &workers).expect("worker namespace symlink");

    assert!(matches!(
        reconcile_packaged_native_catalogs(directory.path()),
        Err(PackagedNativeCatalogRecoveryError::InvalidPath { path }) if path == workers
    ));
    assert!(target.exists());
}

#[test]
fn operational_phase_uses_exact_actor_ownership_and_durable_phase() {
    let epoch = DaemonEpoch::from_bytes([0x91; 16]).expect("daemon epoch");
    let execution = ExecutionId::from_bytes([0x92; 16]).expect("execution");
    let basis = CampaignHash::derive("packaged-status-test", b"basis");
    let running = AttemptRuntimeState::Running {
        execution_basis: basis,
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch: epoch,
        execution,
    };
    let activity = |worker_in_flight, cancellation_requested, completion_pending| {
        BTreeMap::from([(
            execution,
            LocalExecutionActivity {
                execution,
                worker_in_flight,
                cancellation_requested,
                completion_pending,
                cancellation_pending: false,
            },
        )])
    };

    assert_eq!(
        operational_phase(
            running,
            epoch,
            &activity(false, false, false),
            &BTreeMap::new(),
        ),
        Ok(Some(OperationalPhase::Preparing))
    );
    let preparing = BTreeMap::from([(execution, PackagedWorldLifecyclePhase::Preparing)]);
    assert_eq!(
        operational_phase(running, epoch, &activity(true, false, false), &preparing),
        Ok(Some(OperationalPhase::Preparing))
    );
    let active = BTreeMap::from([(execution, PackagedWorldLifecyclePhase::Running)]);
    assert_eq!(
        operational_phase(running, epoch, &activity(true, false, false), &active),
        Ok(Some(OperationalPhase::Running))
    );
    assert_eq!(
        operational_phase(running, epoch, &activity(true, true, false), &active),
        Ok(Some(OperationalPhase::Canceling))
    );
    assert_eq!(
        operational_phase(
            running,
            epoch,
            &activity(false, false, true),
            &BTreeMap::new(),
        ),
        Ok(Some(OperationalPhase::Publishing))
    );
    assert_eq!(
        operational_phase(
            running,
            DaemonEpoch::from_bytes([0x93; 16]).expect("stale epoch"),
            &activity(true, false, false),
            &active,
        ),
        Ok(None)
    );
    assert_eq!(
        operational_phase(
            running,
            epoch,
            &activity(true, false, false),
            &BTreeMap::new()
        ),
        Err(())
    );

    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        4,
        b"packaged-status-checkpoint",
    ))
    .expect("checkpoint");
    let paused = AttemptRuntimeState::Paused {
        execution_basis: basis,
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch: epoch,
        execution,
        checkpoint,
        promotion_basis: None,
    };
    assert_eq!(
        operational_phase(paused, epoch, &BTreeMap::new(), &BTreeMap::new()),
        Ok(Some(OperationalPhase::Paused))
    );
}

#[test]
fn actor_status_snapshots_reject_intervening_ownership_changes() {
    let epoch = DaemonEpoch::from_bytes([0x94; 16]).expect("daemon epoch");
    let stable = LocalExecutorOperationalSnapshot {
        revision: 7,
        daemon_epoch: epoch,
        activities: Vec::new(),
    };
    assert!(successive_actor_snapshots(&stable, &stable));

    let changed = LocalExecutorOperationalSnapshot {
        revision: 8,
        ..stable.clone()
    };
    assert!(!successive_actor_snapshots(&stable, &changed));
}
