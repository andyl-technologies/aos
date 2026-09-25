//! Packaged executor composition, endpoint, and lifecycle regression tests.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use crucible::{
    Configuration, ContentHash, ExecutionFingerprint, FingerprintSample, Icount, NodeId, Plan,
    Properties, QuantumOutcome, QuantumRequest, QuantumTerminalVerdict, ScenarioDef,
    ScenarioDefForm, SchedulerError, SchedulerEventLogEntry, Seed, VirtualTime, World,
};
use crucible_api::{ProductionFaultEvidenceSnapshot, ProductionVmNodeReplayLaunchProfile};
use crucible_campaign::{
    AssignmentId, AttemptId, BudgetGrant, CampaignCommandId, CampaignControlAction,
    CampaignLineage, CampaignLineageId, CampaignMode, CampaignOperationalStatus, CampaignPolicy,
    CampaignSeed, CampaignWorldStatus, ConfigurationId, ControlRequest, CoverageProjection,
    ExactCheckpointId, ExactRational, ExecutionId, ExecutionRetentionIntent, ExecutorClient,
    ExplorerPolicy, FairnessPolicy, FindingCandidateBundle, FindingCandidateBundleId,
    FindingCandidateCore, FindingExactPins, FindingExactRetention,
    FindingExactRetentionDisposition, FindingExactRetentionIncomplete, FindingKind,
    FindingMinimizationEvidence, FindingSignature, FindingSignatureMinimizationEvidence,
    FindingTarget, MeasurementSet, Observation, ObservationCandidate, PinChange, PinRequest,
    PinRetention, ProgressiveWideningPolicy, PropertyVerdictSet, PuctPolicy, RetentionPolicy,
    ScenarioDefId, StopOutcome, SubmitAttemptRequest,
};
use crucible_cas::content_store::{
    ContentId, DirectoryBlobBackend, ImmutableBlobBackend, MemoryBlobBackend, MemoryRefBackend,
    ObjectKind,
};
use crucible_protocol::SelectionReply;
use crucible_qemu::{
    QemuChildProcessContract, QemuLaunchArtifactIdentityError, QemuLaunchResourceRequirements,
    QemuNodeChild, QemuNodeSelectablePendingRequest, QemuParkedCampaignMarker,
    QemuPreparedRunDirectory,
};

use super::*;
use crate::{
    AssignmentLedger, AttemptExecutionContext, AttemptExecutionKey, AttemptExecutionOrigin,
    AttemptExecutionRuntimeBasis, AttemptStateCas, AttemptWorkResult, AttemptWorkerFailure,
    CompletedFindingCandidate, DirectoryAssignmentLedger, DirectoryExactPinMaterializationStore,
    EXACT_PIN_MATERIALIZATION_DIRECTORY, ExactCheckpointStore, ExactPinMaterializationSelection,
    HotCheckpointFallbackRecord, HotCheckpointFallbackRetentionCas,
    HotCheckpointFallbackRetentionStore, HotCheckpointFallbackSlot, HotCheckpointPoolKey,
    HotCheckpointResourceProfile, LocalAttemptWorker, LoopbackExecutorService,
    QemuAttemptCancellationSignal, QemuFreshAttemptLifecycleFactory,
    QemuFreshAttemptLifecycleOwner, QueuedAttempt,
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

impl crate::qemu_resource_guard::QemuAttemptSelectedHostResourceFactory for UnusedHostFactory {
    fn begin_selected(
        &mut self,
        resources: AttemptResourceLimits,
        selected_checkpoint: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Result<
        (
            Self::Owner,
            Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
        ),
        crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure,
    > {
        if selected_checkpoint.is_some() {
            return Err(
                crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                    QemuVmRealizationError::Executor {
                        operation: "begin unused packaged test host",
                        message: String::from("test does not execute a guest"),
                    },
                    selected_checkpoint,
                ),
            );
        }
        self.begin(resources)
            .map(|owner| (owner, None))
            .map_err(Into::into)
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
        _work: &mut crate::CheckpointPromotionRestartWork,
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
        ProductionVmLifecycleConfig::new(
            "qemu",
            "plugin",
            "kernel",
            "root",
            directory.path().join("run-state"),
        ),
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
        PackagedQemuExecutorStorage::new(
            repository,
            Arc::new(crucible_cas::content_store::DirectoryBlobBackend::new(
                "packaged-executor-checkpoints",
                directory.path().join("shared-store"),
            )),
        ),
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
        PackagedQemuExecutorStorage::new(
            Arc::clone(&repository),
            Arc::new(DirectoryBlobBackend::new(
                "packaged-restart-checkpoints",
                directory.path().join("checkpoints"),
            )),
        ),
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

#[test]
fn packaged_executor_advertises_exact_restore_with_one_owner_per_worker() {
    let directory = tempfile::tempdir().expect("packaged executor directory");
    let config = config(&directory, 2);
    let socket = config.endpoint().path().to_owned();
    let repository = repository_with_campaigns(&[("packaged", b"shared", "qemu-test")]);
    let service = compose_packaged_qemu_executor_with_checkpoint_promotions(
        PackagedQemuExecutorStorage::new(
            repository,
            Arc::new(crucible_cas::content_store::DirectoryBlobBackend::new(
                "packaged-executor-promoted-checkpoints",
                directory.path().join("shared-store"),
            )),
        ),
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
            crate::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
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
        CampaignPolicy::identity(
            scenario,
            CampaignSeed::from_bytes([7; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                widening: Some(widening),
                puct: PuctPolicy::new(1_000_000, 1, 0),
            },
        ),
        CampaignPolicy::rules(
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness policy"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
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
    let attempt_record = repository
        .load_attempt(attempt)
        .expect("load packaged attempt");
    let measurements = MeasurementSet::from_evaluation(
        crucible_campaign::CampaignHash::derive(
            "crucible.test.measurement-definitions.v1",
            b"packaged executor",
        ),
        1,
        crucible_campaign::CampaignHash::derive(
            "crucible.test.measurement-evaluation.v1",
            b"packaged executor",
        ),
        b"packaged executor".to_vec(),
        std::collections::BTreeSet::new(),
    )
    .expect("measurements");
    let measurements = repository
        .publish_measurement_set(&measurements)
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
        Observation::outcome(
            lineage.genesis(),
            lineage.genesis_content(),
            attempt_record.path(),
            StopOutcome::TerminalSuccess,
            measurements,
            properties,
            coverage,
        ),
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
        3,
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
    let retention_basis = repository
        .attempt_retention_policy_basis_at(
            repository
                .head(CAMPAIGN)
                .expect("packaged finding campaign head")
                .snapshot_id(),
            attempt,
        )
        .expect("packaged finding retention basis");
    let exact_retention = FindingExactRetention::new(
        retention_basis.snapshot(),
        retention_basis.policy(),
        retention_basis.admission(),
        0,
        FindingExactRetentionDisposition::Incomplete(
            FindingExactRetentionIncomplete::MissingSafeBoundaryCapture,
        ),
    )
    .expect("packaged incomplete finding retention");
    let bundle = FindingCandidateBundle::new_with_exact_retention(
        FindingCandidateCore::new(
            observation,
            signature,
            original,
            minimized,
            signatures,
            FindingExactPins::default(),
        ),
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
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
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
    let production_root = directory.path().join("production-checkpoint");
    let production =
        crucible_api::build_exact_ram_production_checkpoint_codec_fixture(&production_root)
            .expect("build exact-RAM production checkpoint");
    let backend = Arc::new(DirectoryBlobBackend::new(
        "packaged-exact-pin-store",
        directory.path().join("objects"),
    ));
    let repository = Arc::new(CampaignRepository::new(
        backend.clone(),
        Arc::new(MemoryRefBackend::new()),
    ));
    let scenario = production.source().scenario_def();
    let configuration = production.configuration().clone();
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

    let checkpoint_backend: Arc<dyn ImmutableBlobBackend> = backend;
    let checkpoints = Arc::new(
        ExactCheckpointStore::new(checkpoint_backend, 1024 * 1024).expect("exact checkpoint store"),
    );
    let prepared = checkpoints
        .prepare_production_closure(production.closure().clone())
        .expect("prepare production checkpoint");
    let checkpoint = checkpoints
        .publish_production_closure(&prepared)
        .expect("publish production checkpoint")
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

#[derive(Default)]
struct ControlledLifecycleBoundary {
    state: Mutex<(u8, u8)>,
    changed: Condvar,
    requested_fingerprint_nodes: Mutex<Vec<NodeId>>,
    fail_fingerprint_sample: AtomicBool,
    fail_effect_trace: AtomicBool,
    live_network_choice_pause: AtomicBool,
    choice_free_parallel_boot: AtomicBool,
    marker_reads: AtomicUsize,
    marker_releases: Mutex<Vec<(NodeId, String, ContentHash)>>,
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

    fn set_live_network_choice_pause(&mut self, enabled: bool) {
        self.boundary
            .live_network_choice_pause
            .store(enabled, Ordering::Release);
    }

    fn set_choice_free_parallel_boot(&mut self, enabled: bool) {
        self.boundary
            .choice_free_parallel_boot
            .store(enabled, Ordering::Release);
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

    fn prepare_terminal_checkpoint(
        &mut self,
        _cause: crucible::CheckpointTerminalCause,
    ) -> Result<(), SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("controlled lifecycle cannot retain a terminal checkpoint cause"),
        })
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        panic!("controlled lifecycle does not capture a checkpoint")
    }

    fn parked_campaign_marker(
        &mut self,
        node: &NodeId,
    ) -> Result<Option<QemuParkedCampaignMarker>, SchedulerError> {
        assert_eq!(node.name, "marker-node");
        self.boundary.marker_reads.fetch_add(1, Ordering::AcqRel);
        Ok(Some(QemuParkedCampaignMarker {
            marker: String::from("fault.transport.ready"),
            marker_icount: Icount { retired: 41 },
            physical_icount: Icount { retired: 42 },
        }))
    }

    fn release_parked_campaign_marker(
        &mut self,
        node: &NodeId,
        marker: &str,
        selected: ContentHash,
    ) -> Result<(), SchedulerError> {
        self.boundary
            .marker_releases
            .lock()
            .expect("controlled marker releases")
            .push((node.clone(), marker.to_owned(), selected));
        Ok(())
    }

    fn campaign_marker_release_committed(
        &self,
        node: &NodeId,
        marker: &str,
        selected: ContentHash,
    ) -> Result<bool, SchedulerError> {
        Ok(self
            .boundary
            .marker_releases
            .lock()
            .expect("controlled marker releases")
            .iter()
            .any(|release| release == &(node.clone(), marker.to_owned(), selected)))
    }

    fn campaign_network_queues_empty(&self) -> Result<bool, SchedulerError> {
        Ok(true)
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

    fn prepare_terminal_fingerprints(&mut self) -> Result<(), SchedulerError> {
        Ok(())
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
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    );
    let factory = PackagedStatusLifecycleFactory {
        inner: ControlledLifecycleFactory {
            boundary: Arc::clone(&boundary),
            fail_shutdown: false,
        },
        lifecycles: PackagedWorldLifecycleTracker::new(),
    };
    let (mut factory, _evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(factory);
    let mut lifecycle = factory
        .start_fresh_lifecycle(
            &scenario,
            &source,
            &start,
            &crucible::SignalFaultCampaignReplayPlan::empty(start.clone()),
            &context,
        )
        .expect("start delegated lifecycle");

    lifecycle.set_live_network_choice_pause(true);
    lifecycle.set_choice_free_parallel_boot(true);
    assert!(boundary.live_network_choice_pause.load(Ordering::Acquire));
    assert!(boundary.choice_free_parallel_boot.load(Ordering::Acquire));

    let marker_node = NodeId {
        name: String::from("marker-node"),
    };
    let marker = lifecycle
        .parked_campaign_marker(&marker_node)
        .expect("delegated marker lookup")
        .expect("stored campaign marker");
    assert_eq!(marker.marker, "fault.transport.ready");
    assert_eq!(marker.marker_icount, Icount { retired: 41 });
    assert_eq!(marker.physical_icount, Icount { retired: 42 });
    assert_eq!(boundary.marker_reads.load(Ordering::Acquire), 1);

    let selected = ContentHash::from_bytes(b"marker-selected-branch");
    lifecycle
        .release_parked_campaign_marker(&marker_node, &marker.marker, selected)
        .expect("delegated marker release");
    assert!(
        lifecycle
            .campaign_marker_release_committed(&marker_node, &marker.marker, selected)
            .expect("delegated marker release proof")
    );
    assert!(
        lifecycle
            .campaign_network_queues_empty()
            .expect("delegated network queue proof")
    );
    assert_eq!(
        *boundary
            .marker_releases
            .lock()
            .expect("controlled marker releases"),
        vec![(marker_node, marker.marker, selected)]
    );

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
            crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
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
    let failure = AttemptWorkerFailure::Terminal(crate::RepositoryAttemptWorkerError::Model(
        DiagnosticOuterError(DiagnosticInnerError(std::io::Error::other(
            "leaf execution failure",
        ))),
    ));

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

    let oversized = AttemptWorkerFailure::Terminal(crate::RepositoryAttemptWorkerError::Model(
        DiagnosticOuterError(DiagnosticInnerError(std::io::Error::other(
            "x".repeat(MAX_PACKAGED_ATTEMPT_FAILURE_DIAGNOSTIC_BYTES * 2),
        ))),
    ));
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
    assert!(
        diagnostic
            .contains("construct production hot-fork world lifecycle: original hot-fork failure")
    );
    assert!(diagnostic.lines().any(|line| {
        line.starts_with("  caused by [2]: ") && line.contains("hot-fork cleanup failure")
    }));
}

fn controlled_submit_request(epoch: DaemonEpoch) -> SubmitAttemptRequest {
    let typed_id = |tag: &str, kind: &str, schema_version: u32, byte: u8| {
        format!(
            "{tag}@{kind}.{schema_version}.{}",
            format!("{byte:02x}").repeat(32)
        )
    };
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x90; 16]).expect("assignment"),
        epoch,
        CampaignLineageId::parse(&typed_id(
            "crucible.campaign.lineage",
            "campaign-fact",
            1,
            0x91,
        ))
        .expect("lineage"),
        AttemptId::parse(&typed_id(
            "crucible.campaign.attempt",
            "campaign-fact",
            9,
            0x92,
        ))
        .expect("attempt"),
        resources(),
        ExecutionRetentionIntent::Discard,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
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

mod lifecycle_recovery;
