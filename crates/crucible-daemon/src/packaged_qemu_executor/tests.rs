//! Packaged executor composition, endpoint, and lifecycle regression tests.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crucible::{Checkpoint, CheckpointKind, Configuration, ScenarioDef, VirtualTime};
use crucible_campaign::{
    CampaignCommandId, CampaignLineage, CampaignMode, CampaignPolicy, CampaignSeed,
    ConfigurationId, ExactCheckpointId, ExactRational, ExecutorClient, ExplorerPolicy,
    FairnessPolicy, PinChange, PinRequest, PinRetention, ProgressiveWideningPolicy, PuctPolicy,
    RetentionPolicy, ScenarioDefId,
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, ImmutableBlobBackend, MemoryBlobBackend,
    MemoryRefBackend, ObjectKind,
};
use crucible_qemu::{
    QemuChildProcessContract, QemuLaunchResourceRequirements, QemuNodeChild,
    QemuPreparedRunDirectory, QemuReplayOracleValidation, QemuVmSnapshot,
};

use super::*;
use crate::{
    DirectoryAssignmentLedger, DirectoryExactPinMaterializationStore,
    EXACT_PIN_MATERIALIZATION_DIRECTORY, ExactCheckpointStore, ExactPinRetentionAdmin,
    LoopbackExecutorService, QemuAttemptCancellationSignal,
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

#[test]
fn packaged_executor_serves_the_exact_composed_description_and_joins() {
    let directory = tempfile::tempdir().expect("packaged executor directory");
    let config = config(&directory, 2);
    let socket = config.endpoint().path().to_owned();
    let repository = repository_with_campaigns(&[("packaged", b"shared", "qemu-test")]);
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
            1,
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
                    b"pin",
                )),
                expected_snapshot,
                change: PinChange::new(
                    fixture.configuration,
                    Some(PinRetention::Exact),
                    "retain packaged exact checkpoint",
                )
                .expect("exact pin change"),
            },
        )
        .expect("apply exact pin");
}

#[test]
fn packaged_materializer_selects_a_checkpoint_when_the_pin_arrives_later() {
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
    assert_eq!(selected.checkpoint(), fixture.checkpoint);
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
    let basis = authenticate_packaged_campaigns(&repository, &campaigns)
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

    let incompatible = repository_with_campaigns(&[
        ("alpha", b"shared", "qemu-test"),
        ("beta", b"shared", "different-qemu"),
    ]);
    assert!(matches!(
        authenticate_packaged_campaigns(&incompatible, &campaigns),
        Err(PackagedQemuExecutorError::CampaignCompatibilityMismatch { campaign })
            if campaign.as_str() == "beta"
    ));

    let multiple_scenarios = repository_with_campaigns(&[
        ("alpha", b"alpha-scenario", "qemu-test"),
        ("beta", b"beta-scenario", "qemu-test"),
    ]);
    let basis = authenticate_packaged_campaigns(&multiple_scenarios, &campaigns)
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
    let error = match prepare_packaged_qemu_executor(repository, checkpoint_backend, config) {
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
    let error = match prepare_packaged_qemu_executor(repository, checkpoint_backend, config) {
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
