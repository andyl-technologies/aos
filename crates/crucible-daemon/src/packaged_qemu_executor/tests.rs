//! Packaged executor composition, endpoint, and lifecycle regression tests.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use crucible_campaign::ExecutorClient;
use crucible_qemu::{
    QemuChildProcessContract, QemuLaunchResourceRequirements, QemuNodeChild,
    QemuPreparedRunDirectory,
};

use super::*;
use crate::{LoopbackExecutorService, QemuAttemptCancellationSignal};

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
        CampaignName::new("packaged").expect("campaign name"),
        endpoint,
        ExecutorLoopbackServerConfig::default(),
        directory.path().join("ledger"),
        directory.path().join("checkpoints"),
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
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(crucible_cas::content_store::MemoryBlobBackend::new(
            "packaged-executor",
            1024 * 1024,
        )),
        Arc::new(crucible_cas::content_store::MemoryRefBackend::new()),
    ));
    let service = compose_packaged_qemu_executor(repository, profile(), config, UnusedHostFactory)
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
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(crucible_cas::content_store::MemoryBlobBackend::new(
            "packaged-executor-exact",
            1024 * 1024,
        )),
        Arc::new(crucible_cas::content_store::MemoryRefBackend::new()),
    ));
    let service = compose_packaged_qemu_executor_with_checkpoint_promotions(
        repository,
        profile(),
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
        config(&directory, 1).campaign.clone(),
        config(&directory, 1).endpoint.clone(),
        ExecutorLoopbackServerConfig::default(),
        directory.path().join("ledger-overflow"),
        directory.path().join("checkpoints-overflow"),
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
fn invalid_campaign_fails_before_operational_owner_mutation() {
    let directory = tempfile::tempdir().expect("packaged executor directory");
    let config = config(&directory, 1);
    let ledger = config.ledger_root().to_owned();
    let checkpoints = config.checkpoint_root().to_owned();
    let socket = config.endpoint().path().to_owned();
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(crucible_cas::content_store::MemoryBlobBackend::new(
            "missing-packaged-campaign",
            1024 * 1024,
        )),
        Arc::new(crucible_cas::content_store::MemoryRefBackend::new()),
    ));

    let error = match prepare_packaged_qemu_executor(repository, config) {
        Ok(_) => panic!("missing campaign must fail before executor preparation"),
        Err(error) => error,
    };
    assert!(matches!(error, PackagedQemuExecutorError::Repository(_)));
    assert!(!ledger.exists());
    assert!(!checkpoints.exists());
    assert!(!socket.exists());
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
