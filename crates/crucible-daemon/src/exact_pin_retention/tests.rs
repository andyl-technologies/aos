//! Exact-pin materialization journal regressions.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crucible::model::{
    FaultPhase, SignalId, WorldNodeArchitecture, WorldNodeClockSource, WorldNodeDramGeometry,
    WorldNodeFaultCapabilities, WorldNodeRegister, WorldNodeRegisterGroup,
};
use crucible::{
    AdvanceOutcome, Backend, BackendError, BackendInput, Checkpoint, CheckpointKind, Configuration,
    ContentHash, EventLog, ExecutionFingerprint, ExecutionHorizon, Icount, NodeId, RuntimeState,
    ScenarioDef, World,
};
use crucible_campaign::{
    AttemptResourceLimits, CampaignCommandId, CampaignLineage, CampaignMode, CampaignPolicy,
    CampaignSeed, ExactRational, ExplorerPolicy, FairnessPolicy, PinChange, PinRequest,
    ProgressiveWideningPolicy, PuctPolicy, RetentionPolicy, ScenarioDefId,
};
use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, BlobSource, ByteRange, ImmutableBlobBackend,
    MemoryBlobBackend, MemoryRefBackend, ObjectKind, PlacementReceipt, PutReceipt, StoreError,
    StoreGraph, StoreGraphConfig, StoreNodeId, StoreNodeSpec,
};
use crucible_qemu::{
    DeterministicLaunchProfile, QemuBakedGenesisRestoreAdmission, QemuBakedGenesisSnapshot,
    QemuCachedAncestor, QemuChildProcessContract, QemuFailedLaunchChildSource,
    QemuFaultCapabilityRequirement, QemuGuardedNodeRealizationLauncher,
    QemuGuardedThinNodeRealizationLauncher, QemuLaunchArtifact, QemuLaunchCommand,
    QemuLaunchCommandBuilder, QemuLaunchPluginConfig, QemuLoadvmCommandAuthorization,
    QemuLoadvmRealizationAdmission, QemuNodeLauncher, QemuNodeRealizationExecutor,
    QemuNodeRestorePlan, QemuPreparedRunDirectory, QemuRealizedNodeBackend, QemuReplayOracleCheck,
    QemuReplayOracleValidation, QemuReplayValidationNodeLauncher, QemuVmLaunchConfig,
    QemuVmLiveRealizationExecutor, QemuVmRealizationError, QemuVmRealizationExecutor,
    QemuVmRealizationKind, QemuVmRealizationOperation, QemuVmRealizationStore, QemuVmReplayRequest,
    QemuVmSnapshot, QemuVmStateBinding,
};
use crucible_shmem::{
    FAULT_REGISTER_CAPABILITY_IMPULSE, FAULT_REGISTER_CAPABILITY_VMSTATE, FaultCapabilityScope,
    FaultRegisterCapabilityManifestV1, FaultRegisterCapabilityRowV1, FaultRegisterGroupV1,
};

use super::*;

const STORE_LIMIT: u64 = 1024 * 1024;

struct TestDurableBackend {
    memory: MemoryBlobBackend,
    cancel_vmstate_read: Mutex<Option<crate::ExecutionCancellation>>,
}

impl TestDurableBackend {
    fn new() -> Self {
        Self {
            memory: MemoryBlobBackend::new("exact-pin-materialization-test", 64 * STORE_LIMIT),
            cancel_vmstate_read: Mutex::new(None),
        }
    }

    fn cancel_next_vmstate_read(&self, cancellation: crate::ExecutionCancellation) {
        *self
            .cancel_vmstate_read
            .lock()
            .expect("canceling backend lock") = Some(cancellation);
    }

    fn object_count(&self) -> usize {
        self.memory.object_count().expect("count test objects")
    }
}

impl ImmutableBlobBackend for TestDurableBackend {
    fn name(&self) -> &str {
        "exact-pin-materialization-test"
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

    fn contains(&self, id: crucible_cas::content_store::ContentId) -> Result<bool, StoreError> {
        self.memory.contains(id)
    }

    fn read(
        &self,
        id: crucible_cas::content_store::ContentId,
        range: Option<ByteRange>,
    ) -> Result<BlobHandle, StoreError> {
        let handle = self.memory.read(id, range)?;
        if id.kind() == ObjectKind::DeviceState && id.schema_version() == 1 {
            let cancellation = self
                .cancel_vmstate_read
                .lock()
                .map_err(|_| StoreError::Poisoned {
                    operation: "arm canceling VMState test source",
                })?
                .take();
            if let Some(cancellation) = cancellation {
                return Ok(BlobHandle::new(Arc::new(CancelAfterReadSource {
                    handle,
                    cancellation,
                })));
            }
        }
        Ok(handle)
    }

    fn put_if_absent(
        &self,
        id: crucible_cas::content_store::ContentId,
        source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        self.memory.put_if_absent(id, source)?;
        Ok(PutReceipt {
            id,
            placements: vec![PlacementReceipt {
                backend: self.name().to_owned(),
                durable: true,
                logical_length: source.logical_length(),
            }],
        })
    }
}

struct CancelAfterReadSource {
    handle: BlobHandle,
    cancellation: crate::ExecutionCancellation,
}

impl BlobSource for CancelAfterReadSource {
    fn logical_length(&self) -> u64 {
        self.handle.logical_length()
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(CancelAfterReadReader {
            source: self.handle.open()?,
            cancellation: self.cancellation.clone(),
            signaled: false,
        }))
    }
}

struct CancelAfterReadReader {
    source: Box<dyn Read + Send>,
    cancellation: crate::ExecutionCancellation,
    signaled: bool,
}

impl Read for CancelAfterReadReader {
    fn read(&mut self, destination: &mut [u8]) -> std::io::Result<usize> {
        let read = self.source.read(destination)?;
        if read != 0 && !self.signaled {
            self.cancellation.cancel_for_test();
            self.signaled = true;
        }
        Ok(read)
    }
}

struct Fixture {
    repository: CampaignRepository,
    refs: Arc<MemoryRefBackend>,
    checkpoints: ExactCheckpointStore,
    campaign: CampaignName,
    configuration: ConfigurationId,
    pin_fact: CampaignFactId,
    checkpoint: ExactCheckpointId,
}

struct GuardedResumeLauncher {
    snapshot: ContentHash,
    runtime: ContentHash,
    icount: Icount,
    launches: Arc<AtomicUsize>,
}

struct GuardedResumeNode {
    runtime: ContentHash,
    icount: Icount,
}

struct GuardedThinLauncher {
    checkpoint: ContentHash,
    runtime: ContentHash,
    icount: Icount,
    launches: Arc<AtomicUsize>,
    fail_after_launch: bool,
}

impl QemuNodeLauncher for GuardedResumeLauncher {
    type Node = GuardedResumeNode;
}

impl QemuFailedLaunchChildSource for GuardedResumeLauncher {
    fn take_failed_launch_child(&mut self) -> Option<crucible_qemu::QemuNodeChild> {
        None
    }
}

impl QemuGuardedNodeRealizationLauncher for GuardedResumeLauncher {
    fn launch_materialized_exact_node_guarded(
        &mut self,
        _config: &Configuration,
        snapshot: &QemuVmSnapshot,
        _restore: QemuNodeRestorePlan<'_>,
        _process_contract: &QemuChildProcessContract,
    ) -> Result<Self::Node, QemuVmRealizationError> {
        if snapshot.id() != self.snapshot {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "guarded resume test",
                message: String::from("snapshot does not match selected root"),
            });
        }
        self.launches.fetch_add(1, Ordering::SeqCst);
        Ok(GuardedResumeNode {
            runtime: self.runtime,
            icount: self.icount,
        })
    }
}

impl QemuNodeLauncher for GuardedThinLauncher {
    type Node = GuardedResumeNode;
}

impl QemuFailedLaunchChildSource for GuardedThinLauncher {
    fn take_failed_launch_child(&mut self) -> Option<crucible_qemu::QemuNodeChild> {
        None
    }
}

impl QemuGuardedThinNodeRealizationLauncher for GuardedThinLauncher {
    fn launch_thin_path_node_guarded(
        &mut self,
        _config: &Configuration,
        restore: QemuNodeRestorePlan<'_>,
        _process_contract: &QemuChildProcessContract,
    ) -> Result<Self::Node, QemuVmRealizationError> {
        if restore.checkpoint().id != self.checkpoint {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "guarded thin replay test",
                message: String::from("checkpoint does not match prepared thin path"),
            });
        }
        self.launches.fetch_add(1, Ordering::SeqCst);
        if self.fail_after_launch {
            return Err(QemuVmRealizationError::ExecutorUnavailable {
                operation: "guarded thin replay test",
                message: String::from("injected post-spawn thin-path failure"),
            });
        }
        Ok(GuardedResumeNode {
            runtime: self.runtime,
            icount: self.icount,
        })
    }
}

impl Backend for GuardedResumeNode {
    fn advance_to_horizon(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<AdvanceOutcome, BackendError> {
        self.icount = horizon.icount;
        Ok(AdvanceOutcome::ReachedHorizon)
    }

    fn fingerprint(&mut self) -> Result<ExecutionFingerprint, BackendError> {
        Ok(ExecutionFingerprint { hash: self.runtime })
    }

    fn deliver_input(&mut self, _input: BackendInput) -> Result<(), BackendError> {
        Ok(())
    }

    fn snapshot(&mut self) -> Result<Checkpoint, BackendError> {
        Err(BackendError::NotImplemented {
            operation: "guarded resume test snapshot",
        })
    }

    fn restore(&mut self, _checkpoint: &Checkpoint) -> Result<(), BackendError> {
        Err(BackendError::NotImplemented {
            operation: "guarded resume test restore",
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        Ok(())
    }
}

impl QemuRealizedNodeBackend for GuardedResumeNode {
    fn prepare_authoritative_observation_stream(&mut self) -> Result<(), BackendError> {
        Ok(())
    }

    fn advance_live_to_horizon(
        &mut self,
        horizon: ExecutionHorizon,
        _event_log: &mut EventLog,
    ) -> Result<AdvanceOutcome, BackendError> {
        self.advance_to_horizon(horizon)
    }

    fn seal_live_observation_boundary(
        &mut self,
        _event_log: &mut EventLog,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    fn capture_live_exact_snapshot_paused(
        &mut self,
        _node: &NodeId,
        _checkpoint: Checkpoint,
    ) -> Result<QemuVmSnapshot, BackendError> {
        Err(BackendError::NotImplemented {
            operation: "guarded resume test capture",
        })
    }

    fn shutdown_live_with_event_log(
        &mut self,
        _event_log: &mut EventLog,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    fn current_icount(&mut self) -> Result<Icount, BackendError> {
        Ok(self.icount)
    }
}

struct GuardedResumeGuard {
    resources: AttemptResourceLimits,
    cancellation: crate::ExecutionCancellation,
    process_contract: QemuChildProcessContract,
    finishes: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
    failed_children: Vec<crucible_qemu::QemuNodeChild>,
}

struct ReplayValidationStore {
    baked: QemuBakedGenesisSnapshot,
}

impl QemuVmRealizationStore for ReplayValidationStore {
    fn exact_snapshot(
        &mut self,
        _config: &Configuration,
    ) -> Result<Option<QemuVmSnapshot>, QemuVmRealizationError> {
        Ok(None)
    }

    fn nearest_cached_ancestor(
        &mut self,
        _config: &Configuration,
    ) -> Result<Option<QemuCachedAncestor>, QemuVmRealizationError> {
        Ok(None)
    }

    fn baked_genesis(
        &mut self,
        _world: &World,
        _def: &ScenarioDef,
    ) -> Result<QemuBakedGenesisSnapshot, QemuVmRealizationError> {
        Ok(self.baked.clone())
    }
}

struct ReplayValidationExecutor {
    runtime: ContentHash,
    probe_calls: usize,
    baked_calls: usize,
}

impl QemuVmRealizationExecutor for ReplayValidationExecutor {
    fn load_exact_snapshot(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        _authorization: QemuLoadvmCommandAuthorization,
        _admission: QemuLoadvmRealizationAdmission,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        Ok(replay_validation_runtime(
            config,
            snapshot.checkpoint(),
            self.runtime,
        ))
    }

    fn load_exact_snapshot_for_replay_oracle_probe(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        _authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        self.probe_calls += 1;
        Ok(replay_validation_runtime(
            config,
            snapshot.checkpoint(),
            self.runtime,
        ))
    }

    fn load_baked_genesis(
        &mut self,
        config: &Configuration,
        admission: QemuBakedGenesisRestoreAdmission<'_>,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        self.baked_calls += 1;
        Ok(replay_validation_runtime(
            config,
            admission.checkpoint(),
            self.runtime,
        ))
    }

    fn replay_one_quantum(
        &mut self,
        _runtime: RuntimeState,
        _request: QemuVmReplayRequest,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        Err(QemuVmRealizationError::Executor {
            operation: "replay exact-pin validation test quantum",
            message: String::from("genesis validation must not replay a suffix"),
        })
    }
}

fn replay_validation_runtime(
    configuration: &Configuration,
    checkpoint: &Checkpoint,
    runtime: ContentHash,
) -> RuntimeState {
    let state = checkpoint
        .state
        .as_ref()
        .expect("materialized replay-validation checkpoint");
    RuntimeState {
        id: runtime,
        configuration: configuration.id(),
        node_blobs: checkpoint.node_blobs.clone(),
        node_icounts: checkpoint.node_icounts.clone(),
        scheduler: state.scheduler.clone(),
        event_log: state.event_log,
    }
}

impl crate::QemuAttemptOperationalBoundary for GuardedResumeGuard {
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &crate::ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.cancellation.is_canceled() {
            Err(QemuVmRealizationError::Canceled {
                operation: "guarded exact resume test",
            })
        } else {
            Ok(())
        }
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.check_operational_boundary()
    }
}

impl crate::QemuAttemptResourceGuard for GuardedResumeGuard {
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        self.finishes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn quarantine(&mut self) {
        self.quarantines.fetch_add(1, Ordering::SeqCst);
    }
}

impl crate::QemuAttemptProcessResourceGuard for GuardedResumeGuard {
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        Ok(&self.process_contract)
    }

    fn retain_failed_launch_child(&mut self, child: crucible_qemu::QemuNodeChild) {
        self.failed_children.push(child);
    }
}

fn guarded_resume_guard(resources: AttemptResourceLimits) -> GuardedResumeGuard {
    let (cgroup_procs, _cgroup_peer) = UnixStream::pair().expect("cgroup descriptor pair");
    let (cancellation_event, _cancellation_peer) =
        UnixStream::pair().expect("cancellation descriptor pair");
    GuardedResumeGuard {
        resources,
        cancellation: crate::ExecutionCancellation::default(),
        process_contract: QemuChildProcessContract::from_unvalidated_test_descriptors(
            cgroup_procs.into(),
            cancellation_event.into(),
            resources.maximum_vcpus(),
            resources.maximum_resident_bytes(),
            resources.maximum_disk_bytes(),
        ),
        finishes: Arc::new(AtomicUsize::new(0)),
        quarantines: Arc::new(AtomicUsize::new(0)),
        failed_children: Vec::new(),
    }
}

#[test]
fn replay_validated_materialization_resumes_only_through_guarded_launcher() {
    let backend = Arc::new(TestDurableBackend::new());
    let fixture = fixture_with_backend("guarded-resume", backend);
    let original = fixture
        .checkpoints
        .load(fixture.checkpoint)
        .expect("load unvalidated checkpoint");
    let runtime_hash = ContentHash::from_canonical_material(
        "crucible.test.exact-pin-materialization.runtime.v1",
        "guarded-resume",
    );
    let validated = QemuVmSnapshot::diskless(
        original.snapshot().checkpoint().clone(),
        QemuReplayOracleValidation::Match { runtime_hash },
    )
    .expect("replay-validated snapshot");
    let prepared_checkpoint = fixture
        .checkpoints
        .prepare(&validated, BlobHandle::from_bytes(vec![0x5a; 4096]))
        .expect("prepare replay-validated checkpoint");
    let checkpoint = fixture
        .checkpoints
        .publish(&prepared_checkpoint)
        .expect("publish replay-validated checkpoint")
        .root();

    let temp = tempfile::tempdir().expect("guarded resume workspace");
    let mut selections = DirectoryExactPinMaterializationStore::open(temp.path().join("pins"))
        .expect("selection store");
    let selection = ExactPinMaterializationSelection::prepare(
        &fixture.repository,
        &fixture.checkpoints,
        &fixture.campaign,
        fixture.configuration,
        checkpoint,
    )
    .expect("authenticate replay-validated selection");
    selections
        .select(selection)
        .expect("select validated checkpoint");

    let command = materialization_command();
    let run_directory = temp.path().join("run");
    std::fs::create_dir(&run_directory).expect("run directory");
    std::fs::write(
        run_directory.join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME),
        b"provisioned",
    )
    .expect("provision VMState file");
    let mut prepared_run_directory = QemuPreparedRunDirectory::open_for_materialization(
        &command,
        &run_directory,
        u32::MAX,
        u64::MAX,
        u64::MAX,
    )
    .expect("open materialization destination");
    let materialized = crate::materialize_selected_exact_checkpoint(
        &fixture.repository,
        &fixture.checkpoints,
        &mut selections,
        &fixture.campaign,
        fixture.configuration,
        &mut prepared_run_directory,
        &crate::ExecutionCancellation::default(),
    )
    .expect("materialize replay-validated checkpoint");

    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.exact-pin-materialization",
        "guarded-resume",
    ));
    let launches = Arc::new(AtomicUsize::new(0));
    let launcher = GuardedResumeLauncher {
        snapshot: validated.id(),
        runtime: runtime_hash,
        icount: Icount { retired: 0 },
        launches: launches.clone(),
    };
    let mut executor = QemuNodeRealizationExecutor::new(
        NodeId {
            name: String::from("vm-a"),
        },
        launcher,
    );
    let resources = AttemptResourceLimits::new(1, 512 * 1024 * 1024, 16 * 1024 * 1024, 16)
        .expect("resource limits");
    let mut guard = guarded_resume_guard(resources);

    let realization = crate::realize_materialized_exact_checkpoint_guarded(
        &mut executor,
        &mut guard,
        &configuration,
        &materialized,
    )
    .expect("resume guarded exact checkpoint");

    assert_eq!(launches.load(Ordering::SeqCst), 1);
    assert_eq!(realization.operation, QemuVmRealizationOperation::Resume);
    assert_eq!(realization.configuration, configuration);
    assert_eq!(realization.runtime.id, runtime_hash);
    assert_eq!(realization.runtime.configuration, configuration.id());
    assert!(matches!(
        realization.branch,
        QemuVmRealizationKind::ExactSnapshotLoadvm { ref checkpoint }
            if checkpoint.id == validated.checkpoint().id
    ));
}

#[test]
fn unvalidated_materialization_is_rejected_before_guarded_launch() {
    let backend = Arc::new(TestDurableBackend::new());
    let fixture = fixture_with_backend("guarded-not-run", backend);
    let temp = tempfile::tempdir().expect("guarded resume workspace");
    let mut selections = DirectoryExactPinMaterializationStore::open(temp.path().join("pins"))
        .expect("selection store");
    select_fixture(&mut selections, &fixture).expect("select unvalidated checkpoint");
    let command = materialization_command();
    let run_directory = temp.path().join("run");
    std::fs::create_dir(&run_directory).expect("run directory");
    std::fs::write(
        run_directory.join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME),
        b"provisioned",
    )
    .expect("provision VMState file");
    let mut prepared_run_directory = QemuPreparedRunDirectory::open_for_materialization(
        &command,
        &run_directory,
        u32::MAX,
        u64::MAX,
        u64::MAX,
    )
    .expect("open materialization destination");
    let materialized = crate::materialize_selected_exact_checkpoint(
        &fixture.repository,
        &fixture.checkpoints,
        &mut selections,
        &fixture.campaign,
        fixture.configuration,
        &mut prepared_run_directory,
        &crate::ExecutionCancellation::default(),
    )
    .expect("materialize unvalidated checkpoint");
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.exact-pin-materialization",
        "guarded-not-run",
    ));
    let launches = Arc::new(AtomicUsize::new(0));
    let launcher = GuardedResumeLauncher {
        snapshot: materialized.snapshot().id(),
        runtime: ContentHash::from_canonical_material(
            "crucible.test.exact-pin-materialization.runtime.v1",
            "guarded-not-run",
        ),
        icount: Icount { retired: 0 },
        launches: launches.clone(),
    };
    let mut executor = QemuNodeRealizationExecutor::new(
        NodeId {
            name: String::from("vm-a"),
        },
        launcher,
    );
    let resources = AttemptResourceLimits::new(1, 4096, 4096, 1).expect("resource limits");
    let mut guard = guarded_resume_guard(resources);

    assert!(matches!(
        crate::realize_materialized_exact_checkpoint_guarded(
            &mut executor,
            &mut guard,
            &configuration,
            &materialized,
        ),
        Err(crate::ExactCheckpointResumeError::Realization(
            QemuVmRealizationError::SavevmPolicy { .. }
        ))
    ));
    assert_eq!(launches.load(Ordering::SeqCst), 0);
}

#[test]
fn selected_raw_checkpoint_promotes_to_a_bound_oracle_match_without_vmstate_rewrite() {
    let backend = Arc::new(TestDurableBackend::new());
    let fixture = fixture_with_backend("oracle-promotion", backend.clone());
    let temp = tempfile::tempdir().expect("oracle promotion workspace");
    let mut selections = DirectoryExactPinMaterializationStore::open(temp.path().join("pins"))
        .expect("selection store");
    select_fixture(&mut selections, &fixture).expect("select raw checkpoint");
    let source = fixture
        .checkpoints
        .load(fixture.checkpoint)
        .expect("load selected raw checkpoint");
    let source_vmstate = source.vmstate_id();
    let runtime_hash = ContentHash::from_canonical_material(
        "crucible.test.exact-pin-materialization.runtime.v1",
        "oracle-promotion",
    );
    let count_before = backend.object_count();
    let foreign = QemuReplayOracleCheck::from_unvalidated_test_result(
        ContentHash::from_canonical_material(
            "crucible.test.exact-pin-materialization.foreign-snapshot.v1",
            "oracle-promotion",
        ),
        QemuReplayOracleValidation::Match { runtime_hash },
    );

    assert!(matches!(
        selections.promote_replay_oracle_match(
            &fixture.repository,
            &fixture.checkpoints,
            &fixture.campaign,
            fixture.configuration,
            foreign,
        ),
        Err(ExactPinRetentionError::ReplayOracle(
            QemuVmRealizationError::InvalidCheckpoint {
                role: "replay-oracle promotion",
                ..
            }
        ))
    ));
    assert_eq!(backend.object_count(), count_before);

    let check = QemuReplayOracleCheck::from_unvalidated_test_result(
        source.snapshot().id(),
        QemuReplayOracleValidation::Match { runtime_hash },
    );
    let promotion = selections
        .promote_replay_oracle_match(
            &fixture.repository,
            &fixture.checkpoints,
            &fixture.campaign,
            fixture.configuration,
            check,
        )
        .expect("promote selected checkpoint");

    assert_eq!(promotion.source(), fixture.checkpoint);
    assert_ne!(promotion.promoted(), fixture.checkpoint);
    assert_eq!(
        promotion.disposition(),
        ExactPinSelectionDisposition::Replaced
    );
    assert_eq!(backend.object_count(), count_before + 2);
    let promoted = fixture
        .checkpoints
        .load(promotion.promoted())
        .expect("load promoted checkpoint");
    assert_eq!(promoted.vmstate_id(), source_vmstate);
    assert_eq!(
        promoted.snapshot().replay_oracle_validation(),
        QemuReplayOracleValidation::Match { runtime_hash }
    );
    let mut fence = selections
        .acquire_exact_pin_retention_fence()
        .expect("selection fence");
    assert_eq!(
        fence
            .selection(&fixture.campaign, fixture.configuration)
            .expect("load promoted selection")
            .expect("promoted selection")
            .checkpoint(),
        promotion.promoted()
    );
}

#[test]
fn selected_checkpoint_fat_thin_validation_promotes_exact_root() {
    let backend = Arc::new(TestDurableBackend::new());
    let fixture = fixture_with_backend("oracle-validator", backend.clone());
    let temp = tempfile::tempdir().expect("oracle validator workspace");
    let mut selections = DirectoryExactPinMaterializationStore::open(temp.path().join("pins"))
        .expect("selection store");
    select_fixture(&mut selections, &fixture).expect("select raw checkpoint");
    let source = fixture
        .checkpoints
        .load(fixture.checkpoint)
        .expect("load selected raw checkpoint");
    let source_vmstate = source.vmstate_id();
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.exact-pin-materialization",
        "oracle-validator",
    ));
    assert_eq!(
        ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes)),
        fixture.configuration
    );
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.exact-pin-materialization.world.v1",
        "oracle-validator",
    ));
    let runtime_hash = ContentHash::from_canonical_material(
        "crucible.test.exact-pin-materialization.runtime.v1",
        "oracle-validator",
    );
    let mut store = ReplayValidationStore {
        baked: QemuBakedGenesisSnapshot {
            world_id: world.id,
            checkpoint: source.snapshot().checkpoint().clone(),
        },
    };
    let mut executor = ReplayValidationExecutor {
        runtime: runtime_hash,
        probe_calls: 0,
        baked_calls: 0,
    };
    let count_before = backend.object_count();

    let promotion = ExactPinReplayValidator::new(&mut store, &mut executor)
        .validate_and_promote(
            &fixture.repository,
            &fixture.checkpoints,
            &mut selections,
            ExactPinReplayTarget::new(
                &world,
                &configuration,
                &fixture.campaign,
                fixture.configuration,
            ),
        )
        .expect("validate and promote selected checkpoint");

    assert_eq!(executor.probe_calls, 1);
    assert_eq!(executor.baked_calls, 1);
    assert_eq!(promotion.source(), fixture.checkpoint);
    assert_ne!(promotion.promoted(), fixture.checkpoint);
    assert_eq!(
        promotion.disposition(),
        ExactPinSelectionDisposition::Replaced
    );
    assert_eq!(backend.object_count(), count_before + 2);
    let promoted = fixture
        .checkpoints
        .load(promotion.promoted())
        .expect("load replay-validated checkpoint");
    assert_eq!(promoted.vmstate_id(), source_vmstate);
    assert_eq!(
        promoted.snapshot().replay_oracle_validation(),
        QemuReplayOracleValidation::Match { runtime_hash }
    );
    let mut fence = selections
        .acquire_exact_pin_retention_fence()
        .expect("selection fence");
    assert_eq!(
        fence
            .selection(&fixture.campaign, fixture.configuration)
            .expect("load promoted selection")
            .expect("promoted selection")
            .checkpoint(),
        promotion.promoted()
    );
}

#[test]
fn guarded_fat_thin_session_reaps_before_promoting_selected_root() {
    let backend = Arc::new(TestDurableBackend::new());
    let fixture = fixture_with_backend("guarded-oracle-session", backend);
    let temp = tempfile::tempdir().expect("guarded oracle workspace");
    let mut selections = DirectoryExactPinMaterializationStore::open(temp.path().join("pins"))
        .expect("selection store");
    select_fixture(&mut selections, &fixture).expect("select raw checkpoint");
    let source = fixture
        .checkpoints
        .load(fixture.checkpoint)
        .expect("load selected raw checkpoint");
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.exact-pin-materialization",
        "guarded-oracle-session",
    ));
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.exact-pin-materialization.world.v1",
        "guarded-oracle-session",
    ));
    let runtime_hash = ContentHash::from_canonical_material(
        "crucible.test.exact-pin-materialization.runtime.v1",
        "guarded-oracle-session",
    );
    let exact_launches = Arc::new(AtomicUsize::new(0));
    let thin_launches = Arc::new(AtomicUsize::new(0));
    let launcher = QemuReplayValidationNodeLauncher::new(
        GuardedResumeLauncher {
            snapshot: source.snapshot().id(),
            runtime: runtime_hash,
            icount: Icount { retired: 0 },
            launches: exact_launches.clone(),
        },
        GuardedThinLauncher {
            checkpoint: source.snapshot().checkpoint().id,
            runtime: runtime_hash,
            icount: Icount { retired: 0 },
            launches: thin_launches.clone(),
            fail_after_launch: false,
        },
    );
    let mut executor = QemuNodeRealizationExecutor::new(
        NodeId {
            name: String::from("vm-a"),
        },
        launcher,
    );
    let resources = AttemptResourceLimits::new(1, 512 * 1024 * 1024, 16 * 1024 * 1024, 16)
        .expect("resource limits");
    let guard = guarded_resume_guard(resources);
    let finishes = guard.finishes.clone();
    let quarantines = guard.quarantines.clone();
    let mut store = ReplayValidationStore {
        baked: QemuBakedGenesisSnapshot {
            world_id: world.id,
            checkpoint: source.snapshot().checkpoint().clone(),
        },
    };
    let promotion = selections
        .validate_and_promote_replay_guarded(
            &fixture.repository,
            &fixture.checkpoints,
            ExactPinReplayTarget::new(
                &world,
                &configuration,
                &fixture.campaign,
                fixture.configuration,
            ),
            &mut store,
            &mut executor,
            guard,
        )
        .expect("guarded compare, reap, and promotion");

    assert_eq!(exact_launches.load(Ordering::SeqCst), 1);
    assert_eq!(thin_launches.load(Ordering::SeqCst), 1);
    assert_eq!(finishes.load(Ordering::SeqCst), 1);
    assert_eq!(quarantines.load(Ordering::SeqCst), 0);
    assert!(!executor.live_backend_is_active());
    assert_ne!(promotion.promoted(), fixture.checkpoint);
}

#[test]
fn failed_guarded_thin_launch_quarantines_resources_without_promotion() {
    let backend = Arc::new(TestDurableBackend::new());
    let fixture = fixture_with_backend("guarded-oracle-failure", backend.clone());
    let temp = tempfile::tempdir().expect("guarded oracle failure workspace");
    let mut selections = DirectoryExactPinMaterializationStore::open(temp.path().join("pins"))
        .expect("selection store");
    select_fixture(&mut selections, &fixture).expect("select raw checkpoint");
    let source = fixture
        .checkpoints
        .load(fixture.checkpoint)
        .expect("load selected raw checkpoint");
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.exact-pin-materialization",
        "guarded-oracle-failure",
    ));
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.exact-pin-materialization.world.v1",
        "guarded-oracle-failure",
    ));
    let runtime_hash = ContentHash::from_canonical_material(
        "crucible.test.exact-pin-materialization.runtime.v1",
        "guarded-oracle-failure",
    );
    let launcher = QemuReplayValidationNodeLauncher::new(
        GuardedResumeLauncher {
            snapshot: source.snapshot().id(),
            runtime: runtime_hash,
            icount: Icount { retired: 0 },
            launches: Arc::new(AtomicUsize::new(0)),
        },
        GuardedThinLauncher {
            checkpoint: source.snapshot().checkpoint().id,
            runtime: runtime_hash,
            icount: Icount { retired: 0 },
            launches: Arc::new(AtomicUsize::new(0)),
            fail_after_launch: true,
        },
    );
    let mut executor = QemuNodeRealizationExecutor::new(
        NodeId {
            name: String::from("vm-a"),
        },
        launcher,
    );
    let guard = guarded_resume_guard(
        AttemptResourceLimits::new(1, 512 * 1024 * 1024, 16 * 1024 * 1024, 16)
            .expect("resource limits"),
    );
    let finishes = guard.finishes.clone();
    let quarantines = guard.quarantines.clone();
    let mut store = ReplayValidationStore {
        baked: QemuBakedGenesisSnapshot {
            world_id: world.id,
            checkpoint: source.snapshot().checkpoint().clone(),
        },
    };
    let count_before = backend.object_count();

    assert!(matches!(
        selections.validate_and_promote_replay_guarded(
            &fixture.repository,
            &fixture.checkpoints,
            ExactPinReplayTarget::new(
                &world,
                &configuration,
                &fixture.campaign,
                fixture.configuration,
            ),
            &mut store,
            &mut executor,
            guard,
        ),
        Err(ExactPinRetentionError::ReplayOracle(
            QemuVmRealizationError::ReapQuarantined {
                operation: "finish guarded replay-oracle comparison",
                ..
            }
        ))
    ));

    assert_eq!(finishes.load(Ordering::SeqCst), 0);
    assert_eq!(quarantines.load(Ordering::SeqCst), 1);
    assert_eq!(backend.object_count(), count_before);
    let mut fence = selections
        .acquire_exact_pin_retention_fence()
        .expect("selection fence");
    assert_eq!(
        fence
            .selection(&fixture.campaign, fixture.configuration)
            .expect("load unchanged selection")
            .expect("raw selection")
            .checkpoint(),
        fixture.checkpoint
    );
}

#[test]
fn selected_checkpoint_materializes_authenticated_vmstate_for_exact_restore() {
    let backend = Arc::new(TestDurableBackend::new());
    let fixture = fixture_with_backend("restore", backend);
    let temp = tempfile::tempdir().expect("restore workspace");
    let mut selections = DirectoryExactPinMaterializationStore::open(temp.path().join("pins"))
        .expect("selection store");
    select_fixture(&mut selections, &fixture).expect("select checkpoint");
    let command = materialization_command();
    let run_directory = temp.path().join("run");
    std::fs::create_dir(&run_directory).expect("run directory");
    let vmstate = run_directory.join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME);
    std::fs::write(&vmstate, b"provisioned").expect("provision VMState file");
    let mut prepared = QemuPreparedRunDirectory::open_for_materialization(
        &command,
        &run_directory,
        u32::MAX,
        u64::MAX,
        u64::MAX,
    )
    .expect("pin materialization destination");

    let restored = crate::materialize_selected_exact_checkpoint(
        &fixture.repository,
        &fixture.checkpoints,
        &mut selections,
        &fixture.campaign,
        fixture.configuration,
        &mut prepared,
        &crate::ExecutionCancellation::default(),
    )
    .expect("materialize selected exact checkpoint");

    assert_eq!(restored.checkpoint(), fixture.checkpoint);
    assert_eq!(restored.pin_fact(), fixture.pin_fact);
    prepared
        .require_exact_vmstate(restored.vmstate_binding())
        .expect("exact root binding");
    assert_eq!(
        std::fs::read(&vmstate).expect("materialized bytes"),
        vec![0x5a; 4096]
    );

    drop(prepared);
    let mut reopened = QemuPreparedRunDirectory::open_for_materialization(
        &command,
        &run_directory,
        u32::MAX,
        u64::MAX,
        u64::MAX,
    )
    .expect("reopen pinned destination after daemon restart");
    assert!(matches!(
        reopened.require_exact_vmstate(restored.vmstate_binding()),
        Err(crucible_qemu::QemuSpawnError::PreparedVmStateNotReady { .. })
    ));
    let rematerialized = crate::materialize_selected_exact_checkpoint(
        &fixture.repository,
        &fixture.checkpoints,
        &mut selections,
        &fixture.campaign,
        fixture.configuration,
        &mut reopened,
        &crate::ExecutionCancellation::default(),
    )
    .expect("rematerialize exact checkpoint after restart");
    reopened
        .require_exact_vmstate(rematerialized.vmstate_binding())
        .expect("reopened exact root binding");
    assert_eq!(
        std::fs::read(vmstate).expect("rematerialized bytes"),
        vec![0x5a; 4096]
    );
}

#[test]
fn attempt_checkpoint_materialization_accepts_only_exact_start_boundaries() {
    let fixture = fixture("attempt-resume-boundary");
    let parent = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.exact-pin-materialization",
        "attempt-resume-parent",
    ));
    let selected = crucible::step(
        &parent,
        crucible::Decision::RngDraw(crucible::RngDecision {
            stream: crucible::RngStreamId::from_name("attempt-resume-selection"),
            value: 17,
        }),
    );
    let checkpoint = Checkpoint::from_recorded_configuration(
        &selected,
        Some(&parent),
        crucible::VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("post-selection checkpoint");
    let snapshot = QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
        .expect("post-selection QEMU snapshot");
    let prepared = fixture
        .checkpoints
        .prepare(&snapshot, BlobHandle::from_bytes(vec![0x6b; 4096]))
        .expect("prepare post-selection checkpoint");
    let checkpoint = fixture
        .checkpoints
        .publish(&prepared)
        .expect("publish post-selection checkpoint")
        .root();
    let foreign = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.exact-pin-materialization",
        "foreign-attempt-boundary",
    ));
    let command = materialization_command();
    let temp = tempfile::tempdir().expect("attempt resume workspace");

    let accepted_directory = temp.path().join("accepted");
    std::fs::create_dir(&accepted_directory).expect("accepted run directory");
    let accepted_vmstate = accepted_directory.join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME);
    std::fs::write(&accepted_vmstate, b"provisioned").expect("provision accepted VMState");
    let mut accepted = QemuPreparedRunDirectory::open_for_materialization(
        &command,
        &accepted_directory,
        u32::MAX,
        u64::MAX,
        u64::MAX,
    )
    .expect("pin accepted materialization destination");

    let materialized = crate::materialize_attempt_exact_checkpoint(
        &fixture.checkpoints,
        checkpoint,
        &parent,
        Some(&selected),
        &mut accepted,
        &crate::ExecutionCancellation::default(),
    )
    .expect("materialize exact post-selection checkpoint");
    assert_eq!(materialized.checkpoint(), checkpoint);
    assert_eq!(
        materialized.snapshot().checkpoint().configuration,
        selected.id()
    );
    accepted
        .require_exact_vmstate(materialized.vmstate_binding())
        .expect("exact operational root binding");
    assert_eq!(
        std::fs::read(&accepted_vmstate).expect("materialized attempt VMState"),
        vec![0x6b; 4096]
    );

    let rejected_directory = temp.path().join("rejected");
    std::fs::create_dir(&rejected_directory).expect("rejected run directory");
    let rejected_vmstate = rejected_directory.join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME);
    std::fs::write(&rejected_vmstate, b"provisioned").expect("provision rejected VMState");
    let mut rejected = QemuPreparedRunDirectory::open_for_materialization(
        &command,
        &rejected_directory,
        u32::MAX,
        u64::MAX,
        u64::MAX,
    )
    .expect("pin rejected materialization destination");

    assert!(matches!(
        crate::materialize_attempt_exact_checkpoint(
            &fixture.checkpoints,
            checkpoint,
            &foreign,
            None,
            &mut rejected,
            &crate::ExecutionCancellation::default(),
        ),
        Err(crate::ExactCheckpointRestoreError::CheckpointConfigurationMismatch {
            checkpoint,
            configuration,
        }) if checkpoint == materialized.checkpoint() && configuration == selected.id()
    ));
    assert_eq!(
        std::fs::read(rejected_vmstate).expect("unchanged rejected VMState"),
        b"provisioned"
    );
}

#[test]
fn exact_restore_binding_distinguishes_same_metadata_with_different_vmstate() {
    let backend = Arc::new(TestDurableBackend::new());
    let fixture = fixture_with_backend("root-binding", backend);
    let temp = tempfile::tempdir().expect("restore workspace");
    let mut selections = DirectoryExactPinMaterializationStore::open(temp.path().join("pins"))
        .expect("selection store");
    select_fixture(&mut selections, &fixture).expect("select first checkpoint");
    let command = materialization_command();
    let run_directory = temp.path().join("run");
    std::fs::create_dir(&run_directory).expect("run directory");
    let vmstate = run_directory.join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME);
    std::fs::write(&vmstate, b"provisioned").expect("provision VMState file");
    let mut prepared = QemuPreparedRunDirectory::open_for_materialization(
        &command,
        &run_directory,
        u32::MAX,
        u64::MAX,
        u64::MAX,
    )
    .expect("pin materialization destination");
    let cancellation = crate::ExecutionCancellation::default();
    let first = crate::materialize_selected_exact_checkpoint(
        &fixture.repository,
        &fixture.checkpoints,
        &mut selections,
        &fixture.campaign,
        fixture.configuration,
        &mut prepared,
        &cancellation,
    )
    .expect("materialize first checkpoint");

    let snapshot = fixture
        .checkpoints
        .load(fixture.checkpoint)
        .expect("reload first checkpoint")
        .snapshot()
        .clone();
    let second = fixture
        .checkpoints
        .prepare(&snapshot, BlobHandle::from_bytes(vec![0x6b; 4096]))
        .and_then(|checkpoint| fixture.checkpoints.publish(&checkpoint))
        .expect("publish second checkpoint root");
    let selection = ExactPinMaterializationSelection::prepare(
        &fixture.repository,
        &fixture.checkpoints,
        &fixture.campaign,
        fixture.configuration,
        second.root(),
    )
    .expect("authenticate replacement checkpoint");
    assert_eq!(
        selections.select(selection).expect("replace selection"),
        ExactPinSelectionDisposition::Replaced
    );
    let replacement = crate::materialize_selected_exact_checkpoint(
        &fixture.repository,
        &fixture.checkpoints,
        &mut selections,
        &fixture.campaign,
        fixture.configuration,
        &mut prepared,
        &cancellation,
    )
    .expect("materialize replacement checkpoint");

    assert_eq!(first.snapshot().id(), replacement.snapshot().id());
    assert_ne!(first.checkpoint(), replacement.checkpoint());
    assert_ne!(first.vmstate_binding(), replacement.vmstate_binding());
    assert!(matches!(
        prepared.require_exact_vmstate(first.vmstate_binding()),
        Err(crucible_qemu::QemuSpawnError::PreparedVmStateBindingMismatch { .. })
    ));
    prepared
        .require_exact_vmstate(replacement.vmstate_binding())
        .expect("replacement exact root binding");
    assert_eq!(
        std::fs::read(vmstate).expect("replacement VMState bytes"),
        vec![0x6b; 4096]
    );
}

#[test]
fn stale_exact_pin_selection_fails_before_vmstate_mutation() {
    let backend = Arc::new(TestDurableBackend::new());
    let fixture = fixture_with_backend("stale-restore", backend);
    let temp = tempfile::tempdir().expect("restore workspace");
    let mut selections = DirectoryExactPinMaterializationStore::open(temp.path().join("pins"))
        .expect("selection store");
    select_fixture(&mut selections, &fixture).expect("select checkpoint");

    let head = fixture
        .repository
        .head(fixture.campaign.as_str())
        .expect("pinned head");
    fixture
        .repository
        .apply_pin(
            fixture.campaign.as_str(),
            &PinRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.exact-pin-materialization.repin.v1",
                    b"stale-restore",
                )),
                expected_snapshot: head.snapshot_id(),
                change: PinChange::new(
                    fixture.configuration,
                    Some(PinRetention::Exact),
                    "renew exact materialization",
                )
                .expect("replacement exact pin"),
            },
        )
        .expect("replace exact pin fact");

    let command = materialization_command();
    let run_directory = temp.path().join("run");
    std::fs::create_dir(&run_directory).expect("run directory");
    let vmstate = run_directory.join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME);
    std::fs::write(&vmstate, b"provisioned").expect("provision VMState file");
    let mut prepared = QemuPreparedRunDirectory::open_for_materialization(
        &command,
        &run_directory,
        u32::MAX,
        u64::MAX,
        u64::MAX,
    )
    .expect("pin materialization destination");

    assert!(matches!(
        crate::materialize_selected_exact_checkpoint(
            &fixture.repository,
            &fixture.checkpoints,
            &mut selections,
            &fixture.campaign,
            fixture.configuration,
            &mut prepared,
            &crate::ExecutionCancellation::default(),
        ),
        Err(crate::ExactCheckpointRestoreError::Selection(
            ExactPinRetentionError::StaleSelection { .. }
        ))
    ));
    assert_eq!(
        std::fs::read(vmstate).expect("unchanged provisioned bytes"),
        b"provisioned"
    );
}

#[test]
fn canceled_exact_restore_fails_before_selection_or_vmstate_io() {
    let backend = Arc::new(TestDurableBackend::new());
    let fixture = fixture_with_backend("canceled-restore", backend);
    let temp = tempfile::tempdir().expect("restore workspace");
    let mut selections = DirectoryExactPinMaterializationStore::open(temp.path().join("pins"))
        .expect("selection store");
    select_fixture(&mut selections, &fixture).expect("select checkpoint");
    let command = materialization_command();
    let run_directory = temp.path().join("run");
    std::fs::create_dir(&run_directory).expect("run directory");
    let vmstate = run_directory.join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME);
    std::fs::write(&vmstate, b"provisioned").expect("provision VMState file");
    let mut prepared = QemuPreparedRunDirectory::open_for_materialization(
        &command,
        &run_directory,
        u32::MAX,
        u64::MAX,
        u64::MAX,
    )
    .expect("pin materialization destination");
    let cancellation = crate::ExecutionCancellation::default();
    cancellation.cancel_for_test();

    assert!(matches!(
        crate::materialize_selected_exact_checkpoint(
            &fixture.repository,
            &fixture.checkpoints,
            &mut selections,
            &fixture.campaign,
            fixture.configuration,
            &mut prepared,
            &cancellation,
        ),
        Err(crate::ExactCheckpointRestoreError::Canceled)
    ));
    assert_eq!(
        std::fs::read(vmstate).expect("unchanged provisioned bytes"),
        b"provisioned"
    );
}

#[test]
fn cancellation_after_vmstate_copy_begins_leaves_destination_unready() {
    let backend = Arc::new(TestDurableBackend::new());
    let fixture = fixture_with_backend("mid-copy-cancel", backend.clone());
    let temp = tempfile::tempdir().expect("restore workspace");
    let mut selections = DirectoryExactPinMaterializationStore::open(temp.path().join("pins"))
        .expect("selection store");
    select_fixture(&mut selections, &fixture).expect("select checkpoint");
    let command = materialization_command();
    let run_directory = temp.path().join("run");
    std::fs::create_dir(&run_directory).expect("run directory");
    let vmstate = run_directory.join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME);
    std::fs::write(&vmstate, b"provisioned").expect("provision VMState file");
    let mut prepared = QemuPreparedRunDirectory::open_for_materialization(
        &command,
        &run_directory,
        u32::MAX,
        u64::MAX,
        u64::MAX,
    )
    .expect("pin materialization destination");
    let cancellation = crate::ExecutionCancellation::default();
    backend.cancel_next_vmstate_read(cancellation.clone());

    assert!(matches!(
        crate::materialize_selected_exact_checkpoint(
            &fixture.repository,
            &fixture.checkpoints,
            &mut selections,
            &fixture.campaign,
            fixture.configuration,
            &mut prepared,
            &cancellation,
        ),
        Err(crate::ExactCheckpointRestoreError::Canceled)
    ));
    let binding = QemuVmStateBinding::from_exact_checkpoint_root_digest(
        fixture.checkpoint.content_id().digest(),
    );
    assert!(matches!(
        prepared.require_exact_vmstate(binding),
        Err(crucible_qemu::QemuSpawnError::PreparedVmStateNotReady { .. })
    ));
    assert!(
        std::fs::read(vmstate)
            .expect("partial destination")
            .is_empty()
    );
}

#[test]
fn gc_requires_current_selection_and_ignores_stale_record_after_unpin() {
    let temp = tempfile::tempdir().expect("exact-pin GC root");
    let node = StoreNodeId::new("durable").expect("store node");
    let (graph, admin) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: node.clone(),
        admitted_kinds: BTreeSet::from([
            ObjectKind::CampaignFact,
            ObjectKind::CampaignSnapshot,
            ObjectKind::MerkleNode,
            ObjectKind::Scenario,
            ObjectKind::Configuration,
            ObjectKind::Policy,
            ObjectKind::ExactManifest,
            ObjectKind::RamExtent,
            ObjectKind::DiskExtent,
            ObjectKind::DeviceState,
            ObjectKind::Observation,
            ObjectKind::Finding,
            ObjectKind::Projection,
            ObjectKind::Trace,
        ]),
        nodes: BTreeMap::from([(
            node,
            StoreNodeSpec::Directory {
                root: temp.path().join("objects"),
            },
        )]),
    })
    .expect("durable store graph");
    let graph = Arc::new(graph);
    let backend: Arc<dyn ImmutableBlobBackend> = graph.clone();
    let fixture = fixture_with_backend("gc", backend);
    let mut ledger = crate::MemoryAssignmentLedger::default();
    let mut selections = DirectoryExactPinMaterializationStore::open(temp.path().join("pins"))
        .expect("selection store");

    assert!(matches!(
        crate::plan_single_host_campaign_gc(
            &fixture.repository,
            fixture.refs.as_ref(),
            &mut ledger,
            None,
            None,
            &admin,
        ),
        Err(crate::CampaignGcPlanningError::MissingExactPinMaterialization { .. })
    ));
    select_fixture(&mut selections, &fixture).expect("select exact materialization");
    let planned = crate::plan_single_host_campaign_gc(
        &fixture.repository,
        fixture.refs.as_ref(),
        &mut ledger,
        None,
        Some(&mut selections),
        &admin,
    )
    .expect("plan with exact materialization");
    assert!(
        planned
            .roots()
            .iter()
            .any(|root| root == fixture.checkpoint.content_id())
    );
    assert!(
        !planned
            .candidates()
            .iter()
            .any(|candidate| candidate.id() == fixture.checkpoint.content_id())
    );
    let (mut journal, _) =
        crate::DirectoryCampaignGcJournal::create(temp.path().join("gc-journal"), &planned)
            .expect("persist exact-pin GC plan");

    let head = fixture
        .repository
        .head(fixture.campaign.as_str())
        .expect("current pinned head");
    let unpin = PinRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive(
            "crucible.test.exact-pin-materialization.unpin.v1",
            b"gc",
        )),
        expected_snapshot: head.snapshot_id(),
        change: PinChange::new(fixture.configuration, None, "release exact materialization")
            .expect("unpin change"),
    };
    fixture
        .repository
        .apply_pin(fixture.campaign.as_str(), &unpin)
        .expect("unpin campaign");

    assert!(matches!(
        crate::apply_single_host_campaign_gc(
            &mut journal,
            &fixture.repository,
            fixture.refs.as_ref(),
            &mut ledger,
            None,
            Some(&mut selections),
            &admin,
        ),
        Err(crate::CampaignGcApplyError::RefBasisChanged)
    ));
    assert!(
        graph
            .contains(fixture.checkpoint.content_id())
            .expect("checkpoint retained after stale plan rejection")
    );

    let after_unpin = crate::plan_single_host_campaign_gc(
        &fixture.repository,
        fixture.refs.as_ref(),
        &mut ledger,
        None,
        Some(&mut selections),
        &admin,
    )
    .expect("plan after unpin with stale selection record");
    assert!(
        !after_unpin
            .roots()
            .iter()
            .any(|root| root == fixture.checkpoint.content_id())
    );
    assert!(
        after_unpin
            .candidates()
            .iter()
            .any(|candidate| candidate.id() == fixture.checkpoint.content_id())
    );
    drop(admin);
    drop(graph);
}

#[test]
fn selection_authenticates_pin_and_checkpoint_and_survives_restart() {
    let temp = tempfile::tempdir().expect("selection journal root");
    let fixture = fixture("round-trip");
    let mut store = DirectoryExactPinMaterializationStore::open(temp.path())
        .expect("open exact-pin selection store");

    assert_eq!(
        select_fixture(&mut store, &fixture).expect("select exact checkpoint"),
        ExactPinSelectionDisposition::Stored
    );
    assert_eq!(
        select_fixture(&mut store, &fixture).expect("replay exact selection"),
        ExactPinSelectionDisposition::Existing
    );

    let path = store.selection_path(&fixture.campaign, fixture.configuration);
    let bytes = fs::read(&path).expect("read canonical selection");
    let decoded = decode_selection(&bytes).expect("decode canonical selection");
    assert_eq!(
        CampaignHash::derive(
            "crucible.test.exact-pin-materialization-selection-golden.v1",
            &bytes,
        )
        .to_hex(),
        "ca7198fa080f09a40df4c9142425566ad40958c1d9d8c30404749aee642614bb"
    );
    assert_eq!(decoded.campaign(), &fixture.campaign);
    assert_eq!(decoded.configuration(), fixture.configuration);
    assert_eq!(decoded.pin_fact(), fixture.pin_fact);
    assert_eq!(decoded.checkpoint(), fixture.checkpoint);
    drop(store);

    let mut reopened = DirectoryExactPinMaterializationStore::open(temp.path())
        .expect("reopen exact-pin selection store");
    let mut fence = reopened
        .acquire_exact_pin_retention_fence()
        .expect("acquire restarted selection fence");
    assert_eq!(
        fence
            .selection(&fixture.campaign, fixture.configuration)
            .expect("load restarted selection"),
        Some(decoded)
    );
}

#[test]
fn selection_rejects_wrong_checkpoint_before_journal_write() {
    let temp = tempfile::tempdir().expect("selection journal root");
    let expected = fixture("expected");
    let foreign = fixture("foreign");
    let mut store = DirectoryExactPinMaterializationStore::open(temp.path())
        .expect("open exact-pin selection store");

    assert!(matches!(
        ExactPinMaterializationSelection::prepare(
            &expected.repository,
            &foreign.checkpoints,
            &expected.campaign,
            expected.configuration,
            foreign.checkpoint,
        ),
        Err(ExactPinRetentionError::CheckpointConfigurationMismatch { .. })
    ));
    assert!(
        store
            .acquire_exact_pin_retention_fence()
            .expect("selection fence")
            .selection(&expected.campaign, expected.configuration)
            .expect("selection lookup")
            .is_none()
    );
}

#[test]
fn clear_is_idempotent_and_corruption_fails_closed() {
    let temp = tempfile::tempdir().expect("selection journal root");
    let fixture = fixture("clear");
    let mut store = DirectoryExactPinMaterializationStore::open(temp.path())
        .expect("open exact-pin selection store");
    select_fixture(&mut store, &fixture).expect("select checkpoint");
    assert_eq!(
        store
            .clear(&fixture.campaign, fixture.configuration)
            .expect("clear selection"),
        ExactPinSelectionClearDisposition::Removed
    );
    assert_eq!(
        store
            .clear(&fixture.campaign, fixture.configuration)
            .expect("replay clear"),
        ExactPinSelectionClearDisposition::Absent
    );

    select_fixture(&mut store, &fixture).expect("restore selection");
    let path = store.selection_path(&fixture.campaign, fixture.configuration);
    let mut bytes = fs::read(&path).expect("read selection");
    let index = SELECTION_MAGIC.len() + 3;
    bytes[index] ^= 0x80;
    fs::write(&path, bytes).expect("corrupt selection");
    assert!(matches!(
        store
            .acquire_exact_pin_retention_fence()
            .expect("selection fence")
            .selection(&fixture.campaign, fixture.configuration),
        Err(ExactPinRetentionError::Corrupt { .. })
    ));
}

fn fixture(name: &str) -> Fixture {
    let backend = Arc::new(TestDurableBackend::new());
    fixture_with_backend(name, backend)
}

fn select_fixture(
    store: &mut DirectoryExactPinMaterializationStore,
    fixture: &Fixture,
) -> Result<ExactPinSelectionDisposition, ExactPinRetentionError> {
    let selection = ExactPinMaterializationSelection::prepare(
        &fixture.repository,
        &fixture.checkpoints,
        &fixture.campaign,
        fixture.configuration,
        fixture.checkpoint,
    )?;
    store.select(selection)
}

fn fixture_with_backend(name: &str, backend: Arc<dyn ImmutableBlobBackend>) -> Fixture {
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(backend.clone(), refs.clone());
    let scenario =
        ScenarioDef::from_canonical_material("crucible.test.exact-pin-materialization", name);
    let configuration = Configuration::genesis(scenario.clone());
    let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes));
    let configuration_id =
        ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes));
    let scenario_artifact = repository
        .publish_scenario_artifact(scenario_id, 1, name.as_bytes().to_vec())
        .expect("scenario artifact");
    let configuration_artifact = repository
        .publish_configuration_artifact(
            scenario_id,
            scenario_artifact,
            configuration_id,
            1,
            name.as_bytes().to_vec(),
        )
        .expect("configuration artifact");
    let lineage = CampaignLineage::new(
        scenario_id,
        scenario_artifact,
        configuration_id,
        configuration_artifact,
        "crucible-v1",
        "qemu-build-v1",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("lineage");
    let policy = policy(scenario_id);
    let campaign = CampaignName::new(format!("exact-pin-{name}")).expect("campaign name");
    let created = repository
        .create(campaign.as_str(), &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    let pin = PinRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive(
            "crucible.test.exact-pin-materialization.command.v1",
            name.as_bytes(),
        )),
        expected_snapshot: created.snapshot_id(),
        change: PinChange::new(
            configuration_id,
            Some(PinRetention::Exact),
            "retain exact materialization",
        )
        .expect("pin change"),
    };
    repository
        .apply_pin(campaign.as_str(), &pin)
        .expect("pin campaign");
    let mut pin_fact = None;
    repository
        .visit_pin_retention_roots(campaign.as_str(), &mut |record| {
            pin_fact = Some(record.fact());
        })
        .expect("pin inventory");

    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        crucible::VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("checkpoint");
    let snapshot = QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
        .expect("QEMU snapshot");
    let checkpoints = ExactCheckpointStore::new(backend, STORE_LIMIT).expect("checkpoint store");
    let prepared = checkpoints
        .prepare(&snapshot, BlobHandle::from_bytes(vec![0x5a; 4096]))
        .expect("prepare checkpoint");
    let checkpoint = checkpoints
        .publish(&prepared)
        .expect("publish checkpoint")
        .root();

    Fixture {
        repository,
        refs,
        checkpoints,
        campaign,
        configuration: configuration_id,
        pin_fact: pin_fact.expect("exact pin fact"),
        checkpoint,
    }
}

fn materialization_command() -> QemuLaunchCommand {
    let manifest = FaultRegisterCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        cpu_model: String::from("qemu64-x86_64-cpu"),
        rows: vec![FaultRegisterCapabilityRowV1 {
            numeric_id: 1,
            name: String::from("rax"),
            width_bits: 8,
            group: FaultRegisterGroupV1::GeneralPurpose,
            model_phase_mask: 1 << (11 - 1),
            side_effects: 0,
            capabilities: FAULT_REGISTER_CAPABILITY_IMPULSE | FAULT_REGISTER_CAPABILITY_VMSTATE,
            writable_mask: vec![0x0f],
            reserved_mask: vec![0x30],
            ignored_mask: vec![0x40],
            read_only_mask: vec![0x80],
        }],
    };
    let encoded = manifest.encode().expect("encode register manifest");
    let signal = |value: &str| SignalId::parse(value).expect("canonical signal ID");
    let node = WorldNodeFaultCapabilities {
        id: signal("node-capabilities"),
        node: signal("vm-a"),
        architecture: WorldNodeArchitecture::X86_64,
        cpu_model: manifest.cpu_model,
        register_schema: ContentHash::from_bytes(&encoded),
        registers: vec![WorldNodeRegister {
            id: signal("rax"),
            name: String::from("rax"),
            numeric_id: 1,
            group: WorldNodeRegisterGroup::GeneralPurpose,
            width_bits: 8,
            per_vcpu: true,
            model_phases: vec![FaultPhase::BeforeInstruction],
            side_effects: Vec::new(),
            impulse: true,
            persistent: false,
            vmstate: true,
            writable_mask_hex: String::from("0f"),
            reserved_mask_hex: String::from("30"),
            ignored_mask_hex: String::from("40"),
            read_only_mask_hex: String::from("80"),
        }],
        address_spaces: Vec::new(),
        page_bytes: 4096,
        dram_geometry: WorldNodeDramGeometry::emulated_v1(),
        interrupts: Vec::new(),
        hardware_errors: Vec::new(),
        clock_sources: vec![WorldNodeClockSource::emulated_x86_tsc_v1(signal(
            "x86-tsc-vcpu-0",
        ))],
        accelerators: Vec::new(),
        ready_markers: Vec::new(),
        semantic_version: 1,
    };
    let requirement =
        QemuFaultCapabilityRequirement::current_v1_for_node(&node).expect("fault requirement");
    let artifact = |domain: &str, path: &str| {
        QemuLaunchArtifact::new(
            ContentHash::from_canonical_material(domain, "restore"),
            path,
        )
    };
    let vm = QemuVmLaunchConfig::new(
        "vm-a",
        artifact(
            "kernel",
            "/nix/store/33333333333333333333333333333333-crucible-kernel/bzImage",
        ),
        artifact(
            "root-image",
            "/nix/store/44444444444444444444444444444444-crucible-root/root.qcow2",
        ),
    );
    let plugin = QemuLaunchPluginConfig::new(
        "/nix/store/22222222222222222222222222222222-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so",
        0,
    )
    .with_fault_target_node("vm-a");
    QemuLaunchCommandBuilder::new(
        DeterministicLaunchProfile::conservative_default().expect("launch profile"),
        vm,
        "/nix/store/11111111111111111111111111111111-aos-qemu/bin/qemu-system-x86_64",
        plugin,
        requirement,
    )
    .build()
    .expect("materialization command")
}

fn policy(scenario: ScenarioDefId) -> CampaignPolicy {
    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1).expect("rational"),
        ExactRational::new(1, 2).expect("rational"),
        1,
        100,
        1,
    )
    .expect("widening");
    CampaignPolicy::new(
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
    .expect("policy")
}
