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
use std::time::Duration;

use crucible::model::MeasurementTerminalState;
use crucible::{
    Configuration, ContentHash, Decision, EventLog, ExecutionFingerprint, FingerprintSample,
    Icount, MarkerId, NodeId, ObservableEvent, ScenarioDefForm, ScenarioSelectableLimits,
    ScenarioSelectables, SchedulerEventLogEntry, SchedulerNodeActivity, SchedulerQuiescence,
    SelectionDecision, World, WorldNodeDef,
};
use crucible_api::vm_lifecycle::{
    hot_fork_adoption_count_for_test,
    prepared_multi_node_hot_fork_source_world_for_scenario_for_test,
    prepared_multi_node_hot_fork_source_world_with_powered_off_for_scenario_for_test,
    reset_hot_fork_adoption_count_for_test,
};
use crucible_api::{ProductionFaultEvidenceSnapshot, ProductionVmNodeReplayLaunchProfile};
use crucible_campaign::{
    AlternativeId, AssignmentId, Attempt, AttemptResourceLimits, AttemptStart, AttemptStartMode,
    BooleanDomain, BranchPath, BranchPathSegment, BudgetGrant, CampaignCommandId,
    CampaignControlAction, CampaignExecutorStore, CampaignHash, CampaignLineage, CampaignMode,
    CampaignPolicy, CampaignRepository, CampaignSeed, ChoiceClassContext, ChoiceCoordinate,
    ChoiceDomain, ChoiceSource, ChoiceValue, ConfigurationId, ControlRequest, CoverageProjection,
    DaemonEpoch, DiscreteAlternative, DiscreteDomain, ExactCheckpointId, ExactRational,
    ExecutionId, ExecutionRetentionIntent, ExecutorCompatibilityProfile, ExecutorService,
    ExplorerPolicy, FairnessPolicy, IntegerDomain, IntegerRepresentation, IntegerValue,
    Observation, ObservationCandidate, ProgressiveWideningPolicy, PropertyVerdictSet, PuctPolicy,
    RetentionPolicy, SelectableDeclaration, Selection, SelectionOrigin, StopCondition, StopOutcome,
    SubmitAttemptDisposition, SubmitAttemptRequest,
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
    QemuNodeSelectablePendingRequest, QemuPreparedRunDirectory, QemuProcessIdentity,
    QemuTestHotForkIsolationFault, QemuTestHotForkOutcome, QemuVmRealizationError,
    linux_process_identity, scripted_hot_fork_source_for_test,
    scripted_hot_fork_source_with_state_for_test,
};
use rustix::process::{Pid, PidfdFlags, pidfd_open};

use super::*;
use crate::packaged_qemu_executor::PackagedQemuInitialExecutionRunner;
use crate::qemu_campaign_lifecycle::{
    QemuAttemptExecutionEvidence, QemuTerminalEvidenceExecutionRunner,
    QemuTerminalEvidenceExecutionRunnerError,
};
use crate::{
    AttemptExecutionKey, AttemptExecutionRuntimeBasis, AttemptResultStageOutcome,
    AttemptWorkerReconcileOutcome, AuthenticatedCanonicalQemuHotForkSource, CompletionOutcome,
    CrucibleExecutionModel, CrucibleExecutionRunner, CrucibleMaterializationTier,
    ExactCheckpointStore, ExecutionCancellation, ExecutionCheckpointRequest, ExecutorCapacity,
    HotCheckpointFallback, HotCheckpointHotnessSignals, HotCheckpointLimits,
    HotCheckpointPlannedDemotion, HotCheckpointPoolKey, HotCheckpointResourceProfile,
    HotCheckpointSourceDemoter, HotCheckpointTemplateDemotionFailure,
    HotCheckpointTemplateDemotionSink, LocalAttemptWorker, LocalExecutorSupervisor,
    ManagedQemuHotForkSourceWorld, ManagedQemuHotForkSourceWorldPool, MemoryAssignmentLedger,
    MemoryHotCheckpointFallbackRetentionStore, PreparedAttemptWorkResult,
    QemuAttemptExecutionRouter, QemuAttemptOperationalBoundary, QemuAttemptResourceGuard,
    QemuAttemptStartReplayProof, QemuAttemptStartVerifier, QemuFreshModeledDriver,
    QemuHotFirstExecutionRouter, QemuHotForkSourceWorldDemoter,
    QemuHotForkSourceWorldDemotionError, QemuOrdinaryResumeRunner, QemuSavepointReplayProof,
    QemuSelectedOriginResumeRunner, QemuSelectedOriginVerifier, RepositoryAttemptAdmission,
    RepositoryAttemptWorker, SharedManagedQemuHotForkSourceWorldPool,
    decode_crucible_configuration_artifact_with_selections, encode_crucible_configuration_artifact,
    encode_crucible_scenario_artifact, prepare_attempt_result, publish_prepared_attempt_result,
    reconcile_published_attempt_result, stage_prepared_attempt_result,
};

#[path = "tests/native_acceptance.rs"]
mod native_acceptance;

#[path = "tests/world_fork_atomicity.rs"]
mod world_fork_atomicity;

#[cfg(feature = "destructive-recovery-faults")]
const WORLD_FORK_PREFLIGHT_FAILURE_CHILD_ENVIRONMENT: &str =
    "CRUCIBLE_DESTRUCTIVE_RECOVERY_WORLD_FORK_PREFLIGHT_FAILURE_CHILD";
#[cfg(feature = "destructive-recovery-faults")]
const CHILD_RESOURCE_ALIAS_CHILD_ENVIRONMENT: &str =
    "CRUCIBLE_DESTRUCTIVE_RECOVERY_CHILD_RESOURCE_ALIAS_CHILD";
#[cfg(feature = "destructive-recovery-faults")]
const DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT: &str = "CRUCIBLE_DESTRUCTIVE_RECOVERY_TRIGGER";
#[cfg(feature = "destructive-recovery-faults")]
const WORLD_FORK_PREFLIGHT_FAILURE_TRIGGER: &str =
    "crucible.destructive-recovery.world-fork-preflight-failure";
#[cfg(feature = "destructive-recovery-faults")]
const CHILD_RESOURCE_ALIAS_TRIGGER: &str = "crucible.destructive-recovery.child-resource-alias";
#[cfg(feature = "destructive-recovery-faults")]
const WORLD_FORK_PREFLIGHT_FAILURE_TEST_NAME: &str = "qemu_hot_fork_world_factory::tests::reconciliation::lifecycle::world_fork_preflight_failure_restores_source_world";
#[cfg(feature = "destructive-recovery-faults")]
const CHILD_RESOURCE_ALIAS_TEST_NAME: &str = "qemu_hot_fork_world_factory::tests::reconciliation::lifecycle::child_resource_alias_rejects_before_fork_and_restores_source_world";

struct ScriptedWorldGuard {
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    process_contract: QemuChildProcessContract,
    run_root: tempfile::TempDir,
    finishes: Arc<AtomicUsize>,
    finish_failures_remaining: Arc<AtomicUsize>,
    prepare_rejections_remaining: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
    prepared_run_directories: Arc<Mutex<Vec<PathBuf>>>,
    retained_child_processes: Arc<Mutex<Vec<u32>>>,
    retained_child_identities: Arc<Mutex<Vec<QemuProcessIdentity>>>,
    retained_child_requests: Arc<Mutex<Vec<crucible_qemu::QmpHotForkRequest>>>,
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
        if self
            .finish_failures_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(test_realization_error("scripted target cleanup failure"));
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
        if self
            .prepare_rejections_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(test_realization_error(
                "scripted target run-directory rejection",
            ));
        }

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
        let prepared = QemuPreparedRunDirectory::open_for_test_requirements(
            requirements,
            generation.clone(),
            &self.process_contract,
        )
        .map_err(test_realization_error)?;
        self.prepared_run_directories
            .lock()
            .map_err(|_error| test_realization_error("prepared directory registry is poisoned"))?
            .push(generation);
        Ok(prepared)
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
        self.retained_child_identities
            .lock()
            .map_err(|_error| {
                QemuNodeChannelError::new(
                    "record scripted child identity",
                    "scripted child identity registry is poisoned",
                )
            })?
            .push(identity.clone());
        self.retained_child_requests
            .lock()
            .map_err(|_error| {
                QemuNodeChannelError::new(
                    "record scripted child request",
                    "scripted child request registry is poisoned",
                )
            })?
            .push(basis.request());
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
    finish_failures_remaining: Arc<AtomicUsize>,
    prepare_rejections_remaining: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
    prepared_run_directories: Arc<Mutex<Vec<PathBuf>>>,
    retained_child_processes: Arc<Mutex<Vec<u32>>>,
    retained_child_identities: Arc<Mutex<Vec<QemuProcessIdentity>>>,
    retained_child_requests: Arc<Mutex<Vec<crucible_qemu::QmpHotForkRequest>>>,
    guard_liveness: Arc<Mutex<Option<Weak<()>>>>,
}

impl ScriptedWorldObservations {
    fn new() -> Self {
        Self {
            finishes: Arc::new(AtomicUsize::new(0)),
            finish_failures_remaining: Arc::new(AtomicUsize::new(0)),
            prepare_rejections_remaining: Arc::new(AtomicUsize::new(0)),
            quarantines: Arc::new(AtomicUsize::new(0)),
            prepared_run_directories: Arc::new(Mutex::new(Vec::new())),
            retained_child_processes: Arc::new(Mutex::new(Vec::new())),
            retained_child_identities: Arc::new(Mutex::new(Vec::new())),
            retained_child_requests: Arc::new(Mutex::new(Vec::new())),
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
        _selected_checkpoint: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Result<Self::Guard, crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure>
    {
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
            finish_failures_remaining: Arc::clone(&self.observations.finish_failures_remaining),
            prepare_rejections_remaining: Arc::clone(
                &self.observations.prepare_rejections_remaining,
            ),
            quarantines: Arc::clone(&self.observations.quarantines),
            prepared_run_directories: Arc::clone(&self.observations.prepared_run_directories),
            retained_child_processes: Arc::clone(&self.observations.retained_child_processes),
            retained_child_identities: Arc::clone(&self.observations.retained_child_identities),
            retained_child_requests: Arc::clone(&self.observations.retained_child_requests),
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
    result: crate::PreparedSemanticAttemptResult,
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
        let (events, _bytes, _completed_quanta, _frontier, _terminal_quiescence, _terminal_verdict) =
            materialization.into_parts();
        assert!(events.is_empty());
        self.drives.fetch_add(1, Ordering::SeqCst);
        Ok(QemuFreshDriveOutcome::Observation(
            self.result.observation().clone(),
        ))
    }

    fn seal(
        &mut self,
        candidate: Self::Pending,
        _final_events: Vec<crucible::SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        self.seals.fetch_add(1, Ordering::SeqCst);
        assert_eq!(&candidate, self.result.observation());
        Ok(AttemptExecutionProduct::prepared_semantic(
            self.result.clone(),
        ))
    }
}

#[derive(Clone)]
struct BranchReplayObservations {
    replay_requests: Arc<Mutex<Vec<Configuration>>>,
    guest_replies: Arc<Mutex<Vec<crucible_protocol::SelectionReply>>>,
    driver_starts: Arc<Mutex<Vec<Configuration>>>,
    terminal_fingerprint_prepares: Arc<AtomicUsize>,
    shutdowns: Arc<AtomicUsize>,
    recoveries: Arc<AtomicUsize>,
    recovery_failures_remaining: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
}

impl BranchReplayObservations {
    fn new() -> Self {
        Self {
            replay_requests: Arc::new(Mutex::new(Vec::new())),
            guest_replies: Arc::new(Mutex::new(Vec::new())),
            driver_starts: Arc::new(Mutex::new(Vec::new())),
            terminal_fingerprint_prepares: Arc::new(AtomicUsize::new(0)),
            shutdowns: Arc::new(AtomicUsize::new(0)),
            recoveries: Arc::new(AtomicUsize::new(0)),
            recovery_failures_remaining: Arc::new(AtomicUsize::new(0)),
            quarantines: Arc::new(AtomicUsize::new(0)),
        }
    }
}

struct BranchReplayLifecycle {
    runtime_basis: AttemptExecutionRuntimeBasis,
    selected: Configuration,
    pending_guest_request: Option<QemuNodeSelectablePendingRequest>,
    observations: BranchReplayObservations,
}

impl QemuFreshAttemptLifecycleOwner for BranchReplayLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {}

    fn set_attempt_stop_frontier(
        &mut self,
        _frontier: Option<crucible::VirtualTime>,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn drive_quantum(
        &mut self,
        request: crucible::QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, crucible::SchedulerError> {
        self.observations
            .replay_requests
            .lock()
            .expect("branch replay requests")
            .push(request.configuration.clone());
        let configuration = if self.pending_guest_request.is_some() {
            request.configuration
        } else {
            self.selected.clone()
        };

        Ok(crucible::QuantumOutcome {
            configuration,
            frontier: crucible::VirtualTime { ticks: 1 },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }

    fn completed_quanta(&self) -> u64 {
        0
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<crucible::QuantumTerminalVerdict> {
        None
    }

    fn prepare_terminal_checkpoint(
        &mut self,
        _cause: crucible::CheckpointTerminalCause,
    ) -> Result<(), SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from(
                "branch replay fixture cannot retain a terminal checkpoint cause",
            ),
        })
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, crucible::SchedulerError> {
        Ok(false)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, crucible::SchedulerError> {
        Ok(self.pending_guest_request.take().into_iter().collect())
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &crucible::Configuration,
        _decision: crucible::SelectionDecision,
        _selected: &crucible::Configuration,
        _pending: &QemuNodeSelectablePendingRequest,
        reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<crucible::SchedulerEventLogEntry>, crucible::SchedulerError> {
        self.observations
            .guest_replies
            .lock()
            .expect("branch replay guest replies")
            .push(reply.clone());
        Ok(Vec::new())
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &AttemptExecutionContext,
    ) -> Result<crate::CapturedAttemptCheckpoint, crucible::SchedulerError> {
        Err(crucible::SchedulerError::BoundaryViolation {
            message: String::from("scripted branch replay has no checkpoint authority"),
        })
    }

    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("branch replay fixture has no replay launch profiles"),
        })
    }

    fn fault_evidence_snapshot(
        &self,
    ) -> Result<ProductionFaultEvidenceSnapshot, crucible::SchedulerError> {
        Err(crucible::SchedulerError::BoundaryViolation {
            message: String::from("scripted branch replay has no fault evidence"),
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn prepare_terminal_fingerprints(&mut self) -> Result<(), SchedulerError> {
        self.observations
            .terminal_fingerprint_prepares
            .fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        let hash = ContentHash::from_bytes(node.name.as_bytes());
        Ok(FingerprintSample {
            node,
            at: crucible::VirtualTime { ticks: 1 },
            fingerprint: ExecutionFingerprint { hash },
        })
    }

    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, SchedulerError> {
        Ok(None)
    }

    fn shutdown(
        &mut self,
    ) -> Result<Vec<crucible::SchedulerEventLogEntry>, crucible::SchedulerError> {
        self.observations.shutdowns.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }
}

impl QemuHotForkWorldLifecycleOwner for BranchReplayLifecycle {
    fn runtime_basis(&self) -> AttemptExecutionRuntimeBasis {
        self.runtime_basis
    }

    fn start_materialization(
        &self,
    ) -> Result<crate::QemuFreshStartMaterialization, crucible::SchedulerError> {
        Ok(crate::QemuFreshStartMaterialization::genesis())
    }

    fn reconcile_execution_disposition(
        &mut self,
        _disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, crucible_api::LifecycleApiError> {
        Ok(AttemptExecutionReconciliationStep::Complete)
    }
}

struct BranchReplayLifecycleFactory {
    observations: BranchReplayObservations,
}

impl QemuHotForkWorldLifecycleFactory for BranchReplayLifecycleFactory {
    type Lifecycle = BranchReplayLifecycle;
    type Error = Infallible;

    fn try_start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuHotForkWorldLifecycleStart<Self::Lifecycle>, AttemptWorkerFailure<Self::Error>>
    {
        let crate::CrucibleResolvedAttemptStart::Branch {
            selection,
            selected,
            ..
        } = input.start()
        else {
            panic!("branch replay factory requires a branch attempt")
        };
        let pending_guest_request =
            matches!(selection.opportunity().source(), ChoiceSource::Guest { .. }).then(|| {
                branch_replay_guest_pending(
                    selection.declaration(),
                    selection.opportunity().instance(),
                )
            });

        Ok(QemuHotForkWorldLifecycleStart::Started(
            BranchReplayLifecycle {
                runtime_basis: context.runtime_basis().expect("branch runtime basis"),
                selected: selected.clone(),
                pending_guest_request,
                observations: self.observations.clone(),
            },
        ))
    }

    fn recover(&mut self, lifecycle: Self::Lifecycle) -> Result<(), Self::Lifecycle> {
        self.observations.recoveries.fetch_add(1, Ordering::SeqCst);
        if self
            .observations
            .recovery_failures_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(lifecycle);
        }
        Ok(())
    }

    fn quarantine(&mut self, lifecycle: Self::Lifecycle) {
        lifecycle
            .observations
            .quarantines
            .fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Clone)]
struct InheritedBoundaryObservations {
    drives: Arc<AtomicUsize>,
    terminal_fingerprint_prepares: Arc<AtomicUsize>,
    shutdowns: Arc<AtomicUsize>,
    recoveries: Arc<AtomicUsize>,
}

impl InheritedBoundaryObservations {
    fn new() -> Self {
        Self {
            drives: Arc::new(AtomicUsize::new(0)),
            terminal_fingerprint_prepares: Arc::new(AtomicUsize::new(0)),
            shutdowns: Arc::new(AtomicUsize::new(0)),
            recoveries: Arc::new(AtomicUsize::new(0)),
        }
    }
}

struct InheritedBoundaryLifecycle {
    runtime_basis: AttemptExecutionRuntimeBasis,
    configuration: Configuration,
    start_events: Vec<SchedulerEventLogEntry>,
    completed_quanta: u64,
    frontier: crucible::VirtualTime,
    observations: InheritedBoundaryObservations,
}

impl QemuFreshAttemptLifecycleOwner for InheritedBoundaryLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {}

    fn set_attempt_stop_frontier(
        &mut self,
        _frontier: Option<crucible::VirtualTime>,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn drive_quantum(
        &mut self,
        _request: crucible::QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, crucible::SchedulerError> {
        self.observations.drives.fetch_add(1, Ordering::SeqCst);
        Err(crucible::SchedulerError::BoundaryViolation {
            message: String::from("inherited absolute stop forbids another quantum"),
        })
    }

    fn completed_quanta(&self) -> u64 {
        self.completed_quanta
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<crucible::QuantumTerminalVerdict> {
        None
    }

    fn prepare_terminal_checkpoint(
        &mut self,
        _cause: crucible::CheckpointTerminalCause,
    ) -> Result<(), SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from(
                "inherited boundary fixture cannot retain a terminal checkpoint cause",
            ),
        })
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, crucible::SchedulerError> {
        Ok(false)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, crucible::SchedulerError> {
        Ok(Vec::new())
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &crucible::Configuration,
        _decision: crucible::SelectionDecision,
        _selected: &crucible::Configuration,
        _pending: &QemuNodeSelectablePendingRequest,
        _reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<crucible::SchedulerEventLogEntry>, crucible::SchedulerError> {
        Ok(Vec::new())
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &AttemptExecutionContext,
    ) -> Result<crate::CapturedAttemptCheckpoint, crucible::SchedulerError> {
        Err(crucible::SchedulerError::BoundaryViolation {
            message: String::from("inherited-boundary fixture has no checkpoint authority"),
        })
    }

    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("inherited-boundary fixture has no replay launch profiles"),
        })
    }

    fn fault_evidence_snapshot(
        &self,
    ) -> Result<ProductionFaultEvidenceSnapshot, crucible::SchedulerError> {
        Err(crucible::SchedulerError::BoundaryViolation {
            message: String::from("inherited-boundary fixture has no fault evidence"),
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn prepare_terminal_fingerprints(&mut self) -> Result<(), SchedulerError> {
        self.observations
            .terminal_fingerprint_prepares
            .fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        let hash = ContentHash::from_bytes(node.name.as_bytes());
        Ok(FingerprintSample {
            node,
            at: self.frontier,
            fingerprint: ExecutionFingerprint { hash },
        })
    }

    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, SchedulerError> {
        Ok(None)
    }

    fn shutdown(
        &mut self,
    ) -> Result<Vec<crucible::SchedulerEventLogEntry>, crucible::SchedulerError> {
        self.observations.shutdowns.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }
}

impl QemuHotForkWorldLifecycleOwner for InheritedBoundaryLifecycle {
    fn runtime_basis(&self) -> AttemptExecutionRuntimeBasis {
        self.runtime_basis
    }

    fn start_materialization(
        &self,
    ) -> Result<crate::QemuFreshStartMaterialization, crucible::SchedulerError> {
        let event_log_bytes = self
            .start_events
            .iter()
            .map(SchedulerEventLogEntry::canonical_material_len)
            .sum();
        Ok(crate::QemuFreshStartMaterialization::from_resume_parts(
            self.configuration.clone(),
            self.start_events.clone(),
            event_log_bytes,
            self.completed_quanta,
            self.frontier,
            SchedulerQuiescence::default(),
            None,
        ))
    }

    fn reconcile_execution_disposition(
        &mut self,
        _disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, crucible_api::LifecycleApiError> {
        Ok(AttemptExecutionReconciliationStep::Complete)
    }
}

struct InheritedBoundaryLifecycleFactory {
    start_events: Vec<SchedulerEventLogEntry>,
    completed_quanta: u64,
    frontier: crucible::VirtualTime,
    observations: InheritedBoundaryObservations,
}

impl QemuHotForkWorldLifecycleFactory for InheritedBoundaryLifecycleFactory {
    type Lifecycle = InheritedBoundaryLifecycle;
    type Error = Infallible;

    fn try_start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuHotForkWorldLifecycleStart<Self::Lifecycle>, AttemptWorkerFailure<Self::Error>>
    {
        Ok(QemuHotForkWorldLifecycleStart::Started(
            InheritedBoundaryLifecycle {
                runtime_basis: context.runtime_basis().expect("inherited runtime basis"),
                configuration: input.start().configuration().clone(),
                start_events: self.start_events.clone(),
                completed_quanta: self.completed_quanta,
                frontier: self.frontier,
                observations: self.observations.clone(),
            },
        ))
    }

    fn recover(&mut self, _lifecycle: Self::Lifecycle) -> Result<(), Self::Lifecycle> {
        self.observations.recoveries.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn quarantine(&mut self, _lifecycle: Self::Lifecycle) {}
}

struct BranchReplayDriver {
    result: crate::PreparedSemanticAttemptResult,
    observations: BranchReplayObservations,
}

impl QemuFreshAttemptDriver for BranchReplayDriver {
    type Pending = ObservationCandidate;
    type Error = Infallible;

    fn drive(
        &mut self,
        _lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        materialization: crate::QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>> {
        let (events, bytes, _completed_quanta, _frontier, quiescence, verdict) =
            materialization.into_parts();
        assert!(events.is_empty());
        assert_eq!(bytes, 0);
        assert!(quiescence.is_none());
        assert!(verdict.is_none());
        let crate::CrucibleResolvedAttemptStart::Branch { selected, .. } = input.start() else {
            panic!("branch replay driver requires a branch attempt")
        };
        self.observations
            .driver_starts
            .lock()
            .expect("branch driver starts")
            .push(selected.clone());
        Ok(QemuFreshDriveOutcome::Observation(
            self.result.observation().clone(),
        ))
    }

    fn seal(
        &mut self,
        candidate: Self::Pending,
        final_events: Vec<crucible::SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        assert!(final_events.is_empty());
        assert_eq!(&candidate, self.result.observation());
        Ok(AttemptExecutionProduct::prepared_semantic(
            self.result.clone(),
        ))
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

impl QemuSelectedOriginVerifier for NeverFallbackRunner {
    fn verify_selected_origin(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        _target: &crate::qemu_campaign_driver::QemuSelectedResumeBoundary,
    ) -> Result<QemuSavepointReplayProof, AttemptWorkerFailure<Self::Error>> {
        panic!("hot-world fixture never verifies a fallback selected origin")
    }
}

impl QemuAttemptStartVerifier for NeverFallbackRunner {
    fn verify_attempt_start(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
    ) -> Result<QemuAttemptStartReplayProof, AttemptWorkerFailure<Self::Error>> {
        panic!("hot-world fixture never verifies a fallback attempt start")
    }
}

struct NeverResumeRunner;

impl CrucibleExecutionRunner for NeverResumeRunner {
    type Error = &'static str;

    fn execute(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        panic!("packaged hot-world fixture never executes an exact resume")
    }
}

impl QemuSelectedOriginResumeRunner for NeverResumeRunner {
    fn authenticate_selected_resume_boundary(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
    ) -> Result<
        Option<crate::qemu_campaign_driver::QemuSelectedResumeBoundary>,
        AttemptWorkerFailure<Self::Error>,
    > {
        panic!("packaged hot-world fixture never authenticates an exact resume")
    }

    fn execute_verified_selected_origin(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        _proof: QemuSavepointReplayProof,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        panic!("packaged hot-world fixture never executes a selected exact resume")
    }
}

impl QemuOrdinaryResumeRunner for NeverResumeRunner {
    fn execute_verified_attempt_start(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        _proof: QemuAttemptStartReplayProof,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        panic!("packaged hot-world fixture never executes an ordinary exact resume")
    }
}

struct RecordingUnavailableSourceWorldProvider {
    checkouts: Arc<AtomicUsize>,
}

impl super::source_world_provider_sealed::Sealed for RecordingUnavailableSourceWorldProvider {}

impl QemuHotForkSourceWorldProvider for RecordingUnavailableSourceWorldProvider {
    type Error = Infallible;

    fn checkout(
        &mut self,
        _key: &QemuHotForkSourceWorldKey,
    ) -> Result<Option<QemuHotForkSourceWorldLease>, Self::Error> {
        self.checkouts.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }

    fn restore(&mut self, source: QemuHotForkSourceWorldLease) {
        let _retained_for_process_lifetime = Box::leak(Box::new(source));
    }

    fn abandon(&mut self) {}
}

#[derive(Debug, thiserror::Error)]
#[error("scripted source provider failure")]
struct ScriptedSourceProviderError;

struct FailingSourceWorldProvider;

impl super::source_world_provider_sealed::Sealed for FailingSourceWorldProvider {}

impl QemuHotForkSourceWorldProvider for FailingSourceWorldProvider {
    type Error = ScriptedSourceProviderError;

    fn checkout(
        &mut self,
        _key: &QemuHotForkSourceWorldKey,
    ) -> Result<Option<QemuHotForkSourceWorldLease>, Self::Error> {
        Err(ScriptedSourceProviderError)
    }

    fn restore(&mut self, source: QemuHotForkSourceWorldLease) {
        let _retained_for_process_lifetime = Box::leak(Box::new(source));
    }

    fn abandon(&mut self) {}
}

struct CleanupOrderedSourceWorldProvider {
    inner: QemuSingleHotForkSourceWorldProvider,
    finishes: Arc<AtomicUsize>,
    finish_count_at_restore: Arc<AtomicUsize>,
}

struct FactoryReapingDemotionSink;

impl HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>
    for FactoryReapingDemotionSink
{
    type Error = QemuHotForkSourceWorldDemotionError;

    fn validate_fallback(
        &mut self,
        _key: HotCheckpointPoolKey,
        _fallback: HotCheckpointFallback,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn demote(
        &mut self,
        world: ManagedQemuHotForkSourceWorld,
        plan: HotCheckpointPlannedDemotion,
    ) -> Result<(), HotCheckpointTemplateDemotionFailure<ManagedQemuHotForkSourceWorld, Self::Error>>
    {
        QemuHotForkSourceWorldDemoter.demote_source(world, plan)
    }
}

impl CleanupOrderedSourceWorldProvider {
    fn available(&self) -> bool {
        self.inner.available()
    }
}

impl super::source_world_provider_sealed::Sealed for CleanupOrderedSourceWorldProvider {}

impl QemuHotForkSourceWorldProvider for CleanupOrderedSourceWorldProvider {
    type Error = Infallible;

    fn checkout(
        &mut self,
        key: &QemuHotForkSourceWorldKey,
    ) -> Result<Option<QemuHotForkSourceWorldLease>, Self::Error> {
        self.inner.checkout(key)
    }

    fn restore(&mut self, source: QemuHotForkSourceWorldLease) {
        self.finish_count_at_restore
            .store(self.finishes.load(Ordering::SeqCst), Ordering::SeqCst);
        self.inner.restore(source);
    }

    fn abandon(&mut self) {
        self.inner.abandon();
    }
}

#[test]
fn source_provider_failure_preserves_its_diagnostic_chain() {
    let input = execution_input();
    let observations = ScriptedWorldObservations::new();
    let run_state = tempfile::tempdir().expect("run state");
    let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
        FailingSourceWorldProvider,
        ScriptedWorldGuardFactory { observations },
        run_state.path(),
        QemuShutdownPolicy::fast_test(),
        QemuAsyncDriverPolicy::fast_test(),
    );

    let failure = factory
        .try_start(&input, &execution_context(&input, 0x72))
        .err()
        .expect("provider checkout should fail");
    let error = match failure {
        AttemptWorkerFailure::Retryable(error) => error,
        _ => panic!("provider checkout failure should remain retryable"),
    };
    let source = std::error::Error::source(&error)
        .unwrap_or_else(|| panic!("provider diagnostic should remain in the source chain"));

    assert_eq!(source.to_string(), "scripted source provider failure");
}

struct RecordingFallbackRunner {
    result: crate::PreparedSemanticAttemptResult,
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
            AttemptExecutionProduct::prepared_semantic(self.result.clone()),
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
    let scenario = test_execution_scenario();
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
    let scenario = test_execution_scenario();
    execution_input_for_scenario_with_stop(scenario, StopCondition::Terminal)
}

fn test_execution_scenario() -> ScenarioDefForm {
    let source = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    let nodes = source
        .world()
        .vm_nodes()
        .iter()
        .cloned()
        .map(|mut node| {
            node.kernel = None;
            node.root_image = None;
            node.initrd = None;
            WorldNodeDef::Vm(node)
        })
        .chain(source.world().io_nodes().cloned().map(WorldNodeDef::Io))
        .collect();
    let world = World::from_node_defs_and_links(nodes, source.world().links().to_vec())
        .expect("test execution World")
        .with_fault_topology(source.world().fault_topology().clone())
        .expect("test execution fault topology");
    ScenarioDefForm::from_components_with_measurements_and_app_random_draw_cap(
        &world,
        source.plan(),
        source.properties(),
        source.measurements(),
        source.seed(),
        source.app_random_draw_cap(),
    )
    .and_then(|scenario| scenario.with_selectables(source.selectables().clone()))
    .expect("test execution scenario")
}

fn prepared_test_source_world(
    source_nodes: Vec<crucible_qemu::QemuNode>,
) -> Result<
    (
        Vec<(NodeId, crucible_api::ProductionVmNodeGeneration)>,
        crucible_api::ProductionVmHotForkSourceWorld,
    ),
    crucible_api::LifecycleApiError,
> {
    prepared_multi_node_hot_fork_source_world_for_scenario_for_test(
        &test_execution_scenario(),
        source_nodes,
    )
}

fn execution_input_for_scenario(scenario: ScenarioDefForm) -> CrucibleAttemptExecution {
    let configuration = Configuration::genesis(scenario.scenario_def());
    execution_input_for_scenario_configuration(scenario, configuration)
}

fn execution_input_for_scenario_configuration(
    scenario: ScenarioDefForm,
    configuration: Configuration,
) -> CrucibleAttemptExecution {
    execution_input_for_scenario_configuration_with_stop(
        scenario,
        configuration,
        StopCondition::Terminal,
    )
}

fn execution_input_for_scenario_with_stop(
    scenario: ScenarioDefForm,
    stop: StopCondition,
) -> CrucibleAttemptExecution {
    let configuration = Configuration::genesis(scenario.scenario_def());
    execution_input_for_scenario_configuration_with_stop(scenario, configuration, stop)
}

fn execution_input_for_scenario_configuration_with_stop(
    scenario: ScenarioDefForm,
    configuration: Configuration,
    stop: StopCondition,
) -> CrucibleAttemptExecution {
    execution_input_for_scenario_configuration_with_stop_and_qemu_build(
        scenario,
        configuration,
        stop,
        "qemu-test",
    )
}

fn execution_input_for_scenario_configuration_with_stop_and_qemu_build(
    scenario: ScenarioDefForm,
    configuration: Configuration,
    stop: StopCondition,
    qemu_build: &str,
) -> CrucibleAttemptExecution {
    let definition = scenario.scenario_def();
    let scenario_artifact =
        encode_crucible_scenario_artifact(&scenario).expect("encoded scenario artifact");
    let scenario_id = scenario_artifact.scenario();
    let scenario_content = scenario_artifact.id().expect("scenario artifact id");
    assert_eq!(configuration.def, definition);
    let configuration_artifact =
        encode_crucible_configuration_artifact(&scenario_artifact, &configuration.schedule)
            .expect("encoded configuration artifact");
    let configuration_id = configuration_artifact.configuration();
    let configuration_content = configuration_artifact
        .id()
        .expect("configuration artifact id");
    let lineage = CampaignLineage::new(
        scenario_id,
        scenario_content,
        configuration_id,
        configuration_content,
        "crucible-test",
        qemu_build,
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
        stop,
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
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .with_runtime_basis(execution_basis(input, execution_byte))
}

fn branch_replay_guest_pending(
    declaration: &SelectableDeclaration,
    instance: &str,
) -> QemuNodeSelectablePendingRequest {
    let ChoiceSource::Guest { node, .. } = declaration.source() else {
        panic!("branch guest request requires a guest declaration")
    };
    let request = SelectionRequest::new(7, declaration.name(), instance, None, 256)
        .expect("guest replay selection request");
    QemuNodeSelectablePendingRequest::from_test_parts(
        crucible::NodeId { name: node.clone() },
        SelectablePlanPendingRequest::new(request, 11, 0, 0x1000),
    )
}

#[path = "tests/branch_runner.rs"]
mod branch_runner;
#[path = "tests/reconciliation.rs"]
mod reconciliation;
