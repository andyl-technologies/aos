//! Real-node executor for QEMU VM realization.
//!
//! This Linux-only executor bridges the policy-level realization coordinator to
//! a live [`QemuNode`]. The launcher performs the authorized VMState `loadvm`
//! before node assembly; after that, replay uses the shared-memory hot path and
//! deterministic fingerprint sampling without reopening generic QMP
//! save/restore on the scheduler-facing node.

use crucible::{
    AdvanceOutcome, Backend, BackendError, Checkpoint, CheckpointKind, Configuration, ContentHash,
    EventLog, EventLogOffset, Icount, NodeId, RuntimeState, SchedulerSendAuthorizer,
};
use crucible_shmem::RegionConfig;

use crate::node_factory::{
    QemuPreparedWarmRestoreLaunch, spawn_setup_and_restore_prepared_qemu_node_guarded,
};
use crate::{
    QemuCapturedVmState, QemuChildProcessContract, QemuExactSnapshotPolicy,
    QemuGuardedExactNodeLaunch, QemuGuardedRestoredNodeLaunch, QemuHostIoRuntime,
    QemuLaunchCommand, QemuLiveNodeIdentity, QemuLiveNodeStepGateConfig, QemuLiveNodeStepGateError,
    QemuLoadvmCommandAuthorization, QemuLoadvmRealizationAdmission, QemuNode,
    QemuNodeFactoryRuntime, QemuNodeRestorePlan, QemuPreparedRunDirectory, QemuSpawnError,
    QemuVmStateBinding, QemuWarmRestoreLaunchError, launch_qemu_live_node_exact_snapshot_guarded,
    launch_qemu_live_node_restored_guarded, spawn_setup_and_restore_qemu_node,
};

use super::{
    QemuBakedGenesisRestoreAdmission, QemuVmRealizationError, QemuVmRealizationExecutor,
    QemuVmReplayRequest, QemuVmSnapshot, validate_checkpoint_loadvm_state,
    validate_checkpoint_matches_config, validate_runtime_matches_admission, validate_snapshot_pair,
};

/// Backend operations required after a QEMU node has been restored.
///
/// This deliberately does not expose generic snapshot or restore: the
/// scheduler-facing node receives VMState authority only before assembly, via a
/// [`QemuNodeRestorePlan`].
pub trait QemuRealizedNodeBackend: Backend {
    /// Prepares the paused post-restore observation stream for canonical use.
    ///
    /// Implementations must reject a coverage-enabled process unless both the
    /// producer novelty state and host consumer state have been reset to one
    /// authenticated post-restore generation. Merely draining queued setup
    /// events is insufficient for publish-once coverage transports.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when setup observations cannot be discarded or
    /// the authenticated coverage-generation reset did not complete.
    fn prepare_authoritative_observation_stream(&mut self) -> Result<(), BackendError>;

    /// Advances one live quantum while appending observable events to `event_log`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the bounded quantum or event-log append fails.
    fn advance_live_to_horizon(
        &mut self,
        horizon: crucible::ExecutionHorizon,
        event_log: &mut EventLog,
    ) -> Result<AdvanceOutcome, BackendError>;

    /// Drains observable events at a paused modeled observation boundary.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the transport drain or event-log append fails.
    fn seal_live_observation_boundary(
        &mut self,
        event_log: &mut EventLog,
    ) -> Result<(), BackendError>;

    /// Captures one exact snapshot while leaving the realized node paused.
    ///
    /// The caller owns scheduler and event-log admission. Implementations own
    /// VMState and host-I/O capture and must leave the process paused after
    /// either success or an indeterminate capture failure.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when exact VMState or host-I/O capture fails.
    fn capture_live_exact_snapshot_paused(
        &mut self,
        node: &NodeId,
        checkpoint: Checkpoint,
    ) -> Result<QemuVmSnapshot, BackendError>;

    /// Drains final observable events, shuts down, and attests process reap.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when final drain or shutdown fails.
    fn shutdown_live_with_event_log(
        &mut self,
        event_log: &mut EventLog,
    ) -> Result<(), BackendError>;

    /// Reads the current retired instruction count for the realized node.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the shared-memory hot path cannot be read.
    fn current_icount(&mut self) -> Result<Icount, BackendError>;
}

/// Narrow live-node operations available to a modeled attempt driver.
///
/// This facade deliberately excludes generic snapshot, restore, shutdown, and
/// process-replacement authority. VMState operations remain owned by the
/// realization executor.
pub trait QemuLiveAttemptBackend {
    /// Advances the live node to one scheduler-authorized horizon.
    ///
    /// Observable events from the completed quantum are appended to the one
    /// supplied unified event log before this method returns.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the bounded quantum cannot complete.
    fn advance_to_horizon(
        &mut self,
        horizon: crucible::ExecutionHorizon,
    ) -> Result<AdvanceOutcome, BackendError>;

    /// Samples the live node's deterministic execution fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the fingerprint cannot be read.
    fn fingerprint(&mut self) -> Result<crucible::ExecutionFingerprint, BackendError>;

    /// Delivers one already-scheduled deterministic input.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the input cannot be delivered.
    fn deliver_input(&mut self, input: crucible::BackendInput) -> Result<(), BackendError>;

    /// Reads the current retired instruction count.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the shared-memory hot path cannot be read.
    fn current_icount(&mut self) -> Result<Icount, BackendError>;

    /// Returns the read-only unified event log updated by live advancement.
    #[must_use]
    fn event_log(&self) -> &EventLog;
}

/// Reap attestation for one live backend shutdown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuLiveBackendShutdown {
    observation_boundary_unchanged: bool,
}

impl QemuLiveBackendShutdown {
    /// Attests a reaped backend whose sealed observation boundary stayed unchanged.
    #[must_use]
    pub const fn unchanged() -> Self {
        Self {
            observation_boundary_unchanged: true,
        }
    }

    /// Attests reap while reporting observable events after prior sealing.
    #[must_use]
    pub const fn changed_after_seal() -> Self {
        Self {
            observation_boundary_unchanged: false,
        }
    }

    /// Returns whether final drain appended no events after observation sealing.
    #[must_use]
    pub const fn observation_boundary_unchanged(self) -> bool {
        self.observation_boundary_unchanged
    }
}

/// Live-backend capability exposed after policy-controlled QEMU realization.
///
/// Implementations retain ownership of process launch, VMState restore, and
/// teardown. Attempt drivers receive only a bounded mutable borrow of the
/// already-realized backend; they cannot replace it or invoke generic restore.
pub trait QemuVmLiveRealizationExecutor {
    /// Returns whether an installed backend still owns a process generation.
    #[must_use]
    fn live_backend_is_active(&self) -> bool;

    /// Borrows the active backend and its one unified event log.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when no realized backend is active.
    fn live_backend_mut(
        &mut self,
    ) -> Result<&mut dyn QemuLiveAttemptBackend, QemuVmRealizationError>;

    /// Seals the paused modeled observation boundary and returns newly appended events.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when final observation drain fails.
    fn seal_live_observation_boundary(&mut self) -> Result<bool, QemuVmRealizationError>;

    /// Captures the active backend at one exact scheduler boundary.
    ///
    /// The executor authenticates the checkpoint against the installed
    /// configuration, current node instruction count, and executor-owned
    /// unified event log before delegating VMState capture. Once boundary
    /// sealing begins, the backend remains unavailable for further modeled
    /// execution even when capture fails.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when no backend is active, the exact
    /// live basis differs, observation sealing fails, or snapshot capture fails.
    fn capture_live_exact_snapshot(
        &mut self,
        checkpoint: Checkpoint,
    ) -> Result<QemuVmSnapshot, QemuVmRealizationError>;

    /// Shuts down and reaps the active backend, when one exists.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the backend shutdown ladder
    /// reports failure.
    fn shutdown_live_backend(&mut self) -> Result<QemuLiveBackendShutdown, QemuVmRealizationError>;
}

impl QemuRealizedNodeBackend for QemuNode {
    fn prepare_authoritative_observation_stream(&mut self) -> Result<(), BackendError> {
        QemuNode::prepare_authoritative_observation_stream(self)
            .map(|_| ())
            .map_err(BackendError::from)
    }

    fn advance_live_to_horizon(
        &mut self,
        horizon: crucible::ExecutionHorizon,
        event_log: &mut EventLog,
    ) -> Result<AdvanceOutcome, BackendError> {
        self.advance_to_ceiling_with_event_log(horizon.icount, event_log)
            .map(|(outcome, _)| outcome)
            .map_err(BackendError::from)
    }

    fn seal_live_observation_boundary(
        &mut self,
        event_log: &mut EventLog,
    ) -> Result<(), BackendError> {
        self.drain_observable_events_into(event_log)
            .map(|_| ())
            .map_err(BackendError::from)
    }

    fn capture_live_exact_snapshot_paused(
        &mut self,
        node: &NodeId,
        checkpoint: Checkpoint,
    ) -> Result<QemuVmSnapshot, BackendError> {
        self.capture_exact_snapshot_paused(node, checkpoint)
            .map_err(BackendError::from)
    }

    fn shutdown_live_with_event_log(
        &mut self,
        event_log: &mut EventLog,
    ) -> Result<(), BackendError> {
        self.shutdown_child_with_event_log(event_log)
            .map(|_| ())
            .map_err(BackendError::from)
    }

    fn current_icount(&mut self) -> Result<Icount, BackendError> {
        QemuNode::current_icount(self).map_err(BackendError::from)
    }
}

/// Common node type retained by one real-node launcher.
pub trait QemuNodeLauncher {
    /// Concrete node handle returned by this launcher.
    type Node: QemuRealizedNodeBackend;
}

/// Paused node operation that seals one retained hot-fork template.
///
/// Implementations must leave the node paused and retain every template and
/// branch-private descriptor after success. An error must leave the same node
/// owned by its realization executor for cleanup or exact retry.
pub trait QemuHotForkTemplatePreparer: QemuRealizedNodeBackend {
    /// Prepares the QEMU transaction and every branch-private child resource.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the paused node cannot establish
    /// the complete retained-template transaction or its bounded private-ring
    /// image and child resources.
    fn prepare_retained_hot_fork_template(
        &mut self,
        block_snapshot_bindings: &[crate::QmpHotForkBlockSnapshotBinding],
        maximum_ring_image_bytes: usize,
    ) -> Result<(), QemuVmRealizationError>;
}

impl QemuHotForkTemplatePreparer for QemuNode {
    fn prepare_retained_hot_fork_template(
        &mut self,
        block_snapshot_bindings: &[crate::QmpHotForkBlockSnapshotBinding],
        maximum_ring_image_bytes: usize,
    ) -> Result<(), QemuVmRealizationError> {
        self.prepare_hot_fork_template(block_snapshot_bindings)
            .map_err(|source| QemuVmRealizationError::Executor {
                operation: "prepare retained hot-fork template",
                message: source.to_string(),
            })?;
        self.prepare_hot_fork_child_resources(maximum_ring_image_bytes)
            .map_err(|source| QemuVmRealizationError::Executor {
                operation: "prepare retained hot-fork child resources",
                message: source.to_string(),
            })?;
        Ok(())
    }
}

/// Linear identity retained while a prepared hot-fork source is in use.
///
/// Only [`QemuPreparedHotForkTemplate::into_parts`] can produce this token. It
/// keeps the exact realized configuration and unified event-log prefix paired
/// while daemon-side child reconciliation temporarily owns the raw source
/// node.
#[must_use = "reassemble the exact prepared template after child reconciliation"]
pub struct QemuHotForkTemplateIdentity {
    configuration: ContentHash,
    event_log: EventLog,
}

impl QemuHotForkTemplateIdentity {
    /// Returns the exact configuration realized by the retained source.
    #[must_use]
    pub const fn configuration(&self) -> ContentHash {
        self.configuration
    }

    /// Clones the immutable event prefix for one branch-private child.
    #[must_use]
    pub fn fork_event_log(&self) -> EventLog {
        self.event_log.clone()
    }

    /// Returns the retained source event-log prefix.
    #[must_use]
    pub const fn event_log(&self) -> &EventLog {
        &self.event_log
    }
}

impl std::fmt::Debug for QemuHotForkTemplateIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkTemplateIdentity")
            .field("configuration", &self.configuration)
            .field("event_log_offset", &self.event_log.offset())
            .finish_non_exhaustive()
    }
}

/// Exact paused node and observation prefix admitted as a retained template.
///
/// The capability is minted only by
/// [`QemuNodeRealizationExecutor::prepare_active_hot_fork_template`], after the
/// executor has exact-bound the active node to its realized configuration and
/// QEMU has acknowledged the complete template/resource transaction.
#[must_use = "launch, recover, or quarantine the retained hot-fork template"]
pub struct QemuPreparedHotForkTemplate<N> {
    node: N,
    identity: QemuHotForkTemplateIdentity,
}

impl<N> QemuPreparedHotForkTemplate<N> {
    /// Returns the exact source configuration identity.
    #[must_use]
    pub const fn configuration(&self) -> ContentHash {
        self.identity.configuration()
    }

    /// Returns the retained source event-log prefix.
    #[must_use]
    pub const fn event_log(&self) -> &EventLog {
        self.identity.event_log()
    }

    /// Separates the node from its non-forgeable configuration/log identity.
    pub fn into_parts(self) -> (N, QemuHotForkTemplateIdentity) {
        (self.node, self.identity)
    }

    /// Reassembles a reconciled source with its original exact identity token.
    pub fn from_reconciled_parts(node: N, identity: QemuHotForkTemplateIdentity) -> Self {
        Self { node, identity }
    }
}

impl<N> QemuPreparedHotForkTemplate<N>
where
    N: QemuRealizedNodeBackend,
{
    /// Drains final observations and reaps this retired source template.
    ///
    /// Successful return attests that the backend no longer owns a live child.
    /// A failure retains the exact, potentially partially shut down source so
    /// its unique process authority can move into quarantine instead of being
    /// mistaken for a reusable template.
    ///
    /// # Errors
    ///
    /// Returns [`QemuPreparedHotForkTemplateShutdownFailure`] when final event
    /// draining or the backend shutdown/reap ladder fails.
    pub fn shutdown_for_demotion(
        mut self,
    ) -> Result<(), QemuPreparedHotForkTemplateShutdownFailure<N>> {
        match self
            .node
            .shutdown_live_with_event_log(&mut self.identity.event_log)
        {
            Ok(()) => Ok(()),
            Err(source) => Err(QemuPreparedHotForkTemplateShutdownFailure {
                template: Box::new(self),
                source,
            }),
        }
    }
}

/// Failed retained-source shutdown preserving its unique process authority.
#[must_use = "retry shutdown or transfer the retained source into quarantine"]
pub struct QemuPreparedHotForkTemplateShutdownFailure<N> {
    template: Box<QemuPreparedHotForkTemplate<N>>,
    source: BackendError,
}

impl<N> QemuPreparedHotForkTemplateShutdownFailure<N> {
    /// Separates the retained source from its shutdown diagnostic.
    pub fn into_parts(self) -> (QemuPreparedHotForkTemplate<N>, BackendError) {
        (*self.template, self.source)
    }
}

impl<N> std::fmt::Debug for QemuPreparedHotForkTemplateShutdownFailure<N> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuPreparedHotForkTemplateShutdownFailure")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl<N> std::fmt::Debug for QemuPreparedHotForkTemplate<N> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuPreparedHotForkTemplate")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

/// Launches a QEMU node that has already been VMState-restored before assembly.
pub trait QemuNodeRealizationLauncher: QemuNodeLauncher {
    /// Launches and assembles a node for `restore`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when process launch, plugin setup,
    /// QMP restore, or node assembly fails.
    fn launch_restored_node(
        &mut self,
        config: &Configuration,
        restore: QemuNodeRestorePlan<'_>,
    ) -> Result<Self::Node, QemuVmRealizationError>;
}

/// Exact-root-bound launcher for one guarded warm restore.
///
/// Unlike [`QemuNodeRealizationLauncher`], this capability receives the exact
/// paired snapshot and the sealed child-process contract. Implementations must
/// reject any snapshot other than the one whose authenticated VMState was
/// committed into their prepared run-directory authority, and must use only a
/// guarded child-spawn path.
pub trait QemuGuardedNodeRealizationLauncher: QemuNodeLauncher {
    /// Launches one exact materialized snapshot under `process_contract`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the snapshot/root basis differs,
    /// guarded process launch fails, or restored node assembly fails.
    fn launch_materialized_exact_node_guarded(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        restore: QemuNodeRestorePlan<'_>,
        process_contract: &QemuChildProcessContract,
    ) -> Result<Self::Node, QemuVmRealizationError>;
}

/// Launches a trusted thin-path VMState under one child-process contract.
///
/// This capability is distinct from [`QemuGuardedNodeRealizationLauncher`]: a
/// replay-oracle probe must consume the selected exact-root binding, while its
/// independently prepared baked-genesis or cached-ancestor path must not reuse
/// that target VMState authority.
pub trait QemuGuardedThinNodeRealizationLauncher: QemuNodeLauncher {
    /// Launches one prepared proper-ancestor or baked-genesis restore.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the restore checkpoint differs
    /// from the prepared VMState, guarded process launch fails, or restored
    /// node assembly fails.
    fn launch_thin_path_node_guarded(
        &mut self,
        config: &Configuration,
        restore: QemuNodeRestorePlan<'_>,
        process_contract: &QemuChildProcessContract,
    ) -> Result<Self::Node, QemuVmRealizationError>;
}

/// Retains a direct child whose post-spawn realization cleanup could not reap it.
///
/// Concrete guarded launchers implement this sealed handoff so the attempt
/// guard can authenticate the child against its cgroup and transfer it to the
/// nondroppable process-quarantine owner. A launcher with a retained child must
/// reject another launch until the caller takes that authority.
pub trait QemuFailedLaunchChildSource: QemuNodeLauncher {
    /// Takes the nonduplicable direct-child handle retained after failed reap.
    #[must_use]
    fn take_failed_launch_child(&mut self) -> Option<crate::QemuNodeChild>;
}

/// Owns the pinned VMState inode used by one guarded live QEMU generation.
///
/// The realization executor invokes this capability only after its active node
/// has returned an exact reap attestation. It yields a read-only positional
/// source, never the run-directory or mutation authority.
pub trait QemuCapturedVmStateSource: QemuNodeLauncher {
    /// Seals the stable VMState bytes after process reap.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the pinned inode changed, has an
    /// invalid length, or cannot be synchronized and duplicated.
    fn capture_vmstate_after_reap(&self) -> Result<QemuCapturedVmState, QemuVmRealizationError>;
}

/// Concrete launcher that composes QEMU spawn, plugin setup, QMP load, and node assembly.
pub struct QemuWarmRestoreNodeLauncher<A, R, F> {
    command: QemuLaunchCommand,
    run_directory: std::path::PathBuf,
    region_config: RegionConfig,
    slot_index: u32,
    runtime_factory: F,
    failed_child: Option<crate::QemuNodeChild>,
    _runtime: std::marker::PhantomData<fn() -> (A, R)>,
}

/// One-shot launcher for prepared exact-checkpoint-root-bound artifacts.
///
/// Construction authenticates the process-local VMState and required root-
/// overlay binding before the authority can enter a real-node executor. Launch
/// rechecks the complete snapshot identity and checkpoint identity, while the
/// node factory repeats the artifact checks immediately before guarded spawn.
pub struct QemuExactRootWarmRestoreNodeLauncher<A, R, F> {
    command: QemuLaunchCommand,
    run_directory: QemuPreparedRunDirectory,
    vmstate_binding: QemuVmStateBinding,
    snapshot: ContentHash,
    checkpoint: ContentHash,
    region_config: RegionConfig,
    slot_index: u32,
    runtime_factory: F,
    failed_child: Option<crate::QemuNodeChild>,
    _runtime: std::marker::PhantomData<fn() -> (A, R)>,
}

/// One-shot guarded launcher for authenticated thin-path artifacts.
///
/// The owner prepares a baked-genesis or proper-ancestor VMState in a pinned
/// run directory and binds this launcher to that checkpoint identity. Unlike an
/// exact-root launcher, this type cannot consume the selected target snapshot.
pub struct QemuPreparedThinWarmRestoreNodeLauncher<A, R, F> {
    command: QemuLaunchCommand,
    run_directory: QemuPreparedRunDirectory,
    vmstate_binding: QemuVmStateBinding,
    checkpoint: ContentHash,
    region_config: RegionConfig,
    slot_index: u32,
    runtime_factory: F,
    failed_child: Option<crate::QemuNodeChild>,
    _runtime: std::marker::PhantomData<fn() -> (A, R)>,
}

/// Scenario-profile exact-target launcher for one replay-oracle generation.
///
/// Unlike the lower-level generic launcher, this owner reuses the same
/// scenario-aware live-node gate profile as the production lifecycle, including
/// block, 9p, network, app-random, and fault-channel configuration.
pub struct QemuExactProfileWarmRestoreNodeLauncher {
    config: QemuLiveNodeStepGateConfig,
    run_directory: QemuPreparedRunDirectory,
    vmstate_binding: QemuVmStateBinding,
    snapshot: ContentHash,
    checkpoint: ContentHash,
    identity: OwnedLiveNodeIdentity,
    failed_child: Option<crate::QemuNodeChild>,
}

/// Scenario-profile thin-path launcher for one replay-oracle generation.
pub struct QemuThinProfileWarmRestoreNodeLauncher {
    config: QemuLiveNodeStepGateConfig,
    run_directory: QemuPreparedRunDirectory,
    vmstate_binding: QemuVmStateBinding,
    checkpoint: ContentHash,
    identity: OwnedLiveNodeIdentity,
    failed_child: Option<crate::QemuNodeChild>,
}

struct OwnedLiveNodeIdentity {
    node: String,
    router: String,
    crash_detector: String,
}

impl OwnedLiveNodeIdentity {
    fn borrowed(&self) -> QemuLiveNodeIdentity<'_> {
        QemuLiveNodeIdentity::new(&self.node, &self.router, &self.crash_detector)
    }
}

/// Paired launch authorities used by one guarded replay-oracle executor.
///
/// `exact` owns the selected target's exact-root materialization; `thin` owns
/// an independently prepared baked-genesis or proper-ancestor VMState. The
/// wrapper routes each operation without exposing either launcher through the
/// other's capability trait.
pub struct QemuReplayValidationNodeLauncher<X, T> {
    exact: X,
    thin: T,
}

impl<A, R, F> QemuExactRootWarmRestoreNodeLauncher<A, R, F> {
    /// Creates a launcher for one already materialized exact checkpoint root.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] unless `run_directory` has committed the
    /// supplied root binding for VMState and every command-required root
    /// overlay.
    pub fn new(
        command: QemuLaunchCommand,
        run_directory: QemuPreparedRunDirectory,
        vmstate_binding: QemuVmStateBinding,
        snapshot: &QemuVmSnapshot,
        region_config: RegionConfig,
        slot_index: u32,
        runtime_factory: F,
    ) -> Result<Self, QemuSpawnError> {
        run_directory.require_exact_launch_artifacts(&command, vmstate_binding)?;
        Ok(Self {
            command,
            run_directory,
            vmstate_binding,
            snapshot: snapshot.id(),
            checkpoint: snapshot.checkpoint().id,
            region_config,
            slot_index,
            runtime_factory,
            failed_child: None,
            _runtime: std::marker::PhantomData,
        })
    }

    /// Returns the selected snapshot identity admitted by this launcher.
    #[must_use]
    pub const fn snapshot(&self) -> ContentHash {
        self.snapshot
    }
}

impl<A, R, F> QemuPreparedThinWarmRestoreNodeLauncher<A, R, F> {
    /// Creates a launcher for one independently authenticated thin checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] unless the pinned VMState and, when required
    /// by `command`, root overlay both carry `vmstate_binding`.
    pub fn new(
        command: QemuLaunchCommand,
        run_directory: QemuPreparedRunDirectory,
        vmstate_binding: QemuVmStateBinding,
        checkpoint: ContentHash,
        region_config: RegionConfig,
        slot_index: u32,
        runtime_factory: F,
    ) -> Result<Self, QemuSpawnError> {
        run_directory.require_exact_launch_artifacts(&command, vmstate_binding)?;
        Ok(Self {
            command,
            run_directory,
            vmstate_binding,
            checkpoint,
            region_config,
            slot_index,
            runtime_factory,
            failed_child: None,
            _runtime: std::marker::PhantomData,
        })
    }
}

impl QemuExactProfileWarmRestoreNodeLauncher {
    /// Creates one exact-target launcher from a retained production profile.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] unless the profile names the pinned
    /// directory and both required artifacts carry the exact-root binding.
    pub fn new(
        config: QemuLiveNodeStepGateConfig,
        run_directory: QemuPreparedRunDirectory,
        vmstate_binding: QemuVmStateBinding,
        snapshot: &QemuVmSnapshot,
        node: impl Into<String>,
        crash_detector: impl Into<String>,
    ) -> Result<Self, QemuVmRealizationError> {
        validate_profile_materialization(&config, &run_directory, vmstate_binding)?;
        Ok(Self {
            config,
            run_directory,
            vmstate_binding,
            snapshot: snapshot.id(),
            checkpoint: snapshot.checkpoint().id,
            identity: OwnedLiveNodeIdentity {
                node: node.into(),
                router: String::from("crucible-router"),
                crash_detector: crash_detector.into(),
            },
            failed_child: None,
        })
    }
}

impl QemuThinProfileWarmRestoreNodeLauncher {
    /// Creates one independently bound baked-genesis or ancestor launcher.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] unless the profile names the pinned
    /// directory and both required artifacts carry the thin-catalog binding.
    pub fn new(
        config: QemuLiveNodeStepGateConfig,
        run_directory: QemuPreparedRunDirectory,
        vmstate_binding: QemuVmStateBinding,
        checkpoint: ContentHash,
        node: impl Into<String>,
        crash_detector: impl Into<String>,
    ) -> Result<Self, QemuVmRealizationError> {
        validate_profile_materialization(&config, &run_directory, vmstate_binding)?;
        Ok(Self {
            config,
            run_directory,
            vmstate_binding,
            checkpoint,
            identity: OwnedLiveNodeIdentity {
                node: node.into(),
                router: String::from("crucible-router"),
                crash_detector: crash_detector.into(),
            },
            failed_child: None,
        })
    }
}

impl<X, T> QemuReplayValidationNodeLauncher<X, T> {
    /// Pairs disjoint exact-probe and thin-path launch authorities.
    #[must_use]
    pub const fn new(exact: X, thin: T) -> Self {
        Self { exact, thin }
    }

    /// Returns the selected exact-root launcher.
    #[must_use]
    pub const fn exact(&self) -> &X {
        &self.exact
    }

    /// Returns the independently prepared thin-path launcher.
    #[must_use]
    pub const fn thin(&self) -> &T {
        &self.thin
    }
}

impl<A, R, F> QemuWarmRestoreNodeLauncher<A, R, F> {
    /// Creates a warm-restore node launcher.
    #[must_use]
    pub fn new(
        command: QemuLaunchCommand,
        run_directory: impl Into<std::path::PathBuf>,
        region_config: RegionConfig,
        slot_index: u32,
        runtime_factory: F,
    ) -> Self {
        Self {
            command,
            run_directory: run_directory.into(),
            region_config,
            slot_index,
            runtime_factory,
            failed_child: None,
            _runtime: std::marker::PhantomData,
        }
    }
}

impl<A, R, F> QemuNodeLauncher for QemuWarmRestoreNodeLauncher<A, R, F>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
    F: FnMut(&Configuration) -> QemuNodeFactoryRuntime<A, R>,
{
    type Node = QemuNode;
}

impl<A, R, F> QemuNodeLauncher for QemuExactRootWarmRestoreNodeLauncher<A, R, F>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
    F: FnMut(&Configuration) -> QemuNodeFactoryRuntime<A, R>,
{
    type Node = QemuNode;
}

impl<A, R, F> QemuNodeLauncher for QemuPreparedThinWarmRestoreNodeLauncher<A, R, F>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
    F: FnMut(&Configuration) -> QemuNodeFactoryRuntime<A, R>,
{
    type Node = QemuNode;
}

impl QemuNodeLauncher for QemuExactProfileWarmRestoreNodeLauncher {
    type Node = QemuNode;
}

impl QemuNodeLauncher for QemuThinProfileWarmRestoreNodeLauncher {
    type Node = QemuNode;
}

impl<X, T> QemuNodeLauncher for QemuReplayValidationNodeLauncher<X, T>
where
    X: QemuNodeLauncher,
    T: QemuNodeLauncher<Node = X::Node>,
{
    type Node = X::Node;
}

impl<A, R, F> QemuFailedLaunchChildSource for QemuWarmRestoreNodeLauncher<A, R, F>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
    F: FnMut(&Configuration) -> QemuNodeFactoryRuntime<A, R>,
{
    fn take_failed_launch_child(&mut self) -> Option<crate::QemuNodeChild> {
        self.failed_child.take()
    }
}

impl<A, R, F> QemuFailedLaunchChildSource for QemuExactRootWarmRestoreNodeLauncher<A, R, F>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
    F: FnMut(&Configuration) -> QemuNodeFactoryRuntime<A, R>,
{
    fn take_failed_launch_child(&mut self) -> Option<crate::QemuNodeChild> {
        self.failed_child.take()
    }
}

impl<A, R, F> QemuCapturedVmStateSource for QemuExactRootWarmRestoreNodeLauncher<A, R, F>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
    F: FnMut(&Configuration) -> QemuNodeFactoryRuntime<A, R>,
{
    fn capture_vmstate_after_reap(&self) -> Result<QemuCapturedVmState, QemuVmRealizationError> {
        self.run_directory
            .capture_vmstate_after_reap()
            .map_err(|source| QemuVmRealizationError::Executor {
                operation: "capture reaped QEMU VMState artifact",
                message: source.to_string(),
            })
    }
}

impl<A, R, F> QemuFailedLaunchChildSource for QemuPreparedThinWarmRestoreNodeLauncher<A, R, F>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
    F: FnMut(&Configuration) -> QemuNodeFactoryRuntime<A, R>,
{
    fn take_failed_launch_child(&mut self) -> Option<crate::QemuNodeChild> {
        self.failed_child.take()
    }
}

impl QemuFailedLaunchChildSource for QemuExactProfileWarmRestoreNodeLauncher {
    fn take_failed_launch_child(&mut self) -> Option<crate::QemuNodeChild> {
        self.failed_child.take()
    }
}

impl QemuFailedLaunchChildSource for QemuThinProfileWarmRestoreNodeLauncher {
    fn take_failed_launch_child(&mut self) -> Option<crate::QemuNodeChild> {
        self.failed_child.take()
    }
}

impl<X, T> QemuFailedLaunchChildSource for QemuReplayValidationNodeLauncher<X, T>
where
    X: QemuFailedLaunchChildSource,
    T: QemuFailedLaunchChildSource<Node = X::Node>,
{
    fn take_failed_launch_child(&mut self) -> Option<crate::QemuNodeChild> {
        self.exact
            .take_failed_launch_child()
            .or_else(|| self.thin.take_failed_launch_child())
    }
}

impl<A, R, F> QemuNodeRealizationLauncher for QemuWarmRestoreNodeLauncher<A, R, F>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
    F: FnMut(&Configuration) -> QemuNodeFactoryRuntime<A, R>,
{
    fn launch_restored_node(
        &mut self,
        config: &Configuration,
        restore: QemuNodeRestorePlan<'_>,
    ) -> Result<Self::Node, QemuVmRealizationError> {
        require_no_failed_launch_child(&self.failed_child)?;
        let runtime = (self.runtime_factory)(config);
        let result = spawn_setup_and_restore_qemu_node(
            &self.command,
            &self.run_directory,
            self.region_config,
            self.slot_index,
            restore,
            runtime,
            // Diskless warm restore issues no host-serviced device I/O during
            // priming; a block-capable caller supplies a servicing closure here.
            |_current_icount| {},
        );
        retain_warm_restore_result(result, &mut self.failed_child)
    }
}

impl<A, R, F> QemuGuardedNodeRealizationLauncher for QemuExactRootWarmRestoreNodeLauncher<A, R, F>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
    F: FnMut(&Configuration) -> QemuNodeFactoryRuntime<A, R>,
{
    fn launch_materialized_exact_node_guarded(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        restore: QemuNodeRestorePlan<'_>,
        process_contract: &QemuChildProcessContract,
    ) -> Result<Self::Node, QemuVmRealizationError> {
        require_no_failed_launch_child(&self.failed_child)?;
        if snapshot.id() != self.snapshot || restore.checkpoint().id != self.checkpoint {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "guarded exact-root warm restore",
                message: String::from(
                    "snapshot metadata does not match the materialized exact checkpoint root",
                ),
            });
        }
        let runtime = (self.runtime_factory)(config);
        let result = spawn_setup_and_restore_prepared_qemu_node_guarded(
            QemuPreparedWarmRestoreLaunch::new(
                &self.command,
                &self.run_directory,
                self.vmstate_binding,
                process_contract,
                self.region_config,
                self.slot_index,
            ),
            restore,
            runtime,
            |_current_icount| {},
        );
        retain_warm_restore_result(result, &mut self.failed_child)
    }
}

impl<A, R, F> QemuGuardedThinNodeRealizationLauncher
    for QemuPreparedThinWarmRestoreNodeLauncher<A, R, F>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
    F: FnMut(&Configuration) -> QemuNodeFactoryRuntime<A, R>,
{
    fn launch_thin_path_node_guarded(
        &mut self,
        config: &Configuration,
        restore: QemuNodeRestorePlan<'_>,
        process_contract: &QemuChildProcessContract,
    ) -> Result<Self::Node, QemuVmRealizationError> {
        require_no_failed_launch_child(&self.failed_child)?;
        if restore.checkpoint().id != self.checkpoint {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "guarded thin-path warm restore",
                message: String::from(
                    "restore checkpoint does not match the prepared thin-path VMState",
                ),
            });
        }
        let runtime = (self.runtime_factory)(config);
        let result = spawn_setup_and_restore_prepared_qemu_node_guarded(
            QemuPreparedWarmRestoreLaunch::new(
                &self.command,
                &self.run_directory,
                self.vmstate_binding,
                process_contract,
                self.region_config,
                self.slot_index,
            ),
            restore,
            runtime,
            |_current_icount| {},
        );
        retain_warm_restore_result(result, &mut self.failed_child)
    }
}

impl QemuGuardedNodeRealizationLauncher for QemuExactProfileWarmRestoreNodeLauncher {
    fn launch_materialized_exact_node_guarded(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        restore: QemuNodeRestorePlan<'_>,
        process_contract: &QemuChildProcessContract,
    ) -> Result<Self::Node, QemuVmRealizationError> {
        require_no_failed_launch_child(&self.failed_child)?;
        if snapshot.id() != self.snapshot || restore.checkpoint().id != self.checkpoint {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "guarded exact-profile warm restore",
                message: String::from(
                    "snapshot metadata does not match the materialized exact target",
                ),
            });
        }
        let result = launch_qemu_live_node_exact_snapshot_guarded(
            &self.config,
            QemuGuardedExactNodeLaunch::new(
                &self.run_directory,
                process_contract,
                self.vmstate_binding,
                self.identity.borrowed(),
                snapshot,
            ),
        );
        retain_profile_restore_result(result, &mut self.failed_child, config)
    }
}

impl QemuGuardedThinNodeRealizationLauncher for QemuThinProfileWarmRestoreNodeLauncher {
    fn launch_thin_path_node_guarded(
        &mut self,
        config: &Configuration,
        restore: QemuNodeRestorePlan<'_>,
        process_contract: &QemuChildProcessContract,
    ) -> Result<Self::Node, QemuVmRealizationError> {
        require_no_failed_launch_child(&self.failed_child)?;
        if restore.checkpoint().id != self.checkpoint {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "guarded thin-profile warm restore",
                message: String::from(
                    "restore checkpoint does not match the materialized thin target",
                ),
            });
        }
        let result = launch_qemu_live_node_restored_guarded(
            &self.config,
            QemuGuardedRestoredNodeLaunch::new(
                &self.run_directory,
                process_contract,
                self.vmstate_binding,
                self.identity.borrowed(),
                restore,
            ),
        );
        retain_profile_restore_result(result, &mut self.failed_child, config)
    }
}

impl<X, T> QemuGuardedNodeRealizationLauncher for QemuReplayValidationNodeLauncher<X, T>
where
    X: QemuGuardedNodeRealizationLauncher,
    T: QemuNodeLauncher<Node = X::Node>,
{
    fn launch_materialized_exact_node_guarded(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        restore: QemuNodeRestorePlan<'_>,
        process_contract: &QemuChildProcessContract,
    ) -> Result<Self::Node, QemuVmRealizationError> {
        self.exact.launch_materialized_exact_node_guarded(
            config,
            snapshot,
            restore,
            process_contract,
        )
    }
}

impl<X, T> QemuGuardedThinNodeRealizationLauncher for QemuReplayValidationNodeLauncher<X, T>
where
    X: QemuNodeLauncher,
    T: QemuGuardedThinNodeRealizationLauncher<Node = X::Node>,
{
    fn launch_thin_path_node_guarded(
        &mut self,
        config: &Configuration,
        restore: QemuNodeRestorePlan<'_>,
        process_contract: &QemuChildProcessContract,
    ) -> Result<Self::Node, QemuVmRealizationError> {
        self.thin
            .launch_thin_path_node_guarded(config, restore, process_contract)
    }
}

/// Realization executor backed by one active QEMU node at a time.
pub struct QemuNodeRealizationExecutor<L>
where
    L: QemuNodeLauncher,
{
    node: NodeId,
    launcher: L,
    active_node: Option<L::Node>,
    active_configuration: Option<ContentHash>,
    event_log: EventLog,
    observation_sealed: bool,
}

impl<L> QemuNodeRealizationExecutor<L>
where
    L: QemuNodeLauncher,
{
    /// Creates a node realization executor for `node`.
    #[must_use]
    pub fn new(node: NodeId, launcher: L) -> Self {
        Self {
            node,
            launcher,
            active_node: None,
            active_configuration: None,
            event_log: EventLog::new(),
            observation_sealed: false,
        }
    }

    /// Returns the exact modeled node bound to this realization executor.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
    }

    /// Converts the exact active paused node into one retained hot-fork template.
    ///
    /// Template coordination runs while the node, its exact realized
    /// configuration, and unified event log remain inside this executor. Only
    /// after QEMU and all branch-private resources are prepared successfully
    /// are those three authorities moved into the returned capability. A
    /// failure leaves the active node and event log installed here.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when no exact active configuration is
    /// installed or the node cannot prepare the complete bounded hot-fork
    /// transaction.
    pub fn prepare_active_hot_fork_template(
        &mut self,
        block_snapshot_bindings: &[crate::QmpHotForkBlockSnapshotBinding],
        maximum_ring_image_bytes: usize,
    ) -> Result<QemuPreparedHotForkTemplate<L::Node>, QemuVmRealizationError>
    where
        L::Node: QemuHotForkTemplatePreparer,
    {
        let configuration =
            self.active_configuration
                .ok_or_else(|| QemuVmRealizationError::Executor {
                    operation: "prepare active retained hot-fork template",
                    message: String::from("no exact active configuration is installed"),
                })?;
        let node = self
            .active_node
            .as_mut()
            .ok_or_else(|| QemuVmRealizationError::Executor {
                operation: "prepare active retained hot-fork template",
                message: String::from("no active QEMU node is installed"),
            })?;
        node.prepare_retained_hot_fork_template(block_snapshot_bindings, maximum_ring_image_bytes)?;

        let node = self
            .active_node
            .take()
            .ok_or_else(|| QemuVmRealizationError::Executor {
                operation: "transfer active retained hot-fork template",
                message: String::from("prepared active QEMU node disappeared"),
            })?;
        self.active_configuration = None;
        self.observation_sealed = false;
        let event_log = std::mem::replace(&mut self.event_log, EventLog::new());
        Ok(QemuPreparedHotForkTemplate {
            node,
            identity: QemuHotForkTemplateIdentity {
                configuration,
                event_log,
            },
        })
    }

    /// Shuts down the active realized node, when one exists.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the backend shutdown ladder
    /// reports failure.
    pub fn shutdown_active_node(&mut self) -> Result<(), QemuVmRealizationError> {
        self.shutdown_active_node_for("shutdown active realized QEMU node")
    }

    /// Removes the active node after guarded shutdown failed to attest reap.
    ///
    /// The caller must transfer the returned node into a resource-owning
    /// quarantine before releasing attempt capacity. This method performs no
    /// shutdown operation and returns `None` when no live node is installed.
    // crucible-lint: allow rust-allow -- this sealed handoff is consumed by the next concrete guard-composition slice.
    #[allow(dead_code)]
    pub(crate) fn take_active_node_for_quarantine(&mut self) -> Option<L::Node> {
        self.observation_sealed = false;
        self.active_configuration = None;
        self.active_node.take()
    }

    /// Transfers an unreaped real node's direct-child authority to quarantine.
    ///
    /// This operation deliberately destroys every modeled channel and live
    /// backend capability before returning the nonduplicable child handle. The
    /// caller must authenticate and retain that child in the exact attempt
    /// process owner before releasing any resource enforcement.
    #[must_use]
    pub fn take_active_direct_child_for_quarantine(&mut self) -> Option<crate::QemuNodeChild>
    where
        L: QemuNodeLauncher<Node = QemuNode>,
    {
        self.take_active_node_for_quarantine()
            .and_then(QemuNode::into_direct_child_for_quarantine)
    }

    /// Takes a direct child retained after a post-spawn launch reap failure.
    ///
    /// The caller must authenticate the returned child against the exact
    /// attempt cgroup and transfer it to the nondroppable process-quarantine
    /// owner before releasing resources. Until this handoff occurs, concrete
    /// launchers reject every subsequent launch.
    #[must_use]
    pub fn take_failed_launch_child_for_quarantine(&mut self) -> Option<crate::QemuNodeChild>
    where
        L: QemuFailedLaunchChildSource,
    {
        self.launcher.take_failed_launch_child()
    }

    /// Captures one exact checkpoint and seals its VMState after process reap.
    ///
    /// The live node remains paused after metadata capture. This operation then
    /// performs the final observable-event drain, terminates and reaps the
    /// process, rejects any event-log change at the sealed boundary, and only
    /// afterward lends the narrow stable VMState reader.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when capture, final drain, shutdown,
    /// reap, or stable VMState sealing fails. A shutdown failure retains the
    /// active node for the caller's quarantine path.
    pub fn capture_exact_checkpoint_artifact(
        &mut self,
        checkpoint: Checkpoint,
    ) -> Result<(QemuVmSnapshot, QemuCapturedVmState), QemuVmRealizationError>
    where
        L: QemuCapturedVmStateSource,
    {
        let snapshot = self.capture_live_exact_snapshot(checkpoint)?;
        let shutdown = self.shutdown_live_backend()?;
        if !shutdown.observation_boundary_unchanged() {
            return Err(QemuVmRealizationError::Executor {
                operation: "capture exact QEMU checkpoint artifact",
                message: String::from(
                    "final shutdown drain changed the sealed checkpoint observation boundary",
                ),
            });
        }
        let vmstate = self.launcher.capture_vmstate_after_reap()?;
        Ok((snapshot, vmstate))
    }

    fn launch_and_install(
        &mut self,
        config: &Configuration,
        restore: QemuNodeRestorePlan<'_>,
        operation: &'static str,
    ) -> Result<ContentHash, QemuVmRealizationError>
    where
        L: QemuNodeRealizationLauncher,
    {
        self.shutdown_active_node_for("replace active realized QEMU node")?;
        let mut node = self.launcher.launch_restored_node(config, restore)?;
        QemuRealizedNodeBackend::prepare_authoritative_observation_stream(&mut node)
            .map_err(|source| node_backend_error(operation, source))?;
        let runtime_id = Backend::fingerprint(&mut node)
            .map(|fingerprint| fingerprint.hash)
            .map_err(|source| node_backend_error(operation, source))?;
        self.active_node = Some(node);
        Ok(runtime_id)
    }

    fn shutdown_active_node_for(
        &mut self,
        operation: &'static str,
    ) -> Result<(), QemuVmRealizationError> {
        if let Some(node) = self.active_node.as_mut() {
            QemuRealizedNodeBackend::shutdown_live_with_event_log(node, &mut self.event_log)
                .map_err(|source| node_backend_error(operation, source))?;
            self.active_node = None;
        }
        self.active_configuration = None;
        self.observation_sealed = false;
        Ok(())
    }

    fn retain_runtime_basis(&mut self, runtime: &RuntimeState) {
        self.active_configuration = Some(runtime.configuration);
        self.event_log = EventLog::from_offset(runtime.event_log);
        self.observation_sealed = false;
    }

    fn validate_capture_checkpoint_basis(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<(), QemuVmRealizationError> {
        let active_configuration =
            self.active_configuration
                .ok_or_else(|| QemuVmRealizationError::Executor {
                    operation: "capture live exact QEMU snapshot",
                    message: String::from("no active configuration is installed"),
                })?;
        if checkpoint.configuration != active_configuration || checkpoint.id != active_configuration
        {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "live exact snapshot capture",
                message: format!(
                    "checkpoint configuration {:?} and identity {:?} do not match installed configuration {:?}",
                    checkpoint.configuration, checkpoint.id, active_configuration
                ),
            });
        }

        let expected_icount = checkpoint.node_icounts.get(&self.node).ok_or_else(|| {
            QemuVmRealizationError::InvalidCheckpoint {
                role: "live exact snapshot capture",
                message: format!(
                    "checkpoint has no instruction count for realized node `{}`",
                    self.node.name
                ),
            }
        })?;
        let node = self
            .active_node
            .as_mut()
            .ok_or_else(|| QemuVmRealizationError::Executor {
                operation: "capture live exact QEMU snapshot",
                message: String::from("no QEMU node has been restored"),
            })?;
        let observed_icount = QemuRealizedNodeBackend::current_icount(node)
            .map_err(|source| node_backend_error("authenticate exact snapshot icount", source))?;
        if observed_icount != *expected_icount {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "live exact snapshot capture",
                message: format!(
                    "checkpoint icount {} does not match realized node icount {}",
                    expected_icount.retired, observed_icount.retired
                ),
            });
        }

        let expected_event_log = checkpoint
            .state
            .as_ref()
            .ok_or_else(|| QemuVmRealizationError::InvalidCheckpoint {
                role: "live exact snapshot capture",
                message: String::from("exact checkpoint has no materialized scheduler state"),
            })?
            .event_log;
        if expected_event_log != self.event_log.offset() {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "live exact snapshot capture",
                message: format!(
                    "checkpoint event-log offset {:?} does not match installed offset {:?}",
                    expected_event_log,
                    self.event_log.offset()
                ),
            });
        }
        Ok(())
    }
}

impl<L> QemuNodeRealizationExecutor<L>
where
    L: QemuGuardedNodeRealizationLauncher,
{
    /// Resumes one exact-root-bound snapshot under production replay admission.
    ///
    /// This is the safe external entry point for a retained campaign checkpoint.
    /// It derives the low-level `loadvm` authorization inside the QEMU policy
    /// boundary and refuses snapshots without matching replay-oracle evidence.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when replay evidence is absent or
    /// mismatched, or when the exact materialization, process contract, restore
    /// plan, or resulting runtime differs.
    pub fn resume_materialized_exact_snapshot_guarded(
        &mut self,
        process_contract: &QemuChildProcessContract,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        let policy = QemuExactSnapshotPolicy::production();
        let admission = policy
            .accept_loadvm_realized_runtime(snapshot.replay_oracle_validation())
            .map_err(|source| QemuVmRealizationError::SavevmPolicy { source })?;
        self.load_materialized_exact_snapshot_guarded(
            process_contract,
            config,
            snapshot,
            policy.authorize_loadvm_runtime(),
            admission,
        )
    }

    /// Loads one exact-root-bound snapshot through the guarded launcher.
    ///
    /// The paired snapshot identity is checked by the launcher before its
    /// prepared VMState authority can spawn a child. The restored runtime is
    /// then checked against replay-oracle admission before becoming active.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the exact materialization basis,
    /// child process contract, restore plan, or runtime admission differs.
    fn load_materialized_exact_snapshot_guarded(
        &mut self,
        process_contract: &QemuChildProcessContract,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        authorization: QemuLoadvmCommandAuthorization,
        admission: QemuLoadvmRealizationAdmission,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        validate_checkpoint_matches_config(&snapshot.checkpoint, config, "exact snapshot")?;
        validate_snapshot_pair(snapshot)?;
        require_fat_materialized_snapshot(snapshot, "exact snapshot")?;
        validate_checkpoint_loadvm_state(&snapshot.checkpoint, "exact snapshot")?;
        let restore = QemuNodeRestorePlan::new(&snapshot.checkpoint, authorization, admission)
            .with_host_io_checkpoint(&snapshot.host_io)
            .with_node_continuation(&snapshot.node);
        self.shutdown_active_node_for("replace active realized QEMU node")?;
        let mut node = self.launcher.launch_materialized_exact_node_guarded(
            config,
            snapshot,
            restore,
            process_contract,
        )?;
        QemuRealizedNodeBackend::prepare_authoritative_observation_stream(&mut node).map_err(
            |source| node_backend_error("load guarded exact-root QEMU snapshot", source),
        )?;
        let runtime_id = Backend::fingerprint(&mut node)
            .map(|fingerprint| fingerprint.hash)
            .map_err(|source| {
                node_backend_error("fingerprint guarded exact-root QEMU snapshot", source)
            })?;
        self.active_node = Some(node);
        let runtime = runtime_from_checkpoint_material(config, &snapshot.checkpoint, runtime_id)?;
        validate_runtime_matches_admission(&runtime, admission)?;
        self.retain_runtime_basis(&runtime);
        Ok(runtime)
    }

    /// Loads the materialized snapshot under probe-only authorization.
    ///
    /// This operation exists for the fat side of replay-oracle validation. It
    /// does not grant production runtime admission; a caller must compare the
    /// returned runtime with an independently realized thin path before using
    /// the snapshot as an execution template.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the exact materialization basis,
    /// guarded process contract, restore plan, or snapshot pair differs.
    pub fn load_materialized_exact_snapshot_probe_guarded(
        &mut self,
        process_contract: &QemuChildProcessContract,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        validate_checkpoint_matches_config(&snapshot.checkpoint, config, "exact snapshot probe")?;
        validate_snapshot_pair(snapshot)?;
        require_fat_materialized_snapshot(snapshot, "exact snapshot probe")?;
        validate_checkpoint_loadvm_state(&snapshot.checkpoint, "exact snapshot probe")?;
        let restore =
            QemuNodeRestorePlan::snapshot_completeness_probe(&snapshot.checkpoint, authorization)
                .with_host_io_checkpoint(&snapshot.host_io)
                .with_node_continuation(&snapshot.node);
        self.shutdown_active_node_for("replace active realized QEMU node")?;
        let mut node = self.launcher.launch_materialized_exact_node_guarded(
            config,
            snapshot,
            restore,
            process_contract,
        )?;
        QemuRealizedNodeBackend::prepare_authoritative_observation_stream(&mut node).map_err(
            |source| node_backend_error("probe guarded exact-root QEMU snapshot", source),
        )?;
        let runtime_id = Backend::fingerprint(&mut node)
            .map(|fingerprint| fingerprint.hash)
            .map_err(|source| {
                node_backend_error("fingerprint guarded exact-root QEMU snapshot probe", source)
            })?;
        self.active_node = Some(node);
        let runtime = runtime_from_checkpoint_material(config, &snapshot.checkpoint, runtime_id)?;
        self.retain_runtime_basis(&runtime);
        Ok(runtime)
    }

    /// Replays one bounded quantum on a guarded materialized exact runtime.
    ///
    /// The caller owns operational quantum charging. This method owns only the
    /// live runtime/event-log exactness checks and backend transition.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when no node is active, the supplied
    /// runtime is stale, or the backend cannot reach the requested boundary.
    pub fn replay_materialized_one_quantum(
        &mut self,
        runtime: RuntimeState,
        request: QemuVmReplayRequest,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        self.replay_one_quantum_inner(runtime, request)
    }
}

impl<L> QemuNodeRealizationExecutor<L>
where
    L: QemuGuardedThinNodeRealizationLauncher,
{
    /// Loads one independently prepared proper-ancestor snapshot under a guard.
    ///
    /// The thin launcher binds the restore checkpoint to a VMState authority
    /// distinct from the selected replay-oracle target. The resulting runtime
    /// must still satisfy production replay admission before it can seed suffix
    /// replay.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the snapshot is incomplete, the
    /// prepared checkpoint basis differs, guarded launch fails, or runtime
    /// admission differs.
    pub fn load_prepared_thin_snapshot_guarded(
        &mut self,
        process_contract: &QemuChildProcessContract,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        authorization: QemuLoadvmCommandAuthorization,
        admission: QemuLoadvmRealizationAdmission,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        validate_checkpoint_matches_config(&snapshot.checkpoint, config, "thin snapshot")?;
        validate_snapshot_pair(snapshot)?;
        require_fat_materialized_snapshot(snapshot, "thin snapshot")?;
        validate_checkpoint_loadvm_state(&snapshot.checkpoint, "thin snapshot")?;
        let restore = QemuNodeRestorePlan::new(&snapshot.checkpoint, authorization, admission)
            .with_host_io_checkpoint(&snapshot.host_io)
            .with_node_continuation(&snapshot.node);
        let runtime_id = self.launch_thin_and_install(
            process_contract,
            config,
            restore,
            "load guarded thin-path QEMU snapshot",
        )?;
        let runtime = runtime_from_checkpoint_material(config, &snapshot.checkpoint, runtime_id)?;
        validate_runtime_matches_admission(&runtime, admission)?;
        self.retain_runtime_basis(&runtime);
        Ok(runtime)
    }

    /// Loads one independently prepared baked-genesis snapshot under a guard.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the prepared checkpoint basis,
    /// guarded launch, baked-genesis admission, or runtime state differs.
    pub fn load_prepared_baked_genesis_guarded(
        &mut self,
        process_contract: &QemuChildProcessContract,
        config: &Configuration,
        admission: QemuBakedGenesisRestoreAdmission<'_>,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        let checkpoint = admission.checkpoint();
        let restore = QemuNodeRestorePlan::baked_genesis(admission);
        let runtime_id = self.launch_thin_and_install(
            process_contract,
            config,
            restore,
            "load guarded baked QEMU genesis",
        )?;
        let runtime = runtime_from_scheduled_checkpoint_material(config, checkpoint, runtime_id);
        self.retain_runtime_basis(&runtime);
        Ok(runtime)
    }

    fn launch_thin_and_install(
        &mut self,
        process_contract: &QemuChildProcessContract,
        config: &Configuration,
        restore: QemuNodeRestorePlan<'_>,
        operation: &'static str,
    ) -> Result<ContentHash, QemuVmRealizationError> {
        self.shutdown_active_node_for("replace active guarded replay-oracle QEMU node")?;
        let mut node =
            self.launcher
                .launch_thin_path_node_guarded(config, restore, process_contract)?;
        QemuRealizedNodeBackend::prepare_authoritative_observation_stream(&mut node)
            .map_err(|source| node_backend_error(operation, source))?;
        let runtime_id = Backend::fingerprint(&mut node)
            .map(|fingerprint| fingerprint.hash)
            .map_err(|source| node_backend_error(operation, source))?;
        self.active_node = Some(node);
        Ok(runtime_id)
    }
}

impl<L> QemuVmRealizationExecutor for QemuNodeRealizationExecutor<L>
where
    L: QemuNodeRealizationLauncher,
{
    fn load_exact_snapshot(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        authorization: QemuLoadvmCommandAuthorization,
        admission: QemuLoadvmRealizationAdmission,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        let restore = QemuNodeRestorePlan::new(&snapshot.checkpoint, authorization, admission)
            .with_host_io_checkpoint(&snapshot.host_io)
            .with_node_continuation(&snapshot.node);
        let runtime_id =
            self.launch_and_install(config, restore, "load exact QEMU node snapshot")?;
        let runtime = runtime_from_checkpoint_material(config, &snapshot.checkpoint, runtime_id)?;
        validate_runtime_matches_admission(&runtime, admission)?;
        self.retain_runtime_basis(&runtime);
        Ok(runtime)
    }

    fn load_exact_snapshot_for_replay_oracle_probe(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        let restore =
            QemuNodeRestorePlan::snapshot_completeness_probe(&snapshot.checkpoint, authorization)
                .with_host_io_checkpoint(&snapshot.host_io)
                .with_node_continuation(&snapshot.node);
        let runtime_id = self.launch_and_install(
            config,
            restore,
            "load exact QEMU node snapshot for replay oracle",
        )?;
        let runtime = runtime_from_checkpoint_material(config, &snapshot.checkpoint, runtime_id)?;
        self.retain_runtime_basis(&runtime);
        Ok(runtime)
    }

    fn load_baked_genesis(
        &mut self,
        config: &Configuration,
        admission: QemuBakedGenesisRestoreAdmission<'_>,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        let checkpoint = admission.checkpoint();
        let restore = QemuNodeRestorePlan::baked_genesis(admission);
        let runtime_id = self.launch_and_install(config, restore, "load baked QEMU genesis")?;
        let runtime = runtime_from_scheduled_checkpoint_material(config, checkpoint, runtime_id);
        self.retain_runtime_basis(&runtime);
        Ok(runtime)
    }

    fn replay_one_quantum(
        &mut self,
        runtime: RuntimeState,
        request: QemuVmReplayRequest,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        self.replay_one_quantum_inner(runtime, request)
    }
}

impl<L> QemuNodeRealizationExecutor<L>
where
    L: QemuNodeLauncher,
{
    fn replay_one_quantum_inner(
        &mut self,
        runtime: RuntimeState,
        request: QemuVmReplayRequest,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        if self.observation_sealed {
            return Err(QemuVmRealizationError::Executor {
                operation: "replay one QEMU node quantum",
                message: String::from("modeled observation boundary is already sealed"),
            });
        }
        if runtime.event_log != self.event_log.offset() {
            return Err(QemuVmRealizationError::Executor {
                operation: "replay one QEMU node quantum",
                message: format!(
                    "runtime event-log offset {:?} does not match installed offset {:?}",
                    runtime.event_log,
                    self.event_log.offset()
                ),
            });
        }
        let horizon = replay_horizon_from_runtime(&runtime)?;
        let node_id = self.node.clone();
        let node = self
            .active_node
            .as_mut()
            .ok_or_else(|| QemuVmRealizationError::Executor {
                operation: "replay one QEMU node quantum",
                message: String::from("no QEMU node has been restored"),
            })?;
        match QemuRealizedNodeBackend::advance_live_to_horizon(node, horizon, &mut self.event_log)
            .map_err(|source| node_backend_error("advance QEMU node replay quantum", source))?
        {
            AdvanceOutcome::ReachedHorizon => {}
            AdvanceOutcome::Paused { at } => {
                return Err(QemuVmRealizationError::Executor {
                    operation: "advance QEMU node replay quantum",
                    message: format!(
                        "backend paused at {} before replay horizon {}",
                        at.retired, horizon.icount.retired
                    ),
                });
            }
        }
        let runtime_id = Backend::fingerprint(node)
            .map(|fingerprint| fingerprint.hash)
            .map_err(|source| node_backend_error("sample QEMU node replay fingerprint", source))?;
        let current_icount = QemuRealizedNodeBackend::current_icount(node)
            .map_err(|source| node_backend_error("sample QEMU node replay icount", source))?;

        let runtime = runtime_from_live_replay(
            runtime,
            request,
            node_id,
            current_icount,
            runtime_id,
            self.event_log.offset(),
        );
        self.active_configuration = Some(runtime.configuration);
        Ok(runtime)
    }
}

impl<L> QemuVmLiveRealizationExecutor for QemuNodeRealizationExecutor<L>
where
    L: QemuNodeLauncher,
{
    fn live_backend_is_active(&self) -> bool {
        self.active_node.is_some()
    }

    fn live_backend_mut(
        &mut self,
    ) -> Result<&mut dyn QemuLiveAttemptBackend, QemuVmRealizationError> {
        if self.active_node.is_none() {
            return Err(QemuVmRealizationError::Executor {
                operation: "borrow active realized QEMU node",
                message: String::from("no QEMU node has been restored"),
            });
        }
        Ok(self)
    }

    fn seal_live_observation_boundary(&mut self) -> Result<bool, QemuVmRealizationError> {
        let before = self.event_log.offset();
        let node = self
            .active_node
            .as_mut()
            .ok_or_else(|| QemuVmRealizationError::Executor {
                operation: "seal live QEMU observation boundary",
                message: String::from("no QEMU node has been restored"),
            })?;
        QemuRealizedNodeBackend::seal_live_observation_boundary(node, &mut self.event_log)
            .map_err(|source| node_backend_error("seal live QEMU observation boundary", source))?;
        let after = self.event_log.offset();
        self.observation_sealed = true;
        Ok(after == before)
    }

    fn capture_live_exact_snapshot(
        &mut self,
        checkpoint: Checkpoint,
    ) -> Result<QemuVmSnapshot, QemuVmRealizationError> {
        if self.observation_sealed {
            return Err(QemuVmRealizationError::Executor {
                operation: "capture live exact QEMU snapshot",
                message: String::from("modeled observation boundary is already sealed"),
            });
        }
        if self.active_node.is_none() {
            return Err(QemuVmRealizationError::Executor {
                operation: "capture live exact QEMU snapshot",
                message: String::from("no QEMU node has been restored"),
            });
        }
        let active_configuration =
            self.active_configuration
                .ok_or_else(|| QemuVmRealizationError::Executor {
                    operation: "capture live exact QEMU snapshot",
                    message: String::from("no active configuration is installed"),
                })?;
        if checkpoint.configuration != active_configuration || checkpoint.id != active_configuration
        {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "live exact snapshot capture",
                message: String::from(
                    "checkpoint identity does not name the installed configuration",
                ),
            });
        }

        let node = self
            .active_node
            .as_mut()
            .ok_or_else(|| QemuVmRealizationError::Executor {
                operation: "capture live exact QEMU snapshot",
                message: String::from("no QEMU node has been restored"),
            })?;
        self.observation_sealed = true;
        QemuRealizedNodeBackend::seal_live_observation_boundary(node, &mut self.event_log)
            .map_err(|source| node_backend_error("seal exact snapshot boundary", source))?;
        self.validate_capture_checkpoint_basis(&checkpoint)?;

        let node = self
            .active_node
            .as_mut()
            .ok_or_else(|| QemuVmRealizationError::Executor {
                operation: "capture live exact QEMU snapshot",
                message: String::from("no QEMU node has been restored"),
            })?;
        QemuRealizedNodeBackend::capture_live_exact_snapshot_paused(node, &self.node, checkpoint)
            .map_err(|source| node_backend_error("capture live exact QEMU snapshot", source))
    }

    fn shutdown_live_backend(&mut self) -> Result<QemuLiveBackendShutdown, QemuVmRealizationError> {
        let Some(node) = self.active_node.as_mut() else {
            return Ok(QemuLiveBackendShutdown::unchanged());
        };
        let before = self.event_log.offset();
        QemuRealizedNodeBackend::shutdown_live_with_event_log(node, &mut self.event_log)
            .map_err(|source| node_backend_error("shutdown active realized QEMU node", source))?;
        let after = self.event_log.offset();
        self.active_node = None;
        self.active_configuration = None;
        let unchanged = !self.observation_sealed || before == after;
        self.observation_sealed = false;
        Ok(QemuLiveBackendShutdown {
            observation_boundary_unchanged: unchanged,
        })
    }
}

impl<L> QemuLiveAttemptBackend for QemuNodeRealizationExecutor<L>
where
    L: QemuNodeLauncher,
{
    fn advance_to_horizon(
        &mut self,
        horizon: crucible::ExecutionHorizon,
    ) -> Result<AdvanceOutcome, BackendError> {
        if self.observation_sealed {
            return Err(BackendError::Rejected {
                message: String::from("modeled observation boundary is already sealed"),
            });
        }
        let node = self
            .active_node
            .as_mut()
            .ok_or_else(|| BackendError::Rejected {
                message: String::from("no QEMU node has been restored"),
            })?;
        QemuRealizedNodeBackend::advance_live_to_horizon(node, horizon, &mut self.event_log)
    }

    fn fingerprint(&mut self) -> Result<crucible::ExecutionFingerprint, BackendError> {
        let node = self
            .active_node
            .as_mut()
            .ok_or_else(|| BackendError::Rejected {
                message: String::from("no QEMU node has been restored"),
            })?;
        Backend::fingerprint(node)
    }

    fn deliver_input(&mut self, input: crucible::BackendInput) -> Result<(), BackendError> {
        if self.observation_sealed {
            return Err(BackendError::Rejected {
                message: String::from("modeled observation boundary is already sealed"),
            });
        }
        let node = self
            .active_node
            .as_mut()
            .ok_or_else(|| BackendError::Rejected {
                message: String::from("no QEMU node has been restored"),
            })?;
        Backend::deliver_input(node, input)
    }

    fn current_icount(&mut self) -> Result<Icount, BackendError> {
        let node = self
            .active_node
            .as_mut()
            .ok_or_else(|| BackendError::Rejected {
                message: String::from("no QEMU node has been restored"),
            })?;
        QemuRealizedNodeBackend::current_icount(node)
    }

    fn event_log(&self) -> &EventLog {
        &self.event_log
    }
}

fn runtime_from_checkpoint_material(
    config: &Configuration,
    checkpoint: &Checkpoint,
    runtime_id: ContentHash,
) -> Result<RuntimeState, QemuVmRealizationError> {
    if checkpoint.configuration != config.id() {
        return Err(QemuVmRealizationError::InvalidCheckpoint {
            role: "node realization",
            message: format!(
                "checkpoint configuration {:?} does not match configuration {:?}",
                checkpoint.configuration,
                config.id()
            ),
        });
    }
    Ok(runtime_from_scheduled_checkpoint_material(
        config, checkpoint, runtime_id,
    ))
}

fn require_fat_materialized_snapshot(
    snapshot: &QemuVmSnapshot,
    role: &'static str,
) -> Result<(), QemuVmRealizationError> {
    if snapshot.checkpoint.kind != CheckpointKind::Fat {
        return Err(QemuVmRealizationError::InvalidCheckpoint {
            role,
            message: String::from("guarded exact restore requires a fat checkpoint"),
        });
    }
    Ok(())
}

fn runtime_from_scheduled_checkpoint_material(
    config: &Configuration,
    checkpoint: &Checkpoint,
    runtime_id: ContentHash,
) -> RuntimeState {
    let scheduler = checkpoint
        .state
        .as_ref()
        .map(|state| state.scheduler.clone())
        .unwrap_or_else(|| crucible::SchedulerState::from_schedule(&config.schedule));
    let event_log = checkpoint
        .state
        .as_ref()
        .map(|state| state.event_log)
        .unwrap_or_default();
    RuntimeState {
        id: runtime_id,
        configuration: config.id(),
        node_blobs: checkpoint.node_blobs.clone(),
        node_icounts: checkpoint.node_icounts.clone(),
        scheduler,
        event_log,
    }
}

fn runtime_from_live_replay(
    runtime: RuntimeState,
    request: QemuVmReplayRequest,
    node: NodeId,
    current_icount: Icount,
    runtime_id: ContentHash,
    event_log: EventLogOffset,
) -> RuntimeState {
    let mut scheduler = runtime.scheduler;
    scheduler.apply_decision(&request.decision);
    let mut node_icounts = runtime.node_icounts;
    node_icounts.insert(node, current_icount);
    RuntimeState {
        id: runtime_id,
        configuration: request.to.id(),
        node_blobs: runtime.node_blobs,
        node_icounts,
        scheduler,
        event_log,
    }
}

fn replay_horizon_from_runtime(
    runtime: &RuntimeState,
) -> Result<crucible::ExecutionHorizon, QemuVmRealizationError> {
    let current = runtime
        .node_icounts
        .values()
        .map(|icount| icount.retired)
        .max()
        .ok_or_else(|| QemuVmRealizationError::Executor {
            operation: "derive QEMU node replay horizon",
            message: String::from("runtime has no restored node instruction counts"),
        })?;
    let retired = current
        .checked_add(1)
        .ok_or_else(|| QemuVmRealizationError::Executor {
            operation: "derive QEMU node replay horizon",
            message: String::from("current instruction count is already at u64::MAX"),
        })?;
    Ok(crucible::ExecutionHorizon {
        icount: Icount { retired },
    })
}

fn warm_restore_error(source: QemuWarmRestoreLaunchError) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation: "launch warm QEMU node",
        message: source.to_string(),
    }
}

fn validate_profile_materialization(
    config: &QemuLiveNodeStepGateConfig,
    run_directory: &QemuPreparedRunDirectory,
    binding: QemuVmStateBinding,
) -> Result<(), QemuVmRealizationError> {
    if config.run_directory() != run_directory.path() {
        return Err(QemuVmRealizationError::InvalidCheckpoint {
            role: "scenario-profile warm restore",
            message: String::from(
                "launch profile does not name the descriptor-pinned run directory",
            ),
        });
    }
    run_directory
        .require_exact_vmstate(binding)
        .map_err(profile_materialization_error)?;
    if config.resource_requirements().has_root_overlay() {
        run_directory
            .require_exact_root_overlay(binding)
            .map_err(profile_materialization_error)?;
    }
    Ok(())
}

fn profile_materialization_error(source: QemuSpawnError) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation: "admit scenario-profile warm restore artifacts",
        message: source.to_string(),
    }
}

fn retain_profile_restore_result(
    result: Result<QemuNode, QemuLiveNodeStepGateError>,
    failed_child: &mut Option<crate::QemuNodeChild>,
    config: &Configuration,
) -> Result<QemuNode, QemuVmRealizationError> {
    match result {
        Ok(node) => Ok(node),
        Err(mut source) => {
            *failed_child = source.take_unreaped_child();
            Err(QemuVmRealizationError::Executor {
                operation: "launch scenario-profile warm QEMU node",
                message: format!("configuration {}: {source}", config.id().to_hex()),
            })
        }
    }
}

fn require_no_failed_launch_child(
    failed_child: &Option<crate::QemuNodeChild>,
) -> Result<(), QemuVmRealizationError> {
    if failed_child.is_some() {
        return Err(QemuVmRealizationError::ReapQuarantined {
            operation: "launch warm QEMU node",
            message: String::from(
                "a prior failed launch still owns an unreaped direct-child handle",
            ),
        });
    }
    Ok(())
}

fn retain_warm_restore_result(
    result: Result<QemuNode, QemuWarmRestoreLaunchError>,
    failed_child: &mut Option<crate::QemuNodeChild>,
) -> Result<QemuNode, QemuVmRealizationError> {
    match result {
        Ok(node) => Ok(node),
        Err(mut source) => {
            *failed_child = source.take_unreaped_child();
            Err(warm_restore_error(source))
        }
    }
}

fn node_backend_error(operation: &'static str, source: BackendError) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation,
        message: source.to_string(),
    }
}

#[cfg(test)]
mod tests;
