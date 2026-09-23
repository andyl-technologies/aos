//! Real-node executor for QEMU VM realization.
//!
//! This Linux-only executor bridges the policy-level realization coordinator to
//! a live [`QemuNode`]. The launcher restores authenticated v9 device and RAM
//! descriptors before node assembly; after that, replay uses the shared-memory
//! hot path and deterministic fingerprint sampling without reopening generic
//! QMP save/restore on the scheduler-facing node.

use crucible::{
    AdvanceOutcome, Backend, BackendError, Checkpoint, CheckpointKind, Configuration, ContentHash,
    EventLog, Icount, NodeId, RuntimeState,
};
use std::error::Error as _;
use std::sync::Arc;

use crate::node_factory::QemuNodeCheckpointAssertion;
use crate::{
    QemuChildProcessContract, QemuGuardedBakedRestoreAdmission, QemuGuardedProbeRestoreAdmission,
    QemuLiveNodeIdentity, QemuLiveNodeStepGateConfig, QemuLiveNodeStepGateError, QemuNode,
    QemuPreparedRunDirectory,
};
#[cfg(target_os = "linux")]
use crate::{
    QemuProductionExactRestoreLaunch, QemuProductionExactRestoreRequest,
    QemuProductionFreshLaunchAdmission, launch_qemu_production_fresh_node,
};

use super::{
    QemuBakedGenesisRestoreAdmission, QemuReplayOracleMatch, QemuReplayOracleProbeAdmission,
    QemuVmRealizationError, QemuVmReplayRequest, QemuVmSnapshot,
    validate_checkpoint_matches_config, validate_exact_checkpoint_state, validate_snapshot_pair,
};

struct QemuReplayObservationAuthority;

/// Opaque exact-leg observation produced by a guarded replay-oracle executor.
pub struct QemuReplayOracleExactObservation {
    runtime: RuntimeState,
    authority: Arc<QemuReplayObservationAuthority>,
    generation: u64,
}

/// Opaque thin-leg observation produced by a guarded replay-oracle executor.
pub struct QemuReplayOracleThinObservation {
    runtime: RuntimeState,
    authority: Arc<QemuReplayObservationAuthority>,
    generation: u64,
}

/// Backend operations required after a QEMU node has been restored.
///
/// This deliberately does not expose generic snapshot or restore: the
/// scheduler-facing node receives device-state authority only before assembly,
/// via the crate-internal sealed descriptor restore boundary.
pub(crate) trait QemuRealizedNodeBackend: Backend {
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

/// Paused node operation that seals one retained hot-fork template.
///
/// Implementations must leave the node paused and retain every template and
/// branch-private descriptor after success. An error must leave the same node
/// owned by its realization executor for cleanup or exact retry.
pub(crate) trait QemuHotForkTemplatePreparer: QemuRealizedNodeBackend {
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
        self.prepare_hot_fork_template_barriers(block_snapshot_bindings)
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
/// It keeps the exact realized configuration and unified event-log prefix
/// paired while whole-world child reconciliation temporarily borrows the raw
/// source node.
#[must_use = "reassemble the exact prepared template after child reconciliation"]
pub(crate) struct QemuHotForkTemplateIdentity {
    configuration: ContentHash,
    event_log: EventLog,
    launch_resources: crate::QemuLaunchResourceRequirements,
}

impl QemuHotForkTemplateIdentity {
    pub(crate) fn new_prepared(
        configuration: ContentHash,
        event_log: EventLog,
        launch_resources: crate::QemuLaunchResourceRequirements,
    ) -> Self {
        Self {
            configuration,
            event_log,
            launch_resources,
        }
    }

    /// Returns the exact configuration realized by the retained source.
    #[must_use]
    pub const fn configuration(&self) -> ContentHash {
        self.configuration
    }

    /// Returns the admitted launch resource profile of the retained source.
    ///
    /// A child forked from the template is admitted into its own run
    /// directory under this same baseline; its private VMState container is
    /// provisioned there before the fork copies the frozen source bytes.
    #[must_use]
    pub const fn launch_resources(&self) -> crate::QemuLaunchResourceRequirements {
        self.launch_resources
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
            .field("launch_resources", &self.launch_resources)
            .finish_non_exhaustive()
    }
}

mod guarded_launcher_ops {
    use super::*;

    /// Exact-root-bound launcher for one guarded checkpoint restore.
    ///
    /// This capability receives the exact paired snapshot and the sealed
    /// child-process contract retained by its atomic request. Implementations must reject any snapshot other than
    /// the one whose authenticated version-nine descriptors were committed into
    /// their prepared run-directory authority, and must use only a guarded
    /// child-spawn path.
    pub(crate) trait Exact {
        /// Launches one exact target solely for replay-oracle comparison.
        ///
        /// # Errors
        ///
        /// Returns [`QemuVmRealizationError`] when descriptor preparation, guarded
        /// launch, or restored node assembly fails.
        fn launch_materialized_probe_node_guarded(
            &mut self,
            config: &Configuration,
            snapshot: &QemuVmSnapshot,
            restore: QemuGuardedProbeRestoreAdmission<'_>,
        ) -> Result<QemuNode, QemuVmRealizationError>;
    }

    /// Launches a trusted descriptor-backed thin-path checkpoint under one child-process contract.
    ///
    /// A replay-oracle probe must consume the selected exact-root binding, while its
    /// independently prepared baked-genesis or cached-ancestor path must not reuse
    /// that target checkpoint authority.
    pub(crate) trait Thin {
        /// Launches one admitted baked-genesis restore.
        ///
        /// # Errors
        ///
        /// Returns [`QemuVmRealizationError`] when descriptor preparation, guarded
        /// launch, or restored node assembly fails.
        fn launch_baked_genesis_node_guarded(
            &mut self,
            config: &Configuration,
            restore: QemuGuardedBakedRestoreAdmission<'_>,
            process_contract: &QemuChildProcessContract,
        ) -> Result<QemuNode, QemuVmRealizationError>;
    }
}

use guarded_launcher_ops::{
    Exact as QemuGuardedNodeRealizationLauncherOps,
    Thin as QemuGuardedThinNodeRealizationLauncherOps,
};

/// Retains a direct child whose post-spawn realization cleanup could not reap it.
///
/// Concrete guarded launchers implement this sealed handoff so the attempt
/// guard can authenticate the child against its cgroup and transfer it to the
/// nondroppable process-quarantine owner. A launcher with a retained child must
/// reject another launch until the caller takes that authority.
trait QemuFailedLaunchChildSource {
    /// Takes the nonduplicable direct-child handle retained after failed reap.
    #[must_use]
    fn take_failed_launch_child(&mut self) -> Option<crate::QemuNodeChild>;
}

mod admission;
mod replay_physical;
use admission::QemuReplayValidationNodeLauncher;
pub use admission::{QemuReplayValidationExactAdmission, QemuReplayValidationThinAdmission};

/// Realization executor backed by one active QEMU node at a time.
pub struct QemuReplayValidationExecutor {
    node: NodeId,
    launcher: QemuReplayValidationNodeLauncher,
    active_node: Option<QemuNode>,
    active_configuration: Option<Configuration>,
    active_runtime_id: Option<ContentHash>,
    event_log: EventLog,
    authority: Arc<QemuReplayObservationAuthority>,
    next_generation: u64,
    exact_observation_generation: Option<u64>,
    thin_observation_generation: Option<u64>,
}

impl QemuReplayValidationExecutor {
    /// Creates the concrete executor for one admitted exact/thin comparison.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the exact and thin admissions
    /// do not describe one compatible realization boundary.
    pub fn new(
        exact: QemuReplayValidationExactAdmission,
        thin: QemuReplayValidationThinAdmission,
    ) -> Result<Self, QemuVmRealizationError> {
        QemuReplayValidationNodeLauncher::new(exact, thin)
            .map(QemuReplayValidationNodeLauncher::into_executor)
    }

    /// Returns the exact modeled node bound to this realization executor.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
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

    /// Takes a direct child retained after a post-spawn launch reap failure.
    ///
    /// The caller must authenticate the returned child against the exact
    /// attempt cgroup and transfer it to the nondroppable process-quarantine
    /// owner before releasing resources. Until this handoff occurs, concrete
    /// launchers reject every subsequent launch.
    #[must_use]
    pub fn take_failed_launch_child_for_quarantine(&mut self) -> Option<crate::QemuNodeChild> {
        self.launcher.take_failed_launch_child()
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
        self.active_runtime_id = None;
        Ok(())
    }

    fn retain_runtime_basis(&mut self, runtime: &RuntimeState, configuration: &Configuration) {
        self.active_configuration = Some(configuration.clone());
        self.active_runtime_id = Some(runtime.id);
        self.event_log = EventLog::from_offset(runtime.event_log);
    }

    fn issue_observation_generation(&mut self) -> Result<u64, QemuVmRealizationError> {
        self.next_generation = self.next_generation.checked_add(1).ok_or_else(|| {
            QemuVmRealizationError::Executor {
                operation: "issue replay-oracle observation",
                message: String::from("observation generation exhausted"),
            }
        })?;
        Ok(self.next_generation)
    }

    fn validate_observation(
        &self,
        authority: &Arc<QemuReplayObservationAuthority>,
        generation: u64,
        expected_generation: Option<u64>,
        role: &'static str,
    ) -> Result<(), QemuVmRealizationError> {
        validate_observation_binding(
            &self.authority,
            authority,
            generation,
            expected_generation,
            role,
        )
    }
}

impl QemuReplayValidationExecutor {
    /// Loads the materialized snapshot for the private completeness probe.
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
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
    ) -> Result<QemuReplayOracleExactObservation, QemuVmRealizationError> {
        let admission = QemuReplayOracleProbeAdmission::new(snapshot);
        let snapshot = admission.snapshot();
        validate_checkpoint_matches_config(&snapshot.checkpoint, config, "exact snapshot probe")?;
        validate_snapshot_pair(snapshot)?;
        require_fat_materialized_snapshot(snapshot, "exact snapshot probe")?;
        validate_exact_checkpoint_state(&snapshot.checkpoint, "exact snapshot probe")?;
        eprintln!("CRUCIBLE-PROMOTION-PROBE-TRACE-V1 stage=validated");
        let restore = QemuGuardedProbeRestoreAdmission::new(&snapshot.checkpoint);
        self.shutdown_active_node_for("replace active realized QEMU node")?;
        eprintln!("CRUCIBLE-PROMOTION-PROBE-TRACE-V1 stage=prior-node-cleared");
        let mut node = self
            .launcher
            .launch_materialized_probe_node_guarded(config, snapshot, restore)?;
        eprintln!("CRUCIBLE-PROMOTION-PROBE-TRACE-V1 stage=exact-node-launched-paused");
        QemuRealizedNodeBackend::prepare_authoritative_observation_stream(&mut node).map_err(
            |source| node_backend_error("probe guarded exact-root QEMU snapshot", source),
        )?;
        eprintln!("CRUCIBLE-PROMOTION-PROBE-TRACE-V1 stage=observation-stream-ready");
        let runtime_id = Backend::fingerprint(&mut node)
            .map(|fingerprint| fingerprint.hash)
            .map_err(|source| {
                node_backend_error("fingerprint guarded exact-root QEMU snapshot probe", source)
            })?;
        eprintln!("CRUCIBLE-PROMOTION-PROBE-TRACE-V1 stage=fingerprint-ready");
        self.active_node = Some(node);
        let runtime = runtime_from_checkpoint_material(config, &snapshot.checkpoint, runtime_id)?;
        self.retain_runtime_basis(&runtime, config);
        let generation = self.issue_observation_generation()?;
        self.exact_observation_generation = Some(generation);
        Ok(QemuReplayOracleExactObservation {
            runtime,
            authority: Arc::clone(&self.authority),
            generation,
        })
    }
}

impl QemuReplayValidationExecutor {
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
        world: &crucible::World,
        snapshot: &super::QemuBakedGenesisSnapshot,
    ) -> Result<QemuReplayOracleThinObservation, QemuVmRealizationError> {
        let admission = QemuBakedGenesisRestoreAdmission::new(snapshot, world)?;
        validate_thin_snapshot(self.launcher.thin_snapshot(), snapshot.source_snapshot)?;
        let checkpoint = admission.checkpoint();
        validate_checkpoint_matches_config(checkpoint, config, "thin baked-genesis replay")?;
        let restore = QemuGuardedBakedRestoreAdmission::new(admission);
        let runtime_id = self.launch_thin_and_install(
            process_contract,
            config,
            restore,
            "load guarded baked QEMU genesis",
        )?;
        let runtime = runtime_from_scheduled_checkpoint_material(config, checkpoint, runtime_id);
        self.retain_runtime_basis(&runtime, config);
        let generation = self.issue_observation_generation()?;
        self.thin_observation_generation = Some(generation);
        Ok(QemuReplayOracleThinObservation {
            runtime,
            authority: Arc::clone(&self.authority),
            generation,
        })
    }

    /// Finishes one concrete fat/thin replay comparison.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when either guarded observation names
    /// another configuration.
    pub fn finish_replay_oracle_comparison(
        &mut self,
        snapshot: &QemuVmSnapshot,
        configuration: &Configuration,
        fat: QemuReplayOracleExactObservation,
        thin: QemuReplayOracleThinObservation,
    ) -> Result<QemuReplayOracleMatch, QemuVmRealizationError> {
        if snapshot.id() != self.launcher.exact_snapshot() {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "replay-oracle comparison source",
                message: String::from(
                    "comparison source differs from the admitted materialized exact snapshot",
                ),
            });
        }
        self.validate_observation(
            &fat.authority,
            fat.generation,
            self.exact_observation_generation,
            "exact replay-oracle observation",
        )?;
        self.validate_observation(
            &thin.authority,
            thin.generation,
            self.thin_observation_generation,
            "thin replay-oracle observation",
        )?;
        super::validate_oracle_runtime_configuration(
            "exact checkpoint probe",
            &fat.runtime,
            configuration.id(),
        )?;
        super::validate_oracle_runtime_configuration(
            "thin replay",
            &thin.runtime,
            configuration.id(),
        )?;
        self.exact_observation_generation = None;
        self.thin_observation_generation = None;
        if fat.runtime.id != thin.runtime.id {
            return Err(QemuVmRealizationError::ReplayOracleMismatch {
                fat_hash: fat.runtime.id,
                thin_hash: thin.runtime.id,
            });
        }
        let source = self.launcher.take_exact_target().ok_or_else(|| {
            QemuVmRealizationError::InvalidCheckpoint {
                role: "replay-oracle comparison source",
                message: String::from("rooted exact target authority is absent or was consumed"),
            }
        })?;

        Ok(QemuReplayOracleMatch {
            node: self.node.clone(),
            source,
            runtime_hash: fat.runtime.id,
        })
    }

    fn launch_thin_and_install(
        &mut self,
        process_contract: &QemuChildProcessContract,
        config: &Configuration,
        restore: QemuGuardedBakedRestoreAdmission<'_>,
        operation: &'static str,
    ) -> Result<ContentHash, QemuVmRealizationError> {
        self.shutdown_active_node_for("replace active guarded replay-oracle QEMU node")?;
        let mut node =
            self.launcher
                .launch_baked_genesis_node_guarded(config, restore, process_contract)?;
        QemuRealizedNodeBackend::prepare_authoritative_observation_stream(&mut node)
            .map_err(|source| node_backend_error(operation, source))?;
        let runtime_id = Backend::fingerprint(&mut node)
            .map(|fingerprint| fingerprint.hash)
            .map_err(|source| node_backend_error(operation, source))?;
        self.active_node = Some(node);
        Ok(runtime_id)
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

fn validate_admitted_nodes(exact: &NodeId, thin: &NodeId) -> Result<(), QemuVmRealizationError> {
    if exact == thin {
        return Ok(());
    }
    Err(QemuVmRealizationError::InvalidCheckpoint {
        role: "replay-oracle modeled node",
        message: String::from("exact and thin admissions name different modeled nodes"),
    })
}

fn validate_replay_profiles(
    exact: &QemuLiveNodeStepGateConfig,
    thin: &QemuLiveNodeStepGateConfig,
) -> Result<(), QemuVmRealizationError> {
    if exact.has_same_replay_profile(thin) {
        return Ok(());
    }
    Err(QemuVmRealizationError::InvalidCheckpoint {
        role: "replay-oracle launch profile",
        message: String::from("exact and thin admissions use different immutable launch profiles"),
    })
}

fn validate_thin_snapshot(
    admitted: ContentHash,
    supplied: ContentHash,
) -> Result<(), QemuVmRealizationError> {
    if admitted == supplied {
        return Ok(());
    }
    Err(QemuVmRealizationError::InvalidCheckpoint {
        role: "thin replay source",
        message: String::from("baked snapshot differs from the snapshot admitted for thin replay"),
    })
}

fn validate_observation_binding(
    executor: &Arc<QemuReplayObservationAuthority>,
    observation: &Arc<QemuReplayObservationAuthority>,
    generation: u64,
    expected_generation: Option<u64>,
    role: &'static str,
) -> Result<(), QemuVmRealizationError> {
    if Arc::ptr_eq(executor, observation) && expected_generation == Some(generation) {
        return Ok(());
    }
    Err(QemuVmRealizationError::InvalidCheckpoint {
        role,
        message: String::from(
            "observation was issued by another executor or stale process generation",
        ),
    })
}

fn validate_replay_transition(
    active_configuration: Option<&Configuration>,
    active_runtime_id: Option<ContentHash>,
    runtime: &RuntimeState,
    request: &QemuVmReplayRequest,
) -> Result<(), QemuVmRealizationError> {
    let active_configuration =
        active_configuration.ok_or_else(|| QemuVmRealizationError::Executor {
            operation: "replay one QEMU node quantum",
            message: String::from("no active replay configuration is installed"),
        })?;
    if active_configuration != request.from() || runtime.configuration != request.from().id() {
        return Err(QemuVmRealizationError::InvalidCheckpoint {
            role: "replay transition source",
            message: String::from(
                "request source differs from the active configuration or runtime",
            ),
        });
    }
    if active_runtime_id != Some(runtime.id) {
        return Err(QemuVmRealizationError::InvalidCheckpoint {
            role: "replay runtime generation",
            message: String::from("runtime differs from the active replay generation"),
        });
    }
    let canonical_target =
        crucible::try_step(request.from(), request.decision().clone()).map_err(|source| {
            QemuVmRealizationError::InvalidCheckpoint {
                role: "replay transition target",
                message: format!("decision violates the scenario model: {source}"),
            }
        })?;
    if canonical_target != *request.to() {
        return Err(QemuVmRealizationError::InvalidCheckpoint {
            role: "replay transition target",
            message: String::from("request target is not the canonical modeled transition"),
        });
    }
    Ok(())
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

fn retain_profile_restore_result(
    result: Result<QemuNode, QemuLiveNodeStepGateError>,
    failed_child: &mut Option<crate::QemuNodeChild>,
    config: &Configuration,
) -> Result<QemuNode, QemuVmRealizationError> {
    match result {
        Ok(node) => Ok(node),
        Err(mut source) => {
            let mut detail = source.to_string();
            let mut cause = source.source();
            for _ in 0..4 {
                let Some(next) = cause else { break };
                detail.push_str(": ");
                detail.push_str(&next.to_string());
                cause = next.source();
            }
            *failed_child = source.take_unreaped_child();
            Err(QemuVmRealizationError::Executor {
                operation: "launch scenario-profile restored QEMU node",
                message: format!("{detail}; configuration {}", config.id().to_hex()),
            })
        }
    }
}

fn require_no_failed_launch_child(
    failed_child: &Option<crate::QemuNodeChild>,
) -> Result<(), QemuVmRealizationError> {
    if failed_child.is_some() {
        return Err(QemuVmRealizationError::ReapQuarantined {
            operation: "launch restored QEMU node",
            message: String::from(
                "a prior failed launch still owns an unreaped direct-child handle",
            ),
        });
    }
    Ok(())
}

fn node_backend_error(operation: &'static str, source: BackendError) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation,
        message: source.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crucible::{Decision, EventLogOffset, RngDecision, RngStreamId, Schedule, SchedulerState};

    use super::*;

    fn replay_fixture() -> (Configuration, RuntimeState, QemuVmReplayRequest) {
        let definition = crucible::ScenarioDef::from_canonical_material(
            "crucible.test.qemu.replay-authority",
            "transition",
        );
        let configuration = Configuration::genesis(definition);
        let request = QemuVmReplayRequest::new(
            configuration.clone(),
            Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("replay-authority"),
                value: 7,
            }),
        )
        .unwrap_or_else(|error| panic!("test replay request should be valid: {error}"));
        let runtime = RuntimeState {
            id: ContentHash::from_bytes(b"active replay runtime"),
            configuration: configuration.id(),
            node_blobs: BTreeMap::new(),
            node_icounts: BTreeMap::new(),
            scheduler: SchedulerState::from_schedule(&Schedule::empty()),
            event_log: EventLogOffset::default(),
        };
        (configuration, runtime, request)
    }

    #[test]
    fn replay_transition_rejects_mismatched_source_and_stale_runtime() {
        let (configuration, mut runtime, request) = replay_fixture();
        let unrelated = Configuration::genesis(crucible::ScenarioDef::from_canonical_material(
            "crucible.test.qemu.replay-authority",
            "unrelated",
        ));

        assert!(matches!(
            validate_replay_transition(Some(&unrelated), Some(runtime.id), &runtime, &request,),
            Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "replay transition source",
                ..
            })
        ));

        runtime.id = ContentHash::from_bytes(b"stale replay runtime");
        assert!(matches!(
            validate_replay_transition(
                Some(&configuration),
                Some(ContentHash::from_bytes(b"active replay runtime")),
                &runtime,
                &request,
            ),
            Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "replay runtime generation",
                ..
            })
        ));
    }

    #[test]
    fn replay_transition_rejects_forged_target() {
        let (configuration, runtime, mut request) = replay_fixture();
        request.to = configuration.clone();

        assert!(matches!(
            validate_replay_transition(Some(&configuration), Some(runtime.id), &runtime, &request,),
            Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "replay transition target",
                ..
            })
        ));
    }

    #[test]
    fn observations_reject_cross_executor_and_stale_generations() {
        let first = Arc::new(QemuReplayObservationAuthority);
        let second = Arc::new(QemuReplayObservationAuthority);

        assert!(validate_observation_binding(&first, &first, 4, Some(4), "exact").is_ok());
        assert!(matches!(
            validate_observation_binding(&first, &second, 4, Some(4), "exact"),
            Err(QemuVmRealizationError::InvalidCheckpoint { role: "exact", .. })
        ));
        assert!(matches!(
            validate_observation_binding(&first, &first, 3, Some(4), "thin"),
            Err(QemuVmRealizationError::InvalidCheckpoint { role: "thin", .. })
        ));
    }

    #[test]
    fn admissions_reject_node_and_full_snapshot_transplants() {
        let first_node = NodeId {
            name: String::from("first"),
        };
        let second_node = NodeId {
            name: String::from("second"),
        };
        assert!(validate_admitted_nodes(&first_node, &first_node).is_ok());
        assert!(validate_admitted_nodes(&first_node, &second_node).is_err());

        let first_snapshot = ContentHash::from_bytes(b"first full snapshot");
        let second_snapshot = ContentHash::from_bytes(b"second full snapshot");
        assert!(validate_thin_snapshot(first_snapshot, first_snapshot).is_ok());
        assert!(validate_thin_snapshot(first_snapshot, second_snapshot).is_err());
    }

    #[test]
    fn admissions_reject_different_immutable_launch_profiles() {
        let first = QemuLiveNodeStepGateConfig::new(
            "/qemu",
            "/plugin",
            "/kernel",
            "/firmware",
            "/run/first",
        )
        .with_process_generation(1);
        let same = first
            .clone()
            .with_run_directory("/run/second")
            .with_process_generation(2);
        let different = same.clone().with_scenario_seed(17);

        assert!(validate_replay_profiles(&first, &same).is_ok());
        assert!(matches!(
            validate_replay_profiles(&first, &different),
            Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "replay-oracle launch profile",
                ..
            })
        ));
    }

    #[test]
    fn baked_checkpoint_rejects_unrelated_configuration() {
        let source = Configuration::genesis(crucible::ScenarioDef::from_canonical_material(
            "crucible.test.qemu.replay-authority",
            "baked-source",
        ));
        let unrelated = Configuration::genesis(crucible::ScenarioDef::from_canonical_material(
            "crucible.test.qemu.replay-authority",
            "baked-unrelated",
        ));
        let checkpoint = Checkpoint::from_recorded_configuration(
            &source,
            None,
            crucible::VirtualTime { ticks: 0 },
            BTreeMap::new(),
            CheckpointKind::Fat,
            BTreeMap::new(),
        )
        .unwrap_or_else(|error| panic!("build baked checkpoint: {error}"));

        assert!(matches!(
            validate_checkpoint_matches_config(
                &checkpoint,
                &unrelated,
                "thin baked-genesis replay",
            ),
            Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "thin baked-genesis replay",
                ..
            })
        ));
    }
}
