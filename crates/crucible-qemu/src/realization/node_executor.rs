//! Real-node executor for QEMU VM realization.
//!
//! This Linux-only executor bridges the policy-level realization coordinator to
//! a live [`QemuNode`]. The launcher performs the authorized VMState `loadvm`
//! before node assembly; after that, replay uses the shared-memory hot path and
//! deterministic fingerprint sampling without reopening generic QMP
//! save/restore on the scheduler-facing node.

use crucible::{
    AdvanceOutcome, Backend, BackendError, Checkpoint, Configuration, ContentHash, Icount, NodeId,
    RuntimeState, SchedulerSendAuthorizer,
};
use crucible_shmem::RegionConfig;

use crate::{
    QemuHostIoRuntime, QemuLaunchCommand, QemuLoadvmCommandAuthorization,
    QemuLoadvmRealizationAdmission, QemuNode, QemuNodeFactoryRuntime, QemuNodeRestorePlan,
    QemuWarmRestoreLaunchError, spawn_setup_and_restore_qemu_node,
};

use super::{
    QemuBakedGenesisRestoreAdmission, QemuVmRealizationError, QemuVmRealizationExecutor,
    QemuVmReplayRequest, QemuVmSnapshot, validate_runtime_matches_admission,
};

/// Backend operations required after a QEMU node has been restored.
///
/// This deliberately does not expose generic snapshot or restore: the
/// scheduler-facing node receives VMState authority only before assembly, via a
/// [`QemuNodeRestorePlan`].
pub trait QemuRealizedNodeBackend: Backend {
    /// Reads the current retired instruction count for the realized node.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the shared-memory hot path cannot be read.
    fn current_icount(&mut self) -> Result<Icount, BackendError>;
}

impl QemuRealizedNodeBackend for QemuNode {
    fn current_icount(&mut self) -> Result<Icount, BackendError> {
        QemuNode::current_icount(self).map_err(BackendError::from)
    }
}

/// Launches a QEMU node that has already been VMState-restored before assembly.
pub trait QemuNodeRealizationLauncher {
    /// Concrete node handle returned by this launcher.
    type Node: QemuRealizedNodeBackend;

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

/// Concrete launcher that composes QEMU spawn, plugin setup, QMP load, and node assembly.
pub struct QemuWarmRestoreNodeLauncher<A, R, F> {
    command: QemuLaunchCommand,
    run_directory: std::path::PathBuf,
    region_config: RegionConfig,
    slot_index: u32,
    runtime_factory: F,
    _runtime: std::marker::PhantomData<fn() -> (A, R)>,
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
            _runtime: std::marker::PhantomData,
        }
    }
}

impl<A, R, F> QemuNodeRealizationLauncher for QemuWarmRestoreNodeLauncher<A, R, F>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
    F: FnMut(&Configuration) -> QemuNodeFactoryRuntime<A, R>,
{
    type Node = QemuNode;

    fn launch_restored_node(
        &mut self,
        config: &Configuration,
        restore: QemuNodeRestorePlan<'_>,
    ) -> Result<Self::Node, QemuVmRealizationError> {
        let runtime = (self.runtime_factory)(config);
        spawn_setup_and_restore_qemu_node(
            &self.command,
            &self.run_directory,
            self.region_config,
            self.slot_index,
            restore,
            runtime,
            // Diskless warm restore issues no host-serviced device I/O during
            // priming; a block-capable caller supplies a servicing closure here.
            |_current_icount| {},
        )
        .map_err(warm_restore_error)
    }
}

/// Realization executor backed by one active QEMU node at a time.
pub struct QemuNodeRealizationExecutor<L>
where
    L: QemuNodeRealizationLauncher,
{
    node: NodeId,
    launcher: L,
    active_node: Option<L::Node>,
}

impl<L> QemuNodeRealizationExecutor<L>
where
    L: QemuNodeRealizationLauncher,
{
    /// Creates a node realization executor for `node`.
    #[must_use]
    pub fn new(node: NodeId, launcher: L) -> Self {
        Self {
            node,
            launcher,
            active_node: None,
        }
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

    fn launch_and_install(
        &mut self,
        config: &Configuration,
        restore: QemuNodeRestorePlan<'_>,
        operation: &'static str,
    ) -> Result<ContentHash, QemuVmRealizationError> {
        let mut node = self.launcher.launch_restored_node(config, restore)?;
        let runtime_id = node
            .fingerprint()
            .map(|fingerprint| fingerprint.hash)
            .map_err(|source| node_backend_error(operation, source))?;
        self.shutdown_active_node_for("replace active realized QEMU node")?;
        self.active_node = Some(node);
        Ok(runtime_id)
    }

    fn active_node_mut(
        &mut self,
        operation: &'static str,
    ) -> Result<&mut L::Node, QemuVmRealizationError> {
        self.active_node
            .as_mut()
            .ok_or_else(|| QemuVmRealizationError::Executor {
                operation,
                message: String::from("no QEMU node has been restored"),
            })
    }

    fn shutdown_active_node_for(
        &mut self,
        operation: &'static str,
    ) -> Result<(), QemuVmRealizationError> {
        if let Some(mut node) = self.active_node.take() {
            node.shutdown()
                .map_err(|source| node_backend_error(operation, source))?;
        }
        Ok(())
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
        let restore = QemuNodeRestorePlan::new(&snapshot.checkpoint, authorization, admission);
        let runtime_id =
            self.launch_and_install(config, restore, "load exact QEMU node snapshot")?;
        let runtime = runtime_from_checkpoint_material(config, &snapshot.checkpoint, runtime_id)?;
        validate_runtime_matches_admission(&runtime, admission)?;
        Ok(runtime)
    }

    fn load_exact_snapshot_for_replay_oracle_probe(
        &mut self,
        _config: &Configuration,
        _snapshot: &QemuVmSnapshot,
        _authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        Err(QemuVmRealizationError::Executor {
            operation: "load exact QEMU node snapshot for replay oracle",
            message: String::from(
                "real-node replay-oracle probes require a probe-only restore admission path",
            ),
        })
    }

    fn load_baked_genesis(
        &mut self,
        config: &Configuration,
        admission: QemuBakedGenesisRestoreAdmission<'_>,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        let checkpoint = admission.checkpoint();
        let restore = QemuNodeRestorePlan::baked_genesis(admission);
        let runtime_id = self.launch_and_install(config, restore, "load baked QEMU genesis")?;
        Ok(runtime_from_scheduled_checkpoint_material(
            config, checkpoint, runtime_id,
        ))
    }

    fn replay_one_quantum(
        &mut self,
        runtime: RuntimeState,
        request: QemuVmReplayRequest,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        let horizon = replay_horizon_from_runtime(&runtime)?;
        let node_id = self.node.clone();
        let node = self.active_node_mut("replay one QEMU node quantum")?;
        match node
            .advance_to_horizon(horizon)
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
        let runtime_id = node
            .fingerprint()
            .map(|fingerprint| fingerprint.hash)
            .map_err(|source| node_backend_error("sample QEMU node replay fingerprint", source))?;
        let current_icount = node
            .current_icount()
            .map_err(|source| node_backend_error("sample QEMU node replay icount", source))?;

        Ok(runtime_from_live_replay(
            runtime,
            request,
            node_id,
            current_icount,
            runtime_id,
        ))
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
        event_log: runtime.event_log,
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

fn node_backend_error(operation: &'static str, source: BackendError) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation,
        message: source.to_string(),
    }
}

#[cfg(test)]
mod tests;
