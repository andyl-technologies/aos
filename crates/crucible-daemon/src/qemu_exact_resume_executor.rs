//! Concrete guarded QEMU executor for durable attempt-checkpoint resume.
//!
//! This adapter owns the immutable exact-checkpoint store and the static QEMU
//! launch recipe. For each resumed attempt it obtains the one descriptor-pinned
//! run directory from that attempt's resource guard, streams and authenticates
//! the exact root into the retained VMState inode, constructs a root-bound
//! launcher, and installs the resulting real node behind the narrow live
//! backend facade. Fresh exact-cache and thin-replay starts remain a separate
//! composition because they require independently provisioned source images.

use crucible::{Configuration, NodeId, SchedulerSendAuthorizer};
use crucible_campaign::ExactCheckpointId;
use crucible_qemu::{
    QemuBakedGenesisRestoreAdmission, QemuCapturedVmState, QemuExactRootWarmRestoreNodeLauncher,
    QemuHostIoRuntime, QemuLaunchCommand, QemuLiveAttemptBackend, QemuLoadvmCommandAuthorization,
    QemuLoadvmRealizationAdmission, QemuNodeFactoryRuntime, QemuNodeRealizationExecutor,
    QemuVmLiveRealizationExecutor, QemuVmRealizationError, QemuVmRealizationExecutor,
    QemuVmReplayRequest, QemuVmSnapshot,
};
use crucible_shmem::RegionConfig;

use crate::{
    ExactCheckpointRestoreError, ExactCheckpointResumeError, ExactCheckpointStore,
    QemuAttemptProcessResourceGuard, QemuExactCheckpointRealization,
    QemuGuardedLiveRealizationExecutor, materialize_attempt_exact_checkpoint,
    realize_materialized_attempt_checkpoint_guarded,
};

/// Real-node executor for one durable exact-checkpoint resume at a time.
///
/// The value is reusable after a session has attested reap and released its
/// guard. It deliberately rejects fresh exact-cache, replay-oracle probe,
/// baked-genesis, and thin-replay entry points: those paths require a second,
/// independently provisioned VMState authority and are composed separately.
pub struct QemuExactResumeLiveRealizationExecutor<A, R, F>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
    F: FnMut(&Configuration) -> QemuNodeFactoryRuntime<A, R> + Clone,
{
    checkpoints: ExactCheckpointStore,
    command: QemuLaunchCommand,
    node: NodeId,
    region_config: RegionConfig,
    slot_index: u32,
    runtime_factory: F,
    executor: Option<QemuNodeRealizationExecutor<QemuExactRootWarmRestoreNodeLauncher<A, R, F>>>,
}

impl<A, R, F> QemuExactResumeLiveRealizationExecutor<A, R, F>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
    F: FnMut(&Configuration) -> QemuNodeFactoryRuntime<A, R> + Clone,
{
    /// Creates a reusable exact-resume executor from immutable launch policy.
    #[must_use]
    pub const fn new(
        checkpoints: ExactCheckpointStore,
        command: QemuLaunchCommand,
        node: NodeId,
        region_config: RegionConfig,
        slot_index: u32,
        runtime_factory: F,
    ) -> Self {
        Self {
            checkpoints,
            command,
            node,
            region_config,
            slot_index,
            runtime_factory,
            executor: None,
        }
    }

    /// Returns the immutable exact-checkpoint store.
    #[must_use]
    pub const fn checkpoints(&self) -> &ExactCheckpointStore {
        &self.checkpoints
    }

    /// Returns the validated static QEMU launch command.
    #[must_use]
    pub const fn command(&self) -> &QemuLaunchCommand {
        &self.command
    }

    fn executor_mut(
        &mut self,
        operation: &'static str,
    ) -> Result<
        &mut QemuNodeRealizationExecutor<QemuExactRootWarmRestoreNodeLauncher<A, R, F>>,
        QemuVmRealizationError,
    > {
        self.executor
            .as_mut()
            .ok_or_else(|| QemuVmRealizationError::Executor {
                operation,
                message: String::from("no exact-checkpoint QEMU executor is installed"),
            })
    }
}

impl<A, R, F> QemuVmRealizationExecutor for QemuExactResumeLiveRealizationExecutor<A, R, F>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
    F: FnMut(&Configuration) -> QemuNodeFactoryRuntime<A, R> + Clone,
{
    fn load_exact_snapshot(
        &mut self,
        _config: &Configuration,
        _snapshot: &QemuVmSnapshot,
        _authorization: QemuLoadvmCommandAuthorization,
        _admission: QemuLoadvmRealizationAdmission,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
        Err(fresh_path_rejected("load an ordinary exact snapshot"))
    }

    fn load_exact_snapshot_for_replay_oracle_probe(
        &mut self,
        _config: &Configuration,
        _snapshot: &QemuVmSnapshot,
        _authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
        Err(fresh_path_rejected("load a replay-oracle probe"))
    }

    fn load_baked_genesis(
        &mut self,
        _config: &Configuration,
        _admission: QemuBakedGenesisRestoreAdmission<'_>,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
        Err(fresh_path_rejected("load baked genesis"))
    }

    fn replay_one_quantum(
        &mut self,
        _runtime: crucible::RuntimeState,
        _request: QemuVmReplayRequest,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
        Err(unguarded_path_rejected("replay an exact-resume quantum"))
    }
}

impl<A, R, F> QemuVmLiveRealizationExecutor for QemuExactResumeLiveRealizationExecutor<A, R, F>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
    F: FnMut(&Configuration) -> QemuNodeFactoryRuntime<A, R> + Clone,
{
    fn live_backend_is_active(&self) -> bool {
        self.executor
            .as_ref()
            .is_some_and(QemuVmLiveRealizationExecutor::live_backend_is_active)
    }

    fn live_backend_mut(
        &mut self,
    ) -> Result<&mut dyn QemuLiveAttemptBackend, QemuVmRealizationError> {
        self.executor_mut("borrow exact-resume QEMU backend")?
            .live_backend_mut()
    }

    fn seal_live_observation_boundary(&mut self) -> Result<bool, QemuVmRealizationError> {
        self.executor_mut("seal exact-resume observation boundary")?
            .seal_live_observation_boundary()
    }

    fn capture_live_exact_snapshot(
        &mut self,
        checkpoint: crucible::Checkpoint,
    ) -> Result<QemuVmSnapshot, QemuVmRealizationError> {
        self.executor_mut("capture exact-resume QEMU snapshot")?
            .capture_live_exact_snapshot(checkpoint)
    }

    fn shutdown_live_backend(
        &mut self,
    ) -> Result<crucible_qemu::QemuLiveBackendShutdown, QemuVmRealizationError> {
        match self.executor.as_mut() {
            Some(executor) => executor.shutdown_live_backend(),
            None => Ok(crucible_qemu::QemuLiveBackendShutdown::unchanged()),
        }
    }
}

impl<A, R, F, G> QemuGuardedLiveRealizationExecutor<G>
    for QemuExactResumeLiveRealizationExecutor<A, R, F>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
    F: FnMut(&Configuration) -> QemuNodeFactoryRuntime<A, R> + Clone,
    G: QemuAttemptProcessResourceGuard,
{
    fn resume_exact_checkpoint_guarded(
        &mut self,
        guard: &mut G,
        checkpoint: ExactCheckpointId,
        initial: &Configuration,
        post_selection: Option<&Configuration>,
    ) -> Result<QemuExactCheckpointRealization, QemuVmRealizationError> {
        if self.live_backend_is_active() {
            return Err(QemuVmRealizationError::Executor {
                operation: "resume exact attempt checkpoint",
                message: String::from("a prior exact-resume backend is still active"),
            });
        }

        guard.check_operational_boundary()?;
        let mut run_directory =
            guard.prepare_generation_run_directory(self.command.resource_requirements())?;
        let materialized = materialize_attempt_exact_checkpoint(
            &self.checkpoints,
            checkpoint,
            initial,
            post_selection,
            &mut run_directory,
            guard.cancellation(),
        )
        .map_err(map_materialization_error)?;
        let configuration = if materialized.snapshot().checkpoint().configuration == initial.id() {
            initial
        } else {
            post_selection.ok_or_else(|| QemuVmRealizationError::InvalidCheckpoint {
                role: "attempt exact resume",
                message: String::from("checkpoint names no legal attempt configuration"),
            })?
        };
        let launcher = QemuExactRootWarmRestoreNodeLauncher::new(
            self.command.clone(),
            run_directory,
            materialized.vmstate_binding(),
            materialized.snapshot(),
            self.region_config,
            self.slot_index,
            self.runtime_factory.clone(),
        )
        .map_err(map_spawn_error)?;
        self.executor = Some(QemuNodeRealizationExecutor::new(
            self.node.clone(),
            launcher,
        ));

        let executor = self.executor_mut("resume exact attempt checkpoint")?;
        realize_materialized_attempt_checkpoint_guarded(
            executor,
            guard,
            configuration,
            &materialized,
        )
        .map_err(map_resume_error)
    }

    fn load_exact_snapshot_guarded(
        &mut self,
        _guard: &mut G,
        _config: &Configuration,
        _snapshot: &QemuVmSnapshot,
        _authorization: QemuLoadvmCommandAuthorization,
        _admission: QemuLoadvmRealizationAdmission,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
        Err(fresh_path_rejected("load an ordinary exact snapshot"))
    }

    fn load_exact_snapshot_for_replay_oracle_probe_guarded(
        &mut self,
        _guard: &mut G,
        _config: &Configuration,
        _snapshot: &QemuVmSnapshot,
        _authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
        Err(fresh_path_rejected("load a replay-oracle probe"))
    }

    fn load_baked_genesis_guarded(
        &mut self,
        _guard: &mut G,
        _config: &Configuration,
        _admission: QemuBakedGenesisRestoreAdmission<'_>,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
        Err(fresh_path_rejected("load baked genesis"))
    }

    fn replay_one_quantum_guarded(
        &mut self,
        guard: &mut G,
        runtime: crucible::RuntimeState,
        request: QemuVmReplayRequest,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
        guard.check_operational_boundary()?;
        let result = self
            .executor_mut("replay exact-resume QEMU quantum")?
            .replay_materialized_one_quantum(runtime, request);
        guard.check_operational_boundary()?;
        result
    }

    fn capture_exact_checkpoint_artifact_guarded(
        &mut self,
        guard: &mut G,
        checkpoint: crucible::Checkpoint,
    ) -> Result<(QemuVmSnapshot, QemuCapturedVmState), QemuVmRealizationError> {
        guard.check_operational_boundary()?;
        let result = self
            .executor_mut("capture exact-resume checkpoint artifact")?
            .capture_exact_checkpoint_artifact(checkpoint);
        guard.check_operational_boundary()?;
        result
    }

    fn shutdown_live_backend_guarded(
        &mut self,
        guard: &mut G,
    ) -> Result<crucible_qemu::QemuLiveBackendShutdown, QemuVmRealizationError> {
        guard.check_operational_boundary()?;
        let result = self.shutdown_live_backend();
        guard.check_operational_boundary()?;
        result
    }

    fn reap_failed_realization_guarded(
        &mut self,
        guard: &mut G,
    ) -> Result<(), QemuVmRealizationError> {
        let Some(executor) = self.executor.as_mut() else {
            return Ok(());
        };
        let mut transferred = false;
        if let Some(child) = executor.take_failed_launch_child_for_quarantine() {
            guard.retain_failed_launch_child(child);
            transferred = true;
        }
        if let Some(child) = executor.take_active_direct_child_for_quarantine() {
            guard.retain_failed_launch_child(child);
            transferred = true;
        }
        if transferred {
            Err(QemuVmRealizationError::ReapQuarantined {
                operation: "reap failed exact-resume QEMU realization",
                message: String::from(
                    "direct-child authority was transferred to the attempt resource guard",
                ),
            })
        } else {
            Ok(())
        }
    }
}

fn fresh_path_rejected(operation: &'static str) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation,
        message: String::from(
            "the exact-resume executor does not own an independently provisioned fresh-start image",
        ),
    }
}

fn unguarded_path_rejected(operation: &'static str) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation,
        message: String::from("the concrete exact-resume executor requires an attempt guard"),
    }
}

fn map_materialization_error(error: ExactCheckpointRestoreError) -> QemuVmRealizationError {
    match error {
        ExactCheckpointRestoreError::Canceled => QemuVmRealizationError::Canceled {
            operation: "materialize exact attempt checkpoint",
        },
        ExactCheckpointRestoreError::Checkpoint(error) if error.is_retryable() => {
            QemuVmRealizationError::StoreUnavailable {
                operation: "materialize exact attempt checkpoint",
                message: error.to_string(),
            }
        }
        ExactCheckpointRestoreError::Checkpoint(error) => QemuVmRealizationError::Store {
            operation: "materialize exact attempt checkpoint",
            message: error.to_string(),
        },
        ExactCheckpointRestoreError::Spawn(error) => map_spawn_error(error),
        ExactCheckpointRestoreError::CheckpointConfigurationMismatch { .. }
        | ExactCheckpointRestoreError::MissingSchedulerContinuation { .. }
        | ExactCheckpointRestoreError::SchedulerConfigurationMismatch { .. }
        | ExactCheckpointRestoreError::MissingSelection { .. }
        | ExactCheckpointRestoreError::Selection(_) => QemuVmRealizationError::InvalidCheckpoint {
            role: "attempt exact resume",
            message: error.to_string(),
        },
    }
}

fn map_spawn_error(error: crucible_qemu::QemuSpawnError) -> QemuVmRealizationError {
    match error {
        crucible_qemu::QemuSpawnError::Io { .. } => QemuVmRealizationError::ExecutorUnavailable {
            operation: "prepare exact-resume QEMU launch",
            message: error.to_string(),
        },
        _ => QemuVmRealizationError::Executor {
            operation: "prepare exact-resume QEMU launch",
            message: error.to_string(),
        },
    }
}

fn map_resume_error(error: ExactCheckpointResumeError) -> QemuVmRealizationError {
    match error {
        ExactCheckpointResumeError::Canceled => QemuVmRealizationError::Canceled {
            operation: "resume exact attempt checkpoint",
        },
        ExactCheckpointResumeError::Realization(error) => error,
    }
}
