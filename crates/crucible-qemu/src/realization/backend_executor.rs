//! Backend-backed executor for QEMU VM realization.

use crucible::{
    AdvanceOutcome, Backend, BackendError, Checkpoint, Configuration, ContentHash, EventLogOffset,
    ExecutionHorizon, Icount, RuntimeState, SchedulerState,
};

use super::{
    QemuBakedGenesisRestoreAdmission, QemuVmRealizationError, QemuVmRealizationExecutor,
    QemuVmReplayRequest, QemuVmSnapshot, validate_checkpoint_matches_config,
    validate_runtime_matches_admission,
};
use crate::{QemuLoadvmCommandAuthorization, QemuLoadvmRealizationAdmission};

/// Adapts a concrete backend into the QEMU realization executor contract.
pub struct QemuBackendRealizationExecutor<B> {
    backend: B,
}

impl<B> QemuBackendRealizationExecutor<B> {
    /// Builds a realization executor over an owned backend.
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }
}

impl<B> QemuVmRealizationExecutor for QemuBackendRealizationExecutor<B>
where
    B: Backend,
{
    fn load_exact_snapshot(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        _authorization: QemuLoadvmCommandAuthorization,
        admission: QemuLoadvmRealizationAdmission,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        if snapshot.is_live_capture() {
            return Err(QemuVmRealizationError::Executor {
                operation: "restore exact snapshot through model backend",
                message: String::from(
                    "model backends cannot restore paired production QEMU snapshots",
                ),
            });
        }
        self.backend
            .restore(&snapshot.checkpoint)
            .map_err(|source| backend_executor_error("restore model checkpoint", source))?;
        let runtime_id = self.backend_runtime_id("sample model checkpoint fingerprint")?;
        let runtime = exact_runtime_from_checkpoint(config, &snapshot.checkpoint, runtime_id)?;
        validate_runtime_matches_admission(&runtime, admission)?;
        Ok(runtime)
    }

    fn load_exact_snapshot_for_replay_oracle_probe(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        _authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        if snapshot.is_live_capture() {
            return Err(QemuVmRealizationError::Executor {
                operation: "probe exact snapshot through model backend",
                message: String::from(
                    "model backends cannot probe paired production QEMU snapshots",
                ),
            });
        }
        self.backend
            .restore(&snapshot.checkpoint)
            .map_err(|source| backend_executor_error("restore model checkpoint probe", source))?;
        let runtime_id = self.backend_runtime_id("sample model checkpoint probe fingerprint")?;
        exact_runtime_from_checkpoint(config, &snapshot.checkpoint, runtime_id)
    }

    fn load_baked_genesis(
        &mut self,
        config: &Configuration,
        admission: QemuBakedGenesisRestoreAdmission<'_>,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        let snapshot = admission.snapshot();
        self.backend
            .restore(&snapshot.checkpoint)
            .map_err(|source| backend_executor_error("restore baked genesis", source))?;
        let runtime_id = self.backend_runtime_id("sample baked genesis fingerprint")?;
        Ok(runtime_from_scheduled_backend_material(
            config,
            &snapshot.checkpoint,
            runtime_id,
            EventLogOffset::default(),
        ))
    }

    fn replay_one_quantum(
        &mut self,
        runtime: RuntimeState,
        request: QemuVmReplayRequest,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        let horizon = replay_horizon_from_runtime(&runtime)?;
        let event_log = runtime.event_log;
        match self
            .backend
            .advance_to_horizon(horizon)
            .map_err(|source| backend_executor_error("advance replay quantum", source))?
        {
            AdvanceOutcome::ReachedHorizon => {}
            AdvanceOutcome::Paused { at } => {
                return Err(QemuVmRealizationError::Executor {
                    operation: "advance replay quantum",
                    message: format!(
                        "backend paused at {} before replay horizon {}",
                        at.retired, horizon.icount.retired
                    ),
                });
            }
        }

        let checkpoint = self
            .backend
            .snapshot()
            .map_err(|source| backend_executor_error("snapshot replay quantum", source))?;
        let runtime_id = self.backend_runtime_id("sample replay quantum fingerprint")?;
        Ok(runtime_from_scheduled_backend_material(
            &request.to,
            &checkpoint,
            runtime_id,
            event_log,
        ))
    }
}

impl<B> QemuBackendRealizationExecutor<B>
where
    B: Backend,
{
    fn backend_runtime_id(
        &mut self,
        operation: &'static str,
    ) -> Result<ContentHash, QemuVmRealizationError> {
        self.backend
            .fingerprint()
            .map(|fingerprint| fingerprint.hash)
            .map_err(|source| backend_executor_error(operation, source))
    }
}

fn exact_runtime_from_checkpoint(
    config: &Configuration,
    checkpoint: &Checkpoint,
    runtime_id: ContentHash,
) -> Result<RuntimeState, QemuVmRealizationError> {
    validate_checkpoint_matches_config(checkpoint, config, "backend realization")?;
    Ok(runtime_from_checkpoint_material(
        config, checkpoint, runtime_id,
    ))
}

fn runtime_from_checkpoint_material(
    config: &Configuration,
    checkpoint: &Checkpoint,
    runtime_id: ContentHash,
) -> RuntimeState {
    let scheduler = checkpoint
        .state
        .as_ref()
        .map(|state| state.scheduler.clone())
        .unwrap_or_else(|| SchedulerState::from_schedule(&config.schedule));
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

fn runtime_from_scheduled_backend_material(
    config: &Configuration,
    checkpoint: &Checkpoint,
    runtime_id: ContentHash,
    event_log: EventLogOffset,
) -> RuntimeState {
    RuntimeState {
        id: runtime_id,
        configuration: config.id(),
        node_blobs: checkpoint.node_blobs.clone(),
        node_icounts: checkpoint.node_icounts.clone(),
        scheduler: SchedulerState::from_schedule(&config.schedule),
        event_log,
    }
}

fn replay_horizon_from_runtime(
    runtime: &RuntimeState,
) -> Result<ExecutionHorizon, QemuVmRealizationError> {
    let current = runtime
        .node_icounts
        .values()
        .map(|icount| icount.retired)
        .max()
        .ok_or_else(|| QemuVmRealizationError::Executor {
            operation: "derive replay horizon",
            message: String::from("runtime has no restored node instruction counts"),
        })?;
    let retired = current
        .checked_add(1)
        .ok_or_else(|| QemuVmRealizationError::Executor {
            operation: "derive replay horizon",
            message: String::from("current instruction count is already at u64::MAX"),
        })?;
    Ok(ExecutionHorizon {
        icount: Icount { retired },
    })
}

fn backend_executor_error(operation: &'static str, source: BackendError) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation,
        message: source.to_string(),
    }
}

#[cfg(test)]
#[path = "backend_executor_test.rs"]
mod tests;
