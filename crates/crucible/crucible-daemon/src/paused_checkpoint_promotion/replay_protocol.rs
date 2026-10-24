//! Keeps replay operations scoped to their actual retained native owner.
//!
//! Main-owned replay guards are opaque selectors. Borrowed contracts and failed
//! children stay within a scoped actual native guard; finite returned reports
//! retain the original role without allocating another diagnostic carrier.

use super::*;
use crate::AttemptWorkerFailure;
use crate::lifecycle_cleanup::{PreparedSourceFailure, PreparedSourceRefusal};
use crucible_host_resources::host_supervision::HostSupervisionError;

pub(crate) type FreshReplayFailure = AttemptWorkerFailure<
    crate::QemuFreshExecutionRunnerError<
        crate::QemuAttemptProductionVmLifecycleError,
        crate::QemuFreshModeledDriverError,
    >,
>;

#[derive(Debug, Error)]
pub(crate) enum ProductionReplayError {
    #[error(transparent)]
    Realization(#[from] QemuVmRealizationError),
    #[error(transparent)]
    Preparation(#[from] crate::QemuAttemptProductionVmLifecycleError),
    #[error(transparent)]
    Prepared(#[from] PreparedSourceFailure),
    #[error("replay admission refused: {first}; retained Main phase: {role}")]
    Admission {
        #[source]
        first: QemuVmRealizationError,
        role: PreparedSourceFailure,
    },
    #[error("replay transport refused: {failure}; independent acknowledgment: {acknowledgment:?}")]
    Transport {
        #[source]
        failure: PreparedSourceFailure,
        acknowledgment: Option<crate::lifecycle_cleanup::ServiceMainPreclaimError>,
    },
    #[error(transparent)]
    Launch(#[from] crucible_qemu_host::QemuLiveNodeStepGateError),
    #[error("original replay Restore admission refused: {first}; retained role: {role}")]
    OriginalAdmission {
        #[source]
        first: HostSupervisionError,
        role: PreparedSourceFailure,
    },
    #[error(
        "original replay Restore refused: {original}; comparison: {comparison:?}; node cleanup: {node_cleanup:?}"
    )]
    OriginalBoundary {
        original: HostSupervisionError,
        #[source]
        comparison: Option<QemuVmRealizationError>,
        node_cleanup: Option<QemuVmRealizationError>,
    },
    #[error("private replay execution failed: {first}; independent return: {cleanup:?}")]
    Execution {
        #[source]
        first: FreshReplayFailure,
        cleanup: Option<ProductionReplayCleanup>,
    },
    #[error(transparent)]
    Cleanup(#[from] ProductionReplayCleanup),
}

#[derive(Debug, Error)]
pub(crate) enum ProductionReplayCleanup {
    #[error(transparent)]
    Native(#[from] crate::QemuAttemptResourceGuardCleanupFailure),
    #[error(
        "same Main replay phase refused: {failure}; Restore completion: {post:?}; return observation: {progress:?}"
    )]
    Prepared {
        #[source]
        failure: PreparedSourceFailure,
        post: Option<HostSupervisionError>,
        progress: Option<PreparedSourceRefusal>,
    },
    #[error("replay returned with history: {body}; Restore completion: {post:?}")]
    Returned {
        #[source]
        body: crate::ProductionVmConstructionPostBody,
        post: Option<HostSupervisionError>,
    },
}

pub(crate) struct ProductionReplayBeginFailure {
    first: ProductionReplayError,
    selected: Option<SelectedExactCheckpointRoot>,
}

impl ProductionReplayBeginFailure {
    pub(crate) fn new(
        first: ProductionReplayError,
        selected: Option<SelectedExactCheckpointRoot>,
    ) -> Self {
        Self { first, selected }
    }

    pub(crate) fn into_parts(self) -> (ProductionReplayError, Option<SelectedExactCheckpointRoot>) {
        (self.first, self.selected)
    }
}

pub(crate) enum ReplayBoundaryRefusal {
    Original(crucible_host_resources::host_supervision::HostSupervisionError),
    Native(QemuVmRealizationError),
}

pub(crate) fn check_replay_boundary(
    original: Option<&crucible_host_resources::host_supervision::HostOperationGuard>,
    native: impl FnOnce() -> Result<(), QemuVmRealizationError>,
) -> Result<(), ReplayBoundaryRefusal> {
    if let Some(original) = original {
        original
            .wait_slice()
            .map_err(ReplayBoundaryRefusal::Original)?;
    }
    native().map_err(ReplayBoundaryRefusal::Native)
}

/// Factory for node-specific guarded production replay-oracle sessions.
///
/// The factory installs one aggregate attempt guard for the complete root
/// comparison, then constructs each node's executor and realization store under
/// that retained guard. The caller verifies every executor node, runs both
/// realization paths, and structurally finishes the aggregate guard once.
pub(crate) trait ProductionPausedCheckpointReplayFactory {
    /// Attempt resource owner retained until comparison cleanup.
    type Guard;
    /// The actual native guard remains inside its original retained owner.
    type NativeGuard: QemuAttemptProcessResourceGuard;

    fn guard_matches(
        &self,
        guard: &Self::Guard,
        resources: AttemptResourceLimits,
        cancellation: &ExecutionCancellation,
    ) -> bool;

    fn with_native_guard<T>(
        &mut self,
        guard: &mut Self::Guard,
        apply: impl FnOnce(
            &mut Self::NativeGuard,
            Option<&crucible_host_resources::host_supervision::HostOperationGuard>,
        ) -> T,
    ) -> Result<T, PreparedSourceFailure>;

    fn finish_replay(&mut self, guard: &mut Self::Guard) -> Result<(), ProductionReplayCleanup>;

    /// Binds authenticated durable semantic facts before any physical replay.
    fn configure_execution(
        &mut self,
        _basis: crate::qemu_baked_genesis::ProductionCheckpointReplayBasis,
    ) -> Result<(), QemuVmRealizationError> {
        Ok(())
    }

    /// Records one completely authenticated and physically cleaned node comparison.
    fn target_completed(&mut self, _guard: &mut Self::Guard) -> Result<(), ProductionReplayError> {
        Ok(())
    }

    /// Installs the single aggregate guard for one complete root comparison.
    ///
    /// # Errors
    ///
    /// Returns a failure that retains the selected root when no resource owner
    /// escaped and consumes it when cleanup required quarantine.
    fn begin_replay(
        &mut self,
        selected_checkpoint: SelectedExactCheckpointRoot,
        cancellation: &ExecutionCancellation,
        resources: AttemptResourceLimits,
    ) -> Result<Self::Guard, ProductionReplayBeginFailure>;

    /// Prepares one node-specific replay executor under the aggregate guard.
    ///
    /// # Errors
    ///
    /// Retains the actual admission, Original or native failure when either
    /// replay leg cannot be admitted under the retained guard.
    fn begin_target(
        &mut self,
        world: &World,
        configuration: &Configuration,
        target: ProductionVmReplayExactNodeRestoreAdmission,
        guard: &mut Self::Guard,
    ) -> Result<ProductionPausedCheckpointReplaySession, ProductionReplayError>;

    /// Reexecutes one savepoint attempt and returns its reached modeled boundary.
    ///
    /// # Errors
    ///
    /// Retains the actual execution and independent retirement failures when
    /// the attempt or its exact reached boundary cannot be collected.
    fn replay_savepoint_capture(
        &mut self,
        attempt: &CrucibleAttemptExecution,
        run_state_root: &Path,
        cancellation: &ExecutionCancellation,
        resources: AttemptResourceLimits,
    ) -> Result<crate::QemuSavepointReplayProof, ProductionReplayError>;

    /// Replays an ordinary attempt to a source checkpoint's exact boundary.
    ///
    /// # Errors
    ///
    /// Retains the actual execution and independent retirement failures when
    /// full-world replay cannot reproduce the target boundary or return its World.
    fn replay_checkpoint_boundary(
        &mut self,
        attempt: &CrucibleAttemptExecution,
        run_state_root: &Path,
        cancellation: &ExecutionCancellation,
        resources: AttemptResourceLimits,
        target: &crate::qemu_campaign_driver::QemuSelectedResumeBoundary,
    ) -> Result<crate::QemuSavepointReplayProof, ProductionReplayError>;
}
