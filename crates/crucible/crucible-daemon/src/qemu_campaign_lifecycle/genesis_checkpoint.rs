//! Exact checkpoint capture at a scenario's fresh genesis boundary.
//!
//! A genesis candidate is captured from the ordinary production lifecycle with
//! no modeled quantum, through the same portable checkpoint path attempts use.
//! The lifecycle is always torn down before the candidate is returned, and a
//! teardown failure takes precedence over any earlier capture result.

use super::*;

/// Failure before a fresh genesis checkpoint candidate reached teardown.
#[derive(Debug, Error)]
pub enum QemuFreshGenesisCheckpointCaptureFailure {
    /// The freshly launched lifecycle was not at an exact checkpoint boundary.
    #[error("fresh genesis lifecycle is not checkpoint ready")]
    NotCheckpointReady,
    /// Exact checkpoint capture failed at the authenticated genesis boundary.
    #[error("capture fresh genesis checkpoint: {0}")]
    Capture(#[source] SchedulerError),
    /// Immutable replay launch profiles could not be copied from the lifecycle.
    #[error("capture fresh genesis replay launch profiles: {0}")]
    LaunchProfiles(#[source] SchedulerError),
    /// The capture named a scenario or configuration other than exact genesis.
    #[error("fresh genesis checkpoint capture returned a foreign semantic basis")]
    BasisMismatch,
}

/// Exact native capture and immutable launch basis produced at fresh genesis.
#[derive(Debug)]
pub struct QemuFreshGenesisCheckpointCandidate {
    capture: CapturedAttemptCheckpoint,
    launch_profiles: Vec<ProductionVmNodeReplayLaunchProfile>,
}

impl QemuFreshGenesisCheckpointCandidate {
    /// Returns the exact captured scenario identity.
    #[must_use]
    pub fn scenario(&self) -> ContentHash {
        self.capture.scenario()
    }

    /// Returns the exact captured genesis configuration identity.
    #[must_use]
    pub fn configuration(&self) -> ContentHash {
        self.capture.configuration()
    }

    /// Returns immutable replay profiles in World node order.
    #[must_use]
    pub fn launch_profiles(&self) -> &[ProductionVmNodeReplayLaunchProfile] {
        &self.launch_profiles
    }

    /// Consumes the candidate into its native capture and immutable profiles.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CapturedAttemptCheckpoint,
        Vec<ProductionVmNodeReplayLaunchProfile>,
    ) {
        (self.capture, self.launch_profiles)
    }
}

/// Failure while producing one independently captured genesis checkpoint candidate.
#[derive(Debug, Error)]
pub enum QemuFreshGenesisCheckpointError<E> {
    /// Fresh lifecycle construction failed with its original retry class.
    #[error("start fresh genesis checkpoint lifecycle: {0}")]
    Start(#[source] AttemptWorkerFailure<E>),
    /// Capture failed after lifecycle construction and teardown succeeded.
    #[error(transparent)]
    Capture(#[from] QemuFreshGenesisCheckpointCaptureFailure),
    /// Teardown failed and therefore retains precedence over an earlier result.
    #[error("tear down fresh genesis checkpoint lifecycle: {cleanup}")]
    Cleanup {
        /// Earlier capture failure, when teardown followed another failure.
        prior: Option<Box<QemuFreshGenesisCheckpointCaptureFailure>>,
        /// Mandatory lifecycle teardown failure.
        #[source]
        cleanup: SchedulerError,
    },
}

/// Captures a fresh exact checkpoint at the scenario's genesis ready boundary.
///
/// This is the QEMU-backed bootstrap primitive for a future authenticated baked-
/// genesis catalog. It starts the ordinary production lifecycle at exact
/// genesis, performs no modeled quantum, captures through the same portable
/// checkpoint path used by attempts, and always tears the lifecycle down before
/// returning. The returned value remains only a candidate: a catalog owner must
/// require the current version-nine production closure and authenticate its
/// complete semantic snapshot catalog before replay validation.
///
/// # Errors
///
/// Returns [`QemuFreshGenesisCheckpointError`] when guarded lifecycle startup
/// fails, genesis is not checkpoint ready, capture returns a foreign basis, or
/// mandatory teardown cannot be attested. Teardown failure takes precedence
/// and retains any earlier capture diagnostic.
pub(crate) fn capture_fresh_genesis_checkpoint_candidate<F>(
    factory: &mut F,
    source: &ScenarioDefForm,
    context: &AttemptExecutionContext,
) -> Result<QemuFreshGenesisCheckpointCandidate, QemuFreshGenesisCheckpointError<F::Error>>
where
    F: QemuFreshAttemptLifecycleFactory,
{
    let scenario = source.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let signal_fault_replay = crucible_engine::SignalFaultCampaignReplayPlan::empty(genesis.clone());
    let mut lifecycle = factory
        .start_fresh_lifecycle(&scenario, source, &genesis, &signal_fault_replay, context)
        .map_err(QemuFreshGenesisCheckpointError::Start)?;

    let captured = match lifecycle.exact_checkpoint_ready() {
        Ok(true) => lifecycle
            .capture_attempt_checkpoint(context)
            .map_err(QemuFreshGenesisCheckpointCaptureFailure::Capture)
            .and_then(|capture| {
                if capture.scenario() != scenario.id() || capture.configuration() != genesis.id() {
                    return Err(QemuFreshGenesisCheckpointCaptureFailure::BasisMismatch);
                }
                let launch_profiles = lifecycle
                    .replay_launch_profiles()
                    .map_err(QemuFreshGenesisCheckpointCaptureFailure::LaunchProfiles)?;
                Ok(QemuFreshGenesisCheckpointCandidate {
                    capture,
                    launch_profiles,
                })
            }),
        Ok(false) => Err(QemuFreshGenesisCheckpointCaptureFailure::NotCheckpointReady),
        Err(error) => Err(QemuFreshGenesisCheckpointCaptureFailure::Capture(error)),
    };
    let cleanup = lifecycle.shutdown();

    match (captured, cleanup) {
        (Ok(capture), Ok(_final_events)) => Ok(capture),
        (Err(error), Ok(_final_events)) => Err(error.into()),
        (Ok(_capture), Err(cleanup)) => Err(QemuFreshGenesisCheckpointError::Cleanup {
            prior: None,
            cleanup,
        }),
        (Err(prior), Err(cleanup)) => Err(QemuFreshGenesisCheckpointError::Cleanup {
            prior: Some(Box::new(prior)),
            cleanup,
        }),
    }
}
