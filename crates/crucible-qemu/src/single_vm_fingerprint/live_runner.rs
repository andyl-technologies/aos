//! Production primitives for fresh, observation-only fingerprint launches.
//!
//! [`LiveRunnerConfig`] pins every immutable guest and tool input. [`LiveRunnerArtifacts`]
//! owns one fresh attempt directory, [`LiveRunnerQmpPoller`] observes QEMU through typed
//! QMP status and topology queries, and [`LiveObservationProcess`] owns bounded teardown.
//! This module deliberately does not implement divergence state dumps.

mod artifacts;
mod config;
mod process;
mod qmp_poll;
mod verified_inputs;

pub use artifacts::{LiveRunnerArtifactRoot, LiveRunnerArtifacts, LiveRunnerArtifactsError};
pub use config::{
    LiveRunnerConfig, LiveRunnerConfigError, LiveRunnerImmutableInputs, LiveRunnerLaunchFields,
    LiveRunnerLaunchKind, LiveRunnerLaunchSpec,
};
pub use process::{
    LiveObservationAttempt, LiveObservationProcess, LiveObservationProcessError,
    LiveObservationShutdown, LiveObservationShutdownPolicy, spawn_live_observation_process,
};
pub use qmp_poll::{
    LiveRunnerQmpConnector, LiveRunnerQmpObservation, LiveRunnerQmpPollError,
    LiveRunnerQmpPollPolicy, LiveRunnerQmpPoller, LiveRunnerQmpSession, LiveRunnerSleeper,
    ThreadLiveRunnerSleeper, TypedLiveRunnerQmpConnector,
};
pub use verified_inputs::{
    VerifiedGuestImageDigests, VerifiedLiveRunInputs, VerifiedLiveRunInputsError,
};
