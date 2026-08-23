//! Error type for the loaded-QEMU plugin quantum/idle time-authority gate.

use std::path::PathBuf;
use std::time::Duration;

use crucible_shmem::{RegionLayoutError, SetupRegionMapError};
use thiserror::Error;

use crate::{
    LaunchProfileError, QemuHostPluginSetupError, QemuLaunchCommandError,
    QemuMappedQuantumShmemHotPathError, QemuNodeChannelError, QemuSpawnError,
};

/// Failure returned by the production loaded-QEMU plugin quantum gate.
#[derive(Debug, Error)]
pub enum LivePluginQuantumGateError {
    /// The schedule used a zero ceiling step.
    #[error("quantum schedule ceiling step must be non-zero")]
    ZeroCeilingStep,
    /// Preparing the run directory failed.
    #[error("prepare quantum run directory `{path}` failed: {source}")]
    PrepareRunDirectory {
        /// Run directory that could not be prepared.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// The bounded scheduler-preemption adversary could not run or clean up.
    #[error("bounded scheduler-preemption adversary failed: {source}")]
    SchedulerPreemption {
        /// Underlying controller, signal, or watchdog error.
        source: crate::BoundedSchedulerPreemptionError,
    },
    /// The conservative deterministic launch profile was invalid.
    #[error("build deterministic launch profile failed: {source}")]
    LaunchProfile {
        /// Underlying launch-profile error.
        source: LaunchProfileError,
    },
    /// Writing the deterministic guest entropy seed failed.
    #[error("write guest entropy seed into `{path}` failed: {source}")]
    GuestEntropySeed {
        /// Run directory the seed could not be written into.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// The concrete QEMU launch command was invalid.
    #[error("build quantum QEMU launch command failed: {source}")]
    LaunchCommand {
        /// Underlying command-construction error.
        source: QemuLaunchCommandError,
    },
    /// The shared-memory layout was invalid.
    #[error("build quantum shared-memory layout failed: {source}")]
    RegionLayout {
        /// Underlying layout error.
        source: RegionLayoutError,
    },
    /// QEMU could not be spawned with the fixed inherited descriptors.
    #[error("spawn quantum loaded QEMU failed: {source}")]
    Spawn {
        /// Underlying spawn error.
        source: QemuSpawnError,
    },
    /// The live plugin setup handshake failed.
    #[error("complete quantum loaded-QEMU plugin setup failed: {source}")]
    HostSetup {
        /// Underlying setup error.
        source: QemuHostPluginSetupError,
    },
    /// The plugin replied `SetupAck` with a non-ready status.
    #[error("quantum plugin refused to become schedulable after SetupAck")]
    SetupAckNotReady,
    /// Mapping the completed shared-memory setup region failed.
    #[error("map quantum loaded-QEMU shared-memory region failed: {source}")]
    RegionMap {
        /// Underlying mapping error.
        source: SetupRegionMapError,
    },
    /// Binding the mapped hot path failed.
    #[error("bind quantum loaded-QEMU shared-memory hot path failed: {source}")]
    MappedHotPath {
        /// Underlying hot-path error.
        source: QemuMappedQuantumShmemHotPathError,
    },
    /// A live shared-memory or control-channel operation failed.
    #[error("quantum loaded-QEMU operation `{operation}` failed: {source}")]
    Channel {
        /// Gate operation being attempted.
        operation: &'static str,
        /// Underlying channel error.
        source: QemuNodeChannelError,
    },
    /// The guest never entered an idle wait before the boot search bound.
    #[error(
        "quantum guest never idled: ceiling reached {ceiling_icount} without an idle park (bound {max_search_icount})"
    )]
    GuestNeverIdled {
        /// Ceiling the search reached without observing an idle park.
        ceiling_icount: u64,
        /// Configured boot search bound.
        max_search_icount: u64,
    },
    /// A quantum did not publish a boundary before the host bound expired.
    #[error(
        "quantum did not reach a boundary at ceiling {ceiling_icount} within {timeout:?}; last snapshot was {last_snapshot:?}, next deadline was {last_deadline_icount:?}"
    )]
    QuantumTimeout {
        /// Ceiling the quantum was advancing toward.
        ceiling_icount: u64,
        /// Last coherent shared-memory node snapshot.
        last_snapshot: crucible_shmem::NodeSlotSnapshot,
        /// Last published next-deadline coordinate, when one was armed.
        last_deadline_icount: Option<u64>,
        /// Host-side diagnostic timeout.
        timeout: Duration,
    },
    /// The asynchronous fingerprint worker did not publish the requested boundary sample in time.
    #[error(
        "quantum fingerprint sample at icount {expected_icount} was not published within {timeout:?}"
    )]
    FingerprintSampleTimeout {
        /// Exact boundary whose fingerprint was requested.
        expected_icount: u64,
        /// Host-side diagnostic timeout.
        timeout: Duration,
    },
    /// The asynchronous fingerprint worker skipped past the requested boundary sample.
    #[error("quantum fingerprint sample advanced past icount {expected_icount} to {sample_icount}")]
    FingerprintSampleAdvanced {
        /// Exact boundary whose fingerprint was requested.
        expected_icount: u64,
        /// Later boundary published by the worker.
        sample_icount: u64,
    },
    /// QEMU exited before a quantum published its boundary.
    #[error("quantum QEMU exited before reaching a boundary at ceiling {ceiling_icount}: {status}")]
    ChildExitBeforeBoundary {
        /// Ceiling the quantum was advancing toward.
        ceiling_icount: u64,
        /// Exact platform exit-status diagnostic.
        status: String,
    },
    /// The idle-jump quantum did not advance past the idle onset.
    #[error("quantum idle-jump did not advance past idle onset {idle_onset_icount}")]
    IdleJumpDidNotAdvance {
        /// Idle onset the idle-jump quantum started from.
        idle_onset_icount: u64,
    },
    /// The second run diverged from the first, breaking determinism.
    #[error("quantum second run diverged from the first: {reason}")]
    SecondRunDiverged {
        /// Deterministic description of the divergence.
        reason: String,
    },
    /// Replaying the live host-observable schedule through `SimDouble` diverged.
    #[error("live plugin and SimDouble host-observable schedules diverged: {reason}")]
    SimDoubleScheduleMismatch {
        /// Deterministic description of the first rejected schedule property.
        reason: String,
    },
    /// The plugin did not publish `Done` after consuming control `Quit`.
    #[error("quantum plugin did not publish teardown Done within {timeout:?}")]
    PluginQuitTimeout {
        /// Host-side diagnostic timeout.
        timeout: Duration,
    },
    /// The QEMU child did not exit naturally after plugin teardown.
    #[error("quantum QEMU did not exit naturally within {timeout:?}")]
    ChildExitTimeout {
        /// Host-side diagnostic timeout.
        timeout: Duration,
    },
    /// Polling the QEMU child failed.
    #[error("poll quantum QEMU natural exit failed: {source}")]
    ChildWait {
        /// Underlying child wait error.
        source: crate::QemuShutdownTargetError,
    },
    /// QEMU exited naturally but reported failure or signal termination.
    #[error("quantum QEMU teardown exit was not clean: {status}")]
    ChildExitUnclean {
        /// Exact platform exit-status diagnostic.
        status: String,
    },
}

impl LivePluginQuantumGateError {
    /// Builds a [`LivePluginQuantumGateError::Channel`] for a named operation.
    pub(super) fn channel(operation: &'static str, source: QemuNodeChannelError) -> Self {
        Self::Channel { operation, source }
    }
}
