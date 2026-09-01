//! Failures returned by the production loaded-QEMU plugin install gate.

use std::path::PathBuf;
use std::time::Duration;

use crucible::SchedulerError;
use crucible_shmem::{RegionLayoutError, SetupRegionMapError};
use thiserror::Error;

use crate::{
    LaunchProfileError, QemuHostPluginSetupError, QemuLaunchCommandError,
    QemuMappedQuantumShmemHotPathError, QemuNodeChannelError, QemuSpawnError,
    QemuWhiteboxSetupError,
};

/// Reports a failure in the production loaded-QEMU plugin install gate.
#[derive(Debug, Error)]
pub enum LivePluginInstallGateError {
    /// The requested horizon was zero.
    #[error("loaded-QEMU install horizon must be non-zero")]
    ZeroHorizon,
    /// Preparing the run directory failed.
    #[error("prepare install run directory `{path}` failed: {source}")]
    PrepareRunDirectory {
        /// Run directory that could not be prepared.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
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
    #[error("build install QEMU launch command failed: {source}")]
    LaunchCommand {
        /// Underlying command-construction error.
        source: QemuLaunchCommandError,
    },
    /// Live QEMU reported a missing or colliding white-box doorbell port.
    #[error("validate live QEMU white-box setup failed: {source}")]
    WhiteboxSetup {
        /// Underlying stopped-machine probe error.
        source: QemuWhiteboxSetupError,
    },
    /// The shared-memory layout was invalid.
    #[error("build install shared-memory layout failed: {source}")]
    RegionLayout {
        /// Underlying layout error.
        source: RegionLayoutError,
    },
    /// QEMU could not be spawned with the fixed inherited descriptors.
    #[error("spawn install loaded QEMU failed: {source}")]
    Spawn {
        /// Underlying spawn error.
        source: QemuSpawnError,
    },
    /// The live plugin setup handshake failed.
    #[error("complete install loaded-QEMU plugin setup failed: {source}")]
    HostSetup {
        /// Underlying setup error.
        source: QemuHostPluginSetupError,
    },
    /// The plugin replied `SetupAck` with a non-ready status.
    #[error("install plugin refused to become schedulable after SetupAck")]
    SetupAckNotReady,
    /// Mapping the completed shared-memory setup region failed.
    #[error("map install loaded-QEMU shared-memory region failed: {source}")]
    RegionMap {
        /// Underlying mapping error.
        source: SetupRegionMapError,
    },
    /// Binding the mapped hot path failed.
    #[error("bind install loaded-QEMU shared-memory hot path failed: {source}")]
    MappedHotPath {
        /// Underlying hot-path error.
        source: QemuMappedQuantumShmemHotPathError,
    },
    /// A live shared-memory or control-channel operation failed.
    #[error("install loaded-QEMU operation `{operation}` failed: {source}")]
    Channel {
        /// Gate operation being attempted.
        operation: &'static str,
        /// Underlying channel error.
        source: QemuNodeChannelError,
    },
    /// Appending drained plugin observations to the unified event log failed.
    #[error("append install loaded-QEMU observations to event log failed: {source}")]
    EventLog {
        /// Underlying scheduler event-log error.
        source: SchedulerError,
    },
    /// A causal plugin result arrived without seeded host configuration.
    #[error("live app-random result arrived without host configuration")]
    AppRandomNotConfigured,
    /// The plugin emitted a causal decision other than app-random.
    #[error("live plugin emitted unsupported causal decision `{decision}`")]
    UnsupportedCausalDecision {
        /// Debug representation of the rejected decision.
        decision: String,
    },
    /// The host recorder rejected the live app-random request.
    #[error("host app-random recorder rejected live decision: {message}")]
    AppRandomRecorder {
        /// Recorder diagnostic.
        message: String,
    },
    /// The live reply differed from the host's seeded reconstruction.
    #[error("live app-random value {actual} differs from seeded host value {expected}")]
    AppRandomValueMismatch {
        /// Value published by the production plugin.
        actual: u64,
        /// Value independently reconstructed by the host.
        expected: u64,
    },
    /// QEMU did not publish the requested icount before the host bound expired.
    #[error(
        "install loaded QEMU did not reach icount {horizon_icount} within {timeout:?}; last icount was {last_icount}"
    )]
    CompletionTimeout {
        /// Required exact boundary.
        horizon_icount: u64,
        /// Last observed QEMU icount.
        last_icount: u64,
        /// Host-side diagnostic timeout.
        timeout: Duration,
    },
    /// QEMU exited before publishing the requested exact boundary.
    #[error("install QEMU exited before reaching icount {horizon_icount}: {status}")]
    ChildExitBeforeBoundary {
        /// Required exact boundary.
        horizon_icount: u64,
        /// Exact platform exit-status diagnostic.
        status: String,
    },
    /// The digest worker did not publish the exact-boundary fingerprint in time.
    #[error(
        "install plugin did not publish the icount {icount} execution fingerprint within {timeout:?}: {last_error}"
    )]
    FingerprintTimeout {
        /// Exact boundary whose fingerprint was requested.
        icount: u64,
        /// Host-side diagnostic timeout.
        timeout: Duration,
        /// Last retryable shared-memory diagnostic.
        last_error: String,
    },
    /// QEMU exited before the digest worker published the boundary fingerprint.
    #[error("install QEMU exited before publishing the icount {icount} fingerprint: {status}")]
    ChildExitBeforeFingerprint {
        /// Exact boundary whose fingerprint was requested.
        icount: u64,
        /// Exact platform exit-status diagnostic.
        status: String,
    },
    /// A run crossed rather than stopped at the requested exact boundary.
    #[error("install loaded QEMU completed at icount {actual}, expected {expected}")]
    InexactBoundary {
        /// Required exact boundary.
        expected: u64,
        /// Published boundary.
        actual: u64,
    },
    /// The plugin did not publish `Done` after consuming control `Quit`.
    #[error("install plugin did not publish teardown Done within {timeout:?}")]
    PluginQuitTimeout {
        /// Host-side diagnostic timeout.
        timeout: Duration,
    },
    /// The QEMU child did not exit naturally after plugin teardown.
    #[error("install QEMU did not exit naturally within {timeout:?}")]
    ChildExitTimeout {
        /// Host-side diagnostic timeout.
        timeout: Duration,
    },
    /// Polling the QEMU child failed.
    #[error("poll install QEMU natural exit failed: {source}")]
    ChildWait {
        /// Underlying child wait error.
        source: crate::QemuShutdownTargetError,
    },
    /// QEMU exited naturally but reported failure or signal termination.
    #[error("install QEMU teardown exit was not clean: {status}")]
    ChildExitUnclean {
        /// Exact platform exit-status diagnostic.
        status: String,
    },
}
