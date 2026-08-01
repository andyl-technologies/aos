//! Typed failures for the certifying live 9p-I/O gate.

use std::path::PathBuf;

use thiserror::Error;

use super::QemuLive9pIoServicerError;
use crate::{
    LaunchProfileError, QemuHostPluginSetupError, QemuLaunchCommandError,
    QemuMappedQuantumShmemHotPathError, QemuNodeChannelError, QmpError,
};

/// Error returned by the certifying live 9p-I/O gate.
#[derive(Debug, Error)]
pub enum QemuLive9pIoGateError {
    /// The run subdirectory could not be created.
    #[error("prepare run directory {path} failed")]
    PrepareRunDirectory {
        /// Run subdirectory path.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The deterministic launch profile could not be derived.
    #[error("derive deterministic launch profile failed")]
    LaunchProfile {
        /// Underlying launch-profile error.
        source: LaunchProfileError,
    },
    /// The guest entropy seed file could not be written.
    #[error("write guest entropy seed under {path} failed")]
    GuestEntropySeed {
        /// Run subdirectory path.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The QEMU launch command could not be built.
    #[error("build QEMU launch command failed")]
    LaunchCommand {
        /// Underlying launch-command error.
        source: QemuLaunchCommandError,
    },
    /// The shared-memory region layout could not be computed.
    #[error("compute shared-memory region layout failed")]
    RegionLayout {
        /// Underlying region-layout error.
        source: crucible_shmem::RegionLayoutError,
    },
    /// QEMU could not be spawned with the negotiated descriptors.
    #[error("spawn QEMU child failed")]
    Spawn {
        /// Underlying spawn error.
        source: crate::QemuSpawnError,
    },
    /// The plugin setup handshake failed.
    #[error("complete QEMU plugin setup handshake failed")]
    HostSetup {
        /// Underlying host-setup error.
        source: QemuHostPluginSetupError,
    },
    /// The plugin setup acknowledgement did not permit scheduling.
    #[error("plugin setup acknowledgement did not permit scheduling")]
    SetupAckNotReady,
    /// The first no-wake quantum did not release the plugin boot barrier.
    #[error("9p gate priming quantum did not reach its ceiling: {advance}")]
    PrimeDidNotReach {
        /// Debug rendering of the priming outcome.
        advance: String,
    },
    /// QEMU's main loop did not complete the post-prime QMP handshake.
    #[error("connect post-prime QMP channel failed")]
    QmpConnect {
        /// Typed QMP failure.
        #[source]
        source: QmpError,
    },
    /// QMP reported that the post-prime VM was not running.
    #[error("post-prime QMP status was not running: {status}")]
    QmpNotRunning {
        /// Typed run-state kind.
        status: String,
    },
    /// The 9p-I/O servicer could not be built or serviced.
    #[error("9p-I/O servicer failed")]
    NinepServicer {
        /// Underlying 9p-servicer error.
        source: QemuLive9pIoServicerError,
    },
    /// The drive hot path could not map the shared-memory region.
    #[error("map drive shared-memory region failed")]
    DriveRegionMap {
        /// Underlying setup-region mapping error.
        source: crucible_shmem::SetupRegionMapError,
    },
    /// The drive mapped hot-path adapter could not bind the region.
    #[error("bind drive mapped hot path failed")]
    DriveHotPath {
        /// Underlying mapped hot-path binding error.
        source: QemuMappedQuantumShmemHotPathError,
    },
    /// A drive quantum boundary could not be published.
    #[error("{operation} failed")]
    Drive {
        /// Drive operation that failed.
        operation: &'static str,
        /// Underlying shared-memory channel error.
        source: QemuNodeChannelError,
    },
    /// Waiting on the child's natural exit failed during the drive.
    #[error("wait on QEMU child exit failed")]
    ChildWait {
        /// Underlying child-wait error.
        source: crate::QemuShutdownTargetError,
    },
    /// The second run diverged from the reference run.
    #[error("second run diverged from the reference run: {reason}")]
    SecondRunDiverged {
        /// Human-readable divergence detail.
        reason: String,
    },
    /// A sim leg did not prove its required real-I/O behavior.
    #[error(
        "{run} sim leg failed certification: {reason}; \
         advance={advance}; diagnostics={diagnostics}"
    )]
    CertificationFailed {
        /// Stable name of the failed sim leg.
        run: &'static str,
        /// Human-readable missing certification property.
        reason: &'static str,
        /// Debug rendering of the observed advance outcome.
        advance: String,
        /// Debug rendering of the live 9p observations.
        diagnostics: String,
    },
    /// The TCG control leg never observed the guest issue a 9p op.
    #[error("TCG control leg did not observe the guest issue a 9p op (no msize warning)")]
    ControlDidNotIssue9p,
    /// The TCG control run subdirectory could not be created.
    #[error("prepare TCG control run directory {path} failed")]
    ControlRunDirectory {
        /// Control run subdirectory path.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The TCG control stderr capture file could not be created.
    #[error("create TCG control stderr capture {path} failed")]
    ControlStderr {
        /// Stderr capture file path.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The TCG control QEMU child could not be spawned.
    #[error("spawn TCG control QEMU child failed")]
    ControlSpawn {
        /// Underlying spawn error.
        source: std::io::Error,
    },
}

impl QemuLive9pIoGateError {
    /// Builds a [`QemuLive9pIoGateError::Drive`] for a drive operation.
    pub(super) fn drive(operation: &'static str, source: QemuNodeChannelError) -> Self {
        Self::Drive { operation, source }
    }
}
