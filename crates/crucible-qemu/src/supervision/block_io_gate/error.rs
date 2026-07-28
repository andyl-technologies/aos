//! Error taxonomy for the certifying block-I/O gate.

use super::*;
use thiserror::Error;

/// Error returned by the certifying live block-I/O gate.
#[derive(Debug, Error)]
pub enum QemuLiveBlockIoGateError {
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
    /// The block-I/O servicer could not be built.
    #[error("build block-I/O servicer failed")]
    BlockServicer {
        /// Underlying block-servicer error.
        source: QemuLiveBlockIoServicerError,
    },
    /// The asynchronous device host-work pool could not run.
    #[error("device host-work pool failed")]
    HostWorkPool {
        /// Underlying host-work pool error.
        source: QemuLiveBlockHostWorkPoolError,
    },
    /// The drive hot path could not map the shared-memory region.
    #[error("map drive shared-memory region failed")]
    DriveRegionMap {
        /// Underlying setup-region mapping error.
        source: crucible_shmem::SetupRegionMapError,
    },
    /// The observer mapping could not read the guest node slot.
    #[error("read drive node slot failed")]
    DriveSlot {
        /// Underlying mapped-region access error.
        source: crucible_shmem::MappedSetupRegionAccessError,
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
    /// Canonical I/O observations could not be appended to the unified log.
    #[error("build canonical block-I/O event log failed")]
    CanonicalLog {
        /// Underlying event-log error.
        source: SchedulerError,
    },
    /// The pre-dispatch pin did not cover the observed request's completion.
    #[error(
        "published completion {published_completion_icount:?} does not pin observed completion {observed_completion_icount}"
    )]
    PinMismatch {
        /// Completion computed directly from the observed request.
        observed_completion_icount: u64,
        /// Earliest completion published before dispatch.
        published_completion_icount: Option<u64>,
    },
    /// A certifying race leg did not produce its required ordering.
    #[error("{role} device host-work race was not forced: {evidence}")]
    RaceNotForced {
        /// Race leg that failed.
        role: &'static str,
        /// Captured race evidence.
        evidence: String,
    },
    /// The second run diverged from the reference run.
    #[error("second run diverged from the reference run: {reason}")]
    SecondRunDiverged {
        /// Human-readable divergence detail.
        reason: String,
    },
}

impl QemuLiveBlockIoGateError {
    /// Builds a [`QemuLiveBlockIoGateError::Drive`] for a drive operation.
    pub(super) fn drive(operation: &'static str, source: QemuNodeChannelError) -> Self {
        Self::Drive { operation, source }
    }
}
