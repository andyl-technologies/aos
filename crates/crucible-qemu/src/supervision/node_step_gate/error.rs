//! Error taxonomy for the live node-step gate.

use super::*;
use crate::QemuAsyncDriverRuntimeError;
use thiserror::Error;

/// Error returned by the live [`QemuNode`] bounded-step gate.
#[derive(Debug, Error)]
pub enum QemuLiveNodeStepGateError {
    /// A scheduled ceiling reached or exceeded the busy cap.
    #[error(
        "scheduled ceiling {ceiling_icount} reaches busy cap {busy_cap_icount}; the guest would idle and forfeit determinism"
    )]
    CeilingAboveBusyCap {
        /// Offending scheduled ceiling.
        ceiling_icount: u64,
        /// Exclusive busy-window upper bound.
        busy_cap_icount: u64,
    },
    /// The run subdirectory could not be created.
    #[error("prepare run directory {path} failed")]
    PrepareRunDirectory {
        /// Run subdirectory path.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A checkpoint-operation cancellation event could not be retained.
    #[error("retain checkpoint-operation cancellation event failed")]
    CheckpointCancellation {
        /// Underlying eventfd creation error.
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
    /// The live white-box setup probe failed.
    #[error("validate live white-box setup failed")]
    WhiteboxSetup {
        /// Underlying setup-probe error.
        source: QemuWhiteboxSetupError,
    },
    /// The guarded image tool could not initialize the exact VMState container.
    #[error("prepare exact VMState container failed")]
    ExactVmstatePreparation {
        /// Underlying contained image-tool failure.
        source: crate::spawn::QemuGuardedImagePreparationError,
    },
    /// The QMP channel configuration was rejected.
    #[error("build QMP channel config failed")]
    QmpChannelConfig {
        /// Underlying launch-command error.
        source: QemuLaunchCommandError,
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
    /// The diagnostic path did not name the descriptor-pinned launch directory.
    #[error(
        "configured QEMU run directory {configured} does not match prepared directory {prepared}"
    )]
    PreparedRunDirectoryMismatch {
        /// Path used to derive the launch command and endpoints.
        configured: PathBuf,
        /// Exact path retained by the prepared directory capability.
        prepared: PathBuf,
    },
    /// The supplied exact snapshot was not emitted by a live QEMU node.
    #[error("production exact restore rejected a non-live or identity-inconsistent snapshot")]
    InvalidExactSnapshot,
    /// A live exact save/crash/load continuation violated its identity contract.
    #[error("live exact snapshot invariant failed: {reason}")]
    ExactSnapshotInvariant {
        /// Deterministic mismatch or missing-evidence detail.
        reason: String,
    },
    /// The priming hot path could not map the shared-memory region.
    #[error("map priming shared-memory region failed")]
    PrimeRegionMap {
        /// Underlying setup-region mapping error.
        source: crucible_shmem::SetupRegionMapError,
    },
    /// The priming mapped hot-path adapter could not bind the region.
    #[error("bind priming mapped hot path failed")]
    PrimeHotPath {
        /// Underlying mapped hot-path binding error.
        source: QemuMappedQuantumShmemHotPathError,
    },
    /// A priming quantum boundary could not be published or read.
    #[error("{operation} failed: {source}")]
    Prime {
        /// Priming operation that failed.
        operation: &'static str,
        /// Underlying shared-memory channel error.
        source: QemuNodeChannelError,
    },
    /// The guest never reached the priming ceiling off the boot barrier.
    #[error("priming quantum did not reach ceiling {ceiling_icount} off the boot barrier")]
    PrimeStalled {
        /// Priming ceiling the guest failed to reach.
        ceiling_icount: u64,
    },
    /// The production host-I/O runtime could not map the shared-memory region.
    #[error("build live host-I/O runtime failed")]
    HostIoRuntime {
        /// Underlying host-I/O runtime error.
        source: QemuLiveHostIoRuntimeError,
    },
    /// Setup-time callbacks did not settle before ordinary scheduling.
    #[error("fence priming host-I/O handoff failed")]
    PrimeHandoff {
        /// Underlying control-boundary settlement error.
        source: QemuAsyncDriverRuntimeError,
    },
    /// The World-backed block servicer could not be constructed or configured.
    #[error("build live block-I/O servicer failed")]
    BlockServicer {
        /// Underlying block-servicer error.
        source: crate::QemuLiveBlockIoServicerError,
    },
    /// The World-backed 9p servicer could not be constructed or serviced.
    #[error("build live 9p-I/O servicer failed")]
    NinepServicer {
        /// Underlying 9p-servicer error.
        source: crate::QemuLive9pIoServicerError,
    },
    /// The accelerator host adapter could not be constructed or serviced.
    #[error("build live accelerator servicer failed")]
    AcceleratorServicer {
        /// Underlying accelerator-servicer error.
        source: crate::QemuLiveAcceleratorServicerError,
    },
    /// The typed QMP VMState channel could not connect.
    #[error("connect QMP VMState channel failed")]
    QmpConnect {
        /// Underlying QMP error.
        source: QmpError,
    },
    /// QEMU did not authenticate and adopt the pinned startup block roots.
    #[error("adopt pinned QEMU launch block roots failed")]
    QmpLaunchFdsetAdoption {
        /// Underlying QMP error.
        source: QmpError,
    },
    /// QEMU could not resume after stopped-state control authentication.
    #[error("start QEMU after stopped-state control authentication failed")]
    QmpStart {
        /// Underlying QMP error.
        source: QemuNodeChannelError,
    },
    /// QEMU's realized fingerprint providers differ from the launch contract.
    #[error("authenticate realized QEMU fingerprint projection manifest failed")]
    FingerprintProjectionManifest {
        /// Underlying typed QMP or manifest mismatch error.
        source: QemuNodeChannelError,
    },
    /// The scheduler-facing node could not be assembled.
    #[error("assemble live QEMU node failed")]
    NodeFactory {
        /// Underlying node-factory error.
        source: QemuNodeFactoryError,
    },
    /// A failed launch step could not synchronously reap its direct child.
    #[error(
        "live QEMU node launch failed ({primary}); mandatory child reap also failed ({cleanup})"
    )]
    FailedCleanup {
        /// Primary launch or assembly failure.
        primary: Box<QemuLiveNodeStepGateError>,
        /// Independent force-kill/reap failure.
        cleanup: crate::QemuShutdownTargetError,
        /// Nonduplicable direct-child handle retained after failed reap.
        unreaped_child: Option<Box<crate::QemuNodeChild>>,
    },
    /// A bounded node step failed.
    #[error("{operation} failed")]
    Step {
        /// Node operation that failed.
        operation: &'static str,
        /// Underlying node error.
        source: QemuNodeError,
    },
    /// A bounded step made no progress toward its ceiling.
    ///
    /// This is the signal that the guest parked below the ceiling and the node's
    /// advance path did not rouse it -- the wake defect the first live node user
    /// is expected to surface if a busy window ever hits an idle wait.
    #[error(
        "node step for ceiling {ceiling_icount} stalled at {last_icount} with next deadline {next_deadline_icount:?} after {reissue_count} re-issues"
    )]
    StepStalled {
        /// Ceiling the step was driving toward.
        ceiling_icount: u64,
        /// Last observed node icount.
        last_icount: u64,
        /// Plugin-published idle deadline at the stalled coordinate, if idle.
        next_deadline_icount: Option<u64>,
        /// Re-issues attempted before the stall was declared.
        reissue_count: u32,
    },
    /// Reading the terminal execution fingerprint failed.
    #[error("read execution fingerprint failed")]
    ExecutionFingerprint {
        /// Underlying node error.
        source: QemuNodeError,
    },
    /// Node shutdown escalation failed.
    #[error("shut down live QEMU node failed")]
    Shutdown {
        /// Underlying node error.
        source: QemuNodeError,
    },
}

impl QemuLiveNodeStepGateError {
    /// Extracts a direct child whose mandatory synchronous reap failed.
    ///
    /// A guarded caller must transfer the returned handle into its attempt
    /// resource owner before releasing containment or storage authority.
    #[must_use]
    pub fn take_unreaped_child(&mut self) -> Option<crate::QemuNodeChild> {
        match self {
            Self::WhiteboxSetup { source } => source.take_unreaped_child(),
            Self::ExactVmstatePreparation { source } => source.take_unreaped_child(),
            Self::NodeFactory { source } => source.take_unreaped_child(),
            Self::FailedCleanup { unreaped_child, .. } => unreaped_child.take().map(|child| *child),
            _ => None,
        }
    }

    /// Builds a [`QemuLiveNodeStepGateError::Step`] for a node operation.
    pub(super) fn node_op(operation: &'static str, source: QemuNodeError) -> Self {
        Self::Step { operation, source }
    }

    /// Builds a [`QemuLiveNodeStepGateError::Prime`] for a priming operation.
    pub(super) fn prime(operation: &'static str, source: QemuNodeChannelError) -> Self {
        Self::Prime { operation, source }
    }
}
