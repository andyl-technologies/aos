//! Errors reported by the live network-I/O certification gate.

use std::path::PathBuf;

use thiserror::Error;

use super::QemuLiveNetworkIoServicerError;
use crate::{
    LaunchProfileError, QemuHostPluginSetupError, QemuLaunchCommandError,
    QemuMappedQuantumShmemHotPathError, QemuNodeChannelError, QmpError,
    supervision::bounded_scheduler_preemption::BoundedSchedulerPreemptionError,
};

/// Failure produced by the live network-I/O certification.
#[derive(Debug, Error)]
pub enum QemuLiveNetworkIoGateError {
    /// A run directory could not be created.
    #[error("prepare live network run directory {path} failed")]
    PrepareRunDirectory {
        /// Run directory path.
        path: PathBuf,
        /// Filesystem failure.
        source: std::io::Error,
    },
    /// The deterministic launch profile was invalid.
    #[error("derive live network launch profile failed")]
    LaunchProfile {
        /// Launch profile failure.
        source: LaunchProfileError,
    },
    /// The guest entropy seed file could not be materialized.
    #[error("write guest entropy seed under {path} failed")]
    GuestEntropySeed {
        /// Run directory path.
        path: PathBuf,
        /// Filesystem failure.
        source: std::io::Error,
    },
    /// QEMU argv construction or validation failed.
    #[error("build live network QEMU launch command failed")]
    LaunchCommand {
        /// Launch construction failure.
        source: QemuLaunchCommandError,
    },
    /// The shared-memory layout could not be computed.
    #[error("compute live network shared-memory layout failed")]
    RegionLayout {
        /// Layout failure.
        source: crucible_shmem::RegionLayoutError,
    },
    /// QEMU could not be spawned.
    #[error("spawn live network QEMU failed")]
    Spawn {
        /// Spawn failure.
        source: crate::QemuSpawnError,
    },
    /// Plugin setup failed.
    #[error("complete live network plugin setup failed")]
    HostSetup {
        /// Setup failure.
        source: QemuHostPluginSetupError,
    },
    /// The plugin setup acknowledgement did not permit scheduling.
    #[error("live network plugin setup acknowledgement was not ready")]
    SetupAckNotReady,
    /// The resource-bounded host-scheduling adversary failed.
    #[error("live network bounded scheduler preemption failed")]
    SchedulerPreemption {
        /// Typed signal, watchdog, or wall-bound failure.
        source: BoundedSchedulerPreemptionError,
    },
    /// The network router mapping or ring operation failed.
    #[error("live network servicer failed")]
    NetworkServicer {
        /// Servicer failure.
        source: QemuLiveNetworkIoServicerError,
    },
    /// The scheduler hot-path mapping failed.
    #[error("map live network drive region failed")]
    DriveRegionMap {
        /// Mapping failure.
        source: crucible_shmem::SetupRegionMapError,
    },
    /// The mapped quantum hot path could not be constructed.
    #[error("construct live network hot path failed")]
    DriveHotPath {
        /// Hot-path failure.
        source: QemuMappedQuantumShmemHotPathError,
    },
    /// A shared-memory quantum operation failed.
    #[error("{operation} failed")]
    Drive {
        /// Operation label.
        operation: &'static str,
        /// Channel failure.
        source: QemuNodeChannelError,
    },
    /// The guest failed to leave the plugin startup barrier.
    #[error("live network guest did not reach priming ceiling {ceiling}: {evidence}")]
    PrimeDidNotReach {
        /// The exact scheduler ceiling that was not reached.
        ceiling: u64,
        /// Final node-slot state or the error that prevented observing it.
        evidence: String,
    },
    /// Real QEMU did not retain the pre-driver frame in canonical shared memory.
    #[error("live network boot-time frame did not prove guest backpressure: {evidence}")]
    BootBackpressureNotRetained {
        /// Canonical inbound-ring state observed at the first boundary.
        evidence: String,
    },
    /// A retained frame remained after the guest NIC became ready.
    #[error("live network retained frame {frame:?} did not deliver on canonical retry")]
    BackpressureRetryDidNotDeliver {
        /// The deterministic boot-time frame key.
        frame: crucible_shmem::FrameDeliveryKey,
    },
    /// The first retained retry was not observed at its canonical deadline.
    #[error(
        "live network retained frame {frame:?} did not retry exactly at {expected_retry_icount}: {evidence}"
    )]
    BackpressureRetryCoordinate {
        /// The deterministic boot-time frame key.
        frame: crucible_shmem::FrameDeliveryKey,
        /// The retry coordinate derived from the persisted last attempt.
        expected_retry_icount: u64,
        /// Node and transport evidence observed around the retry boundary.
        evidence: String,
    },
    /// Guest userspace did not acknowledge the exact retained frame.
    #[error(
        "live network retained frame {frame:?} left shared memory without a guest acknowledgement: {evidence}"
    )]
    BackpressureAcknowledgementDidNotArrive {
        /// The deterministic boot-time frame key.
        frame: crucible_shmem::FrameDeliveryKey,
        /// Guest TX and node evidence captured after retry.
        evidence: String,
    },
    /// The fresh-process retained-network exact snapshot proof failed.
    #[error("live retained-network exact snapshot certification failed")]
    RetainedExactSnapshot {
        /// Exact-snapshot launch, capture, restore, or continuation failure.
        source: crate::QemuLiveNodeStepGateError,
    },
    /// The probe/reply discovery quantum did not park with a scheduled reply.
    #[error(
        "live network probe discovery did not schedule a reply and park at its ceiling: {evidence}"
    )]
    ProbeDiscoveryDidNotPark {
        /// Final network and node state.
        evidence: String,
    },
    /// The fixed reply did not fall after the probe-discovery ceiling.
    #[error(
        "live network reply icount {reply_delivery_icount} is not after discovery ceiling {discovery_ceiling_icount}"
    )]
    ReplyOutsideDiscoveryWindow {
        /// Ceiling used to park after observing the guest probe.
        discovery_ceiling_icount: u64,
        /// Router-stamped reply delivery icount.
        reply_delivery_icount: u64,
    },
    /// The plugin did not publish the authorized reply event boundary.
    #[error("live network guest did not reach reply icount {reply_delivery_icount}: {evidence}")]
    ReplyDeliveryDidNotReach {
        /// Authorized reply delivery icount.
        reply_delivery_icount: u64,
        /// Final node-slot observation.
        evidence: String,
    },
    /// The guest did not emit the post-reply acknowledgement.
    #[error("live network guest acknowledgement did not arrive: {evidence}")]
    AcknowledgementDidNotArrive {
        /// Final network and node-slot observations.
        evidence: String,
    },
    /// QMP connection or status query failed.
    #[error("live network QMP synchronization failed")]
    QmpConnect {
        /// QMP failure.
        source: QmpError,
    },
    /// QMP reported a non-running VM.
    #[error("live network QEMU was not running after priming: {status}")]
    QmpNotRunning {
        /// QMP run-state diagnostic.
        status: String,
    },
    /// Child status polling failed.
    #[error("poll live network QEMU child failed")]
    ChildWait {
        /// Child supervision failure.
        source: crate::QemuShutdownTargetError,
    },
    /// QEMU exited before the exchange completed.
    #[error("live network QEMU exited before acknowledgement: {status}")]
    ChildExited {
        /// Process status.
        status: String,
    },
    /// A run did not satisfy the live exchange contract.
    #[error("live network {run} certification failed: {reason}; evidence={evidence}")]
    CertificationFailed {
        /// Run label.
        run: &'static str,
        /// Failed invariant.
        reason: &'static str,
        /// Captured diagnostic evidence.
        evidence: String,
    },
    /// The hostile-host run changed deterministic observations.
    #[error(
        "live network hostile-host observations diverged: reference={reference}; hostile={hostile}"
    )]
    SecondRunDiverged {
        /// Reference projection.
        reference: String,
        /// Hostile-host projection.
        hostile: String,
    },
}

impl QemuLiveNetworkIoGateError {
    pub(super) fn drive(operation: &'static str, source: QemuNodeChannelError) -> Self {
        Self::Drive { operation, source }
    }
}
