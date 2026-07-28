//! Typed failures and small conversion helpers for the live runner.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crucible::{ContentHash, NodeId};
use thiserror::Error;

use crate::QemuNodeChannelError;
use crate::single_vm_fingerprint::{SingleVmFingerprintGateError, SingleVmFingerprintRunError};

/// An error produced while running the live Rust-plugin fingerprint backend.
#[derive(Debug, Error)]
pub enum PluginFingerprintRunnerError {
    /// A QEMU or plugin build artifact could not be read for hashing.
    #[error("cannot read build artifact {path} for content hashing")]
    ReadBuildArtifact {
        /// Artifact path that could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The fingerprint definition could not be minted.
    #[error("cannot mint the rust-plugin fingerprint definition: {0}")]
    Definition(SingleVmFingerprintGateError),
    /// The per-run directory could not be prepared.
    #[error("cannot prepare run directory {path}")]
    PrepareRunDirectory {
        /// Directory that could not be created.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A stale translation-prefetch report could not be removed.
    #[error("cannot prepare translation-prefetch report path {path}")]
    PrepareTranslationPrefetchReport {
        /// Artifact path that could not be prepared.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// QEMU did not emit a readable translation-prefetch report.
    #[error("cannot read translation-prefetch report {path}")]
    ReadTranslationPrefetchReport {
        /// Artifact path that could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// QEMU emitted translation-prefetch evidence inconsistent with the launch.
    #[error("invalid translation-prefetch report {path}: {reason}")]
    InvalidTranslationPrefetchReport {
        /// Malformed artifact path.
        path: PathBuf,
        /// Stable rejection reason.
        reason: &'static str,
    },
    /// A stale per-run terminal dump artifact could not be removed.
    #[error("cannot prepare terminal state-dump path {path}")]
    PrepareStateDump {
        /// Artifact path that could not be prepared.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The terminal dump artifact could not be read.
    #[error("cannot read terminal state-dump artifact {path}")]
    ReadStateDump {
        /// Artifact path that could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The plugin reported a terminal raw-state export failure.
    #[error("terminal state-dump export failed: {diagnostic}")]
    StateDumpExport {
        /// Plugin diagnostic.
        diagnostic: String,
    },
    /// The terminal dump artifact was malformed.
    #[error("invalid terminal state-dump artifact {path}: {reason}")]
    InvalidStateDump {
        /// Malformed artifact path.
        path: PathBuf,
        /// Stable rejection reason.
        reason: &'static str,
    },
    /// The terminal dump did not appear within the liveness bound.
    #[error("terminal state dump at icount {target_icount} timed out after {timeout:?}")]
    StateDumpTimeout {
        /// Requested exact boundary.
        target_icount: u64,
        /// Host liveness bound.
        timeout: Duration,
    },
    /// A dump-enabled run completed without returning a parsed artifact.
    #[error("terminal state dump at icount {target_icount} was not returned")]
    MissingStateDump {
        /// Requested exact boundary.
        target_icount: u64,
    },
    /// The two dump sides did not report the requested boundary.
    #[error(
        "state-dump boundary mismatch: target={target_icount} first={first_icount} second={second_icount}"
    )]
    StateDumpTargetMismatch {
        /// Requested boundary.
        target_icount: u64,
        /// First-run artifact boundary.
        first_icount: u64,
        /// Second-run artifact boundary.
        second_icount: u64,
    },
    /// The two raw dumps did not cover the same register/RAM topology.
    #[error("both terminal state-dump sides must cover the same vCPU and RAM topology")]
    StateDumpTopologyMismatch,
    /// The live plugin did not acknowledge the scheduled fault activation.
    #[error(
        "fault activation at icount {target_icount} was not consumed: expected sequence {expected_sequence}, observed {observed_sequence}"
    )]
    FaultActivationNotConsumed {
        /// Exact activation boundary.
        target_icount: u64,
        /// Published mailbox sequence.
        expected_sequence: u32,
        /// Plugin-acknowledged mailbox sequence.
        observed_sequence: u32,
    },
    /// Parsed raw state could not satisfy the structured dump contract.
    #[error("cannot build structured terminal state dump: {0}")]
    BuildStateDump(SingleVmFingerprintGateError),
    /// The deterministic launch profile could not be derived.
    #[error("cannot derive deterministic launch profile")]
    LaunchProfile {
        /// Underlying launch profile error.
        source: crate::LaunchProfileError,
    },
    /// The guest entropy seed file could not be written.
    #[error("cannot write guest entropy seed into {path}")]
    GuestEntropySeed {
        /// Directory that could not receive the seed.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The QEMU launch command could not be assembled.
    #[error("cannot assemble QEMU launch command")]
    LaunchCommand {
        /// Underlying launch command error.
        source: crate::QemuLaunchCommandError,
    },
    /// The shared-memory region layout could not be computed.
    #[error("cannot compute shared-memory region layout")]
    RegionLayout {
        /// Underlying region layout error.
        source: crucible_shmem::RegionLayoutError,
    },
    /// The QEMU child could not be spawned with passed descriptors.
    #[error("cannot spawn QEMU child with passed descriptors")]
    Spawn {
        /// Underlying spawn error.
        source: crate::QemuSpawnError,
    },
    /// The host plugin setup handshake failed.
    #[error("QEMU host plugin setup handshake failed")]
    HostSetup {
        /// Underlying host setup error.
        source: crate::QemuHostPluginSetupError,
    },
    /// The setup acknowledgement was not schedulable.
    #[error("QEMU setup acknowledgement was not schedulable")]
    SetupAckNotReady,
    /// The setup shared-memory region could not be mapped.
    #[error("cannot map the setup shared-memory region")]
    RegionMap {
        /// Underlying region map error.
        source: crucible_shmem::SetupRegionMapError,
    },
    /// The mapped quantum hot path could not be bound or read.
    #[error("mapped quantum hot path failed")]
    MappedHotPath {
        /// Underlying mapped hot-path error.
        source: crate::QemuMappedQuantumShmemHotPathError,
    },
    /// A quantum stopped without reaching the requested target.
    #[error("quantum for target {target_icount} stopped at {reached_icount} ({outcome})")]
    TargetNotReached {
        /// Requested aggregate-icount target.
        target_icount: u64,
        /// Aggregate icount actually reached.
        reached_icount: u64,
        /// The plugin's reported advance outcome.
        outcome: String,
    },
    /// The guest parked idle before reaching a busy-phase target.
    #[error(
        "guest idled at {idle_icount} (deadline {deadline_icount}) before target {target_icount}"
    )]
    GuestIdledBeforeTarget {
        /// Requested aggregate-icount target.
        target_icount: u64,
        /// Aggregate icount at which the guest parked.
        idle_icount: u64,
        /// Published next virtual-timer deadline.
        deadline_icount: u64,
    },
    /// The plugin published no fingerprint sample at a boundary.
    #[error("no fingerprint sample was published at target {target_icount}")]
    MissingFingerprintSample {
        /// Target with no published sample.
        target_icount: u64,
    },
    /// A published fingerprint sample was stamped with an unexpected icount.
    #[error(
        "fingerprint sample icount {sample_icount} != reached {reached_icount} for target {target_icount}"
    )]
    FingerprintSampleIcountMismatch {
        /// Requested aggregate-icount target.
        target_icount: u64,
        /// Aggregate icount actually reached.
        reached_icount: u64,
        /// The icount stamped into the sample.
        sample_icount: u64,
    },
    /// A quantum did not reach its boundary before the host timeout.
    #[error("quantum for target {target_icount} timed out at {last_icount} after {timeout:?}")]
    QuantumTimeout {
        /// Requested aggregate-icount target.
        target_icount: u64,
        /// Last observed aggregate icount.
        last_icount: u64,
        /// Host completion bound.
        timeout: Duration,
    },
    /// The QEMU child exited before a quantum boundary.
    #[error("QEMU child exited before target {target_icount}: {status}")]
    ChildExitBeforeBoundary {
        /// Target the child never reached.
        target_icount: u64,
        /// Child exit status text.
        status: String,
    },
    /// Waiting on the QEMU child failed.
    #[error("cannot wait on the QEMU child")]
    ChildWait {
        /// Underlying wait error.
        source: crate::QemuShutdownTargetError,
    },
    /// The plugin did not publish terminal teardown before the host timeout.
    #[error("plugin teardown did not complete within {timeout:?}")]
    PluginQuitTimeout {
        /// Host completion bound.
        timeout: Duration,
    },
    /// The QEMU child did not exit naturally before the host timeout.
    #[error("QEMU child did not exit within {timeout:?}")]
    ChildExitTimeout {
        /// Host completion bound.
        timeout: Duration,
    },
    /// The QEMU child exited with a non-success status.
    #[error("QEMU child exited uncleanly: {status}")]
    ChildExitUnclean {
        /// Child exit status text.
        status: String,
    },
    /// A shared-memory hot-path channel operation failed.
    #[error("hot-path channel operation '{operation}' failed: {source}")]
    Channel {
        /// The failing operation name.
        operation: &'static str,
        /// Underlying channel error.
        source: QemuNodeChannelError,
    },
    /// The fingerprint stream could not be assembled from the samples.
    #[error("cannot build fingerprint stream: {0}")]
    BuildStream(SingleVmFingerprintGateError),
}

pub(super) fn to_run_error(error: PluginFingerprintRunnerError) -> SingleVmFingerprintRunError {
    SingleVmFingerprintRunError::new(error.to_string())
}

pub(super) fn channel_error(
    operation: &'static str,
    source: QemuNodeChannelError,
) -> PluginFingerprintRunnerError {
    PluginFingerprintRunnerError::Channel { operation, source }
}

pub(super) fn hash_file(path: &Path) -> Result<String, PluginFingerprintRunnerError> {
    let bytes =
        fs::read(path).map_err(|source| PluginFingerprintRunnerError::ReadBuildArtifact {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(ContentHash::from_bytes(&bytes).to_hex())
}

pub(super) fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub(super) fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}
