//! Safe opaque owners and nonauthorizing startup projections.

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use crate::cgroup::RetainedCgroupAnchor;
use crate::inventory::{MountId, MountNamespace};
use crate::pidfd::{PidFd, PidFdCredentials, PidFdProcessIdentity};
use crate::{Error, Result};

/// Hard implementation ceiling for one complete initial descriptor table.
pub const MAXIMUM_INITIAL_PROCESS_DESCRIPTORS_V1: usize = 1_024;
/// Hard implementation ceiling for one observed numeric descriptor.
pub const MAXIMUM_INITIAL_DESCRIPTOR_NUMBER_V1: u32 = 1_048_575;
/// Hard implementation ceiling for all activation hint bytes.
pub const MAXIMUM_ACTIVATION_HINT_BYTES_V1: usize = 512 * 1_024;

/// Bounds the untrusted kernel and environment data read during capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupFdCaptureHardLimitsV1 {
    maximum_descriptors: usize,
    maximum_descriptor_number: u32,
    maximum_activation_hint_bytes: usize,
}

impl StartupFdCaptureHardLimitsV1 {
    /// Returns the fixed hard limits for dormant Mount-manager capture.
    #[must_use]
    pub const fn mount_manager() -> Self {
        Self {
            maximum_descriptors: MAXIMUM_INITIAL_PROCESS_DESCRIPTORS_V1,
            maximum_descriptor_number: MAXIMUM_INITIAL_DESCRIPTOR_NUMBER_V1,
            maximum_activation_hint_bytes: MAXIMUM_ACTIVATION_HINT_BYTES_V1,
        }
    }

    pub(super) fn validate(self) -> Result<()> {
        if self.maximum_descriptors == 0
            || self.maximum_descriptors > MAXIMUM_INITIAL_PROCESS_DESCRIPTORS_V1
            || self.maximum_descriptor_number < 3
            || self.maximum_descriptor_number > MAXIMUM_INITIAL_DESCRIPTOR_NUMBER_V1
            || self.maximum_activation_hint_bytes == 0
            || self.maximum_activation_hint_bytes > MAXIMUM_ACTIVATION_HINT_BYTES_V1
        {
            return Err(Error::invalid(
                "startup FD capture limits",
                "limits exceed the closed implementation profile",
            ));
        }
        Ok(())
    }

    pub(super) const fn maximum_descriptors(self) -> usize {
        self.maximum_descriptors
    }

    pub(super) const fn maximum_descriptor_number(self) -> u32 {
        self.maximum_descriptor_number
    }

    pub(super) const fn maximum_activation_hint_bytes(self) -> usize {
        self.maximum_activation_hint_bytes
    }
}

/// Classifies one observed kernel object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialDescriptorObjectKindV1 {
    /// Regular file.
    Regular,
    /// Directory.
    Directory,
    /// Socket.
    Socket,
    /// FIFO or pipe.
    Fifo,
    /// Character device.
    Character,
    /// Block device.
    Block,
    /// Symbolic link.
    Symlink,
    /// Another kernel object class.
    Other,
}

/// Projects socket-specific kernel facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialSocketObservationV1 {
    /// Kernel address family.
    pub domain: u32,
    /// Kernel socket type without creation flags.
    pub socket_type: u32,
    /// Whether the socket is listening.
    pub accepting: bool,
    /// Exact bounded local `sockaddr` bytes.
    pub local_address: Vec<u8>,
}

/// Projects one stable descriptor observation without granting ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialDescriptorObservationV1 {
    /// Original numeric descriptor.
    pub number: u32,
    /// Descriptor flags.
    pub descriptor_flags: u32,
    /// Open-file-description status flags.
    pub status_flags: u32,
    /// Kernel object class.
    pub object_kind: InitialDescriptorObjectKindV1,
    /// Object device.
    pub device: u64,
    /// Object inode.
    pub inode: u64,
    /// Object mode.
    pub mode: u32,
    /// Device number for device nodes.
    pub special_device: u64,
    /// Object size.
    pub size: u64,
    /// Unique Mount ID when supported for this object.
    pub unique_mount_id: Option<u64>,
    /// Per-mount read-only state when available.
    pub mount_read_only: Option<bool>,
    /// Socket-specific observation.
    pub socket: Option<InitialSocketObservationV1>,
}

/// Owns one descriptor copied from the complete initial table.
pub struct ClaimedInitialDescriptorV1 {
    pub(super) original_number: u32,
    pub(super) descriptor: OwnedFd,
    pub(super) observation: InitialDescriptorObservationV1,
}

impl ClaimedInitialDescriptorV1 {
    /// Returns the original process-start descriptor number.
    #[must_use]
    pub const fn original_number(&self) -> u32 {
        self.original_number
    }

    /// Returns the stable double-observed kernel projection.
    #[must_use]
    pub const fn observation(&self) -> &InitialDescriptorObservationV1 {
        &self.observation
    }

    /// Observes whether this descriptor's Mount is currently read-only.
    ///
    /// This check is separate from generic initial-table capture because a
    /// detached retained Mount has a stable Mount ID but is not a member of the
    /// current Mount namespace. Only the protected SourceRoot admission path
    /// invokes this current-namespace policy check.
    ///
    /// # Errors
    ///
    /// Returns an error when the descriptor has no Mount identity or the
    /// current namespace cannot observe that exact Mount.
    pub fn observe_current_mount_read_only(&self) -> Result<bool> {
        let mount_id = MountId::from_fd(self.descriptor.as_fd())?;
        Ok(MountNamespace::current().observe(mount_id)?.is_read_only())
    }

    /// Consumes this entry into its safely owned retained descriptor.
    #[must_use]
    pub fn into_fd(self) -> OwnedFd {
        self.descriptor
    }

    pub(super) fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

/// Stores the bounded activation environment as nonauthoritative bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationEnvironmentHintsV1 {
    /// Raw `LISTEN_PID` bytes when present.
    pub listen_pid: Option<Vec<u8>>,
    /// Raw `LISTEN_FDS` bytes when present.
    pub listen_fds: Option<Vec<u8>>,
    /// Raw `LISTEN_FDNAMES` bytes when present.
    pub listen_fdnames: Option<Vec<u8>>,
}

/// Stores an exact GNU build-ID without interpreting it as authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutableBuildIdentityV1 {
    bytes: [u8; 64],
    length: u8,
}

impl ExecutableBuildIdentityV1 {
    /// Returns the exact canonical GNU build-ID bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }
}

/// Projects one pinned fs-verity-protected executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupExecutableObservationV1 {
    /// Executable device.
    pub device: u64,
    /// Executable inode.
    pub inode: u64,
    /// Executable size.
    pub size: u64,
    /// Executable mode.
    pub mode: u32,
    /// SHA-256 fs-verity measurement.
    pub fs_verity_sha256: [u8; 32],
    /// Exact GNU build identity.
    pub build_identity: ExecutableBuildIdentityV1,
}

/// Projects one exact pinned process execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupProcessObservationV1 {
    /// Current kernel boot.
    pub kernel_boot_id: [u8; 16],
    /// Stable process identity.
    pub process: PidFdProcessIdentity,
    /// Complete pidfd credentials.
    pub credentials: PidFdCredentials,
    /// Kernel cgroup ID.
    pub cgroup_id: u64,
    /// Canonical cgroup-v2 path.
    pub cgroup_path: String,
    /// Final systemd unit component.
    pub unit: String,
    /// Pinned executable facts.
    pub executable: StartupExecutableObservationV1,
}

pub(super) struct RetainedStartupProcessV1 {
    pub(super) pidfd: PidFd,
    pub(super) cgroup: RetainedCgroupAnchor,
    pub(super) executable: OwnedFd,
    pub(super) observation: StartupProcessObservationV1,
}

impl RetainedStartupProcessV1 {
    pub(super) fn internal_fds(&self) -> [BorrowedFd<'_>; 3] {
        [
            self.pidfd.as_fd(),
            self.cgroup.as_fd(),
            self.executable.as_fd(),
        ]
    }
}

/// Owns the complete claimed table and retained execution provenance.
pub struct ClaimedInitialProcessFdTableV1 {
    pub(super) execution: RetainedStartupProcessV1,
    pub(super) launcher: RetainedStartupProcessV1,
    pub(super) descriptors: Vec<ClaimedInitialDescriptorV1>,
    pub(super) activation_hints: ActivationEnvironmentHintsV1,
    pub(super) boot_time_before_ns: u64,
    pub(super) boot_time_after_ns: u64,
    pub(super) realtime_before_ns: i128,
    pub(super) realtime_after_ns: i128,
    pub(super) scanner_descriptor_numbers: Vec<u32>,
}

impl ClaimedInitialProcessFdTableV1 {
    /// Returns the Mount-manager execution projection.
    #[must_use]
    pub const fn execution(&self) -> &StartupProcessObservationV1 {
        &self.execution.observation
    }

    /// Returns the exact direct-launcher execution projection.
    #[must_use]
    pub const fn launcher(&self) -> &StartupProcessObservationV1 {
        &self.launcher.observation
    }

    /// Returns the complete sorted descriptor table.
    #[must_use]
    pub fn descriptors(&self) -> &[ClaimedInitialDescriptorV1] {
        &self.descriptors
    }

    /// Returns bounded nonauthoritative activation hints.
    #[must_use]
    pub const fn activation_hints(&self) -> &ActivationEnvironmentHintsV1 {
        &self.activation_hints
    }

    /// Returns the capture boot-time interval in nanoseconds.
    #[must_use]
    pub const fn boot_time_interval_ns(&self) -> (u64, u64) {
        (self.boot_time_before_ns, self.boot_time_after_ns)
    }

    /// Returns the capture realtime interval in nanoseconds since Unix epoch.
    #[must_use]
    pub const fn realtime_interval_ns(&self) -> (i128, i128) {
        (self.realtime_before_ns, self.realtime_after_ns)
    }

    /// Returns the exact sorted scanner-owned descriptor numbers.
    #[must_use]
    pub fn scanner_descriptor_numbers(&self) -> &[u32] {
        &self.scanner_descriptor_numbers
    }

    /// Revalidates execution, launcher, cgroups, executables, and all FDs.
    ///
    /// # Errors
    ///
    /// Returns an error if any retained kernel identity changed, exited, was
    /// removed, or no longer reproduces its captured observation.
    pub fn revalidate(&self) -> Result<()> {
        super::scan::revalidate_claimed_table(self)
    }

    /// Consumes the capability into execution projections and owned entries.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        StartupProcessObservationV1,
        StartupProcessObservationV1,
        Vec<ClaimedInitialDescriptorV1>,
        ActivationEnvironmentHintsV1,
    ) {
        (
            self.execution.observation,
            self.launcher.observation,
            self.descriptors,
            self.activation_hints,
        )
    }
}

pub(super) fn build_identity(bytes: &[u8]) -> Result<ExecutableBuildIdentityV1> {
    if bytes.is_empty() || bytes.len() > 64 {
        return Err(Error::invalid(
            "executable build ID",
            "GNU build ID length is outside 1..=64",
        ));
    }
    let mut output = [0; 64];
    output[..bytes.len()].copy_from_slice(bytes);
    Ok(ExecutableBuildIdentityV1 {
        bytes: output,
        length: u8::try_from(bytes.len())
            .map_err(|_| Error::invalid("executable build ID", "length does not fit u8"))?,
    })
}
