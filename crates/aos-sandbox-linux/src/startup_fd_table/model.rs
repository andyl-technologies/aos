//! Safe opaque owners and nonauthorizing startup projections.

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use crate::cgroup::RetainedCgroupAnchor;
use crate::inventory::{MountId, MountNamespace};
use crate::pidfd::{PidFd, PidFdCredentials, PidFdProcessIdentity};
use crate::{Error, Result};

/// Retains the scratch descriptor and first cause of one image DATA measurement.
///
/// This owner does not assert execution, PID1 provenance, a startup role or a
/// completed descriptor-table claim. The caller must retain the genuine image
/// provider separately. A failed or repeated measurement cannot be retried.
pub struct RetainedStartupImageMeasurementV2 {
    pub(super) scratch: Option<std::fs::File>,
    pub(super) observation: Option<StartupExecutableObservationV1>,
    first_failure: Option<Error>,
    attempted: bool,
}

impl RetainedStartupImageMeasurementV2 {
    /// Creates an empty, nonauthorizing measurement reservoir.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            scratch: None,
            observation: None,
            first_failure: None,
            attempted: false,
        }
    }

    /// Measures a borrowed image through the sole startup image parser.
    ///
    /// The safe duplicate is parked before any ELF read. Both it and the first
    /// actual error remain resident through refusal and unwinding.
    ///
    /// # Errors
    /// Borrows the first native or parser error, or the permanent repeated-call
    /// refusal. This never constructs a process or descriptor authority.
    pub fn measure_once(&mut self, image: BorrowedFd<'_>) -> std::result::Result<(), &Error> {
        if self.attempted {
            self.first_failure.get_or_insert_with(|| {
                Error::invalid("startup image measurement", "measurement already attempted")
            });
        } else {
            self.attempted = true;
            match super::execution::measure_retained_image(image, &mut self.scratch) {
                Ok(observation) => self.observation = Some(observation),
                Err(error) => self.first_failure = Some(error),
            }
        }

        match self.first_failure.as_ref() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Returns completed measurement DATA, never an execution witness.
    #[must_use]
    pub const fn observation(&self) -> Option<StartupExecutableObservationV1> {
        if self.first_failure.is_some() {
            None
        } else {
            self.observation
        }
    }

    /// Borrows the actual first failure without observation or retry.
    #[must_use]
    pub const fn failure(&self) -> Option<&Error> {
        self.first_failure.as_ref()
    }
}

impl Default for RetainedStartupImageMeasurementV2 {
    fn default() -> Self {
        Self::new()
    }
}

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

impl std::os::fd::AsFd for ClaimedInitialDescriptorV1 {
    fn as_fd(&self) -> BorrowedFd<'_> {
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

/// Projects a retained process without claiming its executed image.
///
/// Selected Mount capture uses this projection for the genuine direct parent.
/// The PID1 image must independently be borrowed from its fixed provider and
/// measured by Core before any startup authority can be established.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupKernelProcessObservationV2 {
    /// Exact observed kernel boot.
    pub kernel_boot_id: [u8; 16],
    /// Original pidfd process identity.
    pub process: PidFdProcessIdentity,
    /// Complete original pidfd credentials.
    pub credentials: PidFdCredentials,
    /// Original kernel cgroup ID.
    pub cgroup_id: u64,
    /// Canonical original cgroup path.
    pub cgroup_path: String,
    /// Original cgroup unit component.
    pub unit: String,
}

pub(super) enum PendingProcessObservationV2 {
    Execution(StartupProcessObservationV1),
    Kernel(StartupKernelProcessObservationV2),
}

#[derive(Default)]
pub(super) struct PendingStartupProcessV2 {
    pub(super) pidfd: Option<PidFd>,
    pub(super) cgroup: Option<RetainedCgroupAnchor>,
    pub(super) executable: Option<OwnedFd>,
    pub(super) executable_scratch: Option<std::fs::File>,
    pub(super) current_executable: Option<OwnedFd>,
    pub(super) current_executable_scratch: Option<std::fs::File>,
    pub(super) observation: Option<PendingProcessObservationV2>,
}

impl PendingStartupProcessV2 {
    pub(super) fn execution(&self) -> Option<&StartupProcessObservationV1> {
        match self.observation.as_ref()? {
            PendingProcessObservationV2::Execution(observation) => Some(observation),
            PendingProcessObservationV2::Kernel(_) => None,
        }
    }

    pub(super) fn kernel(&self) -> Option<&StartupKernelProcessObservationV2> {
        match self.observation.as_ref()? {
            PendingProcessObservationV2::Kernel(observation) => Some(observation),
            PendingProcessObservationV2::Execution(_) => None,
        }
    }

    pub(super) fn internal_fds(&self) -> impl Iterator<Item = BorrowedFd<'_>> {
        self.pidfd.iter().map(|pidfd| pidfd.as_fd())
            .chain(self.cgroup.iter().map(|cgroup| cgroup.as_fd()))
            .chain(self.executable.iter().map(|executable| executable.as_fd()))
            .chain(self.executable_scratch.iter().map(|scratch| scratch.as_fd()))
            .chain(self.current_executable.iter().map(|executable| executable.as_fd()))
            .chain(self.current_executable_scratch.iter().map(|scratch| scratch.as_fd()))
    }
}

/// Retains one incomplete selected Mount startup capture and its first cause.
///
/// Successful scanning does not complete a launcher-image claim. Core must
/// still own and validate the genuine fixed-Mount PID1 image messages. This
/// owner accepts no supplied descriptors, process IDs, roles or image DATA.
pub struct PendingInitialProcessFdTableV2 {
    pub(super) scanner: Option<OwnedFd>,
    pub(super) execution: PendingStartupProcessV2,
    pub(super) launcher: PendingStartupProcessV2,
    pub(super) descriptors: Option<Vec<ClaimedInitialDescriptorV1>>,
    pub(super) pending_descriptor: Option<OwnedFd>,
    pub(super) original_standard: Option<Vec<OwnedFd>>,
    pub(super) activation_hints: Option<ActivationEnvironmentHintsV1>,
    pub(super) first_scan: Option<std::collections::BTreeSet<u32>>,
    pub(super) second_scan: Option<std::collections::BTreeSet<u32>>,
    pub(super) external_numbers: Option<Vec<u32>>,
    pub(super) scanner_descriptor_numbers: Option<Vec<u32>>,
    pub(super) boot_time_before_ns: Option<u64>,
    pub(super) boot_time_after_ns: Option<u64>,
    pub(super) realtime_before_ns: Option<i128>,
    pub(super) realtime_after_ns: Option<i128>,
    pub(super) scanned: bool,
    pub(super) succeeded: bool,
    pub(super) interval_finished: bool,
    pub(super) attempted: bool,
    pub(super) first_failure: Option<Error>,
    pub(super) signal_restore: Option<Result<()>>,
    not_sync: std::marker::PhantomData<std::cell::Cell<()>>,
}

impl PendingInitialProcessFdTableV2 {
    /// Creates an empty, nonpositive original-capture reservoir.
    #[must_use]
    pub fn new() -> Self {
        Self {
            scanner: None,
            execution: PendingStartupProcessV2::default(),
            launcher: PendingStartupProcessV2::default(),
            descriptors: None,
            pending_descriptor: None,
            original_standard: None,
            activation_hints: None,
            first_scan: None,
            second_scan: None,
            external_numbers: None,
            scanner_descriptor_numbers: None,
            boot_time_before_ns: None,
            boot_time_after_ns: None,
            realtime_before_ns: None,
            realtime_after_ns: None,
            scanned: false,
            succeeded: false,
            interval_finished: false,
            attempted: false,
            first_failure: None,
            signal_restore: None,
            not_sync: std::marker::PhantomData,
        }
    }

    /// Captures the whole initial table without opening the parent's image.
    ///
    /// # Safety
    /// Requires the same exclusive original-FD, single-threaded and fixed
    /// signal/environment contract as [`super::claim_initial_process_fd_table_once`].
    /// It must precede every thread or runtime constructor in the process.
    ///
    /// # Errors
    /// Borrows the actual first capture error. The sole process-wide capture
    /// latch is shared with the ordinary consuming API and cannot be retried.
    pub unsafe fn capture_once(&mut self) -> std::result::Result<(), &Error> {
        if self.attempted || self.failure().is_some() {
            if self.failure().is_none() {
                self.first_failure = Some(Error::invalid("startup FD capture", "capture was already attempted"));
            }
        } else {
            self.attempted = true;
            // SAFETY: this method forwards its exclusive original ownership
            // contract into the sole scanner and process-wide capture latch.
            match unsafe { super::capture_selected_once(self) } {
                Ok(()) => self.succeeded = true,
                Err(error) if self.failure().is_none() => self.first_failure = Some(error),
                Err(_) => {}
            }
        }
        self.result()
    }

    /// Rechecks the original kernel and retained descriptor owners in place.
    ///
    /// This does not check or approve the parent image. That independent
    /// fixed-PID1 observation remains Core's responsibility at every crossing.
    ///
    /// # Errors
    /// Borrows the first capture/currentness cause; failure ends this owner and
    /// subsequent calls perform no observation or recovery.
    pub fn recheck_kernel_and_table(&mut self) -> std::result::Result<(), &Error> {
        if !self.succeeded && self.failure().is_none() {
            self.first_failure = Some(Error::invalid("startup FD capture", "capture did not complete"));
        }
        if self.failure().is_none() {
            if let Err(error) = super::scan::revalidate_selected_table(self) {
                self.first_failure = Some(error);
            }
        }
        self.result()
    }

    /// Samples the actual closing clocks after the external image join.
    ///
    /// This performs a final kernel/table bookend but does not examine or
    /// approve image DATA. Core must independently retain that real provider.
    /// The original beginning is never changed; the interval cannot be renewed.
    ///
    /// # Errors
    /// Borrows the first kernel/clock cause, incomplete capture or repeated
    /// interval-completion refusal. Failure permits no subsequent observation.
    pub fn finish_image_join_interval(&mut self) -> std::result::Result<(), &Error> {
        if self.interval_finished && self.failure().is_none() {
            self.first_failure = Some(Error::invalid("startup capture time", "interval already completed"));
        }
        if self.recheck_kernel_and_table().is_err() {
            return self.result();
        }
        match super::scan::finish_selected_interval(self) {
            Ok(()) => self.interval_finished = true,
            Err(error) => self.first_failure = Some(error),
        }
        self.result()
    }

    fn result(&self) -> std::result::Result<(), &Error> {
        match self.failure() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Borrows the actual first native or validation cause without observation.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.first_failure.as_ref().or_else(|| {
            self.signal_restore.as_ref().and_then(|result| result.as_ref().err())
        })
    }

    /// Borrows signal restoration's separate native outcome.
    ///
    /// A failed capture cause remains first even if this later operation fails.
    #[must_use]
    pub fn signal_restoration(&self) -> Option<&Result<()>> {
        self.signal_restore.as_ref()
    }

    /// Returns the genuine captured self execution, not a launcher assertion.
    #[must_use]
    pub fn execution(&self) -> Option<&StartupProcessObservationV1> {
        self.succeeded.then(|| self.execution.execution()).flatten()
    }

    /// Returns the retained direct-parent kernel projection without image DATA.
    #[must_use]
    pub fn launcher_kernel(&self) -> Option<&StartupKernelProcessObservationV2> {
        self.succeeded.then(|| self.launcher.kernel()).flatten()
    }

    /// Borrows the complete captured duplicate table, without granting roles.
    #[must_use]
    pub fn descriptors(&self) -> Option<&[ClaimedInitialDescriptorV1]> {
        self.succeeded.then(|| self.descriptors.as_deref()).flatten()
    }

    /// Borrows the original activation hints as nonauthorizing DATA.
    #[must_use]
    pub fn activation_hints(&self) -> Option<&ActivationEnvironmentHintsV1> {
        self.succeeded.then(|| self.activation_hints.as_ref()).flatten()
    }

    /// Borrows the exact scanner-owned descriptor-number projection.
    #[must_use]
    pub fn scanner_descriptor_numbers(&self) -> Option<&[u32]> {
        self.succeeded.then(|| self.scanner_descriptor_numbers.as_deref()).flatten()
    }

    /// Returns actual capture clocks, including any completed image-join update.
    #[must_use]
    pub fn intervals(&self) -> Option<((u64, u64), (i128, i128))> {
        if !self.succeeded {
            return None;
        }
        Some(((self.boot_time_before_ns?, self.boot_time_after_ns?),
            (self.realtime_before_ns?, self.realtime_after_ns?)))
    }
}

impl Default for PendingInitialProcessFdTableV2 {
    fn default() -> Self {
        Self::new()
    }
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
