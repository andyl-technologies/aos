//! Retained pidfd guard for the custody process itself.
//!
//! The guard pins the loading process once and never creates or replaces that
//! retained pidfd from its numeric PID after capture. Each observation
//! sandwiches pidfd information and procfs-derived identity between exact boot,
//! PID, effective-UID, and effective-GID observations. The procfs identity
//! helper opens numeric `/proc/PID/stat` only inside that retained-pidfd
//! information and liveness sandwich.
//! Cross-call comparison deliberately excludes PPID because a parent may exit,
//! while PPID must still remain stable inside each individual observation.

use std::num::NonZeroU32;

use aos_linux_descriptors::boot::KernelBootId;
use crate::pidfd::CurrentSelfPidFdCustodyV1;
use aos_linux_descriptors::pidfd::PidFd;
use aos_linux_descriptors::pidfd::PidFdCredentials;
use aos_linux_descriptors::pidfd::PidFdInfo;
use crate::pidfd::PidFdProcessIdentity;

mod observations;
pub use observations::SelfExecutionObservationV1;

/// A redacted refusal to capture or revalidate the current process.
///
/// Native errors, incomplete observations, and identity mismatches all return
/// this error without disclosing observed identifiers or kernel causes.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("retained process execution observation refused")]
pub struct SelfExecutionObservationError;

/// Retains the selected self-process capture's actual failed native prefixes.
///
/// This exposes neither the descriptor nor a retry. Its display preserves the
/// redacted observation classification, while its source borrows the actual
/// first cause. Dropping it disposes custody without proving process death or
/// releasing an upper resource obligation.
pub struct RetainedSelfExecutionCaptureError {
    capture: Box<SelectedSelfCaptureV1>,
}

impl std::fmt::Debug for RetainedSelfExecutionCaptureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedSelfExecutionCaptureError")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for RetainedSelfExecutionCaptureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&SelfExecutionObservationError, formatter)
    }
}

impl std::error::Error for RetainedSelfExecutionCaptureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.capture.failure())
    }
}

/// Retains the current process's pidfd and stable execution baseline.
///
/// Capture selects the calling process through the kernel. The descriptor and
/// baseline remain private, and revalidation reuses that same descriptor.
/// This guard establishes observed process identity without granting role or
/// session authority.
///
/// # Examples
///
/// ```no_run
/// use aos_sandbox_linux::self_execution::RetainedSelfExecutionGuard;
///
/// let guard = RetainedSelfExecutionGuard::capture()?;
/// guard.validate_current()?;
/// # Ok::<(), aos_sandbox_linux::self_execution::SelfExecutionObservationError>(())
/// ```
pub struct RetainedSelfExecutionGuard {
    original: SelfExecutionOriginalV1,
    baseline: ExecutionBaseline,
}

enum SelfExecutionOriginalV1 {
    Ordinary(PidFd),
    Selected(Box<SelectedSelfCaptureV1>),
}

struct SelectedSelfCaptureV1 {
    process: CurrentSelfPidFdCustodyV1,
    capture: Option<aos_linux_descriptors::Result<PidFdProcessIdentity>>,
    observation: SelfExecutionObservationV1,
}

impl SelectedSelfCaptureV1 {
    fn new() -> Self {
        Self {
            process: CurrentSelfPidFdCustodyV1::new(),
            capture: None,
            observation: SelfExecutionObservationV1::new(),
        }
    }

    fn failure(&self) -> &(dyn std::error::Error + 'static) {
        self.capture.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.observation.failure())
            .unwrap_or(&SelfExecutionObservationError)
    }
}

impl RetainedSelfExecutionGuard {
    /// Bounds selected capture's additional heap and fixed native scratch.
    ///
    /// The actual inline guard/error layout is counted separately. The bound
    /// covers the retained initial stat owner and one complete baseline probe.
    #[must_use]
    pub const fn selected_capture_heap_bytes_v1() -> usize {
        // Box::new may reach an additional construction temporary. Charge it
        // explicitly rather than assuming placement optimization or stack slack.
        2 * std::mem::size_of::<SelectedSelfCaptureV1>()
            + crate::pidfd::PidFdProcObservationsV1::stat_receiving_footprint_v1().0
            + SelfExecutionObservationV1::receiving_heap_bytes_v1()
    }

    /// Bounds selected capture's actual retained file-descriptor peak.
    #[must_use]
    pub const fn selected_capture_opened_file_bound_v1() -> usize {
        // Same current-self pidfd/stat originals plus the baseline probe files.
        2 + SelfExecutionObservationV1::opened_file_bound_v1()
    }

    /// Bounds selected capture's additional native/representation cells.
    #[must_use]
    pub const fn selected_capture_metadata_cell_bound_v1() -> usize {
        crate::pidfd::PidFdProcObservationsV1::stat_receiving_footprint_v1().1
            + SelfExecutionObservationV1::metadata_cell_bound_v1() + 4
    }

    /// Captures and validates the current process through one newly opened pidfd.
    ///
    /// # Errors
    ///
    /// Returns [`SelfExecutionObservationError`] if a native observation fails,
    /// required credentials or a nonzero cgroup identity are absent, or the
    /// scalar, pidfd, procfs identity, and liveness observations disagree.
    pub fn capture() -> Result<Self, SelfExecutionObservationError> {
        let mut source = KernelObservationSource;
        let (pidfd, baseline) = capture_with(&mut source)?;
        Ok(Self {
            original: SelfExecutionOriginalV1::Ordinary(pidfd),
            baseline,
        })
    }

    /// Captures the same process while retaining any acquired pidfd on refusal.
    ///
    /// # Errors
    /// Returns an owning [`RetainedSelfExecutionCaptureError`] for a failed
    /// native capture, bounded original procfs read or unchanged execution
    /// comparison. This selected route additionally requires the original
    /// boot/stat descriptors to be procfs. A negative owner cannot be extracted,
    /// repaired or used to create a complete execution guard.
    pub fn capture_retaining() -> Result<Self, RetainedSelfExecutionCaptureError> {
        // The selected caller prices this actual private carrier before entry.
        // Ordinary guards retain their compact original representation.
        let mut capture = Box::new(SelectedSelfCaptureV1::new());
        capture.capture = Some(capture.process.capture_current());
        if !matches!(capture.capture, Some(Ok(_))) {
            return Err(RetainedSelfExecutionCaptureError { capture });
        }
        let original = match capture.process.pidfd() {
            Ok(original) => original,
            Err(_) => std::process::abort(),
        };
        match capture.observation.observe_baseline_once(original) {
            Ok(baseline) => {
                capture.observation.dispose_positive_originals();
                Ok(Self {
                    original: SelfExecutionOriginalV1::Selected(capture),
                    baseline,
                })
            }
            Err(_) => Err(RetainedSelfExecutionCaptureError { capture }),
        }
    }

    /// Returns the process ID held by this actual completed capture.
    #[doc(hidden)]
    pub const fn captured_process_id_v1(&self) -> u32 {
        self.baseline.process_id
    }

    /// Reports the surviving native roster of a completed selected capture.
    ///
    /// The selected original owns its same current-self pidfd and initial
    /// proc-stat descriptor. Ordinary captures provide no selected residency.
    #[doc(hidden)]
    pub fn selected_retained_open_file_count_v1(&self) -> Option<usize> {
        match &self.original {
            SelfExecutionOriginalV1::Selected(original) => original.process.completed_stat_native_file_count_v1(),
            SelfExecutionOriginalV1::Ordinary(_) => None,
        }
    }

    /// Returns the boot identity pinned by the complete capture sandwich.
    pub const fn boot_id(&self) -> [u8; 16] {
        self.baseline.boot_id
    }
}

impl RetainedSelfExecutionGuard {
    /// Validates the current process against its original retained baseline.
    ///
    /// Checks boot identity, PID, TGID, start time, every credential dimension,
    /// cgroup identity, and liveness through the original retained descriptor.
    /// Parent identity may change between calls but must agree within each
    /// observation.
    ///
    /// # Errors
    ///
    /// Returns [`SelfExecutionObservationError`] if a native observation fails,
    /// required observations are absent or inconsistent, the process is no
    /// longer alive, or its stable execution baseline has changed.
    pub fn validate_current(&self) -> Result<(), SelfExecutionObservationError> {
        let mut source = KernelObservationSource;
        let original = self.original_pidfd()?;
        validate_with(&mut source, original, self.baseline)
    }

    /// Observes the same original while retaining acquired native prefixes.
    ///
    /// The destination owns both fixed boot-ID reads, the proc-stat descriptor
    /// and partial bytes, actual information/liveness Results, and unchanged
    /// baseline comparison. No received or caller-selected descriptor is used.
    ///
    /// # Errors
    /// Returns the existing redacted refusal for repeated/incomplete observation,
    /// failed native operations or changed execution facts. The caller retains
    /// the destination, whose failure accessor borrows the actual first cause.
    pub fn validate_current_retaining(
        &self,
        destination: &mut SelfExecutionObservationV1,
    ) -> Result<(), SelfExecutionObservationError> {
        destination.validate_once(self.original_pidfd()?, self.baseline)
    }

    fn original_pidfd(&self) -> Result<&PidFd, SelfExecutionObservationError> {
        match &self.original {
            SelfExecutionOriginalV1::Ordinary(original) => Ok(original),
            SelfExecutionOriginalV1::Selected(original) => original.process.pidfd()
                .map_err(|_| SelfExecutionObservationError),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ScalarObservation {
    boot_id: [u8; 16],
    process_id: u32,
    effective_user_id: u32,
    effective_group_id: u32,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct CredentialObservation {
    real_user_id: u32,
    real_group_id: u32,
    effective_user_id: u32,
    effective_group_id: u32,
    saved_user_id: u32,
    saved_group_id: u32,
    filesystem_user_id: u32,
    filesystem_group_id: u32,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct InformationObservation {
    process_id: u32,
    thread_group_id: u32,
    parent_process_id: u32,
    credentials: Option<CredentialObservation>,
    cgroup_id: Option<u64>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct IdentityObservation {
    process_id: u32,
    thread_group_id: u32,
    parent_process_id: u32,
    cgroup_id: Option<u64>,
    start_time_ticks: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ExecutionBaseline {
    boot_id: [u8; 16],
    process_id: u32,
    thread_group_id: u32,
    start_time_ticks: u64,
    cgroup_id: u64,
    credentials: CredentialObservation,
}

trait ExecutionObservationSource {
    type Process;

    fn scalars(&mut self) -> Result<ScalarObservation, SelfExecutionObservationError>;

    fn open_self(
        &mut self,
        process_id: NonZeroU32,
    ) -> Result<Self::Process, SelfExecutionObservationError>;

    fn information(
        &mut self,
        process: &Self::Process,
    ) -> Result<InformationObservation, SelfExecutionObservationError>;

    fn identity(
        &mut self,
        process: &Self::Process,
    ) -> Result<IdentityObservation, SelfExecutionObservationError>;

    fn alive(&mut self, process: &Self::Process) -> Result<bool, SelfExecutionObservationError>;
}

struct KernelObservationSource;

impl ExecutionObservationSource for KernelObservationSource {
    type Process = PidFd;

    fn scalars(&mut self) -> Result<ScalarObservation, SelfExecutionObservationError> {
        let boot_id = KernelBootId::current()
            .map_err(|_| SelfExecutionObservationError)?
            .into_bytes();
        let process_id = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
            .map_err(|_| SelfExecutionObservationError)?;
        Ok(ScalarObservation {
            boot_id,
            process_id,
            effective_user_id: rustix::process::geteuid().as_raw(),
            effective_group_id: rustix::process::getegid().as_raw(),
        })
    }

    fn open_self(
        &mut self,
        process_id: NonZeroU32,
    ) -> Result<Self::Process, SelfExecutionObservationError> {
        PidFd::open(process_id).map_err(|_| SelfExecutionObservationError)
    }

    fn information(
        &mut self,
        process: &Self::Process,
    ) -> Result<InformationObservation, SelfExecutionObservationError> {
        process
            .info()
            .map(information_from_pidfd)
            .map_err(|_| SelfExecutionObservationError)
    }

    fn identity(
        &mut self,
        process: &Self::Process,
    ) -> Result<IdentityObservation, SelfExecutionObservationError> {
        crate::pidfd::process_identity(process)
            .map(identity_from_pidfd)
            .map_err(|_| SelfExecutionObservationError)
    }

    fn alive(&mut self, process: &Self::Process) -> Result<bool, SelfExecutionObservationError> {
        process
            .is_alive()
            .map_err(|_| SelfExecutionObservationError)
    }
}

fn capture_with<Source: ExecutionObservationSource>(
    source: &mut Source,
) -> Result<(Source::Process, ExecutionBaseline), SelfExecutionObservationError> {
    let before = source.scalars()?;
    let process_id = NonZeroU32::new(before.process_id).ok_or(SelfExecutionObservationError)?;
    let process = source.open_self(process_id)?;
    let baseline = observe_after_scalars(source, &process, before)?;
    Ok((process, baseline))
}

fn validate_with<Source: ExecutionObservationSource>(
    source: &mut Source,
    process: &Source::Process,
    baseline: ExecutionBaseline,
) -> Result<(), SelfExecutionObservationError> {
    let before = source.scalars()?;
    let current = observe_after_scalars(source, process, before)?;
    if current != baseline {
        return Err(SelfExecutionObservationError);
    }
    Ok(())
}

fn observe_after_scalars<Source: ExecutionObservationSource>(
    source: &mut Source,
    process: &Source::Process,
    before: ScalarObservation,
) -> Result<ExecutionBaseline, SelfExecutionObservationError> {
    let information_before = source.information(process)?;
    let identity = source.identity(process)?;
    let information_after = source.information(process)?;
    let alive = source.alive(process)?;
    let after = source.scalars()?;

    if before != after || information_before != information_after || !alive {
        return Err(SelfExecutionObservationError);
    }
    baseline_from_observation(before, information_before, identity)
}

fn baseline_from_observation(
    scalars: ScalarObservation,
    information: InformationObservation,
    identity: IdentityObservation,
) -> Result<ExecutionBaseline, SelfExecutionObservationError> {
    let credentials = information
        .credentials
        .ok_or(SelfExecutionObservationError)?;
    let cgroup_id = information
        .cgroup_id
        .filter(|value| *value != 0)
        .ok_or(SelfExecutionObservationError)?;

    if information.process_id != scalars.process_id
        || information.thread_group_id != scalars.process_id
        || credentials.effective_user_id != scalars.effective_user_id
        || credentials.effective_group_id != scalars.effective_group_id
        || identity.process_id != information.process_id
        || identity.thread_group_id != information.thread_group_id
        || identity.parent_process_id != information.parent_process_id
        || identity.cgroup_id != Some(cgroup_id)
    {
        return Err(SelfExecutionObservationError);
    }

    Ok(ExecutionBaseline {
        boot_id: scalars.boot_id,
        process_id: information.process_id,
        thread_group_id: information.thread_group_id,
        start_time_ticks: identity.start_time_ticks,
        cgroup_id,
        credentials,
    })
}

fn information_from_pidfd(information: PidFdInfo) -> InformationObservation {
    InformationObservation {
        process_id: information.pid(),
        thread_group_id: information.thread_group_id(),
        parent_process_id: information.parent_pid(),
        credentials: information.credentials().map(credentials_from_pidfd),
        cgroup_id: information.cgroup_id(),
    }
}

const fn credentials_from_pidfd(credentials: PidFdCredentials) -> CredentialObservation {
    CredentialObservation {
        real_user_id: credentials.real_user_id(),
        real_group_id: credentials.real_group_id(),
        effective_user_id: credentials.effective_user_id(),
        effective_group_id: credentials.effective_group_id(),
        saved_user_id: credentials.saved_user_id(),
        saved_group_id: credentials.saved_group_id(),
        filesystem_user_id: credentials.filesystem_user_id(),
        filesystem_group_id: credentials.filesystem_group_id(),
    }
}

const fn identity_from_pidfd(identity: PidFdProcessIdentity) -> IdentityObservation {
    IdentityObservation {
        process_id: identity.pid(),
        thread_group_id: identity.thread_group_id(),
        parent_process_id: identity.parent_pid(),
        cgroup_id: identity.cgroup_id(),
        start_time_ticks: identity.start_time_ticks(),
    }
}

#[cfg(test)]
mod tests;
