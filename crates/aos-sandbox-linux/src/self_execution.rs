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

use crate::boot::KernelBootId;
use crate::pidfd::{PidFd, PidFdCredentials, PidFdInfo, PidFdProcessIdentity};

/// A redacted refusal to capture or revalidate the current process.
///
/// Native errors, incomplete observations, and identity mismatches all return
/// this error without disclosing observed identifiers or kernel causes.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("retained process execution observation refused")]
pub struct SelfExecutionObservationError;

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
    pidfd: PidFd,
    baseline: ExecutionBaseline,
}

impl RetainedSelfExecutionGuard {
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
        Ok(Self { pidfd, baseline })
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
        validate_with(&mut source, &self.pidfd, self.baseline)
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
        process
            .process_identity()
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
