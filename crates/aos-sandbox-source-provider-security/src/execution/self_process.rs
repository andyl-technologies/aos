//! Retained self pidfd and exact execution baseline.

use std::num::NonZeroU32;

use aos_sandbox_linux::pidfd::{PidFd, PidFdCredentials, PidFdInfo, PidFdProcessIdentity};

use super::{CurrentKernelBootV1, read_cgroup_path_digest};
use crate::SourceProviderSecurityError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExecutionBaselineV1 {
    pub(crate) boot_id: [u8; 16],
    pub(crate) pid: u32,
    pub(crate) tgid: u32,
    pub(crate) start_time_ticks: u64,
    pub(crate) cgroup_id: u64,
    pub(crate) cgroup_path_digest: [u8; 32],
    pub(crate) credentials: PidFdCredentials,
}

pub(crate) struct RetainedSelfExecutionV1 {
    pidfd: PidFd,
    baseline: ExecutionBaselineV1,
}

impl RetainedSelfExecutionV1 {
    pub(crate) fn capture() -> Result<Self, SourceProviderSecurityError> {
        let boot_before = CurrentKernelBootV1::capture()?;
        let pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
            .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?;
        let tgid = pid;
        let pidfd =
            PidFd::open(NonZeroU32::new(pid).ok_or(SourceProviderSecurityError::ExecutionChanged)?)
                .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?;
        let baseline = observe(&pidfd, boot_before.boot_id(), pid, tgid)?;
        Ok(Self { pidfd, baseline })
    }

    pub(crate) const fn boot_id(&self) -> [u8; 16] {
        self.baseline.boot_id
    }

    pub(crate) const fn baseline(&self) -> ExecutionBaselineV1 {
        self.baseline
    }

    pub(crate) fn revalidate(&self) -> Result<(), SourceProviderSecurityError> {
        let pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
            .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?;
        let current = observe(&self.pidfd, self.baseline.boot_id, pid, pid)?;
        if current == self.baseline {
            Ok(())
        } else {
            Err(SourceProviderSecurityError::ExecutionChanged)
        }
    }
}

fn observe(
    pidfd: &PidFd,
    expected_boot: [u8; 16],
    expected_pid: u32,
    expected_tgid: u32,
) -> Result<ExecutionBaselineV1, SourceProviderSecurityError> {
    let boot_before = CurrentKernelBootV1::capture()?;
    let info_before = pidfd
        .info()
        .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?;
    let identity = pidfd
        .process_identity()
        .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?;
    let (cgroup_path_digest, _) = read_cgroup_path_digest(info_before.pid())?;
    let info_after = pidfd
        .info()
        .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?;
    let alive = pidfd
        .is_alive()
        .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?;
    let boot_after = CurrentKernelBootV1::capture()?;
    if boot_before.boot_id() != expected_boot
        || boot_after.boot_id() != expected_boot
        || info_before != info_after
        || !alive
    {
        return Err(SourceProviderSecurityError::ExecutionChanged);
    }
    baseline_from(
        info_before,
        identity,
        expected_pid,
        expected_tgid,
        expected_boot,
        cgroup_path_digest,
    )
}

fn baseline_from(
    info: PidFdInfo,
    identity: PidFdProcessIdentity,
    expected_pid: u32,
    expected_tgid: u32,
    boot_id: [u8; 16],
    cgroup_path_digest: [u8; 32],
) -> Result<ExecutionBaselineV1, SourceProviderSecurityError> {
    let credentials = info
        .credentials()
        .ok_or(SourceProviderSecurityError::ExecutionChanged)?;
    let cgroup_id = info
        .cgroup_id()
        .filter(|value| *value != 0)
        .ok_or(SourceProviderSecurityError::ExecutionChanged)?;
    if info.pid() != expected_pid
        || info.thread_group_id() != expected_tgid
        || expected_pid != expected_tgid
        || identity.pid() != info.pid()
        || identity.thread_group_id() != info.thread_group_id()
        || identity.parent_pid() != info.parent_pid()
        || identity.cgroup_id() != Some(cgroup_id)
        || identity.start_time_ticks() == 0
        || cgroup_path_digest == [0; 32]
    {
        return Err(SourceProviderSecurityError::ExecutionChanged);
    }
    Ok(ExecutionBaselineV1 {
        boot_id,
        pid: expected_pid,
        tgid: expected_tgid,
        start_time_ticks: identity.start_time_ticks(),
        cgroup_id,
        cgroup_path_digest,
        credentials,
    })
}
