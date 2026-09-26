//! Retained remote execution evidence from one descriptor-subject record.

use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind};
use aos_sandbox_linux::pidfd::{PidFdCredentials, PidFdInfo, PidFdProcessIdentity};
use aos_sandbox_linux::seqpacket::{ConnectionPeerIdentity, KernelAuthorizedRecordSubject};

use super::{CurrentKernelBootV1, read_cgroup_path_digest};
use crate::SourceProviderSecurityError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RemoteBaselineV1 {
    boot_id: [u8; 16],
    pid: u32,
    tgid: u32,
    parent_pid: u32,
    start_time_ticks: u64,
    cgroup_id: u64,
    cgroup_path_digest: [u8; 32],
    credentials: PidFdCredentials,
    socket_cookie: u64,
}

/// Retains the record-subject pidfd that anchors one direct peer execution.
pub(crate) struct ProcessExecutionEvidenceV1 {
    subject: KernelAuthorizedRecordSubject,
    baseline: RemoteBaselineV1,
}

impl ProcessExecutionEvidenceV1 {
    pub(crate) fn capture(
        peer: &ConnectionPeerIdentity,
        subject: KernelAuthorizedRecordSubject,
    ) -> Result<Self, SourceProviderSecurityError> {
        let peer_credentials = peer.credentials();
        let subject_credentials = subject.credentials();
        if peer_credentials.pid() != subject_credentials.pid()
            || peer_credentials.uid() != subject_credentials.uid()
            || peer_credentials.gid() != subject_credentials.gid()
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let boot = CurrentKernelBootV1::capture()?;
        let baseline = observe(
            &subject,
            boot.boot_id(),
            peer.socket_cookie().get(),
            subject_credentials.pid().get(),
            subject_credentials.uid(),
            subject_credentials.gid(),
        )?;
        if peer.initial_info().pid() != baseline.pid
            || peer.initial_info().thread_group_id() != baseline.tgid
            || peer.initial_info().credentials() != Some(baseline.credentials)
            || peer.initial_info().cgroup_id() != Some(baseline.cgroup_id)
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        require_peer_matches(peer, baseline)?;
        Ok(Self { subject, baseline })
    }

    pub(crate) fn revalidate(
        &self,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), SourceProviderSecurityError> {
        if peer.socket_cookie().get() != self.baseline.socket_cookie
            || peer.credentials().pid().get() != self.baseline.pid
            || peer.credentials().uid() != self.baseline.credentials.effective_user_id()
            || peer.credentials().gid() != self.baseline.credentials.effective_group_id()
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        require_peer_matches(peer, self.baseline)?;
        let current = observe(
            &self.subject,
            self.baseline.boot_id,
            self.baseline.socket_cookie,
            self.baseline.pid,
            self.subject.credentials().uid(),
            self.subject.credentials().gid(),
        )?;
        if current == self.baseline {
            Ok(())
        } else {
            Err(SourceProviderSecurityError::SessionContinuity)
        }
    }

    pub(crate) fn has_same_execution(&self, other: &Self) -> bool {
        self.baseline == other.baseline
    }

    pub(crate) const fn boot_id(&self) -> [u8; 16] {
        self.baseline.boot_id
    }

    pub(crate) const fn pid(&self) -> u32 {
        self.baseline.pid
    }

    pub(crate) const fn tgid(&self) -> u32 {
        self.baseline.tgid
    }

    pub(crate) const fn parent_pid(&self) -> u32 {
        self.baseline.parent_pid
    }

    pub(crate) const fn start_time_ticks(&self) -> u64 {
        self.baseline.start_time_ticks
    }

    pub(crate) const fn cgroup_id(&self) -> u64 {
        self.baseline.cgroup_id
    }

    pub(crate) const fn cgroup_path_digest(&self) -> [u8; 32] {
        self.baseline.cgroup_path_digest
    }

    pub(crate) const fn credentials(&self) -> PidFdCredentials {
        self.baseline.credentials
    }

    pub(crate) fn is_alive(&self) -> Result<bool, SourceProviderSecurityError> {
        self.subject
            .is_alive()
            .map_err(|_| SourceProviderSecurityError::ExecutionChanged)
    }

    pub(crate) fn mount_namespace(&self) -> Result<NamespaceFd, SourceProviderSecurityError> {
        self.subject
            .pidfd()
            .namespace(NamespaceKind::Mount)
            .map_err(|_| SourceProviderSecurityError::DescriptorObservation)
    }

    pub(crate) fn require_mount_namespace(
        &self,
        expected: &NamespaceFd,
    ) -> Result<(), SourceProviderSecurityError> {
        let current = self.mount_namespace()?;
        if current.identity() == expected.identity() {
            Ok(())
        } else {
            Err(SourceProviderSecurityError::DescriptorObservation)
        }
    }
}

fn require_peer_matches(
    peer: &ConnectionPeerIdentity,
    expected: RemoteBaselineV1,
) -> Result<(), SourceProviderSecurityError> {
    let boot_before = CurrentKernelBootV1::capture()?;
    let info_before = peer
        .pidfd()
        .info()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let identity = peer
        .pidfd()
        .process_identity()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let info_after = peer
        .pidfd()
        .info()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let alive = peer
        .is_alive()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let boot_after = CurrentKernelBootV1::capture()?;
    let matches = boot_before.boot_id() == expected.boot_id
        && boot_after.boot_id() == expected.boot_id
        && info_before == info_after
        && alive
        && info_before.pid() == expected.pid
        && info_before.thread_group_id() == expected.tgid
        && info_before.credentials() == Some(expected.credentials)
        && info_before.cgroup_id() == Some(expected.cgroup_id)
        && identity.pid() == expected.pid
        && identity.thread_group_id() == expected.tgid
        && identity.parent_pid() == info_before.parent_pid()
        && identity.cgroup_id() == Some(expected.cgroup_id)
        && identity.start_time_ticks() == expected.start_time_ticks;
    if matches {
        Ok(())
    } else {
        Err(SourceProviderSecurityError::SessionContinuity)
    }
}

fn observe(
    subject: &KernelAuthorizedRecordSubject,
    expected_boot: [u8; 16],
    socket_cookie: u64,
    expected_pid: u32,
    nominated_uid: u32,
    nominated_gid: u32,
) -> Result<RemoteBaselineV1, SourceProviderSecurityError> {
    let boot_before = CurrentKernelBootV1::capture()?;
    let info_before = subject
        .pidfd()
        .info()
        .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?;
    let identity = subject
        .pidfd()
        .process_identity()
        .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?;
    let (cgroup_path_digest, _) = read_cgroup_path_digest(expected_pid)?;
    let info_after = subject
        .pidfd()
        .info()
        .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?;
    let alive = subject
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
    remote_baseline_from(
        info_before,
        identity,
        expected_boot,
        socket_cookie,
        expected_pid,
        nominated_uid,
        nominated_gid,
        cgroup_path_digest,
    )
}

#[allow(clippy::too_many_arguments)]
fn remote_baseline_from(
    info: PidFdInfo,
    identity: PidFdProcessIdentity,
    boot_id: [u8; 16],
    socket_cookie: u64,
    expected_pid: u32,
    nominated_uid: u32,
    nominated_gid: u32,
    cgroup_path_digest: [u8; 32],
) -> Result<RemoteBaselineV1, SourceProviderSecurityError> {
    let credentials = info
        .credentials()
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let cgroup_id = info
        .cgroup_id()
        .filter(|value| *value != 0)
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let exact = info.pid() == expected_pid
        && info.thread_group_id() == expected_pid
        && identity.pid() == info.pid()
        && identity.thread_group_id() == info.thread_group_id()
        && identity.parent_pid() == info.parent_pid()
        && identity.cgroup_id() == Some(cgroup_id)
        && identity.start_time_ticks() != 0
        && credentials.effective_user_id() == nominated_uid
        && credentials.effective_group_id() == nominated_gid
        && cgroup_path_digest != [0; 32]
        && socket_cookie != 0;
    if !exact {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(RemoteBaselineV1 {
        boot_id,
        pid: expected_pid,
        tgid: expected_pid,
        parent_pid: info.parent_pid(),
        start_time_ticks: identity.start_time_ticks(),
        cgroup_id,
        cgroup_path_digest,
        credentials,
        socket_cookie,
    })
}
