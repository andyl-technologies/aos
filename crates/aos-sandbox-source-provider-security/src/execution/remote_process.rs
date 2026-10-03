//! Retained remote execution evidence from one descriptor-subject record.

use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind};
use aos_sandbox_linux::pidfd::{PidFd, PidFdCredentials, PidFdInfo, PidFdProcessIdentity};
use aos_sandbox_linux::seqpacket::{ConnectionPeerIdentity, KernelAuthorizedRecordSubject};

use super::{
    CurrentKernelBootV1, SelectedExecutionRoleV1, SelectedPeerEstablishmentV1,
    read_cgroup_path_digest, require_selected_provider_cgroup,
};
use crate::SourceProviderSecurityError;
use crate::carrier::{ReceivedSourceProviderRecordV1, RetainedSourceProviderRecordV5};

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
    selected_role: Option<SelectedExecutionRoleV1>,
    pid1_establishment: Option<RemoteBaselineV1>,
}

impl ProcessExecutionEvidenceV1 {
    pub(crate) fn capture(
        peer: &ConnectionPeerIdentity,
        subject: KernelAuthorizedRecordSubject,
    ) -> Result<Self, SourceProviderSecurityError> {
        Self::capture_retaining(peer, subject).map_err(|(error, _subject)| error)
    }

    /// Returns the original subject pin if any baseline observation fails.
    pub(crate) fn capture_retaining(
        peer: &ConnectionPeerIdentity,
        subject: KernelAuthorizedRecordSubject,
    ) -> Result<Self, (SourceProviderSecurityError, KernelAuthorizedRecordSubject)> {
        let baseline = match Self::capture_baseline(peer, &subject) {
            Ok(baseline) => baseline,
            Err(error) => return Err((error, subject)),
        };
        Ok(Self {
            subject,
            baseline,
            selected_role: None,
            pid1_establishment: None,
        })
    }

    /// Observes the actual subject while its entire typed packet remains parked.
    ///
    /// The baseline never escapes as caller-nominated DATA. Only after the
    /// existing complete observation succeeds are the same subject and packet
    /// moved directly into bound execution custody, without postchecks.
    pub(crate) fn capture_parked_record(
        peer: &ConnectionPeerIdentity,
        slot: &mut Option<RetainedSourceProviderRecordV5>,
    ) -> Result<(), SourceProviderSecurityError> {
        let Some(RetainedSourceProviderRecordV5::Received(received)) = slot.as_ref() else {
            return Err(SourceProviderSecurityError::SessionContinuity);
        };
        let baseline = Self::capture_baseline(peer, received.subject())?;

        // Exclusive custody and the checked variant cannot change across the
        // observation. The final region contains only ownership transfers.
        if let Some(RetainedSourceProviderRecordV5::Received(received)) = slot.take() {
            let (payload, subject, descriptors) = received.into_parts();
            *slot = Some(RetainedSourceProviderRecordV5::Bound(
                ReceivedSourceProviderRecordV1 {
                    payload,
                    descriptors,
                    execution: Self {
                        subject,
                        baseline,
                        selected_role: None,
                        pid1_establishment: None,
                    },
                },
            ));
        }

        Ok(())
    }

    /// Checks selected task subjects while the entire formed record stays parked.
    ///
    /// Direct peers preserve the original strict equality recipe. Only genuine
    /// selected Root custody selects the fixed activated Provider recipe, which
    /// keeps PID1 establishment separate from the actual Source record task.
    pub(crate) fn capture_selected_parked_record(
        peer: &ConnectionPeerIdentity,
        slot: &mut Option<RetainedSourceProviderRecordV5>,
        establishment: SelectedPeerEstablishmentV1,
    ) -> Result<(), SourceProviderSecurityError> {
        let (expected_role, pid1_establishment) = match establishment {
            SelectedPeerEstablishmentV1::Direct(role) => {
                Self::capture_parked_record(peer, slot)?;
                (role, None)
            }
            SelectedPeerEstablishmentV1::ActivatedProvider => {
                let Some(RetainedSourceProviderRecordV5::Received(received)) = slot.as_ref() else {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                };
                let pid1 = capture_pid1_establishment(peer)?;
                let subject = received.subject();
                let credentials = subject.credentials();
                let baseline = observe(
                    subject,
                    pid1.boot_id,
                    peer.socket_cookie().get(),
                    credentials.pid().get(),
                    credentials.uid(),
                    credentials.gid(),
                )?;
                require_selected_provider_cgroup(baseline.pid)?;
                require_pid1_establishment(peer, pid1)?;

                // Both observations precede this infallible original transfer.
                // The caller's same socket fence already covers the raw slot.
                if let Some(RetainedSourceProviderRecordV5::Received(received)) = slot.take() {
                    let (payload, subject, descriptors) = received.into_parts();
                    *slot = Some(RetainedSourceProviderRecordV5::Bound(
                        ReceivedSourceProviderRecordV1 {
                            payload,
                            descriptors,
                            execution: Self {
                                subject,
                                baseline,
                                selected_role: Some(SelectedExecutionRoleV1::Provider),
                                pid1_establishment: Some(pid1),
                            },
                        },
                    ));
                }
                (SelectedExecutionRoleV1::Provider, Some(pid1))
            }
        };
        let Some(RetainedSourceProviderRecordV5::Bound(record)) = slot.as_mut() else {
            return Err(SourceProviderSecurityError::SessionContinuity);
        };
        record.execution.selected_role = Some(expected_role);
        record.execution.pid1_establishment = pid1_establishment;
        record.execution.revalidate(peer)
    }

    fn capture_baseline(
        peer: &ConnectionPeerIdentity,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<RemoteBaselineV1, SourceProviderSecurityError> {
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
            subject,
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
        Ok(baseline)
    }

    pub(crate) fn revalidate(
        &self,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), SourceProviderSecurityError> {
        self.require_selected_tasks(peer)?;

        match self.pid1_establishment {
            Some(pid1) => {
                require_pid1_establishment(peer, pid1)?;
                require_selected_provider_cgroup(self.baseline.pid)?;
            }
            None => {
                if peer.socket_cookie().get() != self.baseline.socket_cookie
                    || peer.credentials().pid().get() != self.baseline.pid
                    || peer.credentials().uid() != self.baseline.credentials.effective_user_id()
                    || peer.credentials().gid() != self.baseline.credentials.effective_group_id()
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                require_peer_matches(peer, self.baseline)?;
            }
        }
        let current = observe(
            &self.subject,
            self.baseline.boot_id,
            self.baseline.socket_cookie,
            self.baseline.pid,
            self.subject.credentials().uid(),
            self.subject.credentials().gid(),
        )?;
        if current == self.baseline {
            if let Some(pid1) = self.pid1_establishment {
                require_selected_provider_cgroup(self.baseline.pid)?;
                require_pid1_establishment(peer, pid1)?;
            }
            self.require_selected_tasks(peer)?;
            Ok(())
        } else {
            Err(SourceProviderSecurityError::SessionContinuity)
        }
    }

    pub(crate) fn has_same_execution(&self, other: &Self) -> bool {
        self.baseline == other.baseline
            && self.selected_role == other.selected_role
            && self.pid1_establishment == other.pid1_establishment
    }

    fn require_selected_tasks(
        &self,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), SourceProviderSecurityError> {
        if let Some(role) = self.selected_role {
            if self.pid1_establishment.is_none() {
                role.require_task(peer.pidfd())?;
            }
            role.require_task(self.subject.pidfd())?;
        }
        Ok(())
    }

    /// Lends shaped DATA from the separate, currently rechecked PID1 original.
    pub(crate) fn pid1_establishment_identity(
        &self,
        peer: &ConnectionPeerIdentity,
    ) -> Result<Option<aos_sandbox_source_provider_protocol::SourceProviderProcessIdentityV1>, SourceProviderSecurityError> {
        let Some(pid1) = self.pid1_establishment else {
            return Ok(None);
        };
        require_pid1_establishment(peer, pid1)?;
        aos_sandbox_source_provider_protocol::SourceProviderProcessIdentityV1::new(
            pid1.credentials.effective_user_id(),
            pid1.credentials.effective_group_id(),
            pid1.tgid,
            pid1.start_time_ticks,
            super::cgroup_object_digest(pid1.cgroup_path_digest),
            peer.is_alive()
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?,
        )
        .map(Some)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)
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

fn capture_pid1_establishment(
    peer: &ConnectionPeerIdentity,
) -> Result<RemoteBaselineV1, SourceProviderSecurityError> {
    require_pid1_subject(peer)?;
    let boot = CurrentKernelBootV1::capture()?;
    let baseline = observe_process(
        peer.pidfd(),
        boot.boot_id(),
        peer.socket_cookie().get(),
        1,
        0,
        0,
    )?;
    if peer.initial_info().pid() != baseline.pid
        || peer.initial_info().thread_group_id() != baseline.tgid
        || peer.initial_info().credentials() != Some(baseline.credentials)
        || peer.initial_info().cgroup_id() != Some(baseline.cgroup_id)
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    require_pid1_establishment(peer, baseline)?;
    Ok(baseline)
}

fn require_pid1_establishment(
    peer: &ConnectionPeerIdentity,
    expected: RemoteBaselineV1,
) -> Result<(), SourceProviderSecurityError> {
    require_pid1_subject(peer)?;
    if peer.socket_cookie().get() != expected.socket_cookie
        || expected.pid != 1
        || expected.tgid != 1
        || expected.credentials.real_user_id() != 0
        || expected.credentials.real_group_id() != 0
        || expected.credentials.effective_user_id() != 0
        || expected.credentials.effective_group_id() != 0
        || expected.credentials.saved_user_id() != 0
        || expected.credentials.saved_group_id() != 0
        || expected.credentials.filesystem_user_id() != 0
        || expected.credentials.filesystem_group_id() != 0
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    require_peer_matches(peer, expected)?;
    let observed = observe_process(
        peer.pidfd(),
        expected.boot_id,
        expected.socket_cookie,
        1,
        0,
        0,
    )?;
    if observed != expected {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    require_pid1_subject(peer)
}

fn require_pid1_subject(
    peer: &ConnectionPeerIdentity,
) -> Result<(), SourceProviderSecurityError> {
    if peer.credentials().pid().get() != 1
        || peer.credentials().uid() != 0
        || peer.credentials().gid() != 0
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    aos_sandbox_linux::selinux_policy::require_enforcing()
        .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?;
    if aos_sandbox_linux::guest_confinement::task_has_subject(
        peer.pidfd(),
        "system_u:system_r:init_t:s0",
    )
    .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?
    {
        Ok(())
    } else {
        Err(SourceProviderSecurityError::ExecutionChanged)
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
    observe_process(
        subject.pidfd(),
        expected_boot,
        socket_cookie,
        expected_pid,
        nominated_uid,
        nominated_gid,
    )
}

fn observe_process(
    process: &PidFd,
    expected_boot: [u8; 16],
    socket_cookie: u64,
    expected_pid: u32,
    nominated_uid: u32,
    nominated_gid: u32,
) -> Result<RemoteBaselineV1, SourceProviderSecurityError> {
    let boot_before = CurrentKernelBootV1::capture()?;
    let info_before = process
        .info()
        .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?;
    let identity = process
        .process_identity()
        .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?;
    let (cgroup_path_digest, _) = read_cgroup_path_digest(expected_pid)?;
    let info_after = process
        .info()
        .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?;
    let alive = process
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
