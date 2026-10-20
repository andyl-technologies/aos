//! Exact node-controller execution verification for Storage RPC.
//!
//! Connection establishment and every record carry independent kernel pidfds
//! and credentials. Storage first verifies the establisher before reading any
//! bytes, then sandwiches request-record verification between fresh checks of
//! that same live leader in the retained controller service cgroup.

use aos_proto::aos::sandbox::local::v1::Audience;
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::{ConnectionPeerIdentity, KernelAuthorizedRecordSubject};
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};

use crate::service::StorageServiceError;

/// Identifies the configured live controller execution for one connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerExecution {
    info: PidFdInfo,
    credentials: PeerCredentials,
}

impl ControllerExecution {
    /// Returns the credentials bound to protocol negotiation and request headers.
    #[must_use]
    pub(crate) const fn credentials(self) -> PeerCredentials {
        self.credentials
    }
}

/// Retains the exact controller cgroup and fixed local-account policy.
#[derive(Debug)]
pub struct ControllerPeerVerifier {
    controller_cgroup: RetainedCgroupAnchor,
    policy: PeerPolicy,
}

impl ControllerPeerVerifier {
    /// Constructs a verifier around the deployment-selected controller cgroup.
    ///
    /// # Errors
    ///
    /// Returns [`StorageServiceError`] when the retained cgroup is no longer an
    /// active cgroup-v2 directory.
    pub fn new(
        controller_cgroup: RetainedCgroupAnchor,
        controller_identity: (u32, u32),
    ) -> Result<Self, StorageServiceError> {
        if !(1..65_536).contains(&controller_identity.0)
            || !(1..65_536).contains(&controller_identity.1)
        {
            return Err(StorageServiceError::Activation(
                "controller UID and GID must both be in 1..65535".to_owned(),
            ));
        }
        controller_cgroup.validate_current()?;

        Ok(Self {
            controller_cgroup,
            policy: PeerPolicy {
                uid: controller_identity.0,
                gid: Some(controller_identity.1),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
        })
    }

    /// Returns the fixed protocol peer policy.
    #[must_use]
    pub const fn policy(&self) -> PeerPolicy {
        self.policy
    }

    /// Revalidates the retained controller cgroup before accepting a peer.
    ///
    /// # Errors
    ///
    /// Returns [`StorageServiceError`] when the cgroup has been retired or
    /// replaced.
    pub fn validate_current(&self) -> Result<(), StorageServiceError> {
        self.controller_cgroup
            .validate_current()
            .map_err(Into::into)
    }

    /// Verifies a connection establisher before any peer bytes are read.
    ///
    /// # Errors
    ///
    /// Returns `()` for every account, cgroup, process-leader, pidfd, liveness,
    /// or kernel-identity mismatch.
    pub(crate) fn verify_connection(
        &self,
        peer: &ConnectionPeerIdentity,
    ) -> Result<ControllerExecution, ()> {
        let observed = peer.credentials();
        if observed.uid() != self.policy.uid
            || self
                .policy
                .gid
                .is_some_and(|expected| observed.gid() != expected)
        {
            return Err(());
        }
        let info = self
            .controller_cgroup
            .verify_exact_membership(peer.pidfd())
            .map_err(|_| ())?;
        let pid = observed.pid().get();
        if info.pid() != pid || info.thread_group_id() != pid || !peer.is_alive().map_err(|_| ())? {
            return Err(());
        }

        Ok(ControllerExecution {
            info,
            credentials: PeerCredentials {
                uid: observed.uid(),
                gid: observed.gid(),
                pid: Some(pid),
            },
        })
    }

    /// Rechecks the original connection execution immediately before effects.
    pub(crate) fn recheck_connection(
        &self,
        expected: ControllerExecution,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), ()> {
        let current = self.verify_connection(peer)?;
        if current.credentials != expected.credentials || !same_process(current.info, expected.info)
        {
            return Err(());
        }

        Ok(())
    }

    /// Binds one record subject to the already verified connection execution.
    pub(crate) fn verify_record(
        &self,
        expected: ControllerExecution,
        peer: &ConnectionPeerIdentity,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<(), ()> {
        self.recheck_connection(expected, peer)?;
        let observed = subject.credentials();
        if observed.uid() != expected.credentials.uid
            || observed.gid() != expected.credentials.gid
            || observed.pid().get() != expected.credentials.pid.ok_or(())?
        {
            return Err(());
        }
        let current = self
            .controller_cgroup
            .verify_exact_membership(subject.pidfd())
            .map_err(|_| ())?;
        let pid = observed.pid().get();
        if current.pid() != pid
            || current.thread_group_id() != pid
            || !subject.is_alive().map_err(|_| ())?
            || !same_process(current, expected.info)
        {
            return Err(());
        }
        self.recheck_connection(expected, peer)
    }
}

fn same_process(left: PidFdInfo, right: PidFdInfo) -> bool {
    left.pid() == right.pid()
        && left.thread_group_id() == right.thread_group_id()
        && left.cgroup_id() == right.cgroup_id()
}

fn verify_root_service_connection(
    cgroup: &RetainedCgroupAnchor,
    peer: &ConnectionPeerIdentity,
) -> Result<PidFdInfo, ()> {
    verify_root_service_connection_typed(cgroup, peer).map_err(|_| ())
}

/// Keeps policy refusal distinct from the original Linux observation failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RootServicePeerError {
    /// The observed account or process relation does not match the closed role.
    #[error("root service peer provenance did not match")]
    PolicyMismatch,
    /// The original membership or liveness observation failed.
    #[error("root service peer observation failed: {0}")]
    Linux(#[from] aos_sandbox_linux::Error),
    /// The caller retains the reached native prefix and borrows its real cause.
    #[error("root service native observation is retained by its original")]
    RetainedObservation,
}

fn verify_root_service_connection_typed(
    cgroup: &RetainedCgroupAnchor,
    peer: &ConnectionPeerIdentity,
) -> Result<PidFdInfo, RootServicePeerError> {
    verify_root_service_connection_engine(cgroup, peer, None)
}

fn verify_root_service_connection_engine(
    cgroup: &RetainedCgroupAnchor,
    peer: &ConnectionPeerIdentity,
    mut retained: Option<&mut RootServiceConnectionOriginalV2>,
) -> Result<PidFdInfo, RootServicePeerError> {
    let credentials = peer.credentials();
    if credentials.uid() != 0 || credentials.gid() != 0 {
        return Err(RootServicePeerError::PolicyMismatch);
    }
    let info = match retained.as_deref_mut() {
        None => cgroup.verify_exact_membership(peer.pidfd())?,
        Some(original) => {
            original.membership.capture_once(cgroup, peer.pidfd(), None)
                .map_err(|_| RootServicePeerError::RetainedObservation)?;
            original.membership.completed_info().ok_or(RootServicePeerError::RetainedObservation)?
        }
    };
    let pid = credentials.pid().get();
    if info.pid() != pid || info.thread_group_id() != pid || !match retained {
        None => peer.is_alive()?,
        Some(original) => {
            original.alive = Some(peer.is_alive());
            match original.alive.as_ref() {
                Some(Ok(alive)) => *alive,
                _ => return Err(RootServicePeerError::RetainedObservation),
            }
        }
    } {
        return Err(RootServicePeerError::PolicyMismatch);
    }
    Ok(info)
}

fn verify_root_service_record(
    cgroup: &RetainedCgroupAnchor,
    expected: PidFdInfo,
    peer: &ConnectionPeerIdentity,
    subject: &KernelAuthorizedRecordSubject,
) -> Result<(), ()> {
    verify_root_service_record_typed(cgroup, expected, peer, subject).map_err(|_| ())
}

fn verify_root_service_record_typed(
    cgroup: &RetainedCgroupAnchor,
    expected: PidFdInfo,
    peer: &ConnectionPeerIdentity,
    subject: &KernelAuthorizedRecordSubject,
) -> Result<(), RootServicePeerError> {
    verify_root_service_record_engine(cgroup, expected, peer, subject, None)
}

fn verify_root_service_record_engine(
    cgroup: &RetainedCgroupAnchor,
    expected: PidFdInfo,
    peer: &ConnectionPeerIdentity,
    subject: &KernelAuthorizedRecordSubject,
    mut retained: Option<&mut RootServiceRecordOriginalV2>,
) -> Result<(), RootServicePeerError> {
    // Recheck the original connection both before and after authenticating
    // the independently reported record subject.
    let current = verify_root_service_connection_engine(
        cgroup, peer, retained.as_deref_mut().map(|original| &mut original.before),
    )?;
    let credentials = subject.credentials();
    if !same_process(current, expected)
        || credentials.uid() != 0
        || credentials.gid() != 0
        || credentials.pid().get() != expected.pid()
        || !match retained.as_deref_mut() {
            None => subject.is_alive()?,
            Some(original) => {
                original.alive = Some(subject.is_alive());
                match original.alive.as_ref() {
                    Some(Ok(alive)) => *alive,
                    _ => return Err(RootServicePeerError::RetainedObservation),
                }
            }
        }
    {
        return Err(RootServicePeerError::PolicyMismatch);
    }
    let record_info = match retained.as_deref_mut() {
        None => cgroup.verify_exact_membership(subject.pidfd())?,
        Some(original) => {
            original.membership.capture_once(cgroup, subject.pidfd(), None)
                .map_err(|_| RootServicePeerError::RetainedObservation)?;
            original.membership.completed_info().ok_or(RootServicePeerError::RetainedObservation)?
        }
    };
    if !same_process(record_info, expected) {
        return Err(RootServicePeerError::PolicyMismatch);
    }
    let after = verify_root_service_connection_engine(
        cgroup, peer, retained.as_deref_mut().map(|original| &mut original.after),
    )?;
    if !same_process(after, expected) {
        return Err(RootServicePeerError::PolicyMismatch);
    }
    Ok(())
}

/// Retains one existing connection-membership/liveness observation.
///
/// Empty construction does not admit a peer or pay an observation. The sole
/// caller prepays this representation and stores its complete typed result.
pub(crate) struct RootServiceConnectionOriginalV2 {
    membership: aos_sandbox_linux::cgroup::RuntimeScopeMembershipOriginalV1,
    alive: Option<Result<bool, aos_sandbox_linux::Error>>,
    result: Option<Result<PidFdInfo, RootServicePeerError>>,
}

impl RootServiceConnectionOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            membership: aos_sandbox_linux::cgroup::RuntimeScopeMembershipOriginalV1::new(),
            alive: None,
            result: None,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.membership.failure().map(|cause| cause as _)
            .or_else(|| self.alive.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    pub(crate) fn completed_info(&self) -> Option<PidFdInfo> {
        self.result.as_ref()?.as_ref().ok().copied()
    }

    pub(crate) fn receiving_demand_v2() -> Option<(usize, usize)> {
        let (bytes, files, _) = aos_sandbox_linux::cgroup::RuntimeScopeMembershipOriginalV1::exact_receiving_demand_v1()?;
        Some((bytes.checked_add(3 * std::mem::size_of::<Self>())?, files))
    }
}

/// Retains the exact old before/subject/after record-membership sandwich.
pub(crate) struct RootServiceRecordOriginalV2 {
    before: RootServiceConnectionOriginalV2,
    alive: Option<Result<bool, aos_sandbox_linux::Error>>,
    membership: aos_sandbox_linux::cgroup::RuntimeScopeMembershipOriginalV1,
    after: RootServiceConnectionOriginalV2,
    result: Option<Result<(), RootServicePeerError>>,
}

impl RootServiceRecordOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            before: RootServiceConnectionOriginalV2::new(),
            alive: None,
            membership: aos_sandbox_linux::cgroup::RuntimeScopeMembershipOriginalV1::new(),
            after: RootServiceConnectionOriginalV2::new(),
            result: None,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before.failure()
            .or_else(|| self.alive.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.membership.failure().map(|cause| cause as _))
            .or_else(|| self.after.failure())
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    pub(crate) fn receiving_demand_v2() -> Option<(usize, usize)> {
        let (connection_bytes, connection_files) = RootServiceConnectionOriginalV2::receiving_demand_v2()?;
        let (bytes, files, _) = aos_sandbox_linux::cgroup::RuntimeScopeMembershipOriginalV1::exact_receiving_demand_v1()?;
        Some((connection_bytes.checked_mul(2)?.checked_add(bytes)?
            .checked_add(3 * std::mem::size_of::<Self>())?,
            connection_files.checked_mul(2)?.checked_add(files)?))
    }
}

/// Keeps both independent subject bookends after an entered root request.
pub(crate) struct RootServiceSubjectPostOriginalV2 {
    alive: Option<Result<bool, aos_sandbox_linux::Error>>,
    membership: aos_sandbox_linux::cgroup::RuntimeScopeMembershipOriginalV1,
    result: Option<Result<(), RootServicePeerError>>,
}

impl RootServiceSubjectPostOriginalV2 {
    pub(crate) fn new() -> Self {
        Self { alive: None,
            membership: aos_sandbox_linux::cgroup::RuntimeScopeMembershipOriginalV1::new(),
            result: None }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.alive.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.membership.failure().map(|cause| cause as _))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

/// Pins the exact root-account Host service allowed to request root mounts.
#[derive(Debug)]
pub struct HostRootExportPeerVerifier {
    host_cgroup: RetainedCgroupAnchor,
}

impl HostRootExportPeerVerifier {
    /// Retains the deployment's exact Host broker service cgroup.
    ///
    /// # Errors
    ///
    /// Returns an error if the cgroup is not active.
    pub fn new(host_cgroup: RetainedCgroupAnchor) -> Result<Self, StorageServiceError> {
        host_cgroup.validate_current()?;
        Ok(Self { host_cgroup })
    }

    // Only the fixed Host service capture supplies this already checked pair.
    // Do not add the ordinary constructor's second active-file probe: its
    // partial failure would be outside the actual retained capture owner.
    pub(crate) fn take_fixed_capture_v2(
        original: &mut aos_sandbox_linux::cgroup::ControllerStartupHostCgroupReadbackV1,
    ) -> Result<(aos_sandbox_linux::cgroup::CgroupV2Root, Self), StorageServiceError> {
        let (root, host_cgroup) = original.take_validated_pair().ok_or_else(|| {
            StorageServiceError::Kernel(aos_sandbox_linux::Error::InvalidInput {
                field: "Storage root-export Host cgroup",
                message: "fixed original capture incomplete or refused".into(),
            })
        })?;
        Ok((root, Self { host_cgroup }))
    }

    /// Rechecks the retained service cgroup before accepting another request.
    ///
    /// # Errors
    ///
    /// Returns an error if the cgroup was retired or replaced.
    pub fn validate_current(&self) -> Result<(), StorageServiceError> {
        self.host_cgroup.validate_current().map_err(Into::into)
    }

    pub(crate) fn verify_connection_retaining_v2(
        &self,
        peer: &ConnectionPeerIdentity,
        original: &mut RootServiceConnectionOriginalV2,
    ) -> Result<PidFdInfo, RootServicePeerError> {
        if original.result.is_some() {
            return Err(RootServicePeerError::PolicyMismatch);
        }
        original.result = Some(verify_root_service_connection_engine(
            &self.host_cgroup, peer, Some(original),
        ));
        original.completed_info().ok_or(RootServicePeerError::RetainedObservation)
    }

    pub(crate) fn verify_record_retaining_v2(
        &self,
        expected: PidFdInfo,
        peer: &ConnectionPeerIdentity,
        subject: &KernelAuthorizedRecordSubject,
        original: &mut RootServiceRecordOriginalV2,
    ) -> Result<(), RootServicePeerError> {
        if original.result.is_some() {
            return Err(RootServicePeerError::PolicyMismatch);
        }
        original.result = Some(verify_root_service_record_engine(
            &self.host_cgroup, expected, peer, subject, Some(original),
        ));
        if matches!(original.result, Some(Ok(()))) { Ok(()) }
        else { Err(RootServicePeerError::RetainedObservation) }
    }

    // A final failed connection bookend cannot suppress the independently
    // owed record-subject probes. Both use the existing native engines and
    // retained destinations; only the pure result conjunction is evaluated last.
    pub(crate) fn observe_record_subject_owed_v2(
        &self,
        expected: PidFdInfo,
        subject: &KernelAuthorizedRecordSubject,
        original: &mut RootServiceSubjectPostOriginalV2,
    ) -> Result<(), RootServicePeerError> {
        if original.result.is_some() {
            return Err(RootServicePeerError::PolicyMismatch);
        }
        original.alive = Some(subject.is_alive());
        let observed = original.membership.capture_once(&self.host_cgroup, subject.pidfd(), None);
        original.result = Some((|| {
            if !matches!(original.alive, Some(Ok(true))) || observed.is_err() {
                return Err(RootServicePeerError::RetainedObservation);
            }
            let current = original.membership.completed_info()
                .ok_or(RootServicePeerError::RetainedObservation)?;
            let credentials = subject.credentials();
            if credentials.uid() != 0 || credentials.gid() != 0
                || credentials.pid().get() != expected.pid()
                || !same_process(current, expected)
            { return Err(RootServicePeerError::PolicyMismatch); }
            Ok(())
        })());
        if matches!(original.result, Some(Ok(()))) { Ok(()) }
        else { Err(RootServicePeerError::RetainedObservation) }
    }

    pub(crate) fn verify_connection(&self, peer: &ConnectionPeerIdentity) -> Result<PidFdInfo, ()> {
        verify_root_service_connection(&self.host_cgroup, peer)
    }

    pub(crate) fn verify_record(
        &self,
        expected: PidFdInfo,
        peer: &ConnectionPeerIdentity,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<(), ()> {
        verify_root_service_record(&self.host_cgroup, expected, peer, subject)
    }
}

/// Pins the sole root-account SourceProvider service allowed to submit plans.
#[derive(Debug)]
pub struct ProviderLiveExportPeerVerifier {
    provider_cgroup: RetainedCgroupAnchor,
}

impl ProviderLiveExportPeerVerifier {
    /// Retains the deployment's exact SourceProvider service cgroup.
    ///
    /// # Errors
    ///
    /// Returns an error if the cgroup is not active.
    pub fn new(provider_cgroup: RetainedCgroupAnchor) -> Result<Self, StorageServiceError> {
        provider_cgroup.validate_current()?;
        Ok(Self { provider_cgroup })
    }

    /// Rechecks the retained service cgroup before accepting a request.
    ///
    /// # Errors
    ///
    /// Returns an error if the cgroup was retired or replaced.
    pub fn validate_current(&self) -> Result<(), StorageServiceError> {
        self.provider_cgroup.validate_current().map_err(Into::into)
    }

    pub(crate) fn verify_connection(&self, peer: &ConnectionPeerIdentity) -> Result<PidFdInfo, ()> {
        verify_root_service_connection(&self.provider_cgroup, peer)
    }

    /// Retains the actual observation cause for a Storage-private consumer.
    ///
    /// # Errors
    ///
    /// Refuses a root-role mismatch or retains the exact Linux observation error.
    pub(crate) fn verify_connection_typed(
        &self,
        peer: &ConnectionPeerIdentity,
    ) -> Result<PidFdInfo, RootServicePeerError> {
        verify_root_service_connection_typed(&self.provider_cgroup, peer)
    }

    pub(crate) fn verify_record(
        &self,
        expected: PidFdInfo,
        peer: &ConnectionPeerIdentity,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<(), ()> {
        verify_root_service_record(&self.provider_cgroup, expected, peer, subject)
    }

    /// Reuses the same currentness sandwich without erasing its Linux cause.
    ///
    /// # Errors
    ///
    /// Refuses an execution mismatch or retains the exact Linux observation error.
    pub(crate) fn verify_record_typed(
        &self,
        expected: PidFdInfo,
        peer: &ConnectionPeerIdentity,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<(), RootServicePeerError> {
        verify_root_service_record_typed(&self.provider_cgroup, expected, peer, subject)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_peer_failure_keeps_policy_and_linux_observation_distinct() {
        use std::error::Error as _;

        assert!(RootServicePeerError::PolicyMismatch.source().is_none());
        let error = RootServicePeerError::Linux(
            aos_sandbox_linux::Error::WrongDescriptorType {
                expected: "cgroup",
            },
        );

        let RootServicePeerError::Linux(cause) = &error else {
            panic!("Linux observation was reclassified as policy refusal");
        };
        let source = error.source().unwrap();
        assert!(std::ptr::eq(
            source.downcast_ref::<aos_sandbox_linux::Error>().unwrap(),
            cause,
        ));
    }
}
