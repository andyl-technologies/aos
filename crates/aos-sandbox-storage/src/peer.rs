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

    /// Rechecks the retained service cgroup before accepting another request.
    ///
    /// # Errors
    ///
    /// Returns an error if the cgroup was retired or replaced.
    pub fn validate_current(&self) -> Result<(), StorageServiceError> {
        self.host_cgroup.validate_current().map_err(Into::into)
    }

    pub(crate) fn verify_connection(&self, peer: &ConnectionPeerIdentity) -> Result<PidFdInfo, ()> {
        let credentials = peer.credentials();
        if credentials.uid() != 0 || credentials.gid() != 0 {
            return Err(());
        }
        let info = self
            .host_cgroup
            .verify_exact_membership(peer.pidfd())
            .map_err(|_| ())?;
        let pid = credentials.pid().get();
        if info.pid() != pid || info.thread_group_id() != pid || !peer.is_alive().map_err(|_| ())? {
            return Err(());
        }
        Ok(info)
    }

    pub(crate) fn verify_record(
        &self,
        expected: PidFdInfo,
        peer: &ConnectionPeerIdentity,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<(), ()> {
        let current = self.verify_connection(peer)?;
        let credentials = subject.credentials();
        if !same_process(current, expected)
            || credentials.uid() != 0
            || credentials.gid() != 0
            || credentials.pid().get() != expected.pid()
            || !subject.is_alive().map_err(|_| ())?
        {
            return Err(());
        }
        let record_info = self
            .host_cgroup
            .verify_exact_membership(subject.pidfd())
            .map_err(|_| ())?;
        if !same_process(record_info, expected) {
            return Err(());
        }
        self.verify_connection(peer).and_then(|current| {
            if same_process(current, expected) {
                Ok(())
            } else {
                Err(())
            }
        })
    }
}
