//! Retained kernel authentication for namespace-inspector peers.
//!
//! Socket credentials and pidfds identify a kernel subject but do not establish
//! its application role. This module binds those subjects to the root UID/GID
//! snapshot supplied by `SO_PEERCRED` or `SCM_CREDENTIALS`, a strictly resolved
//! cgroup-v2 object, a provisioned executable inode, and the exact effective
//! SELinux domain observed through procfs. Every pidfd observation must include
//! Linux 6.18's complete credential tuple. All eight IDs must remain root and
//! the effective IDs must agree with the historical `SO_PEERCRED` or
//! `SCM_CREDENTIALS` nomination.
//!
//! Process inspection is deliberately a repeated observation, not a claim of
//! global atomicity or proof that a mutable value never changed and changed
//! back. The verifier compares pidfd identity and credentials, exact cgroup
//! membership, executable inode, and MAC context around the central
//! observations, then finishes with pidfd liveness. A process can still change
//! immediately after admission; callers must retain the returned evidence and
//! revalidate it at the effect boundary.
//!
//! An exact process label does not prove that SELinux is globally enabled or
//! enforcing, nor that the loaded policy has the required negative rules. The
//! procfs inode labels available to SELinux identify the target task and inode
//! class, not the individual `stat`, `attr/current`, or `exe` pathname. Policy
//! allowing these observations therefore also exposes other same-class procfs
//! entries for that exact target when their additional kernel checks permit it.
//! Production integration must explicitly qualify and accept that target-wide
//! surface with compensating syscall/kernel confinement, or replace these
//! procfs observations with an independently reviewed mechanism.
//!
//! The production inspector composes this verifier with protected deployment
//! credentials and the native systemd-manager query. Its SELinux deployment is
//! still a qualification prerequisite: exact labels do not establish that the
//! loaded policy is enforcing. This evidence-only path does not construct
//! Network mutation or readiness authority.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::{PidFd, PidFdCredentials, PidFdInfo, PidFdProcessIdentity};
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, KernelAuthorizedRecordSubject, PeerCredentials, RecordCredentials,
};
use aos_sandbox_linux::unix_stream::{UnixStreamPeerCredentials, UnixStreamPeerIdentity};

use super::{
    InspectorProcessIdentityV1, KernelAuthenticatedInspectorPeerV1,
    KernelAuthenticatedSystemdManagerV1, NetworkNamespaceInspectorPeerRoleV1,
};
use crate::systemd_socket_instance::validate_systemd_socket_instance_fields;

const BROKER_CGROUP: &str = "aos.slice/aos-control.slice/aos-netd.service";
const INSPECTOR_CGROUP_PREFIX: &str =
    "aos.slice/aos-control.slice/aos-sandbox-network-namespace-inspector@";
const INSPECTOR_CGROUP_SUFFIX: &str = ".service";
const BROKER_MAC_CONTEXT: &[u8] = b"system_u:system_r:aos_sandbox_network_publisher_t";
const INSPECTOR_MAC_CONTEXT: &[u8] = b"system_u:system_r:aos_sandbox_namespace_inspector_t";
const LIFECYCLE_WORKER_MAC_CONTEXT: &[u8] =
    b"system_u:system_r:aos_sandbox_network_lifecycle_worker_t";
const MANAGER_MAC_CONTEXT: &[u8] = b"system_u:system_r:init_t";
const MAXIMUM_MAC_CONTEXT_BYTES: usize = 256;
const MAXIMUM_PROC_PATH_BYTES: usize = 64;
const MAXIMUM_INSPECTOR_CGROUP_RECORD_BYTES: usize = 4 + 512 + 1;
const ROOT_UID: u32 = 0;
const ROOT_GID: u32 = 0;

/// Rejects an inspector launched outside its fixed SELinux domain before it
/// opens the protected deployment credentials.
pub(super) fn require_current_inspector_mac_context()
-> Result<(), NamespaceInspectorKernelAuthenticationError> {
    let observed = read_effective_mac_context(std::process::id())?;
    if !is_inspector_mac_context(&observed) {
        return Err(NamespaceInspectorKernelAuthenticationError::Mismatch);
    }
    Ok(())
}

fn is_inspector_mac_context(observed: &[u8]) -> bool {
    observed == INSPECTOR_MAC_CONTEXT
}

/// Reports failure to provision or authenticate a namespace-inspector peer.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NamespaceInspectorKernelAuthenticationError {
    /// A trusted descriptor or kernel observation failed.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    /// A fixed executable descriptor or procfs observation failed.
    #[error("namespace-inspector kernel authentication failed during {operation}: {source}")]
    Io {
        /// Names the bounded operation which failed.
        operation: &'static str,
        /// Preserves the kernel error without converting it to a role mismatch.
        #[source]
        source: std::io::Error,
    },
    /// Provisioning supplied an invalid or aliased executable role.
    #[error("namespace-inspector executable provisioning is invalid: {0}")]
    InvalidProvisioning(&'static str),
    /// The observed subject did not satisfy every fixed role property.
    #[error("namespace-inspector kernel subject did not match its fixed role")]
    Mismatch,
}

/// Owns the fixed kernel objects used to authenticate inspector protocol roles.
#[derive(Debug)]
pub(crate) struct NamespaceInspectorKernelVerifierV1 {
    cgroup_root: CgroupV2Root,
    broker_executable: FixedExecutable,
    inspector_executable: FixedExecutable,
    lifecycle_worker_executable: FixedExecutable,
    manager_executable: FixedExecutable,
}

impl NamespaceInspectorKernelVerifierV1 {
    /// Adopts the global cgroup-v2 root and the four provisioned executables.
    ///
    /// The executable descriptors must be close-on-exec regular executable
    /// files. Their retained inode identities must be pairwise distinct. The
    /// caller remains responsible for obtaining them through protected local
    /// provisioning rather than caller-controlled paths. This staged
    /// constructor is not independently a production authority boundary: its
    /// caller must also consume protected deployment policy and run under the
    /// reviewed enforcing SELinux deployment.
    ///
    /// # Errors
    ///
    /// Returns an error when the cgroup root is invalid, an executable is not a
    /// close-on-exec regular executable file, or two role descriptors alias.
    pub(crate) fn from_owned(
        cgroup_root: OwnedFd,
        broker_executable: OwnedFd,
        inspector_executable: OwnedFd,
        lifecycle_worker_executable: OwnedFd,
        manager_executable: OwnedFd,
    ) -> Result<Self, NamespaceInspectorKernelAuthenticationError> {
        let broker_executable = FixedExecutable::from_owned(broker_executable)?;
        let inspector_executable = FixedExecutable::from_owned(inspector_executable)?;
        let lifecycle_worker_executable = FixedExecutable::from_owned(lifecycle_worker_executable)?;
        let manager_executable = FixedExecutable::from_owned(manager_executable)?;

        let identities = [
            broker_executable.identity,
            inspector_executable.identity,
            lifecycle_worker_executable.identity,
            manager_executable.identity,
        ];
        if identities
            .iter()
            .enumerate()
            .any(|(index, identity)| identities[..index].contains(identity))
        {
            return Err(
                NamespaceInspectorKernelAuthenticationError::InvalidProvisioning(
                    "role executables must not alias",
                ),
            );
        }

        Ok(Self {
            cgroup_root: CgroupV2Root::from_owned(cgroup_root)?,
            broker_executable,
            inspector_executable,
            lifecycle_worker_executable,
            manager_executable,
        })
    }

    /// Authenticates and retains the broker which established a connection.
    ///
    /// # Errors
    ///
    /// Returns an error for every credential, descriptor, procfs, liveness, or
    /// fixed-role mismatch. A procfs permission denial is not converted to weak
    /// evidence.
    pub(crate) fn authenticate_broker_connection<'peer>(
        &self,
        peer: &'peer ConnectionPeerIdentity,
    ) -> Result<RetainedInspectorConnectionPeerV1<'peer>, NamespaceInspectorKernelAuthenticationError>
    {
        let evidence = self.authenticate(
            peer.pidfd(),
            peer.initial_info(),
            TransportCredentials::from(peer.credentials()),
            RoleExpectation::broker(&self.broker_executable),
        )?;

        Ok(RetainedInspectorConnectionPeerV1 { peer, evidence })
    }

    /// Authenticates and retains the broker nominated for one received record.
    ///
    /// # Errors
    ///
    /// Returns an error for every credential, descriptor, procfs, liveness, or
    /// fixed-role mismatch. The record subject is consumed so its pidfd remains
    /// retained.
    pub(crate) fn authenticate_broker_record(
        &self,
        subject: KernelAuthorizedRecordSubject,
    ) -> Result<RetainedInspectorRecordSubjectV1, NamespaceInspectorKernelAuthenticationError> {
        let evidence = self.authenticate(
            subject.pidfd(),
            subject.initial_info(),
            TransportCredentials::from(subject.credentials()),
            RoleExpectation::broker(&self.broker_executable),
        )?;

        Ok(RetainedInspectorRecordSubjectV1 { subject, evidence })
    }

    /// Authenticates and retains an inspector record for one manager-provided instance.
    ///
    /// `instance` is a cgroup locator only. A future caller must obtain it from
    /// the authenticated manager activation; caller wire must never select it.
    /// This method does not construct activation evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed instance or any credential, descriptor,
    /// procfs, liveness, or fixed-role mismatch.
    pub(crate) fn authenticate_inspector_record(
        &self,
        subject: KernelAuthorizedRecordSubject,
        instance: &str,
    ) -> Result<RetainedInspectorRecordSubjectV1, NamespaceInspectorKernelAuthenticationError> {
        validate_systemd_socket_instance_fields(instance)
            .map_err(|_| NamespaceInspectorKernelAuthenticationError::Mismatch)?;
        let cgroup = inspector_cgroup(instance)?;
        let evidence = self.authenticate(
            subject.pidfd(),
            subject.initial_info(),
            TransportCredentials::from(subject.credentials()),
            RoleExpectation::inspector(&self.inspector_executable, &cgroup),
        )?;

        Ok(RetainedInspectorRecordSubjectV1 { subject, evidence })
    }

    /// Authenticates and retains PID 1 as the socket-activation connection peer.
    ///
    /// # Errors
    ///
    /// Returns an error unless the connection peer is live PID 1 with root
    /// credentials, exact `init.scope` membership, the provisioned manager
    /// executable, and the fixed `init_t` effective MAC context.
    pub(crate) fn authenticate_manager_connection<'peer>(
        &self,
        peer: &'peer ConnectionPeerIdentity,
    ) -> Result<
        RetainedSystemdManagerConnectionV1<'peer>,
        NamespaceInspectorKernelAuthenticationError,
    > {
        let evidence = self.authenticate(
            peer.pidfd(),
            peer.initial_info(),
            TransportCredentials::from(peer.credentials()),
            RoleExpectation::manager(&self.manager_executable),
        )?;

        Ok(RetainedSystemdManagerConnectionV1 { peer, evidence })
    }

    /// Authenticates PID 1 on a retained connection to the private manager stream.
    ///
    /// # Errors
    ///
    /// Returns an error unless the stream peer is live PID 1 with the exact
    /// root credentials, cgroup, executable, and effective MAC context.
    pub(crate) fn authenticate_manager_stream<'peer>(
        &self,
        peer: &'peer UnixStreamPeerIdentity,
    ) -> Result<RetainedSystemdManagerStreamV1<'peer>, NamespaceInspectorKernelAuthenticationError>
    {
        let evidence = self.authenticate(
            peer.pidfd(),
            peer.initial_info(),
            TransportCredentials::from(peer.credentials()),
            RoleExpectation::manager(&self.manager_executable),
        )?;

        Ok(RetainedSystemdManagerStreamV1 { peer, evidence })
    }

    /// Authenticates the invoking inspector through its independently opened pidfd.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed instance or any credential, cgroup,
    /// executable, MAC, process-identity, or liveness mismatch.
    pub(crate) fn authenticate_inspector_pidfd<'pidfd>(
        &self,
        pidfd: &'pidfd PidFd,
        instance: &str,
    ) -> Result<RetainedInspectorPidFdV1<'pidfd>, NamespaceInspectorKernelAuthenticationError> {
        validate_systemd_socket_instance_fields(instance)
            .map_err(|_| NamespaceInspectorKernelAuthenticationError::Mismatch)?;
        let cgroup = inspector_cgroup(instance)?;
        let initial_info = pidfd.info()?;
        let transport = transport_from_pidfd_info(initial_info)?;
        let evidence = self.authenticate(
            pidfd,
            initial_info,
            transport,
            RoleExpectation::inspector(&self.inspector_executable, &cgroup),
        )?;

        Ok(RetainedInspectorPidFdV1 {
            pidfd,
            initial_info,
            transport,
            evidence,
        })
    }

    /// Authenticates one broker-transferred lifecycle-worker leader pidfd.
    ///
    /// The pidfd is already type-checked by the Linux boundary. Its cgroup
    /// locator comes only from a canonical request that is subsequently
    /// matched to protected expected-attempt policy.
    ///
    /// # Errors
    ///
    /// Returns an error for any credential, cgroup, executable, MAC,
    /// process-identity, or liveness mismatch.
    pub(crate) fn authenticate_lifecycle_worker_pidfd<'pidfd>(
        &self,
        pidfd: &'pidfd PidFd,
        cgroup: &str,
    ) -> Result<RetainedInspectorPidFdV1<'pidfd>, NamespaceInspectorKernelAuthenticationError> {
        super::validate_lifecycle_worker_cgroup(cgroup)
            .map_err(|_| NamespaceInspectorKernelAuthenticationError::Mismatch)?;
        let initial_info = pidfd.info()?;
        let transport = transport_from_pidfd_info(initial_info)?;
        let evidence = self.authenticate(
            pidfd,
            initial_info,
            transport,
            RoleExpectation::lifecycle_worker(&self.lifecycle_worker_executable, Path::new(cgroup)),
        )?;

        Ok(RetainedInspectorPidFdV1 {
            pidfd,
            initial_info,
            transport,
            evidence,
        })
    }

    fn authenticate(
        &self,
        pidfd: &PidFd,
        initial_info: PidFdInfo,
        transport_credentials: TransportCredentials,
        expected: RoleExpectation<'_>,
    ) -> Result<RetainedKernelProcessEvidenceV1, NamespaceInspectorKernelAuthenticationError> {
        let initial_pidfd = PidFdObservation::try_from(initial_info)?;
        let pidfd_before = PidFdObservation::try_from(pidfd.info()?)?;
        let before = pidfd.process_identity()?;
        let cgroup = self.cgroup_root.resolve(expected.cgroup)?;
        cgroup.verify_exact_membership(pidfd)?;

        let executable_before = open_proc_executable(before.pid())?;
        let mac_before = read_effective_mac_context(before.pid())?;
        let executable_after = open_proc_executable(before.pid())?;
        let mac_after = read_effective_mac_context(before.pid())?;

        cgroup.verify_exact_membership(pidfd)?;
        let after = pidfd.process_identity()?;
        let pidfd_after = PidFdObservation::try_from(pidfd.info()?)?;
        validate_observation(
            expected,
            transport_credentials,
            initial_pidfd,
            pidfd_before,
            before.into(),
            after.into(),
            pidfd_after,
            executable_before.identity,
            executable_after.identity,
            &mac_before,
            &mac_after,
            cgroup.kernel_id(),
        )?;
        if !pidfd.is_alive()? {
            return Err(NamespaceInspectorKernelAuthenticationError::Mismatch);
        }
        cgroup.validate_current()?;

        Ok(RetainedKernelProcessEvidenceV1 {
            role: expected.role,
            process: after,
            cgroup_id: cgroup.kernel_id(),
            credentials: AuthenticatedCredentials {
                transport: transport_credentials,
                pidfd: pidfd_after.credentials,
            },
            cgroup,
            executable: executable_after.descriptor,
        })
    }
}

/// Retains a connection peer together with all authenticated kernel objects.
#[derive(Debug)]
pub(crate) struct RetainedInspectorConnectionPeerV1<'peer> {
    peer: &'peer ConnectionPeerIdentity,
    evidence: RetainedKernelProcessEvidenceV1,
}

impl RetainedInspectorConnectionPeerV1<'_> {
    /// Projects the checked role into the pure protocol model.
    ///
    /// # Errors
    ///
    /// Returns an error unless fresh pidfd identity and credentials, cgroup,
    /// executable, and MAC observations still match the retained admission
    /// baseline.
    pub(crate) fn authenticated_peer(
        &self,
    ) -> Result<KernelAuthenticatedInspectorPeerV1, NamespaceInspectorKernelAuthenticationError>
    {
        self.evidence.reauthenticate(
            self.peer.pidfd(),
            self.peer.initial_info(),
            self.peer.credentials().into(),
        )?;
        self.evidence.inspector_peer()
    }

    /// Revalidates the retained pidfd and cgroup at the current boundary.
    ///
    /// # Errors
    ///
    /// Returns an error if the process exited, changed credentials, migrated,
    /// its retained cgroup became inactive, or its executable or effective MAC
    /// domain changed.
    pub(crate) fn revalidate_retained(
        &self,
    ) -> Result<(), NamespaceInspectorKernelAuthenticationError> {
        self.evidence.reauthenticate(
            self.peer.pidfd(),
            self.peer.initial_info(),
            self.peer.credentials().into(),
        )
    }

    /// Checks whether a record retained the same exact authenticated execution.
    ///
    /// # Errors
    ///
    /// Returns an error if either retained process or cgroup can no longer be
    /// revalidated. A successful `false` is an identity mismatch.
    pub(crate) fn same_execution(
        &self,
        record: &RetainedInspectorRecordSubjectV1,
    ) -> Result<bool, NamespaceInspectorKernelAuthenticationError> {
        self.revalidate_retained()?;
        record.revalidate_retained()?;

        self.evidence.same_execution(&record.evidence)
    }
}

/// Owns a record subject together with all authenticated kernel objects.
#[derive(Debug)]
pub(crate) struct RetainedInspectorRecordSubjectV1 {
    subject: KernelAuthorizedRecordSubject,
    evidence: RetainedKernelProcessEvidenceV1,
}

impl RetainedInspectorRecordSubjectV1 {
    /// Projects the checked role into the pure protocol model.
    ///
    /// # Errors
    ///
    /// Returns an error unless fresh pidfd identity and credentials, cgroup,
    /// executable, and MAC observations still match the retained admission
    /// baseline.
    pub(crate) fn authenticated_peer(
        &self,
    ) -> Result<KernelAuthenticatedInspectorPeerV1, NamespaceInspectorKernelAuthenticationError>
    {
        self.evidence.reauthenticate(
            self.subject.pidfd(),
            self.subject.initial_info(),
            self.subject.credentials().into(),
        )?;
        self.evidence.inspector_peer()
    }

    /// Revalidates the retained pidfd and cgroup at the current boundary.
    ///
    /// # Errors
    ///
    /// Returns an error if the process exited, changed credentials, migrated,
    /// its retained cgroup became inactive, or its executable or effective MAC
    /// domain changed.
    pub(crate) fn revalidate_retained(
        &self,
    ) -> Result<(), NamespaceInspectorKernelAuthenticationError> {
        self.evidence.reauthenticate(
            self.subject.pidfd(),
            self.subject.initial_info(),
            self.subject.credentials().into(),
        )
    }
}

/// Retains the authenticated PID 1 connection without minting activation state.
#[derive(Debug)]
pub(crate) struct RetainedSystemdManagerConnectionV1<'peer> {
    peer: &'peer ConnectionPeerIdentity,
    evidence: RetainedKernelProcessEvidenceV1,
}

/// Retains the authenticated PID 1 Unix-stream connection.
#[derive(Debug)]
pub(crate) struct RetainedSystemdManagerStreamV1<'peer> {
    peer: &'peer UnixStreamPeerIdentity,
    evidence: RetainedKernelProcessEvidenceV1,
}

impl RetainedSystemdManagerStreamV1<'_> {
    /// Projects fresh checked manager evidence into the pure model.
    ///
    /// # Errors
    ///
    /// Returns an error unless every retained PID 1 observation still matches.
    pub(crate) fn authenticated_manager(
        &self,
    ) -> Result<KernelAuthenticatedSystemdManagerV1, NamespaceInspectorKernelAuthenticationError>
    {
        self.evidence.reauthenticate(
            self.peer.pidfd(),
            self.peer.initial_info(),
            self.peer.credentials().into(),
        )?;
        self.evidence.systemd_manager()
    }

    /// Revalidates the retained PID 1 stream peer.
    ///
    /// # Errors
    ///
    /// Returns an error if any retained PID 1 observation changed.
    pub(crate) fn revalidate_retained(
        &self,
    ) -> Result<(), NamespaceInspectorKernelAuthenticationError> {
        self.evidence.reauthenticate(
            self.peer.pidfd(),
            self.peer.initial_info(),
            self.peer.credentials().into(),
        )
    }
}

/// Retains one pidfd-only role authentication across effect boundaries.
#[derive(Debug)]
pub(crate) struct RetainedInspectorPidFdV1<'pidfd> {
    pidfd: &'pidfd PidFd,
    initial_info: PidFdInfo,
    transport: TransportCredentials,
    evidence: RetainedKernelProcessEvidenceV1,
}

impl RetainedInspectorPidFdV1<'_> {
    /// Projects an authenticated inspector role into the pure model.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is the inspector role and every retained
    /// kernel observation still matches.
    pub(crate) fn authenticated_inspector(
        &self,
    ) -> Result<KernelAuthenticatedInspectorPeerV1, NamespaceInspectorKernelAuthenticationError>
    {
        self.revalidate_retained()?;
        self.evidence.inspector_peer()
    }

    /// Returns the exact process identity after fresh reauthentication.
    ///
    /// # Errors
    ///
    /// Returns an error if credentials, cgroup, executable, MAC, process
    /// identity, or liveness no longer matches admission.
    pub(crate) fn process(
        &self,
    ) -> Result<InspectorProcessIdentityV1, NamespaceInspectorKernelAuthenticationError> {
        self.revalidate_retained()?;
        Ok(model_process(
            self.evidence.process,
            self.evidence.cgroup_id,
        ))
    }

    /// Revalidates every retained pidfd-only role observation.
    ///
    /// # Errors
    ///
    /// Returns an error if any admitted process property changed.
    pub(crate) fn revalidate_retained(
        &self,
    ) -> Result<(), NamespaceInspectorKernelAuthenticationError> {
        self.evidence
            .reauthenticate(self.pidfd, self.initial_info, self.transport)
    }
}

impl RetainedSystemdManagerConnectionV1<'_> {
    /// Projects the checked manager into the pure protocol model.
    ///
    /// # Errors
    ///
    /// Returns an error unless fresh PID 1 identity and credentials,
    /// manager-cgroup, executable, and MAC observations still match the
    /// admission baseline.
    pub(crate) fn authenticated_manager(
        &self,
    ) -> Result<KernelAuthenticatedSystemdManagerV1, NamespaceInspectorKernelAuthenticationError>
    {
        self.evidence.reauthenticate(
            self.peer.pidfd(),
            self.peer.initial_info(),
            self.peer.credentials().into(),
        )?;
        self.evidence.systemd_manager()
    }

    /// Revalidates the retained PID 1 pidfd and manager cgroup.
    ///
    /// # Errors
    ///
    /// Returns an error if PID 1 exited, changed identity or credentials,
    /// migrated, its retained cgroup became inactive, or its executable or MAC
    /// domain changed.
    pub(crate) fn revalidate_retained(
        &self,
    ) -> Result<(), NamespaceInspectorKernelAuthenticationError> {
        self.evidence.reauthenticate(
            self.peer.pidfd(),
            self.peer.initial_info(),
            self.peer.credentials().into(),
        )
    }
}

#[derive(Debug)]
struct RetainedKernelProcessEvidenceV1 {
    role: AuthenticatedRole,
    process: PidFdProcessIdentity,
    cgroup_id: u64,
    credentials: AuthenticatedCredentials,
    cgroup: RetainedCgroupAnchor,
    // Retaining the descriptor pins the executable inode accepted above.
    executable: OwnedFd,
}

impl RetainedKernelProcessEvidenceV1 {
    fn inspector_peer(
        &self,
    ) -> Result<KernelAuthenticatedInspectorPeerV1, NamespaceInspectorKernelAuthenticationError>
    {
        let role = match self.role {
            AuthenticatedRole::Broker => NetworkNamespaceInspectorPeerRoleV1::Broker,
            AuthenticatedRole::Inspector => NetworkNamespaceInspectorPeerRoleV1::Inspector,
            AuthenticatedRole::LifecycleWorker | AuthenticatedRole::Manager => {
                return Err(NamespaceInspectorKernelAuthenticationError::Mismatch);
            }
        };

        Ok(KernelAuthenticatedInspectorPeerV1 {
            role,
            process: model_process(self.process, self.cgroup_id),
            uid: self.credentials.pidfd.effective_user_id,
            gid: self.credentials.pidfd.effective_group_id,
        })
    }

    fn systemd_manager(
        &self,
    ) -> Result<KernelAuthenticatedSystemdManagerV1, NamespaceInspectorKernelAuthenticationError>
    {
        if self.role != AuthenticatedRole::Manager {
            return Err(NamespaceInspectorKernelAuthenticationError::Mismatch);
        }
        Ok(KernelAuthenticatedSystemdManagerV1 {
            pid: self.process.pid(),
            thread_group_id: self.process.thread_group_id(),
            parent_pid: self.process.parent_pid(),
            cgroup_id: self.cgroup_id,
            uid: self.credentials.pidfd.effective_user_id,
            gid: self.credentials.pidfd.effective_group_id,
        })
    }

    fn reauthenticate(
        &self,
        pidfd: &PidFd,
        initial_info: PidFdInfo,
        transport_credentials: TransportCredentials,
    ) -> Result<(), NamespaceInspectorKernelAuthenticationError> {
        let initial_pidfd = PidFdObservation::try_from(initial_info)?;
        let pidfd_before = PidFdObservation::try_from(pidfd.info()?)?;
        let before = pidfd.process_identity()?;
        self.cgroup.verify_exact_membership(pidfd)?;

        let executable_before = open_proc_executable(before.pid())?;
        let mac_before = read_effective_mac_context(before.pid())?;
        let executable_after = open_proc_executable(before.pid())?;
        let mac_after = read_effective_mac_context(before.pid())?;

        self.cgroup.verify_exact_membership(pidfd)?;
        let after = pidfd.process_identity()?;
        let pidfd_after = PidFdObservation::try_from(pidfd.info()?)?;
        let expected_executable = executable_identity(self.executable.as_fd())?;
        validate_observation(
            RoleExpectation::retained(self.role, expected_executable),
            transport_credentials,
            initial_pidfd,
            pidfd_before,
            before.into(),
            after.into(),
            pidfd_after,
            executable_before.identity,
            executable_after.identity,
            &mac_before,
            &mac_after,
            self.cgroup_id,
        )?;
        self.cgroup.validate_current()?;
        let observed_credentials = AuthenticatedCredentials {
            transport: transport_credentials,
            pidfd: pidfd_after.credentials,
        };
        validate_retained_baseline(
            after.into(),
            observed_credentials,
            self.process.into(),
            self.credentials,
        )?;
        if !pidfd.is_alive()? {
            return Err(NamespaceInspectorKernelAuthenticationError::Mismatch);
        }
        Ok(())
    }

    fn same_execution(
        &self,
        other: &Self,
    ) -> Result<bool, NamespaceInspectorKernelAuthenticationError> {
        let same = self.role == other.role
            && self.process == other.process
            && self.credentials == other.credentials
            && self.cgroup.kernel_id() == other.cgroup.kernel_id()
            && executable_identity(self.executable.as_fd())?
                == executable_identity(other.executable.as_fd())?;
        Ok(same)
    }
}

fn validate_retained_baseline(
    observed_process: ProcessIdentitySnapshot,
    observed_credentials: AuthenticatedCredentials,
    retained_process: ProcessIdentitySnapshot,
    retained_credentials: AuthenticatedCredentials,
) -> Result<(), NamespaceInspectorKernelAuthenticationError> {
    if observed_process != retained_process || observed_credentials != retained_credentials {
        return Err(NamespaceInspectorKernelAuthenticationError::Mismatch);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthenticatedRole {
    Broker,
    Inspector,
    LifecycleWorker,
    Manager,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TransportCredentials {
    pid: u32,
    uid: u32,
    gid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthenticatedCredentials {
    transport: TransportCredentials,
    pidfd: KernelCredentialSnapshot,
}

impl From<PeerCredentials> for TransportCredentials {
    fn from(credentials: PeerCredentials) -> Self {
        Self {
            pid: credentials.pid().get(),
            uid: credentials.uid(),
            gid: credentials.gid(),
        }
    }
}

impl From<RecordCredentials> for TransportCredentials {
    fn from(credentials: RecordCredentials) -> Self {
        Self {
            pid: credentials.pid().get(),
            uid: credentials.uid(),
            gid: credentials.gid(),
        }
    }
}

impl From<UnixStreamPeerCredentials> for TransportCredentials {
    fn from(credentials: UnixStreamPeerCredentials) -> Self {
        Self {
            pid: credentials.pid().get(),
            uid: credentials.uid(),
            gid: credentials.gid(),
        }
    }
}

fn transport_from_pidfd_info(
    info: PidFdInfo,
) -> Result<TransportCredentials, NamespaceInspectorKernelAuthenticationError> {
    let credentials = info
        .credentials()
        .ok_or(NamespaceInspectorKernelAuthenticationError::Mismatch)?;
    Ok(TransportCredentials {
        pid: info.pid(),
        uid: credentials.effective_user_id(),
        gid: credentials.effective_group_id(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KernelCredentialSnapshot {
    real_user_id: u32,
    real_group_id: u32,
    effective_user_id: u32,
    effective_group_id: u32,
    saved_user_id: u32,
    saved_group_id: u32,
    filesystem_user_id: u32,
    filesystem_group_id: u32,
}

impl KernelCredentialSnapshot {
    fn is_root(self) -> bool {
        self.real_user_id == ROOT_UID
            && self.real_group_id == ROOT_GID
            && self.effective_user_id == ROOT_UID
            && self.effective_group_id == ROOT_GID
            && self.saved_user_id == ROOT_UID
            && self.saved_group_id == ROOT_GID
            && self.filesystem_user_id == ROOT_UID
            && self.filesystem_group_id == ROOT_GID
    }
}

impl From<PidFdCredentials> for KernelCredentialSnapshot {
    fn from(credentials: PidFdCredentials) -> Self {
        Self {
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PidFdObservation {
    process: PidFdProcessSnapshot,
    credentials: KernelCredentialSnapshot,
}

impl TryFrom<PidFdInfo> for PidFdObservation {
    type Error = NamespaceInspectorKernelAuthenticationError;

    fn try_from(info: PidFdInfo) -> Result<Self, Self::Error> {
        let credentials = require_kernel_credentials(info.credentials().map(Into::into))?;

        Ok(Self {
            process: info.into(),
            credentials,
        })
    }
}

fn require_kernel_credentials(
    credentials: Option<KernelCredentialSnapshot>,
) -> Result<KernelCredentialSnapshot, NamespaceInspectorKernelAuthenticationError> {
    credentials.ok_or(NamespaceInspectorKernelAuthenticationError::Mismatch)
}

#[derive(Debug)]
struct FixedExecutable {
    descriptor: OwnedFd,
    identity: ExecutableIdentity,
}

impl FixedExecutable {
    fn from_owned(
        descriptor: OwnedFd,
    ) -> Result<Self, NamespaceInspectorKernelAuthenticationError> {
        let flags =
            rustix::io::fcntl_getfd(&descriptor).map_err(|source| io("fcntl(F_GETFD)", source))?;
        if !flags.contains(rustix::io::FdFlags::CLOEXEC) {
            return Err(
                NamespaceInspectorKernelAuthenticationError::InvalidProvisioning(
                    "executable descriptors must be close-on-exec",
                ),
            );
        }
        let identity = executable_identity(descriptor.as_fd())?;
        Ok(Self {
            descriptor,
            identity,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct ObservedExecutable {
    descriptor: OwnedFd,
    identity: ExecutableIdentity,
}

#[derive(Clone, Copy)]
struct RoleExpectation<'policy> {
    role: AuthenticatedRole,
    cgroup: &'policy Path,
    executable: ExecutableIdentity,
    mac_context: &'static [u8],
    pid: Option<u32>,
    parent_pid: Option<u32>,
}

impl<'policy> RoleExpectation<'policy> {
    fn broker(executable: &'policy FixedExecutable) -> Self {
        Self {
            role: AuthenticatedRole::Broker,
            cgroup: Path::new(BROKER_CGROUP),
            executable: executable.identity,
            mac_context: BROKER_MAC_CONTEXT,
            pid: None,
            parent_pid: None,
        }
    }

    fn inspector(executable: &'policy FixedExecutable, cgroup: &'policy Path) -> Self {
        Self {
            role: AuthenticatedRole::Inspector,
            cgroup,
            executable: executable.identity,
            mac_context: INSPECTOR_MAC_CONTEXT,
            pid: None,
            parent_pid: None,
        }
    }

    fn manager(executable: &'policy FixedExecutable) -> Self {
        Self {
            role: AuthenticatedRole::Manager,
            cgroup: Path::new("init.scope"),
            executable: executable.identity,
            mac_context: MANAGER_MAC_CONTEXT,
            pid: Some(1),
            parent_pid: Some(0),
        }
    }

    fn lifecycle_worker(executable: &'policy FixedExecutable, cgroup: &'policy Path) -> Self {
        Self {
            role: AuthenticatedRole::LifecycleWorker,
            cgroup,
            executable: executable.identity,
            mac_context: LIFECYCLE_WORKER_MAC_CONTEXT,
            pid: None,
            parent_pid: None,
        }
    }

    fn retained(role: AuthenticatedRole, executable: ExecutableIdentity) -> Self {
        let (mac_context, pid, parent_pid) = match role {
            AuthenticatedRole::Broker => (BROKER_MAC_CONTEXT, None, None),
            AuthenticatedRole::Inspector => (INSPECTOR_MAC_CONTEXT, None, None),
            AuthenticatedRole::LifecycleWorker => (LIFECYCLE_WORKER_MAC_CONTEXT, None, None),
            AuthenticatedRole::Manager => (MANAGER_MAC_CONTEXT, Some(1), Some(0)),
        };
        Self {
            role,
            // Validation does not consume the locator; retained reauthentication
            // uses the already-resolved exact cgroup anchor instead.
            cgroup: Path::new("."),
            executable,
            mac_context,
            pid,
            parent_pid,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_observation(
    expected: RoleExpectation<'_>,
    transport_credentials: TransportCredentials,
    initial_pidfd: PidFdObservation,
    pidfd_before: PidFdObservation,
    before: ProcessIdentitySnapshot,
    after: ProcessIdentitySnapshot,
    pidfd_after: PidFdObservation,
    executable_before: ExecutableIdentity,
    executable_after: ExecutableIdentity,
    mac_before: &[u8],
    mac_after: &[u8],
    cgroup_id: u64,
) -> Result<(), NamespaceInspectorKernelAuthenticationError> {
    let expected_pid = expected.pid.unwrap_or(transport_credentials.pid);
    let expected_parent = expected.parent_pid.unwrap_or(before.parent_pid);
    let expected_process = PidFdProcessSnapshot {
        pid: before.pid,
        thread_group_id: before.thread_group_id,
        parent_pid: before.parent_pid,
        cgroup_id: before.cgroup_id,
    };
    let identity_matches = before == after
        && before.pid == expected_pid
        && before.thread_group_id == expected_pid
        && before.parent_pid == expected_parent
        && (expected.role == AuthenticatedRole::Manager || before.parent_pid != 0)
        && before.cgroup_id == Some(cgroup_id)
        && initial_pidfd.process == expected_process
        && pidfd_before.process == expected_process
        && pidfd_after.process == expected_process;
    let credential_matches = initial_pidfd.credentials == pidfd_before.credentials
        && pidfd_before.credentials == pidfd_after.credentials
        && pidfd_after.credentials.is_root()
        && transport_credentials.uid == pidfd_after.credentials.effective_user_id
        && transport_credentials.gid == pidfd_after.credentials.effective_group_id;
    let role_matches = transport_credentials.pid == expected_pid
        && executable_before == expected.executable
        && executable_after == expected.executable
        && mac_before == expected.mac_context
        && mac_after == expected.mac_context;

    if !identity_matches || !credential_matches || !role_matches {
        return Err(NamespaceInspectorKernelAuthenticationError::Mismatch);
    }
    Ok(())
}

fn inspector_cgroup(
    instance: &str,
) -> Result<PathBuf, NamespaceInspectorKernelAuthenticationError> {
    let mut cgroup = String::with_capacity(
        INSPECTOR_CGROUP_PREFIX.len() + instance.len() + INSPECTOR_CGROUP_SUFFIX.len(),
    );
    cgroup.push_str(INSPECTOR_CGROUP_PREFIX);
    cgroup.push_str(instance);
    cgroup.push_str(INSPECTOR_CGROUP_SUFFIX);
    if cgroup.len() > 512 {
        return Err(NamespaceInspectorKernelAuthenticationError::Mismatch);
    }
    Ok(PathBuf::from(cgroup))
}

/// Uses the response writer's cgroup only to locate a candidate service unit.
///
/// The retained pidfd, exact cgroup anchor, executable, MAC domain, and signed
/// PID 1 launch must still authenticate that candidate before it is trusted.
pub(super) fn inspector_instance_from_record_subject(
    subject: &KernelAuthorizedRecordSubject,
) -> Result<String, NamespaceInspectorKernelAuthenticationError> {
    let before = subject.pidfd().process_identity()?;
    if subject.initial_info() != subject.pidfd().info()?
        || subject.credentials().pid().get() != before.pid()
    {
        return Err(NamespaceInspectorKernelAuthenticationError::Mismatch);
    }

    let path = proc_path(before.pid(), "cgroup")?;
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| io("open(/proc/PID/cgroup)", source))?;
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take((MAXIMUM_INSPECTOR_CGROUP_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| NamespaceInspectorKernelAuthenticationError::Io {
            operation: "read(/proc/PID/cgroup)",
            source,
        })?;

    let after = subject.pidfd().process_identity()?;
    if before != after || subject.initial_info() != subject.pidfd().info()? {
        return Err(NamespaceInspectorKernelAuthenticationError::Mismatch);
    }
    parse_inspector_instance_cgroup(&bytes)
}

fn parse_inspector_instance_cgroup(
    bytes: &[u8],
) -> Result<String, NamespaceInspectorKernelAuthenticationError> {
    if bytes.len() > MAXIMUM_INSPECTOR_CGROUP_RECORD_BYTES {
        return Err(NamespaceInspectorKernelAuthenticationError::Mismatch);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| NamespaceInspectorKernelAuthenticationError::Mismatch)?;
    let instance = text
        .strip_prefix("0::/")
        .and_then(|cgroup| cgroup.strip_prefix(INSPECTOR_CGROUP_PREFIX))
        .and_then(|unit| unit.strip_suffix('\n'))
        .and_then(|unit| unit.strip_suffix(INSPECTOR_CGROUP_SUFFIX))
        .ok_or(NamespaceInspectorKernelAuthenticationError::Mismatch)?;
    validate_systemd_socket_instance_fields(instance)
        .map_err(|_| NamespaceInspectorKernelAuthenticationError::Mismatch)?;
    Ok(instance.to_owned())
}

fn open_proc_executable(
    pid: u32,
) -> Result<ObservedExecutable, NamespaceInspectorKernelAuthenticationError> {
    let path = proc_path(pid, "exe")?;
    // Following this procfs magic link is intentional: O_PATH pins the exact
    // executable inode without granting read or execute operations through it.
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| io("open(/proc/PID/exe)", source))?;
    let identity = executable_identity(descriptor.as_fd())?;
    Ok(ObservedExecutable {
        descriptor,
        identity,
    })
}

fn executable_identity(
    descriptor: BorrowedFd<'_>,
) -> Result<ExecutableIdentity, NamespaceInspectorKernelAuthenticationError> {
    let metadata =
        rustix::fs::fstat(descriptor).map_err(|source| io("fstat(executable)", source))?;
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::RegularFile
        || metadata.st_mode & 0o111 == 0
    {
        return Err(
            NamespaceInspectorKernelAuthenticationError::InvalidProvisioning(
                "executable descriptor must name an executable regular file",
            ),
        );
    }
    let device = metadata.st_dev as u64;
    let inode = metadata.st_ino as u64;
    if device == 0 || inode == 0 {
        return Err(
            NamespaceInspectorKernelAuthenticationError::InvalidProvisioning(
                "executable identity must be nonzero",
            ),
        );
    }
    Ok(ExecutableIdentity { device, inode })
}

fn read_effective_mac_context(
    pid: u32,
) -> Result<Vec<u8>, NamespaceInspectorKernelAuthenticationError> {
    let path = proc_path(pid, "attr/current")?;
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| io("open(/proc/PID/attr/current)", source))?;
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take((MAXIMUM_MAC_CONTEXT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| NamespaceInspectorKernelAuthenticationError::Io {
            operation: "read(/proc/PID/attr/current)",
            source,
        })?;
    if bytes.is_empty() || bytes.len() > MAXIMUM_MAC_CONTEXT_BYTES {
        return Err(NamespaceInspectorKernelAuthenticationError::Mismatch);
    }
    parse_effective_mac_context(bytes)
}

fn parse_effective_mac_context(
    mut bytes: Vec<u8>,
) -> Result<Vec<u8>, NamespaceInspectorKernelAuthenticationError> {
    if bytes.pop() != Some(0) || bytes.is_empty() || bytes.contains(&0) {
        return Err(NamespaceInspectorKernelAuthenticationError::Mismatch);
    }
    Ok(bytes)
}

fn proc_path(pid: u32, leaf: &str) -> Result<PathBuf, NamespaceInspectorKernelAuthenticationError> {
    if pid == 0 {
        return Err(NamespaceInspectorKernelAuthenticationError::Mismatch);
    }
    let path = PathBuf::from(format!("/proc/{pid}/{leaf}"));
    let normalized = path.is_absolute()
        && path.as_os_str().len() <= MAXIMUM_PROC_PATH_BYTES
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    if !normalized {
        return Err(NamespaceInspectorKernelAuthenticationError::Mismatch);
    }
    Ok(path)
}

fn model_process(process: PidFdProcessIdentity, cgroup_id: u64) -> InspectorProcessIdentityV1 {
    InspectorProcessIdentityV1 {
        pid: process.pid(),
        thread_group_id: process.thread_group_id(),
        parent_pid: process.parent_pid(),
        cgroup_id,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessIdentitySnapshot {
    pid: u32,
    thread_group_id: u32,
    parent_pid: u32,
    cgroup_id: Option<u64>,
    start_time_ticks: u64,
}

impl From<PidFdProcessIdentity> for ProcessIdentitySnapshot {
    fn from(process: PidFdProcessIdentity) -> Self {
        Self {
            pid: process.pid(),
            thread_group_id: process.thread_group_id(),
            parent_pid: process.parent_pid(),
            cgroup_id: process.cgroup_id(),
            start_time_ticks: process.start_time_ticks(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PidFdProcessSnapshot {
    pid: u32,
    thread_group_id: u32,
    parent_pid: u32,
    cgroup_id: Option<u64>,
}

impl From<PidFdInfo> for PidFdProcessSnapshot {
    fn from(process: PidFdInfo) -> Self {
        Self {
            pid: process.pid(),
            thread_group_id: process.thread_group_id(),
            parent_pid: process.parent_pid(),
            cgroup_id: process.cgroup_id(),
        }
    }
}

fn io(
    operation: &'static str,
    source: rustix::io::Errno,
) -> NamespaceInspectorKernelAuthenticationError {
    NamespaceInspectorKernelAuthenticationError::Io {
        operation,
        source: source.into(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[derive(Clone, Copy)]
    struct TestObservation {
        transport_credentials: TransportCredentials,
        initial_pidfd: PidFdObservation,
        pidfd_before: PidFdObservation,
        before: ProcessIdentitySnapshot,
        after: ProcessIdentitySnapshot,
        pidfd_after: PidFdObservation,
        executable_before: ExecutableIdentity,
        executable_after: ExecutableIdentity,
        mac_before: &'static [u8],
        mac_after: &'static [u8],
        cgroup_id: u64,
    }

    impl TestObservation {
        fn authenticate(
            self,
            expected: RoleExpectation<'_>,
        ) -> Result<(), NamespaceInspectorKernelAuthenticationError> {
            validate_observation(
                expected,
                self.transport_credentials,
                self.initial_pidfd,
                self.pidfd_before,
                self.before,
                self.after,
                self.pidfd_after,
                self.executable_before,
                self.executable_after,
                self.mac_before,
                self.mac_after,
                self.cgroup_id,
            )
        }
    }

    fn executable(device: u64, inode: u64) -> FixedExecutable {
        FixedExecutable {
            descriptor: File::open("/dev/null").unwrap().into(),
            identity: ExecutableIdentity { device, inode },
        }
    }

    fn broker_expectation(executable: &FixedExecutable) -> RoleExpectation<'_> {
        RoleExpectation::broker(executable)
    }

    fn broker_observation() -> TestObservation {
        let process = ProcessIdentitySnapshot {
            pid: 41,
            thread_group_id: 41,
            parent_pid: 1,
            cgroup_id: Some(91),
            start_time_ticks: 7,
        };
        let pidfd = PidFdObservation {
            process: PidFdProcessSnapshot {
                pid: 41,
                thread_group_id: 41,
                parent_pid: 1,
                cgroup_id: Some(91),
            },
            credentials: root_kernel_credentials(),
        };
        TestObservation {
            transport_credentials: TransportCredentials {
                pid: 41,
                uid: 0,
                gid: 0,
            },
            initial_pidfd: pidfd,
            pidfd_before: pidfd,
            before: process,
            after: process,
            pidfd_after: pidfd,
            executable_before: ExecutableIdentity {
                device: 11,
                inode: 12,
            },
            executable_after: ExecutableIdentity {
                device: 11,
                inode: 12,
            },
            mac_before: BROKER_MAC_CONTEXT,
            mac_after: BROKER_MAC_CONTEXT,
            cgroup_id: 91,
        }
    }

    fn root_kernel_credentials() -> KernelCredentialSnapshot {
        KernelCredentialSnapshot {
            real_user_id: 0,
            real_group_id: 0,
            effective_user_id: 0,
            effective_group_id: 0,
            saved_user_id: 0,
            saved_group_id: 0,
            filesystem_user_id: 0,
            filesystem_group_id: 0,
        }
    }

    #[test]
    fn exact_broker_observation_is_accepted() {
        let executable = executable(11, 12);
        assert!(
            broker_observation()
                .authenticate(broker_expectation(&executable))
                .is_ok()
        );
    }

    #[test]
    fn pidfd_credentials_are_required_and_every_id_must_be_root() {
        assert!(matches!(
            require_kernel_credentials(None),
            Err(NamespaceInspectorKernelAuthenticationError::Mismatch)
        ));

        let root = root_kernel_credentials();
        let nonroot = [
            KernelCredentialSnapshot {
                real_user_id: 1,
                ..root
            },
            KernelCredentialSnapshot {
                real_group_id: 1,
                ..root
            },
            KernelCredentialSnapshot {
                effective_user_id: 1,
                ..root
            },
            KernelCredentialSnapshot {
                effective_group_id: 1,
                ..root
            },
            KernelCredentialSnapshot {
                saved_user_id: 1,
                ..root
            },
            KernelCredentialSnapshot {
                saved_group_id: 1,
                ..root
            },
            KernelCredentialSnapshot {
                filesystem_user_id: 1,
                ..root
            },
            KernelCredentialSnapshot {
                filesystem_group_id: 1,
                ..root
            },
        ];
        let executable = executable(11, 12);

        for credentials in nonroot {
            let mut observation = broker_observation();
            observation.initial_pidfd.credentials = credentials;
            observation.pidfd_before.credentials = credentials;
            observation.pidfd_after.credentials = credentials;

            assert!(matches!(
                observation.authenticate(broker_expectation(&executable)),
                Err(NamespaceInspectorKernelAuthenticationError::Mismatch)
            ));
        }
    }

    #[test]
    fn pidfd_credential_fences_and_transport_nomination_must_agree() {
        let executable = executable(11, 12);

        let mut changed_initial = broker_observation();
        changed_initial.initial_pidfd.credentials.saved_user_id = 1;
        let mut changed_before = broker_observation();
        changed_before.pidfd_before.credentials.saved_user_id = 1;
        let mut changed_after = broker_observation();
        changed_after.pidfd_after.credentials.saved_user_id = 1;
        let mut nominated_user = broker_observation();
        nominated_user.transport_credentials.uid = 1;
        let mut nominated_group = broker_observation();
        nominated_group.transport_credentials.gid = 1;

        for observation in [
            changed_initial,
            changed_before,
            changed_after,
            nominated_user,
            nominated_group,
        ] {
            assert!(matches!(
                observation.authenticate(broker_expectation(&executable)),
                Err(NamespaceInspectorKernelAuthenticationError::Mismatch)
            ));
        }
    }

    #[test]
    fn every_pidfd_identity_observation_must_match_the_process_sandwich() {
        let executable = executable(11, 12);

        let mut changed_initial = broker_observation();
        changed_initial.initial_pidfd.process.parent_pid = 2;
        let mut changed_before = broker_observation();
        changed_before.pidfd_before.process.cgroup_id = Some(92);
        let mut changed_after = broker_observation();
        changed_after.pidfd_after.process.thread_group_id = 42;

        for observation in [changed_initial, changed_before, changed_after] {
            assert!(matches!(
                observation.authenticate(broker_expectation(&executable)),
                Err(NamespaceInspectorKernelAuthenticationError::Mismatch)
            ));
        }
    }

    #[test]
    fn retained_credential_baseline_rejects_transport_or_pidfd_drift() {
        let transport = broker_observation().transport_credentials;
        let pidfd = root_kernel_credentials();
        let retained = AuthenticatedCredentials { transport, pidfd };
        let process = broker_observation().after;
        assert!(validate_retained_baseline(process, retained, process, retained).is_ok());

        let changed_transport = TransportCredentials {
            uid: 1,
            ..transport
        };
        let changed_pidfd = KernelCredentialSnapshot {
            filesystem_group_id: 1,
            ..pidfd
        };
        assert!(matches!(
            validate_retained_baseline(
                process,
                AuthenticatedCredentials {
                    transport: changed_transport,
                    pidfd,
                },
                process,
                retained,
            ),
            Err(NamespaceInspectorKernelAuthenticationError::Mismatch)
        ));
        assert!(matches!(
            validate_retained_baseline(
                process,
                AuthenticatedCredentials {
                    transport,
                    pidfd: changed_pidfd,
                },
                process,
                retained,
            ),
            Err(NamespaceInspectorKernelAuthenticationError::Mismatch)
        ));
        assert!(matches!(
            validate_retained_baseline(
                ProcessIdentitySnapshot {
                    start_time_ticks: 8,
                    ..process
                },
                retained,
                process,
                retained,
            ),
            Err(NamespaceInspectorKernelAuthenticationError::Mismatch)
        ));
    }

    #[test]
    fn every_role_axis_fails_closed() {
        let executable = executable(11, 12);

        let mut wrong_uid = broker_observation();
        wrong_uid.transport_credentials.uid = 1;
        let mut wrong_cgroup = broker_observation();
        wrong_cgroup.after.cgroup_id = Some(92);
        let mut wrong_executable = broker_observation();
        wrong_executable.executable_after.inode = 13;
        let mut wrong_mac = broker_observation();
        wrong_mac.mac_after = INSPECTOR_MAC_CONTEXT;
        let mut changed_execution = broker_observation();
        changed_execution.after.start_time_ticks = 8;

        for observation in [
            wrong_uid,
            wrong_cgroup,
            wrong_executable,
            wrong_mac,
            changed_execution,
        ] {
            assert!(matches!(
                observation.authenticate(broker_expectation(&executable)),
                Err(NamespaceInspectorKernelAuthenticationError::Mismatch)
            ));
        }
    }

    #[test]
    fn executable_or_mac_change_with_stable_process_and_cgroup_is_rejected() {
        let executable = executable(11, 12);
        let mut changed_executable = broker_observation();
        changed_executable.executable_before.inode = 13;
        changed_executable.executable_after.inode = 13;
        let mut changed_mac = broker_observation();
        changed_mac.mac_before = INSPECTOR_MAC_CONTEXT;
        changed_mac.mac_after = INSPECTOR_MAC_CONTEXT;

        for observation in [changed_executable, changed_mac] {
            assert!(matches!(
                observation.authenticate(broker_expectation(&executable)),
                Err(NamespaceInspectorKernelAuthenticationError::Mismatch)
            ));
            assert_eq!(observation.before, observation.after);
            assert_eq!(observation.before.cgroup_id, Some(observation.cgroup_id));
        }
    }

    #[test]
    fn authenticated_roles_are_not_interchangeable() {
        let broker = executable(11, 12);
        let inspector = executable(11, 13);
        let manager = executable(11, 14);
        let lifecycle_worker = executable(11, 15);
        let observation = broker_observation();

        assert!(matches!(
            observation.authenticate(RoleExpectation::inspector(
                &inspector,
                Path::new("aos.slice/aos-control.slice/aos-sandbox-network-namespace-inspector@0-1-2_3-0.service"),
            )),
            Err(NamespaceInspectorKernelAuthenticationError::Mismatch)
        ));
        assert!(matches!(
            observation.authenticate(RoleExpectation::manager(&manager)),
            Err(NamespaceInspectorKernelAuthenticationError::Mismatch)
        ));
        assert!(matches!(
            observation.authenticate(RoleExpectation::lifecycle_worker(
                &lifecycle_worker,
                Path::new(
                    "aos.slice/aos-control.slice/aos-sandbox-network-lifecycle-worker@0-1-2_3-0.service",
                ),
            )),
            Err(NamespaceInspectorKernelAuthenticationError::Mismatch)
        ));
        assert!(
            observation
                .authenticate(RoleExpectation::broker(&broker))
                .is_ok()
        );
    }

    #[test]
    fn inspector_instance_builds_only_one_canonical_relative_cgroup() {
        assert_eq!(
            inspector_cgroup("0-984321-543_876-0").unwrap(),
            Path::new(
                "aos.slice/aos-control.slice/aos-sandbox-network-namespace-inspector@0-984321-543_876-0.service"
            )
        );
        assert!(validate_systemd_socket_instance_fields("0-1-2_3-0/../escape").is_err());
    }

    #[test]
    fn response_writer_cgroup_is_only_a_strict_instance_locator() {
        let canonical = b"0::/aos.slice/aos-control.slice/aos-sandbox-network-namespace-inspector@0-984321-543_876-0.service\n";
        assert_eq!(
            parse_inspector_instance_cgroup(canonical).unwrap(),
            "0-984321-543_876-0"
        );

        for invalid in [
            &canonical[..canonical.len() - 1],
            b"0::/aos.slice/aos-control.slice/aos-sandbox-network-namespace-inspector@00-984321-543_876-0.service\n",
            b"0::/aos.slice/aos-control.slice/aos-sandbox-network-namespace-inspector@0-984321-543_876-0.service\n0::/other\n",
            b"0::/aos.slice/aos-control.slice/aos-sandbox-network-namespace-inspector@0-984321-543_876-0.service/child\n",
            b"0::/aos.slice/aos-control.slice/aos-sandbox-network-lifecycle-worker@0-984321-543_876-0.service\n",
        ] {
            assert!(parse_inspector_instance_cgroup(invalid).is_err());
        }
    }

    #[test]
    fn manager_uses_fixed_init_scope_locator() {
        let manager = executable(11, 14);
        assert_eq!(
            RoleExpectation::manager(&manager).cgroup,
            Path::new("init.scope")
        );
    }

    #[test]
    fn selinux_proc_context_requires_exactly_one_terminal_nul() {
        let mut kernel_record = BROKER_MAC_CONTEXT.to_vec();
        kernel_record.push(0);
        assert_eq!(
            parse_effective_mac_context(kernel_record).unwrap(),
            BROKER_MAC_CONTEXT
        );

        let mut absent_terminator = BROKER_MAC_CONTEXT.to_vec();
        let mut internal_terminator = BROKER_MAC_CONTEXT.to_vec();
        internal_terminator.extend_from_slice(&[0, b'x', 0]);
        let mut double_terminator = BROKER_MAC_CONTEXT.to_vec();
        double_terminator.extend_from_slice(&[0, 0]);
        let mut whitespace_changed = BROKER_MAC_CONTEXT.to_vec();
        whitespace_changed.extend_from_slice(&[b'\n', 0]);

        assert!(parse_effective_mac_context(std::mem::take(&mut absent_terminator)).is_err());
        assert!(parse_effective_mac_context(internal_terminator).is_err());
        assert!(parse_effective_mac_context(double_terminator).is_err());
        assert_ne!(
            parse_effective_mac_context(whitespace_changed).unwrap(),
            BROKER_MAC_CONTEXT
        );
    }

    #[test]
    fn inspector_startup_accepts_only_its_exact_mac_domain() {
        assert!(is_inspector_mac_context(INSPECTOR_MAC_CONTEXT));
        assert!(!is_inspector_mac_context(BROKER_MAC_CONTEXT));
        assert!(!is_inspector_mac_context(LIFECYCLE_WORKER_MAC_CONTEXT));

        let mut extended = INSPECTOR_MAC_CONTEXT.to_vec();
        extended.extend_from_slice(b":s0");
        assert!(!is_inspector_mac_context(&extended));
    }
}
