//! Retained kernel authentication for namespace-inspector peers.
//!
//! Socket credentials and pidfds identify a kernel subject but do not establish
//! its application role. This module binds those subjects to the root UID/GID
//! snapshot supplied by `SO_PEERCRED` or `SCM_CREDENTIALS`, a strictly resolved
//! cgroup-v2 object, a provisioned executable inode, and the exact effective
//! SELinux domain observed through procfs. Linux 6.18 PIDFD_GET_INFO reports
//! task credentials, but the current [`PidFdInfo`] wrapper does not expose
//! them. This staged adapter can therefore check the retained socket snapshot
//! for consistency but cannot yet claim a fresh effective-UID/GID observation;
//! typed credential exposure is a production-authentication prerequisite.
//!
//! Process inspection is deliberately a repeated observation, not a claim of
//! atomicity. The verifier compares stable pidfd identity, exact cgroup
//! membership, executable inode, and MAC context before and after the central
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
//! The production executable, systemd-manager property adapter, and checked
//! enforcing-policy prerequisite are not composed yet. This module must remain
//! unreachable from production role construction until that prerequisite is
//! qualified. In particular, it does not construct
//! [`super::AuthenticatedNamespaceInspectorActivationV1`].

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::{PidFd, PidFdInfo, PidFdProcessIdentity};
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, KernelAuthorizedRecordSubject, PeerCredentials, RecordCredentials,
};

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
const MANAGER_MAC_CONTEXT: &[u8] = b"system_u:system_r:init_t";
const MAXIMUM_MAC_CONTEXT_BYTES: usize = 256;
const MAXIMUM_PROC_PATH_BYTES: usize = 64;
const ROOT_UID: u32 = 0;
const ROOT_GID: u32 = 0;

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
    manager_executable: FixedExecutable,
}

impl NamespaceInspectorKernelVerifierV1 {
    /// Adopts the global cgroup-v2 root and the three provisioned executables.
    ///
    /// The executable descriptors must be close-on-exec regular executable
    /// files. Their retained inode identities must be pairwise distinct. The
    /// caller remains responsible for obtaining them through protected local
    /// provisioning rather than caller-controlled paths. This staged
    /// constructor is not a production authority boundary: its future caller
    /// must first consume a checked deployment token proving that SELinux is
    /// enabled, enforcing, and running the reviewed effective policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the cgroup root is invalid, an executable is not a
    /// close-on-exec regular executable file, or two role descriptors alias.
    pub(crate) fn from_owned(
        cgroup_root: OwnedFd,
        broker_executable: OwnedFd,
        inspector_executable: OwnedFd,
        manager_executable: OwnedFd,
    ) -> Result<Self, NamespaceInspectorKernelAuthenticationError> {
        let broker_executable = FixedExecutable::from_owned(broker_executable)?;
        let inspector_executable = FixedExecutable::from_owned(inspector_executable)?;
        let manager_executable = FixedExecutable::from_owned(manager_executable)?;

        if broker_executable.identity == inspector_executable.identity
            || broker_executable.identity == manager_executable.identity
            || inspector_executable.identity == manager_executable.identity
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
            manager_executable,
        })
    }

    /// Authenticates and retains the broker which established a connection.
    ///
    /// # Errors
    ///
    /// Returns an error for every descriptor, procfs, liveness, or fixed-role
    /// mismatch. A procfs permission denial is not converted to weak evidence.
    pub(crate) fn authenticate_broker_connection<'peer>(
        &self,
        peer: &'peer ConnectionPeerIdentity,
    ) -> Result<RetainedInspectorConnectionPeerV1<'peer>, NamespaceInspectorKernelAuthenticationError>
    {
        let evidence = self.authenticate(
            peer.pidfd(),
            peer.initial_info(),
            Credentials::from(peer.credentials()),
            RoleExpectation::broker(&self.broker_executable),
        )?;

        Ok(RetainedInspectorConnectionPeerV1 { peer, evidence })
    }

    /// Authenticates and retains the broker nominated for one received record.
    ///
    /// # Errors
    ///
    /// Returns an error for every descriptor, procfs, liveness, or fixed-role
    /// mismatch. The record subject is consumed so its pidfd remains retained.
    pub(crate) fn authenticate_broker_record(
        &self,
        subject: KernelAuthorizedRecordSubject,
    ) -> Result<RetainedInspectorRecordSubjectV1, NamespaceInspectorKernelAuthenticationError> {
        let evidence = self.authenticate(
            subject.pidfd(),
            subject.initial_info(),
            Credentials::from(subject.credentials()),
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
    /// Returns an error for a malformed instance or any descriptor, procfs,
    /// liveness, or fixed-role mismatch.
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
            Credentials::from(subject.credentials()),
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
            Credentials::from(peer.credentials()),
            RoleExpectation::manager(&self.manager_executable),
        )?;

        Ok(RetainedSystemdManagerConnectionV1 { peer, evidence })
    }

    fn authenticate(
        &self,
        pidfd: &PidFd,
        initial_info: PidFdInfo,
        credentials: Credentials,
        expected: RoleExpectation<'_>,
    ) -> Result<RetainedKernelProcessEvidenceV1, NamespaceInspectorKernelAuthenticationError> {
        let before = pidfd.process_identity()?;
        let cgroup = self.cgroup_root.resolve(expected.cgroup)?;
        cgroup.verify_exact_membership(pidfd)?;

        let executable_before = open_proc_executable(before.pid())?;
        let mac_before = read_effective_mac_context(before.pid())?;
        let executable_after = open_proc_executable(before.pid())?;
        let mac_after = read_effective_mac_context(before.pid())?;

        cgroup.verify_exact_membership(pidfd)?;
        let after = pidfd.process_identity()?;
        validate_observation(
            expected,
            credentials,
            initial_info.into(),
            before.into(),
            after.into(),
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
            credentials,
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
    /// Returns an error unless a fresh complete pidfd, cgroup, executable, and
    /// MAC observation still matches the retained admission baseline.
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
    /// Returns an error if the process exited, migrated, its retained cgroup
    /// became inactive, or its executable or effective MAC domain changed.
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
    /// Returns an error unless a fresh complete pidfd, cgroup, executable, and
    /// MAC observation still matches the retained admission baseline.
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
    /// Returns an error if the process exited, migrated, its retained cgroup
    /// became inactive, or its executable or effective MAC domain changed.
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

impl RetainedSystemdManagerConnectionV1<'_> {
    /// Projects the checked manager into the pure protocol model.
    ///
    /// # Errors
    ///
    /// Returns an error unless a fresh complete PID 1, manager-cgroup,
    /// executable, and MAC observation still matches the admission baseline.
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
    /// Returns an error if PID 1 exited, changed identity, migrated, its
    /// retained cgroup became inactive, or its executable or MAC domain changed.
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
    credentials: Credentials,
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
            AuthenticatedRole::Manager => {
                return Err(NamespaceInspectorKernelAuthenticationError::Mismatch);
            }
        };

        Ok(KernelAuthenticatedInspectorPeerV1 {
            role,
            process: model_process(self.process, self.cgroup_id),
            uid: self.credentials.uid,
            gid: self.credentials.gid,
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
            uid: self.credentials.uid,
            gid: self.credentials.gid,
        })
    }

    fn reauthenticate(
        &self,
        pidfd: &PidFd,
        initial_info: PidFdInfo,
        credentials: Credentials,
    ) -> Result<(), NamespaceInspectorKernelAuthenticationError> {
        let before = pidfd.process_identity()?;
        self.cgroup.verify_exact_membership(pidfd)?;

        let executable_before = open_proc_executable(before.pid())?;
        let mac_before = read_effective_mac_context(before.pid())?;
        let executable_after = open_proc_executable(before.pid())?;
        let mac_after = read_effective_mac_context(before.pid())?;

        self.cgroup.verify_exact_membership(pidfd)?;
        let after = pidfd.process_identity()?;
        let expected_executable = executable_identity(self.executable.as_fd())?;
        validate_observation(
            RoleExpectation::retained(self.role, expected_executable),
            credentials,
            initial_info.into(),
            before.into(),
            after.into(),
            executable_before.identity,
            executable_after.identity,
            &mac_before,
            &mac_after,
            self.cgroup_id,
        )?;
        self.cgroup.validate_current()?;
        if after != self.process || credentials != self.credentials || !pidfd.is_alive()? {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthenticatedRole {
    Broker,
    Inspector,
    Manager,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Credentials {
    pid: u32,
    uid: u32,
    gid: u32,
}

impl From<PeerCredentials> for Credentials {
    fn from(credentials: PeerCredentials) -> Self {
        Self {
            pid: credentials.pid().get(),
            uid: credentials.uid(),
            gid: credentials.gid(),
        }
    }
}

impl From<RecordCredentials> for Credentials {
    fn from(credentials: RecordCredentials) -> Self {
        Self {
            pid: credentials.pid().get(),
            uid: credentials.uid(),
            gid: credentials.gid(),
        }
    }
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

    fn retained(role: AuthenticatedRole, executable: ExecutableIdentity) -> Self {
        let (mac_context, pid, parent_pid) = match role {
            AuthenticatedRole::Broker => (BROKER_MAC_CONTEXT, None, None),
            AuthenticatedRole::Inspector => (INSPECTOR_MAC_CONTEXT, None, None),
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
    credentials: Credentials,
    initial: InitialProcessSnapshot,
    before: ProcessIdentitySnapshot,
    after: ProcessIdentitySnapshot,
    executable_before: ExecutableIdentity,
    executable_after: ExecutableIdentity,
    mac_before: &[u8],
    mac_after: &[u8],
    cgroup_id: u64,
) -> Result<(), NamespaceInspectorKernelAuthenticationError> {
    let expected_pid = expected.pid.unwrap_or(credentials.pid);
    let expected_parent = expected.parent_pid.unwrap_or(before.parent_pid);
    let identity_matches = before == after
        && before.pid == expected_pid
        && before.thread_group_id == expected_pid
        && before.parent_pid == expected_parent
        && (expected.role == AuthenticatedRole::Manager || before.parent_pid != 0)
        && before.cgroup_id == Some(cgroup_id)
        && initial.pid == before.pid
        && initial.thread_group_id == before.thread_group_id
        && initial.parent_pid == before.parent_pid
        && initial.cgroup_id == before.cgroup_id;
    let role_matches = credentials.pid == expected_pid
        && credentials.uid == ROOT_UID
        && credentials.gid == ROOT_GID
        && executable_before == expected.executable
        && executable_after == expected.executable
        && mac_before == expected.mac_context
        && mac_after == expected.mac_context;

    if !identity_matches || !role_matches {
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
struct InitialProcessSnapshot {
    pid: u32,
    thread_group_id: u32,
    parent_pid: u32,
    cgroup_id: Option<u64>,
}

impl From<PidFdInfo> for InitialProcessSnapshot {
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
        credentials: Credentials,
        initial: InitialProcessSnapshot,
        before: ProcessIdentitySnapshot,
        after: ProcessIdentitySnapshot,
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
                self.credentials,
                self.initial,
                self.before,
                self.after,
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
        TestObservation {
            credentials: Credentials {
                pid: 41,
                uid: 0,
                gid: 0,
            },
            initial: InitialProcessSnapshot {
                pid: 41,
                thread_group_id: 41,
                parent_pid: 1,
                cgroup_id: Some(91),
            },
            before: process,
            after: process,
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
    fn every_role_axis_fails_closed() {
        let executable = executable(11, 12);

        let mut wrong_uid = broker_observation();
        wrong_uid.credentials.uid = 1;
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
    fn broker_inspector_and_manager_roles_are_not_interchangeable() {
        let broker = executable(11, 12);
        let inspector = executable(11, 13);
        let manager = executable(11, 14);
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
}
