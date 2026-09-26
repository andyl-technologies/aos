//! Move-only RootMount custody for one signed method-45 Host response.
//!
//! The five SCM_RIGHTS descriptors are adopted only from the same authenticated
//! response record and compared with Host's namespace identity body. This is
//! current Host observation, not launch-stable userns or Controller namespace
//! generation evidence. No FD or mount authority escapes this closed owner.

use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::path::BeneathRoot;
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind, PidFd, PidFdInfo};
use aos_sandbox_protocol::ValidatedAssignmentFence;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1,
};
use aos_sandbox_protocol::mount_scope::decode_mount_scope_request;
use aos_sandbox_protocol::mount_scope_identity::{
    HostNamespaceIdentityV1, ValidatedMountScopeIdentityResponseV1,
    decode_mount_scope_identity_response_v1,
};
use rustix::fs::{Mode, OFlags, fcntl_getfl, open};
use rustix::time::{ClockId, clock_gettime};

use crate::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    ProtectedBrokerOutcomeCurrentV1, ProtectedBrokerOutcomeCurrentnessOwnerV1,
};

const HOST_SERVICE_CGROUP: &str = "aos.slice/aos-control.slice/aos-sandbox-hostd.service";

/// Reports the exact current Host claim without granting a Mount effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedHostMountScopeIdentityV1 {
    assignment: ValidatedAssignmentFence,
    runtime_handle: [u8; 32],
    payload_scope_handle: [u8; 32],
    boot_id: KernelBootId,
    runtime_invocation_id: [u8; 16],
    mount_namespace: HostNamespaceIdentityV1,
    user_namespace: HostNamespaceIdentityV1,
    deadline_boottime_nanoseconds: u64,
}

impl ProtectedHostMountScopeIdentityV1 {
    /// Returns the Host-observed assignment fence.
    #[must_use]
    pub const fn assignment(self) -> ValidatedAssignmentFence {
        self.assignment
    }

    /// Returns the assignment-derived runtime handle.
    #[must_use]
    pub const fn runtime_handle(self) -> [u8; 32] {
        self.runtime_handle
    }

    /// Returns the retained Host-minted payload-scope handle.
    #[must_use]
    pub const fn payload_scope_handle(self) -> [u8; 32] {
        self.payload_scope_handle
    }

    /// Returns the current kernel boot checked against the signed Host body.
    #[must_use]
    pub const fn boot_id(self) -> KernelBootId {
        self.boot_id
    }

    /// Returns the Host-reported runtime invocation, not an independent launch proof.
    #[must_use]
    pub const fn runtime_invocation_id(self) -> [u8; 16] {
        self.runtime_invocation_id
    }

    /// Returns the identity of the actual received mount namespace FD.
    #[must_use]
    pub const fn mount_namespace(self) -> HostNamespaceIdentityV1 {
        self.mount_namespace
    }

    /// Returns the current received user namespace FD, not launch-stable userns proof.
    #[must_use]
    pub const fn user_namespace(self) -> HostNamespaceIdentityV1 {
        self.user_namespace
    }

    /// Returns the exclusive Host query deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(self) -> u64 {
        self.deadline_boottime_nanoseconds
    }
}

/// Retains signed terminal currentness with all five physically checked FDs.
///
/// The result has no descriptor accessor or effect method. A future Controller
/// cut and Mount journal join must independently establish admission.
#[must_use = "retain the signed Host terminal and its exact received descriptors"]
pub struct ProtectedHostMountScopeIdentityTransferV1 {
    outcome: AuthenticatedBrokerMethodOutcomeV1,
    currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    physical: HostMountScopePhysicalReadbackV1,
}

/// Keeps a unique protected journal borrow beside the five Host FDs.
#[must_use = "retain protected Host currentness through a future Controller join"]
pub struct ProtectedHostMountScopeCurrentV1<'session> {
    current: ProtectedBrokerOutcomeCurrentV1<'session>,
    physical: HostMountScopePhysicalReadbackV1,
}

struct HostMountScopePhysicalReadbackV1 {
    host_process: PidFd,
    host_service: RetainedCgroupAnchor,
    host_info: PidFdInfo,
    payload: PidFd,
    cgroup: RetainedCgroupAnchor,
    payload_info: PidFdInfo,
    root: BeneathRoot,
    mount: NamespaceFd,
    user: NamespaceFd,
    cgroup_hint: Vec<u8>,
    identity: ProtectedHostMountScopeIdentityV1,
}

impl ProtectedHostMountScopeIdentityTransferV1 {
    pub(crate) fn from_authenticated_response(
        outcome: AuthenticatedBrokerMethodOutcomeV1,
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
        descriptors: Vec<OwnedFd>,
        host_peer_pidfd: OwnedFd,
    ) -> Result<Self, ()> {
        if outcome.method() != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE_IDENTITY_V1
            || outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        {
            return Err(());
        }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(());
        };
        let request = outcome.request();
        let now = boottime().ok_or(())?;
        let query = decode_mount_scope_request(
            request.exact_body(),
            request.peer(),
            request.peer_policy(),
            now,
        )
        .map_err(|_| ())?;
        let response =
            decode_mount_scope_identity_response_v1(exact_body, &query).map_err(|_| ())?;
        let boot_id = KernelBootId::current().map_err(|_| ())?;
        if boot_id.into_bytes() != *response.host_boot_id() {
            return Err(());
        }

        let (payload, cgroup, root, mount, user, payload_info) =
            verify_received_descriptors(descriptors, &response)?;
        let cgroup_root =
            CgroupV2Root::from_owned(File::open("/sys/fs/cgroup").map_err(|_| ())?.into())
                .map_err(|_| ())?;
        let host_service = cgroup_root
            .resolve(Path::new(HOST_SERVICE_CGROUP))
            .map_err(|_| ())?;
        let host_process = PidFd::from_owned(host_peer_pidfd).map_err(|_| ())?;
        let host_info = host_service
            .verify_exact_membership(&host_process)
            .map_err(|_| ())?;
        let credentials = host_info.credentials().ok_or(())?;
        if host_info.pid() != host_info.thread_group_id()
            || credentials.real_user_id() != 0
            || credentials.real_group_id() != 0
            || credentials.effective_user_id() != 0
            || credentials.effective_group_id() != 0
            || credentials.saved_user_id() != 0
            || credentials.saved_group_id() != 0
            || credentials.filesystem_user_id() != 0
            || credentials.filesystem_group_id() != 0
        {
            return Err(());
        }
        let identity = ProtectedHostMountScopeIdentityV1 {
            assignment: *query.fence(),
            runtime_handle: *query.runtime_handle(),
            payload_scope_handle: *query.payload_scope_handle(),
            boot_id,
            runtime_invocation_id: *response.runtime_invocation_id(),
            mount_namespace: response.mount_namespace(),
            user_namespace: response.user_namespace(),
            deadline_boottime_nanoseconds: query.header().deadline_boottime_nanoseconds(),
        };
        let physical = HostMountScopePhysicalReadbackV1 {
            host_process,
            host_service,
            host_info,
            payload,
            cgroup,
            payload_info,
            root,
            mount,
            user,
            cgroup_hint: response.scope().leader_cgroup_hint().to_vec(),
            identity,
        };
        physical.recheck().map_err(|_| ())?;
        Ok(Self {
            outcome,
            currentness,
            physical,
        })
    }

    /// Returns nonauthorizing facts after fresh physical readback.
    ///
    /// # Errors
    ///
    /// Rejects expiry, reboot, or changed Host/payload/root/namespace pins.
    pub fn identity(&self) -> Result<ProtectedHostMountScopeIdentityV1, &'static str> {
        self.physical.recheck()?;
        Ok(self.physical.identity)
    }

    /// Joins the exact signed terminal to a unique protected journal borrow.
    ///
    /// No View/Attachment or Controller namespace-generation join exists yet.
    ///
    /// # Errors
    ///
    /// Rejects a superseded terminal or changed physical Host scope.
    pub fn into_current<'session>(
        self,
        session: &'session mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<ProtectedHostMountScopeCurrentV1<'session>, BrokerSessionSecurityError> {
        let Self {
            outcome,
            currentness,
            physical,
        } = self;
        let current = session.revalidate_broker_outcome(currentness)?;
        if current.authenticated_outcome() != &outcome || physical.recheck().is_err() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(ProtectedHostMountScopeCurrentV1 { current, physical })
    }
}

impl ProtectedHostMountScopeCurrentV1<'_> {
    /// Rechecks both protected terminal currentness and current Host kernel pins.
    ///
    /// # Errors
    ///
    /// Rejects a superseded terminal or changed physical Host scope.
    pub fn recheck(&mut self) -> Result<(), BrokerSessionSecurityError> {
        self.current.revalidate()?;
        self.physical
            .recheck()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        self.current.revalidate()
    }

    /// Returns comparison facts only while the signed terminal remains current.
    ///
    /// # Errors
    ///
    /// Rejects a superseded terminal or changed physical Host scope.
    pub fn identity(
        &mut self,
    ) -> Result<ProtectedHostMountScopeIdentityV1, BrokerSessionSecurityError> {
        self.recheck()?;
        Ok(self.physical.identity)
    }
}

impl HostMountScopePhysicalReadbackV1 {
    fn recheck(&self) -> Result<(), &'static str> {
        if KernelBootId::current().map_err(|_| "boot")? != self.identity.boot_id
            || boottime().ok_or("clock")? >= self.identity.deadline_boottime_nanoseconds
            || self.mount.identity().device != self.identity.mount_namespace.device()
            || self.mount.identity().inode != self.identity.mount_namespace.inode()
            || self.user.identity().device != self.identity.user_namespace.device()
            || self.user.identity().inode != self.identity.user_namespace.inode()
        {
            return Err("stale");
        }
        let host_info = self
            .host_service
            .verify_exact_membership(&self.host_process)
            .map_err(|_| "host")?;
        let hint = Path::new(OsStr::from_bytes(&self.cgroup_hint));
        let payload_info = if self.cgroup_hint.is_empty() {
            self.cgroup.verify_exact_membership(&self.payload)
        } else {
            self.cgroup
                .verify_descendant_membership(&self.payload, hint)
        }
        .map_err(|_| "payload")?;
        if host_info != self.host_info || payload_info != self.payload_info {
            return Err("identity");
        }
        let mount = self
            .payload
            .namespace(NamespaceKind::Mount)
            .map_err(|_| "mount")?;
        let user = self
            .payload
            .namespace(NamespaceKind::User)
            .map_err(|_| "user")?;
        if mount.identity() != self.mount.identity() || user.identity() != self.user.identity() {
            return Err("namespace changed");
        }
        let root_path = format!("/proc/{}/root", payload_info.pid());
        let root = open(
            root_path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "root")?;
        let retained_root = rustix::fs::fstat(self.root.as_fd()).map_err(|_| "root")?;
        let current_root = rustix::fs::fstat(&root).map_err(|_| "root")?;
        if (retained_root.st_dev, retained_root.st_ino)
            != (current_root.st_dev, current_root.st_ino)
            || self
                .host_service
                .verify_exact_membership(&self.host_process)
                .map_err(|_| "host")?
                != self.host_info
            || !self.payload.is_alive().map_err(|_| "payload")?
            || boottime().ok_or("clock")? >= self.identity.deadline_boottime_nanoseconds
        {
            return Err("changed");
        }
        Ok(())
    }
}

fn verify_received_descriptors(
    descriptors: Vec<OwnedFd>,
    response: &ValidatedMountScopeIdentityResponseV1,
) -> Result<
    (
        PidFd,
        RetainedCgroupAnchor,
        BeneathRoot,
        NamespaceFd,
        NamespaceFd,
        PidFdInfo,
    ),
    (),
> {
    let [payload_fd, cgroup_fd, root_fd, mount_fd, user_fd]: [OwnedFd; 5] =
        descriptors.try_into().map_err(|_| ())?;
    for fd in [&cgroup_fd, &root_fd] {
        if !fcntl_getfl(fd).map_err(|_| ())?.contains(OFlags::PATH) {
            return Err(());
        }
    }
    let payload = PidFd::from_owned(payload_fd).map_err(|_| ())?;
    let cgroup = CgroupV2Root::from_owned(cgroup_fd)
        .and_then(|root| root.resolve(Path::new(".")))
        .map_err(|_| ())?;
    let root = BeneathRoot::from_owned(root_fd).map_err(|_| ())?;
    let (mount, user) = verify_received_namespaces(
        mount_fd,
        user_fd,
        response.mount_namespace(),
        response.user_namespace(),
    )?;
    let hint = response.scope().leader_cgroup_hint();
    let payload_info = if hint.is_empty() {
        cgroup.verify_exact_membership(&payload)
    } else {
        cgroup.verify_descendant_membership(&payload, Path::new(OsStr::from_bytes(hint)))
    }
    .map_err(|_| ())?;
    if payload_info.pid() != payload_info.thread_group_id() {
        return Err(());
    }
    Ok((payload, cgroup, root, mount, user, payload_info))
}

fn verify_received_namespaces(
    mount_fd: OwnedFd,
    user_fd: OwnedFd,
    expected_mount: HostNamespaceIdentityV1,
    expected_user: HostNamespaceIdentityV1,
) -> Result<(NamespaceFd, NamespaceFd), ()> {
    let mount = NamespaceFd::from_owned(mount_fd, NamespaceKind::Mount).map_err(|_| ())?;
    let user = NamespaceFd::from_owned(user_fd, NamespaceKind::User).map_err(|_| ())?;
    let mount_identity = mount.identity();
    let user_identity = user.identity();
    if (mount_identity.device, mount_identity.inode)
        != (expected_mount.device(), expected_mount.inode())
        || (user_identity.device, user_identity.inode)
            != (expected_user.device(), expected_user.inode())
    {
        return Err(());
    }
    Ok((mount, user))
}

fn boottime() -> Option<u64> {
    let now = clock_gettime(ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).ok()?;
    let nanos = u64::try_from(now.tv_nsec).ok()?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}

#[cfg(test)]
mod tests {
    use std::os::fd::BorrowedFd;

    use aos_proto::aos::sandbox::local::v1::{
        AssignmentFence, Audience, ObserveMountScopeRequest, RequestHeader,
    };
    use aos_sandbox_broker_session_protocol::{
        BrokerSessionProtocolV1, authenticated_broker_methods_for_role_v1,
    };
    use aos_sandbox_protocol::mount_scope::decode_mount_scope_request;
    use aos_sandbox_protocol::mount_scope_identity::{
        decode_mount_scope_identity_response_v1, encode_mount_scope_identity_response_v1,
    };
    use aos_sandbox_protocol::semantics::host::runtime_handle_v1;
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
    use buffa::Message as _;

    use super::*;

    fn response() -> ValidatedMountScopeIdentityResponseV1 {
        let request = ObserveMountScopeRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 0,
                request_id: vec![1; 16],
                audience: Audience::AUDIENCE_ROOT_MOUNT.into(),
                deadline_boottime_nanoseconds: 101,
                maximum_response_bytes: 8192,
                ..Default::default()
            })
            .into(),
            fence: Some(AssignmentFence {
                sandbox_id: vec![2; 16],
                incarnation_id: vec![3; 16],
                assignment_epoch: 1,
                desired_generation: 2,
                assignment_digest: vec![4; 32],
                ..Default::default()
            })
            .into(),
            runtime_handle: runtime_handle_v1(&[3; 16], 1, &[4; 32]).to_vec(),
            payload_scope_handle: vec![5; 32],
            ..Default::default()
        };
        let request = decode_mount_scope_request(
            &request.encode_to_vec(),
            PeerCredentials {
                uid: 0,
                gid: 0,
                pid: Some(7),
            },
            PeerPolicy {
                uid: 0,
                gid: Some(0),
                audience: Audience::AUDIENCE_ROOT_MOUNT,
            },
            100,
        )
        .unwrap();
        let body = encode_mount_scope_identity_response_v1(
            &request,
            b"init.scope",
            &[6; 16],
            &[7; 16],
            HostNamespaceIdentityV1::new(8, 9).unwrap(),
            HostNamespaceIdentityV1::new(10, 11).unwrap(),
        )
        .unwrap();
        decode_mount_scope_identity_response_v1(&body, &request).unwrap()
    }

    #[test]
    fn received_namespace_fds_must_match_both_host_reported_nsfs_identities() {
        let mount: OwnedFd = File::open("/proc/self/ns/mnt").unwrap().into();
        let user: OwnedFd = File::open("/proc/self/ns/user").unwrap().into();
        let mount_identity = NamespaceFd::from_owned(mount, NamespaceKind::Mount).unwrap();
        let user_identity = NamespaceFd::from_owned(user, NamespaceKind::User).unwrap();
        let mount = mount_identity.identity();
        let user = user_identity.identity();
        let mount_expected = HostNamespaceIdentityV1::new(mount.device, mount.inode).unwrap();
        let user_expected = HostNamespaceIdentityV1::new(user.device, user.inode).unwrap();
        let duplicate = |fd: BorrowedFd<'_>| fd.try_clone_to_owned().unwrap();

        assert!(
            verify_received_namespaces(
                duplicate(mount_identity.as_fd()),
                duplicate(user_identity.as_fd()),
                mount_expected,
                user_expected,
            )
            .is_ok()
        );
        assert!(
            verify_received_namespaces(
                duplicate(user_identity.as_fd()),
                duplicate(mount_identity.as_fd()),
                mount_expected,
                user_expected,
            )
            .is_err()
        );
        for (wrong_mount, wrong_user) in [
            (
                HostNamespaceIdentityV1::new(mount.device + 1, mount.inode).unwrap(),
                user_expected,
            ),
            (
                HostNamespaceIdentityV1::new(mount.device, mount.inode + 1).unwrap(),
                user_expected,
            ),
            (
                mount_expected,
                HostNamespaceIdentityV1::new(user.device + 1, user.inode).unwrap(),
            ),
            (
                mount_expected,
                HostNamespaceIdentityV1::new(user.device, user.inode + 1).unwrap(),
            ),
        ] {
            assert!(
                verify_received_namespaces(
                    duplicate(mount_identity.as_fd()),
                    duplicate(user_identity.as_fd()),
                    wrong_mount,
                    wrong_user,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn inexact_table_and_ordinary_descriptors_cannot_form_mount_readback() {
        let response = response();
        assert!(verify_received_descriptors(Vec::new(), &response).is_err());

        let ordinary: Vec<OwnedFd> = (0..5)
            .map(|_| File::open("/dev/null").unwrap().into())
            .collect();
        assert!(verify_received_descriptors(ordinary, &response).is_err());

        let cgroup = open(
            "/sys/fs/cgroup",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let descriptors = vec![
            File::open("/dev/null").unwrap().into(),
            cgroup,
            File::open("/dev/null").unwrap().into(),
            File::open("/proc/self/ns/mnt").unwrap().into(),
            File::open("/proc/self/ns/user").unwrap().into(),
        ];
        assert!(verify_received_descriptors(descriptors, &response).is_err());
    }

    #[test]
    fn typed_identity_readback_remains_unadvertised_to_root_mount() {
        assert!(
            !authenticated_broker_methods_for_role_v1(
                BrokerSessionProtocolV1::Host,
                Audience::AUDIENCE_ROOT_MOUNT,
            )
            .contains(&BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE_IDENTITY_V1)
        );
    }
}
