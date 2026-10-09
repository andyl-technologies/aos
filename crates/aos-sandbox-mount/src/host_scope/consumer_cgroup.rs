//! Move-only Host-origin readback of one retained payload cgroup.
//!
//! `ObserveMountScope` authenticates Host and its current Guardian payload
//! scope before transferring the cgroup O_PATH descriptor. This wrapper keeps
//! that live Host and payload evidence with the leader's exact cgroup object,
//! resolving Host's validated descendant hint when the leader is not in the
//! payload subtree root. It never accepts a caller-nominated FD or kernfs ID,
//! identifies an Attachment, or authorizes a LocalLive export. Other tasks
//! can occupy different descendant cgroups; one leader ID never stands for
//! the subtree.

use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::{
    CgroupPopulationMonitor, CgroupPopulationState, CgroupV2Root, RetainedCgroupAnchor,
};
use aos_sandbox_protocol::ValidatedAssignmentFence;

use super::{HostScopeError, ObservedMountScope, Result};

/// Describes the exact Host-retained cgroup object and bounded observation.
///
/// These scalar fields are comparison data, never a substitute for the held
/// readback, its O_PATH descriptor, and fresh Host/Guardian currentness checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedHostCgroupIdentityV1 {
    boot_id: KernelBootId,
    assignment: ValidatedAssignmentFence,
    runtime_handle: [u8; 32],
    payload_scope_handle: [u8; 32],
    kernfs_id: u64,
    valid_until_boottime_nanoseconds: u64,
}

impl ProtectedHostCgroupIdentityV1 {
    /// Returns the kernel incarnation in which the object was observed.
    #[must_use]
    pub const fn boot_id(self) -> KernelBootId {
        self.boot_id
    }

    /// Returns Host's exact signed current-assignment fence.
    #[must_use]
    pub const fn assignment(self) -> ValidatedAssignmentFence {
        self.assignment
    }

    /// Returns the assignment-derived runtime handle checked by Host.
    #[must_use]
    pub const fn runtime_handle(self) -> [u8; 32] {
        self.runtime_handle
    }

    /// Returns Host's opaque retained Guardian payload-scope handle.
    #[must_use]
    pub const fn payload_scope_handle(self) -> [u8; 32] {
        self.payload_scope_handle
    }

    /// Returns the full 64-bit cgroup-v2 kernfs ID of the leader's exact cgroup.
    #[must_use]
    pub const fn kernfs_id(self) -> u64 {
        self.kernfs_id
    }

    /// Returns the exclusive BOOTTIME deadline of the signed Host query.
    #[must_use]
    pub const fn valid_until_boottime_nanoseconds(self) -> u64 {
        self.valid_until_boottime_nanoseconds
    }

    /// Compares an independently verified claim's assignment and time window.
    ///
    /// This is only a necessary join check. It does not verify that the claim
    /// was signed or that its named View/Attachment and holder remain current.
    #[must_use]
    pub fn matches_assignment_window(
        self,
        assignment: ValidatedAssignmentFence,
        boot_id: KernelBootId,
        expires_boottime_nanoseconds: u64,
    ) -> bool {
        self.assignment == assignment
            && self.boot_id == boot_id
            && expires_boottime_nanoseconds != 0
            && expires_boottime_nanoseconds <= self.valid_until_boottime_nanoseconds
    }
}

/// Holds the authenticated Host execution, exact leader membership, and cgroup FD.
///
/// The type is intentionally neither `Clone` nor caller-constructible. A
/// separate protected Controller/RootMount claim must name the View/Attachment,
/// holder authority and Provider effect; Storage must join that claim to this
/// live Host-origin object before any private deny-stage kernel handoff.
pub struct ProtectedHostCgroupReadbackV1 {
    scope: ObservedMountScope,
    leader_cgroup: RetainedCgroupAnchor,
    identity: ProtectedHostCgroupIdentityV1,
    population: CgroupPopulationMonitor,
}

impl ProtectedHostCgroupReadbackV1 {
    pub(super) fn from_observed(scope: ObservedMountScope) -> Result<Self> {
        let boot_id = KernelBootId::current()?;
        scope.recheck()?;
        let leader_cgroup = exact_leader_cgroup(&scope)?;
        let leader = leader_cgroup.verify_exact_membership(&scope.payload)?;
        if leader != scope.payload_info {
            return Err(HostScopeError::PayloadIdentity);
        }
        let population = leader_cgroup.population_monitor()?;
        let identity = ProtectedHostCgroupIdentityV1 {
            boot_id,
            assignment: *scope.metadata.fence(),
            runtime_handle: *scope.metadata.runtime_handle(),
            payload_scope_handle: *scope.metadata.payload_scope_handle(),
            kernfs_id: leader_cgroup.kernel_id(),
            valid_until_boottime_nanoseconds: scope.deadline,
        };
        let readback = Self {
            scope,
            leader_cgroup,
            identity,
            population,
        };
        readback.recheck()?;
        Ok(readback)
    }

    /// Returns comparison metadata without transferring kernel authority.
    #[must_use]
    pub const fn identity(&self) -> ProtectedHostCgroupIdentityV1 {
        self.identity
    }

    /// Rechecks the same boot, Host execution, Guardian payload, and cgroup.
    ///
    /// The original signed-query deadline is not renewed. No View/Attachment
    /// or RootMount holder currentness is inferred from this Host-only proof.
    ///
    /// # Errors
    ///
    /// Rejects expiry, reboot, changed Host or payload identity, exited
    /// payload, changed membership, or a retired/replaced cgroup object.
    pub fn recheck(&self) -> Result<()> {
        if KernelBootId::current()? != self.identity.boot_id {
            return Err(HostScopeError::PayloadIdentity);
        }
        self.scope.recheck()?;
        let leader = self
            .leader_cgroup
            .verify_exact_membership(&self.scope.payload)?;
        if leader != self.scope.payload_info
            || self.leader_cgroup.kernel_id() != self.identity.kernfs_id
        {
            return Err(HostScopeError::PayloadIdentity);
        }
        self.scope.recheck()
    }

    /// Borrows the exact cgroup-v2 O_PATH descriptor after fresh readback.
    ///
    /// This descriptor is not a grant. The caller must keep this readback
    /// held and recheck it around any separate authenticated transfer.
    ///
    /// # Errors
    ///
    /// Returns the same currentness failures as [`Self::recheck`].
    pub fn cgroup_fd(&self) -> Result<BorrowedFd<'_>> {
        self.recheck()?;
        Ok(self.leader_cgroup.as_fd())
    }

    /// Reads the exact retained cgroup's population or kernel retirement.
    ///
    /// This observation may remain useful after the Host query expires, but
    /// neither emptiness nor retirement alone proves LocalLive hard revocation.
    ///
    /// # Errors
    ///
    /// Rejects a changed boot or malformed/unavailable cgroup events readback.
    pub fn population_state(&self) -> Result<CgroupPopulationState> {
        if KernelBootId::current()? != self.identity.boot_id {
            return Err(HostScopeError::PayloadIdentity);
        }
        Ok(self.population.state()?)
    }
}

fn exact_leader_cgroup(scope: &ObservedMountScope) -> Result<RetainedCgroupAnchor> {
    let hint = scope.metadata.leader_cgroup_hint();
    if hint.is_empty() {
        let duplicate = rustix::io::fcntl_dupfd_cloexec(scope.cgroup.as_fd(), 0)?;
        return Ok(CgroupV2Root::from_owned(duplicate)?.resolve(Path::new("."))?);
    }

    let relative = Path::new(std::ffi::OsStr::from_bytes(hint));
    Ok(scope.cgroup.resolve_descendant(relative)?)
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{
        AssignmentFence, Audience, ObserveMountScopeRequest, RequestHeader,
    };
    use aos_sandbox_protocol::mount_scope::decode_mount_scope_request;
    use aos_sandbox_protocol::semantics::host::runtime_handle_v1;
    use buffa::Message as _;

    use super::*;
    use crate::host_scope::{PeerCredentials, PeerPolicy};

    fn assignment(epoch: u64) -> ValidatedAssignmentFence {
        let request = ObserveMountScopeRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![1; 16],
                audience: Audience::AUDIENCE_ROOT_MOUNT.into(),
                deadline_boottime_nanoseconds: 100,
                maximum_response_bytes: 8192,
                ..Default::default()
            })
            .into(),
            fence: Some(AssignmentFence {
                sandbox_id: vec![2; 16],
                incarnation_id: vec![3; 16],
                assignment_epoch: epoch,
                desired_generation: 4,
                assignment_digest: vec![5; 32],
                ..Default::default()
            })
            .into(),
            runtime_handle: runtime_handle_v1(&[3; 16], epoch, &[5; 32]).to_vec(),
            payload_scope_handle: vec![6; 32],
            ..Default::default()
        };
        *decode_mount_scope_request(
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
            1,
        )
        .unwrap()
        .fence()
    }

    #[test]
    fn independent_claim_requires_same_assignment_boot_and_bounded_lifetime() {
        let boot = KernelBootId::parse(b"00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let other_boot = KernelBootId::parse(b"10112233-4455-6677-8899-aabbccddeeff").unwrap();
        let host = ProtectedHostCgroupIdentityV1 {
            boot_id: boot,
            assignment: assignment(1),
            runtime_handle: [7; 32],
            payload_scope_handle: [8; 32],
            kernfs_id: 9,
            valid_until_boottime_nanoseconds: 100,
        };

        assert!(host.matches_assignment_window(assignment(1), boot, 100));
        assert!(!host.matches_assignment_window(assignment(2), boot, 99));
        assert!(!host.matches_assignment_window(assignment(1), other_boot, 99));
        assert!(!host.matches_assignment_window(assignment(1), boot, 101));
        assert!(!host.matches_assignment_window(assignment(1), boot, 0));
    }
}
