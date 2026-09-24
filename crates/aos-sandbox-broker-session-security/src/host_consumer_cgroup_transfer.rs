//! Closed signed-session Host-to-Storage cgroup descriptor custody.
//!
//! A method-34 response may be received only with its exact two SCM_RIGHTS
//! descriptors on the authenticated session. This move-only readback compares
//! the signed response to the current boot, retained Host service process,
//! payload leader PIDFD, and exact cgroup-v2 O_PATH object. It neither names a
//! View/Attachment nor exposes an FD, lease, or kernel grant to Storage.

use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::Path;

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::{PidFd, PidFdInfo};
use aos_sandbox_protocol::ValidatedAssignmentFence;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1,
};
use aos_sandbox_protocol::host_consumer_cgroup::{
    decode_consumer_cgroup_request_v1, decode_consumer_cgroup_response_v1,
};
use rustix::fs::{OFlags, fcntl_getfl};
use rustix::time::{ClockId, clock_gettime};

use crate::ProtectedBrokerOutcomeCurrentnessOwnerV1;

const HOST_SERVICE_CGROUP: &str = "aos.slice/aos-control.slice/aos-sandbox-hostd.service";

/// Holds comparison facts from one signed and physically checked Host reply.
///
/// These scalars are nonauthorizing without the move-only readback and a
/// separately verified current named-consumer claim from Storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedHostConsumerCgroupIdentityV1 {
    assignment: ValidatedAssignmentFence,
    runtime_handle: [u8; 32],
    payload_scope_handle: [u8; 32],
    boot_id: KernelBootId,
    kernfs_id: u64,
    deadline_boottime_nanoseconds: u64,
}

impl ProtectedHostConsumerCgroupIdentityV1 {
    /// Returns the exact Host assignment fence.
    #[must_use]
    pub const fn assignment(self) -> ValidatedAssignmentFence {
        self.assignment
    }

    /// Returns the assignment-derived runtime handle.
    #[must_use]
    pub const fn runtime_handle(self) -> [u8; 32] {
        self.runtime_handle
    }

    /// Returns the exact retained Guardian scope handle.
    #[must_use]
    pub const fn payload_scope_handle(self) -> [u8; 32] {
        self.payload_scope_handle
    }

    /// Returns the kernel boot of both the signed reply and local procfs.
    #[must_use]
    pub const fn boot_id(self) -> KernelBootId {
        self.boot_id
    }

    /// Returns the full physical cgroup-v2 kernfs ID.
    #[must_use]
    pub const fn kernfs_id(self) -> u64 {
        self.kernfs_id
    }

    /// Returns the exclusive BOOTTIME request deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(self) -> u64 {
        self.deadline_boottime_nanoseconds
    }
}

/// Retains one authenticated signed outcome and exact live Host/payload pins.
///
/// No public constructor or FD accessor exists. The signed session remains
/// production-unadvertised, and this type cannot authorize a LocalLive effect.
#[must_use = "retain signed Host currentness until the named consumer join"]
pub struct ProtectedHostConsumerCgroupTransferV1 {
    _outcome: AuthenticatedBrokerMethodOutcomeV1,
    _currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    host_process: PidFd,
    host_service: RetainedCgroupAnchor,
    host_info: PidFdInfo,
    payload: PidFd,
    cgroup: RetainedCgroupAnchor,
    payload_info: PidFdInfo,
    identity: ProtectedHostConsumerCgroupIdentityV1,
}

impl ProtectedHostConsumerCgroupTransferV1 {
    pub(crate) fn from_authenticated_response(
        outcome: AuthenticatedBrokerMethodOutcomeV1,
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
        descriptors: Vec<OwnedFd>,
        host_peer_pidfd: OwnedFd,
    ) -> Result<Self, ()> {
        if outcome.method() != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP
            || outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        {
            return Err(());
        }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(());
        };
        let request = outcome.request();
        let now = boottime().ok_or(())?;
        let query = decode_consumer_cgroup_request_v1(
            request.exact_body(),
            request.peer(),
            request.peer_policy(),
            now,
        )
        .map_err(|_| ())?;
        let response = decode_consumer_cgroup_response_v1(exact_body, &query).map_err(|_| ())?;
        let boot_id = KernelBootId::current().map_err(|_| ())?;
        if boot_id.into_bytes() != response.boot_id() {
            return Err(());
        }

        let (payload, cgroup, payload_info) =
            verify_payload_descriptors(descriptors, response.cgroup_kernfs_id())?;

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
        if host_info.pid() != host_info.thread_group_id() {
            return Err(());
        }
        let identity = ProtectedHostConsumerCgroupIdentityV1 {
            assignment: *query.fence(),
            runtime_handle: *query.runtime_handle(),
            payload_scope_handle: *query.payload_scope_handle(),
            boot_id,
            kernfs_id: cgroup.kernel_id(),
            deadline_boottime_nanoseconds: query.header().deadline_boottime_nanoseconds(),
        };
        let readback = Self {
            _outcome: outcome,
            _currentness: currentness,
            host_process,
            host_service,
            host_info,
            payload,
            cgroup,
            payload_info,
            identity,
        };
        readback.recheck().map_err(|_| ())?;
        Ok(readback)
    }

    /// Returns nonauthorizing comparison facts after fresh physical readback.
    ///
    /// # Errors
    ///
    /// Rejects an expired or physically stale retained Host observation.
    pub fn identity(&self) -> Result<ProtectedHostConsumerCgroupIdentityV1, &'static str> {
        self.recheck()?;
        Ok(self.identity)
    }

    /// Rechecks boot, deadline, exact Host process, payload, and cgroup object.
    ///
    /// This cannot prove a current Attachment or prevent later task migration.
    /// The retained signed terminal still needs a protected journal-head check
    /// at any future effect boundary; this does not authorize FD export.
    ///
    /// # Errors
    ///
    /// Rejects expiry, reboot, substituted/retired cgroup, Host or payload
    /// exit, or changed exact cgroup membership.
    pub fn recheck(&self) -> Result<(), &'static str> {
        if KernelBootId::current().map_err(|_| "boot")? != self.identity.boot_id
            || boottime().ok_or("clock")? >= self.identity.deadline_boottime_nanoseconds
            || self.cgroup.kernel_id() != self.identity.kernfs_id
        {
            return Err("stale");
        }
        let host_info = self
            .host_service
            .verify_exact_membership(&self.host_process)
            .map_err(|_| "host")?;
        let payload_info = self
            .cgroup
            .verify_exact_membership(&self.payload)
            .map_err(|_| "payload")?;
        if host_info != self.host_info || payload_info != self.payload_info {
            return Err("identity");
        }
        let final_host_info = self.host_service
            .verify_exact_membership(&self.host_process)
            .map_err(|_| "host")?;
        if final_host_info != self.host_info {
            return Err("host identity");
        }
        if boottime().ok_or("clock")? >= self.identity.deadline_boottime_nanoseconds {
            return Err("deadline");
        }
        Ok(())
    }
}

fn boottime() -> Option<u64> {
    let now = clock_gettime(ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).ok()?;
    let nanos = u64::try_from(now.tv_nsec).ok()?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}

fn verify_payload_descriptors(
    descriptors: Vec<OwnedFd>,
    expected_kernfs_id: u64,
) -> Result<(PidFd, RetainedCgroupAnchor, PidFdInfo), ()> {
    let [payload_fd, cgroup_fd]: [OwnedFd; 2] = descriptors.try_into().map_err(|_| ())?;
    if !fcntl_getfl(&cgroup_fd)
        .map_err(|_| ())?
        .contains(OFlags::PATH)
    {
        return Err(());
    }
    let payload = PidFd::from_owned(payload_fd).map_err(|_| ())?;
    let cgroup = CgroupV2Root::from_owned(cgroup_fd)
        .and_then(|root| root.resolve(Path::new(".")))
        .map_err(|_| ())?;
    let payload_info = cgroup.verify_exact_membership(&payload).map_err(|_| ())?;
    if payload_info.pid() != payload_info.thread_group_id()
        || cgroup.kernel_id() != expected_kernfs_id
    {
        return Err(());
    }
    Ok((payload, cgroup, payload_info))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_or_substituted_descriptor_pairs_fail_closed() {
        let ordinary: OwnedFd = File::open("/dev/null").unwrap().into();
        assert!(verify_payload_descriptors(vec![ordinary], 1).is_err());

        let payload: OwnedFd = File::open("/dev/null").unwrap().into();
        let cgroup: OwnedFd = File::open("/dev/null").unwrap().into();
        assert!(verify_payload_descriptors(vec![payload, cgroup], 1).is_err());
    }
}
