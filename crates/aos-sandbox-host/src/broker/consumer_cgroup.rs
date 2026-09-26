//! Physical Host readback for Storage's exact consumer cgroup query.
//!
//! This module does not name a View or Attachment and does not authorize a
//! Storage grant. The descriptors remain sealed here until an authenticated
//! response owner can retain currentness through a terminal send and replay.

use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_broker::BrokerAuthorizationFenceV1;
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_protocol::host_consumer_cgroup::{
    ValidatedConsumerCgroupRequestV1, encode_consumer_cgroup_response_v1,
};

use super::{HostBroker, RetainedRuntimePins, ensure_response_bound};
use crate::authorization::HostAuthorityV1;
use crate::plan::HostCatalog;
use crate::state::HostStateStore;
use crate::worker::HostWorker;
use crate::{HostError, Result};

/// Holds current Host pins and the exact physical cgroup through descriptor send.
pub(crate) struct PreparedConsumerCgroupReply<'a> {
    body: Vec<u8>,
    descriptors: [OwnedFd; 2],
    pins: &'a RetainedRuntimePins,
    cgroup: RetainedCgroupAnchor,
    authority: &'a HostAuthorityV1,
    prior_authorization: Vec<u8>,
    current_fence: BrokerAuthorizationFenceV1,
    sandbox_id: [u8; 16],
    boot_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
}

impl PreparedConsumerCgroupReply<'_> {
    /// Releases the exact response and descriptor pair only after a final
    /// physical, assignment, boot, and deadline observation.
    pub(crate) fn into_checked_parts<T>(self, clock: &mut T) -> Result<(Vec<u8>, Vec<OwnedFd>)>
    where
        T: FnMut() -> Result<RawPairedClockSample>,
    {
        self.check_before_send(clock)?;
        Ok((self.body, Vec::from(self.descriptors)))
    }

    /// Rechecks the assignment, boot, deadline, and exact physical membership.
    ///
    /// # Errors
    ///
    /// Rejects a changed Host assignment, retired or migrated payload, or an
    /// expired or substituted boot-time request before the descriptor send.
    pub(crate) fn check_before_send<T>(&self, clock: &mut T) -> Result<()>
    where
        T: FnMut() -> Result<RawPairedClockSample>,
    {
        self.pins.recheck_kernel()?;
        self.cgroup
            .verify_exact_membership(self.pins.payload.pidfd())
            .map_err(|error| HostError::Worker(error.to_string()))?;

        let observed = clock()?;
        if observed.host_boot_id() != self.boot_id
            || observed.boottime_nanoseconds() >= self.deadline_boottime_nanoseconds
            || KernelBootId::current()
                .map_err(|error| HostError::Worker(error.to_string()))?
                .into_bytes()
                != self.boot_id
        {
            return Err(HostError::Fence(
                "consumer cgroup readback expired or rebooted",
            ));
        }

        let current = self
            .authority
            .open_fence(&self.sandbox_id, &self.prior_authorization)?;
        self.authority.check_current_fence(&current)?;
        if current != self.current_fence {
            return Err(HostError::Fence(
                "consumer cgroup assignment changed before descriptor send",
            ));
        }
        self.cgroup
            .verify_exact_membership(self.pins.payload.pidfd())
            .map_err(|error| HostError::Worker(error.to_string()))?;
        self.pins.recheck_kernel()?;

        let final_clock = clock()?;
        if final_clock.host_boot_id() != self.boot_id
            || final_clock.boottime_nanoseconds() >= self.deadline_boottime_nanoseconds
        {
            return Err(HostError::Fence(
                "consumer cgroup readback expired or rebooted",
            ));
        }
        Ok(())
    }
}

impl<C, S, W> HostBroker<C, S, W>
where
    C: HostCatalog,
    S: HostStateStore,
    W: HostWorker + Sync,
{
    /// Prepares Storage's read-only observation from the exact current runtime.
    ///
    /// # Errors
    ///
    /// Rejects a stale assignment, scope handle, expired deadline, kernel
    /// identity mismatch, or a payload outside its exact retained cgroup.
    pub(crate) async fn prepare_consumer_cgroup<T>(
        &mut self,
        request: &ValidatedConsumerCgroupRequestV1,
        clock: &mut T,
    ) -> Result<PreparedConsumerCgroupReply<'_>>
    where
        T: FnMut() -> Result<RawPairedClockSample> + Send,
    {
        let identity = self.checked_scope_runtime(request.fence())?;
        let expected_assignment = request
            .fence()
            .broker_assignment()
            .map_err(|_| HostError::UnknownHandle)?;
        let (prior_authorization, current_fence) = self.open_scope_fence(request.fence())?;
        self.authority.check_current_fence(&current_fence)?;
        if current_fence.assignment() != expected_assignment {
            return Err(HostError::Fence(
                "consumer cgroup query does not match current assignment",
            ));
        }

        self.recover_completed_runtime_scope(identity).await?;
        self.refresh_payload_scope(identity).await?;
        let pins = self
            .payload_pin(&identity)
            .ok_or(HostError::UnknownHandle)?;
        if &pins.scope_handle != request.payload_scope_handle() {
            return Err(HostError::UnknownHandle);
        }
        pins.recheck_kernel()?;

        // The retained payload anchor may be an ancestor. Resolve the exact
        // leader cgroup and demand equality before naming its full kernfs ID.
        let root = CgroupV2Root::from_owned(pins.payload.cgroup().try_clone_to_owned().map_err(
            |source| HostError::Descriptor {
                operation: "clone consumer cgroup root",
                source,
            },
        )?)
        .map_err(|error| HostError::Worker(error.to_string()))?;
        let relative = if pins.payload.relative_cgroup_hint().is_empty() {
            Path::new(".")
        } else {
            Path::new(pins.payload.relative_cgroup_hint())
        };
        let cgroup = root
            .resolve(relative)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        cgroup
            .verify_exact_membership(pins.payload.pidfd())
            .map_err(|error| HostError::Worker(error.to_string()))?;

        let observed = clock()?;
        let boot_id = KernelBootId::current()
            .map_err(|error| HostError::Worker(error.to_string()))?
            .into_bytes();
        if observed.host_boot_id() != boot_id
            || observed.boottime_nanoseconds() >= request.header().deadline_boottime_nanoseconds()
        {
            return Err(HostError::Fence(
                "consumer cgroup readback expired or rebooted",
            ));
        }
        let body = encode_consumer_cgroup_response_v1(request, boot_id, cgroup.kernel_id())?;
        ensure_response_bound(&body, request.header().maximum_response_bytes())?;
        let descriptors = [
            pins.payload
                .pidfd()
                .as_fd()
                .try_clone_to_owned()
                .map_err(|source| HostError::Descriptor {
                    operation: "clone consumer payload pidfd",
                    source,
                })?,
            cgroup
                .as_fd()
                .try_clone_to_owned()
                .map_err(|source| HostError::Descriptor {
                    operation: "clone exact consumer cgroup",
                    source,
                })?,
        ];
        let reply = PreparedConsumerCgroupReply {
            body,
            descriptors,
            pins,
            cgroup,
            authority: &self.authority,
            prior_authorization,
            current_fence,
            sandbox_id: *request.fence().sandbox_id(),
            boot_id,
            deadline_boottime_nanoseconds: request.header().deadline_boottime_nanoseconds(),
        };
        reply.check_before_send(clock)?;
        Ok(reply)
    }
}
