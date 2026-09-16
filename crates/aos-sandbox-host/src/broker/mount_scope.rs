//! Exact retained-scope admission before RootMount namespace/root export.
//!
//! The signed query cannot install a lease, renew a fence, or substitute a new
//! payload after reboot. All descriptor duplicates remain borrowed by the
//! prepared reply's live authority and kernel checks until the bounded send.

use std::os::fd::{BorrowedFd, OwnedFd};

use aos_sandbox_broker::BrokerAdmissionError;
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, DesiredGeneration, IncarnationId, ObjectDigest,
    RawPairedClockSample, SandboxId,
};
use aos_sandbox_protocol::mount_scope::{ValidatedMountScopeRequest, encode_mount_scope_response};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;

use super::{HostBroker, ensure_response_bound, payload_scope::PreparedPayloadScopeReply};
use crate::plan::HostCatalog;
use crate::state::HostStateStore;
use crate::worker::{HostRuntimeIdentity, HostWorker};
use crate::{HostError, Result};

impl<C: HostCatalog, S: HostStateStore, W: HostWorker + Sync> HostBroker<C, S, W> {
    pub(crate) async fn prepare_mount_scope<T>(
        &mut self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: &ValidatedMountScopeRequest,
        request_body: &[u8],
        clock: &mut T,
    ) -> Result<PreparedPayloadScopeReply<'_, 5>>
    where
        T: FnMut() -> Result<RawPairedClockSample> + Send,
    {
        self.ensure_healthy()?;
        self.state.validate_authenticated(&self.authority)?;

        let fence = request.fence();
        let identity = HostRuntimeIdentity::new(
            *fence.sandbox_id(),
            *fence.incarnation_id(),
            fence.assignment_epoch(),
            fence.desired_generation(),
            *fence.assignment_digest(),
        );
        if !self.state.contains_runtime(&identity) {
            return Err(HostError::UnknownHandle);
        }

        let prior = self
            .state
            .prior_authorization(fence.sandbox_id())
            .ok_or(HostError::UnknownHandle)?
            .to_vec();
        let current = self.authority.open_fence(fence.sandbox_id(), &prior)?;
        let admitted =
            self.authority
                .admit_mount_scope(artifacts, request, request_body, &clock()?, prior)?;
        if admitted.fence != current {
            return Err(HostError::Fence(
                "mount scope query does not match installed authority",
            ));
        }

        self.authority
            .check_before_effect(&admitted.effect, &mut || {
                clock().map_err(|_| BrokerAdmissionError::FenceRejected)
            })?;

        self.refresh_payload_scope(identity).await?;
        let pins = self
            .payload_pin(&identity)
            .ok_or(HostError::UnknownHandle)?;

        // Refresh may discover a replacement after reboot. It must never make
        // an old signed exact-scope query authorize that new payload.
        if &pins.scope_handle != request.payload_scope_handle() {
            return Err(HostError::UnknownHandle);
        }
        pins.recheck_kernel()?;

        let body =
            encode_mount_scope_response(request, pins.payload.relative_cgroup_hint().as_bytes())?;
        ensure_response_bound(&body, request.header().maximum_response_bytes())?;

        let descriptors = [
            duplicate(pins.payload.pidfd().as_fd())?,
            duplicate(pins.payload.cgroup())?,
            duplicate(pins.payload.root())?,
            duplicate(pins.payload.mount().as_fd())?,
            duplicate(pins.payload.user().as_fd())?,
        ];

        let reply = PreparedPayloadScopeReply {
            body,
            descriptors,
            pins,
            authority: &self.authority,
            effect: admitted.effect,
        };
        reply.check_before_send(clock)?;

        Ok(reply)
    }

    /// Reopens RootMount descriptors for an exact protected terminal replay.
    ///
    /// No new effect admission or deadline renewal occurs. The protected
    /// assignment fence, retained payload scope, live kernel identities, and
    /// monotone boot clock are rechecked around physical readback.
    pub(crate) async fn reopen_mount_scope_for_terminal_replay<T>(
        &mut self,
        request: &ValidatedMountScopeRequest,
        clock: &mut T,
    ) -> Result<(Vec<u8>, Vec<OwnedFd>)>
    where
        T: FnMut() -> Result<RawPairedClockSample> + Send,
    {
        self.ensure_healthy()?;
        self.state.validate_authenticated(&self.authority)?;

        let fence = request.fence();
        let identity = HostRuntimeIdentity::new(
            *fence.sandbox_id(),
            *fence.incarnation_id(),
            fence.assignment_epoch(),
            fence.desired_generation(),
            *fence.assignment_digest(),
        );
        if !self.state.contains_runtime(&identity) {
            return Err(HostError::UnknownHandle);
        }
        let expected_assignment = BrokerAssignment::new(
            SandboxId::from_bytes(*fence.sandbox_id()),
            IncarnationId::from_bytes(*fence.incarnation_id()),
            AssignmentEpoch::new(fence.assignment_epoch()),
            DesiredGeneration::new(fence.desired_generation()),
            ObjectDigest::from_bytes(*fence.assignment_digest()),
        )
        .map_err(|_| HostError::UnknownHandle)?;
        let prior = self
            .state
            .prior_authorization(fence.sandbox_id())
            .ok_or(HostError::UnknownHandle)?;
        let current = self.authority.open_fence(fence.sandbox_id(), prior)?;
        self.authority.check_current_fence(&current)?;
        if current.assignment() != expected_assignment {
            return Err(HostError::Fence(
                "mount scope replay does not match installed authority",
            ));
        }
        let _before_readback = clock()?;

        self.refresh_payload_scope(identity).await?;
        let pins = self
            .payload_pin(&identity)
            .ok_or(HostError::UnknownHandle)?;
        if &pins.scope_handle != request.payload_scope_handle() {
            return Err(HostError::UnknownHandle);
        }
        pins.recheck_kernel()?;
        let body =
            encode_mount_scope_response(request, pins.payload.relative_cgroup_hint().as_bytes())?;
        ensure_response_bound(&body, request.header().maximum_response_bytes())?;
        let descriptors = [
            duplicate(pins.payload.pidfd().as_fd())?,
            duplicate(pins.payload.cgroup())?,
            duplicate(pins.payload.root())?,
            duplicate(pins.payload.mount().as_fd())?,
            duplicate(pins.payload.user().as_fd())?,
        ];
        pins.recheck_kernel()?;
        let _after_readback = clock()?;
        let current_after = self.authority.open_fence(fence.sandbox_id(), &prior)?;
        self.authority.check_current_fence(&current_after)?;
        if current_after != current {
            return Err(HostError::Fence(
                "mount scope authority changed during replay readback",
            ));
        }

        Ok((body, Vec::from(descriptors)))
    }
}

fn duplicate(descriptor: BorrowedFd<'_>) -> Result<OwnedFd> {
    descriptor
        .try_clone_to_owned()
        .map_err(|source| HostError::Descriptor {
            operation: "clone retained mount-scope descriptor",
            source,
        })
}
