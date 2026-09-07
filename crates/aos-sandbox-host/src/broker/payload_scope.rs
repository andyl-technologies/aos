//! Live signed-query admission before exporting retained payload kernel objects.
//!
//! This path never restores payload authority from a completed receipt. It
//! requires the exact installed plan and ownership generation, plus a fresh
//! observation of the launch-retained payload. Querying cannot renew or advance
//! the durable fence. Returned descriptors are observations, not holder mapping
//! or permission to deliver a channel into the payload.

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use aos_sandbox_broker::{BrokerAdmissionError, BrokerEffectIntentV2};
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::payload_scope::{
    ValidatedPayloadScopeRequest, encode_payload_scope_response,
};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;

use super::{HostBroker, RetainedRuntimePins, ensure_response_bound};
use crate::authorization::HostAuthorityV1;
use crate::plan::HostCatalog;
use crate::state::HostStateStore;
use crate::worker::{HostRuntimeIdentity, HostWorker};
use crate::{HostError, Result};

/// Keeps the exact runtime pins and authority borrowed until the send finishes.
pub(crate) struct PreparedPayloadScopeReply<'a, const N: usize = 2> {
    pub(super) body: Vec<u8>,
    pub(super) descriptors: [OwnedFd; N],
    pub(super) pins: &'a RetainedRuntimePins,
    pub(super) authority: &'a HostAuthorityV1,
    pub(super) effect: BrokerEffectIntentV2,
}

impl<const N: usize> PreparedPayloadScopeReply<'_, N> {
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn descriptors(&self) -> [BorrowedFd<'_>; N] {
        std::array::from_fn(|index| self.descriptors[index].as_fd())
    }

    /// Rechecks both retained kernel identity and the live query deadline.
    pub(crate) fn check_before_send<T>(&self, clock: &mut T) -> Result<()>
    where
        T: FnMut() -> Result<RawPairedClockSample>,
    {
        self.pins.recheck_kernel()?;
        self.authority.check_before_effect(&self.effect, &mut || {
            clock().map_err(|_| BrokerAdmissionError::FenceRejected)
        })?;
        self.pins.recheck_kernel()
    }
}

impl<C, S, W> HostBroker<C, S, W>
where
    C: HostCatalog,
    S: HostStateStore,
    W: HostWorker,
{
    pub(crate) async fn prepare_payload_scope<T>(
        &mut self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: &ValidatedPayloadScopeRequest,
        request_body: &[u8],
        clock: &mut T,
    ) -> Result<PreparedPayloadScopeReply<'_>>
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
            .ok_or(HostError::UnknownHandle)?;
        let current = self.authority.open_fence(fence.sandbox_id(), prior)?;
        let observed = clock()?;
        let admitted = self.authority.admit_payload_scope(
            artifacts,
            request,
            request_body,
            &observed,
            prior,
        )?;
        // Admission can propose a newer valid lease. This read path cannot
        // install that fence, and a newer request cannot prove an older runtime
        // belongs to it. Only an already-installed exact fence may export pins.
        if admitted.fence != current {
            return Err(HostError::Fence(
                "payload query does not match installed authority",
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
        pins.recheck_kernel()?;
        let body = encode_payload_scope_response(
            fence,
            request.runtime_handle(),
            &pins.scope_handle,
            pins.payload.relative_cgroup_hint().as_bytes(),
        )?;
        ensure_response_bound(&body, request.header().maximum_response_bytes())?;
        let descriptors = [
            pins.payload
                .pidfd()
                .as_fd()
                .try_clone_to_owned()
                .map_err(|source| HostError::Descriptor {
                    operation: "clone payload pidfd",
                    source,
                })?,
            pins.payload
                .cgroup()
                .try_clone_to_owned()
                .map_err(|source| HostError::Descriptor {
                    operation: "clone payload cgroup",
                    source,
                })?,
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
}
