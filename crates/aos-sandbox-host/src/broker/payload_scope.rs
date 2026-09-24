//! Live signed-query admission before exporting retained payload kernel objects.
//!
//! This path never treats a completed receipt as payload authority. After a
//! broker restart it may rebuild volatile kernel pins only from the
//! authenticated completed Guardian record, the exact saved manager identities,
//! and a fresh kernel proof equal to the durable proof. It still requires the
//! exact installed plan and ownership generation. Querying cannot renew or
//! advance the durable fence. Returned descriptors are observations, not holder
//! mapping or permission to deliver a channel into the payload.

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use aos_sandbox_broker::{BrokerAdmissionError, BrokerEffectIntentV1};
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::payload_scope::{
    ValidatedPayloadScopeRequest, encode_payload_scope_response,
};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;

use super::{HostBroker, RetainedRuntimePins, ensure_response_bound};
use crate::authorization::HostAuthorityV1;
use crate::plan::HostCatalog;
use crate::state::HostStateStore;
use crate::worker::HostWorker;
use crate::{HostError, Result};

/// Keeps the exact runtime pins and authority borrowed until the send finishes.
pub(crate) struct PreparedPayloadScopeReply<'a, const N: usize = 2> {
    pub(super) body: Vec<u8>,
    pub(super) descriptors: [OwnedFd; N],
    pub(super) pins: &'a RetainedRuntimePins,
    pub(super) authority: &'a HostAuthorityV1,
    pub(super) effect: BrokerEffectIntentV1,
}

impl<const N: usize> PreparedPayloadScopeReply<'_, N> {
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn descriptors(&self) -> [BorrowedFd<'_>; N] {
        std::array::from_fn(|index| self.descriptors[index].as_fd())
    }

    pub(crate) fn into_parts(self) -> (Vec<u8>, Vec<OwnedFd>) {
        (self.body, Vec::from(self.descriptors))
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
    W: HostWorker + Sync,
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
        let fence = request.fence();
        let identity = self.checked_scope_runtime(fence)?;
        let (prior, current) = self.open_scope_fence(fence)?;
        let observed = clock()?;
        let admitted = self.authority.admit_payload_scope(
            artifacts,
            request,
            request_body,
            &observed,
            &prior,
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

        self.recover_completed_runtime_scope(identity).await?;
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

    /// Reopens descriptors for an already-protected exact terminal replay.
    ///
    /// This path deliberately does not admit a new effect or renew the
    /// historical request deadline. It requires the request assignment to
    /// equal the current protected fence and rechecks the live kernel objects
    /// and monotone boot clock around physical readback.
    pub(crate) async fn reopen_payload_scope_for_terminal_replay<T>(
        &mut self,
        request: &ValidatedPayloadScopeRequest,
        clock: &mut T,
    ) -> Result<(Vec<u8>, Vec<OwnedFd>)>
    where
        T: FnMut() -> Result<RawPairedClockSample> + Send,
    {
        let fence = request.fence();
        let identity = self.checked_scope_runtime(fence)?;
        let expected_assignment = fence
            .broker_assignment()
            .map_err(|_| HostError::UnknownHandle)?;
        let (prior, current) = self.open_scope_fence(fence)?;
        self.authority.check_current_fence(&current)?;
        if current.assignment() != expected_assignment {
            return Err(HostError::Fence(
                "payload replay does not match installed authority",
            ));
        }
        let _before_readback = clock()?;

        self.recover_completed_runtime_scope(identity).await?;
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
                    operation: "clone replay payload pidfd",
                    source,
                })?,
            pins.payload
                .cgroup()
                .try_clone_to_owned()
                .map_err(|source| HostError::Descriptor {
                    operation: "clone replay payload cgroup",
                    source,
                })?,
        ];
        pins.recheck_kernel()?;
        let _after_readback = clock()?;
        let current_after = self.authority.open_fence(fence.sandbox_id(), &prior)?;
        self.authority.check_current_fence(&current_after)?;
        if current_after != current {
            return Err(HostError::Fence(
                "payload authority changed during replay readback",
            ));
        }
        Ok((body, Vec::from(descriptors)))
    }
}
