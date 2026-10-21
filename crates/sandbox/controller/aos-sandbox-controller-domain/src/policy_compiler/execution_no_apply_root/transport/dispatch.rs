//! Moves the whole genuine Execution graph into the existing Root finisher.
//!
//! Every offered owner, including a failed body, uses the finite no-shutdown
//! completion arm. Only actual ACK/Root6/native posts produce a passive fixed
//! confirmation plan; only the common genuine Dpositive boundary unlocks its
//! permanent-F sender. No Result or decoded packet grants that boundary.

use super::*;
use crate::policy_compiler::root_policy_prelude::{
    RootPolicyDispositionGuardV1, RootPolicyPreludeNativeOriginalV1, RootPolicyPreludeOriginalV1,
};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

pub(crate) struct RootExecutionNoApplyDispatchOriginalV2 {
    disposition: RootPolicyDispositionGuardV1,
    original: UnixStream,
    prelude: RootPolicyPreludeNativeOriginalV1,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<Native>>,
    body: Option<Result<(), Cause>>,
    peer_post: Option<Result<(), NormalRootStartupErrorV1>>,
    peer_settled: Option<Result<(), NormalRootStartupErrorV1>>,
}

impl RootExecutionNoApplyDispatchOriginalV2 {
    fn require_complete(&self) -> Result<&Native, NormalRootStartupErrorV1> {
        if !self.disposition.entered
            || self.disposition.handed_off
            || !matches!(self.peer, Some(Ok(())))
            || !matches!(self.body, Some(Ok(())))
            || !matches!(self.peer_post, Some(Ok(())))
            || !matches!(self.peer_settled, Some(Ok(())))
            || self.prelude.failure_before_v1().is_some()
            || self.prelude.failure_after_v1().is_some()
            || self.failure().is_some()
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        let native = self
            .native
            .as_deref()
            .ok_or(NormalRootStartupErrorV1::Service)?;
        native
            .require_complete()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        Ok(native)
    }

    pub(crate) fn require_same_complete_v2(
        &self,
        original: &RetainedUnixStream,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.require_complete()?;
        original
            .require_same_endpoint_v1(self.original.as_fd())
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    pub(crate) fn completed_confirmation_plan_v2(
        &self,
    ) -> Result<crate::normal_root::RootPolicyPositiveCompletionPlanV2, NormalRootStartupErrorV1>
    {
        let native = self.require_complete()?;
        let query = native
            .opening
            .query()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        let ack = native
            .acknowledged
            .acknowledgement_data_v2()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        Ok(
            crate::normal_root::RootPolicyPositiveCompletionPlanV2::execution_no_apply_data_v2(
                query
                    .digest_v2()
                    .map_err(|_| NormalRootStartupErrorV1::Service)?,
                *ack.root_floor.as_bytes(),
                ack,
                native
                    .opening
                    .current_cutoff_v1()
                    .map_err(|_| NormalRootStartupErrorV1::Service)?,
            ),
        )
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.prelude
            .failure_before_v1()
            .or_else(|| error(&self.peer))
            .or_else(|| self.native.as_ref().and_then(|native| native.failure()))
            .or_else(|| boxed_error(&self.body))
            .or_else(|| self.prelude.failure_after_v1())
            .or_else(|| error(&self.peer_post))
            .or_else(|| error(&self.peer_settled))
    }

    // The shared native financial consumer is the sole successful destructor.
    pub(crate) fn complete_upper_disposal_v2(mut self) {
        self.disposition.handed_off = true;
        drop(self);
    }
}

impl<'flight, 'listener, 'startup> RootExecutionNoApplyReceivingV2<'flight, 'listener, 'startup> {
    pub(super) fn finish_offered_v2(mut self) -> Result<(), NormalRootStartupErrorV1> {
        let complete = matches!(self.body, Some(Ok(())))
            && matches!(self.peer_post, Some(Ok(())))
            && self
                .native
                .as_deref()
                .is_some_and(|native| native.require_complete().is_ok());
        if complete {
            self.peer_settled = Some(
                self.prelude
                    .original
                    .flight
                    .settle_execution_no_apply_controller_peer_positive_once_v2(),
            );
        }
        let Self {
            prelude,
            peer,
            native,
            body,
            peer_post,
            peer_settled,
        } = self;
        let RootPolicyPreludeOriginalV1 {
            disposition,
            original,
            flight,
            native: prelude,
            ..
        } = prelude.original;
        let work = RootExecutionNoApplyDispatchOriginalV2 {
            disposition,
            original,
            prelude,
            peer,
            native,
            body,
            peer_post,
            peer_settled,
        };
        flight.finish_execution_no_apply_dispatch_once_v2(work)
    }
}
