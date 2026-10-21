//! Transfers the same completed resource work into Root's upper native finisher.

use super::{
    RootHostLaunchOpeningOriginalV2,
    native::RootStartResourceNativeOriginalV2,
    server::{First, RootStartResourceReceivingV2},
};
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::root_policy_prelude::{
    RootPolicyDispositionGuardV1, RootPolicyPreludeNativeOriginalV1, RootPolicyPreludeOriginalV1,
};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

type Cause = Box<dyn std::error::Error>;

pub(crate) struct RootStartResourceDispatchOriginalV2 {
    disposition: RootPolicyDispositionGuardV1,
    original: UnixStream,
    prelude: RootPolicyPreludeNativeOriginalV1,
    opening: RootHostLaunchOpeningOriginalV2,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<RootStartResourceNativeOriginalV2>>,
    unsigned: Option<Result<(), Cause>>,
    final_result: Option<Result<(), Cause>>,
    first: Option<First>,
    negative: Option<Result<(), NormalRootStartupErrorV1>>,
    negative_disposition: Option<Result<(), NormalRootStartupErrorV1>>,
    closed: bool,
}

impl RootStartResourceDispatchOriginalV2 {
    pub(crate) fn require_same_complete_v2(
        &self,
        native: &RetainedUnixStream,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.closed
            || self.first.is_some()
            || self.negative.is_some()
            || self.negative_disposition.is_some()
            || !matches!(self.unsigned, Some(Ok(())))
            || !matches!(self.final_result, Some(Ok(())))
            || self.failure().is_some()
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.native
            .as_ref()
            .and_then(|native| native.final_exchange.as_ref())
            .ok_or(NormalRootStartupErrorV1::Service)?
            .require_complete_v2()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        native
            .require_same_endpoint_v1(self.original.as_fd())
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.prelude
            .failure_before_v1()
            .or_else(|| self.peer.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.opening.failure())
            .or_else(|| self.native.as_ref().and_then(|native| native.failure()))
            .or_else(|| {
                self.unsigned
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| {
                self.final_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| self.prelude.failure_after_v1())
    }

    // Only the actual same-purpose token consumer calls this after all upper
    // posts. Destroy the whole owning prefix before completing that token.
    pub(crate) fn complete_upper_disposal_v2(mut self) {
        self.disposition.handed_off = true;
        drop(self);
    }
}

impl<'flight, 'listener, 'startup> RootStartResourceReceivingV2<'flight, 'listener, 'startup> {
    pub(super) fn into_completed_dispatch_v2(
        self,
    ) -> Result<
        (
            RootStartResourceDispatchOriginalV2,
            &'flight mut RootPolicyAcceptedFlightV1<'listener, 'startup>,
        ),
        Self,
    > {
        if self.require_final_complete_v2().is_err() {
            return Err(self);
        }
        let Self {
            prelude,
            opening,
            peer,
            native,
            unsigned,
            final_result,
            first,
            negative,
            negative_disposition,
            closed,
        } = self;
        let RootPolicyPreludeOriginalV1 {
            disposition,
            original,
            flight,
            native: prelude,
            ..
        } = prelude.original;
        Ok((
            RootStartResourceDispatchOriginalV2 {
                disposition,
                original,
                prelude,
                opening,
                peer,
                native,
                unsigned,
                final_result,
                first,
                negative,
                negative_disposition,
                closed,
            },
            flight,
        ))
    }
}
