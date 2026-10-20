//! Transfers whole completed Recover work to the sole Root disposition engine.

use super::{receiving::RootFinalityRecoverNativeOriginalV1, RootFinalityRecoverReceivingV1};
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::root_policy_prelude::{
    RootPolicyDispositionGuardV1, RootPolicyPreludeNativeOriginalV1, RootPolicyPreludeOriginalV1,
};
use aos_sandbox_linux::unix_stream::RetainedUnixStream;
use std::error::Error;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

/// Holds every reached original through actual End, Root post and upper disposal.
pub(crate) struct RootFinalityRecoverDispatchOriginalV1 {
    disposition: RootPolicyDispositionGuardV1,
    original: UnixStream,
    prelude: RootPolicyPreludeNativeOriginalV1,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    geometry: Option<Result<aos_sandbox_core::ResourceVector, Box<dyn Error>>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<RootFinalityRecoverNativeOriginalV1>>,
    result: Option<Result<(), crate::journal::JournalError>>,
}

impl RootFinalityRecoverDispatchOriginalV1 {
    pub(crate) fn require_same_complete_v1(
        &self,
        native: &RetainedUnixStream,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.failure().is_some()
            || !matches!(self.peer, Some(Ok(())))
            || !matches!(self.funding, Some(Ok(())))
            || !matches!(self.result, Some(Ok(())))
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.native
            .as_ref()
            .ok_or(NormalRootStartupErrorV1::Service)?
            .require_disposed_complete_v1()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        native
            .require_same_endpoint_v1(self.original.as_fd())
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.prelude
            .failure_before_v1()
            .or_else(|| self.peer.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.geometry.as_ref()?.as_ref().err().map(|cause| &**cause))
            .or_else(|| {
                self.funding
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.native
                    .as_ref()
                    .and_then(|native| native.owned_failure_v1())
            })
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.prelude.failure_after_v1())
    }

    pub(crate) fn complete_upper_disposal_v1(mut self) {
        self.disposition.handed_off = true;
        drop(self);
    }
}

impl<'flight, 'listener, 'startup> RootFinalityRecoverReceivingV1<'flight, 'listener, 'startup> {
    pub(super) fn into_completed_dispatch_v1(
        self,
    ) -> Result<
        (
            RootFinalityRecoverDispatchOriginalV1,
            &'flight mut RootPolicyAcceptedFlightV1<'listener, 'startup>,
        ),
        Self,
    > {
        if self.require_complete_v1().is_err() {
            return Err(self);
        }
        let Self {
            prelude,
            peer,
            entry,
            geometry,
            funding,
            native,
            result,
            negative,
            negative_disposition,
            closed,
        } = self;
        // These controls have already been required absent by the actual
        // complete gate; no failed original is retired by this transfer.
        let _completed_controls = (entry, negative, negative_disposition, closed);
        let RootPolicyPreludeOriginalV1 {
            disposition,
            original,
            flight,
            native: prelude,
            ..
        } = prelude.original;
        Ok((
            RootFinalityRecoverDispatchOriginalV1 {
                disposition,
                original,
                prelude,
                peer,
                geometry,
                funding,
                native,
                result,
            },
            flight,
        ))
    }
}
