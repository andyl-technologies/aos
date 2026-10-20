//! Transfers whole completed Start input work to the sole Root disposition engine.

use super::{receiving::RootStartAssignmentInputsNativeOriginalV2,
    opening::RootStartAssignmentInputsOpeningOriginalV2 as Opening, RootStartAssignmentInputsReceivingV2};
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::root_policy_prelude::{
    RootPolicyDispositionGuardV1, RootPolicyPreludeNativeOriginalV1, RootPolicyPreludeOriginalV1,
};
use aos_sandbox_linux::unix_stream::RetainedUnixStream;
use std::error::Error;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

/// Holds every reached original through actual End, Root post and upper disposal.
pub(crate) struct RootStartAssignmentInputsDispatchOriginalV2 {
    disposition: RootPolicyDispositionGuardV1,
    original: UnixStream,
    prelude: RootPolicyPreludeNativeOriginalV1,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    opening: Opening,
    funding: Option<Result<(), crate::journal::JournalError>>,
    native: Option<Box<RootStartAssignmentInputsNativeOriginalV2>>,
    result: Option<Result<(), crate::journal::JournalError>>,
}

impl RootStartAssignmentInputsDispatchOriginalV2 {
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
            .require_disposed_complete_v2()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        native
            .require_same_endpoint_v1(self.original.as_fd())
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.prelude
            .failure_before_v1()
            .or_else(|| self.peer.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.opening.failure())
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
                    .and_then(|native| native.failure(&self.opening, None))
            })
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.prelude.failure_after_v1())
    }

    pub(crate) fn complete_upper_disposal_v1(mut self) {
        self.disposition.handed_off = true;
        drop(self);
    }
}

impl<'flight, 'listener, 'startup> RootStartAssignmentInputsReceivingV2<'flight, 'listener, 'startup> {
    pub(super) fn into_completed_dispatch_v2(
        self,
    ) -> Result<
        (
            RootStartAssignmentInputsDispatchOriginalV2,
            &'flight mut RootPolicyAcceptedFlightV1<'listener, 'startup>,
        ),
        Self,
    > {
        if self.require_complete_v2().is_err() {
            return Err(self);
        }
        let Self {
            prelude,
            peer,
            opening,
            funding,
            native,
            result,
            negative,
            negative_disposition,
            entry_original_selected,
            closed,
        } = self;
        // These controls have already been required absent by the actual
        // complete gate; no failed original is retired by this transfer.
        let _completed_controls = (entry_original_selected, negative, negative_disposition, closed);
        let RootPolicyPreludeOriginalV1 {
            disposition,
            original,
            flight,
            native: prelude,
            ..
        } = prelude.original;
        Ok((
            RootStartAssignmentInputsDispatchOriginalV2 {
                disposition,
                original,
                prelude,
                peer,
                opening,
                funding,
                native,
                result,
            },
            flight,
        ))
    }
}
