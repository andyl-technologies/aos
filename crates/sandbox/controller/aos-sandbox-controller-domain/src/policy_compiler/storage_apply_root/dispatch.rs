//! Transfers the completed actual Apply work into the same Root flight.
//!
//! The private constructor moves the entire paid exchange after final160 and
//! actual purpose settlement. The upper same-purpose finisher still owns End,
//! independent Root post, token preparation and physical upper disposal.

use std::error::Error;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::root_policy_prelude::{RootPolicyPreludeOriginalV1,
    RootPolicyDispositionGuardV1, RootPolicyPreludeNativeOriginalV1};
use super::{RootStorageApplyReceivingV1, RootStorageApplyOpeningOriginalV1,
    UnsignedFailureSourceV1, receiving::RootStorageApplyNativeOriginalV1};

pub(crate) struct RootStorageApplyDispatchOriginalV1 {
    disposition: RootPolicyDispositionGuardV1,
    original: UnixStream,
    prelude: RootPolicyPreludeNativeOriginalV1,
    opening: RootStorageApplyOpeningOriginalV1,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<RootStorageApplyNativeOriginalV1>>,
    unsigned: Option<Result<(), Box<dyn Error>>>,
    unsigned_failure: Option<UnsignedFailureSourceV1>,
    negative: Option<Result<(), NormalRootStartupErrorV1>>,
    negative_disposition: Option<Result<(), NormalRootStartupErrorV1>>,
    closed: bool,
}

impl RootStorageApplyDispatchOriginalV1 {
    pub(crate) fn require_same_complete_v1(&self, native: &RetainedUnixStream)
        -> Result<(), NormalRootStartupErrorV1>
    {
        if self.closed || self.failure().is_some() || !matches!(self.unsigned, Some(Ok(())))
            || self.unsigned_failure.is_some() || self.negative.is_some() || self.negative_disposition.is_some()
        { return Err(NormalRootStartupErrorV1::Service); }
        self.native.as_ref().and_then(|native| native.final_exchange.as_ref())
            .ok_or(NormalRootStartupErrorV1::Service)?.require_complete_v1()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        native.require_same_endpoint_v1(self.original.as_fd()).map_err(|_| NormalRootStartupErrorV1::Service)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.prelude.failure_before_v1()
            .or_else(|| self.peer.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.opening.failure())
            .or_else(|| self.native.as_ref().and_then(|native| native.failure()))
            .or_else(|| self.unsigned.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.prelude.failure_after_v1())
    }

    // This is called only after actual same-purpose token preparation. The
    // whole native/model/socket prefix is destroyed before token completion.
    pub(crate) fn complete_upper_disposal_v1(mut self) {
        self.disposition.handed_off = true;
        drop(self);
    }
}

impl<'flight, 'listener, 'startup> RootStorageApplyReceivingV1<'flight, 'listener, 'startup> {
    pub(crate) fn into_completed_dispatch_v1(self)
        -> Result<(RootStorageApplyDispatchOriginalV1,
            &'flight mut RootPolicyAcceptedFlightV1<'listener, 'startup>), Self>
    {
        if self.require_final_complete_v1().is_err() { return Err(self); }
        let Self { prelude, opening, peer, native, unsigned, unsigned_failure,
            negative, negative_disposition, closed } = self;
        // The omitted negative_post is necessarily None on this positive-only
        // transfer. All native owners and its first-field guard move together.
        let RootPolicyPreludeOriginalV1 { disposition, original, flight, native: prelude, .. } = prelude.original;
        Ok((RootStorageApplyDispatchOriginalV1 { disposition, original, prelude,
            opening, peer, native, unsigned, unsigned_failure, negative, negative_disposition, closed }, flight))
    }
}
