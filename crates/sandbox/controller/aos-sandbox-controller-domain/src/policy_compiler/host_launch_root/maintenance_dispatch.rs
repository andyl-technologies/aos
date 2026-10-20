//! Transfers the whole actual Maintenance graph to the shared Root upper finisher.

use super::{
    maintenance_opening::RootMaintenanceStorageOpeningOriginalV2,
    maintenance_native::RootMaintenanceNativeOriginalV3,
    maintenance_server::{MaintenanceFirstV3, RootMaintenanceStorageReceivingV3},
};
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::root_policy_prelude::{
    RootPolicyDispositionGuardV1, RootPolicyPreludeNativeOriginalV1, RootPolicyPreludeOriginalV1,
};
use aos_sandbox_linux::unix_stream::RetainedUnixStream;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

type Cause = Box<dyn std::error::Error>;

pub(crate) struct RootMaintenanceStorageDispatchOriginalV3 {
    disposition: RootPolicyDispositionGuardV1,
    original: UnixStream,
    prelude: RootPolicyPreludeNativeOriginalV1,
    opening: RootMaintenanceStorageOpeningOriginalV2,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<RootMaintenanceNativeOriginalV3>>,
    unsigned: Option<Result<(), Cause>>,
    final_result: Option<Result<(), Cause>>,
    first: Option<MaintenanceFirstV3>,
    negative: Option<Result<(), NormalRootStartupErrorV1>>,
    negative_disposition: Option<Result<(), NormalRootStartupErrorV1>>,
    closed: bool,
}

impl RootMaintenanceStorageDispatchOriginalV3 {
    pub(crate) fn require_same_complete_v3(
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
            .require_complete_v3()
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
    pub(crate) fn complete_upper_disposal_v3(mut self) {
        self.disposition.handed_off = true;
        drop(self);
    }
}

impl<'flight, 'listener, 'startup> RootMaintenanceStorageReceivingV3<'flight, 'listener, 'startup> {
    pub(super) fn into_completed_dispatch_v3(
        self,
    ) -> Result<
        (
            RootMaintenanceStorageDispatchOriginalV3,
            &'flight mut RootPolicyAcceptedFlightV1<'listener, 'startup>,
        ),
        Self,
    > {
        if self.require_final_complete_v3().is_err() {
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
            RootMaintenanceStorageDispatchOriginalV3 {
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
