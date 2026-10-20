//! Owns the shared retained public-mutation authorization native prefix.
//!
//! Each caller keeps its own genuine receiving purpose. This
//! mechanical owner holds only the actual peer/boot/floor destinations used by
//! their sole common authorization engine; it creates no financial or policy grant.

use std::error::Error;
use aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1;
use crate::public_api_session::PublicApiPeerRecheckV1;
use crate::cli_model::authorization_adapter::{CurrentCapabilityDecisionV1,
    RetainedAuthorizationTimeFloorV1};

/// Retains the actual native destinations used by the one authorization engine.
pub(crate) struct PublicMutationAuthorizationNativeV1 {
    pub(crate) boot: RootOriginalKernelBootIdAttemptV1,
    pub(crate) handle_peers: [PublicApiPeerRecheckV1; 2],
    pub(crate) peers: [PublicApiPeerRecheckV1; 2],
    pub(crate) time_floor: RetainedAuthorizationTimeFloorV1,
    pub(crate) decision: Option<CurrentCapabilityDecisionV1>,
    pub(crate) new_use: Option<Result<(), crate::JournalError>>,
}

impl PublicMutationAuthorizationNativeV1 {
    pub(crate) fn new() -> Self {
        Self {
            boot: RootOriginalKernelBootIdAttemptV1::new(),
            handle_peers: std::array::from_fn(|_| PublicApiPeerRecheckV1::new()),
            peers: std::array::from_fn(|_| PublicApiPeerRecheckV1::new()),
            time_floor: RetainedAuthorizationTimeFloorV1::default(),
            decision: None,
            new_use: None,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.handle_peers[0].failure().or_else(|| self.handle_peers[1].failure())
            .or_else(|| self.boot.failure()).or_else(|| self.peers[0].failure())
            .or_else(|| self.time_floor.failure().map(|cause| cause as _))
            .or_else(|| self.peers[1].failure())
            .or_else(|| self.new_use.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

