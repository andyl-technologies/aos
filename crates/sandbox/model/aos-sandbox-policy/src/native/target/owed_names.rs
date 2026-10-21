//! Owns the separately owed Target-name post without consulting body refusal.
//!
//! The destination uses the sole fixed Policy Owner sampler and custody
//! driver. Its failure latch is independent from the current-input destination,
//! so an earlier body refusal cannot suppress this already owed observation.

use super::currentness::{self, PolicyTargetCurrentCustodyV1};
use crate::native::{PolicyNativeJournalErrorV1 as ErrorV1, journal::RootPolicyJournalV1};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use std::error::Error;

pub(super) struct PolicyTargetOwedNamesCustodyV1 {
    original: PolicyTargetCurrentCustodyV1,
}

impl PolicyTargetOwedNamesCustodyV1 {
    pub(super) fn new() -> Self {
        Self {
            original: PolicyTargetCurrentCustodyV1::new(),
        }
    }

    pub(super) fn constructor_demand_v1() -> Result<ResourceVector, ErrorV1> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(ErrorV1::geometry)?;
        PolicyTargetCurrentCustodyV1::constructor_demand_v1()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(|_| ErrorV1::geometry())
    }

    pub(super) fn finish_once_v1(&self, journal: &RootPolicyJournalV1) -> Result<(), ErrorV1> {
        currentness::require_current_names_v1(journal, &self.original)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}
