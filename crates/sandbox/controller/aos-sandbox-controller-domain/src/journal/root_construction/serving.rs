//! Binds a completed Root transfer to its same held Journal and financial owner.
//!
//! These private identities are comparison carriers. They retain the existing
//! instance allocation and next sequence; they construct no writer, Root grant,
//! currentness result or serving permission. The terminal producer must finish
//! its actual native readback and posts before capturing its handoff bindings.

use std::sync::Arc;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::super::{Journal, JournalAuthorityInstance, JournalError};
use super::super::native_backing::JournalNativeBackingV1;

/// Keeps the actual opened instance and its completed next sequence private.
#[must_use]
pub(crate) struct RootJournalServingIdentityV1 {
    instance: Arc<JournalAuthorityInstance>,
    next: u64,
}

impl RootJournalServingIdentityV1 {
    /// Compares two captured opaque cuts without accepting a scalar identity.
    pub(crate) fn require_same_captured_cut_v2(&self, other: &Self) -> Result<(), JournalError> {
        if !Arc::ptr_eq(&self.instance, &other.instance) || self.next != other.next {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Prices two retained identities and their capture/return construction peak.
    pub(crate) fn pair_demand_v1() -> Result<ResourceVector, JournalError> {
        let bytes = std::mem::size_of::<Self>().checked_mul(8)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::LimitExceeded("Root serving identity"))?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }
}

impl Journal {
    /// Captures only an existing healthy Root-backed Journal without native IO.
    pub(crate) fn root_serving_identity_v1(
        &self,
    ) -> Result<RootJournalServingIdentityV1, JournalError> {
        self.require_root_serving_native_v1()?;
        if self.root_journal_financial.is_none() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(RootJournalServingIdentityV1 {
            instance: Arc::clone(&self.authority_instance),
            next: self.snapshot_sequence(),
        })
    }

    /// Compares the exact opened instance and unchanged completed sequence.
    pub(crate) fn require_root_serving_identity_v1(
        &self,
        identity: &RootJournalServingIdentityV1,
    ) -> Result<(), JournalError> {
        self.require_root_serving_native_v1()?;
        if !Arc::ptr_eq(&identity.instance, &self.authority_instance)
            || identity.next != self.snapshot_sequence()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Requires the same financial allocation and genuine permanent native link.
    ///
    /// This performs no native IO, re-opening, debit, reset or release. The real
    /// listener's startup borrow prevents its Initial owner from being dropped
    /// while the pair moves. Native operations continue to use their existing
    /// invocation mutex; a refused or ended invocation cannot pass this check.
    pub(crate) fn require_root_serving_financial_v1(
        &self,
        expected: &aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1,
    ) -> Result<(), JournalError> {
        self.require_root_serving_native_v1()?;
        let actual = self.root_journal_financial.as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        actual.require_same_v1(expected).map_err(|_| JournalError::RootFinancial(actual.clone()))?;
        match &self.native {
            JournalNativeBackingV1::Root(writer) => actual.require_writer_v1(writer)
                .map_err(|_| JournalError::RootFinancial(actual.clone())),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    fn require_root_serving_native_v1(&self) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        match &self.native {
            JournalNativeBackingV1::Root(writer) if !writer.is_closed_or_poisoned_v1() => Ok(()),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }
}
