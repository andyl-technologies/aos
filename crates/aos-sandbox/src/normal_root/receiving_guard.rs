//! Retains same-original financial exclusion through an upper receiving borrow.
//!
//! Shared Journal fees take the lower exclusion mutex without locking Domain.
//! Selected upper callers take that same mutex before U and release U first.
//! This restores the old fee exclusion while keeping lower native N and sums
//! M locks out of upper computation, native IO and physical owner destruction.

use std::sync::MutexGuard;

use aos_sandbox_broker::receiving::{RootJournalFinancialBorrowV1, RootUpperMutationGuardV1};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use super::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::controller_resource_reservation::RootReceivingOriginalV1;

/// Borrows one actual upper receiver and its same-original fee exclusion.
pub(crate) struct RootReceivingGuardV1<'startup> {
    // Field order preserves the entire old U interval: U unlocks before L.
    original: MutexGuard<'startup, RootReceivingOriginalV1>,
    mutation: RootUpperMutationGuardV1<'startup>,
}

impl RootReceivingGuardV1<'_> {
    // These are distinct constructor/return destinations at the existing
    // fixed entry, including the negative path before a credential prepay.
    pub(crate) fn construction_demand_v1() -> Option<ResourceVector> {
        type Credential<'a> = super::RootStartupCredentialReceivingLoanV1<'a>;
        type Failure<'a> = crate::policy_compiler::RootCurrentFailureViewV1<'a>;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<Result<Self, Error>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Failure<'_>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Option<Failure<'_>>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Credential<'_>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Result<Credential<'_>, Error>>().checked_mul(2)?)?;
        ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::MetadataEntries, 12)
            .checked_add(super::RootPolicyAcceptedFlightV1::financial_failure_view_demand_v1()?)
            .ok()
    }

    /// Borrows the same upper owner without releasing either lock.
    pub(crate) fn original_v1(&self) -> &RootReceivingOriginalV1 {
        &self.original
    }

    /// Reborrows the same upper owner within its existing exclusion interval.
    pub(crate) fn original_mut_v1(&mut self) -> &mut RootReceivingOriginalV1 {
        &mut self.original
    }

    /// Denies new native work before releasing this same upper interval.
    pub(super) fn refuse_v1(&self) {
        self.mutation.refuse_v1();
    }

    // A returned validation refusal need not have a new field destination.
    // Preserve that exact Result and deny while both original locks remain
    // held. This invokes no body callback or successful role transition.
    pub(super) fn finish_returned_v1<T, E>(&self, returned: Result<T, E>) -> Result<T, E> {
        if returned.is_err() {
            self.mutation.refuse_v1();
        }
        returned
    }

    /// Borrows both the whole entered upper receiver and its actual L guard.
    ///
    /// # Errors
    /// Refuses incomplete credentials or foreign, ended or failed lower custody.
    pub(super) fn borrow_startup_credential_financial_v1(
        &mut self,
    ) -> Result<RootJournalFinancialBorrowV1<'_>, Error> {
        // The private factory keeps BOTH this exact L and the whole Upper
        // borrowed until the returned fixed credential loan is released.
        self.original
            .borrow_startup_credential_financial_v1(&self.mutation)
    }
}

impl Drop for RootReceivingGuardV1<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() || self.original.failure().is_some() {
            self.mutation.refuse_v1();
        }
    }
}

impl ProductionNormalRootStartupV1 {
    /// Acquires original financial exclusion before its upper receiving mutex.
    ///
    /// # Errors
    /// Refuses missing attachment or a poisoned upper mutex, denying the same
    /// lower original before either acquired guard can be released.
    pub(super) fn lock_receiving_v1(&self) -> Result<RootReceivingGuardV1<'_>, Error> {
        let financial = self.receiving_financial.as_ref().ok_or(Error::Service)?;
        let mutation = financial.enter_upper_mutation_v1();
        let source = self.receiving.as_ref().ok_or_else(|| {
            mutation.refuse_v1();
            Error::Service
        })?;
        let original = source.lock().map_err(|_| {
            mutation.refuse_v1();
            Error::Service
        })?;
        Ok(RootReceivingGuardV1 { original, mutation })
    }
}
