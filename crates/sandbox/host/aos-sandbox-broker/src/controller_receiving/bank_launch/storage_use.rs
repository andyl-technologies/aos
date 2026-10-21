//! Retains the single U ledger claimed from its actual native reserve publication.
//!
//! A passive binding selects comparison DATA only. The actual same committed J,
//! native writer and private publication receipt admit construction once. Upper
//! ReturnedAppend, Source, Root and Cache joins remain independently mandatory.

use std::error::Error;
use std::sync::{Arc, atomic::Ordering};

use aos_sandbox_model::component_receiving::ComponentServiceReceivingLedgerV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::resource_bank::{self as bank, Claim};

use super::append::ControllerDurableAppendReceiptV1;
use super::identity::ControllerWriterIdentityV1;
use super::{
    CacheControllerOriginalRefV1, ControllerBankLaunchErrorV1, ControllerCoordinatorWriterV1,
    ControllerCreateContinuationLedgerOriginalV1,
};
use crate::controller_receiving::source_prebank::ControllerSourceOriginalRefV1;
use crate::controller_receiving::{
    ControllerReceivingOriginalV1, profile::ControllerSelfProfileOriginalV1,
};

/// Refuses further use while the same U owner retains the original cause.
#[derive(Debug, thiserror::Error)]
#[error("original Create Storage use receiving is closed")]
pub struct ControllerCreateStorageUseClosedV1;

/// Owns the one ledger for the actual native Reserved Create Storage use.
///
/// Dropping a short borrower never refunds credit, changes the claim or closes
/// an independent native interval. This owner cannot be built from bank DATA.
pub struct ControllerCreateStorageUseReceivingOriginalV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    identity: Arc<ControllerWriterIdentityV1>,
    publication: Arc<ControllerDurableAppendReceiptV1>,
    claim: Claim,
    ledger: ComponentServiceReceivingLedgerV1,
    admission: Option<Result<(), ControllerBankLaunchErrorV1>>,
}

/// Borrows this same U for finite Cache charges and original comparisons.
pub struct ControllerCreateStorageUseFundingLoanV1<'funding, 'profile> {
    owner: &'funding mut ControllerCreateStorageUseReceivingOriginalV1,
    profile: &'profile ControllerSelfProfileOriginalV1,
}

/// Reborrows the same U for the actual upper Root observation interval.
///
/// Only an existing native Cache U funding borrower constructs this loan. It
/// contains no account, allowance, cached highwater, Source getter or phase.
/// Its methods preserve the original owner's exact reservation/debit paths.
pub struct ControllerCacheRootObservationFundingLoanV1<'borrow> {
    owner: &'borrow mut ControllerCreateStorageUseReceivingOriginalV1,
}

impl ControllerCacheRootObservationFundingLoanV1<'_> {
    /// Checks the same original Reserved U without another native observation.
    ///
    /// # Errors
    /// Refuses retained U debt or changed claim/original/publication DATA.
    pub fn require_reserved_v1(&self) -> Result<(), ControllerCreateStorageUseClosedV1> {
        self.owner.require_reserved_v1()
    }

    /// Debits the original Root observation's additional work on this same U.
    ///
    /// # Errors
    /// Retains the actual same ledger's arithmetic, capacity or prior refusal.
    pub fn reserve_additional_v1(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), ControllerCreateStorageUseClosedV1> {
        self.owner.reserve_additional_v1(demand)
    }
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Claims U once after its actual native reserve stage has been disposed.
    ///
    /// The committed J pays construction before any replay scratch or ledger
    /// is created. The selector is rejoined to the sole actual native map.
    ///
    /// # Errors
    /// Refuses unprepaid or foreign J/profile/writer custody, native uncertainty,
    /// a noncurrent Reserved U, a different last publication or repeated claim.
    pub fn begin_create_storage_use_receiving_once_v1(
        &mut self,
        funding: &mut ControllerCreateContinuationLedgerOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        binding: bank::CreateStorageUseBindingV1,
    ) -> Result<ControllerCreateStorageUseReceivingOriginalV1, ControllerBankLaunchErrorV1> {
        let bytes =
            ControllerCreateStorageUseReceivingOriginalV1::receiving_construction_bytes_v1()
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        funding
            .require_storage_use_construction_v1(
                self,
                profile,
                ResourceVector::ZERO.with(D::MemoryBytes, bytes),
            )
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        let state = self.fixed.bank_state_v1()?;
        let (_, claim) = binding.reserved_replayed_pair_v1(state)?;
        if claim.native_fields().enrollment != self.fixed.original().writer_enrollment()?.identity {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let transaction = binding.reserve_transaction_id()?;
        let publication = self
            .fixed
            .last_receipt
            .as_ref()
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        if !Arc::ptr_eq(&publication.identity, self.fixed.identity())
            || publication.transaction != transaction
            || !self.fixed.contains_bank_transaction_v1(&transaction)?
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        // Burn before cloning or constructing the retained receiving owner.
        if publication.storage_use_claimed.swap(true, Ordering::AcqRel) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(ControllerCreateStorageUseReceivingOriginalV1 {
            original: Arc::clone(self.fixed.original()),
            identity: Arc::clone(self.fixed.identity()),
            publication: Arc::clone(publication),
            claim,
            ledger: ComponentServiceReceivingLedgerV1::new(claim.native_fields().amount),
            admission: None,
        })
    }
}

impl ControllerCreateStorageUseReceivingOriginalV1 {
    /// Prices actual factory, replay, return and retained controls before entry.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<Result<Self, ControllerBankLaunchErrorV1>>())?
            .checked_add(std::mem::size_of::<(
                Claim,
                bank::CreateStorageUseBindingV1,
                [u8; 16],
                ResourceVector,
                crate::receiving::OriginalEnrollment,
                Result<(), ControllerBankLaunchErrorV1>,
            )>())?
            // expected() and writer_enrollment() each return the actual typed
            // enrollment result before the caller projects its identity.
            .checked_add(std::mem::size_of::<Result<
                crate::receiving::OriginalEnrollment,
                crate::controller_receiving::ControllerReceivingErrorV1,
            >>().checked_mul(2)?)?
            .checked_add(bank::CreateStorageUseBindingV1::reserved_replay_receiving_bytes_v1()?)
    }

    /// Debits additional work on this same U without replacing earlier charges.
    ///
    /// # Errors
    /// Retains the actual accounting refusal; an earlier refusal stays selected.
    pub fn reserve_additional_v1(
        &mut self,
        additional: ResourceVector,
    ) -> Result<(), ControllerCreateStorageUseClosedV1> {
        self.require_reserved_v1()?;
        self.admission = Some(
            self.ledger
                .reserve(additional)
                .map_err(|cause| ControllerBankLaunchErrorV1::Accounting(*cause)),
        );
        self.require_reserved_v1()
    }

    /// Requires the retained reserved owner without minting current authority.
    ///
    /// # Errors
    /// Refuses original closure, prior debt or changed publication affinity.
    pub fn require_reserved_v1(&self) -> Result<(), ControllerCreateStorageUseClosedV1> {
        if self.failure_v1().is_some()
            || self.original.is_closed()
            || self.claim.native_fields().state != bank::ClaimState::Reserved
            || !self.identity.has_original(&self.original)
            || !Arc::ptr_eq(&self.publication.identity, &self.identity)
        {
            return Err(ControllerCreateStorageUseClosedV1);
        }
        Ok(())
    }

    /// Returns the actual reserved claim as comparison DATA.
    ///
    /// # Errors
    /// Refuses a closed owner or retained receiving failure.
    pub fn claim_data_v1(&self) -> Result<Claim, ControllerCreateStorageUseClosedV1> {
        self.require_reserved_v1()?;
        Ok(self.claim)
    }

    /// Returns the actual irreversible charged vector as comparison DATA.
    #[must_use]
    pub fn charged_v1(&self) -> ResourceVector {
        self.ledger.charged()
    }

    /// Borrows the original arithmetic or affinity cause.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.ledger.failure().map(|cause| cause as _).or_else(|| {
            self.admission
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _)
        })
    }

    fn refuse(&mut self, cause: ControllerBankLaunchErrorV1) -> ControllerCreateStorageUseClosedV1 {
        if self.failure_v1().is_none() {
            self.admission = Some(Err(cause));
        }
        ControllerCreateStorageUseClosedV1
    }

    /// Retains abandonment of an entered upper U borrower without refunding it.
    pub fn retain_refusal_v1(&mut self) {
        self.refuse(ControllerBankLaunchErrorV1::Conflict);
    }

    fn require_profile(
        &mut self,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerCreateStorageUseClosedV1> {
        self.require_reserved_v1()?;
        if let Err(cause) = self
            .original
            .require_create_continuation_profile_v1(profile)
        {
            return Err(self.refuse(cause.into()));
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn reserve_observer_archive_growth_v1(
        &mut self,
        profile: &ControllerSelfProfileOriginalV1,
        required: ResourceVector,
    ) -> Result<(), ControllerCreateStorageUseClosedV1> {
        self.require_profile(profile)?;
        self.reserve_additional_v1(required)
    }

    /// Borrows this original's finite financial port under its same profile.
    ///
    /// # Errors
    /// Refuses closed U, prior debt or a foreign actual native profile.
    pub fn borrow_cache_funding_v1<'funding, 'profile>(
        &'funding mut self,
        profile: &'profile ControllerSelfProfileOriginalV1,
    ) -> Result<
        ControllerCreateStorageUseFundingLoanV1<'funding, 'profile>,
        ControllerCreateStorageUseClosedV1,
    > {
        self.require_profile(profile)?;
        Ok(ControllerCreateStorageUseFundingLoanV1 {
            owner: self,
            profile,
        })
    }
}

impl ControllerCreateStorageUseFundingLoanV1<'_, '_> {
    pub(super) fn borrow_root_observation_funding_v1(
        &mut self,
    ) -> ControllerCacheRootObservationFundingLoanV1<'_> {
        ControllerCacheRootObservationFundingLoanV1 { owner: &mut *self.owner }
    }

    /// Checks the same retained U reservation without creating another borrower.
    ///
    /// This is the exact original owner's read-only reservation comparison.
    /// It performs no debit, replay, profile acquisition or native observation.
    ///
    /// # Errors
    /// Refuses prior U debt or changed reserved claim/original publication.
    pub fn require_reserved_v1(&self) -> Result<(), ControllerCreateStorageUseClosedV1> {
        self.owner.require_reserved_v1()
    }

    /// Debits actual additional Cache work on the same irreversible U ledger.
    ///
    /// # Errors
    /// Retains foreign profile or arithmetic failure on the actual U original.
    pub fn reserve_additional_v1(
        &mut self,
        additional: ResourceVector,
    ) -> Result<(), ControllerCreateStorageUseClosedV1> {
        self.owner.require_profile(self.profile)?;
        self.owner.reserve_additional_v1(additional)
    }

    /// Compares required complete work with this U's actual cumulative charge.
    ///
    /// # Errors
    /// Retains insufficient prior payment or a foreign/closed profile.
    pub fn require_charged_v1(
        &mut self,
        required: ResourceVector,
    ) -> Result<(), ControllerCreateStorageUseClosedV1> {
        self.owner.require_profile(self.profile)?;
        if let Err(cause) = self.owner.ledger.charged().checked_sub(required) {
            return Err(self
                .owner
                .refuse(ControllerBankLaunchErrorV1::Accounting(cause)));
        }
        Ok(())
    }

    /// Rejoins the same native Cache Controller original without exporting it.
    ///
    /// # Errors
    /// Retains foreign Cache/native affinity or earlier U debt.
    pub fn require_controller_original_v1(
        &mut self,
        actual: &CacheControllerOriginalRefV1,
    ) -> Result<(), ControllerCreateStorageUseClosedV1> {
        self.owner.require_profile(self.profile)?;
        if !actual.matches_actual_original(&self.owner.identity, &self.owner.original) {
            return Err(self.owner.refuse(ControllerBankLaunchErrorV1::Conflict));
        }
        Ok(())
    }

    /// Rejoins the actual Source original without a new account or native loan.
    ///
    /// # Errors
    /// Retains foreign Source affinity or earlier U debt.
    pub fn require_source_original_v1(
        &mut self,
        actual: &ControllerSourceOriginalRefV1,
    ) -> Result<(), ControllerCreateStorageUseClosedV1> {
        self.owner.require_profile(self.profile)?;
        if !actual.has_same_original_v1(&self.owner.original) {
            return Err(self.owner.refuse(ControllerBankLaunchErrorV1::Conflict));
        }
        Ok(())
    }

    /// Borrows the same original cause after a closed debit or affinity check.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.owner.failure_v1()
    }
}
