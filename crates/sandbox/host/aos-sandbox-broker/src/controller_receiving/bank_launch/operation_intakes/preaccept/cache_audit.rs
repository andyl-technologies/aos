//! Lends the same actual Source-associated C17 debit to a fixed Cache audit.
//!
//! The borrower keeps both the genuine intake and its entered native turn
//! borrowed until the reader returns. Identity and required vectors only
//! select comparisons; they cannot construct a funding original or a turn.

use super::*;
use crate::controller_receiving::bank_launch::{
    CacheControllerOriginalRefV1, ControllerCacheAuditIdentityDataV1,
};

/// Borrows one actual Delete intake and its same entered preaccept turn.
///
/// Only the continuously held Source loan can construct this value after the
/// existing C17 reservation succeeds. Native before, after and positive
/// disposal remain on the caller's original turn after this borrower drops.
#[must_use]
pub struct ControllerCacheDeleteAuditFundingLoanV1<'funding, 'profile> {
    intake: &'funding ControllerOperationIntakeOriginalV1,
    turn: &'funding mut ControllerDeletePreacceptTurnOriginalV1<'profile>,
    identity: ControllerCacheAuditIdentityDataV1,
    complete: ResourceVector,
    semantic: ResourceVector,
}

impl ControllerCacheDeleteAuditFundingLoanV1<'_, '_> {
    /// Prices the concrete lower construction and forwarding representations.
    ///
    /// The actual Cache fixed invoice includes this passive MemoryBytes term
    /// before the genuine Source reservation and before constructing the loan.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        // Source and receiving each carry the same fixed arguments and return
        // the same borrowed owner. The original reservation's checked receipt
        // is retained separately while its bound is compared, without a copy
        // of the native turn or another financial ledger.
        type Arguments<'a> = (
            &'a mut (), &'a mut (), &'a (), &'a (), &'a mut (),
            ControllerCacheAuditIdentityDataV1,
            ControllerOperationIntakeDemandDataV1, ResourceVector, ResourceVector,
        );
        std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<Arguments<'_>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Result<Self, ControllerBankLaunchErrorV1>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Result<ControllerOperationIntakeDemandDataV1, ControllerBankLaunchErrorV1>>())?
            .checked_add(std::mem::size_of::<ControllerOperationIntakeDemandDataV1>())?
            .checked_add(std::mem::size_of::<ResourceVector>())?
            .checked_add(Self::recurring_control_bytes_v1()?)
    }

    /// Prices the fixed controls used by the same sequential audit borrower.
    ///
    /// This term is included once in construction's existing fixed invoice.
    /// It grants no new debit and does not estimate compiler optimizations.
    #[must_use]
    fn recurring_control_bytes_v1() -> Option<usize> {
        type Guard<'a> = MutexGuard<'a, ControllerOperationIntakesV1>;
        std::mem::size_of::<Result<(), ControllerBankLaunchErrorV1>>().checked_mul(4)?
            .checked_add(std::mem::size_of::<Result<ResourceVector, ControllerBankLaunchErrorV1>>())?
            .checked_add(std::mem::size_of::<Result<Guard<'_>, std::sync::TryLockError<Guard<'_>>>>())?
            .checked_add(std::mem::size_of::<Guard<'_>>())?
            .checked_add(std::mem::size_of::<ControllerCacheAuditIdentityDataV1>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<ResourceVector>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<(
                &CacheControllerOriginalRefV1, Result<(), ControllerBankLaunchErrorV1>,
            )>())
    }

    /// Rejoins the native Cache owner's actual Controller original.
    ///
    /// The loan already borrows the real Source-associated intake and entered
    /// turn from their genuine Source factory. No second Source reference or
    /// supplied association DATA is needed at this private Cache comparison.
    ///
    /// # Errors
    /// Refuses a foreign Cache original or a failed, retired or foreign turn.
    pub fn require_cache_original_v1(
        &mut self,
        cache: &CacheControllerOriginalRefV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !cache.matches_actual_original(&self.intake.identity, &self.intake.original) {
            self.turn.refuse_primary_v1();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.require_original_v1()
    }

    /// Rechecks the same actual entered turn and fixed Cache association.
    ///
    /// # Errors
    /// Refuses a changed association, retired or failed turn, or same-C17
    /// failure. The original turn retains its existing first-cause chronology.
    pub fn require_named_preparation_v1(
        &mut self,
        identity: ControllerCacheAuditIdentityDataV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if identity != self.identity {
            self.turn.refuse_primary_v1();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.turn.require_prepaid_cache_read_frontier_v1()?;
        if self.require_original_v1().is_err() {
            self.turn.refuse_primary_v1();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    /// Compares reached complete demand with this same actually prepaid peak.
    ///
    /// This check neither grows a reservation nor returns available capacity.
    ///
    /// # Errors
    /// Refuses a changed association, failed original or any excess dimension.
    pub fn admit_complete_v1(
        &mut self,
        identity: ControllerCacheAuditIdentityDataV1,
        complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_named_preparation_v1(identity)?;
        if !complete.is_within(self.complete) {
            self.turn.refuse_primary_v1();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    /// Binds the native Cache constructor's actual captured shape to this loan.
    ///
    /// The private constructor independently derives both requirements from its
    /// real five captured owners. Supplied DATA cannot lower the retained peak.
    ///
    /// # Errors
    /// Refuses substituted identity, base or semantic requirements or a failed turn.
    pub fn require_cache_shape_v1(
        &mut self,
        identity: ControllerCacheAuditIdentityDataV1,
        complete: ResourceVector,
        semantic: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_named_preparation_v1(identity)?;
        if complete != self.complete || semantic != self.semantic {
            self.turn.refuse_primary_v1();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    /// Returns the fixed semantic requirement held by the same successful loan.
    ///
    /// # Errors
    /// Refuses a failed, retired or foreign actual original or native turn.
    pub fn prepaid_semantic_demand_v1(&self) -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        self.require_original_v1()?;
        Ok(self.semantic)
    }

    fn require_original_v1(&self) -> Result<(), ControllerBankLaunchErrorV1> {
        if !self.intake.active || !self.intake.delete_source_scope_open
            || self.intake.purpose != OperationIntakePurposeV1::Delete
            || !Arc::ptr_eq(&self.intake.original, &self.turn.original)
            || !Arc::ptr_eq(&self.intake.identity, &self.turn.identity)
            || self.turn.completed || self.turn.reentry.is_some() || self.turn.after_result.is_some()
            || !matches!(self.turn.entry, Some(Ok(())))
            || !matches!(self.turn.before_result, Some(Ok(_)))
            || !matches!(self.turn.before_gate, Some(Ok(())))
            || self.turn.before.value().is_none()
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.intake.original.operation_intakes.try_lock()
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
            .slot(OperationIntakePurposeV1::Delete)
            .require_delete_preaccept_turn_v1(self.turn.ordinal)
            .map_err(ControllerBankLaunchErrorV1::from)
    }
}

impl ControllerOperationIntakeReceivingLoanV1<'_> {
    /// Reserves on this actual entered C17 before borrowing its fixed audit.
    ///
    /// # Errors
    /// Retains the original debit refusal before a later turn or bound refusal.
    pub(crate) fn borrow_delete_cache_audit_funding_v1<'funding, 'profile, P>(
        &'funding mut self,
        controller: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        turn: &'funding mut ControllerDeletePreacceptTurnOriginalV1<'profile>,
        identity: ControllerCacheAuditIdentityDataV1,
        additional: ControllerOperationIntakeDemandDataV1,
        complete: ResourceVector,
        semantic: ResourceVector,
    ) -> Result<ControllerCacheDeleteAuditFundingLoanV1<'funding, 'profile>, ControllerBankLaunchErrorV1> {
        // Keep the original Source debit before the later Cache bound and turn
        // comparisons. A later refusal cannot suppress its earlier real cause.
        let receipt = self.reserve_delete_preaccept_with_receipt_v2(
            controller, launch, profile, additional,
        )?;
        if !complete.is_within(receipt.demand_v1()) || !semantic.is_within(complete)
            || !std::ptr::eq(profile, turn.profile) || !turn.same_writer(controller)
            || !Arc::ptr_eq(&self.owner.original, &turn.original)
            || !Arc::ptr_eq(&self.owner.identity, &turn.identity)
        {
            turn.refuse_primary_v1();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let mut loan = ControllerCacheDeleteAuditFundingLoanV1 {
            intake: &*self.owner, turn, identity, complete, semantic,
        };
        loan.require_named_preparation_v1(identity)?;
        Ok(loan)
    }
}
