//! Lends the retained decoder bank before birth without creating a cold group.
//!
//! The same bank later moves into its historical cold owner. A synchronous
//! shared borrow cannot substitute for its completed production validation,
//! genuine ticket/source identity or independently funded semantic revalidation.

use super::*;
use crate::node_state::{CompleteOriginalNativeTicket, RetainedCold17Collection};
use std::cell::Ref;
use std::mem::size_of;

impl CompleteOriginalRestorationSource {
    /// Borrows the exact completed collection while collecting remains unbound.
    ///
    /// The caller separately admits the defining fixed counter, any callback
    /// output and the actual Provider checkpoint/semantic work before entry.
    /// Admission and whole-owner census callbacks must run after this method
    /// returns and releases its shared collection guard. Callback refusal keeps
    /// its own Source output/once slot; this lender moves and clones no owner.
    ///
    /// # Errors
    /// Refuses another archive ticket, foreign actor, incomplete production
    /// collection, ordinary/bound/spent target, missing ticket issuance or a
    /// busy/moved collection. Both callback outcomes receive the same postguard.
    pub(crate) fn with_restored_decoded_collection_prebirth_data<R>(
        &self,
        ticket: &CompleteOriginalNativeTicket,
        inspect: impl FnOnce(&RetainedCold17Collection) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.authenticate_restored_prebirth_ticket_data(ticket)?;
        let collection = self
            .inner
            .restored_collection
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let retained = collection.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        retained.authenticate_completed_data(&self.inner.archive)?;
        retained.authenticate_production_declaration_data(&self.inner.archive)?;

        let result = inspect(retained);
        drop(collection);
        self.authenticate_restored_prebirth_ticket_data(ticket)?;
        result
    }

    /// Authenticates the exact ticket before an unbound current17 DATA loan.
    pub(crate) fn authenticate_restored_prebirth_ticket_data(
        &self,
        ticket: &CompleteOriginalNativeTicket,
    ) -> Result<(), RuntimeError> {
        self.inner
            .authenticate_collecting_prebirth_storage_phase()?;
        self.restored_host_record_data()?;
        ticket.authenticate_source(self)?;
        self.inner.authenticate_collecting_prebirth_storage_phase()
    }

    /// Declares the unbound current17 source/ticket DATA guard's fixed controls.
    pub(crate) fn restored_prebirth_source_counter_scratch_data() -> usize {
        CompleteOriginalSource::collecting_prebirth_phase_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&CompleteOriginalNativeTicket>()
            + size_of::<(&Rc<CompleteOriginalSource>, &Rc<CompleteOriginalSource>)>()
            + size_of::<
                Result<
                    &crate::node_contract::HostSchedulingRestoredContinuationRecord17,
                    RuntimeError,
                >,
            >()
            + size_of::<Result<(), RuntimeError>>()
    }

    /// Declares fixed guard/loan/result workspace before a synchronous borrow.
    ///
    /// Callback closure controls and its actual constructor R/T/S remain the
    /// caller's separate obligation. This method measures no cache and issues
    /// no native authority or allocation credit.
    pub(crate) fn restored_decoded_collection_prebirth_counter_scratch_data<R>() -> usize {
        Self::restored_prebirth_source_counter_scratch_data()
            + RetainedCold17Collection::completed_loan_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&CompleteOriginalNativeTicket>()
            + size_of::<(&Rc<CompleteOriginalSource>, &Rc<CompleteOriginalSource>)>()
            + size_of::<Ref<'static, Option<RetainedCold17Collection>>>()
            + size_of::<
                Result<Ref<'static, Option<RetainedCold17Collection>>, std::cell::BorrowError>,
            >()
            + size_of::<Option<&RetainedCold17Collection>>()
            + size_of::<&RetainedCold17Collection>()
            + size_of::<
                Result<
                    &crate::node_contract::HostSchedulingRestoredContinuationRecord17,
                    RuntimeError,
                >,
            >()
            + size_of::<Result<R, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
