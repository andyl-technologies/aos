//! Borrows an actual Initial15 archive input before the fresh target is born.
//!
//! The original Source and issued ticket supply immutable historical DATA only.
//! Journal and Control parsing require their own admitted retained constructors;
//! this loan does not fabricate a fresh Source, World, native gate or budget.

use super::*;
use std::mem::size_of;

#[path = "prebirth_control/attempt.rs"]
mod attempt;
pub use attempt::{
    CompleteInitial15PrebirthControlAttempt, CompleteInitial15PrebirthControlConstructionData,
};

/// Borrows one verified native owner's real prebirth journal input.
///
/// Construction checks the actual completed Source allocation, original owner,
/// administrative settlement and unbound target phase. It performs no decode,
/// serializer, hash, schema factory, allocation or I/O. The later constructor
/// must retain its own parsed partials before any further callback.
pub struct CompleteInitial15PrebirthControlInput<'a> {
    ticket: &'a CompleteOriginalNativeTicket,
    owner: &'a NativeOwnerState,
    journal: &'a ContentRef,
    journal_bytes: &'a [u8],
}

impl CompleteOriginalNativeTicket {
    /// Borrows this exact original Initial15 owner's immutable journal prebirth.
    ///
    /// Old session/owner identities remain historical data. The actual factory
    /// must separately bind its own private launch and complete prospective rows
    /// before sealing a new native startup carrier.
    ///
    /// # Errors
    /// Refuses foreign actor custody, target binding already started, another
    /// native family, absent/ambiguous settlement, missing body or changed length.
    pub fn initial15_prebirth_control_input_data(
        &self,
    ) -> Result<CompleteInitial15PrebirthControlInput<'_>, RuntimeError> {
        authenticate_prebirth_source(&self.source)?;
        self.source.host.initial_data()?;
        let owner = self.owner()?;
        // The completed Source loader already authenticated the complete schema
        // definition. This dispatch retains that actual family; it creates no
        // schema, portable capability or authorization from an arbitrary Id.
        if owner.key.schema.id.as_str() != "source-owned.packet-native-continuation/14" {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let journal = self.original_restoration_journal_reference_data()?;
        let journal_bytes = self
            .source
            .content()
            .get(journal)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if u64::try_from(journal_bytes.len()).map_err(|_| RuntimeError::ResourceLimit)?
            != journal.length.get()
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let input = CompleteInitial15PrebirthControlInput {
            ticket: self,
            owner,
            journal,
            journal_bytes,
        };
        input.authenticate_origin_data()?;
        Ok(input)
    }

    /// Names this actual borrowed Source/ticket/settlement guard's fixed views.
    pub fn initial15_prebirth_control_input_counter_scratch_data() -> usize {
        Self::original_restoration_journal_counter_scratch_data()
            + size_of::<CompleteInitial15PrebirthControlInput<'static>>()
            + size_of::<Result<CompleteInitial15PrebirthControlInput<'static>, RuntimeError>>()
            + size_of::<&CompleteOriginalSource>()
            + size_of::<&CompleteOriginalNativeTicket>()
            + size_of::<&NativeOwnerState>()
            + size_of::<&ContentRef>()
            + size_of::<&[u8]>()
            + size_of::<(&ContentRef, &[u8])>()
            + size_of::<&CompleteInitial15PrebirthControlInput<'static>>()
            + size_of::<Option<&[u8]>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<u64, std::num::TryFromIntError>>()
            + size_of::<std::cell::Ref<'static, collecting::CollectingTargetPhase>>()
            + size_of::<
                Result<
                    std::cell::Ref<'static, collecting::CollectingTargetPhase>,
                    std::cell::BorrowError,
                >,
            >()
            + size_of::<std::cell::Ref<'static, Option<Rc<()>>>>()
            + size_of::<Result<std::cell::Ref<'static, Option<Rc<()>>>, std::cell::BorrowError>>()
            + size_of::<Result<&HostSchedulingContinuationRecord, RuntimeError>>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
    }
}

impl<'a> CompleteInitial15PrebirthControlInput<'a> {
    /// Rechecks the actual original Source/owner and its still-unbound phase.
    ///
    /// # Errors
    /// Refuses an expired target phase or changed Source/owner/settlement role.
    pub fn authenticate_origin_data(&self) -> Result<(), RuntimeError> {
        authenticate_prebirth_source(&self.ticket.source)?;
        if !std::ptr::eq(self.ticket.owner()?, self.owner)
            || self.ticket.original_restoration_journal_reference_data()? != self.journal
            || self.ticket.source.content().get(self.journal) != Some(self.journal_bytes)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.ticket.source.authenticate_birth()
    }

    /// Borrows the complete actual journal reference and retained signed body.
    ///
    /// This performs no decode; the real prospective parser row is separate.
    pub fn journal_data(&self) -> (&'a ContentRef, &'a [u8]) {
        (self.journal, self.journal_bytes)
    }

    /// Borrows the exact original owner already checked by this completed Source.
    pub fn owner_data(&self) -> &'a NativeOwnerState {
        self.owner
    }

    pub(crate) fn content_data(&self) -> &'a VerifiedStateContent {
        self.ticket.source.content()
    }
}

fn authenticate_prebirth_source(source: &CompleteOriginalSource) -> Result<(), RuntimeError> {
    source.authenticate_birth()?;
    source.authenticate_ticket_phase()?;
    if source.target_started.get()
        || source
            .target
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .is_some()
    {
        return Err(RuntimeError::UnsupportedFacet);
    }
    source.authenticate_birth()
}
