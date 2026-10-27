//! Retains the one original exchange while guarded later publication borrows it.
//!
//! Only the exchange permits interior mutation. The decoded Source, launch,
//! immutable policy and original SDK owners retain ordinary immutable loans.
//! A busy exchange refuses inspection; it never becomes an absent exchange.

use super::*;
use std::cell::{BorrowError, BorrowMutError, Ref, RefCell, RefMut};

/// Owns one original retained exchange without moving or duplicating its stream.
pub(in super::super) struct Holder {
    exchange: RefCell<Option<Exchange>>,
}

impl Holder {
    /// Initializes an unbound retained slot without allocation.
    pub(in super::super) fn empty_data() -> Self {
        Self {
            exchange: RefCell::new(None),
        }
    }

    /// Lends the destination only through an exclusive original owner borrow.
    pub(in super::super) fn destination_data(&mut self) -> &mut Option<Exchange> {
        self.exchange.get_mut()
    }

    /// Lends actual optional custody, refusing a concurrent physical mutation.
    ///
    /// # Errors
    /// Refuses an outstanding mutable exchange loan without changing custody.
    pub(in super::super) fn borrow_data(&self) -> Result<Ref<'_, Option<Exchange>>, ProviderError> {
        self.exchange.try_borrow().map_err(|_| refused())
    }

    /// Lends the same physical owner inside an enclosing original effect scope.
    ///
    /// The caller authenticates complete Hello/Source/SDK custody and releases
    /// this loan before its terminal guards and surviving-allocation census.
    ///
    /// # Errors
    /// Refuses any outstanding exchange loan without moving the stream.
    pub(in super::super) fn borrow_mut_data(
        &self,
    ) -> Result<RefMut<'_, Option<Exchange>>, ProviderError> {
        self.exchange.try_borrow_mut().map_err(|_| refused())
    }

    /// Names fixed holder construction beside the separately retained owner.
    pub(in super::super) fn constructor_transient_data() -> usize {
        size_of::<Self>() + size_of::<RefCell<Option<Exchange>>>()
    }

    /// Names actual guards, borrow refusals and fixed borrowed-result controls.
    pub(in super::super) fn counter_scratch_data() -> usize {
        size_of::<&Self>() * 2
            + size_of::<&mut Self>()
            + size_of::<&mut Option<Exchange>>()
            + size_of::<Ref<'static, Option<Exchange>>>() * 2
            + size_of::<RefMut<'static, Option<Exchange>>>() * 2
            + size_of::<BorrowError>()
            + size_of::<BorrowMutError>()
            + size_of::<Result<Ref<'static, Option<Exchange>>, BorrowError>>()
            + size_of::<Result<RefMut<'static, Option<Exchange>>, BorrowMutError>>()
            + size_of::<Result<Ref<'static, Option<Exchange>>, ProviderError>>() * 2
            + size_of::<Result<RefMut<'static, Option<Exchange>>, ProviderError>>() * 2
    }
}
