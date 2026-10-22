//! Keeps an admitted control's value alive through its shared allocation close.
//!
//! Every observer uses this private owner. Raw Arc and Weak aliases cannot escape,
//! so the final owner can close the header before dropping the value's real loans.

use std::ops::Deref;
use std::sync::Arc;

/// Retains a prepaid control without exposing an independently living header.
pub(super) struct RetainedControl<T> {
    shared: Option<Arc<T>>,
}

impl<T> RetainedControl<T> {
    /// Allocates only after the caller admits this header and all owned payloads.
    ///
    /// The value must retain the original payer through its own destruction.
    pub(super) fn new(value: T) -> Self {
        Self {
            shared: Some(Arc::new(value)),
        }
    }

    /// Compares existing allocation identities without issuing resource credit.
    pub(super) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(self.shared(), other.shared())
    }

    fn shared(&self) -> &Arc<T> {
        match &self.shared {
            Some(shared) => shared,
            None => unreachable!("a live control retains its original allocation"),
        }
    }
}

impl<T> Clone for RetainedControl<T> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<T> Deref for RetainedControl<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.shared()
    }
}

impl<T> Drop for RetainedControl<T> {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take() {
            // Every strong observer consumes its Arc this way. With no Weak
            // observers, header destruction precedes the extracted value's Drop.
            drop(Arc::into_inner(shared));
        }
    }
}
