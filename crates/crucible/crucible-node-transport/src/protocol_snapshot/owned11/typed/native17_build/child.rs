//! Retains one lazily initialized concrete child after its allocation is admitted.
//!
//! An empty slot has only a Vec header and a once flag. Concrete builder trees
//! therefore stop at each slot instead of recursively defaulting every possible
//! descendant. Capacity remains owned after child failure or output transfer.

use crate::ProviderError;
use crate::protocol_snapshot::owned11::typed::{Ledger, invalid};
use crate::retained_metadata::MetadataObserver;
use std::mem::size_of;

/// Owns one concrete child attempt without eagerly constructing its descendants.
pub(crate) struct Native17ChildSlot<Attempt: Default> {
    children: Vec<Attempt>,
    started: bool,
}

impl<Attempt: Default> Default for Native17ChildSlot<Attempt> {
    fn default() -> Self {
        Self {
            children: Vec::new(),
            started: false,
        }
    }
}

impl<Attempt: Default> Native17ChildSlot<Attempt> {
    /// Prices the persistent child bank before any reservation or initialization.
    ///
    /// # Errors
    /// Refuses absent or suspended aggregate accounting, a child header above
    /// the owned-backing bound or exhausted admitted target credit.
    pub(crate) fn preflight_data(ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        if !ledger.has_native17_targets_data() || ledger.native17_targets_suspended_data() {
            ledger.fail_native17_targets_data();
            return Err(invalid());
        }
        if size_of::<Attempt>() > ledger.limits.maximum_owned_backing_bytes {
            ledger.fail_native17_targets_data();
            return Err(invalid());
        }
        ledger.native17_target_vector_data::<Attempt>(1)
    }

    /// Initializes the same admitted child inside its already installed slot.
    ///
    /// The concrete attempt's Default constructs empty headers only. Nested
    /// child banks are initialized later by their own admitted builder steps.
    ///
    /// # Errors
    /// Refuses reuse, exhausted credit, allocation failure or widened capacity.
    /// Any successful reservation remains in this slot on every later error.
    pub(crate) fn begin_data(
        &mut self,
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<&mut Attempt, ProviderError> {
        if std::mem::replace(&mut self.started, true) {
            return Err(invalid());
        }
        Self::preflight_data(ledger)?;

        self.children.try_reserve_exact(1).map_err(|_| invalid())?;
        if size_of::<Attempt>() != 0 && self.children.capacity() != 1 {
            return Err(invalid());
        }
        self.children.push(Attempt::default());
        self.children.first_mut().ok_or_else(invalid)
    }

    /// Borrows an initialized child while preserving its independently owned bank.
    pub(crate) fn child_data(&self) -> Option<&Attempt> {
        self.children.first()
    }

    /// Counts actual reserved backing even when no child was initialized.
    ///
    /// # Errors
    /// Refuses observer exhaustion or checked backing-layout overflow.
    pub(crate) fn observe_backing_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.vector::<Attempt>(self.children.capacity())
    }
}
