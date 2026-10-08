//! Terminal shared ownership and nullable storage for original decode accounts.

use std::ops::Deref;
use std::sync::Arc;

use super::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, StoreAuthority};

/// Closes the shared control before dropping its paid concrete value.
pub(super) struct TerminalOwner<T> {
    value: Option<Arc<T>>,
}

impl<T> TerminalOwner<T> {
    pub(super) fn new(value: T) -> Self {
        Self {
            value: Some(Arc::new(value)),
        }
    }

    pub(super) fn shares_owner(&self, other: &Self) -> bool {
        match (&self.value, &other.value) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    pub(super) fn is_exclusive(&self) -> bool {
        self.value
            .as_ref()
            .is_some_and(|value| Arc::strong_count(value) == 1)
    }
}

impl<T> Clone for TerminalOwner<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.as_ref().map(Arc::clone),
        }
    }
}

impl<T> Deref for TerminalOwner<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match &self.value {
            Some(value) => value,
            // Only an internal nullable slot or Drop contains an empty owner.
            // Slot borrowers test presence before exposing a public budget.
            None => unreachable!("an empty decode owner cannot be borrowed"),
        }
    }
}

impl<T> Drop for TerminalOwner<T> {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            drop(Arc::into_inner(value));
        }
    }
}

/// Keeps native authority controls terminal without changing external owners.
#[derive(Clone)]
pub(super) enum Authority {
    External(Arc<dyn DecodeResourceAuthority>),
    Store(TerminalOwner<StoreAuthority>),
}

impl Authority {
    pub(super) fn is_exclusive(&self) -> bool {
        match self {
            Self::External(value) => Arc::strong_count(value) == 1,
            Self::Store(value) => value.is_exclusive(),
        }
    }

    pub(super) fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        match self {
            Self::External(value) => value.verify_live(),
            Self::Store(value) => value.verify_live(),
        }
    }

    pub(super) fn reserve(&self, bytes: u64) -> Result<super::ResourceLoan, DecodeAdmissionError> {
        match self {
            Self::External(value) => value.reserve(bytes),
            Self::Store(value) => value.reserve(bytes),
        }
    }
}

/// Stores an optional account in the same one-pointer extent as its owner.
///
/// An empty budget is confined to this private slot. Borrowing and extracting
/// it return `None`, so public budgets always retain a live shared owner.
#[derive(Clone)]
pub(crate) struct DecodeBudgetSlot {
    budget: DecodeBudget,
}

impl DecodeBudgetSlot {
    pub(crate) const fn empty() -> Self {
        Self {
            budget: DecodeBudget(TerminalOwner { value: None }),
        }
    }

    pub(crate) fn as_ref(&self) -> Option<&DecodeBudget> {
        self.budget.0.value.as_ref().map(|_| &self.budget)
    }

    pub(crate) fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}

impl Default for DecodeBudgetSlot {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<DecodeBudget> for DecodeBudgetSlot {
    fn from(budget: DecodeBudget) -> Self {
        Self { budget }
    }
}
