//! Closes paid shared controls before destroying their original metadata charge.
//!
//! Every strong alias follows the same terminal extraction rule. No raw or weak
//! aliases escape, so exactly one final close extracts the value after freeing
//! its reference-counted allocation. Nullable slots preserve pointer-sized roots.

use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

/// Retains one value until its final shared control has physically closed.
pub(crate) struct TerminalOwner<T> {
    value: Option<Arc<T>>,
}

impl<T> TerminalOwner<T> {
    /// Constructs one shared control under the caller's existing admission.
    pub(crate) fn new(value: T) -> Self {
        Self {
            value: Some(Arc::new(value)),
        }
    }

    /// Reports whether two live owners retain the same physical allocation.
    pub(crate) fn ptr_eq(left: &Self, right: &Self) -> bool {
        match (&left.value, &right.value) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl<T> Clone for TerminalOwner<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
        }
    }
}

impl<T> Deref for TerminalOwner<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match &self.value {
            Some(value) => value,
            // Only Drop or an empty slot contains None. Slots expose an owner
            // only after checking presence, and Drop never lends its state.
            None => unreachable!("an empty terminal owner cannot be borrowed"),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for TerminalOwner<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.deref().fmt(formatter)
    }
}

impl<T> Drop for TerminalOwner<T> {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            drop(Arc::into_inner(value));
        }
    }
}

/// Stores an optional terminal owner without a second nullable discriminant.
pub(crate) struct TerminalOwnerSlot<T>(TerminalOwner<T>);

impl<T> TerminalOwnerSlot<T> {
    /// Borrows the live owner while retaining its existing terminal discipline.
    pub(crate) fn as_ref(&self) -> Option<&TerminalOwner<T>> {
        self.0.value.as_ref().map(|_| &self.0)
    }
}

impl<T> Default for TerminalOwnerSlot<T> {
    fn default() -> Self {
        Self(TerminalOwner { value: None })
    }
}

impl<T> From<TerminalOwner<T>> for TerminalOwnerSlot<T> {
    fn from(owner: TerminalOwner<T>) -> Self {
        Self(owner)
    }
}

impl<T> Clone for TerminalOwnerSlot<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: fmt::Debug> fmt::Debug for TerminalOwnerSlot<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_ref().fmt(formatter)
    }
}
