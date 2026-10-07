//! Shares concrete operational failures without exposing ordinary Arc aliases.
//!
//! Typed and erased observers consume the same private allocation. The final
//! observer extracts its concrete error after the allocation closes, allowing
//! original resource ownership inside that error to remain live through close.

use std::alloc::{Layout, LayoutError};
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use super::BackendOperationalCause;

/// Shares an originally funded concrete operational error and its custody.
///
/// Clones and erased backend observers share one allocation. No raw `Arc` or
/// weak reference escapes this owner. Its final observer deallocates the shared
/// control before dropping the concrete error and its retained resource loans.
/// The caller must admit the allocation and every owned error payload before
/// construction; this owner creates neither resource credit nor authority.
#[repr(transparent)]
pub struct SharedOperationalCause<E: Error + Send + Sync + 'static> {
    shared: Option<Arc<E>>,
}

impl<E: Error + Send + Sync + 'static> SharedOperationalCause<E> {
    /// Retains an originally funded concrete error in one shared allocation.
    ///
    /// Original credit must cover [`Self::allocation_bytes`] and the error's
    /// separately owned payloads before this constructor allocates. The credit
    /// remains inside the concrete error or another original retained owner.
    #[must_use]
    pub fn new(source: E) -> Self {
        Self {
            shared: Some(Arc::new(source)),
        }
    }

    /// Returns the aligned shared allocation extent for the concrete error.
    ///
    /// This includes the two reference counters and concrete value, excluding
    /// the owner handle and any separately allocated payloads inside the error.
    /// It follows the pinned standard library's `Arc` allocation layout.
    ///
    /// # Errors
    /// Returns an error if the combined allocation cannot be represented.
    pub fn allocation_bytes() -> Result<usize, LayoutError> {
        let (layout, _) = Layout::new::<[AtomicUsize; 2]>().extend(Layout::new::<E>())?;
        Ok(layout.pad_to_align().size())
    }

    /// Borrows the original concrete error without detaching its custody.
    #[must_use]
    pub fn source_ref(&self) -> &E {
        self.shared()
    }

    /// Creates an erased observer of the same originally funded allocation.
    ///
    /// This increments its existing reference count without allocating another
    /// body, control or loan. The concrete cause remains downcastable through
    /// the backend observer's standard error chain.
    #[must_use]
    pub fn backend_cause(&self) -> BackendOperationalCause {
        BackendOperationalCause::from_shared(Arc::clone(self.shared()))
    }

    /// Transfers ownership into an erased observer without allocating or cloning.
    #[must_use]
    pub fn into_backend_cause(mut self) -> BackendOperationalCause {
        match self.shared.take() {
            Some(shared) => BackendOperationalCause::from_shared(shared),
            None => unreachable!("a live operational cause owns its concrete error"),
        }
    }

    fn shared(&self) -> &Arc<E> {
        match &self.shared {
            Some(shared) => shared,
            None => unreachable!("a live operational cause owns its concrete error"),
        }
    }
}

impl<E: Error + Send + Sync + 'static> Clone for SharedOperationalCause<E> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<E: Error + Send + Sync + 'static> Drop for SharedOperationalCause<E> {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take() {
            drop(Arc::into_inner(shared));
        }
    }
}

impl<E: Error + Send + Sync + 'static> fmt::Debug for SharedOperationalCause<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SharedOperationalCause")
            .field(self.source_ref())
            .finish()
    }
}

impl<E: Error + Send + Sync + 'static> PartialEq for SharedOperationalCause<E> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(self.shared(), other.shared())
    }
}

impl<E: Error + Send + Sync + 'static> Eq for SharedOperationalCause<E> {}

// The trait and all Arc-bearing constructors remain private to the backend
// boundary. Dispatch retains a concrete Self for extraction, avoiding a second
// Box allocation or ordinary destruction of an erased Arc's inner error.
pub(super) trait ClosedOperationalCause: Send + Sync {
    fn original(&self) -> &(dyn Error + 'static);

    fn close(self: Arc<Self>);
}

impl<E: Error + Send + Sync + 'static> ClosedOperationalCause for E {
    fn original(&self) -> &(dyn Error + 'static) {
        self
    }

    fn close(self: Arc<Self>) {
        drop(Arc::into_inner(self));
    }
}

#[cfg(test)]
mod tests;
