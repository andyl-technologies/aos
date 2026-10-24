//! Retains prepaid resource custody through the final shared allocation close.
//!
//! Every clone hides its concrete reference-counted owner. The final clone
//! extracts that owner after deallocating its control block, then drops the
//! original loan value. No weak reference or raw shared owner can escape.
//! This is an in-process ownership API, never a wire or shared-memory layout.

use std::fmt;
use std::sync::Arc;

trait TerminalLoan: Send + Sync {
    fn close(self: Arc<Self>);
}

#[repr(transparent)]
struct Owner<L>(L);

impl<L: Send + Sync + 'static> TerminalLoan for Owner<L> {
    fn close(self: Arc<Self>) {
        // All strong aliases use into_inner and there are no exposed Weak
        // aliases. Exactly one extracts the value after its control closes.
        drop(Arc::into_inner(self));
    }
}

// ArcInner has a C-layout counter prefix. This extent includes its padding
// for over-aligned loan values, without creating a second allocation.
#[repr(C)]
struct AllocationExtent<L> {
    _strong: usize,
    _weak: usize,
    _owner: Owner<L>,
}

/// Shares an original prepaid resource loan until its final allocation closes.
///
/// Cloning retains the same admission and creates no allocation or new credit.
/// The concrete loan value is destroyed after its shared control allocation is
/// deallocated, so its refund cannot make that allocation prematurely free.
/// No weak reference, raw owner, or access to the concrete value is exposed.
///
/// This handle only preserves supplied custody. Its constructor does not
/// acquire resources or infer capacity; the caller prepays its exact extent.
pub struct ResourceLoan {
    shared: Option<Arc<dyn TerminalLoan>>,
}

impl ResourceLoan {
    /// Returns the shared control and concrete loan value's allocation extent.
    ///
    /// Callers include these bytes in the original admission before creating
    /// the loan. This excludes the separately stored handle and any allocations
    /// already owned by the supplied loan value.
    pub const fn allocation_bytes<L>() -> u64 {
        std::mem::size_of::<AllocationExtent<L>>() as u64
    }

    /// Creates a shared owner from an already prepaid concrete loan value.
    ///
    /// The caller reserves [`Self::allocation_bytes`] for `L` in the original
    /// resource account before calling this method. Moving the value retains
    /// its existing authority; this method performs exactly one allocation,
    /// adds no reservation, and performs no operational supervision check.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crucible_ram::ResourceLoan;
    ///
    /// // A provider first admits this exact extent in its original account.
    /// let bytes = ResourceLoan::allocation_bytes::<()>();
    /// let loan = ResourceLoan::new(());
    /// let borrower = loan.clone();
    /// drop(loan);
    /// drop(borrower);
    /// assert!(bytes >= 2 * std::mem::size_of::<usize>() as u64);
    /// ```
    pub fn new<L: Send + Sync + 'static>(loan: L) -> Self {
        Self {
            shared: Some(Arc::new(Owner(loan))),
        }
    }
}

impl Clone for ResourceLoan {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl Drop for ResourceLoan {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take() {
            shared.close();
        }
    }
}

impl fmt::Debug for ResourceLoan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceLoan")
            .finish_non_exhaustive()
    }
}

/// Retains an optional resource loan without an additional nullable state.
///
/// An empty slot owns no credit. A present slot retains exactly the supplied
/// loan and shares its final allocation-close discipline when cloned. This
/// slot is for owners whose existing resource contract permits absent custody;
/// admission methods return a present [`ResourceLoan`] directly.
#[derive(Clone)]
pub struct ResourceLoanSlot(ResourceLoan);

impl ResourceLoanSlot {
    /// Borrows the retained loan when the slot contains original custody.
    pub fn as_ref(&self) -> Option<&ResourceLoan> {
        self.0.shared.as_ref().map(|_| &self.0)
    }

    /// Removes original custody and leaves an empty slot.
    pub fn take(&mut self) -> Option<ResourceLoan> {
        let loan = std::mem::take(self).0;
        if loan.shared.is_some() {
            Some(loan)
        } else {
            None
        }
    }
}

impl Default for ResourceLoanSlot {
    fn default() -> Self {
        Self(ResourceLoan { shared: None })
    }
}

impl From<ResourceLoan> for ResourceLoanSlot {
    fn from(loan: ResourceLoan) -> Self {
        Self(loan)
    }
}

impl From<Option<ResourceLoan>> for ResourceLoanSlot {
    fn from(loan: Option<ResourceLoan>) -> Self {
        match loan {
            Some(loan) => Self(loan),
            None => Self::default(),
        }
    }
}

impl fmt::Debug for ResourceLoanSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceLoanSlot")
            .field("loan", &self.as_ref())
            .finish()
    }
}
