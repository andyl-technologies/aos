//! Retains one prepaid concrete binder through terminal control deallocation.
//!
//! The opaque handle exposes binding and cloning, while its private adapter
//! consumes every Arc alias before the original binder value releases credit.
//! No ordinary Arc or Weak reference to this control is exposed.

use std::alloc::Layout;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use super::{StoreError, StorePhysicalQuotaBinder, StorePhysicalQuotaGuard};

/// Opaque retained ownership of one prepaid physical-quota binder.
///
/// The concrete provider value and its single shared control must be funded
/// before construction. Every alias closes the control before the last
/// provider value releases its original service and accounts.
pub struct StorePhysicalQuotaBinderHandle {
    owner: Option<Arc<dyn TerminalBinder>>,
}

impl StorePhysicalQuotaBinderHandle {
    /// Publishes a prepaid concrete binder in its one shared control.
    ///
    /// `binder` is the concrete original value, rather than an existing Arc.
    /// The caller prepays [`Self::allocation_bytes`] in its original accounts
    /// and retains those accounts in `binder` through terminal deallocation.
    pub fn new<B: StorePhysicalQuotaBinder + 'static>(binder: B) -> Self {
        Self {
            owner: Some(Arc::new(Owner { value: binder })),
        }
    }

    /// Returns the complete target allocation extent for a concrete binder.
    ///
    /// # Errors
    /// Refuses a layout overflow on the compilation target.
    pub fn allocation_bytes<B: StorePhysicalQuotaBinder + 'static>() -> Result<usize, StoreError> {
        Layout::new::<(AtomicUsize, AtomicUsize)>()
            .extend(Layout::new::<Owner<B>>())
            .map(|(layout, _)| layout.pad_to_align().size())
            .map_err(|_| StoreError::Quota)
    }

    /// Authenticates and pins the requested operator-installed quota boundary.
    ///
    /// # Errors
    /// Returns the concrete provider's original authentication or quota error.
    pub fn bind(
        &self,
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.owner()
            .bind(root, project_id, maximum_physical_bytes, maximum_inodes)
    }

    /// Reserves fixed memory-node custody under the retained original service.
    ///
    /// # Errors
    /// Returns the provider's original memory admission refusal.
    pub fn reserve_memory_namespace(
        &self,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.owner().reserve_memory_namespace(bytes)
    }

    /// Verifies the same original service before a covered memory mutation.
    ///
    /// # Errors
    /// Returns the provider's original permission or supervision refusal.
    pub fn verify_memory_namespace(&self) -> Result<(), StoreError> {
        self.owner().verify_memory_namespace()
    }

    fn owner(&self) -> &dyn TerminalBinder {
        match &self.owner {
            Some(owner) => owner.as_ref(),
            None => unreachable!("a live binder handle owns its provider"),
        }
    }
}

impl Clone for StorePhysicalQuotaBinderHandle {
    fn clone(&self) -> Self {
        Self {
            owner: self.owner.clone(),
        }
    }
}

impl Drop for StorePhysicalQuotaBinderHandle {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            owner.close();
        }
    }
}

trait TerminalBinder: StorePhysicalQuotaBinder {
    fn close(self: Arc<Self>);
}

#[repr(transparent)]
struct Owner<B> {
    value: B,
}

impl<B: StorePhysicalQuotaBinder + 'static> TerminalBinder for Owner<B> {
    fn close(self: Arc<Self>) {
        drop(Arc::into_inner(self));
    }
}

impl<B: StorePhysicalQuotaBinder> StorePhysicalQuotaBinder for Owner<B> {
    fn reserve_memory_namespace(
        &self,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.value.reserve_memory_namespace(bytes)
    }

    fn verify_memory_namespace(&self) -> Result<(), StoreError> {
        self.value.verify_memory_namespace()
    }

    fn bind(
        &self,
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.value
            .bind(root, project_id, maximum_physical_bytes, maximum_inodes)
    }
}
