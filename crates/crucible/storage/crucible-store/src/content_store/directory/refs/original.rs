//! Keeps the genuine quota-bound reference control under external custody.
//!
//! The same quota guard pays the actual root buffer and shared backend before
//! allocation. Its loan also remains outside the backend through the final
//! strong/weak control free. Ordinary reference formats and operations remain
//! those of `QuotaDirectoryRefs`.

use std::alloc::Layout;
use std::os::unix::ffi::OsStringExt;

use super::*;
use crate::owned_decode::{DecodeAdmissionError, ResourceLoan};

#[cfg(test)]
mod tests;

/// Holds original reference credit outside all backend and inventory aliases.
#[must_use = "close reference users and inventory before their original credit"]
pub struct OriginalDirectoryRefOwner {
    backend: Option<Arc<QuotaDirectoryRefs>>,
    guard: Option<Arc<dyn StorePhysicalQuotaGuard>>,
    resources: Option<ResourceLoan>,
    failure: Option<DecodeAdmissionError>,
    closed: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("original reference control refused: {source}; original: {original_after:?}")]
struct RefControlCause {
    #[source]
    source: StoreError,
    original_after: Option<StoreError>,
}

impl OriginalDirectoryRefOwner {
    /// Creates the genuine reference views after admitting their exact control.
    ///
    /// The root is borrowed until its buffer is paid. This constructor creates
    /// no directory or descriptor; later reference operations use the same
    /// supplied physical guard and their existing operation reservations.
    ///
    /// # Errors
    /// Refuses the original physical guard, capacity, allocation, or the same
    /// original post-publication boundary. Failed publication retains credit.
    pub fn open(root: &Path, guard: Arc<dyn StorePhysicalQuotaGuard>) -> Result<Self, StoreError> {
        guard.verify()?;
        let extent = shared_bytes::<QuotaDirectoryRefs>()?
            .checked_add(shared_bytes::<RefControlCause>()?)
            .and_then(|bytes| bytes.checked_add(root.as_os_str().len() as u64))
            .ok_or(StoreError::Quota)?;
        let resources = guard.reserve_resources(0, extent)?;
        let mut owner = Self {
            backend: None,
            guard: Some(guard),
            resources: Some(resources),
            failure: None,
            closed: false,
        };
        let work = (|| {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(root.as_os_str().len())
                .map_err(|source| StoreError::Allocation {
                    source,
                    custody: None,
                })?;
            bytes.extend_from_slice(root.as_os_str().as_encoded_bytes());
            let path = PathBuf::from(std::ffi::OsString::from_vec(bytes));
            let guard = owner.guard.as_ref().ok_or(StoreError::Unavailable)?;
            let resources = owner.resources.as_ref().ok_or(StoreError::Unavailable)?;
            owner.backend = Some(Arc::new(QuotaDirectoryRefs {
                child: DirectoryRefBackend::new(path),
                guard: Arc::clone(guard),
                _resources: resources.clone(),
            }));
            Ok(())
        })();
        let after = owner
            .guard
            .as_ref()
            .ok_or(StoreError::Unavailable)?
            .verify();
        owner.reconcile(work, after)?;
        Ok(owner)
    }

    /// Shares ordinary mutation and inventory views of the same allocation.
    ///
    /// # Errors
    /// Refuses consumed custody, its first failure, or the original guard.
    pub fn authorities(&self) -> Result<DirectoryRefAuthorities, StoreError> {
        self.check()?;
        let backend = self.backend.as_ref().ok_or(StoreError::Unavailable)?;
        Ok((
            Arc::clone(backend) as Arc<dyn MutableRefBackend>,
            Arc::clone(backend) as Arc<dyn RefStoreAdmin>,
        ))
    }

    /// Frees the actual reference control before returning its original loan.
    ///
    /// # Errors
    /// Refuses any remaining strong or weak view, a first retained failure, or
    /// the original guard's separate pre/post-deallocation boundary.
    pub fn try_close(&mut self) -> Result<(), StoreError> {
        if self.closed {
            return Ok(());
        }
        self.check()?;
        if let Some(backend) = self.backend.as_mut() {
            Arc::get_mut(backend).ok_or(StoreError::Unavailable)?;
        }
        drop(self.backend.take());
        let after = self.guard.as_ref().ok_or(StoreError::Unavailable)?.verify();
        self.reconcile(Ok(()), after)?;
        drop(self.guard.take());
        drop(self.resources.take());
        self.closed = true;
        Ok(())
    }

    fn check(&self) -> Result<(), StoreError> {
        if let Some(source) = self.failure.as_ref() {
            return Err(StoreError::DecodeAdmission {
                source: source.clone(),
                custody: None,
            });
        }
        self.guard.as_ref().ok_or(StoreError::Unavailable)?.verify()
    }

    fn reconcile(
        &mut self,
        work: Result<(), StoreError>,
        after: Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let cause = match (work, after) {
            (Ok(()), Ok(())) => return Ok(()),
            (Err(source), after) => RefControlCause {
                source,
                original_after: after.err(),
            },
            (Ok(()), Err(source)) => RefControlCause {
                source,
                original_after: None,
            },
        };
        let source = self
            .failure
            .get_or_insert_with(|| DecodeAdmissionError::new(cause))
            .clone();
        Err(StoreError::DecodeAdmission {
            source,
            custody: None,
        })
    }
}

impl Drop for OriginalDirectoryRefOwner {
    fn drop(&mut self) {
        if !self.closed {
            // A returned error, alias or unwind cannot refund this control.
            std::mem::forget(self.backend.take());
            std::mem::forget(self.guard.take());
            std::mem::forget(self.failure.take());
            std::mem::forget(self.resources.take());
        }
    }
}

fn shared_bytes<T>() -> Result<u64, StoreError> {
    Layout::new::<(usize, usize)>()
        .extend(Layout::new::<T>())
        .map(|(layout, _)| layout.pad_to_align().size() as u64)
        .map_err(|_| StoreError::Quota)
}
