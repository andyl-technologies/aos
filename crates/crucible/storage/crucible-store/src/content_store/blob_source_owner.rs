//! Private shared source ownership through the final control allocation close.

use std::io::Read;
use std::sync::Arc;

use super::{BlobSource, CheckedReadAccess, CheckedReader, OwnedBlobBytes, StoreError};
use crate::owned_decode::DecodeBudget;

trait TerminalSource: BlobSource {
    fn close(self: Arc<Self>);
}

#[repr(transparent)]
struct Owner<S>(S);

impl<S: BlobSource + 'static> TerminalSource for Owner<S> {
    fn close(self: Arc<Self>) {
        // Every alias closes through this concrete type, with no Weak escape.
        // Exactly one concurrent closer extracts the source after deallocation.
        drop(Arc::into_inner(self));
    }
}

impl<S: BlobSource + 'static> BlobSource for Owner<S> {
    fn checked_read_access(&self) -> CheckedReadAccess {
        self.0.checked_read_access()
    }

    fn logical_length(&self) -> u64 {
        self.0.logical_length()
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        self.0.open()
    }

    fn open_with_boundary(
        &self,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<CheckedReader, StoreError> {
        self.0.open_with_boundary(original, boundary)
    }

    fn read_all_with_boundary(
        &self,
        original: &DecodeBudget,
        maximum: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<OwnedBlobBytes, StoreError> {
        self.0.read_all_with_boundary(original, maximum, boundary)
    }
}

#[repr(C)]
struct AllocationExtent<S> {
    _strong: usize,
    _weak: usize,
    _owner: Owner<S>,
}

pub(super) const fn allocation_bytes<S>() -> u64 {
    std::mem::size_of::<AllocationExtent<S>>() as u64
}

// The slot becomes empty only during Drop, when no safe borrow can access it.
// Keeping that state private permits consuming the Arc without unsafe code.
#[derive(Clone)]
pub(super) struct SourceOwner {
    shared: Option<Arc<dyn TerminalSource>>,
}

impl SourceOwner {
    pub(super) fn new<S: BlobSource + 'static>(source: S) -> Self {
        Self {
            shared: Some(Arc::new(Owner(source))),
        }
    }

    fn source(&self) -> Option<&dyn TerminalSource> {
        self.shared.as_deref()
    }
}

impl Drop for SourceOwner {
    fn drop(&mut self) {
        if let Some(source) = self.shared.take() {
            source.close();
        }
    }
}

impl BlobSource for SourceOwner {
    fn checked_read_access(&self) -> CheckedReadAccess {
        self.shared.as_deref().map_or(
            CheckedReadAccess::Unsupported,
            BlobSource::checked_read_access,
        )
    }

    fn logical_length(&self) -> u64 {
        self.shared.as_deref().map_or(0, BlobSource::logical_length)
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        match self.source() {
            Some(source) => source.open(),
            None => Err(StoreError::Unavailable),
        }
    }

    fn open_with_boundary(
        &self,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<CheckedReader, StoreError> {
        match self.source() {
            Some(source) => source.open_with_boundary(original, boundary),
            None => Err(StoreError::Unavailable),
        }
    }

    fn read_all_with_boundary(
        &self,
        original: &DecodeBudget,
        maximum: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<OwnedBlobBytes, StoreError> {
        match self.source() {
            Some(source) => source.read_all_with_boundary(original, maximum, boundary),
            None => Err(StoreError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Source {
        drops: Arc<AtomicUsize>,
    }

    impl BlobSource for Source {
        fn logical_length(&self) -> u64 {
            0
        }

        fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
            Ok(Box::new(std::io::empty()))
        }
    }

    impl Drop for Source {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[repr(align(64))]
    struct AlignedSource;

    #[test]
    fn source_owner_preserves_fat_pointer_and_concrete_value_geometry() {
        assert_eq!(
            std::mem::size_of::<SourceOwner>(),
            std::mem::size_of::<Arc<dyn BlobSource>>()
        );
        assert_eq!(
            std::mem::size_of::<Owner<Source>>(),
            std::mem::size_of::<Source>()
        );
        assert_eq!(
            std::mem::align_of::<Owner<Source>>(),
            std::mem::align_of::<Source>()
        );
        assert_eq!(std::mem::size_of::<AllocationExtent<AlignedSource>>(), 64);
        assert_eq!(std::mem::align_of::<AllocationExtent<AlignedSource>>(), 64);
    }

    #[test]
    fn concurrent_final_aliases_destroy_the_same_source_once() {
        let drops = Arc::new(AtomicUsize::new(0));
        let source = SourceOwner::new(Source {
            drops: drops.clone(),
        });
        let first = source.clone();
        let second = source.clone();
        drop(source);
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        std::thread::scope(|scope| {
            scope.spawn(move || drop(first));
            scope.spawn(move || drop(second));
        });

        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}
