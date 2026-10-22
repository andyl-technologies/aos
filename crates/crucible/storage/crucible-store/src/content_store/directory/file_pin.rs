//! Shared file custody through both file and source control allocation closure.

use std::fs::File;
use std::sync::Arc;

use crate::owned_decode::DecodeScratch;

use super::FileBorrow;

struct FileOwner<R> {
    file: File,
    _resources: R,
    _credit: DecodeScratch,
}

#[repr(C)]
struct AllocationExtent<R> {
    _strong: usize,
    _weak: usize,
    _owner: FileOwner<R>,
}

// Empty slots exist only during private Drop, after every safe borrow ends.
// Default unit resources preserve existing Directory reader/pin geometry.
pub(in crate::content_store) struct FilePin<R = ()>(Option<Arc<FileOwner<R>>>);

impl FilePin {
    pub(super) fn new(file: File, credit: DecodeScratch) -> Self {
        Self::with_resources(file, credit, ())
    }
}

impl<R> FilePin<R> {
    /// Retains concrete descriptor custody inside the same terminal file owner.
    pub(in crate::content_store) fn with_resources(
        file: File,
        credit: DecodeScratch,
        resources: R,
    ) -> Self {
        Self(Some(Arc::new(FileOwner {
            file,
            _resources: resources,
            _credit: credit,
        })))
    }

    pub(in crate::content_store) const fn allocation_bytes() -> u64 {
        std::mem::size_of::<AllocationExtent<R>>() as u64
    }

    pub(in crate::content_store) fn file(&self) -> Option<&File> {
        self.0.as_deref().map(|owner| &owner.file)
    }
}

impl<R> Clone for FilePin<R> {
    fn clone(&self) -> Self {
        Self(self.0.as_ref().map(Arc::clone))
    }
}

impl<R> FileBorrow for FilePin<R> {
    fn file(&self) -> Option<&File> {
        FilePin::file(self)
    }
}

impl<R> Drop for FilePin<R> {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            // Every alias uses the same concrete control. The final closer
            // frees it before File, descriptor custody, and original credit.
            drop(Arc::into_inner(owner));
        }
    }
}

#[cfg(test)]
mod descriptor_tests;
