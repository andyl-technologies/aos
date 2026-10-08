//! Shared file custody through both file and source control allocation closure.

use std::fs::File;
use std::sync::Arc;

use crate::owned_decode::DecodeScratch;

use super::FileBorrow;

struct FileOwner {
    file: File,
    _credit: DecodeScratch,
}

#[repr(C)]
struct AllocationExtent {
    _strong: usize,
    _weak: usize,
    _owner: FileOwner,
}

// Empty slots exist only during private Drop, after every safe borrow ends.
#[derive(Clone)]
pub(super) struct FilePin(Option<Arc<FileOwner>>);

impl FilePin {
    pub(super) fn new(file: File, credit: DecodeScratch) -> Self {
        Self(Some(Arc::new(FileOwner {
            file,
            _credit: credit,
        })))
    }

    pub(super) const fn allocation_bytes() -> u64 {
        std::mem::size_of::<AllocationExtent>() as u64
    }
}

impl FileBorrow for FilePin {
    fn file(&self) -> Option<&File> {
        self.0.as_deref().map(|owner| &owner.file)
    }
}

impl Drop for FilePin {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            // Every alias uses the same concrete control. The final closer
            // frees it before dropping File and the original combined loan.
            drop(Arc::into_inner(owner));
        }
    }
}
