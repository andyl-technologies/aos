//! Checked immutable-body lookup and borrowed complete reads under caller custody.

use super::*;
use crate::content_store::checked_reader::{self, AuditedCheckedBlobReader};
use crate::owned_decode::{DecodeBudget, DecodeScratch, ResourceLoanSlot};
use std::sync::TryLockError;

pub(super) fn lock<'a>(
    backend: &'a MemoryBlobBackend,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<MutexGuard<'a, MemoryBlobState>, StoreError> {
    loop {
        checked_reader::check(original, boundary)?;
        match backend.state.try_lock() {
            Ok(state) => return Ok(state),
            Err(TryLockError::WouldBlock) => std::hint::spin_loop(),
            Err(TryLockError::Poisoned(_)) => {
                return Err(StoreError::Poisoned {
                    operation: "checked-memory-state",
                });
            }
        }
    }
}

pub(super) fn lookup(
    backend: &MemoryBlobBackend,
    original: &DecodeBudget,
    id: ContentId,
    range: Option<ByteRange>,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<BlobHandle, StoreError> {
    backend.require_namespace()?;
    let state = lock(backend, original, boundary)?;
    let object = state.objects.get(&id).ok_or(StoreError::NotFound { id })?;
    let length = object.bytes()?.len() as u64;
    let range = range.unwrap_or(ByteRange { offset: 0, length });
    validate_range(length, range)?;
    let credit = original
        .reserve_scratch_bytes(BlobHandle::source_allocation_bytes::<Source>())
        .map_err(|error| batch::admission_under(original, error))?;
    checked_reader::check(original, boundary)?;
    // The body was authenticated before insertion and remains immutable. Its
    // payer retains allocation custody, while this lookup's existing original
    // account owns execution; completing a publisher cannot revoke stored data.
    let source = Source {
        object: object.clone(),
        id,
        range,
        full: range.offset == 0 && range.length == length,
        _credit: credit,
    };
    drop(state);
    checked_reader::check(original, boundary)?;
    if range.offset == 0 && range.length == length {
        Ok(BlobHandle::authenticated(id, source))
    } else {
        Ok(BlobHandle::integrity_checked(id, source))
    }
}

struct Source {
    object: MemoryBody,
    id: ContentId,
    range: ByteRange,
    full: bool,
    _credit: DecodeScratch,
}

impl BlobSource for Source {
    fn checked_read_access(&self) -> CheckedReadAccess {
        if self.full {
            CheckedReadAccess::Whole
        } else {
            CheckedReadAccess::Owning
        }
    }

    fn logical_length(&self) -> u64 {
        self.range.length
    }

    fn open(&self) -> Result<Box<dyn std::io::Read + Send>, StoreError> {
        // Ordinary access retains the same immutable body and checked source
        // credit; checked dispatch never uses this compatibility entry point.
        let handle = memory_handle(self.id, self.object.clone())?;
        handle.slice(Some(self.range))?.open()
    }

    fn open_with_boundary(
        &self,
        caller: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<CheckedReader, StoreError> {
        checked_reader::check(caller, boundary)?;
        let credit = caller
            .reserve_scratch_array::<Reader>(1)
            .map_err(|error| batch::admission_under(caller, error))?;
        checked_reader::check(caller, boundary)?;
        Ok(CheckedReader::admitted(
            Box::new(Reader {
                object: self.object.clone(),
                id: self.id,
                range: self.range,
                offset: 0,
                original: caller.clone(),
                failed: false,
            }),
            credit,
            ResourceLoanSlot::default(),
        ))
    }

    fn read_all_with_boundary(
        &self,
        caller: &DecodeBudget,
        maximum: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<OwnedBlobBytes, StoreError> {
        let start = usize::try_from(self.range.offset).map_err(|_| StoreError::Quota)?;
        let length = usize::try_from(self.range.length).map_err(|_| StoreError::Quota)?;
        let end = start.checked_add(length).ok_or(StoreError::Quota)?;
        let bytes = self.object.bytes()?;
        validate_range(bytes.len() as u64, self.range)?;
        let mut cursor = std::io::Cursor::new(&bytes[start..end]);
        let mut check = || checked_reader::check(caller, boundary);
        batch::read_reader_under(
            caller,
            caller,
            self.range.length,
            maximum,
            &mut check,
            &mut |output, _| {
                std::io::Read::read(&mut cursor, output).map_err(|source| StoreError::StreamIo {
                    operation: "read-checked-memory-body",
                    source,
                })
            },
        )
    }
}

struct Reader {
    object: MemoryBody,
    id: ContentId,
    range: ByteRange,
    offset: u64,
    original: DecodeBudget,
    failed: bool,
}

impl AuditedCheckedBlobReader for Reader {}

impl CheckedBlobReader for Reader {
    fn original_account(&self) -> &DecodeBudget {
        &self.original
    }

    fn full_eof_identity(&self) -> Option<ContentId> {
        Some(self.id)
    }

    fn read_with_boundary(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        if self.failed {
            return Err(checked_reader::failed());
        }
        let result = (|| {
            checked_reader::check(&self.original, boundary)?;
            let length = (self.range.length - self.offset).min(output.len().min(64 * 1024) as u64);
            let start =
                usize::try_from(self.range.offset + self.offset).map_err(|_| StoreError::Quota)?;
            let count = usize::try_from(length).map_err(|_| StoreError::Quota)?;
            let bytes = self.object.bytes()?;
            output[..count].copy_from_slice(&bytes[start..start + count]);
            self.offset += length;
            checked_reader::check(&self.original, boundary)?;
            Ok(count)
        })();
        self.failed = result.is_err();
        result
    }
}

#[cfg(test)]
pub(super) fn allocation_geometry() -> (usize, u64, usize) {
    (
        std::mem::size_of::<Source>(),
        BlobHandle::source_allocation_bytes::<Source>(),
        std::mem::size_of::<Reader>(),
    )
}
