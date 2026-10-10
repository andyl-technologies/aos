//! One terminal source allocation for already owned, paid canonical bytes.
// SPDX-License-Identifier: Apache-2.0

use std::io::{Cursor, Read};

use super::{BlobHandle, BlobSource, CheckedReadAccess, OwnedBlobBytes, StoreError, batch};
use crate::owned_decode::{DecodeBudget, DecodeScratch};

impl BlobHandle {
    /// Retains paid bytes in a source supporting complete checked reads.
    ///
    /// The incoming owner already retains its body credit. Source control is
    /// admitted before its shared allocation, and every handle alias keeps
    /// both owners. Ordinary and deferred opens deliberately remain unsupported.
    ///
    /// # Errors
    /// Returns original refusal before source birth. This method does not
    /// authenticate the supplied bytes or create a resource allowance.
    pub fn from_owned_bytes(bytes: OwnedBlobBytes) -> Result<Self, StoreError> {
        let original = bytes.original_account();
        original
            .verify_live()
            .map_err(|error| batch::admission_under(original, error))?;
        let credit = original
            .reserve_scratch_bytes(Self::source_allocation_bytes::<Source>())
            .map_err(|error| batch::admission_under(original, error))?;
        Ok(Self::new(Source {
            bytes,
            _credit: credit,
        }))
    }
}

struct Source {
    bytes: OwnedBlobBytes,
    _credit: DecodeScratch,
}

impl BlobSource for Source {
    fn logical_length(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn checked_read_access(&self) -> CheckedReadAccess {
        CheckedReadAccess::Whole
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Err(StoreError::Unsupported {
            capability: "prepaid-source-complete-checked-read",
        })
    }

    fn read_all_with_boundary(
        &self,
        caller: &DecodeBudget,
        maximum: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<OwnedBlobBytes, StoreError> {
        let mut reader = Cursor::new(&self.bytes[..]);
        batch::read_reader_under(
            self.bytes.original_account(),
            caller,
            self.logical_length(),
            maximum,
            boundary,
            &mut |output, _| {
                reader.read(output).map_err(|source| StoreError::StreamIo {
                    operation: "read-prepaid-canonical-source",
                    source,
                })
            },
        )
    }
}
