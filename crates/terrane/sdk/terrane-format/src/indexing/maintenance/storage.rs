//! Allocates stable canonical byte slices in a caller-owned epoch.

use bumpalo::Bump;
use core::cell::Cell;

use super::Error;

/// A fallible, monotone byte arena shared by immutable maintenance snapshots.
///
/// The caller owns the arena and must keep it alive while any retained Tree
/// borrows its bytes. Payload accounting covers requested slice lengths rather
/// than allocator metadata or reserved chunks. The arena has no bounded-space
/// or cross-thread guarantee.
#[derive(Debug)]
pub struct ByteArena {
    arena: Bump,
    limit: usize,
    payload: Cell<usize>,
}

impl ByteArena {
    /// Creates an arena with an explicit maximum cumulative payload length.
    ///
    /// # Errors
    /// Returns an allocation error if the initial arena chunk cannot be reserved.
    pub fn new(limit: usize) -> Result<Self, Error> {
        Ok(Self {
            arena: Bump::try_new().map_err(|_| Error::Allocation)?,
            limit,
            payload: Cell::new(0),
        })
    }

    /// Returns cumulative successfully allocated payload bytes.
    pub fn payload_bytes(&self) -> usize {
        self.payload.get()
    }

    /// Copies bytes into stable storage shared by every retained snapshot.
    ///
    /// # Errors
    /// Rejects payload overflow, the configured limit or an allocation failure.
    pub fn copy(&self, bytes: &[u8]) -> Result<&[u8], Error> {
        let next = self
            .payload
            .get()
            .checked_add(bytes.len())
            .ok_or(Error::Allocation)?;
        if next > self.limit {
            return Err(Error::Allocation);
        }
        let stored = self
            .arena
            .try_alloc_slice_copy(bytes)
            .map_err(|_| Error::Allocation)?;
        self.payload.set(next);
        Ok(stored)
    }
}
