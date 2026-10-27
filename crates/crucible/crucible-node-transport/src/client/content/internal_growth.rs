//! Prices new internal content buffers and metadata at unchanged local ceilings.
//!
//! Borrowed installation and incoming transfers allocate beneath these caps.
//! Existing buffers remain separately charged, including caller-owned buffers
//! and reference strings installed with spare capacity. This DATA grants no
//! capacity or Source action.

use super::*;
use std::mem::size_of;

// Validation fixes the algorithm, blob domain and lowercase digest. The media
// type contributes at most 128 printable bytes. Tree entries own inline headers.
const MAXIMUM_REFERENCE_TEXT_BYTES: usize = "blake3-256".len() + "cnp.blob.v1".len() + 64 + 128;

/// Reports separately priced internal growth without changing content quotas.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalClientContentGrowthStorageData {
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl OriginalClientContentGrowthStorageData {
    /// Returns new buffer, alias-view, map, identity and reference backing.
    pub fn retained_requested_bytes_data(self) -> usize {
        self.retained
    }

    /// Returns internal reallocation, borrowed-roster and verification work.
    pub fn maximum_simultaneous_transient_bytes_data(self) -> usize {
        self.transient
    }

    /// Returns explicit fixed quote, hashing and borrowed result views.
    pub fn counter_scratch_bytes_data(self) -> usize {
        self.scratch
    }

    /// Adds an enclosing DATA counter without issuing allocation permission.
    pub(in crate::client) fn with_additional_counter_storage_data(
        mut self,
        additional: usize,
        maximum: usize,
    ) -> Result<Self, ProviderError> {
        self.scratch = add(self.scratch, additional)?;
        if sum(&[self.retained, self.transient, self.scratch])? > maximum {
            return Err(exhausted());
        }
        Ok(self)
    }
}

impl ClientContent {
    /// Borrows the actual object ceiling for the closed runtime metadata walk.
    pub(in crate::client) fn packet_runtime_object_ceiling_data(&self) -> usize {
        self.maximum_objects
    }

    /// Bounds future internal allocations under the same byte and object caps.
    ///
    /// The retained row covers borrowed installation, mutable incoming transfers,
    /// completed immutable objects and both observed Rc views. A Begin reserves
    /// numeric length; chunks allocate its buffer later. Existing allocations
    /// remain independently charged and receive no spare-capacity refund.
    ///
    /// This covers allocations made inside content custody. Caller-owned buffers
    /// and reference strings passed to `install` can have capacity beyond their
    /// length; callers price those arguments separately. Wire decoders, caller
    /// iterators and DTOs,
    /// journals and conservative whole-Source observation growth also require
    /// independent funding. The fixed counter is admitted before this DATA walk.
    ///
    /// # Errors
    /// Refuses arithmetic overflow, unsupported tree layouts or a complete
    /// retained/transient/scratch row above the independent supplied restriction.
    pub fn original_internal_growth_storage_data(
        &self,
        maximum: usize,
    ) -> Result<OriginalClientContentGrowthStorageData, ProviderError> {
        // The existing full receiver row names the actual private Transfer and
        // object layouts. Its four text views must also cover the two full
        // references, duplicate digest key and independent transfer identity.
        let identity_text = sum(&[
            multiply(2, MAXIMUM_REFERENCE_TEXT_BYTES)?,
            64,
            crucible_node_format::MAX_ID_BYTES,
        ])?;
        let reference_text = MAXIMUM_REFERENCE_TEXT_BYTES.max(identity_text.div_ceil(4));
        let retained = self.restored_settled_capture_receiver_storage_data(reference_text)?;

        // A growth request is at most twice its required extent, or the pinned
        // eight-byte minimum. An existing oversized allocation stays in the
        // current census; cloning a shared Vec copies its length, not capacity.
        let reallocation = add(
            multiply(2, self.maximum_bytes)?,
            multiply(8, self.maximum_objects)?,
        )?;
        let prospective = multiply(self.maximum_objects, size_of::<(&ContentRef, &[u8])>())?;
        let transient = sum(&[
            reallocation,
            prospective,
            // Verification constructs a hash; successful method returns can
            // retain a separate full reference and transfer ID at the same cut.
            multiply(2, MAXIMUM_REFERENCE_TEXT_BYTES)?,
            crucible_node_format::MAX_ID_BYTES,
        ])?;
        let scratch = Self::original_internal_growth_counter_scratch_data();
        if sum(&[retained, transient, scratch])? > maximum {
            return Err(exhausted());
        }

        Ok(OriginalClientContentGrowthStorageData {
            retained,
            transient,
            scratch,
        })
    }

    /// Names internal-growth layout, hash, borrowed-roster and result headers.
    pub fn original_internal_growth_counter_scratch_data() -> usize {
        Self::restored_settled_capture_receiver_counter_scratch_data()
            + 2 * size_of::<OriginalClientContentGrowthStorageData>()
            + size_of::<Result<OriginalClientContentGrowthStorageData, ProviderError>>()
            + size_of::<&Self>()
            + size_of::<&[usize]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<[usize; 24]>()
            + size_of::<std::alloc::Layout>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<[u8; 64]>()
            + 2 * size_of::<crucible_node_format::HashRef>()
            + size_of::<BlobBeginResult>()
            + size_of::<BlobChunkResult>()
            + size_of::<BlobFinishResult>()
            + size_of::<Result<BlobBeginResult, ProviderError>>()
            + size_of::<Result<BlobChunkResult, ProviderError>>()
            + size_of::<Result<BlobFinishResult, ProviderError>>()
            + size_of::<Vec<(&'static ContentRef, &'static [u8])>>()
            + size_of::<std::vec::IntoIter<(&'static ContentRef, &'static [u8])>>()
            + size_of::<Result<Vec<(&'static ContentRef, &'static [u8])>, ProviderError>>()
    }
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn multiply(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0, |total, value| add(total, *value))
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("original content internal growth projection")
}

#[cfg(test)]
mod tests;
