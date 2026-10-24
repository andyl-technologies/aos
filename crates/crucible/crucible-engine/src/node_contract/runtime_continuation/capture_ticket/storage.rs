//! Counts concrete owned capture buffers and their nested public metadata.
//!
//! This counts requested storage extents, including unused capacity. It does not
//! bound allocator bookkeeping or the separate decoded core snapshot trees;
//! those require the complete pre-effect metadata geometry before dispatch.

use super::*;
use std::mem::size_of;

pub(super) fn add(total: usize, bytes: usize) -> Result<usize, RuntimeError> {
    total.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
}

fn vector<T>(values: &Vec<T>) -> Result<usize, RuntimeError> {
    values
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or(RuntimeError::ResourceLimit)
}

fn reference(reference: &ContentRef) -> Result<usize, RuntimeError> {
    let bytes = add(
        reference.hash.algorithm.capacity(),
        reference.hash.domain.capacity(),
    )?;
    let bytes = add(bytes, reference.hash.digest.capacity())?;
    add(bytes, reference.media_type.capacity())
}

pub(super) fn payload(payload: &InputPayload) -> Result<usize, RuntimeError> {
    add(payload.bytes.capacity(), reference(&payload.reference)?)
}

pub(super) fn payload_vector(payloads: &Vec<InputPayload>) -> Result<usize, RuntimeError> {
    payloads
        .iter()
        .try_fold(vector(payloads)?, |bytes, object| {
            add(bytes, payload(object)?)
        })
}

pub(super) fn captured(
    captured: &super::super::InstalledOriginalLineageCapture,
) -> Result<usize, RuntimeError> {
    let native = &captured.native;
    // Complete packet-five codecs currently select neither schema extensions
    // nor physical artifact adoption. Unknown trees never receive a zero-cost
    // interpretation, and ordinary native capture keeps its separate codecs.
    if !native.key.schema.extensions.is_empty() || !native.artifacts.is_empty() {
        return Err(RuntimeError::UnsupportedFacet);
    }
    let mut bytes = add(
        native.owner.allocated_capacity(),
        vector(&native.participants)?,
    )?;
    for participant in &native.participants {
        bytes = add(bytes, participant.allocated_capacity())?;
    }
    bytes = add(bytes, native.key.implementation.allocated_capacity())?;
    bytes = add(bytes, native.key.profile.allocated_capacity())?;
    bytes = add(bytes, native.key.schema.id.allocated_capacity())?;
    bytes = add(bytes, reference(&native.key.schema.definition)?)?;
    // Removing the final entry can leave an empty BTree leaf allocated. The
    // closed empty-extension grammar therefore still reserves one node.
    bytes = add(bytes, super::value_layout::map_node_bytes())?;
    bytes = add(bytes, payload(&native.state)?)?;
    bytes = add(bytes, payload_vector(&native.evidence)?)?;
    // An empty artifact vector can still own a large allocation.
    bytes = add(bytes, vector(&native.artifacts)?)?;
    add(bytes, payload(&captured.journal)?)
}

pub(super) fn attempt(attempt: &OriginalLineageCaptureAttempt) -> Result<usize, RuntimeError> {
    use super::owned::OwnedStorage;

    let mut bytes = shared_allocation::<OriginalLineageCaptureAttempt>();
    bytes = add(bytes, attempt.capture_id.allocated_capacity())?;
    bytes = add(bytes, attempt.activation.record().owned_storage()?)?;
    bytes = add(bytes, payload(&attempt.runtime_object)?)?;
    bytes = add(bytes, vector(&attempt.owners)?)?;
    for owner in &attempt.owners {
        bytes = add(bytes, owner.owner.owned_storage()?)?;
        bytes = add(bytes, owner.participants.owned_storage()?)?;
        bytes = add(bytes, owner.operation.allocated_capacity())?;
    }
    let captures = attempt
        .captures
        .try_borrow()
        .map_err(|_| RuntimeError::OutstandingObligations)?;
    bytes = add(bytes, vector(&captures)?)?;
    for capture in captures.iter().flatten() {
        bytes = add(bytes, captured(capture)?)?;
    }
    let settlements = attempt
        .settlements
        .try_borrow()
        .map_err(|_| RuntimeError::OutstandingObligations)?;
    bytes = add(bytes, vector(&settlements)?)?;
    for (state, journal) in settlements.iter().flatten() {
        bytes = add(bytes, reference(state)?)?;
        bytes = add(bytes, reference(journal)?)?;
    }
    bytes = add(bytes, attempt.host.owned_snapshot_storage()?)?;
    if let Some(archive) = attempt.persisted.get() {
        bytes = add(bytes, archive.capture_owned_storage()?)?;
    }
    Ok(bytes)
}

// RcInner/ArcInner are repr(C): two pointer-sized reference counters followed
// by the actual data with its own alignment. Counting a header by addition
// alone would omit padding for a future over-aligned selected data type.
#[repr(C)]
#[allow(dead_code)]
struct SharedAllocation<T> {
    strong: usize,
    weak: usize,
    data: T,
}

pub(super) fn shared_allocation<T>() -> usize {
    size_of::<SharedAllocation<T>>()
}

/// Bounds shared control blocks separately from observed inline payload bytes.
pub(super) fn protocol_shared_header_storage(
    views: usize,
    maximum_data_alignment: usize,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    use std::{alloc::Layout, mem::align_of};

    if views == 0 {
        return Ok(0);
    }
    Layout::from_size_align(0, maximum_data_alignment).map_err(|_| RuntimeError::InvalidReceipt)?;
    let alignment = maximum_data_alignment.max(align_of::<usize>());
    let header = (2 * size_of::<usize>())
        .checked_add(alignment - 1)
        .map(|n| n & !(alignment - 1))
        .ok_or(RuntimeError::ResourceLimit)?;
    // Unsized slices may need trailing padding as well as the aligned header.
    // Charge every retained view; no reference identity grants a byte discount.
    let bytes = header
        .checked_add(alignment - 1)
        .and_then(|n| n.checked_mul(views))
        .ok_or(RuntimeError::ResourceLimit)?;
    if bytes > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(bytes)
}

#[cfg(test)]
mod shared_layout_tests {
    use super::*;

    #[repr(align(64))]
    #[allow(dead_code)]
    struct Aligned(u8);

    #[test]
    fn reference_counted_header_accounts_for_data_alignment() {
        assert_eq!(shared_allocation::<Aligned>(), 128);
        assert!(shared_allocation::<Aligned>() > 2 * size_of::<usize>() + size_of::<Aligned>());
    }

    #[test]
    fn protocol_shared_headers_cover_aligned_and_unsized_payload_padding()
    -> Result<(), crate::node_contract::RuntimeError> {
        let headers =
            protocol_shared_header_storage(1, std::mem::align_of::<Aligned>(), usize::MAX)?;
        assert!(headers + size_of::<Aligned>() >= shared_allocation::<Aligned>());
        let bytes = protocol_shared_header_storage(3, 1, usize::MAX)?;
        assert!(bytes >= 3 * 2 * size_of::<usize>());
        assert_eq!(protocol_shared_header_storage(0, 0, 0)?, 0);
        assert!(protocol_shared_header_storage(1, 3, usize::MAX).is_err());
        assert!(protocol_shared_header_storage(usize::MAX, 64, usize::MAX).is_err());
        assert!(protocol_shared_header_storage(1, 8, 1).is_err());
        Ok(())
    }
}
