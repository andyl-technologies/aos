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
}
