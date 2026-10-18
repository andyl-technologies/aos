//! Checks simultaneous admission storage arithmetic from existing finite policy.
//!
//! This is a conservative checked envelope for payloads, collection elements,
//! state copies and physical-job slots. It is neither measured RSS nor an
//! allocator-success guarantee; allocation and native capacity failures remain
//! explicit errors. Arc clones do not duplicate their encoded payloads.

use super::{
    super::NativeCacheOwnerConfig,
    backing::AdmissionJob,
    io::{DirectoryProgress, PendingFile},
};
use std::{io, mem::size_of};
use terrane::host::cache::{LeaseRecord, PinRecord, ReservationRecord, ResidenceRecord};
use terrane_core::{
    derived::{AttrRecord, AttributeValue},
    manifest::ChunkRef,
    refs::{Commit, PackLocation, Provenance},
    tree_format::{Attribute, ChildRef, Entry, ExtendedAttribute, LeafItem, Property},
};

/// Checks retained, queued and active overlaps before the worker is created.
///
/// # Errors
/// Refuses arithmetic overflow in any concurrently retained storage category.
pub(super) fn check(config: &NativeCacheOwnerConfig) -> io::Result<()> {
    let total = check_parts(
        config.state.records,
        config.queued_commands,
        config.reads.max_allocation_bytes,
        config.location.chunk_profile().maximum(),
        config.state.bytes,
    )?;
    // The owned write ticket, readback path and native metadata operations each
    // retain a path derived from the actual configured root, not a guessed max.
    let path = config
        .location
        .root()
        .as_os_str()
        .len()
        .checked_add(32)
        .ok_or_else(overflow)?;
    let total = total
        .checked_add(path.checked_mul(4).ok_or_else(overflow)?)
        .and_then(|sum| sum.checked_add(size_of::<super::super::snapshot::PreparedSnapshotWrite>()))
        .and_then(|sum| sum.checked_add(6 * size_of::<std::fs::File>()))
        .ok_or_else(overflow)?;
    // Publication claims retain the configured domain, and an uncertain reply
    // retains its bounded protobuf packet. Count those separately from encoded
    // input/plaintext payloads; a small read window does not bound labels.
    let jobs = config
        .state
        .records
        .checked_add(config.queued_commands)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(overflow)?;
    let labels = config
        .location
        .domain()
        .len()
        .checked_add(config.quota_owner.len())
        .and_then(|bytes| bytes.checked_mul(8))
        .ok_or_else(overflow)?;
    let replies = crate::publisher_local::validation::MAX_PACKET
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(labels))
        .ok_or_else(overflow)?;
    total
        .checked_add(jobs.checked_mul(replies).ok_or_else(overflow)?)
        .ok_or_else(overflow)?;
    Ok(())
}

fn check_parts(
    records: usize,
    queued: usize,
    window: usize,
    maximum: usize,
    state: usize,
) -> io::Result<usize> {
    let mut total = 0usize;
    let mut add = |count: usize, bytes: usize| -> io::Result<()> {
        total = total
            .checked_add(count.checked_mul(bytes).ok_or_else(overflow)?)
            .ok_or_else(overflow)?;
        Ok(())
    };
    let jobs = records
        .checked_add(queued)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(overflow)?;
    // Each retained or queued input is bounded by CAPACITY, including both
    // metadata Vecs together. The active Arc refers to its existing job input.
    add(jobs, window)?;

    // One-hop dictionary decoding holds its decoded Vec and returned plaintext
    // copy together; the following chunk decode holds that dictionary and its
    // own plaintext. Three profile-bounded windows cover either transition.
    add(3, maximum.min(window))?;

    // Reconstruction and the second PackReader overlap: Core/native table
    // conversion, recovered index construction (including Vec growth), one
    // verified body and its canonical validation/re-encoding scratch. Each
    // underlying serialized/record allocation is limited by the read window.
    add(4, window)?; // Core/native record tables and conversion capacity.
    add(2, window)?; // Reconstructed index and its growth overlap.
    add(2, window)?; // Current body and canonical byte scratch.

    // Schema collections can expand beyond their encoded byte count. Charge
    // every byte as an element of EACH relevant variable-length schema type,
    // with a second capacity-growth window. This deliberately overestimates
    // mutually exclusive node/manifest forms instead of treating bytes as RSS.
    let schema_element = [
        size_of::<ChunkRef>(),
        size_of::<Commit>(),
        size_of::<PackLocation>(),
        size_of::<Provenance>(),
        size_of::<AttrRecord>(),
        size_of::<AttributeValue>(),
        size_of::<Entry<'static>>(),
        size_of::<LeafItem<'static>>(),
        size_of::<ChildRef>(),
        size_of::<Attribute<'static>>(),
        size_of::<ExtendedAttribute<'static>>(),
        size_of::<Property<'static>>(),
        size_of::<(String, Vec<u8>)>(),
        size_of::<usize>() * 6,
    ]
    .into_iter()
    .try_fold(0usize, |sum, n| sum.checked_add(n).ok_or_else(overflow))?;
    add(window.checked_mul(2).ok_or_else(overflow)?, schema_element)?;

    // Up to six typed state/string sets coexist: current state, caller's next
    // or pinned intent, retained expected state, owned write ticket, parsed
    // readback and newly synchronized provenance. Six additional byte windows
    // cover preflight/serialization, Tokio's writer copy, bounded encoded
    // readback and parser/closing scratch. This is checked storage arithmetic,
    // not an allocator/RSS guarantee; no extra clone is assumed free.
    add(12, state)?;
    let state_record = size_of::<PinRecord>()
        + size_of::<ReservationRecord>()
        + size_of::<LeaseRecord>()
        + size_of::<ResidenceRecord>();
    // Six live typed sets plus collection capacity overlap.
    add(records.checked_mul(8).ok_or_else(overflow)?, state_record)?;
    // Incoming hashes, dedup trees, next-state pins and retained job closure.
    // A tree node's links are accounted separately from its String and bytes.
    let hash_slot = size_of::<String>() + 64 + size_of::<usize>() * 6;
    add(
        records
            .checked_add(1)
            .and_then(|n| n.checked_mul(4))
            .ok_or_else(overflow)?,
        hash_slot,
    )?;

    // Fixed layout depth: two members, three directory-progress entries and
    // their cloned chains. Names are generated (32hex pack/token, 64hex hash),
    // never copied from a caller path. Descriptor/job headers are not payloads.
    let physical = size_of::<AdmissionJob>()
        + size_of::<super::super::publication::InlineJob>()
        + 2 * size_of::<PendingFile>()
        + 3 * size_of::<DirectoryProgress>()
        + 24 * size_of::<std::fs::File>()
        + 32 * size_of::<String>()
        + 32 * 128;
    add(jobs, physical)?;

    // Queued commands keep large repair custody behind a box. Resume retains
    // its original queued completion box through either RPC outcome. Count the
    // pointees as well as command headers rather than treating indirection as
    // a reduction in simultaneous retained storage.
    let command = size_of::<super::super::retention::Command>()
        + size_of::<crate::host_cache::DerivedIndexRepair>()
        + size_of::<crate::host_cache::CompletedRecovery>();
    add(jobs, command)?;

    // Preserve checked descriptor-count arithmetic independently of byte sums.
    jobs.checked_mul(24).ok_or_else(overflow)?;
    Ok(total)
}

fn overflow() -> io::Error {
    io::Error::other("simultaneous admission storage budget overflow")
}

#[cfg(test)]
mod tests {
    use super::check_parts;

    #[test]
    fn simultaneous_active_copies_and_state_headers_are_checked() {
        assert!(check_parts(64, 4, 4096, 8192, 4096).is_ok());
        // The old input-only product fits; active schema expansion does not.
        let window = usize::MAX / 16;
        assert!(3usize.checked_mul(window).is_some());
        assert!(check_parts(1, 1, window, 1, 1).is_err());
        assert!(check_parts(usize::MAX, 1, 1, 1, 1).is_err());
        assert!(check_parts(1, 1, 1, 1, usize::MAX / 4).is_err());
    }
}
