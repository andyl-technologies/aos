//! Checks saved recipient queues against original staged and consumed inputs.

use super::*;
use crate::node_scheduling::InputIdentity;
use std::mem::size_of;

pub(super) fn validate_input_queue(
    snapshot: &SchedulingSnapshot,
    batch: &SavedInputBatch,
) -> Result<(), SchedulingError> {
    // The caller checks the consumed prefix's length and original identities.
    // Consumption removes that recipient's entry from the live pending queue.
    // Match the recipient and logical input, so changed coordinates cannot
    // replay it and another recipient's fanout remains independent.
    let consumed_deliveries = &batch.deliveries[..batch.consumed.len()];
    for consumed in consumed_deliveries {
        if snapshot.pending_deliveries.iter().any(|pending| {
            pending.consumer == consumed.consumer
                && pending.producer == consumed.producer
                && pending.source_sequence == consumed.source_sequence
        }) {
            return Err(SchedulingError::InvalidSnapshot);
        }
    }

    // The caller has checked strict EventKey ordering. Borrow its four fields
    // for logarithmic lookup without constructing cloned identifier keys.
    let unconsumed_deliveries = &batch.deliveries[batch.consumed.len()..];
    for expected in unconsumed_deliveries {
        let key = (
            expected.delivery,
            &expected.consumer,
            &expected.producer,
            expected.source_sequence,
        );
        let index = snapshot
            .pending_deliveries
            .binary_search_by(|pending| {
                (
                    pending.delivery,
                    &pending.consumer,
                    &pending.producer,
                    pending.source_sequence,
                )
                    .cmp(&key)
            })
            .map_err(|_| SchedulingError::InvalidSnapshot)?;

        // The ordering key alone omits payload and native provenance. Require
        // the complete staged record to survive until actual consumption.
        if snapshot.pending_deliveries.get(index) != Some(expected) {
            return Err(SchedulingError::InvalidSnapshot);
        }
    }
    Ok(())
}

/// Checks global public identity after each recipient's consumed prefix.
///
/// Fanout recipients have distinct public sequences. A consumed identity cannot
/// also name another consumed input or a pending input at any recipient. The
/// temporary index borrows identifiers from the original saved record.
///
/// # Errors
/// Refuses repeated consumed identities or any identity shared by consumed and
/// pending custody, without modifying the original histories.
pub(super) fn validate_consumed_source_identities(
    snapshot: &SchedulingSnapshot,
) -> Result<(), SchedulingError> {
    let mut consumed = BTreeSet::new();
    for batch in &snapshot.input_batches {
        for identity in &batch.consumed {
            if !consumed.insert((&identity.producer, identity.source_sequence)) {
                return Err(SchedulingError::InvalidSnapshot);
            }
        }
    }

    for delivery in &snapshot.pending_deliveries {
        if consumed.contains(&(&delivery.producer, delivery.source_sequence)) {
            return Err(SchedulingError::InvalidSnapshot);
        }
    }
    Ok(())
}

/// Checks staged input identities against their original saved histories.
///
/// A consumed entry has left pending_deliveries, but its producer and native
/// endpoint histories remain part of the saved continuation. The existing
/// indexes are borrowed without constructing a new bank.
///
/// # Errors
/// Refuses an absent producer or native endpoint history, an input at or beyond
/// the next public sequence, or a native FIFO identity beyond the last observed.
pub(super) fn validate_source_history(
    sequences: &BTreeMap<Id, Option<U64>>,
    native_sequences: &[SavedNativeSequence],
    delivery: &Delivery,
) -> Result<(), SchedulingError> {
    let next = sequences
        .get(&delivery.producer)
        .ok_or(SchedulingError::InvalidSnapshot)?;
    if next.is_some_and(|next| next <= delivery.source_sequence) {
        return Err(SchedulingError::InvalidSnapshot);
    }

    let native_last = native_sequences
        .iter()
        .find(|saved| saved.endpoint == delivery.producer_endpoint)
        .ok_or(SchedulingError::InvalidSnapshot)?;
    if delivery.native_sequence > native_last.last_sequence {
        return Err(SchedulingError::InvalidSnapshot);
    }
    Ok(())
}

// Adds this borrowed validation walk to the original construction quote. No
// child storage or replacement event identity is constructed by the check.
pub(in crate::node_scheduling) const fn counter_scratch_data() -> usize {
    size_of::<&SchedulingSnapshot>()
        + size_of::<&SavedInputBatch>()
        + size_of::<&[Delivery]>()
        + 2 * size_of::<std::slice::Iter<'static, Delivery>>()
        + 3 * size_of::<&Delivery>()
        + size_of::<std::ops::RangeTo<usize>>()
        + size_of::<usize>()
        + 4 * size_of::<bool>()
        + size_of::<Result<(), SchedulingError>>()
        + pending_queue_counter_scratch_data()
        + source_history_counter_scratch_data()
        + consumed_identity_counter_scratch_data()
}

// Names the actual borrowed index header, insertion and membership loans,
// original history cursors and tuple keys. Its tree backing is priced separately.
const fn consumed_identity_counter_scratch_data() -> usize {
    size_of::<&SchedulingSnapshot>()
        + size_of::<BTreeSet<(&Id, U64)>>()
        + size_of::<&mut BTreeSet<(&Id, U64)>>()
        + size_of::<&BTreeSet<(&Id, U64)>>()
        + size_of::<std::slice::Iter<'static, SavedInputBatch>>()
        + size_of::<&SavedInputBatch>()
        + size_of::<std::slice::Iter<'static, InputIdentity>>()
        + size_of::<&InputIdentity>()
        + size_of::<std::slice::Iter<'static, Delivery>>()
        + size_of::<&Delivery>()
        + 2 * size_of::<(&Id, U64)>()
        + size_of::<&(&Id, U64)>()
        + 2 * size_of::<bool>()
        + size_of::<Result<(), SchedulingError>>()
}

// Prices the independent borrowed history lookup, iterator and its closure,
// optional/result views, copied public sequence and comparison predicates.
const fn source_history_counter_scratch_data() -> usize {
    size_of::<&BTreeMap<Id, Option<U64>>>()
        + size_of::<&[SavedNativeSequence]>()
        + 2 * size_of::<&Delivery>()
        + size_of::<&Id>()
        + size_of::<std::slice::Iter<'static, SavedNativeSequence>>()
        + size_of::<&&SavedNativeSequence>()
        + size_of::<&SavedNativeSequence>()
        + size_of::<Option<&SavedNativeSequence>>()
        + size_of::<Result<&SavedNativeSequence, SchedulingError>>()
        + size_of::<&Option<U64>>()
        + size_of::<Option<&Option<U64>>>()
        + size_of::<Result<&Option<U64>, SchedulingError>>()
        + size_of::<Option<U64>>()
        + size_of::<U64>()
        + 3 * size_of::<bool>()
        + size_of::<Result<(), SchedulingError>>()
}

// Counts the independent remaining-prefix walk and borrowed binary-search views.
// The lookup constructs no EventKey, cloned ID, tree or other child backing.
const fn pending_queue_counter_scratch_data() -> usize {
    size_of::<&[Delivery]>()
        + size_of::<std::slice::Iter<'static, Delivery>>()
        + size_of::<std::ops::RangeFrom<usize>>()
        + 3 * size_of::<&Delivery>()
        + 2 * size_of::<(Position, &Id, &Id, U64)>()
        + 2 * size_of::<&(Position, &Id, &Id, U64)>()
        + 2 * size_of::<Option<&Delivery>>()
        + size_of::<std::cmp::Ordering>()
        + size_of::<Result<usize, usize>>()
        + size_of::<Result<usize, SchedulingError>>()
        + size_of::<usize>()
        + size_of::<bool>()
        + binary_search_counter_scratch_data()
}

// The selected AOS Rust slice search owns size/base/half/mid/insertion indices,
// loop/final comparisons and five predicates. Keep these independent of the
// caller's index, and include the search/get slice loans and mutable comparator.
const fn binary_search_counter_scratch_data() -> usize {
    5 * size_of::<usize>()
        + 2 * size_of::<std::cmp::Ordering>()
        + 5 * size_of::<bool>()
        + 2 * size_of::<&[Delivery]>()
        + size_of::<&mut &(Position, &Id, &Id, U64)>()
}

#[cfg(test)]
#[path = "input_custody/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "input_custody/operation_identity_tests.rs"]
mod operation_identity_tests;

#[cfg(test)]
#[path = "input_custody/source_history_tests.rs"]
mod source_history_tests;

#[cfg(test)]
#[path = "input_custody/global_source_identity_tests.rs"]
mod global_source_identity_tests;
