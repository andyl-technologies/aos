//! Checks saved recipient queues against original staged and consumed inputs.

use super::*;
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
