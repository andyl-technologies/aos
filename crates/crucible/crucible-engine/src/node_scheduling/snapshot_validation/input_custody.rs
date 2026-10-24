//! Checks saved recipient queues against their original consumed input prefixes.

use super::*;
use std::mem::size_of;

pub(super) fn validate_consumed_queue(
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
}

#[cfg(test)]
#[path = "input_custody/tests.rs"]
mod tests;
