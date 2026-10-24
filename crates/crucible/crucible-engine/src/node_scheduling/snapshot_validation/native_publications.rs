//! Joins every retained recipient to one immutable native publication.
//!
//! Fanout may change recipient, public sequence and delivery conversion. The
//! original endpoint/FIFO pair still identifies exactly one publication, even
//! after a recipient consumes its input and removes it from the pending queue.

use super::*;
use crucible_node_format::Endpoint;
use std::{collections::btree_map::Entry, mem::size_of};

type Publications<'a> = BTreeMap<(&'a Endpoint, U64), &'a Delivery>;

pub(super) fn validate(snapshot: &SchedulingSnapshot) -> Result<(), SchedulingError> {
    let mut publications = Publications::new();
    for delivery in &snapshot.pending_deliveries {
        record(&mut publications, delivery)?;
    }
    for batch in &snapshot.input_batches {
        for delivery in &batch.deliveries {
            record(&mut publications, delivery)?;
        }
    }
    Ok(())
}

fn record<'a>(
    publications: &mut Publications<'a>,
    delivery: &'a Delivery,
) -> Result<(), SchedulingError> {
    match publications.entry((&delivery.producer_endpoint, delivery.native_sequence)) {
        Entry::Vacant(entry) => {
            entry.insert(delivery);
        }
        Entry::Occupied(entry) => {
            let original = entry.get();
            if original.publication_id != delivery.publication_id
                || original.provenance_ref != delivery.provenance_ref
                || original.publication != delivery.publication
                || original.payload != delivery.payload
                || original.evaluation != delivery.evaluation
                || original.causal_parents != delivery.causal_parents
                || original.external_root != delivery.external_root
            {
                return Err(SchedulingError::InvalidSnapshot);
            }
        }
    }
    Ok(())
}

// Tree backing is independently funded from the complete retained row count.
// All keys and values borrow the original snapshot; no identifiers are cloned.
pub(super) const fn counter_scratch_data() -> usize {
    size_of::<&SchedulingSnapshot>()
        + size_of::<Publications<'static>>()
        + size_of::<&mut Publications<'static>>()
        + 2 * size_of::<std::slice::Iter<'static, Delivery>>()
        + size_of::<std::slice::Iter<'static, SavedInputBatch>>()
        + size_of::<&SavedInputBatch>()
        + 2 * size_of::<&Delivery>()
        + size_of::<&&Delivery>()
        + size_of::<(&Endpoint, U64)>()
        + size_of::<Entry<'static, (&Endpoint, U64), &Delivery>>()
        + size_of::<std::collections::btree_map::VacantEntry<'static, (&Endpoint, U64), &Delivery>>(
        )
        + size_of::<std::collections::btree_map::OccupiedEntry<'static, (&Endpoint, U64), &Delivery>>(
        )
        + 7 * size_of::<bool>()
        + 2 * size_of::<Result<(), SchedulingError>>()
}

#[cfg(test)]
#[path = "native_publications/tests.rs"]
mod tests;
