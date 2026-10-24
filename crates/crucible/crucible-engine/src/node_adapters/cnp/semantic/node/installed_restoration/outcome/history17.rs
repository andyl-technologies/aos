//! Reuses the defining restore outcome comparison for historical DATA only.
//!
//! This adapter does not call an actor or issue an operation admission. Its
//! caller supplies the independently verified original and current records.

use super::*;

/// Compares every outcome field using only the defining fresh-owner substitution.
///
/// # Errors
/// Refuses a changed result body, fullref, publication inventory, scheduling
/// frontier, input progress or any owner outside the exact fresh route.
pub(in crate::node_adapters::cnp::semantic::node) fn historical_outcome_correspondence17_data(
    saved: &OperationOutcome,
    owners: &[OwnerIdentity],
    current: &OperationOutcome,
) -> Result<(), RuntimeError> {
    outcome_correspondence(saved, owners, current)
}

/// Counts the same defining borrowed comparison and iterator frames.
pub(in crate::node_adapters::cnp::semantic::node) fn historical_outcome_correspondence17_counter_scratch_data()
-> usize {
    counter_scratch_data()
}
