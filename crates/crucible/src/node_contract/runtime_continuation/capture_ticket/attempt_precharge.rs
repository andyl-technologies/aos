//! Admits the closed four-owner attempt before its first owning allocation.
//!
//! The selected capture banks and cached host preparation remain separately
//! charged by the same geometry seal. This counts only core construction work.

use super::*;
use std::mem::size_of;

pub(super) const OPERATION_BYTES: usize = 32;

pub(super) fn requested(
    graph: &crate::node_admission::AdmittedGraph,
    activation: &WorldActivation,
    capture_id: &Id,
    source: &OriginalLineageRuntimeRecord,
    object: &InputPayload,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    if activation.record().owners.len() != 4 || graph.ownership_policy().capture_owners.len() != 4 {
        return Err(RuntimeError::UnsupportedFacet);
    }

    let mut bytes = storage::shared_allocation::<OriginalLineageCaptureAttempt>();
    bytes = storage::add(bytes, capture_id.as_str().len())?;
    bytes = storage::add(
        bytes,
        crate::node_contract::NodeRuntime::capture_reference_storage(&object.reference)?,
    )?;
    // canonical_json writes to a growing Vec. Count cumulative old/new requests
    // as well as the independently retained original runtime-object bank.
    let encoded = object
        .bytes
        .len()
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(8))
        .ok_or(RuntimeError::ResourceLimit)?;
    bytes = storage::add(bytes, encoded)?;
    bytes = storage::add(
        bytes,
        crate::node_contract::NodeRuntime::capture_serialization_storage(source, maximum)?,
    )?;
    bytes = storage::add(bytes, 4 * size_of::<OriginalCaptureOwnerReservation>())?;
    bytes = storage::add(
        bytes,
        4 * size_of::<Option<super::super::InstalledOriginalLineageCapture>>(),
    )?;
    bytes = storage::add(bytes, 4 * size_of::<Option<(ContentRef, ContentRef)>>())?;

    for policy in &graph.ownership_policy().capture_owners {
        let owner = activation
            .record()
            .owners
            .iter()
            .find(|owner| owner.owner == policy.owner_id)
            .ok_or(RuntimeError::ForeignAuthority)?;
        bytes = storage::add(bytes, owner.owner.as_str().len())?;
        bytes = storage::add(bytes, owner.incarnation.as_str().len())?;
        let mut participants = 0usize;
        for node in graph.node_ids().filter(|node| {
            graph
                .binding(node)
                .is_some_and(|binding| binding.compatibility.capture_owner.id == policy.owner_id)
        }) {
            participants = storage::add(participants, 1)?;
            bytes = storage::add(bytes, node.as_str().len())?;
        }
        if participants != 1 {
            return Err(RuntimeError::UnsupportedFacet);
        }
        // The dispatcher reserves exactly one participant and a fixed operation
        // String bank. Formatting cannot silently request a larger allocation.
        bytes = storage::add(bytes, size_of::<Id>())?;
        bytes = storage::add(bytes, OPERATION_BYTES)?;
    }

    bytes = storage::add(bytes, capture_id.as_str().len())?;
    bytes = storage::add(
        bytes,
        crate::node_contract::NodeRuntime::capture_map_node_storage::<
            Id,
            Rc<OriginalLineageCaptureAttempt>,
        >(),
    )?;
    if bytes > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(bytes)
}

/// Constructs the exact precharged operation bank without geometric growth.
pub(super) fn operation(sequence: U64, index: usize) -> Result<Id, RuntimeError> {
    use std::fmt::Write as _;

    if !(1..=64).contains(&sequence.get()) || index >= 4 {
        return Err(RuntimeError::InvalidReceipt);
    }
    let mut value = String::new();
    value
        .try_reserve_exact(OPERATION_BYTES)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    write!(value, "native-capture/{}/{index}", sequence.get())
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if value.capacity() > OPERATION_BYTES {
        return Err(RuntimeError::ResourceLimit);
    }
    Id::new(value).map_err(|_| RuntimeError::InvalidReceipt)
}

#[cfg(test)]
mod tests {
    // A failed fixed-bank invariant intentionally panics in these controls.
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn operation_bank_covers_every_closed_attempt_without_growth() {
        for sequence in 1..=64 {
            for index in 0..4 {
                let operation = operation(U64::new(sequence), index).unwrap();
                assert_eq!(
                    operation.as_str(),
                    format!("native-capture/{sequence}/{index}")
                );
                assert_eq!(operation.allocated_capacity(), OPERATION_BYTES);
            }
        }
    }

    #[test]
    fn operation_bank_refuses_outside_lifetime_before_constructing_identity() {
        assert_eq!(operation(U64::new(0), 0), Err(RuntimeError::InvalidReceipt));
        assert_eq!(
            operation(U64::new(65), 0),
            Err(RuntimeError::InvalidReceipt)
        );
        assert_eq!(operation(U64::new(1), 4), Err(RuntimeError::InvalidReceipt));
    }
}
