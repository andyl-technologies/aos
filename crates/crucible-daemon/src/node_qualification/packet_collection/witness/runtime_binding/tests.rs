//! Checks complete pre-Child handle-copy credit without constructing authority.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Malformed bounded data or changed credit is the test signal; no native permission is constructed.
#![allow(clippy::unwrap_used)]

use crucible::node_contract::{ActivationRecord, NodeRoute, OwnerIdentity};
use crucible_node_contract::{Id, Phase, Position, U64, canonical};

use super::*;

#[test]
fn all_future_original_slots_are_credited_before_retention() {
    assert!(OriginalBindings::reserve(0).is_err());
    assert!(OriginalBindings::reserve(MAXIMUM_BINDING_BYTES / MAXIMUM_ENTRY_BYTES).is_ok());
    assert!(OriginalBindings::reserve(MAXIMUM_BINDING_BYTES / MAXIMUM_ENTRY_BYTES + 1).is_err());
    assert!(OriginalBindings::reserve(usize::MAX).is_err());
}

#[test]
fn maximal_selected_one_owner_fields_fit_complete_two_copy_slot() {
    let identifier = Id::new("x".repeat(128)).unwrap();
    let owner = OwnerIdentity {
        owner: identifier.clone(),
        incarnation: identifier.clone(),
        generation: U64::new(u64::MAX),
    };
    let route = NodeRoute {
        node: identifier.clone(),
        owners: vec![owner.clone()],
    };
    let record = ActivationRecord {
        generation: U64::new(u64::MAX),
        activation_id: identifier.clone(),
        world_binding_hash: canonical::hash("cnp.world-binding.v1", b"bounded-world-data").unwrap(),
        owners: vec![owner],
        boundary: Position::new(
            U64::new(u64::MAX),
            U64::new(u64::MAX),
            Phase::BoundaryControl,
        ),
    };
    let mut reference = canonical::content_ref(b"original-body", "application/json").unwrap();
    reference.media_type = "\\".repeat(128);
    reference.length = U64::new(u64::MAX);
    let fields = (
        &identifier,
        &route,
        scope::activation_view(&record),
        &reference,
    );

    let bytes = scope::encoded_size(&fields, MAXIMUM_ENTRY_BYTES / 2).unwrap();
    assert!(bytes * 2 <= MAXIMUM_ENTRY_BYTES);
    // This is only a sizing view of data: no WorldActivation or token exists.
}
