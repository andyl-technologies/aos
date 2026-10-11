//! Checks exact preparation ownership without removing the original transfer FIFO.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Synthetic metadata controls intentionally fail on an invalid original domain association.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible::node_admission::StateDomain;
use crucible_node_contract::{Id, canonical};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn original() -> OwnershipPolicy {
    OwnershipPolicy {
        schema_version: 1,
        domains: vec![
            StateDomain {
                id: id("owner/block/state"),
                capture_owner_id: id("owner/block"),
                execution_owner_ids: vec![id("owner/block")],
                future_affecting: true,
            },
            StateDomain {
                id: id("transfer/state"),
                capture_owner_id: id("owner/block"),
                execution_owner_ids: vec![id("owner/block"), id("owner/source")],
                future_affecting: true,
            },
        ],
        objects: vec![StateObject {
            id: id("block"),
            node_ids: vec![id("block")],
            future_affecting: true,
            state: ObjectState::Mutable {
                domain_id: id("owner/block/state"),
            },
        }],
        internal_dependencies: Vec::new(),
        capture_owners: Vec::new(),
        inventory_proof_ref: canonical::content_ref(b"metadata control only", "text/plain")
            .unwrap(),
    }
}

#[test]
fn model_preparation_preserves_distinct_transfer_domain() {
    let ownership = original();
    let before = ownership.clone();
    let domain = model_preparation_domain(
        &ownership,
        &id("block"),
        &id("owner/block"),
        &[id("owner/block/state"), id("transfer/state")],
    )
    .unwrap();

    assert_eq!(domain, id("owner/block/state"));
    assert_eq!(ownership, before);
}

#[test]
fn model_preparation_refuses_missing_ambiguous_or_foreign_primary_object() {
    let domain = [id("owner/block/state"), id("transfer/state")];
    let mut missing = original();
    missing.objects.clear();
    let mut duplicate = original();
    duplicate.objects.push(duplicate.objects[0].clone());
    let mut foreign = original();
    foreign.domains[0].capture_owner_id = id("owner/foreign");
    let mut participant = original();
    participant.objects[0].node_ids.push(id("source"));
    let mut outside = original();
    outside.objects[0].state = ObjectState::OutsideScope;

    for ownership in [missing, duplicate, foreign, participant, outside] {
        assert!(
            model_preparation_domain(&ownership, &id("block"), &id("owner/block"), &domain)
                .is_err()
        );
    }
    assert!(
        model_preparation_domain(
            &original(),
            &id("block"),
            &id("owner/block"),
            &[id("transfer/state")]
        )
        .is_err()
    );
}
