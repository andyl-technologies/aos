//! Model-only tests for shared-domain exclusion in restored original grants.

// Test panics expose lost or incorrectly reminted original grant custody.
// crucible-lint: allow panic-shortcut -- These restore tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn saved_world() -> RuntimeSnapshot {
    let (graph, _) = crate::node_admission::test_fixture_with_content();
    let owners: Vec<_> = graph
        .owners()
        .map(|owner| {
            let binding = graph.binding(&owner.owner.participant_ids[0]).unwrap();
            SavedRuntimeOwner {
                identity: OwnerIdentity {
                    owner: owner.owner.id.clone(),
                    incarnation: binding.authority.incarnation_id.clone(),
                    generation: binding.authority.owner_generation,
                },
                lifecycle: Lifecycle::Executing,
                operation: None,
                domains: vec![id("domain/shared")],
            }
        })
        .collect();
    let cut = Position::new(
        100.into(),
        0.into(),
        crucible_node_contract::Phase::BoundaryControl,
    );
    RuntimeSnapshot {
        schema_version: 1,
        source_activation: SavedRuntimeActivation {
            generation: 1.into(),
            activation_id: id("source/activation"),
            world_binding_hash: graph.world_binding_hash().clone(),
            owners: owners.iter().map(|owner| owner.identity.clone()).collect(),
            boundary: cut,
        },
        capture_cut: cut,
        capture_ordinal: 7.into(),
        owners,
        operations: vec![],
        inputs: vec![],
    }
}

#[test]
fn independent_restored_owners_cannot_hold_concurrent_grants_for_one_domain() {
    let snapshot = saved_world();
    let mut owners = BTreeMap::new();
    let mut domains = BTreeMap::new();
    reserve_saved_route(
        &snapshot,
        &[snapshot.owners[0].identity.clone()],
        &id("original/a"),
        &mut owners,
        &mut domains,
    )
    .unwrap();

    let result = reserve_saved_route(
        &snapshot,
        &[snapshot.owners[1].identity.clone()],
        &id("original/z"),
        &mut owners,
        &mut domains,
    );

    assert_eq!(result, Err(RuntimeError::OwnerBusy));
}

#[test]
fn one_original_grant_can_reserve_multiple_owners_of_the_same_domain() {
    let snapshot = saved_world();
    let mut owners = BTreeMap::new();
    let mut domains = BTreeMap::new();
    let route: Vec<_> = snapshot
        .owners
        .iter()
        .map(|owner| owner.identity.clone())
        .collect();

    reserve_saved_route(
        &snapshot,
        &route,
        &id("original/shared"),
        &mut owners,
        &mut domains,
    )
    .unwrap();

    assert_eq!(owners.len(), 2);
    assert_eq!(domains.len(), 1);
}
