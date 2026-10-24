//! Checks exact original map scopes in the model-only graph projection.

// crucible-lint: allow panic-shortcut -- These model-only projection tests deliberately panic on invalid fixtures or violated original-scope invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::super::{prepare, tests::ModelPolicy};
use super::*;

#[test]
fn model_projection_keeps_all_closed_references_and_the_authenticated_selected_root() {
    let graph = crate::node_admission::test_model_graph_with_extension();
    let policy = ModelPolicy::new(&graph);
    let selected = prepare(&graph, &policy, StateLimits::default()).unwrap();
    let prior_calls = policy.calls.get();

    let projection = immutable_refs(&graph, &selected, StateLimits::default()).unwrap();
    projection.verify(&graph, StateLimits::default()).unwrap();
    let references = projection.roots();

    assert!(references.windows(2).all(|pair| pair[0] < pair[1]));
    for expected in [
        &selected.record.reference,
        &graph.world().scenario_ref,
        &graph.world().ownership_ref,
        &graph.world().coordinator_contract_ref,
        &graph.world().initialization_ref,
    ] {
        assert!(references.contains(expected));
    }
    for id in graph.node_ids() {
        let descriptor = graph.descriptor(id).unwrap();
        assert!(references.contains(&descriptor.model_ref));
        assert!(references.contains(&descriptor.configuration_ref));
        assert!(references.contains(&descriptor.initialization_ref));
        let compatibility = &graph.binding(id).unwrap().compatibility;
        assert!(references.contains(&compatibility.capabilities_ref));
        assert!(references.contains(&compatibility.guarantees_ref));
        assert!(references.contains(&compatibility.operating_contract.policy_ref));
    }
    assert_eq!(policy.calls.get(), prior_calls);
}

#[test]
fn copied_selection_cannot_project_another_world_or_changed_original_record() {
    let graph = crate::node_admission::test_model_graph_with_extension();
    let policy = ModelPolicy::new(&graph);
    let mut selected = prepare(&graph, &policy, StateLimits::default()).unwrap();
    selected.inventory.world_binding_hash.digest = "f".repeat(64);
    assert_eq!(
        immutable_refs(&graph, &selected, StateLimits::default())
            .unwrap_err()
            .code,
        StateErrorCode::NativeEvidence
    );

    let mut changed = graph.world().clone();
    changed.ordering_profile = "unqualified-ordering".to_owned();
    let collector = Collector {
        graph: &graph,
        limits: StateLimits::default(),
        references: vec![],
    };
    let failure = collector
        .check_map(
            &changed,
            &changed.extensions,
            Kind::WorldBinding,
            None,
            Path::World,
        )
        .unwrap_err();
    assert_eq!(failure.code, StateErrorCode::NativeEvidence);
    assert!(collector.references.is_empty());
}

#[test]
fn exact_record_hash_cannot_replace_its_original_typed_application_scope() {
    let graph = crate::node_admission::test_model_graph_with_extension();
    let world = graph.world();
    let collector = Collector {
        graph: &graph,
        limits: StateLimits::default(),
        references: vec![],
    };

    let failure = collector
        .check_map(
            world,
            &world.extensions,
            Kind::WorldBinding,
            None,
            Path::Node,
        )
        .unwrap_err();

    assert_eq!(failure.code, StateErrorCode::NativeEvidence);
    assert!(collector.references.is_empty());
}

#[test]
fn exhausted_projection_credits_never_issue_partial_root_inventory() {
    let graph = crate::node_admission::test_model_graph_with_extension();
    let policy = ModelPolicy::new(&graph);
    let selected = prepare(&graph, &policy, StateLimits::default()).unwrap();
    let calls = policy.calls.get();

    for limits in [
        StateLimits {
            maximum_record_bytes: 1,
            ..StateLimits::default()
        },
        StateLimits {
            maximum_content_objects: 1,
            ..StateLimits::default()
        },
        StateLimits {
            maximum_content_objects: usize::MAX,
            ..StateLimits::default()
        },
    ] {
        assert_eq!(
            immutable_refs(&graph, &selected, limits).unwrap_err().code,
            StateErrorCode::ResourceLimit
        );
    }
    assert_eq!(policy.calls.get(), calls);
}

#[test]
fn retained_projection_cannot_cross_worlds_or_bypass_a_smaller_record_ceiling() {
    let graph = crate::node_admission::test_model_graph_with_extension();
    let policy = ModelPolicy::new(&graph);
    let selected = prepare(&graph, &policy, StateLimits::default()).unwrap();
    let projection = immutable_refs(&graph, &selected, StateLimits::default()).unwrap();
    let (plain, _) = crate::node_admission::test_fixture_with_content();

    assert_eq!(
        projection
            .verify(&plain, StateLimits::default())
            .unwrap_err()
            .code,
        StateErrorCode::NativeEvidence
    );
    assert_eq!(
        projection
            .verify(
                &graph,
                StateLimits {
                    maximum_record_bytes: 1,
                    ..StateLimits::default()
                }
            )
            .unwrap_err()
            .code,
        StateErrorCode::ResourceLimit
    );
    projection.verify(&graph, StateLimits::default()).unwrap();
}
