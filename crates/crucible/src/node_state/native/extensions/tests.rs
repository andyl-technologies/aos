//! Exercises semantic data closure with explicit model-only policy authentication.
//!
//! No test issues native capture, source archive, backend qualification, or live
//! execution authority. Native acceptance requires separately enrolled profiles.

// crucible-lint: allow panic-shortcut -- These model-only semantic tests deliberately panic on invalid fixture data or violated closure invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::Cell;
use std::collections::BTreeMap;

use crucible_node_contract::{ContentRef, ExtensionDeclaration, HashRef, canonical};

use crate::node_admission::AdmittedGraph;
use crate::node_state::{StateError, StateErrorCode, StateLimits};

use super::*;

pub(super) struct ModelPolicy {
    identity: HashRef,
    policy: (ContentRef, Vec<u8>),
    rows: BTreeMap<ContentRef, Vec<ContentRef>>,
    pub(super) calls: Cell<usize>,
}

impl ModelPolicy {
    pub(super) fn new(graph: &AdmittedGraph) -> Self {
        let selected = graph.selected_extensions();
        let bytes =
            b"explicit model-only native preservation/dependency codec; no native qualification"
                .to_vec();
        let policy = (canonical::content_ref(&bytes, "text/plain").unwrap(), bytes);
        let mut rows: BTreeMap<_, _> = selected
            .objects()
            .map(|(reference, _)| (reference.clone(), vec![]))
            .collect();
        for application in selected.applications() {
            let reference = &application.selected().selection.declaration;
            let bytes = selected
                .objects()
                .find(|(candidate, _)| *candidate == reference)
                .unwrap()
                .1;
            let declaration: ExtensionDeclaration = canonical::decode(bytes, 8192).unwrap();
            assert_eq!(
                declaration.identifier.as_str(),
                "model/whole-graph-metadata"
            );
            assert!(declaration.dependencies.is_empty());
            let mut dependencies = vec![
                declaration.owner.publication_origin,
                declaration.schema.definition,
                declaration.specification,
                declaration.timing_effects,
                declaration.state_effects,
                declaration.error_behavior,
                declaration.conformance,
            ];
            dependencies.sort();
            dependencies.dedup();
            rows.insert(reference.clone(), dependencies);

            let body =
                canonical::canonical_json(&serde_json::to_value(application).unwrap()).unwrap();
            let reference = canonical::content_ref(&body, "application/json").unwrap();
            let mut dependencies = vec![
                application.selected().selection.declaration.clone(),
                application.handler_identity().clone(),
            ];
            dependencies.extend(semantic_dependencies(application.semantic_contract()));
            dependencies.sort();
            dependencies.dedup();
            rows.insert(reference, dependencies);
        }
        for definition in selected.definitions() {
            let bytes =
                canonical::canonical_json(&serde_json::to_value(definition).unwrap()).unwrap();
            let reference = canonical::content_ref(&bytes, "application/json").unwrap();
            let mut dependencies = vec![
                definition.selection().declaration.clone(),
                definition.handler_identity().clone(),
            ];
            dependencies.extend(semantic_dependencies(definition.semantic_contract()));
            dependencies.sort();
            dependencies.dedup();
            rows.insert(reference, dependencies);
        }
        rows.insert(policy.0.clone(), vec![]);
        Self {
            identity: selected.identity().unwrap(),
            policy,
            rows,
            calls: Cell::new(0),
        }
    }
}

fn semantic_dependencies(
    contract: &crate::node_admission::ExtensionSemanticContract,
) -> Vec<ContentRef> {
    vec![
        contract.class_contract.clone(),
        contract.facet_contract.clone(),
        contract.mode_contract.clone(),
        contract.port_contract.clone(),
        contract.timing_contract.clone(),
        contract.state_contract.clone(),
        contract.error_contract.clone(),
        contract.qualification_contract.clone(),
    ]
}

impl NativeExtensionPreservationPolicy for ModelPolicy {
    fn authenticate_selection(&self, graph: &AdmittedGraph) -> Result<(), StateError> {
        self.calls.set(self.calls.get() + 1);
        if graph.selected_extensions().identity().map_err(|error| {
            StateError::new(StateErrorCode::Content, "model policy", error.to_string())
        })? != self.identity
        {
            return Err(StateError::new(
                StateErrorCode::NativeEvidence,
                "model policy",
                "selected source semantics differ",
            ));
        }
        Ok(())
    }

    fn policy(&self, maximum: usize) -> Result<(ContentRef, Vec<u8>), StateError> {
        self.calls.set(self.calls.get() + 1);
        if self.policy.1.len() > maximum {
            return Err(StateError::new(
                StateErrorCode::ResourceLimit,
                "model policy",
                "policy credit exhausted",
            ));
        }
        Ok(self.policy.clone())
    }

    fn dependencies(
        &self,
        _: &AdmittedGraph,
        reference: &ContentRef,
        _: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        self.calls.set(self.calls.get() + 1);
        let row = self.rows.get(reference).ok_or_else(|| {
            StateError::new(
                StateErrorCode::NativeEvidence,
                "model policy",
                "unknown source codec row",
            )
        })?;
        if row.len() > maximum {
            return Err(StateError::new(
                StateErrorCode::ResourceLimit,
                "model policy",
                "dependency credit exhausted",
            ));
        }
        Ok(row.clone())
    }
}

#[test]
fn model_selected_closure_retains_exact_scopes_handlers_bodies_and_dependency_rows() {
    let graph = crate::node_admission::test_model_graph_with_extension();
    let policy = ModelPolicy::new(&graph);
    let prepared = prepare(&graph, &policy, StateLimits::default()).unwrap();

    assert_eq!(
        prepared.inventory.selection_identity,
        graph.selected_extensions().identity().unwrap()
    );
    assert_eq!(
        prepared.inventory.world_binding_hash,
        *graph.world_binding_hash()
    );
    assert_eq!(
        prepared.inventory.dependencies.len(),
        prepared.objects.len()
    );
    for object in &prepared.objects {
        object.reference.verify(&object.bytes).unwrap();
        let row = prepared
            .inventory
            .dependencies
            .iter()
            .find(|row| row.reference == object.reference)
            .unwrap();
        assert_eq!(row.dependencies, policy.rows[&object.reference]);
    }
    assert_eq!(policy.calls.get(), prepared.objects.len() + 2);
}

#[test]
fn exhausted_object_credit_and_unsupported_ceilings_refuse_before_policy_callbacks() {
    let graph = crate::node_admission::test_model_graph_with_extension();
    for limits in [
        StateLimits {
            maximum_content_objects: 1,
            ..StateLimits::default()
        },
        StateLimits {
            maximum_total_content_bytes: 1,
            ..StateLimits::default()
        },
        StateLimits {
            maximum_dependency_depth: usize::MAX,
            ..StateLimits::default()
        },
        StateLimits {
            maximum_dependency_depth: 0,
            ..StateLimits::default()
        },
    ] {
        let policy = ModelPolicy::new(&graph);
        let failure = prepare(&graph, &policy, limits).err().unwrap();
        assert_eq!(failure.code, StateErrorCode::ResourceLimit);
        assert_eq!(policy.calls.get(), 0);
    }
}

#[test]
fn missing_rows_are_not_inferred_as_self_contained_leaves() {
    let graph = crate::node_admission::test_model_graph_with_extension();
    let mut policy = ModelPolicy::new(&graph);
    policy.rows.remove(
        &graph
            .selected_extensions()
            .objects()
            .next()
            .unwrap()
            .0
            .clone(),
    );

    let failure = prepare(&graph, &policy, StateLimits::default())
        .err()
        .unwrap();
    assert_eq!(failure.code, StateErrorCode::NativeEvidence);
    assert!(failure.reason.contains("unknown source codec row"));
}

#[test]
fn foreign_dependency_and_cycle_refuse_the_whole_prepared_closure() {
    let graph = crate::node_admission::test_model_graph_with_extension();
    let key = graph
        .selected_extensions()
        .objects()
        .next()
        .unwrap()
        .0
        .clone();
    for dependency in [
        canonical::content_ref(b"outside original selected scope", "text/plain").unwrap(),
        key.clone(),
    ] {
        let mut policy = ModelPolicy::new(&graph);
        policy.rows.insert(key.clone(), vec![dependency]);

        let failure = prepare(&graph, &policy, StateLimits::default())
            .err()
            .unwrap();
        assert_eq!(failure.code, StateErrorCode::NativeEvidence);
    }
}

#[test]
fn undeclared_typed_alias_cannot_replace_an_original_codec_dependency() {
    let graph = crate::node_admission::test_model_graph_with_extension();
    let mut policy = ModelPolicy::new(&graph);
    let (owner, original) = policy
        .rows
        .iter()
        .find_map(|(owner, dependencies)| {
            dependencies
                .first()
                .map(|dependency| (owner.clone(), dependency.clone()))
        })
        .unwrap();

    // Equal octet commitments do not enroll a new typed role. The installed
    // original codec must name the independently admitted complete reference.
    let mut undeclared = original.clone();
    undeclared.media_type = "application/x-undeclared-extension-role".to_owned();
    assert_eq!(undeclared.hash, original.hash);
    assert!(!policy.rows.contains_key(&undeclared));
    policy.rows.insert(owner, vec![undeclared]);

    let failure = prepare(&graph, &policy, StateLimits::default())
        .err()
        .unwrap();
    assert_eq!(failure.code, StateErrorCode::NativeEvidence);
    assert!(failure.reason.contains("outside exact retained selection"));
}

#[test]
fn valid_shared_dependency_depth_is_checked_without_replacing_original_rows() {
    let graph = crate::node_admission::test_model_graph_with_extension();
    let policy = ModelPolicy::new(&graph);
    let failure = prepare(
        &graph,
        &policy,
        StateLimits {
            maximum_dependency_depth: 2,
            ..StateLimits::default()
        },
    )
    .err()
    .unwrap();
    assert_eq!(failure.code, StateErrorCode::NativeEvidence);

    let prepared = prepare(
        &graph,
        &policy,
        StateLimits {
            maximum_dependency_depth: 3,
            ..StateLimits::default()
        },
    )
    .unwrap();
    assert_eq!(prepared.inventory.dependencies.len(), policy.rows.len());
}

#[test]
fn larger_installation_allowance_does_not_expand_selected_semantic_codec() {
    let graph = crate::node_admission::test_model_graph_with_extension();
    let policy = ModelPolicy::new(&graph);
    let ordinary = prepare(&graph, &policy, StateLimits::default()).unwrap();
    let expanded = prepare(
        &graph,
        &policy,
        StateLimits {
            maximum_content_bytes: 128 * 1024 * 1024,
            ..StateLimits::default()
        },
    )
    .unwrap();
    assert_eq!(ordinary.record.reference, expanded.record.reference);
    assert_eq!(ordinary.record.bytes, expanded.record.bytes);
    assert_eq!(ordinary.objects, expanded.objects);
}
