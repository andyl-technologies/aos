//! Installed registry projection controls use explicit model-only namespace authority.

use super::*;
use crucible_node_provider::handshake::{
    ExtensionOfferV1, InstalledExtensionNegotiationVerifier, select_installed_extensions,
};

#[test]
fn authenticated_registry_projection_retains_exact_handler_without_qualification() {
    let mut source = ModelInstallation::default();
    let registration = source.registration("model/peer-contract", false);
    let selection = registration.selection.clone();
    let identity = registration.handler.identity().clone();
    let registry = Rc::new(install(vec![registration], &source).unwrap());
    let peer = InstalledExtensionPeerPolicy::new(
        registry,
        std::slice::from_ref(&selection),
        std::slice::from_ref(&selection),
    )
    .unwrap();

    let offer = ExtensionOfferV1 {
        format: U64::new(1),
        required: vec![selection.clone()],
        optional: vec![],
    };
    let selected = select_installed_extensions(&offer, &peer, &vec![]).unwrap();

    assert_eq!(selected.selected, vec![selection.clone()]);
    assert_eq!(peer.contract(&selection).unwrap().1, &identity);
    assert_eq!(source.callbacks.get(), 0);
}

#[test]
fn tuple_substitution_or_foreign_namespace_cannot_project_registry_authority() {
    let mut source = ModelInstallation::default();
    let registration = source.registration("model/peer-contract", false);
    let selection = registration.selection.clone();
    let registry = Rc::new(install(vec![registration], &source).unwrap());
    for field in ["version", "schema", "declaration", "identifier"] {
        let mut changed = selection.clone();
        match field {
            "version" => changed.semantic_version.patch = U64::new(1),
            "schema" => changed.schema_digest.digest = "0".repeat(64),
            "identifier" => changed.identifier = id("foreign/peer-contract"),
            _ => changed.declaration.length = U64::new(1),
        }
        assert!(InstalledExtensionPeerPolicy::new(Rc::clone(&registry), &[changed], &[]).is_err());
    }
    assert_eq!(source.callbacks.get(), 0);
}

#[test]
fn installed_dependency_and_feature_omission_refuse_without_semantic_effects() {
    let mut source = ModelInstallation::default();
    let first = source.registration("model/a", false);
    let first_selection = first.selection.clone();
    let mut second = source.registration("model/b", false);
    let mut declaration = source.declaration(&second.selection);
    declaration.dependencies = vec![ExtensionDependency::Extension {
        selection: first_selection.clone(),
    }];
    declaration.required_features = vec![id("cnp.control-evidence/1")];
    second.selection = source.selection(&declaration);
    let second_selection = second.selection.clone();
    let registry = Rc::new(install(vec![first, second], &source).unwrap());
    let peer = InstalledExtensionPeerPolicy::new(
        registry,
        &[first_selection.clone(), second_selection.clone()],
        std::slice::from_ref(&second_selection),
    )
    .unwrap();

    assert!(
        peer.verify_selection(
            std::slice::from_ref(&second_selection),
            &vec![id("cnp.control-evidence/1")]
        )
        .is_err()
    );
    assert!(
        peer.verify_selection(
            &[first_selection.clone(), second_selection.clone()],
            &vec![]
        )
        .is_err()
    );
    assert!(
        peer.verify_selection(
            &[first_selection, second_selection],
            &vec![id("cnp.control-evidence/1")]
        )
        .is_ok()
    );
    assert_eq!(source.callbacks.get(), 0);
}

#[test]
fn original_admitted_set_projects_its_frozen_exact_definitions() {
    let graph = model_graph_with_extension();
    let mut source = ModelInstallation::default();
    let registration = source.registration("model/whole-graph-metadata", false);
    let registry = Rc::new(install(vec![registration], &source).unwrap());

    let policy =
        InstalledExtensionPeerPolicy::from_admitted_set(registry, graph.selected_extensions())
            .unwrap();

    let expected: Vec<_> = graph
        .selected_extensions()
        .definitions()
        .map(|definition| definition.selection().clone())
        .collect();
    assert_eq!(policy.supported(), expected);
    assert_eq!(policy.required(), expected);
    assert_eq!(source.callbacks.get(), 0);
}
