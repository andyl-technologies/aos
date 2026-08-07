//! Executable entry point for the isolated retained-control contracts.

#[path = "../src/retained_control/classifier.rs"]
mod classifier;
#[path = "../src/retained_control/primitives.rs"]
mod primitives;

use std::collections::BTreeSet;

use classifier::{
    api_methods_from_generated_descriptors, validate_complete_method_manifest,
    ForbiddenSymbolCategory, ForbiddenSymbolFixture, GeneratedApiDescriptorArtifact,
    MethodDescriptor,
};

#[test]
fn retained_method_classifier_fixture_is_structurally_valid() {
    let methods: Vec<MethodDescriptor> = serde_json::from_str(include_str!(
        "fixtures/retained-control-method-classification-v1.json"
    ))
    .unwrap();
    let descriptor: GeneratedApiDescriptorArtifact = serde_json::from_str(include_str!(
        "../../../docs/rfcs/0012-hub-surface-topology/hub-api-manifest-v1.json"
    ))
    .unwrap();
    let generated =
        api_methods_from_generated_descriptors(aos_proto_types::EXPECTED_CONNECT_METHODS).unwrap();
    let mut checked = descriptor
        .api_methods()
        .unwrap()
        .iter()
        .map(|method| {
            (
                &method.service,
                &method.method,
                &method.request,
                &method.response,
            )
        })
        .collect::<Vec<_>>();
    checked.sort();
    let mut generated_metadata = generated
        .iter()
        .map(|method| {
            (
                &method.service,
                &method.method,
                &method.request,
                &method.response,
            )
        })
        .collect::<Vec<_>>();
    generated_metadata.sort();
    assert_eq!(checked, generated_metadata);
    let violations = validate_complete_method_manifest(&methods, &generated);
    assert!(violations.is_empty(), "{violations:#?}");
}

#[test]
fn hard_cut_fixture_is_valid_and_covers_every_surface_category() {
    let fixture: ForbiddenSymbolFixture = serde_json::from_str(include_str!(
        "fixtures/retained-control-forbidden-symbols-v1.json"
    ))
    .unwrap();
    fixture.validate().unwrap();

    let categories = fixture
        .symbols
        .iter()
        .map(|entry| entry.category)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        categories,
        BTreeSet::from([
            ForbiddenSymbolCategory::Api,
            ForbiddenSymbolCategory::Cli,
            ForbiddenSymbolCategory::Web,
            ForbiddenSymbolCategory::Schema,
            ForbiddenSymbolCategory::Code,
        ])
    );
}

#[test]
fn hard_cut_fixture_scans_the_complete_production_source_universe() {
    let fixture: ForbiddenSymbolFixture = serde_json::from_str(include_str!(
        "fixtures/retained-control-forbidden-symbols-v1.json"
    ))
    .unwrap();
    let repository_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap();
    let matches = fixture.scan_repository_root(repository_root).unwrap();
    assert!(
        matches.is_empty(),
        "forbidden hard-cut symbols remain: {matches:#?}"
    );
}
