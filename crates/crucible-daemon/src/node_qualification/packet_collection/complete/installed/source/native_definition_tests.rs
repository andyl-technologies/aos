//! Exercises actual Source construction with declared, unselected target grammar.

use super::*;
use crate::node_qualification::packet_collection::complete::{
    records::validate_original_native_definition_data, tests::native_roundtrip,
};
use crucible_node_provider::reference_packet::service::native_startup::restoration_suffix_schema;

#[test]
fn original_five_constructs_full_suffix_grammar_without_selecting_startup_sixteen() {
    // The existing fixture measures and copies this ELF only as constructor
    // DATA. No process is launched and it is never treated as a native receipt.
    let executable = std::env::current_exe().unwrap();
    let (_code_source, declaration) = native_roundtrip::declaration(&executable);
    let selected: Manifest = serde_json::from_value(declaration).unwrap();
    let content = super::super::manifest::content(selected.content).unwrap();

    let (sources, _) = prepare_sources(
        selected.participants,
        &selected.coordinator,
        selected.maximum_native_rows,
        selected.maximum_initial_bytes,
        selected.mechanism,
        true,
        true,
        true,
        false,
        &content,
    )
    .unwrap();

    let suffix = restoration_suffix_schema().unwrap();
    for (member, source) in sources.iter().enumerate() {
        assert!(
            source
                .is_original_restoration_observation_declaration_data()
                .unwrap()
        );
        assert!(
            !source
                .is_original_restored_suffix_declaration_data()
                .unwrap()
        );
        validate_original_native_definition_data(source, &content, member).unwrap();

        let mut missing = content.clone();
        assert!(missing.remove(&suffix.definition).is_some());
        assert!(validate_original_native_definition_data(source, &missing, member,).is_err());

        let mut changed = content.clone();
        changed.insert(suffix.definition.clone(), b"changed suffix bytes".to_vec());
        assert!(validate_original_native_definition_data(source, &changed, member,).is_err());
        assert!(
            !source
                .is_original_restored_suffix_declaration_data()
                .unwrap()
        );
    }
}
