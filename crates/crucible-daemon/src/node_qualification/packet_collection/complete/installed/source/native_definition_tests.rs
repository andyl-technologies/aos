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

#[test]
fn full_invocation_fresh_report_quote_preserves_sixty_four_kib_query_limits() {
    use crucible_node_provider::reference_packet::service::report_startup::{
        PacketNativeReportStartupPurpose, original_invocation_report_startup_storage_data,
    };

    let executable = std::env::current_exe().unwrap();
    let (_code_source, declaration) = native_roundtrip::declaration(&executable);
    let selected: Manifest = serde_json::from_value(declaration).unwrap();
    let measurements = selected.measurements.map(|one| PacketFixtureMeasurements {
        peer: artifact(one.peer),
        host: one.host,
        sources: one.sources.into_iter().map(artifact).collect(),
    });
    let content = super::super::manifest::content(selected.content).unwrap();
    let (_sources, declarations) = prepare_sources(
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
    let initial_bytes = encoded(&selected.coordinator).unwrap();
    let initial = InstalledContent {
        reference: canonical::content_ref(&initial_bytes, "application/json").unwrap(),
        bytes: Bytes::new(initial_bytes),
    };
    let directory = tempfile::tempdir().unwrap();
    let paths =
        std::array::from_fn(|member| directory.path().join(format!("effect-{member}.sock")));
    let launches = launch_declarations(
        declarations,
        &selected.coordinator,
        &initial,
        &measurements,
        &paths,
    )
    .unwrap();

    // These are the actual same Source-selected full32-format launch records
    // from the installed regression. No native process or receipt is created.
    for mut launch in launches {
        assert_eq!(launch.limits.frame_bytes.get(), 65_536);
        let data = original_invocation_report_startup_storage_data(
            &launch,
            PacketNativeReportStartupPurpose::FreshCompletedAdmit13,
        )
        .unwrap();
        assert_eq!(data.raw_report_capacity(), 16_384);
        assert!(data.retained_growth_bytes() > 0);
        assert!(data.maximum_simultaneous_transient_bytes() > 0);

        launch.limits.frame_bytes = U64::new(0);
        assert!(
            original_invocation_report_startup_storage_data(
                &launch,
                PacketNativeReportStartupPurpose::FreshCompletedAdmit13,
            )
            .is_err()
        );
    }
}
