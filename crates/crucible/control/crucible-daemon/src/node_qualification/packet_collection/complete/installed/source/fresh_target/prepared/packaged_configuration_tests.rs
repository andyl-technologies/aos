//! Exercises real code installation from a fresh independently measured configuration.
//!
//! The fixture producer measures this actual test ELF before creating any World
//! identity. The code-only route creates no isolated template, worker, archive
//! ticket, native child or Ready witness and installs no deployment reservation.

use super::*;
use crate::node_qualification::packet_collection::complete::installed::manifest::{
    FundedSelection, load_funded,
};
use crate::node_qualification::{CompleteSceneFixtureInputs, write_complete_scene_fixture};
use crucible_engine::node_admission::AdmissionEvidence;
use std::os::unix::fs::PermissionsExt;

#[test]
#[ignore = "requires CRUCIBLE_FUNDED_SOURCE_FIXTURES pointing to built portable fixtures"]
fn fresh_packaged_configuration_installs_original_code_authority_and_plan() {
    let artifact = PathBuf::from(
        std::env::var_os("CRUCIBLE_FUNDED_SOURCE_FIXTURES").expect("explicit fixture artifact"),
    );
    let mut inputs: serde_json::Value =
        serde_json::from_slice(&std::fs::read(artifact.join("support-inputs.json")).unwrap())
            .unwrap();
    // These are new operator inputs to the real producer, never repairs to a
    // pinned configuration, World hash, coordinator or Host prepared token.
    inputs["host_executable"] = serde_json::json!(std::env::current_exe().unwrap());
    let inputs: CompleteSceneFixtureInputs = serde_json::from_value(inputs).unwrap();
    let parent = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let fixture = parent.path().join("configuration");
    write_complete_scene_fixture(inputs, &fixture).unwrap();
    let path = fixture.join("configuration.json");
    let bytes = std::fs::read(&path).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    let pin = InstalledCompleteSceneManifest::new(path, reference).unwrap();
    let FundedSelection::Configuration(configuration) = load_funded(&pin).unwrap() else {
        panic!("expected the fresh closed configuration");
    };
    let (selected, host, _) = configuration.materialize().unwrap();
    // The real test ELF includes the complete test harness and exceeds the
    // production cold-archive default. Fund these explicit code-only fetches
    // from the fresh fixture's actual measured files and declared content cap.
    let mut limits = NativeArchiveLimits::default();
    limits.state.maximum_content_bytes = selected.measurements.iter().fold(
        limits.state.maximum_content_bytes,
        |maximum, measurement| {
            maximum
                .max(usize::try_from(measurement.host.length.get()).unwrap())
                .max(usize::try_from(measurement.peer.content.length.get()).unwrap())
        },
    );
    limits.state.maximum_total_content_bytes =
        usize::try_from(selected.resources.content_bytes.get()).unwrap();
    let mut output = None;

    PreparedCompleteRestoration::prepare_with_code_host_into(
        selected,
        None,
        None,
        Some((host, pin)),
        parent.path().join("code"),
        limits,
        &mut output,
    )
    .unwrap();

    let prepared = output.as_ref().unwrap();
    assert!(prepared.code_graph.is_some());
    assert!(prepared.code_owners.is_some());
    assert!(prepared.import18_selection.is_none());
    assert!(!prepared.prebirth_attempted);
    assert!(!prepared.installation_attempted);

    let authority = prepared.code_authority.as_ref();
    let fixture_ref = &authority.witness_plan().unit.fixtures;
    let bytes = authority.content(fixture_ref, 1024 * 1024).unwrap();
    fixture_ref.verify(&bytes).unwrap();
    let document = canonical::parse_json(&bytes, 1024 * 1024).unwrap();
    assert_eq!(
        document["schema"],
        "crucible.complete-scene.qualification-fixtures/1"
    );
    let coordinator: ContentRef = serde_json::from_value(document["coordinator"].clone()).unwrap();
    let body = authority.content(&coordinator, 1024 * 1024).unwrap();
    coordinator.verify(&body).unwrap();
    assert_eq!(body, encoded(&prepared.selected.coordinator).unwrap());

    let launches: [ContentRef; 3] = serde_json::from_value(document["launches"].clone()).unwrap();
    for (reference, original) in launches.iter().zip(prepared.launches.originals().unwrap()) {
        let body = authority.content(reference, 1024 * 1024).unwrap();
        reference.verify(&body).unwrap();
        assert_eq!(body, encoded(original).unwrap());
    }
}
