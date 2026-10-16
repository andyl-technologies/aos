//! Checks explicit edition separation without creating native or readiness owners.

use super::*;

fn selected() -> serde_json::Value {
    serde_json::json!({
        "complete_restore":"SourceSignedTransfer12",
        "restore_input_emitter":"CanonicalSdkRestoreInputs12",
        "fresh_restore_allocation":"completed_admit13",
    })
}

#[test]
fn full_mechanism_is_explicit_and_older_installations_cannot_be_upgraded() {
    let old = serde_json::json!({"schema":"crucible.complete-scene.installation/1"});
    assert!(authenticate_edition_data(&old).is_ok());
    for mechanism in [serde_json::Value::Null, selected()] {
        let mut changed = old.clone();
        changed["mechanism"] = mechanism;
        assert!(authenticate_edition_data(&changed).is_err());
    }
    let full = serde_json::json!({"schema":"crucible.complete-scene.installation/2","mechanism":selected()});
    assert!(authenticate_edition_data(&full).is_ok());
    let tuple: CompleteMechanism = serde_json::from_value(full["mechanism"].clone()).unwrap();
    assert!(
        authenticate_selection_data("crucible.complete-scene.installation/2", Some(tuple)).is_ok()
    );
    assert!(
        authenticate_selection_data("crucible.complete-scene.installation/1", Some(tuple)).is_err()
    );
    assert!(authenticate_selection_data("crucible.complete-scene.installation/2", None).is_err());
}

#[test]
fn incomplete_foreign_and_weaker_restore_tuples_refuse() {
    for field in [
        "complete_restore",
        "restore_input_emitter",
        "fresh_restore_allocation",
    ] {
        let mut missing = selected();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<CompleteMechanism>(missing).is_err());
    }
    let mut foreign = selected();
    foreign["accepted"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CompleteMechanism>(foreign).is_err());
    let mut weaker = selected();
    weaker["complete_restore"] = serde_json::json!("SourceSignedOwned11");
    let weaker: CompleteMechanism = serde_json::from_value(weaker).unwrap();
    assert!(weaker.authenticate().is_err());
}

#[test]
fn relabelled_preparation_package_refuses_before_namespace_or_private_birth() {
    use crate::node_qualification::packet_collection::complete::{
        installed::{InstalledCompleteScene, InstalledCompleteSceneManifest},
        tests::installed_scene_declaration,
    };
    let (_original, mut declaration) = installed_scene_declaration();
    declaration["schema"] = serde_json::json!("crucible.complete-scene.installation/2");
    declaration["mechanism"] = selected();
    let bytes = canonical::canonical_json(&declaration).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("installation.json");
    std::fs::write(&path, bytes).unwrap();
    let pin = InstalledCompleteSceneManifest::new(path, reference).unwrap();
    let scene = directory.path().join("refused-scene");

    // A full tuple cannot repair absent full immutable schema/feature rosters.
    // Existing source binders reject before namespace, receivers, entropy or
    // private birth construction; the controlled package remains unqualified.
    assert!(InstalledCompleteScene::install(pin, scene.clone()).is_err());
    assert!(!scene.exists());
}
