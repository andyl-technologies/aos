//! Checks the actual closed decoder and the production local coordinator builder.
//!
//! The saved ordinary coordinator is an independent preexisting test oracle,
//! never an input to the production recipe or a repaired production snapshot.

use super::*;
use std::rc::Rc;

fn configuration_value() -> (impl Sized, serde_json::Value, serde_json::Value) {
    let (scene, mut value) =
        crate::node_qualification::packet_collection::complete::tests::installed_scene_declaration(
        );
    let oracle = value
        .as_object_mut()
        .unwrap()
        .remove("coordinator")
        .unwrap();
    value["schema"] = serde_json::json!(SCHEMA);
    value["mechanism"] = serde_json::json!("SourceSignedImport18");
    value["restoration"] = serde_json::json!({
        "complete_restore": "SourceSignedTransfer12",
        "restore_input_emitter": "CanonicalSdkRestoreInputs12",
        "fresh_restore_allocation": "completed_admit13",
    });
    value["initial"] = serde_json::json!({
        "activation_id": oracle["template"]["activation"]["activation_id"],
        "generation": oracle["template"]["activation"]["generation"],
        "native_prepared_tokens": oracle["participants"].as_array().unwrap().iter()
            .map(|one| one["prepared_token"].clone()).collect::<Vec<_>>(),
    });
    value["maximum_retained_outputs"] = serde_json::json!(3);
    value["maximum_coordinator_records"] = serde_json::json!(64);
    (scene, value, oracle)
}

#[test]
fn fresh_production_builder_matches_the_independent_original_coordinator() {
    let (_scene, value, oracle) = configuration_value();
    let selected = decode(value).unwrap();
    let host = HostSchedulingOwner::new_complete_original_continuation(
        selected.host.clone(),
        selected.world.identity().unwrap(),
    )
    .unwrap();
    let original = host.source();

    let coordinator = coordinator::build(&selected, &host).unwrap();

    assert_eq!(serde_json::to_value(&coordinator).unwrap(), oracle);
    assert_eq!(&coordinator.host.prepared_token, original.prepared_token());
    assert_eq!(
        coordinator.host.initial_node,
        original.initial_node_record().unwrap()
    );
    assert!(Rc::ptr_eq(&original, &host.source()));
    for participant in &coordinator.participants {
        coordinator.validate(participant).unwrap();
    }
    // This is a genuine ordinary coordinator/Host control. The older fixture
    // lacks complete7 contracts and therefore cannot certify funded activation.
    assert!(selected.materialize().is_err());
}

#[test]
fn every_missing_root_or_initial_field_refuses_without_default_repair() {
    let (_scene, value, _) = configuration_value();
    for name in value.as_object().unwrap().keys() {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(name);
        assert!(decode(missing).is_err(), "missing root field {name}");
    }
    for name in ["activation_id", "generation", "native_prepared_tokens"] {
        let mut missing = value.clone();
        missing["initial"].as_object_mut().unwrap().remove(name);
        assert!(decode(missing).is_err(), "missing initial field {name}");
    }
}

#[test]
fn snapshots_tokens_hash_repairs_and_unknown_fields_cannot_be_configuration() {
    let (_scene, value, oracle) = configuration_value();
    for name in [
        "coordinator",
        "template",
        "prepared_token",
        "ready",
        "accepted",
        "repair_hashes",
    ] {
        let mut changed = value.clone();
        changed[name] = oracle.clone();
        assert!(decode(changed).is_err(), "extra root field {name}");
        let mut changed = value.clone();
        changed["initial"][name] = oracle.clone();
        assert!(decode(changed).is_err(), "extra initial field {name}");
    }
    for name in ["prepared_token", "process", "initial_node"] {
        let mut changed = value.clone();
        changed["host"][name] = serde_json::json!("foreign");
        assert!(decode(changed).is_err());
    }
}

#[test]
fn old_installation_parsers_remain_distinct_and_configuration_requires_its_own_root() {
    let (_scene, value, _) = configuration_value();
    assert!(mechanism::authenticate_edition_data(&value).is_err());
    assert!(import18::decode_import18(value.clone()).is_err());
    for schema in [
        "crucible.complete-scene.installation/7",
        "crucible.complete-scene.installation/8",
        "crucible.complete-scene.configuration/2",
    ] {
        let mut changed = value.clone();
        changed["schema"] = serde_json::json!(schema);
        assert!(decode(changed).is_err());
    }
    let (_scene, old) =
        crate::node_qualification::packet_collection::complete::tests::installed_scene_declaration(
        );
    let original = canonical::canonical_json(&old).unwrap();
    mechanism::authenticate_edition_data(&old).unwrap();
    let _: Manifest = serde_json::from_value(old.clone()).unwrap();
    assert_eq!(canonical::canonical_json(&old).unwrap(), original);
}

#[test]
fn invalid_expected_data_and_new_profile_boundaries_refuse() {
    let (_scene, value, _) = configuration_value();
    for count in [0, 65] {
        let mut changed = value.clone();
        changed["maximum_operations"] = serde_json::json!(count);
        assert!(decode(changed).is_err());
    }
    for outputs in [0, 2, 4] {
        let mut changed = value.clone();
        changed["maximum_retained_outputs"] = serde_json::json!(outputs);
        assert!(decode(changed).is_err());
    }
    for (name, replacement) in [
        ("generation", serde_json::json!("0")),
        (
            "native_prepared_tokens",
            serde_json::json!(["bad token", "b", "c"]),
        ),
        ("native_prepared_tokens", serde_json::json!(["a", "b"])),
    ] {
        let mut changed = value.clone();
        changed["initial"][name] = replacement;
        assert!(decode(changed).is_err());
    }
    let selected = decode(value).unwrap();
    assert_eq!(selected.maximum_operations, 64);
    assert_eq!(selected.maximum_retained_outputs, 3);
}

#[test]
fn original_content_missing_drift_and_duplicates_never_receive_hash_repair() {
    let (_scene, value, _) = configuration_value();
    let mut drift = value.clone();
    drift["content"][0]["bytes"] = serde_json::json!("AA==");
    assert!(decode(drift).is_err());
    let mut duplicate = value.clone();
    let row = duplicate["content"][0].clone();
    duplicate["content"].as_array_mut().unwrap().push(row);
    assert!(decode(duplicate).is_err());

    let mut selected = decode(value).unwrap();
    let reference = selected.world.coordinator_contract_ref.clone();
    selected.content.retain(|row| row.reference != reference);
    let host = HostSchedulingOwner::new_complete_original_continuation(
        selected.host.clone(),
        selected.world.identity().unwrap(),
    )
    .unwrap();
    assert!(coordinator::build(&selected, &host).is_err());
}

#[test]
fn foreign_original_host_world_is_not_adopted_by_the_builder() {
    let (_scene, value, _) = configuration_value();
    let selected = decode(value).unwrap();
    let foreign = canonical::json_hash("cnp.test.foreign-world.v1", &selected.world).unwrap();
    assert_ne!(foreign, selected.world.identity().unwrap());
    let host =
        HostSchedulingOwner::new_complete_original_continuation(selected.host.clone(), foreign)
            .unwrap();
    assert!(coordinator::build(&selected, &host).is_err());
}

#[test]
fn actual_coordinator_contract_refuses_other_guarantees_facets_and_repeatability() {
    let (_scene, value, _) = configuration_value();
    let selected = decode(value).unwrap();
    let host = HostSchedulingOwner::new_complete_original_continuation(
        selected.host.clone(),
        selected.world.identity().unwrap(),
    )
    .unwrap();
    let original = coordinator::build(&selected, &host).unwrap();
    original.validate(&original.participants[0]).unwrap();
    assert_eq!(
        original.template["nodes"][0]["guarantees"]["repeatability"],
        serde_json::json!(Repeatability::Unqualified)
    );

    // Refuse foreign claims; never repair their references or binding hashes.
    for repeatability in [Repeatability::Qualified, Repeatability::Nondeterministic] {
        let mut changed = original.clone();
        changed.template["nodes"][0]["guarantees"]["repeatability"] =
            serde_json::json!(repeatability);
        assert!(changed.validate(&changed.participants[0]).is_err());
    }
    for repeatability in [Repeatability::Qualified, Repeatability::Unqualified] {
        let mut changed = original.clone();
        changed.template["nodes"][0]["effective_repeatability"] = serde_json::json!(repeatability);
        assert!(changed.validate(&changed.participants[0]).is_err());
        let mut changed = original.clone();
        changed.template["world_repeatability"] = serde_json::json!(repeatability);
        assert!(changed.validate(&changed.participants[0]).is_err());
    }
    let mut changed = original.clone();
    changed.template["nodes"][0]["facets"] = serde_json::json!(["exact-execution"]);
    assert!(changed.validate(&changed.participants[0]).is_err());
    original.validate(&original.participants[0]).unwrap();
}
