//! Exercises closed kind separation, bounded evidence and complete retained backing.

use super::*;
use serde_json::{Value, json};

fn reference(name: &str) -> ContentRef {
    canonical::content_ref(name.as_bytes(), "application/json").unwrap()
}

fn pair(name: &str) -> Value {
    json!({
        "original": reference(&format!("{name}-original")),
        "terminal": reference(&format!("{name}-terminal")),
    })
}

fn fixture(kind: &str) -> Value {
    let mut value = json!({
        "kind": kind,
        "schema": NATIVE_IMPORT18_RESTORED_RECORD_SCHEMA,
        "scope": {
            "target": {
                "native_pid": "1", "session": "actual-session",
                "incarnation": "actual-incarnation", "node": "actual-node",
                "owner": "actual-owner", "owner_generation": "1",
                "binding_hash": canonical::hash("cnp.owner-binding.v1", b"owner").unwrap(),
                "world": canonical::hash("cnp.world-binding.v1", b"world").unwrap(),
                "activation": "actual-activation", "generation": "1",
                "prepared_token": "actual-token", "gate": "actual-gate",
                "admission": "actual-admission", "transaction": "actual-transaction",
            },
            "source_birth": reference("SourceBinding18"),
            "bootstrap": pair("bootstrap"),
            "recipe_identity": Bytes::new(vec![3; 32]),
            "import_binding": reference("binding18"),
            "inputs": PacketNativeImport18InputRole::ALL.map(|role| {
                let name = format!("input-{}", role.ordinal_data());
                let media = if role == PacketNativeImport18InputRole::SemanticSpend {
                    PacketNativeImport18SemanticSpendFamily::Complete18.media_type_data()
                } else {
                    "application/json"
                };
                canonical::content_ref(name.as_bytes(), media).unwrap()
            }),
            "prepare": pair("prepare"),
        },
        "physical_gate_held": kind == "commit_held",
    });
    if kind == "commit_held" {
        value["commit"] = json!(reference("commit-original"));
        value["context_digest"] = json!(Bytes::new(vec![5; 32]));
        value["local_cursor"] = json!({"time_ps":"7", "microstep":"2", "phase":3});
        value["inventory_hash"] = json!(canonical::hash("inventory", b"literal-model").unwrap());
    } else {
        value["commit"] = pair("commit");
        value["arm"] = pair("arm");
        value["world"] = pair("world");
        value["observe"] = json!(reference("first-observe-original"));
        value["native_record"] = json!(reference("unchanged-native-proof"));
    }
    value
}

fn typed(value: Value) -> PacketNativeImport18RestoredRecordData {
    serde_json::from_value(value).unwrap()
}

#[test]
fn both_complete_kinds_round_trip_and_require_the_exact_independent_body_limit() {
    for kind in ["commit_held", "first_observed"] {
        let record = typed(fixture(kind));
        let body = serde_json::to_vec(&record).unwrap();

        record.validate_data(body.len()).unwrap();
        assert!(record.validate_data(body.len() - 1).is_err());
        assert_eq!(
            serde_json::from_slice::<PacketNativeImport18RestoredRecordData>(&body).unwrap(),
            record
        );
    }
}

#[test]
fn closed_shapes_refuse_missing_extra_cross_kind_and_carrying_response_fields() {
    for kind in ["commit_held", "first_observed"] {
        let original = fixture(kind);
        for key in original.as_object().unwrap().keys() {
            let mut missing = original.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(
                serde_json::from_value::<PacketNativeImport18RestoredRecordData>(missing).is_err(),
                "{kind}: {key}"
            );
        }
        for extra in ["response", "restore_response", "assigned_response", "other"] {
            let mut changed = original.clone();
            changed[extra] = json!(reference("own-response-cycle"));
            assert!(
                serde_json::from_value::<PacketNativeImport18RestoredRecordData>(changed).is_err()
            );
        }
        let mut changed = original;
        changed["kind"] = json!(if kind == "commit_held" {
            "first_observed"
        } else {
            "commit_held"
        });
        assert!(serde_json::from_value::<PacketNativeImport18RestoredRecordData>(changed).is_err());
    }
}

#[test]
fn nested_scope_target_pairs_and_seven_bank_rosters_are_closed() {
    for kind in ["commit_held", "first_observed"] {
        for path in [
            vec!["scope"],
            vec!["scope", "target"],
            vec!["scope", "prepare"],
            vec!["scope", "bootstrap"],
        ] {
            let mut value = fixture(kind);
            let mut object = &mut value;
            for key in path {
                object = &mut object[key];
            }
            object["foreign"] = json!(true);
            assert!(
                serde_json::from_value::<PacketNativeImport18RestoredRecordData>(value).is_err()
            );
        }
        for count in [6, 8] {
            let mut value = fixture(kind);
            value["scope"]["inputs"] = json!(vec![reference("input"); count]);
            assert!(
                serde_json::from_value::<PacketNativeImport18RestoredRecordData>(value).is_err()
            );
        }
    }
}

#[test]
fn old_editions_changed_physical_reports_and_invalid_scope_data_refuse() {
    for kind in ["commit_held", "first_observed"] {
        let original = fixture(kind);
        for edition in [5, 12, 13, 17] {
            let mut changed = original.clone();
            changed["schema"] = json!(format!("source-owned.packet-restored-native/{edition}"));
            assert!(typed(changed).validate_data(usize::MAX).is_err());
        }
        for (path, replacement) in [
            (vec!["physical_gate_held"], json!(kind != "commit_held")),
            (
                vec!["scope", "recipe_identity"],
                json!(Bytes::new(vec![3; 31])),
            ),
            (vec!["scope", "target", "native_pid"], json!("0")),
            (
                vec!["scope", "target", "native_pid"],
                json!((i32::MAX as u64 + 1).to_string()),
            ),
            (vec!["scope", "target", "generation"], json!("0")),
            (vec!["scope", "target", "owner_generation"], json!("0")),
            (
                vec!["scope", "source_birth", "media_type"],
                json!("application/cbor"),
            ),
            (vec!["scope", "import_binding", "length"], json!("0")),
            (
                vec!["scope", "prepare", "terminal"],
                original["scope"]["prepare"]["original"].clone(),
            ),
            (
                vec!["scope", "bootstrap", "terminal"],
                original["scope"]["bootstrap"]["original"].clone(),
            ),
        ] {
            let mut changed = original.clone();
            let mut field = &mut changed;
            for key in path {
                field = &mut field[key];
            }
            *field = replacement;
            assert!(typed(changed).validate_data(usize::MAX).is_err());
        }
    }
}

#[test]
fn complete_retained_walk_counts_capacity_even_when_the_record_is_invalid() {
    use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
    let backing = |record: &PacketNativeImport18RestoredRecordData| {
        let mut observer = MetadataObserver::new();
        observer.observe(record).unwrap();
        requested_metadata_backing_storage_data(&observer.finish()).unwrap()
    };

    for kind in ["commit_held", "first_observed"] {
        let mut record = typed(fixture(kind));
        let before = backing(&record);
        let (scope, physical) = match &mut record {
            PacketNativeImport18RestoredRecordData::CommitHeld(record) => {
                (&mut record.scope, &mut record.physical_gate_held)
            }
            PacketNativeImport18RestoredRecordData::FirstObserved(record) => {
                (&mut record.scope, &mut record.physical_gate_held)
            }
        };
        let prior_capacity = scope.source_birth.media_type.capacity();
        scope.source_birth.media_type.reserve(513);
        let delta = scope.source_birth.media_type.capacity() - prior_capacity;
        *physical = !*physical;

        assert!(record.validate_data(usize::MAX).is_err());
        assert_eq!(backing(&record), before + delta);
    }
}

#[test]
fn input_roster_compares_all_seven_complete_references_in_their_actual_order() {
    let mut binding = super::super::tests::fixture();
    let mut prepare = super::super::super::transfer::prepare_fixture_data();
    prepare.native_protocol = reference("native-after");
    prepare.native_control = reference("native-Control");
    prepare.native_anchor = reference("native-anchor");
    prepare.restoration.owner_state = reference("native-Snapshot");
    prepare.restoration.journal = reference("native-Journal");
    binding.normalization = reference("normalization18");
    binding.semantic_spend = canonical::content_ref(
        b"semantic-spend18",
        binding.semantic_spend_family.media_type_data(),
    )
    .unwrap();

    let mut scope: PacketNativeImport18RecordScopeData =
        serde_json::from_value(fixture("commit_held")["scope"].clone()).unwrap();
    scope.inputs = PacketNativeImport18InputRole::ALL
        .map(|role| role.reference_data(&prepare, &binding).clone());
    scope
        .authenticate_input_roster_data(&prepare, &binding)
        .unwrap();

    for role in PacketNativeImport18InputRole::ALL {
        let mut changed = scope.clone();
        let input = &mut changed.inputs[role.ordinal_data()];
        input.length = U64::new(input.length.get() + 1);
        assert!(
            changed
                .authenticate_input_roster_data(&prepare, &binding)
                .is_err()
        );
    }
    let mut swapped = scope;
    swapped.inputs.swap(0, 1);
    assert!(
        swapped
            .authenticate_input_roster_data(&prepare, &binding)
            .is_err()
    );
}

#[test]
fn compiled_definition_matches_both_actual_serialized_field_rosters() {
    use std::collections::BTreeSet;
    let contract: Value =
        serde_json::from_slice(&native_import18_restored_record_contract_data().unwrap()).unwrap();
    let keys = |value: &Value| -> BTreeSet<String> {
        value.as_object().unwrap().keys().cloned().collect()
    };
    let declared = |key: &str| -> BTreeSet<String> {
        contract[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap().to_owned())
            .collect()
    };

    for (kind, fields) in [
        ("commit_held", "commit_held_fields"),
        ("first_observed", "first_observed_fields"),
    ] {
        let record = typed(fixture(kind));
        let value = serde_json::to_value(record).unwrap();

        assert_eq!(keys(&value), declared(fields));
        assert_eq!(keys(&value["scope"]), declared("scope"));
        assert_eq!(keys(&value["scope"]["target"]), declared("target"));
        assert_eq!(
            keys(&value["scope"]["bootstrap"]),
            declared("completed_pair")
        );
        assert_eq!(keys(&value["scope"]["prepare"]), declared("completed_pair"));
    }
}
