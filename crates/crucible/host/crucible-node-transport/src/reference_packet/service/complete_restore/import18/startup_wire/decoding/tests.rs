//! Exercises real inert body decoders without creating opaque Initial or Recipe.

use super::*;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use serde_json::json;

fn recipe() -> Value {
    json!({
        "schema": NATIVE_IMPORT18_PREBIRTH_RECIPE_SCHEMA,
        "native_family": "snapshot17",
        "source_family": "captured17",
        "semantic_spend_family": "complete18",
        "geometry_identity": ([0u8; 32]),
        "historical_shape_identity": ([0u8; 32]),
        "selected_launch_identity": ([0u8; 32]),
        "private_launch_identity": ([0u8; 32]),
        "lease_identity": ([0u8; 32]),
        "nonce": ([0u8; 32]),
        "generation": "1",
        "archived_reference_identities": ([[0u8; 32]; 5]),
        "archived_lengths": (["1"; 5]),
        "semantic_reference_identity": ([0u8; 32]),
        "semantic_length": "1",
        "decoder_limits": (["1"; 10]),
        "maximum_target_requested_bytes": "1",
        "maximum_before_bytes": "1",
        "normalization_projection_bytes": "1",
        "normalization_maximum": "1",
        "semantic_spend_maximum": "1",
        "escrow": (["1"; 3]),
        "phases": ([["1"; 3]; 5]),
        "identity": ([0u8; 32]),
    })
}

fn boot(source_bytes: usize, registration: Value) -> Value {
    json!({
        "schema": NATIVE_IMPORT18_PRIVATE_BOOT_SCHEMA,
        "private_key": Bytes::new(vec![23; 32]),
        "birth_id": Bytes::new(vec![17; 32]),
        "source_birth": {
            "schema": NATIVE_IMPORT18_SOURCE_BINDING_SCHEMA,
            "declaration": {
                "schema": NATIVE_IMPORT18_SOURCE_DECLARATION_SCHEMA,
                "source_birth": Bytes::new(vec![255; source_bytes]),
                "fresh_restore_allocation_selection": "completed_admit13",
            },
            "mechanism": "SourceSignedImport18",
            "prebirth_recipe": recipe(),
            "initial_funding": {
                "retained_requested_bytes": "1",
                "maximum_simultaneous_transient_bytes": "1",
                "declared_counter_scratch_bytes": "1",
            },
        },
        "expected_host_registration": registration,
        "private_launch": "private.data",
        "host_executable": canonical::content_ref(b"inert", "application/octet-stream").unwrap(),
    })
}

fn quote_boot(raw: &[u8], maximum: usize) -> Result<[usize; 3], ProviderError> {
    body(
        raw,
        private_body_typed_geometry_data()[2],
        private_body_typed_partials_data()[2],
        maximum,
    )
}

fn selected_launch(reactive: bool) -> Value {
    let (_, _, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    // Real closed DTOs exercise the nested container layouts. The empty model
    // deliberately supplies no validated native launch or Source authority.
    let program = if reactive {
        json!({
            "kind": "reactive",
            "program": {
                "schema": "source-owned.packet-connected-program/4",
                "connections": [],
                "output": null,
            },
        })
    } else {
        json!({
            "kind": "producer",
            "program": {"schema": "source-owned.packet-program.v1", "events": []},
        })
    };
    json!({
        "schema_version": 9,
        "mechanism": "SourceSignedImport18",
        "prebirth_recipe_identity": ([0u8; 32]),
        "initial_funding": {
            "retained_requested_bytes": "1",
            "maximum_simultaneous_transient_bytes": "1",
            "declared_counter_scratch_bytes": "1",
        },
        "launch": {
            "schema_version": 5,
            "selection": selection,
            "program": program,
            "controller_pid": "1",
            "controller_uid": "0",
            "controller_executable": coordinator.reference,
            "admission_token": Bytes::new(vec![7; 32]),
            "initial_coordinator": coordinator,
            "limits": {
                "frame_bytes": "65536",
                "nesting": "64",
                "requests": "64",
                "journal_entries": "256",
                "blob_chunk_bytes": "1024",
            },
            "storage": {
                "snapshot_bytes": "16384",
                "control_snapshot_bytes": "8192",
                "protocol_snapshot_bytes": "65536",
                "frame_bank_bytes": "65536",
                "frames_per_direction": "256",
                "hello_bytes": "131080",
                "settlement_bytes": "65536",
            },
            "effects": "/not-opened-by-bootstrap-layout-control",
        },
    })
}

#[test]
fn selected9_quote_covers_actual_producer_and_reactive_launch_backing() {
    for reactive in [false, true] {
        let wire = selected_launch(reactive);
        let raw = canonical::canonical_json(&wire).unwrap();
        let row = body(
            &raw,
            private_body_typed_geometry_data()[1],
            private_body_typed_partials_data()[1],
            usize::MAX / 4,
        )
        .unwrap();
        let strict = canonical::parse_json(&raw, raw.len()).unwrap();
        let parsed: PacketNativeImport18SelectedLaunchWireData =
            serde_json::from_value(strict).unwrap();
        let actual =
            crate::retained_metadata::observe_retained_native_launch(&parsed.launch).unwrap();
        assert!(row[0] >= requested_metadata_backing_storage_data(&actual).unwrap());

        let recipe_raw = canonical::canonical_json(&recipe()).unwrap();
        let boot_raw = canonical::canonical_json(&boot(32, json!({}))).unwrap();
        let all = private_body_decode_backing_data([&recipe_raw, &raw, &boot_raw], usize::MAX / 4)
            .unwrap();
        assert_eq!(all[1], row);
        assert!(!private_body_typed_geometry_data()[0].has_heap_fields);
    }
}

#[test]
fn boot_decode_quote_covers_actual_backing_and_refuses_one_short_complete_work() {
    for length in [0, 1, 2, 3, 4, 31, 32, 33, 2049] {
        let wire = boot(length, json!({"dense": [[], {}, [1, 2, 3]], "text": "𝄞"}));
        let raw = canonical::canonical_json(&wire).unwrap();
        let row = quote_boot(&raw, usize::MAX / 4).unwrap();
        let strict = canonical::parse_json(&raw, raw.len()).unwrap();
        let parsed: PacketNativeImport18PrivateBootWireData =
            serde_json::from_value(strict).unwrap();

        let mut observer = MetadataObserver::new();
        observer.observe(&parsed.private_key).unwrap();
        observer.observe(&parsed.birth_id).unwrap();
        observer
            .observe(parsed.source_birth.declaration.source_birth_data())
            .unwrap();
        observer
            .observe(&parsed.expected_host_registration)
            .unwrap();
        observer.observe(&parsed.private_launch).unwrap();
        observer.observe(&parsed.host_executable).unwrap();
        let actual = requested_metadata_backing_storage_data(&observer.finish()).unwrap();
        assert!(row[0] >= actual);
        assert_eq!(
            parsed
                .source_birth
                .declaration
                .source_birth_data()
                .as_slice(),
            vec![255; length]
        );

        let peak = sum(&row).unwrap();
        assert_eq!(quote_boot(&raw, peak).unwrap(), row);
        assert!(quote_boot(&raw, peak - 1).is_err());
    }
}

#[test]
fn malformed_typed_prefixes_receive_error_storage_without_a_producer_recipe() {
    let original = boot(32, json!({"registration": []}));
    let mut bad_key = original.clone();
    bad_key["private_key"] = json!("!");
    let mut bad_birth = original.clone();
    bad_birth["birth_id"] = json!("AB");
    let mut missing_fresh = original.clone();
    missing_fresh["source_birth"]["declaration"]
        .as_object_mut()
        .unwrap()
        .remove("fresh_restore_allocation_selection");
    let mut unknown = original;
    unknown["unrecognized"] = json!({"retained": "prefix"});

    for malformed in [bad_key, bad_birth, missing_fresh, unknown] {
        let raw = canonical::canonical_json(&malformed).unwrap();
        let row = quote_boot(&raw, usize::MAX / 4).unwrap();
        let strict = canonical::parse_json(&raw, raw.len()).unwrap();
        let error = match serde_json::from_value::<PacketNativeImport18PrivateBootWireData>(strict)
        {
            Ok(_) => panic!("malformed private DATA parsed"),
            Err(error) => error,
        };
        assert!(row[0] >= error.to_string().len());
        assert!(row[1] >= error.to_string().len());
    }
}

#[test]
fn rawvalue_reset_quote_accounts_for_the_actual_owned_value_adapter() {
    let literal =
        json!({"$serde_json::private::RawValue": "{\"expanded\":[1,2,{\"v\":\"text\"}]}"});
    let wire = boot(32, literal.clone());
    let raw = canonical::canonical_json(&wire).unwrap();
    let row = quote_boot(&raw, usize::MAX / 4).unwrap();
    let extra = raw_value_reparse::quote_raw_json_data(&raw, usize::MAX / 4).unwrap();
    assert_eq!(extra.detected_strings_data(), 1);
    let strict = canonical::parse_json(&raw, raw.len()).unwrap();
    let parsed: PacketNativeImport18PrivateBootWireData = serde_json::from_value(strict).unwrap();
    let expected: Value = serde_json::from_value(literal).unwrap();
    assert_eq!(parsed.expected_host_registration, expected);
    let mut observer = MetadataObserver::new();
    observer
        .observe(&parsed.expected_host_registration)
        .unwrap();
    assert!(row[0] >= requested_metadata_backing_storage_data(&observer.finish()).unwrap());

    assert!(private_body_decode_backing_data([&raw; 3], 1).is_err());
    assert!(private_body_decode_backing_data([&raw; 3], usize::MAX / 4).is_ok());
}
