//! Compares nonsecret Hello/registration inputs with the original real helpers.
//!
//! The coordinator/selection come from the existing real canonical ACK fixture.
//! The enclosing launch is inert test DATA. These controls neither validate a
//! complete launch nor create a worker/Source or adopt the fixture authority.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::reference_packet::service::{
    PacketNative5AckEmitterSelection, PacketNative5ConfirmationSelection,
    PacketNative5LaunchValidationFields, PacketNative5ProtocolMetadataLimits,
};
use crucible_node_format::Bytes;
use serde_json::json;

#[path = "fields_tests/original.rs"]
mod original;

// The saved full-launch oracle retains its original closed grammar tables.
const FIELDS: [&str; 9] = [
    "schema",
    "role",
    "connection_id",
    "session_id",
    "incarnation_id",
    "limits",
    "features",
    "extensions",
    "envelope_extensions",
];
const LIMIT_FIELDS: [&str; 5] = [
    "frame_bytes",
    "nesting",
    "requests",
    "journal_entries",
    "blob_chunk_bytes",
];

fn launch() -> PacketNative5SourceLaunch {
    let (_handshake, authority, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let mut launch: PacketNative5SourceLaunch = serde_json::from_value(json!({
        "schema_version":5,
        "selection":selection,
        "program":{"kind":"producer","program":{
            "schema":"source-owned.packet-program.v1","events":[]
        }},
        "controller_pid":"1","controller_uid":"0",
        "controller_executable":coordinator.reference,
        "admission_token":Bytes::new(vec![7;32]),
        "initial_coordinator":coordinator,
        "limits":authority.limits(),
        "storage":{"snapshot_bytes":"16384","control_snapshot_bytes":"8192",
            "protocol_snapshot_bytes":"65536","frame_bank_bytes":"65536",
            "frames_per_direction":"256","hello_bytes":"131080",
            "settlement_bytes":"65536"},
        "effects":"/not-opened-by-hello-fields"
    }))
    .unwrap();
    launch.confirmation_selection = Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5);
    launch.ack_emitter_selection = Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5);
    launch.protocol_metadata_limits = Some(PacketNative5ProtocolMetadataLimits {
        native_before_rows: U64::new(128),
        native_after_rows: U64::new(256),
    });
    launch
}

fn planned(
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
) -> Value {
    let binding = &launch.selection.realization.bindings[0];
    let mut names = None;
    declaration
        .retain_registration_names_into_data(&mut names)
        .unwrap();
    let (features, keys) = names.unwrap();
    json!({
        "schema":PLANNED_SCHEMA,"role":"controller","connection_id":"controller-field-projection",
        "session_id":binding.authority.session_id,
        "incarnation_id":binding.authority.incarnation_id,
        "limits":launch.limits,"features":features,"extensions":[],"envelope_extensions":keys
    })
}

fn declaration_result(
    result: Result<PacketNativeImport18HelloDeclarationData, ProviderError>,
) -> Result<
    (
        [Option<&'static str>; FEATURES],
        [Option<(&'static str, &'static str)>; KEYS],
        usize,
        usize,
    ),
    String,
> {
    result
        .map(|value| {
            (
                *value.features_data(),
                *value.keys_data(),
                value.feature_count_data(),
                value.key_count_data(),
            )
        })
        .map_err(|error| format!("{error:?}; {error}"))
}

fn quote_result(
    result: Result<PacketNativeImport18ProspectiveHostRegistrationData, ProviderError>,
) -> Result<([u8; 32], usize), String> {
    result
        .map(|value| {
            (
                value.planned_identity_data(),
                value.maximum_encoded_bytes_data(),
            )
        })
        .map_err(|error| format!("{error:?}; {error}"))
}

fn original_quote_result(
    result: Result<original::SavedProjection, ProviderError>,
) -> Result<([u8; 32], usize), String> {
    result
        .map(|value| value.parts_data())
        .map_err(|error| format!("{error:?}; {error}"))
}

fn check_result(result: Result<(), ProviderError>) -> Result<(), String> {
    result.map_err(|error| format!("{error:?}; {error}"))
}

fn compare_plan(
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
    planned: &Value,
) {
    let fields = PacketNative5LaunchValidationFields::from_launch_data(launch);
    for maximum in [0, 1, 64, 4096, usize::MAX] {
        let expected =
            original_quote_result(original::prospective(launch, declaration, planned, maximum));
        assert_eq!(
            quote_result(native_import18_prospective_host_registration_data(
                launch,
                declaration,
                planned,
                maximum
            )),
            expected
        );
        assert_eq!(
            quote_result(
                native_import18_prospective_host_registration_from_fields_data(
                    &fields,
                    declaration,
                    planned,
                    maximum
                )
            ),
            expected
        );
    }
}

#[test]
fn hello_all_selector_and_target_shapes_match_the_saved_original() {
    let mut launch = launch();
    let bindings = launch.selection.realization.bindings.clone();
    for schema in [4, 5] {
        launch.schema_version = schema;
        for count in 0..=2 {
            launch.selection.realization.bindings =
                (0..count).map(|_| bindings[0].clone()).collect();
            for tuple in 0..8 {
                launch.confirmation_selection = (tuple & 1 != 0)
                    .then_some(PacketNative5ConfirmationSelection::AfterProtocolPoll5);
                launch.ack_emitter_selection =
                    (tuple & 2 != 0).then_some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5);
                launch.protocol_metadata_limits =
                    (tuple & 4 != 0).then_some(PacketNative5ProtocolMetadataLimits {
                        native_before_rows: U64::new(128),
                        native_after_rows: U64::new(256),
                    });
                let fields = PacketNative5LaunchValidationFields::from_launch_data(&launch);
                let expected = declaration_result(original::declaration(&launch));
                assert_eq!(
                    declaration_result(native_import18_hello_declaration_data(&launch)),
                    expected
                );
                assert_eq!(
                    declaration_result(native_import18_hello_declaration_from_fields_data(&fields)),
                    expected
                );
            }
        }
    }
}

#[test]
fn prospective_all_rosters_keep_original_limits_projection_and_identity() {
    use crate::reference_packet::service::{
        capture_allocation::PacketNative5CaptureAllocationSelection as Capture,
        fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection as Fresh,
    };
    let mut launch = launch();
    for restoration in [None,Some(super::super::super::super::PacketNative5CompleteRestoreSelection::SourceSignedOwned11),
        Some(super::super::super::super::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)] {
        launch.complete_restore_selection = restoration;
        for capture in [false,true] {
            launch.capture_allocation_selection = capture.then_some(Capture::OriginalObserve12);
            for fresh in [false,true] {
                launch.fresh_restore_allocation_selection = fresh.then_some(Fresh::CompletedAdmit13);
                let declaration = original::declaration(&launch).unwrap();
                let planned = planned(&launch,&declaration);
                assert!(original::prospective(&launch,&declaration,&planned,usize::MAX).is_ok());
                compare_plan(&launch,&declaration,&planned);
            }
        }
    }
}

#[test]
fn planned_field_errors_and_noncanonical_limits_preserve_original_diagnostics() {
    let launch = launch();
    let declaration = original::declaration(&launch).unwrap();
    let original = planned(&launch, &declaration);
    let changes: &[fn(&mut Value)] = &[
        |value| *value = Value::Null,
        |value| {
            value.as_object_mut().unwrap().remove("schema");
        },
        |value| {
            value["unknown"] = Value::Null;
        },
        |value| value["schema"] = json!("different"),
        |value| value["role"] = json!("native"),
        |value| value["session_id"] = json!("foreign-session"),
        |value| value["incarnation_id"] = json!("foreign-incarnation"),
        |value| value["connection_id"] = json!(""),
        |value| value["extensions"] = json!([{}]),
        |value| value["features"] = json!([]),
        |value| value["features"][0] = Value::Null,
        |value| {
            value["features"].as_array_mut().unwrap().swap(0, 1);
        },
        |value| {
            let first = value["features"][0].clone();
            value["features"][1] = first;
        },
        |value| value["envelope_extensions"] = json!([]),
        |value| value["envelope_extensions"][0] = json!("unknown.key"),
        |value| value["limits"]["unknown"] = json!("1"),
    ];
    for change in changes {
        let mut planned = original.clone();
        change(&mut planned);
        compare_plan(&launch, &declaration, &planned);
    }
    for field in LIMIT_FIELDS {
        for bad in [
            json!(""),
            json!("01"),
            json!("-1"),
            json!("18446744073709551616"),
            json!(0),
        ] {
            let mut planned = original.clone();
            planned["limits"][field] = bad;
            compare_plan(&launch, &declaration, &planned);
        }
    }
}

#[test]
fn saved_plan_checks_shared_fields_before_unchanged_identity_comparison() {
    let launch = launch();
    let declaration = original::declaration(&launch).unwrap();
    let planned = planned(&launch, &declaration);
    let expected_saved =
        original::prospective(&launch, &declaration, &planned, usize::MAX).unwrap();
    let saved = native_import18_prospective_host_registration_data(
        &launch,
        &declaration,
        &planned,
        usize::MAX,
    )
    .unwrap();
    assert_eq!(
        (
            saved.planned_identity_data(),
            saved.maximum_encoded_bytes_data()
        ),
        expected_saved.parts_data()
    );
    let fields = PacketNative5LaunchValidationFields::from_launch_data(&launch);
    let pointer = launch.initial_coordinator.bytes.as_slice().as_ptr();
    let capacity = launch.initial_coordinator.bytes.allocation_capacity();
    for changed in [planned.clone(), {
        let mut value = planned.clone();
        value["connection_id"] = json!("other-valid-controller");
        value
    }] {
        let expected = check_result(original::authenticate_saved(
            &saved,
            &launch,
            &declaration,
            &changed,
        ));
        assert_eq!(
            check_result(saved.authenticate_planned_data(&launch, &declaration, &changed)),
            expected
        );
        assert_eq!(
            check_result(saved.authenticate_planned_from_fields_data(
                &fields,
                &declaration,
                &changed
            )),
            expected
        );
    }
    assert_eq!(
        launch.initial_coordinator.bytes.as_slice().as_ptr(),
        pointer
    );
    assert_eq!(
        launch.initial_coordinator.bytes.allocation_capacity(),
        capacity
    );
}

#[test]
fn ignored_secret_and_path_never_enter_the_hello_or_plan_adapter() {
    use std::os::unix::ffi::OsStringExt;
    let mut launch = launch();
    let declaration = original::declaration(&launch).unwrap();
    let planned = planned(&launch, &declaration);
    let expected = original_quote_result(original::prospective(
        &launch,
        &declaration,
        &planned,
        usize::MAX,
    ));
    launch.admission_token = Bytes::new(vec![0; 1]);
    launch.effects = std::ffi::OsString::from_vec(vec![0xff]).into();
    launch.initial_coordinator.bytes = Bytes::new(b"not-decoded-by-this-helper".to_vec());
    let fields = PacketNative5LaunchValidationFields::from_launch_data(&launch);
    assert_eq!(
        quote_result(
            native_import18_prospective_host_registration_from_fields_data(
                &fields,
                &declaration,
                &planned,
                usize::MAX
            )
        ),
        expected
    );
    compare_plan(&launch, &declaration, &planned);
    let unsupported = PacketNative5LaunchValidationFields {
        schema_version: 4,
        ..fields
    };
    assert!(native_import18_hello_declaration_from_fields_data(&unsupported).is_err());
}
