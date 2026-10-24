//! Compares the closed launch quote with actual owning deserialization.

use super::*;
use crucible_node_format::*;
use serde::Deserialize;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn input(reactive: bool) -> Result<Value, ProviderError> {
    let (_, _, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let program = if reactive {
        json!({"kind":"reactive","program":{
            "schema":"source-owned.packet-connected-program/4","connections":[],"output":null}})
    } else {
        json!({"kind":"producer","program":{
            "schema":"source-owned.packet-program.v1","events":[{
                "id":"event-a","evaluation":{"time_ps":"0","microstep":"0","phase":3},
                "completion":{"time_ps":"0","microstep":"0","phase":1},"payload":"AAEC"}]}})
    };
    Ok(
        json!({"schema_version":5,"selection":selection,"program":program,
        "controller_pid":"1","controller_uid":"0","controller_executable":coordinator.reference,
        "admission_token":Bytes::new(vec![7;32]),"initial_coordinator":coordinator,
        "limits":{"frame_bytes":"65536","nesting":"64","requests":"64",
            "journal_entries":"256","blob_chunk_bytes":"1024"},
        "storage":{"snapshot_bytes":"16384","control_snapshot_bytes":"8192",
            "protocol_snapshot_bytes":"65536","frame_bank_bytes":"65536",
            "frames_per_direction":"256","hello_bytes":"131080","settlement_bytes":"65536"},
        "effects":"/not-opened-by-data-control"}),
    )
}

#[test]
fn actual_owned_and_borrowed_launch_decodes_fit_the_native_projection() -> TestResult {
    // These are real native DTO deserializations, not accepted native launches:
    // semantic validation/admission remains a distinct unchanged production call.
    for reactive in [false, true] {
        let mut value = input(reactive)?;
        value["selection"]["provider"]["extensions"]["nested"] =
            json!({"a":[{}, {}, {"b":"\\uD834\\uDD1E"}],"bytes":"AAEC"});
        let raw = canonical::canonical_json(&value)?;
        assert!(recognized(&raw).is_ok());
        let original: PacketNative5SourceLaunch = serde_json::from_value(value.clone())?;
        let borrowed = PacketNative5SourceLaunch::deserialize(&value)?;
        let old = super::super::super::super::complete_restore::transfer::selected_issuer_decode_storage_data(
            &raw, size_of::<PacketNative5SourceLaunch>(), usize::MAX)?;
        let row = quote(&raw, usize::MAX)?;
        for actual in [&original, &borrowed] {
            let facts = crate::retained_metadata::observe_retained_native_launch(actual)?;
            let bytes = requested_metadata_backing_storage_data(&facts)?;
            assert!(row >= bytes + size_of::<PacketNative5SourceLaunch>());
        }
        assert!(row < old);
        assert_eq!(quote(&raw, row)?, row);
        assert!(quote(&raw, row - 1).is_err());
    }
    Ok(())
}

#[test]
fn unknown_launch_classes_and_fields_keep_the_original_issuer_quote() -> TestResult {
    for mutation in [0, 1, 2] {
        let mut value = input(false)?;
        match mutation {
            0 => value["schema_version"] = json!(6),
            1 => value["unrecognized_owner"] = json!([{}, {}, {}]),
            _ => value["program"]["kind"] = json!("unknown_program"),
        }
        let raw = canonical::canonical_json(&value)?;
        assert!(recognized(&raw).is_err());
        let old = super::super::super::super::complete_restore::transfer::selected_issuer_decode_storage_data(
            &raw, size_of::<PacketNative5SourceLaunch>(), usize::MAX)?;
        assert_eq!(quote(&raw, usize::MAX)?, old);
        assert!(PacketNative5SourceLaunch::decode(&raw, raw.len()).is_err());
    }
    assert!(recognized(br#"{"schema_version":5,"schema_version":5}"#).is_err());
    Ok(())
}

#[test]
fn raw_launch_array_occurrences_are_counted_before_semantic_rejection() -> TestResult {
    let first = input(false)?;
    let mut second = first.clone();
    let event = second["program"]["program"]["events"][0].clone();
    second["program"]["program"]["events"] = Value::Array(vec![event; 37]);
    let first_raw = canonical::canonical_json(&first)?;
    let second_raw = canonical::canonical_json(&second)?;
    assert!(recognized(&second_raw).is_ok());
    assert!(quote(&second_raw, usize::MAX)? > quote(&first_raw, usize::MAX)?);
    // No post-validate two-event assumption is used to price malformed input.
    assert!(PacketNative5SourceLaunch::decode(&second_raw, second_raw.len()).is_err());
    Ok(())
}
