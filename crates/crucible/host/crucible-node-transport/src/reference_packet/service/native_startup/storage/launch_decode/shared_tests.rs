//! Compares the shared launch classifier with the independent pre-move source.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

// Deliberately invalid typed values exercise classification without fabricating
// a validated launch, Source, reservation, or actual native constructor.
const PRODUCER: &[u8] = br#"{"schema_version":5,"selection":null,"program":{"kind":"producer","program":{"schema":null,"events":[]}},"controller_pid":null,"controller_uid":null,"controller_executable":null,"admission_token":null,"initial_coordinator":null,"limits":null,"storage":null,"effects":null}"#;
const REACTIVE: &[u8] = br#"{"schema_version":5,"selection":null,"program":{"kind":"reactive","program":{"schema":null,"connections":[],"output":null}},"controller_pid":null,"controller_uid":null,"controller_executable":null,"admission_token":null,"initial_coordinator":null,"limits":null,"storage":null,"effects":null}"#;

fn classification(bytes: &[u8], old: bool) -> Result<(), String> {
    if old {
        original::recognized(bytes)
    } else {
        recognized(bytes)
    }
    .map_err(|error| format!("{error:?}"))
}

#[test]
fn shared_launch_classification_preserves_original_fields_and_refusals() {
    for bytes in [
        PRODUCER,
        REACTIVE,
        b"null",
        b"{}",
        br#"{"schema_version":5,"schema_version":5}"#,
        br#"{"program":{"kind":"producer","kind":"producer","program":{}}}"#,
        br#"{"program":{"kind":"unknown","program":{}}}"#,
        br#"{"program":{"kind":"producer","program":{"schema":null,"events":[],"events":[]}}}"#,
        br#"{"program":{"kind":"reactive","program":{"schema":null,"connections":[]}}}"#,
        br#"{"schema_version":6,"unrecognized_owner":null}"#,
        br#"{"schema_version":5,"escaped\u005ffield":null}"#,
        br#"{"schema_version":5"#,
    ] {
        assert_eq!(classification(bytes, false), classification(bytes, true));
    }

    assert!(recognized(PRODUCER).is_ok());
    assert!(recognized(REACTIVE).is_ok());
    assert!(PacketNative5SourceLaunch::decode(PRODUCER, PRODUCER.len()).is_err());
    assert!(PacketNative5SourceLaunch::decode(REACTIVE, REACTIVE.len()).is_err());
}

#[test]
fn shared_launch_roster_and_counter_keep_actual_pre_move_types() {
    use crucible_source_birth_data::profile::reference_packet::service::native_startup::launch_decode;

    assert_eq!(launch_decode::typed_slot(), original::typed_slot());
    assert_eq!(coordinator_decode::typed_slot(), original::typed_slot());
    assert_eq!(element_slot(), original::element_slot());
    assert_eq!(counter_scratch_data(), original::counter_scratch_data());
}

#[test]
fn unchanged_quote_keeps_generic_raw_bound_and_native_final_bound() -> TestResult {
    // The issuer bounds its raw input separately from the returned phase sum.
    // Do not replace its unchanged fallback with the native final-total bound.
    let raw = b"{}";
    let generic = super::super::super::super::complete_restore::transfer::selected_issuer_decode_storage_data(
        raw, size_of::<PacketNative5SourceLaunch>(), raw.len(),
    )?;
    assert!(recognized(raw).is_err());
    assert_eq!(quote(raw, raw.len())?, generic);
    assert!(generic > raw.len());
    assert!(quote(raw, raw.len() - 1).is_err());

    let native = quote(PRODUCER, usize::MAX)?;
    assert!(native > PRODUCER.len());
    assert_eq!(quote(PRODUCER, native)?, native);
    assert!(quote(PRODUCER, native - 1).is_err());
    Ok(())
}
