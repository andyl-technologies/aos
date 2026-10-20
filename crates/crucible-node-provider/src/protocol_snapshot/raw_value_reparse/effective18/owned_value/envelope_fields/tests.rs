//! Exercises real first-cut construction, refusal and same-owner census.

use super::*;
use crate::envelope::Envelope;
use serde_json::json;

fn frame(value: Value) -> RetainedFrame {
    RetainedFrame {
        bytes: serde_json::to_vec(&value).unwrap(),
        value,
    }
}

fn assert_observed_failure(owner: &NativeImport18EnvelopeFieldsAttemptData<'_>) {
    assert!(owner.failed);
    assert!(!owner.complete);
    let requested_bytes = owner.retained_requested_storage_data(usize::MAX).unwrap();
    assert_eq!(
        owner.census_data(),
        EnvelopeFieldsCensus18Data::Observed {
            requested_bytes,
            within_row: requested_bytes <= owner.row.retained,
        }
    );
}

#[test]
fn no_cut_exact_outer_window_reaches_semantic_refusal_but_one_short_stops_before_it() {
    for value in [Value::Null, json!({}), json!([])] {
        let raw = frame(value);
        let mut exact =
            NativeImport18EnvelopeFieldsConstructionData::quote_data(&raw, usize::MAX).unwrap();
        assert_eq!(exact.cuts, 0);

        // Supply the actual outer owner/Some/Vec window independently of the
        // quoted T. Calling the real constructor makes an omitted initializer
        // observable: a one-short row would otherwise reach semantic refusal.
        exact.transient = size_of::<NativeImport18EnvelopeFieldsAttemptData<'static>>()
            + size_of::<Option<NativeImport18EnvelopeFieldsAttemptData<'static>>>()
            + size_of::<Vec<Cut>>();
        let mut output = None;
        let result =
            NativeImport18EnvelopeFieldsAttemptData::read_into_data(&raw, &exact, &mut output);
        assert!(matches!(result, Err(ProviderError::Frame(_))));
        assert_observed_failure(output.as_ref().unwrap());
        assert_eq!(output.as_ref().unwrap().cuts.capacity(), 0);

        let mut short = exact;
        short.transient -= 1;
        let mut short_output = None;
        let result = NativeImport18EnvelopeFieldsAttemptData::read_into_data(
            &raw,
            &short,
            &mut short_output,
        );
        assert!(matches!(result, Err(ProviderError::ResourceExhausted(_))));
        assert_observed_failure(short_output.as_ref().unwrap());
        assert_eq!(short_output.as_ref().unwrap().cuts.capacity(), 0);

        // Exercise the actual recheck/census path for the other independent
        // axes too; neither refused row can manufacture a completed bank.
        let mut short_retained = exact;
        short_retained.retained -= 1;
        let mut short_scratch = exact;
        short_scratch.scratch -= 1;
        for short in [short_retained, short_scratch] {
            let mut short_output = None;
            assert!(matches!(
                NativeImport18EnvelopeFieldsAttemptData::read_into_data(
                    &raw,
                    &short,
                    &mut short_output
                ),
                Err(ProviderError::ResourceExhausted(_))
            ));
            assert_observed_failure(short_output.as_ref().unwrap());
            if short.retained < exact.retained {
                assert!(matches!(
                    short_output.as_ref().unwrap().census_data(),
                    EnvelopeFieldsCensus18Data::Observed {
                        within_row: false,
                        ..
                    }
                ));
            }
        }
    }
}

#[test]
fn exact_error_prefix_is_retained_and_censused_while_short_rows_cannot_visit_it() {
    let raw = frame(json!({"body": {"first": null}, "zz_unknown": false}));
    let exact = NativeImport18EnvelopeFieldsConstructionData::quote_data(&raw, usize::MAX).unwrap();
    let mut output = None;

    let result = NativeImport18EnvelopeFieldsAttemptData::read_into_data(&raw, &exact, &mut output);
    assert!(matches!(result, Err(ProviderError::Frame(_))));
    let owner = output.as_ref().unwrap();
    assert_observed_failure(owner);
    assert_eq!(owner.cuts.len(), 1);
    assert!(owner.cuts[0].attempt.as_ref().unwrap().state.complete);
    assert!(owner.cuts.capacity() >= exact.cuts);

    let mut short_retained = exact;
    short_retained.retained -= 1;
    let mut short_transient = exact;
    short_transient.transient -= 1;
    let mut short_scratch = exact;
    short_scratch.scratch -= 1;
    for short in [short_retained, short_transient, short_scratch] {
        let mut short_output = None;
        assert!(matches!(
            NativeImport18EnvelopeFieldsAttemptData::read_into_data(
                &raw,
                &short,
                &mut short_output
            ),
            Err(ProviderError::ResourceExhausted(_))
        ));
        let owner = short_output.as_ref().unwrap();
        assert_observed_failure(owner);
        assert!(owner.cuts.is_empty());
        assert_eq!(owner.cuts.capacity(), 0);
    }
}

#[test]
fn failed_scalar_reason_is_preserved_and_counted_with_the_same_flat_output() {
    let raw = frame(json!({"session_id": "invalid identifier"}));
    let row = NativeImport18EnvelopeFieldsConstructionData::quote_data(&raw, usize::MAX).unwrap();
    let mut output = None;

    let result = NativeImport18EnvelopeFieldsAttemptData::read_into_data(&raw, &row, &mut output);
    let reason_capacity = match &result {
        Err(ProviderError::Contract(crucible_node_contract::ContractError::Invalid {
            field,
            reason,
        })) => {
            assert_eq!(*field, "id");
            assert_eq!(reason, "expected 1–128 bounded ASCII identifier bytes");
            reason.capacity()
        }
        other => panic!("original Id validation error changed: {other:?}"),
    };
    let owner = output.as_ref().unwrap();
    assert!(owner.failed);
    assert!(!owner.complete);
    assert_eq!(owner.cuts.len(), 1);
    assert!(owner.cuts[0].attempt.as_ref().unwrap().state.complete);
    assert_eq!(
        owner.census_data(),
        EnvelopeFieldsCensus18Data::Observed {
            requested_bytes: owner.retained_requested_storage_data(usize::MAX).unwrap()
                + reason_capacity,
            within_row: true,
        }
    );
    assert!(reason_capacity > 0);
}

fn envelope() -> Value {
    json!({
        "protocol": "CNP/1", "message": "response", "session_id": "session-1",
        "incarnation_id": "provider-1", "node_id": null,
        "execution_owner_id": "owner-1", "capture_owner_id": null,
        "request_id": "request-1", "operation_id": "operation-1", "sequence": "1",
        "method": "poll", "body": {"extensions": {}, "result": {}}, "extensions": {}
    })
}

#[test]
fn actual_map_sequence_and_unit_enum_forms_match_locked_envelope_acceptance() {
    let object = envelope();
    let sequence = json!([
        "CNP/1", {"response": null}, "session-1", "provider-1", null,
        "owner-1", null, "request-1", "operation-1", "1", {"poll": null},
        {"extensions": {}, "result": {}}, {}
    ]);
    let mut bad_sequence = sequence.clone();
    bad_sequence.as_array_mut().unwrap().push(Value::Null);
    let mut bad_enum = object.clone();
    bad_enum["message"] = json!({"response": []});
    let mut missing = object.clone();
    missing.as_object_mut().unwrap().remove("node_id");

    for value in [object, sequence, bad_sequence, bad_enum, missing] {
        // This control constructs only shallow ordinary comparison values.
        let expected = serde_json::from_value::<Envelope>(value.clone()).is_ok();
        let raw = frame(value);
        let row =
            NativeImport18EnvelopeFieldsConstructionData::quote_data(&raw, usize::MAX).unwrap();
        let mut output = None;
        let actual =
            NativeImport18EnvelopeFieldsAttemptData::read_into_data(&raw, &row, &mut output);
        assert_eq!(actual.is_ok(), expected);
        assert!(matches!(
            output.as_ref().unwrap().census_data(),
            EnvelopeFieldsCensus18Data::Observed {
                within_row: true,
                ..
            }
        ));
    }
}

#[test]
fn deep_flat_body_pass_survives_later_unknown_field_and_refuses_retry() {
    let payload = format!("{}0{}", "[".repeat(80), "]".repeat(80));
    let raw = frame(json!({
        "body": {"field": {"$serde_json::private::RawValue": payload}},
        "zz_unknown": false
    }));
    let row = NativeImport18EnvelopeFieldsConstructionData::quote_data(&raw, usize::MAX).unwrap();
    let mut output = None;

    assert!(
        NativeImport18EnvelopeFieldsAttemptData::read_into_data(&raw, &row, &mut output).is_err()
    );
    let owner = output.as_ref().unwrap();
    assert_observed_failure(owner);
    assert_eq!(owner.cuts.len(), 1);
    let child = owner.cuts[0].attempt.as_ref().unwrap();
    assert!(child.state.complete);
    if matches!(child.state.mode, Some(RawMode::Reparse)) {
        assert!(child.maximum_intermediate_depth_data() >= 80);
    }
    let retained = owner.retained_requested_storage_data(usize::MAX).unwrap();

    assert!(
        NativeImport18EnvelopeFieldsAttemptData::read_into_data(&raw, &row, &mut output).is_err()
    );
    assert_eq!(
        output
            .as_ref()
            .unwrap()
            .retained_requested_storage_data(usize::MAX)
            .unwrap(),
        retained
    );
    // The only deep successful child remains flat; no recursive expected
    // Value, Envelope or derived deep equality/destructor is constructed.
}

#[test]
fn body_and_extensions_are_structural_maps_without_a_root_value_pass() {
    let mut value = envelope();
    value["body"] = json!({"$serde_json::private::RawValue": "null"});
    value["extensions"] = json!({"$serde_json::private::RawValue": "null"});
    let raw = frame(value);
    let row = NativeImport18EnvelopeFieldsConstructionData::quote_data(&raw, usize::MAX).unwrap();
    let mut output = None;

    NativeImport18EnvelopeFieldsAttemptData::read_into_data(&raw, &row, &mut output).unwrap();
    let owner = output.as_ref().unwrap();
    for field in [EnvelopeField18Data::Body, EnvelopeField18Data::Extensions] {
        let input = &raw.value[if field == EnvelopeField18Data::Body {
            "body"
        } else {
            "extensions"
        }][RAW_VALUE_KEY];
        let view = owner.completed_cut_data(&raw, field, 0, input).unwrap();
        assert!(matches!(
            view.kind_data().unwrap(),
            NativeImport18OwnedValuePassKindData::String("null")
        ));
        let foreign = Value::String("null".into());
        assert!(owner.completed_cut_data(&raw, field, 0, &foreign).is_err());
    }
}

#[test]
fn method_mirror_matches_the_complete_selected_protocol_enum() {
    let methods = [
        ("hello", Method::Hello),
        ("discover", Method::Discover),
        ("realize", Method::Realize),
        ("admit", Method::Admit),
        ("native_import18_bootstrap", Method::NativeImport18Bootstrap),
        ("activate", Method::Activate),
        ("input", Method::Input),
        ("observe", Method::Observe),
        ("begin", Method::Begin),
        ("poll", Method::Poll),
        ("cancel", Method::Cancel),
        ("quantum_close", Method::QuantumClose),
        ("world_activate", Method::WorldActivate),
        ("abort", Method::Abort),
        ("retire", Method::Retire),
        ("blob_begin", Method::BlobBegin),
        ("blob_chunk", Method::BlobChunk),
        ("blob_finish", Method::BlobFinish),
        ("release", Method::Release),
        ("operation_update", Method::OperationUpdate),
        ("observation_ready", Method::ObservationReady),
        ("provider_fault", Method::ProviderFault),
    ];

    for (name, expected) in methods {
        let value = Value::String(name.to_owned());
        let decoded: Method = serde_json::from_value(value.clone()).unwrap();

        assert_eq!(method_data(&value).unwrap(), expected);
        assert_eq!(decoded, expected);
        assert_eq!(serde_json::to_value(expected).unwrap(), value);
    }

    assert!(
        method_data(&Value::String(
            "native_import18_bootstrap_unknown".to_owned()
        ))
        .is_err()
    );
}
