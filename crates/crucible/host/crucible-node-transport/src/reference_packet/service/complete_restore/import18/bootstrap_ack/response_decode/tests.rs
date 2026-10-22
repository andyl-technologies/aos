//! Exercises retained transport DATA without manufacturing Source or Recipe authority.

use super::*;
use crate::envelope::Nullable;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use crucible_node_format::values::MAX_ID_BYTES;

fn operands() -> (Envelope, Value) {
    let row = PacketNativeStartupAllocationRow {
        retained_requested_bytes: U64::new(1),
        maximum_simultaneous_transient_bytes: U64::new(2),
        declared_counter_scratch_bytes: U64::new(3),
    };
    let request = PacketNativeImport18BootstrapRequest {
        schema: NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA.into(),
        recipe_identity: Bytes::new(vec![1; 32]),
        initial_funding: row,
    };
    let mut original = crate::envelope::tests::request();
    original.method = Method::NativeImport18Bootstrap;
    original.sequence = U64::new(2);
    original.node_id = Nullable(None);
    original.execution_owner_id = Nullable(None);
    original.capture_owner_id = Nullable(None);
    original.operation_id = Nullable(None);
    original.session_id = Nullable(Some(Id::new("s".repeat(MAX_ID_BYTES)).unwrap()));
    original.incarnation_id = Nullable(Some(Id::new("i".repeat(MAX_ID_BYTES)).unwrap()));
    original.request_id = Nullable(Some(Id::new("r".repeat(MAX_ID_BYTES)).unwrap()));
    original.body = serde_json::to_value(&request)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    original.extensions.clear();
    original.extensions.insert(
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
        serde_json::json!({}),
    );

    let mut response = original.clone();
    response.message = MessageKind::Response;
    response.body = serde_json::json!({
        "status": "completed", "operation_state": "completed", "extensions": {},
        "result": {
            "schema": NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA,
            "state": "bootstrap_only", "recipe_identity": request.recipe_identity,
            "initial_funding": row,
        },
    })
    .as_object()
    .unwrap()
    .clone();
    response.extensions.clear();
    // These fixed-width DATA fields are deliberately not authenticated MACs.
    response.extensions.insert(
        NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.into(),
        serde_json::json!({
            "schema": NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT,
            "algorithm": PACKET_COMPLETE_RESTORE_ALGORITHM, "state": "bootstrap_only",
            "context_digest": Bytes::new(vec![2; 32]),
            "assigned_response": Bytes::new(vec![3; 32]), "mac": Bytes::new(vec![4; 32]),
        }),
    );
    (original, serde_json::to_value(response).unwrap())
}

fn decode(
    original: &Envelope,
    raw: &Value,
) -> (
    Result<(), ProviderError>,
    PacketNativeImport18BootstrapResponseDecodeData,
) {
    let row = native_import18_bootstrap_response_decode_quote_data(usize::MAX).unwrap();
    let mut output = None;
    let result = native_import18_bootstrap_response_decode_into_data(
        original,
        raw,
        &row,
        usize::MAX,
        &mut output,
    );
    (result, output.unwrap())
}

#[test]
fn closed_response_retains_every_independent_output_inside_the_component_quote() {
    let (original, raw) = operands();
    let unchanged = raw.clone();

    let (result, owner) = decode(&original, &raw);

    result.unwrap();
    assert_eq!(raw, unchanged);
    let history = owner.borrowed_history_data();
    assert!(history.decoded);
    assert!(!history.failed);
    assert_eq!(
        history.step,
        Some(PacketNativeImport18BootstrapResponseDecodeStep::Receipt)
    );
    assert!(history.failure.is_none());
    let request = history.request.unwrap();
    history
        .result
        .unwrap()
        .authenticate_request_data(request)
        .unwrap();
    history.receipt.unwrap().validate_data().unwrap();
    assert!(owner.retained_requested_bytes_data().unwrap() <= history.requested_storage[0]);

    let envelope = history.envelope.unwrap();
    original.matches_response(envelope).unwrap();
    let ResponseShape::Completed { result, .. } = history.body.unwrap() else {
        panic!("closed completed body");
    };
    assert_eq!(
        result,
        envelope.body.get("result").unwrap().as_object().unwrap()
    );
    assert_ne!(
        result.get("schema").unwrap().as_str().unwrap().as_ptr(),
        envelope.body["result"]["schema"].as_str().unwrap().as_ptr()
    );
    assert_eq!(request.recipe_identity.allocation_capacity(), 33);
    assert_eq!(
        history
            .result
            .unwrap()
            .recipe_identity
            .allocation_capacity(),
        33
    );
    assert_eq!(history.receipt.unwrap().mac.allocation_capacity(), 33);
}

#[test]
fn changed_recipe_or_row_keeps_typed_result_and_refuses_an_occupied_retry() {
    for recipe_fault in [true, false] {
        let (original, mut raw) = operands();
        if recipe_fault {
            raw["body"]["result"]["recipe_identity"] =
                serde_json::to_value(Bytes::new(vec![9; 32])).unwrap();
        } else {
            raw["body"]["result"]["initial_funding"]["retained_requested_bytes"] =
                Value::String(u64::MAX.to_string());
        }
        let (result, owner) = decode(&original, &raw);

        assert!(result.is_err());
        let history = owner.borrowed_history_data();
        assert!(history.failed);
        assert!(!history.decoded);
        assert_eq!(
            history.step,
            Some(PacketNativeImport18BootstrapResponseDecodeStep::Result)
        );
        assert!(
            history.envelope.is_some()
                && history.request.is_some()
                && history.body.is_some()
                && history.result.is_some()
        );
        assert!(history.receipt.is_none() && history.failure.is_none());
        assert!(owner.retained_requested_bytes_data().unwrap() <= history.requested_storage[0]);
        let pointer = history.result.unwrap().schema.as_ptr();
        let mut output = Some(owner);
        let (_, valid) = operands();
        let row = native_import18_bootstrap_response_decode_quote_data(usize::MAX).unwrap();

        assert!(
            native_import18_bootstrap_response_decode_into_data(
                &original,
                &valid,
                &row,
                usize::MAX,
                &mut output
            )
            .is_err()
        );
        assert_eq!(
            output
                .as_ref()
                .unwrap()
                .borrowed_history_data()
                .result
                .unwrap()
                .schema
                .as_ptr(),
            pointer
        );
    }
}

#[test]
fn malformed_digest_keeps_the_exact_preceding_decoder_prefix_and_coordinates() {
    for receipt_fault in [false, true] {
        let (original, mut raw) = operands();
        let step = if receipt_fault {
            raw["extensions"][NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT]["mac"] =
                Value::String("!".repeat(43));
            PacketNativeImport18BootstrapResponseDecodeStep::Receipt
        } else {
            raw["body"]["result"]["recipe_identity"] = Value::String("!".repeat(43));
            PacketNativeImport18BootstrapResponseDecodeStep::Result
        };
        let (result, owner) = decode(&original, &raw);

        assert!(result.is_err());
        let history = owner.borrowed_history_data();
        assert_eq!(history.step, Some(step));
        assert_eq!(history.failure.unwrap().step, step);
        assert!(history.failed && !history.decoded);
        assert!(history.envelope.is_some() && history.request.is_some() && history.body.is_some());
        assert_eq!(history.result.is_some(), receipt_fault);
        assert!(history.receipt.is_none());
        assert!(owner.retained_requested_bytes_data().unwrap() <= history.requested_storage[0]);
    }
}

#[test]
fn every_response_header_fault_refuses_before_dto_construction() {
    for (field, changed) in [
        ("protocol", Value::String("other".into())),
        ("message", Value::String("request".into())),
        ("method", Value::String("admit".into())),
        ("sequence", Value::String("3".into())),
        ("session_id", Value::String("foreign".into())),
        ("incarnation_id", Value::String("foreign".into())),
        ("request_id", Value::String("foreign".into())),
        ("node_id", Value::String("node".into())),
        ("execution_owner_id", Value::String("owner".into())),
        ("capture_owner_id", Value::String("capture".into())),
        ("operation_id", Value::String("operation".into())),
    ] {
        let (original, mut raw) = operands();
        raw[field] = changed;

        let (result, owner) = decode(&original, &raw);

        assert!(result.is_err(), "{field}");
        let history = owner.borrowed_history_data();
        assert!(history.failed && !history.decoded);
        assert!(history.step.is_none() && history.envelope.is_none());
    }
}

#[test]
fn closed_rosters_refuse_unknown_missing_and_oversized_values_before_decode() {
    for path in [
        "",
        "/body",
        "/body/result",
        "/body/result/initial_funding",
        "/body/extensions",
        "/extensions",
        "receipt",
    ] {
        for remove in [false, true] {
            let (original, mut raw) = operands();
            // The extension key contains a slash, so borrow that map directly.
            let map = if path == "receipt" {
                raw["extensions"][NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT]
                    .as_object_mut()
                    .unwrap()
            } else {
                raw.pointer_mut(path).unwrap().as_object_mut().unwrap()
            };
            if remove && !map.is_empty() {
                let key = map.keys().next().unwrap().clone();
                map.remove(&key);
            } else {
                map.insert("unknown".into(), serde_json::json!([[["unpriced"]]]));
            }

            let (result, owner) = decode(&original, &raw);

            assert!(result.is_err(), "{path}, remove {remove}");
            assert!(owner.borrowed_history_data().step.is_none());
        }
    }
    for field in ["schema", "state", "recipe_identity"] {
        let (original, mut raw) = operands();
        raw["body"]["result"][field] = Value::String("x".repeat(4096));
        let (result, owner) = decode(&original, &raw);
        assert!(result.is_err());
        assert!(owner.borrowed_history_data().envelope.is_none());
    }
}

#[test]
fn nonterminal_or_error_body_never_becomes_a_bootstrap_only_output() {
    for body in [
        serde_json::json!({"status":"accepted", "operation_state":"running", "result":{}, "extensions":{}}),
        serde_json::json!({"status":"error", "operation_state":"unknown", "error":{"details":{"nested":[1,2,3]}}, "extensions":{}}),
    ] {
        let (original, mut raw) = operands();
        raw["body"] = body;
        let retained_raw = raw.clone();

        let (result, owner) = decode(&original, &raw);

        assert!(result.is_err());
        assert_eq!(raw, retained_raw);
        assert!(owner.borrowed_history_data().step.is_none());
    }
}

#[test]
fn short_restriction_retains_the_spent_empty_owner_and_quote_is_independent() {
    let row = native_import18_bootstrap_response_decode_quote_data(usize::MAX).unwrap();
    let peak = storage::sum(&row.requested_storage_data()).unwrap();
    assert!(native_import18_bootstrap_response_decode_quote_data(peak - 1).is_err());
    assert_eq!(
        native_import18_bootstrap_response_decode_quote_data(peak)
            .unwrap()
            .requested_storage_data(),
        row.requested_storage_data()
    );
    let (original, raw) = operands();
    let mut output = None;

    assert!(
        native_import18_bootstrap_response_decode_into_data(
            &original,
            &raw,
            &row,
            peak - 1,
            &mut output
        )
        .is_err()
    );

    let owner = output.as_ref().unwrap();
    let history = owner.borrowed_history_data();
    assert!(history.failed && !history.decoded && history.step.is_none());
    assert_eq!(
        owner.retained_requested_bytes_data().unwrap(),
        size_of::<PacketNativeImport18BootstrapResponseDecodeData>()
    );
}

#[test]
fn changed_original_header_or_closed_body_refuses_before_response_allocation() {
    for fault in 0..11 {
        let (mut original, raw) = operands();
        let id = Some(Id::new("concrete").unwrap());
        match fault {
            0 => original.protocol = "other".into(),
            1 => original.message = MessageKind::Response,
            2 => original.method = Method::Admit,
            3 => original.sequence = U64::new(3),
            4 => original.node_id = Nullable(id),
            5 => original.execution_owner_id = Nullable(id),
            6 => original.capture_owner_id = Nullable(id),
            7 => original.operation_id = Nullable(id),
            8 => original.extensions.clear(),
            9 => {
                original
                    .body
                    .insert("unknown".into(), serde_json::json!([[["unpriced"]]]));
            }
            10 => {
                original.body["initial_funding"] =
                    serde_json::json!({"retained_requested_bytes": []});
            }
            _ => unreachable!(),
        }

        let (result, owner) = decode(&original, &raw);

        assert!(result.is_err(), "fault {fault}");
        let history = owner.borrowed_history_data();
        assert!(history.failed && !history.decoded);
        assert!(history.step.is_none() && history.envelope.is_none());
    }
}

#[test]
fn invalid_initial_row_keeps_the_actual_original_typed_request() {
    let (mut original, raw) = operands();
    original.body["initial_funding"]["retained_requested_bytes"] = Value::String("0".into());

    let (result, owner) = decode(&original, &raw);

    assert!(result.is_err());
    let history = owner.borrowed_history_data();
    assert_eq!(
        history.step,
        Some(PacketNativeImport18BootstrapResponseDecodeStep::Request)
    );
    assert!(history.envelope.is_some() && history.request.is_some());
    assert!(history.body.is_none() && history.failure.is_none());
    assert_eq!(
        history
            .request
            .unwrap()
            .initial_funding
            .retained_requested_bytes
            .get(),
        0
    );
    assert!(owner.retained_requested_bytes_data().unwrap() <= history.requested_storage[0]);
}

#[test]
fn maximum_width_initial_data_stays_within_the_independent_quote() {
    let (mut original, mut raw) = operands();
    let row = serde_json::json!({
        "retained_requested_bytes": (u64::MAX - 2).to_string(),
        "maximum_simultaneous_transient_bytes": "1",
        "declared_counter_scratch_bytes": "1",
    });
    original.body["initial_funding"] = row.clone();
    raw["body"]["result"]["initial_funding"] = row;

    let (result, owner) = decode(&original, &raw);

    result.unwrap();
    let history = owner.borrowed_history_data();
    assert_eq!(
        history
            .request
            .unwrap()
            .initial_funding
            .requested_peak_data()
            .unwrap(),
        u64::MAX
    );
    assert!(owner.retained_requested_bytes_data().unwrap() <= history.requested_storage[0]);
}
