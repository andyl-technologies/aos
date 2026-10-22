//! Exercises raw grammar DATA without constructing an opaque Source owner.

use super::*;

fn operands() -> (Envelope, Value) {
    super::super::tests::operands()
}

#[test]
fn maximum_ascii_ids_escaped_fields_and_large_whitespace_preserve_closed_spelling() {
    let (original, mut response) = operands();
    let funding = response["body"]["result"]["initial_funding"]
        .as_object_mut()
        .unwrap();
    funding.insert(
        "retained_requested_bytes".into(),
        Value::String((u64::MAX - 2).to_string()),
    );
    funding.insert(
        "maximum_simultaneous_transient_bytes".into(),
        Value::String("1".into()),
    );
    funding.insert(
        "declared_counter_scratch_bytes".into(),
        Value::String("1".into()),
    );
    for raw in [
        serde_json::to_vec(&response).unwrap(),
        serde_json::to_vec_pretty(&response).unwrap(),
    ] {
        native_import18_bootstrap_raw_preflight_data(&original, &raw).unwrap();
    }

    let raw = serde_json::to_vec(&response).unwrap();
    let mut escaped = vec![b' '; 100_000];
    let mut quoted = false;
    for byte in raw {
        if byte == b'"' {
            quoted = !quoted;
            escaped.push(byte);
        } else if quoted {
            escaped.extend_from_slice(format!("\\u{byte:04x}").as_bytes());
        } else {
            escaped.push(byte);
        }
    }
    escaped.extend_from_slice(b"\r\n\t ");
    native_import18_bootstrap_raw_preflight_data(&original, &escaped).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&escaped).unwrap(), response);
}

#[test]
fn unknown_duplicate_expanded_and_wrong_closed_fields_refuse_before_dom_construction() {
    let (original, response) = operands();
    let paths = [
        ("/protocol", Value::String("CNP/2".into())),
        ("/sequence", Value::String("3".into())),
        ("/node_id", Value::String("unexpected".into())),
        ("/request_id", Value::String("r".repeat(MAX_ID_BYTES + 1))),
        ("/request_id", Value::String("other".into())),
        ("/body", serde_json::json!([])),
        ("/body/extensions", serde_json::json!({"extra": null})),
        ("/body/result/state", Value::String("ready".into())),
        (
            "/body/result/recipe_identity",
            Value::String("!".repeat(43)),
        ),
        (
            "/body/result/initial_funding/retained_requested_bytes",
            Value::String("01".into()),
        ),
        (
            "/body/result/initial_funding/retained_requested_bytes",
            Value::String("18446744073709551616".into()),
        ),
        (
            "/body/result/initial_funding/retained_requested_bytes",
            Value::String("-1".into()),
        ),
    ];
    for (path, changed) in paths {
        let mut value = response.clone();
        *value.pointer_mut(path).unwrap() = changed;
        assert!(
            native_import18_bootstrap_raw_preflight_data(
                &original,
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err(),
            "{path}"
        );
    }
    let raw = serde_json::to_string(&response).unwrap();
    for replacement in [
        "\"protocol\":\"CNP/1\",\"protocol\":\"CNP/1\"",
        "\"protocol\":\"CNP/1\",\"\\u0070rotocol\":\"CNP/1\"",
        "\"unknown\":null,\"protocol\":\"CNP/1\"",
    ] {
        let changed = raw.replace("\"protocol\":\"CNP/1\"", replacement);
        assert!(
            native_import18_bootstrap_raw_preflight_data(&original, changed.as_bytes()).is_err()
        );
    }
}

#[test]
fn every_incomplete_prefix_and_invalid_escape_refuses() {
    let (original, response) = operands();
    let raw = serde_json::to_string(&response).unwrap();
    for end in 0..raw.len() {
        assert!(
            native_import18_bootstrap_raw_preflight_data(&original, &raw.as_bytes()[..end])
                .is_err(),
            "prefix {end}"
        );
    }
    for replacement in ["\\u00g0", "\\uD800\\uDC00", "\\u0080", "\\x43", "CNP/1\n"] {
        let changed = raw.replace("CNP/1", replacement);
        assert!(
            native_import18_bootstrap_raw_preflight_data(&original, changed.as_bytes()).is_err(),
            "escape {replacement}"
        );
    }
    let trailing = raw + " null";
    assert!(native_import18_bootstrap_raw_preflight_data(&original, trailing.as_bytes()).is_err());
}

#[test]
fn oversized_keys_and_scalars_stop_at_the_fixed_decoded_window() {
    let (original, _) = operands();
    for prefix in ["{\"", "{\"protocol\":\""] {
        let raw = prefix.to_string() + &"x".repeat(100_000);
        let mut scanner = Scanner {
            original: &original,
            input: raw.as_bytes(),
            position: 0,
        };

        assert!(scanner.object(Object::Envelope).is_err());

        assert!(scanner.position <= prefix.len() + MAX_ID_BYTES + 1);
    }
    assert!(
        native_import18_bootstrap_raw_preflight_counter_scratch_data() >= 7 * size_of::<Ascii>()
    );
}
