//! Compares borrowed representation checks with the unchanged owned SDK codec.

use super::super::BootData;
use super::*;
use crucible_node_format::canonical;
use serde::Deserialize;
use serde_json::json;

fn boot() -> Value {
    json!({
        "schema": "inert-boot-schema",
        "private_key": Bytes::new(vec![7; 32]),
        "birth_id": Bytes::new(vec![9; 32]),
        "source_birth": {"retained": [null, {"payload": "source"}]},
        "expected_host_registration": [null, {"payload": "host"}],
        "private_launch": "private-launch",
        "host_executable": canonical::content_ref(b"inert", "application/test").unwrap(),
    })
}

fn agrees(value: &Value) {
    assert_eq!(
        inspect_data(value).is_ok(),
        BootData::deserialize(value).is_ok(),
        "borrowed shape differs from the owned SDK codec: {value}"
    );
}

#[test]
fn boot_shape_acceptance_matches_owned_fields_without_authenticating_data() {
    let original = boot();
    agrees(&original);
    let copied = inspect_data(&original).unwrap().copy_data().unwrap();
    let decoded = BootData::deserialize(&original).unwrap();
    assert_eq!(copied.schema, decoded.schema);
    assert_eq!(copied.private_key, decoded.private_key);
    assert_eq!(copied.birth_id, decoded.birth_id);
    assert_eq!(copied.private_launch, decoded.private_launch);
    assert_eq!(copied.host_executable, decoded.host_executable);
    assert_eq!(copied.source_birth, decoded.source_birth);
    assert_eq!(
        copied.expected_host_registration,
        decoded.expected_host_registration
    );

    let alternatives = [
        Value::Null,
        json!(true),
        json!(0),
        json!(""),
        json!("text"),
        json!([]),
        json!({}),
    ];

    for field in BOOT_FIELDS {
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove(field);
        agrees(&missing);

        for alternative in &alternatives {
            let mut changed = original.clone();
            changed[field] = alternative.clone();
            agrees(&changed);
        }
    }
    for field in CONTENT_FIELDS {
        let mut missing = original.clone();
        missing["host_executable"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        agrees(&missing);

        for alternative in &alternatives {
            let mut changed = original.clone();
            changed["host_executable"][field] = alternative.clone();
            agrees(&changed);
        }
    }
    for field in HASH_FIELDS {
        let mut missing = original.clone();
        missing["host_executable"]["hash"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        agrees(&missing);

        for alternative in &alternatives {
            let mut changed = original.clone();
            changed["host_executable"]["hash"][field] = alternative.clone();
            agrees(&changed);
        }
    }

    for path in ["", "/host_executable", "/host_executable/hash"] {
        let mut unknown = original.clone();
        unknown
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), Value::Null);
        agrees(&unknown);
    }
    for decimal in [
        "0",
        "00",
        "01",
        "10",
        "-0",
        "+1",
        "1 ",
        "1.0",
        "1e0",
        "١",
        "18446744073709551615",
        "18446744073709551616",
    ] {
        let mut changed = original.clone();
        changed["host_executable"]["length"] = json!(decimal);
        agrees(&changed);
    }
    for identifier in [
        "x".repeat(128),
        "x".repeat(129),
        "_invalid".into(),
        "a b".into(),
    ] {
        let mut changed = original.clone();
        changed["private_launch"] = json!(identifier);
        agrees(&changed);
    }

    // These strings are deliberately not validated hashes or a boot schema.
    // Representation inspection must leave those genuine checks to the owner.
    let mut inert = original;
    inert["host_executable"]["hash"] = json!({
        "algorithm": "untrusted", "domain": "untrusted", "digest": "untrusted"
    });
    agrees(&inert);
    assert!(inspect_data(&inert).is_ok());
}

#[test]
fn byte_quanta_match_the_sdk_for_every_ascii_symbol_and_partial_tail() {
    let agrees = |encoded: &str| {
        assert_eq!(
            octets(encoded).is_ok(),
            Bytes::deserialize(&Value::String(encoded.into())).is_ok(),
            "base64 acceptance differs for {encoded:?}"
        );
    };

    agrees("");
    for length in 1..=12 {
        for offset in 0..length {
            for symbol in 0..=127 {
                let mut bytes = vec![b'A'; length];
                bytes[offset] = symbol;
                agrees(std::str::from_utf8(&bytes).unwrap());
            }
        }
    }
    for length in [1, 2, 3, 4, 31, 32, 33, 63, 64, 65, 255, 256, 257, 1024] {
        let bytes = vec![0xfb; length];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        agrees(&encoded);

        for offset in [0, encoded.len() / 2, encoded.len() - 1] {
            let mut damaged = encoded.as_bytes().to_vec();
            damaged[offset] = b'!';
            agrees(std::str::from_utf8(&damaged).unwrap());
        }
    }
    for encoded in ["AA==", "AAA=", "+///", "é", "AAAAé", "AA\nAA"] {
        agrees(encoded);
    }
}

#[test]
fn original_boot_copies_opaque_json_literally_without_a_second_parser() {
    for literal in [
        json!({"$serde_json::private::RawValue": "not JSON"}),
        json!({"$serde_json::private::RawValue": "17"}),
        json!({"$serde_json::private::Number": "not a number"}),
        json!([{"nested": {"$serde_json::private::RawValue": "{"}}]),
    ] {
        let mut value = boot();
        value["source_birth"] = literal.clone();
        value["expected_host_registration"] = literal.clone();

        let data = inspect_data(&value).unwrap().copy_data().unwrap();
        drop(value);

        assert_eq!(data.source_birth, literal);
        assert_eq!(data.expected_host_registration, literal);
        assert_eq!(data.private_key.as_slice(), &[7; 32]);
        assert_eq!(data.birth_id.as_slice(), &[9; 32]);
        assert_eq!(data.private_launch.as_str(), "private-launch");
        assert_eq!(data.schema, "inert-boot-schema");
    }
}
