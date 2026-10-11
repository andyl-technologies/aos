//! Numeric version and phase interoperability across direct and strict decoding.

// crucible-lint: allow panic-shortcut -- These version numbers tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use crucible_node_contract::{Phase, Position, SchemaRef, Validate, Version, canonical};
use serde::Deserialize;

#[derive(Deserialize)]
struct VersionRecord {
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    version: Version,
}

#[test]
fn version_numbers_accept_integral_notations_without_changing_identity() {
    let definition = serde_json::to_string(
        &canonical::content_ref(b"schema definition", "application/json").unwrap(),
    )
    .unwrap();
    for (expected, tokens) in [
        (1, ["1", "1.0", "1e0", "10e-1"]),
        (65_535, ["65535", "65535.0", "65535e0", "655350e-1"]),
    ] {
        let mut previous_identity = None;
        for token in tokens {
            let json = format!(
                "{{\"id\":\"schema/test\",\"version\":{token},\"definition\":{definition},\"extensions\":{{}}}}"
            );
            let direct: SchemaRef = serde_json::from_str(&json).unwrap();
            let strict: SchemaRef = canonical::decode(json.as_bytes(), 4096).unwrap();
            assert_eq!(direct.version, expected, "direct {token}");
            assert_eq!(strict, direct, "strict {token}");

            let identity = canonical::json_hash("cnp.schema-test.v1", &strict).unwrap();
            if let Some(previous) = &previous_identity {
                assert_eq!(previous, &identity, "identity changed for {token}");
            }
            previous_identity = Some(identity);
        }
    }
}

#[test]
fn version_numbers_reject_fractions_negative_values_and_range_excess() {
    for token in [
        "1.5",
        "1e-1",
        "-1",
        "-1.0",
        "-1e0",
        "65536",
        "65536.0",
        "6.5536e4",
        "18446744073709551615",
        "1e300",
        "1e400",
        "\"1\"",
        "true",
        "null",
    ] {
        let json = format!("{{\"version\":{token}}}");
        assert!(
            serde_json::from_str::<VersionRecord>(&json).is_err(),
            "accepted {token}"
        );
    }
    for token in ["0", "0.0", "0e0", "-0.0"] {
        let json = format!("{{\"version\":{token}}}");
        assert_eq!(
            serde_json::from_str::<VersionRecord>(&json)
                .unwrap()
                .version,
            0
        );
    }

    let definition = canonical::content_ref(b"schema", "application/json").unwrap();
    let schema = SchemaRef {
        id: crucible_node_contract::Id::new("schema/test").unwrap(),
        version: 0,
        definition,
        extensions: Default::default(),
    };
    assert!(
        schema.validate().is_err(),
        "positive editions still reject zero"
    );
}

#[test]
fn phases_accept_integral_notations_but_keep_the_closed_baseline_range() {
    for (expected, tokens) in [
        (Phase::BoundaryControl, ["0", "0.0", "0e0"]),
        (Phase::Publication, ["1", "1.0", "1e0"]),
        (Phase::Delivery, ["2", "2.0", "2e0"]),
        (Phase::Reaction, ["3", "3.0", "3e0"]),
    ] {
        for token in tokens {
            assert_eq!(serde_json::from_str::<Phase>(token).unwrap(), expected);
            let json = format!("{{\"time_ps\":\"50\",\"microstep\":\"0\",\"phase\":{token}}}");
            let direct: Position = serde_json::from_str(&json).unwrap();
            let strict: Position = canonical::decode(json.as_bytes(), 4096).unwrap();
            assert_eq!(direct.phase, expected);
            assert_eq!(strict, direct);
        }
    }
    for token in ["-1", "0.5", "4", "4.0", "4e0", "65536.0", "\"1\""] {
        assert!(
            serde_json::from_str::<Phase>(token).is_err(),
            "accepted phase {token}"
        );
        let json = format!("{{\"time_ps\":\"50\",\"microstep\":\"0\",\"phase\":{token}}}");
        assert!(canonical::decode::<Position>(json.as_bytes(), 4096).is_err());
    }
}
