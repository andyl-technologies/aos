//! Legacy byte-array compatibility and early unsupported-runtime refusal tests.

use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Deserialize, Deserializer, Serialize};

use super::decode_supported_coordinator;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyRecord {
    runtime: LegacyRuntime,
    payload: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyRuntime {
    schema_version: u16,
}

static TYPED_DECODES: AtomicUsize = AtomicUsize::new(0);

struct CountedRecord;

impl<'de> Deserialize<'de> for CountedRecord {
    fn deserialize<D: Deserializer<'de>>(_deserializer: D) -> Result<Self, D::Error> {
        TYPED_DECODES.fetch_add(1, Ordering::Relaxed);
        Err(serde::de::Error::custom("typed reconstruction reached"))
    }
}

#[test]
fn host_runtime_header_preserves_legacy_large_byte_arrays_and_literal_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    for version in 1..=4 {
        let literal = format!(
            "{{\"runtime\":{{\"schema_version\":{version}}},\"payload\":[{}]}}",
            std::iter::repeat_n("92", 65_537)
                .collect::<Vec<_>>()
                .join(",")
        );
        // The portable parser's array cap would reject this previously accepted
        // numeric byte buffer. The header probe must retain the raw legacy path.
        assert!(
            crucible_node_contract::canonical::parse_json(literal.as_bytes(), literal.len())
                .is_err()
        );
        let record: LegacyRecord = decode_supported_coordinator(literal.as_bytes())?;
        assert_eq!(record.runtime.schema_version, version);
        assert_eq!(record.payload, vec![92; 65_537]);
        assert_eq!(serde_json::to_string(&record)?, literal);
    }
    Ok(())
}

#[test]
fn host_runtime_header_refuses_six_before_typed_reconstruction_with_late_version() {
    TYPED_DECODES.store(0, Ordering::Relaxed);
    for version in ["6", "6.0", "6e0"] {
        let literal = format!(
            "{{\"scheduler\":{{\"opaque\":[{}]}},\"runtime\":{{\"inputs\":[{}],\"schema_version\":{version}}}}}",
            std::iter::repeat_n("0", 65_537)
                .collect::<Vec<_>>()
                .join(","),
            std::iter::repeat_n("null", 65_537)
                .collect::<Vec<_>>()
                .join(",")
        );
        let result = decode_supported_coordinator::<CountedRecord>(literal.as_bytes());
        assert!(result.is_err_and(|error| error.to_string().contains("condition runtime six")));
    }
    assert_eq!(TYPED_DECODES.load(Ordering::Relaxed), 0);
}

#[test]
fn host_runtime_header_keeps_closed_typed_legacy_rejection() {
    for literal in [
        "{\"runtime\":{\"schema_version\":1},\"payload\":[],\"unknown\":1}",
        "{\"runtime\":{\"schema_version\":1,\"unknown\":1},\"payload\":[]}",
        "{\"runtime\":{\"schema_version\":1,\"schema_version\":2},\"payload\":[]}",
        "{\"runtime\":{\"schema_version\":6,\"schema_version\":1},\"payload\":[]}",
    ] {
        assert!(decode_supported_coordinator::<LegacyRecord>(literal.as_bytes()).is_err());
    }
}
