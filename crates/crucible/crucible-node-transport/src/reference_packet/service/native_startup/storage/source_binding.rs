//! Uses the sole shared closed Source-base occurrence calculation.

pub(super) use crucible_source_birth_data::profile::reference_packet::service::native_startup::source_binding::{
    SourceBindingStorage, project, project_invocation,
};

#[cfg(test)]
const BASE: [&[u8]; 9] = [
    b"selection",
    b"program",
    b"coordinator",
    b"limits",
    b"storage",
    b"capture_profile",
    b"confirmation_selection",
    b"ack_emitter_selection",
    b"codec_metadata_extent",
];
#[cfg(test)]
const EXTRA: [&[u8]; 9] = [
    b"schema",
    b"native_codec_metadata_extent",
    b"protocol_metadata_limits",
    b"complete_restore_selection",
    b"restore_input_emitter_selection",
    b"capture_allocation_selection",
    b"fresh_restore_allocation_selection",
    b"report_startup_allocation",
    b"native_startup_allocation",
];

#[cfg(test)]
mod invocation_tests {
    use super::*;
    use crucible_node_format::canonical;
    use serde_json::json;

    // Closed inert field occurrences exercise the census, not a typed launch,
    // Source member, parser authority or semantic binding.
    fn source(schema: &str) -> serde_json::Value {
        let mut value = serde_json::Map::new();
        for name in BASE.into_iter().chain(EXTRA) {
            value.insert(
                std::str::from_utf8(name).unwrap().into(),
                serde_json::Value::Null,
            );
        }
        value.insert("schema".into(), json!(schema));
        serde_json::Value::Object(value)
    }

    #[test]
    fn invocation_source_census_keeps_legacy_roster_and_exact_unchanged_base() {
        let old = source("source-owned.packet-canonical-ack-source-binding/14");
        let old = canonical::canonical_json(&old).unwrap();
        let legacy = project(&old, usize::MAX).unwrap();
        assert!(project_invocation(&old, usize::MAX).is_err());

        let mut current = source("source-owned.packet-canonical-ack-source-binding/15");
        current["invocation"] = json!({"inert_occurrence":true});
        let encoded = canonical::canonical_json(&current).unwrap();
        let selected = project_invocation(&encoded, usize::MAX).unwrap();
        assert_eq!(selected.base_encoded_bytes, legacy.base_encoded_bytes);
        assert_eq!(selected.base_decoded_bytes, legacy.base_decoded_bytes);
        assert_eq!(
            selected.base_value_backing_bytes,
            legacy.base_value_backing_bytes
        );
        assert!(project(&encoded, usize::MAX).is_err());

        for name in [
            "invocation",
            "schema",
            "native_startup_allocation",
            "selection",
        ] {
            let mut changed = current.clone();
            changed.as_object_mut().unwrap().remove(name);
            assert!(
                project_invocation(&canonical::canonical_json(&changed).unwrap(), usize::MAX)
                    .is_err()
            );
        }
        current["foreign"] = json!(null);
        assert!(
            project_invocation(&canonical::canonical_json(&current).unwrap(), usize::MAX).is_err()
        );
    }
}
