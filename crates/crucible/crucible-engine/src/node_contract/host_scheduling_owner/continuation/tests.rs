//! Exercises inert codec correlations over actual core snapshots and modeled peers.

// Test panics identify corrupted fixture data; no native or live host capture is claimed.
#![allow(clippy::unwrap_used)]

use super::*;

fn limits() -> HostSchedulingContinuationLimits {
    HostSchedulingContinuationLimits {
        maximum_record_bytes: 2 * 1024 * 1024,
        lineage: OriginalInputLineageLimits::default(),
    }
}

fn encoded() -> Vec<u8> {
    let (_, runtime, activation) =
        crate::node_contract::runtime::host_continuation_runtime_fixture();
    let owner = super::super::tests::source_owner();
    let source = owner.source();
    let cut = Position::new(
        0.into(),
        0.into(),
        crucible_node_format::Phase::BoundaryControl,
    );
    let record = HostSchedulingContinuationRecord {
        schema_version: 2,
        source: source.selection().clone(),
        runtime: HostSchedulingRuntimeRecord::Legacy(Box::new(
            runtime
                .runtime_snapshot(cut, 7.into(), limits().maximum_record_bytes)
                .unwrap(),
        )),
        scheduling: runtime
            .retirement_scheduler_snapshot(&activation, cut, 7.into())
            .unwrap(),
        objects: vec![],
    };
    canonical::canonical_json(&serde_json::to_value(record).unwrap()).unwrap()
}

#[test]
fn portable_record_roundtrip_retains_complete_original_snapshot_pair() {
    let bytes = encoded();
    let record = HostSchedulingContinuationRecord::decode(&bytes, limits()).unwrap();
    assert_eq!(
        canonical::canonical_json(&serde_json::to_value(record).unwrap()).unwrap(),
        bytes
    );
}

#[test]
fn portable_record_refuses_changed_cut_ordinal_and_source_activation() {
    for variant in 0..3 {
        let mut value = canonical::parse_json(&encoded(), limits().maximum_record_bytes).unwrap();
        match variant {
            0 => value["scheduling"]["capture_cut"]["time_ps"] = json!("1"),
            1 => value["scheduling"]["capture_ordinal"] = json!("8"),
            _ => value["scheduling"]["source_activation_id"] = json!("foreign"),
        }
        let bytes = canonical::canonical_json(&value).unwrap();
        assert!(HostSchedulingContinuationRecord::decode(&bytes, limits()).is_err());
    }
}

#[test]
fn portable_record_refuses_unknown_nested_fields_and_new_editions() {
    for variant in 0..3 {
        let mut value = canonical::parse_json(&encoded(), limits().maximum_record_bytes).unwrap();
        match variant {
            0 => value["source"]["unexpected"] = json!(true),
            1 => value["runtime"]["unexpected"] = json!(true),
            _ => value["schema_version"] = json!(3),
        }
        let bytes = canonical::canonical_json(&value).unwrap();
        assert!(HostSchedulingContinuationRecord::decode(&bytes, limits()).is_err());
    }
}

#[test]
fn portable_record_refuses_one_byte_short_record_credit() {
    let bytes = encoded();
    let mut short = limits();
    short.maximum_record_bytes = bytes.len() - 1;
    assert!(HostSchedulingContinuationRecord::decode(&bytes, short).is_err());
    let mut exact = limits();
    exact.maximum_record_bytes = bytes.len();
    assert!(HostSchedulingContinuationRecord::decode(&bytes, exact).is_ok());
}
