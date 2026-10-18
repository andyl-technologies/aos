//! Exercises retained concrete owners after later data-only decoding failures.

use super::*;
use crate::protocol_snapshot::owned11::{
    json_value::HistoricalJsonLimits,
    typed::{HistoricalType, Ledger, historical_struct, invalid},
};
use crate::retained_metadata::records::{
    MetadataCapacityRecord, MetadataRecordKind, ValidatedMetadataRecords,
};
use std::mem::{align_of, size_of};

fn limits() -> HistoricalJsonLimits {
    HistoricalJsonLimits {
        maximum_input_bytes: 4096,
        maximum_nodes: 100,
        maximum_depth: 16,
        maximum_owned_backing_bytes: 1 << 20,
        maximum_tree_entries: 100,
    }
}

fn string_row(capacity: usize) -> MetadataCapacityRecord {
    MetadataCapacityRecord {
        kind: MetadataRecordKind::String,
        extent: capacity,
        element_bytes: 1,
        alignment: 1,
    }
}

fn facts<T: Native17Build>(
    attempt: &T::Attempt,
) -> crate::retained_metadata::RetainedProtocolMetadataFacts {
    let mut observer = MetadataObserver::new();
    T::observe_attempt_data(attempt, &mut observer).unwrap();
    observer.finish()
}

#[test]
fn later_vector_child_failure_keeps_earlier_string_and_both_attempt_slots() {
    let rows = serde_json::to_vec(&[
        MetadataCapacityRecord {
            kind: MetadataRecordKind::Vector,
            extent: 4,
            element_bytes: size_of::<String>(),
            alignment: align_of::<String>(),
        },
        string_row(37),
    ])
    .unwrap();
    let records = ValidatedMetadataRecords::validate(&rows, 8, 1 << 20).unwrap();
    let mut ledger = Ledger::new(records.rows(), limits());
    let mut attempt = <Vec<String> as Native17Build>::Attempt::default();

    assert!(
        Vec::<String>::read_into_data(br#"["first","second"]"#, &mut ledger, &mut attempt).is_err()
    );

    assert!(Vec::<String>::output_data(&attempt).is_none());
    let retained = facts::<Vec<String>>(&attempt);
    assert_eq!(retained.string_capacity_bytes, 37);
    assert_eq!(
        retained.vector_capacity_bytes,
        4 * size_of::<String>() + 2 * size_of::<<String as Native17Build>::Attempt>()
    );
    assert!(Vec::<String>::read_into_data(b"[]", &mut ledger, &mut attempt).is_err());
    assert_eq!(facts::<Vec<String>>(&attempt), retained);
}

struct TwoFields {
    first: String,
    second: String,
}

historical_struct!(TwoFields {
    first: String,
    second: String
});
native17_struct!(TwoFields {
    first: String,
    second: String
});

#[test]
fn object_suffix_failure_preserves_completed_field_outputs() {
    let rows = serde_json::to_vec(&[string_row(29), string_row(43)]).unwrap();
    let records = ValidatedMetadataRecords::validate(&rows, 8, 1 << 20).unwrap();
    let mut ledger = Ledger::new(records.rows(), limits());
    ledger
        .begin_native17_targets_data(limits().maximum_owned_backing_bytes)
        .unwrap();
    let mut attempt = <TwoFields as Native17Build>::Attempt::default();

    assert!(
        TwoFields::read_into_data(
            br#"{"first":"one","second":"two","unexpected":true}"#,
            &mut ledger,
            &mut attempt
        )
        .is_err()
    );

    assert!(TwoFields::output_data(&attempt).is_none());
    assert_eq!(attempt.fields.head.output.as_deref(), Some("one"));
    assert_eq!(attempt.fields.tail.head.output.as_deref(), Some("two"));
    let retained = facts::<TwoFields>(&attempt);
    assert_eq!(retained.string_capacity_bytes, 72);
    assert_eq!(
        retained.vector_capacity_bytes,
        2 * size_of::<<String as Native17Build>::Attempt>()
    );
}

#[test]
fn vector_preflight_prices_retained_child_headers_before_allocation() {
    let rows = serde_json::to_vec(&[
        MetadataCapacityRecord {
            kind: MetadataRecordKind::Vector,
            extent: 3,
            element_bytes: size_of::<String>(),
            alignment: align_of::<String>(),
        },
        string_row(17),
    ])
    .unwrap();
    let records = ValidatedMetadataRecords::validate(&rows, 8, 1 << 20).unwrap();
    let mut ledger = Ledger::new(records.rows(), limits());
    ledger
        .begin_native17_targets_data(3 * size_of::<String>() + 17)
        .unwrap();

    assert!(Vec::<String>::preflight_data(br#"["one"]"#, &mut ledger).is_err());
}

#[test]
fn invalid_identifier_preserves_decoded_string_capacity() {
    let rows = serde_json::to_vec(&[string_row(61)]).unwrap();
    let records = ValidatedMetadataRecords::validate(&rows, 8, 1 << 20).unwrap();
    let mut ledger = Ledger::new(records.rows(), limits());
    let mut attempt = <crucible_node_contract::Id as Native17Build>::Attempt::default();

    assert!(
        crucible_node_contract::Id::read_into_data(
            br#""invalid space""#,
            &mut ledger,
            &mut attempt
        )
        .is_err()
    );

    assert!(crucible_node_contract::Id::output_data(&attempt).is_none());
    assert_eq!(
        facts::<crucible_node_contract::Id>(&attempt).string_capacity_bytes,
        61
    );
}

#[test]
fn extensions_roundtrip_keeps_actual_nested_backing_without_a_second_root_tree() {
    let mut key = String::with_capacity(31);
    key.push_str("data/key");
    let mut text = String::with_capacity(47);
    text.push_str("escaped \" café 😀");
    let mut values = Vec::with_capacity(7);
    values.push(serde_json::Value::String(text));
    let mut original = crucible_node_contract::Extensions::new();
    original.insert(key, serde_json::Value::Array(values));
    let mut bank = crate::retained_metadata::records::MetadataRecordBank::reserve(32).unwrap();
    let mut source = MetadataObserver::recording(&mut bank);
    source.observe(&original).unwrap();
    let source_facts = source.finish();
    let encoded = serde_json::to_vec(&original).unwrap();
    let rows = serde_json::to_vec(&bank).unwrap();
    let records = ValidatedMetadataRecords::validate(&rows, 32, 1 << 20).unwrap();
    let mut ledger = Ledger::new(records.rows(), limits());
    let mut attempt = <crucible_node_contract::Extensions as Native17Build>::Attempt::default();

    crucible_node_contract::Extensions::read_into_data(&encoded, &mut ledger, &mut attempt)
        .unwrap();

    let restored = crucible_node_contract::Extensions::output_data(&attempt).unwrap();
    assert_eq!(serde_json::to_vec(restored).unwrap(), encoded);
    let retained = facts::<crucible_node_contract::Extensions>(&attempt);
    assert_eq!(
        retained.string_capacity_bytes,
        source_facts.string_capacity_bytes
    );
    assert_eq!(
        retained.vector_capacity_bytes,
        source_facts.vector_capacity_bytes
    );
    assert_eq!(retained.tree_containers, source_facts.tree_containers);
    assert_eq!(retained.tree_entries, source_facts.tree_entries);
    assert!(ledger.rows.next().is_none());
}

#[test]
fn object_child_credit_failure_precedes_child_reservation() {
    let rows = serde_json::to_vec(&[string_row(29), string_row(43)]).unwrap();
    let records = ValidatedMetadataRecords::validate(&rows, 8, 1 << 20).unwrap();
    let mut ledger = Ledger::new(records.rows(), limits());
    ledger.begin_native17_targets_data(1).unwrap();
    let mut attempt = <TwoFields as Native17Build>::Attempt::default();

    assert!(
        TwoFields::read_into_data(
            br#"{"first":"one","second":"two"}"#,
            &mut ledger,
            &mut attempt,
        )
        .is_err()
    );

    assert!(attempt.fields.head.child.child_data().is_none());
    assert!(attempt.fields.head.output.is_none());
    let retained = facts::<TwoFields>(&attempt);
    assert_eq!(retained.vector_capacity_bytes, 0);
    assert_eq!(retained.string_capacity_bytes, 0);
}

#[test]
fn object_child_banks_match_preflight_and_survive_output_transfer() {
    let input = br#"{"first":"one","second":"two"}"#;
    let rows = serde_json::to_vec(&[string_row(29), string_row(43)]).unwrap();
    let records = ValidatedMetadataRecords::validate(&rows, 8, 1 << 20).unwrap();
    let child_backing = 2 * size_of::<<String as Native17Build>::Attempt>();
    let maximum = 29 + 43 + child_backing;
    let mut preflight = Ledger::new(records.rows(), limits());
    preflight.begin_native17_targets_data(maximum).unwrap();
    preflight.native17_target_embedded_root_data().unwrap();

    TwoFields::preflight_data(input, &mut preflight).unwrap();
    assert_eq!(preflight.finish_native17_targets_data().unwrap(), maximum);

    let mut ledger = Ledger::new(records.rows(), limits());
    ledger.begin_native17_targets_data(maximum).unwrap();
    ledger.native17_target_embedded_root_data().unwrap();
    let mut attempt = <TwoFields as Native17Build>::Attempt::default();
    TwoFields::read_into_data(input, &mut ledger, &mut attempt).unwrap();
    assert_eq!(ledger.finish_native17_targets_data().unwrap(), maximum);

    let output = TwoFields::take_output_data(&mut attempt).unwrap();
    assert_eq!(output.first, "one");
    assert_eq!(output.second, "two");
    let residual = facts::<TwoFields>(&attempt);
    assert_eq!(residual.vector_capacity_bytes, child_backing);
    assert_eq!(residual.string_capacity_bytes, 0);
}

#[test]
fn object_child_bank_requires_an_independently_admitted_target_ledger() {
    let rows = serde_json::to_vec(&[string_row(29), string_row(43)]).unwrap();
    let records = ValidatedMetadataRecords::validate(&rows, 8, 1 << 20).unwrap();
    let mut ledger = Ledger::new(records.rows(), limits());
    let mut attempt = <TwoFields as Native17Build>::Attempt::default();

    assert!(
        TwoFields::read_into_data(
            br#"{"first":"one","second":"two"}"#,
            &mut ledger,
            &mut attempt,
        )
        .is_err()
    );

    assert!(attempt.fields.head.child.child_data().is_none());
    assert_eq!(facts::<TwoFields>(&attempt).vector_capacity_bytes, 0);
    assert_eq!(facts::<TwoFields>(&attempt).string_capacity_bytes, 0);
}
