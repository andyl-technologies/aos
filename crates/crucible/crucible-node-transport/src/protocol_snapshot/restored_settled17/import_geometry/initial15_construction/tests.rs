//! Exercises real prewalk bounds and failure custody without fabricating a native owner.

use super::*;
use crate::{
    client::{compact_cursor::CompactContentLimits, compact_metadata8::CompactMetadata8Limits},
    protocol_snapshot::owned11::json_value::HistoricalJsonLimits,
};
use crucible_node_format::canonical;

fn decoder_limits() -> OwnedProtocol11DataLimits {
    OwnedProtocol11DataLimits {
        json: HistoricalJsonLimits {
            maximum_input_bytes: 65_536,
            maximum_nodes: 4096,
            maximum_depth: 64,
            maximum_owned_backing_bytes: 65_536,
            maximum_tree_entries: 4096,
        },
        content: CompactMetadata8Limits {
            content: CompactContentLimits {
                max_input_bytes: 65_536,
                max_rows: 64,
                max_groups: 64,
                max_first_group_capacity_bytes: 65_536,
            },
            maximum_metadata_capacity_bytes: 65_536,
        },
        maximum_metadata_rows: 64,
        maximum_literal_backing_bytes: 65_536,
    }
}

fn inputs<'a>(
    protocol_reference: &'a ContentRef,
    protocol: &'a [u8],
    empty_reference: &'a ContentRef,
) -> RestoredSettledNative17Input<'a> {
    RestoredSettledNative17Input {
        snapshot: (empty_reference, b"{}"),
        current_protocol: (protocol_reference, protocol),
        control: (empty_reference, b"{}"),
        anchor: (empty_reference, b"{}"),
        journal: (empty_reference, b"{}"),
    }
}

fn import_limits() -> RestoredSettledNative17Limits {
    RestoredSettledNative17Limits::new([65_536; 5], 65_536, 16, 16, 4096, 1_048_576).unwrap()
}

#[test]
fn real_alias_prewalk_counts_first_groups_without_minting_a_validated_plan() {
    let aliases = br#"[["registrar-epoch",0],["registrar-gate",1],["registrar-epoch",0]]"#;
    assert_eq!(required_summary_entries_data(aliases, 3).unwrap(), 2);
    assert!(required_summary_entries_data(aliases, 2).is_err());
    assert!(required_summary_entries_data(br#"[["registrar-epoch",1]]"#, 3).is_err());
    assert!(required_summary_entries_data(br#"[["unknown-role",0]]"#, 3).is_err());

    // Full kind/view equality is deliberately left to the defining validator.
    // Counting this malformed reused group cannot return a validated owner.
    assert_eq!(
        required_summary_entries_data(br#"[["registrar-epoch",0],["registrar-gate",0]]"#, 3)
            .unwrap(),
        1,
    );
}

#[test]
fn constructor_quote_checks_actual_function_boundary_and_both_fixed_axes() {
    // This syntax-only native body permits a prequote; it is NOT a complete
    // native15 graph and the actual existing validator must refuse it below.
    let protocol = br#"["source-private.cnp-protocol/11",null,[],[["registrar-epoch",0],["registrar-gate",1]]]"#;
    let protocol_reference = canonical::content_ref(protocol, "application/json").unwrap();
    let empty_reference = canonical::content_ref(b"{}", "application/json").unwrap();
    let input = inputs(&protocol_reference, protocol, &empty_reference);
    let quote = Initial15NativeImportGeometryConstructionData::quote_data(
        &input,
        decoder_limits(),
        import_limits(),
        4096,
        usize::MAX,
    )
    .unwrap();
    let [retained, transient, scratch] = quote.requested_axes_data();
    assert_eq!(transient, 0);
    assert_eq!(quote.summary_entries, 2);
    assert_eq!(
        retained,
        size_of::<Initial15NativeImportGeometryAttempt>() + 2 * size_of::<HistoricalAliasSummary>()
    );
    assert_eq!(
        scratch,
        Initial15NativeImportGeometryConstructionData::counter_scratch_data()
    );
    let peak = retained.checked_add(scratch).unwrap();
    let exact = Initial15NativeImportGeometryConstructionData::quote_data(
        &input,
        decoder_limits(),
        import_limits(),
        4096,
        peak,
    )
    .unwrap();
    assert_eq!(exact.requested_axes_data(), quote.requested_axes_data());
    assert!(
        Initial15NativeImportGeometryConstructionData::quote_data(
            &input,
            decoder_limits(),
            import_limits(),
            4096,
            peak - 1,
        )
        .is_err()
    );
    for maximum in [0, retained, scratch] {
        assert!(
            Initial15NativeImportGeometryConstructionData::quote_data(
                &input,
                decoder_limits(),
                import_limits(),
                4096,
                maximum,
            )
            .is_err()
        );
    }
}

#[test]
fn actual_validator_refusal_retains_allocated_aliases_and_never_lends_geometry() {
    let protocol = br#"["source-private.cnp-protocol/11",null,[],[["registrar-epoch",0],["registrar-gate",1]]]"#;
    let protocol_reference = canonical::content_ref(protocol, "application/json").unwrap();
    let empty_reference = canonical::content_ref(b"{}", "application/json").unwrap();
    let input = inputs(&protocol_reference, protocol, &empty_reference);
    let quote = Initial15NativeImportGeometryConstructionData::quote_data(
        &input,
        decoder_limits(),
        import_limits(),
        4096,
        usize::MAX,
    )
    .unwrap();
    let mut destination = None;
    assert!(quote.construct_into_data(&input, &mut destination).is_err());
    let failed = destination.as_ref().unwrap();
    assert!(!failed.complete);
    assert_eq!(failed.summaries.len(), 2);
    assert_eq!(failed.summaries.capacity(), 2);
    assert_eq!(
        failed
            .retained_requested_storage_data(quote.retained)
            .unwrap(),
        quote.retained
    );
    assert!(
        failed
            .retained_requested_storage_data(quote.retained - 1)
            .is_err()
    );
    assert!(failed.geometry_data(&input).is_err());
    assert!(quote.construct_into_data(&input, &mut destination).is_err());
    assert_eq!(destination.as_ref().unwrap().summaries.capacity(), 2);
}

#[test]
fn changed_full_role_is_retained_before_failure_without_allocating_alias_bank() {
    let protocol = br#"["source-private.cnp-protocol/11",null,[],[]]"#;
    let protocol_reference = canonical::content_ref(protocol, "application/json").unwrap();
    let empty_reference = canonical::content_ref(b"{}", "application/json").unwrap();
    let original = inputs(&protocol_reference, protocol, &empty_reference);
    let quote = Initial15NativeImportGeometryConstructionData::quote_data(
        &original,
        decoder_limits(),
        import_limits(),
        4096,
        usize::MAX,
    )
    .unwrap();

    let changed_bytes = br#"["source-private.cnp-protocol/11",true,[],[]]"#;
    assert_eq!(changed_bytes.len(), protocol.len());
    let changed_reference = canonical::content_ref(changed_bytes, "application/json").unwrap();
    let changed = inputs(&changed_reference, changed_bytes, &empty_reference);
    let mut destination = None;
    assert!(
        quote
            .construct_into_data(&changed, &mut destination)
            .is_err()
    );
    let retained = destination.as_ref().unwrap();
    assert_eq!(retained.summaries.capacity(), 0);
    assert!(!retained.complete);
    assert!(retained.geometry.is_none());
    assert!(retained.geometry_data(&original).is_err());
    assert_eq!(retained.row.correspondence, quote.correspondence);
}
