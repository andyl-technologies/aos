//! Exercises explicit17 alias dispatch with captured DATA backing identities.

#![cfg(test)]

use super::*;
use crate::client::compact_cursor::{ContentGroupEdge, ContentGroupKind};
use crate::protocol_snapshot::owned11::aliases::{
    HistoricalAliasSummary, ValidatedHistoricalAliases,
};
use crate::protocol_snapshot::restored_settled17::aliases::{
    RestoredSettledNative17AliasSummary, ValidatedRestoredSettledNative17Aliases,
};
use crate::retained_metadata::MetadataObserver;
use crate::retained_metadata::aliases::{MetadataAliasBank, MetadataSharedKind};
use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};
use std::rc::Rc;
use std::sync::Arc;

fn limits() -> HistoricalJsonLimits {
    HistoricalJsonLimits {
        maximum_input_bytes: 1024,
        maximum_nodes: 32,
        maximum_depth: 8,
        maximum_owned_backing_bytes: 1024,
        maximum_tree_entries: 0,
    }
}

fn capture_roots(kind: MetadataSharedKind) -> Vec<u8> {
    let first = Rc::new(Vec::<u8>::with_capacity(19));
    let alias = first.clone();
    let distinct = Rc::new(Vec::<u8>::with_capacity(19));
    let mut bank = MetadataAliasBank::reserve(3).unwrap();
    for owner in [&first, &alias, &distinct] {
        bank.retain(kind, owner.as_ref()).unwrap();
    }
    bank.finish_lookup();
    serde_json::to_vec(&bank).unwrap()
}

#[test]
fn native_rc_aliases_preserve_equal_distinct_groups_and_failed_replay() {
    let input = capture_roots(MetadataSharedKind::NativeRestoredPhysicalHold);
    assert_eq!(
        input,
        br#"[["native-restored-physical-hold",0],["native-restored-physical-hold",0],["native-restored-physical-hold",1]]"#,
    );
    let mut old = [HistoricalAliasSummary::default(); 2];
    assert!(ValidatedHistoricalAliases::validate(&input, &mut old, 3).is_err());

    let mut summaries = [RestoredSettledNative17AliasSummary::default(); 2];
    let mut plan =
        ValidatedRestoredSettledNative17Aliases::validate(&input, &mut summaries, 3).unwrap();
    let records = ValidatedMetadataRecords::validate(b"[]", 0, 0).unwrap();
    let mut ledger = Ledger::new(records.rows(), limits());
    ledger.settled_aliases = Some(plan.views().unwrap());

    for expected in [0, 0, 1] {
        let group = ledger
            .shared_begin(MetadataSharedKind::NativeRestoredPhysicalHold)
            .unwrap();
        assert_eq!(group, expected);
        ledger
            .shared_finish(group, 24, b"historical-data", b"capacity-19")
            .unwrap();
    }
    ledger.finish_aliases().unwrap();
    drop(ledger);

    // A successful pass allows replay but cannot erase its first-view digest.
    let mut ledger = Ledger::new(records.rows(), limits());
    ledger.settled_aliases = Some(plan.views().unwrap());
    assert!(
        ledger
            .shared(
                MetadataSharedKind::NativeRestoredPhysicalHold,
                24,
                b"changed-data",
                b"capacity-19",
            )
            .is_err()
    );
    assert!(ledger.finish_aliases().is_err());
    drop(ledger);
    assert!(plan.views().is_err());
    drop(plan);
    assert!(ValidatedRestoredSettledNative17Aliases::validate(&input, &mut summaries, 3).is_err());
}

#[test]
fn typed_selected_slice_child_uses_the_same_explicit17_groups() {
    let first: Arc<[crucible_node_format::ExtensionSelection]> = Arc::from([]);
    let alias = first.clone();
    let distinct: Arc<[crucible_node_format::ExtensionSelection]> = Arc::from([]);
    let mut bank = MetadataAliasBank::reserve(3).unwrap();
    let mut source_records = MetadataRecordBank::reserve(3).unwrap();
    let mut observer = MetadataObserver::recording_with_aliases(&mut source_records, &mut bank);
    for owner in [&first, &alias, &distinct] {
        observer
            .shared_original(MetadataSharedKind::SelectedExtensions, owner.as_ref())
            .unwrap();
    }
    observer.finish();
    bank.finish_lookup();
    let input = serde_json::to_vec(&bank).unwrap();
    let mut summaries = [RestoredSettledNative17AliasSummary::default(); 2];
    let mut plan =
        ValidatedRestoredSettledNative17Aliases::validate(&input, &mut summaries, 3).unwrap();
    let encoded_records = serde_json::to_vec(&source_records).unwrap();
    let records = ValidatedMetadataRecords::validate(&encoded_records, 3, 0).unwrap();
    let mut selected = [None, None];
    let mut ledger = Ledger::new(records.rows(), limits());
    ledger.settled_aliases = Some(plan.views().unwrap());
    ledger.selected_groups = Some(&mut selected);

    let mut restored = Vec::new();
    for occurrence in 0..3 {
        let selected =
            crate::protocol_snapshot::owned11::state::selected_extensions(b"[]", &mut ledger, true)
                .unwrap_or_else(|error| panic!("selected occurrence {occurrence}: {error:?}"))
                .unwrap()
                .unwrap();
        restored.push(selected);
    }

    assert!(Arc::ptr_eq(&restored[0], &restored[1]));
    assert!(!Arc::ptr_eq(&restored[0], &restored[2]));
    assert!(ledger.rows.next().is_none());
    ledger.finish_aliases().unwrap();
}

#[test]
fn compact_content_groups_conjoin_real_rc_aliases() {
    let input = capture_roots(MetadataSharedKind::ContentBytes);
    let mut summaries = [RestoredSettledNative17AliasSummary::default(); 2];
    let mut plan =
        ValidatedRestoredSettledNative17Aliases::validate(&input, &mut summaries, 3).unwrap();
    let records = ValidatedMetadataRecords::validate(b"[]", 0, 0).unwrap();
    let mut ledger = Ledger::new(records.rows(), limits());
    ledger.settled_aliases = Some(plan.views().unwrap());

    for index in [0, 0, 1] {
        let edge = ContentGroupEdge {
            kind: ContentGroupKind::Transfer,
            index,
        };
        assert_eq!(
            ledger
                .shared_content(edge, 24, b"digest", b"capacity-19")
                .unwrap(),
            index,
        );
    }
    ledger.finish_aliases().unwrap();
}

#[test]
fn changed_view_layout_capacity_kind_short_and_unfinished_passes_stay_failed() {
    let input = capture_roots(MetadataSharedKind::NativeRestoredPhysicalHold);
    let records = ValidatedMetadataRecords::validate(b"[]", 0, 0).unwrap();
    for failure in 0..6 {
        let mut summaries = [RestoredSettledNative17AliasSummary::default(); 2];
        let mut plan =
            ValidatedRestoredSettledNative17Aliases::validate(&input, &mut summaries, 3).unwrap();
        let mut ledger = Ledger::new(records.rows(), limits());
        ledger.settled_aliases = Some(plan.views().unwrap());
        ledger
            .shared(
                MetadataSharedKind::NativeRestoredPhysicalHold,
                24,
                b"same",
                b"cap19",
            )
            .unwrap();

        let kind = MetadataSharedKind::NativeRestoredPhysicalHold;
        match failure {
            0 => assert!(ledger.shared(kind, 24, b"changed", b"cap19").is_err()),
            1 => assert!(ledger.shared(kind, 25, b"same", b"cap19").is_err()),
            2 => assert!(ledger.shared(kind, 24, b"same", b"cap20").is_err()),
            3 => assert!(
                ledger
                    .shared(MetadataSharedKind::Codec, 24, b"same", b"cap19")
                    .is_err()
            ),
            4 => {} // Leave a short pass with two unvisited rows.
            5 => {
                ledger.shared_begin(kind).unwrap();
            }
            _ => unreachable!(),
        }

        assert!(ledger.finish_aliases().is_err());
        drop(ledger);
        assert!(plan.views().is_err());
    }
}

#[test]
fn content_edge_mismatches_cannot_be_ignored_before_finish() {
    let records = ValidatedMetadataRecords::validate(b"[]", 0, 0).unwrap();
    for (input, second_index) in [
        (
            br#"[["content-bytes",0],["content-bytes",0]]"#.as_slice(),
            1,
        ),
        (
            br#"[["content-bytes",0],["content-bytes",1]]"#.as_slice(),
            0,
        ),
    ] {
        let mut summaries = [RestoredSettledNative17AliasSummary::default(); 2];
        let mut plan =
            ValidatedRestoredSettledNative17Aliases::validate(input, &mut summaries, 2).unwrap();
        let mut ledger = Ledger::new(records.rows(), limits());
        ledger.settled_aliases = Some(plan.views().unwrap());
        let edge = ContentGroupEdge {
            kind: ContentGroupKind::Transfer,
            index: 0,
        };
        ledger.shared_content(edge, 24, b"same", b"cap19").unwrap();
        let inconsistent_edge = ContentGroupEdge {
            kind: ContentGroupKind::Transfer,
            index: second_index,
        };
        assert!(
            ledger
                .shared_content(inconsistent_edge, 24, b"same", b"cap19")
                .is_err()
        );
        assert!(ledger.finish_aliases().is_err());
        drop(ledger);
        assert!(plan.views().is_err());
    }
}

#[test]
fn mixed_backends_refuse_before_typed_children_or_alias_rows() {
    let input = br#"[["codec",0]]"#;
    let mut old_summaries = [HistoricalAliasSummary::default(); 1];
    let mut new_summaries = [RestoredSettledNative17AliasSummary::default(); 1];
    let mut old = ValidatedHistoricalAliases::validate(input, &mut old_summaries, 1).unwrap();
    let mut new =
        ValidatedRestoredSettledNative17Aliases::validate(input, &mut new_summaries, 1).unwrap();
    let records = ValidatedMetadataRecords::validate(b"[]", 0, 0).unwrap();
    let mut ledger = Ledger::new(records.rows(), limits());
    ledger.aliases = Some(old.views().unwrap());
    ledger.settled_aliases = Some(new.views().unwrap());

    assert!(ledger.read::<bool>(b"true", false).is_err());
    assert_eq!(ledger.nodes, 0);
    assert!(
        ledger
            .shared(MetadataSharedKind::Codec, 24, b"same", b"")
            .is_err()
    );
    assert!(ledger.shared_begin(MetadataSharedKind::Codec).is_err());
    assert!(ledger.shared_finish(0, 24, b"same", b"").is_err());
    assert!(
        ledger
            .shared_reference(MetadataSharedKind::Codec, 24)
            .is_err()
    );
    assert!(ledger.finish_aliases().is_err());
    assert!(ledger.aliases.is_some());
    assert!(ledger.settled_aliases.is_some());
}

#[test]
fn role_references_require_complete_definition_in_the_current_pass() {
    let root = Rc::new(7u64);
    let mut bank = MetadataAliasBank::reserve(2).unwrap();
    for _ in 0..2 {
        bank.retain(MetadataSharedKind::NativeBoot, root.as_ref())
            .unwrap();
    }
    bank.finish_lookup();
    let input = serde_json::to_vec(&bank).unwrap();
    let records = ValidatedMetadataRecords::validate(b"[]", 0, 0).unwrap();
    let mut summaries = [RestoredSettledNative17AliasSummary::default(); 1];
    let mut plan =
        ValidatedRestoredSettledNative17Aliases::validate(&input, &mut summaries, 2).unwrap();
    let mut ledger = Ledger::new(records.rows(), limits());
    ledger.settled_aliases = Some(plan.views().unwrap());

    let defined = ledger
        .shared(MetadataSharedKind::NativeBoot, 8, b"boot-data", b"cap")
        .unwrap();
    assert_eq!(
        ledger
            .shared_reference(MetadataSharedKind::NativeBoot, 8)
            .unwrap(),
        defined
    );
    ledger.finish_aliases().unwrap();
    drop(ledger);

    let mut replay = Ledger::new(records.rows(), limits());
    replay.settled_aliases = Some(plan.views().unwrap());
    assert!(
        replay
            .shared_reference(MetadataSharedKind::NativeBoot, 8)
            .is_err()
    );
    assert!(replay.finish_aliases().is_err());
    drop(replay);
    assert!(plan.views().is_err());
}

#[test]
fn exhausted_roster_errors_and_dropped_passes_cannot_replay() {
    let input = br#"[["codec",0]]"#;
    let records = ValidatedMetadataRecords::validate(b"[]", 0, 0).unwrap();
    let mut summaries = [RestoredSettledNative17AliasSummary::default(); 1];
    let mut plan =
        ValidatedRestoredSettledNative17Aliases::validate(input, &mut summaries, 1).unwrap();
    let mut ledger = Ledger::new(records.rows(), limits());
    ledger.settled_aliases = Some(plan.views().unwrap());
    ledger
        .shared(MetadataSharedKind::Codec, 8, b"codec-data", b"")
        .unwrap();
    assert!(
        ledger
            .shared(MetadataSharedKind::Codec, 8, b"codec-data", b"")
            .is_err()
    );
    assert!(ledger.finish_aliases().is_err());
    drop(ledger);
    assert!(plan.views().is_err());

    let mut summaries = [RestoredSettledNative17AliasSummary::default(); 1];
    let mut plan =
        ValidatedRestoredSettledNative17Aliases::validate(input, &mut summaries, 1).unwrap();
    drop(plan.views().unwrap());
    assert!(plan.views().is_err());
}

#[test]
fn source_order_allows_nested_full_groups_but_refuses_unfinished_references() {
    let parent = Rc::new(3u64);
    let child = Rc::new(5u64);
    let mut bank = MetadataAliasBank::reserve(3).unwrap();
    bank.retain(
        MetadataSharedKind::NativeRestoredPhysicalHold,
        parent.as_ref(),
    )
    .unwrap();
    bank.retain(MetadataSharedKind::NativeBoot, child.as_ref())
        .unwrap();
    bank.retain(MetadataSharedKind::NativeBoot, child.as_ref())
        .unwrap();
    bank.finish_lookup();
    let input = serde_json::to_vec(&bank).unwrap();
    let records = ValidatedMetadataRecords::validate(b"[]", 0, 0).unwrap();
    let mut summaries = [RestoredSettledNative17AliasSummary::default(); 2];
    let mut plan =
        ValidatedRestoredSettledNative17Aliases::validate(&input, &mut summaries, 3).unwrap();
    let mut ledger = Ledger::new(records.rows(), limits());
    ledger.settled_aliases = Some(plan.views().unwrap());

    let parent_group = ledger
        .shared_begin(MetadataSharedKind::NativeRestoredPhysicalHold)
        .unwrap();
    let child_group = ledger
        .shared(MetadataSharedKind::NativeBoot, 8, b"boot-data", b"cap")
        .unwrap();
    assert_eq!(
        ledger
            .shared_reference(MetadataSharedKind::NativeBoot, 8)
            .unwrap(),
        child_group
    );
    ledger
        .shared_finish(
            parent_group,
            8,
            b"parent-data",
            b"parent-and-child-capacities",
        )
        .unwrap();
    ledger.finish_aliases().unwrap();
    drop(ledger);

    // Current-pass definition is required even though a prior pass completed.
    let mut replay = Ledger::new(records.rows(), limits());
    replay.settled_aliases = Some(plan.views().unwrap());
    replay
        .shared_begin(MetadataSharedKind::NativeRestoredPhysicalHold)
        .unwrap();
    replay.shared_begin(MetadataSharedKind::NativeBoot).unwrap();
    assert!(
        replay
            .shared_reference(MetadataSharedKind::NativeBoot, 8)
            .is_err()
    );
    assert!(
        replay
            .shared_finish(child_group, 8, b"boot-data", b"cap")
            .is_err()
    );
    assert!(replay.finish_aliases().is_err());
}

#[test]
fn failed_role_layout_check_cannot_be_repaired_as_a_full_view() {
    let input = br#"[["native-boot",0],["native-boot",0]]"#;
    let records = ValidatedMetadataRecords::validate(b"[]", 0, 0).unwrap();
    let mut summaries = [RestoredSettledNative17AliasSummary::default(); 1];
    let mut plan =
        ValidatedRestoredSettledNative17Aliases::validate(input, &mut summaries, 2).unwrap();
    let mut ledger = Ledger::new(records.rows(), limits());
    ledger.settled_aliases = Some(plan.views().unwrap());
    let group = ledger
        .shared(MetadataSharedKind::NativeBoot, 8, b"boot-data", b"cap")
        .unwrap();

    assert!(
        ledger
            .shared_reference(MetadataSharedKind::NativeBoot, 16)
            .is_err()
    );
    assert!(
        ledger
            .shared_finish(group, 8, b"boot-data", b"cap")
            .is_err()
    );
    assert!(ledger.finish_aliases().is_err());
}

#[test]
fn malformed_trailing_alias_grammar_preserves_admitted_partial_scratch() {
    let input = br#"[["native-boot",0]][]"#;
    let mut summaries = [RestoredSettledNative17AliasSummary::default(); 1];
    assert!(ValidatedRestoredSettledNative17Aliases::validate(input, &mut summaries, 1).is_err());
    assert!(
        ValidatedRestoredSettledNative17Aliases::validate(
            br#"[["native-boot",0]]"#,
            &mut summaries,
            1,
        )
        .is_err()
    );
}
