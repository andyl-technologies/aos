//! Original arm identity, native order and bounded cut parsing regressions.

// crucible-lint: allow panic-shortcut -- These initialization cut tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use crucible_node_contract::U64;

use super::{NativeInitializationClass, NativeInitializationCut, NativeInitializationRow};

fn original() -> NativeInitializationCut {
    let mut cut = NativeInitializationCut {
        hold_generation: U64::new(7),
        prepared_scope_hash: [1; 32],
        initialization_commitment: [2; 32],
        original_cut_digest: [0; 32],
        rows: vec![
            NativeInitializationRow {
                class: NativeInitializationClass::QmpDispatcherStartup,
                callback_id: U64::new(1),
                arm_generation: U64::new(11),
                context_id: U64::new(1),
            },
            NativeInitializationRow {
                class: NativeInitializationClass::IdeZeroErrorRestart,
                callback_id: U64::new(6),
                arm_generation: U64::new(12),
                context_id: U64::new(2),
            },
        ],
    };
    cut.original_cut_digest = cut.computed_digest().unwrap();
    cut
}

#[test]
fn closed_big_endian_rows_retain_native_order_and_original_arm_identity() {
    let cut = original();
    let encoded = cut.encode().unwrap();

    assert_eq!(encoded.len(), 184);
    assert_eq!(
        &encoded[..16],
        &[0, 0, 0, 1, 0, 0, 0, 120, 0, 0, 0, 2, 0, 0, 0, 0]
    );
    assert_eq!(&encoded[120..124], &1u32.to_be_bytes());
    assert_eq!(&encoded[136..144], &11u64.to_be_bytes());
    assert_eq!(&encoded[152..156], &4u32.to_be_bytes());
    assert_eq!(NativeInitializationCut::decode(&encoded).unwrap(), cut);
}

#[test]
fn reordered_or_rearmed_objects_cannot_reuse_a_digest_or_lifetime_generation() {
    let cut = original();
    let mut changed = cut.clone();
    changed.rows.swap(0, 1);
    assert!(changed.validate().is_err());
    assert_ne!(changed.computed_digest().unwrap(), cut.original_cut_digest);
    assert_eq!(changed.hold_generation, cut.hold_generation);

    let mut changed = cut.clone();
    changed.rows[0].arm_generation = U64::new(13);
    assert!(changed.validate().is_err());
    assert_ne!(changed.computed_digest().unwrap(), cut.original_cut_digest);
    assert_eq!(changed.rows[0].callback_id, cut.rows[0].callback_id);
}

#[test]
fn every_truncation_open_field_trailing_byte_and_oversized_count_is_refused() {
    let encoded = original().encode().unwrap();
    for length in 0..encoded.len() {
        assert!(NativeInitializationCut::decode(&encoded[..length]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(NativeInitializationCut::decode(&trailing).is_err());

    for (offset, value) in [(0, 2), (4, 121), (8, u32::MAX), (12, 1), (120, 3), (124, 1)] {
        let mut changed = encoded.clone();
        changed[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        assert!(NativeInitializationCut::decode(&changed).is_err());
    }
}

#[test]
fn authentic_empty_cut_is_distinct_from_omitting_original_source_identity() {
    let mut cut = original();
    cut.rows.clear();
    cut.original_cut_digest = cut.computed_digest().unwrap();
    let encoded = cut.encode().unwrap();

    assert_eq!(encoded.len(), 120);
    assert!(
        NativeInitializationCut::decode(&encoded)
            .unwrap()
            .rows
            .is_empty()
    );
    cut.hold_generation = U64::new(0);
    assert!(cut.computed_digest().is_err());
}

#[test]
fn duplicate_callbacks_missing_arms_and_exhausted_arm_generations_are_refused() {
    let mut cut = original();
    cut.rows[1].callback_id = cut.rows[0].callback_id;
    assert!(cut.computed_digest().is_err());

    let mut cut = original();
    cut.rows[0].arm_generation = U64::new(0);
    assert!(cut.computed_digest().is_err());
    cut.rows[0].arm_generation = U64::new(u64::MAX);
    assert!(cut.computed_digest().is_err());
}
