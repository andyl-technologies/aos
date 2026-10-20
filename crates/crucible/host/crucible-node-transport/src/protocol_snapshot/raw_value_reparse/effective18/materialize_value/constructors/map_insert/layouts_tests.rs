//! Checks actual public anchors and private source-field bounds without unsafe.

use super::*;
use std::collections::btree_map::{Entry, IntoIter, OccupiedEntry, VacantEntry};

#[test]
fn actual_public_geometry_matches_the_locked_default_map_profile() {
    assert!(profile_matches());
    assert!(NODE >= size_of::<usize>() + size_of::<NonNull<u8>>());
    assert!(HANDLE >= NODE + size_of::<usize>());
    assert!(SPLIT >= 2 * NODE + size_of::<(String, Value)>());
    assert!(LAZY_RANGE >= 2 * OPTIONAL_LAZY_HANDLE);
    assert!(size_of::<IntoIter<String, Value>>() <= record(&[LAZY_RANGE, WORD, 0]));
    assert!(
        size_of::<Entry<'static, String, Value>>()
            >= size_of::<OccupiedEntry<'static, String, Value>>()
    );
    assert!(
        size_of::<Entry<'static, String, Value>>()
            >= size_of::<VacantEntry<'static, String, Value>>()
    );
}

#[test]
fn field_padding_and_small_tag_bounds_do_not_assume_mirror_abi() {
    assert_eq!(record(&[]), 8);
    assert!(record(&[1, 8, 2]) >= 11);
    assert!(tagged(NODE) >= NODE + WORD);
    assert_eq!(record(&[usize::MAX, 1]), usize::MAX);
    assert_eq!(tagged(usize::MAX), usize::MAX);
}
