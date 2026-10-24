//! Exercises actual map construction, replacement and fully drained retirement.
//!
//! These ordinary controls are intentionally UNRUN in the authoring cohort.
//! Public geometry/census checks do not measure private implementation frames.

use super::*;
use crate::retained_metadata::requested_storage::tree_storage_data;
use std::mem::align_of;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn bytes(row: [usize; 3]) -> usize {
    row.into_iter().sum()
}

#[test]
fn empty_map_has_no_node_backing_and_real_constructor_controls() -> TestResult {
    let row = map_insertion_series_data(0, usize::MAX)?;
    assert_eq!(row[0], 0);
    assert!(row[1] >= size_of::<Map<String, Value>>());
    assert!(row[2] >= map_fixed_counter_data());
    let map = Map::<String, Value>::new();
    assert!(map.is_empty());
    assert_eq!(map.into_iter().next(), None);
    let retire = map_retirement_data(1, 0, usize::MAX)?;
    assert_eq!(retire[0], 0);
    assert!(retire[1] > 0 && retire[2] > 0);
    Ok(())
}

#[test]
fn actual_split_series_matches_reported_backing_and_drains_in_order() -> TestResult {
    let members = 180usize; // exceeds the locked 11-key leaf and one-level root
    let row = map_insertion_series_data(members, usize::MAX)?;
    assert_eq!(
        row[0],
        tree_storage_data(
            1,
            members,
            size_of::<String>() + size_of::<Value>(),
            align_of::<Value>()
        )?
    );
    let mut map = Map::new();
    for index in (0..members).rev() {
        assert!(
            map.insert(format!("k{index:04}"), Value::Number(index.into()))
                .is_none()
        );
    }
    let mut expected = 0;
    for (key, value) in map {
        assert_eq!(key, format!("k{expected:04}"));
        assert_eq!(value, Value::Number(expected.into()));
        expected += 1;
    }
    assert_eq!(expected, members);
    let retire = map_retirement_data(1, members, usize::MAX)?;
    assert_eq!(retire[0], 0);
    assert!(retire[1] > 0 && retire[2] > map_fixed_counter_data());
    Ok(())
}

#[test]
fn occupied_branch_returns_the_real_old_value_before_shallow_retirement() -> TestResult {
    let _row = map_insertion_series_data(2, usize::MAX)?;
    let mut map = Map::new();
    assert!(
        map.insert("same".to_owned(), Value::String("old".to_owned()))
            .is_none()
    );
    let old = map.insert("same".to_owned(), Value::Bool(true));
    assert_eq!(old, Some(Value::String("old".to_owned())));
    // This representative old value is shallow. Deep values belong to the
    // parent guard's independently tested iterative retirement workspace.
    let mut iter = map.into_iter();
    assert_eq!(iter.next(), Some(("same".to_owned(), Value::Bool(true))));
    assert!(iter.next().is_none());
    drop(iter);
    Ok(())
}

#[test]
fn exact_and_one_short_limits_are_checked_before_any_map_effect() -> TestResult {
    for members in [0, 1, 12, 180] {
        let row = map_insertion_series_data(members, usize::MAX)?;
        let exact = bytes(row);
        assert_eq!(map_insertion_series_data(members, exact)?, row);
        assert!(map_insertion_series_data(members, exact - 1).is_err());
    }
    for (objects, members) in [(0, 0), (1, 0), (1, 180), (5, 180)] {
        let row = map_retirement_data(objects, members, usize::MAX)?;
        let exact = bytes(row);
        assert_eq!(map_retirement_data(objects, members, exact)?, row);
        assert!(map_retirement_data(objects, members, exact - 1).is_err());
    }
    assert!(map_insertion_series_data(usize::MAX, usize::MAX).is_err());
    assert!(map_retirement_data(0, 1, usize::MAX).is_err());
    Ok(())
}
