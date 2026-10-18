//! Canonical collection and envelope admission tests.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

#[test]
fn bounded_sequence_rejects_hostile_declared_length_before_allocation() {
    let mut encoded = vec![0x9b];
    encoded.extend_from_slice(&u64::MAX.to_be_bytes());

    let error = match ciborium::de::from_reader::<BoundedVec<u8, 4>, _>(encoded.as_slice()) {
        Ok(_) => panic!("hostile declared length must be rejected"),
        Err(error) => map_decode_error(error),
    };
    assert_eq!(
        error,
        BoundedCborError::ResourceLimit {
            field: "bounded CBOR sequence",
            current: 0,
            requested: u64::MAX,
            configured: 4,
            hard: 4,
        }
    );
}

#[test]
fn bounded_sequence_round_trips_without_changing_cbor_shape() {
    let bounded = BoundedVec::<u8, 4>::new(vec![1, 2, 3])
        .unwrap_or_else(|error| panic!("admit fixture: {error:?}"));
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&bounded, &mut encoded)
        .unwrap_or_else(|error| panic!("encode fixture: {error}"));
    let decoded = ciborium::de::from_reader::<BoundedVec<u8, 4>, _>(encoded.as_slice())
        .unwrap_or_else(|error| panic!("decode fixture: {error}"));
    assert_eq!(decoded.into_inner(), vec![1, 2, 3]);
}

#[test]
fn bounded_map_rejects_hostile_declared_length_before_allocation() {
    let mut encoded = vec![0xbb];
    encoded.extend_from_slice(&u64::MAX.to_be_bytes());

    let error = match ciborium::de::from_reader::<BoundedMap<u8, u8, 4>, _>(encoded.as_slice()) {
        Ok(_) => panic!("hostile declared map length must be rejected"),
        Err(error) => map_decode_error(error),
    };
    assert_eq!(
        error,
        BoundedCborError::ResourceLimit {
            field: "bounded CBOR map",
            current: 0,
            requested: u64::MAX,
            configured: 4,
            hard: 4,
        }
    );
}

#[test]
fn bounded_map_and_set_preserve_tree_cbor_shape() {
    let tree_map = BTreeMap::from([(1_u8, 2_u8), (3, 4)]);
    let mut bounded_map = BoundedMap::<u8, u8, 4>::new();
    for (key, value) in &tree_map {
        bounded_map
            .try_insert(*key, *value)
            .unwrap_or_else(|error| panic!("map fixture should allocate: {error}"));
    }
    let mut tree_map_bytes = Vec::new();
    let mut bounded_map_bytes = Vec::new();
    ciborium::ser::into_writer(&tree_map, &mut tree_map_bytes)
        .unwrap_or_else(|error| panic!("tree map should encode: {error}"));
    ciborium::ser::into_writer(&bounded_map, &mut bounded_map_bytes)
        .unwrap_or_else(|error| panic!("bounded map should encode: {error}"));
    assert_eq!(bounded_map_bytes, tree_map_bytes);

    let tree_set = BTreeSet::from([1_u8, 3]);
    let mut bounded_set = BoundedSet::<u8, 4>::new();
    for value in &tree_set {
        bounded_set
            .try_insert(*value)
            .unwrap_or_else(|error| panic!("set fixture should allocate: {error}"));
    }
    let mut tree_set_bytes = Vec::new();
    let mut bounded_set_bytes = Vec::new();
    ciborium::ser::into_writer(&tree_set, &mut tree_set_bytes)
        .unwrap_or_else(|error| panic!("tree set should encode: {error}"));
    ciborium::ser::into_writer(&bounded_set, &mut bounded_set_bytes)
        .unwrap_or_else(|error| panic!("bounded set should encode: {error}"));
    assert_eq!(bounded_set_bytes, tree_set_bytes);
}

#[test]
fn bounded_map_and_set_delegate_nested_duplication_fallibly() {
    let mut map = BoundedMap::<String, String, 2>::new();
    map.try_insert(String::from("key"), String::from("value"))
        .unwrap_or_else(|error| panic!("map fixture should allocate: {error}"));
    let duplicate = map
        .try_clone_with(
            |key| Ok::<_, &'static str>(key.clone()),
            |_value| Err("nested value allocation"),
            || "outer map allocation",
        )
        .err()
        .unwrap_or_else(|| panic!("nested clone refusal must propagate"));
    assert_eq!(duplicate, "nested value allocation");

    let mut set = BoundedSet::<String, 2>::new();
    set.try_insert(String::from("value"))
        .unwrap_or_else(|error| panic!("set fixture should allocate: {error}"));
    let duplicate = set
        .try_clone_with(
            |_value| Err("nested set allocation"),
            || "outer set allocation",
        )
        .err()
        .unwrap_or_else(|| panic!("nested clone refusal must propagate"));
    assert_eq!(duplicate, "nested set allocation");
}

#[test]
fn bounded_map_rejects_noncanonical_key_order() {
    let descending_map = [0xa2, 0x02, 0x00, 0x01, 0x00];
    assert!(
        ciborium::de::from_reader::<BoundedMap<u8, u8, 4>, _>(descending_map.as_slice()).is_err()
    );
}

#[test]
fn bounded_map_and_set_reject_programmatic_growth_past_the_ceiling() {
    let mut map = BoundedMap::<u8, u8, 1>::new();
    assert_eq!(map.try_insert(1, 2), Ok(None));
    assert_eq!(
        map.try_insert(3, 4),
        Err(BoundedCborError::ResourceLimit {
            field: "bounded CBOR map",
            current: 1,
            requested: 1,
            configured: 1,
            hard: 1,
        })
    );
    assert_eq!(map.try_insert(1, 5), Ok(Some(2)));

    let mut set = BoundedSet::<u8, 1>::new();
    assert_eq!(set.try_insert(1), Ok(true));
    assert_eq!(set.try_insert(1), Ok(false));
    assert_eq!(
        set.try_insert(2),
        Err(BoundedCborError::ResourceLimit {
            field: "bounded CBOR set",
            current: 1,
            requested: 1,
            configured: 1,
            hard: 1,
        })
    );
}
