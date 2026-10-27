//! Exercises real immutable lookup and ordinary-parser profile independence.

use super::*;
use crate::{ContractError, canonical::parse_json};
use std::{mem::size_of, ptr};

// This independently observes the real container's ordering in a fixture.
// Production DATA never creates a map or executes such a feature probe.
fn observes_sorted_backend() -> bool {
    let mut object = Map::new();
    object.insert("z".to_owned(), Value::Null);
    object.insert("a".to_owned(), Value::Null);
    object.keys().map(String::as_str).eq(["a", "z"])
}

#[test]
fn data_agrees_with_actual_backend_and_keeps_unsupported_profiles_closed() {
    let ordinary = observes_sorted_backend();
    let supported_anchors = geometry::SUPPORTED;

    if ordinary && supported_anchors {
        let [retained, transient, scratch] = STRICT_JSON_KEY_LOOKUP_STORAGE_DATA
            .expect("source-pinned supported BTreeMap profile supplies DATA");
        assert_eq!(retained, 0);
        assert!(transient > 0 && transient < usize::MAX);
        assert!(scratch > 0 && scratch < usize::MAX);
    } else {
        assert!(STRICT_JSON_KEY_LOOKUP_STORAGE_DATA.is_none());
    }

    if !ordinary {
        // This is the actual alternate branch, not a fabricated larger map.
        assert!(size_of::<Map<String, Value>>() >= INDEXMAP_MINIMUM);
    }
}

#[test]
fn empty_and_singleton_lookup_keep_actual_inputs_and_child_identity() {
    let mut object = Map::new();
    let key = String::from("retained-key");
    let key_bytes = key.as_ptr();
    let owner = &object as *const Map<String, Value>;

    assert!(!object.contains_key(&key));
    assert!(object.get(&key).is_none());
    assert_eq!(owner, &object as *const Map<String, Value>);
    assert_eq!(key_bytes, key.as_ptr());

    object.insert(key.clone(), Value::String("original child".to_owned()));
    let (stored_key, stored_value) = object.get_key_value(&key).unwrap();
    let stored_key_bytes = stored_key.as_ptr();
    let stored_child_bytes = stored_value.as_str().unwrap().as_ptr();
    let child = stored_value as *const Value;

    assert!(object.contains_key(&key));
    assert!(!object.contains_key(&String::from("retained-ke")));
    assert!(!object.contains_key(&String::from("retained-key-extra")));
    assert!(ptr::eq(object.get(&key).unwrap(), child));
    assert_eq!(
        object.get_key_value(&key).unwrap().0.as_ptr(),
        stored_key_bytes
    );
    assert_eq!(
        object.get(&key).unwrap().as_str().unwrap().as_ptr(),
        stored_child_bytes
    );
    assert_eq!(object.len(), 1);
    assert_eq!(key_bytes, key.as_ptr());
}

#[test]
fn multilevel_first_middle_last_and_missing_search_preserve_value_addresses() {
    let mut object = Map::new();
    for index in (0..4096).rev() {
        object.insert(format!("key-{index:05}"), Value::Bool(index % 2 == 0));
    }
    let before: Vec<_> = object
        .iter()
        .map(|(key, value)| (key.as_ptr(), value as *const Value))
        .collect();

    for index in [0, 1, 10, 11, 12, 2047, 2048, 4094, 4095] {
        let key = format!("key-{index:05}");
        assert!(object.contains_key(&key));
        assert_eq!(object.get(&key), Some(&Value::Bool(index % 2 == 0)));
    }
    for key in ["", "key-", "key-00000-", "key-000005", "key-04096", "z"] {
        let key = key.to_owned();
        assert!(!object.contains_key(&key));
        assert!(object.get(&key).is_none());
    }

    assert_eq!(object.len(), 4096);
    let after: Vec<_> = object
        .iter()
        .map(|(key, value)| (key.as_ptr(), value as *const Value))
        .collect();
    assert_eq!(before, after);
}

#[test]
fn unicode_and_long_shared_prefix_queries_use_exact_string_identity() {
    let prefix = "prefix".repeat(1024);
    let keys = [
        String::new(),
        String::from("\0"),
        String::from("é"),
        String::from("e\u{301}"),
        String::from("\u{e000}"),
        String::from("😀"),
        format!("{prefix}a"),
        format!("{prefix}aa"),
        format!("{prefix}b"),
    ];
    let mut object = Map::new();
    for (index, key) in keys.iter().enumerate() {
        object.insert(key.clone(), Value::String(index.to_string()));
    }

    for (index, key) in keys.iter().enumerate() {
        let query = String::from(key.as_str());
        assert!(object.contains_key(&query));
        assert_eq!(
            object.get(&query).unwrap().as_str(),
            Some(index.to_string().as_str())
        );
        assert!(ptr::eq(
            object.get(key).unwrap(),
            object.get(&query).unwrap()
        ));
    }
    for key in [
        prefix.clone(),
        format!("{prefix}aaa"),
        String::from("E\u{301}"),
    ] {
        assert!(!object.contains_key(&key));
    }
    assert_eq!(object.len(), keys.len());
}

#[test]
fn ordinary_duplicate_order_and_accepted_inputs_do_not_depend_on_supplier_data() {
    let bytes = br#"{"z":true,"a":0,"nested":{"value":null}}"#;
    let value = parse_json(bytes, bytes.len()).unwrap();
    let object = value.as_object().unwrap();
    assert!(object.contains_key(&String::from("nested")));
    assert!(object.contains_key(&String::from("a")));

    for bytes in [
        br#"{"a":0,"\u0061" !}"#.as_slice(),
        br#"{"a":0,"\u0061": not-json}"#.as_slice(),
    ] {
        match parse_json(bytes, bytes.len()) {
            Err(ContractError::Invalid { field, reason }) => {
                assert_eq!(field, "json");
                assert_eq!(reason, "duplicate object key at byte 15");
            }
            other => panic!("original duplicate-before-colon error required: {other:?}"),
        }
    }
}
