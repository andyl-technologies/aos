//! Compares the shared row with the independently retained original raw producer.

use super::*;

fn components(row: original::DecodedStorage) -> DecodedStorage {
    DecodedStorage {
        value_backing: row.value_backing,
        typed_backing: row.typed_backing,
        work: row.work,
    }
}

#[test]
fn original_raw_occurrence_components_and_exact_short_boundaries_remain_identical() {
    for bytes in [
        b"{}".as_slice(),
        b"[]",
        b"null",
        b"1.0",
        b"-0.0",
        br#"{"a":{},"b":[{},{},"x",1,2],"c":"\uD834\uDD1E"}"#,
        br#"{"$serde_json::private::RawValue":"[1,2]","literal":[true,false,null]}"#,
    ] {
        let expected = components(
            original::quote(bytes, size_of::<Value>(), size_of::<Value>(), usize::MAX).unwrap(),
        );
        let actual = quote(bytes, size_of::<Value>(), size_of::<Value>(), usize::MAX).unwrap();
        assert_eq!(actual, expected);
        let exact = expected.total(usize::MAX).unwrap();
        assert_eq!(
            quote(bytes, size_of::<Value>(), size_of::<Value>(), exact).unwrap(),
            expected
        );
        assert!(quote(bytes, size_of::<Value>(), size_of::<Value>(), exact - 1).is_err());
    }
    assert!(counter_scratch_data() > original::counter_scratch_data());
}

#[test]
fn original_unsupported_raw_shapes_and_arithmetic_refusals_remain_identical() {
    for bytes in [b"".as_slice(), b"[}", b"{", b"\"unfinished", b"]", b"[[]"] {
        let old = original::quote(bytes, size_of::<Value>(), size_of::<Value>(), usize::MAX);
        let new = quote(bytes, size_of::<Value>(), size_of::<Value>(), usize::MAX);
        assert_eq!(old.is_ok(), new.is_ok());
        if let (Err(old), Err(new)) = (old, new) {
            assert_eq!(old.to_string(), new.to_string());
        }
    }
    assert!(quote(b"{}", 0, size_of::<Value>(), usize::MAX).is_err());
    assert!(quote(b"[]", usize::MAX, usize::MAX, usize::MAX).is_err());
    let deep = vec![b'['; 65];
    assert!(original::quote(&deep, 1, 1, usize::MAX).is_err());
    assert!(quote(&deep, 1, 1, usize::MAX).is_err());
}
