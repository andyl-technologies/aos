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

#[test]
fn declared_custom_table_refusal_precedes_member_deserialization()
-> Result<(), Box<dyn std::error::Error>> {
    use crucible::owned_decode::{
        DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, ResourceLoan,
    };
    use std::cell::Cell;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    thread_local! {
        static ELEMENTS: Cell<u64> = const { Cell::new(0) };
    }
    struct Member {
        _value: u64,
    }
    impl<'de> serde::Deserialize<'de> for Member {
        fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
            ELEMENTS.with(|count| count.set(count.get() + 1));
            let value = u64::deserialize(decoder)?;
            Ok(Self { _value: value })
        }
    }
    struct Authority {
        refusing: AtomicBool,
        calls: AtomicU64,
    }
    impl DecodeResourceAuthority for Authority {
        fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
            Ok(())
        }

        fn reserve(&self, _: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.refusing.load(Ordering::SeqCst) {
                return Err(DecodeAdmissionError::new(std::fmt::Error));
            }
            Ok(ResourceLoan::new(()))
        }
    }
    let authority = Arc::new(Authority {
        refusing: AtomicBool::new(false),
        calls: AtomicU64::new(0),
    });
    let original = DecodeBudget::new(authority.clone(), 1024 * 1024)?;
    authority.calls.store(0, Ordering::SeqCst);
    authority.refusing.store(true, Ordering::SeqCst);
    ELEMENTS.with(|count| count.set(0));
    let _scope = original.enter();

    assert!(ciborium::de::from_reader::<BoundedVec<Member, 4>, _>(&[0x82, 1, 2][..]).is_err());
    assert_eq!(ELEMENTS.with(Cell::get), 0);
    assert_eq!(authority.calls.load(Ordering::SeqCst), 1);
    let first = original.failure()?.expect("table original refusal");
    assert!(ciborium::de::from_reader::<BoundedVec<Member, 4>, _>(&[0x82, 1, 2][..]).is_err());
    assert_eq!(original.failure()?.expect("sticky table refusal"), first);
    assert_eq!(authority.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn custom_table_growth_retains_exact_ordinary_wire_and_original_refusal()
-> Result<(), Box<dyn std::error::Error>> {
    let _original = crucible::test_support::fixture_decode_scope(1024 * 1024)?;
    let wire = [0x82, 7, 8];
    let decoded: BoundedVec<u64, 4> = ciborium::de::from_reader(wire.as_slice())?;
    assert_eq!(decoded.as_slice(), &[7, 8]);
    assert_eq!(encode_prefixed(&decoded, b"", "table fixture", 16)?, wire);
    Ok(())
}

#[test]
fn original_leaf_adapter_preserves_custom_declared_bound_before_members()
-> Result<(), Box<dyn std::error::Error>> {
    use serde::Deserialize;
    use std::cell::Cell;

    thread_local! {
        static MEMBERS: Cell<u64> = const { Cell::new(0) };
    }
    struct Member(u64);

    impl<'de> Deserialize<'de> for Member {
        fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
            MEMBERS.with(|count| count.set(count.get() + 1));
            u64::deserialize(decoder).map(Self)
        }
    }

    let _original = crucible::test_support::fixture_decode_scope(1024 * 1024)?;
    MEMBERS.with(|count| count.set(0));
    let result = crucible::owned_decode::from_cbor_slice::<BoundedVec<Member, 1>>(&[0x82, 1, 2]);

    assert!(result.is_err());
    assert_eq!(MEMBERS.with(Cell::get), 0);
    let healthy: BoundedVec<Member, 2> = crucible::owned_decode::from_cbor_slice(&[0x82, 1, 2])?;
    assert_eq!(healthy.as_slice()[0].0, 1);
    assert_eq!(healthy.as_slice()[1].0, 2);
    Ok(())
}

#[test]
fn original_custom_table_keeps_nested_ordinary_sequence_hints_suppressed()
-> Result<(), Box<dyn std::error::Error>> {
    use serde::de::{SeqAccess, Visitor};

    struct NestedSequence(Vec<u64>);

    impl<'de> serde::Deserialize<'de> for NestedSequence {
        fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
            struct NestedVisitor;

            impl<'de> Visitor<'de> for NestedVisitor {
                type Value = NestedSequence;

                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("a nested ordinary sequence")
                }

                fn visit_seq<A: SeqAccess<'de>>(
                    self,
                    mut sequence: A,
                ) -> Result<Self::Value, A::Error> {
                    assert_eq!(sequence.size_hint(), Some(0));
                    let mut values = Vec::new();
                    while let Some(value) = sequence.next_element()? {
                        values.push(value);
                    }
                    Ok(NestedSequence(values))
                }
            }

            decoder.deserialize_seq(NestedVisitor)
        }
    }

    let _original = crucible::test_support::fixture_decode_scope(1024 * 1024)?;
    let decoded: BoundedVec<NestedSequence, 1> =
        crucible::owned_decode::from_cbor_slice(&[0x81, 0x82, 3, 7])?;

    assert_eq!(decoded.as_slice()[0].0, &[3, 7]);
    Ok(())
}

#[test]
fn original_nested_string_refusal_precedes_the_owning_visitor_copy()
-> Result<(), Box<dyn std::error::Error>> {
    use crucible::owned_decode::{
        DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, ResourceLoan,
    };
    use serde::de::Visitor;
    use std::cell::Cell;
    use std::sync::Arc;

    thread_local! {
        static COPIES: Cell<u64> = const { Cell::new(0) };
    }
    struct OwningString(String);

    impl<'de> serde::Deserialize<'de> for OwningString {
        fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
            struct StringVisitor;

            impl<'de> Visitor<'de> for StringVisitor {
                type Value = OwningString;

                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("an owning string")
                }

                fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                    COPIES.with(|count| count.set(count.get() + 1));
                    Ok(OwningString(value.to_owned()))
                }
            }

            decoder.deserialize_string(StringVisitor)
        }
    }

    struct RefuseString {
        target: u64,
    }

    impl DecodeResourceAuthority for RefuseString {
        fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
            Ok(())
        }

        fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
            if bytes == self.target {
                return Err(DecodeAdmissionError::new(std::fmt::Error));
            }
            Ok(ResourceLoan::new(()))
        }
    }

    let text = "a".repeat(4096);
    let mut wire = Vec::new();
    ciborium::ser::into_writer(&vec![text], &mut wire)?;
    let target = 8192 + (4 * std::mem::size_of::<ResourceLoan>()) as u64;
    let original = DecodeBudget::new(Arc::new(RefuseString { target }), 1024 * 1024)?;
    let _scope = original.enter();
    COPIES.with(|count| count.set(0));

    let result = crucible::owned_decode::from_cbor_slice::<BoundedVec<OwningString, 1>>(&wire);

    assert!(result.is_err());
    assert_eq!(COPIES.with(Cell::get), 0);
    assert!(original.failure()?.is_some());
    // The fixture's field is genuinely an owning output, even though the
    // refused execution must never construct one.
    assert_eq!(
        std::mem::size_of::<OwningString>(),
        std::mem::size_of::<String>()
    );
    let control = OwningString(String::new());
    assert!(control.0.is_empty());
    Ok(())
}

#[test]
fn original_leaf_adapter_preserves_map_bound_before_keys_or_values()
-> Result<(), Box<dyn std::error::Error>> {
    use serde::Deserialize;
    use std::cell::Cell;

    thread_local! {
        static MEMBERS: Cell<u64> = const { Cell::new(0) };
    }
    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    struct Member(u64);

    impl<'de> Deserialize<'de> for Member {
        fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
            MEMBERS.with(|count| count.set(count.get() + 1));
            u64::deserialize(decoder).map(Self)
        }
    }

    let _original = crucible::test_support::fixture_decode_scope(1024 * 1024)?;
    MEMBERS.with(|count| count.set(0));
    let wire = [0xa2, 1, 2, 3, 4];

    let result = crucible::owned_decode::from_cbor_slice::<BoundedMap<Member, Member, 1>>(&wire);

    assert!(result.is_err());
    assert_eq!(MEMBERS.with(Cell::get), 0);
    let healthy: BoundedMap<Member, Member, 2> = crucible::owned_decode::from_cbor_slice(&wire)?;
    assert_eq!(healthy.len(), 2);
    assert_eq!(healthy.get(&Member(1)).map(|member| member.0), Some(2));
    assert_eq!(healthy.get(&Member(3)).map(|member| member.0), Some(4));
    assert_eq!(MEMBERS.with(Cell::get), 4);
    Ok(())
}
