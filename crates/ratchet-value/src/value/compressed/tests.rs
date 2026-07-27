//! Candidate-C codec and serial scalar-store tests.

use super::*;

#[test]
fn compressed_word_is_exactly_one_machine_word() {
    assert_eq!(std::mem::size_of::<CompressedValueWord>(), 8);
    assert_eq!(std::mem::align_of::<CompressedValueWord>(), 8);
}

#[test]
fn scalar_encodings_roundtrip_and_large_integers_require_boxes() {
    let negative =
        CompressedValueWord::inline_int(i64::from(i32::MIN)).expect("i32 minimum is inline");
    assert_eq!(negative.as_inline_int(), Some(i64::from(i32::MIN)));
    assert_eq!(CompressedValueWord::boolean(true).as_bool(), Some(true));
    assert_eq!(CompressedValueWord::null().semantic_tag(), ValueTag::Null);
    assert_eq!(
        CompressedValueWord::inline_int(i64::from(i32::MAX) + 1),
        Err(CompressedValueError::IntegerRequiresBox {
            value: i64::from(i32::MAX) + 1
        })
    );
}

#[test]
fn typed_indices_and_forced_thunk_bits_roundtrip() {
    let arena = SharedFlatStoreArena::new();
    let domain = arena.arena_domain_id().expect("reservation has a domain");
    let index = ArenaIndex::new(0xfeed_beef);
    let list =
        CompressedValueWord::heap(domain, ValueTag::List, index).expect("list is heap-backed");
    assert_eq!(list.arena_index(), Some(index));
    assert_eq!(list.arena_domain(), Some(domain));
    assert_eq!(list.semantic_tag(), ValueTag::List);

    let thunk = CompressedValueWord::heap(domain, ValueTag::Thunk, index)
        .expect("thunk is heap-backed")
        .with_forced_bit()
        .expect("thunk accepts forced bit");
    assert!(thunk.is_forced_thunk());
    assert_eq!(CompressedValueWord::from_raw(thunk.raw()), Ok(thunk));
    assert_eq!(thunk.arena_index(), Some(index));
}

#[test]
fn scalar_store_rejects_an_equal_offset_from_another_arena_domain() {
    let mut left = CandidateCScalarStore::new(SharedFlatStoreArena::new());
    let right = CandidateCScalarStore::new(SharedFlatStoreArena::new());
    let word = left.encode_int(i64::MAX).expect("wide integer boxes");

    assert!(matches!(
        right.decode_int(word),
        Err(CandidateCScalarError::ArenaDomainMismatch { .. })
    ));
}

#[test]
fn scalar_store_inlines_i32_and_hash_conses_boxed_values() {
    let arena = SharedFlatStoreArena::new();
    let mut store = CandidateCScalarStore::new(arena.clone());

    let inline = store.encode_int(-7).expect("small integer encodes");
    assert_eq!(store.decode_int(inline).expect("small integer decodes"), -7);
    assert_eq!(store.boxed_int_count(), 0);

    let wide_value = i64::from(i32::MAX) + 1;
    let wide = store.encode_int(wide_value).expect("wide integer boxes");
    assert_eq!(
        store.encode_int(wide_value).expect("wide integer reuses"),
        wide
    );
    assert_eq!(
        store.decode_int(wide).expect("wide integer decodes"),
        wide_value
    );
    assert_eq!(store.boxed_int_count(), 1);

    let nan_bits = 0x7ff8_0000_0000_0042;
    let float = store
        .encode_float(f64::from_bits(nan_bits))
        .expect("float boxes");
    assert_eq!(
        store
            .encode_float(f64::from_bits(nan_bits))
            .expect("float reuses"),
        float
    );
    assert_eq!(
        store.decode_float(float).expect("float decodes").to_bits(),
        nan_bits
    );
    assert_eq!(store.boxed_float_count(), 1);
    assert_eq!(
        arena.permanent_stats().used_bytes,
        arena
            .reservation_stats()
            .expect("reservation stats")
            .low_used_bytes
    );
}

#[test]
fn scalar_store_retirement_rejects_old_words_and_reuses_its_domain() {
    let arena = SharedFlatStoreArena::new();
    let mut store = CandidateCScalarStore::new(arena);
    let inline = store.encode_int(-7).expect("small integer encodes");
    let wide_value = i64::from(i32::MAX) + 1;
    let old_int = store.encode_int(wide_value).expect("wide integer boxes");
    let old_float = store.encode_float(-0.0).expect("float boxes");
    let domain = old_int.arena_domain().expect("boxed word has a domain");

    let report = store
        .retire_all_boxed()
        .expect("valid scalar population retires");

    assert_eq!(report.retired_ints(), 1);
    assert_eq!(report.retired_floats(), 1);
    assert_eq!(report.arena_domain(), Some(domain));
    assert!(
        report.zero_page_advice().is_some(),
        "a live reservation reports its zero-page advice outcome"
    );
    assert_eq!(store.boxed_int_count(), 0);
    assert_eq!(store.boxed_float_count(), 0);
    assert!(store.decode_int(old_int).is_err());
    assert!(store.decode_float(old_float).is_err());
    assert_eq!(
        store
            .decode_int(inline)
            .expect("inline values survive store retirement"),
        -7
    );

    let new_int = store
        .encode_int(wide_value)
        .expect("boxing resumes after retirement");
    let new_float = store
        .encode_float(-0.0)
        .expect("float boxing resumes after retirement");
    assert_ne!(new_int, old_int);
    assert_ne!(new_float, old_float);
    assert_eq!(new_int.arena_domain(), Some(domain));
    assert_eq!(new_float.arena_domain(), Some(domain));
    assert_eq!(
        store.decode_int(new_int).expect("new integer decodes"),
        wide_value
    );
    assert_eq!(
        store
            .decode_float(new_float)
            .expect("new float decodes")
            .to_bits(),
        (-0.0f64).to_bits()
    );
    assert_eq!(store.boxed_int_count(), 1);
    assert_eq!(store.boxed_float_count(), 1);
}

#[test]
fn scalar_store_retirement_validation_error_is_failure_atomic() {
    let mut store = CandidateCScalarStore::new(SharedFlatStoreArena::new());
    let first_value = i64::from(i32::MAX) + 1;
    let second_value = first_value + 1;
    let first = store.encode_int(first_value).expect("first integer boxes");
    let second = store
        .encode_int(second_value)
        .expect("second integer boxes");
    let second_address = *store
        .int_addresses
        .get(&second_value)
        .expect("second hash-cons entry exists");
    store.int_addresses.insert(first_value, second_address);

    assert!(matches!(
        store.retire_all_boxed(),
        Err(CandidateCScalarError::HashConsValueMismatch {
            kind: "integer",
            ..
        })
    ));
    assert_eq!(store.boxed_int_count(), 2);
    assert_eq!(
        store
            .decode_int(first)
            .expect("first cell remains live after refusal"),
        first_value
    );
    assert_eq!(
        store
            .decode_int(second)
            .expect("second cell remains live after refusal"),
        second_value
    );
}

#[test]
fn raw_decoder_rejects_invalid_metadata() {
    let forced_bool = (u64::from(COMPRESSED_FORCED_BIT | 0x02) << 32) | 1;
    assert_eq!(
        CompressedValueWord::from_raw(forced_bool),
        Err(CompressedValueError::ForcedBitOnNonThunk {
            kind: CompressedValueKind::Bool
        })
    );
    assert_eq!(
        CompressedValueWord::from_raw((0x02_u64 << 32) | 7),
        Err(CompressedValueError::InvalidBoolPayload { payload: 7 })
    );
    assert_eq!(
        CompressedValueWord::from_raw((0x03_u64 << 32) | 1),
        Err(CompressedValueError::InvalidNullPayload { payload: 1 })
    );
    assert_eq!(
        CompressedValueWord::from_raw((0x12_u64 << 32) | 8),
        Err(CompressedValueError::MissingArenaDomain {
            kind: CompressedValueKind::List
        })
    );
    assert_eq!(
        CompressedValueWord::from_raw(((0x102_u64) << 32) | 1),
        Err(CompressedValueError::ArenaDomainOnInline {
            kind: CompressedValueKind::Bool,
            domain: 1
        })
    );
}
