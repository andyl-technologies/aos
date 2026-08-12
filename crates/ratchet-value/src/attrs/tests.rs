//! Unit tests for flat attrset storage, ordering, and selection.

use super::*;

fn symbols(names: &[&[u8]]) -> (SymbolTable, Vec<Symbol>) {
    let mut table = SymbolTable::new();
    let mut ids = Vec::new();
    for name in names {
        ids.push(table.intern(name).expect("symbol interns"));
    }
    (table, ids)
}

fn keys(entries: &[AttrEntry]) -> Vec<Symbol> {
    entries.iter().map(|entry| entry.key).collect()
}

#[test]
fn lexicographic_prefix_never_contradicts_raw_byte_order() {
    let values: &[&[u8]] = &[
        b"",
        b"\0",
        b"\0\0",
        b"a",
        b"abcdefg",
        b"abcdefgh",
        b"abcdefh",
        b"same-prefix-left",
        b"same-prefix-right",
        b"\x7f",
        b"\x80",
        b"\xff",
        b"\xff\0",
    ];

    for left in values {
        for right in values {
            let token_order = lexicographic_prefix(left).cmp(&lexicographic_prefix(right));
            let byte_order = left.cmp(right);
            if token_order != std::cmp::Ordering::Equal {
                assert_eq!(token_order, byte_order, "{left:?} versus {right:?}");
            }
        }
    }
}

#[test]
fn empty_attrset_has_no_entries() {
    let attrs = FlatAttrs::empty();
    assert!(attrs.is_empty());
    assert_eq!(attrs.len(), 0);
    assert!(attrs.entries_by_symbol().is_empty());
    assert!(attrs.source_order().is_empty());
    assert!(attrs.iteration_order().is_empty());
    assert_eq!(attrs.iter_source_order().len(), 0);
    assert_eq!(attrs.iter_lexicographic().len(), 0);
}

#[test]
fn entries_are_sorted_by_symbol_for_lookup() {
    let (symbols, ids) = symbols(&[b"z", b"a", b"m"]);
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(ids[2], Value::int(3)),
            AttrEntry::new(ids[1], Value::int(2)),
            AttrEntry::new(ids[0], Value::int(1)),
        ],
        &symbols,
    )
    .expect("attrset builds");

    assert_eq!(keys(attrs.entries_by_symbol()), ids);
    assert_eq!(attrs.get(ids[0]).expect("z exists").as_int(), Ok(1));
    assert_eq!(attrs.get(ids[1]).expect("a exists").as_int(), Ok(2));
    assert_eq!(attrs.get(ids[2]).expect("m exists").as_int(), Ok(3));
    assert!(!attrs.contains_key(Symbol::new(99)));
}

#[test]
fn source_order_iteration_uses_construction_order() {
    let (symbols, ids) = symbols(&[b"z", b"a", b"m"]);
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(ids[2], Value::int(3)),
            AttrEntry::new(ids[1], Value::int(2)),
            AttrEntry::new(ids[0], Value::int(1)),
        ],
        &symbols,
    )
    .expect("attrset builds");

    let keys: Vec<Symbol> = attrs.iter_source_order().map(|entry| entry.key).collect();
    assert_eq!(keys, vec![ids[2], ids[1], ids[0]]);
    assert_eq!(attrs.source_order(), &[2, 1, 0]);
}

#[test]
fn symbol_slot_replacement_preserves_permutations() {
    let (symbols, ids) = symbols(&[b"z", b"a", b"m"]);
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(ids[2], Value::int(3)),
            AttrEntry::new(ids[1], Value::int(2)),
            AttrEntry::new(ids[0], Value::int(1)),
        ],
        &symbols,
    )
    .expect("attrset builds");

    let replaced = attrs
        .with_symbol_slot_value(1, ids[1], Value::int(22))
        .expect("symbol slot replacement succeeds");

    assert_eq!(attrs.source_order(), replaced.source_order());
    assert_eq!(attrs.iteration_order(), replaced.iteration_order());
    assert_eq!(replaced.get(ids[0]).expect("z exists").as_int(), Ok(1));
    assert_eq!(replaced.get(ids[1]).expect("a exists").as_int(), Ok(22));
    assert_eq!(replaced.get(ids[2]).expect("m exists").as_int(), Ok(3));
}

#[test]
fn symbol_slot_replacement_rejects_stale_slot_metadata() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(1)),
            AttrEntry::new(ids[1], Value::int(2)),
        ],
        &symbols,
    )
    .expect("attrset builds");

    let out_of_bounds = attrs
        .with_symbol_slot_value(7, ids[0], Value::int(9))
        .expect_err("out-of-bounds slot rejects replacement");
    assert_eq!(
        out_of_bounds,
        AttrError::SlotOutOfBounds { slot: 7, len: 2 }
    );
    let key_mismatch = attrs
        .with_symbol_slot_value(1, ids[0], Value::int(9))
        .expect_err("stale slot key rejects replacement");
    assert_eq!(
        key_mismatch,
        AttrError::SlotKeyMismatch {
            slot: 1,
            expected: ids[0],
            actual: ids[1],
        }
    );
}

#[test]
fn lexicographic_iteration_uses_raw_symbol_bytes() {
    let (symbols, ids) = symbols(&[b"b", b"a\xff", b"a", b"a\x00"]);
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(0)),
            AttrEntry::new(ids[1], Value::int(1)),
            AttrEntry::new(ids[2], Value::int(2)),
            AttrEntry::new(ids[3], Value::int(3)),
        ],
        &symbols,
    )
    .expect("attrset builds");

    let names: Vec<&[u8]> = attrs
        .iter_lexicographic()
        .map(|entry| symbols.resolve(entry.key).expect("symbol resolves"))
        .collect();
    assert_eq!(
        names,
        vec![
            b"a".as_slice(),
            b"a\x00".as_slice(),
            b"a\xff".as_slice(),
            b"b".as_slice(),
        ]
    );
    assert_eq!(attrs.iteration_order(), &[2, 3, 1, 0]);
}

#[test]
fn raw_equality_includes_values_order_and_positions() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let base = FlatAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(1)),
            AttrEntry::new(ids[1], Value::int(2)),
        ],
        &symbols,
    )
    .expect("attrset builds");
    let same = FlatAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(1)),
            AttrEntry::new(ids[1], Value::int(2)),
        ],
        &symbols,
    )
    .expect("matching attrset builds");
    let different_value = FlatAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(1)),
            AttrEntry::new(ids[1], Value::int(3)),
        ],
        &symbols,
    )
    .expect("different-value attrset builds");
    let different_order = FlatAttrs::new(
        vec![
            AttrEntry::new(ids[1], Value::int(2)),
            AttrEntry::new(ids[0], Value::int(1)),
        ],
        &symbols,
    )
    .expect("different-order attrset builds");
    let positioned = FlatAttrs::new(
        vec![AttrEntry::with_position(
            ids[0],
            Value::int(1),
            AttrPosition::new(0, Span::new(0, 1)),
        )],
        &symbols,
    )
    .expect("positioned attrset builds");
    let unpositioned = FlatAttrs::new(vec![AttrEntry::new(ids[0], Value::int(1))], &symbols)
        .expect("unpositioned attrset builds");

    assert!(base.raw_eq(&same));
    assert!(!base.raw_eq(&different_value));
    assert!(!base.raw_eq(&different_order));
    assert!(!positioned.raw_eq(&unpositioned));
}

#[test]
fn duplicate_symbols_are_rejected() {
    let (symbols, ids) = symbols(&[b"a"]);
    let error = FlatAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(1)),
            AttrEntry::new(ids[0], Value::int(2)),
        ],
        &symbols,
    )
    .expect_err("duplicate key is invalid");

    assert_eq!(error, AttrError::DuplicateKey { key: ids[0] });
}

#[test]
fn missing_symbols_are_rejected() {
    let symbols = SymbolTable::new();
    let missing = Symbol::new(7);
    let error = FlatAttrs::new(vec![AttrEntry::new(missing, Value::null())], &symbols)
        .expect_err("unknown key is invalid");

    assert_eq!(error, AttrError::UnknownSymbol { key: missing });
}

#[test]
fn exact_size_lexicographic_iterator_tracks_remaining_entries() {
    let (symbols, ids) = symbols(&[b"c", b"a", b"b"]);
    let attrs = FlatAttrs::new(
        ids.iter()
            .copied()
            .map(|symbol| AttrEntry::new(symbol, Value::bool(true)))
            .collect(),
        &symbols,
    )
    .expect("attrset builds");
    let mut iter = attrs.iter_lexicographic();

    assert_eq!(iter.len(), 3);
    assert_eq!(
        symbols.resolve(iter.next().expect("first").key),
        Some(&b"a"[..])
    );
    assert_eq!(iter.len(), 2);
    assert_eq!(
        symbols.resolve(iter.next().expect("second").key),
        Some(&b"b"[..])
    );
    assert_eq!(
        symbols.resolve(iter.next().expect("third").key),
        Some(&b"c"[..])
    );
    assert!(iter.next().is_none());
}

#[test]
fn small_construction_matches_general_ordering_semantics() {
    // Adversarial byte orderings where symbol-id order and lexicographic
    // order diverge, in both construction orders. The two-entry path
    // avoids rank reads; its permutations must match the documented
    // semantics exactly.
    let (symbols, ids) = symbols(&[b"b", b"a\xff", b"a", b"a\x00"]);
    for (left, right) in [(0, 1), (1, 0), (1, 3), (3, 1), (2, 3), (3, 2)] {
        let attrs = FlatAttrs::new(
            vec![
                AttrEntry::new(ids[left], Value::int(left as i64)),
                AttrEntry::new(ids[right], Value::int(right as i64)),
            ],
            &symbols,
        )
        .expect("two-entry attrset builds");
        // Storage sorted by symbol id.
        let stored: Vec<Symbol> = attrs.iter_by_symbol().map(|entry| entry.key).collect();
        let mut expected_storage = vec![ids[left], ids[right]];
        expected_storage.sort();
        assert_eq!(stored, expected_storage);
        // Source order reproduces construction order.
        let source: Vec<Symbol> = attrs.iter_source_order().map(|entry| entry.key).collect();
        assert_eq!(source, vec![ids[left], ids[right]]);
        // Lexicographic order follows raw bytes.
        let lex: Vec<&[u8]> = attrs
            .iter_lexicographic()
            .map(|entry| symbols.resolve(entry.key).expect("symbol resolves"))
            .collect();
        let mut expected_lex = vec![
            symbols.resolve(ids[left]).unwrap(),
            symbols.resolve(ids[right]).unwrap(),
        ];
        expected_lex.sort();
        assert_eq!(lex, expected_lex);
    }
    // Singleton path validates the symbol and orders trivially.
    let single = FlatAttrs::new(vec![AttrEntry::new(ids[1], Value::int(7))], &symbols)
        .expect("one-entry attrset builds");
    assert_eq!(single.source_order(), &[0]);
    assert_eq!(single.iteration_order(), &[0]);
    let missing = Symbol::new(99);
    assert_eq!(
        FlatAttrs::new(vec![AttrEntry::new(missing, Value::int(1))], &symbols)
            .expect_err("unknown key is invalid"),
        AttrError::UnknownSymbol { key: missing }
    );
}

#[test]
fn lexicographic_order_uses_current_symbol_bytes_after_more_interning() {
    let mut symbols = SymbolTable::new();
    let b = symbols.intern(b"b").expect("b interns");
    let a_ff = symbols.intern(b"a\xff").expect("a-ff interns");
    let base = FlatAttrs::new(
        vec![
            AttrEntry::new(b, Value::int(1)),
            AttrEntry::new(a_ff, Value::int(2)),
        ],
        &symbols,
    )
    .expect("base attrset builds");

    let a = symbols.intern(b"a").expect("a interns later");
    let a_nul = symbols.intern(b"a\x00").expect("a-nul interns later");
    let later = FlatAttrs::new(
        vec![
            AttrEntry::new(b, Value::int(1)),
            AttrEntry::new(a_ff, Value::int(2)),
            AttrEntry::new(a, Value::int(3)),
            AttrEntry::new(a_nul, Value::int(4)),
        ],
        &symbols,
    )
    .expect("later attrset builds");

    let base_names: Vec<&[u8]> = base
        .iter_lexicographic()
        .map(|entry| symbols.resolve(entry.key).expect("symbol resolves"))
        .collect();
    let later_names: Vec<&[u8]> = later
        .iter_lexicographic()
        .map(|entry| symbols.resolve(entry.key).expect("symbol resolves"))
        .collect();

    assert_eq!(base_names, vec![b"a\xff".as_slice(), b"b".as_slice()]);
    assert_eq!(
        later_names,
        vec![
            b"a".as_slice(),
            b"a\x00".as_slice(),
            b"a\xff".as_slice(),
            b"b".as_slice(),
        ]
    );
}

/// The default-deny storage classifier: owned arrays classify as `Owned`
/// (must ride an owned-attrs payload segment at heap-image capture) and the
/// classifier match is wildcard-free, so a new `AttrsStorage` variant fails
/// to compile in `storage_kind` before it can silently restore dangling.
#[cfg(feature = "candidate_c_value")]
#[test]
fn storage_kind_classifies_owned_arrays_for_capture() {
    let entries = vec![
        AttrEntry::new(Symbol::new(1), Value::int(1)),
        AttrEntry::new(Symbol::new(2), Value::int(2)),
    ];
    let attrs = FlatAttrs::from_restored_parts(entries, vec![0, 1], vec![0, 1]);
    assert_eq!(attrs.storage_kind(), super::AttrsStorageKind::Owned);
    assert_eq!(
        FlatAttrs::empty().storage_kind(),
        super::AttrsStorageKind::Owned,
        "an empty attrset is owned-storage (empty Vecs; trivially safe either way)"
    );
}
