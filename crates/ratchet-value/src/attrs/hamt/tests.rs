//! Unit tests for persistent HAMT attr storage.

use super::*;
use crate::attrs::{AttrError, AttrPosition};
use crate::syntax::Span;
use crate::value::Value;

fn symbols(names: &[&[u8]]) -> (SymbolTable, Vec<Symbol>) {
    let mut table = SymbolTable::new();
    let mut ids = Vec::new();
    for name in names {
        ids.push(table.intern(name).expect("symbol interns"));
    }
    (table, ids)
}

fn many_symbols(count: usize) -> (SymbolTable, Vec<Symbol>) {
    let mut table = SymbolTable::new();
    let mut ids = Vec::new();
    for index in 0..count {
        let name = format!("key-{index:02}");
        ids.push(table.intern(name.as_bytes()).expect("symbol interns"));
    }
    (table, ids)
}

fn int_value(attrs: &HamtAttrs, key: Symbol) -> i64 {
    attrs
        .get(key)
        .expect("key exists")
        .as_int()
        .expect("value is int")
}

fn root_node_child(attrs: &HamtAttrs, chunk: u32) -> Arc<HamtNode> {
    let root = attrs.root.as_ref().expect("root exists");
    let bit = 1 << chunk;
    let slot = sparse_index(root.bitmap, bit);
    match root.slots.get(slot).expect("root slot exists") {
        HamtSlot::Node(child) => child.clone(),
        HamtSlot::Entry(_) => panic!("root slot should contain a child node"),
    }
}

#[test]
fn empty_hamt_has_no_entries() {
    let attrs = HamtAttrs::empty();

    assert!(attrs.is_empty());
    assert_eq!(attrs.len(), 0);
    assert!(attrs.keys_by_symbol().is_empty());
    assert!(attrs.iteration_order().is_empty());
    assert_eq!(attrs.iter_by_symbol().len(), 0);
    assert_eq!(attrs.iter_lexicographic().len(), 0);
}

#[test]
fn construction_sorts_keys_for_lookup_and_preserves_lexicographic_view() {
    let (symbols, ids) = symbols(&[b"b", b"a\xff", b"a", b"a\x00"]);
    let attrs = HamtAttrs::new(
        vec![
            AttrEntry::new(ids[3], Value::int(3)),
            AttrEntry::new(ids[1], Value::int(1)),
            AttrEntry::new(ids[0], Value::int(0)),
            AttrEntry::new(ids[2], Value::int(2)),
        ],
        &symbols,
    )
    .expect("HAMT builds");

    assert_eq!(attrs.keys_by_symbol(), ids.as_slice());
    assert_eq!(int_value(&attrs, ids[0]), 0);
    assert_eq!(int_value(&attrs, ids[1]), 1);
    assert_eq!(int_value(&attrs, ids[2]), 2);
    assert_eq!(int_value(&attrs, ids[3]), 3);
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
}

#[test]
fn construction_rejects_duplicate_and_unknown_keys() {
    let (symbols, ids) = symbols(&[b"a"]);
    let duplicate = HamtAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(1)),
            AttrEntry::new(ids[0], Value::int(2)),
        ],
        &symbols,
    )
    .expect_err("duplicate key is invalid");
    assert_eq!(duplicate, HamtError::DuplicateKey { key: ids[0] });

    let missing = Symbol::new(7);
    let unknown = HamtAttrs::new(vec![AttrEntry::new(missing, Value::null())], &symbols)
        .expect_err("unknown key is invalid");
    assert_eq!(unknown, HamtError::UnknownSymbol { key: missing });
}

#[test]
fn nested_branches_lookup_distinct_dense_symbols() {
    let (symbols, ids) = many_symbols(34);
    let attrs = HamtAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(0)),
            AttrEntry::new(ids[32], Value::int(32)),
            AttrEntry::new(ids[33], Value::int(33)),
        ],
        &symbols,
    )
    .expect("HAMT builds");

    assert_eq!(int_value(&attrs, ids[0]), 0);
    assert_eq!(int_value(&attrs, ids[32]), 32);
    assert_eq!(int_value(&attrs, ids[33]), 33);
    let root = attrs.root.as_ref().expect("root exists");
    assert_eq!(root.bitmap.count_ones(), 2);
    assert!(
        root.slots
            .iter()
            .any(|slot| matches!(slot, HamtSlot::Node(_))),
        "symbols 0 and 32 share the low trie chunk and should branch below root"
    );
}

#[test]
fn nested_insert_and_replace_share_unmodified_root_branches() {
    let (symbols, ids) = many_symbols(65);
    let base = HamtAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(0)),
            AttrEntry::new(ids[32], Value::int(32)),
            AttrEntry::new(ids[1], Value::int(1)),
            AttrEntry::new(ids[33], Value::int(33)),
        ],
        &symbols,
    )
    .expect("base HAMT builds");
    let untouched_before = root_node_child(&base, chunk_for(ids[1], 0));

    let (inserted, insert_update) = base
        .insert(AttrEntry::new(ids[64], Value::int(64)), &symbols)
        .expect("nested insert succeeds");
    assert_eq!(insert_update, HamtUpdate::Inserted);
    assert!(!base.contains_key(ids[64]));
    assert_eq!(int_value(&inserted, ids[64]), 64);
    assert!(std::sync::Arc::ptr_eq(
        &untouched_before,
        &root_node_child(&inserted, chunk_for(ids[1], 0))
    ));

    let (replaced, replace_update) = base
        .insert(AttrEntry::new(ids[32], Value::int(320)), &symbols)
        .expect("nested replace succeeds");
    assert_eq!(
        replace_update,
        HamtUpdate::Replaced {
            previous: AttrEntry::new(ids[32], Value::int(32)),
        }
    );
    assert_eq!(int_value(&base, ids[32]), 32);
    assert_eq!(int_value(&replaced, ids[32]), 320);
    assert!(std::sync::Arc::ptr_eq(
        &untouched_before,
        &root_node_child(&replaced, chunk_for(ids[1], 0))
    ));
}

#[test]
fn insert_new_key_preserves_old_root_and_updates_cached_orders() {
    let (symbols, ids) = symbols(&[b"b", b"a", b"c"]);
    let base = HamtAttrs::new(vec![AttrEntry::new(ids[0], Value::int(1))], &symbols)
        .expect("base HAMT builds");
    let (updated, mutation) = base
        .insert(AttrEntry::new(ids[1], Value::int(2)), &symbols)
        .expect("insert succeeds");

    assert_eq!(mutation, HamtUpdate::Inserted);
    assert_eq!(base.len(), 1);
    assert!(!base.contains_key(ids[1]));
    assert_eq!(updated.len(), 2);
    assert_eq!(int_value(&updated, ids[0]), 1);
    assert_eq!(int_value(&updated, ids[1]), 2);
    assert_eq!(updated.keys_by_symbol(), &[ids[0], ids[1]]);
    let names: Vec<&[u8]> = updated
        .iter_lexicographic()
        .map(|entry| symbols.resolve(entry.key).expect("symbol resolves"))
        .collect();
    assert_eq!(names, vec![b"a".as_slice(), b"b".as_slice()]);
}

#[test]
fn incremental_insert_order_matches_batch_across_rank_renumbering() {
    // Interning a lexicographically-earlier key after `base` is built renumbers
    // every rank; the incremental splice must still produce the byte-order
    // identical to a batch rebuild (the guarantee the O(n) insert relies on).
    let mut table = SymbolTable::new();
    let m = table.intern(b"m").expect("m interns");
    let base = HamtAttrs::new(vec![AttrEntry::new(m, Value::int(1))], &table).expect("base builds");

    // These intern AFTER `base`; "a" sorts before "m", so all ranks renumber.
    let a = table.intern(b"a").expect("a interns");
    let z = table.intern(b"z").expect("z interns");
    let (step, _) = base
        .insert(AttrEntry::new(a, Value::int(2)), &table)
        .expect("insert a");
    let (incremental, _) = step
        .insert(AttrEntry::new(z, Value::int(3)), &table)
        .expect("insert z");

    let batch = HamtAttrs::new(
        vec![
            AttrEntry::new(m, Value::int(1)),
            AttrEntry::new(a, Value::int(2)),
            AttrEntry::new(z, Value::int(3)),
        ],
        &table,
    )
    .expect("batch builds");

    assert_eq!(incremental.iteration_order(), batch.iteration_order());
    let names: Vec<&[u8]> = incremental
        .iter_lexicographic()
        .map(|entry| table.resolve(entry.key).expect("symbol resolves"))
        .collect();
    assert_eq!(
        names,
        vec![b"a".as_slice(), b"m".as_slice(), b"z".as_slice()]
    );
}

#[test]
fn insert_existing_key_replaces_value_without_changing_old_root() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let base = HamtAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(1)),
            AttrEntry::new(ids[1], Value::int(2)),
        ],
        &symbols,
    )
    .expect("base HAMT builds");
    let (updated, mutation) = base
        .insert(AttrEntry::new(ids[0], Value::int(3)), &symbols)
        .expect("replace succeeds");

    assert_eq!(
        mutation,
        HamtUpdate::Replaced {
            previous: AttrEntry::new(ids[0], Value::int(1)),
        }
    );
    assert_eq!(base.len(), 2);
    assert_eq!(int_value(&base, ids[0]), 1);
    assert_eq!(updated.len(), 2);
    assert_eq!(int_value(&updated, ids[0]), 3);
    assert_eq!(updated.keys_by_symbol(), base.keys_by_symbol());
    assert_eq!(updated.iteration_order(), base.iteration_order());
}

#[test]
fn update_from_flat_is_right_biased_and_preserves_left_root() {
    let (symbols, ids) = symbols(&[b"a", b"b", b"c", b"d"]);
    let base = HamtAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(10)),
            AttrEntry::with_position(
                ids[1],
                Value::int(20),
                AttrPosition::new(0, Span::new(2, 3)),
            ),
            AttrEntry::new(ids[2], Value::int(30)),
        ],
        &symbols,
    )
    .expect("base HAMT builds");
    let right = FlatAttrs::new(
        vec![
            AttrEntry::with_position(
                ids[1],
                Value::int(200),
                AttrPosition::new(1, Span::new(4, 5)),
            ),
            AttrEntry::new(ids[3], Value::int(40)),
        ],
        &symbols,
    )
    .expect("right flat attrs build");

    let (merged, summary) = base
        .update_from_flat(&right, &symbols)
        .expect("flat update merge succeeds");

    assert_eq!(summary.inserted(), 1);
    assert_eq!(summary.replaced(), 1);
    assert_eq!(summary.applied(), 2);
    assert_eq!(base.len(), 3);
    assert!(!base.contains_key(ids[3]));
    assert_eq!(int_value(&base, ids[1]), 20);
    assert_eq!(merged.len(), 4);
    assert_eq!(int_value(&merged, ids[0]), 10);
    assert_eq!(int_value(&merged, ids[1]), 200);
    assert_eq!(int_value(&merged, ids[2]), 30);
    assert_eq!(int_value(&merged, ids[3]), 40);
    assert_eq!(
        merged.get_entry(ids[1]).expect("b exists").position,
        Some(AttrPosition::new(1, Span::new(4, 5)))
    );
    assert_eq!(merged.keys_by_symbol(), ids.as_slice());
}

#[test]
fn update_from_flat_recomputes_raw_byte_lexicographic_order() {
    let (symbols, ids) = symbols(&[b"b", b"a\xff", b"a", b"a\x00"]);
    let base = HamtAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(10)),
            AttrEntry::new(ids[1], Value::int(20)),
        ],
        &symbols,
    )
    .expect("base HAMT builds");
    let right = FlatAttrs::new(
        vec![
            AttrEntry::new(ids[2], Value::int(30)),
            AttrEntry::new(ids[3], Value::int(40)),
        ],
        &symbols,
    )
    .expect("right flat attrs build");

    let (merged, summary) = base
        .update_from_flat(&right, &symbols)
        .expect("flat update merge succeeds");

    assert_eq!(summary.inserted(), 2);
    assert_eq!(summary.replaced(), 0);
    assert_eq!(merged.keys_by_symbol(), ids.as_slice());
    let names: Vec<&[u8]> = merged
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
}

#[test]
fn update_from_hamt_shares_untouched_branches() {
    let (symbols, ids) = many_symbols(65);
    let base = HamtAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(0)),
            AttrEntry::new(ids[32], Value::int(32)),
            AttrEntry::new(ids[1], Value::int(1)),
            AttrEntry::new(ids[33], Value::int(33)),
        ],
        &symbols,
    )
    .expect("base HAMT builds");
    let right = HamtAttrs::new(
        vec![
            AttrEntry::new(ids[32], Value::int(320)),
            AttrEntry::new(ids[64], Value::int(64)),
        ],
        &symbols,
    )
    .expect("right HAMT builds");
    let untouched_before = root_node_child(&base, chunk_for(ids[1], 0));

    let (merged, summary) = base
        .update_from_hamt(&right, &symbols)
        .expect("HAMT update merge succeeds");

    assert_eq!(summary.inserted(), 1);
    assert_eq!(summary.replaced(), 1);
    assert_eq!(base.len(), 4);
    assert!(!base.contains_key(ids[64]));
    assert_eq!(int_value(&base, ids[32]), 32);
    assert_eq!(merged.len(), 5);
    assert_eq!(int_value(&merged, ids[32]), 320);
    assert_eq!(int_value(&merged, ids[64]), 64);
    assert!(std::sync::Arc::ptr_eq(
        &untouched_before,
        &root_node_child(&merged, chunk_for(ids[1], 0))
    ));
}

#[test]
fn update_merge_with_empty_right_operand_is_accounted_as_empty() {
    let (symbols, ids) = symbols(&[b"a"]);
    let base = HamtAttrs::new(vec![AttrEntry::new(ids[0], Value::int(1))], &symbols)
        .expect("base HAMT builds");
    let right = FlatAttrs::empty();

    let (merged, summary) = base
        .update_from_flat(&right, &symbols)
        .expect("empty update merge succeeds");

    assert_eq!(summary, HamtMergeSummary::default());
    assert!(summary.is_empty());
    assert!(base.raw_eq(&merged));
}

#[test]
fn cached_lexicographic_view_uses_current_symbol_rank_snapshot() {
    let mut symbols = SymbolTable::new();
    let b = symbols.intern(b"b").expect("b interns");
    let a_ff = symbols.intern(b"a\xff").expect("a-ff interns");
    let base = HamtAttrs::new(
        vec![
            AttrEntry::new(b, Value::int(1)),
            AttrEntry::new(a_ff, Value::int(2)),
        ],
        &symbols,
    )
    .expect("base HAMT builds");

    let a = symbols.intern(b"a").expect("a interns later");
    let a_nul = symbols.intern(b"a\x00").expect("a-nul interns later");
    let (with_a, _) = base
        .insert(AttrEntry::new(a, Value::int(3)), &symbols)
        .expect("first insert succeeds");
    let (updated, _) = with_a
        .insert(AttrEntry::new(a_nul, Value::int(4)), &symbols)
        .expect("second insert succeeds");

    let base_names: Vec<&[u8]> = base
        .iter_lexicographic()
        .map(|entry| symbols.resolve(entry.key).expect("symbol resolves"))
        .collect();
    let updated_names: Vec<&[u8]> = updated
        .iter_lexicographic()
        .map(|entry| symbols.resolve(entry.key).expect("symbol resolves"))
        .collect();

    assert_eq!(base_names, vec![b"a\xff".as_slice(), b"b".as_slice()]);
    assert_eq!(
        updated_names,
        vec![
            b"a".as_slice(),
            b"a\x00".as_slice(),
            b"a\xff".as_slice(),
            b"b".as_slice(),
        ]
    );
}

#[test]
fn raw_equality_includes_values_keys_and_positions() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let left = HamtAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(1)),
            AttrEntry::new(ids[1], Value::int(2)),
        ],
        &symbols,
    )
    .expect("left builds");
    let same = HamtAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(1)),
            AttrEntry::new(ids[1], Value::int(2)),
        ],
        &symbols,
    )
    .expect("same builds");
    let different_value = HamtAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(1)),
            AttrEntry::new(ids[1], Value::int(3)),
        ],
        &symbols,
    )
    .expect("different value builds");
    let positioned = HamtAttrs::new(
        vec![AttrEntry::with_position(
            ids[0],
            Value::int(1),
            AttrPosition::new(0, Span::new(0, 1)),
        )],
        &symbols,
    )
    .expect("positioned builds");
    let unpositioned = HamtAttrs::new(vec![AttrEntry::new(ids[0], Value::int(1))], &symbols)
        .expect("unpositioned builds");

    assert!(left.raw_eq(&same));
    assert!(!left.raw_eq(&different_value));
    assert!(!positioned.raw_eq(&unpositioned));
}

#[test]
fn from_flat_preserves_lookup_and_lexicographic_order() {
    let (symbols, ids) = symbols(&[b"z", b"a", b"m"]);
    let flat = FlatAttrs::new(
        vec![
            AttrEntry::new(ids[2], Value::int(3)),
            AttrEntry::new(ids[1], Value::int(2)),
            AttrEntry::new(ids[0], Value::int(1)),
        ],
        &symbols,
    )
    .expect("flat builds");
    let hamt = HamtAttrs::from_flat(&flat, &symbols).expect("HAMT builds from flat");

    assert_eq!(hamt.len(), flat.len());
    assert_eq!(int_value(&hamt, ids[0]), 1);
    assert_eq!(int_value(&hamt, ids[1]), 2);
    assert_eq!(int_value(&hamt, ids[2]), 3);
    let flat_names: Vec<&[u8]> = flat
        .iter_lexicographic()
        .map(|entry| symbols.resolve(entry.key).expect("symbol resolves"))
        .collect();
    let hamt_names: Vec<&[u8]> = hamt
        .iter_lexicographic()
        .map(|entry| symbols.resolve(entry.key).expect("symbol resolves"))
        .collect();
    assert_eq!(hamt_names, flat_names);
}

#[test]
fn flat_duplicate_error_surface_stays_distinct_from_hamt_errors() {
    let (symbols, ids) = symbols(&[b"a"]);
    let flat_error = FlatAttrs::new(
        vec![
            AttrEntry::new(ids[0], Value::int(1)),
            AttrEntry::new(ids[0], Value::int(2)),
        ],
        &symbols,
    )
    .expect_err("flat duplicate key is invalid");

    assert_eq!(flat_error, AttrError::DuplicateKey { key: ids[0] });
}

#[cfg(debug_assertions)]
#[test]
fn bulk_build_matches_sequential_insertion() {
    for count in [0usize, 1, 2, 3, 5, 8, 16, 31, 32, 33, 40, 64, 100] {
        let (_symbols, ids) = many_symbols(count);
        let mut entries: Vec<AttrEntry> = ids
            .iter()
            .enumerate()
            .map(|(index, &id)| AttrEntry::new(id, Value::int(index as i64)))
            .collect();
        entries.sort_unstable_by_key(|entry| entry.key);
        let bulk = build_root(&entries).expect("bulk build succeeds");
        let sequential = build_root_sequential(&entries).expect("sequential build succeeds");
        assert!(
            roots_structurally_equal(bulk.as_deref(), sequential.as_deref()),
            "bulk and sequential HAMT construction diverged for {count} entries",
        );
    }
}
