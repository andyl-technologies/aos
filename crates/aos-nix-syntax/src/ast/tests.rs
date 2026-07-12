//! Unit tests for the `ast` module (split out for the RFC-0007 §2 cap).

use super::*;

fn span(start: u32, end: u32) -> Span {
    Span::new(start, end)
}

#[test]
fn ids_and_slices_are_u32_sized() {
    assert_eq!(std::mem::size_of::<NodeId>(), 4);
    assert_eq!(std::mem::size_of::<Symbol>(), 4);
    assert_eq!(std::mem::size_of::<ChildSlice>(), 8);
    assert_eq!(std::mem::size_of::<NodeKind>(), 1);
    assert_eq!(std::mem::size_of::<BinOpKind>(), 1);
    assert_eq!(std::mem::size_of::<UnaryOpKind>(), 1);
}

#[test]
fn symbol_table_interns_dense_ids() {
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("a interns");
    let b = symbols.intern(b"b").expect("b interns");
    let a_again = symbols.intern(b"a").expect("a interns again");

    assert_eq!(a.as_u32(), 0);
    assert_eq!(b.as_u32(), 1);
    assert_eq!(a, a_again);
    assert_eq!(symbols.resolve(a), Some(b"a".as_slice()));
    assert_eq!(symbols.resolve(b), Some(b"b".as_slice()));
    assert_eq!(symbols.lookup(b"a"), Some(a));
    assert_eq!(symbols.lookup(b"missing"), None);
}

#[test]
fn symbol_table_tracks_current_lexicographic_ranks() {
    let mut symbols = SymbolTable::new();
    let b = symbols.intern(b"b").expect("b interns");
    let a_ff = symbols.intern(b"a\xff").expect("a-ff interns");
    let a = symbols.intern(b"a").expect("a interns");

    assert_eq!(symbols.lexicographic_rank(a), Some(0));
    assert_eq!(symbols.lexicographic_rank(a_ff), Some(1));
    assert_eq!(symbols.lexicographic_rank(b), Some(2));

    let a_nul = symbols.intern(b"a\x00").expect("a-nul interns");
    assert_eq!(symbols.lexicographic_rank(a), Some(0));
    assert_eq!(symbols.lexicographic_rank(a_nul), Some(1));
    assert_eq!(symbols.lexicographic_rank(a_ff), Some(2));
    assert_eq!(symbols.lexicographic_rank(b), Some(3));
    assert_eq!(symbols.lexicographic_rank(Symbol::new(99)), None);
}

#[test]
fn shared_symbol_table_reports_inserted_and_existing_admissions() {
    let symbols = SharedSymbolTable::new();
    let first = symbols.intern(b"name").expect("first symbol interns");
    let second = symbols.intern(b"name").expect("second symbol reuses");

    assert_eq!(first.symbol(), Symbol::new(0));
    assert_eq!(first.kind(), SharedSymbolAdmissionKind::Inserted);
    assert_eq!(second.symbol(), first.symbol());
    assert_eq!(second.kind(), SharedSymbolAdmissionKind::Existing);

    let snapshot = symbols.snapshot().expect("snapshot succeeds");
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot.resolve(first.symbol()), Some(b"name".as_slice()));
}

#[test]
fn shared_symbol_table_wraps_existing_tables() {
    let mut base = SymbolTable::new();
    let existing = base.intern(b"base").expect("base interns");
    let symbols = SharedSymbolTable::from_table(base);

    let admission = symbols.intern(b"base").expect("existing symbol reuses");

    assert_eq!(admission.symbol(), existing);
    assert_eq!(admission.kind(), SharedSymbolAdmissionKind::Existing);
}

#[test]
fn shared_symbol_table_single_flights_concurrent_same_key_misses() {
    use std::sync::Barrier;
    use std::thread;

    let symbols = SharedSymbolTable::new();
    let barrier = Arc::new(Barrier::new(8));
    let handles = (0..8)
        .map(|_| {
            let symbols = symbols.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                symbols
                    .intern(b"shared")
                    .expect("shared symbol interns from thread")
            })
        })
        .collect::<Vec<_>>();

    let admissions = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread joins"))
        .collect::<Vec<_>>();

    assert!(admissions.iter().all(|admission| {
        admission.symbol() == Symbol::new(0)
            && matches!(
                admission.kind(),
                SharedSymbolAdmissionKind::Inserted | SharedSymbolAdmissionKind::Existing
            )
    }));
    assert_eq!(
        admissions
            .iter()
            .filter(|admission| admission.kind() == SharedSymbolAdmissionKind::Inserted)
            .count(),
        1
    );
    assert_eq!(
        admissions
            .iter()
            .filter(|admission| admission.kind() == SharedSymbolAdmissionKind::Existing)
            .count(),
        7
    );
    assert_eq!(symbols.snapshot().expect("snapshot succeeds").len(), 1);
}

#[test]
fn shared_symbol_table_keeps_mixed_key_race_snapshot_coherent() {
    use std::collections::BTreeMap;
    use std::sync::Barrier;
    use std::thread;

    let keys = [
        b"alpha".as_slice(),
        b"beta".as_slice(),
        b"gamma".as_slice(),
        b"delta".as_slice(),
    ];
    let symbols = SharedSymbolTable::new();
    let barrier = Arc::new(Barrier::new(keys.len()));
    let handles = keys
        .iter()
        .copied()
        .map(|key| {
            let symbols = symbols.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let admission = symbols
                    .intern(key)
                    .expect("distinct symbol interns from thread");
                (key.to_vec(), admission)
            })
        })
        .collect::<Vec<_>>();

    let mut by_key = BTreeMap::new();
    for handle in handles {
        let (key, admission) = handle.join().expect("thread joins");
        assert_eq!(admission.kind(), SharedSymbolAdmissionKind::Inserted);
        assert_eq!(by_key.insert(key, admission.symbol()), None);
    }

    let snapshot = symbols.snapshot().expect("snapshot succeeds");
    assert_eq!(snapshot.len(), keys.len());
    let mut dense_ids = by_key.values().copied().collect::<Vec<_>>();
    dense_ids.sort_by_key(|symbol| symbol.as_u32());
    dense_ids.dedup();
    assert_eq!(dense_ids.len(), keys.len());
    for (key, symbol) in by_key {
        assert_eq!(snapshot.resolve(symbol), Some(key.as_slice()));
    }
}

#[test]
fn shared_symbol_table_reports_poisoned_lock() {
    use std::thread;

    let symbols = SharedSymbolTable::new();
    let poisoned = symbols.clone();
    let _ = thread::spawn(move || {
        let _guard = poisoned.inner.lock().expect("lock before poison");
        panic!("poison shared symbol table lock");
    })
    .join();

    assert_eq!(
        symbols
            .intern(b"after")
            .expect_err("poisoned lock rejects interning"),
        SharedSymbolTableError::Poisoned
    );
    assert_eq!(
        symbols
            .snapshot()
            .expect_err("poisoned lock rejects snapshots"),
        SharedSymbolTableError::Poisoned
    );
}

#[test]
fn arena_allocates_nodes_in_order() {
    let mut arena = AstArena::new();
    let one = arena
        .push_node(NodeKind::Int, span(0, 1), NodeData::Int(1))
        .expect("first node allocates");
    let two = arena
        .push_node(
            NodeKind::Ident,
            span(2, 5),
            NodeData::Symbol(Symbol::new(7)),
        )
        .expect("second node allocates");

    assert_eq!(one.as_u32(), 0);
    assert_eq!(two.as_u32(), 1);
    assert_eq!(arena.len(), 2);
    assert_eq!(arena.node(one).expect("node exists").kind, NodeKind::Int);
    assert_eq!(arena.node(two).expect("node exists").span, span(2, 5));
}

#[test]
fn child_pool_stores_variable_arity_runs() {
    let mut arena = AstArena::new();
    let a = arena
        .push_node(
            NodeKind::Ident,
            span(0, 1),
            NodeData::Symbol(Symbol::new(1)),
        )
        .expect("a node allocates");
    let b = arena
        .push_node(
            NodeKind::Ident,
            span(2, 3),
            NodeData::Symbol(Symbol::new(2)),
        )
        .expect("b node allocates");
    let slice = arena
        .push_child_slice(&[a, b])
        .expect("child slice allocates");
    let list = arena
        .push_node(NodeKind::List, span(0, 3), NodeData::Children(slice))
        .expect("list node allocates");

    assert_eq!(arena.child_slice(slice).expect("slice is valid"), &[a, b]);
    assert_eq!(
        arena.node(list).expect("list exists").data,
        NodeData::Children(ChildSlice::new(0, 2))
    );
}

#[test]
fn invalid_child_slice_is_reported() {
    let arena = AstArena::new();
    let error = arena
        .child_slice(ChildSlice::new(10, 2))
        .expect_err("invalid slice errors");
    assert_eq!(
        error.kind(),
        &AstErrorKind::InvalidChildSlice { start: 10, len: 2 }
    );
}
