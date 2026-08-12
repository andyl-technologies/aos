//! Ordering-semantics tests for the rank-free small-shape construction path.

use super::*;
use crate::syntax::{Symbol, SymbolTable};

fn symbols(names: &[&[u8]]) -> (SymbolTable, Vec<Symbol>) {
    let mut table = SymbolTable::new();
    let mut ids = Vec::new();
    for name in names {
        ids.push(table.intern(name).expect("symbol interns"));
    }
    (table, ids)
}

#[test]
fn small_shape_construction_matches_general_ordering_semantics() {
    // Two-key shapes take the rank-free construction path; their storage,
    // permutations, inverse rank table, and fingerprint must be raw-equal to
    // what a three-key general construction implies for the same pair. We
    // check against the documented semantics directly with adversarial byte
    // orderings where symbol-id order and raw-byte order diverge.
    let (symbols, ids) = symbols(&[b"b", b"a\xff", b"a", b"a\x00"]);
    for (left, right) in [(0usize, 1usize), (1, 0), (1, 3), (3, 1), (2, 3), (3, 2)] {
        let shape = AttrShape::from_construction_order(&[ids[left], ids[right]], &symbols)
            .expect("two-key shape builds");
        let mut expected_storage = vec![ids[left], ids[right]];
        expected_storage.sort();
        assert_eq!(shape.keys_by_symbol(), expected_storage.as_slice());
        let source: Vec<Symbol> = shape.iter_source_order().collect();
        assert_eq!(source, vec![ids[left], ids[right]]);
        let lex: Vec<&[u8]> = shape
            .iter_lexicographic()
            .map(|key| symbols.resolve(key).expect("symbol resolves"))
            .collect();
        let mut expected_lex = vec![
            symbols.resolve(ids[left]).expect("left resolves"),
            symbols.resolve(ids[right]).expect("right resolves"),
        ];
        expected_lex.sort();
        assert_eq!(lex, expected_lex);
        // The inverse rank table matches the iteration permutation.
        for slot in 0..2u32 {
            let rank = shape
                .lexicographic_rank_for_symbol_slot(slot)
                .expect("slot has a rank");
            assert_eq!(shape.iteration_order()[rank as usize], slot);
        }
    }

    // Singleton and duplicate/unknown error semantics.
    let single =
        AttrShape::from_construction_order(&[ids[1]], &symbols).expect("one-key shape builds");
    assert_eq!(single.source_order(), &[0]);
    assert_eq!(single.iteration_order(), &[0]);
    assert_eq!(single.lexicographic_rank_by_symbol_slot(), &[0]);
    assert!(matches!(
        AttrShape::from_construction_order(&[ids[0], ids[0]], &symbols),
        Err(ShapeError::DuplicateKey { .. })
    ));
    let missing = Symbol::new(99);
    assert!(matches!(
        AttrShape::from_construction_order(&[missing], &symbols),
        Err(ShapeError::UnknownSymbol { .. })
    ));
}
