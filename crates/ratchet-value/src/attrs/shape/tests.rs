//! Unit tests for shape descriptors, tables, plans, and shaped attrs.

use super::*;
use crate::syntax::{Symbol, SymbolTable};
use crate::value::Value;

fn symbols(names: &[&[u8]]) -> (SymbolTable, Vec<Symbol>) {
    let mut table = SymbolTable::new();
    let mut ids = Vec::new();
    for name in names {
        ids.push(table.intern(name).expect("symbol interns"));
    }
    (table, ids)
}

#[test]
fn empty_shapes_have_empty_orders_and_a_stable_fingerprint() {
    let shape = AttrShape::empty();
    let other = AttrShape::empty();

    assert!(shape.is_empty());
    assert_eq!(shape.len(), 0);
    assert_eq!(shape.keys_by_symbol(), &[]);
    assert_eq!(shape.source_order(), &[]);
    assert_eq!(shape.iteration_order(), &[]);
    assert_eq!(shape.lexicographic_rank_by_symbol_slot(), &[]);
    assert_eq!(shape.lexicographic_rank_for_symbol_slot(0), None);
    assert_eq!(shape.fingerprint(), other.fingerprint());
}

#[test]
fn shapes_sort_keys_by_symbol_for_slot_lookup() {
    let (symbols, ids) = symbols(&[b"z", b"a", b"m"]);
    let shape = AttrShape::from_construction_order(&[ids[2], ids[1], ids[0]], &symbols)
        .expect("shape builds");

    assert_eq!(shape.keys_by_symbol(), ids.as_slice());
    assert_eq!(shape.slot(ids[0]), Some(0));
    assert_eq!(shape.slot(ids[1]), Some(1));
    assert_eq!(shape.slot(ids[2]), Some(2));
    assert_eq!(shape.slot(Symbol::new(99)), None);
    assert!(shape.contains_key(ids[1]));
}

#[test]
fn source_order_tracks_construction_order_over_symbol_slots() {
    let (symbols, ids) = symbols(&[b"z", b"a", b"m"]);
    let shape = AttrShape::from_construction_order(&[ids[2], ids[1], ids[0]], &symbols)
        .expect("shape builds");

    let keys: Vec<Symbol> = shape.iter_source_order().collect();
    assert_eq!(keys, vec![ids[2], ids[1], ids[0]]);
    assert_eq!(shape.source_order(), &[2, 1, 0]);
    assert_eq!(shape.iter_source_order().len(), 3);
}

#[test]
fn lexicographic_order_uses_raw_symbol_bytes() {
    let (symbols, ids) = symbols(&[b"b", b"a\xff", b"a", b"a\x00"]);
    let shape = AttrShape::from_construction_order(&ids, &symbols).expect("shape builds");

    let names: Vec<&[u8]> = shape
        .iter_lexicographic()
        .map(|key| symbols.resolve(key).expect("symbol resolves"))
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
    assert_eq!(shape.iteration_order(), &[2, 3, 1, 0]);
    assert_eq!(shape.lexicographic_rank_by_symbol_slot(), &[3, 2, 0, 1]);
    assert_eq!(shape.lexicographic_rank_for_symbol_slot(0), Some(3));
    assert_eq!(shape.lexicographic_rank_for_symbol_slot(2), Some(0));
    assert_eq!(shape.lexicographic_rank_for_symbol_slot(4), None);
}

#[test]
fn key_vector_fingerprint_ignores_construction_order() {
    let (symbols, ids) = symbols(&[b"a", b"b", b"c"]);
    let left = AttrShape::from_construction_order(&[ids[0], ids[1], ids[2]], &symbols)
        .expect("left shape builds");
    let right = AttrShape::from_construction_order(&[ids[2], ids[1], ids[0]], &symbols)
        .expect("right shape builds");

    assert_eq!(left.keys_by_symbol(), right.keys_by_symbol());
    assert_eq!(left.fingerprint(), right.fingerprint());
    assert_ne!(left.source_order(), right.source_order());
}

#[test]
fn raw_shape_equality_is_scoped_to_one_symbol_universe() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let left = AttrShape::from_construction_order(&ids, &symbols).expect("left shape builds");
    let same = AttrShape::from_construction_order(&ids, &symbols).expect("same shape builds");
    let different_order = AttrShape::from_construction_order(&[ids[1], ids[0]], &symbols)
        .expect("different-order shape builds");

    assert!(left.raw_eq(&same));
    assert!(!left.raw_eq(&different_order));
}

#[test]
fn transitions_for_existing_keys_return_existing_slots() {
    let (symbols, ids) = symbols(&[b"z", b"a"]);
    let shape =
        AttrShape::from_construction_order(&[ids[1], ids[0]], &symbols).expect("shape builds");

    match shape
        .transition_insert_key(ids[0], &symbols)
        .expect("existing-key transition succeeds")
    {
        ShapeTransition::ExistingKey { key, slot } => {
            assert_eq!(key, ids[0]);
            assert_eq!(slot, 0);
        }
        ShapeTransition::AppendKey { .. } => panic!("existing key must not append"),
    }
}

#[test]
fn transitions_append_new_keys_in_construction_order() {
    let (symbols, ids) = symbols(&[b"z", b"a", b"m"]);
    let parent = AttrShape::from_construction_order(&[ids[1], ids[0]], &symbols)
        .expect("parent shape builds");

    match parent
        .transition_insert_key(ids[2], &symbols)
        .expect("append transition succeeds")
    {
        ShapeTransition::AppendKey {
            key,
            source_slot,
            symbol_slot,
            child,
        } => {
            assert_eq!(key, ids[2]);
            assert_eq!(source_slot, 2);
            assert_eq!(symbol_slot, 2);
            assert_eq!(
                child.iter_source_order().collect::<Vec<_>>(),
                vec![ids[1], ids[0], ids[2]]
            );
            let names: Vec<&[u8]> = child
                .iter_lexicographic()
                .map(|key| symbols.resolve(key).expect("symbol resolves"))
                .collect();
            assert_eq!(
                names,
                vec![b"a".as_slice(), b"m".as_slice(), b"z".as_slice()]
            );
        }
        ShapeTransition::ExistingKey { .. } => panic!("new key must append"),
    }
}

#[test]
fn transitions_recompute_symbol_slot_for_low_id_appended_keys() {
    let (symbols, ids) = symbols(&[b"a", b"m", b"z"]);
    let parent = AttrShape::from_construction_order(&[ids[1], ids[2]], &symbols)
        .expect("parent shape builds");

    match parent
        .transition_insert_key(ids[0], &symbols)
        .expect("append transition succeeds")
    {
        ShapeTransition::AppendKey {
            source_slot,
            symbol_slot,
            child,
            ..
        } => {
            assert_eq!(source_slot, 2);
            assert_eq!(symbol_slot, 0);
            assert_eq!(child.keys_by_symbol(), ids.as_slice());
            assert_eq!(
                child.iter_source_order().collect::<Vec<_>>(),
                vec![ids[1], ids[2], ids[0]]
            );
        }
        ShapeTransition::ExistingKey { .. } => panic!("new key must append"),
    }
}

#[test]
fn transitions_reject_unknown_new_keys_without_changing_parent() {
    let (symbols, ids) = symbols(&[b"a"]);
    let parent = AttrShape::from_construction_order(&ids, &symbols).expect("parent shape builds");

    assert_eq!(
        parent
            .transition_insert_key(Symbol::new(42), &symbols)
            .expect_err("unknown key is rejected"),
        ShapeError::UnknownSymbol {
            key: Symbol::new(42),
        }
    );
    assert_eq!(parent.iter_source_order().collect::<Vec<_>>(), ids);
}

#[test]
fn transitions_reject_existing_key_when_symbol_table_is_mismatched() {
    let (symbols, ids) = symbols(&[b"a"]);
    let parent = AttrShape::from_construction_order(&ids, &symbols).expect("parent shape builds");
    let empty_symbols = SymbolTable::new();

    assert_eq!(
        parent
            .transition_insert_key(ids[0], &empty_symbols)
            .expect_err("mismatched symbol table is rejected"),
        ShapeError::UnknownSymbol { key: ids[0] }
    );
}

#[test]
fn shape_table_starts_with_pointer_identity_empty_root() {
    let table = ShapeTable::new().expect("shape table initializes");
    let empty = table.empty();
    let same_empty = table.empty();

    assert_eq!(empty.id(), ShapeId::new(0));
    assert!(empty.shape().is_empty());
    assert!(empty.ptr_eq(&same_empty));
}

#[test]
fn shape_table_interns_raw_equal_shapes_to_one_handle() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let mut table = ShapeTable::new().expect("shape table initializes");

    let first = table
        .intern_construction_order(&ids, &symbols)
        .expect("first shape interns");
    let same = table
        .intern_construction_order(&ids, &symbols)
        .expect("same shape interns");
    let different_source_order = table
        .intern_construction_order(&[ids[1], ids[0]], &symbols)
        .expect("different source-order shape interns");

    assert!(first.ptr_eq(&same));
    assert_eq!(first.id(), same.id());
    assert!(!first.ptr_eq(&different_source_order));
    assert_ne!(first.id(), different_source_order.id());
}

#[test]
fn shape_table_transition_edges_are_cached_on_parent() {
    let (symbols, ids) = symbols(&[b"a"]);
    let mut table = ShapeTable::new().expect("shape table initializes");
    let empty = table.empty();

    let first = table
        .transition_insert_key(&empty, ids[0], &symbols)
        .expect("first transition succeeds");
    let ShapeTableTransition::AppendKey {
        child: first_child,
        source_slot,
        symbol_slot,
        cached,
        ..
    } = first
    else {
        panic!("new key should append");
    };
    assert_eq!(source_slot, 0);
    assert_eq!(symbol_slot, 0);
    assert!(!cached);

    let second = table
        .transition_insert_key(&empty, ids[0], &symbols)
        .expect("cached transition succeeds");
    let ShapeTableTransition::AppendKey {
        child: second_child,
        cached,
        ..
    } = second
    else {
        panic!("cached new-key edge should append");
    };
    assert!(cached);
    assert_eq!(first_child.id(), second_child.id());
    assert!(first_child.ptr_eq(&second_child));
}

#[test]
fn shape_table_cached_edges_preserve_distinct_source_and_symbol_slots() {
    let (symbols, ids) = symbols(&[b"a", b"m", b"z"]);
    let mut table = ShapeTable::new().expect("shape table initializes");
    let parent = table
        .intern_construction_order(&[ids[1], ids[2]], &symbols)
        .expect("parent shape interns");

    let first = table
        .transition_insert_key(&parent, ids[0], &symbols)
        .expect("first transition succeeds");
    let ShapeTableTransition::AppendKey {
        child: first_child,
        source_slot,
        symbol_slot,
        cached,
        ..
    } = first
    else {
        panic!("new key should append");
    };
    assert_eq!(source_slot, 2);
    assert_eq!(symbol_slot, 0);
    assert!(!cached);

    let second = table
        .transition_insert_key(&parent, ids[0], &symbols)
        .expect("cached transition succeeds");
    let ShapeTableTransition::AppendKey {
        child: second_child,
        source_slot,
        symbol_slot,
        cached,
        ..
    } = second
    else {
        panic!("cached new-key edge should append");
    };
    assert_eq!(source_slot, 2);
    assert_eq!(symbol_slot, 0);
    assert!(cached);
    assert!(first_child.ptr_eq(&second_child));
}

#[test]
fn shape_table_transition_reuses_preinterned_child_shape() {
    let (symbols, ids) = symbols(&[b"a"]);
    let mut table = ShapeTable::new().expect("shape table initializes");
    let direct = table
        .intern_construction_order(&ids, &symbols)
        .expect("direct shape interns");
    let empty = table.empty();

    let transition = table
        .transition_insert_key(&empty, ids[0], &symbols)
        .expect("transition succeeds");
    let ShapeTableTransition::AppendKey { child, cached, .. } = transition else {
        panic!("new key should append");
    };

    assert!(!cached);
    assert_eq!(child.id(), direct.id());
    assert!(child.ptr_eq(&direct));
}

#[test]
fn shape_table_existing_key_transition_returns_parent_handle() {
    let (symbols, ids) = symbols(&[b"a"]);
    let mut table = ShapeTable::new().expect("shape table initializes");
    let parent = table
        .intern_construction_order(&ids, &symbols)
        .expect("parent shape interns");

    let transition = table
        .transition_insert_key(&parent, ids[0], &symbols)
        .expect("existing-key transition succeeds");
    let ShapeTableTransition::ExistingKey {
        parent: returned,
        key,
        slot,
    } = transition
    else {
        panic!("existing key should not append");
    };

    assert_eq!(key, ids[0]);
    assert_eq!(slot, 0);
    assert_eq!(returned.id(), parent.id());
    assert!(returned.ptr_eq(&parent));
}

#[test]
fn shape_table_rejects_foreign_or_unknown_handles() {
    let (symbols, ids) = symbols(&[b"a"]);
    let mut table = ShapeTable::new().expect("shape table initializes");
    let foreign = ShapeTable::new()
        .expect("foreign table initializes")
        .empty();

    assert_eq!(
        table
            .transition_insert_key(&foreign, ids[0], &symbols)
            .expect_err("foreign handle is rejected"),
        ShapeError::ForeignShapeHandle {
            id: ShapeId::new(0)
        }
    );

    let mut larger_foreign = ShapeTable::new().expect("larger foreign table initializes");
    let unknown = larger_foreign
        .intern_construction_order(&ids, &symbols)
        .expect("unknown shape interns in foreign table");
    let unknown_id = unknown.id();
    assert_eq!(
        table
            .transition_insert_key(&unknown, ids[0], &symbols)
            .expect_err("unknown shape id is rejected"),
        ShapeError::UnknownShapeId { id: unknown_id }
    );
}

#[test]
fn shape_table_rejects_existing_key_when_symbol_table_is_mismatched() {
    let (symbols, ids) = symbols(&[b"a"]);
    let mut table = ShapeTable::new().expect("shape table initializes");
    let parent = table
        .intern_construction_order(&ids, &symbols)
        .expect("parent shape interns");
    let empty_symbols = SymbolTable::new();

    assert_eq!(
        table
            .transition_insert_key(&parent, ids[0], &empty_symbols)
            .expect_err("mismatched symbol table is rejected"),
        ShapeError::UnknownSymbol { key: ids[0] }
    );
}

#[test]
fn shape_table_rejects_overlapping_raw_ids_from_different_symbol_universe() {
    let (primary_symbols, ids) = symbols(&[b"a", b"b"]);
    let mut table = ShapeTable::new().expect("shape table initializes");
    let parent = table
        .intern_construction_order(&[ids[0]], &primary_symbols)
        .expect("parent shape interns");
    let (foreign_symbols, foreign_ids) = symbols(&[b"not-a", b"not-b"]);
    assert_eq!(foreign_ids, ids);

    assert_eq!(
        table
            .transition_insert_key(&parent, ids[1], &foreign_symbols)
            .expect_err("foreign symbol universe is rejected"),
        ShapeError::MismatchedSymbolUniverse { key: ids[0] }
    );
}

#[test]
fn static_shape_plan_resolves_shape_and_instantiates_values() {
    let (symbols, ids) = symbols(&[b"z", b"a", b"m"]);
    let mut table = ShapeTable::new().expect("shape table initializes");

    let plan = StaticShapePlan::resolve(&mut table, &[ids[2], ids[0], ids[1]], &symbols)
        .expect("static shape resolves");

    assert_eq!(plan.len(), 3);
    assert!(!plan.is_empty());
    assert_eq!(plan.source_to_symbol_slots(), &[2, 0, 1]);
    assert_eq!(plan.symbol_slot_for_source_slot(0), Some(2));
    assert_eq!(plan.symbol_slot_for_source_slot(1), Some(0));
    assert_eq!(plan.symbol_slot_for_source_slot(2), Some(1));
    assert_eq!(plan.symbol_slot_for_source_slot(3), None);

    let attrs = plan
        .instantiate(&[Value::int(30), Value::int(10), Value::int(20)])
        .expect("static attrs instantiate");

    assert!(attrs.shape().ptr_eq(plan.shape()));
    assert_eq!(
        attrs
            .values_by_symbol()
            .iter()
            .map(|value| value.as_int().expect("int"))
            .collect::<Vec<_>>(),
        vec![10, 20, 30]
    );
    assert_eq!(attrs.get(ids[0]).expect("z").as_int().expect("int"), 10);
    assert_eq!(attrs.get(ids[1]).expect("a").as_int().expect("int"), 20);
    assert_eq!(attrs.get(ids[2]).expect("m").as_int().expect("int"), 30);

    let second = plan
        .instantiate(&[Value::int(3), Value::int(1), Value::int(2)])
        .expect("second static attrs instantiate");
    assert!(attrs.shape().ptr_eq(second.shape()));
}

#[test]
fn static_shape_plan_rejects_duplicate_keys() {
    let (symbols, ids) = symbols(&[b"a"]);
    let mut table = ShapeTable::new().expect("shape table initializes");

    assert_eq!(
        StaticShapePlan::resolve(&mut table, &[ids[0], ids[0]], &symbols)
            .expect_err("duplicate static key is rejected"),
        StaticShapePlanError::DuplicateKey {
            key: ids[0],
            source_slot: 1,
            symbol_slot: 0,
        }
    );
}

#[test]
fn static_shape_plan_rejects_mismatched_value_counts() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let mut table = ShapeTable::new().expect("shape table initializes");
    let plan = StaticShapePlan::resolve(&mut table, &ids, &symbols).expect("static shape resolves");

    assert_eq!(
        plan.instantiate(&[Value::int(1)])
            .expect_err("value count is checked"),
        StaticShapePlanError::ValueCountMismatch {
            expected: 2,
            actual: 1,
        }
    );
}

#[test]
fn shaped_update_plan_preserves_left_slots_then_new_right_source_order() {
    let (symbols, ids) = symbols(&[b"a", b"b", b"c", b"d"]);
    let mut operand_table = ShapeTable::new().expect("operand shape table initializes");
    let left_shape = operand_table
        .intern_construction_order(&[ids[1], ids[2], ids[0]], &symbols)
        .expect("left shape interns");
    let right_shape = operand_table
        .intern_construction_order(&[ids[1], ids[3]], &symbols)
        .expect("right shape interns");
    let left = ShapedAttrs::from_source_order(
        left_shape,
        &[Value::int(20), Value::int(30), Value::int(10)],
    )
    .expect("left attrs build");
    let right = ShapedAttrs::from_source_order(right_shape, &[Value::int(200), Value::int(40)])
        .expect("right attrs build");
    let mut result_table = ShapeTable::new().expect("result shape table initializes");

    let plan = ShapedUpdatePlan::plan(&mut result_table, &left, &right, &symbols)
        .expect("update plan builds");

    assert_eq!(plan.source_keys(), &[ids[1], ids[2], ids[0], ids[3]]);
    assert_eq!(plan.static_plan().source_to_symbol_slots(), &[1, 2, 0, 3]);
    let result = plan
        .instantiate(&left, &right)
        .expect("update plan instantiates");

    assert!(result.shape().ptr_eq(plan.shape()));
    assert_eq!(result.get(ids[0]).expect("a").as_int().expect("int"), 10);
    assert_eq!(result.get(ids[1]).expect("b").as_int().expect("int"), 200);
    assert_eq!(result.get(ids[2]).expect("c").as_int().expect("int"), 30);
    assert_eq!(result.get(ids[3]).expect("d").as_int().expect("int"), 40);

    let source_entries: Vec<_> = result
        .iter_source_order()
        .map(|entry| {
            (
                symbols.resolve(entry.key).expect("key resolves"),
                entry.value.as_int().expect("int"),
            )
        })
        .collect();
    assert_eq!(
        source_entries,
        vec![
            (b"b".as_slice(), 200),
            (b"c".as_slice(), 30),
            (b"a".as_slice(), 10),
            (b"d".as_slice(), 40),
        ]
    );
}

#[test]
fn shaped_update_plan_handles_empty_operands() {
    let (symbols, ids) = symbols(&[b"a"]);
    let mut operand_table = ShapeTable::new().expect("operand shape table initializes");
    let empty =
        ShapedAttrs::from_source_order(operand_table.empty(), &[]).expect("empty attrs build");
    let shape = operand_table
        .intern_construction_order(&[ids[0]], &symbols)
        .expect("shape interns");
    let non_empty = ShapedAttrs::from_source_order(shape, &[Value::int(1)]).expect("attrs build");
    let mut result_table = ShapeTable::new().expect("result shape table initializes");

    let plan = ShapedUpdatePlan::plan(&mut result_table, &empty, &non_empty, &symbols)
        .expect("update plan builds");
    let result = plan
        .instantiate(&empty, &non_empty)
        .expect("update plan instantiates");

    assert_eq!(plan.source_keys(), &[ids[0]]);
    assert_eq!(result.get(ids[0]).expect("a").as_int().expect("int"), 1);
}

#[test]
fn shaped_update_plan_rejects_mismatched_operand_shapes() {
    let (symbols, ids) = symbols(&[b"a", b"b", b"c", b"d"]);
    let mut operand_table = ShapeTable::new().expect("operand shape table initializes");
    let left_shape = operand_table
        .intern_construction_order(&[ids[0]], &symbols)
        .expect("left shape interns");
    let right_shape = operand_table
        .intern_construction_order(&[ids[1]], &symbols)
        .expect("right shape interns");
    let left_extra_shape = operand_table
        .intern_construction_order(&[ids[0], ids[2]], &symbols)
        .expect("left extra shape interns");
    let right_extra_shape = operand_table
        .intern_construction_order(&[ids[1], ids[3]], &symbols)
        .expect("right extra shape interns");
    let left =
        ShapedAttrs::from_source_order(left_shape, &[Value::int(1)]).expect("left attrs build");
    let right =
        ShapedAttrs::from_source_order(right_shape, &[Value::int(2)]).expect("right attrs build");
    let left_extra =
        ShapedAttrs::from_source_order(left_extra_shape, &[Value::int(1), Value::int(3)])
            .expect("left extra attrs build");
    let right_extra =
        ShapedAttrs::from_source_order(right_extra_shape, &[Value::int(2), Value::int(4)])
            .expect("right extra attrs build");
    let mut result_table = ShapeTable::new().expect("result shape table initializes");
    let plan = ShapedUpdatePlan::plan(&mut result_table, &left, &right, &symbols)
        .expect("update plan builds");

    assert_eq!(
        plan.instantiate(&left_extra, &right)
            .expect_err("left shape mismatch is rejected"),
        ShapedUpdateError::OperandShapeMismatch {
            side: ShapedUpdateOperand::Left,
            expected: left.shape().id(),
            actual: left_extra.shape().id(),
        }
    );
    assert_eq!(
        plan.instantiate(&left, &right_extra)
            .expect_err("right shape mismatch is rejected"),
        ShapedUpdateError::OperandShapeMismatch {
            side: ShapedUpdateOperand::Right,
            expected: right.shape().id(),
            actual: right_extra.shape().id(),
        }
    );
}

#[test]
fn shaped_attrs_reorder_source_values_into_symbol_slots() {
    let (symbols, ids) = symbols(&[b"z", b"a", b"m"]);
    let mut table = ShapeTable::new().expect("shape table initializes");
    let shape = table
        .intern_construction_order(&[ids[2], ids[0], ids[1]], &symbols)
        .expect("shape interns");

    let attrs =
        ShapedAttrs::from_source_order(shape, &[Value::int(30), Value::int(10), Value::int(20)])
            .expect("shaped attrs build");

    assert_eq!(attrs.len(), 3);
    assert!(!attrs.is_empty());
    assert_eq!(attrs.get(ids[0]).expect("z").as_int().expect("int"), 10);
    assert_eq!(attrs.get(ids[1]).expect("a").as_int().expect("int"), 20);
    assert_eq!(attrs.get(ids[2]).expect("m").as_int().expect("int"), 30);
    assert_eq!(
        attrs
            .values_by_symbol()
            .iter()
            .map(|value| value.as_int().expect("int"))
            .collect::<Vec<_>>(),
        vec![10, 20, 30]
    );

    let source_entries: Vec<_> = attrs
        .iter_source_order()
        .map(|entry| {
            (
                symbols.resolve(entry.key).expect("key resolves"),
                entry.value.as_int().expect("int"),
            )
        })
        .collect();
    assert_eq!(
        source_entries,
        vec![
            (b"m".as_slice(), 30),
            (b"z".as_slice(), 10),
            (b"a".as_slice(), 20),
        ]
    );

    let lexicographic_entries: Vec<_> = attrs
        .iter_lexicographic()
        .map(|entry| {
            (
                symbols.resolve(entry.key).expect("key resolves"),
                entry.value.as_int().expect("int"),
            )
        })
        .collect();
    assert_eq!(
        lexicographic_entries,
        vec![
            (b"a".as_slice(), 20),
            (b"m".as_slice(), 30),
            (b"z".as_slice(), 10),
        ]
    );
}

#[test]
fn shaped_attrs_accept_symbol_order_values_directly() {
    let (symbols, ids) = symbols(&[b"b", b"a"]);
    let mut table = ShapeTable::new().expect("shape table initializes");
    let shape = table
        .intern_construction_order(&[ids[1], ids[0]], &symbols)
        .expect("shape interns");

    let attrs = ShapedAttrs::from_symbol_order(shape, &[Value::int(1), Value::int(2)])
        .expect("shaped attrs build");

    assert_eq!(attrs.get_slot(0).expect("slot 0").as_int().expect("int"), 1);
    assert_eq!(attrs.get_slot(1).expect("slot 1").as_int().expect("int"), 2);
    assert!(attrs.get_slot(2).is_none());
}

#[test]
fn shaped_attrs_reject_mismatched_value_counts() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let mut table = ShapeTable::new().expect("shape table initializes");
    let shape = table
        .intern_construction_order(&ids, &symbols)
        .expect("shape interns");

    assert_eq!(
        ShapedAttrs::from_source_order(shape.clone(), &[Value::int(1)])
            .expect_err("source-order value count is checked"),
        ShapedAttrsError::ValueCountMismatch {
            expected: 2,
            actual: 1,
        }
    );
    assert_eq!(
        ShapedAttrs::from_symbol_order(shape, &[Value::int(1), Value::int(2), Value::int(3)])
            .expect_err("symbol-order value count is checked"),
        ShapedAttrsError::ValueCountMismatch {
            expected: 2,
            actual: 3,
        }
    );
}

#[test]
fn shaped_attrs_raw_equality_requires_interned_shape_identity() {
    let (symbols, ids) = symbols(&[b"a"]);
    let mut table = ShapeTable::new().expect("shape table initializes");
    let shape = table
        .intern_construction_order(&ids, &symbols)
        .expect("shape interns");
    let same_shape = table
        .intern_construction_order(&ids, &symbols)
        .expect("same shape interns");
    let mut foreign_table = ShapeTable::new().expect("foreign table initializes");
    let foreign_shape = foreign_table
        .intern_construction_order(&ids, &symbols)
        .expect("foreign shape interns");

    let left = ShapedAttrs::from_symbol_order(shape, &[Value::int(1)]).expect("left attrs build");
    let same =
        ShapedAttrs::from_symbol_order(same_shape, &[Value::int(1)]).expect("same attrs build");
    let different_value = ShapedAttrs::from_symbol_order(left.shape().clone(), &[Value::int(2)])
        .expect("different attrs build");
    let foreign = ShapedAttrs::from_symbol_order(foreign_shape, &[Value::int(1)])
        .expect("foreign attrs build");

    assert!(left.raw_eq(&same));
    assert!(!left.raw_eq(&different_value));
    assert!(!left.raw_eq(&foreign));
}

#[test]
fn shaped_attr_cons_reuses_raw_equal_instances() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let mut shape_table = ShapeTable::new().expect("shape table initializes");
    let shape = shape_table
        .intern_construction_order(&ids, &symbols)
        .expect("shape interns");
    let same_shape = shape_table
        .intern_construction_order(&ids, &symbols)
        .expect("same shape interns");
    let mut cons = ShapedAttrConsTable::new();

    let first = cons
        .intern(
            ShapedAttrs::from_symbol_order(shape, &[Value::int(1), Value::bool(true)])
                .expect("first attrs build"),
        )
        .expect("first attrs intern");
    let second = cons
        .intern(
            ShapedAttrs::from_symbol_order(same_shape, &[Value::int(1), Value::bool(true)])
                .expect("second attrs build"),
        )
        .expect("second attrs intern");

    assert!(std::sync::Arc::ptr_eq(&first, &second));
    assert_eq!(cons.bucket_count(), 1);
}

#[test]
fn shaped_attr_cons_keeps_different_raw_values_separate() {
    let (symbols, ids) = symbols(&[b"a"]);
    let mut shape_table = ShapeTable::new().expect("shape table initializes");
    let shape = shape_table
        .intern_construction_order(&ids, &symbols)
        .expect("shape interns");
    let mut cons = ShapedAttrConsTable::new();

    let first = cons
        .intern(
            ShapedAttrs::from_symbol_order(shape.clone(), &[Value::int(1)])
                .expect("first attrs build"),
        )
        .expect("first attrs intern");
    let second = cons
        .intern(
            ShapedAttrs::from_symbol_order(shape, &[Value::int(2)]).expect("second attrs build"),
        )
        .expect("second attrs intern");

    assert!(!std::sync::Arc::ptr_eq(&first, &second));
    assert!(!first.raw_eq(&second));
}

#[test]
fn shaped_attr_cons_does_not_merge_foreign_same_fingerprint_shapes() {
    let left_shape = ShapeTable::new()
        .expect("left shape table initializes")
        .empty();
    let right_shape = ShapeTable::new()
        .expect("right shape table initializes")
        .empty();
    let left_attrs = ShapedAttrs::from_symbol_order(left_shape, &[]).expect("left attrs build");
    let right_attrs = ShapedAttrs::from_symbol_order(right_shape, &[]).expect("right attrs build");
    assert_eq!(left_attrs.fingerprint(), right_attrs.fingerprint());

    let mut cons = ShapedAttrConsTable::new();
    assert!(cons.is_empty());

    let left = cons.intern(left_attrs).expect("left attrs intern");
    let right = cons.intern(right_attrs).expect("right attrs intern");

    assert!(!std::sync::Arc::ptr_eq(&left, &right));
    assert!(!left.raw_eq(&right));
    assert_eq!(cons.bucket_count(), 1);
}

#[test]
fn shapes_reject_duplicate_or_unknown_keys() {
    let (symbols, ids) = symbols(&[b"a"]);

    assert_eq!(
        AttrShape::from_construction_order(&[ids[0], ids[0]], &symbols)
            .expect_err("duplicate key is rejected"),
        ShapeError::DuplicateKey { key: ids[0] }
    );
    assert_eq!(
        AttrShape::from_construction_order(&[Symbol::new(42)], &symbols)
            .expect_err("unknown key is rejected"),
        ShapeError::UnknownSymbol {
            key: Symbol::new(42),
        }
    );
}

#[test]
fn shape_table_replica_shares_descriptors_and_dense_ids() {
    let (symbols, ids) = symbols(&[b"a", b"b", b"c"]);
    let mut table = ShapeTable::new().expect("table builds");
    let interned = table
        .intern_construction_order(&[ids[0], ids[1]], &symbols)
        .expect("shape interns");

    let replica = table.replica().expect("replica builds");
    assert_eq!(replica.len(), table.len());

    let mirrored = replica.handle(interned.id()).expect("replica resolves id");
    assert!(mirrored.ptr_eq(&interned), "replica shares descriptor Arcs");
    // Handles from the replica pass the authoritative table's identity checks
    // (and vice versa), which is what lets one worker's handle drive another
    // table in the shared-log protocol.
    assert!(
        table
            .transition_insert_key_cached(&mirrored, ids[0])
            .expect("existing key resolves on the source table")
            .is_some()
    );

    // Interning through the source table then replicating the suffix keeps
    // ids dense and identical on the replica.
    let mut replica = replica;
    let extended = table
        .intern_construction_order(&[ids[2]], &symbols)
        .expect("new shape interns");
    table
        .replicate_suffix_into(&mut replica)
        .expect("suffix replicates");
    assert_eq!(replica.len(), table.len());
    let mirrored = replica
        .handle(extended.id())
        .expect("replicated id resolves");
    assert!(mirrored.ptr_eq(&extended));
}

#[test]
fn shape_table_cached_transitions_resolve_without_interning() {
    let (symbols, ids) = symbols(&[b"a", b"b"]);
    let mut table = ShapeTable::new().expect("table builds");
    let root = table.empty();

    // A never-seen edge is a cached-path miss.
    assert!(
        table
            .transition_insert_key_cached(&root, ids[0])
            .expect("cached probe succeeds")
            .is_none()
    );

    let ShapeTableTransition::AppendKey { child, .. } = table
        .transition_insert_key(&root, ids[0], &symbols)
        .expect("append transitions")
    else {
        panic!("new key appends");
    };

    // The interned edge now resolves read-only, to the same child.
    let Some(ShapeTableTransition::AppendKey {
        child: cached_child,
        cached,
        ..
    }) = table
        .transition_insert_key_cached(&root, ids[0])
        .expect("cached probe succeeds")
    else {
        panic!("cached edge resolves");
    };
    assert!(cached);
    assert!(cached_child.ptr_eq(&child));

    // Existing keys resolve to their slot without table growth.
    let before = table.len();
    let Some(ShapeTableTransition::ExistingKey { slot, .. }) = table
        .transition_insert_key_cached(&child, ids[0])
        .expect("cached probe succeeds")
    else {
        panic!("existing key resolves");
    };
    assert_eq!(slot, 0);
    assert_eq!(table.len(), before);
    // And a genuinely new edge still misses.
    assert!(
        table
            .transition_insert_key_cached(&child, ids[1])
            .expect("cached probe succeeds")
            .is_none()
    );
}

#[test]
fn shape_table_replicate_suffix_rejects_foreign_handles_gracefully() {
    let (symbols, ids) = symbols(&[b"a"]);
    let mut table = ShapeTable::new().expect("table builds");
    let mut unrelated = ShapeTable::new().expect("second table builds");
    let interned = table
        .intern_construction_order(&[ids[0]], &symbols)
        .expect("shape interns");

    // A handle from an unrelated table (same id space, different Arcs) fails
    // the identity check instead of aliasing the wrong record.
    let foreign_root = unrelated.empty();
    assert!(matches!(
        table.transition_insert_key_cached(&foreign_root, ids[0]),
        Err(ShapeError::ForeignShapeHandle { .. })
    ));
    let _ = interned;
}
