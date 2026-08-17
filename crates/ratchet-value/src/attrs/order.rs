//! Order-parity helpers for attrset representation precursors.
//!
//! The active evaluator still uses [`crate::attrs::FlatAttrs`], but RFC-0007
//! phase 5 introduces shaped and HAMT attrset layouts that must present the
//! same observable raw-byte lexicographic order. This module provides a small
//! harness substrate for checking that all current value-level representations
//! expose the same ordered key vector before those representations are wired
//! into `.drv`-producing evaluator paths.

use thiserror::Error;

use crate::attrs::FlatAttrs;
use crate::attrs::hamt::HamtAttrs;
use crate::attrs::repr::AttrSetReprValue;
use crate::attrs::shape::ShapedAttrs;
use crate::syntax::{Symbol, SymbolTable};

/// A borrowed attrset whose observable lexicographic key order can be checked.
#[derive(Clone, Copy, Debug)]
pub enum AttrOrderTarget<'a> {
    /// A flat attrset.
    Flat(&'a FlatAttrs),
    /// A HAMT attrset.
    Hamt(&'a HamtAttrs),
    /// A shaped attrset.
    Shaped(&'a ShapedAttrs),
    /// A policy-dispatched Flat/HAMT wrapper.
    Repr(&'a AttrSetReprValue),
}

impl AttrOrderTarget<'_> {
    /// Returns the backing representation label.
    pub const fn repr(self) -> AttrOrderRepr {
        match self {
            Self::Flat(_) => AttrOrderRepr::Flat,
            Self::Hamt(_) => AttrOrderRepr::Hamt,
            Self::Shaped(_) => AttrOrderRepr::Shaped,
            Self::Repr(value) => match value {
                AttrSetReprValue::Flat(_) => AttrOrderRepr::ReprFlat,
                AttrSetReprValue::Hamt(_) => AttrOrderRepr::ReprHamt,
            },
        }
    }

    /// Returns the number of bindings in the target.
    pub fn len(self) -> usize {
        match self {
            Self::Flat(attrs) => attrs.len(),
            Self::Hamt(attrs) => attrs.len(),
            Self::Shaped(attrs) => attrs.len(),
            Self::Repr(value) => value.len(),
        }
    }

    /// Returns whether the target has no bindings.
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
}

/// The representation label used in order-parity diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttrOrderRepr {
    /// A flat attrset.
    Flat,
    /// A HAMT attrset.
    Hamt,
    /// A shaped attrset.
    Shaped,
    /// A policy wrapper currently holding a flat attrset.
    ReprFlat,
    /// A policy wrapper currently holding a HAMT attrset.
    ReprHamt,
}

/// Collects and validates the target's raw-byte lexicographic key order.
///
/// This checks the representation's own observable iterator. It does not call
/// C++ Nix and does not prove `.drv` byte parity; it is the in-process harness
/// layer used before differential gates exercise evaluator output. `target`
/// and `symbols` must belong to the same symbol universe.
///
/// # Errors
///
/// Returns [`AttrOrderError::UnknownSymbol`] when any key cannot be resolved
/// through `symbols`, [`AttrOrderError::OutOfOrder`] when the target iterator
/// is not raw-byte lexicographic, or [`AttrOrderError::AllocationFailed`] when
/// scratch storage cannot be reserved.
pub fn collect_checked_lexicographic_keys(
    target: AttrOrderTarget<'_>,
    symbols: &SymbolTable,
) -> Result<Box<[Symbol]>, AttrOrderError> {
    let repr = target.repr();
    let mut keys = Vec::new();
    keys.try_reserve_exact(target.len())
        .map_err(|_| AttrOrderError::AllocationFailed {
            repr,
            entries: target.len(),
        })?;
    extend_keys(target, &mut keys);
    validate_raw_byte_order(repr, &keys, symbols)?;
    Ok(keys.into_boxed_slice())
}

/// Checks that two attrset representations expose the same lexicographic order.
///
/// Both targets and `symbols` must belong to the same symbol universe.
///
/// # Errors
///
/// Returns [`AttrOrderError`] if either side's order cannot be collected or if
/// the collected key vectors differ.
pub fn assert_same_lexicographic_order(
    left: AttrOrderTarget<'_>,
    right: AttrOrderTarget<'_>,
    symbols: &SymbolTable,
) -> Result<(), AttrOrderError> {
    let left_repr = left.repr();
    let right_repr = right.repr();
    let left_keys = collect_checked_lexicographic_keys(left, symbols)?;
    let right_keys = collect_checked_lexicographic_keys(right, symbols)?;
    if left_keys == right_keys {
        Ok(())
    } else {
        Err(AttrOrderError::OrderMismatch {
            left_repr,
            right_repr,
            left_keys,
            right_keys,
        })
    }
}

fn extend_keys(target: AttrOrderTarget<'_>, keys: &mut Vec<Symbol>) {
    match target {
        AttrOrderTarget::Flat(attrs) => {
            keys.extend(attrs.iter_lexicographic().map(|entry| entry.key));
        }
        AttrOrderTarget::Hamt(attrs) => {
            keys.extend(attrs.iter_lexicographic().map(|entry| entry.key));
        }
        AttrOrderTarget::Shaped(attrs) => {
            keys.extend(attrs.iter_lexicographic().map(|entry| entry.key));
        }
        AttrOrderTarget::Repr(AttrSetReprValue::Flat(attrs)) => {
            keys.extend(attrs.iter_lexicographic().map(|entry| entry.key));
        }
        AttrOrderTarget::Repr(AttrSetReprValue::Hamt(attrs)) => {
            keys.extend(attrs.iter_lexicographic().map(|entry| entry.key));
        }
    }
}

fn validate_raw_byte_order(
    repr: AttrOrderRepr,
    keys: &[Symbol],
    symbols: &SymbolTable,
) -> Result<(), AttrOrderError> {
    let mut previous: Option<(Symbol, &[u8])> = None;
    for key in keys {
        let name = symbols
            .resolve(*key)
            .ok_or(AttrOrderError::UnknownSymbol { repr, key: *key })?;
        if let Some((previous_key, previous_name)) = previous {
            if previous_name > name {
                return Err(AttrOrderError::OutOfOrder {
                    repr,
                    left_key: previous_key,
                    right_key: *key,
                    left_name: previous_name.to_vec().into_boxed_slice(),
                    right_name: name.to_vec().into_boxed_slice(),
                });
            }
        }
        previous = Some((*key, name));
    }
    Ok(())
}

/// An attrset order-parity failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AttrOrderError {
    /// A target key did not resolve through the supplied symbol table.
    #[error("{repr:?} order contained unknown symbol {key:?}")]
    UnknownSymbol {
        /// The representation whose order was checked.
        repr: AttrOrderRepr,
        /// The unresolved key.
        key: Symbol,
    },
    /// A target iterator was not raw-byte lexicographic.
    #[error(
        "{repr:?} order placed {left_key:?} before {right_key:?}, but {left_name:?} > {right_name:?}"
    )]
    OutOfOrder {
        /// The representation whose order was checked.
        repr: AttrOrderRepr,
        /// The earlier key in the target order.
        left_key: Symbol,
        /// The later key in the target order.
        right_key: Symbol,
        /// The earlier key's raw byte spelling.
        left_name: Box<[u8]>,
        /// The later key's raw byte spelling.
        right_name: Box<[u8]>,
    },
    /// Two targets exposed different lexicographic key vectors.
    #[error("{left_repr:?} and {right_repr:?} exposed different lexicographic key vectors")]
    OrderMismatch {
        /// The left representation.
        left_repr: AttrOrderRepr,
        /// The right representation.
        right_repr: AttrOrderRepr,
        /// The left target's collected keys.
        left_keys: Box<[Symbol]>,
        /// The right target's collected keys.
        right_keys: Box<[Symbol]>,
    },
    /// Scratch storage for collecting keys could not be reserved.
    #[error("failed to reserve {entries} order-parity entries for {repr:?}")]
    AllocationFailed {
        /// The representation being collected.
        repr: AttrOrderRepr,
        /// The requested entry count.
        entries: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attrs::hamt::HamtAttrs;
    use crate::attrs::repr::AttrSetReprValue;
    use crate::attrs::shape::{ShapeTable, ShapedAttrs, ShapedUpdatePlan};
    use crate::attrs::{AttrEntry, FlatAttrs};
    use crate::value::Value;

    fn symbols(names: &[&[u8]]) -> (SymbolTable, Vec<Symbol>) {
        let mut table = SymbolTable::new();
        let mut ids = Vec::new();
        for name in names {
            ids.push(table.intern(name).expect("symbol interns"));
        }
        (table, ids)
    }

    fn key_names(keys: &[Symbol], symbols: &SymbolTable) -> Vec<Vec<u8>> {
        keys.iter()
            .map(|key| symbols.resolve(*key).expect("key resolves").to_vec())
            .collect()
    }

    #[test]
    fn parity_harness_matches_flat_hamt_shaped_and_wrapped_values() {
        let (symbols, ids) = symbols(&[b"b", b"a\xff", b"a", b"a\x00"]);
        let entries = vec![
            AttrEntry::new(ids[0], Value::int(10)),
            AttrEntry::new(ids[1], Value::int(20)),
            AttrEntry::new(ids[2], Value::int(30)),
            AttrEntry::new(ids[3], Value::int(40)),
        ];
        let flat = FlatAttrs::new(entries.clone(), &symbols).expect("flat attrs build");
        let hamt = HamtAttrs::new(entries, &symbols).expect("HAMT attrs build");
        let mut shapes = ShapeTable::new().expect("shape table initializes");
        let shape = shapes
            .intern_construction_order(&[ids[1], ids[0], ids[3], ids[2]], &symbols)
            .expect("shape interns");
        let shaped = ShapedAttrs::from_source_order(
            shape,
            &[
                Value::int(20),
                Value::int(10),
                Value::int(40),
                Value::int(30),
            ],
        )
        .expect("shaped attrs build");
        let wrapped_flat = AttrSetReprValue::from_flat(flat.clone());
        let wrapped_hamt = AttrSetReprValue::from_hamt(hamt.clone());

        let flat_keys = collect_checked_lexicographic_keys(AttrOrderTarget::Flat(&flat), &symbols)
            .expect("flat order checks");
        assert_eq!(
            key_names(&flat_keys, &symbols),
            vec![
                b"a".to_vec(),
                b"a\x00".to_vec(),
                b"a\xff".to_vec(),
                b"b".to_vec(),
            ]
        );
        assert_same_lexicographic_order(
            AttrOrderTarget::Flat(&flat),
            AttrOrderTarget::Hamt(&hamt),
            &symbols,
        )
        .expect("flat and HAMT order match");
        assert_same_lexicographic_order(
            AttrOrderTarget::Flat(&flat),
            AttrOrderTarget::Shaped(&shaped),
            &symbols,
        )
        .expect("flat and shaped order match");
        assert_same_lexicographic_order(
            AttrOrderTarget::Flat(&flat),
            AttrOrderTarget::Repr(&wrapped_flat),
            &symbols,
        )
        .expect("flat and wrapped flat order match");
        assert_same_lexicographic_order(
            AttrOrderTarget::Flat(&flat),
            AttrOrderTarget::Repr(&wrapped_hamt),
            &symbols,
        )
        .expect("flat and wrapped HAMT order match");
    }

    #[test]
    fn parity_harness_matches_shaped_update_transition_result_order() {
        let (symbols, ids) = symbols(&[b"b", b"a\xff", b"m", b"a\x00", b"a"]);
        let mut operand_table = ShapeTable::new().expect("operand shape table initializes");
        let left_shape = operand_table
            .intern_construction_order(&[ids[0], ids[1], ids[2]], &symbols)
            .expect("left shape interns");
        let right_shape = operand_table
            .intern_construction_order(&[ids[1], ids[3], ids[4]], &symbols)
            .expect("right shape interns");
        let left = ShapedAttrs::from_source_order(
            left_shape,
            &[Value::int(10), Value::int(20), Value::int(30)],
        )
        .expect("left attrs build");
        let right = ShapedAttrs::from_source_order(
            right_shape,
            &[Value::int(200), Value::int(40), Value::int(50)],
        )
        .expect("right attrs build");
        let mut result_table = ShapeTable::new().expect("result shape table initializes");

        let plan = ShapedUpdatePlan::plan(&mut result_table, &left, &right, &symbols)
            .expect("shaped update plan builds");
        let shaped = plan
            .instantiate(&left, &right)
            .expect("shaped update result instantiates");
        let flat = FlatAttrs::new(
            vec![
                AttrEntry::new(ids[0], Value::int(10)),
                AttrEntry::new(ids[1], Value::int(200)),
                AttrEntry::new(ids[2], Value::int(30)),
                AttrEntry::new(ids[3], Value::int(40)),
                AttrEntry::new(ids[4], Value::int(50)),
            ],
            &symbols,
        )
        .expect("flat result builds");
        let hamt = HamtAttrs::from_flat(&flat, &symbols).expect("HAMT result builds");

        assert_same_lexicographic_order(
            AttrOrderTarget::Shaped(&shaped),
            AttrOrderTarget::Flat(&flat),
            &symbols,
        )
        .expect("shaped update result matches flat raw-byte order");
        assert_same_lexicographic_order(
            AttrOrderTarget::Shaped(&shaped),
            AttrOrderTarget::Hamt(&hamt),
            &symbols,
        )
        .expect("shaped update result matches HAMT raw-byte order");
        let shaped_keys =
            collect_checked_lexicographic_keys(AttrOrderTarget::Shaped(&shaped), &symbols)
                .expect("shaped update order checks");
        assert_eq!(
            key_names(&shaped_keys, &symbols),
            vec![
                b"a".to_vec(),
                b"a\x00".to_vec(),
                b"a\xff".to_vec(),
                b"b".to_vec(),
                b"m".to_vec(),
            ]
        );
    }

    #[test]
    fn parity_harness_reports_mismatched_key_vectors() {
        let (symbols, ids) = symbols(&[b"a", b"b"]);
        let left = FlatAttrs::new(
            vec![
                AttrEntry::new(ids[0], Value::int(1)),
                AttrEntry::new(ids[1], Value::int(2)),
            ],
            &symbols,
        )
        .expect("left flat attrs build");
        let right = FlatAttrs::new(vec![AttrEntry::new(ids[0], Value::int(1))], &symbols)
            .expect("right flat attrs build");

        assert_eq!(
            assert_same_lexicographic_order(
                AttrOrderTarget::Flat(&left),
                AttrOrderTarget::Flat(&right),
                &symbols,
            )
            .expect_err("different key vectors are rejected"),
            AttrOrderError::OrderMismatch {
                left_repr: AttrOrderRepr::Flat,
                right_repr: AttrOrderRepr::Flat,
                left_keys: Box::from([ids[0], ids[1]]),
                right_keys: Box::from([ids[0]]),
            }
        );
    }

    #[test]
    fn parity_harness_rejects_unresolved_symbols() {
        let (symbols, ids) = symbols(&[b"a"]);
        let flat = FlatAttrs::new(vec![AttrEntry::new(ids[0], Value::int(1))], &symbols)
            .expect("flat attrs build");
        let wrong_symbols = SymbolTable::new();

        assert_eq!(
            collect_checked_lexicographic_keys(AttrOrderTarget::Flat(&flat), &wrong_symbols)
                .expect_err("wrong symbol universe is rejected"),
            AttrOrderError::UnknownSymbol {
                repr: AttrOrderRepr::Flat,
                key: ids[0],
            }
        );
    }
}
