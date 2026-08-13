//! Representation-dispatching attr selection for `select_slow`.
//!
//! This module is the safe value-level substrate for RFC-0007 §09's slow
//! resolver: selection dispatches over flat, HAMT, and shaped attrset storage
//! and returns the selected runtime value. The active tree-walk evaluator uses
//! the flat branch for dynamic path segments and scoped-global fallback probes;
//! lowered static `Select`/`HasAttr` and `WithVar` probes over heap values with
//! projected metadata build transient shaped/HAMT views and use the matching
//! [`crate::attrs::pic`] cache. Native runtime helpers, active HAMT/shaped
//! evaluator storage, and full shaped/native PIC integration remain future work.

use thiserror::Error;

use crate::attrs::FlatAttrs;
use crate::attrs::hamt::HamtAttrs;
use crate::attrs::shape::ShapedAttrs;
use crate::syntax::Symbol;
use crate::value::Value;

/// A borrowed attrset representation accepted by the slow select resolver.
#[derive(Clone, Copy, Debug)]
pub enum AttrSelectTarget<'a> {
    /// A Phase-1 flat attrset using binary-search lookup.
    Flat(&'a FlatAttrs),
    /// A future persistent HAMT attrset using trie lookup.
    Hamt(&'a HamtAttrs),
    /// A shaped attrset using shape-slot lookup.
    Shaped(&'a ShapedAttrs),
}

impl AttrSelectTarget<'_> {
    /// Returns the backing representation kind.
    pub const fn kind(self) -> AttrSelectRepr {
        match self {
            Self::Flat(_) => AttrSelectRepr::Flat,
            Self::Hamt(_) => AttrSelectRepr::Hamt,
            Self::Shaped(_) => AttrSelectRepr::Shaped,
        }
    }

    /// Returns the number of bindings in the target attrset.
    pub fn len(self) -> usize {
        match self {
            Self::Flat(attrs) => attrs.len(),
            Self::Hamt(attrs) => attrs.len(),
            Self::Shaped(attrs) => attrs.len(),
        }
    }

    /// Returns whether the target attrset has no bindings.
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
}

/// The backing representation used for one slow select lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttrSelectRepr {
    /// A flat attrset.
    Flat,
    /// A HAMT attrset.
    Hamt,
    /// A shaped attrset.
    Shaped,
}

/// The result of a representation-dispatching slow attr selection.
#[derive(Clone, Copy, Debug)]
pub enum AttrSelectOutcome {
    /// The selected key was present.
    Hit {
        /// The selected runtime value.
        value: Value,
        /// Metadata about the representation path used by the resolver.
        source: AttrSelectSource,
    },
    /// The selected key was absent.
    Missing {
        /// The representation that was searched.
        repr: AttrSelectRepr,
    },
}

/// Metadata for a successful slow select lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttrSelectSource {
    /// A flat attrset binary-search lookup.
    Flat,
    /// A HAMT trie lookup.
    Hamt,
    /// A shaped attrset slot lookup.
    Shaped {
        /// The symbol-sorted slot loaded from the shaped value array.
        slot: u32,
    },
}

/// A failed representation-dispatching slow select operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AttrSelectError {
    /// A shaped attrset's shape resolved a slot outside its value array.
    #[error("shaped select_slow slot {slot} is out of range for {len} values")]
    ShapedSlotOutOfRange {
        /// The slot resolved by the shape descriptor.
        slot: u32,
        /// The shaped attrset value count.
        len: usize,
    },
}

/// Selects `key` from `target` using representation-dispatching slow lookup.
///
/// # Errors
///
/// Returns [`AttrSelectError::ShapedSlotOutOfRange`] if a shaped attrset's
/// descriptor resolves a slot outside its value array. Public shaped attrset
/// constructors preserve this invariant; the error exists to keep the slow
/// resolver explicit at the representation boundary.
pub fn select_slow(
    target: AttrSelectTarget<'_>,
    key: Symbol,
) -> Result<AttrSelectOutcome, AttrSelectError> {
    match target {
        AttrSelectTarget::Flat(attrs) => Ok(attrs
            .get(key)
            .map(|value| AttrSelectOutcome::Hit {
                value,
                source: AttrSelectSource::Flat,
            })
            .unwrap_or(AttrSelectOutcome::Missing {
                repr: AttrSelectRepr::Flat,
            })),
        AttrSelectTarget::Hamt(attrs) => Ok(attrs
            .get(key)
            .map(|value| AttrSelectOutcome::Hit {
                value,
                source: AttrSelectSource::Hamt,
            })
            .unwrap_or(AttrSelectOutcome::Missing {
                repr: AttrSelectRepr::Hamt,
            })),
        AttrSelectTarget::Shaped(attrs) => {
            let Some(slot) = attrs.shape().shape().slot(key) else {
                return Ok(AttrSelectOutcome::Missing {
                    repr: AttrSelectRepr::Shaped,
                });
            };
            let value = attrs
                .get_slot(slot)
                .ok_or(AttrSelectError::ShapedSlotOutOfRange {
                    slot,
                    len: attrs.len(),
                })?;
            Ok(AttrSelectOutcome::Hit {
                value,
                source: AttrSelectSource::Shaped { slot },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attrs::hamt::HamtAttrs;
    use crate::attrs::shape::{ShapeTable, ShapedAttrs};
    use crate::attrs::{AttrEntry, FlatAttrs};
    use crate::syntax::SymbolTable;

    fn symbols(names: &[&[u8]]) -> (SymbolTable, Vec<Symbol>) {
        let mut table = SymbolTable::new();
        let mut ids = Vec::new();
        for name in names {
            ids.push(table.intern(name).expect("symbol interns"));
        }
        (table, ids)
    }

    fn expect_hit_int(outcome: AttrSelectOutcome, expected: i64) -> AttrSelectSource {
        let AttrSelectOutcome::Hit { value, source } = outcome else {
            panic!("expected select_slow hit");
        };
        assert_eq!(value.as_int().expect("int"), expected);
        source
    }

    #[test]
    fn select_slow_dispatches_to_flat_binary_search() {
        let (symbols, ids) = symbols(&[b"b", b"a"]);
        let attrs = FlatAttrs::new(
            vec![
                AttrEntry::new(ids[0], Value::int(20)),
                AttrEntry::new(ids[1], Value::int(10)),
            ],
            &symbols,
        )
        .expect("flat attrs build");

        assert_eq!(
            expect_hit_int(
                select_slow(AttrSelectTarget::Flat(&attrs), ids[1]).expect("flat select succeeds"),
                10,
            ),
            AttrSelectSource::Flat
        );
    }

    #[test]
    fn select_slow_dispatches_to_hamt_lookup() {
        let (symbols, ids) = symbols(&[b"b", b"a"]);
        let attrs = HamtAttrs::new(
            vec![
                AttrEntry::new(ids[0], Value::int(20)),
                AttrEntry::new(ids[1], Value::int(10)),
            ],
            &symbols,
        )
        .expect("HAMT attrs build");

        assert_eq!(
            expect_hit_int(
                select_slow(AttrSelectTarget::Hamt(&attrs), ids[1]).expect("HAMT select succeeds"),
                10,
            ),
            AttrSelectSource::Hamt
        );
    }

    #[test]
    fn select_slow_dispatches_to_shaped_slot_load() {
        let (symbols, ids) = symbols(&[b"b", b"a"]);
        let mut table = ShapeTable::new().expect("shape table initializes");
        let shape = table
            .intern_construction_order(&[ids[0], ids[1]], &symbols)
            .expect("shape interns");
        let attrs = ShapedAttrs::from_source_order(shape, &[Value::int(20), Value::int(10)])
            .expect("shaped attrs build");

        assert_eq!(
            expect_hit_int(
                select_slow(AttrSelectTarget::Shaped(&attrs), ids[1])
                    .expect("shaped select succeeds"),
                10,
            ),
            AttrSelectSource::Shaped { slot: 1 }
        );
    }

    #[test]
    fn select_slow_reports_missing_per_representation() {
        let (symbols, ids) = symbols(&[b"a", b"missing"]);
        let flat = FlatAttrs::new(vec![AttrEntry::new(ids[0], Value::int(1))], &symbols)
            .expect("flat attrs build");
        let hamt = HamtAttrs::from_flat(&flat, &symbols).expect("HAMT attrs build");
        let mut table = ShapeTable::new().expect("shape table initializes");
        let shape = table
            .intern_construction_order(&[ids[0]], &symbols)
            .expect("shape interns");
        let shaped =
            ShapedAttrs::from_source_order(shape, &[Value::int(1)]).expect("shaped attrs build");

        assert!(matches!(
            select_slow(AttrSelectTarget::Flat(&flat), ids[1]).expect("flat select succeeds"),
            AttrSelectOutcome::Missing {
                repr: AttrSelectRepr::Flat
            }
        ));
        assert!(matches!(
            select_slow(AttrSelectTarget::Hamt(&hamt), ids[1]).expect("HAMT select succeeds"),
            AttrSelectOutcome::Missing {
                repr: AttrSelectRepr::Hamt
            }
        ));
        assert!(matches!(
            select_slow(AttrSelectTarget::Shaped(&shaped), ids[1]).expect("shaped select succeeds"),
            AttrSelectOutcome::Missing {
                repr: AttrSelectRepr::Shaped
            }
        ));
    }
}
