//! Small-constructor inline layout helpers for future list and attr fast paths.
//!
//! The active list and attrset representations remain [`crate::list::NixList`]
//! and [`crate::attrs::FlatAttrs`]. This module only captures the safe contract
//! for the later measured variant: zero-, one-, and two-element lists or
//! attrsets may be represented directly in the value payload path so
//! `length`/single-key `select` can avoid a heap-header load. Larger
//! constructors still classify as heap-backed.
//!
//! Inline payload slots are ordinary [`super::Value`] handles. Placeholder slots
//! are never part of the logical length, are initialized to `null`, and carry no
//! semantic meaning.

use thiserror::Error;

use crate::attrs::AttrEntry;
use crate::syntax::Symbol;

use super::Value;

/// Maximum logical arity carried by the small-constructor inline variant.
pub const SMALL_CONSTRUCTOR_INLINE_CAPACITY: usize = 2;

/// The constructor family being considered for inline representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SmallConstructorKind {
    /// A list spine with up to two element slots.
    List,
    /// A flat attribute set with up to two binding slots.
    Attrs,
}

/// A decision for placing a constructor in the future small-constructor layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SmallConstructorPlacement {
    /// Store the constructor directly in the inline small-constructor path.
    Inline {
        /// The constructor family being represented.
        kind: SmallConstructorKind,
        /// The logical number of occupied slots.
        len: usize,
    },
    /// Store the constructor in the ordinary heap representation.
    Heap {
        /// The constructor family being represented.
        kind: SmallConstructorKind,
        /// The logical constructor arity.
        len: usize,
        /// The reason the inline path is not selected.
        reason: SmallConstructorHeapReason,
    },
}

/// Why a constructor falls back to the ordinary heap representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SmallConstructorHeapReason {
    /// The constructor arity exceeds [`SMALL_CONSTRUCTOR_INLINE_CAPACITY`].
    ExceedsInlineCapacity,
}

/// Classifies whether a constructor can use the future small-constructor path.
pub const fn classify_small_constructor(
    kind: SmallConstructorKind,
    len: usize,
) -> SmallConstructorPlacement {
    if len <= SMALL_CONSTRUCTOR_INLINE_CAPACITY {
        SmallConstructorPlacement::Inline { kind, len }
    } else {
        SmallConstructorPlacement::Heap {
            kind,
            len,
            reason: SmallConstructorHeapReason::ExceedsInlineCapacity,
        }
    }
}

/// An inline list payload with up to two logical element slots.
#[derive(Clone, Copy, Debug)]
pub struct InlineSmallList {
    len: u8,
    elements: [Value; SMALL_CONSTRUCTOR_INLINE_CAPACITY],
}

impl InlineSmallList {
    /// Creates an inline list payload from up to two values.
    ///
    /// Elements are copied as runtime handles and are not forced. Unused payload
    /// slots are initialized to `null` and ignored by all logical accessors.
    ///
    /// # Errors
    ///
    /// Returns [`SmallConstructorError::TooManyListElements`] when `elements`
    /// exceeds [`SMALL_CONSTRUCTOR_INLINE_CAPACITY`].
    pub fn new(elements: &[Value]) -> Result<Self, SmallConstructorError> {
        if elements.len() > SMALL_CONSTRUCTOR_INLINE_CAPACITY {
            return Err(SmallConstructorError::TooManyListElements {
                len: elements.len(),
            });
        }

        let mut inline = Self::empty();
        let mut index = 0;
        while index < elements.len() {
            inline.elements[index] = elements[index];
            index += 1;
        }
        inline.len = elements.len() as u8;
        Ok(inline)
    }

    /// Creates the empty inline list payload.
    pub const fn empty() -> Self {
        Self {
            len: 0,
            elements: [Value::null(); SMALL_CONSTRUCTOR_INLINE_CAPACITY],
        }
    }

    /// Returns the logical element count.
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Returns whether this inline list has no logical elements.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Returns a copied logical element at `index`.
    pub fn get(&self, index: usize) -> Option<Value> {
        if index < self.len() {
            Some(self.elements[index])
        } else {
            None
        }
    }

    /// Returns the logical element prefix.
    pub fn as_slice(&self) -> &[Value] {
        &self.elements[..self.len()]
    }

    /// Returns the raw backing slots, including ignored padding.
    pub const fn raw_slots(self) -> [Value; SMALL_CONSTRUCTOR_INLINE_CAPACITY] {
        self.elements
    }
}

/// An inline attrset payload with up to two logical binding slots.
#[derive(Clone, Copy, Debug)]
pub struct InlineSmallAttrs {
    len: u8,
    entries: [AttrEntry; SMALL_CONSTRUCTOR_INLINE_CAPACITY],
}

impl InlineSmallAttrs {
    /// Creates an inline attrset payload from up to two entries.
    ///
    /// Entries keep the supplied order. This helper does not replace
    /// [`crate::attrs::FlatAttrs`] and does not compute source or lexicographic
    /// permutations; the future shape layer must decide when those cached orders
    /// can be derived without heap materialization.
    ///
    /// # Errors
    ///
    /// Returns [`SmallConstructorError::TooManyAttrEntries`] when `entries`
    /// exceeds [`SMALL_CONSTRUCTOR_INLINE_CAPACITY`]. Returns
    /// [`SmallConstructorError::DuplicateAttrKey`] when the inline payload would
    /// contain the same attribute key twice.
    pub fn new(entries: &[AttrEntry]) -> Result<Self, SmallConstructorError> {
        if entries.len() > SMALL_CONSTRUCTOR_INLINE_CAPACITY {
            return Err(SmallConstructorError::TooManyAttrEntries { len: entries.len() });
        }
        if entries.len() == 2 && entries[0].key == entries[1].key {
            return Err(SmallConstructorError::DuplicateAttrKey {
                key: entries[0].key,
            });
        }

        let mut inline = Self::empty();
        let mut index = 0;
        while index < entries.len() {
            inline.entries[index] = entries[index];
            index += 1;
        }
        inline.len = entries.len() as u8;
        Ok(inline)
    }

    /// Creates the empty inline attrset payload.
    pub const fn empty() -> Self {
        Self {
            len: 0,
            entries: [empty_attr_entry(); SMALL_CONSTRUCTOR_INLINE_CAPACITY],
        }
    }

    /// Returns the logical binding count.
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Returns whether this inline attrset has no logical bindings.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Returns the logical binding prefix in payload order.
    pub fn entries(&self) -> &[AttrEntry] {
        &self.entries[..self.len()]
    }

    /// Returns the value for `key` from the logical inline prefix.
    pub fn get(&self, key: Symbol) -> Option<Value> {
        self.entries()
            .iter()
            .find(|entry| entry.key == key)
            .map(|entry| entry.value)
    }

    /// Returns the raw backing slots, including ignored padding.
    pub const fn raw_slots(self) -> [AttrEntry; SMALL_CONSTRUCTOR_INLINE_CAPACITY] {
        self.entries
    }
}

/// A failed small-constructor inline payload operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SmallConstructorError {
    /// A list had too many elements for the inline small-constructor path.
    #[error(
        "small-constructor list has {len} elements, exceeding inline capacity {SMALL_CONSTRUCTOR_INLINE_CAPACITY}"
    )]
    TooManyListElements {
        /// The rejected list length.
        len: usize,
    },
    /// An attrset had too many bindings for the inline small-constructor path.
    #[error(
        "small-constructor attrset has {len} entries, exceeding inline capacity {SMALL_CONSTRUCTOR_INLINE_CAPACITY}"
    )]
    TooManyAttrEntries {
        /// The rejected attrset length.
        len: usize,
    },
    /// An inline attrset payload would contain duplicate keys.
    #[error("small-constructor attrset has duplicate key {key:?}")]
    DuplicateAttrKey {
        /// The duplicated attribute key.
        key: Symbol,
    },
}

const fn empty_attr_entry() -> AttrEntry {
    AttrEntry::new(Symbol::new(0), Value::null())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attrs::AttrPosition;
    use crate::syntax::Span;

    #[test]
    fn placement_inlines_only_zero_one_or_two_slot_constructors() {
        for kind in [SmallConstructorKind::List, SmallConstructorKind::Attrs] {
            assert_eq!(
                classify_small_constructor(kind, 0),
                SmallConstructorPlacement::Inline { kind, len: 0 }
            );
            assert_eq!(
                classify_small_constructor(kind, 2),
                SmallConstructorPlacement::Inline { kind, len: 2 }
            );
            assert_eq!(
                classify_small_constructor(kind, 3),
                SmallConstructorPlacement::Heap {
                    kind,
                    len: 3,
                    reason: SmallConstructorHeapReason::ExceedsInlineCapacity,
                }
            );
        }
    }

    #[test]
    fn inline_lists_preserve_logical_prefix_and_ignore_padding() {
        let list =
            InlineSmallList::new(&[Value::int(1), Value::bool(true)]).expect("list fits inline");

        assert_eq!(list.len(), 2);
        assert!(!list.is_empty());
        assert_eq!(list.get(0).expect("first").as_int(), Ok(1));
        assert_eq!(list.get(1).expect("second").as_bool(), Ok(true));
        assert!(list.get(2).is_none());
        assert_eq!(list.as_slice().len(), 2);

        let singleton = InlineSmallList::new(&[Value::int(9)]).expect("list fits inline");
        assert_eq!(singleton.len(), 1);
        assert_eq!(singleton.get(0).expect("only").as_int(), Ok(9));
        assert_eq!(singleton.raw_slots()[1].as_null(), Ok(()));
    }

    #[test]
    fn inline_lists_reject_oversized_spines_without_forcing_values() {
        let values = [Value::int(1), Value::int(2), Value::int(3)];

        assert_eq!(
            InlineSmallList::new(&values).expect_err("three elements exceed inline capacity"),
            SmallConstructorError::TooManyListElements { len: 3 }
        );
    }

    #[test]
    fn inline_attrs_preserve_entries_and_positions() {
        let key_a = Symbol::new(1);
        let key_b = Symbol::new(2);
        let position = AttrPosition::new(7, Span::new(3, 5));
        let attrs = InlineSmallAttrs::new(&[
            AttrEntry::with_position(key_b, Value::int(2), position),
            AttrEntry::new(key_a, Value::int(1)),
        ])
        .expect("attrs fit inline");

        assert_eq!(attrs.len(), 2);
        assert!(!attrs.is_empty());
        assert_eq!(attrs.get(key_a).expect("a exists").as_int(), Ok(1));
        assert_eq!(attrs.get(key_b).expect("b exists").as_int(), Ok(2));
        assert!(attrs.get(Symbol::new(99)).is_none());
        assert_eq!(attrs.entries()[0].position, Some(position));
    }

    #[test]
    fn inline_attrs_reject_duplicate_keys_and_oversized_entries() {
        let key = Symbol::new(1);

        assert_eq!(
            InlineSmallAttrs::new(&[
                AttrEntry::new(key, Value::int(1)),
                AttrEntry::new(key, Value::int(2)),
            ])
            .expect_err("duplicate keys are rejected"),
            SmallConstructorError::DuplicateAttrKey { key }
        );
        assert_eq!(
            InlineSmallAttrs::new(&[
                AttrEntry::new(Symbol::new(1), Value::int(1)),
                AttrEntry::new(Symbol::new(2), Value::int(2)),
                AttrEntry::new(Symbol::new(3), Value::int(3)),
            ])
            .expect_err("three entries exceed inline capacity"),
            SmallConstructorError::TooManyAttrEntries { len: 3 }
        );
    }

    #[test]
    fn empty_inline_payloads_have_null_padding() {
        let list = InlineSmallList::empty();
        let attrs = InlineSmallAttrs::empty();

        assert!(list.is_empty());
        assert!(attrs.is_empty());
        assert!(
            list.raw_slots()
                .iter()
                .all(|value| value.as_null() == Ok(()))
        );
        assert!(
            attrs
                .raw_slots()
                .iter()
                .all(|entry| entry.key == Symbol::new(0) && entry.value.as_null() == Ok(()))
        );
    }
}
