//! Phase-1 flat attribute-set representation.
//!
//! The tree-walk oracle starts with immutable flat attrsets: entries are stored
//! sorted by interned [`Symbol`] id for binary-search selection, while separate
//! source-order and raw-byte lexicographic permutations drive primop traversal
//! and observable iteration order for `attrNames`, `attrValues`, and
//! `derivationStrict`.
//!
//! A [`FlatAttrs`] value stores symbols, not names, and does not retain the
//! [`SymbolTable`] used to validate them. Callers must construct and query an
//! attrset with symbols from the same universe: either the shared process table
//! or one consistently remapped file-local table.

use std::convert::TryFrom;

use thiserror::Error;

use crate::syntax::{Span, Symbol, SymbolTable};
use crate::value::Value;

pub mod hamt;
pub mod pic;
pub mod repr;
pub mod shape;

/// Source provenance for one attribute binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttrPosition {
    /// The module that owns the binding source bytes.
    pub module: u32,
    /// The byte span of the binding key within the owning module.
    pub span: Span,
}

impl AttrPosition {
    /// Creates attribute source provenance.
    pub const fn new(module: u32, span: Span) -> Self {
        Self { module, span }
    }
}

/// One immutable attribute binding.
#[derive(Clone, Copy, Debug)]
pub struct AttrEntry {
    /// The interned attribute name.
    pub key: Symbol,
    /// The already-lowered runtime value for the binding.
    pub value: Value,
    /// Optional source position for `builtins.unsafeGetAttrPos`.
    pub position: Option<AttrPosition>,
}

impl AttrEntry {
    /// Creates an attribute binding.
    pub const fn new(key: Symbol, value: Value) -> Self {
        Self {
            key,
            value,
            position: None,
        }
    }

    /// Creates an attribute binding with source provenance.
    pub const fn with_position(key: Symbol, value: Value, position: AttrPosition) -> Self {
        Self {
            key,
            value,
            position: Some(position),
        }
    }
}

/// A flat immutable attribute set.
///
/// The attrset stores only [`Symbol`] ids. Selection APIs compare those ids
/// directly, so lookup keys must come from the same symbol universe that was
/// supplied to [`FlatAttrs::new`].
#[derive(Clone, Debug, Default)]
pub struct FlatAttrs {
    entries: Vec<AttrEntry>,
    source_order: Vec<u32>,
    iteration_order: Vec<u32>,
}

impl FlatAttrs {
    /// Creates an empty attribute set.
    pub const fn empty() -> Self {
        Self {
            entries: Vec::new(),
            source_order: Vec::new(),
            iteration_order: Vec::new(),
        }
    }

    /// Creates a flat attrset from unsorted entries.
    ///
    /// Entries are sorted by interned symbol id for binary-search selection. The
    /// lexicographic iteration permutation is computed from raw symbol bytes in
    /// `symbols`, independent of symbol allocation order. The provided symbol
    /// table defines the symbol universe for future lookup keys.
    ///
    /// # Errors
    ///
    /// Returns [`AttrError::DuplicateKey`] if the input contains the same symbol
    /// more than once. Returns [`AttrError::UnknownSymbol`] if any key cannot be
    /// resolved through `symbols`. Returns [`AttrError::TooManyEntries`] if the
    /// entry count cannot be represented in the `u32` slot permutation. Returns
    /// [`AttrError::AllocationFailed`] if the iteration tables cannot be
    /// reserved.
    pub fn new(mut entries: Vec<AttrEntry>, symbols: &SymbolTable) -> Result<Self, AttrError> {
        let len = entries.len();
        let len_u32 = u32::try_from(len).map_err(|_| AttrError::TooManyEntries { len })?;

        let mut source_keys = Vec::new();
        source_keys
            .try_reserve_exact(len)
            .map_err(|_| AttrError::AllocationFailed { entries: len })?;
        source_keys.extend(entries.iter().map(|entry| entry.key));

        entries.sort_unstable_by_key(|entry| entry.key);
        for pair in entries.windows(2) {
            if pair[0].key == pair[1].key {
                return Err(AttrError::DuplicateKey { key: pair[0].key });
            }
        }

        let mut source_order = Vec::new();
        source_order
            .try_reserve_exact(len)
            .map_err(|_| AttrError::AllocationFailed { entries: len })?;
        for key in source_keys {
            let slot = entries
                .binary_search_by_key(&key, |entry| entry.key)
                .map_err(|_| AttrError::UnknownSymbol { key })?;
            source_order.push(slot as u32);
        }

        let mut sort_names = Vec::new();
        sort_names
            .try_reserve_exact(len)
            .map_err(|_| AttrError::AllocationFailed { entries: len })?;
        for entry in &entries {
            let bytes = symbols
                .resolve(entry.key)
                .ok_or(AttrError::UnknownSymbol { key: entry.key })?;
            sort_names.push(bytes);
        }

        let mut iteration_order = Vec::new();
        iteration_order
            .try_reserve_exact(len)
            .map_err(|_| AttrError::AllocationFailed { entries: len })?;
        for slot in 0..len_u32 {
            iteration_order.push(slot);
        }
        iteration_order.sort_unstable_by(|left, right| {
            let left = *left as usize;
            let right = *right as usize;
            sort_names[left]
                .cmp(sort_names[right])
                .then_with(|| entries[left].key.cmp(&entries[right].key))
        });

        Ok(Self {
            entries,
            source_order,
            iteration_order,
        })
    }

    /// Returns the number of bindings.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the attrset contains no bindings.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the value for `key` using binary search over symbol-sorted
    /// storage.
    ///
    /// `key` must come from the same symbol universe used to construct this
    /// attrset.
    pub fn get(&self, key: Symbol) -> Option<Value> {
        self.get_entry(key).map(|entry| entry.value)
    }

    /// Returns the entry for `key` using binary search over symbol-sorted
    /// storage.
    ///
    /// `key` must come from the same symbol universe used to construct this
    /// attrset.
    pub fn get_entry(&self, key: Symbol) -> Option<&AttrEntry> {
        self.entries
            .binary_search_by_key(&key, |entry| entry.key)
            .ok()
            .and_then(|slot| self.entries.get(slot))
    }

    /// Returns whether the attrset contains `key`.
    ///
    /// `key` must come from the same symbol universe used to construct this
    /// attrset.
    pub fn contains_key(&self, key: Symbol) -> bool {
        self.get_entry(key).is_some()
    }

    /// Returns entries in internal symbol-id order.
    pub fn entries_by_symbol(&self) -> &[AttrEntry] {
        &self.entries
    }

    /// Returns the slot permutation for construction-order iteration.
    pub fn source_order(&self) -> &[u32] {
        &self.source_order
    }

    /// Returns the slot permutation for raw-byte lexicographic iteration.
    pub fn iteration_order(&self) -> &[u32] {
        &self.iteration_order
    }

    /// Returns representation-level flat-attrset equality.
    ///
    /// This is not Nix semantic equality: binding values compare by raw
    /// [`Value`] identity, and the source-order, lexicographic-order, and
    /// binding-position metadata all participate. Callers must compare attrsets
    /// whose symbols come from the same symbol universe described by
    /// [`FlatAttrs::new`].
    pub fn raw_eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self.source_order() == other.source_order()
            && self.iteration_order() == other.iteration_order()
            && self
                .entries_by_symbol()
                .iter()
                .zip(other.entries_by_symbol())
                .all(|(left, right)| {
                    left.key == right.key
                        && left.value.raw_eq(right.value)
                        && left.position == right.position
                })
    }

    /// Iterates entries in internal symbol-id order.
    pub fn iter_by_symbol(&self) -> std::slice::Iter<'_, AttrEntry> {
        self.entries.iter()
    }

    /// Iterates entries in the order supplied to [`FlatAttrs::new`].
    pub fn iter_source_order(&self) -> SourceOrderEntries<'_> {
        SourceOrderEntries {
            attrs: self,
            next: 0,
        }
    }

    /// Iterates entries in raw-byte lexicographic order.
    pub fn iter_lexicographic(&self) -> LexicographicEntries<'_> {
        LexicographicEntries {
            attrs: self,
            next: 0,
        }
    }
}

/// Iterator over [`FlatAttrs`] entries in construction order.
#[derive(Clone, Debug)]
pub struct SourceOrderEntries<'a> {
    attrs: &'a FlatAttrs,
    next: usize,
}

impl<'a> Iterator for SourceOrderEntries<'a> {
    type Item = &'a AttrEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let slot = *self.attrs.source_order.get(self.next)? as usize;
        self.next += 1;
        self.attrs.entries.get(slot)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.attrs.len().saturating_sub(self.next);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for SourceOrderEntries<'_> {}

/// Iterator over [`FlatAttrs`] entries in observable lexicographic order.
#[derive(Clone, Debug)]
pub struct LexicographicEntries<'a> {
    attrs: &'a FlatAttrs,
    next: usize,
}

impl<'a> Iterator for LexicographicEntries<'a> {
    type Item = &'a AttrEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let slot = *self.attrs.iteration_order.get(self.next)? as usize;
        self.next += 1;
        self.attrs.entries.get(slot)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.attrs.len().saturating_sub(self.next);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for LexicographicEntries<'_> {}

/// A flat-attrset construction failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AttrError {
    /// The input contained the same symbol more than once.
    #[error("duplicate attribute key {key:?}")]
    DuplicateKey {
        /// The duplicated symbol.
        key: Symbol,
    },
    /// A key did not resolve through the provided symbol table.
    #[error("unknown attribute key symbol {key:?}")]
    UnknownSymbol {
        /// The unresolved symbol.
        key: Symbol,
    },
    /// The attrset has more entries than the slot permutation can address.
    #[error("too many attribute entries: {len}")]
    TooManyEntries {
        /// The rejected entry count.
        len: usize,
    },
    /// Scratch storage for attrset construction could not be reserved.
    #[error("failed to reserve attribute iteration storage for {entries} entries")]
    AllocationFailed {
        /// The entry count whose construction storage could not be reserved.
        entries: usize,
    },
}

#[cfg(test)]
mod tests {
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
}
