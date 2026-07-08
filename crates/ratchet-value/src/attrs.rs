//! Phase-1 flat attribute-set representation.
//!
//! The tree-walk oracle starts with immutable flat attrsets: entries are stored
//! sorted by interned [`Symbol`] id for binary-search selection, while separate
//! source-order and raw-byte lexicographic permutations drive primop traversal
//! and observable iteration order for `attrNames`, `attrValues`, and
//! `derivationStrict`. Lexicographic permutations are sorted through the
//! [`SymbolTable`]'s cached rank view so construction does not repeatedly
//! compare raw byte strings after interning.
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
pub mod order;
pub mod pic;
pub mod repr;
pub mod select;
pub mod shape;
pub mod telemetry;
mod update;

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
    pub fn new(entries: Vec<AttrEntry>, symbols: &SymbolTable) -> Result<Self, AttrError> {
        let len = entries.len();
        let len_u32 = u32::try_from(len).map_err(|_| AttrError::TooManyEntries { len })?;

        // Sort a permutation of source positions by interned symbol id rather
        // than the entries themselves. Retaining each binding's construction
        // position lets the source-order slots fall out of the inverse
        // permutation directly, replacing the previous per-entry binary search.
        let mut permutation = Vec::new();
        permutation
            .try_reserve_exact(len)
            .map_err(|_| AttrError::AllocationFailed { entries: len })?;
        permutation.extend(0..len_u32);
        permutation.sort_unstable_by_key(|&slot| entries[slot as usize].key);

        // Duplicate keys are adjacent once ordered by symbol id.
        for pair in permutation.windows(2) {
            let key = entries[pair[0] as usize].key;
            if key == entries[pair[1] as usize].key {
                return Err(AttrError::DuplicateKey { key });
            }
        }

        // Materialize entries in symbol-id order and, for each source position,
        // record the storage slot it now occupies (the inverse permutation).
        let mut sorted = Vec::new();
        sorted
            .try_reserve_exact(len)
            .map_err(|_| AttrError::AllocationFailed { entries: len })?;
        let mut source_order = Vec::new();
        source_order
            .try_reserve_exact(len)
            .map_err(|_| AttrError::AllocationFailed { entries: len })?;
        source_order.resize(len, 0u32);
        for (storage_slot, &source_slot) in permutation.iter().enumerate() {
            sorted.push(entries[source_slot as usize]);
            source_order[source_slot as usize] = storage_slot as u32;
        }
        let entries = sorted;

        // Symbol-id order and raw-byte lexicographic order differ in general, so
        // the observable iteration order needs its own permutation sorted by the
        // symbol table's cached lexicographic ranks.
        let mut sort_ranks = Vec::new();
        sort_ranks
            .try_reserve_exact(len)
            .map_err(|_| AttrError::AllocationFailed { entries: len })?;
        for entry in &entries {
            let rank = symbols
                .lexicographic_rank(entry.key)
                .ok_or(AttrError::UnknownSymbol { key: entry.key })?;
            sort_ranks.push(rank);
        }

        // Reuse the scratch permutation buffer for the lexicographic order.
        let mut iteration_order = permutation;
        for (slot, value) in iteration_order.iter_mut().enumerate() {
            *value = slot as u32;
        }
        iteration_order.sort_unstable_by(|left, right| {
            let left = *left as usize;
            let right = *right as usize;
            sort_ranks[left]
                .cmp(&sort_ranks[right])
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

    /// Returns a copy with one symbol-order slot's value replaced.
    ///
    /// This preserves the existing source-order and lexicographic-order
    /// permutations. Callers must pass the key they expect at `slot` so stale
    /// field metadata cannot silently update the wrong binding.
    ///
    /// # Errors
    ///
    /// Returns [`AttrError::SlotOutOfBounds`] if `slot` is not present. Returns
    /// [`AttrError::SlotKeyMismatch`] if the slot exists but contains another
    /// key.
    pub fn with_symbol_slot_value(
        &self,
        slot: usize,
        key: Symbol,
        value: Value,
    ) -> Result<Self, AttrError> {
        let mut replaced = self.clone();
        let len = replaced.entries.len();
        let Some(entry) = replaced.entries.get_mut(slot) else {
            return Err(AttrError::SlotOutOfBounds { slot, len });
        };
        if entry.key != key {
            return Err(AttrError::SlotKeyMismatch {
                slot,
                expected: key,
                actual: entry.key,
            });
        }
        entry.value = value;
        Ok(replaced)
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
    /// A symbol-order slot did not exist.
    #[error("attribute symbol slot {slot} is out of bounds for {len} entries")]
    SlotOutOfBounds {
        /// The requested symbol-order slot.
        slot: usize,
        /// The number of entries in the attrset.
        len: usize,
    },
    /// A symbol-order slot contained a different key than the caller expected.
    #[error("attribute symbol slot {slot} key mismatch: expected {expected:?}, found {actual:?}")]
    SlotKeyMismatch {
        /// The requested symbol-order slot.
        slot: usize,
        /// The key expected by the caller.
        expected: Symbol,
        /// The key stored at the slot.
        actual: Symbol,
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
    fn lexicographic_order_uses_current_symbol_rank_snapshot() {
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
}
