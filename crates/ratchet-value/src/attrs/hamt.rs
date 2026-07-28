//! Persistent HAMT storage for future large attrset update results.
//!
//! This module provides the safe value-level substrate for RFC-0007 §09's
//! large / override-heavy `//` path: immutable bitmap-indexed nodes keyed by
//! dense [`Symbol`] ids, entry overwrites that preserve old roots by structural
//! sharing, and a cached raw-byte lexicographic key view for observable Nix
//! iteration. The ordered view is sorted through the [`SymbolTable`]'s cached
//! rank view, then memoized on the immutable HAMT value. The active tree-walk
//! evaluator still stores attrsets as [`crate::attrs::FlatAttrs`]; this module
//! does not change `//`, selection, or `.drv` bytes until a later representation
//! wrapper wires it into runtime attr values.

use std::convert::TryFrom;
use std::sync::Arc;

use thiserror::Error;

use crate::attrs::{AttrEntry, AttrPosition, FlatAttrs};
use crate::syntax::{Symbol, SymbolTable};

const BITS_PER_LEVEL: u32 = 5;
const CHUNK_MASK: u32 = (1 << BITS_PER_LEVEL) - 1;
const MAX_SHIFT: u32 = 30;

/// An immutable HAMT-backed attrset value.
///
/// Keys are [`Symbol`] ids and are meaningful only within the symbol universe
/// supplied to [`HamtAttrs::new`]. The trie uses the raw dense symbol bits as a
/// reversible hash domain, so distinct `u32` symbols cannot collide after all
/// trie levels have been consumed.
#[derive(Clone, Debug, Default)]
pub struct HamtAttrs {
    root: Option<Arc<HamtNode>>,
    len: usize,
    keys_by_symbol: Box<[Symbol]>,
    iteration_order: Box<[Symbol]>,
}

impl HamtAttrs {
    /// Creates an empty HAMT attrset.
    pub fn empty() -> Self {
        Self {
            root: None,
            len: 0,
            keys_by_symbol: Box::new([]),
            iteration_order: Box::new([]),
        }
    }

    /// Creates a HAMT attrset from unsorted entries.
    ///
    /// Entries are keyed by interned symbol id for lookup. The observable
    /// lexicographic iteration view is cached from raw symbol bytes in
    /// `symbols`, independent of symbol allocation order.
    ///
    /// # Errors
    ///
    /// Returns [`HamtError::DuplicateKey`] if the input contains the same
    /// symbol more than once. Returns [`HamtError::UnknownSymbol`] if any key
    /// cannot be resolved through `symbols`. Returns
    /// [`HamtError::TooManyEntries`] if the entry count exceeds the future
    /// `u32` slot ABI shared with flat attrsets and shapes. Returns
    /// [`HamtError::AllocationFailed`] if scratch storage cannot be reserved.
    pub fn new(mut entries: Vec<AttrEntry>, symbols: &SymbolTable) -> Result<Self, HamtError> {
        let len = entries.len();
        u32::try_from(len).map_err(|_| HamtError::TooManyEntries { len })?;

        entries.sort_unstable_by_key(|entry| entry.key);
        for pair in entries.windows(2) {
            if pair[0].key == pair[1].key {
                return Err(HamtError::DuplicateKey { key: pair[0].key });
            }
        }

        let mut keys_by_symbol = Vec::new();
        keys_by_symbol
            .try_reserve_exact(len)
            .map_err(|_| HamtError::AllocationFailed { entries: len })?;
        for entry in &entries {
            symbols
                .resolve(entry.key)
                .ok_or(HamtError::UnknownSymbol { key: entry.key })?;
            keys_by_symbol.push(entry.key);
        }

        let root = build_root(&entries)?;
        let iteration_order = lexicographic_order(&keys_by_symbol, symbols)?;
        Ok(Self {
            root,
            len,
            keys_by_symbol: keys_by_symbol.into_boxed_slice(),
            iteration_order,
        })
    }

    /// Creates a HAMT attrset from an existing flat attrset.
    ///
    /// # Errors
    ///
    /// Returns [`HamtError`] if a flat key cannot be resolved through `symbols`,
    /// if the key count exceeds the future `u32` slot ABI,
    /// or if scratch storage cannot be reserved.
    pub fn from_flat(attrs: &FlatAttrs, symbols: &SymbolTable) -> Result<Self, HamtError> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(attrs.len())
            .map_err(|_| HamtError::AllocationFailed {
                entries: attrs.len(),
            })?;
        entries.extend(attrs.entries_by_symbol().iter().copied());
        Self::new(entries, symbols)
    }

    /// Returns the number of bindings.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the attrset contains no bindings.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns keys in internal symbol-id order.
    pub fn keys_by_symbol(&self) -> &[Symbol] {
        &self.keys_by_symbol
    }

    /// Returns keys in observable raw-byte lexicographic order.
    pub fn iteration_order(&self) -> &[Symbol] {
        &self.iteration_order
    }

    /// Returns the value for `key`.
    ///
    /// `key` must come from the same symbol universe used to construct this
    /// attrset.
    pub fn get(&self, key: Symbol) -> Option<crate::value::Value> {
        self.get_entry(key).map(|entry| entry.value)
    }

    /// Returns the entry for `key`.
    ///
    /// `key` must come from the same symbol universe used to construct this
    /// attrset.
    pub fn get_entry(&self, key: Symbol) -> Option<&AttrEntry> {
        let root = self.root.as_ref()?;
        get_from_node(root, key, 0)
    }

    /// Returns whether this attrset contains `key`.
    ///
    /// `key` must come from the same symbol universe used to construct this
    /// attrset.
    pub fn contains_key(&self, key: Symbol) -> bool {
        self.get_entry(key).is_some()
    }

    /// Returns a new HAMT with `entry` inserted or replaced.
    ///
    /// Existing roots remain valid and continue to observe the old binding. A
    /// replacement keeps the cached key order unchanged; an insertion updates
    /// both the symbol-id and lexicographic ordered views.
    ///
    /// # Errors
    ///
    /// Returns [`HamtError::UnknownSymbol`] if `entry.key` cannot be resolved
    /// through `symbols`. Returns [`HamtError::TooManyEntries`] if an insertion
    /// would exceed the future `u32` slot ABI. Returns
    /// [`HamtError::AllocationFailed`] if scratch storage cannot be reserved.
    pub fn insert(
        &self,
        entry: AttrEntry,
        symbols: &SymbolTable,
    ) -> Result<(Self, HamtUpdate), HamtError> {
        symbols
            .resolve(entry.key)
            .ok_or(HamtError::UnknownSymbol { key: entry.key })?;

        let (root, mutation) = match &self.root {
            Some(root) => insert_into_node(root, entry, 0)?,
            None => (single_entry_node(entry)?, HamtMutation::Inserted),
        };

        let (len, keys_by_symbol, iteration_order, update) = match mutation {
            HamtMutation::Inserted => {
                let len = self
                    .len
                    .checked_add(1)
                    .ok_or(HamtError::TooManyEntries { len: usize::MAX })?;
                u32::try_from(len).map_err(|_| HamtError::TooManyEntries { len })?;
                let keys_by_symbol = insert_symbol_key(&self.keys_by_symbol, entry.key)?;
                // Splice the one new key into the existing lexicographic order
                // (O(n)) rather than re-ranking and re-sorting all keys
                // (O(n log n)) on every insert.
                let iteration_order =
                    insert_lexicographic(&self.iteration_order, entry.key, symbols)?;
                (len, keys_by_symbol, iteration_order, HamtUpdate::Inserted)
            }
            HamtMutation::Replaced { previous } => (
                self.len,
                self.keys_by_symbol.clone(),
                self.iteration_order.clone(),
                HamtUpdate::Replaced { previous },
            ),
        };

        Ok((
            Self {
                root: Some(root),
                len,
                keys_by_symbol,
                iteration_order,
            },
            update,
        ))
    }

    /// Applies a flat right-hand operand as a persistent `//` update merge.
    ///
    /// The result contains all bindings from `self` and `right`; right-hand
    /// values and source positions replace left-hand bindings on key collision.
    /// The original HAMT remains valid and shares all untouched trie branches
    /// with the result. `self`, `right`, and `symbols` must belong to the same
    /// symbol universe.
    ///
    /// # Errors
    ///
    /// Returns [`HamtError::UnknownSymbol`] if a key from either operand cannot
    /// be resolved through `symbols`, including symbol-universe mismatches.
    /// Returns [`HamtError::TooManyEntries`] if the merged result exceeds the
    /// future `u32` slot ABI. Returns [`HamtError::AllocationFailed`] if scratch
    /// storage cannot be reserved.
    pub fn update_from_flat(
        &self,
        right: &FlatAttrs,
        symbols: &SymbolTable,
    ) -> Result<(Self, HamtMergeSummary), HamtError> {
        self.update_from_entries(right.iter_source_order().copied(), symbols)
    }

    /// Applies a HAMT right-hand operand as a persistent `//` update merge.
    ///
    /// The result contains all bindings from `self` and `right`; right-hand
    /// values and source positions replace left-hand bindings on key collision.
    /// The original HAMT remains valid and shares all untouched trie branches
    /// with the result. `self`, `right`, and `symbols` must belong to the same
    /// symbol universe.
    ///
    /// # Errors
    ///
    /// Returns [`HamtError::UnknownSymbol`] if a key from either operand cannot
    /// be resolved through `symbols`, including symbol-universe mismatches.
    /// Returns [`HamtError::TooManyEntries`] if the merged result exceeds the
    /// future `u32` slot ABI. Returns [`HamtError::AllocationFailed`] if scratch
    /// storage cannot be reserved.
    pub fn update_from_hamt(
        &self,
        right: &Self,
        symbols: &SymbolTable,
    ) -> Result<(Self, HamtMergeSummary), HamtError> {
        self.update_from_entries(right.iter_by_symbol().copied(), symbols)
    }

    fn update_from_entries<I>(
        &self,
        entries: I,
        symbols: &SymbolTable,
    ) -> Result<(Self, HamtMergeSummary), HamtError>
    where
        I: IntoIterator<Item = AttrEntry>,
    {
        let mut root = self.root.clone();
        let mut len = self.len;
        let mut keys_by_symbol = Vec::new();
        keys_by_symbol
            .try_reserve_exact(self.keys_by_symbol.len())
            .map_err(|_| HamtError::AllocationFailed {
                entries: self.keys_by_symbol.len(),
            })?;
        keys_by_symbol.extend_from_slice(&self.keys_by_symbol);

        let mut summary = HamtMergeSummary::default();
        for entry in entries {
            symbols
                .resolve(entry.key)
                .ok_or(HamtError::UnknownSymbol { key: entry.key })?;

            let (next_root, mutation) = match &root {
                Some(root) => insert_into_node(root, entry, 0)?,
                None => (single_entry_node(entry)?, HamtMutation::Inserted),
            };
            match mutation {
                HamtMutation::Inserted => {
                    len = len
                        .checked_add(1)
                        .ok_or(HamtError::TooManyEntries { len: usize::MAX })?;
                    u32::try_from(len).map_err(|_| HamtError::TooManyEntries { len })?;
                    insert_symbol_key_in_place(&mut keys_by_symbol, entry.key)?;
                    summary.record_inserted()?;
                }
                HamtMutation::Replaced { .. } => summary.record_replaced()?,
            }
            root = Some(next_root);
        }

        let iteration_order = lexicographic_order(&keys_by_symbol, symbols)?;
        Ok((
            Self {
                root,
                len,
                keys_by_symbol: keys_by_symbol.into_boxed_slice(),
                iteration_order,
            },
            summary,
        ))
    }

    /// Iterates entries in internal symbol-id order.
    pub fn iter_by_symbol(&self) -> HamtEntries<'_> {
        HamtEntries {
            attrs: self,
            keys: &self.keys_by_symbol,
            next: 0,
        }
    }

    /// Iterates entries in observable raw-byte lexicographic order.
    pub fn iter_lexicographic(&self) -> HamtEntries<'_> {
        HamtEntries {
            attrs: self,
            keys: &self.iteration_order,
            next: 0,
        }
    }

    /// Returns representation-level HAMT equality.
    ///
    /// This is not Nix semantic equality: binding values compare by raw
    /// [`crate::value::Value`] identity, and source-position metadata
    /// participates. Callers must compare attrsets whose symbols come from the
    /// same symbol universe described by [`HamtAttrs::new`].
    pub fn raw_eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self.keys_by_symbol() == other.keys_by_symbol()
            && self.iteration_order() == other.iteration_order()
            && self
                .iter_by_symbol()
                .zip(other.iter_by_symbol())
                .all(|(left, right)| raw_entry_eq(left, right))
    }
}

/// The result of inserting into a HAMT attrset.
///
/// Equality for replacement results compares the previous binding at
/// representation level: keys, raw [`crate::value::Value`] identity, and source
/// position metadata all participate. It is not Nix semantic equality.
#[derive(Clone, Copy, Debug)]
pub enum HamtUpdate {
    /// A new key was added.
    Inserted,
    /// An existing key was replaced.
    Replaced {
        /// The binding that was previously stored for the key.
        previous: AttrEntry,
    },
}

impl PartialEq for HamtUpdate {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Inserted, Self::Inserted) => true,
            (Self::Replaced { previous: left }, Self::Replaced { previous: right }) => {
                raw_entry_eq(left, right)
            }
            _ => false,
        }
    }
}

impl Eq for HamtUpdate {}

/// Accounting for one HAMT `//` update merge.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct HamtMergeSummary {
    inserted: usize,
    replaced: usize,
}

impl HamtMergeSummary {
    /// Returns how many right-hand keys were inserted into the left operand.
    pub const fn inserted(self) -> usize {
        self.inserted
    }

    /// Returns how many right-hand keys replaced existing left bindings.
    pub const fn replaced(self) -> usize {
        self.replaced
    }

    /// Returns how many right-hand bindings were applied.
    pub const fn applied(self) -> usize {
        self.inserted.saturating_add(self.replaced)
    }

    /// Returns whether the merge applied no right-hand bindings.
    pub const fn is_empty(self) -> bool {
        self.inserted == 0 && self.replaced == 0
    }

    fn record_inserted(&mut self) -> Result<(), HamtError> {
        self.inserted = self
            .inserted
            .checked_add(1)
            .ok_or(HamtError::TooManyEntries { len: usize::MAX })?;
        Ok(())
    }

    fn record_replaced(&mut self) -> Result<(), HamtError> {
        self.replaced = self
            .replaced
            .checked_add(1)
            .ok_or(HamtError::TooManyEntries { len: usize::MAX })?;
        Ok(())
    }
}

/// Iterator over [`HamtAttrs`] entries in a cached key order.
#[derive(Clone, Debug)]
pub struct HamtEntries<'a> {
    attrs: &'a HamtAttrs,
    keys: &'a [Symbol],
    next: usize,
}

impl<'a> Iterator for HamtEntries<'a> {
    type Item = &'a AttrEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let key = *self.keys.get(self.next)?;
        self.next += 1;
        let entry = self.attrs.get_entry(key);
        debug_assert!(
            entry.is_some(),
            "HAMT ordered view contained a key missing from the trie"
        );
        entry
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.keys.len().saturating_sub(self.next);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for HamtEntries<'_> {}

/// A failed HAMT attrset operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum HamtError {
    /// The input contained the same symbol more than once.
    #[error("duplicate HAMT attribute key {key:?}")]
    DuplicateKey {
        /// The duplicated symbol.
        key: Symbol,
    },
    /// A key did not resolve through the provided symbol table.
    #[error("unknown HAMT attribute key symbol {key:?}")]
    UnknownSymbol {
        /// The unresolved symbol.
        key: Symbol,
    },
    /// The attrset has more entries than the future `u32` slot ABI can address.
    #[error("too many HAMT attribute entries: {len}")]
    TooManyEntries {
        /// The rejected key count.
        len: usize,
    },
    /// Scratch storage for HAMT construction could not be reserved.
    #[error("failed to reserve HAMT storage for {entries} entries")]
    AllocationFailed {
        /// The entry count whose construction storage could not be reserved.
        entries: usize,
    },
    /// Distinct symbols exhausted every trie level without separating.
    #[error("HAMT key hash collision between {left:?} and {right:?}")]
    KeyHashCollision {
        /// The first colliding key.
        left: Symbol,
        /// The second colliding key.
        right: Symbol,
    },
}

#[derive(Clone, Debug)]
struct HamtNode {
    bitmap: u32,
    slots: Box<[HamtSlot]>,
}

#[derive(Clone, Copy, Debug)]
enum HamtMutation {
    Inserted,
    Replaced { previous: AttrEntry },
}

#[derive(Clone, Debug)]
enum HamtSlot {
    Entry(AttrEntry),
    Node(Arc<HamtNode>),
}

/// Builds the root HAMT node for `entries` in a single bottom-up pass.
///
/// `entries` must already be de-duplicated and sorted by key (as
/// [`HamtAttrs::new`] guarantees). Each node is allocated exactly once, unlike
/// the per-entry [`insert_into_node`] fold which path-copies and then discards a
/// fresh `Arc` chain for every key. The resulting trie is identical to that
/// sequential insertion: a HAMT's shape is fixed by the set of key hashes and is
/// independent of insertion order, so bulk and incremental construction converge
/// on the same nodes (a debug-only equivalence check samples this invariant).
fn build_root(entries: &[AttrEntry]) -> Result<Option<Arc<HamtNode>>, HamtError> {
    let root = if entries.is_empty() {
        None
    } else {
        Some(build_node(entries, 0)?)
    };
    #[cfg(debug_assertions)]
    if sample_bulk_build_verification() {
        let sequential = build_root_sequential(entries)?;
        debug_assert!(
            roots_structurally_equal(root.as_deref(), sequential.as_deref()),
            "HAMT bulk build diverged from sequential insertion",
        );
    }
    Ok(root)
}

/// Builds one HAMT node from `entries` (non-empty, distinct keys) at `shift`.
///
/// Entries are partitioned by their 5-bit chunk at this level; each chunk with a
/// single entry becomes a leaf slot and each chunk with several recurses into a
/// child node built at the next level. Slots are emitted in ascending bit order,
/// matching the sparse indexing that [`get_from_node`] relies on.
///
/// # Errors
///
/// Returns [`HamtError::AllocationFailed`] if scratch or slot storage cannot be
/// reserved, or [`HamtError::KeyHashCollision`] if two distinct keys share every
/// chunk through the deepest level (unreachable for distinct 32-bit symbol ids,
/// which always diverge within the seven available chunks).
fn build_node(entries: &[AttrEntry], shift: u32) -> Result<Arc<HamtNode>, HamtError> {
    if entries.len() == 1 {
        let entry = entries[0];
        return Ok(Arc::new(HamtNode {
            bitmap: bit_for(entry.key, shift),
            slots: Box::new([HamtSlot::Entry(entry)]),
        }));
    }
    if shift > MAX_SHIFT {
        return Err(HamtError::KeyHashCollision {
            left: entries[0].key,
            right: entries[1].key,
        });
    }

    let mut bitmap = 0u32;
    for entry in entries {
        bitmap |= bit_for(entry.key, shift);
    }
    // A scratch buffer sized to the whole input holds each chunk's entries
    // contiguously so children recurse over sub-slices; its exact reservation
    // means the per-chunk pushes never reallocate and invalidate a live bucket.
    let mut scratch: Vec<AttrEntry> = Vec::new();
    scratch
        .try_reserve_exact(entries.len())
        .map_err(|_| HamtError::AllocationFailed {
            entries: entries.len(),
        })?;
    let mut slots: Vec<HamtSlot> = Vec::new();
    slots
        .try_reserve_exact(bitmap.count_ones() as usize)
        .map_err(|_| HamtError::AllocationFailed {
            entries: entries.len(),
        })?;

    let mut remaining = bitmap;
    while remaining != 0 {
        let bit = remaining & remaining.wrapping_neg();
        remaining ^= bit;
        let chunk = bit.trailing_zeros();
        let start = scratch.len();
        for entry in entries {
            if chunk_for(entry.key, shift) == chunk {
                scratch.push(*entry);
            }
        }
        let bucket = &scratch[start..];
        if bucket.len() == 1 {
            slots.push(HamtSlot::Entry(bucket[0]));
        } else {
            slots.push(HamtSlot::Node(build_node(bucket, next_shift(shift))?));
        }
    }

    Ok(Arc::new(HamtNode {
        bitmap,
        slots: slots.into_boxed_slice(),
    }))
}

/// Builds the root node by folding `entries` through [`insert_into_node`].
///
/// Retained only as the reference the debug-only equivalence check in
/// [`build_root`] compares [`build_node`] against.
#[cfg(debug_assertions)]
fn build_root_sequential(entries: &[AttrEntry]) -> Result<Option<Arc<HamtNode>>, HamtError> {
    let mut root: Option<Arc<HamtNode>> = None;
    for entry in entries {
        root = Some(match &root {
            Some(root) => insert_into_node(root, *entry, 0)?.0,
            None => single_entry_node(*entry)?,
        });
    }
    Ok(root)
}

/// Reports whether two optional root nodes are structurally identical.
#[cfg(debug_assertions)]
fn roots_structurally_equal(left: Option<&HamtNode>, right: Option<&HamtNode>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => nodes_structurally_equal(left, right),
        _ => false,
    }
}

/// Reports whether two HAMT nodes have identical bitmaps and slot trees.
#[cfg(debug_assertions)]
fn nodes_structurally_equal(left: &HamtNode, right: &HamtNode) -> bool {
    if left.bitmap != right.bitmap || left.slots.len() != right.slots.len() {
        return false;
    }
    left.slots
        .iter()
        .zip(right.slots.iter())
        .all(|(left, right)| match (left, right) {
            (HamtSlot::Entry(left), HamtSlot::Entry(right)) => raw_entry_eq(left, right),
            (HamtSlot::Node(left), HamtSlot::Node(right)) => nodes_structurally_equal(left, right),
            _ => false,
        })
}

/// Returns `true` for one in every sixteen calls, throttling the debug-only
/// bulk/sequential equivalence check so its second construction stays a sampled
/// cost rather than doubling every attrset build.
#[cfg(debug_assertions)]
fn sample_bulk_build_verification() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed) % 16 == 0
}

fn single_entry_node(entry: AttrEntry) -> Result<Arc<HamtNode>, HamtError> {
    let bit = bit_for(entry.key, 0);
    Ok(Arc::new(HamtNode {
        bitmap: bit,
        slots: Box::new([HamtSlot::Entry(entry)]),
    }))
}

fn get_from_node(node: &HamtNode, key: Symbol, shift: u32) -> Option<&AttrEntry> {
    let bit = bit_for(key, shift);
    if node.bitmap & bit == 0 {
        return None;
    }
    let slot = sparse_index(node.bitmap, bit);
    match node.slots.get(slot)? {
        HamtSlot::Entry(entry) => (entry.key == key).then_some(entry),
        HamtSlot::Node(child) => get_from_node(child, key, next_shift(shift)),
    }
}

fn insert_into_node(
    node: &HamtNode,
    entry: AttrEntry,
    shift: u32,
) -> Result<(Arc<HamtNode>, HamtMutation), HamtError> {
    let bit = bit_for(entry.key, shift);
    let slot = sparse_index(node.bitmap, bit);
    if node.bitmap & bit == 0 {
        let slots = insert_slot(&node.slots, slot, HamtSlot::Entry(entry))?;
        return Ok((
            Arc::new(HamtNode {
                bitmap: node.bitmap | bit,
                slots,
            }),
            HamtMutation::Inserted,
        ));
    }

    let existing = &node.slots[slot];
    let (replacement, mutation) = match existing {
        HamtSlot::Entry(existing) if existing.key == entry.key => (
            HamtSlot::Entry(entry),
            HamtMutation::Replaced {
                previous: *existing,
            },
        ),
        HamtSlot::Entry(existing) => {
            let child = merge_entries(*existing, entry, next_shift(shift))?;
            (HamtSlot::Node(child), HamtMutation::Inserted)
        }
        HamtSlot::Node(child) => {
            let (child, mutation) = insert_into_node(child, entry, next_shift(shift))?;
            (HamtSlot::Node(child), mutation)
        }
    };

    let slots = replace_slot(&node.slots, slot, replacement)?;
    Ok((
        Arc::new(HamtNode {
            bitmap: node.bitmap,
            slots,
        }),
        mutation,
    ))
}

fn merge_entries(
    left: AttrEntry,
    right: AttrEntry,
    shift: u32,
) -> Result<Arc<HamtNode>, HamtError> {
    if shift > MAX_SHIFT {
        return Err(HamtError::KeyHashCollision {
            left: left.key,
            right: right.key,
        });
    }

    let left_bit = bit_for(left.key, shift);
    let right_bit = bit_for(right.key, shift);
    if left_bit == right_bit {
        return Ok(Arc::new(HamtNode {
            bitmap: left_bit,
            slots: Box::new([HamtSlot::Node(merge_entries(
                left,
                right,
                next_shift(shift),
            )?)]),
        }));
    }

    let (first, second) = if sparse_index(left_bit | right_bit, left_bit)
        < sparse_index(left_bit | right_bit, right_bit)
    {
        (HamtSlot::Entry(left), HamtSlot::Entry(right))
    } else {
        (HamtSlot::Entry(right), HamtSlot::Entry(left))
    };

    Ok(Arc::new(HamtNode {
        bitmap: left_bit | right_bit,
        slots: Box::new([first, second]),
    }))
}

fn insert_slot(
    slots: &[HamtSlot],
    index: usize,
    slot: HamtSlot,
) -> Result<Box<[HamtSlot]>, HamtError> {
    let len = slots
        .len()
        .checked_add(1)
        .ok_or(HamtError::AllocationFailed {
            entries: usize::MAX,
        })?;
    let mut next = Vec::new();
    next.try_reserve_exact(len)
        .map_err(|_| HamtError::AllocationFailed { entries: len })?;
    next.extend_from_slice(&slots[..index]);
    next.push(slot);
    next.extend_from_slice(&slots[index..]);
    Ok(next.into_boxed_slice())
}

fn replace_slot(
    slots: &[HamtSlot],
    index: usize,
    slot: HamtSlot,
) -> Result<Box<[HamtSlot]>, HamtError> {
    let mut next = Vec::new();
    next.try_reserve_exact(slots.len())
        .map_err(|_| HamtError::AllocationFailed {
            entries: slots.len(),
        })?;
    next.extend_from_slice(slots);
    next[index] = slot;
    Ok(next.into_boxed_slice())
}

fn insert_symbol_key(keys: &[Symbol], key: Symbol) -> Result<Box<[Symbol]>, HamtError> {
    let index = match keys.binary_search(&key) {
        Ok(index) | Err(index) => index,
    };
    let len = keys
        .len()
        .checked_add(1)
        .ok_or(HamtError::TooManyEntries { len: usize::MAX })?;
    let mut next = Vec::new();
    next.try_reserve_exact(len)
        .map_err(|_| HamtError::AllocationFailed { entries: len })?;
    next.extend_from_slice(&keys[..index]);
    next.push(key);
    next.extend_from_slice(&keys[index..]);
    Ok(next.into_boxed_slice())
}

fn insert_symbol_key_in_place(keys: &mut Vec<Symbol>, key: Symbol) -> Result<(), HamtError> {
    let index = match keys.binary_search(&key) {
        Ok(_) => return Ok(()),
        Err(index) => index,
    };
    keys.try_reserve_exact(1)
        .map_err(|_| HamtError::AllocationFailed {
            entries: keys.len().saturating_add(1),
        })?;
    keys.insert(index, key);
    Ok(())
}

fn lexicographic_order(
    keys_by_symbol: &[Symbol],
    symbols: &SymbolTable,
) -> Result<Box<[Symbol]>, HamtError> {
    let mut key_bytes = Vec::new();
    key_bytes
        .try_reserve_exact(keys_by_symbol.len())
        .map_err(|_| HamtError::AllocationFailed {
            entries: keys_by_symbol.len(),
        })?;
    for key in keys_by_symbol {
        let bytes = symbols
            .resolve(*key)
            .ok_or(HamtError::UnknownSymbol { key: *key })?;
        key_bytes.push(bytes);
    }

    let mut slots = Vec::new();
    slots
        .try_reserve_exact(keys_by_symbol.len())
        .map_err(|_| HamtError::AllocationFailed {
            entries: keys_by_symbol.len(),
        })?;
    for slot in 0..keys_by_symbol.len() {
        slots.push(slot);
    }
    slots.sort_unstable_by(|left, right| {
        key_bytes[*left]
            .cmp(key_bytes[*right])
            .then_with(|| keys_by_symbol[*left].cmp(&keys_by_symbol[*right]))
    });

    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(keys_by_symbol.len())
        .map_err(|_| HamtError::AllocationFailed {
            entries: keys_by_symbol.len(),
        })?;
    for slot in slots {
        ordered.push(keys_by_symbol[slot]);
    }
    Ok(ordered.into_boxed_slice())
}

/// Splices one new key into an already lexicographically-ordered key list.
///
/// `order` is a key list already sorted under [`lexicographic_order`]'s
/// `(resolved bytes, symbol)` comparator, and `key` is a symbol not already
/// present. Returns `order` with `key` inserted at its sorted position, doing a
/// binary search (O(log n) byte comparisons) plus one O(n) copy instead of
/// re-sorting every key on each insert.
///
/// This is order-identical to recomputing [`lexicographic_order`] from scratch:
/// interned symbols have unique byte strings, and raw byte-slice ordering is
/// the observable Nix attribute order. Later interning cannot change the
/// relative order of existing byte strings, so the spliced result matches a
/// full re-sort exactly.
///
/// # Errors
///
/// Returns [`HamtError::UnknownSymbol`] if `key` or a probed key has no rank in
/// `symbols`, or [`HamtError::AllocationFailed`] on reservation failure.
fn insert_lexicographic(
    order: &[Symbol],
    key: Symbol,
    symbols: &SymbolTable,
) -> Result<Box<[Symbol]>, HamtError> {
    let key_bytes = symbols
        .resolve(key)
        .ok_or(HamtError::UnknownSymbol { key })?;

    // Binary search for the insertion point under the (rank, symbol) order.
    let mut lo = 0;
    let mut hi = order.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let probe = order[mid];
        let probe_bytes = symbols
            .resolve(probe)
            .ok_or(HamtError::UnknownSymbol { key: probe })?;
        if (probe_bytes, probe) < (key_bytes, key) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    let len = order
        .len()
        .checked_add(1)
        .ok_or(HamtError::TooManyEntries { len: usize::MAX })?;
    let mut next = Vec::new();
    next.try_reserve_exact(len)
        .map_err(|_| HamtError::AllocationFailed { entries: len })?;
    next.extend_from_slice(&order[..lo]);
    next.push(key);
    next.extend_from_slice(&order[lo..]);
    Ok(next.into_boxed_slice())
}

fn bit_for(key: Symbol, shift: u32) -> u32 {
    1 << chunk_for(key, shift)
}

fn chunk_for(key: Symbol, shift: u32) -> u32 {
    (key.as_u32() >> shift) & CHUNK_MASK
}

fn sparse_index(bitmap: u32, bit: u32) -> usize {
    (bitmap & (bit - 1)).count_ones() as usize
}

fn next_shift(shift: u32) -> u32 {
    shift.saturating_add(BITS_PER_LEVEL)
}

fn raw_entry_eq(left: &AttrEntry, right: &AttrEntry) -> bool {
    left.key == right.key
        && left.value.raw_eq(right.value)
        && positions_raw_eq(left.position, right.position)
}

fn positions_raw_eq(left: Option<AttrPosition>, right: Option<AttrPosition>) -> bool {
    left == right
}

#[cfg(test)]
mod tests;
