//! Phase-1 flat attribute-set representation.
//!
//! The tree-walk oracle starts with immutable flat attrsets: entries are stored
//! sorted by interned [`Symbol`] id for binary-search selection, while separate
//! source-order and raw-byte lexicographic permutations drive primop traversal
//! and observable iteration order for `attrNames`, `attrValues`, and
//! `derivationStrict`. Shape and HAMT permutations use a compact local prefix
//! token and compare complete raw byte strings only when prefixes collide.
//!
//! A [`FlatAttrs`] value stores symbols, not names, and does not retain the
//! [`SymbolTable`] used to validate them. Callers must construct and query an
//! attrset with symbols from the same universe: either the shared process table
//! or one consistently remapped file-local table.

use std::convert::TryFrom;

use thiserror::Error;

use crate::heap::flat::FlatSlice;
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

/// Returns an order-preserving token for the first seven bytes of `bytes`.
///
/// Each byte maps to the 9-bit digit `byte + 1`, while an absent byte maps to
/// zero. Packing seven digits most-significant first preserves byte-slice
/// lexicographic order whenever the tokens differ. Equal tokens require a
/// full comparison because strings can share a seven-byte prefix.
pub(crate) fn lexicographic_prefix(bytes: &[u8]) -> u64 {
    let mut prefix = 0_u64;
    for index in 0..7 {
        prefix <<= 9;
        prefix |= bytes
            .get(index)
            .map_or(0, |byte| u64::from(*byte) + 1);
    }
    prefix
}

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

/// The array storage behind one [`FlatAttrs`].
///
/// RFC-0007 doc 30 stage FV-4: attrsets interned into the evaluator heap's
/// flat object store keep their entry array and both order permutations
/// *inline* in the flat allocation, behind [`FlatSlice`] witnesses, instead
/// of three per-attrset `Vec` allocations. Every other attrset — evaluator
/// temporaries, cache payloads, shared-mode slot payloads — keeps the owned
/// `Vec`s. The variant is invisible through the public API: every reader
/// goes through the slice accessors, so the two representations are
/// observationally identical. A clone always deep-copies into owned storage,
/// so no flat-backed attrset can escape the store by cloning.
#[derive(Debug)]
enum AttrsStorage {
    /// Arrays owned by process-allocator `Vec`s.
    Owned {
        entries: Vec<AttrEntry>,
        source_order: Vec<u32>,
        iteration_order: Vec<u32>,
    },
    /// Arrays inlined in a flat-object allocation (heap-resident attrsets
    /// only).
    Flat {
        entries: FlatSlice<AttrEntry>,
        source_order: FlatSlice<u32>,
        iteration_order: FlatSlice<u32>,
    },
}

/// The storage class behind one attrset's arrays, as heap-image capture must
/// treat it (RFC-0007 doc 31 §1).
///
/// Every variant of [`AttrsStorage`] (private) maps to exactly one capture
/// strategy here, through a wildcard-free match in
/// [`FlatAttrs::storage_kind`]; snapshot capture then matches this enum
/// wildcard-free again. A future storage class therefore cannot reach capture
/// without an explicit decision at both sites.
#[cfg(feature = "candidate_c_value")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttrsStorageKind {
    /// Arrays owned by process-allocator `Vec`s: the dumped headers dangle
    /// after restore, so capture must serialize an owned-attrs payload
    /// segment.
    Owned,
    /// Arrays inlined in the flat allocation: the bytes ride the dumped
    /// lanes and a relocation-entry witness rebase suffices.
    FlatWitness,
}

/// A flat immutable attribute set.
///
/// The attrset stores only [`Symbol`] ids. Selection APIs compare those ids
/// directly, so lookup keys must come from the same symbol universe that was
/// supplied to [`FlatAttrs::new`].
pub struct FlatAttrs {
    storage: AttrsStorage,
}

impl Clone for FlatAttrs {
    fn clone(&self) -> Self {
        // Deep-copy into owned storage: a flat-backed attrset must never
        // propagate its inline-array witnesses outside the flat store
        // payload (see `AttrsStorage`).
        Self {
            storage: AttrsStorage::Owned {
                entries: self.entries().to_vec(),
                source_order: self.source_order().to_vec(),
                iteration_order: self.iteration_order().to_vec(),
            },
        }
    }
}

impl Default for FlatAttrs {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Debug for FlatAttrs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keep the pre-FV-4 derived shape (three arrays rendered as lists)
        // regardless of the storage representation.
        f.debug_struct("FlatAttrs")
            .field("entries", &self.entries())
            .field("source_order", &self.source_order())
            .field("iteration_order", &self.iteration_order())
            .finish()
    }
}

impl FlatAttrs {
    /// Creates an empty attribute set.
    pub const fn empty() -> Self {
        Self {
            storage: AttrsStorage::Owned {
                entries: Vec::new(),
                source_order: Vec::new(),
                iteration_order: Vec::new(),
            },
        }
    }

    /// Creates an attrset from already-validated owned arrays.
    ///
    /// Internal construction door for the update/merge paths, which derive
    /// their arrays from existing validated attrsets; the [`FlatAttrs::new`]
    /// invariants (symbol-sorted entries, inverse source permutation,
    /// lexicographic iteration permutation, equal lengths) are the caller's
    /// obligation.
    pub(crate) fn from_owned_parts(
        entries: Vec<AttrEntry>,
        source_order: Vec<u32>,
        iteration_order: Vec<u32>,
    ) -> Self {
        debug_assert_eq!(entries.len(), source_order.len());
        debug_assert_eq!(entries.len(), iteration_order.len());
        Self {
            storage: AttrsStorage::Owned {
                entries,
                source_order,
                iteration_order,
            },
        }
    }

    /// Creates an attrset over flat-object inline arrays (doc 30 FV-4).
    ///
    /// Only the evaluator heap's flat store constructs these, by copying the
    /// arrays of an already-validated owned attrset into one flat allocation:
    /// the witnesses are valid exactly as long as the flat allocation that
    /// carries the attrset, and every escape path (clone) deep-copies back
    /// into owned storage. The [`FlatAttrs::new`] invariants transfer from
    /// the copied source; equal array lengths are debug-asserted here.
    pub fn from_flat_parts(
        entries: FlatSlice<AttrEntry>,
        source_order: FlatSlice<u32>,
        iteration_order: FlatSlice<u32>,
    ) -> Self {
        debug_assert_eq!(entries.len(), source_order.len());
        debug_assert_eq!(entries.len(), iteration_order.len());
        Self {
            storage: AttrsStorage::Flat {
                entries,
                source_order,
                iteration_order,
            },
        }
    }

    /// Classifies this attrset's array storage for heap-image capture.
    ///
    /// The match is deliberately wildcard-free: adding an [`AttrsStorage`]
    /// variant fails to compile here, forcing an explicit capture-strategy
    /// decision (the default-deny guard against a new owned-storage class
    /// silently restoring dangling — the `AOS_NIX_SNAPSHOT_VERIFY` audit
    /// cannot see out-pointing storage).
    #[cfg(feature = "candidate_c_value")]
    pub fn storage_kind(&self) -> AttrsStorageKind {
        match &self.storage {
            AttrsStorage::Owned { .. } => AttrsStorageKind::Owned,
            AttrsStorage::Flat { .. } => AttrsStorageKind::FlatWitness,
        }
    }

    /// Rebuilds an attrset from restored owned arrays (RFC-0007 doc 31 §1
    /// heap-image restore).
    ///
    /// The [`FlatAttrs::new`] invariants (symbol-sorted entries, inverse
    /// source permutation, lexicographic iteration permutation, equal
    /// lengths) transfer from the captured attrset; the restore decoder
    /// validates permutation bounds and entry sort order before calling this,
    /// since the serialized image is untrusted input.
    #[cfg(feature = "candidate_c_value")]
    pub fn from_restored_parts(
        entries: Vec<AttrEntry>,
        source_order: Vec<u32>,
        iteration_order: Vec<u32>,
    ) -> Self {
        Self::from_owned_parts(entries, source_order, iteration_order)
    }

    /// Returns the symbol-sorted entry array.
    fn entries(&self) -> &[AttrEntry] {
        match &self.storage {
            AttrsStorage::Owned { entries, .. } => entries,
            AttrsStorage::Flat { entries, .. } => entries.as_slice(),
        }
    }

    /// Rebases the interior inline-array witnesses by `delta` bytes.
    ///
    /// The heap-image restore path (RFC-0007 doc 31 §1 decision 6) copies a flat
    /// attrset's bytes into a reservation mapped at a new base, then shifts each
    /// `Flat` witness by `delta = new_base − old_base` so it names its run's new
    /// location. `Owned` attrsets carry no arena witnesses and are left
    /// unchanged. Reads and writes no entry.
    #[cfg(feature = "candidate_c_value")]
    pub fn rebase_witnesses(&mut self, delta: isize) {
        if let AttrsStorage::Flat {
            entries,
            source_order,
            iteration_order,
        } = &mut self.storage
        {
            entries.rebase(delta);
            source_order.rebase(delta);
            iteration_order.rebase(delta);
        }
    }

    /// Rewrites entry values in place through `map`, returning how many entries
    /// changed (RFC-0007 doc 31 §1 step-3 forced-thunk collapse).
    ///
    /// `map` returns `Some(replacement)` for a value to rewrite and `None` to
    /// leave an entry unchanged. Keys, positions, and both order permutations
    /// are untouched, so every selection invariant is preserved; the
    /// structural hash the entry values feed goes stale and the caller must
    /// recompute it (the collapse pass reuses the writeback hash repair).
    ///
    /// Owned storage rewrites through the entry `Vec`. Flat storage rewrites
    /// the object's inline entry run in place, which is only sound while the
    /// caller holds the payload exclusively: reach this method through the
    /// flat store's `&mut self` payload resolution on a quiesced serial heap
    /// (the heap-image collapse pre-pass), never from a shared borrow.
    #[cfg(feature = "candidate_c_value")]
    pub fn rewrite_entry_values(&mut self, map: &mut dyn FnMut(Value) -> Option<Value>) -> usize {
        let entries: &mut [AttrEntry] = match &mut self.storage {
            AttrsStorage::Owned { entries, .. } => entries.as_mut_slice(),
            AttrsStorage::Flat { entries, .. } => {
                // SAFETY: this `&mut self` is derived from the flat store's
                // exclusive payload resolution (the documented calling
                // contract above), so no aliasing reference into the inline
                // run exists for the borrow's duration, and the collapse
                // pre-pass runs on a quiesced serial heap with no concurrent
                // reader. The witness's construction contract covers the
                // initialized, aligned, mapped run.
                unsafe { entries.as_mut_slice() }
            }
        };
        let mut rewritten = 0;
        for entry in entries {
            if let Some(replacement) = map(entry.value) {
                entry.value = replacement;
                rewritten += 1;
            }
        }
        rewritten
    }

    /// Rewrites entry keys and position provenance through the supplied maps,
    /// re-sorting the entry array and remapping both order permutations
    /// (RFC-0007 doc 31 §1 step-4 W1 cross-evaluator re-interning).
    ///
    /// `map_symbol` rewrites an interned key id into the consuming
    /// evaluator's symbol universe; returning `None` (an id outside the
    /// captured table) aborts with `Err(())` and the attrset is left
    /// untouched — the caller refuses the payload. `map_position_module`
    /// rewrites a position's raw module id; returning `None` *degrades that
    /// position to absent* instead of refusing: positions are diagnostic
    /// provenance, and a module with no counterpart in the consuming
    /// evaluator (the capturing evaluation's own root, for example) has no
    /// honest position to report.
    ///
    /// Names are unchanged by re-interning, so the lexicographic iteration
    /// ORDER of entries is preserved; but entries are stored sorted by
    /// interned id and both permutations index storage slots, so the array is
    /// re-sorted by the new ids and the permutations are composed with the
    /// induced slot movement. Duplicate or non-strictly-increasing new ids
    /// (only producible by a forged table with repeated names) also abort.
    ///
    /// The structural hash over this attrset is id-derived (it hashes entry
    /// key ids, position module ids, and both permutations), so the caller
    /// must recompute it through the safe header-update door afterwards.
    ///
    /// Owned storage rewrites through the `Vec`s. Flat storage rewrites the
    /// object's inline runs in place, which is only sound while the caller
    /// holds the payload exclusively: reach this method through the flat
    /// store's `&mut self` payload resolution on a quiesced serial heap (the
    /// heap-image restore pass), never from a shared borrow.
    #[cfg(feature = "candidate_c_value")]
    pub fn reintern_entries(
        &mut self,
        map_symbol: &mut dyn FnMut(Symbol) -> Option<Symbol>,
        map_position_module: &mut dyn FnMut(u32) -> Option<u32>,
    ) -> Result<(), ()> {
        let len = self.len();
        // Stage the rewritten arrays in full before any in-place write, so a
        // refusal leaves the attrset untouched.
        let mut remapped: Vec<AttrEntry> = Vec::with_capacity(len);
        for entry in self.entries() {
            let key = map_symbol(entry.key).ok_or(())?;
            let position = match &entry.position {
                Some(position) => map_position_module(position.module).map(|module| AttrPosition {
                    module,
                    span: position.span,
                }),
                None => None,
            };
            remapped.push(AttrEntry {
                key,
                value: entry.value,
                position,
            });
        }
        // Slot permutation induced by re-sorting on the new ids:
        // `order[new_slot] = old_slot`.
        let mut order: Vec<u32> = (0..len as u32).collect();
        order.sort_unstable_by_key(|&slot| remapped[slot as usize].key);
        // Strictly increasing new ids (duplicates = forged repeated names).
        for pair in order.windows(2) {
            if remapped[pair[0] as usize].key >= remapped[pair[1] as usize].key {
                return Err(());
            }
        }
        let mut inverse = vec![0u32; len];
        for (new_slot, &old_slot) in order.iter().enumerate() {
            inverse[old_slot as usize] = new_slot as u32;
        }
        let sorted: Vec<AttrEntry> = order
            .iter()
            .map(|&old_slot| remapped[old_slot as usize].clone())
            .collect();
        let mut new_source: Vec<u32> = Vec::with_capacity(len);
        for &slot in self.source_order() {
            new_source.push(*inverse.get(slot as usize).ok_or(())?);
        }
        let mut new_iteration: Vec<u32> = Vec::with_capacity(len);
        for &slot in self.iteration_order() {
            new_iteration.push(*inverse.get(slot as usize).ok_or(())?);
        }

        match &mut self.storage {
            AttrsStorage::Owned {
                entries,
                source_order,
                iteration_order,
            } => {
                *entries = sorted;
                *source_order = new_source;
                *iteration_order = new_iteration;
            }
            AttrsStorage::Flat {
                entries,
                source_order,
                iteration_order,
            } => {
                // SAFETY: this `&mut self` is derived from the flat store's
                // exclusive payload resolution (the documented calling
                // contract above), so no aliasing reference into any of the
                // three inline runs exists for the borrow's duration, and the
                // restore pass runs on a quiesced serial heap with no
                // concurrent reader. The witnesses' construction contract
                // covers the initialized, aligned, mapped runs, and every
                // staged array has exactly the run's length.
                unsafe {
                    entries.as_mut_slice().clone_from_slice(&sorted);
                    source_order.as_mut_slice().copy_from_slice(&new_source);
                    iteration_order
                        .as_mut_slice()
                        .copy_from_slice(&new_iteration);
                }
            }
        }
        Ok(())
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

        // One- and two-entry attrsets order trivially by comparing resolved
        // key bytes directly, with no symbol-table rank reads. This matters
        // beyond the constant factor: the rank view rebuilds in `O(symbols)`
        // on the first rank read after any intern, so update chains that
        // intern a fresh key and then build a small `{ key = v; }` literal
        // each iteration would otherwise pay a full rebuild per layer.
        if len <= 2 {
            return Self::new_small(entries, symbols);
        }

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
        // the observable iteration order needs its own permutation. Validate
        // every key before sorting, then compare the interned bytes directly.
        //
        // Do not ask the process-wide symbol table for dense lexicographic
        // ranks here. Interning one new name invalidates that O(symbols) view;
        // nixpkgs commonly interns between construction of modest attrsets, so
        // rebuilding the global view here turns an otherwise local operation
        // into repeated whole-table work.
        for entry in &entries {
            if symbols.resolve(entry.key).is_none() {
                return Err(AttrError::UnknownSymbol { key: entry.key });
            }
        }

        // Reuse the scratch permutation buffer for the lexicographic order.
        let mut iteration_order = permutation;
        for (slot, value) in iteration_order.iter_mut().enumerate() {
            *value = slot as u32;
        }
        iteration_order.sort_unstable_by(|left, right| {
            let left = *left as usize;
            let right = *right as usize;
            symbols
                .resolve(entries[left].key)
                .cmp(&symbols.resolve(entries[right].key))
                .then_with(|| entries[left].key.cmp(&entries[right].key))
        });

        Ok(Self::from_owned_parts(
            entries,
            source_order,
            iteration_order,
        ))
    }

    /// Builds a one- or two-entry attrset without symbol-table rank reads.
    ///
    /// Preserves [`FlatAttrs::new`]'s error semantics: duplicate keys are
    /// rejected before unresolved symbols, and every key must resolve through
    /// `symbols`. Ordering by resolved raw key bytes is definitionally
    /// identical to ordering by the table's lexicographic ranks.
    fn new_small(mut entries: Vec<AttrEntry>, symbols: &SymbolTable) -> Result<Self, AttrError> {
        debug_assert!(entries.len() <= 2);
        if entries.len() == 2 && entries[0].key == entries[1].key {
            return Err(AttrError::DuplicateKey {
                key: entries[0].key,
            });
        }
        let resolve = |key: Symbol| symbols.resolve(key).ok_or(AttrError::UnknownSymbol { key });
        let mut source_order = Vec::new();
        let mut iteration_order = Vec::new();
        let reserve = |slots: &mut Vec<u32>, len: usize| {
            slots
                .try_reserve_exact(len)
                .map_err(|_| AttrError::AllocationFailed { entries: len })
        };
        reserve(&mut source_order, entries.len())?;
        reserve(&mut iteration_order, entries.len())?;
        match entries.len() {
            0 => {}
            1 => {
                resolve(entries[0].key)?;
                source_order.push(0);
                iteration_order.push(0);
            }
            _ => {
                let first = resolve(entries[0].key)?;
                let second = resolve(entries[1].key)?;
                // Storage stays sorted by symbol id; permutations are derived
                // from which input entry sorts first on each axis.
                let symbol_swap = entries[0].key > entries[1].key;
                if symbol_swap {
                    entries.swap(0, 1);
                }
                source_order.extend(if symbol_swap { [1, 0] } else { [0, 1] });
                let byte_swap = (first > second) != symbol_swap;
                iteration_order.extend(if byte_swap { [1, 0] } else { [0, 1] });
            }
        }
        Ok(Self::from_owned_parts(
            entries,
            source_order,
            iteration_order,
        ))
    }

    /// Returns the number of bindings.
    pub fn len(&self) -> usize {
        self.entries().len()
    }

    /// Returns whether the attrset contains no bindings.
    pub fn is_empty(&self) -> bool {
        self.entries().is_empty()
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
        let entries = self.entries();
        entries
            .binary_search_by_key(&key, |entry| entry.key)
            .ok()
            .and_then(|slot| entries.get(slot))
    }

    /// Returns whether the attrset contains `key`.
    ///
    /// `key` must come from the same symbol universe used to construct this
    /// attrset.
    pub fn contains_key(&self, key: Symbol) -> bool {
        self.get_entry(key).is_some()
    }

    /// Returns the symbol-order storage slot holding `key`, if present.
    ///
    /// The slot indexes [`FlatAttrs::entries_by_symbol`]; select-site caches
    /// store it so later instances with the same key layout can load the
    /// entry without repeating the binary search. `key` must come from the
    /// same symbol universe used to construct this attrset.
    pub fn symbol_slot(&self, key: Symbol) -> Option<u32> {
        self.entries()
            .binary_search_by_key(&key, |entry| entry.key)
            .ok()
            .and_then(|slot| u32::try_from(slot).ok())
    }

    /// Returns entries in internal symbol-id order.
    pub fn entries_by_symbol(&self) -> &[AttrEntry] {
        self.entries()
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
        let AttrsStorage::Owned { entries, .. } = &mut replaced.storage else {
            // Clones always deep-copy into owned storage (see `Clone`).
            unreachable!("cloned FlatAttrs storage is always owned");
        };
        let len = entries.len();
        let Some(entry) = entries.get_mut(slot) else {
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
        match &self.storage {
            AttrsStorage::Owned { source_order, .. } => source_order,
            AttrsStorage::Flat { source_order, .. } => source_order.as_slice(),
        }
    }

    /// Returns the slot permutation for raw-byte lexicographic iteration.
    pub fn iteration_order(&self) -> &[u32] {
        match &self.storage {
            AttrsStorage::Owned {
                iteration_order, ..
            } => iteration_order,
            AttrsStorage::Flat {
                iteration_order, ..
            } => iteration_order.as_slice(),
        }
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
        self.entries().iter()
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
        let slot = *self.attrs.source_order().get(self.next)? as usize;
        self.next += 1;
        self.attrs.entries().get(slot)
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
        let slot = *self.attrs.iteration_order().get(self.next)? as usize;
        self.next += 1;
        self.attrs.entries().get(slot)
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
mod tests;
