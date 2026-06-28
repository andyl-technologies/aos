//! Attribute-set shape descriptors for future hidden-class fast paths.
//!
//! A shape captures the key layout shared by attrset instances: the internal
//! symbol-sorted key vector used for binary-search lookup, the construction
//! order permutation, the observable raw-byte lexicographic iteration
//! permutation, and an in-process xxh3 fingerprint of the key vector. This is a
//! safe descriptor only. It does not install a global shape table, transition
//! tree, inline cache, HAMT representation, or runtime fast path.

use std::convert::TryFrom;
use std::hash::{Hash, Hasher};

use thiserror::Error;
use xxhash_rust::xxh3::Xxh3;

use crate::syntax::{Symbol, SymbolTable};

/// An in-process fingerprint of a shape's symbol-sorted key vector.
///
/// This hash is only a lookup accelerator for future shape tables and hash-cons
/// probes. It is not a Nix-observable hash, not durable across implementations,
/// and not sufficient for equality without comparing the key vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShapeFingerprint(u64);

impl ShapeFingerprint {
    /// Returns the raw xxh3 fingerprint bits.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// A hidden-class shape descriptor for flat attrset instances.
///
/// Shape keys are raw [`Symbol`] ids and are meaningful only within the symbol
/// universe supplied to [`AttrShape::from_construction_order`]. Use
/// [`AttrShape::raw_eq`] only when both shapes were built against the same
/// symbol table.
#[derive(Clone, Debug)]
pub struct AttrShape {
    keys: Box<[Symbol]>,
    source_order: Box<[u32]>,
    iteration_order: Box<[u32]>,
    fingerprint: ShapeFingerprint,
}

impl AttrShape {
    /// Creates an empty shape descriptor.
    pub fn empty() -> Self {
        Self {
            keys: Box::new([]),
            source_order: Box::new([]),
            iteration_order: Box::new([]),
            fingerprint: fingerprint_keys(&[]),
        }
    }

    /// Creates a shape from keys in construction order.
    ///
    /// The descriptor stores keys sorted by symbol id for lookup and computes
    /// cached permutations for construction-order and raw-byte lexicographic
    /// iteration.
    ///
    /// # Errors
    ///
    /// Returns [`ShapeError::DuplicateKey`] if `keys` contains the same symbol
    /// more than once. Returns [`ShapeError::UnknownSymbol`] if any key cannot
    /// be resolved through `symbols`. Returns [`ShapeError::TooManyKeys`] if the
    /// shape cannot encode its slot permutations in `u32`. Returns
    /// [`ShapeError::AllocationFailed`] if scratch storage cannot be reserved.
    pub fn from_construction_order(
        keys: &[Symbol],
        symbols: &SymbolTable,
    ) -> Result<Self, ShapeError> {
        let len = keys.len();
        let len_u32 = u32::try_from(len).map_err(|_| ShapeError::TooManyKeys { len })?;

        let mut sorted_keys = Vec::new();
        sorted_keys
            .try_reserve_exact(len)
            .map_err(|_| ShapeError::AllocationFailed { keys: len })?;
        sorted_keys.extend_from_slice(keys);
        sorted_keys.sort_unstable();
        for pair in sorted_keys.windows(2) {
            if pair[0] == pair[1] {
                return Err(ShapeError::DuplicateKey { key: pair[0] });
            }
        }

        let mut source_order = Vec::new();
        source_order
            .try_reserve_exact(len)
            .map_err(|_| ShapeError::AllocationFailed { keys: len })?;
        for key in keys {
            let slot = sorted_keys
                .binary_search(key)
                .map_err(|_| ShapeError::UnknownSymbol { key: *key })?;
            source_order.push(slot as u32);
        }

        let mut sort_names = Vec::new();
        sort_names
            .try_reserve_exact(len)
            .map_err(|_| ShapeError::AllocationFailed { keys: len })?;
        for key in &sorted_keys {
            let bytes = symbols
                .resolve(*key)
                .ok_or(ShapeError::UnknownSymbol { key: *key })?;
            sort_names.push(bytes);
        }

        let mut iteration_order = Vec::new();
        iteration_order
            .try_reserve_exact(len)
            .map_err(|_| ShapeError::AllocationFailed { keys: len })?;
        for slot in 0..len_u32 {
            iteration_order.push(slot);
        }
        iteration_order.sort_unstable_by(|left, right| {
            let left = *left as usize;
            let right = *right as usize;
            sort_names[left]
                .cmp(sort_names[right])
                .then_with(|| sorted_keys[left].cmp(&sorted_keys[right]))
        });

        let fingerprint = fingerprint_keys(&sorted_keys);
        Ok(Self {
            keys: sorted_keys.into_boxed_slice(),
            source_order: source_order.into_boxed_slice(),
            iteration_order: iteration_order.into_boxed_slice(),
            fingerprint,
        })
    }

    /// Returns the number of keys in the shape.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns whether the shape contains no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Returns the symbol-sorted key vector.
    pub fn keys_by_symbol(&self) -> &[Symbol] {
        &self.keys
    }

    /// Returns the construction-order permutation over symbol-sorted slots.
    pub fn source_order(&self) -> &[u32] {
        &self.source_order
    }

    /// Returns the raw-byte lexicographic permutation over symbol-sorted slots.
    pub fn iteration_order(&self) -> &[u32] {
        &self.iteration_order
    }

    /// Returns the in-process fingerprint for this shape's key vector.
    pub const fn fingerprint(&self) -> ShapeFingerprint {
        self.fingerprint
    }

    /// Returns the symbol-sorted slot for `key`.
    pub fn slot(&self, key: Symbol) -> Option<u32> {
        self.keys
            .binary_search(&key)
            .ok()
            .and_then(|slot| u32::try_from(slot).ok())
    }

    /// Returns whether the shape contains `key`.
    pub fn contains_key(&self, key: Symbol) -> bool {
        self.slot(key).is_some()
    }

    /// Returns representation-level shape equality.
    ///
    /// This compares raw symbol ids and cached permutations, not attribute-name
    /// bytes. Callers must compare only shapes whose symbols come from the same
    /// symbol universe described by [`AttrShape::from_construction_order`].
    pub fn raw_eq(&self, other: &Self) -> bool {
        self.keys_by_symbol() == other.keys_by_symbol()
            && self.source_order() == other.source_order()
            && self.iteration_order() == other.iteration_order()
            && self.fingerprint() == other.fingerprint()
    }

    /// Plans the transition produced by adding `key` in construction order.
    ///
    /// Existing keys keep the same shape and return the current symbol-sorted
    /// slot. New keys produce a child descriptor whose construction order is the
    /// parent shape's construction order followed by `key`. This is a local
    /// descriptor calculation only; it does not cache an edge on the parent and
    /// does not intern the child in a global shape table.
    ///
    /// # Errors
    ///
    /// Returns [`ShapeError`] when `key` is unknown to `symbols`, when the child
    /// shape would exceed the slot-permutation range, or when child construction
    /// storage cannot be reserved.
    pub fn transition_insert_key(
        &self,
        key: Symbol,
        symbols: &SymbolTable,
    ) -> Result<ShapeTransition, ShapeError> {
        symbols
            .resolve(key)
            .ok_or(ShapeError::UnknownSymbol { key })?;
        if let Some(slot) = self.slot(key) {
            return Ok(ShapeTransition::ExistingKey { key, slot });
        }

        let len = self
            .len()
            .checked_add(1)
            .ok_or(ShapeError::TooManyKeys { len: usize::MAX })?;
        let source_slot = u32::try_from(self.len()).map_err(|_| ShapeError::TooManyKeys { len })?;

        let mut keys = Vec::new();
        keys.try_reserve_exact(len)
            .map_err(|_| ShapeError::AllocationFailed { keys: len })?;
        keys.extend(self.iter_source_order());
        keys.push(key);

        let child = AttrShape::from_construction_order(&keys, symbols)?;
        let symbol_slot = child.slot(key).ok_or(ShapeError::UnknownSymbol { key })?;
        Ok(ShapeTransition::AppendKey {
            key,
            source_slot,
            symbol_slot,
            child,
        })
    }

    /// Iterates keys in construction order.
    pub fn iter_source_order(&self) -> ShapeOrderKeys<'_> {
        ShapeOrderKeys {
            keys: &self.keys,
            order: &self.source_order,
            next: 0,
        }
    }

    /// Iterates keys in raw-byte lexicographic order.
    pub fn iter_lexicographic(&self) -> ShapeOrderKeys<'_> {
        ShapeOrderKeys {
            keys: &self.keys,
            order: &self.iteration_order,
            next: 0,
        }
    }
}

/// A local shape-transition result.
#[derive(Clone, Debug)]
pub enum ShapeTransition {
    /// The key already exists, so no child shape is required.
    ExistingKey {
        /// The key that was already present.
        key: Symbol,
        /// The existing symbol-sorted slot for `key`.
        slot: u32,
    },
    /// A new key appends to construction order and produces a child descriptor.
    AppendKey {
        /// The appended key.
        key: Symbol,
        /// The new key's construction-order slot.
        source_slot: u32,
        /// The new key's symbol-sorted slot in `child`.
        symbol_slot: u32,
        /// The locally constructed child descriptor.
        child: AttrShape,
    },
}

/// Iterator over shape keys through a cached slot permutation.
#[derive(Clone, Debug)]
pub struct ShapeOrderKeys<'a> {
    keys: &'a [Symbol],
    order: &'a [u32],
    next: usize,
}

impl Iterator for ShapeOrderKeys<'_> {
    type Item = Symbol;

    fn next(&mut self) -> Option<Self::Item> {
        let slot = *self.order.get(self.next)? as usize;
        self.next += 1;
        self.keys.get(slot).copied()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.order.len().saturating_sub(self.next);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ShapeOrderKeys<'_> {}

/// A failed shape descriptor construction.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ShapeError {
    /// The input contained the same symbol more than once.
    #[error("duplicate shape key {key:?}")]
    DuplicateKey {
        /// The duplicated symbol.
        key: Symbol,
    },
    /// A key did not resolve through the provided symbol table.
    #[error("unknown shape key symbol {key:?}")]
    UnknownSymbol {
        /// The unresolved symbol.
        key: Symbol,
    },
    /// The shape has more keys than the slot permutation can address.
    #[error("too many shape keys: {len}")]
    TooManyKeys {
        /// The rejected key count.
        len: usize,
    },
    /// Scratch storage for shape construction could not be reserved.
    #[error("failed to reserve shape construction storage for {keys} keys")]
    AllocationFailed {
        /// The key count whose construction storage could not be reserved.
        keys: usize,
    },
}

fn fingerprint_keys(keys: &[Symbol]) -> ShapeFingerprint {
    let mut hasher = Xxh3::new();
    b"ratchet-value.attr-shape.v1".hash(&mut hasher);
    keys.len().hash(&mut hasher);
    for key in keys {
        key.as_u32().hash(&mut hasher);
    }
    ShapeFingerprint(hasher.finish())
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

    #[test]
    fn empty_shapes_have_empty_orders_and_a_stable_fingerprint() {
        let shape = AttrShape::empty();
        let other = AttrShape::empty();

        assert!(shape.is_empty());
        assert_eq!(shape.len(), 0);
        assert_eq!(shape.keys_by_symbol(), &[]);
        assert_eq!(shape.source_order(), &[]);
        assert_eq!(shape.iteration_order(), &[]);
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
        let parent =
            AttrShape::from_construction_order(&ids, &symbols).expect("parent shape builds");

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
        let parent =
            AttrShape::from_construction_order(&ids, &symbols).expect("parent shape builds");
        let empty_symbols = SymbolTable::new();

        assert_eq!(
            parent
                .transition_insert_key(ids[0], &empty_symbols)
                .expect_err("mismatched symbol table is rejected"),
            ShapeError::UnknownSymbol { key: ids[0] }
        );
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
}
