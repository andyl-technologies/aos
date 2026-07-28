//! Shape descriptors and cached key-order permutations.

use std::convert::TryFrom;
use std::hash::{Hash, Hasher};

use thiserror::Error;
use xxhash_rust::xxh3::Xxh3;

use crate::attrs::lexicographic_prefix;
use crate::syntax::{Symbol, SymbolTable};

use super::ids::{ShapeFingerprint, ShapeId};

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
    lexicographic_rank_by_symbol_slot: Box<[u32]>,
    fingerprint: ShapeFingerprint,
}

impl AttrShape {
    /// Creates an empty shape descriptor.
    pub fn empty() -> Self {
        Self {
            keys: Box::new([]),
            source_order: Box::new([]),
            iteration_order: Box::new([]),
            lexicographic_rank_by_symbol_slot: Box::new([]),
            fingerprint: fingerprint_keys(&[]),
        }
    }

    /// Creates a shape from keys in construction order.
    ///
    /// The descriptor stores keys sorted by symbol id for lookup and computes
    /// cached permutations for construction-order and raw-byte lexicographic
    /// iteration plus the inverse rank table over symbol-sorted slots.
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

        // One- and two-key shapes order trivially by comparing resolved key
        // bytes, with no symbol-table rank reads (whose lazy rank view
        // rebuilds in `O(symbols)` after any intern). Small dynamic literals
        // build such shapes once per fresh key on projection-active paths.
        if len <= 2 {
            return Self::from_construction_order_small(keys, symbols);
        }

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

        let mut key_prefixes = Vec::new();
        key_prefixes
            .try_reserve_exact(len)
            .map_err(|_| ShapeError::AllocationFailed { keys: len })?;
        for key in &sorted_keys {
            let bytes = symbols
                .resolve(*key)
                .ok_or(ShapeError::UnknownSymbol { key: *key })?;
            key_prefixes.push(lexicographic_prefix(bytes));
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
            key_prefixes[left]
                .cmp(&key_prefixes[right])
                .then_with(|| {
                    symbols
                        .resolve(sorted_keys[left])
                        .cmp(&symbols.resolve(sorted_keys[right]))
                })
                .then_with(|| sorted_keys[left].cmp(&sorted_keys[right]))
        });

        let mut lexicographic_rank_by_symbol_slot = Vec::new();
        lexicographic_rank_by_symbol_slot
            .try_reserve_exact(len)
            .map_err(|_| ShapeError::AllocationFailed { keys: len })?;
        lexicographic_rank_by_symbol_slot.resize(len, 0);
        for (rank, slot) in iteration_order.iter().copied().enumerate() {
            lexicographic_rank_by_symbol_slot[slot as usize] = rank as u32;
        }

        let fingerprint = fingerprint_keys(&sorted_keys);
        Ok(Self {
            keys: sorted_keys.into_boxed_slice(),
            source_order: source_order.into_boxed_slice(),
            iteration_order: iteration_order.into_boxed_slice(),
            lexicographic_rank_by_symbol_slot: lexicographic_rank_by_symbol_slot.into_boxed_slice(),
            fingerprint,
        })
    }

    /// Builds a one- or two-key shape without symbol-table rank reads.
    ///
    /// Preserves [`AttrShape::from_construction_order`]'s error semantics:
    /// duplicate keys are rejected before unresolved symbols, and every key
    /// must resolve through `symbols`. Ordering by resolved raw key bytes is
    /// definitionally identical to ordering by cached lexicographic ranks.
    fn from_construction_order_small(
        keys: &[Symbol],
        symbols: &SymbolTable,
    ) -> Result<Self, ShapeError> {
        debug_assert!(keys.len() <= 2);
        if keys.len() == 2 && keys[0] == keys[1] {
            return Err(ShapeError::DuplicateKey { key: keys[0] });
        }
        let resolve = |key: Symbol| {
            symbols
                .resolve(key)
                .ok_or(ShapeError::UnknownSymbol { key })
        };
        let (sorted_keys, source_order, iteration_order): (Vec<Symbol>, Vec<u32>, Vec<u32>) =
            match keys {
                [] => (Vec::new(), Vec::new(), Vec::new()),
                &[key] => {
                    resolve(key)?;
                    (vec![key], vec![0], vec![0])
                }
                &[first_key, second_key, ..] => {
                    let first = resolve(first_key)?;
                    let second = resolve(second_key)?;
                    // Storage stays sorted by symbol id; the permutations are
                    // derived from which input key sorts first on each axis.
                    let symbol_swap = first_key > second_key;
                    let sorted = if symbol_swap {
                        vec![second_key, first_key]
                    } else {
                        vec![first_key, second_key]
                    };
                    let source = if symbol_swap { vec![1, 0] } else { vec![0, 1] };
                    let byte_swap = (first > second) != symbol_swap;
                    let iteration = if byte_swap { vec![1, 0] } else { vec![0, 1] };
                    (sorted, source, iteration)
                }
            };
        // For two slots the lexicographic permutation is its own inverse.
        let lexicographic_rank_by_symbol_slot = iteration_order.clone();
        let fingerprint = fingerprint_keys(&sorted_keys);
        Ok(Self {
            keys: sorted_keys.into_boxed_slice(),
            source_order: source_order.into_boxed_slice(),
            iteration_order: iteration_order.into_boxed_slice(),
            lexicographic_rank_by_symbol_slot: lexicographic_rank_by_symbol_slot.into_boxed_slice(),
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

    /// Returns each symbol-sorted slot's rank in raw-byte lexicographic order.
    ///
    /// `lexicographic_rank_by_symbol_slot()[slot]` returns the position that
    /// `slot` occupies in [`Self::iteration_order`]. This table is shape-local:
    /// it is not a process-global symbol rank and is not durable across
    /// evaluator processes.
    pub fn lexicographic_rank_by_symbol_slot(&self) -> &[u32] {
        &self.lexicographic_rank_by_symbol_slot
    }

    /// Returns a symbol-sorted slot's shape-local lexicographic rank.
    pub fn lexicographic_rank_for_symbol_slot(&self, slot: u32) -> Option<u32> {
        self.lexicographic_rank_by_symbol_slot
            .get(slot as usize)
            .copied()
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
            && self.lexicographic_rank_by_symbol_slot() == other.lexicographic_rank_by_symbol_slot()
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
    /// A key resolved to different bytes than the shape table recorded.
    #[error("shape key {key:?} resolved through a different symbol universe")]
    MismatchedSymbolUniverse {
        /// The symbol whose bytes differed from the interned shape record.
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
    /// A shape table id did not resolve in the active table.
    #[error("unknown shape table id {id:?}")]
    UnknownShapeId {
        /// The unresolved process-local shape id.
        id: ShapeId,
    },
    /// A shape handle was produced by a different shape table.
    #[error("shape handle {id:?} belongs to a different shape table")]
    ForeignShapeHandle {
        /// The process-local id carried by the foreign handle.
        id: ShapeId,
    },
    /// The shape table cannot allocate another process-local id.
    #[error("too many interned shapes: {len}")]
    TooManyShapes {
        /// The rejected shape count.
        len: usize,
    },
    /// Scratch storage for shape-table records could not be reserved.
    #[error("failed to reserve shape table storage for {shapes} shapes")]
    TableAllocationFailed {
        /// The shape count whose table storage could not be reserved.
        shapes: usize,
    },
    /// Scratch storage for a parent transition cache could not be reserved.
    #[error("failed to reserve shape transition storage for {edges} edges")]
    TransitionAllocationFailed {
        /// The edge count whose transition storage could not be reserved.
        edges: usize,
    },
}

fn fingerprint_keys(keys: &[Symbol]) -> ShapeFingerprint {
    let mut hasher = Xxh3::new();
    b"ratchet-value.attr-shape.v1".hash(&mut hasher);
    keys.len().hash(&mut hasher);
    for key in keys {
        key.as_u32().hash(&mut hasher);
    }
    ShapeFingerprint::from_u64(hasher.finish())
}
