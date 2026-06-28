//! Attribute-set shape descriptors for future hidden-class fast paths.
//!
//! A shape captures the key layout shared by attrset instances: the internal
//! symbol-sorted key vector used for binary-search lookup, the construction
//! order permutation, the observable raw-byte lexicographic iteration
//! permutation, the inverse lexicographic rank per symbol slot, and an
//! in-process xxh3 fingerprint of the key vector. The process-local
//! [`ShapeTable`] interns descriptors and caches transition edges for future
//! runtime integration. It does not install a global/shared shape table, inline
//! cache, HAMT representation, or runtime fast path.

use std::convert::TryFrom;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use thiserror::Error;
use xxhash_rust::xxh3::Xxh3;

use crate::hashcons::{HashConsError, HashConsTable};
use crate::syntax::{Symbol, SymbolTable};
use crate::value::Value;

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

/// An in-process fingerprint of a shaped attrset instance.
///
/// This hash is only a bucket key for hash-cons probes. It is not a
/// Nix-observable hash, not durable across evaluator processes, and not
/// sufficient for equality without [`ShapedAttrs::raw_eq`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShapedAttrsFingerprint(u64);

impl ShapedAttrsFingerprint {
    /// Returns the raw xxh3 fingerprint bits.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// A process-local dense record id for an interned shape.
///
/// The id is stable only inside one [`ShapeTable`]. It is not durable, not a
/// serialized cache key, not a pointer, and not meaningful across evaluator
/// processes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShapeId(u32);

impl ShapeId {
    /// Creates a shape-table id from raw bits.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw process-local id.
    pub const fn as_u32(self) -> u32 {
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

        let mut sort_ranks = Vec::new();
        sort_ranks
            .try_reserve_exact(len)
            .map_err(|_| ShapeError::AllocationFailed { keys: len })?;
        for key in &sorted_keys {
            let rank = symbols
                .lexicographic_rank(*key)
                .ok_or(ShapeError::UnknownSymbol { key: *key })?;
            sort_ranks.push(rank);
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
            sort_ranks[left]
                .cmp(&sort_ranks[right])
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

/// A pointer-identity handle to an interned shape.
///
/// Equality by id is valid only for handles produced by the same
/// [`ShapeTable`]. Use [`ShapeHandle::ptr_eq`] when asserting that two handles
/// point at the same interned descriptor.
#[derive(Clone, Debug)]
pub struct ShapeHandle {
    id: ShapeId,
    shape: Arc<AttrShape>,
}

impl ShapeHandle {
    /// Returns the process-local shape id.
    pub const fn id(&self) -> ShapeId {
        self.id
    }

    /// Returns the interned shape descriptor.
    pub fn shape(&self) -> &AttrShape {
        &self.shape
    }

    /// Returns whether two handles point at the same interned descriptor.
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shape, &other.shape)
    }
}

/// A process-local shape interning table with cached transition edges.
///
/// Shape descriptors are interned by fingerprint-filtered raw descriptor
/// equality. Parent transition edges are cached in this table and return the
/// same child handle on repeated insertion of the same key. This table is not
/// global, not lock-free, and not yet connected to runtime attrset allocation.
#[derive(Debug)]
pub struct ShapeTable {
    records: Vec<ShapeRecord>,
}

impl ShapeTable {
    /// Creates a shape table rooted at the empty shape.
    ///
    /// # Errors
    ///
    /// Returns [`ShapeError::TableAllocationFailed`] if the initial table
    /// storage cannot be reserved.
    pub fn new() -> Result<Self, ShapeError> {
        let mut records = Vec::new();
        records
            .try_reserve_exact(1)
            .map_err(|_| ShapeError::TableAllocationFailed { shapes: 1 })?;
        records.push(ShapeRecord {
            shape: Arc::new(AttrShape::empty()),
            key_bytes_by_symbol: Box::new([]),
            transitions: Vec::new(),
        });
        Ok(Self { records })
    }

    /// Returns the interned empty root shape.
    pub fn empty(&self) -> ShapeHandle {
        self.handle_unchecked(ShapeId::new(0))
    }

    /// Interns a shape built from construction-order keys.
    ///
    /// # Errors
    ///
    /// Returns [`ShapeError`] when descriptor construction fails, or when the
    /// table cannot reserve storage for a newly interned shape.
    pub fn intern_construction_order(
        &mut self,
        keys: &[Symbol],
        symbols: &SymbolTable,
    ) -> Result<ShapeHandle, ShapeError> {
        let shape = AttrShape::from_construction_order(keys, symbols)?;
        self.intern_shape(shape, symbols)
    }

    fn intern_shape(
        &mut self,
        shape: AttrShape,
        symbols: &SymbolTable,
    ) -> Result<ShapeHandle, ShapeError> {
        let key_bytes = shape_key_bytes(&shape, symbols)?;
        for (index, record) in self.records.iter().enumerate() {
            if record.shape.fingerprint() == shape.fingerprint()
                && record.shape.raw_eq(&shape)
                && record.key_bytes_by_symbol.as_ref() == key_bytes.as_ref()
            {
                return Ok(self.handle_unchecked(ShapeId::new(index as u32)));
            }
        }

        let len = self.records.len();
        let raw = u32::try_from(len).map_err(|_| ShapeError::TooManyShapes { len })?;
        self.records
            .try_reserve_exact(1)
            .map_err(|_| ShapeError::TableAllocationFailed {
                shapes: len.saturating_add(1),
            })?;
        self.records.push(ShapeRecord {
            shape: Arc::new(shape),
            key_bytes_by_symbol: key_bytes,
            transitions: Vec::new(),
        });
        Ok(self.handle_unchecked(ShapeId::new(raw)))
    }

    /// Resolves an interned shape id to a handle.
    ///
    /// # Errors
    ///
    /// Returns [`ShapeError::UnknownShapeId`] if `id` does not name a shape in
    /// this table.
    pub fn handle(&self, id: ShapeId) -> Result<ShapeHandle, ShapeError> {
        self.record_index(id)?;
        Ok(self.handle_unchecked(id))
    }

    /// Returns the transition produced by adding `key` to `parent`.
    ///
    /// Existing keys return the parent handle and current slot. New keys use
    /// the parent edge cache when present; otherwise the child descriptor is
    /// computed, interned, cached on the parent record, and returned.
    ///
    /// # Errors
    ///
    /// Returns [`ShapeError::UnknownSymbol`] when `key` cannot be resolved
    /// through `symbols`, [`ShapeError::UnknownShapeId`] or
    /// [`ShapeError::ForeignShapeHandle`] when `parent` does not belong to this
    /// table, or other [`ShapeError`] variants when child construction or table
    /// storage fails.
    pub fn transition_insert_key(
        &mut self,
        parent: &ShapeHandle,
        key: Symbol,
        symbols: &SymbolTable,
    ) -> Result<ShapeTableTransition, ShapeError> {
        let key_bytes = symbols
            .resolve(key)
            .ok_or(ShapeError::UnknownSymbol { key })?;
        let parent_index = self.checked_record_index(parent)?;
        self.validate_record_symbols(parent_index, symbols)?;
        let parent_shape = self.records[parent_index].shape.clone();
        if let Some(slot) = parent_shape.slot(key) {
            return Ok(ShapeTableTransition::ExistingKey {
                parent: parent.clone(),
                key,
                slot,
            });
        }

        if let Some((_, edge)) = self.records[parent_index]
            .transitions
            .iter()
            .find(|(cached_key, edge)| *cached_key == key && edge.key_bytes.as_ref() == key_bytes)
        {
            let child = self.handle(edge.child)?;
            return Ok(ShapeTableTransition::AppendKey {
                parent: parent.clone(),
                child,
                key,
                source_slot: edge.source_slot,
                symbol_slot: edge.symbol_slot,
                cached: true,
            });
        }

        let transition = parent_shape.transition_insert_key(key, symbols)?;
        let ShapeTransition::AppendKey {
            source_slot,
            symbol_slot,
            child,
            ..
        } = transition
        else {
            return Ok(ShapeTableTransition::ExistingKey {
                parent: parent.clone(),
                key,
                slot: parent_shape
                    .slot(key)
                    .ok_or(ShapeError::UnknownSymbol { key })?,
            });
        };

        self.records[parent_index]
            .transitions
            .try_reserve_exact(1)
            .map_err(|_| ShapeError::TransitionAllocationFailed {
                edges: self.records[parent_index]
                    .transitions
                    .len()
                    .saturating_add(1),
            })?;
        let edge_key_bytes = key_bytes.to_vec().into_boxed_slice();
        let child = self.intern_shape(child, symbols)?;
        self.records[parent_index].transitions.push((
            key,
            ShapeEdge {
                child: child.id(),
                key_bytes: edge_key_bytes,
                source_slot,
                symbol_slot,
            },
        ));

        Ok(ShapeTableTransition::AppendKey {
            parent: parent.clone(),
            child,
            key,
            source_slot,
            symbol_slot,
            cached: false,
        })
    }

    fn checked_record_index(&self, handle: &ShapeHandle) -> Result<usize, ShapeError> {
        let index = self.record_index(handle.id())?;
        if !Arc::ptr_eq(&self.records[index].shape, &handle.shape) {
            return Err(ShapeError::ForeignShapeHandle { id: handle.id() });
        }
        Ok(index)
    }

    fn record_index(&self, id: ShapeId) -> Result<usize, ShapeError> {
        let index = id.as_u32() as usize;
        if index >= self.records.len() {
            return Err(ShapeError::UnknownShapeId { id });
        }
        Ok(index)
    }

    fn validate_record_symbols(
        &self,
        index: usize,
        symbols: &SymbolTable,
    ) -> Result<(), ShapeError> {
        let record = &self.records[index];
        for (key, expected) in record
            .shape
            .keys_by_symbol()
            .iter()
            .zip(record.key_bytes_by_symbol.iter())
        {
            let Some(actual) = symbols.resolve(*key) else {
                return Err(ShapeError::UnknownSymbol { key: *key });
            };
            if actual != expected.as_ref() {
                return Err(ShapeError::MismatchedSymbolUniverse { key: *key });
            }
        }
        Ok(())
    }

    fn handle_unchecked(&self, id: ShapeId) -> ShapeHandle {
        let index = id.as_u32() as usize;
        ShapeHandle {
            id,
            shape: self.records[index].shape.clone(),
        }
    }
}

/// A shape-table transition result.
#[derive(Clone, Debug)]
pub enum ShapeTableTransition {
    /// The key already exists on the parent shape.
    ExistingKey {
        /// The parent shape.
        parent: ShapeHandle,
        /// The key that already exists.
        key: Symbol,
        /// The existing symbol-sorted slot for `key`.
        slot: u32,
    },
    /// A new key appends to construction order and resolves to a child shape.
    AppendKey {
        /// The parent shape.
        parent: ShapeHandle,
        /// The interned child shape.
        child: ShapeHandle,
        /// The appended key.
        key: Symbol,
        /// The new key's construction-order slot.
        source_slot: u32,
        /// The new key's symbol-sorted slot in `child`.
        symbol_slot: u32,
        /// Whether the child came from an already cached parent edge.
        cached: bool,
    },
}

/// A flat attrset instance paired with an interned shape handle.
///
/// Values are stored in the shape's symbol-sorted slot order. This is the safe
/// layout precursor for the future runtime `{ shape, values }` representation:
/// it does not carry source positions, is not allocated in the evaluator heap,
/// and is not wired into active `FlatAttrs` evaluation.
#[derive(Clone, Debug)]
pub struct ShapedAttrs {
    shape: ShapeHandle,
    values_by_symbol: Box<[Value]>,
}

impl ShapedAttrs {
    /// Creates a shaped attrset from values supplied in construction order.
    ///
    /// Values are copied into the symbol-sorted slot order described by
    /// `shape`. Use [`Self::iter_source_order`] to observe the original
    /// construction order again.
    ///
    /// # Errors
    ///
    /// Returns [`ShapedAttrsError::ValueCountMismatch`] when `values` does not
    /// contain exactly one value per shape key. Returns
    /// [`ShapedAttrsError::ShapeOrderSlotOutOfRange`] if the shape's cached
    /// construction-order permutation refers outside its key vector.
    pub fn from_source_order(
        shape: ShapeHandle,
        values: &[Value],
    ) -> Result<Self, ShapedAttrsError> {
        let expected = shape.shape().len();
        if values.len() != expected {
            return Err(ShapedAttrsError::ValueCountMismatch {
                expected,
                actual: values.len(),
            });
        }

        let mut values_by_symbol = Vec::new();
        values_by_symbol
            .try_reserve_exact(expected)
            .map_err(|_| ShapedAttrsError::AllocationFailed { values: expected })?;
        values_by_symbol.resize(expected, Value::null());
        for (source_slot, symbol_slot) in shape.shape().source_order().iter().copied().enumerate() {
            let Some(target) = values_by_symbol.get_mut(symbol_slot as usize) else {
                return Err(ShapedAttrsError::ShapeOrderSlotOutOfRange {
                    slot: symbol_slot,
                    len: expected,
                });
            };
            *target = values[source_slot];
        }

        Ok(Self {
            shape,
            values_by_symbol: values_by_symbol.into_boxed_slice(),
        })
    }

    /// Creates a shaped attrset from values already in symbol-sorted slot order.
    ///
    /// # Errors
    ///
    /// Returns [`ShapedAttrsError::ValueCountMismatch`] when `values` does not
    /// contain exactly one value per shape key.
    pub fn from_symbol_order(
        shape: ShapeHandle,
        values: &[Value],
    ) -> Result<Self, ShapedAttrsError> {
        let expected = shape.shape().len();
        if values.len() != expected {
            return Err(ShapedAttrsError::ValueCountMismatch {
                expected,
                actual: values.len(),
            });
        }

        let mut values_by_symbol = Vec::new();
        values_by_symbol
            .try_reserve_exact(expected)
            .map_err(|_| ShapedAttrsError::AllocationFailed { values: expected })?;
        values_by_symbol.extend_from_slice(values);

        Ok(Self {
            shape,
            values_by_symbol: values_by_symbol.into_boxed_slice(),
        })
    }

    /// Returns the interned shape handle for this attrset instance.
    pub fn shape(&self) -> &ShapeHandle {
        &self.shape
    }

    /// Returns the number of bindings.
    pub fn len(&self) -> usize {
        self.values_by_symbol.len()
    }

    /// Returns whether this attrset has no bindings.
    pub fn is_empty(&self) -> bool {
        self.values_by_symbol.is_empty()
    }

    /// Returns values in the shape's symbol-sorted slot order.
    pub fn values_by_symbol(&self) -> &[Value] {
        &self.values_by_symbol
    }

    /// Returns a hash-cons bucket fingerprint for this shaped attrset.
    ///
    /// Equal shaped attrsets according to [`Self::raw_eq`] have the same
    /// fingerprint, but callers must still use [`Self::raw_eq`] to confirm a
    /// candidate because this hash can collide and is not a semantic value hash.
    pub fn fingerprint(&self) -> ShapedAttrsFingerprint {
        fingerprint_shaped_attrs(self)
    }

    /// Returns the value for `key` using the shape's symbol-slot lookup.
    ///
    /// `key` must come from the same symbol universe used to construct this
    /// attrset's shape.
    pub fn get(&self, key: Symbol) -> Option<Value> {
        let slot = self.shape.shape().slot(key)? as usize;
        self.values_by_symbol.get(slot).copied()
    }

    /// Returns the value at a symbol-sorted slot.
    pub fn get_slot(&self, slot: u32) -> Option<Value> {
        self.values_by_symbol.get(slot as usize).copied()
    }

    /// Iterates entries in the shape's construction order.
    pub fn iter_source_order(&self) -> ShapedAttrEntries<'_> {
        ShapedAttrEntries {
            attrs: self,
            order: self.shape.shape().source_order(),
            next: 0,
        }
    }

    /// Iterates entries in raw-byte lexicographic order.
    pub fn iter_lexicographic(&self) -> ShapedAttrEntries<'_> {
        ShapedAttrEntries {
            attrs: self,
            order: self.shape.shape().iteration_order(),
            next: 0,
        }
    }

    /// Returns representation-level shaped-attrset equality.
    ///
    /// This requires the same interned shape pointer and raw value equality in
    /// symbol-slot order. It is not Nix semantic equality.
    pub fn raw_eq(&self, other: &Self) -> bool {
        self.shape.ptr_eq(&other.shape)
            && self.values_by_symbol.len() == other.values_by_symbol.len()
            && self
                .values_by_symbol
                .iter()
                .zip(other.values_by_symbol.iter())
                .all(|(left, right)| left.raw_eq(*right))
    }
}

/// Hash-cons table for shaped attrset instances.
///
/// The table stores already-constructed [`ShapedAttrs`] instances behind
/// [`Arc`] handles. It buckets candidates by [`ShapedAttrsFingerprint`] and
/// confirms reuse with [`ShapedAttrs::raw_eq`], so hash collisions or handles
/// from different [`ShapeTable`] instances do not collapse incorrectly.
#[derive(Clone, Debug)]
pub struct ShapedAttrConsTable {
    table: HashConsTable<ShapedAttrsFingerprint, Arc<ShapedAttrs>>,
}

impl ShapedAttrConsTable {
    /// Creates an empty shaped-attrset hash-cons table.
    pub fn new() -> Self {
        Self {
            table: HashConsTable::new(),
        }
    }

    /// Returns whether the table has no hash buckets.
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Returns the number of hash buckets currently stored in the table.
    pub fn bucket_count(&self) -> usize {
        self.table.bucket_count()
    }

    /// Interns `attrs`, reusing an existing raw-equal shaped attrset.
    ///
    /// # Errors
    ///
    /// Returns [`ShapedAttrConsError::HashCons`] if the underlying hash-cons
    /// table cannot reserve space for a new candidate. Returns
    /// [`ShapedAttrConsError::ReservedSlotLost`] if the internal reservation
    /// token no longer names a bucket in this table.
    pub fn intern(&mut self, attrs: ShapedAttrs) -> Result<Arc<ShapedAttrs>, ShapedAttrConsError> {
        let fingerprint = attrs.fingerprint();
        if let Some(existing) = self.table.try_find(&fingerprint, |candidate| {
            Ok::<bool, ShapedAttrConsError>(candidate.raw_eq(&attrs))
        })? {
            return Ok(existing.clone());
        }

        let slot = self.table.reserve_slot(fingerprint)?;
        let interned = Arc::new(attrs);
        if !self.table.push_reserved(slot, interned.clone()) {
            return Err(ShapedAttrConsError::ReservedSlotLost { fingerprint });
        }
        Ok(interned)
    }
}

impl Default for ShapedAttrConsTable {
    fn default() -> Self {
        Self::new()
    }
}

/// A failed shaped attrset hash-cons operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ShapedAttrConsError {
    /// The generic hash-cons table could not reserve candidate storage.
    #[error("shaped attrset hash-cons table error: {0}")]
    HashCons(#[from] HashConsError),
    /// A reserved slot no longer pointed at its bucket when the candidate was pushed.
    #[error("shaped attrset hash-cons reservation disappeared for {fingerprint:?}")]
    ReservedSlotLost {
        /// The bucket fingerprint whose reservation was lost.
        fingerprint: ShapedAttrsFingerprint,
    },
}

/// One shaped attrset binding observed through a cached shape order.
#[derive(Clone, Copy, Debug)]
pub struct ShapedAttrEntry {
    /// The interned attribute name.
    pub key: Symbol,
    /// The value stored for `key`.
    pub value: Value,
}

/// Iterator over shaped attrset entries through a cached shape permutation.
#[derive(Clone, Debug)]
pub struct ShapedAttrEntries<'a> {
    attrs: &'a ShapedAttrs,
    order: &'a [u32],
    next: usize,
}

impl Iterator for ShapedAttrEntries<'_> {
    type Item = ShapedAttrEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let slot = *self.order.get(self.next)? as usize;
        self.next += 1;
        let key = *self.attrs.shape.shape().keys_by_symbol().get(slot)?;
        let value = *self.attrs.values_by_symbol.get(slot)?;
        Some(ShapedAttrEntry { key, value })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.order.len().saturating_sub(self.next);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ShapedAttrEntries<'_> {}

/// A failed shaped attrset instance construction.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ShapedAttrsError {
    /// The value array length did not match the shape key count.
    #[error("shaped attrset expected {expected} values, got {actual}")]
    ValueCountMismatch {
        /// The number of values required by the shape.
        expected: usize,
        /// The number of values supplied by the caller.
        actual: usize,
    },
    /// A cached shape permutation referenced a non-existent symbol slot.
    #[error("shape order slot {slot} is out of range for {len} values")]
    ShapeOrderSlotOutOfRange {
        /// The invalid symbol slot.
        slot: u32,
        /// The number of values in the instance.
        len: usize,
    },
    /// Scratch storage for the shaped value array could not be reserved.
    #[error("failed to reserve shaped attrset storage for {values} values")]
    AllocationFailed {
        /// The value count whose storage could not be reserved.
        values: usize,
    },
}

#[derive(Clone, Debug)]
struct ShapeRecord {
    shape: Arc<AttrShape>,
    key_bytes_by_symbol: Box<[Box<[u8]>]>,
    transitions: Vec<(Symbol, ShapeEdge)>,
}

#[derive(Clone, Debug)]
struct ShapeEdge {
    child: ShapeId,
    key_bytes: Box<[u8]>,
    source_slot: u32,
    symbol_slot: u32,
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
    ShapeFingerprint(hasher.finish())
}

fn fingerprint_shaped_attrs(attrs: &ShapedAttrs) -> ShapedAttrsFingerprint {
    let mut hasher = Xxh3::new();
    b"ratchet-value.shaped-attrs.v1".hash(&mut hasher);
    attrs
        .shape()
        .shape()
        .fingerprint()
        .as_u64()
        .hash(&mut hasher);
    attrs.values_by_symbol().len().hash(&mut hasher);
    for value in attrs.values_by_symbol() {
        value.tag().hash(&mut hasher);
        value.payload_bits().hash(&mut hasher);
    }
    ShapedAttrsFingerprint(hasher.finish())
}

fn shape_key_bytes(
    shape: &AttrShape,
    symbols: &SymbolTable,
) -> Result<Box<[Box<[u8]>]>, ShapeError> {
    let mut names = Vec::new();
    names
        .try_reserve_exact(shape.len())
        .map_err(|_| ShapeError::AllocationFailed { keys: shape.len() })?;
    for key in shape.keys_by_symbol() {
        let bytes = symbols
            .resolve(*key)
            .ok_or(ShapeError::UnknownSymbol { key: *key })?;
        names.push(bytes.to_vec().into_boxed_slice());
    }
    Ok(names.into_boxed_slice())
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

        let unknown = ShapeHandle {
            id: ShapeId::new(99),
            shape: std::sync::Arc::new(AttrShape::empty()),
        };
        assert_eq!(
            table
                .transition_insert_key(&unknown, ids[0], &symbols)
                .expect_err("unknown shape id is rejected"),
            ShapeError::UnknownShapeId {
                id: ShapeId::new(99),
            }
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
    fn shaped_attrs_reorder_source_values_into_symbol_slots() {
        let (symbols, ids) = symbols(&[b"z", b"a", b"m"]);
        let mut table = ShapeTable::new().expect("shape table initializes");
        let shape = table
            .intern_construction_order(&[ids[2], ids[0], ids[1]], &symbols)
            .expect("shape interns");

        let attrs = ShapedAttrs::from_source_order(
            shape,
            &[Value::int(30), Value::int(10), Value::int(20)],
        )
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

        let left =
            ShapedAttrs::from_symbol_order(shape, &[Value::int(1)]).expect("left attrs build");
        let same =
            ShapedAttrs::from_symbol_order(same_shape, &[Value::int(1)]).expect("same attrs build");
        let different_value =
            ShapedAttrs::from_symbol_order(left.shape().clone(), &[Value::int(2)])
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
                ShapedAttrs::from_symbol_order(shape, &[Value::int(2)])
                    .expect("second attrs build"),
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
        let right_attrs =
            ShapedAttrs::from_symbol_order(right_shape, &[]).expect("right attrs build");
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
}
