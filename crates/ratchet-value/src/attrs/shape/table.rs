//! Process-local shape interning and transition cache.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::convert::TryFrom;
use std::sync::Arc;

use crate::syntax::{Symbol, SymbolTable};

use super::descriptor::{AttrShape, ShapeError, ShapeTransition};
use super::ids::{ShapeFingerprint, ShapeId};

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
    /// Maps a shape fingerprint to the ids of every interned record that shares
    /// it, so [`ShapeTable::intern_shape`] can restrict its structural
    /// comparison to fingerprint-matching candidates instead of scanning the
    /// whole record table. Fingerprints collide rarely, so buckets hold one id
    /// in the common case.
    by_fingerprint: HashMap<ShapeFingerprint, Vec<u32>>,
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
        let root = AttrShape::empty();
        let root_fingerprint = root.fingerprint();
        records.push(ShapeRecord {
            shape: Arc::new(root),
            key_bytes_by_symbol: Box::new([]),
            transitions: Vec::new(),
        });
        let mut by_fingerprint = HashMap::new();
        by_fingerprint
            .try_reserve(1)
            .map_err(|_| ShapeError::TableAllocationFailed { shapes: 1 })?;
        by_fingerprint.insert(root_fingerprint, vec![0]);
        Ok(Self {
            records,
            by_fingerprint,
        })
    }

    /// Returns the interned empty root shape.
    pub fn empty(&self) -> ShapeHandle {
        self.handle_unchecked(ShapeId::new(0))
    }

    /// Returns the number of interned shape records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether the table holds only unreachable storage.
    ///
    /// Always `false` for tables built through [`ShapeTable::new`] or
    /// [`ShapeTable::replica`], which contain at least the root shape.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Clones this table into an id-compatible replica.
    ///
    /// The replica shares every interned [`AttrShape`] descriptor `Arc` with
    /// this table, so handles produced by either table pass the other's
    /// pointer-identity checks and dense [`ShapeId`]s mean the same shape in
    /// both. This is the seeding primitive for the parallel evaluator's
    /// prefix-replica shape sharing: one authoritative table is replicated
    /// per worker and extended only through
    /// [`ShapeTable::replicate_suffix_into`].
    ///
    /// # Errors
    ///
    /// Returns [`ShapeError::TableAllocationFailed`] if replica storage cannot
    /// be reserved.
    pub fn replica(&self) -> Result<Self, ShapeError> {
        let mut records = Vec::new();
        records
            .try_reserve_exact(self.records.len())
            .map_err(|_| ShapeError::TableAllocationFailed {
                shapes: self.records.len(),
            })?;
        records.extend(self.records.iter().cloned());
        let mut by_fingerprint = HashMap::new();
        by_fingerprint
            .try_reserve(self.by_fingerprint.len())
            .map_err(|_| ShapeError::TableAllocationFailed {
                shapes: self.records.len(),
            })?;
        for (fingerprint, bucket) in &self.by_fingerprint {
            by_fingerprint.insert(*fingerprint, bucket.clone());
        }
        Ok(Self {
            records,
            by_fingerprint,
        })
    }

    /// Appends this table's unseen record suffix onto a prefix replica.
    ///
    /// `local` must be a prefix replica of this table (seeded through
    /// [`ShapeTable::replica`] and never interned into directly), so every
    /// appended record keeps its dense [`ShapeId`] and shares its descriptor
    /// `Arc`. Cached transition edges on the copied records are preserved;
    /// they reference ids at or below this table's tip, all of which exist in
    /// `local` after the append.
    ///
    /// # Errors
    ///
    /// Returns [`ShapeError::TableAllocationFailed`] if record or index
    /// storage cannot be reserved. A failed reservation leaves `local` a
    /// shorter but still consistent prefix replica.
    pub fn replicate_suffix_into(&self, local: &mut Self) -> Result<(), ShapeError> {
        debug_assert!(
            local.records.len() <= self.records.len(),
            "prefix replica is longer than the authoritative shape table"
        );
        while local.records.len() < self.records.len() {
            let index = local.records.len();
            let record = &self.records[index];
            let raw = u32::try_from(index).map_err(|_| ShapeError::TooManyShapes { len: index })?;
            local
                .records
                .try_reserve(1)
                .map_err(|_| ShapeError::TableAllocationFailed {
                    shapes: index.saturating_add(1),
                })?;
            local.insert_fingerprint_index(record.shape.fingerprint(), raw, index)?;
            local.records.push(record.clone());
        }
        Ok(())
    }

    /// Resolves a transition without interning, using only existing state.
    ///
    /// Returns `Ok(Some(_))` when `key` already exists on `parent` or the
    /// parent record caches an edge for `key`; returns `Ok(None)` when the
    /// transition would have to intern a new child shape (the caller must then
    /// take the mutating [`ShapeTable::transition_insert_key`] path).
    ///
    /// Unlike [`ShapeTable::transition_insert_key`], this fast path performs
    /// no per-record symbol-universe validation and matches cached edges by
    /// `Symbol` identity alone. The caller must therefore drive one table with
    /// one symbol universe: every `Symbol` it passes must come from the same
    /// [`SymbolTable`] lineage (or an id-compatible prefix replica) used for
    /// every other transition on this table. The evaluator guarantees this by
    /// construction; the mutating path keeps the defensive byte-level checks
    /// and remains the arbiter whenever this fast path misses.
    ///
    /// # Errors
    ///
    /// Returns [`ShapeError::UnknownShapeId`] or
    /// [`ShapeError::ForeignShapeHandle`] when `parent` does not belong to
    /// this table.
    pub fn transition_insert_key_cached(
        &self,
        parent: &ShapeHandle,
        key: Symbol,
    ) -> Result<Option<ShapeTableTransition>, ShapeError> {
        let parent_index = self.checked_record_index(parent)?;
        if let Some(slot) = self.records[parent_index].shape.slot(key) {
            return Ok(Some(ShapeTableTransition::ExistingKey {
                parent: parent.clone(),
                key,
                slot,
            }));
        }
        if let Some((_, edge)) = self.records[parent_index]
            .transitions
            .iter()
            .find(|(cached_key, _)| *cached_key == key)
        {
            let child = self.handle(edge.child)?;
            return Ok(Some(ShapeTableTransition::AppendKey {
                parent: parent.clone(),
                child,
                key,
                source_slot: edge.source_slot,
                symbol_slot: edge.symbol_slot,
                cached: true,
            }));
        }
        Ok(None)
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
        let fingerprint = shape.fingerprint();
        if let Some(bucket) = self.by_fingerprint.get(&fingerprint) {
            for &index in bucket {
                let record = &self.records[index as usize];
                if record.shape.raw_eq(&shape)
                    && record.key_bytes_by_symbol.as_ref() == key_bytes.as_ref()
                {
                    return Ok(self.handle_unchecked(ShapeId::new(index)));
                }
            }
        }

        let len = self.records.len();
        let raw = u32::try_from(len).map_err(|_| ShapeError::TooManyShapes { len })?;
        self.records
            .try_reserve_exact(1)
            .map_err(|_| ShapeError::TableAllocationFailed {
                shapes: len.saturating_add(1),
            })?;
        // Record the fingerprint-index slot before mutating `records` so a
        // failed reservation leaves the table's two halves consistent.
        self.insert_fingerprint_index(fingerprint, raw, len)?;
        self.records.push(ShapeRecord {
            shape: Arc::new(shape),
            key_bytes_by_symbol: key_bytes,
            transitions: Vec::new(),
        });
        Ok(self.handle_unchecked(ShapeId::new(raw)))
    }

    /// Records that the shape id `raw` belongs to `fingerprint`'s bucket,
    /// reserving bucket and table capacity fallibly.
    ///
    /// `pending_len` names the record count reported in allocation-failure
    /// errors so they match the error raised for the parallel `records` push.
    ///
    /// # Errors
    ///
    /// Returns [`ShapeError::TableAllocationFailed`] if the index bucket or the
    /// map cannot reserve storage for the new id.
    fn insert_fingerprint_index(
        &mut self,
        fingerprint: ShapeFingerprint,
        raw: u32,
        pending_len: usize,
    ) -> Result<(), ShapeError> {
        let fail = || ShapeError::TableAllocationFailed {
            shapes: pending_len.saturating_add(1),
        };
        // Ensure the map can absorb a potential new bucket without an infallible
        // rehash inside the `Vacant` arm below.
        self.by_fingerprint.try_reserve(1).map_err(|_| fail())?;
        match self.by_fingerprint.entry(fingerprint) {
            Entry::Occupied(mut occupied) => {
                let bucket = occupied.get_mut();
                bucket.try_reserve(1).map_err(|_| fail())?;
                bucket.push(raw);
            }
            Entry::Vacant(vacant) => {
                let mut bucket = Vec::new();
                bucket.try_reserve_exact(1).map_err(|_| fail())?;
                bucket.push(raw);
                vacant.insert(bucket);
            }
        }
        Ok(())
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
