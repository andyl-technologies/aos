//! Process-local shape interning and transition cache.

use std::convert::TryFrom;
use std::sync::Arc;

use crate::syntax::{Symbol, SymbolTable};

use super::descriptor::{AttrShape, ShapeError, ShapeTransition};
use super::ids::ShapeId;

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
