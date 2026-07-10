//! Shaped attrset instances and hash-consing support.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use thiserror::Error;
use xxhash_rust::xxh3::Xxh3;

use crate::hashcons::{HashConsError, HashConsTable};
use crate::syntax::Symbol;
use crate::value::Value;

use super::ids::ShapedAttrsFingerprint;
use super::table::ShapeHandle;

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

    pub(super) fn from_symbol_order_boxed(
        shape: ShapeHandle,
        values_by_symbol: Box<[Value]>,
    ) -> Result<Self, ShapedAttrsError> {
        let expected = shape.shape().len();
        if values_by_symbol.len() != expected {
            return Err(ShapedAttrsError::ValueCountMismatch {
                expected,
                actual: values_by_symbol.len(),
            });
        }

        Ok(Self {
            shape,
            values_by_symbol,
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
/// from different [`crate::attrs::shape::ShapeTable`] instances do not collapse incorrectly.
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
        value.relocation_sensitive_identity_bits().hash(&mut hasher);
    }
    ShapedAttrsFingerprint::from_u64(hasher.finish())
}
