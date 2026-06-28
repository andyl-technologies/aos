//! Polymorphic inline-cache state for future attr selection fast paths.
//!
//! This module captures the safe state-machine contract from RFC-0007 §09:
//! select sites start uninitialized, specialize to one shape, widen to a small
//! polymorphic set, then fall back to megamorphic dispatch after the configured
//! cap. The generic [`InlineCache`] remains a state machine over opaque shape
//! ids; [`ShapedSelectCache`] is a safe shaped-attrset precursor that proves the
//! shape-guard + constant-offset load contract without updating tree-walk
//! behavior, calling the final runtime `select_slow`, or installing
//! deoptimization edges.
//!
//! Cached shape ids are opaque handles supplied by a future shape table. They
//! are not fingerprints, not symbol ids, and not pointer provenance.

use thiserror::Error;

use super::shape::{ShapeHandle, ShapedAttrs};
use crate::syntax::Symbol;
use crate::value::Value;

/// Default maximum number of shape entries kept before going megamorphic.
pub const DEFAULT_POLYMORPHIC_CAP: usize = 4;

/// An opaque shape identity for one inline-cache entry.
///
/// The future shape table owns minting this id. This precursor treats it only as
/// an equality token for one evaluator process; it is not durable and is not a
/// substitute for comparing shape descriptors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InlineCacheShapeId(u32);

impl InlineCacheShapeId {
    /// Creates an opaque inline-cache shape id from raw bits.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw process-local shape id.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// One shape-guarded cached slot load.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InlineCacheEntry {
    /// The opaque shape id guarded by this entry.
    pub shape: InlineCacheShapeId,
    /// The constant slot offset to load after the shape guard succeeds.
    pub slot: u32,
}

impl InlineCacheEntry {
    /// Creates one shape-to-slot cache entry.
    pub const fn new(shape: InlineCacheShapeId, slot: u32) -> Self {
        Self { shape, slot }
    }
}

/// The current state of one select-site inline cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InlineCacheState {
    /// The site has not observed a shape yet.
    Uninitialized,
    /// The site has observed exactly one shape.
    Monomorphic {
        /// The cached shape-to-slot entry.
        entry: InlineCacheEntry,
    },
    /// The site has observed a small bounded set of shapes.
    Polymorphic {
        /// Cached entries in first-observed order.
        entries: Box<[InlineCacheEntry]>,
    },
    /// The site exceeded the polymorphic cap and uses the generic slow path.
    Megamorphic,
}

impl InlineCacheState {
    /// Returns the number of cached shape entries in this state.
    pub fn entry_count(&self) -> usize {
        match self {
            Self::Uninitialized | Self::Megamorphic => 0,
            Self::Monomorphic { .. } => 1,
            Self::Polymorphic { entries } => entries.len(),
        }
    }

    /// Returns whether this state has abandoned specialization.
    pub const fn is_megamorphic(&self) -> bool {
        matches!(self, Self::Megamorphic)
    }
}

/// One mutable inline-cache cell for a select site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InlineCache {
    cap: usize,
    state: InlineCacheState,
}

impl InlineCache {
    /// Creates an uninitialized cache with [`DEFAULT_POLYMORPHIC_CAP`].
    pub const fn new() -> Self {
        Self {
            cap: DEFAULT_POLYMORPHIC_CAP,
            state: InlineCacheState::Uninitialized,
        }
    }

    /// Creates an uninitialized cache with a custom polymorphic cap.
    ///
    /// # Errors
    ///
    /// Returns [`InlineCacheError::ZeroPolymorphicCap`] when `cap` is zero.
    pub const fn with_cap(cap: usize) -> Result<Self, InlineCacheError> {
        if cap == 0 {
            Err(InlineCacheError::ZeroPolymorphicCap)
        } else {
            Ok(Self {
                cap,
                state: InlineCacheState::Uninitialized,
            })
        }
    }

    /// Returns the configured polymorphic entry cap.
    pub const fn cap(&self) -> usize {
        self.cap
    }

    /// Returns the current state.
    pub const fn state(&self) -> &InlineCacheState {
        &self.state
    }

    /// Returns a cached slot for `shape`, if this site has a matching entry.
    pub fn lookup(&self, shape: InlineCacheShapeId) -> Option<u32> {
        match &self.state {
            InlineCacheState::Uninitialized | InlineCacheState::Megamorphic => None,
            InlineCacheState::Monomorphic { entry } => (entry.shape == shape).then_some(entry.slot),
            InlineCacheState::Polymorphic { entries } => entries
                .iter()
                .find(|entry| entry.shape == shape)
                .map(|entry| entry.slot),
        }
    }

    /// Records a slow-path resolution and updates the cache state.
    ///
    /// The slow resolver supplies the authoritative shape-to-slot entry. This
    /// method only maintains the PIC state machine and guards against a shape id
    /// resolving to two different slots at the same select site.
    ///
    /// # Errors
    ///
    /// Returns [`InlineCacheError::ShapeSlotChanged`] if an existing shape entry
    /// is observed with a different slot. Returns
    /// [`InlineCacheError::EntryAllocationFailed`] if widening the polymorphic
    /// entry list cannot reserve storage.
    pub fn record_resolution(
        &mut self,
        entry: InlineCacheEntry,
    ) -> Result<InlineCacheUpdate, InlineCacheError> {
        match &mut self.state {
            InlineCacheState::Uninitialized => {
                self.state = InlineCacheState::Monomorphic { entry };
                Ok(InlineCacheUpdate::InstalledMonomorphic)
            }
            InlineCacheState::Monomorphic { entry: cached } => {
                if cached.shape == entry.shape {
                    validate_same_slot(*cached, entry)?;
                    return Ok(InlineCacheUpdate::ReusedExisting);
                }
                if self.cap == 1 {
                    self.state = InlineCacheState::Megamorphic;
                    return Ok(InlineCacheUpdate::BecameMegamorphic);
                }

                let mut entries = Vec::new();
                entries
                    .try_reserve_exact(2)
                    .map_err(|_| InlineCacheError::EntryAllocationFailed { entries: 2 })?;
                entries.push(*cached);
                entries.push(entry);
                self.state = InlineCacheState::Polymorphic {
                    entries: entries.into_boxed_slice(),
                };
                Ok(InlineCacheUpdate::WidenedToPolymorphic { len: 2 })
            }
            InlineCacheState::Polymorphic { entries } => {
                if let Some(cached) = entries.iter().find(|cached| cached.shape == entry.shape) {
                    validate_same_slot(*cached, entry)?;
                    return Ok(InlineCacheUpdate::ReusedExisting);
                }
                if entries.len() >= self.cap {
                    self.state = InlineCacheState::Megamorphic;
                    return Ok(InlineCacheUpdate::BecameMegamorphic);
                }

                let mut next = Vec::new();
                let len = entries.len().checked_add(1).ok_or(
                    InlineCacheError::EntryAllocationFailed {
                        entries: usize::MAX,
                    },
                )?;
                next.try_reserve_exact(len)
                    .map_err(|_| InlineCacheError::EntryAllocationFailed { entries: len })?;
                next.extend_from_slice(entries);
                next.push(entry);
                self.state = InlineCacheState::Polymorphic {
                    entries: next.into_boxed_slice(),
                };
                Ok(InlineCacheUpdate::AddedPolymorphic { len })
            }
            InlineCacheState::Megamorphic => Ok(InlineCacheUpdate::AlreadyMegamorphic),
        }
    }
}

impl Default for InlineCache {
    fn default() -> Self {
        Self::new()
    }
}

/// The state-machine update produced by [`InlineCache::record_resolution`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InlineCacheUpdate {
    /// The first observed shape installed a monomorphic entry.
    InstalledMonomorphic,
    /// The observed shape was already cached with the same slot.
    ReusedExisting,
    /// A second shape widened the cache to polymorphic.
    WidenedToPolymorphic {
        /// The number of cached entries after widening.
        len: usize,
    },
    /// A new shape was appended to an existing polymorphic cache.
    AddedPolymorphic {
        /// The number of cached entries after appending.
        len: usize,
    },
    /// The site exceeded the configured cap and became megamorphic.
    BecameMegamorphic,
    /// The site was already megamorphic; no cache entry was added.
    AlreadyMegamorphic,
}

/// A failed inline-cache state-machine operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum InlineCacheError {
    /// A custom cache cap was zero.
    #[error("inline-cache polymorphic cap must be greater than zero")]
    ZeroPolymorphicCap,
    /// A shape id resolved to a different slot at the same select site.
    #[error("inline-cache shape {shape:?} changed slot from {previous_slot} to {attempted_slot}")]
    ShapeSlotChanged {
        /// The shape id whose cached slot changed.
        shape: InlineCacheShapeId,
        /// The previously cached slot.
        previous_slot: u32,
        /// The newly attempted slot.
        attempted_slot: u32,
    },
    /// A polymorphic entry list could not reserve storage.
    #[error("failed to reserve {entries} inline-cache entries")]
    EntryAllocationFailed {
        /// The requested entry count.
        entries: usize,
    },
}

fn validate_same_slot(
    cached: InlineCacheEntry,
    attempted: InlineCacheEntry,
) -> Result<(), InlineCacheError> {
    if cached.slot == attempted.slot {
        Ok(())
    } else {
        Err(InlineCacheError::ShapeSlotChanged {
            shape: cached.shape,
            previous_slot: cached.slot,
            attempted_slot: attempted.slot,
        })
    }
}

/// One pointer-guarded shaped attrset slot load.
#[derive(Clone, Debug)]
pub struct ShapedSelectCacheEntry {
    shape: ShapeHandle,
    slot: u32,
}

impl ShapedSelectCacheEntry {
    /// Creates a shaped select-cache entry.
    pub fn new(shape: ShapeHandle, slot: u32) -> Self {
        Self { shape, slot }
    }

    /// Returns the guarded shape handle.
    pub fn shape(&self) -> &ShapeHandle {
        &self.shape
    }

    /// Returns the constant slot offset loaded after the shape guard succeeds.
    pub const fn slot(&self) -> u32 {
        self.slot
    }
}

/// The current state of one shaped select-site cache.
#[derive(Clone, Debug)]
pub enum ShapedSelectCacheState {
    /// The site has not observed a shaped attrset yet.
    Uninitialized,
    /// The site has observed exactly one shape.
    Monomorphic {
        /// The cached pointer-guarded slot load.
        entry: ShapedSelectCacheEntry,
    },
    /// The site has observed a small bounded set of shapes.
    Polymorphic {
        /// Cached entries in first-observed order.
        entries: Box<[ShapedSelectCacheEntry]>,
    },
    /// The site exceeded the polymorphic cap and uses the generic slow path.
    Megamorphic,
}

impl ShapedSelectCacheState {
    /// Returns the number of cached shape entries in this state.
    pub fn entry_count(&self) -> usize {
        match self {
            Self::Uninitialized | Self::Megamorphic => 0,
            Self::Monomorphic { .. } => 1,
            Self::Polymorphic { entries } => entries.len(),
        }
    }

    /// Returns whether this state has abandoned specialization.
    pub const fn is_megamorphic(&self) -> bool {
        matches!(self, Self::Megamorphic)
    }
}

/// A safe shaped-attrset select-site cache.
///
/// This cache guards entries with [`ShapeHandle::ptr_eq`] rather than only the
/// process-local numeric shape id. That keeps the precursor safe even when tests
/// construct shaped attrsets from separate [`super::shape::ShapeTable`]
/// instances that reuse the same local id.
#[derive(Clone, Debug)]
pub struct ShapedSelectCache {
    cap: usize,
    key: Option<Symbol>,
    state: ShapedSelectCacheState,
}

impl ShapedSelectCache {
    /// Creates an uninitialized shaped select cache with [`DEFAULT_POLYMORPHIC_CAP`].
    pub const fn new() -> Self {
        Self {
            cap: DEFAULT_POLYMORPHIC_CAP,
            key: None,
            state: ShapedSelectCacheState::Uninitialized,
        }
    }

    /// Creates an uninitialized shaped select cache with a custom polymorphic cap.
    ///
    /// # Errors
    ///
    /// Returns [`ShapedSelectError::ZeroPolymorphicCap`] when `cap` is zero.
    pub const fn with_cap(cap: usize) -> Result<Self, ShapedSelectError> {
        if cap == 0 {
            Err(ShapedSelectError::ZeroPolymorphicCap)
        } else {
            Ok(Self {
                cap,
                key: None,
                state: ShapedSelectCacheState::Uninitialized,
            })
        }
    }

    /// Returns the configured polymorphic entry cap.
    pub const fn cap(&self) -> usize {
        self.cap
    }

    /// Returns the current shaped select-cache state.
    pub const fn state(&self) -> &ShapedSelectCacheState {
        &self.state
    }

    /// Returns the static key bound to this select-site cache, if observed.
    pub const fn key(&self) -> Option<Symbol> {
        self.key
    }

    /// Selects `key` from `attrs`, using a cached shape guard when available.
    ///
    /// A cached hit compares the runtime attrset's interned shape pointer to the
    /// cached shape pointer, then loads the cached symbol-sorted slot. A miss
    /// resolves the slot through the shape descriptor, loads the value, and
    /// records the resolution in the cache unless the key is absent.
    ///
    /// # Errors
    ///
    /// Returns [`ShapedSelectError::KeyChanged`] if the cache is reused for a
    /// different select key, [`ShapedSelectError::CachedSlotOutOfRange`] when a
    /// cached entry references a slot outside the value array,
    /// [`ShapedSelectError::ResolvedSlotOutOfRange`] when the shape resolves a
    /// slot outside the value array,
    /// [`ShapedSelectError::ShapeSlotChanged`] if a cached shape pointer
    /// resolves to a different slot, or
    /// [`ShapedSelectError::EntryAllocationFailed`] if widening the polymorphic
    /// entry list cannot reserve storage.
    pub fn select(
        &mut self,
        attrs: &ShapedAttrs,
        key: Symbol,
    ) -> Result<ShapedSelectOutcome, ShapedSelectError> {
        self.bind_key(key)?;
        if let Some(entry) = self.lookup_entry(attrs.shape()) {
            let value =
                attrs
                    .get_slot(entry.slot())
                    .ok_or(ShapedSelectError::CachedSlotOutOfRange {
                        slot: entry.slot(),
                        len: attrs.len(),
                    })?;
            return Ok(ShapedSelectOutcome::Hit {
                value,
                slot: entry.slot(),
                source: ShapedSelectSource::Cached,
            });
        }

        let Some(slot) = attrs.shape().shape().slot(key) else {
            return Ok(ShapedSelectOutcome::Missing);
        };
        let value = attrs
            .get_slot(slot)
            .ok_or(ShapedSelectError::ResolvedSlotOutOfRange {
                slot,
                len: attrs.len(),
            })?;
        let update =
            self.record_resolution(ShapedSelectCacheEntry::new(attrs.shape().clone(), slot))?;
        Ok(ShapedSelectOutcome::Hit {
            value,
            slot,
            source: ShapedSelectSource::Resolved { update },
        })
    }

    fn lookup_entry(&self, shape: &ShapeHandle) -> Option<&ShapedSelectCacheEntry> {
        match &self.state {
            ShapedSelectCacheState::Uninitialized | ShapedSelectCacheState::Megamorphic => None,
            ShapedSelectCacheState::Monomorphic { entry } => {
                entry.shape().ptr_eq(shape).then_some(entry)
            }
            ShapedSelectCacheState::Polymorphic { entries } => {
                entries.iter().find(|entry| entry.shape().ptr_eq(shape))
            }
        }
    }

    fn record_resolution(
        &mut self,
        entry: ShapedSelectCacheEntry,
    ) -> Result<InlineCacheUpdate, ShapedSelectError> {
        match &mut self.state {
            ShapedSelectCacheState::Uninitialized => {
                self.state = ShapedSelectCacheState::Monomorphic { entry };
                Ok(InlineCacheUpdate::InstalledMonomorphic)
            }
            ShapedSelectCacheState::Monomorphic { entry: cached } => {
                if cached.shape().ptr_eq(entry.shape()) {
                    validate_same_shaped_slot(cached.slot(), entry.slot())?;
                    return Ok(InlineCacheUpdate::ReusedExisting);
                }
                if self.cap == 1 {
                    self.state = ShapedSelectCacheState::Megamorphic;
                    return Ok(InlineCacheUpdate::BecameMegamorphic);
                }

                let mut entries = Vec::new();
                entries
                    .try_reserve_exact(2)
                    .map_err(|_| ShapedSelectError::EntryAllocationFailed { entries: 2 })?;
                entries.push(cached.clone());
                entries.push(entry);
                self.state = ShapedSelectCacheState::Polymorphic {
                    entries: entries.into_boxed_slice(),
                };
                Ok(InlineCacheUpdate::WidenedToPolymorphic { len: 2 })
            }
            ShapedSelectCacheState::Polymorphic { entries } => {
                if let Some(cached) = entries
                    .iter()
                    .find(|cached| cached.shape().ptr_eq(entry.shape()))
                {
                    validate_same_shaped_slot(cached.slot(), entry.slot())?;
                    return Ok(InlineCacheUpdate::ReusedExisting);
                }
                if entries.len() >= self.cap {
                    self.state = ShapedSelectCacheState::Megamorphic;
                    return Ok(InlineCacheUpdate::BecameMegamorphic);
                }

                let mut next = Vec::new();
                let len = entries.len().checked_add(1).ok_or(
                    ShapedSelectError::EntryAllocationFailed {
                        entries: usize::MAX,
                    },
                )?;
                next.try_reserve_exact(len)
                    .map_err(|_| ShapedSelectError::EntryAllocationFailed { entries: len })?;
                next.extend_from_slice(entries);
                next.push(entry);
                self.state = ShapedSelectCacheState::Polymorphic {
                    entries: next.into_boxed_slice(),
                };
                Ok(InlineCacheUpdate::AddedPolymorphic { len })
            }
            ShapedSelectCacheState::Megamorphic => Ok(InlineCacheUpdate::AlreadyMegamorphic),
        }
    }

    fn bind_key(&mut self, key: Symbol) -> Result<(), ShapedSelectError> {
        match self.key {
            Some(previous) if previous != key => Err(ShapedSelectError::KeyChanged {
                previous,
                attempted: key,
            }),
            Some(_) => Ok(()),
            None => {
                self.key = Some(key);
                Ok(())
            }
        }
    }
}

impl Default for ShapedSelectCache {
    fn default() -> Self {
        Self::new()
    }
}

/// A shaped select-cache lookup result.
#[derive(Clone, Copy, Debug)]
pub enum ShapedSelectOutcome {
    /// The key was present.
    Hit {
        /// The selected value.
        value: Value,
        /// The symbol-sorted slot that was loaded.
        slot: u32,
        /// Whether the value came from the cached fast path or slow resolution.
        source: ShapedSelectSource,
    },
    /// The key is absent from the shaped attrset.
    Missing,
}

/// The path used to produce a shaped select hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapedSelectSource {
    /// The shape guard matched and the cached slot was loaded.
    Cached,
    /// The slot was resolved through the shape descriptor and the cache was updated.
    Resolved {
        /// The state-machine update produced by the slow resolution.
        update: InlineCacheUpdate,
    },
}

/// A failed shaped select-cache operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ShapedSelectError {
    /// A custom cache cap was zero.
    #[error("shaped select-cache polymorphic cap must be greater than zero")]
    ZeroPolymorphicCap,
    /// A select-site cache was reused for a different static key.
    #[error("shaped select-cache key changed from {previous:?} to {attempted:?}")]
    KeyChanged {
        /// The key already bound to the cache.
        previous: Symbol,
        /// The attempted replacement key.
        attempted: Symbol,
    },
    /// A cached slot did not exist in the shaped attrset's value array.
    #[error("shaped select-cache slot {slot} is out of range for {len} cached values")]
    CachedSlotOutOfRange {
        /// The cached slot.
        slot: u32,
        /// The shaped attrset value count.
        len: usize,
    },
    /// A resolved shape slot did not exist in the shaped attrset's value array.
    #[error("shaped select resolved slot {slot} is out of range for {len} values")]
    ResolvedSlotOutOfRange {
        /// The resolved slot.
        slot: u32,
        /// The shaped attrset value count.
        len: usize,
    },
    /// A shape pointer resolved to a different slot at the same select site.
    #[error("shaped select-cache shape changed slot from {previous_slot} to {attempted_slot}")]
    ShapeSlotChanged {
        /// The previously cached slot.
        previous_slot: u32,
        /// The newly attempted slot.
        attempted_slot: u32,
    },
    /// A polymorphic entry list could not reserve storage.
    #[error("failed to reserve {entries} shaped select-cache entries")]
    EntryAllocationFailed {
        /// The requested entry count.
        entries: usize,
    },
}

fn validate_same_shaped_slot(cached: u32, attempted: u32) -> Result<(), ShapedSelectError> {
    if cached == attempted {
        Ok(())
    } else {
        Err(ShapedSelectError::ShapeSlotChanged {
            previous_slot: cached,
            attempted_slot: attempted,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::shape::{ShapeTable, ShapedAttrs};
    use super::*;
    use crate::syntax::SymbolTable;
    use crate::value::Value;

    fn entry(shape: u32, slot: u32) -> InlineCacheEntry {
        InlineCacheEntry::new(InlineCacheShapeId::new(shape), slot)
    }

    fn symbols(names: &[&[u8]]) -> (SymbolTable, Vec<crate::syntax::Symbol>) {
        let mut table = SymbolTable::new();
        let mut ids = Vec::new();
        for name in names {
            ids.push(table.intern(name).expect("symbol interns"));
        }
        (table, ids)
    }

    fn shaped_attrs(
        shape_table: &mut ShapeTable,
        symbols: &SymbolTable,
        keys: &[crate::syntax::Symbol],
        values: &[Value],
    ) -> ShapedAttrs {
        let shape = shape_table
            .intern_construction_order(keys, symbols)
            .expect("shape interns");
        ShapedAttrs::from_source_order(shape, values).expect("shaped attrs build")
    }

    fn expect_hit_int(
        outcome: ShapedSelectOutcome,
        expected_value: i64,
        expected_slot: u32,
    ) -> ShapedSelectSource {
        let ShapedSelectOutcome::Hit {
            value,
            slot,
            source,
        } = outcome
        else {
            panic!("expected shaped select hit");
        };
        assert_eq!(value.as_int().expect("int value"), expected_value);
        assert_eq!(slot, expected_slot);
        source
    }

    #[test]
    fn shaped_select_cache_installs_then_uses_cached_slot() {
        let (symbols, ids) = symbols(&[b"a", b"b"]);
        let mut shape_table = ShapeTable::new().expect("shape table initializes");
        let attrs = shaped_attrs(
            &mut shape_table,
            &symbols,
            &[ids[1], ids[0]],
            &[Value::int(20), Value::int(10)],
        );
        let mut cache = ShapedSelectCache::new();

        assert_eq!(
            expect_hit_int(
                cache
                    .select(&attrs, ids[0])
                    .expect("select resolves through slow path"),
                10,
                0,
            ),
            ShapedSelectSource::Resolved {
                update: InlineCacheUpdate::InstalledMonomorphic,
            }
        );
        assert_eq!(cache.state().entry_count(), 1);

        assert_eq!(
            expect_hit_int(
                cache
                    .select(&attrs, ids[0])
                    .expect("select uses cached slot"),
                10,
                0,
            ),
            ShapedSelectSource::Cached
        );
    }

    #[test]
    fn shaped_select_cache_widens_then_goes_megamorphic() {
        let (symbols, ids) = symbols(&[b"a", b"b", b"c"]);
        let mut shape_table = ShapeTable::new().expect("shape table initializes");
        let first = shaped_attrs(&mut shape_table, &symbols, &[ids[0]], &[Value::int(1)]);
        let second = shaped_attrs(
            &mut shape_table,
            &symbols,
            &[ids[1], ids[0]],
            &[Value::int(20), Value::int(2)],
        );
        let third = shaped_attrs(
            &mut shape_table,
            &symbols,
            &[ids[2], ids[0]],
            &[Value::int(30), Value::int(3)],
        );
        let mut cache = ShapedSelectCache::with_cap(2).expect("nonzero cap");

        assert_eq!(
            expect_hit_int(cache.select(&first, ids[0]).expect("first select"), 1, 0),
            ShapedSelectSource::Resolved {
                update: InlineCacheUpdate::InstalledMonomorphic,
            }
        );
        assert_eq!(
            expect_hit_int(cache.select(&second, ids[0]).expect("second select"), 2, 0),
            ShapedSelectSource::Resolved {
                update: InlineCacheUpdate::WidenedToPolymorphic { len: 2 },
            }
        );
        assert_eq!(cache.state().entry_count(), 2);
        assert_eq!(
            expect_hit_int(cache.select(&third, ids[0]).expect("third select"), 3, 0),
            ShapedSelectSource::Resolved {
                update: InlineCacheUpdate::BecameMegamorphic,
            }
        );
        assert!(cache.state().is_megamorphic());
        assert_eq!(
            expect_hit_int(cache.select(&first, ids[0]).expect("mega select"), 1, 0),
            ShapedSelectSource::Resolved {
                update: InlineCacheUpdate::AlreadyMegamorphic,
            }
        );
    }

    #[test]
    fn shaped_select_cache_missing_key_does_not_update_cache() {
        let (symbols, ids) = symbols(&[b"a", b"missing"]);
        let mut shape_table = ShapeTable::new().expect("shape table initializes");
        let attrs = shaped_attrs(&mut shape_table, &symbols, &[ids[0]], &[Value::int(1)]);
        let mut cache = ShapedSelectCache::new();

        assert!(matches!(
            cache
                .select(&attrs, ids[1])
                .expect("missing key is not an error"),
            ShapedSelectOutcome::Missing
        ));
        assert_eq!(cache.state().entry_count(), 0);
    }

    #[test]
    fn shaped_select_cache_rejects_same_shape_with_different_slot() {
        let (symbols, ids) = symbols(&[b"a", b"b"]);
        let mut shape_table = ShapeTable::new().expect("shape table initializes");
        let attrs = shaped_attrs(
            &mut shape_table,
            &symbols,
            &[ids[0], ids[1]],
            &[Value::int(1), Value::int(2)],
        );
        let mut cache = ShapedSelectCache::new();

        assert_eq!(
            expect_hit_int(cache.select(&attrs, ids[0]).expect("first select"), 1, 0),
            ShapedSelectSource::Resolved {
                update: InlineCacheUpdate::InstalledMonomorphic,
            }
        );
        assert_eq!(
            cache
                .select(&attrs, ids[1])
                .expect_err("same select site cannot change slots for one shape"),
            ShapedSelectError::KeyChanged {
                previous: ids[0],
                attempted: ids[1],
            }
        );
    }

    #[test]
    fn shaped_select_cache_does_not_cross_hit_foreign_same_id_shapes() {
        let (symbols, ids) = symbols(&[b"a"]);
        let mut left_table = ShapeTable::new().expect("left shape table initializes");
        let mut right_table = ShapeTable::new().expect("right shape table initializes");
        let left = shaped_attrs(&mut left_table, &symbols, &[ids[0]], &[Value::int(1)]);
        let right = shaped_attrs(&mut right_table, &symbols, &[ids[0]], &[Value::int(2)]);
        assert_eq!(left.shape().id(), right.shape().id());
        assert!(!left.shape().ptr_eq(right.shape()));
        let mut cache = ShapedSelectCache::new();

        assert_eq!(
            expect_hit_int(cache.select(&left, ids[0]).expect("left select"), 1, 0),
            ShapedSelectSource::Resolved {
                update: InlineCacheUpdate::InstalledMonomorphic,
            }
        );
        assert_eq!(
            expect_hit_int(cache.select(&right, ids[0]).expect("right select"), 2, 0),
            ShapedSelectSource::Resolved {
                update: InlineCacheUpdate::WidenedToPolymorphic { len: 2 },
            }
        );
    }

    #[test]
    fn default_cache_starts_uninitialized_with_cap_four() {
        let cache = InlineCache::new();

        assert_eq!(cache.cap(), DEFAULT_POLYMORPHIC_CAP);
        assert_eq!(cache.state(), &InlineCacheState::Uninitialized);
        assert_eq!(cache.lookup(InlineCacheShapeId::new(1)), None);
    }

    #[test]
    fn first_resolution_installs_monomorphic_entry() {
        let mut cache = InlineCache::new();

        assert_eq!(
            cache.record_resolution(entry(1, 7)),
            Ok(InlineCacheUpdate::InstalledMonomorphic)
        );

        assert_eq!(cache.lookup(InlineCacheShapeId::new(1)), Some(7));
        assert_eq!(cache.state().entry_count(), 1);
    }

    #[test]
    fn second_distinct_shape_widens_to_polymorphic() {
        let mut cache = InlineCache::new();
        cache
            .record_resolution(entry(1, 7))
            .expect("first resolution installs");

        assert_eq!(
            cache.record_resolution(entry(2, 11)),
            Ok(InlineCacheUpdate::WidenedToPolymorphic { len: 2 })
        );

        assert_eq!(cache.lookup(InlineCacheShapeId::new(1)), Some(7));
        assert_eq!(cache.lookup(InlineCacheShapeId::new(2)), Some(11));
        assert_eq!(cache.state().entry_count(), 2);
    }

    #[test]
    fn polymorphic_cache_adds_until_cap_then_goes_megamorphic() {
        let mut cache = InlineCache::with_cap(3).expect("nonzero cap");
        cache
            .record_resolution(entry(1, 10))
            .expect("first resolution installs");
        cache
            .record_resolution(entry(2, 20))
            .expect("second resolution widens");

        assert_eq!(
            cache.record_resolution(entry(3, 30)),
            Ok(InlineCacheUpdate::AddedPolymorphic { len: 3 })
        );
        assert_eq!(cache.lookup(InlineCacheShapeId::new(3)), Some(30));

        assert_eq!(
            cache.record_resolution(entry(4, 40)),
            Ok(InlineCacheUpdate::BecameMegamorphic)
        );
        assert!(cache.state().is_megamorphic());
        assert_eq!(cache.lookup(InlineCacheShapeId::new(1)), None);
        assert_eq!(
            cache.record_resolution(entry(5, 50)),
            Ok(InlineCacheUpdate::AlreadyMegamorphic)
        );
    }

    #[test]
    fn cap_one_goes_megamorphic_on_second_shape() {
        let mut cache = InlineCache::with_cap(1).expect("nonzero cap");
        cache
            .record_resolution(entry(1, 10))
            .expect("first resolution installs");

        assert_eq!(
            cache.record_resolution(entry(2, 20)),
            Ok(InlineCacheUpdate::BecameMegamorphic)
        );
        assert!(cache.state().is_megamorphic());
    }

    #[test]
    fn repeated_shape_reuses_existing_entry_without_duplication() {
        let mut cache = InlineCache::new();
        cache
            .record_resolution(entry(1, 10))
            .expect("first resolution installs");

        assert_eq!(
            cache.record_resolution(entry(1, 10)),
            Ok(InlineCacheUpdate::ReusedExisting)
        );
        assert_eq!(cache.state().entry_count(), 1);
    }

    #[test]
    fn repeated_polymorphic_shape_reuses_existing_entry_without_duplication() {
        let mut cache = InlineCache::new();
        cache
            .record_resolution(entry(1, 10))
            .expect("first resolution installs");
        cache
            .record_resolution(entry(2, 20))
            .expect("second resolution widens");

        assert_eq!(
            cache.record_resolution(entry(2, 20)),
            Ok(InlineCacheUpdate::ReusedExisting)
        );
        assert_eq!(cache.state().entry_count(), 2);
        assert_eq!(cache.lookup(InlineCacheShapeId::new(1)), Some(10));
        assert_eq!(cache.lookup(InlineCacheShapeId::new(2)), Some(20));
    }

    #[test]
    fn same_shape_with_different_slot_is_rejected() {
        let mut cache = InlineCache::new();
        cache
            .record_resolution(entry(1, 10))
            .expect("first resolution installs");

        assert_eq!(
            cache.record_resolution(entry(1, 11)),
            Err(InlineCacheError::ShapeSlotChanged {
                shape: InlineCacheShapeId::new(1),
                previous_slot: 10,
                attempted_slot: 11,
            })
        );
        assert_eq!(cache.lookup(InlineCacheShapeId::new(1)), Some(10));
    }

    #[test]
    fn polymorphic_same_shape_with_different_slot_is_rejected() {
        let mut cache = InlineCache::new();
        cache
            .record_resolution(entry(1, 10))
            .expect("first resolution installs");
        cache
            .record_resolution(entry(2, 20))
            .expect("second resolution widens");

        assert_eq!(
            cache.record_resolution(entry(2, 21)),
            Err(InlineCacheError::ShapeSlotChanged {
                shape: InlineCacheShapeId::new(2),
                previous_slot: 20,
                attempted_slot: 21,
            })
        );
        assert_eq!(cache.state().entry_count(), 2);
        assert_eq!(cache.lookup(InlineCacheShapeId::new(1)), Some(10));
        assert_eq!(cache.lookup(InlineCacheShapeId::new(2)), Some(20));
    }

    #[test]
    fn zero_custom_cap_is_rejected() {
        assert_eq!(
            InlineCache::with_cap(0),
            Err(InlineCacheError::ZeroPolymorphicCap)
        );
    }
}
