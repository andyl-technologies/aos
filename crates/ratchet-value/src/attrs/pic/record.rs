//! Record-resident shaped select caching over flat symbol-order payloads.
//!
//! RFC-0007 §09 stores a hidden-class shape id in every heap attrset record at
//! construction. Because [`super::super::shape::AttrShape`] slots are the
//! symbol-sorted key order and [`FlatAttrs`] storage is symbol-sorted too, the
//! flat entry array already *is* the shaped slot layout: no transient shaped
//! view has to be materialized to serve a shaped select. [`RecordSelectCache`]
//! is the select-site cache for that heap-resident layout - a cached hit is a
//! shape-id guard, a constant-offset entry load, and a key recheck; nothing is
//! copied and no [`super::super::shape::ShapedAttrs`] value is built.
//!
//! The cache guards entries by dense [`ShapeId`] rather than interned shape
//! pointer: the evaluator mints all projected ids from one shape table (or
//! id-compatible parallel replicas of one shared log), so id equality is shape
//! identity there. The per-hit key recheck keeps even a cross-table id
//! collision sound - a colliding slot either stores the requested key (and the
//! value is correct by [`FlatAttrs`] symbol-order invariants) or the lookup
//! falls back to the slow binary-search path.

use thiserror::Error;

use super::super::FlatAttrs;
use super::super::shape::ShapeId;
use super::{DEFAULT_POLYMORPHIC_CAP, InlineCacheUpdate};
use crate::syntax::Symbol;
use crate::value::Value;

/// One shape-id-guarded symbol-order slot load.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecordSelectCacheEntry {
    shape: ShapeId,
    slot: u32,
}

impl RecordSelectCacheEntry {
    /// Creates a record select-cache entry.
    pub const fn new(shape: ShapeId, slot: u32) -> Self {
        Self { shape, slot }
    }

    /// Returns the guarded projected shape id.
    pub const fn shape(&self) -> ShapeId {
        self.shape
    }

    /// Returns the symbol-order slot loaded after the shape guard succeeds.
    pub const fn slot(&self) -> u32 {
        self.slot
    }
}

/// The current state of one record select-site cache.
#[derive(Clone, Debug)]
pub enum RecordSelectCacheState {
    /// The site has not observed a shaped record yet.
    Uninitialized,
    /// The site has observed exactly one projected shape.
    Monomorphic {
        /// The cached shape-guarded slot load.
        entry: RecordSelectCacheEntry,
    },
    /// The site has observed a small bounded set of projected shapes.
    Polymorphic {
        /// Cached entries in first-observed order.
        entries: Box<[RecordSelectCacheEntry]>,
    },
    /// The site exceeded the polymorphic cap and uses the slow path.
    Megamorphic,
}

impl RecordSelectCacheState {
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

/// A select-site cache for heap-resident shaped flat records.
///
/// One cache binds one static select key. A lookup takes the record's
/// projected [`ShapeId`] and its flat symbol-order payload directly; the
/// shaped slot layout is the payload itself, so hits never build a view.
#[derive(Clone, Debug)]
pub struct RecordSelectCache {
    cap: usize,
    key: Option<Symbol>,
    state: RecordSelectCacheState,
}

impl RecordSelectCache {
    /// Creates an uninitialized record select cache with [`DEFAULT_POLYMORPHIC_CAP`].
    pub const fn new() -> Self {
        Self {
            cap: DEFAULT_POLYMORPHIC_CAP,
            key: None,
            state: RecordSelectCacheState::Uninitialized,
        }
    }

    /// Creates an uninitialized record select cache with a custom polymorphic cap.
    ///
    /// # Errors
    ///
    /// Returns [`RecordSelectError::ZeroPolymorphicCap`] when `cap` is zero.
    pub const fn with_cap(cap: usize) -> Result<Self, RecordSelectError> {
        if cap == 0 {
            Err(RecordSelectError::ZeroPolymorphicCap)
        } else {
            Ok(Self {
                cap,
                key: None,
                state: RecordSelectCacheState::Uninitialized,
            })
        }
    }

    /// Returns the configured polymorphic entry cap.
    pub const fn cap(&self) -> usize {
        self.cap
    }

    /// Returns the current record select-cache state.
    pub const fn state(&self) -> &RecordSelectCacheState {
        &self.state
    }

    /// Returns the static key bound to this select-site cache, if observed.
    pub const fn key(&self) -> Option<Symbol> {
        self.key
    }

    /// Selects `key` from a shaped record's flat symbol-order payload.
    ///
    /// A cached hit compares `shape` against the cached projected shape id,
    /// loads the entry at the cached constant slot, and rechecks the stored
    /// key. A guard miss (unknown shape id) resolves by binary search over
    /// the symbol-sorted payload and widens the cache through the standard
    /// `Uninitialized -> Monomorphic -> Polymorphic -> Megamorphic` states. A
    /// key recheck failure resolves by binary search without touching cache
    /// state: it means the id was minted by a foreign shape table, and the
    /// site keeps its calibration for the evaluator's own universe.
    ///
    /// # Errors
    ///
    /// Returns [`RecordSelectError::KeyChanged`] if the cache is reused for a
    /// different select key or
    /// [`RecordSelectError::EntryAllocationFailed`] if widening the
    /// polymorphic entry list cannot reserve storage.
    pub fn select(
        &mut self,
        shape: ShapeId,
        attrs: &FlatAttrs,
        key: Symbol,
    ) -> Result<RecordSelectOutcome, RecordSelectError> {
        self.bind_key(key)?;
        if let Some(slot) = self.lookup_slot(shape) {
            match attrs.entries_by_symbol().get(slot as usize) {
                Some(entry) if entry.key == key => {
                    return Ok(RecordSelectOutcome::Hit {
                        value: entry.value,
                        slot,
                        source: RecordSelectSource::Cached,
                    });
                }
                // The cached slot does not hold the requested key: the
                // projected id came from a different shape universe than the
                // one that calibrated this site. Serve the lookup through the
                // slow path and leave the cache untouched.
                _ => {
                    return Ok(match attrs.symbol_slot(key) {
                        Some(slot) => RecordSelectOutcome::Hit {
                            value: attrs.entries_by_symbol()[slot as usize].value,
                            slot,
                            source: RecordSelectSource::Resolved {
                                update: InlineCacheUpdate::ReusedExisting,
                            },
                        },
                        None => RecordSelectOutcome::Missing,
                    });
                }
            }
        }

        let Some(slot) = attrs.symbol_slot(key) else {
            return Ok(RecordSelectOutcome::Missing);
        };
        let value = attrs.entries_by_symbol()[slot as usize].value;
        let update = self.record_resolution(RecordSelectCacheEntry::new(shape, slot))?;
        Ok(RecordSelectOutcome::Hit {
            value,
            slot,
            source: RecordSelectSource::Resolved { update },
        })
    }

    fn lookup_slot(&self, shape: ShapeId) -> Option<u32> {
        match &self.state {
            RecordSelectCacheState::Uninitialized | RecordSelectCacheState::Megamorphic => None,
            RecordSelectCacheState::Monomorphic { entry } => {
                (entry.shape() == shape).then_some(entry.slot())
            }
            RecordSelectCacheState::Polymorphic { entries } => entries
                .iter()
                .find(|entry| entry.shape() == shape)
                .map(RecordSelectCacheEntry::slot),
        }
    }

    fn record_resolution(
        &mut self,
        entry: RecordSelectCacheEntry,
    ) -> Result<InlineCacheUpdate, RecordSelectError> {
        match &mut self.state {
            RecordSelectCacheState::Uninitialized => {
                self.state = RecordSelectCacheState::Monomorphic { entry };
                Ok(InlineCacheUpdate::InstalledMonomorphic)
            }
            RecordSelectCacheState::Monomorphic { entry: cached } => {
                if cached.shape() == entry.shape() {
                    return Ok(InlineCacheUpdate::ReusedExisting);
                }
                if self.cap == 1 {
                    self.state = RecordSelectCacheState::Megamorphic;
                    return Ok(InlineCacheUpdate::BecameMegamorphic);
                }
                let mut entries = Vec::new();
                entries
                    .try_reserve_exact(2)
                    .map_err(|_| RecordSelectError::EntryAllocationFailed { entries: 2 })?;
                entries.push(*cached);
                entries.push(entry);
                self.state = RecordSelectCacheState::Polymorphic {
                    entries: entries.into_boxed_slice(),
                };
                Ok(InlineCacheUpdate::WidenedToPolymorphic { len: 2 })
            }
            RecordSelectCacheState::Polymorphic { entries } => {
                if entries.iter().any(|cached| cached.shape() == entry.shape()) {
                    return Ok(InlineCacheUpdate::ReusedExisting);
                }
                if entries.len() >= self.cap {
                    self.state = RecordSelectCacheState::Megamorphic;
                    return Ok(InlineCacheUpdate::BecameMegamorphic);
                }
                let len = entries.len().checked_add(1).ok_or(
                    RecordSelectError::EntryAllocationFailed {
                        entries: usize::MAX,
                    },
                )?;
                let mut next = Vec::new();
                next.try_reserve_exact(len)
                    .map_err(|_| RecordSelectError::EntryAllocationFailed { entries: len })?;
                next.extend_from_slice(entries);
                next.push(entry);
                self.state = RecordSelectCacheState::Polymorphic {
                    entries: next.into_boxed_slice(),
                };
                Ok(InlineCacheUpdate::AddedPolymorphic { len })
            }
            RecordSelectCacheState::Megamorphic => Ok(InlineCacheUpdate::AlreadyMegamorphic),
        }
    }

    fn bind_key(&mut self, key: Symbol) -> Result<(), RecordSelectError> {
        match self.key {
            Some(previous) if previous != key => Err(RecordSelectError::KeyChanged {
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

impl Default for RecordSelectCache {
    fn default() -> Self {
        Self::new()
    }
}

/// A record select-cache lookup result.
#[derive(Clone, Copy, Debug)]
pub enum RecordSelectOutcome {
    /// The key was present.
    Hit {
        /// The selected value.
        value: Value,
        /// The symbol-order slot that was loaded.
        slot: u32,
        /// Whether the value came from the cached fast path or slow resolution.
        source: RecordSelectSource,
    },
    /// The key is absent from the record.
    Missing,
}

/// The path used to produce a record select hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordSelectSource {
    /// The shape-id guard matched and the cached slot was loaded.
    Cached,
    /// The slot was resolved by binary search; the cache state may have widened.
    Resolved {
        /// The state-machine update produced by the slow resolution.
        update: InlineCacheUpdate,
    },
}

/// A failed record select-cache operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RecordSelectError {
    /// A custom cache cap was zero.
    #[error("record select-cache polymorphic cap must be greater than zero")]
    ZeroPolymorphicCap,
    /// A select-site cache was reused for a different static key.
    #[error("record select-cache key changed from {previous:?} to {attempted:?}")]
    KeyChanged {
        /// The key already bound to the cache.
        previous: Symbol,
        /// The attempted replacement key.
        attempted: Symbol,
    },
    /// A polymorphic entry list could not reserve storage.
    #[error("failed to reserve {entries} record select-cache entries")]
    EntryAllocationFailed {
        /// The requested entry count.
        entries: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attrs::AttrEntry;
    use crate::syntax::SymbolTable;

    fn symbols(names: &[&[u8]]) -> (SymbolTable, Vec<Symbol>) {
        let mut table = SymbolTable::new();
        let mut ids = Vec::new();
        for name in names {
            ids.push(table.intern(name).expect("symbol interns"));
        }
        (table, ids)
    }

    fn attrs(entries: &[(Symbol, i64)], table: &SymbolTable) -> FlatAttrs {
        FlatAttrs::new(
            entries
                .iter()
                .map(|&(key, value)| AttrEntry::new(key, Value::int(value)))
                .collect(),
            table,
        )
        .expect("attrset builds")
    }

    fn hit_value(outcome: RecordSelectOutcome) -> (i64, RecordSelectSource) {
        match outcome {
            RecordSelectOutcome::Hit { value, source, .. } => {
                (value.as_int().expect("int value"), source)
            }
            RecordSelectOutcome::Missing => panic!("expected hit"),
        }
    }

    #[test]
    fn resolves_then_serves_cached_slot_loads() {
        let (table, ids) = symbols(&[b"ip", b"ptr", b"tape"]);
        let record = attrs(&[(ids[0], 1), (ids[1], 2), (ids[2], 3)], &table);
        let shape = ShapeId::new(7);
        let mut cache = RecordSelectCache::new();

        let (value, source) = hit_value(cache.select(shape, &record, ids[1]).expect("selects"));
        assert_eq!(value, 2);
        assert!(matches!(source, RecordSelectSource::Resolved { .. }));
        assert!(matches!(
            cache.state(),
            RecordSelectCacheState::Monomorphic { .. }
        ));

        // Same shape id, different instance: cached slot load.
        let updated = attrs(&[(ids[0], 10), (ids[1], 20), (ids[2], 30)], &table);
        let (value, source) = hit_value(cache.select(shape, &updated, ids[1]).expect("selects"));
        assert_eq!(value, 20);
        assert_eq!(source, RecordSelectSource::Cached);
    }

    #[test]
    fn widens_to_polymorphic_then_megamorphic_at_cap() {
        let (table, ids) = symbols(&[b"a", b"b", b"c", b"d", b"e", b"f"]);
        let mut cache = RecordSelectCache::with_cap(2).expect("cap accepted");
        let key = ids[0];
        // Shapes with the key at different slots.
        for (index, extra) in [ids[1], ids[2], ids[3]].iter().enumerate() {
            let record = attrs(&[(key, index as i64), (*extra, 99)], &table);
            let outcome = cache
                .select(ShapeId::new(index as u32), &record, key)
                .expect("selects");
            let (value, _) = hit_value(outcome);
            assert_eq!(value, index as i64);
        }
        assert!(cache.state().is_megamorphic());
        // Megamorphic sites still resolve correctly through the slow path.
        let record = attrs(&[(key, 42)], &table);
        let (value, source) = hit_value(
            cache
                .select(ShapeId::new(9), &record, key)
                .expect("selects"),
        );
        assert_eq!(value, 42);
        assert!(matches!(
            source,
            RecordSelectSource::Resolved {
                update: InlineCacheUpdate::AlreadyMegamorphic
            }
        ));
    }

    #[test]
    fn key_recheck_defends_against_foreign_shape_ids() {
        let (table, ids) = symbols(&[b"x", b"y"]);
        let shape = ShapeId::new(3);
        let mut cache = RecordSelectCache::new();
        // Calibrate against a record where `y` lives at slot 1.
        let record = attrs(&[(ids[0], 1), (ids[1], 2)], &table);
        hit_value(cache.select(shape, &record, ids[1]).expect("selects"));

        // A foreign record reusing the same id stores `y` at slot 0.
        let foreign = attrs(&[(ids[1], 7)], &table);
        let (value, source) = hit_value(cache.select(shape, &foreign, ids[1]).expect("selects"));
        assert_eq!(value, 7);
        assert!(matches!(source, RecordSelectSource::Resolved { .. }));
        // The site keeps its original monomorphic calibration.
        let (value, source) = hit_value(cache.select(shape, &record, ids[1]).expect("selects"));
        assert_eq!(value, 2);
        assert_eq!(source, RecordSelectSource::Cached);

        // A foreign record missing the key reports Missing without recording.
        let missing = attrs(&[(ids[0], 5)], &table);
        assert!(matches!(
            cache.select(shape, &missing, ids[1]).expect("selects"),
            RecordSelectOutcome::Missing
        ));
        assert!(matches!(
            cache.state(),
            RecordSelectCacheState::Monomorphic { .. }
        ));
    }

    #[test]
    fn missing_keys_do_not_install_entries() {
        let (table, ids) = symbols(&[b"a", b"b"]);
        let record = attrs(&[(ids[0], 1)], &table);
        let mut cache = RecordSelectCache::new();
        assert!(matches!(
            cache
                .select(ShapeId::new(0), &record, ids[1])
                .expect("selects"),
            RecordSelectOutcome::Missing
        ));
        assert!(matches!(
            cache.state(),
            RecordSelectCacheState::Uninitialized
        ));
    }

    #[test]
    fn rebinding_a_different_key_is_rejected() {
        let (table, ids) = symbols(&[b"a", b"b"]);
        let record = attrs(&[(ids[0], 1), (ids[1], 2)], &table);
        let mut cache = RecordSelectCache::new();
        cache
            .select(ShapeId::new(0), &record, ids[0])
            .expect("selects");
        assert_eq!(
            cache
                .select(ShapeId::new(0), &record, ids[1])
                .expect_err("key rebind rejected"),
            RecordSelectError::KeyChanged {
                previous: ids[0],
                attempted: ids[1],
            }
        );
    }

    #[test]
    fn zero_cap_is_rejected_and_cap_one_goes_megamorphic() {
        assert_eq!(
            RecordSelectCache::with_cap(0).expect_err("zero cap rejected"),
            RecordSelectError::ZeroPolymorphicCap
        );
        let (table, ids) = symbols(&[b"a", b"b"]);
        let mut cache = RecordSelectCache::with_cap(1).expect("cap accepted");
        let first = attrs(&[(ids[0], 1)], &table);
        let second = attrs(&[(ids[0], 2), (ids[1], 3)], &table);
        cache
            .select(ShapeId::new(0), &first, ids[0])
            .expect("selects");
        cache
            .select(ShapeId::new(1), &second, ids[0])
            .expect("selects");
        assert!(cache.state().is_megamorphic());
    }
}
