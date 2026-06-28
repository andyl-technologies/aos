//! Polymorphic inline-cache state for future attr selection fast paths.
//!
//! This module captures the safe state-machine contract from RFC-0007 §09:
//! select sites start uninitialized, specialize to one shape, widen to a small
//! polymorphic set, then fall back to megamorphic dispatch after the configured
//! cap. It does not execute selection, guard a runtime value, update tree-walk
//! behavior, call a slow resolver, or install deoptimization edges.
//!
//! Cached shape ids are opaque handles supplied by a future shape table. They
//! are not fingerprints, not symbol ids, and not pointer provenance.

use thiserror::Error;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(shape: u32, slot: u32) -> InlineCacheEntry {
        InlineCacheEntry::new(InlineCacheShapeId::new(shape), slot)
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
