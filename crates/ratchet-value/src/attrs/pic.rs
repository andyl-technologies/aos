//! Polymorphic inline-cache state for future attr selection fast paths.
//!
//! This module captures the safe state-machine contract from RFC-0007 §09:
//! select sites start uninitialized, specialize to one shape, widen to a small
//! polymorphic set, then fall back to megamorphic dispatch after the configured
//! cap. The generic [`InlineCache`] remains a state machine over opaque shape
//! ids; [`ShapedSelectCache`] is a safe shaped-attrset precursor that proves the
//! shape-guard + constant-offset load contract and resolves uncached shaped
//! lookups through [`crate::attrs::select::select_slow`] before updating PIC
//! state. The active tree-walk evaluator uses it through a projected-shape
//! bridge over flat heap payloads; the final native runtime helper and
//! deoptimization edges remain future work. [`FlatSelectCache`] models a safe
//! precursor for the active flat representation by caching key-validated
//! symbol-order slots. [`HamtSelectCache`] models the HAMT select-site policy
//! and resolves HAMT values through the representation-dispatching
//! [`crate::attrs::select::select_slow`] HAMT branch.
//!
//! Cached shape ids are opaque handles supplied by a future shape table. They
//! are not fingerprints, not symbol ids, and not pointer provenance.

pub mod record;

use thiserror::Error;

use super::FlatAttrs;
use super::hamt::HamtAttrs;
use super::select::{
    AttrSelectError, AttrSelectOutcome, AttrSelectSource, AttrSelectTarget, select_slow,
};
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

/// The current state of one flat select-site cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlatSelectCacheState {
    /// The site has not observed a flat attrset yet.
    Uninitialized,
    /// The site has observed exactly one symbol-order slot for its static key.
    Monomorphic {
        /// The cached symbol-order slot.
        slot: u32,
    },
    /// The site has observed a small bounded set of symbol-order slots.
    Polymorphic {
        /// Cached slots in first-observed order.
        slots: Box<[u32]>,
    },
    /// The site exceeded the polymorphic cap and uses the generic slow path.
    Megamorphic,
}

impl FlatSelectCacheState {
    /// Returns the number of cached slots in this state.
    pub fn entry_count(&self) -> usize {
        match self {
            Self::Uninitialized | Self::Megamorphic => 0,
            Self::Monomorphic { .. } => 1,
            Self::Polymorphic { slots } => slots.len(),
        }
    }

    /// Returns whether this state has abandoned slot specialization.
    pub const fn is_megamorphic(&self) -> bool {
        matches!(self, Self::Megamorphic)
    }
}

/// A safe flat-attrset select-site cache.
///
/// Flat attrsets do not carry interned shape pointers, so this precursor caches
/// observed symbol-order slots for one static select key. A cached hit is
/// admitted only after checking that the current flat attrset still has the
/// selected key at that slot; otherwise the cache falls back to the shared slow
/// resolver and records the newly observed slot. This proves a key-validated
/// slot-load boundary for the current active representation without changing
/// evaluator storage or observable iteration order.
#[derive(Clone, Debug)]
pub struct FlatSelectCache {
    cap: usize,
    key: Option<Symbol>,
    state: FlatSelectCacheState,
}

impl FlatSelectCache {
    /// Creates an uninitialized flat select cache with [`DEFAULT_POLYMORPHIC_CAP`].
    pub const fn new() -> Self {
        Self {
            cap: DEFAULT_POLYMORPHIC_CAP,
            key: None,
            state: FlatSelectCacheState::Uninitialized,
        }
    }

    /// Creates an uninitialized flat select cache with a custom polymorphic cap.
    ///
    /// # Errors
    ///
    /// Returns [`FlatSelectError::ZeroPolymorphicCap`] when `cap` is zero.
    pub const fn with_cap(cap: usize) -> Result<Self, FlatSelectError> {
        if cap == 0 {
            Err(FlatSelectError::ZeroPolymorphicCap)
        } else {
            Ok(Self {
                cap,
                key: None,
                state: FlatSelectCacheState::Uninitialized,
            })
        }
    }

    /// Returns the configured polymorphic slot cap.
    pub const fn cap(&self) -> usize {
        self.cap
    }

    /// Returns the current flat select-cache state.
    pub const fn state(&self) -> &FlatSelectCacheState {
        &self.state
    }

    /// Returns the static key bound to this select-site cache, if observed.
    pub const fn key(&self) -> Option<Symbol> {
        self.key
    }

    /// Selects `key` from `attrs`, using key-validated cached slots when possible.
    ///
    /// The flat attrset and select key must come from the same symbol universe.
    /// Missing keys do not add slot entries or change PIC state because there
    /// is no stable absent slot to guard.
    ///
    /// # Errors
    ///
    /// Returns [`FlatSelectError::KeyChanged`] if the cache is reused for a
    /// different static select key, [`FlatSelectError::ResolvedKeyMissing`] if
    /// the shared slow resolver reports a hit whose slot cannot be recovered,
    /// [`FlatSelectError::UnexpectedSlowSelectSource`] if the shared slow
    /// resolver returns a non-flat hit source, [`FlatSelectError::Select`] if
    /// slow resolution fails, or [`FlatSelectError::EntryAllocationFailed`] if
    /// widening the cached slot list cannot reserve storage.
    pub fn select(
        &mut self,
        attrs: &FlatAttrs,
        key: Symbol,
    ) -> Result<FlatSelectOutcome, FlatSelectError> {
        self.bind_key(key)?;
        if let Some((value, slot)) = self.lookup_cached(attrs, key) {
            return Ok(FlatSelectOutcome::Hit {
                value,
                slot,
                source: FlatSelectSource::Cached,
            });
        }

        let (value, slot) = match select_slow(AttrSelectTarget::Flat(attrs), key)? {
            AttrSelectOutcome::Hit {
                value,
                source: AttrSelectSource::Flat,
            } => (
                value,
                flat_slot(attrs, key).ok_or(FlatSelectError::ResolvedKeyMissing { key })?,
            ),
            AttrSelectOutcome::Hit { source, .. } => {
                return Err(FlatSelectError::UnexpectedSlowSelectSource {
                    select_source: source,
                });
            }
            AttrSelectOutcome::Missing { .. } => return Ok(FlatSelectOutcome::Missing),
        };
        let update = self.record_slot(slot)?;
        Ok(FlatSelectOutcome::Hit {
            value,
            slot,
            source: FlatSelectSource::Resolved { update },
        })
    }

    fn lookup_cached(&self, attrs: &FlatAttrs, key: Symbol) -> Option<(Value, u32)> {
        let slots = attrs.entries_by_symbol();
        match &self.state {
            FlatSelectCacheState::Uninitialized | FlatSelectCacheState::Megamorphic => None,
            FlatSelectCacheState::Monomorphic { slot } => {
                cached_flat_slot(slots, key, *slot).map(|value| (value, *slot))
            }
            FlatSelectCacheState::Polymorphic {
                slots: cached_slots,
            } => cached_slots
                .iter()
                .find_map(|slot| cached_flat_slot(slots, key, *slot).map(|value| (value, *slot))),
        }
    }

    fn record_slot(&mut self, slot: u32) -> Result<InlineCacheUpdate, FlatSelectError> {
        match &mut self.state {
            FlatSelectCacheState::Uninitialized => {
                self.state = FlatSelectCacheState::Monomorphic { slot };
                Ok(InlineCacheUpdate::InstalledMonomorphic)
            }
            FlatSelectCacheState::Monomorphic { slot: cached } => {
                if *cached == slot {
                    return Ok(InlineCacheUpdate::ReusedExisting);
                }
                if self.cap == 1 {
                    self.state = FlatSelectCacheState::Megamorphic;
                    return Ok(InlineCacheUpdate::BecameMegamorphic);
                }

                let mut slots = Vec::new();
                slots
                    .try_reserve_exact(2)
                    .map_err(|_| FlatSelectError::EntryAllocationFailed { entries: 2 })?;
                slots.push(*cached);
                slots.push(slot);
                self.state = FlatSelectCacheState::Polymorphic {
                    slots: slots.into_boxed_slice(),
                };
                Ok(InlineCacheUpdate::WidenedToPolymorphic { len: 2 })
            }
            FlatSelectCacheState::Polymorphic { slots } => {
                if slots.contains(&slot) {
                    return Ok(InlineCacheUpdate::ReusedExisting);
                }
                if slots.len() >= self.cap {
                    self.state = FlatSelectCacheState::Megamorphic;
                    return Ok(InlineCacheUpdate::BecameMegamorphic);
                }

                let mut next = Vec::new();
                let len =
                    slots
                        .len()
                        .checked_add(1)
                        .ok_or(FlatSelectError::EntryAllocationFailed {
                            entries: usize::MAX,
                        })?;
                next.try_reserve_exact(len)
                    .map_err(|_| FlatSelectError::EntryAllocationFailed { entries: len })?;
                next.extend_from_slice(slots);
                next.push(slot);
                self.state = FlatSelectCacheState::Polymorphic {
                    slots: next.into_boxed_slice(),
                };
                Ok(InlineCacheUpdate::AddedPolymorphic { len })
            }
            FlatSelectCacheState::Megamorphic => Ok(InlineCacheUpdate::AlreadyMegamorphic),
        }
    }

    fn bind_key(&mut self, key: Symbol) -> Result<(), FlatSelectError> {
        match self.key {
            Some(previous) if previous != key => Err(FlatSelectError::KeyChanged {
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

impl Default for FlatSelectCache {
    fn default() -> Self {
        Self::new()
    }
}

fn cached_flat_slot(slots: &[super::AttrEntry], key: Symbol, slot: u32) -> Option<Value> {
    slots
        .get(slot as usize)
        .and_then(|entry| (entry.key == key).then_some(entry.value))
}

fn flat_slot(attrs: &FlatAttrs, key: Symbol) -> Option<u32> {
    attrs
        .entries_by_symbol()
        .binary_search_by_key(&key, |entry| entry.key)
        .ok()
        .and_then(|slot| u32::try_from(slot).ok())
}

/// A flat select-cache lookup result.
#[derive(Clone, Copy, Debug)]
pub enum FlatSelectOutcome {
    /// The key was present.
    Hit {
        /// The selected value.
        value: Value,
        /// The symbol-order slot that was loaded.
        slot: u32,
        /// Whether the value came from the cached path or slow resolution.
        source: FlatSelectSource,
    },
    /// The key is absent from the flat attrset.
    Missing,
}

/// The path used to produce a flat select result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlatSelectSource {
    /// A cached key-validated slot was loaded.
    Cached,
    /// The slot was resolved through the shared slow resolver and the cache was updated.
    Resolved {
        /// The state-machine update produced by the slow resolution.
        update: InlineCacheUpdate,
    },
}

/// A failed flat select-cache operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FlatSelectError {
    /// A custom cache cap was zero.
    #[error("flat select-cache polymorphic cap must be greater than zero")]
    ZeroPolymorphicCap,
    /// A select-site cache was reused for a different static key.
    #[error("flat select-cache key changed from {previous:?} to {attempted:?}")]
    KeyChanged {
        /// The key already bound to the cache.
        previous: Symbol,
        /// The attempted replacement key.
        attempted: Symbol,
    },
    /// The shared slow resolver reported a hit but the flat slot could not be recovered.
    #[error("flat select-cache slow resolver hit for {key:?}, but no flat slot was found")]
    ResolvedKeyMissing {
        /// The selected key.
        key: Symbol,
    },
    /// The shared slow resolver returned a non-flat hit source for a flat target.
    #[error("flat select-cache slow resolver returned unexpected source {select_source:?}")]
    UnexpectedSlowSelectSource {
        /// The unexpected hit source.
        select_source: AttrSelectSource,
    },
    /// The representation-dispatching slow resolver failed.
    #[error("flat select-cache slow resolver failed: {0}")]
    Select(#[from] AttrSelectError),
    /// A polymorphic slot list could not reserve storage.
    #[error("failed to reserve {entries} flat select-cache entries")]
    EntryAllocationFailed {
        /// The requested entry count.
        entries: usize,
    },
}

mod hamt_select;
pub use hamt_select::*;
mod shaped_select;
pub use shaped_select::*;

#[cfg(test)]
mod tests;
