//! Shape-guarded polymorphic inline caches for shaped attrsets
//! (split from pic.rs under the §2 file-size cap).
use super::*;

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
    /// resolves through the representation-dispatching `select_slow` shaped
    /// branch, then records the returned shape slot in the cache unless the key
    /// is absent.
    ///
    /// # Errors
    ///
    /// Returns [`ShapedSelectError::KeyChanged`] if the cache is reused for a
    /// different select key, [`ShapedSelectError::CachedSlotOutOfRange`] when a
    /// cached entry references a slot outside the value array,
    /// [`ShapedSelectError::ResolvedSlotOutOfRange`] when the shared slow
    /// resolver reports a shaped slot outside the value array,
    /// [`ShapedSelectError::UnexpectedSlowSelectSource`] if the shared resolver
    /// returns a non-shaped hit source for a shaped target,
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

        let (value, slot) = match select_slow(AttrSelectTarget::Shaped(attrs), key)
            .map_err(ShapedSelectError::from_slow_select)?
        {
            AttrSelectOutcome::Hit {
                value,
                source: AttrSelectSource::Shaped { slot },
            } => (value, slot),
            AttrSelectOutcome::Hit { source, .. } => {
                return Err(ShapedSelectError::UnexpectedSlowSelectSource {
                    select_source: source,
                });
            }
            AttrSelectOutcome::Missing { .. } => return Ok(ShapedSelectOutcome::Missing),
        };
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
    /// The slot was resolved through the shared slow resolver and the cache was updated.
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
    /// A resolved slow-path shape slot did not exist in the shaped attrset's value array.
    #[error("shaped select resolved slot {slot} is out of range for {len} values")]
    ResolvedSlotOutOfRange {
        /// The resolved slot.
        slot: u32,
        /// The shaped attrset value count.
        len: usize,
    },
    /// The shared slow resolver returned a non-shaped hit source for a shaped target.
    #[error("shaped select-cache slow resolver returned unexpected source {select_source:?}")]
    UnexpectedSlowSelectSource {
        /// The unexpected hit source.
        select_source: AttrSelectSource,
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

impl ShapedSelectError {
    fn from_slow_select(source: AttrSelectError) -> Self {
        match source {
            AttrSelectError::ShapedSlotOutOfRange { slot, len } => {
                Self::ResolvedSlotOutOfRange { slot, len }
            }
        }
    }
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
