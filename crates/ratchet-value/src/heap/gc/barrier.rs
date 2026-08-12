//! Write-barrier decision surfaces: generations, heap addresses, thunk-
//! resolve writes, remembered edges/sets, and the dirty-card table.
//!
//! Moved verbatim from `heap/gc.rs` under the RFC-0007 §2 file-size cap; the
//! parent re-exports every public path.

use super::*;

/// The runtime tier in which the generational write barrier is evaluated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GenerationalGcTier {
    /// One-shot CLI or harness evaluation; the bump arena never collects.
    OneShotArena,
    /// Long-lived daemon evaluation with a young generation and remembered set.
    DaemonGenerational,
}

/// The generation that owns a heap object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HeapGeneration {
    /// The object is in the young generation.
    Young,
    /// The object is in the old generation.
    Old,
    /// The object is in permanent space and bypasses promotion churn.
    Permanent,
}

impl HeapGeneration {
    const fn needs_young_target_barrier(self) -> bool {
        matches!(self, Self::Old | Self::Permanent)
    }
}

/// An aligned heap object address used by the generational barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GcHeapAddress {
    address_bits: usize,
}

impl GcHeapAddress {
    /// Creates a heap address from untagged address bits.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError::NullAddress`] when `address_bits` is zero,
    /// or [`GenerationalGcError::LowTagBitsPresent`] when low pointer-tag bits
    /// are still present.
    pub fn new(address_bits: usize) -> Result<Self, GenerationalGcError> {
        if address_bits & POINTER_TAG_MASK != 0 {
            return Err(GenerationalGcError::LowTagBitsPresent { address_bits });
        }
        if address_bits == 0 {
            return Err(GenerationalGcError::NullAddress);
        }
        Ok(Self { address_bits })
    }

    /// Returns the untagged aligned address bits.
    pub const fn address_bits(self) -> usize {
        self.address_bits
    }
}

/// The forced value written into a resolved thunk, classified for GC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResolvedValueGeneration {
    /// The forced value is inline and contains no heap pointer.
    Inline,
    /// The forced value is heap-backed.
    Heap {
        /// The forced value's heap object address.
        address: GcHeapAddress,
        /// The forced value's generation.
        generation: HeapGeneration,
    },
}

impl ResolvedValueGeneration {
    /// Creates a young heap-backed resolved value.
    pub const fn young(address: GcHeapAddress) -> Self {
        Self::Heap {
            address,
            generation: HeapGeneration::Young,
        }
    }

    /// Creates an old heap-backed resolved value.
    pub const fn old(address: GcHeapAddress) -> Self {
        Self::Heap {
            address,
            generation: HeapGeneration::Old,
        }
    }

    /// Creates a permanent heap-backed resolved value.
    pub const fn permanent(address: GcHeapAddress) -> Self {
        Self::Heap {
            address,
            generation: HeapGeneration::Permanent,
        }
    }
}

/// A thunk-resolution write into an already allocated thunk object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ThunkResolveWrite {
    thunk: GcHeapAddress,
    thunk_generation: HeapGeneration,
    value: ResolvedValueGeneration,
}

impl ThunkResolveWrite {
    /// Creates a thunk-resolution write descriptor.
    pub const fn new(
        thunk: GcHeapAddress,
        thunk_generation: HeapGeneration,
        value: ResolvedValueGeneration,
    ) -> Self {
        Self {
            thunk,
            thunk_generation,
            value,
        }
    }

    /// Returns the thunk object being resolved.
    pub const fn thunk(self) -> GcHeapAddress {
        self.thunk
    }

    /// Returns the thunk object's generation.
    pub const fn thunk_generation(self) -> HeapGeneration {
        self.thunk_generation
    }

    /// Returns the forced value being published.
    pub const fn value(self) -> ResolvedValueGeneration {
        self.value
    }
}

/// One old-or-permanent to young edge recorded for minor collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RememberedEdge {
    source: GcHeapAddress,
    target: GcHeapAddress,
}

impl RememberedEdge {
    /// Creates a remembered old-to-young edge.
    pub const fn new(source: GcHeapAddress, target: GcHeapAddress) -> Self {
        Self { source, target }
    }

    /// Returns the old or permanent source object.
    pub const fn source(self) -> GcHeapAddress {
        self.source
    }

    /// Returns the young target object.
    pub const fn target(self) -> GcHeapAddress {
        self.target
    }
}

/// The write-barrier action for resolving a thunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ThunkResolveWriteBarrier {
    /// No generational collector is active for this tier.
    Disabled,
    /// The write does not create an old-to-young edge.
    NotRequired,
    /// The write must be recorded in the remembered set.
    Remember {
        /// The precise edge created by resolving the thunk.
        edge: RememberedEdge,
    },
}

impl ThunkResolveWriteBarrier {
    /// Returns whether the write can publish without recording a remembered edge.
    pub const fn permits_unrecorded_publish(self) -> bool {
        matches!(self, Self::Disabled | Self::NotRequired)
    }
}

/// A dirty card selected by a write barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GcDirtyCard {
    index: usize,
    source: GcHeapAddress,
}

impl GcDirtyCard {
    /// Creates a dirty-card marker for a source object.
    pub const fn new(index: usize, source: GcHeapAddress) -> Self {
        Self { index, source }
    }

    /// Returns the card index selected from the source object address.
    pub const fn index(self) -> usize {
        self.index
    }

    /// Returns the source object whose write dirtied this card.
    pub const fn source(self) -> GcHeapAddress {
        self.source
    }
}

/// A card-table marking result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GcCardTableUpdate {
    /// The card became dirty.
    MarkedDirty {
        /// The dirty-card marker that was inserted.
        card: GcDirtyCard,
    },
    /// The card was already dirty.
    AlreadyDirty {
        /// The already-present dirty-card marker.
        card: GcDirtyCard,
    },
}

/// A report for clearing dirty cards after a minor-GC commit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct GcCardTableClearReport {
    dirty_cards: usize,
}

impl GcCardTableClearReport {
    const fn new(dirty_cards: usize) -> Self {
        Self { dirty_cards }
    }

    /// Returns the number of dirty-card markers removed.
    pub const fn dirty_cards(self) -> usize {
        self.dirty_cards
    }
}

/// Default card size used by the safe daemon write-barrier model.
pub const DEFAULT_GC_CARD_SIZE_BYTES: usize = 512;

/// A read-only dirty-card view captured for minor-GC planning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcCardTableSnapshot<'a> {
    card_size_bytes: usize,
    dirty_cards: &'a [GcDirtyCard],
}

impl<'a> GcCardTableSnapshot<'a> {
    const fn new(card_size_bytes: usize, dirty_cards: &'a [GcDirtyCard]) -> Self {
        Self {
            card_size_bytes,
            dirty_cards,
        }
    }

    /// Returns the card size in bytes.
    pub const fn card_size_bytes(self) -> usize {
        self.card_size_bytes
    }

    /// Returns dirty cards in snapshot order.
    pub const fn dirty_cards(self) -> &'a [GcDirtyCard] {
        self.dirty_cards
    }

    /// Returns the card index selected from a source object address.
    pub const fn card_index_for_source(self, source: GcHeapAddress) -> usize {
        source.address_bits() / self.card_size_bytes
    }

    /// Returns whether this snapshot includes the source object's card.
    pub fn covers_source(self, source: GcHeapAddress) -> bool {
        let index = self.card_index_for_source(source);
        self.dirty_cards.iter().any(|dirty| dirty.index() == index)
    }
}

/// A safe card-table precursor for old/permanent-to-young writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GcCardTable {
    card_size_bytes: usize,
    dirty_cards: Vec<GcDirtyCard>,
}

impl Default for GcCardTable {
    fn default() -> Self {
        Self {
            card_size_bytes: DEFAULT_GC_CARD_SIZE_BYTES,
            dirty_cards: Vec::new(),
        }
    }
}

impl GcCardTable {
    /// Creates an empty card table.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError::InvalidGcCardSize`] if `card_size_bytes`
    /// is zero or not a power of two.
    pub fn new(card_size_bytes: usize) -> Result<Self, GenerationalGcError> {
        if card_size_bytes == 0 || !card_size_bytes.is_power_of_two() {
            return Err(GenerationalGcError::InvalidGcCardSize { card_size_bytes });
        }
        Ok(Self {
            card_size_bytes,
            dirty_cards: Vec::new(),
        })
    }

    /// Returns the card size in bytes.
    pub const fn card_size_bytes(&self) -> usize {
        self.card_size_bytes
    }

    /// Returns dirty cards in first-mark order.
    pub fn dirty_cards(&self) -> &[GcDirtyCard] {
        &self.dirty_cards
    }

    /// Returns a read-only snapshot for minor-GC planning.
    pub fn snapshot(&self) -> GcCardTableSnapshot<'_> {
        GcCardTableSnapshot::new(self.card_size_bytes, &self.dirty_cards)
    }

    /// Clones this card table while reporting allocation failure.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError::GcCardTableAllocationFailed`] if cloned
    /// dirty-card storage cannot be reserved.
    pub fn try_clone(&self) -> Result<Self, GenerationalGcError> {
        let mut dirty_cards = Vec::new();
        dirty_cards
            .try_reserve_exact(self.dirty_cards.len())
            .map_err(|_| GenerationalGcError::GcCardTableAllocationFailed {
                cards: self.dirty_cards.len(),
            })?;
        dirty_cards.extend(self.dirty_cards.iter().copied());
        Ok(Self {
            card_size_bytes: self.card_size_bytes,
            dirty_cards,
        })
    }

    /// Returns the number of dirty cards.
    pub fn len(&self) -> usize {
        self.dirty_cards.len()
    }

    /// Returns whether no cards are dirty.
    pub fn is_empty(&self) -> bool {
        self.dirty_cards.is_empty()
    }

    /// Returns the card marker for `source`.
    pub const fn card_for_source(&self, source: GcHeapAddress) -> GcDirtyCard {
        GcDirtyCard::new(source.address_bits() / self.card_size_bytes, source)
    }

    /// Marks the source object's card dirty.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError::GcCardTableLengthOverflow`] if the dirty
    /// card count overflows, or
    /// [`GenerationalGcError::GcCardTableAllocationFailed`] if card storage
    /// cannot be reserved.
    pub fn mark_source(
        &mut self,
        source: GcHeapAddress,
    ) -> Result<GcCardTableUpdate, GenerationalGcError> {
        let card = self.card_for_source(source);
        if let Some(card) = self
            .dirty_cards
            .iter()
            .copied()
            .find(|dirty| dirty.index() == card.index())
        {
            return Ok(GcCardTableUpdate::AlreadyDirty { card });
        }

        let cards = self
            .dirty_cards
            .len()
            .checked_add(1)
            .ok_or(GenerationalGcError::GcCardTableLengthOverflow)?;
        self.dirty_cards
            .try_reserve_exact(1)
            .map_err(|_| GenerationalGcError::GcCardTableAllocationFailed { cards })?;
        self.dirty_cards.push(card);
        Ok(GcCardTableUpdate::MarkedDirty { card })
    }

    /// Clears every dirty-card marker.
    pub fn clear_dirty_cards(&mut self) -> GcCardTableClearReport {
        let dirty_cards = self.dirty_cards.len();
        self.dirty_cards.clear();
        GcCardTableClearReport::new(dirty_cards)
    }
}

/// Classifies the generational write barrier for a thunk-resolution write.
pub const fn classify_thunk_resolve_write_barrier(
    tier: GenerationalGcTier,
    write: ThunkResolveWrite,
) -> ThunkResolveWriteBarrier {
    match tier {
        GenerationalGcTier::OneShotArena => ThunkResolveWriteBarrier::Disabled,
        GenerationalGcTier::DaemonGenerational => match write.value {
            ResolvedValueGeneration::Inline => ThunkResolveWriteBarrier::NotRequired,
            ResolvedValueGeneration::Heap {
                address: target,
                generation: HeapGeneration::Young,
            } if write.thunk_generation.needs_young_target_barrier() => {
                ThunkResolveWriteBarrier::Remember {
                    edge: RememberedEdge::new(write.thunk, target),
                }
            }
            ResolvedValueGeneration::Heap { .. } => ThunkResolveWriteBarrier::NotRequired,
        },
    }
}

/// A remembered-set insertion result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RememberedSetUpdate {
    /// The edge was newly inserted.
    Inserted,
    /// The same edge was already present.
    AlreadyPresent,
}

/// A collection epoch for remembered-set snapshots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RememberedSetEpoch {
    value: u64,
}

impl RememberedSetEpoch {
    /// Creates a remembered-set epoch from its raw counter value.
    pub const fn new(value: u64) -> Self {
        Self { value }
    }

    /// Returns the raw epoch counter value.
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Returns the next remembered-set epoch.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError::RememberedSetEpochOverflow`] if the epoch
    /// counter cannot advance.
    pub const fn checked_next(self) -> Result<Self, GenerationalGcError> {
        match self.value.checked_add(1) {
            Some(value) => Ok(Self { value }),
            None => Err(GenerationalGcError::RememberedSetEpochOverflow),
        }
    }
}

impl std::fmt::Display for RememberedSetEpoch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(formatter)
    }
}

/// A read-only remembered-set view captured for one minor-GC epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RememberedSetSnapshot<'a> {
    epoch: RememberedSetEpoch,
    edges: &'a [RememberedEdge],
}

impl<'a> RememberedSetSnapshot<'a> {
    const fn new(epoch: RememberedSetEpoch, edges: &'a [RememberedEdge]) -> Self {
        Self { epoch, edges }
    }

    /// Returns the remembered-set epoch this snapshot belongs to.
    pub const fn epoch(self) -> RememberedSetEpoch {
        self.epoch
    }

    /// Returns remembered edges in snapshot order.
    pub const fn edges(self) -> &'a [RememberedEdge] {
        self.edges
    }

    // `pub(super)`: the commit sibling validates staged snapshots directly.
    pub(super) fn validate_epoch(
        self,
        expected: RememberedSetEpoch,
    ) -> Result<Self, GenerationalGcError> {
        if self.epoch != expected {
            return Err(GenerationalGcError::RememberedSetEpochMismatch {
                expected,
                actual: self.epoch,
            });
        }
        Ok(self)
    }
}

/// A simple remembered set for old-to-young edges.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RememberedSet {
    // `pub(super)` fields: the plan-validation and commit siblings read
    // them directly (pre-split same-file access, module-explicit after §2).
    epoch: RememberedSetEpoch,
    pub(super) edges: Vec<RememberedEdge>,
}

impl RememberedSet {
    /// Creates an empty remembered set.
    pub const fn new() -> Self {
        Self::with_epoch(RememberedSetEpoch::new(0))
    }

    /// Creates an empty remembered set for `epoch`.
    pub const fn with_epoch(epoch: RememberedSetEpoch) -> Self {
        Self {
            epoch,
            edges: Vec::new(),
        }
    }

    /// Returns the collection epoch attached to this remembered set.
    pub const fn epoch(&self) -> RememberedSetEpoch {
        self.epoch
    }

    /// Returns remembered edges in insertion order.
    pub fn edges(&self) -> &[RememberedEdge] {
        &self.edges
    }

    /// Returns a read-only snapshot for minor-GC planning.
    pub fn snapshot(&self) -> RememberedSetSnapshot<'_> {
        RememberedSetSnapshot::new(self.epoch, &self.edges)
    }

    /// Clones this remembered set while reporting allocation failure.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError::RememberedSetAllocationFailed`] if cloned
    /// edge storage cannot be reserved.
    pub fn try_clone(&self) -> Result<Self, GenerationalGcError> {
        let mut edges = Vec::new();
        edges.try_reserve_exact(self.edges.len()).map_err(|_| {
            GenerationalGcError::RememberedSetAllocationFailed {
                edges: self.edges.len(),
            }
        })?;
        edges.extend(self.edges.iter().copied());
        Ok(Self {
            epoch: self.epoch,
            edges,
        })
    }

    /// Returns the number of remembered edges.
    pub fn len(&self) -> usize {
        self.edges.len()
    }

    /// Returns whether no edges have been remembered.
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// Records an old-to-young edge.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError::RememberedSetLengthOverflow`] if the edge
    /// count overflows, or [`GenerationalGcError::RememberedSetAllocationFailed`]
    /// if storage for the edge cannot be reserved.
    pub fn record(
        &mut self,
        edge: RememberedEdge,
    ) -> Result<RememberedSetUpdate, GenerationalGcError> {
        if self.edges.contains(&edge) {
            return Ok(RememberedSetUpdate::AlreadyPresent);
        }
        let edges = self
            .edges
            .len()
            .checked_add(1)
            .ok_or(GenerationalGcError::RememberedSetLengthOverflow)?;
        self.edges
            .try_reserve_exact(1)
            .map_err(|_| GenerationalGcError::RememberedSetAllocationFailed { edges })?;
        self.edges.push(edge);
        Ok(RememberedSetUpdate::Inserted)
    }
}
