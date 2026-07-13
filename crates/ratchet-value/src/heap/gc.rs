//! Generational-GC policy surfaces for runtime heap objects.
//!
//! The active runtime does not yet include the daemon collector. This module
//! defines precise policy surfaces for the future Tier-B daemon heap: the
//! write-barrier decision table for the one mutating Nix heap transition
//! (`Blackhole -> Forced(value)`) and minor-GC planning metadata for survivor
//! discovery, relocation, reference rewriting, and remembered-set refresh. The
//! barrier table is deliberately narrow so later collector code records
//! old-to-young edges and dirty source cards in one place instead of spreading
//! field-store barriers across immutable value constructors.

use crate::value::tag::POINTER_TAG_MASK;

mod old_field_rescan;
mod owned_destination;

pub use old_field_rescan::{
    MinorGcOldFieldRescan, MinorGcOldFieldRescanPlan, MinorGcOldObjectFields,
};
pub use owned_destination::{
    MinorGcOwnedDestinationStorage, MinorGcOwnedDestinationStorageCopyReport,
    MinorGcSourceObjectBytes,
};

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

    fn validate_epoch(self, expected: RememberedSetEpoch) -> Result<Self, GenerationalGcError> {
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
    epoch: RememberedSetEpoch,
    edges: Vec<RememberedEdge>,
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

/// Minor-collection age metadata for one young-generation object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NurseryObjectAge {
    address: GcHeapAddress,
    survived_minor_collections: u32,
}

impl NurseryObjectAge {
    /// Creates age metadata for a nursery object.
    pub const fn new(address: GcHeapAddress, survived_minor_collections: u32) -> Self {
        Self {
            address,
            survived_minor_collections,
        }
    }

    /// Returns the young-generation object address.
    pub const fn address(self) -> GcHeapAddress {
        self.address
    }

    /// Returns the number of minor collections already survived.
    pub const fn survived_minor_collections(self) -> u32 {
        self.survived_minor_collections
    }
}

/// Precise outgoing fields for one young-generation object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NurseryObjectFields<'a> {
    address: GcHeapAddress,
    fields: &'a [ResolvedValueGeneration],
}

impl<'a> NurseryObjectFields<'a> {
    /// Creates field metadata for a nursery object.
    pub const fn new(address: GcHeapAddress, fields: &'a [ResolvedValueGeneration]) -> Self {
        Self { address, fields }
    }

    /// Returns the young-generation object address.
    pub const fn address(self) -> GcHeapAddress {
        self.address
    }

    /// Returns precise outgoing field values.
    pub const fn fields(self) -> &'a [ResolvedValueGeneration] {
        self.fields
    }
}

/// Size and alignment metadata for one young-generation object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NurseryObjectLayout {
    address: GcHeapAddress,
    size_bytes: usize,
    align: usize,
}

impl NurseryObjectLayout {
    /// Creates layout metadata for a nursery object.
    pub const fn new(address: GcHeapAddress, size_bytes: usize, align: usize) -> Self {
        Self {
            address,
            size_bytes,
            align,
        }
    }

    /// Returns the young-generation object address.
    pub const fn address(self) -> GcHeapAddress {
        self.address
    }

    /// Returns the object size in bytes that must be copied or promoted.
    pub const fn size_bytes(self) -> usize {
        self.size_bytes
    }

    /// Returns the required destination alignment in bytes.
    pub const fn align(self) -> usize {
        self.align
    }
}

/// Age threshold that promotes nursery survivors into the old generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorGcPromotionPolicy {
    promote_after_survivals: u32,
}

impl MinorGcPromotionPolicy {
    /// Creates a promotion policy from a survivor-count threshold.
    ///
    /// A threshold of zero promotes every survivor immediately. A threshold of
    /// `N` promotes an object once the current minor collection would make its
    /// survived-minor count at least `N`.
    pub const fn new(promote_after_survivals: u32) -> Self {
        Self {
            promote_after_survivals,
        }
    }

    /// Returns the survivor-count threshold that triggers promotion.
    pub const fn promote_after_survivals(self) -> u32 {
        self.promote_after_survivals
    }

    const fn action_for_survivor(self, next_survivals: u32) -> MinorGcSurvivorAction {
        if next_survivals >= self.promote_after_survivals {
            MinorGcSurvivorAction::PromoteToOld
        } else {
            MinorGcSurvivorAction::CopyToNursery
        }
    }
}

/// The copying action selected for a live nursery object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MinorGcSurvivorAction {
    /// Copy the object to the next nursery semispace.
    CopyToNursery,
    /// Promote the object to the old generation.
    PromoteToOld,
}

/// One young object that a minor collection must preserve.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorGcSurvivor {
    address: GcHeapAddress,
    previous_survivals: u32,
    next_survivals: u32,
    action: MinorGcSurvivorAction,
}

impl MinorGcSurvivor {
    /// Returns the live young object address.
    pub const fn address(self) -> GcHeapAddress {
        self.address
    }

    /// Returns the survived-minor count before the current collection.
    pub const fn previous_survivals(self) -> u32 {
        self.previous_survivals
    }

    /// Returns the survived-minor count after the current collection.
    pub const fn next_survivals(self) -> u32 {
        self.next_survivals
    }

    /// Returns whether this survivor is copied or promoted.
    pub const fn action(self) -> MinorGcSurvivorAction {
        self.action
    }
}

/// One destination allocation requirement for a minor-GC survivor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorGcDestinationAllocation {
    survivor: MinorGcSurvivor,
    size_bytes: usize,
    align: usize,
}

impl MinorGcDestinationAllocation {
    /// Returns the survivor that needs destination storage.
    pub const fn survivor(self) -> MinorGcSurvivor {
        self.survivor
    }

    /// Returns the source nursery object address.
    pub const fn source(self) -> GcHeapAddress {
        self.survivor.address()
    }

    /// Returns whether this survivor will be copied or promoted.
    pub const fn action(self) -> MinorGcSurvivorAction {
        self.survivor.action()
    }

    /// Returns the generation that must receive the destination allocation.
    pub const fn destination_generation(self) -> HeapGeneration {
        match self.action() {
            MinorGcSurvivorAction::CopyToNursery => HeapGeneration::Young,
            MinorGcSurvivorAction::PromoteToOld => HeapGeneration::Old,
        }
    }

    /// Returns the destination allocation size in bytes.
    pub const fn size_bytes(self) -> usize {
        self.size_bytes
    }

    /// Returns the destination allocation alignment in bytes.
    pub const fn align(self) -> usize {
        self.align
    }
}

/// Destination allocation requirements for a planned minor collection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MinorGcDestinationAllocationPlan {
    allocations: Vec<MinorGcDestinationAllocation>,
    nursery_bytes: usize,
    old_bytes: usize,
}

impl MinorGcDestinationAllocationPlan {
    /// Builds destination allocation metadata from survivor and layout plans.
    ///
    /// Allocations are emitted in survivor-frontier order. The layout table must
    /// contain exactly one valid layout for each survivor source and no stale
    /// non-survivor entries. Copied survivors contribute to nursery bytes, while
    /// promoted survivors contribute to old-generation bytes.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if destination-allocation storage cannot
    /// be reserved, if a survivor has no layout, if layout metadata is
    /// duplicated or stale, if an object layout has a zero size or invalid
    /// alignment, or if byte totals overflow.
    pub fn from_minor_gc_plan(
        plan: &MinorGcPlan,
        layouts: &[NurseryObjectLayout],
    ) -> Result<Self, GenerationalGcError> {
        validate_unique_nursery_layouts(layouts)?;
        validate_nursery_layout_values(layouts)?;
        validate_nursery_layout_sources_are_live(plan, layouts)?;

        let mut allocations = Vec::new();
        let mut nursery_bytes = 0usize;
        let mut old_bytes = 0usize;
        for survivor in plan.survivors() {
            let layout = nursery_layout_for(layouts, survivor.address())?;
            match survivor.action() {
                MinorGcSurvivorAction::CopyToNursery => {
                    nursery_bytes = checked_add_destination_bytes(
                        nursery_bytes,
                        layout.size_bytes,
                        HeapGeneration::Young,
                    )?;
                }
                MinorGcSurvivorAction::PromoteToOld => {
                    old_bytes = checked_add_destination_bytes(
                        old_bytes,
                        layout.size_bytes,
                        HeapGeneration::Old,
                    )?;
                }
            };
            let allocations_len = allocations
                .len()
                .checked_add(1)
                .ok_or(GenerationalGcError::MinorGcDestinationAllocationLengthOverflow)?;
            allocations.try_reserve_exact(1).map_err(|_| {
                GenerationalGcError::MinorGcDestinationAllocationFailed {
                    allocations: allocations_len,
                }
            })?;
            allocations.push(MinorGcDestinationAllocation {
                survivor: *survivor,
                size_bytes: layout.size_bytes,
                align: layout.align,
            });
        }

        let _total_bytes = checked_add_destination_total_bytes(nursery_bytes, old_bytes)?;

        Ok(Self {
            allocations,
            nursery_bytes,
            old_bytes,
        })
    }

    /// Returns allocation requirements in survivor-frontier order.
    pub fn allocations(&self) -> &[MinorGcDestinationAllocation] {
        &self.allocations
    }

    /// Returns bytes requested from the next nursery semispace.
    pub const fn nursery_bytes(&self) -> usize {
        self.nursery_bytes
    }

    /// Returns bytes requested from old-generation storage.
    pub const fn old_bytes(&self) -> usize {
        self.old_bytes
    }

    /// Returns total destination bytes requested by all survivors.
    pub const fn total_bytes(&self) -> usize {
        self.nursery_bytes + self.old_bytes
    }

    /// Returns the number of destination allocations needed.
    pub fn len(&self) -> usize {
        self.allocations.len()
    }

    /// Returns whether no survivor destination allocations are needed.
    pub fn is_empty(&self) -> bool {
        self.allocations.is_empty()
    }
}

/// One aligned destination placement for a minor-GC survivor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorGcDestinationPlacement {
    allocation: MinorGcDestinationAllocation,
    offset_bytes: usize,
    end_offset_bytes: usize,
}

impl MinorGcDestinationPlacement {
    /// Returns the destination allocation requirement being placed.
    pub const fn allocation(self) -> MinorGcDestinationAllocation {
        self.allocation
    }

    /// Returns the survivor that needs destination storage.
    pub const fn survivor(self) -> MinorGcSurvivor {
        self.allocation.survivor()
    }

    /// Returns the source nursery object address.
    pub const fn source(self) -> GcHeapAddress {
        self.allocation.source()
    }

    /// Returns whether this survivor will be copied or promoted.
    pub const fn action(self) -> MinorGcSurvivorAction {
        self.allocation.action()
    }

    /// Returns the generation whose destination space owns this placement.
    pub const fn destination_generation(self) -> HeapGeneration {
        self.allocation.destination_generation()
    }

    /// Returns the aligned byte offset within the destination generation.
    pub const fn offset_bytes(self) -> usize {
        self.offset_bytes
    }

    /// Returns the byte offset immediately after this placed object.
    pub const fn end_offset_bytes(self) -> usize {
        self.end_offset_bytes
    }

    /// Returns the placed object size in bytes.
    pub const fn size_bytes(self) -> usize {
        self.allocation.size_bytes()
    }

    /// Returns the placed object alignment in bytes.
    pub const fn align(self) -> usize {
        self.allocation.align()
    }
}

/// Aligned destination-space offsets for a planned minor collection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MinorGcDestinationPlacementPlan {
    placements: Vec<MinorGcDestinationPlacement>,
    nursery_reserved_bytes: usize,
    old_reserved_bytes: usize,
}

impl MinorGcDestinationPlacementPlan {
    /// Builds aligned destination offsets from allocation requirements.
    ///
    /// Placements are emitted in survivor-frontier order. Copied survivors are
    /// packed into the next nursery destination space, promoted survivors are
    /// packed into old-generation destination space, and each generation's
    /// offset stream is aligned independently.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if placement storage cannot be reserved,
    /// if placement length overflows, if an allocation carries invalid
    /// alignment metadata, or if per-generation or aggregate reserved byte
    /// totals overflow.
    pub fn from_allocation_plan(
        allocation_plan: &MinorGcDestinationAllocationPlan,
    ) -> Result<Self, GenerationalGcError> {
        let mut placements = Vec::new();
        let mut nursery_reserved_bytes = 0usize;
        let mut old_reserved_bytes = 0usize;

        for allocation in allocation_plan.allocations() {
            let (generation, current) = match allocation.action() {
                MinorGcSurvivorAction::CopyToNursery => {
                    (HeapGeneration::Young, nursery_reserved_bytes)
                }
                MinorGcSurvivorAction::PromoteToOld => (HeapGeneration::Old, old_reserved_bytes),
            };
            let offset = align_destination_offset(current, allocation.align(), generation)?;
            let end_offset = checked_add_destination_placement_bytes(
                offset,
                allocation.size_bytes(),
                generation,
            )?;
            match allocation.action() {
                MinorGcSurvivorAction::CopyToNursery => nursery_reserved_bytes = end_offset,
                MinorGcSurvivorAction::PromoteToOld => old_reserved_bytes = end_offset,
            }

            let placements_len = placements
                .len()
                .checked_add(1)
                .ok_or(GenerationalGcError::MinorGcDestinationPlacementLengthOverflow)?;
            placements.try_reserve_exact(1).map_err(|_| {
                GenerationalGcError::MinorGcDestinationPlacementAllocationFailed {
                    placements: placements_len,
                }
            })?;
            placements.push(MinorGcDestinationPlacement {
                allocation: *allocation,
                offset_bytes: offset,
                end_offset_bytes: end_offset,
            });
        }

        let _total_reserved_bytes = checked_add_destination_placement_total_bytes(
            nursery_reserved_bytes,
            old_reserved_bytes,
        )?;

        Ok(Self {
            placements,
            nursery_reserved_bytes,
            old_reserved_bytes,
        })
    }

    /// Returns placements in survivor-frontier order.
    pub fn placements(&self) -> &[MinorGcDestinationPlacement] {
        &self.placements
    }

    /// Returns reserved bytes needed for the next nursery destination space.
    pub const fn nursery_reserved_bytes(&self) -> usize {
        self.nursery_reserved_bytes
    }

    /// Returns reserved bytes needed for old-generation destination space.
    pub const fn old_reserved_bytes(&self) -> usize {
        self.old_reserved_bytes
    }

    /// Returns total reserved destination bytes, including alignment padding.
    pub const fn total_reserved_bytes(&self) -> usize {
        self.nursery_reserved_bytes + self.old_reserved_bytes
    }

    /// Returns the number of destination placements.
    pub fn len(&self) -> usize {
        self.placements.len()
    }

    /// Returns whether no destination placements are needed.
    pub fn is_empty(&self) -> bool {
        self.placements.is_empty()
    }
}

/// Destination-space bases for materializing relocation addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorGcDestinationBases {
    nursery: GcHeapAddress,
    old: GcHeapAddress,
}

impl MinorGcDestinationBases {
    /// Creates destination-space base metadata.
    pub const fn new(nursery: GcHeapAddress, old: GcHeapAddress) -> Self {
        Self { nursery, old }
    }

    /// Returns the base address for copied nursery survivors.
    pub const fn nursery(self) -> GcHeapAddress {
        self.nursery
    }

    /// Returns the base address for promoted old-generation survivors.
    pub const fn old(self) -> GcHeapAddress {
        self.old
    }
}

/// Relocation destination metadata materialized from placement offsets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MinorGcRelocationDestinationPlan {
    destinations: Vec<MinorGcRelocationDestination>,
}

impl MinorGcRelocationDestinationPlan {
    /// Builds relocation destination metadata from an explicit destination table.
    ///
    /// The input table may be in any order. The returned plan is canonicalized
    /// into survivor-frontier order after validating that every live survivor has
    /// exactly one destination, no stale non-survivor source appears, no two
    /// survivors share a destination address, and no destination reuses a live
    /// from-space source address.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if relocation storage cannot be reserved
    /// or if the explicit destination table fails the same validation as
    /// [`MinorGcRelocationPlan::from_minor_gc_plan`].
    pub fn from_destinations(
        survivor_plan: &MinorGcPlan,
        destinations: &[MinorGcRelocationDestination],
    ) -> Result<Self, GenerationalGcError> {
        let relocation_plan =
            MinorGcRelocationPlan::from_minor_gc_plan(survivor_plan, destinations)?;
        let mut canonical = Vec::new();
        canonical
            .try_reserve_exact(relocation_plan.len())
            .map_err(
                |_| GenerationalGcError::MinorGcRelocationDestinationAllocationFailed {
                    destinations: relocation_plan.len(),
                },
            )?;
        for relocation in relocation_plan.relocations() {
            canonical.push(MinorGcRelocationDestination::new(
                relocation.source(),
                relocation.destination(),
            ));
        }
        Ok(Self {
            destinations: canonical,
        })
    }

    /// Builds relocation destination metadata from placement offsets and bases.
    ///
    /// Destinations are emitted in placement order. Copied survivors use the
    /// nursery base, promoted survivors use the old-generation base, and each
    /// placement's offset is checked against its selected base address.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if destination storage cannot be
    /// reserved, if destination count overflows, if `placement_plan` does not
    /// match `survivor_plan`, if adding a placement offset to its base address
    /// overflows, if materialized address bits fail [`GcHeapAddress`]
    /// validation, if a materialized destination does not satisfy its placement
    /// alignment, or if materialized destinations fail the same validation and
    /// storage reservation as [`MinorGcRelocationPlan::from_minor_gc_plan`].
    pub fn from_placement_plan(
        survivor_plan: &MinorGcPlan,
        placement_plan: &MinorGcDestinationPlacementPlan,
        bases: MinorGcDestinationBases,
    ) -> Result<Self, GenerationalGcError> {
        validate_placement_plan_matches_survivor_plan(survivor_plan, placement_plan)?;

        let mut destinations = Vec::new();
        for placement in placement_plan.placements() {
            let destination = materialized_destination_for(*placement, bases)?;
            let destinations_len = destinations
                .len()
                .checked_add(1)
                .ok_or(GenerationalGcError::MinorGcRelocationDestinationLengthOverflow)?;
            destinations.try_reserve_exact(1).map_err(|_| {
                GenerationalGcError::MinorGcRelocationDestinationAllocationFailed {
                    destinations: destinations_len,
                }
            })?;
            destinations.push(MinorGcRelocationDestination::new(
                placement.source(),
                destination,
            ));
        }
        MinorGcRelocationPlan::from_minor_gc_plan(survivor_plan, &destinations)?;
        Ok(Self { destinations })
    }

    /// Returns relocation destinations in placement order.
    pub fn destinations(&self) -> &[MinorGcRelocationDestination] {
        &self.destinations
    }

    /// Builds the validated relocation map for these materialized destinations.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if relocation storage cannot be reserved
    /// or if destination metadata no longer matches `survivor_plan`.
    pub fn relocation_plan(
        &self,
        survivor_plan: &MinorGcPlan,
    ) -> Result<MinorGcRelocationPlan, GenerationalGcError> {
        MinorGcRelocationPlan::from_minor_gc_plan(survivor_plan, &self.destinations)
    }

    /// Returns the number of materialized relocation destinations.
    pub fn len(&self) -> usize {
        self.destinations.len()
    }

    /// Returns whether no relocation destinations were materialized.
    pub fn is_empty(&self) -> bool {
        self.destinations.is_empty()
    }
}

/// Destination metadata for one live minor-GC survivor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorGcRelocationDestination {
    source: GcHeapAddress,
    destination: GcHeapAddress,
}

impl MinorGcRelocationDestination {
    /// Creates destination metadata for one young survivor.
    pub const fn new(source: GcHeapAddress, destination: GcHeapAddress) -> Self {
        Self {
            source,
            destination,
        }
    }

    /// Returns the source nursery object address.
    pub const fn source(self) -> GcHeapAddress {
        self.source
    }

    /// Returns the allocated destination address.
    pub const fn destination(self) -> GcHeapAddress {
        self.destination
    }
}

/// One planned minor-GC survivor relocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorGcRelocation {
    survivor: MinorGcSurvivor,
    destination: GcHeapAddress,
}

impl MinorGcRelocation {
    /// Returns the source nursery survivor.
    pub const fn survivor(self) -> MinorGcSurvivor {
        self.survivor
    }

    /// Returns the source nursery object address.
    pub const fn source(self) -> GcHeapAddress {
        self.survivor.address()
    }

    /// Returns the allocated destination address.
    pub const fn destination(self) -> GcHeapAddress {
        self.destination
    }

    /// Returns whether this survivor is copied or promoted.
    pub const fn action(self) -> MinorGcSurvivorAction {
        self.survivor.action()
    }

    /// Returns the generation that will own the relocated object.
    pub const fn destination_generation(self) -> HeapGeneration {
        match self.action() {
            MinorGcSurvivorAction::CopyToNursery => HeapGeneration::Young,
            MinorGcSurvivorAction::PromoteToOld => HeapGeneration::Old,
        }
    }

    /// Returns the relocated heap value metadata for this survivor.
    pub const fn relocated_value(self) -> ResolvedValueGeneration {
        ResolvedValueGeneration::Heap {
            address: self.destination,
            generation: self.destination_generation(),
        }
    }
}

/// A relocation map for a planned minor collection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MinorGcRelocationPlan {
    relocations: Vec<MinorGcRelocation>,
}

impl MinorGcRelocationPlan {
    /// Builds a relocation map from a survivor plan and destination table.
    ///
    /// Relocations are emitted in survivor-frontier order. The destination
    /// table must contain exactly one destination for each survivor source and
    /// no stale non-survivor source entries. Destination addresses must be
    /// unique so two survivors cannot be assigned the same copied/promoted
    /// address. Destination addresses must also be outside the live survivor
    /// source set, because from-space addresses cannot be reused as relocation
    /// targets.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if relocation storage cannot be
    /// reserved, if a survivor has no destination, if a destination source is
    /// duplicated or not present in the survivor plan, if two survivors share a
    /// destination address, or if any destination points at a live survivor
    /// source address.
    pub fn from_minor_gc_plan(
        plan: &MinorGcPlan,
        destinations: &[MinorGcRelocationDestination],
    ) -> Result<Self, GenerationalGcError> {
        validate_unique_relocation_sources(destinations)?;
        validate_unique_relocation_destinations(destinations)?;
        validate_relocation_sources_are_live(plan, destinations)?;
        validate_relocation_destinations_are_not_sources(plan, destinations)?;

        let mut relocations = Vec::new();
        for survivor in plan.survivors() {
            let destination =
                relocation_destination_for(destinations, survivor.address())?.destination();
            let relocations_len = relocations
                .len()
                .checked_add(1)
                .ok_or(GenerationalGcError::MinorGcRelocationLengthOverflow)?;
            relocations.try_reserve_exact(1).map_err(|_| {
                GenerationalGcError::MinorGcRelocationAllocationFailed {
                    relocations: relocations_len,
                }
            })?;
            relocations.push(MinorGcRelocation {
                survivor: *survivor,
                destination,
            });
        }

        Ok(Self { relocations })
    }

    /// Returns relocations in survivor-frontier order.
    pub fn relocations(&self) -> &[MinorGcRelocation] {
        &self.relocations
    }

    /// Returns the number of planned relocations.
    pub fn len(&self) -> usize {
        self.relocations.len()
    }

    /// Returns whether the relocation plan is empty.
    pub fn is_empty(&self) -> bool {
        self.relocations.is_empty()
    }
}

/// One planned object copy or promotion for a minor-GC survivor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorGcObjectCopy {
    relocation: MinorGcRelocation,
    size_bytes: usize,
    align: usize,
}

impl MinorGcObjectCopy {
    /// Returns the relocation whose bytes would be copied.
    pub const fn relocation(self) -> MinorGcRelocation {
        self.relocation
    }

    /// Returns the source nursery object address.
    pub const fn source(self) -> GcHeapAddress {
        self.relocation.source()
    }

    /// Returns the destination address for the copied or promoted object.
    pub const fn destination(self) -> GcHeapAddress {
        self.relocation.destination()
    }

    /// Returns whether this copy keeps the object young or promotes it.
    pub const fn action(self) -> MinorGcSurvivorAction {
        self.relocation.action()
    }

    /// Returns the generation that will own the copied or promoted object.
    pub const fn destination_generation(self) -> HeapGeneration {
        self.relocation.destination_generation()
    }

    /// Returns the relocated heap value metadata for this object copy.
    pub const fn relocated_value(self) -> ResolvedValueGeneration {
        self.relocation.relocated_value()
    }

    /// Returns the object size in bytes to copy.
    pub const fn size_bytes(self) -> usize {
        self.size_bytes
    }

    /// Returns the required destination alignment in bytes.
    pub const fn align(self) -> usize {
        self.align
    }
}

/// Caller-owned byte buffers for one planned minor-GC object copy.
#[derive(Debug)]
pub struct MinorGcObjectByteCopyBuffer<'a> {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    source_bytes: &'a [u8],
    destination_bytes: &'a mut [u8],
}

impl<'a> MinorGcObjectByteCopyBuffer<'a> {
    /// Creates byte-buffer metadata for one planned object copy.
    pub fn new(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        source_bytes: &'a [u8],
        destination_bytes: &'a mut [u8],
    ) -> Self {
        Self {
            source,
            destination,
            source_bytes,
            destination_bytes,
        }
    }

    /// Returns the source nursery object address.
    pub const fn source(&self) -> GcHeapAddress {
        self.source
    }

    /// Returns the destination object address.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns the source bytes to copy.
    pub const fn source_bytes(&self) -> &[u8] {
        self.source_bytes
    }

    /// Returns the current destination bytes.
    pub fn destination_bytes(&self) -> &[u8] {
        &*self.destination_bytes
    }
}

/// Object-copy metadata for a planned minor collection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MinorGcObjectCopyPlan {
    copies: Vec<MinorGcObjectCopy>,
}

impl MinorGcObjectCopyPlan {
    /// Builds copy metadata from relocations and nursery layouts.
    ///
    /// Copies are emitted in relocation order. The layout table must contain
    /// exactly one valid layout for each relocated source and no stale
    /// non-relocated entries. Copied survivors keep their young-generation
    /// destination, while promoted survivors use their old-generation
    /// destination.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if copy storage cannot be reserved, if
    /// the copy count overflows, if nursery layout metadata is missing,
    /// duplicated, invalid, or stale for `relocation_plan`, or if a relocation
    /// destination does not satisfy the source object's required alignment,
    /// overlaps another destination range, or overlaps a live source range.
    pub fn from_relocation_plan(
        relocation_plan: &MinorGcRelocationPlan,
        nursery_layouts: &[NurseryObjectLayout],
    ) -> Result<Self, GenerationalGcError> {
        validate_unique_nursery_layouts(nursery_layouts)?;
        validate_nursery_layout_values(nursery_layouts)?;
        validate_nursery_layout_sources_are_relocated(relocation_plan, nursery_layouts)?;

        let mut copies = Vec::new();
        for relocation in relocation_plan.relocations() {
            let layout = nursery_layout_for(nursery_layouts, relocation.source())?;
            validate_relocation_destination_alignment(*relocation, layout)?;
            let copies_len = copies
                .len()
                .checked_add(1)
                .ok_or(GenerationalGcError::MinorGcObjectCopyLengthOverflow)?;
            copies.try_reserve_exact(1).map_err(|_| {
                GenerationalGcError::MinorGcObjectCopyAllocationFailed { copies: copies_len }
            })?;
            copies.push(MinorGcObjectCopy {
                relocation: *relocation,
                size_bytes: layout.size_bytes(),
                align: layout.align(),
            });
        }
        validate_object_copy_destination_ranges_are_disjoint(&copies)?;
        validate_object_copy_destinations_do_not_overlap_sources(&copies)?;

        Ok(Self { copies })
    }

    /// Copies object bytes into caller-owned destination buffers.
    ///
    /// The supplied buffers must match the plan's copy count and copy order.
    /// Each buffer must name the expected source and destination address, and
    /// both source and destination byte slices must have exactly the planned
    /// object size. The method validates every buffer before copying any bytes,
    /// so validation failures leave all destination buffers unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if the buffer count differs from the
    /// plan, if a buffer names a different source or destination object, or if
    /// either source or destination byte length differs from the planned object
    /// size.
    pub fn copy_into_buffers(
        &self,
        buffers: &mut [MinorGcObjectByteCopyBuffer<'_>],
    ) -> Result<(), GenerationalGcError> {
        validate_object_byte_copy_buffers_match_plan(self, buffers)?;
        copy_object_byte_buffers(buffers);
        Ok(())
    }

    /// Returns copy metadata in relocation order.
    pub fn copies(&self) -> &[MinorGcObjectCopy] {
        &self.copies
    }

    /// Returns the number of planned object copies.
    pub fn len(&self) -> usize {
        self.copies.len()
    }

    /// Returns whether no object copies are planned.
    pub fn is_empty(&self) -> bool {
        self.copies.is_empty()
    }
}

/// One forwarding pointer that would be installed for a copied survivor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorGcForwardingPointer {
    copy: MinorGcObjectCopy,
}

impl MinorGcForwardingPointer {
    /// Returns the object-copy metadata that owns this forwarding pointer.
    pub const fn copy(self) -> MinorGcObjectCopy {
        self.copy
    }

    /// Returns the from-space object address to receive the forwarding pointer.
    pub const fn source(self) -> GcHeapAddress {
        self.copy.source()
    }

    /// Returns the relocated destination address stored by the pointer.
    pub const fn destination(self) -> GcHeapAddress {
        self.copy.destination()
    }

    /// Returns whether this forwarding pointer targets young or old space.
    pub const fn action(self) -> MinorGcSurvivorAction {
        self.copy.action()
    }

    /// Returns the generation stored in the forwarded heap value.
    pub const fn destination_generation(self) -> HeapGeneration {
        self.copy.destination_generation()
    }

    /// Returns the heap value metadata that the forwarding pointer represents.
    pub const fn forwarded_value(self) -> ResolvedValueGeneration {
        self.copy.relocated_value()
    }
}

/// A caller-owned forwarding slot for a from-space nursery object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorGcForwardingSlot {
    source: GcHeapAddress,
    forwarded: Option<ResolvedValueGeneration>,
}

impl MinorGcForwardingSlot {
    /// Creates an empty forwarding slot for `source`.
    pub const fn new(source: GcHeapAddress) -> Self {
        Self {
            source,
            forwarded: None,
        }
    }

    /// Creates an occupied forwarding slot for `source`.
    pub const fn with_forwarded_value(
        source: GcHeapAddress,
        forwarded: ResolvedValueGeneration,
    ) -> Self {
        Self {
            source,
            forwarded: Some(forwarded),
        }
    }

    /// Returns the from-space object that owns this slot.
    pub const fn source(self) -> GcHeapAddress {
        self.source
    }

    /// Returns the forwarded value installed in this slot, if any.
    pub const fn forwarded_value(self) -> Option<ResolvedValueGeneration> {
        self.forwarded
    }

    /// Returns whether the slot does not yet hold a forwarding value.
    pub const fn is_empty(self) -> bool {
        self.forwarded.is_none()
    }
}

/// Forwarding-pointer installation metadata for a planned minor collection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MinorGcForwardingPointerPlan {
    pointers: Vec<MinorGcForwardingPointer>,
}

impl MinorGcForwardingPointerPlan {
    /// Builds forwarding-pointer metadata from an object-copy schedule.
    ///
    /// Pointers are emitted in object-copy order. Each pointer records the
    /// from-space source object and the relocated young or old heap value that a
    /// later collector step would install in that object's forwarding slot.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if forwarding-pointer storage cannot be
    /// reserved or if the forwarding-pointer count overflows.
    pub fn from_object_copy_plan(
        copy_plan: &MinorGcObjectCopyPlan,
    ) -> Result<Self, GenerationalGcError> {
        let mut pointers = Vec::new();
        for copy in copy_plan.copies() {
            let pointers_len = pointers
                .len()
                .checked_add(1)
                .ok_or(GenerationalGcError::MinorGcForwardingPointerLengthOverflow)?;
            pointers.try_reserve_exact(1).map_err(|_| {
                GenerationalGcError::MinorGcForwardingPointerAllocationFailed {
                    pointers: pointers_len,
                }
            })?;
            pointers.push(MinorGcForwardingPointer { copy: *copy });
        }

        Ok(Self { pointers })
    }

    /// Installs forwarding values into caller-owned forwarding slots.
    ///
    /// The supplied slots must match the plan's pointer count and source order,
    /// and every slot must still be empty. The method validates every slot
    /// before writing any forwarding value, so validation failures leave all
    /// slots unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if the slot count differs from the plan,
    /// if a slot belongs to a different source object, or if any slot is already
    /// occupied.
    pub fn install_into_slots(
        &self,
        slots: &mut [MinorGcForwardingSlot],
    ) -> Result<(), GenerationalGcError> {
        validate_forwarding_slots_match_plan(self, slots)?;
        install_forwarding_slots(self, slots);
        Ok(())
    }

    /// Returns forwarding-pointer metadata in object-copy order.
    pub fn pointers(&self) -> &[MinorGcForwardingPointer] {
        &self.pointers
    }

    /// Returns the number of forwarding pointers to install.
    pub fn len(&self) -> usize {
        self.pointers.len()
    }

    /// Returns whether no forwarding pointers are planned.
    pub fn is_empty(&self) -> bool {
        self.pointers.is_empty()
    }
}

/// One root or field reference that must be rewritten after minor-GC relocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorGcReferenceRewrite {
    slot: usize,
    source: GcHeapAddress,
    destination: GcHeapAddress,
    destination_generation: HeapGeneration,
}

impl MinorGcReferenceRewrite {
    /// Returns the caller-supplied reference slot index.
    pub const fn slot(self) -> usize {
        self.slot
    }

    /// Returns the young from-space address currently stored in the slot.
    pub const fn source(self) -> GcHeapAddress {
        self.source
    }

    /// Returns the heap value metadata that must replace the old reference.
    pub const fn replacement(self) -> ResolvedValueGeneration {
        ResolvedValueGeneration::Heap {
            address: self.destination,
            generation: self.destination_generation,
        }
    }

    /// Returns the relocated address that must replace the old address.
    pub const fn destination(self) -> GcHeapAddress {
        self.destination
    }

    /// Returns the relocated object's generation after the minor collection.
    pub const fn destination_generation(self) -> HeapGeneration {
        self.destination_generation
    }
}

/// A root and field reference rewrite plan for a minor collection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MinorGcReferenceRewritePlan {
    rewrites: Vec<MinorGcReferenceRewrite>,
}

impl MinorGcReferenceRewritePlan {
    /// Builds rewrite metadata from scanned references and a relocation plan.
    ///
    /// The caller supplies a deterministic root/field reference sequence. Inline,
    /// old-generation, and permanent references are ignored. Every young
    /// reference must have a relocation entry, and duplicate references are kept
    /// as separate rewrites because each slot must be updated independently.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if rewrite storage cannot be reserved, if
    /// the reference slot index overflows, or if a young reference has no
    /// relocation in `relocation_plan`.
    pub fn from_references(
        relocation_plan: &MinorGcRelocationPlan,
        references: impl IntoIterator<Item = ResolvedValueGeneration>,
    ) -> Result<Self, GenerationalGcError> {
        let mut rewrites = Vec::new();
        let mut slot = 0usize;
        for reference in references {
            if let ResolvedValueGeneration::Heap {
                address,
                generation: HeapGeneration::Young,
            } = reference
            {
                let relocation = relocation_for(relocation_plan, address)?;
                let rewrites_len = rewrites
                    .len()
                    .checked_add(1)
                    .ok_or(GenerationalGcError::MinorGcReferenceRewriteLengthOverflow)?;
                rewrites.try_reserve_exact(1).map_err(|_| {
                    GenerationalGcError::MinorGcReferenceRewriteAllocationFailed {
                        rewrites: rewrites_len,
                    }
                })?;
                rewrites.push(MinorGcReferenceRewrite {
                    slot,
                    source: address,
                    destination: relocation.destination(),
                    destination_generation: relocation.destination_generation(),
                });
            }
            slot = slot
                .checked_add(1)
                .ok_or(GenerationalGcError::MinorGcReferenceSlotIndexOverflow)?;
        }

        Ok(Self { rewrites })
    }

    /// Applies planned rewrites to caller-owned reference slots.
    ///
    /// The method first validates that every planned slot exists and still
    /// contains the expected young from-space reference. If validation fails, no
    /// slot is rewritten. This helper mutates only the supplied slice; it does
    /// not know whether those slots are roots, object fields, or a test buffer.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if a planned slot is out of bounds or no
    /// longer contains the expected young from-space reference.
    pub fn apply_to_references(
        &self,
        references: &mut [ResolvedValueGeneration],
    ) -> Result<(), GenerationalGcError> {
        validate_reference_rewrite_slots_match_plan(self, references)?;
        apply_reference_rewrites(self, references);
        Ok(())
    }

    /// Returns rewrites in caller-supplied reference order.
    pub fn rewrites(&self) -> &[MinorGcReferenceRewrite] {
        &self.rewrites
    }

    /// Returns the number of reference slots that require rewriting.
    pub fn len(&self) -> usize {
        self.rewrites.len()
    }

    /// Returns whether no references require rewriting.
    pub fn is_empty(&self) -> bool {
        self.rewrites.is_empty()
    }
}

/// The post-minor-GC disposition for one remembered edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MinorGcRememberedSetRefreshAction {
    /// Retain the edge, rewritten to the copied young-generation destination.
    RetainCopiedYoung {
        /// The old/permanent-to-young edge to keep for the next minor epoch.
        refreshed: RememberedEdge,
    },
    /// Drop the edge because its young target was promoted into old generation.
    DropPromoted {
        /// The promoted old-generation destination.
        destination: GcHeapAddress,
    },
    /// Drop the edge because the young target has no relocation.
    DropDead,
}

/// One remembered-set edge refresh decision after a minor collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorGcRememberedSetRefresh {
    original: RememberedEdge,
    action: MinorGcRememberedSetRefreshAction,
}

impl MinorGcRememberedSetRefresh {
    /// Returns the remembered edge from the source epoch.
    pub const fn original(self) -> RememberedEdge {
        self.original
    }

    /// Returns the refresh action for the edge.
    pub const fn action(self) -> MinorGcRememberedSetRefreshAction {
        self.action
    }

    /// Returns the retained edge when this refresh keeps a copied-young target.
    pub const fn retained_edge(self) -> Option<RememberedEdge> {
        match self.action {
            MinorGcRememberedSetRefreshAction::RetainCopiedYoung { refreshed } => Some(refreshed),
            MinorGcRememberedSetRefreshAction::DropPromoted { .. }
            | MinorGcRememberedSetRefreshAction::DropDead => None,
        }
    }
}

/// A remembered-set refresh plan for the next minor-GC epoch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MinorGcRememberedSetRefreshPlan {
    source_epoch: RememberedSetEpoch,
    refreshes: Vec<MinorGcRememberedSetRefresh>,
}

impl MinorGcRememberedSetRefreshPlan {
    /// Builds remembered-set refresh metadata from a snapshot and relocations.
    ///
    /// Refreshes are emitted in remembered-edge snapshot order. Edges whose
    /// targets were copied to the next nursery are retained with the same source
    /// and rewritten young destination. Edges whose targets promoted to old
    /// generation are dropped, and edges whose targets have no relocation are
    /// treated as stale/dead remembered-set entries and also dropped.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if refresh storage cannot be reserved or
    /// if the refresh length overflows.
    pub fn from_snapshot(
        snapshot: RememberedSetSnapshot<'_>,
        relocation_plan: &MinorGcRelocationPlan,
    ) -> Result<Self, GenerationalGcError> {
        let mut refreshes = Vec::new();
        for edge in snapshot.edges() {
            let refreshes_len = refreshes
                .len()
                .checked_add(1)
                .ok_or(GenerationalGcError::MinorGcRememberedSetRefreshLengthOverflow)?;
            refreshes.try_reserve_exact(1).map_err(|_| {
                GenerationalGcError::MinorGcRememberedSetRefreshAllocationFailed {
                    refreshes: refreshes_len,
                }
            })?;
            refreshes.push(MinorGcRememberedSetRefresh {
                original: *edge,
                action: remembered_set_refresh_action(*edge, relocation_plan),
            });
        }

        Ok(Self {
            source_epoch: snapshot.epoch(),
            refreshes,
        })
    }

    /// Returns the remembered-set epoch consumed by this refresh plan.
    pub const fn source_epoch(&self) -> RememberedSetEpoch {
        self.source_epoch
    }

    /// Returns refresh decisions in remembered-edge snapshot order.
    pub fn refreshes(&self) -> &[MinorGcRememberedSetRefresh] {
        &self.refreshes
    }

    /// Returns retained old/permanent-to-young edges for the next minor epoch.
    pub fn retained_edges(&self) -> impl Iterator<Item = RememberedEdge> + '_ {
        self.refreshes
            .iter()
            .filter_map(|refresh| refresh.retained_edge())
    }

    /// Rebuilds the remembered set for the next minor-GC epoch.
    ///
    /// Only copied-young retained edges are inserted. Promoted and stale/dead
    /// targets are omitted because they no longer name young-generation objects
    /// that need minor-GC remembered edges.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError::RememberedSetEpochOverflow`] if the source
    /// epoch cannot advance. Returns [`GenerationalGcError`] if the rebuilt set
    /// cannot reserve storage for retained edges.
    pub fn rebuild_remembered_set(&self) -> Result<RememberedSet, GenerationalGcError> {
        let mut set = RememberedSet::with_epoch(self.source_epoch.checked_next()?);
        for edge in self.retained_edges() {
            set.record(edge)?;
        }
        Ok(set)
    }

    /// Rebuilds the remembered set after also rescanning dirty old fields.
    ///
    /// Retained copied-young edges from this refresh plan are inserted first.
    /// Edges discovered by the dirty-card rescan are inserted second through the
    /// same deduplicating remembered-set path, so rescanned duplicates do not
    /// perturb the retained snapshot order.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError::RememberedSetEpochOverflow`] if the source
    /// epoch cannot advance. Returns [`GenerationalGcError`] if the rebuilt set
    /// cannot reserve storage for retained or rescanned edges.
    pub fn rebuild_remembered_set_with_old_field_rescan(
        &self,
        old_field_rescan: &MinorGcOldFieldRescanPlan,
    ) -> Result<RememberedSet, GenerationalGcError> {
        let mut set = RememberedSet::with_epoch(self.source_epoch.checked_next()?);
        for edge in self
            .retained_edges()
            .chain(old_field_rescan.retained_edges())
        {
            set.record(edge)?;
        }
        Ok(set)
    }

    /// Returns the number of remembered edges examined.
    pub fn len(&self) -> usize {
        self.refreshes.len()
    }

    /// Returns whether the source remembered-set snapshot was empty.
    pub fn is_empty(&self) -> bool {
        self.refreshes.is_empty()
    }
}

/// A metadata commit plan for the ordered side effects of one minor collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinorGcCommitPlan {
    object_copies: MinorGcObjectCopyPlan,
    forwarding_pointers: MinorGcForwardingPointerPlan,
    reference_rewrites: MinorGcReferenceRewritePlan,
    remembered_set_refresh: MinorGcRememberedSetRefreshPlan,
    next_remembered_set: RememberedSet,
}

/// Caller-owned mutation buffers for applying one minor-GC commit plan.
pub struct MinorGcCommitBuffers<'a, 'bytes> {
    object_byte_copies: &'a mut [MinorGcObjectByteCopyBuffer<'bytes>],
    forwarding_slots: &'a mut [MinorGcForwardingSlot],
    references: &'a mut [ResolvedValueGeneration],
    remembered_set: &'a mut RememberedSet,
    card_table: Option<&'a mut GcCardTable>,
}

impl<'a, 'bytes> MinorGcCommitBuffers<'a, 'bytes> {
    /// Creates caller-owned buffers for a minor-GC commit application.
    pub fn new(
        object_byte_copies: &'a mut [MinorGcObjectByteCopyBuffer<'bytes>],
        forwarding_slots: &'a mut [MinorGcForwardingSlot],
        references: &'a mut [ResolvedValueGeneration],
        remembered_set: &'a mut RememberedSet,
    ) -> Self {
        Self {
            object_byte_copies,
            forwarding_slots,
            references,
            remembered_set,
            card_table: None,
        }
    }

    /// Creates caller-owned buffers plus a card table to clear after commit.
    pub fn with_card_table(
        object_byte_copies: &'a mut [MinorGcObjectByteCopyBuffer<'bytes>],
        forwarding_slots: &'a mut [MinorGcForwardingSlot],
        references: &'a mut [ResolvedValueGeneration],
        remembered_set: &'a mut RememberedSet,
        card_table: &'a mut GcCardTable,
    ) -> Self {
        Self {
            object_byte_copies,
            forwarding_slots,
            references,
            remembered_set,
            card_table: Some(card_table),
        }
    }
}

/// Caller-owned state for applying one minor-GC commit into owned destination storage.
pub struct MinorGcOwnedCommitBuffers<'a, 'bytes> {
    destination_storage: &'a mut MinorGcOwnedDestinationStorage,
    source_bytes: &'a [MinorGcSourceObjectBytes<'bytes>],
    forwarding_slots: &'a mut [MinorGcForwardingSlot],
    references: &'a mut [ResolvedValueGeneration],
    remembered_set: &'a mut RememberedSet,
    card_table: Option<&'a mut GcCardTable>,
}

impl<'a, 'bytes> MinorGcOwnedCommitBuffers<'a, 'bytes> {
    /// Creates caller-owned state for a minor-GC commit using owned destination storage.
    pub fn new(
        destination_storage: &'a mut MinorGcOwnedDestinationStorage,
        source_bytes: &'a [MinorGcSourceObjectBytes<'bytes>],
        forwarding_slots: &'a mut [MinorGcForwardingSlot],
        references: &'a mut [ResolvedValueGeneration],
        remembered_set: &'a mut RememberedSet,
    ) -> Self {
        Self {
            destination_storage,
            source_bytes,
            forwarding_slots,
            references,
            remembered_set,
            card_table: None,
        }
    }

    /// Creates caller-owned state plus a card table to clear after commit.
    pub fn with_card_table(
        destination_storage: &'a mut MinorGcOwnedDestinationStorage,
        source_bytes: &'a [MinorGcSourceObjectBytes<'bytes>],
        forwarding_slots: &'a mut [MinorGcForwardingSlot],
        references: &'a mut [ResolvedValueGeneration],
        remembered_set: &'a mut RememberedSet,
        card_table: &'a mut GcCardTable,
    ) -> Self {
        Self {
            destination_storage,
            source_bytes,
            forwarding_slots,
            references,
            remembered_set,
            card_table: Some(card_table),
        }
    }
}

/// A summary of mutations applied by a minor-GC commit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MinorGcCommitReport {
    object_copies: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    forwarding_pointers: usize,
    reference_rewrites: usize,
    remembered_set_source_epoch: RememberedSetEpoch,
    remembered_set_next_epoch: RememberedSetEpoch,
    remembered_set_source_edges: usize,
    remembered_set_published_edges: usize,
    card_table_dirty_cards_cleared: usize,
}

impl MinorGcCommitReport {
    fn from_commit_parts(
        object_copies: &MinorGcObjectCopyPlan,
        forwarding_pointers: &MinorGcForwardingPointerPlan,
        reference_rewrites: &MinorGcReferenceRewritePlan,
        remembered_set_refresh: &MinorGcRememberedSetRefreshPlan,
        next_remembered_set: &RememberedSet,
    ) -> Self {
        let mut copied_to_nursery = 0;
        let mut promoted_to_old = 0;
        for copy in object_copies.copies() {
            match copy.action() {
                MinorGcSurvivorAction::CopyToNursery => copied_to_nursery += 1,
                MinorGcSurvivorAction::PromoteToOld => promoted_to_old += 1,
            }
        }

        Self {
            object_copies: object_copies.len(),
            copied_to_nursery,
            promoted_to_old,
            forwarding_pointers: forwarding_pointers.len(),
            reference_rewrites: reference_rewrites.len(),
            remembered_set_source_epoch: remembered_set_refresh.source_epoch(),
            remembered_set_next_epoch: next_remembered_set.epoch(),
            remembered_set_source_edges: remembered_set_refresh.len(),
            remembered_set_published_edges: next_remembered_set.len(),
            card_table_dirty_cards_cleared: 0,
        }
    }

    /// Returns the number of object byte copies committed.
    pub const fn object_copies(self) -> usize {
        self.object_copies
    }

    /// Returns the number of survivors copied to the next nursery.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns the number of survivors promoted to old generation.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }

    /// Returns the number of forwarding pointers installed.
    pub const fn forwarding_pointers(self) -> usize {
        self.forwarding_pointers
    }

    /// Returns the number of root or field references rewritten.
    pub const fn reference_rewrites(self) -> usize {
        self.reference_rewrites
    }

    /// Returns the remembered-set epoch consumed by the commit.
    pub const fn remembered_set_source_epoch(self) -> RememberedSetEpoch {
        self.remembered_set_source_epoch
    }

    /// Returns the remembered-set epoch published by the commit.
    pub const fn remembered_set_next_epoch(self) -> RememberedSetEpoch {
        self.remembered_set_next_epoch
    }

    /// Returns the number of remembered edges examined from the source epoch.
    pub const fn remembered_set_source_edges(self) -> usize {
        self.remembered_set_source_edges
    }

    /// Returns the number of remembered edges published for the next epoch.
    pub const fn remembered_set_published_edges(self) -> usize {
        self.remembered_set_published_edges
    }

    /// Returns the number of dirty-card markers cleared after commit.
    pub const fn card_table_dirty_cards_cleared(self) -> usize {
        self.card_table_dirty_cards_cleared
    }
}

impl MinorGcCommitPlan {
    /// Builds a minor-GC commit plan from already validated subplans.
    ///
    /// The commit plan records the deterministic order a later collector
    /// implementation will use: copy/promote object bytes, install forwarding
    /// pointers, rewrite roots and fields, then publish the rebuilt remembered
    /// set for the next minor epoch. This remains metadata only and does not
    /// perform those mutations.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if any subplan does not match
    /// `object_copies`, if the remembered-set epoch cannot advance, or if
    /// rebuilding the next remembered set cannot reserve storage.
    pub fn from_parts(
        object_copies: MinorGcObjectCopyPlan,
        forwarding_pointers: MinorGcForwardingPointerPlan,
        reference_rewrites: MinorGcReferenceRewritePlan,
        remembered_set_refresh: MinorGcRememberedSetRefreshPlan,
    ) -> Result<Self, GenerationalGcError> {
        validate_forwarding_plan_matches_object_copies(&object_copies, &forwarding_pointers)?;
        validate_reference_rewrites_match_object_copies(&object_copies, &reference_rewrites)?;
        validate_remembered_set_refresh_matches_object_copies(
            &object_copies,
            &remembered_set_refresh,
        )?;
        let next_remembered_set = remembered_set_refresh.rebuild_remembered_set()?;

        Ok(Self {
            object_copies,
            forwarding_pointers,
            reference_rewrites,
            remembered_set_refresh,
            next_remembered_set,
        })
    }

    /// Builds a minor-GC commit plan that includes dirty old-field rescans.
    ///
    /// This validates the ordinary commit subplans, validates each dirty
    /// old/permanent field rescan decision against the object-copy schedule,
    /// and precomputes the next remembered set from both retained source
    /// snapshot edges and retained dirty-card rescan edges.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if any subplan or old-field rescan does
    /// not match `object_copies`, if the remembered-set epoch cannot advance, or
    /// if rebuilding the next remembered set cannot reserve storage.
    pub fn from_parts_with_old_field_rescan(
        object_copies: MinorGcObjectCopyPlan,
        forwarding_pointers: MinorGcForwardingPointerPlan,
        reference_rewrites: MinorGcReferenceRewritePlan,
        remembered_set_refresh: MinorGcRememberedSetRefreshPlan,
        old_field_rescan: &MinorGcOldFieldRescanPlan,
    ) -> Result<Self, GenerationalGcError> {
        validate_forwarding_plan_matches_object_copies(&object_copies, &forwarding_pointers)?;
        validate_reference_rewrites_match_object_copies(&object_copies, &reference_rewrites)?;
        validate_remembered_set_refresh_matches_object_copies(
            &object_copies,
            &remembered_set_refresh,
        )?;
        validate_old_field_rescan_matches_object_copies(&object_copies, old_field_rescan)?;
        let next_remembered_set = remembered_set_refresh
            .rebuild_remembered_set_with_old_field_rescan(old_field_rescan)?;

        Ok(Self {
            object_copies,
            forwarding_pointers,
            reference_rewrites,
            remembered_set_refresh,
            next_remembered_set,
        })
    }

    /// Returns object-copy metadata for the commit.
    pub fn object_copies(&self) -> &MinorGcObjectCopyPlan {
        &self.object_copies
    }

    /// Returns forwarding-pointer metadata for the commit.
    pub fn forwarding_pointers(&self) -> &MinorGcForwardingPointerPlan {
        &self.forwarding_pointers
    }

    /// Returns reference-rewrite metadata for the commit.
    pub fn reference_rewrites(&self) -> &MinorGcReferenceRewritePlan {
        &self.reference_rewrites
    }

    /// Returns remembered-set refresh metadata for the commit.
    pub fn remembered_set_refresh(&self) -> &MinorGcRememberedSetRefreshPlan {
        &self.remembered_set_refresh
    }

    /// Returns the rebuilt remembered set for the next minor-GC epoch.
    pub fn next_remembered_set(&self) -> &RememberedSet {
        &self.next_remembered_set
    }

    /// Applies this commit plan to caller-owned mutation buffers.
    ///
    /// The method validates every supplied buffer before making any mutation:
    /// object byte buffers must match the object-copy schedule, forwarding
    /// slots must match and be empty, planned reference slots must still contain
    /// the expected young from-space values, no unplanned young reference may be
    /// present, and the remembered set must still match the refresh source
    /// snapshot. If validation succeeds, mutations are applied in commit order:
    /// copy object bytes, install forwarding values, rewrite references, publish
    /// the next remembered set, then clear the card table when one is supplied.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if any caller-owned buffer no longer
    /// matches this commit plan.
    pub fn apply_to_buffers(
        self,
        buffers: MinorGcCommitBuffers<'_, '_>,
    ) -> Result<(), GenerationalGcError> {
        self.apply_to_buffers_with_report(buffers).map(|_| ())
    }

    /// Applies this commit plan and reports the committed mutation counts.
    ///
    /// This has the same validation and mutation order as
    /// [`Self::apply_to_buffers`], but returns a summary after the byte-copy,
    /// forwarding-pointer, reference-rewrite, remembered-set publication, and
    /// optional card-table clearing steps have all succeeded.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if any caller-owned buffer no longer
    /// matches this commit plan.
    pub fn apply_to_buffers_with_report(
        self,
        buffers: MinorGcCommitBuffers<'_, '_>,
    ) -> Result<MinorGcCommitReport, GenerationalGcError> {
        let Self {
            object_copies,
            forwarding_pointers,
            reference_rewrites,
            remembered_set_refresh,
            next_remembered_set,
        } = self;
        let MinorGcCommitBuffers {
            object_byte_copies,
            forwarding_slots,
            references,
            remembered_set,
            card_table,
        } = buffers;

        let mut report = MinorGcCommitReport::from_commit_parts(
            &object_copies,
            &forwarding_pointers,
            &reference_rewrites,
            &remembered_set_refresh,
            &next_remembered_set,
        );

        validate_object_byte_copy_buffers_match_plan(&object_copies, object_byte_copies)?;
        validate_forwarding_slots_match_plan(&forwarding_pointers, forwarding_slots)?;
        validate_reference_rewrite_commit_slots_match_plan(&reference_rewrites, references)?;
        validate_remembered_set_publication_source(&remembered_set_refresh, remembered_set)?;

        copy_object_byte_buffers(object_byte_copies);
        install_forwarding_slots(&forwarding_pointers, forwarding_slots);
        apply_reference_rewrites(&reference_rewrites, references);
        *remembered_set = next_remembered_set;
        if let Some(card_table) = card_table {
            report.card_table_dirty_cards_cleared = card_table.clear_dirty_cards().dirty_cards();
        }
        Ok(report)
    }

    /// Applies this commit plan to owned destination storage and caller-owned metadata slots.
    ///
    /// This is the owned-storage counterpart to [`Self::apply_to_buffers`].
    /// It validates the source-byte inventory against the destination storage
    /// and object-copy schedule, then validates forwarding slots, reference
    /// rewrites, unplanned young references, and remembered-set publication
    /// before making any mutation.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if the owned destination storage,
    /// source-byte inventory, forwarding slots, reference slots, or
    /// remembered-set state no longer match this commit plan.
    pub fn apply_to_owned_destination_storage(
        self,
        buffers: MinorGcOwnedCommitBuffers<'_, '_>,
    ) -> Result<(), GenerationalGcError> {
        self.apply_to_owned_destination_storage_with_report(buffers)
            .map(|_| ())
    }

    /// Applies this commit plan to owned destination storage and reports mutation counts.
    ///
    /// This has the same validation and mutation order as
    /// [`Self::apply_to_owned_destination_storage`], but returns a summary after
    /// destination byte copying, forwarding-pointer installation, reference
    /// rewriting, remembered-set publication, and optional card-table clearing.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if the owned destination storage,
    /// source-byte inventory, forwarding slots, reference slots, or
    /// remembered-set state no longer match this commit plan.
    pub fn apply_to_owned_destination_storage_with_report(
        self,
        buffers: MinorGcOwnedCommitBuffers<'_, '_>,
    ) -> Result<MinorGcCommitReport, GenerationalGcError> {
        let Self {
            object_copies,
            forwarding_pointers,
            reference_rewrites,
            remembered_set_refresh,
            next_remembered_set,
        } = self;
        let MinorGcOwnedCommitBuffers {
            destination_storage,
            source_bytes,
            forwarding_slots,
            references,
            remembered_set,
            card_table,
        } = buffers;

        let mut report = MinorGcCommitReport::from_commit_parts(
            &object_copies,
            &forwarding_pointers,
            &reference_rewrites,
            &remembered_set_refresh,
            &next_remembered_set,
        );

        destination_storage.validate_copy_from_sources(&object_copies, source_bytes)?;
        validate_forwarding_slots_match_plan(&forwarding_pointers, forwarding_slots)?;
        validate_reference_rewrite_commit_slots_match_plan(&reference_rewrites, references)?;
        validate_remembered_set_publication_source(&remembered_set_refresh, remembered_set)?;

        let _storage_report =
            destination_storage.copy_from_sources(&object_copies, source_bytes)?;
        install_forwarding_slots(&forwarding_pointers, forwarding_slots);
        apply_reference_rewrites(&reference_rewrites, references);
        *remembered_set = next_remembered_set;
        if let Some(card_table) = card_table {
            report.card_table_dirty_cards_cleared = card_table.clear_dirty_cards().dirty_cards();
        }
        Ok(report)
    }

    /// Publishes the rebuilt remembered set into caller-owned collector state.
    ///
    /// This consumes the commit plan because remembered-set publication is the
    /// final plan-owned metadata mutation represented by this helper. The
    /// method validates that `remembered_set` still matches the source epoch
    /// and edge sequence consumed by the refresh plan before replacing it with
    /// the precomputed next-epoch set.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError::MinorGcCommitRememberedSetPublicationEpochMismatch`]
    /// if the caller-owned remembered set is no longer on the epoch consumed by
    /// this commit plan. Returns [`GenerationalGcError`] if the caller-owned
    /// remembered-set edges no longer match the snapshot consumed by the plan.
    pub fn publish_next_remembered_set(
        self,
        remembered_set: &mut RememberedSet,
    ) -> Result<(), GenerationalGcError> {
        validate_remembered_set_publication_source(&self.remembered_set_refresh, remembered_set)?;
        *remembered_set = self.next_remembered_set;
        Ok(())
    }
}

/// A minor-collection frontier plan for the young generation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MinorGcPlan {
    survivors: Vec<MinorGcSurvivor>,
}

impl MinorGcPlan {
    /// Builds the initial young-object frontier for a minor collection.
    ///
    /// Inline, old-generation, and permanent roots do not enter the minor-GC
    /// frontier. Young roots and remembered-set targets are deduplicated in
    /// discovery order, then classified according to the promotion policy.
    /// The remembered-set snapshot must belong to `collection_epoch`. The
    /// caller still owns completeness: the snapshot must contain every current
    /// old/permanent-to-young edge and its targets must refer to objects still
    /// present in `nursery_objects`.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if frontier storage cannot be reserved,
    /// if the snapshot epoch does not match `collection_epoch`, if the frontier
    /// length overflows, if a young frontier object has no nursery age metadata,
    /// or if duplicate nursery age metadata is supplied.
    pub fn from_roots_and_remembered(
        roots: impl IntoIterator<Item = ResolvedValueGeneration>,
        remembered_set: RememberedSetSnapshot<'_>,
        collection_epoch: RememberedSetEpoch,
        nursery_objects: &[NurseryObjectAge],
        promotion_policy: MinorGcPromotionPolicy,
    ) -> Result<Self, GenerationalGcError> {
        validate_unique_nursery_objects(nursery_objects)?;
        let remembered_set = remembered_set.validate_epoch(collection_epoch)?;
        let mut frontier = MinorGcFrontier::new();
        for root in roots {
            if let ResolvedValueGeneration::Heap {
                address,
                generation: HeapGeneration::Young,
            } = root
            {
                frontier.insert(address)?;
            }
        }
        for edge in remembered_set.edges() {
            frontier.insert(edge.target())?;
        }

        survivors_from_frontier(frontier, nursery_objects, promotion_policy)
    }

    /// Builds a transitive young-object survivor plan for a minor collection.
    ///
    /// This extends [`MinorGcPlan::from_roots_and_remembered`] by expanding
    /// each reachable young object's precise outgoing fields. Inline, old, and
    /// permanent fields do not enter the minor-GC frontier. Young fields are
    /// deduplicated in discovery order and recursively expanded.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if the snapshot epoch does not match
    /// `collection_epoch`, if frontier or survivor storage cannot be reserved,
    /// if a live young object has no age or field metadata, or if duplicate
    /// nursery age or field metadata is supplied.
    pub fn from_roots_remembered_and_fields(
        roots: impl IntoIterator<Item = ResolvedValueGeneration>,
        remembered_set: RememberedSetSnapshot<'_>,
        collection_epoch: RememberedSetEpoch,
        nursery_objects: &[NurseryObjectAge],
        nursery_fields: &[NurseryObjectFields<'_>],
        promotion_policy: MinorGcPromotionPolicy,
    ) -> Result<Self, GenerationalGcError> {
        validate_unique_nursery_objects(nursery_objects)?;
        validate_unique_nursery_fields(nursery_fields)?;
        let remembered_set = remembered_set.validate_epoch(collection_epoch)?;
        let mut frontier = MinorGcFrontier::new();
        for root in roots {
            if let ResolvedValueGeneration::Heap {
                address,
                generation: HeapGeneration::Young,
            } = root
            {
                frontier.insert(address)?;
            }
        }
        for edge in remembered_set.edges() {
            frontier.insert(edge.target())?;
        }
        expand_young_fields(&mut frontier, nursery_fields)?;
        survivors_from_frontier(frontier, nursery_objects, promotion_policy)
    }

    /// Returns planned young-generation survivors in frontier order.
    pub fn survivors(&self) -> &[MinorGcSurvivor] {
        &self.survivors
    }

    /// Returns the number of live young objects in the initial frontier.
    pub fn len(&self) -> usize {
        self.survivors.len()
    }

    /// Returns whether the initial young-object frontier is empty.
    pub fn is_empty(&self) -> bool {
        self.survivors.is_empty()
    }
}

#[derive(Debug, Default)]
struct MinorGcFrontier {
    addresses: Vec<GcHeapAddress>,
}

impl MinorGcFrontier {
    const fn new() -> Self {
        Self {
            addresses: Vec::new(),
        }
    }

    fn insert(&mut self, address: GcHeapAddress) -> Result<(), GenerationalGcError> {
        if self.addresses.contains(&address) {
            return Ok(());
        }
        let objects = self
            .addresses
            .len()
            .checked_add(1)
            .ok_or(GenerationalGcError::MinorGcFrontierLengthOverflow)?;
        self.addresses
            .try_reserve_exact(1)
            .map_err(|_| GenerationalGcError::MinorGcFrontierAllocationFailed { objects })?;
        self.addresses.push(address);
        Ok(())
    }
}

fn validate_unique_nursery_objects(
    nursery_objects: &[NurseryObjectAge],
) -> Result<(), GenerationalGcError> {
    for (index, object) in nursery_objects.iter().enumerate() {
        if nursery_objects[index + 1..]
            .iter()
            .any(|other| other.address == object.address)
        {
            return Err(GenerationalGcError::DuplicateNurseryObjectAge {
                address: object.address,
            });
        }
    }
    Ok(())
}

fn validate_unique_nursery_fields(
    nursery_fields: &[NurseryObjectFields<'_>],
) -> Result<(), GenerationalGcError> {
    for (index, object) in nursery_fields.iter().enumerate() {
        if nursery_fields[index + 1..]
            .iter()
            .any(|other| other.address == object.address)
        {
            return Err(GenerationalGcError::DuplicateNurseryObjectFields {
                address: object.address,
            });
        }
    }
    Ok(())
}

fn validate_unique_nursery_layouts(
    nursery_layouts: &[NurseryObjectLayout],
) -> Result<(), GenerationalGcError> {
    for (index, object) in nursery_layouts.iter().enumerate() {
        if nursery_layouts[index + 1..]
            .iter()
            .any(|other| other.address == object.address)
        {
            return Err(GenerationalGcError::DuplicateNurseryObjectLayout {
                address: object.address,
            });
        }
    }
    Ok(())
}

fn validate_nursery_layout_values(
    nursery_layouts: &[NurseryObjectLayout],
) -> Result<(), GenerationalGcError> {
    for layout in nursery_layouts {
        if layout.size_bytes == 0 {
            return Err(GenerationalGcError::InvalidNurseryObjectSize {
                address: layout.address,
                size_bytes: layout.size_bytes,
            });
        }
        if layout.align == 0 || !layout.align.is_power_of_two() {
            return Err(GenerationalGcError::InvalidNurseryObjectAlignment {
                address: layout.address,
                align: layout.align,
            });
        }
    }
    Ok(())
}

fn validate_nursery_layout_sources_are_live(
    plan: &MinorGcPlan,
    nursery_layouts: &[NurseryObjectLayout],
) -> Result<(), GenerationalGcError> {
    for layout in nursery_layouts {
        if !plan
            .survivors()
            .iter()
            .any(|survivor| survivor.address() == layout.address)
        {
            return Err(GenerationalGcError::StaleNurseryObjectLayout {
                address: layout.address,
            });
        }
    }
    Ok(())
}

fn validate_unique_relocation_sources(
    destinations: &[MinorGcRelocationDestination],
) -> Result<(), GenerationalGcError> {
    for (index, destination) in destinations.iter().enumerate() {
        if destinations[index + 1..]
            .iter()
            .any(|other| other.source == destination.source)
        {
            return Err(GenerationalGcError::DuplicateMinorGcRelocationSource {
                address: destination.source,
            });
        }
    }
    Ok(())
}

fn validate_unique_relocation_destinations(
    destinations: &[MinorGcRelocationDestination],
) -> Result<(), GenerationalGcError> {
    for (index, destination) in destinations.iter().enumerate() {
        if destinations[index + 1..]
            .iter()
            .any(|other| other.destination == destination.destination)
        {
            return Err(GenerationalGcError::DuplicateMinorGcRelocationDestination {
                address: destination.destination,
            });
        }
    }
    Ok(())
}

fn validate_relocation_sources_are_live(
    plan: &MinorGcPlan,
    destinations: &[MinorGcRelocationDestination],
) -> Result<(), GenerationalGcError> {
    for destination in destinations {
        if !plan
            .survivors()
            .iter()
            .any(|survivor| survivor.address() == destination.source)
        {
            return Err(GenerationalGcError::StaleMinorGcRelocationSource {
                address: destination.source,
            });
        }
    }
    Ok(())
}

fn validate_relocation_destinations_are_not_sources(
    plan: &MinorGcPlan,
    destinations: &[MinorGcRelocationDestination],
) -> Result<(), GenerationalGcError> {
    for destination in destinations {
        if plan
            .survivors()
            .iter()
            .any(|survivor| survivor.address() == destination.destination)
        {
            return Err(
                GenerationalGcError::MinorGcRelocationDestinationInFromSpace {
                    from: destination.source,
                    destination: destination.destination,
                },
            );
        }
    }
    Ok(())
}

fn validate_placement_plan_matches_survivor_plan(
    survivor_plan: &MinorGcPlan,
    placement_plan: &MinorGcDestinationPlacementPlan,
) -> Result<(), GenerationalGcError> {
    let survivors = survivor_plan.survivors();
    let placements = placement_plan.placements();
    if survivors.len() != placements.len() {
        return Err(
            GenerationalGcError::MinorGcRelocationDestinationPlacementLengthMismatch {
                survivors: survivors.len(),
                placements: placements.len(),
            },
        );
    }

    for (survivor, placement) in survivors.iter().zip(placements) {
        if survivor.address() != placement.source() {
            return Err(
                GenerationalGcError::MinorGcRelocationDestinationPlacementSourceMismatch {
                    expected: survivor.address(),
                    actual: placement.source(),
                },
            );
        }
        if survivor.action() != placement.action() {
            return Err(
                GenerationalGcError::MinorGcRelocationDestinationPlacementActionMismatch {
                    address: survivor.address(),
                    expected: survivor.action(),
                    actual: placement.action(),
                },
            );
        }
    }

    Ok(())
}

fn validate_nursery_layout_sources_are_relocated(
    relocation_plan: &MinorGcRelocationPlan,
    nursery_layouts: &[NurseryObjectLayout],
) -> Result<(), GenerationalGcError> {
    for layout in nursery_layouts {
        if !relocation_plan
            .relocations()
            .iter()
            .any(|relocation| relocation.source() == layout.address)
        {
            return Err(GenerationalGcError::StaleNurseryObjectLayout {
                address: layout.address,
            });
        }
    }
    Ok(())
}

fn validate_relocation_destination_alignment(
    relocation: MinorGcRelocation,
    layout: NurseryObjectLayout,
) -> Result<(), GenerationalGcError> {
    if relocation.destination().address_bits() & (layout.align() - 1) != 0 {
        return Err(
            GenerationalGcError::MinorGcRelocationDestinationAlignmentMismatch {
                address: relocation.source(),
                generation: relocation.destination_generation(),
                destination: relocation.destination(),
                align: layout.align(),
            },
        );
    }
    Ok(())
}

fn validate_object_copy_destination_ranges_are_disjoint(
    copies: &[MinorGcObjectCopy],
) -> Result<(), GenerationalGcError> {
    for (index, copy) in copies.iter().enumerate() {
        let copy_end = object_copy_destination_end(*copy)?;
        for other in &copies[index + 1..] {
            let other_end = object_copy_destination_end(*other)?;
            if copy.destination().address_bits() < other_end
                && other.destination().address_bits() < copy_end
            {
                return Err(
                    GenerationalGcError::MinorGcObjectCopyDestinationRangeOverlap {
                        first_generation: copy.destination_generation(),
                        first: copy.destination(),
                        second_generation: other.destination_generation(),
                        second: other.destination(),
                    },
                );
            }
        }
    }
    Ok(())
}

fn validate_object_copy_destinations_do_not_overlap_sources(
    copies: &[MinorGcObjectCopy],
) -> Result<(), GenerationalGcError> {
    for destination_copy in copies {
        let destination_end = object_copy_destination_end(*destination_copy)?;
        for source_copy in copies {
            let source_end = object_copy_source_end(*source_copy)?;
            if destination_copy.destination().address_bits() < source_end
                && source_copy.source().address_bits() < destination_end
            {
                return Err(
                    GenerationalGcError::MinorGcObjectCopyDestinationSourceRangeOverlap {
                        source_address: source_copy.source(),
                        destination: destination_copy.destination(),
                    },
                );
            }
        }
    }
    Ok(())
}

fn object_copy_destination_end(copy: MinorGcObjectCopy) -> Result<usize, GenerationalGcError> {
    copy.destination()
        .address_bits()
        .checked_add(copy.size_bytes())
        .ok_or(
            GenerationalGcError::MinorGcObjectCopyDestinationAddressOverflow {
                generation: copy.destination_generation(),
                destination: copy.destination(),
                size_bytes: copy.size_bytes(),
            },
        )
}

fn object_copy_source_end(copy: MinorGcObjectCopy) -> Result<usize, GenerationalGcError> {
    copy.source()
        .address_bits()
        .checked_add(copy.size_bytes())
        .ok_or(
            GenerationalGcError::MinorGcObjectCopySourceAddressOverflow {
                address: copy.source(),
                size_bytes: copy.size_bytes(),
            },
        )
}

fn validate_object_byte_copy_buffers_match_plan(
    plan: &MinorGcObjectCopyPlan,
    buffers: &[MinorGcObjectByteCopyBuffer<'_>],
) -> Result<(), GenerationalGcError> {
    if plan.len() != buffers.len() {
        return Err(
            GenerationalGcError::MinorGcObjectByteCopyBufferLengthMismatch {
                copies: plan.len(),
                buffers: buffers.len(),
            },
        );
    }

    for (index, (copy, buffer)) in plan.copies().iter().zip(buffers).enumerate() {
        if copy.source() != buffer.source() {
            return Err(GenerationalGcError::MinorGcObjectByteCopySourceMismatch {
                index,
                expected: copy.source(),
                actual: buffer.source(),
            });
        }
        if copy.destination() != buffer.destination() {
            return Err(
                GenerationalGcError::MinorGcObjectByteCopyDestinationMismatch {
                    index,
                    expected: copy.destination(),
                    actual: buffer.destination(),
                },
            );
        }
        if copy.size_bytes() != buffer.source_bytes().len() {
            return Err(
                GenerationalGcError::MinorGcObjectByteCopySourceLengthMismatch {
                    index,
                    address: copy.source(),
                    expected: copy.size_bytes(),
                    actual: buffer.source_bytes().len(),
                },
            );
        }
        if copy.size_bytes() != buffer.destination_bytes().len() {
            return Err(
                GenerationalGcError::MinorGcObjectByteCopyDestinationLengthMismatch {
                    index,
                    address: copy.destination(),
                    expected: copy.size_bytes(),
                    actual: buffer.destination_bytes().len(),
                },
            );
        }
    }

    Ok(())
}

fn validate_forwarding_slots_match_plan(
    plan: &MinorGcForwardingPointerPlan,
    slots: &[MinorGcForwardingSlot],
) -> Result<(), GenerationalGcError> {
    if plan.len() != slots.len() {
        return Err(
            GenerationalGcError::MinorGcForwardingPointerSlotLengthMismatch {
                pointers: plan.len(),
                slots: slots.len(),
            },
        );
    }

    for (index, (pointer, slot)) in plan.pointers().iter().zip(slots).enumerate() {
        if pointer.source() != slot.source() {
            return Err(
                GenerationalGcError::MinorGcForwardingPointerSlotSourceMismatch {
                    index,
                    expected: pointer.source(),
                    actual: slot.source(),
                },
            );
        }
        if let Some(actual) = slot.forwarded_value() {
            return Err(GenerationalGcError::MinorGcForwardingPointerSlotOccupied {
                index,
                address: slot.source(),
                actual,
            });
        }
    }

    Ok(())
}

fn validate_reference_rewrite_slots_match_plan(
    plan: &MinorGcReferenceRewritePlan,
    references: &[ResolvedValueGeneration],
) -> Result<(), GenerationalGcError> {
    for rewrite in plan.rewrites() {
        validate_reference_rewrite_slot(*rewrite, references)?;
    }
    Ok(())
}

fn validate_reference_rewrite_commit_slots_match_plan(
    plan: &MinorGcReferenceRewritePlan,
    references: &[ResolvedValueGeneration],
) -> Result<(), GenerationalGcError> {
    validate_reference_rewrite_slots_match_plan(plan, references)?;
    for (slot, reference) in references.iter().copied().enumerate() {
        if let ResolvedValueGeneration::Heap {
            address,
            generation: HeapGeneration::Young,
        } = reference
        {
            let planned = plan.rewrites().iter().any(|rewrite| rewrite.slot() == slot);
            if !planned {
                return Err(
                    GenerationalGcError::MinorGcReferenceRewriteUnplannedYoungSlot {
                        slot,
                        address,
                    },
                );
            }
        }
    }
    Ok(())
}

fn copy_object_byte_buffers(buffers: &mut [MinorGcObjectByteCopyBuffer<'_>]) {
    for buffer in buffers {
        buffer
            .destination_bytes
            .copy_from_slice(buffer.source_bytes);
    }
}

fn install_forwarding_slots(
    plan: &MinorGcForwardingPointerPlan,
    slots: &mut [MinorGcForwardingSlot],
) {
    for (pointer, slot) in plan.pointers.iter().zip(slots) {
        slot.forwarded = Some(pointer.forwarded_value());
    }
}

fn apply_reference_rewrites(
    plan: &MinorGcReferenceRewritePlan,
    references: &mut [ResolvedValueGeneration],
) {
    for rewrite in plan.rewrites() {
        references[rewrite.slot()] = rewrite.replacement();
    }
}

fn validate_forwarding_plan_matches_object_copies(
    object_copies: &MinorGcObjectCopyPlan,
    forwarding_pointers: &MinorGcForwardingPointerPlan,
) -> Result<(), GenerationalGcError> {
    if object_copies.len() != forwarding_pointers.len() {
        return Err(
            GenerationalGcError::MinorGcCommitForwardingPointerLengthMismatch {
                copies: object_copies.len(),
                pointers: forwarding_pointers.len(),
            },
        );
    }

    for (index, (copy, pointer)) in object_copies
        .copies()
        .iter()
        .zip(forwarding_pointers.pointers())
        .enumerate()
    {
        let expected = MinorGcForwardingPointer { copy: *copy };
        if *pointer != expected {
            return Err(
                GenerationalGcError::MinorGcCommitForwardingPointerMismatch {
                    index,
                    expected,
                    actual: *pointer,
                },
            );
        }
    }

    Ok(())
}

fn validate_reference_rewrites_match_object_copies(
    object_copies: &MinorGcObjectCopyPlan,
    reference_rewrites: &MinorGcReferenceRewritePlan,
) -> Result<(), GenerationalGcError> {
    for rewrite in reference_rewrites.rewrites() {
        let copy = object_copy_for(object_copies, rewrite.source()).ok_or(
            GenerationalGcError::MinorGcCommitReferenceRewriteSourceMissing {
                address: rewrite.source(),
            },
        )?;
        let expected = copy.relocated_value();
        let actual = rewrite.replacement();
        if actual != expected {
            return Err(GenerationalGcError::MinorGcCommitReferenceRewriteMismatch {
                slot: rewrite.slot(),
                address: rewrite.source(),
                expected,
                actual,
            });
        }
    }

    Ok(())
}

fn validate_remembered_set_refresh_matches_object_copies(
    object_copies: &MinorGcObjectCopyPlan,
    remembered_set_refresh: &MinorGcRememberedSetRefreshPlan,
) -> Result<(), GenerationalGcError> {
    for refresh in remembered_set_refresh.refreshes() {
        let expected = expected_remembered_edge_action(object_copies, refresh.original());
        let actual = refresh.action();
        if actual != expected {
            return Err(
                GenerationalGcError::MinorGcCommitRememberedSetRefreshMismatch {
                    original: refresh.original(),
                    expected,
                    actual,
                },
            );
        }
    }

    Ok(())
}

fn validate_old_field_rescan_matches_object_copies(
    object_copies: &MinorGcObjectCopyPlan,
    old_field_rescan: &MinorGcOldFieldRescanPlan,
) -> Result<(), GenerationalGcError> {
    for rescan in old_field_rescan.rescans() {
        let expected = expected_remembered_edge_action(object_copies, rescan.original());
        let actual = rescan.action();
        if actual != expected {
            return Err(GenerationalGcError::MinorGcCommitOldFieldRescanMismatch {
                original: rescan.original(),
                expected,
                actual,
            });
        }
    }

    Ok(())
}

fn validate_remembered_set_publication_source(
    expected: &MinorGcRememberedSetRefreshPlan,
    actual: &RememberedSet,
) -> Result<(), GenerationalGcError> {
    if actual.epoch() != expected.source_epoch() {
        return Err(
            GenerationalGcError::MinorGcCommitRememberedSetPublicationEpochMismatch {
                expected: expected.source_epoch(),
                actual: actual.epoch(),
            },
        );
    }
    if actual.len() != expected.len() {
        return Err(
            GenerationalGcError::MinorGcCommitRememberedSetPublicationLengthMismatch {
                expected: expected.len(),
                actual: actual.len(),
            },
        );
    }
    for (index, (actual, expected)) in actual.edges().iter().zip(expected.refreshes()).enumerate() {
        let expected = expected.original();
        if *actual != expected {
            return Err(
                GenerationalGcError::MinorGcCommitRememberedSetPublicationEdgeMismatch {
                    index,
                    expected,
                    actual: *actual,
                },
            );
        }
    }
    Ok(())
}

fn expected_remembered_edge_action(
    object_copies: &MinorGcObjectCopyPlan,
    original: RememberedEdge,
) -> MinorGcRememberedSetRefreshAction {
    match object_copy_for(object_copies, original.target()) {
        Some(copy) if copy.action() == MinorGcSurvivorAction::CopyToNursery => {
            MinorGcRememberedSetRefreshAction::RetainCopiedYoung {
                refreshed: RememberedEdge::new(original.source(), copy.destination()),
            }
        }
        Some(copy) => MinorGcRememberedSetRefreshAction::DropPromoted {
            destination: copy.destination(),
        },
        None => MinorGcRememberedSetRefreshAction::DropDead,
    }
}

fn object_copy_for(
    object_copies: &MinorGcObjectCopyPlan,
    address: GcHeapAddress,
) -> Option<MinorGcObjectCopy> {
    object_copies
        .copies()
        .iter()
        .copied()
        .find(|copy| copy.source() == address)
}

fn nursery_age_for(
    nursery_objects: &[NurseryObjectAge],
    address: GcHeapAddress,
) -> Result<NurseryObjectAge, GenerationalGcError> {
    nursery_objects
        .iter()
        .copied()
        .find(|object| object.address == address)
        .ok_or(GenerationalGcError::MissingNurseryObjectAge { address })
}

fn nursery_layout_for(
    nursery_layouts: &[NurseryObjectLayout],
    address: GcHeapAddress,
) -> Result<NurseryObjectLayout, GenerationalGcError> {
    nursery_layouts
        .iter()
        .copied()
        .find(|object| object.address == address)
        .ok_or(GenerationalGcError::MissingNurseryObjectLayout { address })
}

fn checked_add_destination_bytes(
    current: usize,
    size_bytes: usize,
    generation: HeapGeneration,
) -> Result<usize, GenerationalGcError> {
    current
        .checked_add(size_bytes)
        .ok_or(GenerationalGcError::MinorGcDestinationBytesOverflow { generation })
}

fn checked_add_destination_total_bytes(
    nursery_bytes: usize,
    old_bytes: usize,
) -> Result<usize, GenerationalGcError> {
    nursery_bytes
        .checked_add(old_bytes)
        .ok_or(GenerationalGcError::MinorGcDestinationTotalBytesOverflow)
}

fn align_destination_offset(
    offset: usize,
    align: usize,
    generation: HeapGeneration,
) -> Result<usize, GenerationalGcError> {
    if align == 0 || !align.is_power_of_two() {
        return Err(
            GenerationalGcError::InvalidMinorGcDestinationPlacementAlignment { generation, align },
        );
    }
    let mask = align - 1;
    offset
        .checked_add(mask)
        .map(|offset| offset & !mask)
        .ok_or(GenerationalGcError::MinorGcDestinationPlacementBytesOverflow { generation })
}

fn checked_add_destination_placement_bytes(
    offset: usize,
    size_bytes: usize,
    generation: HeapGeneration,
) -> Result<usize, GenerationalGcError> {
    offset
        .checked_add(size_bytes)
        .ok_or(GenerationalGcError::MinorGcDestinationPlacementBytesOverflow { generation })
}

fn checked_add_destination_placement_total_bytes(
    nursery_reserved_bytes: usize,
    old_reserved_bytes: usize,
) -> Result<usize, GenerationalGcError> {
    nursery_reserved_bytes
        .checked_add(old_reserved_bytes)
        .ok_or(GenerationalGcError::MinorGcDestinationPlacementTotalBytesOverflow)
}

fn materialized_destination_for(
    placement: MinorGcDestinationPlacement,
    bases: MinorGcDestinationBases,
) -> Result<GcHeapAddress, GenerationalGcError> {
    let (generation, base) = match placement.action() {
        MinorGcSurvivorAction::CopyToNursery => (HeapGeneration::Young, bases.nursery()),
        MinorGcSurvivorAction::PromoteToOld => (HeapGeneration::Old, bases.old()),
    };
    let address_bits = base
        .address_bits()
        .checked_add(placement.offset_bytes())
        .ok_or(
            GenerationalGcError::MinorGcRelocationDestinationAddressOverflow {
                generation,
                base,
                offset: placement.offset_bytes(),
            },
        )?;
    let destination = GcHeapAddress::new(address_bits)?;
    validate_materialized_destination_alignment(placement, generation, destination)?;
    Ok(destination)
}

fn validate_materialized_destination_alignment(
    placement: MinorGcDestinationPlacement,
    generation: HeapGeneration,
    destination: GcHeapAddress,
) -> Result<(), GenerationalGcError> {
    let align = placement.align();
    if align == 0 || !align.is_power_of_two() {
        return Err(
            GenerationalGcError::InvalidMinorGcDestinationPlacementAlignment { generation, align },
        );
    }
    if destination.address_bits() & (align - 1) != 0 {
        return Err(
            GenerationalGcError::MinorGcRelocationDestinationAlignmentMismatch {
                address: placement.source(),
                generation,
                destination,
                align,
            },
        );
    }
    Ok(())
}

fn relocation_destination_for(
    destinations: &[MinorGcRelocationDestination],
    address: GcHeapAddress,
) -> Result<MinorGcRelocationDestination, GenerationalGcError> {
    destinations
        .iter()
        .copied()
        .find(|destination| destination.source == address)
        .ok_or(GenerationalGcError::MissingMinorGcRelocationDestination { address })
}

fn relocation_for(
    relocation_plan: &MinorGcRelocationPlan,
    address: GcHeapAddress,
) -> Result<MinorGcRelocation, GenerationalGcError> {
    optional_relocation_for(relocation_plan, address)
        .ok_or(GenerationalGcError::MissingMinorGcReferenceRelocation { address })
}

fn optional_relocation_for(
    relocation_plan: &MinorGcRelocationPlan,
    address: GcHeapAddress,
) -> Option<MinorGcRelocation> {
    relocation_plan
        .relocations()
        .iter()
        .copied()
        .find(|relocation| relocation.source() == address)
}

fn validate_reference_rewrite_slot(
    rewrite: MinorGcReferenceRewrite,
    references: &[ResolvedValueGeneration],
) -> Result<(), GenerationalGcError> {
    let actual = references.get(rewrite.slot()).copied().ok_or(
        GenerationalGcError::MinorGcReferenceRewriteSlotOutOfBounds {
            slot: rewrite.slot(),
            slots: references.len(),
        },
    )?;
    let expected = ResolvedValueGeneration::young(rewrite.source());
    if actual != expected {
        return Err(GenerationalGcError::MinorGcReferenceRewriteSlotMismatch {
            slot: rewrite.slot(),
            expected: rewrite.source(),
            actual,
        });
    }
    Ok(())
}

fn remembered_set_refresh_action(
    edge: RememberedEdge,
    relocation_plan: &MinorGcRelocationPlan,
) -> MinorGcRememberedSetRefreshAction {
    match optional_relocation_for(relocation_plan, edge.target()) {
        Some(relocation) if relocation.action() == MinorGcSurvivorAction::CopyToNursery => {
            MinorGcRememberedSetRefreshAction::RetainCopiedYoung {
                refreshed: RememberedEdge::new(edge.source(), relocation.destination()),
            }
        }
        Some(relocation) => MinorGcRememberedSetRefreshAction::DropPromoted {
            destination: relocation.destination(),
        },
        None => MinorGcRememberedSetRefreshAction::DropDead,
    }
}

fn nursery_fields_for<'a>(
    nursery_fields: &'a [NurseryObjectFields<'a>],
    address: GcHeapAddress,
) -> Result<&'a [ResolvedValueGeneration], GenerationalGcError> {
    nursery_fields
        .iter()
        .copied()
        .find(|object| object.address == address)
        .map(NurseryObjectFields::fields)
        .ok_or(GenerationalGcError::MissingNurseryObjectFields { address })
}

fn expand_young_fields(
    frontier: &mut MinorGcFrontier,
    nursery_fields: &[NurseryObjectFields<'_>],
) -> Result<(), GenerationalGcError> {
    let mut index = 0usize;
    while let Some(address) = frontier.addresses.get(index).copied() {
        for field in nursery_fields_for(nursery_fields, address)? {
            if let ResolvedValueGeneration::Heap {
                address,
                generation: HeapGeneration::Young,
            } = *field
            {
                frontier.insert(address)?;
            }
        }
        index += 1;
    }
    Ok(())
}

fn survivors_from_frontier(
    frontier: MinorGcFrontier,
    nursery_objects: &[NurseryObjectAge],
    promotion_policy: MinorGcPromotionPolicy,
) -> Result<MinorGcPlan, GenerationalGcError> {
    let mut survivors = Vec::new();
    for address in frontier.addresses {
        let age = nursery_age_for(nursery_objects, address)?;
        let next_survivals = age.survived_minor_collections.saturating_add(1);
        let action = promotion_policy.action_for_survivor(next_survivals);
        let survivors_len = survivors
            .len()
            .checked_add(1)
            .ok_or(GenerationalGcError::MinorGcSurvivorLengthOverflow)?;
        survivors.try_reserve_exact(1).map_err(|_| {
            GenerationalGcError::MinorGcSurvivorAllocationFailed {
                survivors: survivors_len,
            }
        })?;
        survivors.push(MinorGcSurvivor {
            address,
            previous_survivals: age.survived_minor_collections,
            next_survivals,
            action,
        });
    }

    Ok(MinorGcPlan { survivors })
}

/// Classifies and records the write barrier for a thunk-resolution write.
///
/// # Errors
///
/// Returns [`GenerationalGcError`] if the write requires a remembered edge and
/// the remembered set cannot reserve storage for it.
pub fn record_thunk_resolve_write_barrier(
    tier: GenerationalGcTier,
    write: ThunkResolveWrite,
    remembered_set: &mut RememberedSet,
) -> Result<ThunkResolveWriteBarrier, GenerationalGcError> {
    let action = classify_thunk_resolve_write_barrier(tier, write);
    if let ThunkResolveWriteBarrier::Remember { edge } = action {
        remembered_set.record(edge)?;
    }
    Ok(action)
}

/// Classifies and records the write barrier plus dirty source card.
///
/// # Errors
///
/// Returns [`GenerationalGcError`] if the write requires a remembered edge and
/// the remembered set or card table cannot reserve storage.
pub fn record_thunk_resolve_write_barrier_with_card_table(
    tier: GenerationalGcTier,
    write: ThunkResolveWrite,
    remembered_set: &mut RememberedSet,
    card_table: &mut GcCardTable,
) -> Result<ThunkResolveWriteBarrier, GenerationalGcError> {
    record_thunk_resolve_write_barrier_with_card_marker(tier, write, remembered_set, |source| {
        card_table.mark_source(source)
    })
}

fn record_thunk_resolve_write_barrier_with_card_marker(
    tier: GenerationalGcTier,
    write: ThunkResolveWrite,
    remembered_set: &mut RememberedSet,
    mark_source: impl FnOnce(GcHeapAddress) -> Result<GcCardTableUpdate, GenerationalGcError>,
) -> Result<ThunkResolveWriteBarrier, GenerationalGcError> {
    let action = classify_thunk_resolve_write_barrier(tier, write);
    if let ThunkResolveWriteBarrier::Remember { edge } = action {
        let remembered_update = remembered_set.record(edge)?;
        if let Err(error) = mark_source(edge.source()) {
            if remembered_update == RememberedSetUpdate::Inserted {
                if let Some(index) = remembered_set
                    .edges
                    .iter()
                    .position(|remembered| *remembered == edge)
                {
                    remembered_set.edges.remove(index);
                }
            }
            return Err(error);
        }
    }
    Ok(action)
}

/// A failed generational-GC policy or remembered-set operation.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum GenerationalGcError {
    /// A heap address decoded to zero.
    #[error("GC heap address is null")]
    NullAddress,
    /// A heap address still carried low pointer-tag bits.
    #[error("GC heap address still has low pointer-tag bits set: 0x{address_bits:x}")]
    LowTagBitsPresent {
        /// The rejected address bits.
        address_bits: usize,
    },
    /// The remembered-set edge count overflowed.
    #[error("remembered-set edge count overflow")]
    RememberedSetLengthOverflow,
    /// The remembered set could not reserve storage.
    #[error("failed to reserve {edges} remembered-set edges")]
    RememberedSetAllocationFailed {
        /// The requested remembered-set capacity.
        edges: usize,
    },
    /// A card table was created with an invalid card size.
    #[error("invalid GC card size {card_size_bytes}")]
    InvalidGcCardSize {
        /// The rejected card size in bytes.
        card_size_bytes: usize,
    },
    /// The card-table dirty-card count overflowed.
    #[error("GC card-table dirty-card count overflow")]
    GcCardTableLengthOverflow,
    /// The card table could not reserve storage.
    #[error("failed to reserve {cards} GC dirty-card entries")]
    GcCardTableAllocationFailed {
        /// The requested dirty-card capacity.
        cards: usize,
    },
    /// A remembered-set snapshot did not belong to the requested collection
    /// epoch.
    #[error("remembered-set snapshot epoch {actual} does not match collection epoch {expected}")]
    RememberedSetEpochMismatch {
        /// The minor-GC collection epoch being planned.
        expected: RememberedSetEpoch,
        /// The epoch attached to the remembered-set snapshot.
        actual: RememberedSetEpoch,
    },
    /// The remembered-set epoch counter overflowed.
    #[error("remembered-set epoch overflow")]
    RememberedSetEpochOverflow,
    /// The minor-GC frontier length overflowed.
    #[error("minor-GC frontier length overflow")]
    MinorGcFrontierLengthOverflow,
    /// The minor-GC frontier could not reserve storage.
    #[error("failed to reserve {objects} minor-GC frontier objects")]
    MinorGcFrontierAllocationFailed {
        /// The requested frontier capacity.
        objects: usize,
    },
    /// The minor-GC survivor plan length overflowed.
    #[error("minor-GC survivor length overflow")]
    MinorGcSurvivorLengthOverflow,
    /// The minor-GC survivor plan could not reserve storage.
    #[error("failed to reserve {survivors} minor-GC survivors")]
    MinorGcSurvivorAllocationFailed {
        /// The requested survivor-plan capacity.
        survivors: usize,
    },
    /// The minor-GC destination allocation plan length overflowed.
    #[error("minor-GC destination allocation length overflow")]
    MinorGcDestinationAllocationLengthOverflow,
    /// The minor-GC destination allocation plan could not reserve storage.
    #[error("failed to reserve {allocations} minor-GC destination allocations")]
    MinorGcDestinationAllocationFailed {
        /// The requested destination-allocation capacity.
        allocations: usize,
    },
    /// Minor-GC destination allocation bytes overflowed for one generation.
    #[error("minor-GC destination bytes overflowed for {generation:?}")]
    MinorGcDestinationBytesOverflow {
        /// The destination generation whose byte total overflowed.
        generation: HeapGeneration,
    },
    /// Minor-GC destination allocation bytes overflowed in aggregate.
    #[error("minor-GC total destination bytes overflowed")]
    MinorGcDestinationTotalBytesOverflow,
    /// The minor-GC destination placement plan length overflowed.
    #[error("minor-GC destination placement length overflow")]
    MinorGcDestinationPlacementLengthOverflow,
    /// The minor-GC destination placement plan could not reserve storage.
    #[error("failed to reserve {placements} minor-GC destination placements")]
    MinorGcDestinationPlacementAllocationFailed {
        /// The requested destination-placement capacity.
        placements: usize,
    },
    /// A destination placement carried invalid alignment metadata.
    #[error("invalid minor-GC destination placement alignment {align} for {generation:?}")]
    InvalidMinorGcDestinationPlacementAlignment {
        /// The destination generation being placed.
        generation: HeapGeneration,
        /// The rejected alignment in bytes.
        align: usize,
    },
    /// Minor-GC destination placement reserved bytes overflowed.
    #[error("minor-GC destination placement bytes overflowed for {generation:?}")]
    MinorGcDestinationPlacementBytesOverflow {
        /// The destination generation whose reserved byte total overflowed.
        generation: HeapGeneration,
    },
    /// Minor-GC destination placement reserved bytes overflowed in aggregate.
    #[error("minor-GC total destination placement bytes overflowed")]
    MinorGcDestinationPlacementTotalBytesOverflow,
    /// Owned minor-GC destination storage bytes overflowed.
    #[error("minor-GC destination storage bytes overflowed for {generation:?}")]
    MinorGcDestinationStorageBytesOverflow {
        /// The destination generation whose owned storage length overflowed.
        generation: HeapGeneration,
    },
    /// Owned minor-GC destination storage could not be reserved.
    #[error("failed to reserve {bytes} bytes of minor-GC destination storage for {generation:?}")]
    MinorGcDestinationStorageAllocationFailed {
        /// The destination generation being reserved.
        generation: HeapGeneration,
        /// The byte capacity requested for the owned storage buffer.
        bytes: usize,
    },
    /// Aligning an owned minor-GC destination storage base overflowed.
    #[error(
        "minor-GC destination storage base address overflowed for {generation:?} address 0x{address_bits:x} align {align}"
    )]
    MinorGcDestinationStorageBaseAddressOverflow {
        /// The destination generation whose base address overflowed.
        generation: HeapGeneration,
        /// The raw allocation address being aligned.
        address_bits: usize,
        /// The required base alignment in bytes.
        align: usize,
    },
    /// Owned minor-GC destination storage could not reserve validation metadata.
    #[error("failed to reserve {copies} minor-GC destination storage copy records")]
    MinorGcDestinationStorageCopyPlanAllocationFailed {
        /// The object-copy count being validated.
        copies: usize,
    },
    /// The object-copy plan did not match the owned destination placement count.
    #[error(
        "minor-GC destination storage copy count {copies} does not match placement count {placements}"
    )]
    MinorGcDestinationStorageCopyPlanLengthMismatch {
        /// The destination placement count.
        placements: usize,
        /// The object-copy count.
        copies: usize,
    },
    /// An object-copy plan did not preserve placement source order.
    #[error(
        "minor-GC destination storage copy source mismatch at index {index}: expected 0x{expected:x}, got 0x{actual:x}",
        expected = expected.address_bits(),
        actual = actual.address_bits()
    )]
    MinorGcDestinationStorageCopySourceMismatch {
        /// The mismatched copy index.
        index: usize,
        /// The source object expected by the placement plan.
        expected: GcHeapAddress,
        /// The source object found in the object-copy plan.
        actual: GcHeapAddress,
    },
    /// An object-copy plan carried a different copy/promote action.
    #[error(
        "minor-GC destination storage copy action mismatch for 0x{address:x}: expected {expected:?}, got {actual:?}",
        address = address.address_bits()
    )]
    MinorGcDestinationStorageCopyActionMismatch {
        /// The source object with mismatched copy action.
        address: GcHeapAddress,
        /// The action expected by the placement plan.
        expected: MinorGcSurvivorAction,
        /// The action found in the object-copy plan.
        actual: MinorGcSurvivorAction,
    },
    /// An object-copy plan carried a different destination address.
    #[error(
        "minor-GC destination storage copy destination mismatch for 0x{address:x}: expected 0x{expected:x}, got 0x{actual:x}",
        address = address.address_bits(),
        expected = expected.address_bits(),
        actual = actual.address_bits()
    )]
    MinorGcDestinationStorageCopyDestinationMismatch {
        /// The source object with mismatched destination metadata.
        address: GcHeapAddress,
        /// The destination projected from the placement plan.
        expected: GcHeapAddress,
        /// The destination found in the object-copy plan.
        actual: GcHeapAddress,
    },
    /// An object-copy plan carried a different object size.
    #[error(
        "minor-GC destination storage copy size mismatch for 0x{address:x}: expected {expected}, got {actual}",
        address = address.address_bits()
    )]
    MinorGcDestinationStorageCopySizeMismatch {
        /// The source object with mismatched size metadata.
        address: GcHeapAddress,
        /// The size expected by the placement plan.
        expected: usize,
        /// The size found in the object-copy plan.
        actual: usize,
    },
    /// An object-copy plan carried a different object alignment.
    #[error(
        "minor-GC destination storage copy alignment mismatch for 0x{address:x}: expected {expected}, got {actual}",
        address = address.address_bits()
    )]
    MinorGcDestinationStorageCopyAlignmentMismatch {
        /// The source object with mismatched alignment metadata.
        address: GcHeapAddress,
        /// The alignment expected by the placement plan.
        expected: usize,
        /// The alignment found in the object-copy plan.
        actual: usize,
    },
    /// A planned object copy targeted bytes outside owned destination storage.
    #[error(
        "minor-GC destination storage range for {generation:?} destination 0x{destination:x} size {size_bytes} is outside base 0x{base:x} reserved {reserved_bytes} bytes",
        destination = destination.address_bits(),
        base = base.address_bits()
    )]
    MinorGcDestinationStorageRangeOutOfBounds {
        /// The destination generation being written.
        generation: HeapGeneration,
        /// The owned storage base address for the destination generation.
        base: GcHeapAddress,
        /// The planned destination object address.
        destination: GcHeapAddress,
        /// The planned object size in bytes.
        size_bytes: usize,
        /// The reserved destination bytes for this generation.
        reserved_bytes: usize,
    },
    /// Two planned object copies overlapped in owned destination storage.
    #[error(
        "minor-GC destination storage ranges overlap in {generation:?}: 0x{first:x} and 0x{second:x}",
        first = first.address_bits(),
        second = second.address_bits()
    )]
    MinorGcDestinationStorageRangeOverlap {
        /// The destination generation with overlapping ranges.
        generation: HeapGeneration,
        /// The first overlapping destination object.
        first: GcHeapAddress,
        /// The second overlapping destination object.
        second: GcHeapAddress,
    },
    /// The source-byte inventory length did not match the object-copy plan.
    #[error("minor-GC source-byte count {sources} does not match object-copy count {copies}")]
    MinorGcSourceObjectBytesCountMismatch {
        /// The planned object-copy count.
        copies: usize,
        /// The supplied source-byte count.
        sources: usize,
    },
    /// A source-byte entry was supplied for a different object.
    #[error(
        "minor-GC source-byte object mismatch at index {index}: expected 0x{expected:x}, got 0x{actual:x}",
        expected = expected.address_bits(),
        actual = actual.address_bits()
    )]
    MinorGcSourceObjectBytesSourceMismatch {
        /// The mismatched source-byte index.
        index: usize,
        /// The source object expected by the object-copy plan.
        expected: GcHeapAddress,
        /// The source object found in the source-byte inventory.
        actual: GcHeapAddress,
    },
    /// A source-byte slice had the wrong length for a planned object copy.
    #[error(
        "minor-GC source-byte length {actual} for 0x{address:x} at index {index} does not match planned size {expected}",
        address = address.address_bits()
    )]
    MinorGcSourceObjectBytesLengthMismatch {
        /// The mismatched source-byte index.
        index: usize,
        /// The source object whose bytes were supplied.
        address: GcHeapAddress,
        /// The planned object size.
        expected: usize,
        /// The supplied source byte length.
        actual: usize,
    },
    /// The minor-GC relocation destination plan length overflowed.
    #[error("minor-GC relocation destination length overflow")]
    MinorGcRelocationDestinationLengthOverflow,
    /// The minor-GC relocation destination plan could not reserve storage.
    #[error("failed to reserve {destinations} minor-GC relocation destinations")]
    MinorGcRelocationDestinationAllocationFailed {
        /// The requested relocation-destination capacity.
        destinations: usize,
    },
    /// A destination placement plan did not match the survivor count.
    #[error(
        "minor-GC relocation destination placement count {placements} does not match survivor count {survivors}"
    )]
    MinorGcRelocationDestinationPlacementLengthMismatch {
        /// The survivor count in the minor-GC plan.
        survivors: usize,
        /// The placement count in the destination-placement plan.
        placements: usize,
    },
    /// A destination placement plan did not preserve survivor source order.
    #[error("minor-GC relocation destination placement source mismatch: expected 0x{expected:x}, got 0x{actual:x}", expected = expected.address_bits(), actual = actual.address_bits())]
    MinorGcRelocationDestinationPlacementSourceMismatch {
        /// The survivor source expected at this position.
        expected: GcHeapAddress,
        /// The placement source found at this position.
        actual: GcHeapAddress,
    },
    /// A destination placement action did not match the survivor action.
    #[error(
        "minor-GC relocation destination placement action mismatch for 0x{address:x}: expected {expected:?}, got {actual:?}",
        address = address.address_bits()
    )]
    MinorGcRelocationDestinationPlacementActionMismatch {
        /// The survivor source with mismatched action metadata.
        address: GcHeapAddress,
        /// The action from the survivor plan.
        expected: MinorGcSurvivorAction,
        /// The action from the placement plan.
        actual: MinorGcSurvivorAction,
    },
    /// Materializing a relocation destination address overflowed.
    #[error("minor-GC relocation destination address overflowed for {generation:?} base 0x{base:x} offset {offset}", base = base.address_bits())]
    MinorGcRelocationDestinationAddressOverflow {
        /// The destination generation being materialized.
        generation: HeapGeneration,
        /// The destination-space base address.
        base: GcHeapAddress,
        /// The placement offset in bytes.
        offset: usize,
    },
    /// A materialized relocation destination violated object alignment.
    #[error("minor-GC relocation destination 0x{destination:x} for 0x{address:x} is not {align}-byte aligned in {generation:?}", destination = destination.address_bits(), address = address.address_bits())]
    MinorGcRelocationDestinationAlignmentMismatch {
        /// The survivor source being placed.
        address: GcHeapAddress,
        /// The destination generation being materialized.
        generation: HeapGeneration,
        /// The misaligned relocation destination.
        destination: GcHeapAddress,
        /// The required object alignment in bytes.
        align: usize,
    },
    /// The minor-GC relocation plan length overflowed.
    #[error("minor-GC relocation length overflow")]
    MinorGcRelocationLengthOverflow,
    /// The minor-GC relocation plan could not reserve storage.
    #[error("failed to reserve {relocations} minor-GC relocations")]
    MinorGcRelocationAllocationFailed {
        /// The requested relocation-plan capacity.
        relocations: usize,
    },
    /// The minor-GC object-copy plan length overflowed.
    #[error("minor-GC object-copy length overflow")]
    MinorGcObjectCopyLengthOverflow,
    /// The minor-GC object-copy plan could not reserve storage.
    #[error("failed to reserve {copies} minor-GC object copies")]
    MinorGcObjectCopyAllocationFailed {
        /// The requested object-copy-plan capacity.
        copies: usize,
    },
    /// A planned object-copy destination address range overflowed.
    #[error(
        "minor-GC object-copy destination range overflowed for {generation:?} destination 0x{destination:x} size {size_bytes}",
        destination = destination.address_bits()
    )]
    MinorGcObjectCopyDestinationAddressOverflow {
        /// The destination generation being written.
        generation: HeapGeneration,
        /// The planned destination object address.
        destination: GcHeapAddress,
        /// The planned object size in bytes.
        size_bytes: usize,
    },
    /// A planned object-copy source address range overflowed.
    #[error(
        "minor-GC object-copy source range overflowed for source 0x{address:x} size {size_bytes}",
        address = address.address_bits()
    )]
    MinorGcObjectCopySourceAddressOverflow {
        /// The planned source object address.
        address: GcHeapAddress,
        /// The planned object size in bytes.
        size_bytes: usize,
    },
    /// Two planned object-copy destination ranges overlapped.
    #[error(
        "minor-GC object-copy destination ranges overlap: {first_generation:?} 0x{first:x} and {second_generation:?} 0x{second:x}",
        first = first.address_bits(),
        second = second.address_bits()
    )]
    MinorGcObjectCopyDestinationRangeOverlap {
        /// The first destination generation.
        first_generation: HeapGeneration,
        /// The first overlapping destination object.
        first: GcHeapAddress,
        /// The second destination generation.
        second_generation: HeapGeneration,
        /// The second overlapping destination object.
        second: GcHeapAddress,
    },
    /// A planned object-copy destination range overlapped from-space bytes.
    #[error(
        "minor-GC object-copy destination 0x{destination:x} overlaps source 0x{source:x}",
        destination = destination.address_bits(),
        source = source_address.address_bits()
    )]
    MinorGcObjectCopyDestinationSourceRangeOverlap {
        /// The live from-space source whose bytes would be reused.
        source_address: GcHeapAddress,
        /// The destination object address that overlaps from-space bytes.
        destination: GcHeapAddress,
    },
    /// An object-copy plan received the wrong number of caller-owned byte
    /// buffers.
    #[error("minor-GC object byte-copy buffer count {buffers} does not match copy count {copies}")]
    MinorGcObjectByteCopyBufferLengthMismatch {
        /// The planned object-copy count.
        copies: usize,
        /// The supplied byte-buffer count.
        buffers: usize,
    },
    /// An object-copy byte buffer belonged to a different source object.
    #[error(
        "minor-GC object byte-copy source mismatch at index {index}: expected 0x{expected:x}, got 0x{actual:x}",
        expected = expected.address_bits(),
        actual = actual.address_bits()
    )]
    MinorGcObjectByteCopySourceMismatch {
        /// The mismatched copy index.
        index: usize,
        /// The source object expected by the object-copy plan.
        expected: GcHeapAddress,
        /// The source object found in the caller-owned buffer.
        actual: GcHeapAddress,
    },
    /// An object-copy byte buffer belonged to a different destination object.
    #[error(
        "minor-GC object byte-copy destination mismatch at index {index}: expected 0x{expected:x}, got 0x{actual:x}",
        expected = expected.address_bits(),
        actual = actual.address_bits()
    )]
    MinorGcObjectByteCopyDestinationMismatch {
        /// The mismatched copy index.
        index: usize,
        /// The destination object expected by the object-copy plan.
        expected: GcHeapAddress,
        /// The destination object found in the caller-owned buffer.
        actual: GcHeapAddress,
    },
    /// An object-copy source byte slice had the wrong length.
    #[error(
        "minor-GC object byte-copy source length {actual} for 0x{address:x} at index {index} does not match planned size {expected}",
        address = address.address_bits()
    )]
    MinorGcObjectByteCopySourceLengthMismatch {
        /// The mismatched copy index.
        index: usize,
        /// The source object whose bytes were supplied.
        address: GcHeapAddress,
        /// The planned object size.
        expected: usize,
        /// The supplied source byte length.
        actual: usize,
    },
    /// An object-copy destination byte slice had the wrong length.
    #[error(
        "minor-GC object byte-copy destination length {actual} for 0x{address:x} at index {index} does not match planned size {expected}",
        address = address.address_bits()
    )]
    MinorGcObjectByteCopyDestinationLengthMismatch {
        /// The mismatched copy index.
        index: usize,
        /// The destination object whose buffer was supplied.
        address: GcHeapAddress,
        /// The planned object size.
        expected: usize,
        /// The supplied destination byte length.
        actual: usize,
    },
    /// The minor-GC forwarding-pointer plan length overflowed.
    #[error("minor-GC forwarding-pointer length overflow")]
    MinorGcForwardingPointerLengthOverflow,
    /// The minor-GC forwarding-pointer plan could not reserve storage.
    #[error("failed to reserve {pointers} minor-GC forwarding pointers")]
    MinorGcForwardingPointerAllocationFailed {
        /// The requested forwarding-pointer-plan capacity.
        pointers: usize,
    },
    /// A forwarding-pointer plan received the wrong number of caller-owned
    /// slots.
    #[error(
        "minor-GC forwarding-pointer slot count {slots} does not match pointer count {pointers}"
    )]
    MinorGcForwardingPointerSlotLengthMismatch {
        /// The planned forwarding-pointer count.
        pointers: usize,
        /// The supplied forwarding-slot count.
        slots: usize,
    },
    /// A forwarding-pointer slot belonged to a different source object.
    #[error(
        "minor-GC forwarding-pointer slot source mismatch at index {index}: expected 0x{expected:x}, got 0x{actual:x}",
        expected = expected.address_bits(),
        actual = actual.address_bits()
    )]
    MinorGcForwardingPointerSlotSourceMismatch {
        /// The mismatched slot index.
        index: usize,
        /// The source object expected by the forwarding-pointer plan.
        expected: GcHeapAddress,
        /// The source object found in the caller-owned slot.
        actual: GcHeapAddress,
    },
    /// A forwarding-pointer slot was already occupied.
    #[error(
        "minor-GC forwarding-pointer slot for 0x{address:x} at index {index} is already occupied by {actual:?}",
        address = address.address_bits()
    )]
    MinorGcForwardingPointerSlotOccupied {
        /// The occupied slot index.
        index: usize,
        /// The source object whose slot was already occupied.
        address: GcHeapAddress,
        /// The already-installed forwarding value.
        actual: ResolvedValueGeneration,
    },
    /// A minor-GC commit plan received mismatched copy and forwarding counts.
    #[error(
        "minor-GC commit forwarding-pointer count {pointers} does not match object-copy count {copies}"
    )]
    MinorGcCommitForwardingPointerLengthMismatch {
        /// The object-copy count.
        copies: usize,
        /// The forwarding-pointer count.
        pointers: usize,
    },
    /// A minor-GC commit plan received a forwarding pointer for another copy.
    #[error(
        "minor-GC commit forwarding pointer mismatch at index {index}: expected {expected:?}, got {actual:?}"
    )]
    MinorGcCommitForwardingPointerMismatch {
        /// The mismatched copy index.
        index: usize,
        /// The forwarding pointer projected from the object-copy plan.
        expected: MinorGcForwardingPointer,
        /// The caller-supplied forwarding pointer.
        actual: MinorGcForwardingPointer,
    },
    /// A minor-GC commit plan referenced an uncopied rewrite source.
    #[error("minor-GC commit reference rewrite source is not copied: 0x{address:x}", address = address.address_bits())]
    MinorGcCommitReferenceRewriteSourceMissing {
        /// The missing object-copy source address.
        address: GcHeapAddress,
    },
    /// A minor-GC commit plan received a rewrite for another relocation.
    #[error("minor-GC commit reference rewrite mismatch at slot {slot} for 0x{address:x}: expected {expected:?}, got {actual:?}", address = address.address_bits())]
    MinorGcCommitReferenceRewriteMismatch {
        /// The mismatched reference slot.
        slot: usize,
        /// The rewrite source address.
        address: GcHeapAddress,
        /// The relocated value projected from the object-copy plan.
        expected: ResolvedValueGeneration,
        /// The caller-supplied replacement value.
        actual: ResolvedValueGeneration,
    },
    /// A minor-GC commit plan received a remembered-set refresh decision from
    /// another relocation map.
    #[error(
        "minor-GC commit remembered-set refresh mismatch for {original:?}: expected {expected:?}, got {actual:?}"
    )]
    MinorGcCommitRememberedSetRefreshMismatch {
        /// The remembered edge being refreshed.
        original: RememberedEdge,
        /// The refresh action projected from the object-copy plan.
        expected: MinorGcRememberedSetRefreshAction,
        /// The caller-supplied refresh action.
        actual: MinorGcRememberedSetRefreshAction,
    },
    /// A minor-GC commit plan received a dirty old-field rescan decision from
    /// another relocation map.
    #[error(
        "minor-GC commit old-field rescan mismatch for {original:?}: expected {expected:?}, got {actual:?}"
    )]
    MinorGcCommitOldFieldRescanMismatch {
        /// The remembered edge discovered by rescanning a dirty old field.
        original: RememberedEdge,
        /// The rescan action projected from the object-copy plan.
        expected: MinorGcRememberedSetRefreshAction,
        /// The caller-supplied old-field rescan action.
        actual: MinorGcRememberedSetRefreshAction,
    },
    /// A minor-GC commit plan tried to publish into a remembered set from
    /// another epoch.
    #[error(
        "minor-GC commit remembered-set publication epoch {actual} does not match source epoch {expected}"
    )]
    MinorGcCommitRememberedSetPublicationEpochMismatch {
        /// The epoch consumed by the commit plan.
        expected: RememberedSetEpoch,
        /// The epoch currently held by the caller-owned remembered set.
        actual: RememberedSetEpoch,
    },
    /// A minor-GC commit plan tried to publish over a different remembered-set
    /// snapshot length.
    #[error(
        "minor-GC commit remembered-set publication length {actual} does not match source length {expected}"
    )]
    MinorGcCommitRememberedSetPublicationLengthMismatch {
        /// The edge count consumed by the commit plan.
        expected: usize,
        /// The edge count currently held by the caller-owned remembered set.
        actual: usize,
    },
    /// A minor-GC commit plan tried to publish over a different remembered-set
    /// edge.
    #[error(
        "minor-GC commit remembered-set publication edge mismatch at index {index}: expected {expected:?}, got {actual:?}"
    )]
    MinorGcCommitRememberedSetPublicationEdgeMismatch {
        /// The mismatched remembered-set edge index.
        index: usize,
        /// The edge consumed by the commit plan.
        expected: RememberedEdge,
        /// The edge currently held by the caller-owned remembered set.
        actual: RememberedEdge,
    },
    /// The minor-GC reference rewrite plan length overflowed.
    #[error("minor-GC reference rewrite length overflow")]
    MinorGcReferenceRewriteLengthOverflow,
    /// The minor-GC reference rewrite plan could not reserve storage.
    #[error("failed to reserve {rewrites} minor-GC reference rewrites")]
    MinorGcReferenceRewriteAllocationFailed {
        /// The requested reference-rewrite capacity.
        rewrites: usize,
    },
    /// The caller-supplied reference slot index overflowed.
    #[error("minor-GC reference slot index overflow")]
    MinorGcReferenceSlotIndexOverflow,
    /// An unplanned young reference appeared in a commit reference buffer.
    #[error("minor-GC reference rewrite found unplanned young slot {slot}: 0x{address:x}", address = address.address_bits())]
    MinorGcReferenceRewriteUnplannedYoungSlot {
        /// The unplanned reference slot index.
        slot: usize,
        /// The young from-space address found in the slot.
        address: GcHeapAddress,
    },
    /// A planned reference rewrite targeted a slot outside the supplied buffer.
    #[error("minor-GC reference rewrite slot {slot} is out of bounds for {slots} slots")]
    MinorGcReferenceRewriteSlotOutOfBounds {
        /// The planned slot index.
        slot: usize,
        /// The number of caller-supplied reference slots.
        slots: usize,
    },
    /// A planned reference rewrite found different slot contents.
    #[error("minor-GC reference rewrite slot {slot} expected young 0x{expected:x}, found {actual:?}", expected = expected.address_bits())]
    MinorGcReferenceRewriteSlotMismatch {
        /// The planned slot index.
        slot: usize,
        /// The expected young from-space address.
        expected: GcHeapAddress,
        /// The actual slot contents.
        actual: ResolvedValueGeneration,
    },
    /// The minor-GC remembered-set refresh plan length overflowed.
    #[error("minor-GC remembered-set refresh length overflow")]
    MinorGcRememberedSetRefreshLengthOverflow,
    /// The minor-GC remembered-set refresh plan could not reserve storage.
    #[error("failed to reserve {refreshes} minor-GC remembered-set refreshes")]
    MinorGcRememberedSetRefreshAllocationFailed {
        /// The requested remembered-set refresh capacity.
        refreshes: usize,
    },
    /// The dirty old-field rescan plan length overflowed.
    #[error("minor-GC old-field rescan length overflow")]
    MinorGcOldFieldRescanLengthOverflow,
    /// The dirty old-field rescan plan could not reserve storage.
    #[error("failed to reserve {rescans} minor-GC old-field rescans")]
    MinorGcOldFieldRescanAllocationFailed {
        /// The requested old-field rescan capacity.
        rescans: usize,
    },
    /// A young frontier object had no age metadata.
    #[error("missing nursery age metadata for 0x{address:x}", address = address.address_bits())]
    MissingNurseryObjectAge {
        /// The young object missing nursery metadata.
        address: GcHeapAddress,
    },
    /// A young object appeared more than once in the nursery age table.
    #[error("duplicate nursery age metadata for 0x{address:x}", address = address.address_bits())]
    DuplicateNurseryObjectAge {
        /// The duplicated young object.
        address: GcHeapAddress,
    },
    /// A live young object had no field metadata.
    #[error("missing nursery field metadata for 0x{address:x}", address = address.address_bits())]
    MissingNurseryObjectFields {
        /// The young object missing field metadata.
        address: GcHeapAddress,
    },
    /// A young object appeared more than once in the nursery field table.
    #[error("duplicate nursery field metadata for 0x{address:x}", address = address.address_bits())]
    DuplicateNurseryObjectFields {
        /// The duplicated young object.
        address: GcHeapAddress,
    },
    /// A live survivor had no nursery layout metadata.
    #[error("missing nursery layout metadata for 0x{address:x}", address = address.address_bits())]
    MissingNurseryObjectLayout {
        /// The survivor missing layout metadata.
        address: GcHeapAddress,
    },
    /// A young object appeared more than once in the nursery layout table.
    #[error("duplicate nursery layout metadata for 0x{address:x}", address = address.address_bits())]
    DuplicateNurseryObjectLayout {
        /// The duplicated young object.
        address: GcHeapAddress,
    },
    /// A nursery layout referenced an object outside the survivor plan.
    #[error("nursery layout source is not live: 0x{address:x}", address = address.address_bits())]
    StaleNurseryObjectLayout {
        /// The non-survivor source address.
        address: GcHeapAddress,
    },
    /// A nursery layout had an invalid object size.
    #[error("invalid nursery object size {size_bytes} for 0x{address:x}", address = address.address_bits())]
    InvalidNurseryObjectSize {
        /// The object with invalid layout metadata.
        address: GcHeapAddress,
        /// The rejected size in bytes.
        size_bytes: usize,
    },
    /// A nursery layout had an invalid object alignment.
    #[error("invalid nursery object alignment {align} for 0x{address:x}", address = address.address_bits())]
    InvalidNurseryObjectAlignment {
        /// The object with invalid layout metadata.
        address: GcHeapAddress,
        /// The rejected alignment in bytes.
        align: usize,
    },
    /// A live survivor had no relocation destination metadata.
    #[error("missing minor-GC relocation destination for 0x{address:x}", address = address.address_bits())]
    MissingMinorGcRelocationDestination {
        /// The survivor missing relocation metadata.
        address: GcHeapAddress,
    },
    /// A survivor source appeared more than once in the relocation table.
    #[error("duplicate minor-GC relocation source for 0x{address:x}", address = address.address_bits())]
    DuplicateMinorGcRelocationSource {
        /// The duplicated survivor source.
        address: GcHeapAddress,
    },
    /// Two survivor sources were assigned the same relocation destination.
    #[error("duplicate minor-GC relocation destination 0x{address:x}", address = address.address_bits())]
    DuplicateMinorGcRelocationDestination {
        /// The duplicated relocation destination.
        address: GcHeapAddress,
    },
    /// A relocation source referenced an object outside the survivor plan.
    #[error("minor-GC relocation source is not live: 0x{address:x}", address = address.address_bits())]
    StaleMinorGcRelocationSource {
        /// The non-survivor source address.
        address: GcHeapAddress,
    },
    /// A survivor was assigned a destination that is still in from-space.
    #[error("minor-GC relocation for 0x{from:x} points into from-space at 0x{destination:x}", from = from.address_bits(), destination = destination.address_bits())]
    MinorGcRelocationDestinationInFromSpace {
        /// The source survivor being relocated.
        from: GcHeapAddress,
        /// The invalid destination address.
        destination: GcHeapAddress,
    },
    /// A young root or field reference had no relocation metadata.
    #[error("missing minor-GC reference relocation for 0x{address:x}", address = address.address_bits())]
    MissingMinorGcReferenceRelocation {
        /// The young reference missing relocation metadata.
        address: GcHeapAddress,
    },
}

#[cfg(test)]
mod tests;
