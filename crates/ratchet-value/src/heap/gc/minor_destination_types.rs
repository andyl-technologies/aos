//! Minor-GC survivor and destination planning types: nursery ages/layouts,
//! promotion policy, destination allocation/placement plans, relocations,
//! and object byte-copy plans.
//!
//! Moved verbatim from `heap/gc.rs` under the RFC-0007 §2 file-size cap; the
//! parent re-exports every public path.

use super::*;

/// Minor-collection age metadata for one young-generation object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NurseryObjectAge {
    // `pub(super)` fields: the plan-validation and commit siblings read
    // them directly (pre-split same-file access, module-explicit after §2).
    pub(super) address: GcHeapAddress,
    pub(super) survived_minor_collections: u32,
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
    // `pub(super)` fields: the plan-validation and commit siblings read
    // them directly (pre-split same-file access, module-explicit after §2).
    pub(super) address: GcHeapAddress,
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
    // `pub(super)` fields: the plan-validation and commit siblings read
    // them directly (pre-split same-file access, module-explicit after §2).
    pub(super) address: GcHeapAddress,
    pub(super) size_bytes: usize,
    pub(super) align: usize,
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

    // `pub(super)`: the plan-validation sibling derives survivor actions.
    pub(super) const fn action_for_survivor(self, next_survivals: u32) -> MinorGcSurvivorAction {
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
    // `pub(super)` fields: literal-constructed by the plan-validation
    // sibling (pre-split same-file access, module-explicit after §2).
    pub(super) address: GcHeapAddress,
    pub(super) previous_survivals: u32,
    pub(super) next_survivals: u32,
    pub(super) action: MinorGcSurvivorAction,
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
    pub(super) survivor: MinorGcSurvivor,
    pub(super) size_bytes: usize,
    pub(super) align: usize,
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
    pub(super) allocations: Vec<MinorGcDestinationAllocation>,
    pub(super) nursery_bytes: usize,
    pub(super) old_bytes: usize,
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
    // `pub(super)` fields: the plan-validation and commit siblings read
    // them directly (pre-split same-file access, module-explicit after §2).
    pub(super) source: GcHeapAddress,
    pub(super) destination: GcHeapAddress,
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
    // `pub(super)` fields: the plan-validation and commit siblings read
    // them directly (pre-split same-file access, module-explicit after §2).
    source: GcHeapAddress,
    destination: GcHeapAddress,
    pub(super) source_bytes: &'a [u8],
    pub(super) destination_bytes: &'a mut [u8],
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
