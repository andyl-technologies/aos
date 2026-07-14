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

mod barrier;
mod commit;
mod errors;
mod minor_destination_types;
mod minor_rewrite_types;
mod plan_validation;

// Glob-import the validation helpers so sibling modules (the commit
// pipeline) resolve them through `use super::*`, as before the split.
use plan_validation::*;

pub use barrier::{
    DEFAULT_GC_CARD_SIZE_BYTES, GcCardTable, GcCardTableClearReport, GcCardTableSnapshot,
    GcCardTableUpdate, GcDirtyCard, GcHeapAddress, GenerationalGcTier, HeapGeneration,
    RememberedEdge, RememberedSet, RememberedSetEpoch, RememberedSetSnapshot, RememberedSetUpdate,
    ResolvedValueGeneration, ThunkResolveWrite, ThunkResolveWriteBarrier,
    classify_thunk_resolve_write_barrier,
};
pub use commit::{
    MinorGcCommitBuffers, MinorGcCommitPlan, MinorGcCommitReport, MinorGcOwnedCommitBuffers,
};
pub use errors::GenerationalGcError;
pub use minor_destination_types::{
    MinorGcDestinationAllocation, MinorGcDestinationAllocationPlan, MinorGcDestinationBases,
    MinorGcDestinationPlacement, MinorGcDestinationPlacementPlan, MinorGcObjectByteCopyBuffer,
    MinorGcObjectCopy, MinorGcObjectCopyPlan, MinorGcPromotionPolicy, MinorGcRelocation,
    MinorGcRelocationDestination, MinorGcRelocationDestinationPlan, MinorGcRelocationPlan,
    MinorGcSurvivor, MinorGcSurvivorAction, NurseryObjectAge, NurseryObjectFields,
    NurseryObjectLayout,
};
pub use minor_rewrite_types::{
    MinorGcForwardingPointer, MinorGcForwardingPointerPlan, MinorGcForwardingSlot,
    MinorGcReferenceRewrite, MinorGcReferenceRewritePlan, MinorGcRememberedSetRefresh,
    MinorGcRememberedSetRefreshAction, MinorGcRememberedSetRefreshPlan,
};

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

#[cfg(test)]
mod tests;
