//! Dirty old-field rescanning for minor-GC remembered-set rebuilds.
//!
//! A minor collection can retain copied-young remembered edges from the previous
//! remembered-set snapshot, but dirty old/permanent objects also need a precise
//! field rescan. This module models that rescan over caller-owned field slices
//! and the already validated relocation map.

use super::{
    GcCardTableSnapshot, GcHeapAddress, GenerationalGcError, HeapGeneration, MinorGcRelocation,
    MinorGcRelocationPlan, MinorGcRememberedSetRefreshAction, RememberedEdge,
    ResolvedValueGeneration,
};

/// Precise fields for one old or permanent object considered during rescan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinorGcOldObjectFields<'a> {
    source: GcHeapAddress,
    source_generation: HeapGeneration,
    fields: &'a [ResolvedValueGeneration],
}

impl<'a> MinorGcOldObjectFields<'a> {
    /// Creates old-object field metadata for dirty-card rescanning.
    pub const fn new(
        source: GcHeapAddress,
        source_generation: HeapGeneration,
        fields: &'a [ResolvedValueGeneration],
    ) -> Self {
        Self {
            source,
            source_generation,
            fields,
        }
    }

    /// Returns the object whose fields are being scanned.
    pub const fn source(self) -> GcHeapAddress {
        self.source
    }

    /// Returns the generation that owns the source object.
    pub const fn source_generation(self) -> HeapGeneration {
        self.source_generation
    }

    /// Returns precise outgoing field values for the source object.
    pub const fn fields(self) -> &'a [ResolvedValueGeneration] {
        self.fields
    }
}

/// One dirty old/permanent field classification after a minor collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorGcOldFieldRescan {
    source: GcHeapAddress,
    field_index: usize,
    original: RememberedEdge,
    action: MinorGcRememberedSetRefreshAction,
}

impl MinorGcOldFieldRescan {
    /// Returns the old or permanent source object that owned the field.
    pub const fn source(self) -> GcHeapAddress {
        self.source
    }

    /// Returns the precise field index within the source object.
    pub const fn field_index(self) -> usize {
        self.field_index
    }

    /// Returns the original old/permanent-to-young field edge.
    pub const fn original(self) -> RememberedEdge {
        self.original
    }

    /// Returns how the field contributes to the next remembered set.
    pub const fn action(self) -> MinorGcRememberedSetRefreshAction {
        self.action
    }

    /// Returns the retained copied-young edge, if the rescan keeps one.
    pub const fn retained_edge(self) -> Option<RememberedEdge> {
        match self.action {
            MinorGcRememberedSetRefreshAction::RetainCopiedYoung { refreshed } => Some(refreshed),
            MinorGcRememberedSetRefreshAction::DropPromoted { .. }
            | MinorGcRememberedSetRefreshAction::DropDead => None,
        }
    }
}

/// Dirty-card old-field rescan metadata for one minor collection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MinorGcOldFieldRescanPlan {
    rescans: Vec<MinorGcOldFieldRescan>,
}

impl MinorGcOldFieldRescanPlan {
    /// Builds dirty-card old-field rescan metadata.
    ///
    /// Only old and permanent source objects covered by `dirty_cards` are
    /// scanned. Inline, old, permanent, and non-relocated young field values are
    /// ignored or dropped; copied young targets are retained with their new
    /// nursery destination, while promoted targets are classified as dropped.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if rescan storage cannot be reserved or
    /// if the rescan length overflows.
    pub fn from_dirty_cards(
        dirty_cards: GcCardTableSnapshot<'_>,
        old_fields: &[MinorGcOldObjectFields<'_>],
        relocation_plan: &MinorGcRelocationPlan,
    ) -> Result<Self, GenerationalGcError> {
        let mut rescans = Vec::new();
        for object in old_fields {
            if !source_generation_needs_rescan(object.source_generation())
                || !dirty_cards.covers_source(object.source())
            {
                continue;
            }
            for (field_index, field) in object.fields().iter().copied().enumerate() {
                let ResolvedValueGeneration::Heap {
                    address: target,
                    generation: HeapGeneration::Young,
                } = field
                else {
                    continue;
                };
                let rescans_len = rescans
                    .len()
                    .checked_add(1)
                    .ok_or(GenerationalGcError::MinorGcOldFieldRescanLengthOverflow)?;
                rescans.try_reserve_exact(1).map_err(|_| {
                    GenerationalGcError::MinorGcOldFieldRescanAllocationFailed {
                        rescans: rescans_len,
                    }
                })?;
                let original = RememberedEdge::new(object.source(), target);
                rescans.push(MinorGcOldFieldRescan {
                    source: object.source(),
                    field_index,
                    original,
                    action: old_field_rescan_action(original, relocation_plan),
                });
            }
        }
        Ok(Self { rescans })
    }

    /// Returns rescan decisions in object/field order.
    pub fn rescans(&self) -> &[MinorGcOldFieldRescan] {
        &self.rescans
    }

    /// Returns retained old/permanent-to-young edges discovered by rescanning.
    pub fn retained_edges(&self) -> impl Iterator<Item = RememberedEdge> + '_ {
        self.rescans
            .iter()
            .filter_map(|rescan| rescan.retained_edge())
    }

    /// Returns the number of dirty young-target fields examined.
    pub fn len(&self) -> usize {
        self.rescans.len()
    }

    /// Returns whether no dirty young-target fields were examined.
    pub fn is_empty(&self) -> bool {
        self.rescans.is_empty()
    }
}

const fn source_generation_needs_rescan(generation: HeapGeneration) -> bool {
    matches!(generation, HeapGeneration::Old | HeapGeneration::Permanent)
}

fn old_field_rescan_action(
    edge: RememberedEdge,
    relocation_plan: &MinorGcRelocationPlan,
) -> MinorGcRememberedSetRefreshAction {
    match relocation_for(relocation_plan, edge.target()) {
        Some(relocation) if relocation.destination_generation() == HeapGeneration::Young => {
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

fn relocation_for(
    relocation_plan: &MinorGcRelocationPlan,
    address: GcHeapAddress,
) -> Option<MinorGcRelocation> {
    relocation_plan
        .relocations()
        .iter()
        .copied()
        .find(|relocation| relocation.source() == address)
}

#[cfg(test)]
mod tests;
