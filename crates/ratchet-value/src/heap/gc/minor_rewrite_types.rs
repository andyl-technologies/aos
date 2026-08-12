//! Minor-GC pointer-repair planning types: forwarding pointers/slots,
//! reference rewrites, and remembered-set refresh plans.
//!
//! Moved verbatim from `heap/gc.rs` under the RFC-0007 §2 file-size cap; the
//! parent re-exports every public path.

use super::*;

/// One forwarding pointer that would be installed for a copied survivor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorGcForwardingPointer {
    // `pub(super)` fields: literal-constructed by the plan-validation
    // sibling (pre-split same-file access, module-explicit after §2).
    pub(super) copy: MinorGcObjectCopy,
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
    // `pub(super)`: the commit sibling reads staged slots directly.
    pub(super) forwarded: Option<ResolvedValueGeneration>,
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
    // `pub(super)` fields: the plan-validation and commit siblings read
    // them directly (pre-split same-file access, module-explicit after §2).
    pub(super) pointers: Vec<MinorGcForwardingPointer>,
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
    pub(super) destination: GcHeapAddress,
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
    // `pub(super)`: read directly by the gc unit tests (pre-split
    // same-file access, module-explicit after §2).
    pub(super) rewrites: Vec<MinorGcReferenceRewrite>,
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
    pub(super) original: RememberedEdge,
    pub(super) action: MinorGcRememberedSetRefreshAction,
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
    pub(super) source_epoch: RememberedSetEpoch,
    pub(super) refreshes: Vec<MinorGcRememberedSetRefresh>,
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
