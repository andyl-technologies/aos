//! Collector-poll scan and minor-GC planner-input types: the poll scan,
//! nursery/old field views, reference slots, the poll minor-GC plan, and
//! relocation-destination/record-reservation plumbing.
//!
//! Moved verbatim from `heap/roots.rs` under the RFC-0007 §2 file-size cap;
//! the parent re-exports every public path and glob-imports each child so
//! sibling references keep resolving.

use super::*;

/// A collector-poll request paired with a precise heap graph snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollScan {
    poll: AllocationCollectorPoll,
    scan: PreciseHeapScan,
    heap_records: usize,
    worker_region_owner: u64,
    worker_region_epoch: u64,
    allocation_safepoints: AllocationSafepointState,
    permanent_allocation_safepoints: AllocationSafepointState,
}

impl AllocationCollectorPollScan {
    pub(super) fn new(
        poll: AllocationCollectorPoll,
        scan: PreciseHeapScan,
        heap_records: usize,
        worker_region_owner: u64,
        worker_region_epoch: u64,
        allocation_safepoints: AllocationSafepointState,
        permanent_allocation_safepoints: AllocationSafepointState,
    ) -> Self {
        Self {
            poll,
            scan,
            heap_records,
            worker_region_owner,
            worker_region_epoch,
            allocation_safepoints,
            permanent_allocation_safepoints,
        }
    }

    /// Returns the allocation safepoint collector-poll request.
    pub const fn poll(&self) -> AllocationCollectorPoll {
        self.poll
    }

    /// Returns the precise heap graph reachable at the poll safepoint.
    pub const fn scan(&self) -> &PreciseHeapScan {
        &self.scan
    }

    /// Returns the typed heap record count captured with this scan.
    pub const fn heap_records(&self) -> usize {
        self.heap_records
    }

    /// Returns the heap-region owner captured with this scan.
    pub const fn worker_region_owner(&self) -> u64 {
        self.worker_region_owner
    }

    /// Returns the worker-region epoch captured with this scan.
    pub const fn worker_region_epoch(&self) -> u64 {
        self.worker_region_epoch
    }

    /// Returns worker allocation-safepoint state captured with this scan.
    pub const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.allocation_safepoints
    }

    /// Returns permanent allocation-safepoint state captured with this scan.
    pub const fn permanent_allocation_safepoints(&self) -> AllocationSafepointState {
        self.permanent_allocation_safepoints
    }
}

/// Owned precise field metadata for one young object in a collector-poll plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollNurseryFields {
    address: GcHeapAddress,
    fields: Vec<AllocationCollectorPollNurseryField>,
    field_values: Vec<ResolvedValueGeneration>,
}

impl AllocationCollectorPollNurseryFields {
    pub(super) fn new(
        address: GcHeapAddress,
        fields: Vec<AllocationCollectorPollNurseryField>,
    ) -> Result<Self, EvalHeapError> {
        let mut field_values = Vec::new();
        field_values.try_reserve_exact(fields.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_NURSERY_FIELD_VALUES_TABLE,
                entries: fields.len(),
            }
        })?;
        for field in &fields {
            field_values.push(field.value());
        }
        Ok(Self {
            address,
            fields,
            field_values,
        })
    }

    /// Returns the young object whose fields were scanned.
    pub const fn address(&self) -> GcHeapAddress {
        self.address
    }

    /// Returns the object's precise outgoing fields.
    pub fn fields(&self) -> &[AllocationCollectorPollNurseryField] {
        &self.fields
    }

    pub(super) fn field_values(&self) -> &[ResolvedValueGeneration] {
        &self.field_values
    }
}

/// One precise outgoing field copied from a young object for minor-GC planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollNurseryField {
    source: HeapEdgeSource,
    value: ResolvedValueGeneration,
}

impl AllocationCollectorPollNurseryField {
    pub(super) fn new(source: HeapEdgeSource, value: ResolvedValueGeneration) -> Self {
        Self { source, value }
    }

    /// Returns the object-field label from the typed heap scanner.
    pub const fn source(&self) -> &HeapEdgeSource {
        &self.source
    }

    /// Returns the heap value copied from the field.
    pub const fn value(&self) -> ResolvedValueGeneration {
        self.value
    }
}

/// Owned precise field metadata for one old or permanent object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollOldFields {
    address: GcHeapAddress,
    generation: HeapGeneration,
    fields: Vec<AllocationCollectorPollOldField>,
    field_values: Vec<ResolvedValueGeneration>,
}

impl AllocationCollectorPollOldFields {
    pub(super) fn new(
        address: GcHeapAddress,
        generation: HeapGeneration,
        fields: Vec<AllocationCollectorPollOldField>,
    ) -> Result<Self, EvalHeapError> {
        let mut field_values = Vec::new();
        field_values.try_reserve_exact(fields.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_OLD_FIELD_VALUES_TABLE,
                entries: fields.len(),
            }
        })?;
        for field in &fields {
            field_values.push(field.value());
        }
        Ok(Self {
            address,
            generation,
            fields,
            field_values,
        })
    }

    /// Returns the old or permanent object whose fields were scanned.
    pub const fn address(&self) -> GcHeapAddress {
        self.address
    }

    /// Returns the generation that owns this object.
    pub const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    /// Returns the object's precise outgoing fields.
    pub fn fields(&self) -> &[AllocationCollectorPollOldField] {
        &self.fields
    }

    pub(super) fn field_values(&self) -> &[ResolvedValueGeneration] {
        &self.field_values
    }
}

/// One precise outgoing field copied from an old or permanent object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollOldField {
    source: HeapEdgeSource,
    value: ResolvedValueGeneration,
}

impl AllocationCollectorPollOldField {
    pub(super) fn new(source: HeapEdgeSource, value: ResolvedValueGeneration) -> Self {
        Self { source, value }
    }

    /// Returns the object-field label from the typed heap scanner.
    pub const fn source(&self) -> &HeapEdgeSource {
        &self.source
    }

    /// Returns the heap value copied from the field.
    pub const fn value(&self) -> ResolvedValueGeneration {
        self.value
    }
}

/// The copied root or field location represented by a collector-poll reference slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AllocationCollectorPollReferenceSource {
    /// A copied explicit root slot from the poll scan.
    Root {
        /// The root location reported by the tree-walk scanner.
        source: EvalRootSource,
    },
    /// A copied remembered-set edge target.
    RememberedEdge {
        /// The remembered old-or-permanent to young edge.
        edge: RememberedEdge,
        /// The source object's precise field index in scanner order.
        field_index: usize,
        /// The precise source-field label on the remembered edge source object.
        source: HeapEdgeSource,
    },
    /// A copied dirty old/permanent field discovered from the card table.
    DirtyOldField {
        /// The dirty old or permanent source object.
        object: GcHeapAddress,
        /// The field index in the source object's precise field order.
        field_index: usize,
        /// The precise source-field label on the dirty old object.
        source: HeapEdgeSource,
    },
    /// A copied precise field from a planned young survivor.
    NurseryField {
        /// The survivor object whose field was copied.
        object: GcHeapAddress,
        /// The field index in the object's precise nursery-field order.
        field_index: usize,
        /// The object-field label from the typed heap scanner.
        source: HeapEdgeSource,
    },
}

/// One copied root or field reference that can feed reference-rewrite planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollReferenceSlot {
    source: AllocationCollectorPollReferenceSource,
    value: ResolvedValueGeneration,
    value_tag: Option<ValueTag>,
}

impl AllocationCollectorPollReferenceSlot {
    pub(super) fn new(
        source: AllocationCollectorPollReferenceSource,
        value: ResolvedValueGeneration,
        value_tag: Option<ValueTag>,
    ) -> Self {
        Self {
            source,
            value,
            value_tag,
        }
    }

    /// Returns the copied root or field location represented by this slot.
    pub const fn source(&self) -> &AllocationCollectorPollReferenceSource {
        &self.source
    }

    pub(super) fn is_root(&self) -> bool {
        matches!(
            self.source,
            AllocationCollectorPollReferenceSource::Root { .. }
        )
    }

    /// Returns the reference value copied from the slot.
    pub const fn value(&self) -> ResolvedValueGeneration {
        self.value
    }

    /// Returns the heap value tag copied from the slot, when available.
    ///
    /// Root-backed slots are copied from live [`Value`] roots and carry their
    /// original tag so later live-root writeback code can reconstruct a typed
    /// replacement value. Field-backed slots currently carry generation metadata
    /// only; live field mutation remains a later collector integration step.
    pub const fn value_tag(&self) -> Option<ValueTag> {
        self.value_tag
    }
}

/// A collector-poll snapshot converted into minor-GC planner inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollMinorGcPlan {
    poll: AllocationCollectorPoll,
    heap_records: usize,
    worker_region_owner: u64,
    worker_region_epoch: u64,
    allocation_safepoints: AllocationSafepointState,
    permanent_allocation_safepoints: AllocationSafepointState,
    remembered_set: RememberedSet,
    card_table: Option<GcCardTable>,
    roots: Vec<ResolvedValueGeneration>,
    nursery_objects: Vec<NurseryObjectAge>,
    nursery_fields: Vec<AllocationCollectorPollNurseryFields>,
    old_fields: Vec<AllocationCollectorPollOldFields>,
    reference_slots: Vec<AllocationCollectorPollReferenceSlot>,
    plan: MinorGcPlan,
}

impl AllocationCollectorPollMinorGcPlan {
    pub(super) fn new(
        poll: AllocationCollectorPoll,
        heap_records: usize,
        worker_region_owner: u64,
        worker_region_epoch: u64,
        allocation_safepoints: AllocationSafepointState,
        permanent_allocation_safepoints: AllocationSafepointState,
        remembered_set: RememberedSet,
        card_table: Option<GcCardTable>,
        roots: Vec<ResolvedValueGeneration>,
        nursery_objects: Vec<NurseryObjectAge>,
        nursery_fields: Vec<AllocationCollectorPollNurseryFields>,
        old_fields: Vec<AllocationCollectorPollOldFields>,
        reference_slots: Vec<AllocationCollectorPollReferenceSlot>,
        plan: MinorGcPlan,
    ) -> Self {
        Self {
            poll,
            heap_records,
            worker_region_owner,
            worker_region_epoch,
            allocation_safepoints,
            permanent_allocation_safepoints,
            remembered_set,
            card_table,
            roots,
            nursery_objects,
            nursery_fields,
            old_fields,
            reference_slots,
            plan,
        }
    }

    #[cfg(test)]
    // Pre-split audience was the heap module (`pub(super)` in roots.rs);
    // consumed by heap/tests fixtures.
    pub(in crate::eval::heap) fn from_parts_for_test(
        poll: AllocationCollectorPoll,
        heap_records: usize,
        worker_region_owner: u64,
        worker_region_epoch: u64,
        allocation_safepoints: AllocationSafepointState,
        permanent_allocation_safepoints: AllocationSafepointState,
        remembered_set: RememberedSet,
        roots: Vec<ResolvedValueGeneration>,
        nursery_objects: Vec<NurseryObjectAge>,
        nursery_fields: Vec<AllocationCollectorPollNurseryFields>,
        reference_slots: Vec<AllocationCollectorPollReferenceSlot>,
        plan: MinorGcPlan,
    ) -> Self {
        Self::new(
            poll,
            heap_records,
            worker_region_owner,
            worker_region_epoch,
            allocation_safepoints,
            permanent_allocation_safepoints,
            remembered_set,
            None,
            roots,
            nursery_objects,
            nursery_fields,
            Vec::new(),
            reference_slots,
            plan,
        )
    }

    /// Returns the allocation safepoint collector-poll request.
    pub const fn poll(&self) -> AllocationCollectorPoll {
        self.poll
    }

    /// Returns the typed heap record count captured when this plan was built.
    pub const fn heap_records(&self) -> usize {
        self.heap_records
    }

    /// Returns the heap-region owner captured by this plan.
    pub const fn worker_region_owner(&self) -> u64 {
        self.worker_region_owner
    }

    /// Returns the worker-region epoch captured by this plan.
    pub const fn worker_region_epoch(&self) -> u64 {
        self.worker_region_epoch
    }

    /// Returns the worker allocation-safepoint state captured by this plan.
    pub const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.allocation_safepoints
    }

    /// Returns the permanent allocation-safepoint state captured by this plan.
    pub const fn permanent_allocation_safepoints(&self) -> AllocationSafepointState {
        self.permanent_allocation_safepoints
    }

    /// Returns the remembered-set snapshot consumed by this minor-GC plan.
    pub const fn remembered_set(&self) -> &RememberedSet {
        &self.remembered_set
    }

    /// Returns the owned dirty-card snapshot captured by card-table-aware planning.
    pub const fn card_table(&self) -> Option<&GcCardTable> {
        self.card_table.as_ref()
    }

    /// Returns the root values supplied to the minor-GC planner.
    pub fn roots(&self) -> &[ResolvedValueGeneration] {
        &self.roots
    }

    /// Returns generated age metadata for current young oracle-heap objects.
    pub fn nursery_objects(&self) -> &[NurseryObjectAge] {
        &self.nursery_objects
    }

    /// Returns generated field metadata for current young oracle-heap objects.
    pub fn nursery_fields(&self) -> &[AllocationCollectorPollNurseryFields] {
        &self.nursery_fields
    }

    /// Returns generated field metadata for current old/permanent oracle objects.
    pub fn old_fields(&self) -> &[AllocationCollectorPollOldFields] {
        &self.old_fields
    }

    /// Returns the copied root and field references in rewrite-slot order.
    pub fn reference_slots(&self) -> &[AllocationCollectorPollReferenceSlot] {
        &self.reference_slots
    }

    /// Returns reference values in rewrite-slot order.
    pub fn reference_values(&self) -> impl Iterator<Item = ResolvedValueGeneration> + '_ {
        self.reference_slots.iter().map(|slot| slot.value())
    }

    /// Builds a minor-GC reference-rewrite plan from this poll plan.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if any young reference in this plan does
    /// not have a relocation entry or if the rewrite plan cannot reserve
    /// storage.
    pub fn reference_rewrite_plan(
        &self,
        relocation_plan: &MinorGcRelocationPlan,
    ) -> Result<MinorGcReferenceRewritePlan, GenerationalGcError> {
        MinorGcReferenceRewritePlan::from_references(relocation_plan, self.reference_values())
    }

    /// Builds materialized relocation destinations for this poll plan.
    ///
    /// The returned wrapper keeps destination-allocation requirements, aligned
    /// placement offsets, and materialized relocation destinations together for
    /// callers that need to inspect or validate each step before building
    /// commit metadata. This still does not allocate destination storage or
    /// choose the semispace base addresses itself.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if nursery layout metadata does not match
    /// this plan, if allocation or placement metadata cannot reserve storage or
    /// overflows, or if materialized destinations from `bases` are invalid for
    /// this plan.
    pub fn relocation_destination_plan(
        &self,
        nursery_layouts: &[NurseryObjectLayout],
        bases: MinorGcDestinationBases,
    ) -> Result<AllocationCollectorPollMinorGcRelocationDestinations, GenerationalGcError> {
        let allocation_plan =
            MinorGcDestinationAllocationPlan::from_minor_gc_plan(&self.plan, nursery_layouts)?;
        let placement_plan =
            MinorGcDestinationPlacementPlan::from_allocation_plan(&allocation_plan)?;
        let relocation_destinations = MinorGcRelocationDestinationPlan::from_placement_plan(
            &self.plan,
            &placement_plan,
            bases,
        )?;
        Ok(AllocationCollectorPollMinorGcRelocationDestinations {
            allocation_plan,
            placement_plan,
            relocation_destinations,
        })
    }

    /// Builds materialized relocation destinations from explicit addresses.
    ///
    /// This is the non-contiguous counterpart to
    /// [`Self::relocation_destination_plan`]. It still derives allocation and
    /// placement metadata from `nursery_layouts`, but validates a caller-supplied
    /// destination table rather than materializing addresses from generation
    /// bases. The resulting wrapper keeps the canonical survivor-frontier
    /// destination order beside the same allocation and placement metadata used
    /// by later commit planning.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if nursery layout metadata does not match
    /// this plan, if allocation or placement metadata cannot reserve storage or
    /// overflows, if explicit destinations do not form a valid relocation map, or
    /// if any destination violates the source object's required alignment or
    /// overlaps another planned destination or live source range.
    pub fn explicit_relocation_destination_plan(
        &self,
        nursery_layouts: &[NurseryObjectLayout],
        destinations: &[MinorGcRelocationDestination],
    ) -> Result<AllocationCollectorPollMinorGcRelocationDestinations, GenerationalGcError> {
        let allocation_plan =
            MinorGcDestinationAllocationPlan::from_minor_gc_plan(&self.plan, nursery_layouts)?;
        let placement_plan =
            MinorGcDestinationPlacementPlan::from_allocation_plan(&allocation_plan)?;
        let relocation_destinations =
            MinorGcRelocationDestinationPlan::from_destinations(&self.plan, destinations)?;
        let relocation_plan = relocation_destinations.relocation_plan(&self.plan)?;
        let _ = object_copy_plan_from_destination_placements(&relocation_plan, &placement_plan)?;
        Ok(AllocationCollectorPollMinorGcRelocationDestinations {
            allocation_plan,
            placement_plan,
            relocation_destinations,
        })
    }

    /// Builds ordered minor-GC commit metadata for this poll plan.
    ///
    /// The returned value keeps this plan's copied reference-slot labels next to
    /// the validated lower-level commit plan and the allocation-state snapshot
    /// used by later heap-backed buffer derivation. It still does not own mutable
    /// evaluator roots, object fields, object bytes, forwarding slots, or
    /// remembered-set storage. For card-table-aware plans, dirty old/permanent
    /// field reference slots participate in reference rewriting and dirty
    /// old-field rescans are folded into the precomputed next remembered set.
    /// The destination wrapper must preserve this poll plan's survivor count,
    /// source order, and copy/promote actions.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if destination placements or relocation
    /// destinations do not match this poll plan, if any subplan cannot reserve
    /// storage or detects byte-size overflow, if the remembered-set refresh or
    /// dirty old-field rescan cannot be built, or if the subplans are not
    /// mutually consistent.
    pub fn commit_plan(
        &self,
        relocation_destinations: &AllocationCollectorPollMinorGcRelocationDestinations,
    ) -> Result<AllocationCollectorPollMinorGcCommitPlan<'_>, GenerationalGcError> {
        validate_destination_placements_match_plan(
            &self.plan,
            relocation_destinations.placement_plan(),
        )?;
        let relocation_plan = relocation_destinations
            .relocation_destinations()
            .relocation_plan(&self.plan)?;
        let object_copies = object_copy_plan_from_destination_placements(
            &relocation_plan,
            relocation_destinations.placement_plan(),
        )?;
        let forwarding_pointers =
            MinorGcForwardingPointerPlan::from_object_copy_plan(&object_copies)?;
        let reference_rewrites = self.reference_rewrite_plan(&relocation_plan)?;
        let remembered_set_refresh = MinorGcRememberedSetRefreshPlan::from_snapshot(
            self.remembered_set.snapshot(),
            &relocation_plan,
        )?;
        let commit_plan = match &self.card_table {
            Some(card_table) => {
                let old_field_views = old_field_views(&self.old_fields)?;
                let old_field_rescan = MinorGcOldFieldRescanPlan::from_dirty_cards(
                    card_table.snapshot(),
                    &old_field_views,
                    &relocation_plan,
                )?;
                MinorGcCommitPlan::from_parts_with_old_field_rescan(
                    object_copies,
                    forwarding_pointers,
                    reference_rewrites,
                    remembered_set_refresh,
                    &old_field_rescan,
                )?
            }
            None => MinorGcCommitPlan::from_parts(
                object_copies,
                forwarding_pointers,
                reference_rewrites,
                remembered_set_refresh,
            )?,
        };
        Ok(AllocationCollectorPollMinorGcCommitPlan {
            reference_slots: &self.reference_slots,
            heap_records: self.heap_records,
            worker_region_owner: self.worker_region_owner,
            worker_region_epoch: self.worker_region_epoch,
            allocation_safepoints: self.allocation_safepoints,
            permanent_allocation_safepoints: self.permanent_allocation_safepoints,
            commit_plan,
        })
    }

    /// Returns the planned young-generation survivor frontier.
    pub const fn plan(&self) -> &MinorGcPlan {
        &self.plan
    }
}

/// Materialized relocation destinations for an allocation-poll minor-GC plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollMinorGcRelocationDestinations {
    allocation_plan: MinorGcDestinationAllocationPlan,
    placement_plan: MinorGcDestinationPlacementPlan,
    relocation_destinations: MinorGcRelocationDestinationPlan,
}

impl AllocationCollectorPollMinorGcRelocationDestinations {
    /// Returns destination allocation requirements in survivor-frontier order.
    pub const fn allocation_plan(&self) -> &MinorGcDestinationAllocationPlan {
        &self.allocation_plan
    }

    /// Returns aligned destination placements in survivor-frontier order.
    pub const fn placement_plan(&self) -> &MinorGcDestinationPlacementPlan {
        &self.placement_plan
    }

    /// Consumes this wrapper and returns the aligned destination placements.
    pub fn into_placement_plan(self) -> MinorGcDestinationPlacementPlan {
        self.placement_plan
    }

    /// Returns the materialized relocation-destination plan.
    pub const fn relocation_destinations(&self) -> &MinorGcRelocationDestinationPlan {
        &self.relocation_destinations
    }

    /// Returns materialized relocation destinations in survivor-frontier order.
    pub fn destinations(&self) -> &[MinorGcRelocationDestination] {
        self.relocation_destinations.destinations()
    }
}

/// A heap-record destination reserved before a collector-poll minor-GC plan.
#[derive(Clone, Copy, Debug)]
pub struct AllocationCollectorPollMinorGcDestinationRecordReservation {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    destination_value: Value,
    tag: ValueTag,
}

impl AllocationCollectorPollMinorGcDestinationRecordReservation {
    pub(super) const fn new(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        destination_value: Value,
        tag: ValueTag,
    ) -> Self {
        Self {
            source,
            destination,
            destination_value,
            tag,
        }
    }

    /// Returns the young source object the destination was reserved for.
    pub const fn source(self) -> GcHeapAddress {
        self.source
    }

    /// Returns the reserved destination object address.
    pub const fn destination(self) -> GcHeapAddress {
        self.destination
    }

    /// Returns the heap value for the reserved destination record.
    pub const fn destination_value(self) -> Value {
        self.destination_value
    }

    /// Returns the source heap tag copied by this destination reservation.
    pub const fn tag(self) -> ValueTag {
        self.tag
    }
}

impl PartialEq for AllocationCollectorPollMinorGcDestinationRecordReservation {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
            && self.destination == other.destination
            && self.destination_value.raw_eq(other.destination_value)
            && self.tag == other.tag
    }
}

impl Eq for AllocationCollectorPollMinorGcDestinationRecordReservation {}

/// Destination records reserved for the current young heap before a poll scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollMinorGcDestinationRecordReservations {
    heap_records: usize,
    worker_region_owner: u64,
    worker_region_epoch: u64,
    allocation_safepoints: AllocationSafepointState,
    permanent_allocation_safepoints: AllocationSafepointState,
    reservations: Vec<AllocationCollectorPollMinorGcDestinationRecordReservation>,
}

impl AllocationCollectorPollMinorGcDestinationRecordReservations {
    pub(super) fn new(
        heap_records: usize,
        worker_region_owner: u64,
        worker_region_epoch: u64,
        allocation_safepoints: AllocationSafepointState,
        permanent_allocation_safepoints: AllocationSafepointState,
        reservations: Vec<AllocationCollectorPollMinorGcDestinationRecordReservation>,
    ) -> Self {
        Self {
            heap_records,
            worker_region_owner,
            worker_region_epoch,
            allocation_safepoints,
            permanent_allocation_safepoints,
            reservations,
        }
    }

    /// Returns the heap record count after destination reservation.
    pub const fn heap_records(&self) -> usize {
        self.heap_records
    }

    /// Returns the heap-region owner captured after destination reservation.
    pub const fn worker_region_owner(&self) -> u64 {
        self.worker_region_owner
    }

    /// Returns the worker-region epoch captured after destination reservation.
    pub const fn worker_region_epoch(&self) -> u64 {
        self.worker_region_epoch
    }

    /// Returns the worker allocation-safepoint state captured after reservation.
    pub const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.allocation_safepoints
    }

    /// Returns the permanent allocation-safepoint state captured after reservation.
    pub const fn permanent_allocation_safepoints(&self) -> AllocationSafepointState {
        self.permanent_allocation_safepoints
    }

    /// Returns the reserved source-to-destination records.
    pub fn reservations(&self) -> &[AllocationCollectorPollMinorGcDestinationRecordReservation] {
        &self.reservations
    }

    /// Returns how many destination records were reserved.
    pub fn len(&self) -> usize {
        self.reservations.len()
    }

    /// Returns whether no destination records were reserved.
    pub fn is_empty(&self) -> bool {
        self.reservations.is_empty()
    }
}

pub(super) fn validate_destination_placements_match_plan(
    plan: &MinorGcPlan,
    placement_plan: &MinorGcDestinationPlacementPlan,
) -> Result<(), GenerationalGcError> {
    let survivors = plan.survivors();
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

pub(super) fn object_copy_plan_from_destination_placements(
    relocation_plan: &MinorGcRelocationPlan,
    placement_plan: &MinorGcDestinationPlacementPlan,
) -> Result<MinorGcObjectCopyPlan, GenerationalGcError> {
    let mut nursery_layouts = Vec::new();
    nursery_layouts
        .try_reserve_exact(placement_plan.len())
        .map_err(|_| GenerationalGcError::MinorGcObjectCopyAllocationFailed {
            copies: placement_plan.len(),
        })?;
    for placement in placement_plan.placements() {
        nursery_layouts.push(NurseryObjectLayout::new(
            placement.source(),
            placement.size_bytes(),
            placement.align(),
        ));
    }
    MinorGcObjectCopyPlan::from_relocation_plan(relocation_plan, &nursery_layouts)
}

pub(super) fn validate_object_byte_copy_record_layout(
    copy: MinorGcObjectCopy,
    record: &HeapRecord,
) -> Result<(), EvalHeapError> {
    if !heap_record_layout_matches(record.layout, copy.size_bytes(), copy.align()) {
        return Err(EvalHeapError::CollectorPollObjectByteCopyLayoutMismatch {
            address: copy.source(),
            expected_size: copy.size_bytes(),
            actual_size: record.layout.size_bytes,
            expected_align: copy.align(),
            actual_align: record.layout.align,
        });
    }
    Ok(())
}

pub(super) fn validate_object_byte_copy_request_source_record_layout(
    request: AllocationCollectorPollObjectByteCopyRequest,
    record: &HeapRecord,
) -> Result<(), EvalHeapError> {
    if !heap_record_layout_matches(record.layout, request.size_bytes(), request.align()) {
        return Err(EvalHeapError::CollectorPollObjectByteCopyLayoutMismatch {
            address: request.source(),
            expected_size: request.size_bytes(),
            actual_size: record.layout.size_bytes,
            expected_align: request.align(),
            actual_align: record.layout.align,
        });
    }
    Ok(())
}

pub(super) fn validate_object_body_write_destination_record_layout(
    request: AllocationCollectorPollObjectByteCopyRequest,
    record: &HeapRecord,
) -> Result<(), EvalHeapError> {
    if !heap_record_layout_matches(record.layout, request.size_bytes(), request.align()) {
        return Err(EvalHeapError::CollectorPollObjectBodyWriteLayoutMismatch {
            address: request.destination(),
            expected_size: request.size_bytes(),
            actual_size: record.layout.size_bytes,
            expected_align: request.align(),
            actual_align: record.layout.align,
        });
    }
    Ok(())
}

pub(super) const fn heap_record_layout_matches(
    layout: HeapRecordLayout,
    size_bytes: usize,
    align: usize,
) -> bool {
    layout.size_bytes == size_bytes && layout.align == align
}
