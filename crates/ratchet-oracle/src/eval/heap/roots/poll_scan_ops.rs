//! impl EvalHeap: write-barrier adapters, root-set assembly, precise and
//! collector-poll root scans, minor-GC planning, destination reservation,
//! and byte-copy planning.
//!
//! Moved verbatim from `heap/roots.rs` under the RFC-0007 §2 file-size cap;
//! the parent re-exports every public path and glob-imports each child so
//! sibling references keep resolving.

use super::*;

impl EvalHeap {
    /// Creates a thunk-resolution write barrier for a source thunk.
    ///
    /// The returned adapter can be passed to
    /// [`crate::eval::thunk::ForceGuard::finish_with_barrier`] so the safe
    /// tree-walk thunk publication path records the same
    /// old-or-permanent to young edge that the future daemon collector needs.
    /// The adapter is source-specific: callers must pair it with the force guard
    /// for `source_thunk`, because the guard does not inspect the adapter's
    /// captured source address.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::ThunkResolveBarrierSourceNotThunk`] if
    /// `source_thunk` is not tagged as a thunk. Returns [`EvalHeapError`] if the
    /// source thunk does not belong to this heap, or if its runtime tag disagrees
    /// with the heap side table.
    pub fn thunk_resolve_write_barrier<'a>(
        &'a self,
        tier: GenerationalGcTier,
        source_thunk: Value,
        remembered_set: &'a mut RememberedSet,
    ) -> Result<EvalHeapThunkResolveBarrier<'a>, EvalHeapError> {
        self.thunk_resolve_write_barrier_with_optional_card_table(
            tier,
            source_thunk,
            remembered_set,
            None,
        )
    }

    /// Creates a card-table-aware thunk-resolution write barrier adapter.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::ThunkResolveBarrierSourceNotThunk`] if
    /// `source_thunk` is not tagged as a thunk. Returns [`EvalHeapError`] if the
    /// source thunk does not belong to this heap, or if its runtime tag disagrees
    /// with the heap side table.
    pub fn thunk_resolve_write_barrier_with_card_table<'a>(
        &'a self,
        tier: GenerationalGcTier,
        source_thunk: Value,
        remembered_set: &'a mut RememberedSet,
        card_table: &'a mut GcCardTable,
    ) -> Result<EvalHeapThunkResolveBarrier<'a>, EvalHeapError> {
        self.thunk_resolve_write_barrier_with_optional_card_table(
            tier,
            source_thunk,
            remembered_set,
            Some(card_table),
        )
    }

    pub(super) fn thunk_resolve_write_barrier_with_optional_card_table<'a>(
        &'a self,
        tier: GenerationalGcTier,
        source_thunk: Value,
        remembered_set: &'a mut RememberedSet,
        card_table: Option<&'a mut GcCardTable>,
    ) -> Result<EvalHeapThunkResolveBarrier<'a>, EvalHeapError> {
        if source_thunk.tag() != ValueTag::Thunk {
            return Err(EvalHeapError::ThunkResolveBarrierSourceNotThunk {
                actual: source_thunk.tag(),
            });
        }
        let source_record = self.record_for_scannable_value(source_thunk)?;
        Ok(EvalHeapThunkResolveBarrier {
            heap: self,
            tier,
            source: gc_address_for_record(source_record)?,
            source_generation: generation_for_record(source_record),
            remembered_set,
            card_table,
            last_action: None,
        })
    }

    /// Returns permanent roots held by the heap's hash-cons tables.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn interned_root_set(&self) -> Result<EvalRootSet, EvalRootSetError> {
        let mut roots = EvalRootSet::new();
        self.push_interned_table_roots(
            &mut roots,
            InternedRootTable::String,
            self.string_cons.committed_entries(),
        )?;
        self.push_interned_table_roots(
            &mut roots,
            InternedRootTable::Path,
            self.path_cons.committed_entries(),
        )?;
        self.push_interned_table_roots(
            &mut roots,
            InternedRootTable::List,
            self.list_cons.committed_entries(),
        )?;
        self.push_interned_table_roots(
            &mut roots,
            InternedRootTable::Attrs,
            self.attrs_cons.committed_entries(),
        )?;
        Ok(roots)
    }

    /// Scans the heap graph reachable from explicit roots.
    ///
    /// Only evaluator-owned heap tags are accepted into [`EvalRootSet`], and
    /// only evaluator-owned child fields are emitted as edges. Inline integers,
    /// floats, booleans, nulls, and opaque external pointers are deliberately
    /// skipped so the collector does not retain by bit-pattern coincidence or
    /// chase heap handles owned by another runtime.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if a root or edge points
    /// outside this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if a
    /// value tag disagrees with the heap side-table record. Returns
    /// [`EvalHeapError::Environment`] if a captured frame cannot be read, and
    /// [`EvalHeapError::Thunk`] if a thunk state word is invalid. Returns a
    /// root-scan allocation error if scanner side tables cannot be reserved.
    pub fn scan_precise_roots(
        &self,
        root_set: &EvalRootSet,
    ) -> Result<PreciseHeapScan, EvalHeapError> {
        let mut scan = PreciseHeapScan::with_root_capacity(root_set.len())?;
        let mut worklist = VecDeque::new();
        worklist.try_reserve(root_set.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: WORKLIST_TABLE,
                entries: root_set.len(),
            }
        })?;
        let mut visited = HashSet::new();

        for root in root_set.roots() {
            scan.roots.push(root.clone());
            push_worklist(&mut worklist, root.value())?;
        }

        while let Some(value) = worklist.pop_front() {
            let (tag, ptr) = heap_ptr(value)?;
            let address = ptr.as_ptr() as usize;
            // Flat strings/paths (doc 30 FV-1) are edge-free leaf objects
            // outside the record table; validate them through the flat store
            // and emit the same empty-edge object scan a string record
            // produced before flattening.
            if self.shared.is_none() && matches!(tag, ValueTag::String | ValueTag::Path) {
                self.flat_verify(tag, ptr)?;
                if !push_visited(&mut visited, address)? {
                    continue;
                }
                push_object_scan(&mut scan.objects, HeapObjectScan::new(value, Vec::new()))?;
                continue;
            }
            // Flat lists (doc 30 FV-1) carry edges in their element spine:
            // synthesize the same `ListElement`-labelled edges a record scan
            // produced and keep traversing through them.
            if self.shared.is_none() && tag == ValueTag::List {
                let edges = self.scan_flat_list_edges(self.flat_list_payload(ptr)?)?;
                if !push_visited(&mut visited, address)? {
                    continue;
                }
                for edge in &edges {
                    push_worklist(&mut worklist, edge.value())?;
                }
                push_object_scan(&mut scan.objects, HeapObjectScan::new(value, edges))?;
                continue;
            }
            // Flat attrsets (doc 30 FV-2) carry edges in their entry values:
            // synthesize the same `AttrBinding`-labelled edges a record scan
            // produced and keep traversing through them.
            if self.shared.is_none() && tag == ValueTag::Attrs {
                let edges = self.scan_flat_attrs_edges(self.flat_attrs_payload(ptr)?)?;
                if !push_visited(&mut visited, address)? {
                    continue;
                }
                for edge in &edges {
                    push_worklist(&mut worklist, edge.value())?;
                }
                push_object_scan(&mut scan.objects, HeapObjectScan::new(value, edges))?;
                continue;
            }
            let record = self.record_or_unknown(tag, ptr)?;
            let actual = record.object.tag();
            if actual != tag {
                return Err(EvalHeapError::record_type_mismatch(tag, actual, ptr));
            }
            if !push_visited(&mut visited, address)? {
                continue;
            }

            let edges = self.scan_record_edges(record)?;
            for edge in &edges {
                push_worklist(&mut worklist, edge.value())?;
            }
            push_object_scan(&mut scan.objects, HeapObjectScan::new(value, edges))?;
        }

        Ok(scan)
    }

    /// Builds the precise heap graph for an allocation collector-poll request.
    ///
    /// This is a pre-collector snapshot: it validates and scans the supplied
    /// explicit roots, then pairs the resulting graph with the allocation
    /// safepoint poll request that triggered the scan. It does not invoke a
    /// collector, relocate objects, or retain mutable relocation slots.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if precise root scanning fails.
    pub fn scan_collector_poll_roots(
        &self,
        poll: AllocationCollectorPoll,
        root_set: &EvalRootSet,
    ) -> Result<AllocationCollectorPollScan, EvalHeapError> {
        let scan = self.scan_precise_roots(root_set)?;
        Ok(AllocationCollectorPollScan::new(
            poll,
            scan,
            self.scannable_object_count(),
            self.region_owner,
            self.worker_region_epoch,
            self.allocation_safepoints(),
            self.permanent_allocation_safepoints(),
        ))
    }

    /// Converts a collector-poll heap graph snapshot into a minor-GC plan.
    ///
    /// Worker-domain records are treated as current young-generation objects.
    /// Permanent shared records are treated as permanent objects. Remembered-set
    /// snapshots may carry old-worker or permanent-shared source edges to young
    /// targets, while permanent graph edges must be remembered explicitly. The
    /// method validates that the copied poll scan still matches current heap
    /// record edges before using current worker-domain field metadata for
    /// transitive minor-GC planning.
    ///
    /// This remains a planning bridge: it does not retain mutable root slots,
    /// rewrite fields, install forwarding pointers, or move object bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the poll scan is stale, if a remembered-set
    /// edge references an unknown object or is not old/permanent-to-young, if a
    /// visible permanent-to-young edge is missing from the remembered set, if
    /// copying the remembered-set snapshot cannot reserve storage, or if the
    /// minor-GC planner rejects the generated roots, age metadata, or field
    /// metadata.
    pub fn plan_collector_poll_minor_gc(
        &self,
        poll_scan: &AllocationCollectorPollScan,
        remembered_set: RememberedSetSnapshot<'_>,
        collection_epoch: RememberedSetEpoch,
        promotion_policy: MinorGcPromotionPolicy,
    ) -> Result<AllocationCollectorPollMinorGcPlan, EvalHeapError> {
        self.plan_collector_poll_minor_gc_with_optional_card_table(
            poll_scan,
            remembered_set,
            None,
            collection_epoch,
            promotion_policy,
        )
    }

    /// Converts a collector-poll heap graph snapshot into a card-table-aware
    /// minor-GC plan.
    ///
    /// This performs the same planning work as [`Self::plan_collector_poll_minor_gc`]
    /// and additionally verifies that every remembered edge's source object is
    /// covered by the supplied dirty-card snapshot. It also captures an owned
    /// dirty-card snapshot and current old/permanent field metadata. Dirty
    /// old/permanent fields whose edge is absent from the remembered set seed the
    /// survivor frontier and get heap-backed reference slots for later rewrite
    /// metadata.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] under the same conditions as
    /// [`Self::plan_collector_poll_minor_gc`]. Also returns
    /// [`EvalHeapError::MissingCollectorPollDirtyCard`] when a remembered edge
    /// is not covered by the dirty-card snapshot, or
    /// [`EvalHeapError::MissingCollectorPollRememberedEdge`] when an unremembered
    /// permanent-to-young edge is not covered by a dirty source card.
    pub fn plan_collector_poll_minor_gc_with_card_table(
        &self,
        poll_scan: &AllocationCollectorPollScan,
        remembered_set: RememberedSetSnapshot<'_>,
        card_table: GcCardTableSnapshot<'_>,
        collection_epoch: RememberedSetEpoch,
        promotion_policy: MinorGcPromotionPolicy,
    ) -> Result<AllocationCollectorPollMinorGcPlan, EvalHeapError> {
        self.plan_collector_poll_minor_gc_with_optional_card_table(
            poll_scan,
            remembered_set,
            Some(card_table),
            collection_epoch,
            promotion_policy,
        )
    }

    pub(super) fn plan_collector_poll_minor_gc_with_optional_card_table(
        &self,
        poll_scan: &AllocationCollectorPollScan,
        remembered_set: RememberedSetSnapshot<'_>,
        card_table: Option<GcCardTableSnapshot<'_>>,
        collection_epoch: RememberedSetEpoch,
        promotion_policy: MinorGcPromotionPolicy,
    ) -> Result<AllocationCollectorPollMinorGcPlan, EvalHeapError> {
        self.validate_collector_poll_snapshot_allocation_state(poll_scan)?;
        self.validate_collector_poll_scan_is_current(poll_scan)?;
        self.validate_remembered_set_snapshot(remembered_set)?;
        if let Some(card_table) = card_table {
            self.validate_card_table_snapshot(remembered_set, card_table)?;
        }
        let roots = self.minor_gc_roots_for_poll_scan(poll_scan)?;
        let nursery_objects = self.current_nursery_objects()?;
        let nursery_fields = self.current_nursery_fields()?;
        let old_fields = self.current_old_fields()?;
        let remembered_set_for_plan = match card_table {
            Some(card_table) => Some(remembered_set_with_dirty_old_field_edges(
                remembered_set,
                card_table,
                &old_fields,
            )?),
            None => None,
        };
        let frontier_remembered_set = remembered_set_for_plan
            .as_ref()
            .map_or(remembered_set, RememberedSet::snapshot);
        let nursery_field_views = nursery_field_views(&nursery_fields)?;
        let plan = MinorGcPlan::from_roots_remembered_and_fields(
            roots.iter().copied(),
            frontier_remembered_set,
            collection_epoch,
            &nursery_objects,
            &nursery_field_views,
            promotion_policy,
        )?;
        match card_table {
            Some(card_table) => self
                .validate_current_permanent_edges_are_remembered_or_dirty_survivors(
                    remembered_set,
                    card_table,
                    &plan,
                )?,
            None => self.validate_current_permanent_edges_are_remembered(remembered_set)?,
        }
        let reference_slots = self.minor_gc_reference_slots_for_plan(
            poll_scan,
            remembered_set,
            card_table,
            &plan,
            &nursery_fields,
            &old_fields,
        )?;
        let card_table = match card_table {
            Some(card_table) => Some(owned_card_table_from_snapshot(card_table)?),
            None => None,
        };

        Ok(AllocationCollectorPollMinorGcPlan::new(
            poll_scan.poll(),
            poll_scan.heap_records(),
            poll_scan.worker_region_owner(),
            poll_scan.worker_region_epoch(),
            poll_scan.allocation_safepoints(),
            poll_scan.permanent_allocation_safepoints(),
            remembered_set_from_snapshot(remembered_set)?,
            card_table,
            roots,
            nursery_objects,
            nursery_fields,
            old_fields,
            reference_slots,
            plan,
        ))
    }

    /// Reserves scratch destination records for current young worker objects.
    ///
    /// This must run before the collector-poll scan and minor-GC plan that will
    /// consume the reservations. It records each current young worker-domain
    /// record's tag, allocates a fresh tag-compatible placeholder record,
    /// records the source-to-destination address mapping, and captures the
    /// post-reservation heap snapshot. A later call to
    /// [`Self::plan_collector_poll_minor_gc_reserved_relocation_destinations`]
    /// filters these reservations to the actual survivor frontier.
    ///
    /// Reserved records carry placeholder side-table bodies only to satisfy
    /// typed heap-record invariants before publication. The existing
    /// object-body/generation writer must still validate and install the planned
    /// relocated body before any root or field can publish the destination.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if reservation metadata cannot be allocated, if a
    /// current young record has no destination-record allocator, if a destination
    /// record allocation fails, or if a reserved destination value cannot be
    /// converted back into a heap address.
    pub fn reserve_current_young_minor_gc_destination_records(
        &mut self,
    ) -> Result<AllocationCollectorPollMinorGcDestinationRecordReservations, EvalHeapError> {
        let mut sources = Vec::new();
        for record in &self.records {
            if record.allocation_domain != HeapAllocationDomain::Worker
                || generation_for_record(record) != HeapGeneration::Young
                || record.is_retired()
            {
                continue;
            }

            let entries =
                sources
                    .len()
                    .checked_add(1)
                    .ok_or(EvalHeapError::RootScanLengthOverflow {
                        table: MINOR_GC_DESTINATION_RECORD_RESERVATIONS_TABLE,
                    })?;
            sources
                .try_reserve_exact(1)
                .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                    table: MINOR_GC_DESTINATION_RECORD_RESERVATIONS_TABLE,
                    entries,
                })?;
            sources.push((gc_address_for_record(record)?, record.object.tag()));
        }

        let mut reservations = Vec::new();
        reservations.try_reserve_exact(sources.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_DESTINATION_RECORD_RESERVATIONS_TABLE,
                entries: sources.len(),
            }
        })?;

        for (source, tag) in sources {
            let destination_value = self.alloc_minor_gc_destination_record_like(source, tag)?;
            reservations.push(
                AllocationCollectorPollMinorGcDestinationRecordReservation::new(
                    source,
                    gc_address_for_value(destination_value)?,
                    destination_value,
                    tag,
                ),
            );
        }

        Ok(
            AllocationCollectorPollMinorGcDestinationRecordReservations::new(
                self.scannable_object_count(),
                self.region_owner,
                self.worker_region_epoch,
                self.allocation_safepoints(),
                self.permanent_allocation_safepoints(),
                reservations,
            ),
        )
    }

    /// Builds relocation destinations for a collector-poll minor-GC plan from
    /// current heap-record layout metadata.
    ///
    /// The helper rejects allocations after the minor-GC plan was built, derives
    /// one [`NurseryObjectLayout`] per planned survivor from the side table's
    /// recorded allocation size and alignment, then delegates destination
    /// allocation, placement, and materialization to the poll plan. It still does
    /// not reserve semispace pages, allocate destination objects, copy bytes, or
    /// update live evaluator slots.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the heap record count or allocation-safepoint
    /// state changed after planning, if a planned survivor no longer belongs to
    /// this heap, if survivor-layout storage cannot be reserved, or if the
    /// lower-level relocation-destination planner rejects the derived layouts or
    /// destination bases.
    pub fn plan_collector_poll_minor_gc_relocation_destinations(
        &self,
        plan: &AllocationCollectorPollMinorGcPlan,
        bases: MinorGcDestinationBases,
    ) -> Result<AllocationCollectorPollMinorGcRelocationDestinations, EvalHeapError> {
        self.validate_collector_poll_plan_allocation_state(plan)?;
        let nursery_layouts = self.nursery_layouts_for_minor_gc_plan(plan.plan())?;
        Ok(plan.relocation_destination_plan(&nursery_layouts, bases)?)
    }

    /// Builds relocation destinations from caller-supplied addresses.
    ///
    /// This helper has the same heap snapshot and survivor-layout validation as
    /// [`Self::plan_collector_poll_minor_gc_relocation_destinations`], but it
    /// accepts explicit destination addresses instead of contiguous
    /// generation-space bases. It is intended for future destination-record
    /// allocation code that obtains concrete heap addresses before commit
    /// metadata is built. It still does not allocate destination records, reserve
    /// semispace pages, copy bytes, or update live evaluator slots.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the heap record count or allocation-safepoint
    /// state changed after planning, if a planned survivor no longer belongs to
    /// this heap, if survivor-layout storage cannot be reserved, if the explicit
    /// destination table is not a valid relocation map for `plan`, or if any
    /// destination address violates the source object's required alignment,
    /// overlaps another destination range, or overlaps a live source range.
    pub fn plan_collector_poll_minor_gc_explicit_relocation_destinations(
        &self,
        plan: &AllocationCollectorPollMinorGcPlan,
        destinations: &[MinorGcRelocationDestination],
    ) -> Result<AllocationCollectorPollMinorGcRelocationDestinations, EvalHeapError> {
        self.validate_collector_poll_plan_allocation_state(plan)?;
        let nursery_layouts = self.nursery_layouts_for_minor_gc_plan(plan.plan())?;
        Ok(plan.explicit_relocation_destination_plan(&nursery_layouts, destinations)?)
    }

    /// Builds relocation destinations from pre-reserved destination records.
    ///
    /// `reservations` must come from
    /// [`Self::reserve_current_young_minor_gc_destination_records`] and `plan`
    /// must be built after that reservation without intervening heap allocation.
    /// Only reservations for actual survivors are consumed; reserved records for
    /// dead young objects remain ordinary unreferenced heap records.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if `plan` is stale for the current heap, if
    /// `reservations` were captured for a different heap snapshot, if a survivor
    /// has no reserved destination record, if source or destination records no
    /// longer match their reservation metadata, or if the lower-level explicit
    /// relocation planner rejects the resulting destination table.
    pub fn plan_collector_poll_minor_gc_reserved_relocation_destinations(
        &self,
        plan: &AllocationCollectorPollMinorGcPlan,
        reservations: &AllocationCollectorPollMinorGcDestinationRecordReservations,
    ) -> Result<AllocationCollectorPollMinorGcRelocationDestinations, EvalHeapError> {
        self.validate_collector_poll_plan_allocation_state(plan)?;
        validate_destination_reservation_snapshot_matches_plan(plan, reservations)?;
        let nursery_layouts = self.nursery_layouts_for_minor_gc_plan(plan.plan())?;
        let mut destinations = Vec::new();
        destinations
            .try_reserve_exact(plan.plan().survivors().len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_DESTINATION_RECORD_RESERVATIONS_TABLE,
                entries: plan.plan().survivors().len(),
            })?;

        for survivor in plan.plan().survivors() {
            let reservation = reservations
                .reservations()
                .iter()
                .copied()
                .find(|reservation| reservation.source() == survivor.address())
                .ok_or(
                    EvalHeapError::CollectorPollMinorGcDestinationReservationMissing {
                        source_address: survivor.address(),
                    },
                )?;
            self.validate_minor_gc_destination_record_reservation(reservation)?;
            destinations.push(MinorGcRelocationDestination::new(
                survivor.address(),
                reservation.destination(),
            ));
        }

        Ok(plan.explicit_relocation_destination_plan(&nursery_layouts, &destinations)?)
    }

    /// Derives object byte-copy requests for caller-owned copy buffers.
    ///
    /// Each request is validated against the current heap side table before it is
    /// returned: the source object must still belong to the young worker domain
    /// and must still have the size and alignment captured by the lower-level
    /// object-copy plan. The returned plan does not expose raw heap bytes or
    /// allocate destination storage; it only describes the source/destination,
    /// length, and alignment that a future storage owner must bind to
    /// [`MinorGcObjectByteCopyBuffer`] values.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the heap record count or allocation-safepoint
    /// state changed after commit planning, if request storage cannot be reserved,
    /// if a planned source object no longer belongs to the young worker domain, or
    /// if the current source-record layout no longer matches the commit plan.
    pub fn collector_poll_minor_gc_object_byte_copy_plan(
        &self,
        commit_plan: &AllocationCollectorPollMinorGcCommitPlan<'_>,
    ) -> Result<AllocationCollectorPollObjectByteCopyPlan, EvalHeapError> {
        self.validate_collector_poll_commit_allocation_state(commit_plan)?;
        let copies = commit_plan.commit_plan().object_copies().copies();
        let mut requests = Vec::new();
        requests.try_reserve_exact(copies.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_OBJECT_BYTE_COPY_REQUESTS_TABLE,
                entries: copies.len(),
            }
        })?;
        for copy in copies {
            let record = self.record_for_minor_gc_survivor(copy.source())?;
            validate_object_byte_copy_record_layout(*copy, record)?;
            requests.push(AllocationCollectorPollObjectByteCopyRequest::from_copy(
                *copy,
            ));
        }
        Ok(AllocationCollectorPollObjectByteCopyPlan::new(requests))
    }
}
