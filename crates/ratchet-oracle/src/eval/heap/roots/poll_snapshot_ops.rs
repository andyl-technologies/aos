//! impl EvalHeap: minor-GC poll-input snapshots (roots, nursery/old
//! fields, layouts, reference slots) and generation/record resolution,
//! plus the free snapshot-derivation helpers they call.
//!
//! Moved verbatim from `heap/roots.rs` under the RFC-0007 §2 file-size cap;
//! the parent re-exports every public path and glob-imports each child so
//! sibling references keep resolving.

use super::*;

impl EvalHeap {
    pub(super) fn minor_gc_roots_for_poll_scan(
        &self,
        poll_scan: &AllocationCollectorPollScan,
    ) -> Result<Vec<ResolvedValueGeneration>, EvalHeapError> {
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(poll_scan.scan().roots().len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_ROOTS_TABLE,
                entries: poll_scan.scan().roots().len(),
            })?;
        for root in poll_scan.scan().roots() {
            roots.push(self.resolved_generation_for_value(root.value())?);
        }
        Ok(roots)
    }

    pub(super) fn current_nursery_objects(&self) -> Result<Vec<NurseryObjectAge>, EvalHeapError> {
        let mut nursery_objects = Vec::new();
        for record in &self.records {
            if generation_for_record(record) == HeapGeneration::Young {
                let entries = nursery_objects.len().checked_add(1).ok_or(
                    EvalHeapError::RootScanLengthOverflow {
                        table: MINOR_GC_NURSERY_OBJECTS_TABLE,
                    },
                )?;
                nursery_objects.try_reserve_exact(1).map_err(|_| {
                    EvalHeapError::RootScanAllocationFailed {
                        table: MINOR_GC_NURSERY_OBJECTS_TABLE,
                        entries,
                    }
                })?;
                nursery_objects.push(NurseryObjectAge::new(gc_address_for_record(record)?, 0));
            }
        }
        Ok(nursery_objects)
    }

    pub(super) fn current_nursery_fields(
        &self,
    ) -> Result<Vec<AllocationCollectorPollNurseryFields>, EvalHeapError> {
        let mut nursery_fields = Vec::new();
        for record in &self.records {
            if generation_for_record(record) != HeapGeneration::Young {
                continue;
            }
            let address = gc_address_for_record(record)?;
            let edges = self.scan_record_edges(record)?;
            let mut fields = Vec::new();
            fields.try_reserve_exact(edges.len()).map_err(|_| {
                EvalHeapError::RootScanAllocationFailed {
                    table: MINOR_GC_NURSERY_FIELD_VALUES_TABLE,
                    entries: edges.len(),
                }
            })?;
            for edge in edges {
                fields.push(AllocationCollectorPollNurseryField::new(
                    edge.source().clone(),
                    self.resolved_generation_for_value(edge.value())?,
                ));
            }

            let entries = nursery_fields.len().checked_add(1).ok_or(
                EvalHeapError::RootScanLengthOverflow {
                    table: MINOR_GC_NURSERY_FIELDS_TABLE,
                },
            )?;
            nursery_fields.try_reserve_exact(1).map_err(|_| {
                EvalHeapError::RootScanAllocationFailed {
                    table: MINOR_GC_NURSERY_FIELDS_TABLE,
                    entries,
                }
            })?;
            nursery_fields.push(AllocationCollectorPollNurseryFields::new(address, fields)?);
        }
        Ok(nursery_fields)
    }

    pub(super) fn current_old_fields(
        &self,
    ) -> Result<Vec<AllocationCollectorPollOldFields>, EvalHeapError> {
        let mut old_fields = Vec::new();
        for record in &self.records {
            let generation = generation_for_record(record);
            if !matches!(generation, HeapGeneration::Old | HeapGeneration::Permanent) {
                continue;
            }
            let address = gc_address_for_record(record)?;
            let edges = self.scan_record_edges(record)?;
            let mut fields = Vec::new();
            fields.try_reserve_exact(edges.len()).map_err(|_| {
                EvalHeapError::RootScanAllocationFailed {
                    table: MINOR_GC_OLD_FIELD_VALUES_TABLE,
                    entries: edges.len(),
                }
            })?;
            for edge in edges {
                fields.push(AllocationCollectorPollOldField::new(
                    edge.source().clone(),
                    self.resolved_generation_for_value(edge.value())?,
                ));
            }

            let entries =
                old_fields
                    .len()
                    .checked_add(1)
                    .ok_or(EvalHeapError::RootScanLengthOverflow {
                        table: MINOR_GC_OLD_FIELDS_TABLE,
                    })?;
            old_fields.try_reserve_exact(1).map_err(|_| {
                EvalHeapError::RootScanAllocationFailed {
                    table: MINOR_GC_OLD_FIELDS_TABLE,
                    entries,
                }
            })?;
            old_fields.push(AllocationCollectorPollOldFields::new(
                address, generation, fields,
            )?);
        }
        // Flat lists and attrsets are permanent edge carriers and contribute
        // old-field snapshots exactly as their record-backed forms did.
        for entry in self.flat_lists.iter() {
            let address = GcHeapAddress::new(entry.ptr().as_ptr() as usize)
                .map_err(EvalHeapError::GenerationalGc)?;
            let edges = self.scan_flat_list_edges(entry.object().payload())?;
            self.push_current_old_fields_entry(&mut old_fields, address, edges)?;
        }
        for entry in self.flat_attrs.iter() {
            let address = GcHeapAddress::new(entry.ptr().as_ptr() as usize)
                .map_err(EvalHeapError::GenerationalGc)?;
            let edges = self.scan_flat_attrs_edges(entry.object().payload())?;
            self.push_current_old_fields_entry(&mut old_fields, address, edges)?;
        }
        Ok(old_fields)
    }

    /// Appends one permanent flat object's old-field snapshot.
    ///
    /// Shared tail of the flat-list and flat-attrs arms of
    /// [`EvalHeap::current_old_fields`]; flat objects are permanent by
    /// construction.
    pub(super) fn push_current_old_fields_entry(
        &self,
        old_fields: &mut Vec<AllocationCollectorPollOldFields>,
        address: GcHeapAddress,
        edges: Vec<HeapEdge>,
    ) -> Result<(), EvalHeapError> {
        let mut fields = Vec::new();
        fields.try_reserve_exact(edges.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_OLD_FIELD_VALUES_TABLE,
                entries: edges.len(),
            }
        })?;
        for edge in edges {
            fields.push(AllocationCollectorPollOldField::new(
                edge.source().clone(),
                self.resolved_generation_for_value(edge.value())?,
            ));
        }

        let entries =
            old_fields
                .len()
                .checked_add(1)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: MINOR_GC_OLD_FIELDS_TABLE,
                })?;
        old_fields
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_OLD_FIELDS_TABLE,
                entries,
            })?;
        old_fields.push(AllocationCollectorPollOldFields::new(
            address,
            HeapGeneration::Permanent,
            fields,
        )?);
        Ok(())
    }

    pub(super) fn nursery_layouts_for_minor_gc_plan(
        &self,
        plan: &MinorGcPlan,
    ) -> Result<Vec<NurseryObjectLayout>, EvalHeapError> {
        let mut nursery_layouts = Vec::new();
        nursery_layouts
            .try_reserve_exact(plan.survivors().len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_NURSERY_LAYOUTS_TABLE,
                entries: plan.survivors().len(),
            })?;
        for survivor in plan.survivors() {
            let record = self.record_for_minor_gc_survivor(survivor.address())?;
            nursery_layouts.push(NurseryObjectLayout::new(
                survivor.address(),
                record.layout.size_bytes,
                record.layout.align,
            ));
        }
        Ok(nursery_layouts)
    }

    pub(super) fn minor_gc_reference_slots_for_plan(
        &self,
        poll_scan: &AllocationCollectorPollScan,
        remembered_set: RememberedSetSnapshot<'_>,
        card_table: Option<GcCardTableSnapshot<'_>>,
        plan: &MinorGcPlan,
        nursery_fields: &[AllocationCollectorPollNurseryFields],
        old_fields: &[AllocationCollectorPollOldFields],
    ) -> Result<Vec<AllocationCollectorPollReferenceSlot>, EvalHeapError> {
        let mut reference_slots = Vec::new();
        for root in poll_scan.scan().roots() {
            push_reference_slot(
                &mut reference_slots,
                AllocationCollectorPollReferenceSource::Root {
                    source: root.source().clone(),
                },
                self.resolved_generation_for_value(root.value())?,
                Some(root.value().tag()),
            )?;
        }

        for edge in remembered_set.edges() {
            self.push_remembered_edge_reference_slots(&mut reference_slots, *edge)?;
        }

        if let Some(card_table) = card_table {
            push_dirty_old_field_reference_slots(
                &mut reference_slots,
                card_table,
                remembered_set,
                plan,
                old_fields,
            )?;
        }

        for survivor in plan.survivors() {
            let fields = nursery_fields_for_survivor(nursery_fields, survivor.address())?;
            for (field_index, field) in fields.fields().iter().enumerate() {
                push_reference_slot(
                    &mut reference_slots,
                    AllocationCollectorPollReferenceSource::NurseryField {
                        object: survivor.address(),
                        field_index,
                        source: field.source().clone(),
                    },
                    field.value(),
                    None,
                )?;
            }
        }

        Ok(reference_slots)
    }

    pub(super) fn push_remembered_edge_reference_slots(
        &self,
        reference_slots: &mut Vec<AllocationCollectorPollReferenceSlot>,
        edge: RememberedEdge,
    ) -> Result<(), EvalHeapError> {
        let source_edges = match self.flat_edges_at_gc_address(edge.source())? {
            Some(edges) => edges,
            None => {
                let source_record = self.record_for_gc_address(edge.source(), "source")?;
                self.scan_record_edges(source_record)?
            }
        };
        let mut matched = false;

        for (field_index, source_edge) in source_edges.iter().enumerate() {
            let ResolvedValueGeneration::Heap {
                address,
                generation: HeapGeneration::Young,
            } = self.resolved_generation_for_value(source_edge.value())?
            else {
                continue;
            };
            if address != edge.target() {
                continue;
            }

            matched = true;
            push_reference_slot(
                reference_slots,
                AllocationCollectorPollReferenceSource::RememberedEdge {
                    edge,
                    field_index,
                    source: source_edge.source().clone(),
                },
                ResolvedValueGeneration::Heap {
                    address,
                    generation: HeapGeneration::Young,
                },
                None,
            )?;
        }

        if matched {
            Ok(())
        } else {
            Err(EvalHeapError::StaleCollectorPollRememberedEdge {
                source_address: edge.source(),
                target_address: edge.target(),
            })
        }
    }

    pub(super) fn current_heap_field_reference_value(
        &self,
        index: usize,
        source: &AllocationCollectorPollReferenceSource,
    ) -> Result<ResolvedValueGeneration, EvalHeapError> {
        match source {
            AllocationCollectorPollReferenceSource::Root { source } => {
                Err(EvalHeapError::CollectorPollReferenceSlotNotHeapBacked {
                    index,
                    root_source: source.clone(),
                })
            }
            AllocationCollectorPollReferenceSource::RememberedEdge {
                edge,
                field_index,
                source,
            } => self.current_heap_field_reference_value_at(
                index,
                edge.source(),
                *field_index,
                source,
            ),
            AllocationCollectorPollReferenceSource::DirtyOldField {
                object,
                field_index,
                source,
            } => self.current_heap_field_reference_value_at(index, *object, *field_index, source),
            AllocationCollectorPollReferenceSource::NurseryField {
                object,
                field_index,
                source,
            } => self.current_heap_field_reference_value_at(index, *object, *field_index, source),
        }
    }

    pub(super) fn current_heap_field_reference_value_at(
        &self,
        index: usize,
        object: GcHeapAddress,
        field_index: usize,
        expected_source: &HeapEdgeSource,
    ) -> Result<ResolvedValueGeneration, EvalHeapError> {
        let edges = match self.flat_edges_at_gc_address(object)? {
            Some(edges) => edges,
            None => {
                let record = self.record_for_reference_slot_object(object)?;
                self.scan_record_edges(record)?
            }
        };
        let Some(edge) = edges.get(field_index) else {
            return Err(EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
                index,
                expected: expected_source.clone(),
                actual: None,
            });
        };
        if edge.source() != expected_source {
            return Err(EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
                index,
                expected: expected_source.clone(),
                actual: Some(edge.source().clone()),
            });
        }
        self.resolved_generation_for_value(edge.value())
    }

    pub(super) fn record_for_scannable_value(
        &self,
        value: Value,
    ) -> Result<&HeapRecord, EvalHeapError> {
        let (tag, ptr) = heap_ptr(value)?;
        let record = self.record_or_unknown(tag, ptr)?;
        let actual = record.object.tag();
        if actual == tag {
            Ok(record)
        } else {
            Err(EvalHeapError::record_type_mismatch(tag, actual, ptr))
        }
    }

    pub(super) fn resolved_generation_for_value(
        &self,
        value: Value,
    ) -> Result<ResolvedValueGeneration, EvalHeapError> {
        let (tag, ptr) = heap_ptr(value)?;
        if self.shared.is_none()
            && matches!(
                tag,
                ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
            )
        {
            self.flat_verify(tag, ptr)?;
            return Ok(ResolvedValueGeneration::Heap {
                address: GcHeapAddress::new(ptr.as_ptr() as usize)
                    .map_err(EvalHeapError::GenerationalGc)?,
                generation: HeapGeneration::Permanent,
            });
        }
        let record = self.record_for_scannable_value(value)?;
        Ok(ResolvedValueGeneration::Heap {
            address: gc_address_for_record(record)?,
            generation: generation_for_record(record),
        })
    }

    pub(super) fn resolved_generation_for_thunk_resolve_value(
        &self,
        value: Value,
    ) -> Result<ResolvedValueGeneration, EvalHeapError> {
        if !is_scannable_eval_heap_value(value) {
            return Ok(ResolvedValueGeneration::Inline);
        }
        self.resolved_generation_for_value(value)
    }

    pub(super) fn generation_for_address(
        &self,
        address: GcHeapAddress,
        role: &'static str,
    ) -> Result<HeapGeneration, EvalHeapError> {
        // Flat strings/paths/lists (doc 30 FV-1) are permanent by
        // construction and have no record.
        if self.flat_tag_at_gc_address(address).is_some() {
            return Ok(HeapGeneration::Permanent);
        }
        let record = self.record_for_gc_address(address, role)?;
        Ok(generation_for_record(record))
    }

    pub(crate) fn allocation_domain_for_address(
        &self,
        address: GcHeapAddress,
        role: &'static str,
    ) -> Result<HeapAllocationDomain, EvalHeapError> {
        if self.flat_tag_at_gc_address(address).is_some() {
            return Ok(HeapAllocationDomain::PermanentShared);
        }
        let record = self.record_for_gc_address(address, role)?;
        Ok(record.allocation_domain)
    }

    /// Returns the flat-object tag at a GC address, if a flat store owns it.
    pub(super) fn flat_tag_at_gc_address(&self, address: GcHeapAddress) -> Option<ValueTag> {
        let ptr = NonNull::new(address.address_bits() as *mut HeapObject)?;
        self.flat_kind_tag(ptr)
    }

    /// Synthesizes precise edges for the flat object at a GC address, if a
    /// flat edge-carrying store (lists or attrsets) owns it.
    pub(super) fn flat_edges_at_gc_address(
        &self,
        address: GcHeapAddress,
    ) -> Result<Option<Vec<HeapEdge>>, EvalHeapError> {
        let Some(ptr) = NonNull::new(address.address_bits() as *mut HeapObject) else {
            return Ok(None);
        };
        if let Ok(list) = self.flat_list_payload(ptr) {
            return Ok(Some(self.scan_flat_list_edges(list)?));
        }
        if let Ok(payload) = self.flat_attrs_payload(ptr) {
            return Ok(Some(self.scan_flat_attrs_edges(payload)?));
        }
        Ok(None)
    }

    pub(super) fn record_for_gc_address(
        &self,
        address: GcHeapAddress,
        role: &'static str,
    ) -> Result<&HeapRecord, EvalHeapError> {
        self.records
            .record_at_address(address.address_bits())
            .ok_or(EvalHeapError::UnknownCollectorPollRememberedEdgeAddress { role, address })
    }

    pub(super) fn record_for_minor_gc_survivor(
        &self,
        address: GcHeapAddress,
    ) -> Result<&HeapRecord, EvalHeapError> {
        let record = &self.records[self.record_index_for_minor_gc_survivor(address)?];
        Ok(record)
    }

    pub(super) fn record_index_for_minor_gc_survivor(
        &self,
        address: GcHeapAddress,
    ) -> Result<usize, EvalHeapError> {
        let record_index = self
            .records
            .index_of_address(address.address_bits())
            .ok_or(EvalHeapError::UnknownCollectorPollSurvivorAddress { address })?;
        let record = &self.records[record_index];
        if generation_for_record(record) != HeapGeneration::Young {
            return Err(EvalHeapError::GenerationalGc(
                GenerationalGcError::StaleNurseryObjectLayout { address },
            ));
        }
        Ok(record_index)
    }

    pub(super) fn record_for_reference_slot_object(
        &self,
        address: GcHeapAddress,
    ) -> Result<&HeapRecord, EvalHeapError> {
        let index = self.record_index_for_reference_slot_object(address)?;
        Ok(&self.records[index])
    }

    pub(super) fn record_index_for_reference_slot_object(
        &self,
        address: GcHeapAddress,
    ) -> Result<usize, EvalHeapError> {
        self.records
            .index_of_address(address.address_bits())
            .ok_or(EvalHeapError::UnknownCollectorPollReferenceSlotAddress { address })
    }

    pub(super) fn validate_collector_poll_plan_allocation_state(
        &self,
        plan: &AllocationCollectorPollMinorGcPlan,
    ) -> Result<(), EvalHeapError> {
        if plan.heap_records() != self.scannable_object_count() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "heap record count changed since minor-GC planning",
                expected_records: plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if plan.worker_region_owner() != self.region_owner {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region owner changed since minor-GC planning",
                expected_records: plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if plan.worker_region_epoch() != self.worker_region_epoch {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region epoch changed since minor-GC planning",
                expected_records: plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if plan.allocation_safepoints() != self.allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker allocation safepoints changed since minor-GC planning",
                expected_records: plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if plan.permanent_allocation_safepoints() != self.permanent_allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "permanent allocation safepoints changed since minor-GC planning",
                expected_records: plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        Ok(())
    }

    pub(super) fn validate_collector_poll_commit_allocation_state(
        &self,
        commit_plan: &AllocationCollectorPollMinorGcCommitPlan<'_>,
    ) -> Result<(), EvalHeapError> {
        if commit_plan.heap_records() != self.scannable_object_count() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "heap record count changed since minor-GC commit planning",
                expected_records: commit_plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if commit_plan.worker_region_owner() != self.region_owner {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region owner changed since minor-GC commit planning",
                expected_records: commit_plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if commit_plan.worker_region_epoch() != self.worker_region_epoch {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region epoch changed since minor-GC commit planning",
                expected_records: commit_plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if commit_plan.allocation_safepoints() != self.allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker allocation safepoints changed since minor-GC commit planning",
                expected_records: commit_plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if commit_plan.permanent_allocation_safepoints() != self.permanent_allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "permanent allocation safepoints changed since minor-GC commit planning",
                expected_records: commit_plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        Ok(())
    }
}

pub(super) fn validate_destination_reservation_snapshot_matches_plan(
    plan: &AllocationCollectorPollMinorGcPlan,
    reservations: &AllocationCollectorPollMinorGcDestinationRecordReservations,
) -> Result<(), EvalHeapError> {
    if reservations.heap_records() != plan.heap_records() {
        return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "destination reservation heap record count differs from minor-GC plan",
            expected_records: plan.heap_records(),
            actual_records: reservations.heap_records(),
        });
    }
    if reservations.worker_region_owner() != plan.worker_region_owner() {
        return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "destination reservation worker region owner differs from minor-GC plan",
            expected_records: plan.heap_records(),
            actual_records: reservations.heap_records(),
        });
    }
    if reservations.worker_region_epoch() != plan.worker_region_epoch() {
        return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "destination reservation worker region epoch differs from minor-GC plan",
            expected_records: plan.heap_records(),
            actual_records: reservations.heap_records(),
        });
    }
    if reservations.allocation_safepoints() != plan.allocation_safepoints() {
        return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "destination reservation worker allocation safepoints differ from minor-GC plan",
            expected_records: plan.heap_records(),
            actual_records: reservations.heap_records(),
        });
    }
    if reservations.permanent_allocation_safepoints() != plan.permanent_allocation_safepoints() {
        return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "destination reservation permanent allocation safepoints differ from minor-GC plan",
            expected_records: plan.heap_records(),
            actual_records: reservations.heap_records(),
        });
    }
    Ok(())
}

pub(super) fn nursery_field_views(
    nursery_fields: &[AllocationCollectorPollNurseryFields],
) -> Result<Vec<NurseryObjectFields<'_>>, EvalHeapError> {
    let mut views = Vec::new();
    views.try_reserve_exact(nursery_fields.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: MINOR_GC_NURSERY_FIELDS_TABLE,
            entries: nursery_fields.len(),
        }
    })?;
    for object in nursery_fields {
        views.push(NurseryObjectFields::new(
            object.address(),
            object.field_values(),
        ));
    }
    Ok(views)
}

pub(super) fn old_field_views(
    old_fields: &[AllocationCollectorPollOldFields],
) -> Result<Vec<MinorGcOldObjectFields<'_>>, GenerationalGcError> {
    let mut views = Vec::new();
    views.try_reserve_exact(old_fields.len()).map_err(|_| {
        GenerationalGcError::MinorGcOldFieldRescanAllocationFailed {
            rescans: old_fields.len(),
        }
    })?;
    for object in old_fields {
        views.push(MinorGcOldObjectFields::new(
            object.address(),
            object.generation(),
            object.field_values(),
        ));
    }
    Ok(views)
}

pub(super) fn remembered_set_with_dirty_old_field_edges(
    remembered_set: RememberedSetSnapshot<'_>,
    card_table: GcCardTableSnapshot<'_>,
    old_fields: &[AllocationCollectorPollOldFields],
) -> Result<RememberedSet, GenerationalGcError> {
    let mut frontier = remembered_set_from_snapshot(remembered_set)?;
    for object in old_fields {
        if !card_table.covers_source(object.address()) {
            continue;
        }
        for field in object.fields() {
            let ResolvedValueGeneration::Heap {
                address: target,
                generation: HeapGeneration::Young,
            } = field.value()
            else {
                continue;
            };
            frontier.record(RememberedEdge::new(object.address(), target))?;
        }
    }
    Ok(frontier)
}

pub(super) fn push_dirty_old_field_reference_slots(
    reference_slots: &mut Vec<AllocationCollectorPollReferenceSlot>,
    card_table: GcCardTableSnapshot<'_>,
    remembered_set: RememberedSetSnapshot<'_>,
    plan: &MinorGcPlan,
    old_fields: &[AllocationCollectorPollOldFields],
) -> Result<(), EvalHeapError> {
    for object in old_fields {
        if !card_table.covers_source(object.address()) {
            continue;
        }
        for (field_index, field) in object.fields().iter().enumerate() {
            let ResolvedValueGeneration::Heap {
                address: target,
                generation: HeapGeneration::Young,
            } = field.value()
            else {
                continue;
            };
            if remembered_set
                .edges()
                .contains(&RememberedEdge::new(object.address(), target))
            {
                continue;
            }
            if !plan
                .survivors()
                .iter()
                .any(|survivor| survivor.address() == target)
            {
                continue;
            }
            push_reference_slot(
                reference_slots,
                AllocationCollectorPollReferenceSource::DirtyOldField {
                    object: object.address(),
                    field_index,
                    source: field.source().clone(),
                },
                field.value(),
                None,
            )?;
        }
    }
    Ok(())
}

pub(super) fn nursery_fields_for_survivor(
    nursery_fields: &[AllocationCollectorPollNurseryFields],
    address: GcHeapAddress,
) -> Result<&AllocationCollectorPollNurseryFields, EvalHeapError> {
    nursery_fields
        .iter()
        .find(|fields| fields.address() == address)
        .ok_or(EvalHeapError::GenerationalGc(
            GenerationalGcError::MissingNurseryObjectFields { address },
        ))
}

pub(super) fn remembered_set_from_snapshot(
    snapshot: RememberedSetSnapshot<'_>,
) -> Result<RememberedSet, GenerationalGcError> {
    let mut remembered_set = RememberedSet::with_epoch(snapshot.epoch());
    for edge in snapshot.edges() {
        remembered_set.record(*edge)?;
    }
    Ok(remembered_set)
}

pub(super) fn owned_card_table_from_snapshot(
    snapshot: GcCardTableSnapshot<'_>,
) -> Result<GcCardTable, GenerationalGcError> {
    let mut card_table = GcCardTable::new(snapshot.card_size_bytes())?;
    for card in snapshot.dirty_cards() {
        card_table.mark_source(card.source())?;
    }
    Ok(card_table)
}

pub(super) fn heap_field_writeback_source<'a>(
    source: &'a AllocationCollectorPollReferenceSource,
    object_copies: &MinorGcObjectCopyPlan,
) -> Result<Option<(GcHeapAddress, GcHeapAddress, usize, &'a HeapEdgeSource)>, EvalHeapError> {
    match source {
        AllocationCollectorPollReferenceSource::Root { .. } => Ok(None),
        AllocationCollectorPollReferenceSource::RememberedEdge {
            edge,
            field_index,
            source,
        } => Ok(Some((edge.source(), edge.source(), *field_index, source))),
        AllocationCollectorPollReferenceSource::DirtyOldField {
            object,
            field_index,
            source,
        } => Ok(Some((*object, *object, *field_index, source))),
        AllocationCollectorPollReferenceSource::NurseryField {
            object,
            field_index,
            source,
        } => Ok(Some((
            *object,
            minor_gc_writeback_object_for_nursery_field(object_copies, *object)?,
            *field_index,
            source,
        ))),
    }
}

pub(super) fn validate_reference_slot_matches_rewrite(
    index: usize,
    slot: &AllocationCollectorPollReferenceSlot,
    rewrite: MinorGcReferenceRewrite,
) -> Result<ResolvedValueGeneration, EvalHeapError> {
    let expected = slot.value();
    let rewrite_source = ResolvedValueGeneration::Heap {
        address: rewrite.source(),
        generation: HeapGeneration::Young,
    };
    if expected != rewrite_source {
        return Err(EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index,
            expected,
            actual: rewrite_source,
        });
    }
    Ok(expected)
}

pub(super) fn value_for_resolved_generation(
    tag: ValueTag,
    value: ResolvedValueGeneration,
) -> Result<Value, EvalHeapError> {
    let ResolvedValueGeneration::Heap { address, .. } = value else {
        return Err(EvalHeapError::CollectorPollRootWritebackNonHeapValue { tag, value });
    };
    let ptr = NonNull::new(address.address_bits() as *mut HeapObject)
        .ok_or(EvalHeapError::Value(ValueError::NullHeapPointer { tag }))?;
    Value::heap(tag, ptr).map_err(EvalHeapError::Value)
}

pub(super) fn minor_gc_writeback_object_for_nursery_field(
    object_copies: &MinorGcObjectCopyPlan,
    object: GcHeapAddress,
) -> Result<GcHeapAddress, EvalHeapError> {
    object_copies
        .copies()
        .iter()
        .find(|copy| copy.source() == object)
        .map(|copy| copy.destination())
        .ok_or(EvalHeapError::GenerationalGc(
            GenerationalGcError::MissingMinorGcRelocationDestination { address: object },
        ))
}

pub(super) fn push_reference_slot(
    slots: &mut Vec<AllocationCollectorPollReferenceSlot>,
    source: AllocationCollectorPollReferenceSource,
    value: ResolvedValueGeneration,
    value_tag: Option<ValueTag>,
) -> Result<(), EvalHeapError> {
    let entries = slots
        .len()
        .checked_add(1)
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: MINOR_GC_REFERENCE_SLOTS_TABLE,
        })?;
    slots
        .try_reserve_exact(1)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: MINOR_GC_REFERENCE_SLOTS_TABLE,
            entries,
        })?;
    slots.push(AllocationCollectorPollReferenceSlot::new(
        source, value, value_tag,
    ));
    Ok(())
}
