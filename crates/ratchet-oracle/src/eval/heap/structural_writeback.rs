//! Transactional structural-hash repair after moving-GC field rewrites.
//!
//! Permanent flat lists and attrsets can point into the moving worker heap.
//! Rewriting one such child changes the parent's address-based structural key,
//! so the flat header and hash-cons bucket must move together. This module
//! builds replacement tables and header writes from staged payloads before the
//! live commit mutates anything; publication is then allocation-free.

use std::ptr::NonNull;

use super::arena::{attrs_structural_hash, list_structural_hash};
#[cfg(test)]
use super::environment_writeback::EnvironmentWritebackStage;
#[cfg(test)]
use super::roots::{
    CollectorPollDirectHeapFieldWrite, MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
};
use super::*;

/// Prevalidated structural hashes and replacement hash-cons tables.
pub(super) struct StructuralWritebackStage {
    record_hashes: Vec<(usize, HotXxh3Hash)>,
    flat_list_hashes: Vec<(NonNull<HeapObject>, HotXxh3Hash)>,
    flat_attrs_hashes: Vec<(NonNull<HeapObject>, HotXxh3Hash)>,
    list_cons: Option<HashConsTable<HotXxh3Hash, Value>>,
    attrs_cons: Option<HashConsTable<HotXxh3Hash, Value>>,
}

impl EvalHeap {
    #[cfg(test)]
    #[allow(clippy::type_complexity)]
    pub(super) fn stage_collector_poll_minor_gc_direct_heap_field_writes(
        &self,
        writes: &[CollectorPollDirectHeapFieldWrite],
    ) -> Result<
        (
            Vec<(usize, HeapObjectValue)>,
            Vec<(NonNull<HeapObject>, NixList)>,
            Vec<(NonNull<HeapObject>, FlatAttrs)>,
            EnvironmentWritebackStage,
            StructuralWritebackStage,
        ),
        EvalHeapError,
    > {
        let mut staged: Vec<(usize, HeapObjectValue)> = Vec::new();
        staged.try_reserve_exact(writes.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
                entries: writes.len(),
            }
        })?;
        let mut staged_flat_lists: Vec<(NonNull<HeapObject>, NixList)> = Vec::new();
        let mut staged_flat_attrs: Vec<(NonNull<HeapObject>, FlatAttrs)> = Vec::new();
        let mut staged_environment = EnvironmentWritebackStage::try_new(writes.len()).map_err(
            |_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
                entries: writes.len(),
            },
        )?;

        self.stage_collector_poll_minor_gc_direct_heap_field_writes_into(
            writes,
            &mut staged,
            &mut staged_flat_lists,
            &mut staged_flat_attrs,
            &mut staged_environment,
            writes.len(),
        )?;
        let staged_structural = self.stage_structural_writebacks(
            &staged,
            &staged_flat_lists,
            &staged_flat_attrs,
        )?;

        Ok((
            staged,
            staged_flat_lists,
            staged_flat_attrs,
            staged_environment,
            staged_structural,
        ))
    }

    /// Stages structural hashes for every payload changed by field writeback.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if repair storage or a replacement hash-cons
    /// table cannot be reserved, or if an interned value no longer resolves to
    /// its typed heap payload.
    pub(super) fn stage_structural_writebacks(
        &self,
        staged_records: &[(usize, HeapObjectValue)],
        staged_flat_lists: &[(NonNull<HeapObject>, NixList)],
        staged_flat_attrs: &[(NonNull<HeapObject>, FlatAttrs)],
    ) -> Result<StructuralWritebackStage, EvalHeapError> {
        let record_list_count = staged_records
            .iter()
            .filter(|(_, object)| matches!(object, HeapObjectValue::List(_)))
            .count();
        let mut record_hashes = Vec::new();
        record_hashes
            .try_reserve_exact(record_list_count)
            .map_err(|_| structural_repair_allocation_failed(record_list_count))?;
        for (index, object) in staged_records {
            if let HeapObjectValue::List(list) = object {
                record_hashes.push((*index, list_structural_hash(list)));
            }
        }

        let mut flat_list_hashes = Vec::new();
        flat_list_hashes
            .try_reserve_exact(staged_flat_lists.len())
            .map_err(|_| structural_repair_allocation_failed(staged_flat_lists.len()))?;
        for (ptr, list) in staged_flat_lists {
            flat_list_hashes.push((*ptr, list_structural_hash(list)));
        }

        let mut flat_attrs_hashes = Vec::new();
        flat_attrs_hashes
            .try_reserve_exact(staged_flat_attrs.len())
            .map_err(|_| structural_repair_allocation_failed(staged_flat_attrs.len()))?;
        for (ptr, attrs) in staged_flat_attrs {
            let metadata = self.flat_attrs_payload(*ptr)?.metadata;
            flat_attrs_hashes.push((*ptr, attrs_structural_hash(metadata, attrs)));
        }

        let lists_changed = !record_hashes.is_empty() || !flat_list_hashes.is_empty();
        let list_cons = lists_changed
            .then(|| {
                self.list_cons.try_rekey_committed(|value| {
                    self.projected_list_structural_hash(
                        *value,
                        staged_records,
                        staged_flat_lists,
                    )
                })
            })
            .transpose()?;
        let attrs_cons = (!flat_attrs_hashes.is_empty())
            .then(|| {
                self.attrs_cons.try_rekey_committed(|value| {
                    self.projected_attrs_structural_hash(*value, staged_flat_attrs)
                })
            })
            .transpose()?;

        Ok(StructuralWritebackStage {
            record_hashes,
            flat_list_hashes,
            flat_attrs_hashes,
            list_cons,
            attrs_cons,
        })
    }

    /// Publishes staged structural hashes and hash-cons tables without failure.
    pub(super) fn commit_structural_writebacks(&mut self, stage: StructuralWritebackStage) {
        for (index, hash) in stage.record_hashes {
            self.records[index].structural_hash = Some(hash);
        }
        for (ptr, hash) in stage.flat_list_hashes {
            if let Err(error) =
                self.flat_lists
                    .update_structural_hash(ptr, FlatObjectKind::List, hash.raw())
            {
                unreachable!("staged flat-list structural hash failed to commit: {error}");
            }
            self.flat_stale_hashes.remove(&(ptr.as_ptr() as usize));
        }
        for (ptr, hash) in stage.flat_attrs_hashes {
            if let Err(error) =
                self.flat_attrs
                    .update_structural_hash(ptr, FlatObjectKind::Attrs, hash.raw())
            {
                unreachable!("staged flat-attrs structural hash failed to commit: {error}");
            }
            self.flat_stale_hashes.remove(&(ptr.as_ptr() as usize));
        }
        if let Some(list_cons) = stage.list_cons {
            self.list_cons = list_cons;
        }
        if let Some(attrs_cons) = stage.attrs_cons {
            self.attrs_cons = attrs_cons;
        }
    }

    fn projected_list_structural_hash(
        &self,
        value: Value,
        staged_records: &[(usize, HeapObjectValue)],
        staged_flat_lists: &[(NonNull<HeapObject>, NixList)],
    ) -> Result<HotXxh3Hash, EvalHeapError> {
        let ptr = value.as_list_ptr().map_err(EvalHeapError::Value)?;
        if let Some((_, list)) = staged_flat_lists
            .iter()
            .find(|(candidate, _)| *candidate == ptr)
        {
            return Ok(list_structural_hash(list));
        }
        if self.flat_lists.kind_of(ptr).is_some() {
            return Ok(list_structural_hash(self.flat_list_payload(ptr)?));
        }
        let Some(index) = self.records.index_of_address(ptr.as_ptr() as usize) else {
            return Err(EvalHeapError::unknown(ValueTag::List, ptr));
        };
        let object = staged_records
            .iter()
            .find(|(candidate, _)| *candidate == index)
            .map_or(&self.records[index].object, |(_, object)| object);
        let HeapObjectValue::List(list) = object else {
            return Err(EvalHeapError::record_type_mismatch(
                ValueTag::List,
                object.tag(),
                ptr,
            ));
        };
        Ok(list_structural_hash(list))
    }

    fn projected_attrs_structural_hash(
        &self,
        value: Value,
        staged_flat_attrs: &[(NonNull<HeapObject>, FlatAttrs)],
    ) -> Result<HotXxh3Hash, EvalHeapError> {
        let ptr = value.as_attrs_ptr().map_err(EvalHeapError::Value)?;
        let payload = self.flat_attrs_payload(ptr)?;
        let attrs = staged_flat_attrs
            .iter()
            .find(|(candidate, _)| *candidate == ptr)
            .map_or(&payload.attrs, |(_, attrs)| attrs);
        Ok(attrs_structural_hash(payload.metadata, attrs))
    }
}

fn structural_repair_allocation_failed(entries: usize) -> EvalHeapError {
    EvalHeapError::RootScanAllocationFailed {
        table: "structural writebacks",
        entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attrs::AttrEntry;
    use crate::eval::EvalEnv;
    use crate::syntax::SymbolTable;

    fn gc_address(value: Value) -> GcHeapAddress {
        let ptr = value.as_heap_ptr().expect("value is heap-backed");
        GcHeapAddress::new(ptr.as_ptr() as usize).expect("heap address is nonzero")
    }

    fn lambda(heap: &mut EvalHeap, id: u32) -> Value {
        heap.alloc_lambda(EvalLambda::new(
            IrId::new(id),
            IrId::new(id),
            FrameId::new(id),
            EvalEnv::default(),
        ))
        .expect("lambda allocates")
    }

    fn promote(
        heap: &mut EvalHeap,
        source: Value,
        destination: Value,
    ) -> AllocationCollectorPollObjectByteCopyRequest {
        let request = heap
            .collector_poll_minor_gc_object_byte_copy_request_for_test(
                source,
                destination,
                MinorGcSurvivorAction::PromoteToOld,
            )
            .expect("copy request builds");
        let plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![request]);
        heap.apply_collector_poll_minor_gc_object_body_writes(&plan)
            .expect("object body copies");
        let generations = plan
            .object_generation_write_plan()
            .expect("generation plan builds");
        heap.apply_collector_poll_minor_gc_object_generation_writes(&generations)
            .expect("destination promotes");
        request
    }

    #[test]
    fn list_writeback_repairs_header_and_hash_cons_bucket() {
        let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
        heap.use_record_worker_closures_for_gc_scaffolding();
        let child = lambda(&mut heap, 1);
        let destination = lambda(&mut heap, 2);
        let parent = heap
            .alloc_list(NixList::new(vec![child]))
            .expect("parent list allocates");
        let request = promote(&mut heap, child, destination);
        let write = AllocationCollectorPollDirectHeapFieldWrite::new(
            HeapAllocationDomain::PermanentShared,
            gc_address(parent),
            0,
            HeapEdgeSource::ListElement { index: 0 },
            ResolvedValueGeneration::Heap {
                address: gc_address(destination),
                generation: HeapGeneration::Old,
            },
            request,
        );

        heap.apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
            .expect("list field relocates");

        let ptr = parent.as_list_ptr().expect("parent remains a list");
        let expected = NixList::new(vec![destination]);
        let object = heap
            .flat_lists
            .resolve(ptr, FlatObjectKind::List)
            .expect("parent list resolves");
        assert_eq!(object.structural_hash(), list_structural_hash(&expected).raw());
        assert!(!heap.flat_stale_hashes.contains(&(ptr.as_ptr() as usize)));
        let identical = heap.alloc_list(expected).expect("identical list admits");
        assert!(identical.raw_eq(parent));
        let old = heap
            .alloc_list(NixList::new(vec![child]))
            .expect("old payload allocates independently");
        assert!(!old.raw_eq(parent));
    }

    #[test]
    fn attrs_writeback_repairs_header_and_hash_cons_bucket() {
        let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
        heap.use_record_worker_closures_for_gc_scaffolding();
        let mut symbols = SymbolTable::new();
        let key = symbols.intern(b"name").expect("symbol interns");
        let child = lambda(&mut heap, 1);
        let destination = lambda(&mut heap, 2);
        let attrs = FlatAttrs::new(vec![AttrEntry::new(key, child)], &symbols)
            .expect("attrs build");
        let parent = heap.alloc_attrs(0, attrs).expect("parent attrs allocate");
        let request = promote(&mut heap, child, destination);
        let write = AllocationCollectorPollDirectHeapFieldWrite::new(
            HeapAllocationDomain::PermanentShared,
            gc_address(parent),
            0,
            HeapEdgeSource::AttrBinding {
                shape: 0,
                slot: 0,
                key,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(destination),
                generation: HeapGeneration::Old,
            },
            request,
        );

        heap.apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
            .expect("attrs field relocates");

        let ptr = parent.as_attrs_ptr().expect("parent remains attrs");
        let expected = FlatAttrs::new(vec![AttrEntry::new(key, destination)], &symbols)
            .expect("expected attrs build");
        let object = heap
            .flat_attrs
            .resolve(ptr, FlatObjectKind::Attrs)
            .expect("parent attrs resolve");
        assert_eq!(
            object.structural_hash(),
            attrs_structural_hash(object.payload().metadata, &expected).raw()
        );
        assert!(!heap.flat_stale_hashes.contains(&(ptr.as_ptr() as usize)));
        let identical = heap
            .alloc_attrs(0, expected)
            .expect("identical attrs admit");
        assert!(identical.raw_eq(parent));
        let old_attrs = FlatAttrs::new(vec![AttrEntry::new(key, child)], &symbols)
            .expect("old attrs rebuild");
        let old = heap
            .alloc_attrs(0, old_attrs)
            .expect("old payload allocates independently");
        assert!(!old.raw_eq(parent));
    }
}
