//! Prepublication planning for whole-permanent Candidate-C evacuation.
//!
//! This module turns one precise mutator-root scan into the immutable pieces
//! of a publication transaction: the exact reachable permanent batch, typed
//! root replacements, translated weak hash-cons tables, and a complete source
//! retirement inventory. It deliberately does not install the destination,
//! mutate roots or heap fields, or retire source storage.

use thiserror::Error;

use super::permanent_batch_copy::UnpublishedPermanentBatch;
use super::*;

const PERMANENT_PUBLICATION_CANDIDATES: &str = "permanent-publication-candidates";
const PERMANENT_PUBLICATION_ROOTS: &str = "permanent-publication-roots";
const PERMANENT_PUBLICATION_RETIREMENT: &str = "permanent-publication-retirement";

/// Fallible, source-untouched state for one permanent publication transaction.
pub(in crate::eval) struct PreparedPermanentPublication {
    batch: UnpublishedPermanentBatch,
    root_writebacks: AllocationCollectorPollRootWritebackPlan,
    string_cons: HashConsTable<HotXxh3Hash, Value>,
    path_cons: HashConsTable<HotXxh3Hash, Value>,
    list_cons: HashConsTable<HotXxh3Hash, Value>,
    attrs_cons: HashConsTable<HotXxh3Hash, Value>,
    heap_writebacks: Vec<PermanentHeapWriteback>,
    heap_healing: PermanentHeapHealingStage,
    retirement: Vec<PermanentRetirement>,
}

/// Published healing state whose source permanent allocations remain live.
///
/// The evaluator retains this token across root writeback and the residual
/// alias audit. Dropping it is safe: the installed destination and healed heap
/// fields remain valid while source objects remain available. Only
/// [`EvalHeap::retire_published_permanent_source`] consumes it.
pub(in crate::eval) struct PublishedPermanentPublication {
    retirement: Vec<PermanentRetirement>,
    copied_objects: usize,
    healed_heap_fields: usize,
}

/// Reports source retirement and safe zero-liveness page advice.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::eval) struct PermanentRetirementReport {
    retired_objects: usize,
    copied_objects: usize,
    healed_heap_fields: usize,
    candidate_pages: usize,
    advised_pages: usize,
    advice_failed: bool,
}

impl PermanentRetirementReport {
    /// Returns the number of source permanent allocations retired.
    pub(in crate::eval) const fn retired_objects(self) -> usize {
        self.retired_objects
    }

    /// Returns the number of reachable permanent objects copied.
    pub(in crate::eval) const fn copied_objects(self) -> usize {
        self.copied_objects
    }

    /// Returns the number of non-permanent heap fields healed.
    pub(in crate::eval) const fn healed_heap_fields(self) -> usize {
        self.healed_heap_fields
    }

    /// Returns the number of zero-liveness source pages selected.
    pub(in crate::eval) const fn candidate_pages(self) -> usize {
        self.candidate_pages
    }

    /// Returns the number of source pages that accepted dead-page advice.
    pub(in crate::eval) const fn advised_pages(self) -> usize {
        self.advised_pages
    }

    /// Returns whether the OS rejected safe page advice after retirement.
    pub(in crate::eval) const fn advice_failed(self) -> bool {
        self.advice_failed
    }
}

impl PreparedPermanentPublication {
    /// Returns the prevalidated root replacements.
    pub(in crate::eval) const fn root_writebacks(
        &self,
    ) -> &AllocationCollectorPollRootWritebackPlan {
        &self.root_writebacks
    }

    /// Returns the complete compact forwarding directory.
    pub(in crate::eval::heap) const fn forwarding(&self) -> &EvacuationForwardingDirectory {
        self.batch.forwarding()
    }

    /// Returns the number of reachable objects copied into the destination.
    pub(in crate::eval) fn copied_objects(&self) -> usize {
        self.batch.forwarding().len()
    }

    /// Returns the number of source permanent allocations inventoried for retirement.
    pub(in crate::eval) fn retirement_objects(&self) -> usize {
        self.retirement.len()
    }

    /// Returns the number of non-permanent heap fields staged for healing.
    pub(in crate::eval) fn heap_field_writebacks(&self) -> usize {
        self.heap_writebacks.len()
    }
}

#[derive(Clone, Copy)]
struct PermanentRetirement {
    ptr: NonNull<HeapObject>,
    kind: FlatObjectKind,
}

#[derive(Clone)]
struct PermanentHeapWriteback {
    owner: Value,
    field_index: usize,
    source: HeapEdgeSource,
    expected: Value,
    replacement: Value,
}

struct PermanentHeapHealingStage {
    records: Vec<(usize, HeapObjectValue)>,
    closures: Vec<crate::eval::heap::roots::StagedFlatClosureWrite>,
    environment: crate::eval::heap::environment_writeback::EnvironmentWritebackStage,
}

impl EvalHeap {
    /// Prepares the non-mutating half of a whole-permanent publication.
    ///
    /// `scan` must have been built from mutator roots rather than
    /// [`Self::interned_root_set`]: hash-cons tables are weak indexes and must
    /// not make otherwise dead permanent objects survive. Every reachable
    /// Candidate-C string, path, list, and attrset in the nursery domain is
    /// copied. Only translated committed hash-cons entries enter the staged
    /// replacement tables.
    ///
    /// # Errors
    ///
    /// Returns [`PermanentPublicationError`] if the heap is not a serial
    /// Candidate-C heap, a scanned permanent value is foreign or malformed,
    /// exact staging storage cannot be reserved, batch copying fails, root
    /// metadata cannot be encoded, or a translated hash-cons table cannot be
    /// rebuilt.
    pub(in crate::eval) fn prepare_permanent_publication(
        &self,
        scan: &PreciseHeapScan,
    ) -> Result<PreparedPermanentPublication, PermanentPublicationError> {
        if self.shared.is_some() {
            return Err(PermanentPublicationError::SharedHeap);
        }
        let source_domain = self
            .flat_arena
            .arena_domain_id()
            .ok_or(PermanentPublicationError::SourceDomainUnavailable)?;

        let mut candidates = Vec::new();
        candidates
            .try_reserve_exact(scan.objects().len())
            .map_err(|_| PermanentPublicationError::AllocationFailed {
                table: PERMANENT_PUBLICATION_CANDIDATES,
                entries: scan.objects().len(),
            })?;
        for object in scan.objects() {
            let value = object.value();
            if is_source_permanent_value(value, source_domain) {
                candidates.push(value);
            }
        }
        candidates.sort_unstable_by_key(|value| {
            value
                .word()
                .arena_index()
                .map(crate::heap::ArenaIndex::raw)
                .unwrap_or(u32::MAX)
        });
        candidates.dedup_by(|left, right| left.raw_eq(*right));

        let batch = UnpublishedPermanentBatch::copy_values_from(self, &candidates)
            .map_err(|error| PermanentPublicationError::Batch(error.to_string()))?;
        let root_writebacks = prepare_root_writebacks(scan.roots(), &batch)?;
        let string_cons = translate_hash_cons_table(&self.string_cons, &batch)?;
        let path_cons = translate_hash_cons_table(&self.path_cons, &batch)?;
        let list_cons = translate_hash_cons_table(&self.list_cons, &batch)?;
        let attrs_cons = translate_hash_cons_table(&self.attrs_cons, &batch)?;
        let heap_writebacks = prepare_heap_writebacks(scan.objects(), &batch)?;
        let heap_healing = self.stage_permanent_heap_healing(&heap_writebacks)?;
        let retirement = self.permanent_retirement_inventory()?;

        Ok(PreparedPermanentPublication {
            batch,
            root_writebacks,
            string_cons,
            path_cons,
            list_cons,
            attrs_cons,
            heap_writebacks,
            heap_healing,
            retirement,
        })
    }

    fn permanent_retirement_inventory(
        &self,
    ) -> Result<Vec<PermanentRetirement>, PermanentPublicationError> {
        let entries = self
            .flat
            .live_len()
            .checked_add(self.flat_lists.live_len())
            .and_then(|count| count.checked_add(self.flat_attrs.live_len()))
            .ok_or(PermanentPublicationError::PopulationOverflow)?;
        let mut inventory = Vec::new();
        inventory.try_reserve_exact(entries).map_err(|_| {
            PermanentPublicationError::AllocationFailed {
                table: PERMANENT_PUBLICATION_RETIREMENT,
                entries,
            }
        })?;
        for object in self.flat.iter() {
            inventory.push(PermanentRetirement {
                ptr: object.ptr(),
                kind: object.object().kind(),
            });
        }
        for object in self.flat_lists.iter() {
            inventory.push(PermanentRetirement {
                ptr: object.ptr(),
                kind: object.object().kind(),
            });
        }
        for object in self.flat_attrs.iter() {
            inventory.push(PermanentRetirement {
                ptr: object.ptr(),
                kind: object.object().kind(),
            });
        }
        Ok(inventory)
    }

    fn stage_permanent_heap_healing(
        &self,
        writebacks: &[PermanentHeapWriteback],
    ) -> Result<PermanentHeapHealingStage, PermanentPublicationError> {
        let entries = writebacks.len();
        let mut planned = Vec::new();
        planned.try_reserve_exact(entries).map_err(|_| {
            PermanentPublicationError::AllocationFailed {
                table: "permanent-publication-planned-heap-writes",
                entries,
            }
        })?;
        for writeback in writebacks {
            planned.push(self.plan_permanent_publication_heap_field_write(
                writeback.owner,
                writeback.field_index,
                &writeback.source,
                writeback.expected,
                writeback.replacement,
            )?);
        }

        let mut records = Vec::new();
        records.try_reserve_exact(entries).map_err(|_| {
            PermanentPublicationError::AllocationFailed {
                table: "permanent-publication-staged-records",
                entries,
            }
        })?;
        let mut lists = Vec::new();
        let mut attrs = Vec::new();
        let mut closures = Vec::new();
        let mut environment =
            crate::eval::heap::environment_writeback::EnvironmentWritebackStage::try_new(entries)
                .map_err(|_| PermanentPublicationError::AllocationFailed {
                table: "permanent-publication-staged-environments",
                entries,
            })?;
        self.stage_collector_poll_minor_gc_direct_heap_field_writes_into(
            &planned,
            &mut records,
            &mut lists,
            &mut attrs,
            &mut closures,
            &mut environment,
            entries,
        )?;
        if !lists.is_empty() || !attrs.is_empty() {
            return Err(PermanentPublicationError::UnexpectedPermanentContainerStage);
        }
        Ok(PermanentHeapHealingStage {
            records,
            closures,
            environment,
        })
    }

    /// Installs a prepared destination and commits prevalidated heap healing.
    ///
    /// Root storage is intentionally not owned by [`EvalHeap`]. Callers must
    /// prevalidate root writebacks before invoking this method, apply them
    /// immediately afterward, audit for old source words, and retain the
    /// returned token until that audit succeeds. Source permanent allocations
    /// remain live throughout this phase.
    ///
    /// # Errors
    ///
    /// Returns [`PermanentPublicationError`] if aggregate generation
    /// installation fails. All other fallible work completed during
    /// [`Self::prepare_permanent_publication`], so a successful install is
    /// followed only by allocation-free commits.
    pub(in crate::eval) fn publish_prepared_permanent(
        &mut self,
        prepared: PreparedPermanentPublication,
    ) -> Result<PublishedPermanentPublication, PermanentPublicationError> {
        let PreparedPermanentPublication {
            batch,
            root_writebacks: _,
            string_cons,
            path_cons,
            list_cons,
            attrs_cons,
            heap_writebacks,
            heap_healing,
            retirement,
        } = prepared;
        let copied_objects = batch.forwarding().len();
        let healed_heap_fields = heap_writebacks.len();
        let (generation, forwarding) = batch.into_parts();
        self.install_evacuated_closure_generation_with_forwarding(generation, forwarding)?;

        self.string_cons = string_cons;
        self.path_cons = path_cons;
        self.list_cons = list_cons;
        self.attrs_cons = attrs_cons;
        self.commit_collector_poll_minor_gc_staged_heap_field_writes(heap_healing.records);
        self.commit_collector_poll_minor_gc_staged_flat_closure_writes(heap_healing.closures);
        heap_healing.environment.commit();
        self.flat_cold_hashes = FlatColdHashStore::default();
        self.flat_stale_hashes.clear();

        Ok(PublishedPermanentPublication {
            retirement,
            copied_objects,
            healed_heap_fields,
        })
    }

    /// Retires every old permanent allocation after the zero-alias audit.
    ///
    /// This consumes the publication token, swaps in empty same-arena source
    /// stores to release registry vectors, retires every old allocation through
    /// its typed store so the shared page ledger reaches zero, and finally asks
    /// the arena to discard zero-liveness pages. Advice failure is reported but
    /// cannot roll back already completed, semantically safe retirement.
    pub(in crate::eval) fn retire_published_permanent_source(
        &mut self,
        published: PublishedPermanentPublication,
    ) -> PermanentRetirementReport {
        let PublishedPermanentPublication {
            retirement,
            copied_objects,
            healed_heap_fields,
        } = published;
        let mut old_values = std::mem::replace(
            &mut self.flat,
            FlatObjectStore::with_shared_arena(
                self.flat_arena.clone(),
                FlatKindSet::of(&[FlatObjectKind::String, FlatObjectKind::Path]),
            ),
        );
        let mut old_lists = std::mem::replace(
            &mut self.flat_lists,
            FlatObjectStore::with_shared_arena(
                self.flat_arena.clone(),
                FlatKindSet::of(&[FlatObjectKind::List]),
            ),
        );
        let mut old_attrs = std::mem::replace(
            &mut self.flat_attrs,
            FlatObjectStore::with_shared_arena(
                self.flat_arena.clone(),
                FlatKindSet::of(&[FlatObjectKind::Attrs]),
            ),
        );
        let retired_objects = retirement.len();
        for entry in retirement {
            let result = match entry.kind {
                FlatObjectKind::String | FlatObjectKind::Path => {
                    old_values.retire(entry.ptr, entry.kind)
                }
                FlatObjectKind::List => old_lists.retire(entry.ptr, entry.kind),
                FlatObjectKind::Attrs => old_attrs.retire(entry.ptr, entry.kind),
                _ => unreachable!("permanent retirement inventory contained worker kind"),
            };
            if let Err(error) = result {
                unreachable!("prevalidated permanent retirement failed: {error}");
            }
        }
        let (candidate_pages, advised_pages, advice_failed) =
            match self.flat_arena.advise_zero_liveness_pages() {
                Some(Ok(report)) => (report.candidate_pages(), report.applied_pages(), false),
                Some(Err(_)) => (0, 0, true),
                None => (0, 0, false),
            };
        drop(old_values);
        drop(old_lists);
        drop(old_attrs);

        PermanentRetirementReport {
            retired_objects,
            copied_objects,
            healed_heap_fields,
            candidate_pages,
            advised_pages,
            advice_failed,
        }
    }

    /// Counts retained words that still match the installed source directory.
    ///
    /// `scan` must be rebuilt from the healed mutator roots after publication.
    /// Old source permanent objects that are no longer reachable are
    /// intentionally absent; the audit covers retained roots, retained object
    /// fields, and every committed weak hash-cons entry.
    pub(in crate::eval) fn residual_permanent_source_aliases(
        &self,
        scan: &PreciseHeapScan,
    ) -> usize {
        let Some(forwarding) = &self.evacuated_closure_forwarding else {
            return 0;
        };
        let roots = scan
            .roots()
            .iter()
            .filter(|root| {
                forwarding
                    .translate(root.value(), root.value().tag())
                    .is_some()
            })
            .count();
        let fields = scan
            .objects()
            .iter()
            .flat_map(HeapObjectScan::edges)
            .filter(|edge| {
                forwarding
                    .translate(edge.value(), edge.value().tag())
                    .is_some()
            })
            .count();
        let indexes = self
            .string_cons
            .committed_entries()
            .chain(self.path_cons.committed_entries())
            .chain(self.list_cons.committed_entries())
            .chain(self.attrs_cons.committed_entries())
            .filter(|(_, _, value)| forwarding.translate(**value, value.tag()).is_some())
            .count();
        roots.saturating_add(fields).saturating_add(indexes)
    }
}

fn prepare_heap_writebacks(
    objects: &[HeapObjectScan],
    batch: &UnpublishedPermanentBatch,
) -> Result<Vec<PermanentHeapWriteback>, PermanentPublicationError> {
    let count = objects
        .iter()
        // Scanner source labels identify aggregate owners independently of
        // their Candidate-C carrier encoding. Every list/attrset owner is
        // permanent by evaluator policy, and the unpublished batch has
        // already rewritten the copied destination's internal edges.
        .filter(|object| !is_copied_permanent_container(object))
        .flat_map(HeapObjectScan::edges)
        .filter(|edge| batch.translate(edge.value()).is_some())
        .count();
    let mut writebacks = Vec::new();
    writebacks.try_reserve_exact(count).map_err(|_| {
        PermanentPublicationError::AllocationFailed {
            table: "permanent-publication-heap-writebacks",
            entries: count,
        }
    })?;
    for object in objects {
        if is_copied_permanent_container(object) {
            continue;
        }
        for (field_index, edge) in object.edges().iter().enumerate() {
            let Some(replacement) = batch.translate(edge.value()) else {
                continue;
            };
            writebacks.push(PermanentHeapWriteback {
                owner: object.value(),
                field_index,
                source: edge.source().clone(),
                expected: edge.value(),
                replacement,
            });
        }
    }
    Ok(writebacks)
}

fn is_copied_permanent_container(object: &HeapObjectScan) -> bool {
    object.edges().iter().any(|edge| {
        matches!(
            edge.source(),
            HeapEdgeSource::ListElement { .. } | HeapEdgeSource::AttrBinding { .. }
        )
    })
}

fn prepare_root_writebacks(
    roots: &[EvalRoot],
    batch: &UnpublishedPermanentBatch,
) -> Result<AllocationCollectorPollRootWritebackPlan, PermanentPublicationError> {
    let count = roots
        .iter()
        .filter(|root| batch.translate(root.value()).is_some())
        .count();
    let mut writebacks = Vec::new();
    writebacks.try_reserve_exact(count).map_err(|_| {
        PermanentPublicationError::AllocationFailed {
            table: PERMANENT_PUBLICATION_ROOTS,
            entries: count,
        }
    })?;
    for root in roots {
        let Some(replacement) = batch.translate(root.value()) else {
            continue;
        };
        let slot = writebacks.len();
        writebacks.push(AllocationCollectorPollRootWriteback::new(
            slot,
            root.source().clone(),
            permanent_generation(root.value())?,
            root.value().tag(),
            permanent_generation(replacement)?,
            replacement.tag(),
        ));
    }
    Ok(AllocationCollectorPollRootWritebackPlan::new(writebacks))
}

fn translate_hash_cons_table(
    source: &HashConsTable<HotXxh3Hash, Value>,
    batch: &UnpublishedPermanentBatch,
) -> Result<HashConsTable<HotXxh3Hash, Value>, PermanentPublicationError> {
    let mut translated = HashConsTable::new();
    for (key, _index, value) in source.committed_entries() {
        let Some(replacement) = batch.translate(*value) else {
            continue;
        };
        let slot = translated.reserve_slot(*key)?;
        if !translated.push_reserved(slot, replacement) {
            return Err(PermanentPublicationError::HashConsReservationLost);
        }
    }
    Ok(translated)
}

fn permanent_generation(
    value: Value,
) -> Result<ResolvedValueGeneration, PermanentPublicationError> {
    let ptr = value.as_heap_ptr().map_err(EvalHeapError::Value)?.as_ptr() as usize;
    let address = GcHeapAddress::new(ptr).map_err(EvalHeapError::GenerationalGc)?;
    Ok(ResolvedValueGeneration::permanent(address))
}

fn is_source_permanent_value(value: Value, source_domain: crate::heap::ArenaDomainId) -> bool {
    is_permanent_value_kind(value) && value.word().arena_domain() == Some(source_domain)
}

fn is_permanent_value_kind(value: Value) -> bool {
    matches!(
        value.tag(),
        ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
    )
}

/// Whole-permanent publication preparation failed before source mutation.
#[derive(Debug, Error)]
pub(in crate::eval) enum PermanentPublicationError {
    /// Publication is serial-only.
    #[error("permanent publication requires a serial heap")]
    SharedHeap,
    /// The nursery has no Candidate-C reservation domain.
    #[error("permanent publication source has no Candidate-C domain")]
    SourceDomainUnavailable,
    /// The source permanent population overflowed `usize`.
    #[error("permanent publication source population overflowed")]
    PopulationOverflow,
    /// Exact staging storage could not be reserved.
    #[error("failed to reserve {table} for {entries} entries")]
    AllocationFailed {
        /// The staging table.
        table: &'static str,
        /// The requested exact entry count.
        entries: usize,
    },
    /// The unpublished semantic copy failed.
    #[error("permanent publication batch copy failed: {0}")]
    Batch(String),
    /// Heap metadata could not be resolved or encoded.
    #[error("permanent publication heap metadata failed: {0}")]
    Heap(#[from] EvalHeapError),
    /// A translated hash-cons table could not reserve a slot.
    #[error("permanent publication hash-cons rebuild failed: {0}")]
    HashCons(#[from] HashConsError),
    /// A reserved hash-cons slot unexpectedly rejected its translated value.
    #[error("permanent publication hash-cons reservation was lost")]
    HashConsReservationLost,
    /// A non-Candidate-C permanent container escaped the explicit rejection.
    #[error("permanent publication unexpectedly staged a source permanent container")]
    UnexpectedPermanentContainerStage,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::IrId;
    use crate::syntax::{Span, SymbolTable};

    #[test]
    fn preparation_copies_only_mutator_reachable_permanent_values() {
        let mut heap = EvalHeap::new();
        let reachable = heap
            .alloc_string(NixString::from_bytes(b"reachable".to_vec()))
            .expect("reachable string allocates");
        let unreachable = heap
            .alloc_path(NixString::from_bytes(b"/unreachable".to_vec()))
            .expect("unreachable path allocates");
        let list = heap
            .alloc_list(NixList::new(vec![reachable]))
            .expect("root list allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, list)
            .expect("root storage reserves");
        let scan = heap.scan_precise_roots(&roots).expect("root graph scans");

        let prepared = heap
            .prepare_permanent_publication(&scan)
            .expect("permanent publication prepares");

        assert_eq!(prepared.copied_objects(), 2);
        assert_eq!(prepared.retirement_objects(), 3);
        assert_eq!(prepared.root_writebacks().len(), 1);
        assert_eq!(prepared.heap_field_writebacks(), 0);
        assert!(
            prepared
                .forwarding()
                .translate(reachable, ValueTag::String)
                .is_some()
        );
        assert!(
            prepared
                .forwarding()
                .translate(list, ValueTag::List)
                .is_some()
        );
        assert!(
            prepared
                .forwarding()
                .translate(unreachable, ValueTag::Path)
                .is_none()
        );
        assert_eq!(
            heap.get_path(unreachable)
                .expect("preparation leaves unreachable source live")
                .bytes(),
            b"/unreachable"
        );
    }

    #[test]
    fn preparation_stages_worker_to_permanent_edge_healing() {
        let mut symbols = SymbolTable::new();
        let symbol = symbols.intern(b"captured").expect("test symbol interns");
        let mut heap = EvalHeap::new();
        let string = heap
            .alloc_string(NixString::from_bytes(b"value".to_vec()))
            .expect("string allocates");
        let primop = heap
            .alloc_primop(EvalPrimOp::with_args(
                symbol,
                vec![EvalPrimOpArg::new(IrId::new(1), Span::new(0, 1), string)],
            ))
            .expect("primop allocates");
        let _foreign_store_probe = heap
            .alloc_list(NixList::new(Vec::new()))
            .expect("list allocation refreshes the shared store region index");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, primop)
            .expect("root storage reserves");
        let scan = heap.scan_precise_roots(&roots).expect("root graph scans");

        let prepared = heap
            .prepare_permanent_publication(&scan)
            .expect("permanent publication prepares");

        assert_eq!(prepared.copied_objects(), 1);
        assert_eq!(prepared.root_writebacks().len(), 0);
        assert_eq!(prepared.heap_field_writebacks(), 1);
        assert!(
            heap.get_primop(primop)
                .expect("preparation leaves primop live")
                .args()[0]
                .value()
                .raw_eq(string)
        );
    }

    #[test]
    fn publication_heals_worker_edge_audits_and_retires_source() {
        let mut symbols = SymbolTable::new();
        let symbol = symbols.intern(b"captured").expect("test symbol interns");
        let mut heap = EvalHeap::new();
        let source_string = heap
            .alloc_string(NixString::from_bytes(b"value".to_vec()))
            .expect("string allocates");
        let dead_path = heap
            .alloc_path(NixString::from_bytes(b"/dead".to_vec()))
            .expect("dead path allocates");
        let primop = heap
            .alloc_primop(EvalPrimOp::with_args(
                symbol,
                vec![EvalPrimOpArg::new(
                    IrId::new(1),
                    Span::new(0, 1),
                    source_string,
                )],
            ))
            .expect("primop allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, primop)
            .expect("root storage reserves");
        let scan = heap.scan_precise_roots(&roots).expect("root graph scans");
        let prepared = heap
            .prepare_permanent_publication(&scan)
            .expect("publication prepares");

        let published = heap
            .publish_prepared_permanent(prepared)
            .expect("publication commits");
        let healed_string = heap.get_primop(primop).expect("primop remains live").args()[0].value();
        assert!(!healed_string.raw_eq(source_string));
        assert_eq!(
            heap.get_string(healed_string)
                .expect("destination string resolves")
                .bytes(),
            b"value"
        );
        let healed_scan = heap
            .scan_precise_roots(&roots)
            .expect("healed graph rescans");
        assert_eq!(heap.residual_permanent_source_aliases(&healed_scan), 0);

        let report = heap.retire_published_permanent_source(published);
        assert_eq!(report.retired_objects(), 2);
        assert_eq!(report.copied_objects(), 1);
        assert_eq!(report.healed_heap_fields(), 1);
        assert!(heap.get_string(source_string).is_err());
        assert!(heap.get_path(dead_path).is_err());
        assert_eq!(
            heap.get_string(healed_string)
                .expect("destination survives source retirement")
                .bytes(),
            b"value"
        );
        let new_string = heap
            .alloc_string(NixString::from_bytes(b"new".to_vec()))
            .expect("nursery permanent allocation continues");
        assert_eq!(
            heap.get_string(new_string)
                .expect("new nursery string resolves")
                .bytes(),
            b"new"
        );
    }
}
