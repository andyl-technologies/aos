//! impl EvalHeap: interned-table root pushing, record and flat-store edge
//! scans, and collector-poll snapshot validation.
//!
//! Moved verbatim from `heap/roots.rs` under the RFC-0007 §2 file-size cap;
//! the parent re-exports every public path and glob-imports each child so
//! sibling references keep resolving.

use super::*;

impl EvalHeap {
    /// Validates an evaluator-declared detached-work head root.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] unless `value` names a typed thunk head in the
    /// blackhole state. This prevents special-root metadata from weakening the
    /// rejection of ordinary or unmatched blackholes.
    pub(in crate::eval::heap) fn validate_detached_typed_thunk_head_root(
        &self,
        value: Value,
    ) -> Result<NonNull<HeapObject>, EvalHeapError> {
        let ptr = self.thunk_ptr(value)?;
        let head = self
            .typed_thunk_heads
            .resolve(ptr)
            .map_err(|_| EvalHeapError::unknown(ValueTag::Thunk, ptr))?;
        if head.state() != Some(ThunkState::Blackhole) {
            return Err(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "detached typed-work root did not name a blackholed typed thunk",
            });
        }
        Ok(ptr)
    }

    /// Synthesizes roots retained by typed work detached from a blackholed head.
    ///
    /// This uses the same exhaustive visitor as ordinary suspended thunk
    /// records. The stable head is permanent; its detached work edges must be
    /// rooted separately until the head is published or restored.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if a captured environment cannot be read or a
    /// captured flat-owner handle cannot be resolved in this heap.
    pub(in crate::eval) fn detached_typed_thunk_work_edges(
        &self,
        work: &EvalThunk,
    ) -> Result<Vec<HeapEdge>, EvalHeapError> {
        let mut edges = Vec::new();
        let resolve_flat_owner = |handle| self.flat_closure_capture_owner(handle);
        push_thunk_edges(&mut edges, work, &resolve_flat_owner)?;
        push_parallel_thunk_payload_edge(&mut edges, work)?;
        Ok(edges)
    }

    /// Reads one canonical edge from ordinary Node work detached by a force lease.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the detached work cannot be scanned or the
    /// requested edge no longer exists.
    #[cfg(feature = "collection_poll_probe")]
    pub(in crate::eval) fn detached_node_thunk_work_edge(
        &self,
        ptr: NonNull<HeapObject>,
        work: &EvalThunk,
        edge: usize,
    ) -> Result<HeapEdge, EvalHeapError> {
        self.detached_active_thunk_work_edges(ptr, work)?
            .get(edge)
            .cloned()
            .ok_or(EvalHeapError::ShedRejected {
                address: 0,
                reason: "detached Node work root edge is no longer live",
            })
    }

    /// Rewrites one canonical edge in ordinary Node work detached by a force lease.
    ///
    /// Lexical captures retain their shared frame identity and are updated in
    /// place. Dynamic captures rebuild only the evaluator-owned detached work;
    /// the stable blackholed source remains an edge-free publication shell.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the edge is absent, does not belong to
    /// tail-free Node work, or its capture storage rejects the replacement.
    #[cfg(feature = "collection_poll_probe")]
    pub(in crate::eval) fn rewrite_detached_node_thunk_work_edge(
        &mut self,
        ptr: NonNull<HeapObject>,
        work: &mut EvalThunk,
        edge: usize,
        replacement: Value,
    ) -> Result<(), EvalHeapError> {
        let source = self
            .detached_node_thunk_work_edge(ptr, work, edge)?
            .source()
            .clone();
        if let HeapEdgeSource::CapturedWithScope {
            owner: CapturedRootOwner::Thunk,
            index,
        } = &source
        {
            let dynamic = work.dynamic_env_mut().ok_or(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "detached dynamic with-scope edge has no dynamic environment",
            })?;
            let mut scopes = dynamic.with_env.scopes().to_vec();
            let scope = scopes.get_mut(*index).ok_or(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "detached dynamic with-scope edge is out of bounds",
            })?;
            *scope = EvalWithScope::new(scope.module(), scope.scope(), replacement);
            dynamic.with_env = EvalWithEnv::capture(&scopes).map_err(EvalHeapError::Environment)?;
            return Ok(());
        }
        if let HeapEdgeSource::CapturedScopedGlobal {
            owner: CapturedRootOwner::Thunk,
            index,
        } = &source
        {
            let dynamic = work.dynamic_env_mut().ok_or(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "detached scoped-global edge has no dynamic environment",
            })?;
            let mut scopes = dynamic.scoped_globals.scopes().to_vec();
            let scope = scopes.get_mut(*index).ok_or(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "detached scoped-global edge is out of bounds",
            })?;
            *scope = replacement;
            dynamic.scoped_globals =
                EvalScopedGlobalEnv::capture(&scopes).map_err(EvalHeapError::Environment)?;
            return Ok(());
        }
        match (&mut work.kind, &source) {
            (
                _,
                HeapEdgeSource::CapturedFlatEnv {
                    owner: CapturedRootOwner::Thunk,
                    index,
                },
            ) => {
                let tail = match self
                    .flat_closures
                    .value_tail_mut(ptr, FlatObjectKind::Thunk)
                {
                    Ok(Some(tail)) => tail,
                    Ok(None) => {
                        return Err(EvalHeapError::ShedRejected {
                            address: ptr.as_ptr() as usize,
                            reason: "detached work lost its source-resident capture tail",
                        });
                    }
                    Err(error) => {
                        return Err(self.closure_resolution_error(ValueTag::Thunk, ptr, error));
                    }
                };
                let slot = tail.get_mut(*index).ok_or(EvalHeapError::ShedRejected {
                    address: ptr.as_ptr() as usize,
                    reason: "detached work capture-tail edge is out of bounds",
                })?;
                *slot = replacement;
                Ok(())
            }
            (
                EvalThunkKind::Node { env, .. },
                HeapEdgeSource::CapturedEnv {
                    owner: CapturedRootOwner::Thunk,
                    frame,
                    slot,
                },
            ) => env
                .frames()
                .get(*frame)
                .ok_or(EvalHeapError::ShedRejected {
                    address: 0,
                    reason: "detached Node work lexical frame is no longer live",
                })?
                .set(
                    u32::try_from(*slot).map_err(|_| EvalHeapError::ShedRejected {
                        address: 0,
                        reason: "detached Node work lexical slot exceeds frame coordinates",
                    })?,
                    replacement,
                )
                .map_err(EvalHeapError::Environment),
            (
                EvalThunkKind::Node { env, .. },
                HeapEdgeSource::CapturedFlatEnvOwner {
                    owner: CapturedRootOwner::Thunk,
                },
            ) => {
                let current = self.flat_closure_capture_owner(
                    env.flat_base()
                        .ok_or(EvalHeapError::ShedRejected {
                            address: ptr.as_ptr() as usize,
                            reason: "detached flat-owner edge has no flat environment",
                        })?
                        .tail_handle(),
                )?;
                if current.raw_eq(replacement) {
                    Ok(())
                } else {
                    Err(EvalHeapError::ShedRejected {
                        address: ptr.as_ptr() as usize,
                        reason: "detached inherited flat owner must remain stable",
                    })
                }
            }
            (
                EvalThunkKind::Apply { function_value, .. }
                | EvalThunkKind::GenListElemAtAddOne { function_value, .. },
                HeapEdgeSource::ThunkApplyFunction,
            ) => {
                *function_value = replacement;
                Ok(())
            }
            (
                EvalThunkKind::Apply { argument_value, .. }
                | EvalThunkKind::GenListElemAtAddOne { argument_value, .. },
                HeapEdgeSource::ThunkApplyArgument,
            ) => {
                *argument_value = replacement;
                Ok(())
            }
            _ => Err(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "detached work edge is not writable",
            }),
        }
    }

    /// Synthesizes every root logically owned by an active inline force lease.
    #[cfg(feature = "collection_poll_probe")]
    pub(in crate::eval) fn detached_active_thunk_work_edges(
        &self,
        ptr: NonNull<HeapObject>,
        work: &EvalThunk,
    ) -> Result<Vec<HeapEdge>, EvalHeapError> {
        let mut edges = self.detached_typed_thunk_work_edges(work)?;
        if let Some(values) = self
            .flat_closures
            .value_tail(ptr, FlatObjectKind::Thunk)
            .map_err(|error| self.closure_resolution_error(ValueTag::Thunk, ptr, error))?
        {
            for (index, value) in values.iter().copied().enumerate() {
                push_heap_edge(
                    &mut edges,
                    HeapEdgeSource::CapturedFlatEnv {
                        owner: CapturedRootOwner::Thunk,
                        index,
                    },
                    value,
                )?;
            }
        }
        Ok(edges)
    }

    /// Synthesizes precise edges for a headerless typed thunk head.
    pub(in crate::eval::heap) fn scan_typed_thunk_edges(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<Option<Vec<HeapEdge>>, EvalHeapError> {
        let head = match self.typed_thunk_heads.resolve(ptr) {
            Ok(head) => head,
            Err(_) => return Ok(None),
        };
        let mut edges = Vec::new();
        match head.state() {
            Some(ThunkState::Suspended) => {
                let work =
                    self.typed_thunk_work_ref(ptr)?
                        .ok_or(EvalHeapError::ReleasedThunkWork {
                            address: ptr.as_ptr() as usize,
                        })?;
                let resolve_flat_owner = |handle| self.flat_closure_capture_owner(handle);
                push_thunk_edges(&mut edges, work, &resolve_flat_owner)?;
                push_parallel_thunk_payload_edge(&mut edges, work)?;
            }
            Some(ThunkState::Forced) => {
                if let Some(value) = head.published_value().map_err(EvalHeapError::Thunk)? {
                    push_heap_edge(&mut edges, HeapEdgeSource::ThunkCachedResult, value)?;
                }
            }
            Some(ThunkState::Blackhole) => {
                return Err(EvalHeapError::ShedRejected {
                    address: ptr.as_ptr() as usize,
                    reason: "liveness census reached a blackholed typed thunk",
                });
            }
            None => {
                return Err(EvalHeapError::unknown(ValueTag::Thunk, ptr));
            }
        }
        Ok(Some(edges))
    }

    pub(super) fn push_interned_table_roots<'a>(
        &self,
        roots: &mut EvalRootSet,
        table: InternedRootTable,
        values: impl Iterator<Item = (&'a HotXxh3Hash, usize, &'a Value)>,
    ) -> Result<(), EvalRootSetError> {
        let mut entries = Vec::new();
        for (hash, bucket_index, value) in values {
            let requested = entries
                .len()
                .checked_add(1)
                .ok_or(EvalRootSetError::LengthOverflow)?;
            entries
                .try_reserve_exact(1)
                .map_err(|_| EvalRootSetError::AllocationFailed { roots: requested })?;
            entries.push((*hash, bucket_index, *value));
        }
        entries.sort_by_key(|(hash, bucket_index, _value)| (*hash, *bucket_index));
        for (index, (_hash, _bucket_index, value)) in entries.into_iter().enumerate() {
            roots.try_push_interned(table, index, value)?;
        }
        Ok(())
    }

    // Pre-split audience was the heap module (`pub(super)` in roots.rs);
    // widened path-explicitly after the §2 relocation.
    pub(in crate::eval::heap) fn scan_record_edges(
        &self,
        record: &HeapRecord,
    ) -> Result<Vec<HeapEdge>, EvalHeapError> {
        let mut edges = Vec::new();
        let resolve_flat_owner = |handle| self.flat_closure_capture_owner(handle);
        match &record.object {
            HeapObjectValue::String(_) => {}
            HeapObjectValue::List(list) => {
                for (index, value) in list.iter().copied().enumerate() {
                    push_heap_edge(&mut edges, HeapEdgeSource::ListElement { index }, value)?;
                }
            }
            HeapObjectValue::Lambda(lambda) => {
                push_capture_edges(
                    &mut edges,
                    CapturedRootOwner::Lambda,
                    lambda.env(),
                    lambda.with_scope_env(),
                    lambda.scoped_global_env(),
                    &resolve_flat_owner,
                )?;
            }
            HeapObjectValue::Primop(primop) => {
                for (index, arg) in primop.args().iter().enumerate() {
                    push_heap_edge(
                        &mut edges,
                        HeapEdgeSource::PrimopArgument { index },
                        arg.value(),
                    )?;
                }
            }
            HeapObjectValue::Thunk(thunk) => match thunk.cell().state()? {
                ThunkState::Suspended | ThunkState::Blackhole => {
                    push_thunk_edges(&mut edges, thunk, &resolve_flat_owner)?;
                    push_parallel_thunk_payload_edge(&mut edges, thunk)?;
                }
                ThunkState::Forced => {
                    if let Some(value) = thunk.cell().cached_value()? {
                        push_heap_edge(&mut edges, HeapEdgeSource::ThunkCachedResult, value)?;
                    }
                    push_parallel_thunk_payload_edge(&mut edges, thunk)?;
                }
            },
            // Retired slots are unreachable through resolution (their index
            // entries were removed at retirement); a scan can only reach one
            // through a stale root, which must fail loudly.
            HeapObjectValue::Retired { tag } => {
                return Err(EvalHeapError::UnknownPointer {
                    tag: *tag,
                    address: record.ptr.as_ptr() as usize,
                });
            }
        }
        Ok(edges)
    }

    /// Synthesizes precise edges for a flat list's element spine.
    ///
    /// The flat analog of the [`HeapObjectValue::List`] arm of
    /// [`EvalHeap::scan_record_edges`]: one `ListElement`-labelled edge per
    /// scannable element, in element order, so every consumer (sweep seeding,
    /// pop validation, poll snapshots, staleness comparison) observes the
    /// identical edge stream a record-backed list produced.
    // Pre-split audience was the heap module (`pub(super)` in roots.rs);
    // widened path-explicitly after the §2 relocation.
    pub(in crate::eval::heap) fn scan_flat_list_edges(
        &self,
        list: &NixList,
    ) -> Result<Vec<HeapEdge>, EvalHeapError> {
        let mut edges = Vec::new();
        for (index, value) in list.iter().copied().enumerate() {
            push_heap_edge(&mut edges, HeapEdgeSource::ListElement { index }, value)?;
        }
        Ok(edges)
    }

    /// Synthesizes precise edges for a flat attrset's entry values.
    ///
    /// The flat analog of the [`HeapObjectValue::Attrs`] arm of
    /// [`EvalHeap::scan_record_edges`]: one `AttrBinding`-labelled edge per
    /// scannable entry, in symbol order with the payload's shape id, so
    /// every consumer (sweep seeding, pop validation, poll snapshots,
    /// staleness comparison) observes the identical edge stream a
    /// record-backed attrset produced.
    // Pre-split audience was the heap module (`pub(super)` in roots.rs);
    // widened path-explicitly after the §2 relocation.
    pub(in crate::eval::heap) fn scan_flat_attrs_edges(
        &self,
        payload: &FlatAttrsPayload,
    ) -> Result<Vec<HeapEdge>, EvalHeapError> {
        let mut edges = Vec::new();
        for (slot, entry) in payload.attrs.entries_by_symbol().iter().enumerate() {
            push_heap_edge(
                &mut edges,
                HeapEdgeSource::AttrBinding {
                    shape: payload.metadata.shape(),
                    slot,
                    key: entry.key,
                },
                entry.value,
            )?;
        }
        Ok(edges)
    }

    /// Synthesizes precise edges for a flat worker closure (doc 30 FV-3).
    ///
    /// The flat analog of the [`HeapObjectValue::Lambda`],
    /// [`HeapObjectValue::Primop`], and [`HeapObjectValue::Thunk`] arms of
    /// [`EvalHeap::scan_record_edges`], so every consumer (sweep marking, pop
    /// validation) observes the identical edge stream a record-backed
    /// closure produced: capture edges for lambdas, `PrimopArgument` edges
    /// for builtins, and state-dependent thunk edges (kind captures while
    /// suspended or blackholed, the cached result once forced, plus the
    /// parallel payload edge in both states).
    ///
    /// # Errors
    ///
    /// A retired payload fails as [`EvalHeapError::UnknownPointer`] — a scan
    /// can only reach one through a stale root, which must fail loudly —
    /// A released blackhole is the edge-free publication shell of an active
    /// ordinary Node force; its detached work is scanned through evaluator
    /// roots. Released work in any other state remains invalid.
    // Pre-split audience was the heap module (`pub(super)` in roots.rs);
    // widened path-explicitly after the §2 relocation.
    pub(in crate::eval::heap) fn scan_flat_closure_edges(
        &self,
        ptr: NonNull<HeapObject>,
        payload: &FlatClosurePayload,
    ) -> Result<Vec<HeapEdge>, EvalHeapError> {
        let mut edges = Vec::new();
        let resolve_flat_owner = |handle| self.flat_closure_capture_owner(handle);
        // A lazily shared thunk (`SharedThunk`) carries the same thunk as the
        // inline `Thunk` variant; both scan identical edges through the deref.
        let push_thunk_edges =
            |edges: &mut Vec<HeapEdge>, thunk: &EvalThunk| -> Result<(), EvalHeapError> {
                match thunk.cell().state()? {
                    ThunkState::Blackhole if matches!(thunk.kind(), EvalThunkKind::Released) => {}
                    ThunkState::Suspended | ThunkState::Blackhole => {
                        push_thunk_edges(edges, thunk, &resolve_flat_owner)?;
                        push_parallel_thunk_payload_edge(edges, thunk)?;
                    }
                    ThunkState::Forced => {
                        if let Some(value) = thunk.cell().cached_value()? {
                            push_heap_edge(edges, HeapEdgeSource::ThunkCachedResult, value)?;
                        }
                        push_parallel_thunk_payload_edge(edges, thunk)?;
                    }
                }
                Ok(())
            };
        match payload {
            FlatClosurePayload::Lambda(lambda) => {
                push_capture_edges(
                    &mut edges,
                    CapturedRootOwner::Lambda,
                    lambda.env(),
                    lambda.with_scope_env(),
                    lambda.scoped_global_env(),
                    &resolve_flat_owner,
                )?;
            }
            FlatClosurePayload::Primop(primop) => {
                for (index, arg) in primop.args().iter().enumerate() {
                    push_heap_edge(
                        &mut edges,
                        HeapEdgeSource::PrimopArgument { index },
                        arg.value(),
                    )?;
                }
            }
            FlatClosurePayload::Thunk(thunk) => push_thunk_edges(&mut edges, thunk)?,
            FlatClosurePayload::SharedThunk(thunk) => push_thunk_edges(&mut edges, thunk.as_ref())?,
            FlatClosurePayload::Retired(tag) => {
                return Err(EvalHeapError::UnknownPointer {
                    tag: *tag,
                    address: ptr.as_ptr() as usize,
                });
            }
        }
        let (kind, owner) = match payload.tag() {
            ValueTag::Lambda => (FlatObjectKind::Lambda, CapturedRootOwner::Lambda),
            ValueTag::Thunk => (FlatObjectKind::Thunk, CapturedRootOwner::Thunk),
            _ => return Ok(edges),
        };
        let inline_tail_is_leased = match payload {
            FlatClosurePayload::Thunk(thunk) => {
                thunk.cell().state()? == ThunkState::Blackhole
                    && matches!(thunk.kind(), EvalThunkKind::Released)
            }
            FlatClosurePayload::SharedThunk(thunk) => {
                thunk.cell().state()? == ThunkState::Blackhole
                    && matches!(thunk.kind(), EvalThunkKind::Released)
            }
            FlatClosurePayload::Lambda(_)
            | FlatClosurePayload::Primop(_)
            | FlatClosurePayload::Retired(_) => false,
        };
        if inline_tail_is_leased {
            return Ok(edges);
        }
        if let Some(values) = self
            .flat_closures
            .value_tail(ptr, kind)
            .map_err(|error| self.closure_resolution_error(payload.tag(), ptr, error))?
        {
            for (index, value) in values.iter().copied().enumerate() {
                push_heap_edge(
                    &mut edges,
                    HeapEdgeSource::CapturedFlatEnv { owner, index },
                    value,
                )?;
            }
        }
        Ok(edges)
    }

    pub(super) fn validate_collector_poll_scan_is_current(
        &self,
        poll_scan: &AllocationCollectorPollScan,
    ) -> Result<(), EvalHeapError> {
        for root in poll_scan.scan().roots() {
            self.validate_scannable_value(root.value())?;
        }

        for object in poll_scan.scan().objects() {
            let (tag, ptr) = heap_ptr(object.value())?;
            if self.shared.is_none() && matches!(tag, ValueTag::String | ValueTag::Path) {
                // Flat strings/paths are immutable, edge-free leaves; a scan
                // that recorded them with no edges is always current.
                self.flat_verify(tag, ptr)?;
                if !object.edges().is_empty() {
                    return Err(EvalHeapError::CollectorPollScanStaleObject {
                        address: gc_address_for_value(object.value())?,
                    });
                }
                continue;
            }
            if self.shared.is_none() && tag == ValueTag::List {
                // Flat lists carry edges; re-synthesize them and compare, the
                // exact staleness check a record-backed list received.
                let current_edges = self.scan_flat_list_edges(self.flat_list_payload(ptr)?)?;
                if current_edges != object.edges() {
                    return Err(EvalHeapError::CollectorPollScanStaleObject {
                        address: gc_address_for_value(object.value())?,
                    });
                }
                continue;
            }
            if self.shared.is_none() && tag == ValueTag::Attrs {
                // Flat attrsets carry edges; same staleness re-synthesis.
                let current_edges = self.scan_flat_attrs_edges(self.flat_attrs_payload(ptr)?)?;
                if current_edges != object.edges() {
                    return Err(EvalHeapError::CollectorPollScanStaleObject {
                        address: gc_address_for_value(object.value())?,
                    });
                }
                continue;
            }
            let record = self.record_for_scannable_value(object.value())?;
            let current_edges = self.scan_record_edges(record)?;
            if current_edges != object.edges() {
                return Err(EvalHeapError::CollectorPollScanStaleObject {
                    address: gc_address_for_value(object.value())?,
                });
            }
        }
        Ok(())
    }

    /// Returns the count of scannable typed objects (records plus flat).
    ///
    /// Collector-poll snapshots capture this count and staleness validation
    /// re-compares it, so any typed allocation — record-backed or flat —
    /// invalidates an outstanding snapshot exactly as string records did
    /// before FV-1.
    pub(super) fn scannable_object_count(&self) -> usize {
        self.records
            .len()
            .saturating_add(self.flat.len())
            .saturating_add(self.flat_lists.len())
            .saturating_add(self.flat_attrs.len())
            .saturating_add(self.flat_closures.len())
    }

    /// Validates a scan root value against either heap domain.
    pub(super) fn validate_scannable_value(&self, value: Value) -> Result<(), EvalHeapError> {
        let (tag, ptr) = heap_ptr(value)?;
        if self.shared.is_none()
            && matches!(
                tag,
                ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
            )
        {
            return self.flat_verify(tag, ptr);
        }
        self.record_for_scannable_value(value).map(|_| ())
    }

    pub(super) fn validate_collector_poll_snapshot_allocation_state(
        &self,
        poll_scan: &AllocationCollectorPollScan,
    ) -> Result<(), EvalHeapError> {
        if poll_scan.heap_records() != self.scannable_object_count() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "heap record count changed",
                expected_records: poll_scan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if poll_scan.worker_region_owner() != self.region_owner {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region owner changed",
                expected_records: poll_scan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if poll_scan.worker_region_epoch() != self.worker_region_epoch {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region epoch changed",
                expected_records: poll_scan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if poll_scan.allocation_safepoints() != self.allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker allocation safepoints changed",
                expected_records: poll_scan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if poll_scan.permanent_allocation_safepoints() != self.permanent_allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "permanent allocation safepoints changed",
                expected_records: poll_scan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        Ok(())
    }

    pub(super) fn validate_remembered_set_snapshot(
        &self,
        remembered_set: RememberedSetSnapshot<'_>,
    ) -> Result<(), EvalHeapError> {
        for edge in remembered_set.edges() {
            let source_generation = self.generation_for_address(edge.source(), "source")?;
            let target_generation = self.generation_for_address(edge.target(), "target")?;
            if !matches!(
                source_generation,
                HeapGeneration::Old | HeapGeneration::Permanent
            ) || target_generation != HeapGeneration::Young
            {
                return Err(EvalHeapError::InvalidCollectorPollRememberedEdge {
                    source_address: edge.source(),
                    source_generation,
                    target_address: edge.target(),
                    target_generation,
                });
            }
        }
        Ok(())
    }

    pub(super) fn validate_current_permanent_edges_are_remembered(
        &self,
        remembered_set: RememberedSetSnapshot<'_>,
    ) -> Result<(), EvalHeapError> {
        for record in &self.records {
            if generation_for_record(record) != HeapGeneration::Permanent {
                continue;
            }
            let source = gc_address_for_record(record)?;
            let edges = self.scan_record_edges(record)?;

            for edge in edges {
                let target = self.resolved_generation_for_value(edge.value())?;
                let ResolvedValueGeneration::Heap {
                    address: target,
                    generation: HeapGeneration::Young,
                } = target
                else {
                    continue;
                };
                let remembered_edge = RememberedEdge::new(source, target);
                if !remembered_set.edges().contains(&remembered_edge) {
                    return Err(EvalHeapError::MissingCollectorPollRememberedEdge {
                        source_address: source,
                        target_address: target,
                    });
                }
            }
        }
        // Flat lists and attrsets are permanent edge carriers (doc 30
        // FV-1/FV-2): their permanent-to-young edges must be remembered
        // exactly as record-backed permanent lists' and attrsets' edges were.
        for entry in self.flat_lists.iter() {
            let source = GcHeapAddress::new(entry.ptr().as_ptr() as usize)
                .map_err(EvalHeapError::GenerationalGc)?;
            for edge in self.scan_flat_list_edges(entry.object().payload())? {
                let target = self.resolved_generation_for_value(edge.value())?;
                let ResolvedValueGeneration::Heap {
                    address: target,
                    generation: HeapGeneration::Young,
                } = target
                else {
                    continue;
                };
                let remembered_edge = RememberedEdge::new(source, target);
                if !remembered_set.edges().contains(&remembered_edge) {
                    return Err(EvalHeapError::MissingCollectorPollRememberedEdge {
                        source_address: source,
                        target_address: target,
                    });
                }
            }
        }
        for entry in self.flat_attrs.iter() {
            let source = GcHeapAddress::new(entry.ptr().as_ptr() as usize)
                .map_err(EvalHeapError::GenerationalGc)?;
            for edge in self.scan_flat_attrs_edges(entry.object().payload())? {
                let target = self.resolved_generation_for_value(edge.value())?;
                let ResolvedValueGeneration::Heap {
                    address: target,
                    generation: HeapGeneration::Young,
                } = target
                else {
                    continue;
                };
                let remembered_edge = RememberedEdge::new(source, target);
                if !remembered_set.edges().contains(&remembered_edge) {
                    return Err(EvalHeapError::MissingCollectorPollRememberedEdge {
                        source_address: source,
                        target_address: target,
                    });
                }
            }
        }
        Ok(())
    }

    pub(super) fn validate_current_permanent_edges_are_remembered_or_dirty_survivors(
        &self,
        remembered_set: RememberedSetSnapshot<'_>,
        card_table: GcCardTableSnapshot<'_>,
        plan: &MinorGcPlan,
    ) -> Result<(), EvalHeapError> {
        for record in &self.records {
            if generation_for_record(record) != HeapGeneration::Permanent {
                continue;
            }
            let source = gc_address_for_record(record)?;
            let edges = self.scan_record_edges(record)?;

            for edge in edges {
                let target = self.resolved_generation_for_value(edge.value())?;
                let ResolvedValueGeneration::Heap {
                    address: target,
                    generation: HeapGeneration::Young,
                } = target
                else {
                    continue;
                };
                let remembered_edge = RememberedEdge::new(source, target);
                if remembered_set.edges().contains(&remembered_edge) {
                    continue;
                }
                if card_table.covers_source(source)
                    && plan
                        .survivors()
                        .iter()
                        .any(|survivor| survivor.address() == target)
                {
                    continue;
                }
                return Err(EvalHeapError::MissingCollectorPollRememberedEdge {
                    source_address: source,
                    target_address: target,
                });
            }
        }
        // Flat lists and attrsets: same permanent-to-young coverage
        // requirement, with the same dirty-card survivor escape hatch.
        for entry in self.flat_lists.iter() {
            let source = GcHeapAddress::new(entry.ptr().as_ptr() as usize)
                .map_err(EvalHeapError::GenerationalGc)?;
            for edge in self.scan_flat_list_edges(entry.object().payload())? {
                let target = self.resolved_generation_for_value(edge.value())?;
                let ResolvedValueGeneration::Heap {
                    address: target,
                    generation: HeapGeneration::Young,
                } = target
                else {
                    continue;
                };
                let remembered_edge = RememberedEdge::new(source, target);
                if remembered_set.edges().contains(&remembered_edge) {
                    continue;
                }
                if card_table.covers_source(source)
                    && plan
                        .survivors()
                        .iter()
                        .any(|survivor| survivor.address() == target)
                {
                    continue;
                }
                return Err(EvalHeapError::MissingCollectorPollRememberedEdge {
                    source_address: source,
                    target_address: target,
                });
            }
        }
        for entry in self.flat_attrs.iter() {
            let source = GcHeapAddress::new(entry.ptr().as_ptr() as usize)
                .map_err(EvalHeapError::GenerationalGc)?;
            for edge in self.scan_flat_attrs_edges(entry.object().payload())? {
                let target = self.resolved_generation_for_value(edge.value())?;
                let ResolvedValueGeneration::Heap {
                    address: target,
                    generation: HeapGeneration::Young,
                } = target
                else {
                    continue;
                };
                let remembered_edge = RememberedEdge::new(source, target);
                if remembered_set.edges().contains(&remembered_edge) {
                    continue;
                }
                if card_table.covers_source(source)
                    && plan
                        .survivors()
                        .iter()
                        .any(|survivor| survivor.address() == target)
                {
                    continue;
                }
                return Err(EvalHeapError::MissingCollectorPollRememberedEdge {
                    source_address: source,
                    target_address: target,
                });
            }
        }
        Ok(())
    }

    pub(super) fn validate_card_table_snapshot(
        &self,
        remembered_set: RememberedSetSnapshot<'_>,
        card_table: GcCardTableSnapshot<'_>,
    ) -> Result<(), EvalHeapError> {
        for edge in remembered_set.edges() {
            if !card_table.covers_source(edge.source()) {
                return Err(EvalHeapError::MissingCollectorPollDirtyCard {
                    source_address: edge.source(),
                    target_address: edge.target(),
                    card_index: card_table.card_index_for_source(edge.source()),
                });
            }
        }
        Ok(())
    }
}
