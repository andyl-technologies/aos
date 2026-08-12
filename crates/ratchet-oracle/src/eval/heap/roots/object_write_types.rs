//! Object byte-copy requests/plans, body-write and generation-write
//! reports/plans, and their request validators.
//!
//! Moved verbatim from `heap/roots.rs` under the RFC-0007 §2 file-size cap;
//! the parent re-exports every public path and glob-imports each child so
//! sibling references keep resolving.

use super::*;

/// One object byte-copy request derived from an allocation-poll commit plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollObjectByteCopyRequest {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    action: MinorGcSurvivorAction,
    destination_generation: HeapGeneration,
    size_bytes: usize,
    align: usize,
}

impl AllocationCollectorPollObjectByteCopyRequest {
    pub(super) const fn from_copy(copy: MinorGcObjectCopy) -> Self {
        Self {
            source: copy.source(),
            destination: copy.destination(),
            action: copy.action(),
            destination_generation: copy.destination_generation(),
            size_bytes: copy.size_bytes(),
            align: copy.align(),
        }
    }

    #[cfg(test)]
    /// Creates object byte-copy metadata for tests that exercise sealed reports.
    pub(crate) const fn for_test(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        action: MinorGcSurvivorAction,
        destination_generation: HeapGeneration,
        size_bytes: usize,
        align: usize,
    ) -> Self {
        Self {
            source,
            destination,
            action,
            destination_generation,
            size_bytes,
            align,
        }
    }

    /// Returns the current young-generation source object address.
    pub const fn source(&self) -> GcHeapAddress {
        self.source
    }

    /// Returns the destination address that should receive copied bytes.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns whether this copy keeps the object young or promotes it.
    pub const fn action(&self) -> MinorGcSurvivorAction {
        self.action
    }

    /// Returns the generation that will own the destination object.
    pub const fn destination_generation(&self) -> HeapGeneration {
        self.destination_generation
    }

    /// Returns the byte length callers must bind for source and destination.
    pub const fn size_bytes(&self) -> usize {
        self.size_bytes
    }

    /// Returns the required destination alignment in bytes.
    pub const fn align(&self) -> usize {
        self.align
    }
}

/// Object byte-copy requests in lower-level commit order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollObjectByteCopyPlan {
    requests: Vec<AllocationCollectorPollObjectByteCopyRequest>,
}

impl AllocationCollectorPollObjectByteCopyPlan {
    pub(super) fn new(requests: Vec<AllocationCollectorPollObjectByteCopyRequest>) -> Self {
        Self { requests }
    }

    /// Creates an object byte-copy plan from already-derived copy requests.
    ///
    /// This constructor preserves the caller's commit order. The returned plan
    /// still validates duplicate, overlap, generation, and layout invariants when
    /// it is lowered into a concrete generation or object-body writer.
    pub(crate) fn from_requests(
        requests: Vec<AllocationCollectorPollObjectByteCopyRequest>,
    ) -> Self {
        Self::new(requests)
    }

    #[cfg(test)]
    pub(crate) fn from_requests_for_test(
        requests: Vec<AllocationCollectorPollObjectByteCopyRequest>,
    ) -> Self {
        Self::new(requests)
    }

    /// Returns object byte-copy requests in commit order.
    pub fn requests(&self) -> &[AllocationCollectorPollObjectByteCopyRequest] {
        &self.requests
    }

    /// Returns requests copied into the next nursery in commit order.
    pub fn copy_to_nursery_requests(
        &self,
    ) -> impl Iterator<Item = &AllocationCollectorPollObjectByteCopyRequest> {
        self.requests
            .iter()
            .filter(|request| request.action() == MinorGcSurvivorAction::CopyToNursery)
    }

    /// Returns requests promoted into old generation in commit order.
    pub fn promote_to_old_requests(
        &self,
    ) -> impl Iterator<Item = &AllocationCollectorPollObjectByteCopyRequest> {
        self.requests
            .iter()
            .filter(|request| request.action() == MinorGcSurvivorAction::PromoteToOld)
    }

    /// Returns the number of requests copied into the next nursery.
    pub fn copy_to_nursery_count(&self) -> usize {
        self.copy_to_nursery_requests().count()
    }

    /// Returns the number of requests promoted into old generation.
    pub fn promote_to_old_count(&self) -> usize {
        self.promote_to_old_requests().count()
    }

    /// Returns total requested nursery destination bytes.
    pub fn copy_to_nursery_bytes(&self) -> usize {
        self.copy_to_nursery_requests()
            .fold(0usize, |total, request| {
                total.saturating_add(request.size_bytes())
            })
    }

    /// Returns total requested old-generation destination bytes.
    pub fn promote_to_old_bytes(&self) -> usize {
        self.promote_to_old_requests()
            .fold(0usize, |total, request| {
                total.saturating_add(request.size_bytes())
            })
    }

    /// Returns the number of object byte-copy requests.
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Returns whether no object bytes need copying.
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Builds heap-record generation writes for this object-copy plan.
    ///
    /// The returned plan contains only metadata. Applying it still requires an
    /// [`EvalHeap`] whose destination addresses already resolve to heap records.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if request storage cannot be reserved, if a
    /// request's destination generation disagrees with its survivor action, if
    /// requests contain duplicate source or destination identities, or if a
    /// destination overlaps any survivor source.
    pub fn object_generation_write_plan(
        &self,
    ) -> Result<AllocationCollectorPollObjectGenerationWritePlan, EvalHeapError> {
        AllocationCollectorPollObjectGenerationWritePlan::from_requests(&self.requests)
    }
}

/// A summary of heap-record object-body writes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollObjectBodyWriteReport {
    objects: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    payload_bytes: usize,
}

impl AllocationCollectorPollObjectBodyWriteReport {
    pub(super) fn record(&mut self, request: AllocationCollectorPollObjectByteCopyRequest) {
        self.objects = self.objects.saturating_add(1);
        self.payload_bytes = self.payload_bytes.saturating_add(request.size_bytes());
        match request.action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_to_nursery = self.copied_to_nursery.saturating_add(1);
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_to_old = self.promoted_to_old.saturating_add(1);
            }
        }
    }

    /// Returns how many destination heap-record bodies are covered.
    pub const fn objects(self) -> usize {
        self.objects
    }

    /// Returns how many body-write requests target next-nursery destinations.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns how many body-write requests target promoted old-generation destinations.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }

    /// Returns the total copied-object payload bytes covered by the report.
    pub const fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
}

/// A summary of paired object-body and object-generation writes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollObjectBodyAndGenerationWriteReport {
    body_write_report: AllocationCollectorPollObjectBodyWriteReport,
    generation_write_report: AllocationCollectorPollObjectGenerationWriteReport,
}

impl AllocationCollectorPollObjectBodyAndGenerationWriteReport {
    pub(super) const fn new(
        body_write_report: AllocationCollectorPollObjectBodyWriteReport,
        generation_write_report: AllocationCollectorPollObjectGenerationWriteReport,
    ) -> Self {
        Self {
            body_write_report,
            generation_write_report,
        }
    }

    /// Returns the object-body write report.
    pub const fn body_write_report(self) -> AllocationCollectorPollObjectBodyWriteReport {
        self.body_write_report
    }

    /// Returns the object-generation write report.
    pub const fn generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectGenerationWriteReport {
        self.generation_write_report
    }
}

pub(super) struct CollectorPollObjectBodyWrite {
    pub(super) destination_index: usize,
    pub(super) object: HeapObjectValue,
    pub(super) layout: HeapRecordLayout,
    pub(super) structural_hash: Option<HotXxh3Hash>,
    pub(super) value_hash: Option<ValueHash>,
    pub(super) captured_value_hash: Option<ValueHash>,
}

// Pre-split audience was the heap module (private to roots.rs, imported by
// the writeback stagers via `roots::CollectorPollCopiedHeapFieldWrite`); widened
// path-explicitly after the §2 relocation.
pub(in crate::eval::heap) struct CollectorPollCopiedHeapFieldWrite {
    pub(super) record_index: usize,
    pub(super) writeback_object: GcHeapAddress,
    pub(super) field_index: usize,
    pub(super) source: HeapEdgeSource,
    pub(super) replacement: Value,
    pub(super) base_object: Option<HeapObjectValue>,
}

// Pre-split audience was the heap module (private to roots.rs, imported by
// the writeback stagers via `roots::CollectorPollDirectHeapFieldWrite`); widened
// path-explicitly after the §2 relocation.
pub(in crate::eval::heap) struct CollectorPollDirectHeapFieldWrite {
    pub(super) target: HeapFieldWriteTarget,
    pub(super) writeback_object: GcHeapAddress,
    pub(super) field_index: usize,
    pub(super) source: HeapEdgeSource,
    pub(super) replacement: Value,
    pub(super) remembered_edge: Option<RememberedEdge>,
}

/// The staged destination of one direct heap-field write.
///
/// Records stage by table index (the pre-FV-1 shape); flat lists (doc 30
/// FV-1) and flat attrsets (FV-2) have no record and stage by their stable
/// flat-store address, whose commit goes through the flat store's exclusive
/// `resolve_mut` door.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HeapFieldWriteTarget {
    /// A record-table object, staged by record index.
    Record(usize),
    /// A flat list object, staged by its stable heap address.
    FlatList(NonNull<HeapObject>),
    /// A flat attrset object, staged by its stable heap address.
    FlatAttrs(NonNull<HeapObject>),
    /// A nursery flat closure, staged by its stable heap address.
    FlatClosure(NonNull<HeapObject>, FlatObjectKind),
}

/// One cloned nursery flat-closure payload awaiting transactional publication.
#[derive(Clone, Debug)]
pub(in crate::eval::heap) enum StagedFlatClosurePayload {
    /// An inline thunk payload whose owned fields may be rewritten.
    Thunk(EvalThunk),
    /// A shared thunk payload retained without changing its `Arc` identity.
    SharedThunk(Arc<EvalThunk>),
    /// A lambda payload whose directly owned dynamic captures may be rewritten.
    Lambda(EvalLambda),
    /// A primop payload whose captured argument values may be rewritten.
    Primop(EvalPrimOp),
}

impl StagedFlatClosurePayload {
    /// Converts the staged typed payload into its flat-store representation.
    pub(super) fn into_flat_payload(self) -> FlatClosurePayload {
        match self {
            Self::Thunk(thunk) => FlatClosurePayload::Thunk(thunk),
            Self::SharedThunk(thunk) => FlatClosurePayload::SharedThunk(thunk),
            Self::Lambda(lambda) => FlatClosurePayload::Lambda(lambda),
            Self::Primop(primop) => FlatClosurePayload::Primop(primop),
        }
    }
}

/// One complete staged nursery flat-closure write.
///
/// Payload and inline capture-tail values are cloned before any live mutation.
/// The optional tail preserves the source allocation's exact length, allowing
/// commit to use only fixed-size copies after the source kind and shape have
/// been validated.
#[derive(Clone, Debug)]
pub(in crate::eval::heap) struct StagedFlatClosureWrite {
    pub(super) ptr: NonNull<HeapObject>,
    pub(super) kind: FlatObjectKind,
    pub(super) payload: StagedFlatClosurePayload,
    pub(super) tail: Option<Vec<Value>>,
}

/// Staged live heap writes for a tree-walk minor-GC publication.
pub(crate) struct AllocationCollectorPollLiveHeapFieldWriteStage {
    pub(super) object_body_writes: Vec<CollectorPollObjectBodyWrite>,
    pub(super) object_generation_writes: Vec<(usize, HeapGeneration)>,
    pub(super) staged_heap_field_writes: Vec<(usize, HeapObjectValue)>,
    pub(super) staged_flat_list_writes: Vec<(NonNull<HeapObject>, NixList)>,
    pub(super) staged_flat_attrs_writes: Vec<(NonNull<HeapObject>, FlatAttrs)>,
    pub(super) staged_flat_closure_writes: Vec<StagedFlatClosureWrite>,
    pub(super) staged_environment_writes: EnvironmentWritebackStage,
    pub(super) staged_structural_writebacks: StructuralWritebackStage,
    pub(super) staged_barriers: Option<(RememberedSet, GcCardTable)>,
    pub(super) object_body_and_generation_write_report:
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    pub(super) copied_report: AllocationCollectorPollCopiedHeapFieldWriteReport,
    pub(super) direct_report: AllocationCollectorPollDirectHeapFieldWriteReport,
}

impl AllocationCollectorPollLiveHeapFieldWriteStage {
    /// Returns the paired object-body and generation write report.
    pub(crate) const fn object_body_and_generation_write_report(
        &self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.object_body_and_generation_write_report
    }

    /// Returns the copied heap-field write report.
    pub(crate) const fn copied_report(&self) -> AllocationCollectorPollCopiedHeapFieldWriteReport {
        self.copied_report
    }

    /// Returns the direct heap-field write report.
    pub(crate) const fn direct_report(&self) -> AllocationCollectorPollDirectHeapFieldWriteReport {
        self.direct_report
    }

    /// Returns how many live heap fields are staged for rewrite.
    pub(crate) const fn live_heap_field_writebacks(&self) -> usize {
        self.copied_report
            .fields()
            .saturating_add(self.direct_report.fields())
    }
}

/// Staged side-table forwarding writes for a tree-walk minor-GC publication.
pub(crate) struct AllocationCollectorPollForwardingInstallStage {
    pub(super) planned: Vec<(usize, GcHeapAddress, ResolvedValueGeneration)>,
}

impl AllocationCollectorPollForwardingInstallStage {
    /// Returns the forwarding installation report for this staged write.
    pub(crate) fn report(&self) -> AllocationCollectorPollForwardingInstallReport {
        AllocationCollectorPollForwardingInstallReport {
            forwarding_pointers: self.planned.len(),
        }
    }
}

pub(super) enum RecordOwnedHeapFieldWriteObjectError {
    UnsupportedSource,
    Attr(AttrError),
    Environment(EvalEnvError),
    Thunk(ForceError),
    ParallelThunkPayload(ParallelThunkPayloadError),
}

/// A summary of heap-record object-generation writes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollObjectGenerationWriteReport {
    objects: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    payload_bytes: usize,
}

impl AllocationCollectorPollObjectGenerationWriteReport {
    pub(super) fn record(&mut self, write: &AllocationCollectorPollObjectGenerationWrite) {
        self.objects = self.objects.saturating_add(1);
        self.payload_bytes = self
            .payload_bytes
            .saturating_add(write.request().size_bytes());
        match write.action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_to_nursery = self.copied_to_nursery.saturating_add(1);
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_to_old = self.promoted_to_old.saturating_add(1);
            }
        }
    }

    /// Returns how many destination heap records are covered.
    pub const fn objects(self) -> usize {
        self.objects
    }

    /// Returns how many requests kept destinations in the young generation.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns how many requests promoted destinations to the old generation.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }

    /// Returns the total copied-object payload bytes covered by the report.
    pub const fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
}

/// One planned heap-record generation write for a relocated object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollObjectGenerationWrite {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    action: MinorGcSurvivorAction,
    generation: HeapGeneration,
    request: AllocationCollectorPollObjectByteCopyRequest,
}

impl AllocationCollectorPollObjectGenerationWrite {
    pub(super) fn from_request(request: AllocationCollectorPollObjectByteCopyRequest) -> Self {
        Self {
            source: request.source(),
            destination: request.destination(),
            action: request.action(),
            generation: request.destination_generation(),
            request,
        }
    }

    /// Returns the from-space survivor source object.
    pub const fn source(self) -> GcHeapAddress {
        self.source
    }

    /// Returns the destination object whose heap record should be written.
    pub const fn destination(self) -> GcHeapAddress {
        self.destination
    }

    /// Returns whether this destination stays young or is promoted.
    pub const fn action(self) -> MinorGcSurvivorAction {
        self.action
    }

    /// Returns the generation to write to the destination heap record.
    pub const fn generation(self) -> HeapGeneration {
        self.generation
    }

    /// Returns the object-copy request that produced this generation write.
    pub const fn request(self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }
}

/// Heap-record generation writes derived from object-copy requests.
///
/// The plan is valid for destination records that have already been bound into
/// the evaluator heap side table. It does not allocate destination records, bind
/// object bytes to heap storage, rewrite references, or manage semispaces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollObjectGenerationWritePlan {
    report: AllocationCollectorPollObjectGenerationWriteReport,
    writes: Vec<AllocationCollectorPollObjectGenerationWrite>,
}

impl AllocationCollectorPollObjectGenerationWritePlan {
    pub(super) fn new(writes: Vec<AllocationCollectorPollObjectGenerationWrite>) -> Self {
        let mut report = AllocationCollectorPollObjectGenerationWriteReport::default();
        for write in &writes {
            report.record(write);
        }
        Self { report, writes }
    }

    pub(super) fn from_requests(
        requests: &[AllocationCollectorPollObjectByteCopyRequest],
    ) -> Result<Self, EvalHeapError> {
        let mut writes = Vec::new();
        writes.try_reserve_exact(requests.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_OBJECT_GENERATION_WRITES_TABLE,
                entries: requests.len(),
            }
        })?;

        for (index, request) in requests.iter().copied().enumerate() {
            validate_object_generation_write_request(index, request, &writes)?;
            writes.push(AllocationCollectorPollObjectGenerationWrite::from_request(
                request,
            ));
        }

        Ok(Self::new(writes))
    }

    #[cfg(test)]
    pub(crate) fn from_requests_for_test(
        requests: Vec<AllocationCollectorPollObjectByteCopyRequest>,
    ) -> Result<Self, EvalHeapError> {
        Self::from_requests(&requests)
    }

    /// Returns whether this plan has no heap-record generation writes.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// Returns how many heap-record generation writes are planned.
    pub fn len(&self) -> usize {
        self.writes.len()
    }

    /// Returns aggregate counts for the planned writes.
    pub const fn report(&self) -> AllocationCollectorPollObjectGenerationWriteReport {
        self.report
    }

    /// Returns the planned heap-record generation writes.
    pub fn writes(&self) -> &[AllocationCollectorPollObjectGenerationWrite] {
        &self.writes
    }
}

pub(super) const fn generation_for_destination_action(
    action: MinorGcSurvivorAction,
) -> HeapGeneration {
    match action {
        MinorGcSurvivorAction::CopyToNursery => HeapGeneration::Young,
        MinorGcSurvivorAction::PromoteToOld => HeapGeneration::Old,
    }
}

pub(super) fn validate_object_byte_copy_request_destination_generation(
    request: AllocationCollectorPollObjectByteCopyRequest,
) -> Result<HeapGeneration, EvalHeapError> {
    let expected = generation_for_destination_action(request.action());
    let actual = request.destination_generation();
    if actual != expected {
        return Err(
            EvalHeapError::CollectorPollObjectGenerationWriteGenerationMismatch {
                source_address: request.source(),
                destination: request.destination(),
                expected,
                actual,
                action: request.action(),
            },
        );
    }
    Ok(expected)
}

pub(super) fn validate_collector_poll_minor_gc_copied_heap_field_write_request_invariants(
    writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
) -> Result<(), EvalHeapError> {
    let entries = writes
        .len()
        .checked_mul(2)
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE,
        })?;
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(entries)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE,
            entries,
        })?;

    for write in writes {
        push_unique_heap_field_write_request(&mut requests, write.writeback_object_request());
        push_unique_heap_field_write_request(&mut requests, write.replacement_request());
    }

    let _ =
        AllocationCollectorPollObjectByteCopyPlan::new(requests).object_generation_write_plan()?;
    Ok(())
}

pub(super) fn validate_collector_poll_minor_gc_direct_heap_field_write_request_invariants(
    writes: &[AllocationCollectorPollDirectHeapFieldWrite],
) -> Result<(), EvalHeapError> {
    let mut requests = Vec::new();
    requests.try_reserve_exact(writes.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
            entries: writes.len(),
        }
    })?;

    for write in writes {
        push_unique_heap_field_write_request(&mut requests, write.replacement_request());
    }

    let _ =
        AllocationCollectorPollObjectByteCopyPlan::new(requests).object_generation_write_plan()?;
    Ok(())
}

pub(super) fn validate_collector_poll_minor_gc_heap_field_write_request_invariants(
    copied_writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
    direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
) -> Result<(), EvalHeapError> {
    let copied_entries =
        copied_writes
            .len()
            .checked_mul(2)
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
            })?;
    let entries = copied_entries.checked_add(direct_writes.len()).ok_or(
        EvalHeapError::RootScanLengthOverflow {
            table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
        },
    )?;
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(entries)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
            entries,
        })?;

    for write in copied_writes {
        push_unique_heap_field_write_request(&mut requests, write.writeback_object_request());
        push_unique_heap_field_write_request(&mut requests, write.replacement_request());
    }
    for write in direct_writes {
        push_unique_heap_field_write_request(&mut requests, write.replacement_request());
    }

    let _ =
        AllocationCollectorPollObjectByteCopyPlan::new(requests).object_generation_write_plan()?;
    Ok(())
}

pub(super) fn push_unique_heap_field_write_request(
    requests: &mut Vec<AllocationCollectorPollObjectByteCopyRequest>,
    request: AllocationCollectorPollObjectByteCopyRequest,
) {
    if !requests.iter().any(|existing| *existing == request) {
        requests.push(request);
    }
}

pub(super) fn validate_object_generation_write_request(
    index: usize,
    request: AllocationCollectorPollObjectByteCopyRequest,
    writes: &[AllocationCollectorPollObjectGenerationWrite],
) -> Result<(), EvalHeapError> {
    let _ = validate_object_byte_copy_request_destination_generation(request)?;
    if request.source() == request.destination() {
        return Err(
            EvalHeapError::CollectorPollObjectGenerationWriteDestinationIsSource {
                source_address: request.source(),
            },
        );
    }
    if writes
        .iter()
        .any(|write| write.source() == request.source())
    {
        return Err(
            EvalHeapError::CollectorPollObjectGenerationWriteDuplicateSource {
                index,
                source_address: request.source(),
            },
        );
    }
    if let Some(existing) = writes
        .iter()
        .find(|write| write.destination() == request.destination())
    {
        return Err(
            EvalHeapError::CollectorPollObjectGenerationWriteDuplicateDestination {
                index,
                source_address: request.source(),
                existing_source_address: existing.source(),
                destination: request.destination(),
            },
        );
    }
    if let Some(existing) = writes
        .iter()
        .find(|write| write.source() == request.destination())
    {
        return Err(
            EvalHeapError::CollectorPollObjectGenerationWriteDestinationOverlapsSource {
                index,
                source_address: request.source(),
                existing_source_address: existing.source(),
                destination: request.destination(),
            },
        );
    }
    if let Some(existing) = writes
        .iter()
        .find(|write| write.destination() == request.source())
    {
        return Err(
            EvalHeapError::CollectorPollObjectGenerationWriteDestinationOverlapsSource {
                index,
                source_address: existing.source(),
                existing_source_address: request.source(),
                destination: existing.destination(),
            },
        );
    }

    Ok(())
}
