//! Evaluation outcome, derivation, statistics, trace, IFD-realization, and warning types.

use super::*;
use crate::cache::ImpureInputTraceSource;
use crate::compile::EffectClass;

type IfdRealizerCallback =
    dyn for<'a> Fn(IfdRealization<'a>) -> Result<(), IfdRealizationError> + Send + Sync;

const BOUNDARY_MINOR_GC_ROOT_REFERENCE_VALUES_TABLE: &str =
    "boundary minor-GC root reference values";
const BOUNDARY_MINOR_GC_OBJECT_BYTE_COPY_APPLICATIONS_TABLE: &str =
    "boundary minor-GC object byte-copy applications";
const BOUNDARY_MINOR_GC_OBJECT_SOURCE_BYTES_TABLE: &str = "boundary minor-GC object source bytes";
const BOUNDARY_MINOR_GC_OBJECT_DESTINATION_BYTES_TABLE: &str =
    "boundary minor-GC object destination bytes";
const BOUNDARY_MINOR_GC_OBJECT_BYTE_COPY_BUFFERS_TABLE: &str =
    "boundary minor-GC object byte-copy buffers";
const BOUNDARY_MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE: &str =
    "boundary minor-GC forwarding slot buffer";
const BOUNDARY_MINOR_GC_REFERENCE_BUFFER_TABLE: &str = "boundary minor-GC reference buffer";
const BOUNDARY_MINOR_GC_ROOT_WRITEBACK_SLOTS_TABLE: &str = "boundary minor-GC root writeback slots";
const BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_SLOTS_TABLE: &str =
    "boundary minor-GC heap-field writeback slots";

/// GC-stress heap scans recorded at a successful tree-walk evaluation boundary.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryScans {
    worker: Option<AllocationCollectorPollScan>,
    permanent_shared: Option<AllocationCollectorPollScan>,
}

impl EvalGcStressBoundaryScans {
    /// Creates a boundary-scan report from per-allocator scan results.
    pub(crate) const fn new(
        worker: Option<AllocationCollectorPollScan>,
        permanent_shared: Option<AllocationCollectorPollScan>,
    ) -> Self {
        Self {
            worker,
            permanent_shared,
        }
    }

    /// Returns whether no allocator tier requested a GC-stress boundary scan.
    pub const fn is_empty(&self) -> bool {
        self.worker.is_none() && self.permanent_shared.is_none()
    }

    /// Returns how many allocator tiers produced a boundary scan.
    pub const fn len(&self) -> usize {
        match (self.worker.is_some(), self.permanent_shared.is_some()) {
            (false, false) => 0,
            (true, false) | (false, true) => 1,
            (true, true) => 2,
        }
    }

    /// Returns the worker allocator's GC-stress boundary scan, if any.
    pub const fn worker(&self) -> Option<&AllocationCollectorPollScan> {
        self.worker.as_ref()
    }

    /// Returns the permanent-shared allocator's GC-stress boundary scan, if any.
    pub const fn permanent_shared(&self) -> Option<&AllocationCollectorPollScan> {
        self.permanent_shared.as_ref()
    }
}

/// Minor-GC plans derived from GC-stress boundary scans.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcPlans {
    worker: Option<AllocationCollectorPollMinorGcPlan>,
    permanent_shared: Option<AllocationCollectorPollMinorGcPlan>,
}

impl EvalGcStressBoundaryMinorGcPlans {
    /// Creates a boundary-plan report from per-allocator plan results.
    pub(crate) const fn new(
        worker: Option<AllocationCollectorPollMinorGcPlan>,
        permanent_shared: Option<AllocationCollectorPollMinorGcPlan>,
    ) -> Self {
        Self {
            worker,
            permanent_shared,
        }
    }

    /// Returns whether no allocator tier produced a boundary minor-GC plan.
    pub const fn is_empty(&self) -> bool {
        self.worker.is_none() && self.permanent_shared.is_none()
    }

    /// Returns how many allocator tiers produced a boundary minor-GC plan.
    pub const fn len(&self) -> usize {
        match (self.worker.is_some(), self.permanent_shared.is_some()) {
            (false, false) => 0,
            (true, false) | (false, true) => 1,
            (true, true) => 2,
        }
    }

    /// Returns the worker allocator's boundary minor-GC plan, if any.
    pub const fn worker(&self) -> Option<&AllocationCollectorPollMinorGcPlan> {
        self.worker.as_ref()
    }

    /// Returns the permanent-shared allocator's boundary minor-GC plan, if any.
    pub const fn permanent_shared(&self) -> Option<&AllocationCollectorPollMinorGcPlan> {
        self.permanent_shared.as_ref()
    }
}

/// Relocation destinations derived from GC-stress boundary minor-GC plans.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcRelocationDestinations {
    worker: Option<AllocationCollectorPollMinorGcRelocationDestinations>,
    permanent_shared: Option<AllocationCollectorPollMinorGcRelocationDestinations>,
}

impl EvalGcStressBoundaryMinorGcRelocationDestinations {
    /// Creates a relocation-destination report from per-allocator results.
    pub(crate) const fn new(
        worker: Option<AllocationCollectorPollMinorGcRelocationDestinations>,
        permanent_shared: Option<AllocationCollectorPollMinorGcRelocationDestinations>,
    ) -> Self {
        Self {
            worker,
            permanent_shared,
        }
    }

    /// Returns whether no allocator tier produced a relocation-destination report.
    pub const fn is_empty(&self) -> bool {
        self.worker.is_none() && self.permanent_shared.is_none()
    }

    /// Returns how many allocator tiers produced relocation-destination reports.
    pub const fn len(&self) -> usize {
        match (self.worker.is_some(), self.permanent_shared.is_some()) {
            (false, false) => 0,
            (true, false) | (false, true) => 1,
            (true, true) => 2,
        }
    }

    /// Returns the worker allocator's relocation-destination report, if any.
    pub const fn worker(&self) -> Option<&AllocationCollectorPollMinorGcRelocationDestinations> {
        self.worker.as_ref()
    }

    /// Returns the permanent-shared allocator's relocation-destination report, if any.
    pub const fn permanent_shared(
        &self,
    ) -> Option<&AllocationCollectorPollMinorGcRelocationDestinations> {
        self.permanent_shared.as_ref()
    }
}

/// A boundary minor-GC plan paired with materialized relocation destinations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcRelocationPlan {
    minor_gc_plan: AllocationCollectorPollMinorGcPlan,
    relocation_destinations: AllocationCollectorPollMinorGcRelocationDestinations,
}

impl EvalGcStressBoundaryMinorGcRelocationPlan {
    /// Creates a paired boundary relocation plan.
    pub(crate) const fn new(
        minor_gc_plan: AllocationCollectorPollMinorGcPlan,
        relocation_destinations: AllocationCollectorPollMinorGcRelocationDestinations,
    ) -> Self {
        Self {
            minor_gc_plan,
            relocation_destinations,
        }
    }

    /// Returns the boundary minor-GC plan used to derive the destinations.
    pub const fn minor_gc_plan(&self) -> &AllocationCollectorPollMinorGcPlan {
        &self.minor_gc_plan
    }

    /// Returns the materialized relocation destinations for the minor-GC plan.
    pub const fn relocation_destinations(
        &self,
    ) -> &AllocationCollectorPollMinorGcRelocationDestinations {
        &self.relocation_destinations
    }

    /// Builds ordered commit metadata from this paired boundary plan.
    ///
    /// This delegates to the underlying allocation-poll minor-GC plan using the
    /// destinations derived for that exact plan. It still does not copy object
    /// bytes, install forwarding pointers, mutate roots or fields, publish
    /// remembered sets, or invoke a collector.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if the paired destination placements or
    /// relocation destinations do not match the minor-GC plan, if commit
    /// subplans cannot reserve storage, or if the subplans are inconsistent.
    pub fn commit_plan(
        &self,
    ) -> Result<AllocationCollectorPollMinorGcCommitPlan<'_>, GenerationalGcError> {
        self.minor_gc_plan
            .commit_plan(&self.relocation_destinations)
    }
}

/// Boundary minor-GC relocation plans derived from GC-stress boundary scans.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcRelocationPlans {
    worker: Option<EvalGcStressBoundaryMinorGcRelocationPlan>,
    permanent_shared: Option<EvalGcStressBoundaryMinorGcRelocationPlan>,
}

impl EvalGcStressBoundaryMinorGcRelocationPlans {
    /// Creates a paired relocation-plan report from per-allocator results.
    pub(crate) const fn new(
        worker: Option<EvalGcStressBoundaryMinorGcRelocationPlan>,
        permanent_shared: Option<EvalGcStressBoundaryMinorGcRelocationPlan>,
    ) -> Self {
        Self {
            worker,
            permanent_shared,
        }
    }

    /// Returns whether no allocator tier produced a paired relocation plan.
    pub const fn is_empty(&self) -> bool {
        self.worker.is_none() && self.permanent_shared.is_none()
    }

    /// Returns how many allocator tiers produced paired relocation plans.
    pub const fn len(&self) -> usize {
        match (self.worker.is_some(), self.permanent_shared.is_some()) {
            (false, false) => 0,
            (true, false) | (false, true) => 1,
            (true, true) => 2,
        }
    }

    /// Returns the worker allocator's paired relocation plan, if any.
    pub const fn worker(&self) -> Option<&EvalGcStressBoundaryMinorGcRelocationPlan> {
        self.worker.as_ref()
    }

    /// Returns the permanent-shared allocator's paired relocation plan, if any.
    pub const fn permanent_shared(&self) -> Option<&EvalGcStressBoundaryMinorGcRelocationPlan> {
        self.permanent_shared.as_ref()
    }

    fn into_relocation_destinations(self) -> EvalGcStressBoundaryMinorGcRelocationDestinations {
        EvalGcStressBoundaryMinorGcRelocationDestinations::new(
            self.worker.map(|plan| plan.relocation_destinations),
            self.permanent_shared
                .map(|plan| plan.relocation_destinations),
        )
    }
}

/// Owned commit-preflight metadata derived from a boundary relocation plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcCommitPreflight {
    relocation_plan: EvalGcStressBoundaryMinorGcRelocationPlan,
    object_byte_copy_plan: AllocationCollectorPollObjectByteCopyPlan,
    forwarding_slots: Vec<MinorGcForwardingSlot>,
    reference_buffer: Vec<ResolvedValueGeneration>,
    reference_writeback_plan: AllocationCollectorPollReferenceWritebackPlan,
    root_writeback_slots: Vec<AllocationCollectorPollRootWritebackSlot>,
    heap_field_writeback_slots: Vec<AllocationCollectorPollHeapFieldWritebackSlot>,
}

impl EvalGcStressBoundaryMinorGcCommitPreflight {
    /// Creates owned commit-preflight metadata for one allocator tier.
    pub(crate) const fn new(
        relocation_plan: EvalGcStressBoundaryMinorGcRelocationPlan,
        object_byte_copy_plan: AllocationCollectorPollObjectByteCopyPlan,
        forwarding_slots: Vec<MinorGcForwardingSlot>,
        reference_buffer: Vec<ResolvedValueGeneration>,
        reference_writeback_plan: AllocationCollectorPollReferenceWritebackPlan,
        root_writeback_slots: Vec<AllocationCollectorPollRootWritebackSlot>,
        heap_field_writeback_slots: Vec<AllocationCollectorPollHeapFieldWritebackSlot>,
    ) -> Self {
        Self {
            relocation_plan,
            object_byte_copy_plan,
            forwarding_slots,
            reference_buffer,
            reference_writeback_plan,
            root_writeback_slots,
            heap_field_writeback_slots,
        }
    }

    /// Returns the paired boundary relocation plan used for preflight metadata.
    pub const fn relocation_plan(&self) -> &EvalGcStressBoundaryMinorGcRelocationPlan {
        &self.relocation_plan
    }

    /// Returns object byte-copy requests in commit order.
    pub const fn object_byte_copy_plan(&self) -> &AllocationCollectorPollObjectByteCopyPlan {
        &self.object_byte_copy_plan
    }

    /// Returns total object payload bytes requested by this preflight.
    ///
    /// This excludes destination-space alignment padding; use the paired
    /// relocation placement plan for reserved-byte sizing.
    pub fn object_copy_bytes(&self) -> usize {
        self.copy_to_nursery_bytes()
            .saturating_add(self.promote_to_old_bytes())
    }

    /// Returns object payload bytes copied into the next nursery.
    ///
    /// This excludes destination-space alignment padding; use the paired
    /// relocation placement plan for reserved-byte sizing.
    pub fn copy_to_nursery_bytes(&self) -> usize {
        self.object_byte_copy_plan.copy_to_nursery_bytes()
    }

    /// Returns object payload bytes promoted into old generation.
    ///
    /// This excludes destination-space alignment padding; use the paired
    /// relocation placement plan for reserved-byte sizing.
    pub fn promote_to_old_bytes(&self) -> usize {
        self.object_byte_copy_plan.promote_to_old_bytes()
    }

    /// Returns empty forwarding slots in forwarding-pointer order.
    pub fn forwarding_slots(&self) -> &[MinorGcForwardingSlot] {
        &self.forwarding_slots
    }

    /// Returns copied reference values in commit-buffer order.
    pub fn reference_buffer(&self) -> &[ResolvedValueGeneration] {
        &self.reference_buffer
    }

    /// Returns root and heap-field reference writebacks in commit order.
    pub const fn reference_writeback_plan(&self) -> &AllocationCollectorPollReferenceWritebackPlan {
        &self.reference_writeback_plan
    }

    /// Returns caller-owned root writeback slots copied from the plan.
    pub fn root_writeback_slots(&self) -> &[AllocationCollectorPollRootWritebackSlot] {
        &self.root_writeback_slots
    }

    /// Returns caller-owned heap-field writeback slots copied from the plan.
    pub fn heap_field_writeback_slots(&self) -> &[AllocationCollectorPollHeapFieldWritebackSlot] {
        &self.heap_field_writeback_slots
    }

    /// Applies reference writebacks to this preflight's owned slot buffers.
    ///
    /// The method clones the root and heap-field writeback slots captured by
    /// this preflight, validates them against the copied reference-writeback
    /// plan, applies replacements into those owned buffers, and returns the
    /// mutated buffers with the writeback report. It still does not bind those
    /// buffers to live tree-walk roots, live heap fields, copied object bytes,
    /// object headers, forwarding slots, remembered-set storage, or semispace
    /// storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the copied slot buffers cannot be reserved
    /// or if the copied slots no longer match this preflight's writeback plan.
    pub fn apply_reference_writebacks_to_owned_slots(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcReferenceWritebackApplication, EvalHeapError> {
        let mut root_writeback_slots =
            clone_boundary_root_writeback_slots(&self.root_writeback_slots)?;
        let mut heap_field_writeback_slots =
            clone_boundary_heap_field_writeback_slots(&self.heap_field_writeback_slots)?;
        let report = self
            .reference_writeback_plan
            .apply_to_slots(&mut root_writeback_slots, &mut heap_field_writeback_slots)?;

        Ok(
            EvalGcStressBoundaryMinorGcReferenceWritebackApplication::new(
                report,
                root_writeback_slots,
                heap_field_writeback_slots,
            ),
        )
    }

    /// Applies the commit plan to boundary-owned synthetic commit buffers.
    ///
    /// The method clones this preflight's forwarding slots and reference buffer,
    /// clones the remembered set captured by the minor-GC plan, builds
    /// synthetic source and destination byte buffers from the object byte-copy
    /// requests, and applies the full lower-level commit plan to those owned
    /// buffers. The synthetic byte buffers prove commit ordering and validation
    /// without claiming to bind to live semispace storage or real heap object
    /// bytes. Live tree-walk roots, heap fields, object headers, remembered-set
    /// storage, and semispace pages remain untouched.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if any owned buffer cannot be reserved, if
    /// commit metadata cannot be rebuilt from the paired relocation plan, or if
    /// any owned buffer fails the lower-level commit validation.
    pub fn apply_commit_to_owned_buffers(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcCommitApplication, EvalHeapError> {
        let mut object_byte_copies =
            boundary_minor_gc_object_byte_copy_applications(&self.object_byte_copy_plan)?;
        let mut forwarding_slots = clone_boundary_forwarding_slots(&self.forwarding_slots)?;
        let mut references = clone_boundary_reference_buffer(&self.reference_buffer)?;
        let mut remembered_set =
            clone_boundary_remembered_set(self.relocation_plan.minor_gc_plan().remembered_set())?;

        let report = {
            let commit_plan = self.relocation_plan.commit_plan()?;
            let mut object_byte_copy_buffers =
                boundary_minor_gc_object_byte_copy_buffers(&mut object_byte_copies)?;
            commit_plan.apply_to_buffers_with_report(
                AllocationCollectorPollMinorGcCommitBuffers::new(
                    &mut object_byte_copy_buffers,
                    &mut forwarding_slots,
                    &mut references,
                    &mut remembered_set,
                ),
            )?
        };

        Ok(EvalGcStressBoundaryMinorGcCommitApplication::new(
            report,
            object_byte_copies,
            forwarding_slots,
            references,
            remembered_set,
        ))
    }
}

/// Applied caller-owned reference writeback buffers for one boundary preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcReferenceWritebackApplication {
    report: AllocationCollectorPollReferenceWritebackReport,
    root_writeback_slots: Vec<AllocationCollectorPollRootWritebackSlot>,
    heap_field_writeback_slots: Vec<AllocationCollectorPollHeapFieldWritebackSlot>,
}

impl EvalGcStressBoundaryMinorGcReferenceWritebackApplication {
    const fn new(
        report: AllocationCollectorPollReferenceWritebackReport,
        root_writeback_slots: Vec<AllocationCollectorPollRootWritebackSlot>,
        heap_field_writeback_slots: Vec<AllocationCollectorPollHeapFieldWritebackSlot>,
    ) -> Self {
        Self {
            report,
            root_writeback_slots,
            heap_field_writeback_slots,
        }
    }

    /// Returns the writeback counts reported by the applied plan.
    pub const fn report(&self) -> AllocationCollectorPollReferenceWritebackReport {
        self.report
    }

    /// Returns caller-owned root writeback slots after application.
    pub fn root_writeback_slots(&self) -> &[AllocationCollectorPollRootWritebackSlot] {
        &self.root_writeback_slots
    }

    /// Returns caller-owned heap-field writeback slots after application.
    pub fn heap_field_writeback_slots(&self) -> &[AllocationCollectorPollHeapFieldWritebackSlot] {
        &self.heap_field_writeback_slots
    }
}

/// Applied boundary-owned object byte buffers for one minor-GC object copy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcObjectByteCopyApplication {
    request: AllocationCollectorPollObjectByteCopyRequest,
    source_bytes: Vec<u8>,
    destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcObjectByteCopyApplication {
    fn new(
        request: AllocationCollectorPollObjectByteCopyRequest,
        source_bytes: Vec<u8>,
        destination_bytes: Vec<u8>,
    ) -> Self {
        Self {
            request,
            source_bytes,
            destination_bytes,
        }
    }

    /// Returns the byte-copy request that shaped this owned buffer pair.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }

    /// Returns the synthetic source bytes supplied to the commit application.
    pub fn source_bytes(&self) -> &[u8] {
        &self.source_bytes
    }

    /// Returns the destination bytes after commit application.
    pub fn destination_bytes(&self) -> &[u8] {
        &self.destination_bytes
    }
}

/// Applied boundary-owned buffers for one minor-GC commit preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcCommitApplication {
    report: MinorGcCommitReport,
    object_byte_copies: Vec<EvalGcStressBoundaryMinorGcObjectByteCopyApplication>,
    forwarding_slots: Vec<MinorGcForwardingSlot>,
    references: Vec<ResolvedValueGeneration>,
    remembered_set: RememberedSet,
}

impl EvalGcStressBoundaryMinorGcCommitApplication {
    fn new(
        report: MinorGcCommitReport,
        object_byte_copies: Vec<EvalGcStressBoundaryMinorGcObjectByteCopyApplication>,
        forwarding_slots: Vec<MinorGcForwardingSlot>,
        references: Vec<ResolvedValueGeneration>,
        remembered_set: RememberedSet,
    ) -> Self {
        Self {
            report,
            object_byte_copies,
            forwarding_slots,
            references,
            remembered_set,
        }
    }

    /// Returns the lower-level commit counts for the applied owned buffers.
    pub const fn report(&self) -> MinorGcCommitReport {
        self.report
    }

    /// Returns owned object byte buffers after commit application.
    pub fn object_byte_copies(&self) -> &[EvalGcStressBoundaryMinorGcObjectByteCopyApplication] {
        &self.object_byte_copies
    }

    /// Returns forwarding slots after commit application.
    pub fn forwarding_slots(&self) -> &[MinorGcForwardingSlot] {
        &self.forwarding_slots
    }

    /// Returns copied reference values after commit application.
    pub fn references(&self) -> &[ResolvedValueGeneration] {
        &self.references
    }

    /// Returns the remembered set after commit publication into the owned buffer.
    pub const fn remembered_set(&self) -> &RememberedSet {
        &self.remembered_set
    }
}

fn boundary_minor_gc_object_byte_copy_applications(
    plan: &AllocationCollectorPollObjectByteCopyPlan,
) -> Result<Vec<EvalGcStressBoundaryMinorGcObjectByteCopyApplication>, EvalHeapError> {
    let requests = plan.requests();
    let mut applications = Vec::new();
    applications
        .try_reserve_exact(requests.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_BYTE_COPY_APPLICATIONS_TABLE,
            entries: requests.len(),
        })?;

    for (index, request) in requests.iter().copied().enumerate() {
        applications.push(EvalGcStressBoundaryMinorGcObjectByteCopyApplication::new(
            request,
            boundary_minor_gc_object_source_bytes(index, request.size_bytes())?,
            boundary_minor_gc_object_destination_bytes(request.size_bytes())?,
        ));
    }

    Ok(applications)
}

fn boundary_minor_gc_object_source_bytes(
    index: usize,
    size_bytes: usize,
) -> Result<Vec<u8>, EvalHeapError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size_bytes)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_SOURCE_BYTES_TABLE,
            entries: size_bytes,
        })?;
    let seed = index.to_le_bytes()[0].wrapping_mul(31).wrapping_add(0xa5);
    for offset in 0..size_bytes {
        bytes.push(seed.wrapping_add(offset.to_le_bytes()[0]));
    }
    Ok(bytes)
}

fn boundary_minor_gc_object_destination_bytes(size_bytes: usize) -> Result<Vec<u8>, EvalHeapError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size_bytes)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_DESTINATION_BYTES_TABLE,
            entries: size_bytes,
        })?;
    bytes.resize(size_bytes, 0);
    Ok(bytes)
}

fn boundary_minor_gc_object_byte_copy_buffers<'a>(
    applications: &'a mut [EvalGcStressBoundaryMinorGcObjectByteCopyApplication],
) -> Result<Vec<MinorGcObjectByteCopyBuffer<'a>>, EvalHeapError> {
    let mut buffers = Vec::new();
    buffers.try_reserve_exact(applications.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_BYTE_COPY_BUFFERS_TABLE,
            entries: applications.len(),
        }
    })?;

    for application in applications.iter_mut() {
        let request = application.request;
        let source_bytes = application.source_bytes.as_slice();
        let destination_bytes = application.destination_bytes.as_mut_slice();
        buffers.push(MinorGcObjectByteCopyBuffer::new(
            request.source(),
            request.destination(),
            source_bytes,
            destination_bytes,
        ));
    }

    Ok(buffers)
}

fn clone_boundary_forwarding_slots(
    slots: &[MinorGcForwardingSlot],
) -> Result<Vec<MinorGcForwardingSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().copied());
    Ok(cloned)
}

fn clone_boundary_reference_buffer(
    references: &[ResolvedValueGeneration],
) -> Result<Vec<ResolvedValueGeneration>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned.try_reserve_exact(references.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_REFERENCE_BUFFER_TABLE,
            entries: references.len(),
        }
    })?;
    cloned.extend(references.iter().copied());
    Ok(cloned)
}

fn clone_boundary_remembered_set(
    remembered_set: &RememberedSet,
) -> Result<RememberedSet, EvalHeapError> {
    let mut cloned = RememberedSet::with_epoch(remembered_set.epoch());
    for edge in remembered_set.edges() {
        cloned.record(*edge)?;
    }
    Ok(cloned)
}

fn clone_boundary_root_writeback_slots(
    slots: &[AllocationCollectorPollRootWritebackSlot],
) -> Result<Vec<AllocationCollectorPollRootWritebackSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_SLOTS_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().cloned());
    Ok(cloned)
}

fn clone_boundary_heap_field_writeback_slots(
    slots: &[AllocationCollectorPollHeapFieldWritebackSlot],
) -> Result<Vec<AllocationCollectorPollHeapFieldWritebackSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_SLOTS_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().cloned());
    Ok(cloned)
}

/// Commit-preflight metadata derived from GC-stress boundary scans.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcCommitPreflights {
    worker: Option<EvalGcStressBoundaryMinorGcCommitPreflight>,
    permanent_shared: Option<EvalGcStressBoundaryMinorGcCommitPreflight>,
}

impl EvalGcStressBoundaryMinorGcCommitPreflights {
    /// Creates a commit-preflight report from per-allocator results.
    pub(crate) const fn new(
        worker: Option<EvalGcStressBoundaryMinorGcCommitPreflight>,
        permanent_shared: Option<EvalGcStressBoundaryMinorGcCommitPreflight>,
    ) -> Self {
        Self {
            worker,
            permanent_shared,
        }
    }

    /// Returns whether no allocator tier produced commit-preflight metadata.
    pub const fn is_empty(&self) -> bool {
        self.worker.is_none() && self.permanent_shared.is_none()
    }

    /// Returns how many allocator tiers produced commit-preflight metadata.
    pub const fn len(&self) -> usize {
        match (self.worker.is_some(), self.permanent_shared.is_some()) {
            (false, false) => 0,
            (true, false) | (false, true) => 1,
            (true, true) => 2,
        }
    }

    /// Returns the worker allocator's commit-preflight metadata, if any.
    pub const fn worker(&self) -> Option<&EvalGcStressBoundaryMinorGcCommitPreflight> {
        self.worker.as_ref()
    }

    /// Returns the permanent-shared allocator's commit-preflight metadata, if any.
    pub const fn permanent_shared(&self) -> Option<&EvalGcStressBoundaryMinorGcCommitPreflight> {
        self.permanent_shared.as_ref()
    }

    /// Applies reference writebacks for every recorded boundary preflight.
    ///
    /// Each allocator tier is applied independently to owned slot-buffer copies
    /// from its preflight. The returned report preserves the worker and
    /// permanent-shared partition. This still does not mutate live evaluator
    /// roots, heap fields, object bytes, forwarding slots, remembered-set state,
    /// or semispace storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if any preflight cannot copy its owned
    /// writeback slots or if any copied slot buffer fails validation.
    pub fn apply_reference_writebacks_to_owned_slots(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcReferenceWritebackApplications, EvalHeapError> {
        let worker = self
            .worker
            .as_ref()
            .map(EvalGcStressBoundaryMinorGcCommitPreflight::apply_reference_writebacks_to_owned_slots)
            .transpose()?;
        let permanent_shared = self
            .permanent_shared
            .as_ref()
            .map(EvalGcStressBoundaryMinorGcCommitPreflight::apply_reference_writebacks_to_owned_slots)
            .transpose()?;

        Ok(
            EvalGcStressBoundaryMinorGcReferenceWritebackApplications::new(
                worker,
                permanent_shared,
            ),
        )
    }

    /// Applies complete commit plans for every recorded boundary preflight.
    ///
    /// Each allocator tier is committed independently into owned synthetic
    /// byte buffers plus cloned forwarding, reference, and remembered-set
    /// buffers. This preserves the worker/permanent-shared partition while
    /// still avoiding mutation of live tree-walk roots, heap fields, object
    /// headers, remembered-set storage, or semispace pages.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if any preflight cannot allocate its owned
    /// buffers, rebuild commit metadata, or validate those buffers against the
    /// lower-level commit plan.
    pub fn apply_commits_to_owned_buffers(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcCommitApplications, EvalHeapError> {
        let worker = self
            .worker
            .as_ref()
            .map(EvalGcStressBoundaryMinorGcCommitPreflight::apply_commit_to_owned_buffers)
            .transpose()?;
        let permanent_shared = self
            .permanent_shared
            .as_ref()
            .map(EvalGcStressBoundaryMinorGcCommitPreflight::apply_commit_to_owned_buffers)
            .transpose()?;

        Ok(EvalGcStressBoundaryMinorGcCommitApplications::new(
            worker,
            permanent_shared,
        ))
    }

    /// Applies every boundary commit preflight to owned dry-run buffers.
    ///
    /// This consumes the preflight bundle so the returned dry-run report retains
    /// the exact metadata that produced the owned reference-writeback and commit
    /// applications. It still does not mutate live evaluator roots, live heap
    /// fields, object headers, remembered-set storage, or semispace pages.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if any preflight cannot allocate its owned
    /// writeback or commit buffers, rebuild commit metadata, or validate those
    /// buffers against the lower-level plans.
    pub fn apply_owned_commit_dry_run(
        self,
    ) -> Result<EvalGcStressBoundaryMinorGcCommitDryRun, EvalHeapError> {
        let reference_writebacks = self.apply_reference_writebacks_to_owned_slots()?;
        let commit_applications = self.apply_commits_to_owned_buffers()?;

        Ok(EvalGcStressBoundaryMinorGcCommitDryRun::new(
            self,
            reference_writebacks,
            commit_applications,
        ))
    }
}

/// Owned dry-run application of GC-stress boundary minor-GC commit preflights.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcCommitDryRun {
    preflights: EvalGcStressBoundaryMinorGcCommitPreflights,
    reference_writebacks: EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
    commit_applications: EvalGcStressBoundaryMinorGcCommitApplications,
}

impl EvalGcStressBoundaryMinorGcCommitDryRun {
    const fn new(
        preflights: EvalGcStressBoundaryMinorGcCommitPreflights,
        reference_writebacks: EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
        commit_applications: EvalGcStressBoundaryMinorGcCommitApplications,
    ) -> Self {
        Self {
            preflights,
            reference_writebacks,
            commit_applications,
        }
    }

    /// Returns whether no allocator tier produced a dry-run application.
    pub const fn is_empty(&self) -> bool {
        self.preflights.is_empty()
    }

    /// Returns how many allocator tiers produced dry-run applications.
    pub const fn len(&self) -> usize {
        self.preflights.len()
    }

    /// Returns the preflight metadata used by this dry run.
    pub const fn preflights(&self) -> &EvalGcStressBoundaryMinorGcCommitPreflights {
        &self.preflights
    }

    /// Returns the owned reference-writeback applications.
    pub const fn reference_writebacks(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcReferenceWritebackApplications {
        &self.reference_writebacks
    }

    /// Returns the owned commit-buffer applications.
    pub const fn commit_applications(&self) -> &EvalGcStressBoundaryMinorGcCommitApplications {
        &self.commit_applications
    }

    /// Returns aggregate counts for the owned dry-run applications.
    pub fn summary(&self) -> EvalGcStressBoundaryMinorGcCommitDryRunSummary {
        EvalGcStressBoundaryMinorGcCommitDryRunSummary::from_preflights_and_applications(
            &self.preflights,
            &self.reference_writebacks,
            &self.commit_applications,
        )
    }
}

/// Aggregate counts and payload bytes from owned boundary minor-GC dry runs.
///
/// The summary is telemetry for the synthetic dry-run boundary only. It does
/// not imply that live roots, heap fields, object bytes, forwarding headers,
/// remembered sets, or semispace storage were mutated.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcCommitDryRunSummary {
    tiers: usize,
    object_copies: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    copy_to_nursery_bytes: usize,
    promote_to_old_bytes: usize,
    forwarding_pointers: usize,
    reference_rewrites: usize,
    root_writebacks: usize,
    heap_field_writebacks: usize,
    remembered_set_source_edges: usize,
    remembered_set_published_edges: usize,
}

impl EvalGcStressBoundaryMinorGcCommitDryRunSummary {
    fn from_preflights_and_applications(
        preflights: &EvalGcStressBoundaryMinorGcCommitPreflights,
        reference_writebacks: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
        commit_applications: &EvalGcStressBoundaryMinorGcCommitApplications,
    ) -> Self {
        let mut summary = Self::default();
        summary.add_preflights(preflights);
        summary.add_reference_writeback_applications(reference_writebacks);
        summary.add_commit_applications(commit_applications);
        summary
    }

    fn add_preflights(&mut self, preflights: &EvalGcStressBoundaryMinorGcCommitPreflights) {
        if let Some(preflight) = preflights.worker() {
            self.add_preflight(preflight);
        }
        if let Some(preflight) = preflights.permanent_shared() {
            self.add_preflight(preflight);
        }
    }

    fn add_preflight(&mut self, preflight: &EvalGcStressBoundaryMinorGcCommitPreflight) {
        self.copy_to_nursery_bytes = self
            .copy_to_nursery_bytes
            .saturating_add(preflight.copy_to_nursery_bytes());
        self.promote_to_old_bytes = self
            .promote_to_old_bytes
            .saturating_add(preflight.promote_to_old_bytes());
    }

    fn add_reference_writeback_applications(
        &mut self,
        applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
    ) {
        if let Some(application) = applications.worker() {
            self.add_reference_writeback_report(application.report());
        }
        if let Some(application) = applications.permanent_shared() {
            self.add_reference_writeback_report(application.report());
        }
    }

    fn add_commit_applications(
        &mut self,
        applications: &EvalGcStressBoundaryMinorGcCommitApplications,
    ) {
        if let Some(application) = applications.worker() {
            self.add_commit_report(application.report());
        }
        if let Some(application) = applications.permanent_shared() {
            self.add_commit_report(application.report());
        }
    }

    fn add_reference_writeback_report(
        &mut self,
        report: AllocationCollectorPollReferenceWritebackReport,
    ) {
        self.root_writebacks = self
            .root_writebacks
            .saturating_add(report.root_writebacks());
        self.heap_field_writebacks = self
            .heap_field_writebacks
            .saturating_add(report.heap_field_writebacks());
    }

    fn add_commit_report(&mut self, report: MinorGcCommitReport) {
        self.tiers = self.tiers.saturating_add(1);
        self.object_copies = self.object_copies.saturating_add(report.object_copies());
        self.copied_to_nursery = self
            .copied_to_nursery
            .saturating_add(report.copied_to_nursery());
        self.promoted_to_old = self
            .promoted_to_old
            .saturating_add(report.promoted_to_old());
        self.forwarding_pointers = self
            .forwarding_pointers
            .saturating_add(report.forwarding_pointers());
        self.reference_rewrites = self
            .reference_rewrites
            .saturating_add(report.reference_rewrites());
        self.remembered_set_source_edges = self
            .remembered_set_source_edges
            .saturating_add(report.remembered_set_source_edges());
        self.remembered_set_published_edges = self
            .remembered_set_published_edges
            .saturating_add(report.remembered_set_published_edges());
    }

    /// Returns how many allocator tiers produced dry-run applications.
    pub const fn tiers(self) -> usize {
        self.tiers
    }

    /// Returns the number of object byte-copy applications.
    pub const fn object_copies(self) -> usize {
        self.object_copies
    }

    /// Returns the number of survivors copied to the next nursery.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns the number of survivors promoted to old generation.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }

    /// Returns total object payload bytes requested by all dry-run preflights.
    ///
    /// This excludes destination-space alignment padding; use the relocation
    /// placement plans for reserved-byte sizing.
    pub const fn object_copy_bytes(self) -> usize {
        self.copy_to_nursery_bytes
            .saturating_add(self.promote_to_old_bytes)
    }

    /// Returns object payload bytes copied into next nursery spaces.
    ///
    /// This excludes destination-space alignment padding.
    pub const fn copy_to_nursery_bytes(self) -> usize {
        self.copy_to_nursery_bytes
    }

    /// Returns object payload bytes promoted into old-generation space.
    ///
    /// This excludes destination-space alignment padding.
    pub const fn promote_to_old_bytes(self) -> usize {
        self.promote_to_old_bytes
    }

    /// Returns the number of forwarding slots populated.
    pub const fn forwarding_pointers(self) -> usize {
        self.forwarding_pointers
    }

    /// Returns the number of lower-level reference rewrites applied.
    pub const fn reference_rewrites(self) -> usize {
        self.reference_rewrites
    }

    /// Returns the number of caller-owned root slots rewritten.
    pub const fn root_writebacks(self) -> usize {
        self.root_writebacks
    }

    /// Returns the number of caller-owned heap-field slots rewritten.
    pub const fn heap_field_writebacks(self) -> usize {
        self.heap_field_writebacks
    }

    /// Returns the total number of caller-owned reference slots rewritten.
    pub const fn reference_writebacks(self) -> usize {
        self.root_writebacks
            .saturating_add(self.heap_field_writebacks)
    }

    /// Returns remembered-set edges examined from source epochs.
    pub const fn remembered_set_source_edges(self) -> usize {
        self.remembered_set_source_edges
    }

    /// Returns remembered-set edges published into next epochs.
    pub const fn remembered_set_published_edges(self) -> usize {
        self.remembered_set_published_edges
    }
}

/// Applied reference writeback buffers derived from boundary preflights.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcReferenceWritebackApplications {
    worker: Option<EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
    permanent_shared: Option<EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
}

impl EvalGcStressBoundaryMinorGcReferenceWritebackApplications {
    const fn new(
        worker: Option<EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
        permanent_shared: Option<EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
    ) -> Self {
        Self {
            worker,
            permanent_shared,
        }
    }

    /// Returns whether no allocator tier produced applied writeback buffers.
    pub const fn is_empty(&self) -> bool {
        self.worker.is_none() && self.permanent_shared.is_none()
    }

    /// Returns how many allocator tiers produced applied writeback buffers.
    pub const fn len(&self) -> usize {
        match (self.worker.is_some(), self.permanent_shared.is_some()) {
            (false, false) => 0,
            (true, false) | (false, true) => 1,
            (true, true) => 2,
        }
    }

    /// Returns the worker allocator's applied writeback buffers, if any.
    pub const fn worker(
        &self,
    ) -> Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication> {
        self.worker.as_ref()
    }

    /// Returns the permanent-shared allocator's applied writeback buffers, if any.
    pub const fn permanent_shared(
        &self,
    ) -> Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication> {
        self.permanent_shared.as_ref()
    }
}

/// Applied owned commit buffers derived from boundary preflights.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcCommitApplications {
    worker: Option<EvalGcStressBoundaryMinorGcCommitApplication>,
    permanent_shared: Option<EvalGcStressBoundaryMinorGcCommitApplication>,
}

impl EvalGcStressBoundaryMinorGcCommitApplications {
    const fn new(
        worker: Option<EvalGcStressBoundaryMinorGcCommitApplication>,
        permanent_shared: Option<EvalGcStressBoundaryMinorGcCommitApplication>,
    ) -> Self {
        Self {
            worker,
            permanent_shared,
        }
    }

    /// Returns whether no allocator tier produced an owned commit application.
    pub const fn is_empty(&self) -> bool {
        self.worker.is_none() && self.permanent_shared.is_none()
    }

    /// Returns how many allocator tiers produced owned commit applications.
    pub const fn len(&self) -> usize {
        match (self.worker.is_some(), self.permanent_shared.is_some()) {
            (false, false) => 0,
            (true, false) | (false, true) => 1,
            (true, true) => 2,
        }
    }

    /// Returns the worker allocator's owned commit application, if any.
    pub const fn worker(&self) -> Option<&EvalGcStressBoundaryMinorGcCommitApplication> {
        self.worker.as_ref()
    }

    /// Returns the permanent-shared allocator's owned commit application, if any.
    pub const fn permanent_shared(&self) -> Option<&EvalGcStressBoundaryMinorGcCommitApplication> {
        self.permanent_shared.as_ref()
    }
}

fn boundary_minor_gc_root_reference_values(
    reference_slots: &[AllocationCollectorPollReferenceSlot],
) -> Result<Vec<AllocationCollectorPollRootReferenceValue>, EvalHeapError> {
    let root_count = reference_slots
        .iter()
        .filter(|slot| {
            matches!(
                slot.source(),
                AllocationCollectorPollReferenceSource::Root { .. }
            )
        })
        .count();
    let mut root_values = Vec::new();
    root_values.try_reserve_exact(root_count).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_ROOT_REFERENCE_VALUES_TABLE,
            entries: root_count,
        }
    })?;

    for slot in reference_slots {
        let AllocationCollectorPollReferenceSource::Root { source } = slot.source() else {
            continue;
        };
        root_values.push(AllocationCollectorPollRootReferenceValue::new(
            source.clone(),
            slot.value(),
        ));
    }

    Ok(root_values)
}

fn boundary_minor_gc_root_writeback_slots(
    plan: &AllocationCollectorPollReferenceWritebackPlan,
) -> Result<Vec<AllocationCollectorPollRootWritebackSlot>, EvalHeapError> {
    let writebacks = plan.root_writebacks().writebacks();
    let mut slots = Vec::new();
    slots.try_reserve_exact(writebacks.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_SLOTS_TABLE,
            entries: writebacks.len(),
        }
    })?;

    for writeback in writebacks {
        slots.push(AllocationCollectorPollRootWritebackSlot::new(
            writeback.source().clone(),
            writeback.expected(),
        ));
    }

    Ok(slots)
}

fn boundary_minor_gc_heap_field_writeback_slots(
    plan: &AllocationCollectorPollReferenceWritebackPlan,
) -> Result<Vec<AllocationCollectorPollHeapFieldWritebackSlot>, EvalHeapError> {
    let writebacks = plan.heap_field_writebacks().writebacks();
    let mut slots = Vec::new();
    slots.try_reserve_exact(writebacks.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_SLOTS_TABLE,
            entries: writebacks.len(),
        }
    })?;

    for writeback in writebacks {
        slots.push(AllocationCollectorPollHeapFieldWritebackSlot::new(
            writeback.validation_object(),
            writeback.writeback_object(),
            writeback.field_index(),
            writeback.source().clone(),
            writeback.expected(),
        ));
    }

    Ok(slots)
}

/// A tree-walk evaluation result with its owning evaluator heap.
pub struct EvalOutcome {
    pub(crate) value: Value,
    pub(crate) heap: EvalHeap,
    pub(crate) stats: EvalStats,
    pub(crate) attr_telemetry: AttrTelemetry,
    pub(crate) trace_output: Vec<EvalTraceOutput>,
    pub(crate) warning_output: Vec<EvalWarningOutput>,
    pub(crate) impure_input_trace: Vec<ImpureInputFingerprint>,
    pub(crate) impure_input_trace_complete: bool,
    pub(crate) persist_force_cache_hit_keys: Vec<PersistNodeMetadataKey>,
    pub(crate) derivations: Vec<EvalDerivation>,
    pub(crate) thunk_resolve_remembered_set: RememberedSet,
    pub(crate) thunk_resolve_card_table: GcCardTable,
    pub(crate) memory_budget_action: Option<EvalHeapMemoryBudgetAction>,
    pub(crate) cheap_memory_budget_plan: Option<EvalHeapCheapMemoryBudgetPlan>,
    pub(crate) cheap_memory_advice_report: Option<EvalHeapCheapMemoryAdviceReport>,
    pub(crate) gc_stress_boundary_scans: EvalGcStressBoundaryScans,
}

impl std::fmt::Debug for EvalOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvalOutcome")
            .field("value", &self.value)
            .field("heap", &self.heap)
            .field("stats", &self.stats)
            .field("attr_telemetry", &self.attr_telemetry)
            .field("trace_output", &self.trace_output)
            .field("warning_output", &self.warning_output)
            .field("impure_input_trace", &self.impure_input_trace)
            .field(
                "impure_input_trace_complete",
                &self.impure_input_trace_complete,
            )
            .field("derivations", &self.derivations)
            .field(
                "thunk_resolve_remembered_set",
                &self.thunk_resolve_remembered_set,
            )
            .field("thunk_resolve_card_table", &self.thunk_resolve_card_table)
            .field("memory_budget_action", &self.memory_budget_action)
            .field("cheap_memory_budget_plan", &self.cheap_memory_budget_plan)
            .field(
                "cheap_memory_advice_report",
                &self.cheap_memory_advice_report,
            )
            .field("gc_stress_boundary_scans", &self.gc_stress_boundary_scans)
            .finish()
    }
}

impl EvalOutcome {
    /// Returns the evaluated root value.
    pub const fn value(&self) -> Value {
        self.value
    }

    /// Returns the heap that owns heap-backed values in this result.
    pub const fn heap(&self) -> &EvalHeap {
        &self.heap
    }

    /// Returns mirrored evaluator counters captured at the end of evaluation.
    pub const fn stats(&self) -> &EvalStats {
        &self.stats
    }

    /// Returns byte-neutral attribute-set telemetry captured during evaluation.
    pub const fn attr_telemetry(&self) -> &AttrTelemetry {
        &self.attr_telemetry
    }

    /// Returns user-facing trace output emitted during evaluation.
    pub fn trace_output(&self) -> &[EvalTraceOutput] {
        &self.trace_output
    }

    /// Returns user-facing warning output emitted during evaluation.
    pub fn warning_output(&self) -> &[EvalWarningOutput] {
        &self.warning_output
    }

    /// Returns impure evaluator inputs observed during evaluation.
    pub fn impure_input_trace(&self) -> &[ImpureInputFingerprint] {
        &self.impure_input_trace
    }

    /// Returns whether the impure input trace is complete and cache-usable.
    pub const fn impure_input_trace_complete(&self) -> bool {
        self.impure_input_trace_complete
    }

    /// Returns persistent force-cache metadata keys loaded during evaluation.
    ///
    /// This is diagnostic evaluator metadata and is not serialized into any
    /// Nix-observable value, derivation path, or ATerm surface.
    pub fn persist_force_cache_hit_keys(&self) -> &[PersistNodeMetadataKey] {
        &self.persist_force_cache_hit_keys
    }

    /// Returns derivations observed while evaluating the root expression.
    pub fn derivations(&self) -> &[EvalDerivation] {
        &self.derivations
    }

    /// Returns the remembered set populated by thunk-resolution write barriers.
    pub const fn thunk_resolve_remembered_set(&self) -> &RememberedSet {
        &self.thunk_resolve_remembered_set
    }

    /// Returns the card table populated by thunk-resolution write barriers.
    pub const fn thunk_resolve_card_table(&self) -> &GcCardTable {
        &self.thunk_resolve_card_table
    }

    /// Returns the final high-water heap budget action, if one was configured.
    pub const fn memory_budget_action(&self) -> Option<EvalHeapMemoryBudgetAction> {
        self.memory_budget_action
    }

    /// Returns the final cold-aware heap budget plan, if one was requested.
    ///
    /// This is planning telemetry only. A plan can credit logical cold
    /// hash-consed bytes for future CA-store spill, but it is not evidence that
    /// resident bytes were actually reclaimed during evaluation.
    pub const fn cheap_memory_budget_plan(&self) -> Option<EvalHeapCheapMemoryBudgetPlan> {
        self.cheap_memory_budget_plan
    }

    /// Returns the post-evaluation cheap heap advice report, if one was requested.
    pub const fn cheap_memory_advice_report(&self) -> Option<EvalHeapCheapMemoryAdviceReport> {
        self.cheap_memory_advice_report
    }

    /// Returns GC-stress scans recorded at the successful evaluation boundary.
    pub const fn gc_stress_boundary_scans(&self) -> &EvalGcStressBoundaryScans {
        &self.gc_stress_boundary_scans
    }

    /// Builds minor-GC plans from the recorded GC-stress boundary scans.
    ///
    /// This uses the outcome's remembered-set snapshot and the caller-supplied
    /// promotion policy. It is planning metadata only: it does not choose
    /// semispace destinations, install forwarding pointers, rewrite roots or
    /// fields, publish remembered sets, or invoke a collector.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if a recorded boundary scan is stale relative
    /// to the outcome heap, if the remembered set is incomplete or invalid for
    /// the current heap graph, or if minor-GC planning fails.
    pub fn gc_stress_boundary_minor_gc_plans(
        &self,
        promotion_policy: MinorGcPromotionPolicy,
    ) -> Result<EvalGcStressBoundaryMinorGcPlans, EvalHeapError> {
        let remembered_set = self.thunk_resolve_remembered_set.snapshot();
        let collection_epoch = self.thunk_resolve_remembered_set.epoch();
        let worker = match self.gc_stress_boundary_scans.worker() {
            Some(scan) => Some(self.heap.plan_collector_poll_minor_gc(
                scan,
                remembered_set,
                collection_epoch,
                promotion_policy,
            )?),
            None => None,
        };
        let permanent_shared = match self.gc_stress_boundary_scans.permanent_shared() {
            Some(scan) => Some(self.heap.plan_collector_poll_minor_gc(
                scan,
                remembered_set,
                collection_epoch,
                promotion_policy,
            )?),
            None => None,
        };
        Ok(EvalGcStressBoundaryMinorGcPlans::new(
            worker,
            permanent_shared,
        ))
    }

    /// Builds relocation destinations from recorded GC-stress boundary scans.
    ///
    /// This derives minor-GC plans with the supplied promotion policy, reads the
    /// outcome heap's current layout metadata for planned survivors, and
    /// materializes relocation destinations from `bases`. It is planning
    /// metadata only: it does not reserve semispace storage, copy object bytes,
    /// install forwarding pointers, rewrite roots or fields, publish remembered
    /// sets, or invoke a collector.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary minor-GC planning fails, if the
    /// outcome heap changed since planning, if survivor layout metadata cannot be
    /// derived, or if relocation-destination planning rejects the supplied bases.
    pub fn gc_stress_boundary_minor_gc_relocation_destinations(
        &self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcRelocationDestinations, EvalHeapError> {
        Ok(self
            .gc_stress_boundary_minor_gc_relocation_plans(promotion_policy, bases)?
            .into_relocation_destinations())
    }

    /// Builds paired minor-GC plans and relocation destinations from boundary scans.
    ///
    /// This derives minor-GC plans with the supplied promotion policy, reads the
    /// outcome heap's current layout metadata for planned survivors, and stores
    /// each plan next to the relocation destinations materialized from `bases`.
    /// The paired report can build commit metadata without recomputing or
    /// mismatching those pieces, but it still does not reserve semispace storage,
    /// copy object bytes, install forwarding pointers, rewrite roots or fields,
    /// publish remembered sets, or invoke a collector.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary minor-GC planning fails, if the
    /// outcome heap changed since planning, if survivor layout metadata cannot be
    /// derived, or if relocation-destination planning rejects the supplied bases.
    pub fn gc_stress_boundary_minor_gc_relocation_plans(
        &self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcRelocationPlans, EvalHeapError> {
        let plans = self.gc_stress_boundary_minor_gc_plans(promotion_policy)?;
        let EvalGcStressBoundaryMinorGcPlans {
            worker,
            permanent_shared,
        } = plans;
        let worker = match worker {
            Some(plan) => {
                let destinations = self
                    .heap
                    .plan_collector_poll_minor_gc_relocation_destinations(&plan, bases)?;
                Some(EvalGcStressBoundaryMinorGcRelocationPlan::new(
                    plan,
                    destinations,
                ))
            }
            None => None,
        };
        let permanent_shared = match permanent_shared {
            Some(plan) => {
                let destinations = self
                    .heap
                    .plan_collector_poll_minor_gc_relocation_destinations(&plan, bases)?;
                Some(EvalGcStressBoundaryMinorGcRelocationPlan::new(
                    plan,
                    destinations,
                ))
            }
            None => None,
        };
        Ok(EvalGcStressBoundaryMinorGcRelocationPlans::new(
            worker,
            permanent_shared,
        ))
    }

    /// Builds owned commit-preflight metadata from GC-stress boundary scans.
    ///
    /// This derives paired boundary relocation plans, builds the borrowed commit
    /// metadata long enough to validate and extract owned object byte-copy
    /// requests, empty forwarding slots, copied reference buffers, and reference
    /// writeback metadata plus caller-owned writeback slot buffers, then returns
    /// those artifacts beside the paired relocation plan. It still does not bind
    /// object byte buffers, mutate forwarding slots, rewrite live roots or heap
    /// fields, publish remembered sets, reserve semispace storage, or invoke a
    /// collector.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary relocation planning fails, if commit
    /// metadata cannot be built, if heap-backed byte-copy or writeback validation
    /// fails, or if forwarding-slot storage cannot be reserved.
    pub fn gc_stress_boundary_minor_gc_commit_preflights(
        &self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcCommitPreflights, EvalHeapError> {
        let plans = self.gc_stress_boundary_minor_gc_relocation_plans(promotion_policy, bases)?;
        let EvalGcStressBoundaryMinorGcRelocationPlans {
            worker,
            permanent_shared,
        } = plans;
        let worker = worker
            .map(|plan| self.gc_stress_boundary_minor_gc_commit_preflight(plan))
            .transpose()?;
        let permanent_shared = permanent_shared
            .map(|plan| self.gc_stress_boundary_minor_gc_commit_preflight(plan))
            .transpose()?;

        Ok(EvalGcStressBoundaryMinorGcCommitPreflights::new(
            worker,
            permanent_shared,
        ))
    }

    /// Runs boundary minor-GC commit preflights against owned dry-run buffers.
    ///
    /// This derives boundary commit preflight metadata from the recorded
    /// GC-stress scans, applies reference writebacks into owned slot copies, and
    /// applies commit plans into owned synthetic byte, forwarding, reference,
    /// and remembered-set buffers. The returned report carries all three
    /// artifacts for the exact same worker/permanent-shared partition. It still
    /// does not mutate live evaluator roots, live heap fields, object headers,
    /// remembered-set storage, or semispace pages.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit preflight derivation fails,
    /// if any owned dry-run buffer cannot be allocated, or if any owned buffer
    /// fails validation against the lower-level commit or writeback plans.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run(
        &self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcCommitDryRun, EvalHeapError> {
        self.gc_stress_boundary_minor_gc_commit_preflights(promotion_policy, bases)?
            .apply_owned_commit_dry_run()
    }

    fn gc_stress_boundary_minor_gc_commit_preflight(
        &self,
        relocation_plan: EvalGcStressBoundaryMinorGcRelocationPlan,
    ) -> Result<EvalGcStressBoundaryMinorGcCommitPreflight, EvalHeapError> {
        let root_values = boundary_minor_gc_root_reference_values(
            relocation_plan.minor_gc_plan().reference_slots(),
        )?;
        let (
            object_byte_copy_plan,
            forwarding_slots,
            reference_buffer,
            reference_writeback_plan,
            root_writeback_slots,
            heap_field_writeback_slots,
        ) = {
            let commit_plan = relocation_plan.commit_plan()?;
            let object_byte_copy_plan = self
                .heap
                .collector_poll_minor_gc_object_byte_copy_plan(&commit_plan)?;
            let forwarding_slots = commit_plan.forwarding_slot_buffer()?;
            let reference_buffer = self
                .heap
                .collector_poll_minor_gc_reference_buffer(&commit_plan, &root_values)?;
            let reference_writeback_plan = self
                .heap
                .collector_poll_minor_gc_reference_writeback_plan(&commit_plan)?;
            let root_writeback_slots =
                boundary_minor_gc_root_writeback_slots(&reference_writeback_plan)?;
            let heap_field_writeback_slots =
                boundary_minor_gc_heap_field_writeback_slots(&reference_writeback_plan)?;
            (
                object_byte_copy_plan,
                forwarding_slots,
                reference_buffer,
                reference_writeback_plan,
                root_writeback_slots,
                heap_field_writeback_slots,
            )
        };

        Ok(EvalGcStressBoundaryMinorGcCommitPreflight::new(
            relocation_plan,
            object_byte_copy_plan,
            forwarding_slots,
            reference_buffer,
            reference_writeback_plan,
            root_writeback_slots,
            heap_field_writeback_slots,
        ))
    }

    /// Consumes the outcome into its value and heap.
    pub fn into_parts(self) -> (Value, EvalHeap) {
        (self.value, self.heap)
    }

    /// Consumes the outcome into its value, heap, and evaluation statistics.
    pub fn into_parts_with_stats(self) -> (Value, EvalHeap, EvalStats) {
        (self.value, self.heap, self.stats)
    }

    /// Consumes the outcome into its value, heap, and user-facing trace output.
    pub fn into_full_parts(self) -> (Value, EvalHeap, Vec<EvalTraceOutput>) {
        (self.value, self.heap, self.trace_output)
    }

    /// Consumes the outcome into its value, heap, trace output, and warning output.
    pub fn into_output_parts(
        self,
    ) -> (
        Value,
        EvalHeap,
        Vec<EvalTraceOutput>,
        Vec<EvalWarningOutput>,
    ) {
        (
            self.value,
            self.heap,
            self.trace_output,
            self.warning_output,
        )
    }
}

impl ImpureInputTraceSource for EvalOutcome {
    fn impure_input_trace(&self) -> &[ImpureInputFingerprint] {
        &self.impure_input_trace
    }

    fn impure_input_trace_complete(&self) -> bool {
        self.impure_input_trace_complete
    }
}

/// Mirrored native-evaluator counters aligned with the RFC-0007 stats schema.
///
/// Phase-1 fields that have no implementation yet stay present and zero so
/// downstream tracing consumers can rely on stable field names while later
/// tiers add inline caches, shape transitions, GC, promotions, deopts, and
/// early-cutoff cache behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalStats {
    pub(crate) thunks_forced: u64,
    pub(crate) thunks_allocated: u64,
    pub(crate) thunks_elided: u64,
    pub(crate) thunk_cache_hits: u64,
    pub(crate) inline_cache_hits: u64,
    pub(crate) inline_cache_misses: u64,
    pub(crate) shape_transitions: u64,
    pub(crate) gc_bytes: u64,
    pub(crate) gc_pause_us: u64,
    pub(crate) tier_promotions: u64,
    pub(crate) deopts: u64,
    pub(crate) force_cache_hits: u64,
    pub(crate) force_cache_misses: u64,
    pub(crate) force_cache_memoization_admits: u64,
    pub(crate) force_cache_memoization_bypasses: u64,
    pub(crate) force_cache_materialization_materializes: u64,
    pub(crate) force_cache_materialization_keeps_in_memory: u64,
    pub(crate) source_thunk_region_plan_decisions: u64,
    pub(crate) source_thunk_region_plan_lexical_subregion_decisions: u64,
    pub(crate) source_thunk_region_plan_conservative_fallbacks: u64,
    pub(crate) cache_hits: u64,
    pub(crate) cache_misses: u64,
    pub(crate) early_cutoffs: u64,
    pub(crate) derivation_aterm_path_reuses: u64,
    pub(crate) static_derivation_output_path_reuses: u64,
    pub(crate) derivation_hash_calculations: u64,
    pub(crate) derivation_text_path_calculations: u64,
    pub(crate) heap_chunks: u64,
    pub(crate) heap_reserved_bytes: u64,
    pub(crate) heap_used_bytes: u64,
}

impl EvalStats {
    /// Returns the number of thunks that performed suspended work.
    pub const fn thunks_forced(&self) -> u64 {
        self.thunks_forced
    }

    /// Returns the number of suspended thunk heap records allocated.
    pub const fn thunks_allocated(&self) -> u64 {
        self.thunks_allocated
    }

    /// Returns the number of planned thunk allocations elided by later tiers.
    pub const fn thunks_elided(&self) -> u64 {
        self.thunks_elided
    }

    /// Returns the number of already-forced thunk cell reuses.
    pub const fn thunk_cache_hits(&self) -> u64 {
        self.thunk_cache_hits
    }

    /// Returns the number of inline-cache hits reported by optimized tiers.
    pub const fn inline_cache_hits(&self) -> u64 {
        self.inline_cache_hits
    }

    /// Returns the number of inline-cache misses reported by optimized tiers.
    pub const fn inline_cache_misses(&self) -> u64 {
        self.inline_cache_misses
    }

    /// Returns the number of object-shape transitions reported by optimized tiers.
    pub const fn shape_transitions(&self) -> u64 {
        self.shape_transitions
    }

    /// Returns bytes reclaimed or scanned by a future GC subsystem.
    pub const fn gc_bytes(&self) -> u64 {
        self.gc_bytes
    }

    /// Returns microseconds spent in a future GC subsystem.
    pub const fn gc_pause_us(&self) -> u64 {
        self.gc_pause_us
    }

    /// Returns the number of promotions into optimized evaluator tiers.
    pub const fn tier_promotions(&self) -> u64 {
        self.tier_promotions
    }

    /// Returns the number of optimized-tier deoptimizations.
    pub const fn deopts(&self) -> u64 {
        self.deopts
    }

    /// Returns the number of advisory force-cache hits.
    pub const fn force_cache_hits(&self) -> u64 {
        self.force_cache_hits
    }

    /// Returns the number of advisory force-cache misses.
    pub const fn force_cache_misses(&self) -> u64 {
        self.force_cache_misses
    }

    /// Returns the number of advisory force-cache probes.
    pub const fn force_cache_probes(&self) -> u64 {
        self.force_cache_hits
            .saturating_add(self.force_cache_misses)
    }

    /// Returns force-cache memoization-policy decisions that admitted memoization.
    pub const fn force_cache_memoization_admits(&self) -> u64 {
        self.force_cache_memoization_admits
    }

    /// Returns force-cache memoization-policy decisions that bypassed memoization.
    pub const fn force_cache_memoization_bypasses(&self) -> u64 {
        self.force_cache_memoization_bypasses
    }

    /// Returns force-cache memoization-policy demands with a recorded decision.
    pub const fn force_cache_memoization_demands(&self) -> u64 {
        self.force_cache_memoization_admits
            .saturating_add(self.force_cache_memoization_bypasses)
    }

    /// Returns force-cache materialization decisions that selected durable storage.
    pub const fn force_cache_materialization_materializes(&self) -> u64 {
        self.force_cache_materialization_materializes
    }

    /// Returns force-cache materialization decisions that kept payloads in memory.
    pub const fn force_cache_materialization_keeps_in_memory(&self) -> u64 {
        self.force_cache_materialization_keeps_in_memory
    }

    /// Returns force-cache materialization threshold decisions.
    pub const fn force_cache_materialization_decisions(&self) -> u64 {
        self.force_cache_materialization_materializes
            .saturating_add(self.force_cache_materialization_keeps_in_memory)
    }

    /// Returns region-placement policy decisions sampled at source thunk allocations.
    pub const fn source_thunk_region_plan_decisions(&self) -> u64 {
        self.source_thunk_region_plan_decisions
    }

    /// Returns sampled source thunk decisions that selected a lexical subregion candidate.
    pub const fn source_thunk_region_plan_lexical_subregion_decisions(&self) -> u64 {
        self.source_thunk_region_plan_lexical_subregion_decisions
    }

    /// Returns sampled source thunk decisions that failed closed to the active runtime tier.
    pub const fn source_thunk_region_plan_conservative_fallbacks(&self) -> u64 {
        self.source_thunk_region_plan_conservative_fallbacks
    }

    /// Returns the aggregate number of evaluator cache hits.
    pub const fn cache_hits(&self) -> u64 {
        self.cache_hits
    }

    /// Returns the aggregate number of evaluator cache misses.
    pub const fn cache_misses(&self) -> u64 {
        self.cache_misses
    }

    /// Returns the number of incremental-cache early cutoffs.
    pub const fn early_cutoffs(&self) -> u64 {
        self.early_cutoffs
    }

    /// Returns the number of `.drv` paths reused from clean derivation ATerm records.
    pub const fn derivation_aterm_path_reuses(&self) -> u64 {
        self.derivation_aterm_path_reuses
    }

    /// Returns the number of static derivation output path sets reused from clean records.
    pub const fn static_derivation_output_path_reuses(&self) -> u64 {
        self.static_derivation_output_path_reuses
    }

    /// Returns the number of derivation hash-boundary calculations performed.
    pub const fn derivation_hash_calculations(&self) -> u64 {
        self.derivation_hash_calculations
    }

    /// Returns the number of derivation `.drv` text-path calculations performed.
    pub const fn derivation_text_path_calculations(&self) -> u64 {
        self.derivation_text_path_calculations
    }

    /// Returns the number of bump-arena chunks allocated by the evaluator heap.
    pub const fn heap_chunks(&self) -> u64 {
        self.heap_chunks
    }

    /// Returns bytes reserved by evaluator heap chunks.
    pub const fn heap_reserved_bytes(&self) -> u64 {
        self.heap_reserved_bytes
    }

    /// Returns bytes consumed by evaluator heap allocations.
    pub const fn heap_used_bytes(&self) -> u64 {
        self.heap_used_bytes
    }
}

/// A derivation recorded during tree-walk evaluation.
///
/// Recorded derivations include their ATerm bytes when byte materialization is
/// possible during evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalDerivation {
    pub(crate) absolute_path: String,
    pub(crate) aterm_bytes: Option<Vec<u8>>,
}

impl EvalDerivation {
    pub(crate) fn new(absolute_path: String, aterm_bytes: Option<Vec<u8>>) -> Self {
        Self {
            absolute_path,
            aterm_bytes,
        }
    }

    /// Returns the absolute `/nix/store` path of the `.drv`.
    pub fn absolute_path(&self) -> &str {
        &self.absolute_path
    }

    /// Returns the serialized `.drv` ATerm bytes when they are statically known.
    pub fn aterm_bytes(&self) -> Option<&[u8]> {
        self.aterm_bytes.as_deref()
    }
}

/// User-facing trace output emitted by `builtins.trace`-style builtins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalTraceOutput {
    pub(crate) kind: EvalTraceKind,
    pub(crate) message: Vec<u8>,
}

impl EvalTraceOutput {
    /// Creates a trace output record.
    pub(crate) fn new(kind: EvalTraceKind, message: Vec<u8>) -> Self {
        Self { kind, message }
    }

    /// Returns the builtin family that emitted this output.
    pub const fn kind(&self) -> EvalTraceKind {
        self.kind
    }

    /// Returns the rendered trace message bytes without the `trace: ` prefix.
    pub fn message(&self) -> &[u8] {
        &self.message
    }
}

/// The trace-like builtin that produced user-facing output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvalTraceKind {
    /// Output from `builtins.trace`.
    Trace,
    /// Output from `builtins.traceVerbose`.
    TraceVerbose,
}

/// A request to realize a derivation output needed during evaluation.
///
/// Import-from-derivation (IFD) is the one point where evaluation must pause for
/// the build layer. The tree-walk evaluator does not build by itself; callers
/// may install an [`IfdRealizer`] that realizes the requested derivation output
/// and returns once the filesystem path can be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IfdRealization<'a> {
    pub(crate) path: &'a [u8],
    pub(crate) drv_path: &'a [u8],
    pub(crate) output_name: Option<&'a [u8]>,
    pub(crate) context_kind: ContextKind,
    pub(crate) op: &'static str,
}

impl<'a> IfdRealization<'a> {
    /// Returns the filesystem path that triggered the IFD demand.
    pub const fn path(&self) -> &'a [u8] {
        self.path
    }

    /// Returns the derivation path whose output must be realized.
    pub const fn drv_path(&self) -> &'a [u8] {
        self.drv_path
    }

    /// Returns the requested output name for single-output contexts.
    pub const fn output_name(&self) -> Option<&'a [u8]> {
        self.output_name
    }

    /// Returns the string-context kind that caused the IFD demand.
    pub const fn context_kind(&self) -> ContextKind {
        self.context_kind
    }

    /// Returns the filesystem-reading builtin that triggered the demand.
    pub const fn op(&self) -> &'static str {
        self.op
    }

    /// Returns the dialect effect member for this realization boundary.
    pub const fn effect(&self) -> EffectClass {
        aos_nix_dialect::NIX_EFFECT_IFD
    }
}

/// A failure reported by an import-from-derivation realizer.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct IfdRealizationError {
    pub(crate) message: String,
}

impl IfdRealizationError {
    /// Creates a realization error from a user-facing message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the realizer failure message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Detailed context for an import-from-derivation evaluator error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IfdErrorDetail {
    pub(crate) path: Box<[u8]>,
    pub(crate) drv_path: Box<[u8]>,
    pub(crate) output_name: Option<Box<[u8]>>,
    pub(crate) context_kind: ContextKind,
    pub(crate) message: Option<String>,
}

impl IfdErrorDetail {
    pub(crate) fn new(
        path: Vec<u8>,
        drv_path: Vec<u8>,
        output_name: Option<Vec<u8>>,
        context_kind: ContextKind,
        message: Option<String>,
    ) -> Self {
        Self {
            path: path.into_boxed_slice(),
            drv_path: drv_path.into_boxed_slice(),
            output_name: output_name.map(Vec::into_boxed_slice),
            context_kind,
            message,
        }
    }

    /// Returns the filesystem path that triggered the IFD demand.
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    /// Returns the derivation path recorded in the string context.
    pub fn drv_path(&self) -> &[u8] {
        &self.drv_path
    }

    /// Returns the requested output name for single-output contexts.
    pub fn output_name(&self) -> Option<&[u8]> {
        self.output_name.as_deref()
    }

    /// Returns the context kind that caused the IFD demand.
    pub const fn context_kind(&self) -> ContextKind {
        self.context_kind
    }

    /// Returns the realizer diagnostic, if the realizer failed.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for IfdErrorDetail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "path {:?}, derivation {:?}, output {:?}, context {:?}",
            self.path,
            self.drv_path,
            self.output_name.as_deref(),
            self.context_kind
        )?;
        if let Some(message) = &self.message {
            write!(formatter, ": {message}")?;
        }
        Ok(())
    }
}

/// Callback used to realize derivation outputs at IFD boundaries.
#[derive(Clone)]
pub struct IfdRealizer {
    realize: Arc<IfdRealizerCallback>,
}

impl IfdRealizer {
    /// Creates an IFD realizer from a callback.
    pub fn new<F>(realize: F) -> Self
    where
        F: for<'a> Fn(IfdRealization<'a>) -> Result<(), IfdRealizationError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            realize: Arc::new(realize),
        }
    }

    pub(crate) fn realize(&self, request: IfdRealization<'_>) -> Result<(), IfdRealizationError> {
        (self.realize)(request)
    }
}

impl fmt::Debug for IfdRealizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IfdRealizer")
            .finish_non_exhaustive()
    }
}

/// User-facing warning output emitted by `builtins.warn`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalWarningOutput {
    pub(crate) message: Vec<u8>,
}

impl EvalWarningOutput {
    /// Creates a warning output record.
    pub(crate) fn new(message: Vec<u8>) -> Self {
        Self { message }
    }

    /// Returns the warning message bytes without the `evaluation warning: ` prefix.
    pub fn message(&self) -> &[u8] {
        &self.message
    }
}
