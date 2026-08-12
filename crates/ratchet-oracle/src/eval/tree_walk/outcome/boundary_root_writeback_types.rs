//! Root-writeback destination-binding, write-plan, and outcome-report types.

use super::*;

/// A root writeback matched to an installed destination-byte snapshot.
///
/// The binding is validation metadata for a future live root writer. It proves
/// that an outcome-owned typed root replacement and its generation-style slot
/// point at an installed destination payload, but it is not a live root slot and
/// does not bind bytes to heap-object storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding {
    allocation_domain: HeapAllocationDomain,
    root_source: EvalRootSource,
    replacement_tag: ValueTag,
    destination: GcHeapAddress,
    generation: HeapGeneration,
    request: AllocationCollectorPollObjectByteCopyRequest,
    destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding {
    pub(crate) fn new(
        allocation_domain: HeapAllocationDomain,
        root_source: EvalRootSource,
        replacement_tag: ValueTag,
        destination: GcHeapAddress,
        generation: HeapGeneration,
        request: AllocationCollectorPollObjectByteCopyRequest,
        destination_bytes: Vec<u8>,
    ) -> Self {
        Self {
            allocation_domain,
            root_source,
            replacement_tag,
            destination,
            generation,
            request,
            destination_bytes,
        }
    }

    /// Returns the allocator domain assigned to this root writeback.
    pub const fn allocation_domain(&self) -> HeapAllocationDomain {
        self.allocation_domain
    }

    /// Returns the copied root source that would be rewritten.
    pub const fn root_source(&self) -> &EvalRootSource {
        &self.root_source
    }

    /// Returns the heap tag needed to rebuild the typed replacement value.
    pub const fn replacement_tag(&self) -> ValueTag {
        self.replacement_tag
    }

    /// Returns the destination object address for the replacement value.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns the generation of the destination object.
    pub const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    /// Returns the object-copy request that installed the destination payload.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }

    /// Returns the installed destination payload bytes matched to the root.
    pub fn destination_bytes(&self) -> &[u8] {
        &self.destination_bytes
    }
}

/// Counts for a live root-writeback write plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport {
    roots: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    payload_bytes: usize,
}

impl EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport {
    pub(crate) fn record(&mut self, write: &EvalGcStressBoundaryMinorGcRootWritebackWrite) {
        self.roots = self.roots.saturating_add(1);
        self.payload_bytes = self
            .payload_bytes
            .saturating_add(write.destination_bytes().len());
        match write.request().action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_to_nursery = self.copied_to_nursery.saturating_add(1);
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_to_old = self.promoted_to_old.saturating_add(1);
            }
        }
    }

    /// Returns how many evaluator roots would receive relocated values.
    pub const fn roots(self) -> usize {
        self.roots
    }

    /// Returns how many planned root writes point to next-nursery objects.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns how many planned root writes point to promoted old objects.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }

    /// Returns the total destination payload bytes covered by the plan.
    pub const fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
}

/// One validated live root-writeback input.
///
/// This is an immutable write plan for a future root writer. It proves that an
/// installed root writeback slot still matches an installed root destination
/// binding and carries both the typed replacement [`Value`] and
/// generation-style metadata needed by the eventual writer. It does not mutate
/// evaluator roots.
#[derive(Clone, Debug)]
pub struct EvalGcStressBoundaryMinorGcRootWritebackWrite {
    pub(crate) allocation_domain: HeapAllocationDomain,
    pub(crate) root_source: EvalRootSource,
    pub(crate) replacement_tag: ValueTag,
    pub(crate) replacement_value: Value,
    pub(crate) destination: GcHeapAddress,
    pub(crate) generation: HeapGeneration,
    pub(crate) replacement_metadata: ResolvedValueGeneration,
    pub(crate) request: AllocationCollectorPollObjectByteCopyRequest,
    pub(crate) destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcRootWritebackWrite {
    pub(crate) fn from_source_and_binding(
        source: BoundaryMinorGcRootWritebackWriteSource,
        binding: &EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding,
    ) -> Result<Self, EvalHeapError> {
        Ok(Self {
            allocation_domain: source.allocation_domain,
            root_source: source.root_source,
            replacement_tag: source.replacement_tag,
            replacement_value: source.replacement_value,
            destination: source.destination,
            generation: source.generation,
            replacement_metadata: source.replacement_metadata,
            request: binding.request(),
            destination_bytes: clone_boundary_destination_storage_bytes(
                BOUNDARY_MINOR_GC_ROOT_WRITEBACK_WRITE_BYTES_TABLE,
                binding.destination_bytes(),
            )?,
        })
    }

    /// Returns the allocator domain assigned to this root writeback.
    pub const fn allocation_domain(&self) -> HeapAllocationDomain {
        self.allocation_domain
    }

    /// Returns the copied root source that would be rewritten.
    pub const fn root_source(&self) -> &EvalRootSource {
        &self.root_source
    }

    /// Returns the heap tag carried by the typed replacement value.
    pub const fn replacement_tag(&self) -> ValueTag {
        self.replacement_tag
    }

    /// Returns the typed evaluator value that would be written to the root.
    pub const fn replacement_value(&self) -> Value {
        self.replacement_value
    }

    /// Returns the destination object address for the replacement value.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns the generation of the destination object.
    pub const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    /// Returns the generation-style replacement metadata paired with the root.
    pub const fn replacement_metadata(&self) -> ResolvedValueGeneration {
        self.replacement_metadata
    }

    /// Returns the object-copy request that installed the destination payload.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }

    /// Returns the installed destination payload bytes covered by this write.
    pub fn destination_bytes(&self) -> &[u8] {
        &self.destination_bytes
    }
}

impl PartialEq for EvalGcStressBoundaryMinorGcRootWritebackWrite {
    fn eq(&self, other: &Self) -> bool {
        self.allocation_domain == other.allocation_domain
            && self.root_source == other.root_source
            && self.replacement_tag == other.replacement_tag
            && self.replacement_value.raw_eq(other.replacement_value)
            && self.destination == other.destination
            && self.generation == other.generation
            && self.replacement_metadata == other.replacement_metadata
            && self.request == other.request
            && self.destination_bytes == other.destination_bytes
    }
}

impl Eq for EvalGcStressBoundaryMinorGcRootWritebackWrite {}

/// A validated live root-writeback write plan.
///
/// The plan is derived from installed live reference-writeback metadata and
/// installed writeback-destination bindings. It is a checked input set for a
/// future live root writer; creating it does not write roots, copy object
/// bodies, or bind destination bytes to heap storage.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcRootWritebackWritePlan {
    report: EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport,
    writes: Vec<EvalGcStressBoundaryMinorGcRootWritebackWrite>,
}

impl EvalGcStressBoundaryMinorGcRootWritebackWritePlan {
    pub(crate) fn new(writes: Vec<EvalGcStressBoundaryMinorGcRootWritebackWrite>) -> Self {
        let mut report = EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport::default();
        for write in &writes {
            report.record(write);
        }
        Self { report, writes }
    }

    /// Returns whether this plan has no root writes.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// Returns how many root writes are planned.
    pub fn len(&self) -> usize {
        self.writes.len()
    }

    /// Returns aggregate counts for the plan.
    pub const fn report(&self) -> EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport {
        self.report
    }

    /// Returns the planned live root writes.
    pub fn writes(&self) -> &[EvalGcStressBoundaryMinorGcRootWritebackWrite] {
        &self.writes
    }
}

/// Counts for outcome-owned root slots rewritten by a boundary minor-GC plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport {
    value_stack_roots: usize,
}

impl EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport {
    pub(crate) const fn new(value_stack_roots: usize) -> Self {
        Self { value_stack_roots }
    }

    /// Returns how many outcome-owned value-stack roots were rewritten.
    pub const fn value_stack_roots(self) -> usize {
        self.value_stack_roots
    }

    /// Returns the total number of outcome-owned roots rewritten.
    pub const fn roots(self) -> usize {
        self.value_stack_roots
    }
}

/// Counts for live object-body writes and outcome-owned root rewrites.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveOutcomeRootWritebackReport {
    object_body_and_generation_write_report:
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    outcome_root_writeback_report: EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport,
}

impl EvalGcStressBoundaryMinorGcLiveOutcomeRootWritebackReport {
    pub(crate) const fn new(
        object_body_and_generation_write_report:
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
        outcome_root_writeback_report: EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport,
    ) -> Self {
        Self {
            object_body_and_generation_write_report,
            outcome_root_writeback_report,
        }
    }

    /// Returns the paired object-body and object-generation write report.
    pub const fn object_body_and_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.object_body_and_generation_write_report
    }

    /// Returns the destination object-body write report.
    pub const fn object_body_write_report(self) -> AllocationCollectorPollObjectBodyWriteReport {
        self.object_body_and_generation_write_report
            .body_write_report()
    }

    /// Returns how many destination object bodies were written.
    pub const fn object_bodies_written(self) -> usize {
        self.object_body_write_report().objects()
    }

    /// Returns the destination object-generation write report.
    pub const fn object_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectGenerationWriteReport {
        self.object_body_and_generation_write_report
            .generation_write_report()
    }

    /// Returns how many destination object generations were written.
    pub const fn object_generations_written(self) -> usize {
        self.object_generation_write_report().objects()
    }

    /// Returns the outcome-root writeback report.
    pub const fn outcome_root_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport {
        self.outcome_root_writeback_report
    }

    /// Returns how many outcome-owned value-stack roots were rewritten.
    pub const fn value_stack_roots(self) -> usize {
        self.outcome_root_writeback_report.value_stack_roots()
    }

    /// Returns how many outcome-owned roots were rewritten.
    pub const fn roots(self) -> usize {
        self.outcome_root_writeback_report.roots()
    }
}
