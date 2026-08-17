//! Heap-field and reference writeback apply/preflight reports and existing-destination commit reports.

use super::*;

/// A heap-field writeback matched to installed destination-byte snapshots.
///
/// The binding is validation metadata for a future object-field writer. It
/// proves that the rewritten field value points at an installed destination
/// payload, and for copied nursery fields also proves that the relocated
/// writeback object has an installed destination payload. It does not mutate
/// live object fields or bind bytes to heap-object storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding {
    allocation_domain: HeapAllocationDomain,
    validation_object: GcHeapAddress,
    writeback_object: GcHeapAddress,
    field_index: usize,
    source: HeapEdgeSource,
    replacement_destination: GcHeapAddress,
    replacement_generation: HeapGeneration,
    replacement_request: AllocationCollectorPollObjectByteCopyRequest,
    replacement_destination_bytes: Vec<u8>,
    writeback_object_request: Option<AllocationCollectorPollObjectByteCopyRequest>,
    writeback_object_destination_bytes: Option<Vec<u8>>,
}

impl EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding {
    pub(crate) fn new(
        allocation_domain: HeapAllocationDomain,
        validation_object: GcHeapAddress,
        writeback_object: GcHeapAddress,
        field_index: usize,
        source: HeapEdgeSource,
        replacement_destination: GcHeapAddress,
        replacement_generation: HeapGeneration,
        replacement_request: AllocationCollectorPollObjectByteCopyRequest,
        replacement_destination_bytes: Vec<u8>,
        writeback_object_request: Option<AllocationCollectorPollObjectByteCopyRequest>,
        writeback_object_destination_bytes: Option<Vec<u8>>,
    ) -> Self {
        Self {
            allocation_domain,
            validation_object,
            writeback_object,
            field_index,
            source,
            replacement_destination,
            replacement_generation,
            replacement_request,
            replacement_destination_bytes,
            writeback_object_request,
            writeback_object_destination_bytes,
        }
    }

    /// Returns the allocator domain assigned to the heap-field source.
    pub const fn allocation_domain(&self) -> HeapAllocationDomain {
        self.allocation_domain
    }

    /// Returns the object used to validate the copied field label.
    pub const fn validation_object(&self) -> GcHeapAddress {
        self.validation_object
    }

    /// Returns the object whose field would be rewritten.
    pub const fn writeback_object(&self) -> GcHeapAddress {
        self.writeback_object
    }

    /// Returns the field index in precise scanner order.
    pub const fn field_index(&self) -> usize {
        self.field_index
    }

    /// Returns the copied field source label.
    pub const fn source(&self) -> &HeapEdgeSource {
        &self.source
    }

    /// Returns the destination object address written into the field.
    pub const fn replacement_destination(&self) -> GcHeapAddress {
        self.replacement_destination
    }

    /// Returns the generation of the replacement destination object.
    pub const fn replacement_generation(&self) -> HeapGeneration {
        self.replacement_generation
    }

    /// Returns the object-copy request for the replacement destination payload.
    pub const fn replacement_request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.replacement_request
    }

    /// Returns the installed replacement destination payload bytes.
    pub fn replacement_destination_bytes(&self) -> &[u8] {
        &self.replacement_destination_bytes
    }

    /// Returns the copied writeback object's request, if the field targets one.
    pub const fn writeback_object_request(
        &self,
    ) -> Option<AllocationCollectorPollObjectByteCopyRequest> {
        self.writeback_object_request
    }

    /// Returns the copied writeback object's destination bytes, if installed.
    pub fn writeback_object_destination_bytes(&self) -> Option<&[u8]> {
        self.writeback_object_destination_bytes.as_deref()
    }
}

/// Counts for a live heap-field writeback write plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport {
    fields: usize,
    copied_replacements_to_nursery: usize,
    promoted_replacements_to_old: usize,
    replacement_payload_bytes: usize,
    writeback_object_payload_bytes: usize,
}

impl EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport {
    pub(crate) fn record(&mut self, write: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite) {
        self.fields = self.fields.saturating_add(1);
        self.replacement_payload_bytes = self
            .replacement_payload_bytes
            .saturating_add(write.replacement_destination_bytes().len());
        self.writeback_object_payload_bytes = self.writeback_object_payload_bytes.saturating_add(
            write
                .writeback_object_destination_bytes()
                .map_or(0, <[u8]>::len),
        );
        match write.replacement_request().action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_replacements_to_nursery =
                    self.copied_replacements_to_nursery.saturating_add(1);
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_replacements_to_old =
                    self.promoted_replacements_to_old.saturating_add(1);
            }
        }
    }

    /// Returns how many heap fields would receive relocated values.
    pub const fn fields(self) -> usize {
        self.fields
    }

    /// Returns how many planned field replacements point to next-nursery objects.
    pub const fn copied_replacements_to_nursery(self) -> usize {
        self.copied_replacements_to_nursery
    }

    /// Returns how many planned field replacements point to promoted old objects.
    pub const fn promoted_replacements_to_old(self) -> usize {
        self.promoted_replacements_to_old
    }

    /// Returns the total replacement payload bytes covered by the plan.
    pub const fn replacement_payload_bytes(self) -> usize {
        self.replacement_payload_bytes
    }

    /// Returns payload bytes for relocated writeback objects covered by the plan.
    pub const fn writeback_object_payload_bytes(self) -> usize {
        self.writeback_object_payload_bytes
    }
}

/// Counts for live object-body/generation writes and heap-field rewrites.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackReport {
    object_body_and_generation_write_report:
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    heap_field_writeback_report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
}

impl EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackReport {
    pub(crate) const fn new(
        object_body_and_generation_write_report:
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
        heap_field_writeback_report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
    ) -> Self {
        Self {
            object_body_and_generation_write_report,
            heap_field_writeback_report,
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

    /// Returns the heap-field writeback report.
    pub const fn heap_field_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport {
        self.heap_field_writeback_report
    }

    /// Returns how many heap fields were rewritten.
    pub const fn fields(self) -> usize {
        self.heap_field_writeback_report.fields()
    }
}

/// Counts for prevalidated live object and heap-field writebacks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackPreflightReport {
    object_body_and_generation_write_report:
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    heap_field_writeback_report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
}

impl EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackPreflightReport {
    pub(crate) const fn new(
        object_body_and_generation_write_report:
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
        heap_field_writeback_report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
    ) -> Self {
        Self {
            object_body_and_generation_write_report,
            heap_field_writeback_report,
        }
    }

    /// Returns the paired object-body and object-generation preflight report.
    pub const fn object_body_and_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.object_body_and_generation_write_report
    }

    /// Returns the destination object-body preflight report.
    pub const fn object_body_write_report(self) -> AllocationCollectorPollObjectBodyWriteReport {
        self.object_body_and_generation_write_report
            .body_write_report()
    }

    /// Returns how many destination object bodies were covered by the preflight.
    pub const fn object_body_preflight_objects(self) -> usize {
        self.object_body_write_report().objects()
    }

    /// Returns the destination object-generation preflight report.
    pub const fn object_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectGenerationWriteReport {
        self.object_body_and_generation_write_report
            .generation_write_report()
    }

    /// Returns how many destination object generations were covered by the preflight.
    pub const fn object_generation_preflight_objects(self) -> usize {
        self.object_generation_write_report().objects()
    }

    /// Returns the heap-field writeback plan report.
    pub const fn heap_field_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport {
        self.heap_field_writeback_report
    }

    /// Returns how many supported heap fields are covered by the preflight.
    pub const fn fields(self) -> usize {
        self.heap_field_writeback_report.fields()
    }
}

/// Counts for live object-body/generation writes plus supported reference rewrites.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveReferenceWritebackApplyReport {
    object_body_and_generation_write_report:
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    outcome_root_writeback_report: EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport,
    heap_field_writeback_report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
}

impl EvalGcStressBoundaryMinorGcLiveReferenceWritebackApplyReport {
    pub(crate) const fn new(
        object_body_and_generation_write_report:
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
        outcome_root_writeback_report: EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport,
        heap_field_writeback_report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
    ) -> Self {
        Self {
            object_body_and_generation_write_report,
            outcome_root_writeback_report,
            heap_field_writeback_report,
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

    /// Returns the heap-field writeback report.
    pub const fn heap_field_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport {
        self.heap_field_writeback_report
    }

    /// Returns how many heap fields were rewritten.
    pub const fn fields(self) -> usize {
        self.heap_field_writeback_report.fields()
    }

    /// Returns how many supported references were rewritten.
    pub const fn references(self) -> usize {
        self.roots().saturating_add(self.fields())
    }
}

/// Counts for prevalidated live object and reference writebacks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveReferenceWritebackPreflightReport {
    object_body_and_generation_write_report:
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    root_writeback_report: EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport,
    heap_field_writeback_report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
}

impl EvalGcStressBoundaryMinorGcLiveReferenceWritebackPreflightReport {
    pub(crate) const fn new(
        object_body_and_generation_write_report:
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
        root_writeback_report: EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport,
        heap_field_writeback_report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
    ) -> Self {
        Self {
            object_body_and_generation_write_report,
            root_writeback_report,
            heap_field_writeback_report,
        }
    }

    /// Returns the paired object-body and object-generation preflight report.
    pub const fn object_body_and_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.object_body_and_generation_write_report
    }

    /// Returns the destination object-body preflight report.
    pub const fn object_body_write_report(self) -> AllocationCollectorPollObjectBodyWriteReport {
        self.object_body_and_generation_write_report
            .body_write_report()
    }

    /// Returns how many destination object bodies were covered by the preflight.
    pub const fn object_body_preflight_objects(self) -> usize {
        self.object_body_write_report().objects()
    }

    /// Returns the destination object-generation preflight report.
    pub const fn object_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectGenerationWriteReport {
        self.object_body_and_generation_write_report
            .generation_write_report()
    }

    /// Returns how many destination object generations were covered by the preflight.
    pub const fn object_generation_preflight_objects(self) -> usize {
        self.object_generation_write_report().objects()
    }

    /// Returns the root writeback plan report.
    pub const fn root_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport {
        self.root_writeback_report
    }

    /// Returns how many supported roots are covered by the preflight.
    pub const fn roots(self) -> usize {
        self.root_writeback_report.roots()
    }

    /// Returns the heap-field writeback plan report.
    pub const fn heap_field_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport {
        self.heap_field_writeback_report
    }

    /// Returns how many supported heap fields are covered by the preflight.
    pub const fn fields(self) -> usize {
        self.heap_field_writeback_report.fields()
    }

    /// Returns how many supported references are covered by the preflight.
    pub const fn references(self) -> usize {
        self.roots().saturating_add(self.fields())
    }
}

/// Counts for a read-only existing-destination live commit preflight.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitPreflightReport {
    forwarding_header_write_plan_report: EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport,
    reference_writeback_preflight_report:
        EvalGcStressBoundaryMinorGcLiveReferenceWritebackPreflightReport,
}

impl EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitPreflightReport {
    pub(crate) const fn new(
        forwarding_header_write_plan_report:
            EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport,
        reference_writeback_preflight_report:
            EvalGcStressBoundaryMinorGcLiveReferenceWritebackPreflightReport,
    ) -> Self {
        Self {
            forwarding_header_write_plan_report,
            reference_writeback_preflight_report,
        }
    }

    /// Returns the forwarding-header write-plan report.
    pub const fn forwarding_header_write_plan_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport {
        self.forwarding_header_write_plan_report
    }

    /// Returns how many forwarding headers are covered by the preflight.
    pub const fn forwarding_headers(self) -> usize {
        self.forwarding_header_write_plan_report.headers()
    }

    /// Returns how many forwarding headers point to next-nursery objects.
    pub const fn forwarding_headers_copied_to_nursery(self) -> usize {
        self.forwarding_header_write_plan_report.copied_to_nursery()
    }

    /// Returns how many forwarding headers point to promoted old objects.
    pub const fn forwarding_headers_promoted_to_old(self) -> usize {
        self.forwarding_header_write_plan_report.promoted_to_old()
    }

    /// Returns the payload bytes covered by forwarding-header metadata.
    pub const fn forwarding_header_payload_bytes(self) -> usize {
        self.forwarding_header_write_plan_report.payload_bytes()
    }

    /// Returns the live reference writeback preflight report.
    pub const fn reference_writeback_preflight_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebackPreflightReport {
        self.reference_writeback_preflight_report
    }

    /// Returns the paired object-body and object-generation preflight report.
    pub const fn object_body_and_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.reference_writeback_preflight_report
            .object_body_and_generation_write_report()
    }

    /// Returns how many destination object bodies were covered by the preflight.
    pub const fn object_body_preflight_objects(self) -> usize {
        self.reference_writeback_preflight_report
            .object_body_preflight_objects()
    }

    /// Returns how many destination object generations were covered by the preflight.
    pub const fn object_generation_preflight_objects(self) -> usize {
        self.reference_writeback_preflight_report
            .object_generation_preflight_objects()
    }

    /// Returns how many supported roots are covered by the preflight.
    pub const fn roots(self) -> usize {
        self.reference_writeback_preflight_report.roots()
    }

    /// Returns how many supported heap fields are covered by the preflight.
    pub const fn fields(self) -> usize {
        self.reference_writeback_preflight_report.fields()
    }

    /// Returns how many supported references are covered by the preflight.
    pub const fn references(self) -> usize {
        self.reference_writeback_preflight_report.references()
    }
}

/// Counts for validated forwarding metadata plus committed live reference writes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitApplyReport {
    forwarding_header_write_plan_report: EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport,
    reference_writeback_apply_report: EvalGcStressBoundaryMinorGcLiveReferenceWritebackApplyReport,
    remembered_set_published_edges: usize,
    card_table_clear_report: GcCardTableClearReport,
}

impl EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitApplyReport {
    pub(crate) const fn new(
        forwarding_header_write_plan_report:
            EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport,
        reference_writeback_apply_report:
            EvalGcStressBoundaryMinorGcLiveReferenceWritebackApplyReport,
        remembered_set_published_edges: usize,
        card_table_clear_report: GcCardTableClearReport,
    ) -> Self {
        Self {
            forwarding_header_write_plan_report,
            reference_writeback_apply_report,
            remembered_set_published_edges,
            card_table_clear_report,
        }
    }

    /// Returns the forwarding-header write-plan report that was validated.
    pub const fn forwarding_header_write_plan_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport {
        self.forwarding_header_write_plan_report
    }

    /// Returns how many forwarding headers were validated.
    pub const fn forwarding_headers_validated(self) -> usize {
        self.forwarding_header_write_plan_report.headers()
    }

    /// Returns how many validated forwarding headers point to next-nursery objects.
    pub const fn forwarding_headers_copied_to_nursery(self) -> usize {
        self.forwarding_header_write_plan_report.copied_to_nursery()
    }

    /// Returns how many validated forwarding headers point to promoted old objects.
    pub const fn forwarding_headers_promoted_to_old(self) -> usize {
        self.forwarding_header_write_plan_report.promoted_to_old()
    }

    /// Returns the payload bytes covered by validated forwarding-header metadata.
    pub const fn forwarding_header_payload_bytes(self) -> usize {
        self.forwarding_header_write_plan_report.payload_bytes()
    }

    /// Returns the live reference writeback apply report.
    pub const fn reference_writeback_apply_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebackApplyReport {
        self.reference_writeback_apply_report
    }

    /// Returns the paired object-body and object-generation write report.
    pub const fn object_body_and_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.reference_writeback_apply_report
            .object_body_and_generation_write_report()
    }

    /// Returns the destination object-body write report.
    pub const fn object_body_write_report(self) -> AllocationCollectorPollObjectBodyWriteReport {
        self.reference_writeback_apply_report
            .object_body_write_report()
    }

    /// Returns how many destination object bodies were written.
    pub const fn object_bodies_written(self) -> usize {
        self.reference_writeback_apply_report
            .object_bodies_written()
    }

    /// Returns the destination object-generation write report.
    pub const fn object_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectGenerationWriteReport {
        self.reference_writeback_apply_report
            .object_generation_write_report()
    }

    /// Returns how many destination object generations were written.
    pub const fn object_generations_written(self) -> usize {
        self.reference_writeback_apply_report
            .object_generations_written()
    }

    /// Returns the outcome-root writeback report.
    pub const fn outcome_root_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport {
        self.reference_writeback_apply_report
            .outcome_root_writeback_report()
    }

    /// Returns how many outcome-owned value-stack roots were rewritten.
    pub const fn value_stack_roots(self) -> usize {
        self.reference_writeback_apply_report.value_stack_roots()
    }

    /// Returns how many outcome-owned roots were rewritten.
    pub const fn roots(self) -> usize {
        self.reference_writeback_apply_report.roots()
    }

    /// Returns the heap-field writeback report.
    pub const fn heap_field_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport {
        self.reference_writeback_apply_report
            .heap_field_writeback_report()
    }

    /// Returns how many heap fields were rewritten.
    pub const fn fields(self) -> usize {
        self.reference_writeback_apply_report.fields()
    }

    /// Returns how many supported references were rewritten.
    pub const fn references(self) -> usize {
        self.reference_writeback_apply_report.references()
    }

    /// Returns the number of remembered edges kept published for the next epoch.
    pub const fn remembered_set_published_edges(self) -> usize {
        self.remembered_set_published_edges
    }

    /// Returns the report for the post-reference live card-table clear.
    pub const fn card_table_clear_report(self) -> GcCardTableClearReport {
        self.card_table_clear_report
    }

    /// Returns how many dirty-card markers were cleared from live outcome state.
    pub const fn card_table_dirty_cards_cleared(self) -> usize {
        self.card_table_clear_report.dirty_cards()
    }
}
