//! Existing-destination live commit, heap-field writeback write/plan, and commit-application types.

use super::*;

/// Result of running the existing-destination live commit bridge end to end.
///
/// This report keeps the strict existing-destination metadata installation next
/// to the subsequent live reference commit. The operation is still a
/// tree-walk/GC-stress bridge: it requires destination records that already
/// exist in the evaluator heap, and it does not allocate synthetic destinations,
/// reserve semispace storage, write ABI forwarding headers, mutate active
/// evaluator frames or import caches, update JIT stack maps, or invoke Tier B.
/// The report is returned only when both phases complete; it does not represent
/// a rollback token for metadata installed before a later commit error.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcExistingDestinationLiveCommit {
    live_metadata: EvalGcStressBoundaryMinorGcExistingDestinationLiveMetadataCommitDryRun,
    live_commit: EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitApplyReport,
}

impl EvalGcStressBoundaryMinorGcExistingDestinationLiveCommit {
    pub(crate) const fn new(
        live_metadata: EvalGcStressBoundaryMinorGcExistingDestinationLiveMetadataCommitDryRun,
        live_commit: EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitApplyReport,
    ) -> Self {
        Self {
            live_metadata,
            live_commit,
        }
    }

    /// Returns the strict existing-destination metadata installation report.
    pub const fn live_metadata(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcExistingDestinationLiveMetadataCommitDryRun {
        &self.live_metadata
    }

    /// Returns the applied live reference commit report.
    pub const fn live_commit(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitApplyReport {
        self.live_commit
    }

    /// Returns how many forwarding values were installed by the metadata phase.
    pub const fn forwarding_pointers_installed(&self) -> usize {
        self.live_metadata
            .live_metadata()
            .forwarding_pointers_installed()
    }

    /// Returns how many destination object bodies were written by the commit phase.
    pub const fn object_bodies_written(&self) -> usize {
        self.live_commit.object_bodies_written()
    }

    /// Returns how many destination object generations were written by the commit phase.
    pub const fn object_generations_written(&self) -> usize {
        self.live_commit.object_generations_written()
    }

    /// Returns how many outcome-owned value-stack roots were rewritten.
    pub const fn value_stack_roots(&self) -> usize {
        self.live_commit.value_stack_roots()
    }

    /// Returns how many live heap fields were rewritten.
    pub const fn fields(&self) -> usize {
        self.live_commit.fields()
    }

    /// Returns how many supported references were rewritten.
    pub const fn references(&self) -> usize {
        self.live_commit.references()
    }

    /// Returns how many dirty-card markers were cleared after live field writes.
    pub const fn card_table_dirty_cards_cleared(&self) -> usize {
        self.live_commit.card_table_dirty_cards_cleared()
    }
}

/// One validated live heap-field writeback input.
///
/// This is an immutable write plan for a future object-field writer. It proves
/// that an installed heap-field writeback slot still matches an installed field
/// destination binding, including replacement destination bytes and, when the
/// field belongs to a copied nursery survivor, the relocated writeback object's
/// destination bytes. It does not mutate evaluator object fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite {
    pub(crate) allocation_domain: HeapAllocationDomain,
    pub(crate) validation_object: GcHeapAddress,
    pub(crate) writeback_object: GcHeapAddress,
    pub(crate) field_index: usize,
    pub(crate) source: HeapEdgeSource,
    pub(crate) replacement_destination: GcHeapAddress,
    pub(crate) replacement_generation: HeapGeneration,
    pub(crate) replacement_metadata: ResolvedValueGeneration,
    pub(crate) replacement_request: AllocationCollectorPollObjectByteCopyRequest,
    pub(crate) replacement_destination_bytes: Vec<u8>,
    pub(crate) writeback_object_request: Option<AllocationCollectorPollObjectByteCopyRequest>,
    pub(crate) writeback_object_destination_bytes: Option<Vec<u8>>,
}

impl EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite {
    pub(crate) fn from_source_and_binding(
        source: BoundaryMinorGcHeapFieldWritebackWriteSource,
        binding: &EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
    ) -> Result<Self, EvalHeapError> {
        Ok(Self {
            allocation_domain: source.allocation_domain,
            validation_object: source.validation_object,
            writeback_object: source.writeback_object,
            field_index: source.field_index,
            source: source.source,
            replacement_destination: source.replacement_destination,
            replacement_generation: source.replacement_generation,
            replacement_metadata: source.replacement_metadata,
            replacement_request: binding.replacement_request(),
            replacement_destination_bytes: clone_boundary_destination_storage_bytes(
                BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITE_BYTES_TABLE,
                binding.replacement_destination_bytes(),
            )?,
            writeback_object_request: binding.writeback_object_request(),
            writeback_object_destination_bytes: binding
                .writeback_object_destination_bytes()
                .map(|bytes| {
                    clone_boundary_destination_storage_bytes(
                        BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITE_BYTES_TABLE,
                        bytes,
                    )
                })
                .transpose()?,
        })
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

    /// Returns the generation-style replacement metadata paired with the field.
    pub const fn replacement_metadata(&self) -> ResolvedValueGeneration {
        self.replacement_metadata
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

/// A validated live heap-field writeback write plan.
///
/// The plan is derived from installed live reference-writeback metadata and
/// installed writeback-destination bindings. It is a checked input set for a
/// live heap-field bridge or future broader live object-field writer; creating
/// it does not write fields, copy object bodies, or bind destination bytes to
/// heap storage.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan {
    report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
    writes: Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite>,
}

impl EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan {
    pub(crate) fn new(writes: Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite>) -> Self {
        let mut report = EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport::default();
        for write in &writes {
            report.record(write);
        }
        Self { report, writes }
    }

    /// Returns whether this plan has no heap-field writes.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// Returns how many heap-field writes are planned.
    pub fn len(&self) -> usize {
        self.writes.len()
    }

    /// Returns aggregate counts for the plan.
    pub const fn report(&self) -> EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport {
        self.report
    }

    /// Returns the planned live heap-field writes.
    pub fn writes(&self) -> &[EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite] {
        &self.writes
    }
}

/// Applied boundary-owned buffers for one minor-GC commit preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcCommitApplication {
    report: MinorGcCommitReport,
    object_byte_copies: Vec<EvalGcStressBoundaryMinorGcObjectByteCopyApplication>,
    destination_storage: EvalGcStressBoundaryMinorGcDestinationStorageApplication,
    forwarding_slots: Vec<MinorGcForwardingSlot>,
    references: Vec<ResolvedValueGeneration>,
    remembered_set: RememberedSet,
    card_table: GcCardTable,
}

impl EvalGcStressBoundaryMinorGcCommitApplication {
    pub(crate) fn new(
        report: MinorGcCommitReport,
        object_byte_copies: Vec<EvalGcStressBoundaryMinorGcObjectByteCopyApplication>,
        destination_storage: EvalGcStressBoundaryMinorGcDestinationStorageApplication,
        forwarding_slots: Vec<MinorGcForwardingSlot>,
        references: Vec<ResolvedValueGeneration>,
        remembered_set: RememberedSet,
        card_table: GcCardTable,
    ) -> Self {
        Self {
            report,
            object_byte_copies,
            destination_storage,
            forwarding_slots,
            references,
            remembered_set,
            card_table,
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

    /// Returns the owned destination storage snapshot after object-byte copying.
    pub const fn destination_storage(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcDestinationStorageApplication {
        &self.destination_storage
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

    /// Returns the owned daemon card-table copy after commit application.
    ///
    /// The table is a dry-run clone of the outcome's daemon-wide card table,
    /// not tier-partitioned live card-table state.
    pub const fn card_table(&self) -> &GcCardTable {
        &self.card_table
    }
}

/// Boundary-owned storage application for one minor-GC commit preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcOwnedStorageCommitApplication {
    report: MinorGcCommitReport,
    destination_storage: EvalGcStressBoundaryMinorGcDestinationStorageApplication,
    forwarding_slots: Vec<MinorGcForwardingSlot>,
    references: Vec<ResolvedValueGeneration>,
    remembered_set: RememberedSet,
    card_table: GcCardTable,
}

impl EvalGcStressBoundaryMinorGcOwnedStorageCommitApplication {
    pub(crate) fn new(
        report: MinorGcCommitReport,
        destination_storage: EvalGcStressBoundaryMinorGcDestinationStorageApplication,
        forwarding_slots: Vec<MinorGcForwardingSlot>,
        references: Vec<ResolvedValueGeneration>,
        remembered_set: RememberedSet,
        card_table: GcCardTable,
    ) -> Self {
        Self {
            report,
            destination_storage,
            forwarding_slots,
            references,
            remembered_set,
            card_table,
        }
    }

    /// Returns the lower-level commit counts for the owned-storage application.
    pub const fn report(&self) -> MinorGcCommitReport {
        self.report
    }

    /// Returns the owned destination storage snapshot after commit application.
    pub const fn destination_storage(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcDestinationStorageApplication {
        &self.destination_storage
    }

    /// Returns forwarding slots after commit application.
    pub fn forwarding_slots(&self) -> &[MinorGcForwardingSlot] {
        &self.forwarding_slots
    }

    /// Returns copied reference values after commit application.
    pub fn references(&self) -> &[ResolvedValueGeneration] {
        &self.references
    }

    /// Returns the remembered set after publication into the owned buffer.
    pub const fn remembered_set(&self) -> &RememberedSet {
        &self.remembered_set
    }

    /// Returns the owned daemon card-table copy after commit application.
    pub const fn card_table(&self) -> &GcCardTable {
        &self.card_table
    }
}
