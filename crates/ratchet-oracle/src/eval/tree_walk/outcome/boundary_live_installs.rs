//! Live destination-storage, object-generation, and forwarding destination-binding install types.

use super::*;

/// Applied owned destination storage for one boundary minor-GC preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcDestinationStorageApplication {
    copy_report: MinorGcOwnedDestinationStorageCopyReport,
    nursery_reserved_bytes: usize,
    old_reserved_bytes: usize,
    nursery_destination_bytes: Vec<u8>,
    old_destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcDestinationStorageApplication {
    pub(crate) fn new(
        copy_report: MinorGcOwnedDestinationStorageCopyReport,
        nursery_reserved_bytes: usize,
        old_reserved_bytes: usize,
        nursery_destination_bytes: Vec<u8>,
        old_destination_bytes: Vec<u8>,
    ) -> Self {
        Self {
            copy_report,
            nursery_reserved_bytes,
            old_reserved_bytes,
            nursery_destination_bytes,
            old_destination_bytes,
        }
    }

    /// Returns the owned destination-storage copy report.
    pub const fn copy_report(&self) -> MinorGcOwnedDestinationStorageCopyReport {
        self.copy_report
    }

    /// Returns bytes reserved for copied next-nursery destinations.
    pub const fn nursery_reserved_bytes(&self) -> usize {
        self.nursery_reserved_bytes
    }

    /// Returns bytes reserved for promoted old-generation destinations.
    pub const fn old_reserved_bytes(&self) -> usize {
        self.old_reserved_bytes
    }

    /// Returns the owned next-nursery destination bytes after copying.
    pub fn nursery_destination_bytes(&self) -> &[u8] {
        &self.nursery_destination_bytes
    }

    /// Returns the owned old-generation destination bytes after copying.
    pub fn old_destination_bytes(&self) -> &[u8] {
        &self.old_destination_bytes
    }
}

/// Outcome-owned destination-byte installation counts for a boundary dry run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport {
    object_copies: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    nursery_payload_bytes: usize,
    old_payload_bytes: usize,
}

impl EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport {
    pub(crate) fn record(&mut self, request: AllocationCollectorPollObjectByteCopyRequest) {
        self.object_copies = self.object_copies.saturating_add(1);
        match request.action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_to_nursery = self.copied_to_nursery.saturating_add(1);
                self.nursery_payload_bytes = self
                    .nursery_payload_bytes
                    .saturating_add(request.size_bytes());
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_to_old = self.promoted_to_old.saturating_add(1);
                self.old_payload_bytes =
                    self.old_payload_bytes.saturating_add(request.size_bytes());
            }
        }
    }

    /// Returns how many destination object payloads were installed.
    pub const fn object_copies(self) -> usize {
        self.object_copies
    }

    /// Returns how many installed payloads target next-nursery storage.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns how many installed payloads target old-generation storage.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }

    /// Returns installed next-nursery payload bytes.
    pub const fn nursery_payload_bytes(self) -> usize {
        self.nursery_payload_bytes
    }

    /// Returns installed old-generation payload bytes.
    pub const fn old_payload_bytes(self) -> usize {
        self.old_payload_bytes
    }

    /// Returns total installed object payload bytes.
    pub const fn payload_bytes(self) -> usize {
        self.nursery_payload_bytes
            .saturating_add(self.old_payload_bytes)
    }
}

/// Outcome-owned byte snapshot for one relocated minor-GC object payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes {
    request: AllocationCollectorPollObjectByteCopyRequest,
    destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes {
    pub(crate) fn new(
        request: AllocationCollectorPollObjectByteCopyRequest,
        destination_bytes: Vec<u8>,
    ) -> Self {
        Self {
            request,
            destination_bytes,
        }
    }

    /// Returns the byte-copy request that produced this installed snapshot.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }

    /// Returns the from-space source object address.
    pub const fn source(&self) -> GcHeapAddress {
        self.request.source()
    }

    /// Returns the destination object address represented by this snapshot.
    pub const fn destination(&self) -> GcHeapAddress {
        self.request.destination()
    }

    /// Returns the copied payload bytes for the destination object.
    pub fn destination_bytes(&self) -> &[u8] {
        &self.destination_bytes
    }
}

/// Outcome-owned destination-byte snapshots installed by a boundary dry run.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveDestinationStorage {
    pub(crate) install_report: EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport,
    pub(crate) object_bytes: Vec<EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes>,
}

impl EvalGcStressBoundaryMinorGcLiveDestinationStorage {
    pub(crate) fn can_install(
        &self,
        install_report: EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport,
    ) -> Result<(), EvalHeapError> {
        if install_report.object_copies() != 0 && !self.object_bytes.is_empty() {
            return Err(
                EvalHeapError::BoundaryMinorGcLiveDestinationStorageAlreadyInstalled {
                    existing: self.object_bytes.len(),
                },
            );
        }
        Ok(())
    }

    pub(crate) fn install(
        &mut self,
        object_bytes: Vec<EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes>,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport, EvalHeapError> {
        if object_bytes.is_empty() {
            return Ok(EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport::default());
        }
        let install_report = live_destination_storage_install_report(&object_bytes);
        self.can_install(install_report)?;
        validate_boundary_minor_gc_destination_generation_objects(&object_bytes)?;
        self.object_bytes = object_bytes;
        self.install_report = install_report;
        Ok(install_report)
    }

    pub(crate) fn install_prevalidated(
        &mut self,
        object_bytes: Vec<EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes>,
        install_report: EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport,
    ) {
        if install_report.object_copies() == 0 {
            return;
        }

        self.object_bytes = object_bytes;
        self.install_report = install_report;
    }

    /// Returns whether no destination byte snapshots are installed.
    pub fn is_empty(&self) -> bool {
        self.object_bytes.is_empty()
    }

    /// Returns how many destination object byte snapshots are installed.
    pub fn len(&self) -> usize {
        self.object_bytes.len()
    }

    /// Returns the report for the last non-empty destination-byte install.
    pub const fn install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport {
        self.install_report
    }

    /// Returns the installed destination object byte snapshots.
    pub fn object_bytes(&self) -> &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes] {
        &self.object_bytes
    }
}

/// Outcome-owned object-generation installation counts for a boundary dry run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport {
    objects: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
}

impl EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport {
    pub(crate) fn record(&mut self, generation: &EvalGcStressBoundaryMinorGcLiveObjectGeneration) {
        self.objects = self.objects.saturating_add(1);
        match generation.action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_to_nursery = self.copied_to_nursery.saturating_add(1);
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_to_old = self.promoted_to_old.saturating_add(1);
            }
        }
    }

    /// Returns how many object-generation records were installed.
    pub const fn objects(self) -> usize {
        self.objects
    }

    /// Returns how many installed records target next-nursery generation.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns how many installed records target old generation.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }
}

/// Outcome-owned generation metadata for one relocated minor-GC object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveObjectGeneration {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    action: MinorGcSurvivorAction,
    generation: HeapGeneration,
    request: AllocationCollectorPollObjectByteCopyRequest,
}

impl EvalGcStressBoundaryMinorGcLiveObjectGeneration {
    pub(crate) const fn new(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        action: MinorGcSurvivorAction,
        generation: HeapGeneration,
        request: AllocationCollectorPollObjectByteCopyRequest,
    ) -> Self {
        Self {
            source,
            destination,
            action,
            generation,
            request,
        }
    }

    /// Returns the from-space survivor source object.
    pub const fn source(&self) -> GcHeapAddress {
        self.source
    }

    /// Returns the destination object address.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns whether this destination keeps the object young or promotes it.
    pub const fn action(&self) -> MinorGcSurvivorAction {
        self.action
    }

    /// Returns the generation that owns the destination object in this metadata.
    pub const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    /// Returns the object-copy request that produced this generation metadata.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }
}

/// Outcome-owned object-generation metadata installed by a boundary dry run.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveObjectGenerations {
    pub(crate) install_report: EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport,
    pub(crate) object_generations: Vec<EvalGcStressBoundaryMinorGcLiveObjectGeneration>,
}

impl EvalGcStressBoundaryMinorGcLiveObjectGenerations {
    pub(crate) fn can_install(
        &self,
        install_report: EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport,
    ) -> Result<(), EvalHeapError> {
        if install_report.objects() != 0 && !self.object_generations.is_empty() {
            return Err(
                EvalHeapError::BoundaryMinorGcLiveObjectGenerationsAlreadyInstalled {
                    existing: self.object_generations.len(),
                },
            );
        }
        Ok(())
    }

    pub(crate) fn install(
        &mut self,
        object_generations: Vec<EvalGcStressBoundaryMinorGcLiveObjectGeneration>,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport, EvalHeapError> {
        if object_generations.is_empty() {
            return Ok(EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport::default());
        }
        let install_report = live_object_generation_install_report(&object_generations);
        self.can_install(install_report)?;
        self.install_prevalidated(object_generations, install_report);
        Ok(install_report)
    }

    pub(crate) fn install_prevalidated(
        &mut self,
        object_generations: Vec<EvalGcStressBoundaryMinorGcLiveObjectGeneration>,
        install_report: EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport,
    ) {
        if install_report.objects() == 0 {
            return;
        }

        self.object_generations = object_generations;
        self.install_report = install_report;
    }

    /// Returns whether no object-generation metadata is installed.
    pub fn is_empty(&self) -> bool {
        self.object_generations.is_empty()
    }

    /// Returns how many object-generation records are installed.
    pub fn len(&self) -> usize {
        self.object_generations.len()
    }

    /// Returns the report for the last non-empty object-generation install.
    pub const fn install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport {
        self.install_report
    }

    /// Returns the installed object-generation metadata records.
    pub fn object_generations(&self) -> &[EvalGcStressBoundaryMinorGcLiveObjectGeneration] {
        &self.object_generations
    }
}

/// Outcome-owned forwarding destination-binding installation counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport {
    bindings: usize,
}

impl EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport {
    pub(crate) const fn new(bindings: usize) -> Self {
        Self { bindings }
    }

    /// Returns how many forwarding destination bindings were installed.
    pub const fn bindings(self) -> usize {
        self.bindings
    }
}

/// Outcome-owned forwarding-to-destination binding metadata.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings {
    install_report: EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport,
    forwarding_destination_bindings: Vec<EvalGcStressBoundaryMinorGcForwardingDestinationBinding>,
}

impl EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings {
    pub(crate) fn can_install(
        &self,
        install_report: EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport,
    ) -> Result<(), EvalHeapError> {
        if install_report.bindings() != 0 && !self.forwarding_destination_bindings.is_empty() {
            return Err(
                EvalHeapError::BoundaryMinorGcLiveForwardingDestinationBindingsAlreadyInstalled {
                    existing: self.forwarding_destination_bindings.len(),
                },
            );
        }
        Ok(())
    }

    pub(crate) fn install(
        &mut self,
        forwarding_destination_bindings: Vec<
            EvalGcStressBoundaryMinorGcForwardingDestinationBinding,
        >,
    ) -> Result<
        EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport,
        EvalHeapError,
    > {
        if forwarding_destination_bindings.is_empty() {
            return Ok(
                EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport::default(),
            );
        }
        let install_report =
            live_forwarding_destination_binding_install_report(&forwarding_destination_bindings);
        self.can_install(install_report)?;
        self.install_prevalidated(forwarding_destination_bindings, install_report);
        Ok(install_report)
    }

    pub(crate) fn install_prevalidated(
        &mut self,
        forwarding_destination_bindings: Vec<
            EvalGcStressBoundaryMinorGcForwardingDestinationBinding,
        >,
        install_report: EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport,
    ) {
        if install_report.bindings() == 0 {
            return;
        }

        self.forwarding_destination_bindings = forwarding_destination_bindings;
        self.install_report = install_report;
    }

    /// Returns whether no forwarding destination-binding metadata is installed.
    pub fn is_empty(&self) -> bool {
        self.forwarding_destination_bindings.is_empty()
    }

    /// Returns how many forwarding destination-binding records are installed.
    pub fn len(&self) -> usize {
        self.forwarding_destination_bindings.len()
    }

    /// Returns the install report for the forwarding destination bindings.
    pub const fn install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport {
        self.install_report
    }

    /// Returns installed forwarding destination-binding records.
    pub fn forwarding_destination_bindings(
        &self,
    ) -> &[EvalGcStressBoundaryMinorGcForwardingDestinationBinding] {
        &self.forwarding_destination_bindings
    }
}

/// A destination byte snapshot matched to its future object generation.
///
/// The binding is validation metadata for a future object-generation writer. It
/// proves that an installed destination payload's copy action, destination
/// generation, and byte length agree with the object-copy request that produced
/// it, but it does not bind bytes to heap-object storage or mutate generation
/// metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    action: MinorGcSurvivorAction,
    generation: HeapGeneration,
    request: AllocationCollectorPollObjectByteCopyRequest,
    destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding {
    pub(crate) fn new(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        action: MinorGcSurvivorAction,
        generation: HeapGeneration,
        request: AllocationCollectorPollObjectByteCopyRequest,
        destination_bytes: Vec<u8>,
    ) -> Self {
        Self {
            source,
            destination,
            action,
            generation,
            request,
            destination_bytes,
        }
    }

    /// Returns the from-space survivor source object.
    pub const fn source(&self) -> GcHeapAddress {
        self.source
    }

    /// Returns the destination object address for the copied payload.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns whether this destination keeps the object young or promotes it.
    pub const fn action(&self) -> MinorGcSurvivorAction {
        self.action
    }

    /// Returns the generation that should own the destination object.
    pub const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    /// Returns the object-copy request that installed the destination payload.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }

    /// Returns the installed destination payload bytes.
    pub fn destination_bytes(&self) -> &[u8] {
        &self.destination_bytes
    }
}

/// Counts for a live object-generation write plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcObjectGenerationWritePlanReport {
    objects: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    payload_bytes: usize,
}

impl EvalGcStressBoundaryMinorGcObjectGenerationWritePlanReport {
    pub(crate) fn record(&mut self, write: &EvalGcStressBoundaryMinorGcObjectGenerationWrite) {
        self.objects = self.objects.saturating_add(1);
        self.payload_bytes = self
            .payload_bytes
            .saturating_add(write.destination_bytes().len());
        match write.action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_to_nursery = self.copied_to_nursery.saturating_add(1);
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_to_old = self.promoted_to_old.saturating_add(1);
            }
        }
    }

    /// Returns how many object-generation fields would be written.
    pub const fn objects(self) -> usize {
        self.objects
    }

    /// Returns how many planned generation writes target next-nursery objects.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns how many planned generation writes target old objects.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }

    /// Returns the total destination payload bytes covered by the plan.
    pub const fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
}

/// One validated live object-generation write input.
///
/// This is an immutable write plan for a future heap-record generation writer.
/// It proves that installed live object-generation metadata still matches an
/// installed destination-byte snapshot and carries the payload metadata needed
/// by the eventual writer, but it does not mutate heap records or semispace
/// ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcObjectGenerationWrite {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    action: MinorGcSurvivorAction,
    generation: HeapGeneration,
    request: AllocationCollectorPollObjectByteCopyRequest,
    destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcObjectGenerationWrite {
    pub(crate) fn from_generation_and_binding(
        generation: &EvalGcStressBoundaryMinorGcLiveObjectGeneration,
        binding: &EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding,
    ) -> Result<Self, EvalHeapError> {
        Ok(Self {
            source: generation.source(),
            destination: generation.destination(),
            action: generation.action(),
            generation: generation.generation(),
            request: generation.request(),
            destination_bytes: clone_boundary_destination_storage_bytes(
                BOUNDARY_MINOR_GC_OBJECT_GENERATION_WRITE_BYTES_TABLE,
                binding.destination_bytes(),
            )?,
        })
    }

    /// Returns the from-space survivor source object.
    pub const fn source(&self) -> GcHeapAddress {
        self.source
    }

    /// Returns the destination object address whose generation would be written.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns whether this destination keeps the object young or promotes it.
    pub const fn action(&self) -> MinorGcSurvivorAction {
        self.action
    }

    /// Returns the generation that would be written to the destination object.
    pub const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    /// Returns the object-copy request associated with this generation write.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }

    /// Returns the installed destination payload bytes covered by this write.
    pub fn destination_bytes(&self) -> &[u8] {
        &self.destination_bytes
    }
}

/// A validated live object-generation write plan.
///
/// The plan is derived from installed live object-generation metadata and
/// installed destination-byte snapshots. It is a checked input set for a future
/// heap-record generation writer; creating it does not write heap records, copy
/// object bodies, or change semispace ownership.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcObjectGenerationWritePlan {
    report: EvalGcStressBoundaryMinorGcObjectGenerationWritePlanReport,
    writes: Vec<EvalGcStressBoundaryMinorGcObjectGenerationWrite>,
}

impl EvalGcStressBoundaryMinorGcObjectGenerationWritePlan {
    pub(crate) fn new(writes: Vec<EvalGcStressBoundaryMinorGcObjectGenerationWrite>) -> Self {
        let mut report = EvalGcStressBoundaryMinorGcObjectGenerationWritePlanReport::default();
        for write in &writes {
            report.record(write);
        }
        Self { report, writes }
    }

    /// Returns whether this plan has no object-generation writes.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// Returns how many object-generation writes are planned.
    pub fn len(&self) -> usize {
        self.writes.len()
    }

    /// Returns aggregate counts for the plan.
    pub const fn report(&self) -> EvalGcStressBoundaryMinorGcObjectGenerationWritePlanReport {
        self.report
    }

    /// Returns the planned live object-generation writes.
    pub fn writes(&self) -> &[EvalGcStressBoundaryMinorGcObjectGenerationWrite] {
        &self.writes
    }
}

/// A forwarding value matched to an installed destination-byte snapshot.
///
/// The binding is validation metadata for a future ABI object-header writer. It
/// proves that a forwarding value names the same destination object, generation,
/// and payload bytes as the destination-copy metadata for its source. It does
/// not write object headers, bind bytes to heap-object storage, or mutate
/// generation state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcForwardingDestinationBinding {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    generation: HeapGeneration,
    forwarded_value: ResolvedValueGeneration,
    request: AllocationCollectorPollObjectByteCopyRequest,
    destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcForwardingDestinationBinding {
    pub(crate) fn new(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        generation: HeapGeneration,
        forwarded_value: ResolvedValueGeneration,
        request: AllocationCollectorPollObjectByteCopyRequest,
        destination_bytes: Vec<u8>,
    ) -> Self {
        Self {
            source,
            destination,
            generation,
            forwarded_value,
            request,
            destination_bytes,
        }
    }

    /// Returns the from-space object that owns the forwarding value.
    pub const fn source(&self) -> GcHeapAddress {
        self.source
    }

    /// Returns the destination object address carried by the forwarding value.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns the generation carried by the forwarding value.
    pub const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    /// Returns the complete forwarding metadata value.
    pub const fn forwarded_value(&self) -> ResolvedValueGeneration {
        self.forwarded_value
    }

    /// Returns the object-copy request that installed the destination payload.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }

    /// Returns the installed destination payload bytes.
    pub fn destination_bytes(&self) -> &[u8] {
        &self.destination_bytes
    }
}
