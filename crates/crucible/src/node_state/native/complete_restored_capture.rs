//! Validates the distinct settled17 archive family without restoring live owners.
//!
//! Index3 authentication and bounded immutable content remain generic. Current
//! Host17, native17 and semantic17 are paired through a separate factory callback;
//! original15 validation and its cache are never reinterpreted as this family.

use super::*;
use crate::node_contract::{
    HostSchedulingRestoredContinuationRecord17, NodeRuntime, OriginalInputLineageLimits,
    OriginalLineageRuntimeRecord, RuntimeError, RuntimeOriginalCaptureJournal,
};
use crate::node_scheduling::SchedulingSnapshot;
use crucible_node_contract::ContentRef;
use crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentCheckpoint17;
use std::cell::{Cell, RefCell};
use std::thread::ThreadId;

#[path = "complete_restored_capture/production.rs"]
mod production;
pub use production::CompletedRestoredSettledArchive17Declaration;

#[path = "complete_restored_capture/validation.rs"]
mod validation;

#[path = "complete_restored_capture/terminal.rs"]
mod terminal;

#[path = "complete_restored_capture/terminal_construction.rs"]
mod terminal_construction;
pub(crate) use terminal::{
    RestoredArchive17Current17HeaderWork, RestoredArchive17Initial15QualificationRole,
    RestoredArchive17Initial15Role, RestoredArchive17Initial15Work,
    RestoredArchive17ParentIdentity, RestoredArchive17ParentStep, RestoredArchive17ParentWork,
    RestoredArchive17SourceIndex, RestoredArchive17ValidationAdmission,
    RestoredArchive17ValidationConstructionData, RestoredArchive17ValidationPrewalkData,
    RestoredArchive17ValidationStage, RestoredArchive17ValidationStep,
};

#[path = "complete_restored_capture/coordinator_ancestry17.rs"]
mod coordinator_ancestry17;

#[path = "complete_restored_capture/parent_index.rs"]
mod parent_index;
pub(crate) use parent_index::ParentArchive17ReadScope;

#[path = "complete_restored_capture/collector.rs"]
mod collector;
pub(crate) use collector::{RetainedCold17Collection, RetainedCold17MemberView};

#[path = "complete_restored_capture/receipts.rs"]
mod receipts;

#[path = "complete_restored_capture/dag.rs"]
mod dag;

/// Borrows one actual authenticated current17 archive validation occurrence.
///
/// No public constructor, Clone or deserializer exists. The scope is created
/// only by the current writer or selected signed-load path after Core closure
/// validation. Decoded facts and successful callbacks do not grant native rights.
pub struct CompleteRestoredSettledArchiveValidation<'a> {
    restoration_data: &'a RefCell<[Option<CompleteRestoredSettledNativeRestorationData>; 4]>,
    lineage_limits: OriginalInputLineageLimits,
    terminal_admission: Option<&'a dyn RestoredArchive17ValidationAdmission>,
    // Captured under the preceding Core phase's actual admitted census. The
    // collector adds its own independently retained root, partials and members.
    terminal_prefix_retained_bytes: usize,
    // Exact external owners already included in the defining Core admission.
    validation_additional_retained_bytes: usize,
    collection: &'a RefCell<Option<RetainedCold17Collection>>,
    collection_phase: &'a Cell<collector::CollectorPhase17>,
    validation_origin:
        &'a storage::complete_original_validation_origin::CompleteArchiveValidationOrigin<'a>,
    /// Borrows the actual admitted historical graph and full immutable bindings.
    pub graph: &'a crate::node_admission::AdmittedGraph,
    /// Borrows the same selected-load or still-pending writer archive occurrence.
    pub archive: &'a NativeArchiveRecord,
    /// Borrows the distinct actual current Host17 data, never a synthetic Host2.
    pub host: &'a HostSchedulingRestoredContinuationRecord17,
    /// Borrows current Runtime7 from that same Host owner.
    pub runtime: &'a OriginalLineageRuntimeRecord,
    /// Borrows current scheduler state from that same Host owner.
    pub scheduling: &'a SchedulingSnapshot,
    /// Borrows the actual current administrative ticket/settlement ledger.
    pub administrative: &'a RuntimeOriginalCaptureJournal,
    /// Borrows the signed coordinator object, separate from any receive budget.
    pub checkpoint_reference: &'a ContentRef,
    /// Borrows the retained ordered prefix and its exact current Runtime binding.
    pub checkpoint: &'a CoordinatorCommitmentCheckpoint17,
    coordinator_ancestry: &'a Vec<CoordinatorCommitmentCheckpoint17>,
    /// Borrows full-reference-verified metadata; native images remain streamed.
    pub content: &'a crate::node_state::VerifiedStateContent,
}

impl CompleteRestoredSettledArchiveValidation<'_> {
    /// Borrows the actual writer's phase admission callback, if this is a write.
    pub(crate) fn terminal_admission_data(
        &self,
    ) -> Option<&dyn RestoredArchive17ValidationAdmission> {
        self.terminal_admission
    }

    /// Returns the already-counted Core prefix without a recursive prewalk.
    ///
    /// This includes the full actual attempt, archive occurrence and borrowed
    /// scope headers, capacities and verified content before collection birth.
    /// It excludes caller `additional` and the collection's future owners.
    /// Selected-load validation supplies zero and has no writer phase callback.
    ///
    /// # Errors
    /// The defining captured scalar is returned without allocating or checking
    /// live authority. Actual signed/native/Source joins remain independent.
    pub(crate) fn terminal_prefix_retained_storage_data(&self) -> Result<usize, StateError> {
        Ok(if self.terminal_admission.is_some() {
            self.terminal_prefix_retained_bytes
        } else {
            0
        })
    }

    /// Retains actual validated17 reconstruction DATA for this exact signed owner.
    ///
    /// # Errors
    /// Refuses foreign origin, another owner/content occurrence, a repeated slot
    /// or a busy output bank. No native allocation or restoration is admitted.
    pub fn retain_restored_settled_native_restoration_data(
        &self,
        owner: &NativeOwnerState,
        data: ValidatedCompleteRestoredSettledNativeRestorationData<'_>,
    ) -> Result<(), RuntimeError> {
        self.validation_origin
            .authenticate(self.archive)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let data = data.into_restored_data(owner, self.content)?;
        let index = self
            .archive
            .owners()
            .iter()
            .position(|actual| std::ptr::eq(actual, owner))
            .ok_or(RuntimeError::ForeignAuthority)?;
        let mut output = self
            .restoration_data
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let slot = output
            .get_mut(index)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if slot.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        *slot = Some(data);
        Ok(())
    }

    /// Returns the exact lineage limits admitted for this validation occurrence.
    pub fn lineage_limits(&self) -> OriginalInputLineageLimits {
        self.lineage_limits
    }

    /// Borrows this same authenticated archive's actual finite storage limits.
    ///
    /// # Errors
    /// Refuses replaced, foreign or no-longer-current validation origin.
    pub fn archive_limits_data(&self) -> Result<NativeArchiveLimits, StateError> {
        self.validation_origin.authenticate(self.archive)?;
        Ok(self.archive.limits)
    }

    /// Borrows a real pending writer Runtime, or none for a historical load.
    ///
    /// # Errors
    /// Refuses a foreign/replaced record or stale real capture hold.
    pub fn original_write_runtime_data(&self) -> Result<Option<&NodeRuntime>, StateError> {
        self.validation_origin
            .original_write_runtime_data(self.archive)
    }

    /// Counts actual current Core owners separately from verified content.
    ///
    /// The current Runtime and scheduler are children of Host17, so their
    /// backing is walked there once. This is actual requested-layout census,
    /// not portable padding or permission to reconstruct any native owner.
    ///
    /// # Errors
    /// Refuses foreign origin or overflow in actual current owner storage.
    pub fn retained_allocation_bytes_excluding_content(&self) -> Result<usize, StateError> {
        let base = self.retained_core_bytes_excluding_collection_data()?;
        let collection = self
            .collection
            .try_borrow()
            .map_err(|_| refused("settled17 retained collection is busy"))?;
        let retained = collection
            .as_ref()
            .map(|collection| {
                collection.retained_requested_storage_data(
                    self.archive.limits.state.maximum_total_content_bytes,
                )
            })
            .transpose()
            .map_err(super::super::schema)?
            .unwrap_or(0);
        base.checked_add(retained)
            .ok_or_else(|| refused("settled17 retained collection overflow"))
    }

    // Collector admission already borrows and counts the actual mutable owner.
    // Walking that same RefCell again would refuse its own construction loan.
    fn retained_core_bytes_excluding_collection_data(&self) -> Result<usize, StateError> {
        self.validation_origin.authenticate(self.archive)?;
        let terms = [
            std::mem::size_of::<Self>(),
            std::mem::size_of::<HostSchedulingRestoredContinuationRecord17>(),
            self.host
                .retained_requested_storage_data()
                .map_err(super::super::schema)?,
            NodeRuntime::capture_admin_storage(self.administrative)
                .map_err(super::super::schema)?,
            std::mem::size_of::<CoordinatorCommitmentCheckpoint17>(),
            self.checkpoint
                .retained_backing_requested_bytes_data()
                .map_err(super::super::schema)?,
            NodeRuntime::capture_reference_storage(self.checkpoint_reference)
                .map_err(super::super::schema)?,
            self.archive
                .capture_owned_storage()
                .map_err(super::super::schema)?,
            std::mem::size_of::<RefCell<[Option<CompleteRestoredSettledNativeRestorationData>; 4]>>(
            ),
        ];
        let mut total = terms.into_iter().try_fold(0usize, |total, next| {
            total
                .checked_add(next)
                .ok_or_else(|| refused("settled17 current Core owner census overflow"))
        })?;
        total = total
            .checked_add(
                self.coordinator_ancestry
                    .capacity()
                    .checked_mul(std::mem::size_of::<CoordinatorCommitmentCheckpoint17>())
                    .ok_or_else(|| refused("settled17 coordinator ancestry header overflow"))?,
            )
            .ok_or_else(|| refused("settled17 coordinator ancestry census overflow"))?;
        for parent in self.coordinator_ancestry {
            total = total
                .checked_add(
                    parent
                        .retained_backing_requested_bytes_data()
                        .map_err(super::super::schema)?,
                )
                .ok_or_else(|| refused("settled17 coordinator ancestry backing overflow"))?;
        }
        for data in self
            .restoration_data
            .try_borrow()
            .map_err(|_| refused("settled17 retained geometry bank is busy"))?
            .iter()
            .flatten()
        {
            total = total
                .checked_add(
                    data.native_import_geometry_data()
                        .retained_requested_storage_data()
                        .map_err(super::super::schema)?,
                )
                .ok_or_else(|| refused("settled17 retained geometry overflow"))?;
        }
        self.validation_origin.authenticate(self.archive)?;
        Ok(total)
    }

    /// Reads actual current Native/Controller/Node components before Source birth.
    ///
    /// This is a partial construction stage. It cannot satisfy archive completion
    /// until the genuine parent and Source readers are also retained. Reentry
    /// refuses and leaves every prior success or failed partial in the same bank.
    ///
    /// # Errors
    /// Refuses foreign validation origin, reused/busy output, malformed signed
    /// components, unequal native/SDK/common cuts or exhausted independent credit.
    pub fn collect_current_components_data(
        &self,
        additional_retained_bytes: usize,
    ) -> Result<(), StateError> {
        self.validation_origin.authenticate(self.archive)?;
        if self.terminal_admission.is_some() {
            return collector::collect_terminal_into_data(self, additional_retained_bytes);
        }
        let mut output = self
            .collection
            .try_borrow_mut()
            .map_err(|_| refused("settled17 collection bank is busy"))?;
        let result = RetainedCold17Collection::collect_current_into(
            self,
            additional_retained_bytes,
            &mut output,
        );
        self.validation_origin.authenticate(self.archive)?;
        result
    }

    /// Counts this exact verified metadata owner without copying its bodies.
    ///
    /// # Errors
    /// Refuses foreign validation origin or checked content-layout overflow.
    pub fn retained_verified_content_allocation_bytes(&self) -> Result<usize, StateError> {
        self.validation_origin.authenticate(self.archive)?;
        let bytes = self
            .content
            .capture_owned_storage()
            .map_err(super::super::schema)?;
        self.validation_origin.authenticate(self.archive)?;
        Ok(bytes)
    }

    /// Names the actual authenticated Index3 body under a separate output credit.
    ///
    /// # Errors
    /// Refuses changed origin, unsupported index or finite encoding excess.
    pub fn index_identity_data(
        &self,
        maximum_record_bytes: usize,
        additional_retained_bytes: usize,
    ) -> Result<ContentRef, StateError> {
        self.validation_origin.authenticate(self.archive)?;
        let reference = storage::complete_original_validation_origin::index_identity_data(
            self.archive,
            maximum_record_bytes,
            additional_retained_bytes,
        )?;
        self.validation_origin.authenticate(self.archive)?;
        Ok(reference)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ValidationStage {
    Started,
    Content,
    Host,
    Verified,
    Failed,
    Taken,
}

/// Retains every initialized17 cold-validation owner through failure.
///
/// Its initial header is installed before any content read/typed decode. It is
/// not Clone, serializable or a native permission. Failed attempts stay failed;
/// no retry can renew their caller's finite construction commitment.
pub struct CompleteRestoredSettledArchiveValidationAttempt {
    archive: *const NativeArchiveRecord,
    process: u32,
    thread: ThreadId,
    stage: Cell<ValidationStage>,
    dag_colors: Vec<u8>,
    dag_heights: Vec<usize>,
    dag_stack: Vec<dag::Frame>,
    content: Option<crate::node_state::VerifiedStateContent>,
    closure: crate::node_state::closure::retained::RetainedClosureVerification,
    host: Option<HostSchedulingRestoredContinuationRecord17>,
    administrative: Option<RuntimeOriginalCaptureJournal>,
    runtime_reference: Option<ContentRef>,
    coordinator: Option<CoordinatorCommitmentCheckpoint17>,
    coordinator_ancestry: Vec<CoordinatorCommitmentCheckpoint17>,
    checkpoint_reference: Option<ContentRef>,
    restoration_data: RefCell<[Option<CompleteRestoredSettledNativeRestorationData>; 4]>,
    collection: RefCell<Option<RetainedCold17Collection>>,
    collection_phase: Cell<collector::CollectorPhase17>,
    lineage_limits: OriginalInputLineageLimits,
}

/// Moves already validated current facts into the same actual fresh source owner.
pub(crate) struct CompleteRestoredSettledValidatedArchiveData {
    pub(super) content: crate::node_state::VerifiedStateContent,
    pub(super) host: HostSchedulingRestoredContinuationRecord17,
    pub(super) administrative: RuntimeOriginalCaptureJournal,
    pub(super) runtime_reference: ContentRef,
    pub(super) checkpoint_reference: ContentRef,
    pub(super) checkpoint: CoordinatorCommitmentCheckpoint17,
    pub(super) restoration_data: [Option<CompleteRestoredSettledNativeRestorationData>; 4],
    pub(super) collection: RetainedCold17Collection,
    pub(super) lineage_limits: OriginalInputLineageLimits,
}

impl CompleteRestoredSettledArchiveValidationAttempt {
    fn new(archive: &NativeArchiveRecord, lineage_limits: OriginalInputLineageLimits) -> Self {
        Self {
            archive,
            process: std::process::id(),
            thread: std::thread::current().id(),
            stage: Cell::new(ValidationStage::Started),
            dag_colors: Vec::new(),
            dag_heights: Vec::new(),
            dag_stack: Vec::new(),
            content: None,
            closure: crate::node_state::closure::retained::RetainedClosureVerification::new(),
            host: None,
            administrative: None,
            runtime_reference: None,
            coordinator: None,
            coordinator_ancestry: Vec::new(),
            checkpoint_reference: None,
            restoration_data: RefCell::new(std::array::from_fn(|_| None)),
            collection: RefCell::new(None),
            collection_phase: Cell::new(collector::CollectorPhase17::Pending),
            lineage_limits,
        }
    }

    fn authenticate(&self, archive: &NativeArchiveRecord) -> Result<(), StateError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.archive, archive)
        {
            return Err(refused(
                "settled17 validation attempt belongs to another owner",
            ));
        }
        Ok(())
    }

    /// Counts this retained attempt and every initialized backing owner.
    ///
    /// Archive, code factory and native cold reconstruction banks remain separate
    /// caller obligations. The result confers no decode or allocation right.
    ///
    /// # Errors
    /// Refuses overflow in actual content, Host, journal and reference owners.
    pub fn retained_requested_storage_data(&self) -> Result<usize, RuntimeError> {
        let mut total = std::mem::size_of::<Self>()
            .checked_add(self.closure.retained_requested_storage_data()?)
            .and_then(|bytes| {
                bytes.checked_sub(std::mem::size_of::<
                    crate::node_state::closure::retained::RetainedClosureVerification,
                >())
            })
            .ok_or(RuntimeError::ResourceLimit)?;
        let mut add = |bytes: usize| -> Result<(), RuntimeError> {
            total = total
                .checked_add(bytes)
                .ok_or(RuntimeError::ResourceLimit)?;
            Ok(())
        };
        add(self.dag_colors.capacity())?;
        add(self
            .dag_heights
            .capacity()
            .checked_mul(std::mem::size_of::<usize>())
            .ok_or(RuntimeError::ResourceLimit)?)?;
        add(self
            .dag_stack
            .capacity()
            .checked_mul(std::mem::size_of::<dag::Frame>())
            .ok_or(RuntimeError::ResourceLimit)?)?;
        if let Some(content) = &self.content {
            add(content.capture_owned_storage()?)?;
        }
        if let Some(host) = &self.host {
            add(host.retained_requested_storage_data()?)?;
        }
        if let Some(admin) = &self.administrative {
            add(NodeRuntime::capture_admin_storage(admin)?)?;
        }
        if let Some(reference) = &self.runtime_reference {
            add(NodeRuntime::capture_reference_storage(reference)?)?;
        }
        if let Some(coordinator) = &self.coordinator {
            add(coordinator
                .retained_backing_requested_bytes_data()
                .map_err(|_| RuntimeError::ResourceLimit)?)?;
        }
        if let Some(reference) = &self.checkpoint_reference {
            add(NodeRuntime::capture_reference_storage(reference)?)?;
        }
        add(self
            .coordinator_ancestry
            .capacity()
            .checked_mul(std::mem::size_of::<CoordinatorCommitmentCheckpoint17>())
            .ok_or(RuntimeError::ResourceLimit)?)?;
        for parent in &self.coordinator_ancestry {
            add(parent
                .retained_backing_requested_bytes_data()
                .map_err(|_| RuntimeError::ResourceLimit)?)?;
        }
        for data in self
            .restoration_data
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .iter()
            .flatten()
        {
            add(data
                .native_import_geometry_data()
                .retained_requested_storage_data()
                .map_err(|_| RuntimeError::ResourceLimit)?)?;
        }
        if let Some(collection) = self
            .collection
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .as_ref()
        {
            add(collection.retained_requested_storage_data(usize::MAX)?)?;
        }
        Ok(total)
    }

    /// Moves validated facts once, after the actual factory and selected-load proof.
    ///
    /// # Errors
    /// Refuses another archive, absent completion, a failed/reused attempt or any
    /// missing retained component. It does not issue a ticket or fresh authority.
    pub(crate) fn take_validated_data(
        &mut self,
        archive: &NativeArchiveRecord,
    ) -> Result<CompleteRestoredSettledValidatedArchiveData, StateError> {
        self.authenticate(archive)?;
        archive
            .authenticate_complete_load_admission()
            .map_err(super::super::schema)?;
        if self.stage.get() != ValidationStage::Verified
            || self.content.is_none()
            || self.host.is_none()
            || self.administrative.is_none()
            || self.runtime_reference.is_none()
            || self.coordinator.is_none()
            || self.checkpoint_reference.is_none()
        {
            return Err(refused(
                "settled17 validation is incomplete, failed or already taken",
            ));
        }
        self.collection
            .get_mut()
            .as_ref()
            .ok_or_else(|| refused("settled17 completed decoded owner collection absent"))?
            .authenticate_completed_data(archive)
            .map_err(super::super::schema)?;
        self.stage.set(ValidationStage::Taken);
        let content = self
            .content
            .take()
            .ok_or_else(|| refused("settled17 content absent"))?;
        let host = self
            .host
            .take()
            .ok_or_else(|| refused("settled17 Host absent"))?;
        let administrative = self
            .administrative
            .take()
            .ok_or_else(|| refused("settled17 administrative ledger absent"))?;
        let runtime_reference = self
            .runtime_reference
            .take()
            .ok_or_else(|| refused("settled17 runtime reference absent"))?;
        let checkpoint = self
            .coordinator
            .take()
            .ok_or_else(|| refused("settled17 coordinator checkpoint absent"))?;
        let checkpoint_reference = self
            .checkpoint_reference
            .take()
            .ok_or_else(|| refused("settled17 checkpoint reference absent"))?;
        let restoration_data = std::mem::replace(
            self.restoration_data.get_mut(),
            std::array::from_fn(|_| None),
        );
        let collection = self
            .collection
            .get_mut()
            .take()
            .ok_or_else(|| refused("settled17 completed decoded owner collection absent"))?;
        Ok(CompleteRestoredSettledValidatedArchiveData {
            content,
            host,
            administrative,
            runtime_reference,
            checkpoint_reference,
            checkpoint,
            restoration_data,
            collection,
            lineage_limits: self.lineage_limits,
        })
    }
}

/// Counts fixed views for the retained current17 validation and move boundary.
///
/// Dynamic content, Host and error backing remain actual independent owners.
/// This getter admits no decode, native reconstruction or Source association.
pub fn complete_restored_settled_archive_validation_counter_scratch_data() -> usize {
    let terms = [
        std::mem::size_of::<CompleteRestoredSettledArchiveValidation<'static>>(),
        std::mem::size_of::<&CompleteRestoredSettledArchiveValidationAttempt>(),
        std::mem::size_of::<&mut CompleteRestoredSettledArchiveValidationAttempt>(),
        std::mem::size_of::<&mut Option<CompleteRestoredSettledArchiveValidationAttempt>>(),
        std::mem::size_of::<Option<CompleteRestoredSettledArchiveValidationAttempt>>(),
        std::mem::size_of::<Result<CompleteRestoredSettledValidatedArchiveData, StateError>>(),
        std::mem::size_of::<Result<usize, RuntimeError>>(),
        std::mem::size_of::<Result<(), StateError>>(),
        std::mem::size_of::<
            std::cell::Ref<'static, [Option<CompleteRestoredSettledNativeRestorationData>; 4]>,
        >(),
        std::mem::size_of::<
            std::cell::RefMut<'static, [Option<CompleteRestoredSettledNativeRestorationData>; 4]>,
        >(),
        std::mem::size_of::<std::slice::Iter<'static, NativeOwnerState>>(),
        std::mem::size_of::<std::iter::Enumerate<std::slice::Iter<'static, NativeOwnerState>>>(),
        std::mem::size_of::<(usize, &NativeOwnerState)>(),
        std::mem::size_of::<[usize; 6]>(),
        std::mem::size_of::<std::array::IntoIter<usize, 6>>(),
        std::mem::size_of::<[Option<CompleteRestoredSettledNativeRestorationData>; 4]>(),
        std::mem::size_of::<usize>(),
        std::mem::size_of::<Option<usize>>(),
    ];
    std::mem::size_of_val(&terms)
        + std::mem::size_of::<std::array::IntoIter<usize, 18>>()
        + terms.into_iter().sum::<usize>()
        + crate::node_contract::host_scheduling_restored_continuation_schema17_counter_scratch_data(
        )
        + production::production_counter_scratch_data()
        + collector::counter_scratch_data()
        + parent_index::counter_scratch_data()
}

#[path = "complete_restored_capture/initial15_history.rs"]
mod initial15_history;
pub(crate) use initial15_history::{
    HistoricalInitial15Scope17, Initial15ScopeMember17,
    authenticate_initial15_source_member17_data, initial15_source_member17_counter_scratch_data,
};
