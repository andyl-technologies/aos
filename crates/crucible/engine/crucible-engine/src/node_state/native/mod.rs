//! Backend-bound installed native archives and inactive complete-world restoration.
//!
//! Native archive edition one signs its original digest-keyed metadata table.
//! Edition two signs independently enrolled full typed references and per-role
//! dependency rows while retaining one byte object per digest. Both editions
//! bind bounded core records and separately streamed image/resource files. They
//! are independent of the host archive edition. Installed factories authenticate
//! actual native codecs,
//! original operation custody and complete artifact coverage before a signature
//! can be issued or an autonomous resource can be reconstructed.

mod capture;
mod collecting_scope;
mod complete_original_archive_storage;
mod complete_original_capture;
mod complete_restored_capture;
pub use complete_restored_capture::{
    CompleteRestoredSettledArchiveValidation, CompleteRestoredSettledArchiveValidationAttempt,
    CompletedRestoredSettledArchive17Declaration,
    complete_restored_settled_archive_validation_counter_scratch_data,
};
pub(crate) use complete_restored_capture::{
    CompleteRestoredSettledValidatedArchiveData, ParentArchive17ReadScope,
    RestoredArchive17Current17HeaderWork, RestoredArchive17Initial15QualificationRole,
    RestoredArchive17Initial15Role, RestoredArchive17Initial15Work,
    RestoredArchive17ParentIdentity, RestoredArchive17ParentStep, RestoredArchive17ParentWork,
    RestoredArchive17SourceIndex, RestoredArchive17ValidationAdmission,
    RestoredArchive17ValidationConstructionData, RestoredArchive17ValidationPrewalkData,
    RestoredArchive17ValidationStage, RestoredArchive17ValidationStep, RetainedCold17Collection,
    RetainedCold17MemberView,
};
mod complete_original_dependency_storage;
mod complete_original_factory_storage;
pub use collecting_scope::CollectingCompleteCaptureProvenance;
pub use complete_original_dependency_storage::CompleteOriginalCaptureDependencyStorage;
pub use complete_original_factory_storage::CompleteOriginalCaptureFactoryStorage;
mod complete_original_geometry;
mod complete_original_index;
mod complete_original_native_ticket;
mod complete_original_restoration_data;
mod complete_restored_restoration_data;
pub use complete_original_restoration_data::{
    CompleteOriginalArchivedValidationConstructionData, CompleteOriginalNativeRestorationData,
    CompleteOriginalRestorationIndexConstructionData, ValidatedCompleteNativeRestorationData,
};
pub use complete_restored_restoration_data::{
    CompleteRestoredSettledNativeRestorationData,
    ValidatedCompleteRestoredSettledNativeRestorationData,
};
mod complete_original_source;
mod driver;
pub(crate) mod extensions;
mod historical_capture;
mod lineage_capture;
mod lineage_inventory;
mod lineage_roots;
mod lineage_source;
mod storage;
mod typed_index;
mod writer_final_debits;

pub(super) use capture::source_epoch_evidence;

#[cfg(test)]
mod tests;

use crucible_node_format::{CapturedOwner, Id};

use crate::{
    node_admission::AdmittedGraph,
    node_contract::{
        ActivationRecord, NativeCaptureArtifact, NativeCaptureLimits, RuntimeSnapshot,
    },
};

use super::{
    NativeRestoreStaging, RestoreReservations, StateError, StateLimits, VerifiedStateContent,
};

pub use complete_original_capture::{
    CompleteOriginalArchiveValidation, ImportedClosureGeometry17,
    imported_closure17_counter_scratch_data,
};
pub use complete_original_geometry::{
    CompleteOriginalCaptureGeometry, CompleteOriginalOwnerCaptureGeometry,
    CompleteOriginalOwnerCapturePreflight,
};
pub use complete_original_native_ticket::{
    CompleteOriginalNativeTicket, CompleteOriginalNativeTicketHistory,
};
pub(crate) use complete_original_source::CompleteOriginalSource;
pub use complete_original_source::{
    CompleteOriginalHostTicket, CompleteOriginalRestorationSource, CompleteOriginalSourceHistory,
    CompleteRestoredSettledSourceLoadAttempt,
};
pub(crate) use core_future_metadata::CompleteCaptureAllocationBudget;
pub use driver::NativeWorldRestoreDriver;
pub use extensions::NativeExtensionPreservationPolicy;
pub use lineage_capture::OriginalLineageCaptureRequest;
pub use lineage_source::{
    AuthenticatedOriginalLineageSource, ORIGINAL_LINEAGE_COORDINATOR_MEDIA,
    ORIGINAL_LINEAGE_RUNTIME_MEDIA, OriginalLineageSourcePinFailure, PinnedOriginalLineageSource,
};
pub use storage::{NativeArchive, NativeArchiveRecord, NativeArtifactState, NativeOwnerState};
pub use writer_final_debits::{AuthenticatedWriterFinalDebits, OriginalWriterFinalDebitSource};

/// Bounds metadata and streamed native preservation independently.
#[derive(Clone, Copy, Debug)]
pub struct NativeArchiveLimits {
    /// Bounds complete portable/core state and staged native resources.
    pub state: StateLimits,
    /// Bounds small native records and separately retained image files.
    pub native: NativeCaptureLimits,
}

impl Default for NativeArchiveLimits {
    fn default() -> Self {
        let state = StateLimits::default();
        Self {
            native: NativeCaptureLimits {
                maximum_record_bytes: state.maximum_content_bytes,
                maximum_total_record_bytes: state.maximum_total_content_bytes,
                maximum_objects: state.maximum_content_objects,
                maximum_artifact_bytes: 4 * 1024 * 1024 * 1024,
                maximum_total_artifact_bytes: state.maximum_native_writable_bytes,
            },
            state,
        }
    }
}

/// Borrows original source data under a locally authenticated native archive seal.
///
/// Public digests and image filenames cannot construct this value. It provides
/// preservation data only; fresh native closure, local admission and whole-world
/// activation remain mandatory before any restored owner can execute.
pub struct AuthenticatedNativeSource<'a> {
    record: &'a NativeArchiveRecord,
    owner: &'a NativeOwnerState,
    runtime: &'a RuntimeSnapshot,
    content: &'a VerifiedStateContent,
}

impl AuthenticatedNativeSource<'_> {
    /// Returns the complete authenticated backend-bound owner metadata.
    pub fn owner(&self) -> &NativeOwnerState {
        self.owner
    }

    /// Borrows complete original runtime and acknowledgement custody.
    pub fn runtime(&self) -> &RuntimeSnapshot {
        self.runtime
    }

    /// Borrows authenticated small core records and immutable model inputs.
    pub fn content(&self) -> &VerifiedStateContent {
        self.content
    }

    /// Borrows the original bounded native ledger for this owner.
    ///
    /// # Errors
    /// Refuses an absent or changed native ledger reference.
    pub fn native(&self) -> Result<&[u8], StateError> {
        self.content
            .get(&self.owner.state)
            .ok_or_else(|| refused("authenticated native owner ledger absent"))
    }

    /// Opens independently retained verified native image/resource streams.
    ///
    /// # Errors
    /// Refuses unavailable files, inconsistent metadata or changed bytes.
    pub fn artifacts(&self) -> Result<Vec<NativeCaptureArtifact>, StateError> {
        self.record.owner_artifacts(&self.owner.owner)
    }

    /// Borrows the persistent authenticated archive independently of source paths.
    pub fn archive(&self) -> &NativeArchiveRecord {
        self.record
    }
}

/// Authenticates installed native state and constructs empty owning staging capsules.
///
/// Implementations are trusted local installation procedures, not provider
/// assertions. They independently verify actual backend/code/profile identity,
/// complete native ledgers and every image/resource dependency. Source image
/// certificates never qualify a fresh live peer or grant execution authority.
pub trait NativeWorldFactory {
    /// Borrows exact imported-closure geometry from the actual three Source rows.
    ///
    /// This nonallocating metadata callback runs under the actual current scope,
    /// before owner effects. The caller separately admits returned maps, cloned
    /// references, dependency rows, finished Index backing and store verification.
    ///
    /// # Errors
    /// Defaults to refusal for an unsupported Source family or missing real row.
    fn complete_restored_capture_imported_closure_geometry_data(
        &self,
        _scope: &crate::node_contract::RestoredCollectingCaptureScope17<'_>,
    ) -> Result<ImportedClosureGeometry17, StateError> {
        Err(refused(
            "installed imported current17 closure geometry is unsupported",
        ))
    }

    /// Rechecks completed imported geometry against its pre-effects bound.
    ///
    /// # Errors
    /// Defaults to refusal; rejects incomplete Source outputs or changed custody.
    fn complete_restored_capture_completed_imported_closure_geometry_data(
        &self,
        _scope: &crate::node_contract::RestoredCollectingCaptureScope17<'_>,
    ) -> Result<ImportedClosureGeometry17, StateError> {
        Err(refused(
            "installed completed current17 closure geometry is unsupported",
        ))
    }

    /// Visits each actual parent Index body followed by its exact signed objects.
    ///
    /// The caller has independently admitted all returned reference/adjacency
    /// copies before effects. Bodies remain borrowed from completed Source
    /// custody; a reference alone never supplies missing octets or dependencies.
    ///
    /// # Errors
    /// Defaults to refusal; propagates any changed owner, missing body, stale
    /// current scope or callback failure without treating failure as success.
    fn visit_complete_restored_capture_imported_objects_data(
        &self,
        _scope: &crate::node_contract::RestoredCollectingCaptureScope17<'_>,
        _inspect: &mut dyn FnMut(
            &crucible_node_format::ContentRef,
            &[u8],
            &[crucible_node_format::ContentRef],
        ) -> Result<(), StateError>,
    ) -> Result<(), StateError> {
        Err(refused(
            "installed imported current17 body visitor is unsupported",
        ))
    }

    /// Authenticates the distinct current17 archive and retains all cold owners.
    ///
    /// # Errors
    /// Refuses unsupported implementations, changed signed scopes or incomplete
    /// native, Controller, Node, Source and inherited-parent correspondence.
    fn authenticate_complete_restored_settled_archive(
        &self,
        _scope: CompleteRestoredSettledArchiveValidation<'_>,
    ) -> Result<(), StateError> {
        Err(refused(
            "installed restored settled17 archive codec is unsupported",
        ))
    }

    /// Observes separate complete-factory banks before any cache preparation.
    ///
    /// This data callback uses the same closed source/graph and actual current
    /// retained capacities. Its future term bounds all additional canonical
    /// projection and dependency-reader scratch. It grants no source permission
    /// and cannot pad or replace the four original owning-node preflight rows.
    ///
    /// # Errors
    /// Defaults to refusal; rejects unsupported allocation accounting, changed
    /// original source scope or an unrepresentable finite closed projection.
    fn complete_original_capture_factory_storage(
        &self,
        _graph: &AdmittedGraph,
        _runtime: &crate::node_contract::OriginalLineageRuntimeRecord,
        _scheduling: &crate::node_scheduling::SchedulingSnapshot,
        _limits: NativeArchiveLimits,
    ) -> Result<CompleteOriginalCaptureFactoryStorage, StateError> {
        Err(refused(
            "installed complete factory storage accounting is unsupported",
        ))
    }

    /// Observes dependency metadata after the original owning-node preflight.
    ///
    /// The actual Runtime7 body and private source plans already exist at this
    /// point. This data callback counts only the distinct future born rows,
    /// returned adjacency copies and one simultaneous lookup/hash scratch. The
    /// early factory/cache storage callback remains independently admitted.
    /// It performs no RPC or source effect and grants no allowance or ticket.
    ///
    /// # Errors
    /// Defaults to refusal; rejects an absent, foreign or stale original plan,
    /// unsupported concrete producer or requested-layout overflow.
    fn complete_original_capture_dependency_storage(
        &self,
        _graph: &AdmittedGraph,
        _runtime: &crate::node_contract::OriginalLineageRuntimeRecord,
        _scheduling: &crate::node_scheduling::SchedulingSnapshot,
        _runtime_object: &crate::node_scheduling::InputPayload,
        _limits: NativeArchiveLimits,
    ) -> Result<CompleteOriginalCaptureDependencyStorage, StateError> {
        Err(refused(
            "installed complete dependency storage accounting is unsupported",
        ))
    }

    /// Narrows native records independently of reserved immutable and portable bytes.
    ///
    /// The legacy default preserves the original limit. A selected installed
    /// policy can supply a smaller positive ceiling; the host refuses widening
    /// before any native capture hook. This callback grants no capture authority.
    ///
    /// # Errors
    /// Refuses a changed selected source or an unauthenticated operation budget.
    fn native_capture_record_ceiling(
        &self,
        _graph: &AdmittedGraph,
        _scheduler: &crate::node_scheduling::SchedulingSnapshot,
    ) -> Result<Option<usize>, StateError> {
        Ok(None)
    }

    /// Authenticates complete original selected writer ancestry before live rebind.
    ///
    /// The opaque source has already verified the signed owner/cut, all typed
    /// dependency bodies, attempted debit conservation and original delivery.
    /// The installed policy must additionally bind its exact current compiled
    /// writer/controller profile, complete capture/image/custody closure and
    /// source-issued current transport/kernel ownership. A historical measured
    /// getter, parsed account or digest alone cannot supply this permission.
    /// Approval preserves historical data; operational adoption remains a
    /// separate original native transition under its admitted whole-owner holds.
    ///
    /// # Errors
    /// Refuses unsupported selected writer editions, absent complete original
    /// source qualification or changed current profile/owner dependencies.
    ///
    /// # Panics
    /// An installed implementation may panic. The caller must retain the
    /// original owning source/runtime capsule and its existing failure custody
    /// across callback unwind; approval never transfers that custody.
    fn authenticate_writer_final_debit_source(
        &self,
        _graph: &AdmittedGraph,
        _source: &AuthenticatedNativeSource<'_>,
        _writer: &OriginalWriterFinalDebitSource<'_>,
    ) -> Result<(), StateError> {
        Err(refused(
            "installed complete selected writer source remains unsupported",
        ))
    }

    /// Authenticates the selected original-epoch codec before native effects or allocation.
    ///
    /// Legacy factory policies remain unsupported for scheduler edition two.
    /// Original object references are preservation data, never a native capability.
    ///
    /// # Errors
    /// Refuses unsupported source policy, changed body inventory or native ancestry.
    fn authenticate_scheduling_epochs(
        &self,
        _graph: &AdmittedGraph,
        _runtime: &RuntimeSnapshot,
        _scheduler: &crate::node_scheduling::SchedulingSnapshot,
        _epochs: &crate::node_scheduling::SchedulingEpochEvidence,
    ) -> Result<(), StateError> {
        Err(refused(
            "installed factory has no selected scheduling epoch codec",
        ))
    }

    /// Authenticates complete original coordinator7 and native/Tape2 journals.
    ///
    /// The distinct source reader has already authenticated the signed typed
    /// closure and exact selected policy. This callback must independently check
    /// original preparation, producer/consumer windows, consumed inputs, pending
    /// operations, ACKs and the consumed tape cutoff under the installed source
    /// codec. Its default refuses; selection alone never grants preservation.
    ///
    /// # Errors
    /// Refuses unsupported original-lineage scope or changed complete native journals.
    fn authenticate_original_lineage_source(
        &self,
        _graph: &AdmittedGraph,
        _source: &AuthenticatedOriginalLineageSource<'_>,
    ) -> Result<(), StateError> {
        Err(refused(
            "installed factory has no original-lineage source codec",
        ))
    }

    /// Authenticates the exact live conditional capture scope before model callbacks.
    ///
    /// This separate callback must bind the source-authenticated original tapes,
    /// conditional code/context, unchanged world cut and complete native journal
    /// coverage. Ordinary source qualification is not sufficient.
    ///
    /// # Errors
    /// Refuses unqualified Runtime7 capture or unsupported combined scope.
    fn authenticate_original_lineage_capture(
        &self,
        _graph: &AdmittedGraph,
        _runtime: &crate::node_contract::OriginalLineageRuntimeRecord,
        _scheduler: &crate::node_scheduling::SchedulingSnapshot,
    ) -> Result<(), StateError> {
        Err(refused(
            "installed complete original-lineage capture is unsupported",
        ))
    }

    /// Authenticates source-selected complete capture support before owner effects.
    ///
    /// The source-specific factory conjuncts its genuine current native/host
    /// originals with this complete unchanged-cut data. This default refusal is
    /// separate from Tape2 support and cannot be selected by native key labels.
    ///
    /// # Errors
    /// Refuses unsupported source/factory scope, altered current original state,
    /// incomplete native capture support or exhausted preparation credit.
    fn authenticate_complete_original_lineage_capture(
        &self,
        _graph: &AdmittedGraph,
        _runtime: &crate::node_contract::OriginalLineageRuntimeRecord,
        _scheduler: &crate::node_scheduling::SchedulingSnapshot,
    ) -> Result<(), StateError> {
        Err(refused(
            "installed complete original capture preparation is unsupported",
        ))
    }

    /// Conjuncts a complete capture with its actual original collecting authority.
    ///
    /// The concrete installed factory must retain the same native registry and
    /// host source as the opaque plan. This separate hook grants no ordinary
    /// acceptance and cannot be selected by decoded plan/source references.
    ///
    /// # Errors
    /// Defaults to refusal; rejects a foreign opaque plan or source, missing
    /// installed capture closure, or changed actual runtime/scheduler state.
    fn authenticate_complete_collecting_capture(
        &self,
        _plan: &crate::node_admission::InstalledConformancePlan,
        _source: &crate::node_contract::HostSchedulingSource,
        _graph: &AdmittedGraph,
        _runtime: &crate::node_contract::OriginalLineageRuntimeRecord,
        _scheduling: &crate::node_scheduling::SchedulingSnapshot,
    ) -> Result<(), StateError> {
        Err(refused(
            "installed complete collecting factory is unsupported",
        ))
    }

    /// Authenticates actual installed code against one complete structural request.
    ///
    /// This data-only entry is separate from live collecting graph authority.
    /// It requires a concrete installed archive-code factory and actual plan;
    /// launch/decoded fields alone cannot opt in. No native preparation occurs.
    ///
    /// # Errors
    /// Defaults to refusal; rejects a foreign plan/code factory, unsupported
    /// class/profile/resource selection or changed original structural request.
    fn authenticate_complete_archive_code_request(
        &self,
        _plan: &crate::node_admission::InstalledConformancePlan,
        _request: crate::node_admission::AdmissionRequest<'_>,
    ) -> Result<(), StateError> {
        Err(refused(
            "installed complete archive-code request is unsupported",
        ))
    }

    /// Authenticates a selected code claim without issuing behavioral acceptance.
    ///
    /// Only the private archive-code structural validator uses this hook. Its
    /// result has no live or ordinary graph conversion. Full historical cold
    /// codec validation and independent fresh target gates remain mandatory.
    ///
    /// # Errors
    /// Defaults to refusal for unknown code, Node/profile or immutable claims.
    fn authenticate_complete_archive_code_claim(
        &self,
        _plan: &crate::node_admission::InstalledConformancePlan,
        _claim: crate::node_admission::QualificationClaim<'_>,
    ) -> Result<(), StateError> {
        Err(refused(
            "installed complete archive-code claim is unsupported",
        ))
    }

    /// Authenticates installed historical code before collecting source tickets.
    ///
    /// This separate data-validation entry requires an actual installed code
    /// factory and its original code-selection graph. Core authenticates the
    /// selected signed-load receipt and complete cold closure independently.
    /// Success permits only creation of an explicitly unbound collecting source;
    /// fresh target binding, native preparation, whole admission and completed
    /// restoration remain separate mandatory gates before installation or Arm.
    /// Retired source processes need not remain alive to validate their data.
    ///
    /// # Errors
    /// Defaults to refusal; rejects foreign code authority/graph, changed signed
    /// provenance, unsupported installed codecs or exhausted validation limits.
    fn authenticate_complete_collecting_archive_code_source(
        &self,
        _plan: &crate::node_admission::InstalledConformancePlan,
        _graph: &AdmittedGraph,
        _archive: &NativeArchiveRecord,
        _scope: &CollectingCompleteCaptureProvenance,
    ) -> Result<(), StateError> {
        Err(refused(
            "installed collecting historical code validation is unsupported",
        ))
    }

    /// Authenticates fresh native preparation for a signed collecting archive.
    ///
    /// The source factory binds genuine held fresh native actors/controllers and
    /// installed codecs before the Host2 ticket exists. Actual target Host source
    /// and Runtime7 context are authenticated later before installation and Arm.
    /// Parsed scope facts and launch declarations cannot provide this association.
    ///
    /// # Errors
    /// Defaults to refusal; rejects unsupported adopter, changed historical
    /// closure, foreign fresh registration or another opaque collecting plan.
    fn authenticate_complete_collecting_restoration_source(
        &self,
        _plan: &crate::node_admission::InstalledConformancePlan,
        _graph: &AdmittedGraph,
        _archive: &NativeArchiveRecord,
        _scope: &CollectingCompleteCaptureProvenance,
    ) -> Result<(), StateError> {
        Err(refused(
            "installed collecting native restoration preparation is unsupported",
        ))
    }

    /// Derives the full selected capture plan before any administrative callback.
    ///
    /// The factory authenticates the same current native/host selections and
    /// derives every row from their actual codecs and preallocated banks. It
    /// bounds row and participant allocation before returning the plan. Parsed
    /// metadata, generic hard ceilings and a minimum leaf count cannot opt in.
    /// Core separately admits the whole unchanged world and private ticket.
    ///
    /// # Errors
    /// Refuses unsupported source geometry, altered original selections,
    /// missing prefix/settlement codecs or a plan beyond the supplied credits.
    fn complete_original_lineage_capture_geometry(
        &self,
        _graph: &AdmittedGraph,
        _runtime: &crate::node_contract::OriginalLineageRuntimeRecord,
        _scheduler: &crate::node_scheduling::SchedulingSnapshot,
        _limits: NativeArchiveLimits,
    ) -> Result<CompleteOriginalCaptureGeometry, StateError> {
        Err(refused(
            "installed complete capture geometry is unsupported",
        ))
    }

    /// Authenticates the complete native-five/host-two snapshot and administrative closure.
    ///
    /// The installed implementation must validate actual native capture and
    /// response-prefix history, source/owner associations and exact restoration
    /// dependencies. Labels, generic hashes and archive parsing are insufficient.
    ///
    /// # Errors
    /// Refuses unsupported source/native codecs, incomplete original history,
    /// changed owner or counter scope, or a closure exceeding installed limits.
    fn authenticate_complete_original_lineage_archive(
        &self,
        _scope: CompleteOriginalArchiveValidation<'_>,
    ) -> Result<(), StateError> {
        Err(refused(
            "installed complete original native capture/adoption codec is unsupported",
        ))
    }

    /// Names additional known immutable roots required by the selected model capture.
    ///
    /// The installed policy must bind these roots to the actual accepted runtime,
    /// scheduler and source graph. It must enforce the occurrence ceiling before
    /// allocating the returned vector. Core authenticates their complete typed
    /// closure and charges archive credits before any native capture callback.
    /// An explicitly supported empty roster grants no leaf or native authority.
    ///
    /// # Errors
    /// Refuses unsupported source scope, changed original journals, unknown roots
    /// or a roster exceeding the supplied preallocation ceiling.
    fn original_lineage_capture_immutable_roots(
        &self,
        _graph: &AdmittedGraph,
        _runtime: &crate::node_contract::OriginalLineageRuntimeRecord,
        _scheduler: &crate::node_scheduling::SchedulingSnapshot,
        _maximum: usize,
    ) -> Result<Vec<crucible_node_format::ContentRef>, StateError> {
        Err(refused(
            "installed original-lineage immutable root codec is unsupported",
        ))
    }

    /// Authenticates one original typed body and its complete selected dependency row.
    ///
    /// Missing codec support must refuse; an empty row requires positive leaf
    /// validation. The bound applies before constructing the returned vector.
    ///
    /// # Errors
    /// Refuses unknown body roles, changed original bytes or excessive adjacency.
    fn original_lineage_capture_dependencies(
        &self,
        _graph: &AdmittedGraph,
        _reference: &crucible_node_format::ContentRef,
        _bytes: &[u8],
        _maximum: usize,
    ) -> Result<Vec<crucible_node_format::ContentRef>, StateError> {
        Err(refused(
            "installed original-lineage dependency codec is unsupported",
        ))
    }

    /// Resolves installed support for the exact selected native semantic closure.
    ///
    /// Missing support preserves refusal before native capture or allocation.
    fn extension_preservation_policy(&self) -> Option<&dyn NativeExtensionPreservationPolicy> {
        None
    }

    /// Authenticates complete original native state and streamed artifact closure.
    ///
    /// # Errors
    /// Refuses unsupported backend codecs, altered original prefixes or ACKs,
    /// missing image/resource files, unresolved effects or absent installed proof.
    fn authenticate_source(
        &self,
        graph: &AdmittedGraph,
        owner: &CapturedOwner,
        source: &AuthenticatedNativeSource<'_>,
    ) -> Result<(), StateError>;

    /// Authenticates complete coordinator, runtime, connection and source custody.
    ///
    /// # Errors
    /// Refuses unsupported host state, missing cross-owner transfers or changed
    /// native/coordinator cuts, reservations, queues, payloads or guarantee facts.
    fn authenticate_coordinator(
        &self,
        graph: &AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &crate::node_scheduling::SchedulingSnapshot,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError>;

    /// Computes enforced peak reservations before autonomous allocation.
    ///
    /// # Errors
    /// Refuses unavailable accounting or installed limits that cannot hold the
    /// complete native reconstruction and its backing leases through cleanup.
    fn reservation(
        &self,
        graph: &AdmittedGraph,
        owner: &CapturedOwner,
        source: &AuthenticatedNativeSource<'_>,
        limits: NativeArchiveLimits,
    ) -> Result<RestoreReservations, StateError>;

    /// Constructs an empty nonautonomous capsule retaining the authenticated source.
    ///
    /// No child process, native thread, resource helper or other autonomous
    /// resource may be allocated here. Owner preparation happens only after
    /// `PreparedRestoreAllocation` has installed this capsule under its already
    /// reserved whole-world supervisor. Shared capture owners are prepared once;
    /// the capsule must retain every partial allocation until actual reaping.
    ///
    /// # Errors
    /// Refuses changed fresh bindings, unsupported codecs or unavailable reserved
    /// custody without creating autonomous resources.
    fn empty_staging(
        &self,
        graph: std::rc::Rc<AdmittedGraph>,
        archive: NativeArchiveRecord,
        target: &ActivationRecord,
        reservations: RestoreReservations,
        limits: NativeArchiveLimits,
    ) -> Result<Box<dyn NativeRestoreStaging>, StateError>;
    /// Derives complete geometry from four same-original owning-node occurrences.
    ///
    /// The preflight seal is issued only by the actual runtime after each
    /// readonly capsule loan. Rows alone cannot enroll a mechanism. The concrete
    /// installed factory must conjunct its original source registry and Host2
    /// association with all four actual keys and selected storage facts.
    ///
    /// # Errors
    /// Defaults to refusal. Refuses unsupported source mechanisms, foreign
    /// original owners or incomplete selected whole-world peak accounting.
    fn complete_original_lineage_capture_geometry_from_preflight(
        &self,
        _graph: &AdmittedGraph,
        _runtime: &crate::node_contract::OriginalLineageRuntimeRecord,
        _scheduling: &crate::node_scheduling::SchedulingSnapshot,
        _preflight: &crate::node_contract::PreparedCompleteOriginalCapturePreflight,
        _limits: NativeArchiveLimits,
    ) -> Result<CompleteOriginalCaptureGeometry, StateError> {
        Err(refused(
            "same-original complete capture preflight factory is unsupported",
        ))
    }
}

fn refused(reason: impl Into<String>) -> StateError {
    StateError::new(
        super::StateErrorCode::NativeEvidence,
        "native archive",
        reason,
    )
}

fn require_supported_extensions(graph: &AdmittedGraph) -> Result<(), StateError> {
    if !graph.selected_extensions().is_empty() {
        return Err(refused(
            "native archive edition one has no qualified selected-extension closure codec",
        ));
    }
    Ok(())
}

fn storage_error(error: impl std::fmt::Display) -> StateError {
    StateError::new(
        super::StateErrorCode::Content,
        "native archive storage",
        error.to_string(),
    )
}

fn native_error(error: crate::node_contract::OperationFailure) -> StateError {
    refused(error.reason)
}

fn decode_record<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, StateError> {
    let value =
        crucible_node_format::canonical::parse_json(bytes, maximum).map_err(super::schema)?;
    serde_json::from_value(value).map_err(super::schema)
}

fn owner_state<'a>(
    record: &'a NativeArchiveRecord,
    owner: &Id,
) -> Result<&'a NativeOwnerState, StateError> {
    record
        .index
        .owners
        .iter()
        .find(|state| &state.owner == owner)
        .ok_or_else(|| refused("native archive owner state absent"))
}

mod core_decode_credit;
mod core_future_metadata;

pub use complete_original_source::{
    CompleteInitial15PrebirthControlAttempt, CompleteInitial15PrebirthControlConstructionData,
    CompleteInitial15PrebirthControlInput,
};
