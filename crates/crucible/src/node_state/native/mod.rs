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
mod driver;
pub(crate) mod extensions;
mod lineage_capture;
mod lineage_inventory;
mod lineage_roots;
mod lineage_source;
mod storage;
mod typed_index;

pub(super) use capture::source_epoch_evidence;

#[cfg(test)]
mod tests;

use crucible_node_contract::{CapturedOwner, Id};

use crate::{
    node_admission::AdmittedGraph,
    node_contract::{
        ActivationRecord, NativeCaptureArtifact, NativeCaptureLimits, RuntimeSnapshot,
    },
};

use super::{
    NativeRestoreStaging, RestoreReservations, StateError, StateLimits, VerifiedStateContent,
};

pub use driver::NativeWorldRestoreDriver;
pub use extensions::NativeExtensionPreservationPolicy;
pub use lineage_capture::OriginalLineageCaptureRequest;
pub use lineage_source::{
    AuthenticatedOriginalLineageSource, ORIGINAL_LINEAGE_COORDINATOR_MEDIA,
    ORIGINAL_LINEAGE_RUNTIME_MEDIA, OriginalLineageSourcePinFailure, PinnedOriginalLineageSource,
};
pub use storage::{NativeArchive, NativeArchiveRecord, NativeArtifactState, NativeOwnerState};

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
    ) -> Result<Vec<crucible_node_contract::ContentRef>, StateError> {
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
        _reference: &crucible_node_contract::ContentRef,
        _bytes: &[u8],
        _maximum: usize,
    ) -> Result<Vec<crucible_node_contract::ContentRef>, StateError> {
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
        crucible_node_contract::canonical::parse_json(bytes, maximum).map_err(super::schema)?;
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
