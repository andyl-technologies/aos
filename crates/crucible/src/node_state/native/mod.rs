//! Backend-bound installed native archives and inactive complete-world restoration.
//!
//! Native archive edition one signs a bounded index of small core records and
//! separately streamed image/resource files. It is independent of the existing
//! host archive edition. Installed factories authenticate actual native codecs,
//! original operation custody and complete artifact coverage before a signature
//! can be issued or an autonomous resource can be reconstructed.

mod capture;
mod driver;
mod storage;

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
