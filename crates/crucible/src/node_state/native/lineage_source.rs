//! Authenticates reference-only coordinator7 beneath the signed typed archive.
//!
//! ```json
//! {"schema_version":7,"runtime":{},"scheduler":{},"world_repeatability":"nondeterministic"}
//! ```
//!
//! The two objects contain complete typed references, not embedded bodies. This
//! reader exposes historical data only. Native/tape validation, fresh target
//! preparation and complete-world publication remain independent requirements.

use std::rc::Rc;

use crucible_node_contract::{ContentRef, Id, Repeatability, Validate, canonical};
use serde::{Deserialize, Serialize};

use crate::node_contract::{OriginalInputLineageLimits, OriginalLineageRuntimeRecord};
use crate::node_scheduling::SchedulingSnapshot;

use super::{
    NativeArchiveRecord, NativeOwnerState, NativeWorldFactory, StateError, VerifiedStateContent,
    refused,
};

/// Identifies the selected reference-only original-lineage coordinator body.
pub const ORIGINAL_LINEAGE_COORDINATOR_MEDIA: &str =
    "application/vnd.crucible.native-coordinator+json;version=7";

/// Identifies complete Runtime7 historical input and permission custody.
pub const ORIGINAL_LINEAGE_RUNTIME_MEDIA: &str =
    "application/vnd.crucible.runtime-original-lineage+json;version=7";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalLineageCoordinator {
    pub schema_version: u16,
    pub runtime: ContentRef,
    pub scheduler: ContentRef,
    pub world_repeatability: Repeatability,
}

/// Borrows complete original lineage data under an authenticated TypedIndex2.
///
/// Its constructor is private. It authenticates saved bytes and roles, not
/// native readiness, physical restoration or applicability to a fresh target.
pub struct AuthenticatedOriginalLineageSource<'a> {
    archive: &'a NativeArchiveRecord,
    owner: &'a NativeOwnerState,
    runtime_reference: ContentRef,
    runtime: Rc<OriginalLineageRuntimeRecord>,
    scheduling: Rc<SchedulingSnapshot>,
    repeatability: Repeatability,
    content: &'a VerifiedStateContent,
}

impl AuthenticatedOriginalLineageSource<'_> {
    /// Borrows the signed native owner's complete original scope.
    pub fn owner(&self) -> &NativeOwnerState {
        self.owner
    }

    /// Borrows the complete original source-capture runtime without minting tokens.
    pub fn runtime(&self) -> &OriginalLineageRuntimeRecord {
        &self.runtime
    }

    /// Borrows the independently typed original Runtime7 identity.
    pub fn runtime_reference(&self) -> &ContentRef {
        &self.runtime_reference
    }

    /// Borrows complete original coordinator scheduling and transfer custody.
    pub fn scheduling(&self) -> &SchedulingSnapshot {
        &self.scheduling
    }

    /// Preserves the original whole-world repeatability classification.
    pub fn world_repeatability(&self) -> Repeatability {
        self.repeatability
    }

    /// Borrows signed complete typed bodies independently of operational namespaces.
    pub fn content(&self) -> &VerifiedStateContent {
        self.content
    }

    /// Borrows the signed archive whose backing remains owned during inspection.
    pub fn archive(&self) -> &NativeArchiveRecord {
        self.archive
    }

    /// Borrows this owner's original native or tape ledger.
    ///
    /// # Errors
    /// Refuses absent original native state under the exact signed typed role.
    pub fn native(&self) -> Result<&[u8], StateError> {
        self.content
            .get(&self.owner.state)
            .ok_or_else(|| refused("original lineage native ledger is absent"))
    }
}

impl NativeArchiveRecord {
    /// Authenticates complete reference-only coordinator7 source data.
    ///
    /// Aggregate typed role extents are checked before reading archive bodies.
    /// Every supplied body is independently compared with its signed backing;
    /// hashes, parser DTOs and source-host paths cannot mint this source seal.
    /// Legacy coordinator readers remain unchanged and refuse edition seven.
    ///
    /// # Errors
    /// Refuses legacy inventories, combined selected extensions, another media
    /// role or coordinator edition, absent/conflicting signed bodies, exceeded
    /// credits, inconsistent cuts or source scope, and missing owner journals.
    pub fn authenticated_original_lineage_source<'a>(
        &'a self,
        owner: &Id,
        content: &'a VerifiedStateContent,
        lineage_limits: OriginalInputLineageLimits,
    ) -> Result<AuthenticatedOriginalLineageSource<'a>, StateError> {
        if self.index.schema_version != 2
            || self.index.selected_extensions.is_some()
            || self.manifest.coordinator_state_ref.media_type != ORIGINAL_LINEAGE_COORDINATOR_MEDIA
        {
            return Err(refused("unsupported original lineage archive selection"));
        }
        self.decode_original_lineage_source(owner, content, lineage_limits)
    }

    /// Authenticates a selected original-lineage source through its installed factory.
    ///
    /// The original graph, signed selection root and all typed policy/body rows
    /// must agree before the separately installed coordinator7/native policy is
    /// called. Selection markers and parser DTOs grant no native authority.
    /// The unselected reader continues to refuse every selected source.
    ///
    /// # Errors
    /// Refuses foreign worlds, unsupported selected policy, exceeded aggregate
    /// source credits, changed original closure or native journal authentication.
    pub fn authenticated_selected_original_lineage_source<'a>(
        &'a self,
        owner: &Id,
        content: &'a VerifiedStateContent,
        lineage_limits: OriginalInputLineageLimits,
        graph: &crate::node_admission::AdmittedGraph,
        factory: &dyn super::NativeWorldFactory,
    ) -> Result<AuthenticatedOriginalLineageSource<'a>, StateError> {
        // The complete signed closure includes independently installed code.
        // Archive geometry is credited before policy callbacks or body reads;
        // Runtime7 retains its separate original-input limits during decoding.
        pin::pin_archive_credit(content, self.limits.state)?;
        if self.index.schema_version != 2
            || self.index.selected_extensions.is_none()
            || graph.selected_extensions().is_empty()
            || graph.world_binding_hash() != &self.manifest.world_binding_hash
            || self.manifest.coordinator_state_ref.media_type != ORIGINAL_LINEAGE_COORDINATOR_MEDIA
        {
            return Err(refused("foreign or unsupported selected lineage source"));
        }
        let selected = super::extensions::archive::authenticate_archive(self, graph, factory)?;
        if selected.is_none() {
            return Err(refused("installed original selected closure absent"));
        }
        let source = self.decode_original_lineage_source(owner, content, lineage_limits)?;
        factory.authenticate_original_lineage_source(graph, &source)?;
        Ok(source)
    }

    fn decode_original_lineage_source<'a>(
        &'a self,
        owner: &Id,
        content: &'a VerifiedStateContent,
        lineage_limits: OriginalInputLineageLimits,
    ) -> Result<AuthenticatedOriginalLineageSource<'a>, StateError> {
        authenticate_content(self, content)?;
        let maximum = self.limits.state.maximum_record_bytes;
        let coordinator: OriginalLineageCoordinator =
            decode_original(content, &self.manifest.coordinator_state_ref, maximum)?;
        coordinator.validate()?;
        validate_coordinator_row(self, &coordinator)?;
        let runtime: OriginalLineageRuntimeRecord =
            decode_original(content, &coordinator.runtime, maximum)?;
        let supported = OriginalInputLineageLimits::default();
        let lineage_limits = OriginalInputLineageLimits {
            maximum_objects: lineage_limits
                .maximum_objects
                .min(supported.maximum_objects),
            maximum_bytes: lineage_limits.maximum_bytes.min(supported.maximum_bytes),
            maximum_edges: lineage_limits.maximum_edges.min(supported.maximum_edges),
        };
        runtime
            .validate_original_bodies(content, lineage_limits, maximum)
            .map_err(|error| refused(error.to_string()))?;
        let scheduling: SchedulingSnapshot =
            decode_original(content, &coordinator.scheduler, maximum)?;
        validate_source_scope(self, &runtime, &scheduling)?;
        let state = super::owner_state(self, owner)?;
        if state.cut != runtime.capture_cut
            || state.participants.is_empty()
            || state.participants.iter().any(|node| {
                !runtime
                    .operations
                    .iter()
                    .any(|entry| &entry.route.node == node)
            })
            || state
                .evidence
                .iter()
                .any(|reference| content.get(reference).is_none())
            || content.get(&state.state).is_none()
        {
            return Err(refused(
                "original lineage native journal roster is incomplete",
            ));
        }
        Ok(AuthenticatedOriginalLineageSource {
            archive: self,
            owner: state,
            runtime_reference: coordinator.runtime,
            runtime: Rc::new(runtime),
            scheduling: Rc::new(scheduling),
            repeatability: coordinator.world_repeatability,
            content,
        })
    }
}

fn authenticate_content(
    archive: &NativeArchiveRecord,
    content: &VerifiedStateContent,
) -> Result<(), StateError> {
    if content.object_count() != archive.index.objects.len() {
        return Err(refused("original lineage signed closure is incomplete"));
    }
    let mut total = 0usize;
    for (reference, bytes) in content.entries() {
        let extent = usize::try_from(reference.length.get())
            .map_err(|_| refused("original lineage body extent overflows"))?;
        total = total
            .checked_add(extent)
            .filter(|total| *total <= archive.limits.state.maximum_total_content_bytes)
            .ok_or_else(|| refused("original lineage aggregate source credit exhausted"))?;
        if extent > archive.limits.state.maximum_content_bytes
            || bytes.len() != extent
            || !archive
                .index
                .objects
                .iter()
                .any(|object| &object.reference == reference)
        {
            return Err(refused(
                "original lineage body role is outside signed closure",
            ));
        }
    }
    // The complete aggregate is credited before the first backing read/copy.
    for (reference, bytes) in content.entries() {
        let original = archive.object(reference, bytes.len())?;
        if original != bytes {
            return Err(refused("original lineage signed body changed"));
        }
    }
    Ok(())
}

fn decode_original<T: serde::de::DeserializeOwned>(
    content: &VerifiedStateContent,
    reference: &ContentRef,
    maximum: usize,
) -> Result<T, StateError> {
    let extent = usize::try_from(reference.length.get())
        .map_err(|_| refused("original lineage record extent overflows"))?;
    if extent > maximum {
        return Err(refused("original lineage record credit exhausted"));
    }
    let bytes = content
        .get(reference)
        .ok_or_else(|| refused("original lineage typed record is absent"))?;
    let value = canonical::parse_json(bytes, maximum).map_err(super::super::schema)?;
    if canonical::canonical_json(&value).map_err(super::super::schema)? != bytes {
        return Err(refused("original lineage record is not canonical"));
    }
    serde_json::from_value(value).map_err(super::super::schema)
}

fn validate_source_scope(
    archive: &NativeArchiveRecord,
    runtime: &OriginalLineageRuntimeRecord,
    scheduling: &SchedulingSnapshot,
) -> Result<(), StateError> {
    let source = &runtime.source_activation;
    if scheduling.schema_version != 1
        || runtime.capture_cut != archive.manifest.cut
        || runtime.capture_ordinal != archive.manifest.event_ordinal
        || source.world_binding_hash != archive.manifest.world_binding_hash
        || runtime.capture_cut != scheduling.capture_cut
        || runtime.capture_ordinal != scheduling.capture_ordinal
        || source.activation_id != scheduling.source_activation_id
        || source.generation != scheduling.source_generation
        || source.boundary != scheduling.source_boundary
        || source.world_binding_hash != scheduling.world_binding_hash
        || source.owners.len() != scheduling.source_owners.len()
        || !source
            .owners
            .iter()
            .zip(&scheduling.source_owners)
            .all(|(owner, saved)| {
                owner.owner == saved.owner
                    && owner.incarnation == saved.incarnation
                    && owner.generation == saved.generation
            })
    {
        return Err(refused(
            "original lineage source capture and scheduling scope differ",
        ));
    }
    Ok(())
}

impl OriginalLineageCoordinator {
    fn validate(&self) -> Result<(), StateError> {
        self.runtime.validate().map_err(super::super::schema)?;
        self.scheduler.validate().map_err(super::super::schema)?;
        if self.schema_version != 7
            || self.runtime.media_type != ORIGINAL_LINEAGE_RUNTIME_MEDIA
            || self.scheduler.media_type != "application/json"
            || self.world_repeatability == Repeatability::Qualified
        {
            return Err(refused("unsupported original lineage coordinator scope"));
        }
        Ok(())
    }
}

fn validate_coordinator_row(
    archive: &NativeArchiveRecord,
    coordinator: &OriginalLineageCoordinator,
) -> Result<(), StateError> {
    let row = archive
        .index
        .objects
        .iter()
        .find(|object| object.reference == archive.manifest.coordinator_state_ref)
        .ok_or_else(|| refused("original lineage coordinator row is absent"))?;
    let mut expected = [&coordinator.runtime, &coordinator.scheduler];
    expected.sort();
    if !row.dependencies.iter().eq(expected) {
        return Err(refused(
            "original lineage coordinator dependency row differs",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "lineage_source_tests.rs"]
mod tests;

#[path = "lineage_source_pin.rs"]
mod pin;

pub use pin::{OriginalLineageSourcePinFailure, PinnedOriginalLineageSource};
