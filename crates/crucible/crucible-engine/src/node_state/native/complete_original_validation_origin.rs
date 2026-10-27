//! Binds pre-sign original writes and selected historical loads to real owners.
//!
//! This borrowed witness has no public constructor or serialized form. It
//! identifies validation purpose, never source acceptance, native restoration or
//! an already-signed write. Canonical index identity remains preservation data.

use super::*;
use crate::node_contract::{NodeRuntime, OriginalLineageWorldCapture};
use crate::node_state::CompleteOriginalArchiveValidation;
use std::thread::{self, ThreadId};

pub(in crate::node_state::native) enum CompleteArchiveValidationOrigin<'a> {
    OriginalWrite {
        process: u32,
        thread: ThreadId,
        writer: &'a NativeArchive,
        record: &'a NativeArchiveRecord,
        captures: &'a OriginalLineageWorldCapture,
        runtime: &'a NodeRuntime,
    },
    SelectedLoad {
        record: &'a NativeArchiveRecord,
    },
}

impl<'a> CompleteArchiveValidationOrigin<'a> {
    pub(in crate::node_state::native) fn original_write(
        writer: &'a NativeArchive,
        record: &'a NativeArchiveRecord,
        captures: &'a OriginalLineageWorldCapture,
        runtime: &'a NodeRuntime,
    ) -> Result<Self, StateError> {
        let origin = Self::OriginalWrite {
            process: std::process::id(),
            thread: thread::current().id(),
            writer,
            record,
            captures,
            runtime,
        };
        origin.authenticate(record)?;
        Ok(origin)
    }

    pub(in crate::node_state::native) fn selected_load(
        record: &'a NativeArchiveRecord,
    ) -> Result<Self, StateError> {
        record
            .authenticate_complete_load_admission()
            .map_err(schema)?;
        Ok(Self::SelectedLoad { record })
    }

    pub(in crate::node_state::native) fn original_write_runtime_data(
        &self,
        actual: &NativeArchiveRecord,
    ) -> Result<Option<&NodeRuntime>, StateError> {
        self.authenticate(actual)?;
        let runtime = match self {
            Self::OriginalWrite { runtime, .. } => Some(*runtime),
            Self::SelectedLoad { .. } => None,
        };
        self.authenticate(actual)?;
        Ok(runtime)
    }

    fn archive_limits_data(
        &self,
        actual: &NativeArchiveRecord,
    ) -> Result<NativeArchiveLimits, StateError> {
        self.authenticate(actual)?;
        let limits = actual.limits;
        self.authenticate(actual)?;
        Ok(limits)
    }

    pub(in crate::node_state::native) fn authenticate(
        &self,
        actual: &NativeArchiveRecord,
    ) -> Result<(), StateError> {
        match self {
            Self::OriginalWrite {
                process,
                thread,
                writer,
                record,
                captures,
                runtime,
            } => {
                // Origin precedes the record directory or runtime/body loan.
                if *process != std::process::id()
                    || *thread != thread::current().id()
                    || !std::ptr::eq(*record, actual)
                {
                    return Err(refused("original write validation origin is foreign"));
                }
                captures
                    .authenticate_pending_archive_write_origin(runtime, actual)
                    .map_err(schema)?;
                actual.authenticate_original_write_directory(writer)
            }
            Self::SelectedLoad { record } => {
                actual
                    .authenticate_complete_load_admission()
                    .map_err(schema)?;
                if !std::ptr::eq(*record, actual) {
                    return Err(refused("selected load validation record was replaced"));
                }
                Ok(())
            }
        }
    }
}

impl NativeArchiveRecord {
    pub(in crate::node_state::native) fn authenticate_original_write_directory(
        &self,
        writer: &NativeArchive,
    ) -> Result<(), StateError> {
        if !Arc::ptr_eq(&self.directory, &writer.directory) || self.index.schema_version != 3 {
            return Err(refused(
                "original write record belongs to another archive directory",
            ));
        }
        Ok(())
    }
}

impl CompleteOriginalArchiveValidation<'_> {
    /// Returns this authenticated writer or selected load's actual archive limits.
    ///
    /// The same record's immutable limits are copied after private validation
    /// origin checks on both sides. A factory intersects them with its own
    /// installed bounds before observing or decoding any vendor cold state.
    /// This data loan grants no allocation, Capture or restoration authority.
    ///
    /// # Errors
    /// Refuses foreign or stale origin, a replaced record, or a selected load
    /// without its actual admission receipt.
    pub fn archive_limits_data(&self) -> Result<NativeArchiveLimits, StateError> {
        self.validation_origin.archive_limits_data(self.archive)
    }

    /// Borrows the actual live runtime retained by this original writer.
    ///
    /// A selected historical load has no original runtime loan and returns
    /// `None`. This distinction comes from the authenticated private validation
    /// origin, never from a supplied byte total or a decoded runtime snapshot.
    /// The factory uses the live owner's exhaustive requested-storage observer
    /// before cold reconstruction; this loan grants no capture or restore right.
    ///
    /// # Errors
    /// Refuses a foreign creator, replaced archive, changed original writer or
    /// capture hold, or a historical load without its actual admission receipt.
    pub fn original_write_runtime_data(&self) -> Result<Option<&NodeRuntime>, StateError> {
        self.validation_origin
            .original_write_runtime_data(self.archive)
    }

    /// Identifies this context's exact index after genuine purpose authentication.
    ///
    /// Original write purpose comes only from the same active completed writer
    /// and exact provisional record; historical purpose requires the actual
    /// selected-load admission. Neither path issues native or target permission.
    /// The caller includes its other retained allocations in the supplied term.
    ///
    /// # Errors
    /// Refuses missing/foreign/stale purpose, a replaced record or directory,
    /// unsupported index grammar, finite canonical storage or record overflow.
    pub fn index_identity_data(
        &self,
        maximum_record_bytes: usize,
        additional_retained_bytes: usize,
    ) -> Result<crucible_node_format::ContentRef, StateError> {
        self.validation_origin.authenticate(self.archive)?;
        let reference = index_identity_data(
            self.archive,
            maximum_record_bytes,
            additional_retained_bytes,
        )?;
        self.validation_origin.authenticate(self.archive)?;
        Ok(reference)
    }
}

pub(in crate::node_state::native) fn index_identity_data(
    record: &NativeArchiveRecord,
    maximum_record_bytes: usize,
    additional_retained_bytes: usize,
) -> Result<crucible_node_format::ContentRef, StateError> {
    use super::complete_original_loader::{add, admit};
    let maximum = record.limits.state.maximum_total_content_bytes;
    const MEDIA: &str = "application/vnd.crucible.native-signed-index-body.v3+json";
    // U64 serialization formats at most 20 decimal bytes even during the
    // counting passes. Admit that scratch before invoking any serializer.
    let fixed = std::mem::size_of::<blake3::Hasher>()
        + std::mem::size_of::<ContentRef>()
        + "blake3-256".len()
        + "cnp.blob.v1".len()
        + 64
        + MEDIA.len()
        + 20;
    let retained = add(
        add(
            record.capture_owned_storage().map_err(schema)?,
            additional_retained_bytes,
        )?,
        fixed,
    )?;
    admit(retained, 0, maximum)?;

    let record_maximum = maximum_record_bytes.min(record.limits.state.maximum_record_bytes);
    super::super::super::closure::bounded_record(record.index.as_ref(), record_maximum)?;
    let value_storage = NodeRuntime::capture_serialization_storage(record.index.as_ref(), maximum)
        .map_err(schema)?;
    let encoded_storage =
        NodeRuntime::capture_encoded_output_storage(record.index.as_ref(), maximum)
            .map_err(schema)?;
    admit(retained, add(value_storage, encoded_storage)?, maximum)?;

    let value = serde_json::to_value(record.index.as_ref()).map_err(schema)?;
    let bytes = canonical::canonical_json(&value).map_err(schema)?;
    if bytes.len() > record_maximum {
        return Err(limit("complete index identity record"));
    }
    let reference = canonical::content_ref(&bytes, MEDIA).map_err(schema)?;
    Ok(reference)
}

#[cfg(test)]
#[path = "complete_original_validation_origin_tests.rs"]
mod tests;

impl NativeArchiveRecord {
    fn authenticate_cold_inventory_limits_data(
        &self,
        limits: NativeArchiveLimits,
    ) -> Result<(), StateError> {
        // The original admission proves graph closure under its own bound. It
        // retains no actual maximum-depth fact, so a tighter depth needs a new
        // bounded admission rather than an uncredited traversal here.
        if limits.state.maximum_dependency_depth < self.limits.state.maximum_dependency_depth {
            return Err(refused(
                "effective archive depth requires narrower original admission",
            ));
        }
        if self.manifest.owners.len() > limits.state.maximum_owners_or_domains
            || self.index.owners.len() > limits.state.maximum_owners_or_domains
            || self.index.objects.len() > limits.state.maximum_content_objects
        {
            return Err(refused(
                "effective archive owner or content inventory exceeds credit",
            ));
        }
        let mut edges = 0usize;
        for object in &self.index.objects {
            if object.reference.length.get() > limits.state.maximum_content_bytes as u64
                || object.dependencies.len() > limits.state.maximum_content_objects
            {
                return Err(refused("effective archive object exceeds content credit"));
            }
            edges = edges
                .checked_add(object.dependencies.len())
                .filter(|edges| *edges <= limits.state.maximum_dependency_edges)
                .ok_or_else(|| refused("effective archive dependency edges exceed credit"))?;
        }
        let mut count = 0usize;
        let mut records = 0u64;
        let mut artifacts = 0u64;
        for owner in &self.index.owners {
            count = count
                .checked_add(1)
                .and_then(|count| count.checked_add(owner.evidence.len()))
                .and_then(|count| count.checked_add(owner.artifacts.len()))
                .filter(|count| *count <= limits.native.maximum_objects)
                .ok_or_else(|| refused("effective native inventory exceeds object credit"))?;
            for reference in std::iter::once(&owner.state).chain(&owner.evidence) {
                if reference.length.get() > limits.native.maximum_record_bytes as u64 {
                    return Err(refused("effective native record exceeds record credit"));
                }
                records = records
                    .checked_add(reference.length.get())
                    .filter(|bytes| *bytes <= limits.native.maximum_total_record_bytes as u64)
                    .ok_or_else(|| refused("effective native records exceed total credit"))?;
            }
            for artifact in &owner.artifacts {
                if artifact.content.length.get() > limits.native.maximum_artifact_bytes {
                    return Err(refused("effective native artifact exceeds file credit"));
                }
                artifacts = artifacts
                    .checked_add(artifact.content.length.get())
                    .filter(|bytes| *bytes <= limits.native.maximum_total_artifact_bytes)
                    .ok_or_else(|| refused("effective native artifacts exceed total credit"))?;
            }
        }
        Ok(())
    }
}

impl CompleteOriginalArchiveValidation<'_> {
    /// Checks actual authenticated inventory against the effective cold limits.
    ///
    /// This borrows existing index, content, manifest and domain rows without
    /// hashing, cloning or traversing the dependency graph. A narrower depth
    /// than the original admission is conservatively refused because no actual
    /// depth fact was retained. These data checks grant no resource installation
    /// right; any later installer must enforce every effective native limit.
    ///
    /// # Errors
    /// Refuses foreign validation origin, excessive actual counts, bytes or
    /// artifacts, arithmetic overflow, or an unproved narrower depth bound.
    pub fn authenticate_cold_inventory_limits_data(
        &self,
        limits: NativeArchiveLimits,
    ) -> Result<(), StateError> {
        self.archive_limits_data()?;
        self.archive
            .authenticate_cold_inventory_limits_data(limits)?;
        if self.graph.ownership_policy().domains.len() > limits.state.maximum_owners_or_domains
            || self.content.object_count() > limits.state.maximum_content_objects
            || self.content.total_bytes() > limits.state.maximum_total_content_bytes
        {
            return Err(refused(
                "effective complete domain or verified content exceeds credit",
            ));
        }
        self.archive_limits_data()?;
        Ok(())
    }
}

#[path = "complete_original_validation_origin/index_geometry17.rs"]
mod index_geometry17;

#[path = "complete_original_validation_origin/index_body17.rs"]
mod index_body17;
