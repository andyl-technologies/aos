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
    ) -> Result<crucible_node_contract::ContentRef, StateError> {
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
) -> Result<crucible_node_contract::ContentRef, StateError> {
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
