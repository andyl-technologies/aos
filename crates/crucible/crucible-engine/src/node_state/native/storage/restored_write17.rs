//! Retains a writer-private current17 record until strict terminal completion.
//!
//! This capsule moves the real writer Manifest and Index into owned metadata.
//! It performs no decoder, filesystem read, MAC or historical validation. Its
//! record can only be borrowed for actual completed-output and verifier guards;
//! persistence requires the genuine Scope ledger's completed conjunction.

use super::*;
use crate::node_contract::{
    NodeRuntime, OriginalLineageWorldCapture, PreparedRestoredHost17Capture,
    RestoredCollectingCaptureScope17,
};
use std::rc::Rc;

/// Keeps a pending record private to the actual enclosing write operation.
pub(in crate::node_state::native) struct PendingRestoredArchive17<'a> {
    archive: &'a NativeArchive,
    record: NativeArchiveRecord,
}

impl NativeArchive {
    /// Retains the actual already-encoded writer records before pure decoding.
    ///
    /// The caller independently funds the cloned Index, cloned Manifest and
    /// Arc header before this constructor. Neither this capsule nor a record
    /// loan is an archive load receipt or a completed Source/native grant.
    pub(in crate::node_state::native) fn pending_restored_write17_record_data(
        &self,
        index: Index,
        manifest: CaptureManifest,
        runtime: &NodeRuntime,
        capture: &OriginalLineageWorldCapture,
        scope: &RestoredCollectingCaptureScope17<'_>,
        prepared: &Rc<PreparedRestoredHost17Capture>,
    ) -> Result<PendingRestoredArchive17<'_>, StateError> {
        scope.authenticate_runtime_data(runtime).map_err(schema)?;
        if index.schema_version != 3
            || index.selected_extensions.is_some()
            || manifest.coordinator_state_ref.media_type
                != crucible_node_transport::reference_packet::service::complete_restore::settled_recapture::COORDINATOR_CHECKPOINT17_MEDIA
        {
            return Err(refused("pending current17 writer lost its exact record family"));
        }
        let record = NativeArchiveRecord {
            complete_load: None,
            index: Arc::new(index),
            manifest,
            directory: Arc::clone(&self.directory),
            limits: self.limits,
        };
        capture
            .authenticate_restored_terminal_data(runtime, scope, &record, prepared)
            .map_err(schema)?;
        Ok(PendingRestoredArchive17 {
            archive: self,
            record,
        })
    }
}

impl PendingRestoredArchive17<'_> {
    /// Borrows only the actual local writer metadata for strict terminal checks.
    pub(in crate::node_state::native) fn record_data(&self) -> &NativeArchiveRecord {
        &self.record
    }

    /// Signs the already-validated actual record without repeating pure decoders.
    ///
    /// The complete strict validator checks immutable body/fullref equality and
    /// all Source/native owners before the Scope can reach terminal completion.
    /// The shared persistence tail preserves the existing MAC and disk behavior.
    pub(in crate::node_state::native) fn persist_data(
        self,
        runtime: &NodeRuntime,
        capture: &OriginalLineageWorldCapture,
        scope: &RestoredCollectingCaptureScope17<'_>,
        prepared: &Rc<PreparedRestoredHost17Capture>,
    ) -> Result<NativeArchiveRecord, StateError> {
        scope
            .require_terminal_validation_completed_data(runtime, capture, &self.record)
            .map_err(schema)?;
        capture
            .authenticate_restored_terminal_data(runtime, scope, &self.record, prepared)
            .map_err(schema)?;
        self.archive.persist_record_data(self.record)
    }
}
