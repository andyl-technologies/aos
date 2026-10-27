//! Observes independent Capture signing DTOs without verifying their proofs.

use super::super::capacities::{
    fields_layout_data, record_typed_capture_data, typed_capture_counter_scratch_data,
};
use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;

impl CaptureSigningOwners {
    /// Keeps every independent context and artifact, including rejected partials.
    ///
    /// # Errors
    /// Refuses exhausted rows, unsupported children or checked geometry/depth overflow.
    pub(in super::super) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            capture_attempted,
            capture_sealed,
            capture_context,
            capture_artifact,
            upload_attempted,
            upload_sealed,
            upload_contexts,
            upload_artifacts,
        } = self;
        census.observe_inline_data(capture_attempted);
        census.observe_inline_data(capture_sealed);
        census.observe_inline_data(upload_attempted);
        census.observe_inline_data(upload_sealed);

        if let Some(context) = capture_context {
            record_typed_capture_data(
                RestoredSettledCaptureTypedOwnerData::CaptureContext(context),
                census,
            )?;
        }
        if let Some(artifact) = capture_artifact {
            record_typed_capture_data(
                RestoredSettledCaptureTypedOwnerData::CaptureArtifact(artifact),
                census,
            )?;
        }
        for context in upload_contexts.iter().flatten() {
            record_typed_capture_data(
                RestoredSettledCaptureTypedOwnerData::UploadContext(context),
                census,
            )?;
        }
        for artifact in upload_artifacts.iter().flatten() {
            record_typed_capture_data(
                RestoredSettledCaptureTypedOwnerData::UploadArtifact(artifact),
                census,
            )?;
        }
        Ok(())
    }

    /// Names the actual context/artifact views and fixed-array iterators.
    pub(in super::super) fn capacity_counter_scratch_data() -> usize {
        type ContextViews<'a> = std::iter::Flatten<
            std::slice::Iter<'a, Option<PacketRestoredSettledCaptureUploadContext>>,
        >;
        type ArtifactViews<'a> = std::iter::Flatten<
            std::slice::Iter<'a, Option<PacketRestoredSettledCaptureUploadArtifact>>,
        >;

        fields_layout_data::<Self, _>(|owner| {
            let Self {
                capture_attempted,
                capture_sealed,
                capture_context,
                capture_artifact,
                upload_attempted,
                upload_sealed,
                upload_contexts,
                upload_artifacts,
            } = owner;
            (
                capture_attempted,
                capture_sealed,
                capture_context,
                capture_artifact,
                upload_attempted,
                upload_sealed,
                upload_contexts,
                upload_artifacts,
            )
        }) + size_of::<&Self>()
            + size_of::<&PacketRestoredSettledCaptureContext>()
            + size_of::<&PacketRestoredSettledCaptureArtifact>()
            + size_of::<&PacketRestoredSettledCaptureUploadContext>()
            + size_of::<&PacketRestoredSettledCaptureUploadArtifact>()
            + size_of::<std::slice::Iter<'_, Option<PacketRestoredSettledCaptureUploadContext>>>()
            + size_of::<std::slice::Iter<'_, Option<PacketRestoredSettledCaptureUploadArtifact>>>()
            + size_of::<ContextViews<'_>>()
            + size_of::<ArtifactViews<'_>>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + typed_capture_counter_scratch_data()
    }
}
