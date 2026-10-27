//! Retains genuine assigned Capture17 proofs before the SDK seal can fail.
//!
//! The owning Source Capture effect must already hold its real ticket/Window
//! claim, complete admitted row and SourceRead. These private helpers only seal
//! actual SDK-assigned originals. They neither allocate a grant nor publish IO.
//! Every Source context/artifact remains owned independently of the SDK copy.

#[path = "signing/capacities.rs"]
mod capacities;

use crate::node_adapters::cnp::PacketCompleteSemanticSource;
use crate::node_contract::RuntimeError;
use crucible_node_format::Bytes;
use crucible_node_transport::client::{
    OriginalCanonicalBlobAckEmitter, OriginalCompletedRestoredSettledCaptureData,
    OriginalRestoredSettledCaptureConstructionData, PreparedOriginalRestoredSettledCapture,
    PreparedRestoredSettledCaptureAuxiliaryOriginal, RestoredSettledCaptureTypedOwnerData,
};
use crucible_node_transport::reference_packet::service::restored_settled_capture::{
    MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES, PacketRestoredSettledCaptureArtifact,
    PacketRestoredSettledCaptureContext, restored_settled_capture_assigned_request_digest_data,
    restored_settled_capture_context_schema_data, restored_settled_capture_proof_data,
    upload::{
        PacketRestoredSettledCaptureUploadArtifact, PacketRestoredSettledCaptureUploadContext,
        PacketRestoredSettledCaptureUploadOrdinal, PacketRestoredSettledCaptureUploadRequest,
        restored_settled_capture_upload_assigned_request_digest_data,
        restored_settled_capture_upload_proof_data,
        restored_settled_capture_upload_schema_ids_data,
    },
    verify_restored_settled_capture_proof_data,
};
use std::mem::size_of;

/// Owns actual partials; no field is reconstructed from serialized approval DATA.
pub(super) struct CaptureSigningOwners {
    capture_attempted: bool,
    capture_sealed: bool,
    capture_context: Option<PacketRestoredSettledCaptureContext>,
    capture_artifact: Option<PacketRestoredSettledCaptureArtifact>,
    upload_attempted: [bool; 2],
    upload_sealed: [bool; 2],
    upload_contexts: [Option<PacketRestoredSettledCaptureUploadContext>; 2],
    upload_artifacts: [Option<PacketRestoredSettledCaptureUploadArtifact>; 2],
}

impl CaptureSigningOwners {
    pub(super) fn new_data() -> Self {
        Self {
            capture_attempted: false,
            capture_sealed: false,
            capture_context: None,
            capture_artifact: None,
            upload_attempted: [false; 2],
            upload_sealed: [false; 2],
            upload_contexts: [None, None],
            upload_artifacts: [None, None],
        }
    }

    pub(super) fn seal_capture_data(
        &mut self,
        prepared: &mut PreparedOriginalRestoredSettledCapture<'_>,
        emitter: &OriginalCanonicalBlobAckEmitter,
        key: &[u8; 32],
        sdk: &OriginalRestoredSettledCaptureConstructionData,
        maximum_frame_bytes: usize,
    ) -> Result<(), RuntimeError> {
        if self.capture_attempted || self.upload_sealed != [true; 2] {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.capture_attempted = true;

        // The digest covers this actual assigned Envelope and unsigned request.
        // Source and SDK contexts/artifacts are independent retained owners; the
        // Source construction quote must fund every clone before this call.
        let assigned = restored_settled_capture_assigned_request_digest_data(
            prepared
                .original_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            maximum_frame_bytes,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.capture_context = Some(PacketRestoredSettledCaptureContext {
            schema: restored_settled_capture_context_schema_data().into(),
            request: prepared
                .partial_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?
                .request_data()
                .clone(),
            assigned_request: Bytes::new(assigned.to_vec()),
        });
        let context = self
            .capture_context
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        sdk.authenticate_typed_owner_data(&RestoredSettledCaptureTypedOwnerData::CaptureContext(
            context,
        ))
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let proof = restored_settled_capture_proof_data(key, context)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.capture_artifact = Some(PacketRestoredSettledCaptureArtifact {
            request: context.request.clone(),
            proof,
        });
        let artifact = self
            .capture_artifact
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        sdk.authenticate_typed_owner_data(&RestoredSettledCaptureTypedOwnerData::CaptureArtifact(
            artifact,
        ))
        .map_err(|_| RuntimeError::ResourceLimit)?;
        prepared
            .seal_data(emitter, artifact.clone())
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.capture_sealed = true;
        Ok(())
    }

    pub(super) fn seal_upload_data(
        &mut self,
        prepared: &mut PreparedRestoredSettledCaptureAuxiliaryOriginal<'_>,
        emitter: &OriginalCanonicalBlobAckEmitter,
        key: &[u8; 32],
        request: &PacketRestoredSettledCaptureUploadRequest,
        sdk: &OriginalRestoredSettledCaptureConstructionData,
        maximum_frame_bytes: usize,
    ) -> Result<(), RuntimeError> {
        let index = match request.ordinal {
            PacketRestoredSettledCaptureUploadOrdinal::HistoryPrefix => 0,
            PacketRestoredSettledCaptureUploadOrdinal::RuntimeObject => 1,
        };
        if self.capture_attempted
            || self.upload_attempted[index]
            || index == 1 && !self.upload_sealed[0]
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.upload_attempted[index] = true;

        let assigned = restored_settled_capture_upload_assigned_request_digest_data(
            prepared
                .original_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            maximum_frame_bytes,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.upload_contexts[index] = Some(PacketRestoredSettledCaptureUploadContext {
            schema: restored_settled_capture_upload_schema_ids_data().1.into(),
            request: request.clone(),
            assigned_request: Bytes::new(assigned.to_vec()),
        });
        let context = self.upload_contexts[index]
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        sdk.authenticate_typed_owner_data(&RestoredSettledCaptureTypedOwnerData::UploadContext(
            context,
        ))
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let proof = restored_settled_capture_upload_proof_data(key, context)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.upload_artifacts[index] = Some(PacketRestoredSettledCaptureUploadArtifact {
            request: context.request.clone(),
            proof,
        });
        let artifact = self.upload_artifacts[index]
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        sdk.authenticate_typed_owner_data(&RestoredSettledCaptureTypedOwnerData::UploadArtifact(
            artifact,
        ))
        .map_err(|_| RuntimeError::ResourceLimit)?;
        prepared
            .seal_data(emitter, artifact.clone())
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.upload_sealed[index] = true;
        Ok(())
    }

    pub(super) fn authenticate_capture_data(
        &self,
        completed: &OriginalCompletedRestoredSettledCaptureData<'_>,
        key: &[u8; 32],
        maximum_frame: usize,
    ) -> Result<(), RuntimeError> {
        if !self.capture_attempted || !self.capture_sealed || self.upload_sealed != [true; 2] {
            return Err(RuntimeError::OutstandingObligations);
        }
        let context = self
            .capture_context
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let artifact = self
            .capture_artifact
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let (original, _, _) = completed.capture_pair_data();
        let assigned =
            restored_settled_capture_assigned_request_digest_data(original, maximum_frame)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        if &artifact.request != completed.request_data()
            || context.request != artifact.request
            || context.assigned_request.as_slice() != assigned.as_slice()
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        verify_restored_settled_capture_proof_data(key, context, &artifact.proof)
            .map_err(|_| RuntimeError::InvalidReceipt)
    }

    /// Quotes this Source's three separate context/artifact pairs prospectively.
    ///
    /// Each future owner is bounded by its defining Provider family projection.
    /// The Source retains these copies independently of all SDK copies; later
    /// actual metadata must pass that same row before any SDK seal.
    pub(super) fn future_storage_data(
        sdk: &OriginalRestoredSettledCaptureConstructionData,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        use crucible_node_transport::retained_metadata::serialization_storage::original_json_value_storage_extent_data;

        let context = sdk
            .maximum_context_backing_bytes_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let artifact = sdk
            .maximum_artifact_backing_bytes_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let mut retained = 0usize;
        for bytes in [context, artifact, context, artifact, context, artifact] {
            retained = retained
                .checked_add(bytes)
                .filter(|n| *n <= maximum)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        let assigned = original_json_value_storage_extent_data(sdk.maximum_frame_bytes_data())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let proof = original_json_value_storage_extent_data(
            MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let assigned = assigned
            .canonical_pass_requested_bytes()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let proof = proof
            .canonical_pass_requested_bytes()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let transient = assigned
            .checked_add(proof)
            .ok_or(RuntimeError::ResourceLimit)?;
        let scratch = Self::counter_scratch_data();
        retained
            .checked_add(transient)
            .and_then(|n| n.checked_add(scratch))
            .filter(|n| *n <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok((retained, transient, scratch))
    }

    /// Counts actual independent backing, including a rejected seal's proof partials.
    pub(super) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self {
            capture_attempted: _,
            capture_sealed: _,
            capture_context,
            capture_artifact,
            upload_attempted: _,
            upload_sealed: _,
            upload_contexts,
            upload_artifacts,
        } = self;
        let mut retained = 0usize;
        for owner in [
            capture_context
                .as_ref()
                .map(RestoredSettledCaptureTypedOwnerData::CaptureContext),
            capture_artifact
                .as_ref()
                .map(RestoredSettledCaptureTypedOwnerData::CaptureArtifact),
            upload_contexts[0]
                .as_ref()
                .map(RestoredSettledCaptureTypedOwnerData::UploadContext),
            upload_contexts[1]
                .as_ref()
                .map(RestoredSettledCaptureTypedOwnerData::UploadContext),
            upload_artifacts[0]
                .as_ref()
                .map(RestoredSettledCaptureTypedOwnerData::UploadArtifact),
            upload_artifacts[1]
                .as_ref()
                .map(RestoredSettledCaptureTypedOwnerData::UploadArtifact),
        ]
        .into_iter()
        .flatten()
        {
            let facts = owner
                .retained_metadata_data()
                .map_err(|_| RuntimeError::ResourceLimit)?;
            let bytes =
                PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                    &facts, maximum,
                )?;
            retained = retained
                .checked_add(bytes)
                .filter(|total| *total <= maximum)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok(retained)
    }

    pub(super) fn counter_scratch_data() -> usize {
        size_of::<Self>() + size_of::<Option<Self>>()
            + size_of::<&mut Self>()
            + size_of::<&mut PreparedOriginalRestoredSettledCapture<'static>>()
            + size_of::<&mut PreparedRestoredSettledCaptureAuxiliaryOriginal<'static>>()
            + size_of::<&OriginalCanonicalBlobAckEmitter>() + size_of::<&[u8; 32]>()
            + size_of::<&PacketRestoredSettledCaptureUploadRequest>()
            + size_of::<&PacketRestoredSettledCaptureContext>()
            + size_of::<&PacketRestoredSettledCaptureArtifact>()
            + size_of::<&PacketRestoredSettledCaptureUploadContext>()
            + size_of::<&PacketRestoredSettledCaptureUploadArtifact>()
            + size_of::<[u8; 32]>() + size_of::<usize>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<[Option<RestoredSettledCaptureTypedOwnerData<'static>>; 6]>()
            + size_of::<std::iter::Flatten<std::array::IntoIter<Option<RestoredSettledCaptureTypedOwnerData<'static>>, 6>>>()
            + size_of::<crucible_node_transport::retained_metadata::RetainedProtocolMetadataFacts>()
            + size_of::<Result<crucible_node_transport::retained_metadata::RetainedProtocolMetadataFacts, crucible_node_transport::ProviderError>>()
            + RestoredSettledCaptureTypedOwnerData::counter_scratch_data()
            + size_of::<Result<[u8; 32], crucible_node_transport::ProviderError>>()
            + crucible_node_transport::reference_packet::service::restored_settled_capture::restored_settled_capture_contract_counter_scratch_data()
            + crucible_node_transport::reference_packet::service::restored_settled_capture::upload::restored_settled_capture_upload_counter_scratch_data()
    }
}
