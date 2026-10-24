//! Borrows the exact retained Capture17 phase without issuing an action.
//!
//! The live native owner uses these loans for Source authentication and the
//! finite same-Boot ticket chronology. A typed context is correspondence data;
//! its mere presence never establishes that its MAC was verified.

use super::*;

/// Lends the already retained closed phase and its actual assigned context.
pub(crate) enum NativeCapture17PhaseData<'a> {
    UploadBegin {
        body: &'a BlobBeginRequest,
        artifact: &'a PacketRestoredSettledCaptureUploadArtifact,
        context: &'a PacketRestoredSettledCaptureUploadContext,
    },
    Chunk {
        body: &'a BlobChunkRequest,
        continuation: &'a PacketRestoredSettledCaptureUploadContinuation,
    },
    Finish {
        body: &'a BlobFinishRequest,
        continuation: &'a PacketRestoredSettledCaptureUploadContinuation,
    },
    Capture {
        body: &'a BeginRequest,
        artifact: &'a PacketRestoredSettledCaptureArtifact,
        context: &'a PacketRestoredSettledCaptureContext,
    },
    Confirmation {
        body: &'a PollRequest,
        request: &'a PacketRestoredSettledAfterConfirmationRequest,
    },
}

impl NativeRestoredSettledCaptureAttempt {
    /// Borrows a complete typed phase from this same retained occurrence.
    ///
    /// # Errors
    /// Refuses failed/incomplete custody or a context that differs from its
    /// retained artifact. This method neither verifies a MAC nor spends credit.
    pub(crate) fn phase17_data(&self) -> Result<NativeCapture17PhaseData<'_>, ProviderError> {
        if self.stage != Stage::Typed {
            return Err(invalid());
        }
        match self.body.as_ref().ok_or_else(invalid)? {
            Body::BlobBegin(body) => {
                let artifact = self.upload.as_ref().ok_or_else(invalid)?;
                let context = self.upload_context.as_ref().ok_or_else(invalid)?;
                if context.request != artifact.request {
                    return Err(invalid());
                }
                Ok(NativeCapture17PhaseData::UploadBegin {
                    body,
                    artifact,
                    context,
                })
            }
            Body::BlobChunk(body) => Ok(NativeCapture17PhaseData::Chunk {
                body,
                continuation: self.continuation.as_ref().ok_or_else(invalid)?,
            }),
            Body::BlobFinish(body) => Ok(NativeCapture17PhaseData::Finish {
                body,
                continuation: self.continuation.as_ref().ok_or_else(invalid)?,
            }),
            Body::Capture(body) => {
                let artifact = self.capture.as_ref().ok_or_else(invalid)?;
                let context = self.capture_context.as_ref().ok_or_else(invalid)?;
                if context.request != artifact.request {
                    return Err(invalid());
                }
                Ok(NativeCapture17PhaseData::Capture {
                    body,
                    artifact,
                    context,
                })
            }
            Body::Confirmation(body) => Ok(NativeCapture17PhaseData::Confirmation {
                body,
                request: self.confirmation.as_ref().ok_or_else(invalid)?,
            }),
        }
    }

    /// Verifies an already retained assigned upload against the actual Boot key.
    ///
    /// A later continuation rechecks its seed's MAC instead of treating a
    /// historical `Context` or its typed stage as proof of a previous check.
    ///
    /// # Errors
    /// Refuses another phase, changed assigned original or invalid Source MAC.
    pub(crate) fn authenticate_retained_upload_source17_data(
        &self,
        key: &[u8; 32],
        maximum_frame: usize,
    ) -> Result<(), ProviderError> {
        let NativeCapture17PhaseData::UploadBegin {
            artifact, context, ..
        } = self.phase17_data()?
        else {
            return Err(invalid());
        };
        let digest = restored_settled_capture_upload_assigned_request_digest_data(
            self.original_data()?,
            maximum_frame,
        )?;
        if context.assigned_request.as_slice() != digest {
            return Err(invalid());
        }
        crate::reference_packet::service::restored_settled_capture::upload::verify_restored_settled_capture_upload_proof_data(
            key,
            context,
            &artifact.proof,
        )
    }
}

/// Names only the borrowed phase/context and returned fixed views.
pub(crate) const fn capture17_phase_counter_scratch_data() -> usize {
    size_of::<NativeCapture17PhaseData<'static>>()
        + size_of::<Result<NativeCapture17PhaseData<'static>, ProviderError>>()
        + size_of::<[u8; 32]>()
        + size_of::<Result<[u8; 32], ProviderError>>()
}
