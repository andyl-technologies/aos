//! Borrows defining Capture17 DTO backing without exposing a metadata observer.

use super::*;
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};

/// Borrows one actual separately retained Source or SDK proof owner as DATA.
///
/// These variants expose no live claim, signing key, native permit or constructor.
pub enum RestoredSettledCaptureTypedOwnerData<'a> {
    /// Borrows the complete request bound to an actual Capture ticket.
    CaptureRequest(&'a PacketRestoredSettledCaptureRequest),
    /// Borrows a retained context for an actually assigned Capture Envelope.
    CaptureContext(&'a PacketRestoredSettledCaptureContext),
    /// Borrows a retained signed Capture artifact, including failed proof partials.
    CaptureArtifact(&'a PacketRestoredSettledCaptureArtifact),
    /// Borrows one exact independent auxiliary ordinal declaration.
    UploadRequest(&'a PacketRestoredSettledCaptureUploadRequest),
    /// Borrows a retained context for its actual BlobBegin Envelope.
    UploadContext(&'a PacketRestoredSettledCaptureUploadContext),
    /// Borrows an independently retained signed upload artifact.
    UploadArtifact(&'a PacketRestoredSettledCaptureUploadArtifact),
    /// Borrows the exact fourth-Poll request bound to the proof-filled Capture.
    ConfirmationRequest(&'a PacketRestoredSettledAfterConfirmationRequest),
    /// Borrows the complete independently retained fourth receipt.
    ConfirmationReceipt(&'a PacketRestoredSettledAfterConfirmationReceipt),
}

impl RestoredSettledCaptureTypedOwnerData<'_> {
    /// Counts the complete defining typed walk without cloning or serialization.
    ///
    /// # Errors
    /// Refuses checked traversal, depth or requested-layout arithmetic overflow.
    pub fn retained_metadata_data(&self) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        match self {
            Self::CaptureRequest(value) => observer.observe(*value)?,
            Self::CaptureContext(value) => observer.observe(*value)?,
            Self::CaptureArtifact(value) => observer.observe(*value)?,
            Self::UploadRequest(value) => observer.observe(*value)?,
            Self::UploadContext(value) => observer.observe(*value)?,
            Self::UploadArtifact(value) => observer.observe(*value)?,
            Self::ConfirmationRequest(value) => observer.observe(*value)?,
            Self::ConfirmationReceipt(value) => observer.observe(*value)?,
        }
        Ok(observer.finish())
    }

    /// Bounds the actual largest Bytes base64 temporary independently of output.
    ///
    /// # Errors
    /// Refuses metadata traversal or checked base64 arithmetic overflow.
    pub fn historical_serialization_transient_bytes_data(&self) -> Result<usize, ProviderError> {
        crate::retained_metadata::historical_serialization_transient_data(
            self.retained_metadata_data()?,
        )
    }

    /// Names every borrowed DTO and the actual defining metadata-result views.
    pub fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<&&PacketRestoredSettledCaptureRequest>()
            + size_of::<&&PacketRestoredSettledCaptureContext>()
            + size_of::<&&PacketRestoredSettledCaptureArtifact>()
            + size_of::<&&PacketRestoredSettledCaptureUploadRequest>()
            + size_of::<&&PacketRestoredSettledCaptureUploadContext>()
            + size_of::<&&PacketRestoredSettledCaptureUploadArtifact>()
            + size_of::<&&PacketRestoredSettledAfterConfirmationRequest>()
            + size_of::<&&PacketRestoredSettledAfterConfirmationReceipt>()
            + crate::retained_metadata::historical_serialization_counter_scratch_data()
            + restored_settled_capture_contract_counter_scratch_data()
            + restored_settled_capture_upload_counter_scratch_data()
            + restored_settled_after_confirmation_counter_scratch_data()
    }
}
