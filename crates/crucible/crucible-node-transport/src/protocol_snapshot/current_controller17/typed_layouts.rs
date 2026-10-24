//! Quotes fixed layouts for closed Controller17 validation children.
//!
//! The actual DOM extent separately prices owned text and collection backing.
//! These explicit type and Result layouts describe requested validation work;
//! they grant no owning decoder, live Controller or native permission.

use crate::{
    ProviderError,
    bodies::*,
    client::CanonicalAckCodecMetadataExtent,
    envelope::Envelope,
    reference_packet::{coordinator, service},
};
use crucible_node_format::{ContentRef, ContractError, ExtensionSelection, HashRef, Id, U64};
use serde_json::Value;
use std::collections::BTreeSet;
use std::mem::size_of;

/// Sums the actual closed typed validation children.
///
/// The defining DOM extent independently covers their owned text and collections.
pub(super) fn typed_layout_bytes() -> usize {
    size_of::<Vec<Envelope>>()
        + size_of::<Vec<ContentRef>>()
        + size_of::<Vec<ExtensionSelection>>()
        + size_of::<Vec<u8>>()
        + size_of::<[ContentRef; 2]>()
        + size_of::<[ContentRef; 3]>()
        + size_of::<[ContentRef; 5]>()
        + size_of::<[ContentRef; 7]>()
        + size_of::<[u8; 32]>()
        + size_of::<ActivateRequest>()
        + size_of::<ActivateResult>()
        + size_of::<AdmitResult>()
        + size_of::<BeginAccepted>()
        + size_of::<BeginRequest>()
        + size_of::<BlobBeginRequest>()
        + size_of::<BlobBeginResult>()
        + size_of::<BlobChunkRequest>()
        + size_of::<BlobChunkResult>()
        + size_of::<BlobFinishRequest>()
        + size_of::<BlobFinishResult>()
        + size_of::<CaptureArguments>()
        + size_of::<CaptureResult>()
        + size_of::<ExactRunResult>()
        + size_of::<InputResult>()
        + size_of::<NotificationBody>()
        + size_of::<ObserveRequest>()
        + size_of::<ObserveResult>()
        + size_of::<PollResult>()
        + size_of::<PrepareRestoreResult>()
        + size_of::<ResponseShape>()
        + size_of::<RetireRequest>()
        + size_of::<RetireResult>()
        + size_of::<WorldActivateRequest>()
        + size_of::<WorldActivateResult>()
        + size_of::<CanonicalAckCodecMetadataExtent>()
        + size_of::<Envelope>()
        + size_of::<crate::envelope::Method>()
        + size_of::<coordinator::PacketNative5CoordinatorInstallation>()
        + size_of::<service::PacketNative5CaptureProfile>()
        + size_of::<service::PacketNative5ProtocolMetadataLimits>()
        + size_of::<service::ack_emitter::PacketNative5AckEmitterSelection>()
        + size_of::<service::capture_allocation::PacketNative5CaptureAllocationSelection>()
        + size_of::<service::complete_restore::PacketNative5CompleteRestoreSelection>()
        + size_of::<service::complete_restore::PacketNative5RestoreInputEmitterSelection>()
        + size_of::<service::complete_restore::activation::PacketRestorationActivationRequest>()
        + size_of::<service::complete_restore::activation::PacketRestorationActivationUploadRequest>(
        )
        + size_of::<
            service::complete_restore::restoration_observe::PacketRestorationObservationRequest,
        >()
        + size_of::<service::confirmation::PacketNative5ConfirmationSelection>()
        + size_of::<service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection>(
        )
        + size_of::<service::restored_settled_capture::PacketRestoredSettledCaptureArtifact>()
        + size_of::<service::restored_settled_capture::PacketRestoredSettledCaptureContext>()
        + size_of::<service::restored_settled_capture::PacketRestoredSettledCaptureRequest>()
        + size_of::<service::restored_settled_capture::PacketRestoredSettledCaptureUploadArtifact>()
        + size_of::<service::restored_settled_capture::PacketRestoredSettledCaptureUploadContext>()
        + size_of::<service::restored_settled_capture::PacketRestoredSettledCaptureUploadContinuation>(
        )
        + size_of::<service::restored_settled_capture::PacketRestoredSettledCaptureUploadRequest>()
        + size_of::<
            service::restored_settled_confirmation::PacketRestoredSettledAfterConfirmationReceipt,
        >()
        + size_of::<
            service::restored_settled_confirmation::PacketRestoredSettledAfterConfirmationRequest,
        >()
        + size_of::<ContentRef>()
        + size_of::<HashRef>()
        + size_of::<Id>()
        + size_of::<U64>()
        + size_of::<Value>()
        + size_of::<BTreeSet<String>>()
}

/// Sums the fallible typed-decoder result views without owning their payloads.
pub(super) fn typed_result_views() -> usize {
    typed_result_bytes::<Vec<Envelope>>()
        + typed_result_bytes::<Vec<ContentRef>>()
        + typed_result_bytes::<Vec<ExtensionSelection>>()
        + typed_result_bytes::<Vec<u8>>()
        + typed_result_bytes::<[ContentRef; 2]>()
        + typed_result_bytes::<[ContentRef; 3]>()
        + typed_result_bytes::<[ContentRef; 5]>()
        + typed_result_bytes::<[ContentRef; 7]>()
        + typed_result_bytes::<[u8; 32]>()
        + typed_result_bytes::<ActivateRequest>()
        + typed_result_bytes::<ActivateResult>()
        + typed_result_bytes::<AdmitResult>()
        + typed_result_bytes::<BeginAccepted>()
        + typed_result_bytes::<BeginRequest>()
        + typed_result_bytes::<BlobBeginRequest>()
        + typed_result_bytes::<BlobBeginResult>()
        + typed_result_bytes::<BlobChunkRequest>()
        + typed_result_bytes::<BlobChunkResult>()
        + typed_result_bytes::<BlobFinishRequest>()
        + typed_result_bytes::<BlobFinishResult>()
        + typed_result_bytes::<CaptureArguments>()
        + typed_result_bytes::<CaptureResult>()
        + typed_result_bytes::<ExactRunResult>()
        + typed_result_bytes::<InputResult>()
        + typed_result_bytes::<NotificationBody>()
        + typed_result_bytes::<ObserveRequest>()
        + typed_result_bytes::<ObserveResult>()
        + typed_result_bytes::<PollResult>()
        + typed_result_bytes::<PrepareRestoreResult>()
        + typed_result_bytes::<ResponseShape>()
        + typed_result_bytes::<RetireRequest>()
        + typed_result_bytes::<RetireResult>()
        + typed_result_bytes::<WorldActivateRequest>()
        + typed_result_bytes::<WorldActivateResult>()
        + typed_result_bytes::<CanonicalAckCodecMetadataExtent>()
        + typed_result_bytes::<Envelope>()
        + typed_result_bytes::<crate::envelope::Method>()
        + typed_result_bytes::<coordinator::PacketNative5CoordinatorInstallation>()
        + typed_result_bytes::<service::PacketNative5CaptureProfile>()
        + typed_result_bytes::<service::PacketNative5ProtocolMetadataLimits>()
        + typed_result_bytes::<service::ack_emitter::PacketNative5AckEmitterSelection>()
        + typed_result_bytes::<service::capture_allocation::PacketNative5CaptureAllocationSelection>(
        )
        + typed_result_bytes::<service::complete_restore::PacketNative5CompleteRestoreSelection>()
        + typed_result_bytes::<service::complete_restore::PacketNative5RestoreInputEmitterSelection>(
        )
        + typed_result_bytes::<
            service::complete_restore::activation::PacketRestorationActivationRequest,
        >()
        + typed_result_bytes::<
            service::complete_restore::activation::PacketRestorationActivationUploadRequest,
        >()
        + typed_result_bytes::<
            service::complete_restore::restoration_observe::PacketRestorationObservationRequest,
        >()
        + typed_result_bytes::<service::confirmation::PacketNative5ConfirmationSelection>()
        + typed_result_bytes::<
            service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
        >()
        + typed_result_bytes::<
            service::restored_settled_capture::PacketRestoredSettledCaptureArtifact,
        >()
        + typed_result_bytes::<service::restored_settled_capture::PacketRestoredSettledCaptureContext>(
        )
        + typed_result_bytes::<service::restored_settled_capture::PacketRestoredSettledCaptureRequest>(
        )
        + typed_result_bytes::<
            service::restored_settled_capture::PacketRestoredSettledCaptureUploadArtifact,
        >()
        + typed_result_bytes::<
            service::restored_settled_capture::PacketRestoredSettledCaptureUploadContext,
        >()
        + typed_result_bytes::<
            service::restored_settled_capture::PacketRestoredSettledCaptureUploadContinuation,
        >()
        + typed_result_bytes::<
            service::restored_settled_capture::PacketRestoredSettledCaptureUploadRequest,
        >()
        + typed_result_bytes::<
            service::restored_settled_confirmation::PacketRestoredSettledAfterConfirmationReceipt,
        >()
        + typed_result_bytes::<
            service::restored_settled_confirmation::PacketRestoredSettledAfterConfirmationRequest,
        >()
        + typed_result_bytes::<ContentRef>()
        + typed_result_bytes::<HashRef>()
        + typed_result_bytes::<Id>()
        + typed_result_bytes::<U64>()
        + typed_result_bytes::<Value>()
        + typed_result_bytes::<BTreeSet<String>>()
}

// Each actual decoder propagates these distinct result representations.
const fn typed_result_bytes<T>() -> usize {
    size_of::<Result<T, ProviderError>>()
        + size_of::<Result<T, serde_json::Error>>()
        + size_of::<Result<T, ContractError>>()
}
