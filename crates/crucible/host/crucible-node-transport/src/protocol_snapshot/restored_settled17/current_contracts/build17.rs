//! Owns the closed concrete raw DTO build-attempt implementations.

use super::*;

mod activation;
mod bodies;
mod capture;
mod input;
mod manifest;
mod native;
mod observation;
mod restore;

/// Names the actual per-DTO attempted-state headers.
pub(crate) fn current_contract17_builder_layouts_data() -> [usize; 62] {
    [
        std::mem::size_of::<
            <PacketRestorationActivationAllocationRow as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestorationActivationTarget as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestorationActivationOriginals as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestorationActivationScope as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestorationActivationRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestorationActivationContext as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestorationActivationProof as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestorationActivationArtifact as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestorationActivationUploadRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestorationActivationUploadContext as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestorationActivationUploadArtifact as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <InputRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <BeginRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PollRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <RetireRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <ObserveRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <BlobBeginRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <BlobChunkRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <BlobFinishRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <ExactRunArguments as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <CaptureArguments as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestoredSettledCaptureOutputLimits as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestoredSettledCaptureRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestoredSettledCaptureContext as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestoredSettledCaptureArtifact as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestoredSettledCaptureUploadRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestoredSettledCaptureUploadContext as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestoredSettledCaptureUploadArtifact as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestoredSettledCaptureUploadContinuation as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestoredSettledAfterConfirmationRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketInputCut as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestoredInputReactive17Request as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestoredInputReactive17Context as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestoredInputReactive17Artifact as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <ActivationManifest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PreparedOwner as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketNativeRestoredCommitHold as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <InstalledContent as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestoredSuffixReservationData as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestoredSettledNativeCarrierData as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestoredSettledNativeExistingRowsData as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketNative5StorageSelection as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketConnectedNativeRecord as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketNativeRestoredRecord as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketProgramDefinition as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketNative5StorageLimits as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestorationObservationRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestorationObservationContext as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestorationObservationProof as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketRestorationObservationArtifact as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketCompleteRestoreRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketCompleteRestoreContext as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketCompleteRestoreInputAllocation as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketCompleteRestorePrepareRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketCompleteRestorePrepareContext as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketCompleteRestoreTransferProof as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketCompleteRestoreCommitRequest as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketCompleteRestoreCommitContext as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketCanonicalAckAdmissionContext as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketCanonicalAckAdmissionProof as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PrepareRestoreResult as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >(),
        std::mem::size_of::<
            <PacketNative5Record as
                crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17
            >::Attempt
        >()
    ]
}

mod receipt;
