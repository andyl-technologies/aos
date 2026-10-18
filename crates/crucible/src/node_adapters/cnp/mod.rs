//! Installed CNP-backed quantized nodes with actual retained process custody.
//!
//! Private launch and source qualification precede graph sealing. Public controls
//! preserve original request, input and operation identities; native outcomes
//! remain claims until checked by the installed measured checksum model. Complete
//! world activation uses the coordinator's opaque durable publication authority.
//! Unsupported exact execution, state preservation and causal input mappings
//! refuse explicitly while the original process remains supervised.

mod acceptance;
mod activation;
mod boundary;
mod control;
mod implementation;
mod input;
mod input_commit;
mod lifecycle;
mod lifecycle_resend;
mod lineage;
mod original_conflict;
mod pending;
mod preparation;
mod preparation_adverse;
mod preparation_conflict;
mod preparation_probe;
pub use preparation_conflict::CnpPreRealizationConflictRequest;
mod preparation_resend;
mod process;
mod readiness;
mod retirement;
mod semantic;
mod windows;

pub use acceptance::{CnpAcceptanceScope, CnpAcceptedPreparation, CnpRealizationAcceptance};
pub use control::CnpControlledReference;
pub use lineage::{
    OriginalRuntimeLineage, with_completed_runtime_lineage, with_original_runtime_lineage,
};
pub use preparation::{CnpPreparationFailure, CnpReferencePreparation, CnpReferenceQualification};
pub use process::{
    CnpExtensionAttachmentFailure, CnpLaunchFailure, CnpLaunchGuard, CnpPeerCustody,
    CnpProcessCustodySlot, CnpSemanticRetirement,
};

pub use semantic::{
    CnpConformanceNodeConstructionStorageData, CnpNativeAfterConfirmationCall,
    CnpOriginalSemanticSnapshot, CnpPreparationStorageScratch, CnpRetainedStorageReport,
    CnpRetainedStorageUnknowns, CnpSemanticAcceptance, CnpSemanticAdmissionFailure,
    CnpSemanticAttachmentFailure, CnpSemanticCaptureScope, CnpSemanticConformanceAuthority,
    CnpSemanticConformanceNode, CnpSemanticConformanceProvider,
    CnpSemanticConformanceWorldProvider, CnpSemanticExactConformanceWorldProvider,
    CnpSemanticExactWorldReservation, CnpSemanticExactWorldReservationFailure,
    CnpSemanticInstallation, CnpSemanticLaunchFailure, CnpSemanticLaunchGuard,
    CnpSemanticLaunchReservation, CnpSemanticNode, CnpSemanticPreparation,
    CnpSemanticPreparationFailure, CnpSemanticProcessCustody, CnpSemanticProcessSlot,
    CnpSemanticProvider, CnpSemanticProviderFailure, CnpSemanticRealizationScope,
    CnpSemanticRegistrationPolicy, CnpSemanticRegistry, CnpSemanticReservationFailure,
    CnpSemanticSnapshotReservation, CnpSemanticSource, CnpSemanticSourceRead,
    CnpSemanticTransition, CnpSemanticWorldPreparationFailure, CnpSemanticWorldReservationFailure,
    InstalledCnpConformanceRole, InstalledCnpSemanticRole, OriginalCaptureAllocationData,
    OriginalInstalledRestorationCustodyConstructionData, PACKET_COMPLETE_SETTLED_JOURNAL_SCHEMA,
    PACKET_COMPLETE_SETTLED_REGISTRY_JOURNAL_SCHEMA, PacketCompleteAckHostRegistrationPlan,
    PacketCompleteAckPeerBootFrame, PacketCompleteAckPeerBootMaterial,
    PacketCompleteArchivedOwnerData, PacketCompleteArchivedSemantics,
    PacketCompleteCaptureBankFacts, PacketCompleteCaptureBankLimits,
    PacketCompleteCaptureDependencyLookupData, PacketCompleteCaptureDependencyStorageData,
    PacketCompleteEffectReceiverGroup, PacketCompleteEffectReceiverReader,
    PacketCompleteHistoricalAllocationFacts, PacketCompleteHistoricalNativeGroup,
    PacketCompleteHistoricalProtocolData, PacketCompleteHistoricalProtocolDataBudget,
    PacketCompleteNativeRecord, PacketCompleteNativeRestoredSuffixStartupWire,
    PacketCompleteNativeStartupWire, PacketCompleteNativeWitness, PacketCompleteOriginalHostSdk,
    PacketCompleteRestorePreparation, PacketCompleteSemanticSource, PacketCompleteSettledJournal,
    PacketCompleteSourceRetainedStorage, PacketCompleteSourceRole, PacketConnectedInputWitness,
    PacketConnectedNativeWitness, PacketConnectedSemanticSource, PacketNativeWitness,
    PacketSemanticSource, original_capture_allocation_witness_counter_scratch_data,
    packet_common_grant_authorization,
};

/// Runs an actual installed public checksum node under the common quantized runtime.
pub type CnpReferenceNode =
    super::reference_device::ControlledReferenceNode<CnpControlledReference>;

#[cfg(test)]
mod tests;

pub use preparation_probe::{CnpPreRealizationProbeBody, CnpPreRealizationProbeRequest};

pub use preparation_adverse::{CnpPreparedAdverseBody, CnpPreparedAdverseRequest};

pub use lifecycle_resend::{
    CnpCompletedLifecyclePhase, CnpCompletedLifecycleQualification, CnpCompletedLifecycleScope,
};

pub use original_conflict::CnpOriginalConflictQualification;

mod lineage_reader;

pub use lineage_reader::{
    LineageControlledReference, LineagePreparationFailure, LineageReferenceQualification,
    LineageRuntimeCustody, LineageRuntimeCustodySlot,
};

/// Adapts independently installed vendor profiles with original CNP custody.
pub mod vendor;

pub(crate) use semantic::{
    PacketCompleteInitialLifecycleIdentity, PacketCompleteInitialLifecycleQuote,
};

pub(crate) use semantic::{
    OriginalInitialLifecycleDiagnostics, original_construction_failure_reason,
};

pub(crate) use semantic::{OriginalRestorationColdGroup, OriginalRestorationColdOwnerView};

pub(crate) use semantic::{
    OriginalSourceRestoreSignerConstructionData, OriginalSourceRestoreVerifiedPhase,
    OriginalSourceRestoreVerifiedPhaseKind,
};

pub use semantic::{
    OriginalSourceRestorationActivationConstructionData,
    OriginalSourceRestorationActivationVerifiedPhase,
    OriginalSourceRestorationObservationConstructionData,
    OriginalSourceRestorationObservationVerifiedPhase,
};

pub(crate) use semantic::OriginalSourceRestoredObservationCompletion;

pub use semantic::{
    OriginalRestoredProducerOutcomeConstructionData, OriginalRestoredProducerOutcomeProjection,
};

pub(crate) use semantic::OriginalSourceRestoredProducerPhaseCompletion;

pub(crate) use semantic::{
    OriginalSourceRestoredInstallationExpected17, OriginalSourceRestoredLimits17,
    OriginalSourceRestoredProducerCheckpoint17, OriginalSourceRestoredSettled17DecodeAttempt,
    OriginalSourceRestoredSettled17Read, OriginalSourceRestoredSettled17ReadInputs,
};

pub(crate) use semantic::{
    CnpRestoredNode17DecodeAttempt, CnpRestoredNode17DecodeConstructionData,
    CnpRestoredNode17ProducerAttemptBorrowedData, CnpRestoredNode17RawStorageData,
    CnpRestoredSettledValidatedNode17,
};

pub use semantic::PacketCompleteNativeRestoredSettledStartupWire;

pub(crate) use semantic::{
    OriginalSourceRestoredCaptureCompletion, OriginalSourceRestoredCaptureQuoteInputs,
};

pub(crate) use semantic::OriginalSourceRestoredCaptureEncodingInputs;

pub(crate) use semantic::OriginalSourceRestoredCaptureCountingBanksData;

pub(crate) use semantic::{OriginalInitial15ArchivedGroup, OriginalInitial15ArchivedOwnerRead};

pub use semantic::CompleteHistoricalArchiveFamily;
pub(crate) use semantic::{
    OriginalCompleteHistoricalColdGroup, OriginalRestoredSettledColdGroup,
    OriginalRestoredSettledColdOwnerView,
};

pub(crate) use semantic::OriginalRestoredSettledNodeHistoryView;

pub use semantic::OriginalSourceRestoredCaptureConstructionData;

pub(crate) use semantic::original_restored_settled_semantic_history_counter_scratch_data;
