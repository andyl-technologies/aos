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
    CnpOriginalSemanticSnapshot, CnpSemanticAcceptance, CnpSemanticAdmissionFailure,
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
    InstalledCnpConformanceRole, InstalledCnpSemanticRole, PacketCompleteCaptureBankFacts,
    PacketCompleteCaptureBankLimits, PacketCompleteEffectReceiverGroup,
    PacketCompleteEffectReceiverReader, PacketCompleteNativeRecord, PacketCompleteNativeWitness,
    PacketCompleteSemanticSource, PacketCompleteSourceRole, PacketConnectedInputWitness,
    PacketConnectedNativeWitness, PacketConnectedSemanticSource, PacketNativeWitness,
    PacketSemanticSource, packet_common_grant_authorization,
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
