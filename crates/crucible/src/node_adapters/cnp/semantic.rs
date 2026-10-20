//! Source-installed translation of generic CNP realization and original operations.
//!
//! The public transport does not define arbitrary role receipt semantics. This
//! module requires a separately installed native oracle and behavioral acceptance
//! authority for ordinary mapping into common node operations. A separate
//! opaque collecting route authenticates its original Refused fixture plan and
//! source custody; that route grants no ordinary behavioral qualification.
//! The legacy checksum realization and receipt dialect remain independent.

mod budget;
mod capture;
mod conformance;
mod historical_protocol;
mod implementation;
mod initial_lifecycle_diagnostics;
mod input;
mod lifecycle;
mod node;
mod operations;
mod packet_complete_source;
pub use historical_protocol::{
    PacketCompleteHistoricalAllocationFacts, PacketCompleteHistoricalNativeGroup,
    PacketCompleteHistoricalProtocolData, PacketCompleteHistoricalProtocolDataBudget,
};

mod packet_connected_source;
mod packet_grant;
mod packet_lineage;
mod packet_source;
mod preparation;
mod process;
mod provider;
mod registry;
mod retained_storage;
mod semantic_snapshot;
mod source;
mod state;
mod world_provider;

pub use capture::{CnpNativeAfterConfirmationCall, CnpSemanticCaptureScope};
pub use retained_storage::{
    CnpPreparationStorageScratch, CnpRetainedStorageReport, CnpRetainedStorageUnknowns,
};
pub use semantic_snapshot::{CnpOriginalSemanticSnapshot, CnpSemanticSnapshotReservation};

pub use conformance::{
    CnpSemanticConformanceAuthority, CnpSemanticConformanceNode, CnpSemanticConformanceProvider,
    InstalledCnpConformanceRole,
};
pub use world_provider::{
    CnpSemanticConformanceWorldProvider, CnpSemanticExactConformanceWorldProvider,
    CnpSemanticExactWorldReservation, CnpSemanticExactWorldReservationFailure,
    CnpSemanticWorldPreparationFailure, CnpSemanticWorldReservationFailure,
};

pub use node::{
    CnpConformanceNodeConstructionStorageData, CnpSemanticAdmissionFailure, CnpSemanticNode,
    OriginalInstalledRestorationCustodyConstructionData,
};
pub use packet_complete_source::{
    OriginalCaptureAllocationData, OriginalImport18CaptureBankConstructionData,
    NativeImport18BirthConstructionQuote,
    OriginalNativeImport18SourcePhaseBankConstructionData,
    OriginalNativeSourceTemplate18Attempt, OriginalNativeSourceTemplate18ConstructionData,
    PACKET_COMPLETE_SETTLED_JOURNAL_SCHEMA, PACKET_COMPLETE_SETTLED_REGISTRY_JOURNAL_SCHEMA,
    PacketCompleteAckHostRegistrationPlan, PacketCompleteAckPeerBootFrame,
    PacketCompleteAckPeerBootMaterial, PacketCompleteArchivedOwnerData,
    PacketCompleteArchivedSemantics, PacketCompleteCaptureBankFacts,
    PacketCompleteCaptureBankLimits, PacketCompleteCaptureDependencyLookupData,
    PacketCompleteCaptureDependencyStorageData, PacketCompleteEffectReceiverGroup,
    PacketCompleteEffectReceiverReader, PacketCompleteNativeImport18StartupWire,
    PacketCompleteNativeRecord, PacketCompleteNativeRestoredSuffixStartupWire,
    PacketCompleteNativeStartupWire, PacketCompleteNativeWitness, PacketCompleteOriginalHostSdk,
    PacketCompleteRestorePreparation, PacketCompleteSemanticSource, PacketCompleteSettledJournal,
    PacketCompleteSourceRetainedStorage, PacketCompleteSourceRole,
    original_capture_allocation_witness_counter_scratch_data,
};
pub use packet_connected_source::{
    PacketConnectedInputWitness, PacketConnectedNativeWitness, PacketConnectedSemanticSource,
};
pub use packet_grant::packet_common_grant_authorization;
pub use packet_source::{PacketNativeWitness, PacketSemanticSource};
pub use provider::{CnpSemanticProvider, CnpSemanticProviderFailure};
pub use registry::{CnpSemanticRegistrationPolicy, CnpSemanticRegistry, InstalledCnpSemanticRole};

pub use preparation::{CnpSemanticPreparation, CnpSemanticPreparationFailure};
pub use process::{
    CnpSemanticAttachmentFailure, CnpSemanticLaunchFailure, CnpSemanticLaunchGuard,
    CnpSemanticLaunchReservation, CnpSemanticProcessCustody, CnpSemanticProcessSlot,
    CnpSemanticReservationFailure, CnpSemanticSourceRead,
};
pub use source::{
    CnpSemanticAcceptance, CnpSemanticInstallation, CnpSemanticRealizationScope, CnpSemanticSource,
    CnpSemanticTransition,
};

use crate::node_contract::{EffectKnowledge, OperationFailure};

fn refused(reason: impl initial_lifecycle_diagnostics::InitialRefusalReason) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: initial_lifecycle_diagnostics::refusal_reason(reason),
    }
}

fn unknown(reason: impl std::fmt::Display) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::Unknown,
        reason: initial_lifecycle_diagnostics::unknown_reason(reason),
    }
}

fn refused_display(reason: impl std::fmt::Display) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: initial_lifecycle_diagnostics::refused_display_reason(reason),
    }
}

fn after_effect(mut failure: OperationFailure) -> OperationFailure {
    failure.effects = EffectKnowledge::Unknown;
    failure
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Fixture assertions reject inconsistent complete source selections.
    // crucible-lint: allow rust-allow -- Test constructors use panics as failed selected-record assertions.
    #[allow(clippy::unwrap_used)]
    mod packet_definition;
    // crucible-lint: allow panic-shortcut -- Actual phased byte/socket controls panic on failed source custody assertions.
    // crucible-lint: allow rust-allow -- Source component fixtures use panics only to reject broken original evidence.
    #[allow(clippy::unwrap_used)]
    mod packet_connected;
    // crucible-lint: allow panic-shortcut -- Actual native datagram/projection assertions fail on lost originals or forbidden phase effects.
    // crucible-lint: allow rust-allow -- These test-only fixture constructors intentionally panic on invalid source evidence.
    #[allow(clippy::unwrap_used)]
    mod packet_connected_source;
    // crucible-lint: allow panic-shortcut -- Selected source roster and actual native Arm controls fail on broken fixture evidence.
    // crucible-lint: allow rust-allow -- Test constructors panic only on inconsistent original setup or failed evidence assertions.
    #[allow(clippy::unwrap_used)]
    mod packet_coordinator;
    // crucible-lint: allow panic-shortcut -- Actual native socket and FIFO witnesses fail on lost originals or forbidden effects.
    // crucible-lint: allow rust-allow -- The source process cohort uses panics only for failed native/test observations.
    mod operational_poll;
    // crucible-lint: allow panic-shortcut -- Actual native socket and FIFO witnesses fail on lost originals or forbidden effects.
    #[allow(clippy::unwrap_used)]
    mod packet_execution;
    // crucible-lint: allow panic-shortcut -- Actual process fixture assertions panic on lost originals or incorrect admission ordering.
    // crucible-lint: allow rust-allow -- Tests report failed native custody assertions by panic.
    #[allow(clippy::unwrap_used)]
    mod packet_preparation;
    // crucible-lint: allow panic-shortcut -- Shared fixture codecs fail on malformed original setup.
    // crucible-lint: allow rust-allow -- Only native/test fixture constructors use panics.
    #[allow(clippy::unwrap_used)]
    mod packet_protocol;
    mod preparation_storage;
    mod process;
}

pub(crate) use packet_complete_source::{
    PacketCompleteInitialLifecycleIdentity, PacketCompleteInitialLifecycleQuote,
};

pub(crate) use initial_lifecycle_diagnostics::{
    OriginalInitialLifecycleDiagnostics, unknown_reason as original_construction_failure_reason,
};

pub(crate) use packet_complete_source::{
    OriginalRestorationColdGroup, OriginalRestorationColdOwnerView,
};

pub(crate) use packet_complete_source::{
    OriginalSourceRestoreSignerConstructionData, OriginalSourceRestoreVerifiedPhase,
    OriginalSourceRestoreVerifiedPhaseKind,
};

pub use packet_complete_source::{
    OriginalSourceRestorationActivationConstructionData,
    OriginalSourceRestorationActivationVerifiedPhase,
    OriginalSourceRestorationObservationConstructionData,
    OriginalSourceRestorationObservationVerifiedPhase,
};

pub(crate) use packet_complete_source::OriginalSourceRestoredObservationCompletion;

pub use packet_complete_source::{
    OriginalRestoredProducerOutcomeConstructionData, OriginalRestoredProducerOutcomeProjection,
};

pub(crate) use packet_complete_source::OriginalSourceRestoredProducerPhaseCompletion;

pub(crate) use packet_complete_source::{
    OriginalSourceRestoredFirstObservationHistory17Read, OriginalSourceRestoredInstallation17,
    OriginalSourceRestoredInstallationExpected17, OriginalSourceRestoredLimits17,
    OriginalSourceRestoredProducerCheckpoint17, OriginalSourceRestoredSettled17DecodeAttempt,
    OriginalSourceRestoredSettled17Prelude, OriginalSourceRestoredSettled17Read,
    OriginalSourceRestoredSettled17ReadInputs,
};

pub(crate) use node::{
    CnpRestoredNode17DecodeAttempt, CnpRestoredNode17DecodeConstructionData,
    CnpRestoredNode17ProducerAttemptBorrowedData, CnpRestoredNode17RawStorageData,
    CnpRestoredSettledValidatedNode17,
};

pub use packet_complete_source::PacketCompleteNativeRestoredSettledStartupWire;

pub(crate) use packet_complete_source::{
    OriginalSourceRestoredCaptureCompletion, OriginalSourceRestoredCaptureQuoteInputs,
};

pub(crate) use packet_complete_source::OriginalSourceRestoredCaptureEncodingInputs;

pub(crate) use packet_complete_source::OriginalSourceRestoredCaptureCountingBanksData;

pub(crate) use packet_complete_source::{
    OriginalInitial15ArchivedGroup, OriginalInitial15ArchivedOwnerRead,
};

pub use packet_complete_source::CompleteHistoricalArchiveFamily;
pub(crate) use packet_complete_source::{
    OriginalCompleteHistoricalColdGroup, OriginalRestoredSettledColdGroup,
    OriginalRestoredSettledColdOwnerMetadata, OriginalRestoredSettledColdOwnerView,
};

pub(crate) use node::OriginalRestoredSettledNodeHistoryView;

pub use packet_complete_source::OriginalSourceRestoredCaptureConstructionData;

pub(crate) use node::original_restored_settled_semantic_history_counter_scratch_data;
