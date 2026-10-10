//! Runs admitted native node worlds through the independent observation ledger.
//!
//! The backend owns one prepared world on its native owner thread. Reservation
//! precedes activation; every dispatch uses the world's retained causal scheduler
//! and original runtime tokens. Failures retain the entire world for containment.

mod activation;
mod backend;
mod cache_reuse;
mod condition_execution;
mod condition_publication;
mod factory;
mod service;
mod terminal_publication;

pub use activation::StoredWorldActivationPublisher;
pub use backend::{NodeObservedAdmission, NodeObservedBackend, NodeObservedError};
pub use cache_reuse::{NodeCacheReuseReceipt, NodeCacheReuseRequest, node_cache_key};
pub use condition_execution::ConditionExecution;
pub use condition_publication::StoredConditionResultPublisher;
pub use factory::{
    InstalledCapabilityCandidate, InstalledCapabilityClockFactory, InstalledClockLabelFactory,
    InstalledClockLabelProfile, InstalledConditionDebugProfile, InstalledConditionalReplay,
    InstalledControlledFaultProfile, InstalledGem5ClosedProfile, InstalledGem5Isa,
    InstalledHostIoProfile, InstalledHostSemanticProfile, InstalledHostStateFactory,
    InstalledIoArtifact, InstalledIoArtifactSource, InstalledNativePreservation,
    InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection, InstalledPreparedNativeWorld,
    InstalledPreparedRootWorld, InstalledPreparedWorld, InstalledPublicReferencePackage,
    InstalledRecordedIngressProfile, InstalledRecordedWorld, InstalledReferenceQualifier,
    InstalledReferenceRecording, InstalledReplayRecipe, InstalledRootCleanupFailure,
    InstalledRootCleanupStatus, InstalledRootPreservation, InstalledRootRestore,
    InstalledRootRetirement, InstalledScriptedSourceProfile, MAX_KVM_CANDIDATE_POLICY_BYTES,
    NativeCapturePoint, NativeWorldOutcome, NativeWorldRecord, NativeWorldRequest,
    NativeWorldRetention, NativeWorldService, QualificationRunError,
    ReferenceQualificationObservation, ReferenceQualificationRun, ResolvedCapabilityWorld,
    RootInitialRetirementFailure, RootNamespaceReleaseFailure, RootRestoredRetirementFailure,
    RootUnstartedRetirementFailure, load_installed_kvm_candidate, prepare_installed_kvm_candidate,
};
pub use service::{
    CapabilityCandidateRecipe, CapabilityPreparationAction, CapabilityPreparationRecord,
    CapabilityPreparationRequest, CapabilityPreparationState, ConditionalPreparationRecord,
    ConditionalPreparationRequest, ConditionalPreparationState, NodeDebugRecord,
    NodeDebugResumeRequest, NodeDebugStartRequest, NodeDebugState, NodeDebugStop,
    NodeObservationRetention, NodeObservationService, NodeObservationServiceConfig,
    NodeObservationServiceError, NodePreservingDebugAction, NodePreservingDebugCapture,
    NodePreservingDebugRecord, NodePreservingDebugRequest, NodePreservingDebugResumeRequest,
    NodePreservingDebugState,
};
pub use terminal_publication::StoredTerminalResultPublisher;

#[cfg(test)]
mod tests;

/// Original asynchronous fixed Root recipe request and custody records.
pub use service::{
    RootFirstRefusal, RootGrantedOperation, RootPreparationAction, RootPreparationDiagnostic,
    RootPreparationRecord, RootPreparationRequest, RootPreparationState,
};
