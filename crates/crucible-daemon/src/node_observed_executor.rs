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

pub(crate) use activation::OriginalDirectoryPublicationConstructionData;
pub use activation::StoredWorldActivationPublisher;
pub use backend::{NodeObservedAdmission, NodeObservedBackend, NodeObservedError};
pub use cache_reuse::{NodeCacheReuseReceipt, NodeCacheReuseRequest, node_cache_key};
pub use condition_execution::ConditionExecution;
pub use condition_publication::StoredConditionResultPublisher;
pub use factory::{
    ClockAdmissionObservationData, ClockStateObservationData, Gem5BehavioralCase,
    Gem5BehavioralReport, Gem5BehavioralRequest, Gem5BehavioralRun, InstalledCapabilityCandidate,
    InstalledCapabilityClockFactory, InstalledClockLabelFactory, InstalledClockLabelProfile,
    InstalledConditionDebugProfile, InstalledConditionalReplay, InstalledControlledFaultProfile,
    InstalledGem5BehavioralAcceptance, InstalledGem5ClosedProfile, InstalledGem5Isa,
    InstalledHostIoProfile, InstalledHostSemanticProfile, InstalledHostStateFactory,
    InstalledIndependentNativePreservation, InstalledIndependentNativeRestore, InstalledIoArtifact,
    InstalledIoArtifactSource, InstalledMixedVendorWorldRequest, InstalledNativePreservation,
    InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection, InstalledNormalClockProfile,
    InstalledNormalClockStateFactory, InstalledOriginalLineageAuthority,
    InstalledOriginalLineagePlan, InstalledOriginalLineagePreparation,
    InstalledOriginalLineageSourcePolicy, InstalledPreparedIndependentNativeWorld,
    InstalledPreparedNativeWorld, InstalledPreparedRootWorld, InstalledPreparedWorld,
    InstalledPublicReferencePackage, InstalledRecordedIngressProfile, InstalledRecordedWorld,
    InstalledReferenceQualifier, InstalledReferenceRecording, InstalledReplayRecipe,
    InstalledRootCleanupFailure, InstalledRootCleanupStatus, InstalledRootPreservation,
    InstalledRootRestore, InstalledRootRetirement, InstalledScriptedSourceProfile,
    InstalledSingletonCollector, InstalledTypedReaderCatalog, InstalledTypedReaderCatalogPolicy,
    InstalledTypedReaderConfiguration, InstalledTypedReaderFixtureAuthority,
    InstalledTypedReaderHostInvocation, InstalledTypedReaderOwningPolicy,
    InstalledTypedReaderPackage, InstalledTypedReaderPreparation,
    InstalledTypedReaderPreparedParts, InstalledTypedReaderSourceFixture,
    InstalledVendorContribution, LaunchedTypedReaderProvider, LaunchedTypedReaderSession,
    MAX_KVM_CANDIDATE_POLICY_BYTES, NativeCapturePoint, NativeWorldOutcome, NativeWorldRecord,
    NativeWorldRequest, NativeWorldRetention, NativeWorldService, NormalClockProgramme,
    OriginalClockAdverseWitness, OriginalClockAggregateResources, OriginalClockFailureWitness,
    OriginalClockProcessBootstrap, OriginalClockQualificationRun, OriginalClockStateProgramme,
    OriginalClockStateWitness, OriginalSingletonCollection, OriginalTypedWindowSeal,
    PreparedTypedReaderCohort, PreparedTypedReaderHostCollection,
    PreparedTypedReaderHostInvocation, PreparedTypedReaderHostSources, PreparedTypedReaderSession,
    PublicReferenceVendorProfile, PublicReferenceVendorSelection, QualificationRunError,
    ReclaimedTypedReaderHostCollection, ReclaimedTypedReaderHostSources,
    ReferenceQualificationObservation, ReferenceQualificationRun, ReferenceVendorInstallation,
    ReferenceVendorInstallationRequest, ResolvedCapabilityWorld, RootInitialRetirementFailure,
    RootNamespaceReleaseFailure, RootRestoredRetirementFailure, RootUnstartedRetirementFailure,
    SelectedTypedReaderHostSource, SelectedTypedReaderPublicRole, SingletonCollectionObservation,
    StoredTypedReaderResultPublisher, TypedReaderAdoptionFailure, TypedReaderCohortReservation,
    TypedReaderCollectingDriver, TypedReaderCollectingExtensionPolicy, TypedReaderCollectionWorld,
    TypedReaderCustodyPair, TypedReaderCustodySupervisor, TypedReaderDrivingError,
    TypedReaderFixtureAudit, TypedReaderFixtureLaunchRequest, TypedReaderFixtureLaunches,
    TypedReaderHostCollection, TypedReaderHostExecution, TypedReaderHostIncidents,
    TypedReaderHostInvocationFailure, TypedReaderHostInvocationRequest,
    TypedReaderHostPreparationRequest, TypedReaderHostReport, TypedReaderHostSchemas,
    TypedReaderHostServices, TypedReaderHostSessionScope, TypedReaderHostSourceFailure,
    TypedReaderHostSourcesExecution, TypedReaderHostSourcesRequest, TypedReaderHostStartFailure,
    TypedReaderLaunchError, TypedReaderLaunchFailure, TypedReaderNativeOracles,
    TypedReaderOriginalRow, TypedReaderPrivateAuthorization, TypedReaderProgramme,
    TypedReaderProgrammePeer, TypedReaderProgrammeWindow, TypedReaderSessionFailure,
    TypedReaderSessionLaunchFailure, TypedReaderSessionPreparationFailure,
    TypedReaderSessionRequest, TypedReaderSourceHandshake, TypedReaderWindowDisposition,
    TypedReaderWindowTicket, TypedReaderWitnessAuthority, load_installed_kvm_candidate,
    prepare_installed_kvm_candidate,
};
pub use service::{
    CapabilityCandidateRecipe, CapabilityPreparationAction, CapabilityPreparationRecord,
    CapabilityPreparationRequest, CapabilityPreparationState, CompleteSceneServiceFactory,
    ConditionalPreparationRecord, ConditionalPreparationRequest, ConditionalPreparationState,
    InstalledVendorServiceFactory, NodeDebugRecord, NodeDebugResumeRequest, NodeDebugStartRequest,
    NodeDebugState, NodeDebugStop, NodeObservationRetention, NodeObservationService,
    NodeObservationServiceConfig, NodeObservationServiceError, NodePreservingDebugAction,
    NodePreservingDebugCapture, NodePreservingDebugRecord, NodePreservingDebugRequest,
    NodePreservingDebugResumeRequest, NodePreservingDebugState, OriginalLineageHostInstallation,
    ReferenceVendorServiceFactory,
};
pub use terminal_publication::StoredTerminalResultPublisher;

#[cfg(test)]
mod tests;

/// Original asynchronous fixed Root recipe request and custody records.
pub use service::{
    RootFirstRefusal, RootGrantedOperation, RootPreparationAction, RootPreparationDiagnostic,
    RootPreparationRecord, RootPreparationRequest, RootPreparationState,
};
