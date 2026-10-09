//! Runs admitted native node worlds through the independent observation ledger.
//!
//! The backend owns one prepared world on its native owner thread. Reservation
//! precedes activation; every dispatch uses the world's retained causal scheduler
//! and original runtime tokens. Failures retain the entire world for containment.

mod activation;
mod backend;
mod factory;
mod service;

pub use activation::StoredWorldActivationPublisher;
pub use backend::{NodeObservedAdmission, NodeObservedBackend, NodeObservedError};
pub use factory::{
    InstalledGem5ClosedProfile, InstalledGem5Isa, InstalledHostIoProfile,
    InstalledHostStateFactory, InstalledIoArtifact, InstalledIoArtifactSource,
    InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection, InstalledPreparedWorld,
    InstalledPublicReferencePackage, InstalledRecordedWorld, InstalledReferenceQualifier,
    InstalledReferenceRecording, InstalledScriptedSourceProfile, MAX_KVM_CANDIDATE_POLICY_BYTES,
    NativeCapturePoint, NativeWorldOutcome, NativeWorldRecord, NativeWorldRequest,
    NativeWorldRetention, NativeWorldService, QualificationRunError,
    ReferenceQualificationObservation, ReferenceQualificationRun, load_installed_kvm_candidate,
    prepare_installed_kvm_candidate,
};
pub use service::{
    NodeObservationRetention, NodeObservationService, NodeObservationServiceConfig,
    NodeObservationServiceError,
};

#[cfg(test)]
mod tests;
