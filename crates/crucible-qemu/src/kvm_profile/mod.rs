//! Native KVM discovery and controller-clock profile evidence.
//!
//! [`probe_native_kvm`] opens the real host device and interrogates its system
//! API. [`clock`] defines the bounded controller-time arithmetic, and [`KvmMediationManifest`]
//! validates complete native clock and effect-path inventories. None of these
//! local checks establishes a qualified profile without its kernel, emulator,
//! machine and device implementation evidence. KVM execution remains
//! nondeterministic and architectural capture excludes physical CPU microstate.

mod capture;
pub mod clock;
mod coverage;
mod installed;
mod node;
mod owned_components;
mod prepare;
mod probe;

pub use crate::qmp::{
    QmpKvmAccelerationState, QmpKvmClockComponentState, QmpKvmClockOperation, QmpKvmClockRequest,
    QmpKvmClockV3ComponentState, QmpKvmCompletionSummary, QmpKvmCompletionTransaction,
    QmpKvmInitialResponseObservation, QmpKvmInitialResponseOperation, QmpKvmInitialResponseRequest,
    QmpKvmInitialResponseState, QmpKvmInitialResponseTransaction, QmpKvmMoreResponseObservation,
    QmpKvmMoreResponseOperation, QmpKvmMoreResponseRequest, QmpKvmMoreResponseState,
    QmpKvmMoreResponseTransaction, QmpKvmOriginalAckTransaction, QmpKvmOriginalReturnIdentity,
    QmpKvmOriginalReturnObservation, QmpKvmOriginalReturnOperation, QmpKvmOriginalReturnRequest,
    QmpKvmOriginalReturnState, QmpKvmOriginalReturnsObservation, QmpKvmOriginalReturnsRequest,
    QmpKvmOriginalReturnsState, QmpKvmOriginalWindowObservation, QmpKvmOriginalWindowOperation,
    QmpKvmOriginalWindowRequest, QmpKvmOriginalWindowState, QmpKvmOriginalWindowTransaction,
    QmpKvmResponseBytesObservation, QmpKvmResponseBytesOperation, QmpKvmResponseBytesPayloadKind,
    QmpKvmResponseBytesRequest, QmpKvmResponseBytesState, QmpKvmUserspaceComponentState,
    QmpKvmUserspaceExitPhase, QmpKvmUserspaceExitRecord, QmpKvmUserspaceInventory,
};
pub use capture::{KvmArchitecturalCapture, KvmCaptureIdentity, KvmCapturedState};
pub use coverage::{
    KvmClockSource, KvmMediationEntry, KvmMediationManifest, KvmMediationMechanism,
};
pub use installed::{
    KvmCandidateArtifactPolicy, KvmCandidateArtifactRole, KvmCandidateError, KvmCandidatePolicy,
    KvmCandidatePreparation, KvmInstalledCandidate, KvmStoppedComponentInventory,
    MAX_KVM_CANDIDATE_ARTIFACT_BYTES, MAX_KVM_CANDIDATE_POLICY_BYTES,
    MAX_KVM_CANDIDATE_TOTAL_ARTIFACT_BYTES,
};
pub use node::{KVM_NODE_IMPLEMENTATION_ID, KvmNodePreparationFailure, KvmPreparedNode};
pub use owned_components::{
    KvmComponentError, KvmComponentObservation, KvmComponentSubmission, KvmComponentToken,
    KvmOwnedComponents,
};
pub use prepare::{KvmNativePreparation, prepare_native_kvm};
pub use probe::{KvmArchitecture, KvmHostProbe, probe_native_kvm};

/// Reports operational unavailability or refusal of an unqualified native profile.
#[derive(Debug, thiserror::Error)]
pub enum KvmProfileError {
    /// The native architecture is not one of the admitted implementation targets.
    #[error("native KVM architecture is unsupported: {architecture}")]
    UnsupportedArchitecture {
        /// Names the actual or requested architecture.
        architecture: String,
    },
    /// The actual KVM device could not be opened before native realization.
    #[error("native KVM device is unavailable: {source}")]
    DeviceUnavailable {
        /// Retains the original operating-system failure classification.
        #[source]
        source: std::io::Error,
    },
    /// A path named as KVM is not the expected kernel character device.
    #[error("native KVM path is not the expected kernel character device")]
    InvalidDevice,
    /// A real kernel operation failed without granting execution authority.
    #[error("native KVM operation {operation} failed: {source}")]
    Kernel {
        /// Identifies the system ABI operation.
        operation: &'static str,
        /// Retains the kernel's original failure.
        #[source]
        source: std::io::Error,
    },
    /// The real KVM API version differs from the supported system interface.
    #[error("unsupported native KVM API version {actual}; required 12")]
    ApiVersion {
        /// Reports the value returned by the actual kernel.
        actual: i32,
    },
    /// A complete implementation requirement has no accepted native proof.
    #[error("native KVM mediation is incomplete: {requirement}")]
    MissingMediation {
        /// Names the missing clock, interrupt or effect-path obligation.
        requirement: String,
    },
    /// A native receipt or capture conflicts with its original realization.
    #[error("native KVM identity mismatch: {field}")]
    Identity {
        /// Identifies the incompatible context or field.
        field: &'static str,
    },
    /// Checked controller-time arithmetic cannot represent the requested work.
    #[error("native KVM clock arithmetic overflow")]
    Overflow,
    /// Clock work conflicts with the retained original window or phase.
    #[error("invalid native KVM clock transition: {reason}")]
    ClockTransition {
        /// Explains the refused transition without executing guest work.
        reason: &'static str,
    },
    /// Portable context does not satisfy its closed schema.
    #[error("invalid native KVM portable context: {0}")]
    Contract(#[from] crucible_node_contract::ContractError),
}
