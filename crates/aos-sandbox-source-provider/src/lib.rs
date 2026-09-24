//! Durable provider-owned SourceProvider policy and state.
//!
//! This production-inert crate owns the canonical `AOSSPL01` journal graph,
//! normalized acquisition intent, hostile recovery, exactly-once request
//! reservations, backend effect permits, completion ordering, and retained
//! replay responses. Its constructible dormant backend adapter accepts only an
//! externally supplied raw transport; a fixed root-owned verifier set must
//! authenticate every class-specific observation before completion. Neither
//! transport nor verifier inputs expose protected authority. The crate is a
//! Linux-only boundary and deliberately has no listener, daemon, socket,
//! service, Nix wiring, or production feature advertisement.
//!
//! [`ProviderLedgerV1`] is lent only by [`FixedProviderOwnerV1`], which binds
//! fixed protected custody and journal paths to one authenticated live session.
//! The dormant bootstrap path mints configuration from revalidated security
//! custody and a verified catalog publication; it activates no listener or backend.
//! Request admission always invokes protocol verification inside the ledger
//! facade; arbitrary pre-verified values are never accepted.

#![cfg(target_os = "linux")]

mod acquire;
mod admission;
pub mod backend;
mod backend_adapter;
mod backend_verifier;
mod configuration;
mod error;
mod inventory;
mod limits;
mod migration;
mod owner;
mod pending;
mod recovery;
mod recovery_bridge;
mod release;
mod state;
mod storage_export_selection;
mod transaction;

pub(crate) use aos_sandbox_source_provider_ledger::ledger;
pub(crate) use ledger::{format, model};

pub use admission::{
    DurableAcquireRebindPermitV1, DurableAcquireReplayV1, DurableCachedResponseV1,
    ProviderAdmissionDispositionV1,
};
pub use aos_sandbox_source_provider_ledger::migration::{
    LegacyRecordExpectationV1, MigrationReplacementRecordV1, SupplementalV2MigrationProvenanceV1,
};
pub use aos_sandbox_source_provider_protocol::{
    MAXIMUM_NORMALIZED_ACQUISITION_INTENT_BYTES, NormalizedAcquisitionIntentV1,
};
pub use backend::{
    AcquireObservationV1, AcquirePlanV1, ActiveAcquisitionSnapshotV1, BackendEvidenceClassV1,
    BackendEvidenceStateV1, BackendEvidenceV1, DurableAcquireEffectPermitV1,
    DurableProviderReplyV1, DurableReleaseEffectPermitV1, DurableReleaseTombstoneV1,
    LocalLiveEvidenceBindingV1, ObservedBackendAcquisitionV1, ObservedBackendReleaseV1,
    ProviderPhysicalSourceRootV1, ReleaseObservationV1, ReleasePlanV1, ReopenIdentityV1,
    ReopenObservationV1, ReopenedSourceRootV1, SourceProviderBackendV1,
};
pub use backend_adapter::{
    FixedProviderBackendRequestOutcomeV1, FixedProviderBackendSessionV1,
    FixedProviderReceivedRequestProgressV1, RawAcquireNotAppliedV1, RawAcquireObservationV1,
    RawBackendAcquisitionV1, RawBackendReleaseV1, RawReleaseObservationV1,
    RawReleaseStillPresentV1, RawReopenObservationV1, SourceProviderBackendTransportErrorV1,
    SourceProviderBackendTransportV1,
};
pub use backend_verifier::{
    BackendObservationChallengeV1, BackendVerifierRoleV1, RawBackendAttestationV1,
    backend_acquire_absence_attestation_statement_v1, backend_acquisition_attestation_statement_v1,
    backend_attestation_signing_message_v1, backend_release_attestation_statement_v1,
    backend_release_presence_attestation_statement_v1, backend_reopen_attestation_statement_v1,
};
pub use configuration::VerifiedCatalogPublicationV1;
pub use error::ProviderLedgerError;
pub use inventory::DurableInventoryPermitV1;
pub use ledger::LedgerFormatErrorV1;
pub use limits::ProviderLedgerLimits;
pub use model::{
    ProviderAcquisitionStateV1, ProviderAttemptStateV1, ProviderAuthorityStateV1,
    ProviderRecoveryWorkV1, ProviderReleaseStateV1, RecoveredProviderLedgerV1,
    SourceRootIdentityV1,
};
pub use owner::{
    FixedMountStateMigrationRecoveryOutcomeV2, FixedProviderAcquireReopenV1,
    FixedProviderAuthenticatedSourceRequestV1, FixedProviderCatalogProgressV1,
    FixedProviderHistoricalOutcomeV1, FixedProviderIngressProgressV1, FixedProviderOpenReportV1,
    FixedProviderOwnerStatusV1, FixedProviderOwnerV1, FixedProviderRequestReadbackV1,
    ProtectedProviderMountRetryAuthorityV1,
};
pub use recovery::{
    ProviderRecoveryObservationV1, RecoveryAcquireNotAppliedV1, RecoveryReleaseStillPresentV1,
};
pub use recovery_bridge::ProviderRecoveryContinuationV1;
pub use state::{ProtectedProviderConfigurationV1, ProviderLedgerV1};
pub use storage_export_selection::ProviderStorageExportPlanBasisV1;
