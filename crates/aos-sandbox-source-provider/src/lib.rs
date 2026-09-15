//! Durable provider-owned SourceProvider policy and state.
//!
//! This production-inert crate owns the canonical `AOSSPL01` journal graph,
//! normalized acquisition intent, hostile recovery, exactly-once request
//! reservations, backend effect permits, completion ordering, and retained
//! replay responses. It deliberately has no listener, daemon, socket, service,
//! Nix wiring, production feature advertisement, or real backend adapter.
//!
//! [`ProviderLedgerV1`] is lent only by [`FixedProviderOwnerV1`], which binds
//! fixed protected custody and journal paths to one authenticated live session.
//! The dormant bootstrap path mints configuration from revalidated security
//! custody and a verified catalog publication; it activates no listener or backend.
//! Request admission always invokes protocol verification inside the ledger
//! facade; arbitrary pre-verified values are never accepted.

mod acquire;
mod admission;
pub mod backend;
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
    ObservedBackendAcquisitionV1, ObservedBackendReleaseV1, ProviderPhysicalSourceRootV1,
    ReleaseObservationV1, ReleasePlanV1, ReopenIdentityV1, ReopenObservationV1,
    ReopenedSourceRootV1, SourceProviderBackendV1,
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
    FixedMountStateMigrationRecoveryOutcomeV2, FixedProviderOpenReportV1,
    FixedProviderOwnerStatusV1, FixedProviderOwnerV1,
};
pub use recovery::{
    ProviderRecoveryObservationV1, RecoveryAcquireNotAppliedV1, RecoveryReleaseStillPresentV1,
};
pub use recovery_bridge::ProviderRecoveryContinuationV1;
pub use state::{ProtectedProviderConfigurationV1, ProviderLedgerV1};
