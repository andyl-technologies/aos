//! Protected, production-inert SourceProvider custody foundation.
//!
//! This crate decodes the fixed `AOSPSEC1`, `AOSPTRS2`, and `AOSPRTE1`
//! protected records, retains role-local signing keys and kernel process
//! identity, derives process-exclusive hello nonces, and defines sealed
//! handshake, descriptor, boot, and death-evidence states. Public entry points
//! expose only fixed dormant owners, protected revalidation, and execution-death proof;
//! no raw live-session, signing, descriptor-release, or response-send authority
//! escapes those owners.
//!
//! Purpose-specific provider signing remains inside revalidated live custody.
//! It accepts only typed protocol subjects; it exposes no raw key, generic
//! signing oracle, durable send permission, service, listener, socket path,
//! backend dispatch, feature advertisement, or descriptor-release API.
//!
//! Linux descriptor-subject records identify a privileged sender-nominated
//! process, which is not necessarily the process that executed the socket
//! syscall. Production activation therefore remains gated on a concrete MAC
//! and capability policy that prevents socket-file-description delegation and
//! unauthorized subject nomination. The retained pidfd, credential, cgroup,
//! and socket evidence here does not by itself discharge that system policy.

#![cfg(target_os = "linux")]
#![allow(
    dead_code,
    reason = "the security foundation stays sealed until concrete AOSSPL receipts exist"
)]

mod carrier;
mod catalog;
mod configuration;
mod custody;
mod descriptor;
mod entropy;
mod error;
mod execution;
mod handshake;
pub mod manifest;
mod migration;
mod protected_files;
pub mod route_file;
pub mod trust_file;

pub use carrier::ProviderSourceRootHandoffV1;
pub use catalog::{
    CurrentCatalogPublicationProjectionV1, ProtectedCurrentCatalogPublicationV1,
    ProtectedProviderCatalogSelectionV1, ProtectedProviderHeldSnapshotSelectionV1,
    VerifiedCatalogPublicationV1, verify_catalog_publication, verify_retained_catalog_publication,
};
pub use configuration::{HistoricalProviderVerificationKeyV1, RevalidatedProviderConfigurationV1};
pub use custody::{
    ProtectedProviderCustodyV1, ProtectedRootMountCustodyV1, validate_fixed_provider_authority_v1,
    validate_fixed_root_mount_authority_v1,
};
pub use descriptor::{
    ActiveMountSourceRootV2, CommittedMountSourceReleaseV2, CommittedSourceRootV1,
    ConsumedMountSourceRootV2, MountSourceReleaseAuthorityV2, MountSourceRemovalPreparationV2,
    MountSourceRootCustodyProjectionV2, MountSourceRootCustodyV2,
    NegativeCustodyPostcommitOutcomeV2, NegativeCustodyPostcommitRecoveryV2, ObservedSourceRootV1,
    PendingMountSourceRootCustodyV2, PendingReleasedMountSourceRootV2,
    PreparedActiveMountSourceRootV2, PreparedMountSourceConsumptionV2,
    PreparedMountSourceReleaseV2, PreparedMountSourceRootCustodyV2,
    PreparedReleasedMountSourceRootV2, PreparedStartupMountSourceAdoptionV2,
    RecoveredRetainedMountSourceRootV2, ReleasedMountSourceRootV2,
    RetainedMountSourceReleaseForRemovalV2, SourceRootPostcommitOutcomeV2,
    SourceRootPostcommitRecoveryV2, SourceRootPostcommitSuccessV2,
};
pub use error::SourceProviderSecurityError;
pub use execution::{
    CurrentKernelBootV1, DeadProviderExecutionProjectionV2, DeadProviderExecutionV1,
    ProviderExecutionDeathKindV2,
};
pub use handshake::{
    AcquireReceiptFactsV1, AuthenticatedRootMountCatalogCurrentnessV1,
    AuthenticatedRootMountRecoveryUnavailableV1, AuthorizedMountAcquireVerificationFloorV2,
    AuthorizedMountProviderOutcomeV2, CapturedMountProviderRecoveryOutcomeV2,
    CommittedProviderOutcomeV1, CommittedReopenedMountSourceRootV2,
    CurrentMountProviderSessionPlanV2, CurrentProviderIngressSessionV1, CurrentProviderRequestV1,
    CurrentProviderSessionProjectionV1, CurrentRootMountSourceProviderSessionV1,
    HistoricalMountInventoryAuthorizationV2, HistoricalMountReleaseAuthorizationV2,
    InventoryReadbackProgressV1, MountProviderAuthorityTrustProjectionV2,
    MountProviderRequestProjectionV2, MountProviderRequestSendRecoveryV2,
    MountProviderSessionProjectionV2, MountProviderSignerProjectionV2, PersistedProviderOutcomeV1,
    PreparedMountProviderRequestV2, ProviderCompletionBuilderV1, ProviderIngressReopenCheckpointV1,
    ProviderOutcomeAuthorizationV1, ProviderOwnerSecurityFacadeV1,
    ProviderSessionSupersessionEvidenceV1, ProviderSourceProviderHandshakeStatusV1,
    ProviderSourceProviderOwnerV1, ReceivedMountProviderOutcomePartsV2,
    RecoveredMountProviderOutcomePartsV2, RecoveredMountProviderOutcomeV2,
    ReopenedMountSourceRootV2, ReservedMountProviderRequestV2, RetainedRootRecoveryAuthorizationV2,
    RevalidatedProviderReplayV1, RootMountSourceProviderHandshakeStatusV1,
    RootMountSourceProviderOwnerV1, SentMountProviderRequestV2, VerifiedMountProviderOutcomeV2,
    VerifiedReceivedMountProviderOutcomeV2,
};
pub use migration::{
    AuthorizedMountSourceStateMigrationV2, AuthorizedV2MigrationInstallPartsV1,
    AuthorizedV2MigrationPlanV1, MountSourceStateMigrationInstallOutcomeV2,
    MountSourceStateMigrationRecoveryV2,
};
pub use trust_file::ProtectedTrustHeadLinkV2;
