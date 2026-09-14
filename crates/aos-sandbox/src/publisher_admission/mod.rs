//! Dormant controller authority for project-domain publication.
//!
//! This module is deliberately independent of controller routing and service
//! activation. It defines the protected records and state transitions needed to
//! turn an exact, independently authenticated publisher request into durable
//! admission, prepared-artifact, completion-permit, and terminal accounting
//! facts. The surrounding controller will later adapt [`LedgerMutation`] values
//! to dedicated journal namespaces in one atomic transaction.
//!
//! Static publisher signatures are not effect authority. Only an
//! [`AdmittedPublisherPlan`] produced from a live
//! [`RuntimeJoinedPublisherRequest`] can enter this reducer, and only an
//! outstanding artifact-bound [`CompletionPermitV1`] can authorize canonical
//! naming and catalog completion.

mod accounting;
mod decision;
mod format;
mod model;
mod payload;
mod payload_decode;
mod protocol;
mod read_authority;
mod recovery;
mod replay;
mod source;

pub(crate) use decision::{
    ProtectedMutationBranchV1, ProtectedStoreSettlementReceiptV1, ProtectedStoreSettlementV1,
    RootRegistryOwnerToken, SourceRegistryOwnerToken,
};

pub use accounting::{
    AccountingError, CapacityAccountV1, CapacityPolicyV1, PublicationAccounting, ReservationStateV1,
};
pub use decision::{
    AdmissionError, AdmissionLedger, AdmissionResult, AdmittedPublisherPlan, ArtifactPreparation,
    CatalogEvictionAuthorizationV1, CatalogEvictionCommitV1, CatalogEvictionObservation,
    CommittedAdmissionFrontier, CommittedCatalogObservation, CompletionAuthorityV1,
    CompletionEffectCustodyV1, CompletionEffectObservationV1, CompletionSettlementV1,
    FreshSealedArtifactObservation, LivePublisherExecution, MaterializationAuthority,
    PermitIssueResult, ProtectedStoreCommitToken, RetainedCompletionPermit,
};
pub use format::{
    DecodedProtectedRecordV1, ProtectedRecordCodecError, decode_protected_record_v1,
    encode_protected_record_v1,
};
pub use model::{
    AdmissionDecisionStateV1, AdmissionDecisionV1, AdmissionLimits, ArtifactCommitmentV1,
    AuthorityCheckpointV1, CatalogEvictionReceiptV1, ChallengeConsumptionV1,
    CompletionPermitStateV1, CompletionPermitV1, CompletionReceiptV1, LedgerMutation,
    ProtectedRecordKindV1, PublicationAuthorityEpoch, PublicationPermitId, RecoveryDispositionV1,
    RecoveryObservationKindCodeV1, RecoveryObservationReceiptV1,
};
pub use payload_decode::DecodedPublisherPayloadV1;
pub use protocol::{
    CompletionDispositionV1, DescriptorAccessV1, DescriptorCommitmentV1, ObservedDescriptorV1,
    PublisherLocalBodyV1, PublisherLocalMessageV1, PublisherLocalMethodV1,
    PublisherLocalProtocolError, decode_local_message_v1, encode_local_message_v1,
};
pub use read_authority::{
    AuthorizedCacheRead, CacheReadAuthorityError, CacheReadDecisionV1, CommittedReadEntryV1,
    CurrentReadAuthority, CurrentReadCatalog, ExclusiveCatalogEvictionCustody,
    OpenForReadRequestV1, ReadAuthorityGrantV1, ReadAuthorityRegistryV1, ReadCatalogProjectionV1,
    ReadGrantStateV1, authorize_cache_read_v1,
};
pub use recovery::{
    CatalogRepairCompletionV1, CatalogRepairPermitV1, FailoverResultV1, RecoveryExecutorFenceV1,
    RecoveryObservationV1, RecoveryPhysicalCustodyV1, RecoveryResultV1,
};
pub use replay::{ProtectedLedgerReplayV1, ReplayedPublisherRecordV1, VerifiedHistoryFloorV1};
pub use source::{
    AuthorizedSourceRelease, SourceReleaseError, SourceReleaseRegistry, SourceReleaseStateV1,
    SourceReleaseV1,
};
