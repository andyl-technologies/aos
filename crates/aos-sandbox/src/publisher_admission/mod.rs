//! Dormant controller authority for project-domain publication.
//!
//! This module is deliberately independent of controller routing and service
//! activation. It defines the protected records and state transitions needed to
//! turn an exact, independently authenticated publisher request into durable
//! admission, prepared-artifact, completion-permit, and terminal accounting
//! facts. The dormant protected-journal adapter stores [`LedgerMutation`]
//! values, current head, and any newly outstanding completion effect as one
//! exact durable transaction without activating a service or route.
//!
//! Static publisher signatures are not effect authority. On Linux, only an
//! admitted plan produced from a live runtime join can enter the effect-bearing
//! reducer, and only an outstanding artifact-bound [`CompletionPermitV1`] can
//! authorize canonical naming and catalog completion. Portable accounting,
//! protocol, replay, and recovery models remain available on every target.

mod accounting;
mod controller_adapter;
mod decision;
mod format;
mod model;
mod payload;
mod payload_decode;
mod protected_journal;
mod protocol;
mod read_authority;
mod recovery;
mod replay;
#[cfg(target_os = "linux")]
mod settlement;
mod source;

pub(crate) use controller_adapter::{
    PublisherAdmissionControllerCommitV1, publisher_admission_controller_commit_v1,
};
pub(crate) use decision::{
    CapacityProtectedStoreSettlementV1, ProtectedMutationBranchV1,
    ProtectedStoreSettlementReceiptV1, RootRegistryOwnerToken, SourceRegistryOwnerToken,
    StateOnlyProtectedStoreSettlementV1,
};
pub(crate) use protected_journal::{
    AppliedPublisherAdmissionTransactionV1, PreparedPublisherAdmissionTransactionV1,
    PreparedPublisherCapacityAdmissionV1, PreparedPublisherCapacitySettlementV1,
    PublisherAdmissionColdObservationV1, PublisherAdmissionColdRecoveryV1,
    PublisherAdmissionCommitOutcomeV1, PublisherAdmissionJournalErrorV1,
    PublisherAdmissionJournalRecoveryV1, PublisherAdmissionOutcomeUnknownV1,
    PublisherAdmissionPostcommitCapabilityV1, PublisherAdmissionProtectedJournalV1,
    PublisherCapacityAdmissionCommitOutcomeV1, PublisherCapacityAdmissionOutcomeUnknownV1,
    PublisherCapacityAdmissionRecoveryV1, PublisherCapacitySettlementCommitOutcomeV1,
    PublisherCapacitySettlementOutcomeUnknownV1, PublisherCapacitySettlementRecoveryV1,
    PublisherCompletionCapacityV1, ValidatedPublisherAdmissionColdObservationV1,
    ValidatedPublisherAdmissionPostcommitV1,
};
#[cfg(target_os = "linux")]
pub(crate) use settlement::{
    PublisherCapacityProtectedStoreSettlementV1, PublisherProtectedJournalOwnerErrorV1,
    PublisherProtectedJournalOwnerV1, PublisherStateProtectedStoreSettlementV1,
};

pub use accounting::{
    AccountingError, CapacityAccountV1, CapacityPolicyV1, PublicationAccounting, ReservationStateV1,
};
pub use decision::{
    AdmissionError, AdmissionLedger, AdmissionResult, ArtifactPreparation,
    CatalogEvictionAuthorizationV1, CatalogEvictionCommitV1, CatalogEvictionObservation,
    CommittedAdmissionFrontier, CommittedCatalogObservation, CompletionEffectCustodyV1,
    CompletionEffectObservationV1, FreshSealedArtifactObservation, PermitIssueResult,
    ProtectedStoreCommitToken,
};
#[cfg(target_os = "linux")]
pub use decision::{
    AdmittedPublisherPlan, CompletionAuthorityV1, CompletionSettlementV1, LivePublisherExecution,
    MaterializationAuthority, RetainedCompletionPermit,
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
#[cfg(target_os = "linux")]
pub use read_authority::{AuthorizedCacheRead, CacheReadDecisionV1, authorize_cache_read_v1};
pub use read_authority::{
    CacheReadAuthorityError, CommittedReadEntryV1, CurrentReadAuthority, CurrentReadCatalog,
    ExclusiveCatalogEvictionCustody, OpenForReadRequestV1, ReadAuthorityGrantV1,
    ReadAuthorityRegistryV1, ReadCatalogProjectionV1, ReadGrantStateV1,
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
