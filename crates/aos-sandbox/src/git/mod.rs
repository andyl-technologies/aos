//! Dormant Git repository, immutable-export, and exchange commitments.
//!
//! AOS does not define a replacement Git object protocol. The control envelope
//! in this module authorizes nothing by itself and is intended to select one
//! standard Git protocol-v2 upload-pack or receive-pack conversation after
//! the fixed protected session owner authenticates it and the protected Git
//! journal durably records its pre-effect transaction. No effect is activated.

mod checkpoint;
mod checkpoint_replay;
mod compaction;
mod confinement;
mod durable;
mod durable_payload;
mod fork_history;
mod format;
mod history;
mod journal;
mod lease_recovery;
mod model;
mod pack_format;
mod physical_effect;
mod protected_evidence;
pub mod protected_journal;
pub(crate) mod protected_owner;
mod protocol;
mod smart_owner;
mod smart_transport;
mod time;
pub(crate) mod validator;

pub use compaction::{
    GitRetiredPackSummaryV1, GitTerminalForkTombstoneV1, GitTerminalLeaseTombstoneV1,
    MAXIMUM_GIT_RETIRED_PACKS, MAXIMUM_GIT_TERMINAL_LEASE_TOMBSTONES,
};
pub use confinement::{
    SANDBOX_SOURCE_MAC_RULES_V1, SANDBOX_SOURCE_PROCESS_CONFINEMENT_V1,
    SandboxSourceConfinementErrorV1, SandboxSourceMacPermissionV1, SandboxSourceMacRuleV1,
    SandboxSourceProcessConfinementV1, SandboxSourceProtectedObjectV1,
    SandboxSourceSecurityDomainV1, sandbox_source_confinement_digest_v1,
    validate_sandbox_source_confinement_v1,
};
pub use durable::{
    GitDurableRecordKindV1, GitDurableRecordV1, GitProjectionCheckpointV1, GitProjectionHistoryV1,
    MAXIMUM_GIT_ATOMIC_JOIN_MEMBERS, MAXIMUM_GIT_DURABLE_BYTES, MAXIMUM_GIT_DURABLE_RECORDS,
    bind_git_atomic_join_v1, decode_git_durable_record_v1, decode_git_projection_checkpoint_v1,
    encode_git_durable_record_v1, encode_git_projection_checkpoint_v1, git_atomic_join_digest_v1,
};
pub use durable_payload::{
    GitDurablePayloadV1, MAXIMUM_GIT_DURABLE_PAYLOAD_BYTES, decode_git_durable_payload_v1,
    encode_git_durable_payload_v1,
};
pub use format::{decode_git_exchange_plan_v1, encode_git_exchange_plan_v1};
pub use history::{
    GitDurableHistoryV1, GitExportHistoryRecordV1, GitPackLeaseV1, GitPublicationRecordV1,
    GitReceiveHistoryRecordV1, GitReceivePhaseV1, GitRepositoryStateV1,
};
pub use journal::{
    GIT_JOURNAL_NAMESPACE_V1, GitAcceptedRecordSetV1, GitAcceptedRecordV1,
    GitBootRolloverAuthorityV1, GitJournalHistoryV1, GitJournalOwnershipRecordV1,
    GitJournalRecordKindV1, GitJournalVerifierV1, decode_git_journal_record_v1,
    encode_git_journal_record_v1, git_custodied_payload_digest_v1,
};
pub use model::{
    GitAdvertisedRefV1, GitAncestryProofDigestV1, GitAncestryReportV1, GitAtomicCasDigestV1,
    GitAudienceDigestV1, GitChannelBindingDigestV1, GitDescriptorRoleV1, GitDescriptorV1,
    GitExportGenerationDigestV1, GitExportGenerationV1, GitGraphCompletenessV1,
    GitGraphProofDigestV1, GitGraphValidatorEvidenceV1, GitModelError, GitObjectDatabaseDigestV1,
    GitObjectFormatV1, GitObjectGraphEvidenceV1, GitObjectIdV1, GitObjectInventoryDigestV1,
    GitPackGenerationDigestV1, GitPackGenerationPredecessorV1, GitPackIndexSetDigestV1,
    GitPhysicalObjectEnumerationV1, GitQuarantineDigestV1, GitReadAudienceV1, GitRefMapDigestV1,
    GitRefNameV1, GitRepositoryV1, GitTrustedValidatorV1, GitValidationPolicyDigestV1,
    GitValidatorTrustDigestV1, GitWholeObjectDatabaseV1, ImmutablePackGenerationV1,
    git_pack_index_set_digest_v1, git_ref_map_digest_v1,
};
pub use pack_format::{decode_pack_generation_v1, encode_pack_generation_v1};
pub use physical_effect::{
    DormantSanitizedGitForkEffectAdapterV1, DormantSanitizedGitForkPhysicalEffectV1,
    GitSanitizedForkConfigurationV1, GitSanitizedForkEffectHandoffV1,
    GitSanitizedForkEffectOutcomeV1, GitSanitizedForkExactRetryV1,
    GitSanitizedForkPhysicalCapabilityV1, GitSanitizedForkPhysicalEffectErrorV1,
    GitSanitizedForkPhysicalPlanV1, GitSanitizedForkPrepareOutcomeV1,
    GitSanitizedForkPrepareRecoveryV1, GitSanitizedForkPrepareReopenV1,
    GitSanitizedForkPrepareRetryV1, GitSanitizedForkPrepareUnknownV1,
    GitSanitizedForkProtectedReadbackOwnerV1, GitSanitizedForkReadbackErrorV1,
    GitSanitizedForkRecoveryTokenV1, GitSanitizedForkRecoveryV1,
    GitSanitizedForkSettlementOutcomeV1, GitSanitizedForkSettlementRecoveryV1,
    GitSanitizedForkSettlementRetryV1, GitSanitizedForkSettlementUnknownV1,
    GitSmartProtocolV2BackendV1, ProtectedGitSmartEffectAdapterV1, ProtectedGitSmartEffectErrorV1,
    ProtectedGitSmartInvocationV1,
};
pub use protected_evidence::{GitProtectedEvidenceErrorV1, GitProtectedEvidenceOwnerV1};
pub use protected_owner::GitProtectedJournalOwnerV1;
pub use protocol::{
    GitExchangePlanV1, GitProtocolV2CapabilitiesDigestV1, GitProtocolV2CapabilityV1,
    GitProtocolV2ProfileV1, GitProtocolV2ServiceV1, GitReceiveFenceV1, GitReceivePlanV1,
    GitRefTransitionV1, GitUploadPlanV1,
};
pub use smart_owner::{
    GitSmartProtectedObservationOwnerV1, GitSmartProtectedOwnerErrorV1,
    GitSmartProtectedSessionOwnerV1,
};
pub use smart_transport::{
    CHEAP_SANITIZED_GIT_FORK_FEATURE_MAJOR_V1, CHEAP_SANITIZED_GIT_FORK_FEATURE_MINOR_V1,
    CHEAP_SANITIZED_GIT_FORK_FEATURE_NAMESPACE_V1, CHEAP_SANITIZED_GIT_FORK_FIXTURE_V1,
    CHEAP_SANITIZED_GIT_FORK_UNQUALIFIED_REASON_V1, DormantGitSmartEffectV1,
    GitCheapForkCapabilityAdvertisementV1, GitSmartAuthorityFenceV1, GitSmartDispatchPhaseV1,
    GitSmartDispatchStateV1, GitSmartEffectHandoffV1, GitSmartEffectOutcomeV1, GitSmartEndpointV1,
    GitSmartPrepareOutcomeV1, GitSmartPrepareRecoveryV1, GitSmartRequestV1,
    GitSmartSettlementOutcomeV1, GitSmartSettlementRecoveryV1, GitSmartSettlementRetryV1,
    GitSmartSettlementUnknownV1, GitSmartTransportErrorV1, MAXIMUM_GIT_SMART_COMMAND_BYTES,
    cheap_sanitized_git_fork_fixture_digest_v1,
};
pub use time::{
    GitBootIdV1, GitBoottimeV1, GitCheapForkStatusV1, GitCheapForkV1, GitPackConsumerV1,
    GitPackLeaseStatusV1, GitTrustedBoottimeV1, MAXIMUM_GIT_HISTORY_RECORDS,
    MAXIMUM_GIT_PACK_LEASES,
};
