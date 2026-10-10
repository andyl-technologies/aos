//! Owns protected Policy publication and its original-owner continuations.
//!
//! The pure compiler is owned by `aos-sandbox-policy`. This partition retains
//! the protected ancestry/currentness joins, canonical publication replay and
//! actual Root, Source, Cache and Controller custody. Extracting compiler DATA
//! does not make those effect-owning continuations independent.

mod all_owner_readback_session;
mod binding_v2;
mod cache_journal_readback;
mod cache_readback_pin;
mod cache_readback_session;
mod cache_root_settlement;
mod controller_adapter;
mod controller_effect_ack_readback;
mod controller_effect_ack_readback_v8;
mod controller_hold_pin;
mod controller_hold_readback;
mod controller_project_admission_readback;
mod controller_project_dispatch_readback;
mod controller_project_terminal_readback;

#[cfg(target_os = "linux")]
pub(in crate::policy_compiler) use controller_hold_readback::sign_q04_held_controller_v1;
#[cfg(target_os = "linux")]
pub(in crate::policy_compiler) use controller_project_admission_readback::{
    sign_q04_current_controller_project_v1, sign_q04_prehold_input_v1,
};

pub use controller_project_dispatch_readback::{
    CONTROLLER_PROJECT_DISPATCH_READBACK_BYTES_V1,
    sign_fixed_controller_project_dispatch_readback_v1,
};
#[cfg(test)]
pub(crate) use controller_project_dispatch_readback::{
    sign_synthetic_controller_project_dispatch_v1, verify_controller_project_dispatch_readback_v1,
};

pub use controller_project_terminal_readback::{
    CONTROLLER_PROJECT_TERMINAL_READBACK_BYTES_V1,
    sign_fixed_controller_project_terminal_readback_v1,
};
mod controller_readback_session;
#[cfg(target_os = "linux")]
pub(crate) use controller_readback_session::fresh_root_nonce;
mod controller_root_receipt_readback_v8;
mod controller_v8_readback_envelope;
mod controller_v8_settlement_readback;
mod deployment_head;
#[cfg(target_os = "linux")]
mod git_coverage_enrollment;
#[cfg(target_os = "linux")]
pub use git_coverage_enrollment::{
    GIT_COVERAGE_ROOT_BOOTSTRAP_MAGIC_V1, GitCoverageRootClientV1,
    GitCoverageRootFlightErrorV1, GitCoverageAccountAttemptV1,
    GitCoverageNativeCutDataV1, RootGitCoverageEnrollmentOwnerV1,
};
#[cfg(target_os = "linux")]
mod nix_current_preflight;
#[cfg(target_os = "linux")]
pub use nix_current_preflight::{
    CURRENT_NIX_PREFLIGHT_CONTEXT_BYTES_V1, CURRENT_NIX_CONTROLLER_RECEIPT_BYTES_V1,
    CURRENT_NIX_SOURCE_REQUEST_BYTES_V1, CURRENT_NIX_SOURCE_LEGACY_REPLY_BYTES_V1,
    CURRENT_NIX_SOURCE_LEGACY_GENESIS_REPLY_BYTES_V1, CURRENT_NIX_SOURCE_RESOURCE_REPLY_BYTES_V1,
    CurrentNixPreflightContextV1, CurrentNixPreflightDataErrorV1,
    CurrentNixPreflightAttemptV1, CurrentNixPreflightOriginalsV1,
    CurrentNixSourceIoCellV1,
    VerifiedCurrentNixControllerReceiptV1, VerifiedCurrentNixSourceObservationV1,
};
mod owner_pin_transaction;
mod project_admission_root;

#[cfg(test)]
pub(crate) use project_admission_root::test_root_project_reservation_cancellation_v1;
#[cfg(test)]
pub(crate) use project_admission_root::test_signed_project_heads_for_history_v1;
#[cfg(test)]
pub(crate) use project_admission_root::test_source_project_admission_outcome_v1;
pub(crate) use project_admission_root::{
    ROOT_PROJECT_ADMISSION_INTENT_BYTES_V2, ROOT_PROJECT_HISTORY_FLOOR_BYTES_V1,
    ROOT_PROJECT_NEGATIVE_INTENT_BYTES_V1, validate_root_project_capacity_settlement_v1,
    validate_root_project_capacity_transfer_v1,
};
mod project_source_v2;
mod project_source_v3;
mod protected_journal;
#[cfg(target_os = "linux")]
pub(crate) mod create_q04;
#[cfg(target_os = "linux")]
pub use create_q04::root::{
    OriginalRootCreateQ04AttemptV1, ROOT_CREATE_Q04_QUERY_MAGIC_V1,
    RootCreateQ04SourceObservationLoanV1,
};
mod protected_owner;
mod public_create_source;
pub(crate) use public_create_source::{
    HistoricalCreateProjectSourceHeadsV1, create_project_source_commitment_v1,
};
#[cfg(target_os = "linux")]
pub mod consumer_read_flight;
mod publisher_origin;
mod resolved_policy;
mod resource_read;
mod root_challenge_record;
mod root_project_admission_proof;
mod root_startup_journal;
pub use root_startup_journal::{RootPolicyStartupDeploymentV1, RootPolicyStartupJournalV1};
mod root_v8_released_proof;
mod root_v8_settled_grant;
mod source_genesis_readback;
#[cfg(target_os = "linux")]
mod source_genesis_root;
#[path = "source_genesis_root/successor_records.rs"]
mod first_source_successor_records;
#[cfg(target_os = "linux")]
mod source_successor_readback;
#[cfg(target_os = "linux")]
pub use source_successor_readback::{
    SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2, SourceFirstSuccessorReadbackPhaseV2,
    VerifiedSourceFirstSuccessorReadbackV2, verify_source_first_successor_readback_v2,
    SOURCE_PROJECT_CONTINUATION_READBACK_BYTES_V3, VerifiedSourceProjectContinuationReadbackV3,
    verify_source_project_continuation_readback_v3,
    SOURCE_RESOURCE_SUCCESSOR_LEGACY_GENESIS_BYTES_V4, SOURCE_RESOURCE_SUCCESSOR_READBACK_BYTES_V4,
    verify_source_resource_first_successor_readback_v4,
    verify_source_resource_project_continuation_readback_v5,
};
#[cfg(target_os = "linux")]
pub use source_signer_readback::{
    CurrentNixSourceObservationAttemptV1, observe_fixed_current_nix_source_into_v1,
    sign_fixed_source_first_successor_readback_v2,
    sign_fixed_source_project_continuation_readback_v3,
    sign_fixed_source_resource_successor_readback_v4,
};
#[cfg(target_os = "linux")]
pub use source_genesis_root::{
    HeldControllerFirstSourceSuccessorV2, HeldRootFirstSourceSuccessorIntentV2,
    RootFirstSourceSuccessorFloorProofV2,
    RootFirstSuccessorMutationResultsV2, CurrentRootFirstSourceSuccessorFloorV2,
    FailedOriginalFirstSourceSuccessorV2, FirstSourceSuccessorConsumerPhaseV2,
    FirstSourceSuccessorSelectionV2, OriginalFirstSourceSuccessorInvocationV2,
    HeldControllerProjectSuccessorV3, HeldRootProjectSuccessorIntentV3,
    RootProjectSuccessorFloorProofV3, CurrentRootProjectSuccessorFloorV3,
    OriginalProjectSuccessorInvocationV3, FailedProjectSuccessorInvocationV3,
};
#[cfg(target_os = "linux")]
pub(crate) use source_genesis_root::{ControllerSuccessorOwnerViewV3, RootSuccessorIntentViewV3, RootSuccessorFloorViewV3};
#[cfg(target_os = "linux")]
pub(crate) use source_genesis_root::RootSuccessorNativeServerCutV3;
#[cfg(target_os = "linux")]
pub(crate) use source_genesis_root::{unavailable_project_successor_v3, unavailable_predecessor_successor_v3};

pub use first_source_successor_records::{
    ControllerFirstSourceSuccessorAnchoredV2, ControllerFirstSourceSuccessorBeginV2,
    ControllerFirstSourceSuccessorCompleteV2, RootFirstSourceSuccessorFloorV2,
    RootFirstSourceSuccessorIntentV2, SourceFirstSuccessorAckV2,
    SourceFirstSuccessorPendingV2, SourceFirstSuccessorReceiptV2,
};
pub(crate) use first_source_successor_records::{
    ControllerFirstSourceSuccessorAnchoredFieldsV2, ControllerFirstSourceSuccessorBeginFieldsV2,
    ControllerFirstSourceSuccessorCompleteFieldsV2, RootFirstSourceSuccessorFloorFieldsV2,
    RootFirstSourceSuccessorIntentFieldsV2, SourceFirstSuccessorAckFieldsV2,
    SourceFirstSuccessorPendingFieldsV2, SourceFirstSuccessorReceiptFieldsV2,
};
#[cfg(target_os = "linux")]
pub(crate) use source_genesis_root::{
    require_root_first_source_successor_capacity_owner_v2,
    validate_root_first_source_successor_state_v2,
    validate_root_first_source_successor_transition_v2,
    unavailable_first_source_successor_v2,
};
mod source_hold_pin;
#[cfg(target_os = "linux")]
pub(crate) use source_genesis_root::Q04RootGen1CutLoanV1;
#[cfg(target_os = "linux")]
pub(crate) use public_create_source::{
    consume_completed_gen1_ancestry_v1,
    consume_completed_project_genesis_ancestry_v3,
};
#[cfg(target_os = "linux")]
pub(crate) use source_genesis_root::{
    CompletedRootSourceGenesisFloorV1,
    GlobalRootGenesisNativeCutV2,
};
mod source_hold_readback;
mod source_hold_readback_v2;
#[cfg(target_os = "linux")]
pub use source_genesis_root::{
    RootFirstSourceSuccessorOpeningV2,
    RootProjectGenesisMutationResultsV3, CurrentRootSourceProjectGenesisFloorV3,
    OriginalConfiguredProjectGenesisInvocationV3, FailedConfiguredProjectGenesisInvocationV3,
    ROOT_SOURCE_PROJECT_GENESIS_QUERY_MAGIC_V3, ROOT_SOURCE_PROJECT_GENESIS_HELLO_MAGIC_V3,
    encode_root_source_project_genesis_frame_v3, decode_root_source_project_genesis_frame_v3,
    root_source_project_genesis_payload_bytes_v3,
    root_resource_successor_payload_bytes_v4,
    ROOT_FIRST_SOURCE_SUCCESSOR_HELLO_MAGIC_V2, ROOT_FIRST_SOURCE_SUCCESSOR_QUERY_MAGIC_V2,
    ROOT_PROJECT_SOURCE_SUCCESSOR_HELLO_MAGIC_V3, ROOT_PROJECT_SOURCE_SUCCESSOR_QUERY_MAGIC_V3,
    RootFirstSourceSuccessorFrameKindV2, decode_root_first_source_successor_frame_v2,
    encode_root_first_source_successor_frame_v2,
    encode_root_project_source_successor_frame_v3, decode_root_project_source_successor_frame_v3,
    observe_root_first_source_successor_clock_v2,
    CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1, CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2,
    CurrentRootSourceGenesisFloorV1,
    HeldRootSourceGenesisIntentV1, ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1,
    HeldRootSourceProjectGenesisIntentV3, RootSourceProjectGenesisFloorProofV3,
    FailedOriginalSourceSuccessorInvocationV2, OriginalSourceSuccessorInvocationV2,
    OriginalSourceProjectSuccessorInvocationV3, FailedSourceProjectSuccessorInvocationV3,
    SourceSuccessorIssuancePhaseV2,
    ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1, ROOT_SOURCE_GENESIS_INTENT_BYTES_V1,
    ROOT_SOURCE_GENESIS_INTENT_BYTES_V2,
    ROOT_SOURCE_GENESIS_QUERY_MAGIC_V1, RootSourceGenesisAuthorityV1,
    RootSourceGenesisFloorProofV1, RootSourceGenesisFrameKindV1, RootSourceGenesisIntentRecordV1,
    SOURCE_GENESIS_DEPLOYMENT_INSTANCE_BYTES_V1, SOURCE_HIERARCHY_FLOOR_BYTES_V1,
    SOURCE_HIERARCHY_FLOOR_BYTES_V2,
    SourceHierarchyFloorRecordV1, coordinate_provisioned_source_genesis_v1,
    ROOT_SOURCE_RESOURCE_GENESIS_QUERY_MAGIC_V2, root_source_resource_genesis_payload_bytes_v2,
    OriginalConfiguredGlobalGenesisInvocationV2, FailedConfiguredGlobalGenesisInvocationV2,
    decode_root_source_genesis_frame_v1, encode_root_source_genesis_frame_v1,
    decode_root_source_genesis_frame_v2, encode_root_source_genesis_frame_v2,
    fixed_root_source_genesis_recovery_available_v1,
    sign_controller_source_genesis_completion_readback_v1,
    sign_controller_source_genesis_readback_v1,
};
#[cfg(target_os = "linux")]
pub(crate) use source_genesis_root::{
    unavailable_project_genesis_v3,
    unavailable_global_genesis_v2,
    require_root_source_genesis_capacity_owner_v1, require_root_source_genesis_mutation_v1,
    validate_root_source_genesis_capacity_admission_v1,
    validate_root_source_genesis_capacity_settlement_v1,
    SourceSuccessorSigningCutV2, SourceSuccessorSigningCutV3, CompletedRootSourceProjectGenesisFloorV3,
    unavailable_source_successor_issuer_v2,
    unavailable_project_issuer_v3,
};
mod source_project_admission_readback;
#[cfg(target_os = "linux")]
mod source_signer_readback;
#[cfg(target_os = "linux")]
mod v8_successor_clear;

pub use all_owner_readback_session::{
    ClosedAllOwnerExpectedHoldsV1, ClosedAllOwnerReadbackErrorV1, ClosedAllOwnerReadbackPacketsV1,
    ClosedAllOwnerRootChallengeV1, ClosedAllOwnerRootObservationV1,
    with_fixed_closed_all_owner_readback_session_v1,
};
pub use binding_v2::{
    CLOSED_POLICY_BINDING_BYTES_V2, CLOSED_SOURCE_TERMINAL_RECORD_BYTES_V1,
    CONTROLLER_V8_FINAL_RELEASE_BYTES_V1, ClosedPolicyBindingDecisionV2,
    ClosedPolicyEffectHandoffV2, ClosedPolicyRootCacheCutV2, ClosedPolicyRootCasBaseV2,
    ClosedPolicyRootCasObservationV2, ClosedPolicyRootSessionV2, ClosedPolicyRootSignerJoinV2,
    ClosedSourceTerminalClaimV1, ClosedSourceTerminalRecordV1, ROOT_EFFECT_ACK_RECORD_BYTES_V1,
    ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1, RootEffectAckErrorV1, RootEffectAckV1,
    RootV8EffectAckErrorV1, RootV8EffectAckV1, RootV8HeldTerminalStepV1,
    RootV8SuccessorSettlementV1, RootV8TerminalCustodyV1, RootV8VerifiedTerminalV1,
    StagedClosedPolicyRootBaseV2, StagedClosedPolicySignerChallengeV2,
    acknowledge_and_verify_fixed_closed_root_v8_terminal_v1,
    acknowledge_fixed_closed_root_effect_v1, acknowledge_fixed_closed_root_v8_effect_v1,
    acknowledge_verify_and_release_fixed_closed_root_v8_terminal_v1,
    closed_policy_binding_digest_v2, closed_policy_effect_handoff_v2,
    compare_closed_policy_binding_hold_claims_v2,
    compare_closed_policy_binding_released_cache_claims_v2,
    propose_closed_current_create_explicit_policy_binding_v2,
    read_fixed_inert_closed_policy_binding_hold_v1,
    recover_fixed_closed_policy_binding_decision_v2, recover_fixed_closed_root_effect_ack_v1,
    recover_fixed_closed_root_v8_effect_ack_v1,
    recover_fixed_closed_root_v8_predecessor_settlement_v1,
    recover_fixed_closed_root_v8_terminal_custody_v1,
    recover_fixed_closed_root_v8_verified_terminal_v1,
    recover_fixed_committed_source_held_binding_v2, release_fixed_closed_policy_cache_hold_v1,
    release_fixed_closed_policy_controller_hold_v1,
    release_fixed_closed_policy_source_domain_hold_v1,
    release_fixed_inert_closed_policy_binding_hold_v1,
    require_no_fixed_closed_policy_binding_hold_v1, settle_fixed_closed_root_v8_predecessor_v1,
    sign_fixed_controller_v8_final_release_v1, staged_closed_policy_signer_challenge_v2,
    verify_fixed_closed_root_v8_terminal_v1, with_fixed_explicit_closed_policy_binding_session_v2,
};
pub use cache_journal_readback::{
    ClosedCacheJoinedReadbackErrorV2, read_fixed_policy_cache_hold_v1,
    read_fixed_policy_cache_journals_v1, verify_fixed_policy_cache_owner_readback_v2,
};
pub use cache_readback_pin::{CacheReadbackPinErrorV1, admit_fixed_cache_readback_pin_v1};
pub use cache_readback_session::{
    CacheSignerRootChallengeReadbackV2, CacheSignerRootChallengeStatusV2,
    CacheSignerRootSettlementStateV2, ClosedCacheReadbackSessionErrorV1,
    StagedCacheSignerRootChallengeV2, abandon_fixed_cache_signer_challenge_v2,
    compact_fixed_cache_signer_root_journal_v2, read_fixed_cache_signer_challenge_v2,
    record_fixed_cache_signer_root_settlement_v2, recover_fixed_cache_signer_abandonment_v2,
    recover_fixed_cache_signer_root_history_v2, recover_fixed_cache_signer_root_settlement_v2,
    stage_fixed_cache_signer_challenge_v2, verify_fixed_staged_cache_signer_packet_v2,
};
pub use controller_adapter::{
    PolicyCompilerControllerCommitV1, policy_compiler_controller_commit_v1,
};
pub use controller_effect_ack_readback::{
    CONTROLLER_EFFECT_ACK_READBACK_BYTES_V1, ControllerEffectAckChallengeV1,
    ControllerEffectAckReadbackErrorV1, VerifiedControllerEffectAckV1,
    sign_fixed_controller_effect_ack_readback_v1, verify_controller_effect_ack_readback_v1,
};
pub use controller_effect_ack_readback_v8::{
    CONTROLLER_V8_EFFECT_ACK_READBACK_BYTES_V1, sign_fixed_controller_v8_effect_ack_readback_v1,
    verify_controller_v8_effect_ack_readback_v1,
};
pub use controller_hold_pin::{ControllerHoldPinErrorV1, admit_fixed_controller_hold_pin_v1};
pub use controller_hold_readback::{
    CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1, ControllerHoldReadbackChallengeV1,
    ControllerHoldReadbackErrorV1, PinnedControllerHoldSignerV1, VerifiedControllerHoldReadbackV1,
    encode_controller_hold_signer_credential_v1, sign_fixed_controller_hold_readback_v1,
    verify_controller_hold_readback_v1,
};
pub use controller_project_admission_readback::{
    CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1, ControllerProjectAdmissionChallengeV1,
    ControllerProjectAdmissionReadbackErrorV1, VerifiedControllerProjectAdmissionV1,
    sign_fixed_controller_project_admission_readback_v1,
    verify_controller_project_admission_readback_v1,
};
pub use controller_readback_session::{
    ClosedControllerReadbackSessionErrorV1, ClosedControllerRootChallengeV1,
    ClosedControllerRootObservationV1, with_fixed_closed_controller_readback_session_v1,
};
pub use controller_root_receipt_readback_v8::{
    CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1,
    sign_fixed_controller_v8_root_receipt_readback_v1,
    verify_controller_v8_root_receipt_readback_v1,
};
pub use controller_v8_settlement_readback::{
    CONTROLLER_V8_SETTLEMENT_READBACK_BYTES_V1, sign_fixed_controller_v8_settlement_readback_v1,
};
pub use deployment_head::{
    PolicyDeploymentCatalogDeclarationsV2, PolicyDeploymentHeadErrorV1, PolicyDeploymentHeadV1,
    PolicyDeploymentInputProfileV2, PolicyDeploymentInputsV1, PolicyDeploymentSourcesV1,
    SignedProjectPolicyHeadV1, admit_fixed_policy_deployment_head_v1,
    admit_fixed_policy_deployment_profile_v2, admit_fixed_policy_signer_pins_v1,
    decode_policy_deployment_sources_v1, verify_current_policy_deployment_profile_v2,
    verify_policy_deployment_head_v1,
};
pub use project_admission_root::{
    RootProjectAdmissionIntentV1, RootProjectAdmissionOutcomeKindV1, RootProjectAdmissionOutcomeV1,
    RootProjectAdmissionStageV1, RootProjectHistoryFloorV1, RootProjectHistoryTerminalKindV1,
    RootProjectReservationCancellationV1, abort_fixed_root_project_admission_v1,
    admit_fixed_root_project_source_from_owner_proofs_v1, cancel_fixed_root_project_reservation_v1,
    fixed_root_project_admission_recovery_required_v1,
    fixed_root_project_history_readback_available_v1,
    fixed_root_project_negative_recovery_available_v1,
    prepare_fixed_root_project_admission_intent_v1, prepare_fixed_root_project_negative_intent_v1,
    project_admission_client_nonce_v1, recover_fixed_root_current_project_admission_stage_v1,
    recover_fixed_root_project_admission_intent_v1,
    recover_fixed_root_project_admission_outcome_v1, recover_fixed_root_project_admission_stage_v1,
    recover_fixed_root_project_history_floor_v1,
    recover_fixed_root_project_reservation_cancellation_v1,
    recover_fixed_root_project_source_pin_v1, recover_fixed_root_unstaged_project_intent_v1,
    retire_fixed_root_project_history_v1, stage_fixed_root_project_admission_v1,
};
pub use project_source_v2::{
    AdmittedSignedProjectPolicySourceV2, SignedProjectPolicyHeadV2,
    VerifiedSignedProjectPolicySourceV2, admit_fixed_signed_project_policy_source_v2,
    verify_signed_project_policy_source_v2,
};
pub use project_source_v3::{
    HeldCurrentCreatePolicyInputsV3, PROJECT_POLICY_ASSOCIATION_PACKET_BYTES_V3,
    ProjectPolicyAssociationV3, verify_held_project_policy_association_v3,
    with_current_parentless_create_policy_inputs_v3,
};
pub use protected_journal::{
    AppliedPolicyPublicationV1, PolicyCheckpointCommitOutcomeV1, PolicyCheckpointOutcomeUnknownV1,
    PolicyCheckpointRecoveryV1, PolicyCompilerColdObservationV1, PolicyCompilerEffectHandoffV1,
    PolicyCompilerJournalEnvelopeV1, PolicyCompilerJournalErrorV1, PolicyCompilerJournalKeyV1,
    PolicyCompilerJournalProjectionV1, PolicyCompilerJournalRecordKindV1,
    PolicyCompilerJournalSchemaV1, PolicyCompilerJournalSnapshotV1,
    PolicyCompilerPostcommitCapabilityV1, PolicyCompilerProtectedJournalV1,
    PolicyCompilerReplayValidatorV1, PolicyEffectObservationCommitOutcomeV1,
    PolicyEffectObservationOutcomeUnknownV1, PolicyEffectObservationRecoveryV1,
    PolicyPublicationColdRecoveryV1, PolicyPublicationCommitOutcomeV1,
    PolicyPublicationOutcomeUnknownV1, PolicyPublicationPrerequisitesV1,
    PolicyPublicationRecoveryV1, PreparedPolicyCheckpointV1, PreparedPolicyEffectObservationV1,
    PreparedPolicyPublicationV1,
};
pub use protected_owner::{
    PolicyCompilerProtectedOpenReportV1, PolicyCompilerProtectedOwnerV1,
};
#[cfg(target_os = "linux")]
pub use public_create_source::with_current_create_cache_signer_barrier_v5;
#[cfg(target_os = "linux")]
pub use public_create_source::with_current_create_cache_signer_release_barrier_v7;
#[cfg(target_os = "linux")]
pub use public_create_source::with_current_create_cache_signer_released_barrier_v8;
#[cfg(target_os = "linux")]
pub use public_create_source::with_current_create_cache_signer_terminal_barrier_v6;
#[cfg(target_os = "linux")]
pub use public_create_source::with_current_create_v8_owner_settlement_barrier_v9;
#[cfg(target_os = "linux")]
pub use public_create_source::{
    CurrentCreateCompilerInputErrorV1, current_parentless_create_compiler_input_v1,
    validate_current_create_controller_journal_v1,
};
pub use public_create_source::{
    CurrentCreatePolicyBarrierHeadsV2, CurrentCreatePolicySourceErrorV1,
    CurrentCreateProjectPolicySourceV1,
    checked_parentless_create_policy_draft_v2, checked_parentless_create_verified_policy_draft_v2,
    current_parentless_create_project_source_for_operation_v1,
    current_parentless_create_project_source_v1, with_current_create_policy_source_barrier_v2,
    with_current_create_policy_source_barrier_v3, with_current_create_policy_source_barrier_v4,
    with_current_parentless_create_ancestry_v1,
};
pub use aos_sandbox_policy::{RetainedPublisherCompilerOriginV3, normalized_policy_input_digest_v1};
pub use publisher_origin::{
    CompiledPublisherPolicyRevisionV2, compile_publisher_policy_revision_v2,
};
pub use resolved_policy::{HeldResolvedRuntimePolicyV1, PolicyCompilerStateReadbackOwnerV1};
pub use root_project_admission_proof::{
    ROOT_PROJECT_ADMISSION_ABORT_QUERY_MAGIC, ROOT_PROJECT_ADMISSION_COMMIT_QUERY_MAGIC,
    ROOT_PROJECT_ADMISSION_CURRENT_QUERY_MAGIC, ROOT_PROJECT_ADMISSION_INTENT_QUERY_MAGIC,
    ROOT_PROJECT_ADMISSION_INTENT_REPLAY_MAGIC, ROOT_PROJECT_ADMISSION_OUTCOME_QUERY_MAGIC,
    ROOT_PROJECT_ADMISSION_STAGE_QUERY_MAGIC, ROOT_PROJECT_HISTORY_FLOOR_QUERY_MAGIC,
    ROOT_PROJECT_HISTORY_RETIRE_MAGIC, ROOT_PROJECT_NEGATIVE_INTENT_QUERY_MAGIC,
    ROOT_PROJECT_RESERVATION_CANCEL_MAGIC, ROOT_PROJECT_RESERVATION_CANCEL_QUERY_MAGIC,
    RootProjectAdmissionOutcomeProofV1, RootProjectHistoryFloorProofV1,
    RootProjectReservationCancellationProofV1, abort_fixed_root_project_admission_over_socket_v1,
    cancel_fixed_root_project_reservation_over_socket_v1,
    encode_root_current_project_admission_stage_reply_v1,
    encode_root_project_admission_outcome_reply_v1, encode_root_project_admission_stage_reply_v1,
    encode_root_project_admission_terminal_reply_v1, encode_root_project_history_floor_reply_v1,
    encode_root_project_intent_replay_reply_v1, encode_root_project_intent_reply_v1,
    encode_root_project_negative_intent_reply_v1, encode_root_project_reservation_cancel_reply_v1,
    prepare_fixed_root_project_intent_over_socket_v1,
    prepare_fixed_root_project_negative_intent_over_socket_v1,
    query_fixed_root_current_project_admission_stage_v1,
    query_fixed_root_project_admission_outcome_v1, query_fixed_root_project_history_floor_v1,
    query_fixed_root_project_intent_v1, query_fixed_root_project_negative_intent_v1,
    query_fixed_root_project_reservation_cancellation_v1,
    retire_fixed_root_project_history_over_socket_v1,
    stage_fixed_root_project_admission_over_socket_v1,
    submit_fixed_root_project_admission_over_socket_v1,
};
pub use root_v8_released_proof::{
    POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2, RootV8ReleasedProofV1, read_root_v8_released_proof_v1,
    validate_untrusted_root_v8_release_reply_frame_v1,
};
pub use root_v8_settled_grant::{
    ROOT_V8_SETTLED_QUERY_MAGIC, RootV8SettledGrantV1, encode_root_v8_settled_reply_v1,
    query_fixed_root_v8_settled_grant_v1,
};
#[cfg(target_os = "linux")]
pub use source_genesis_readback::{
    SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V1, SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V2,
    SourceTreeGenesisIntentContextV1,
};
pub use source_genesis_readback::{
    SOURCE_TREE_GENESIS_READBACK_BYTES_V1, SOURCE_TREE_GENESIS_READBACK_BYTES_V2,
    SourceTreeGenesisReadbackPacketV2, SourceTreeGenesisChallengeV1,
    VerifiedSourceTreeGenesisReadbackV1, verify_source_tree_genesis_readback_v1,
    verify_source_tree_genesis_readback_v2,
    SOURCE_PROJECT_GENESIS_READBACK_BYTES_V3, SourceProjectGenesisChallengeV3,
    SOURCE_PROJECT_RESOURCE_GENESIS_READBACK_BYTES_V4, SourceProjectGenesisReadbackPacketV4,
    VerifiedSourceProjectGenesisReadbackV3, verify_source_project_genesis_readback_v3,
};
pub use source_hold_pin::{SourceHoldPinErrorV1, admit_fixed_source_hold_pin_v1};
pub use source_hold_readback::{
    PinnedSourceHoldReadbackSignerV1, SOURCE_HOLD_READBACK_BYTES_V1, SourceHoldReadbackChallengeV1,
    SourceHoldReadbackErrorV1, encode_source_hold_readback_signer_credential_v1,
    record_current_source_signer_challenge_v1, require_current_source_signer_challenge_v1,
    sign_current_source_hold_readback_v1, verify_current_source_hold_readback_v1,
};
pub use source_hold_readback_v2::{
    SOURCE_HOLD_READBACK_BYTES_V2, verify_source_hold_readback_with_names_v2,
};
#[cfg(target_os = "linux")]
pub use source_project_admission_readback::sign_fixed_source_project_completed_terminal_readback_v1;
pub use source_project_admission_readback::{
    SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1,
    SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1,
    SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1, SourceProjectAdmissionChallengeErrorV1,
    VerifiedSourceProjectTerminalReadbackV1, acknowledge_source_project_terminal_retirement_v1,
    preflight_source_project_admission_v1, preflight_source_project_negative_recovery_v1,
    read_source_project_admission_status_v1, read_source_project_reservation_status_v1,
    record_current_source_project_admission_challenge_v1,
    record_source_project_abort_only_challenge_v1,
    require_current_source_project_admission_challenge_v1, reserve_source_project_admission_v1,
    settle_current_source_project_admission_challenge_v1, settle_source_project_reservation_v1,
    verify_source_project_admission_readback_v1,
    verify_source_project_completed_terminal_readback_v1,
    verify_source_project_reservation_readback_v1, verify_source_project_retirement_readback_v1,
};
#[cfg(target_os = "linux")]
pub use source_signer_readback::{
    SourceSignerReadbackErrorV1, sign_fixed_source_project_admission_readback_v1,
    sign_fixed_source_project_reservation_readback_v1,
    sign_fixed_source_project_retirement_readback_v1, sign_fixed_source_signer_readback_v1,
    sign_fixed_source_signer_readback_v2, sign_fixed_source_tree_genesis_readback_v2,
    sign_fixed_source_tree_genesis_readback_v3,
    sign_fixed_source_project_genesis_readback_v3,
    sign_fixed_source_project_genesis_readback_v4,
};
#[cfg(target_os = "linux")]
pub use v8_successor_clear::clear_current_create_v8_successor_fences_v1;
