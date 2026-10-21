//! Owns protected Policy publication and its original-owner continuations.
//!
//! The pure compiler is owned by `aos-sandbox-policy`. This partition retains
//! the protected ancestry/currentness joins, canonical publication replay and
//! actual Root, Source, Cache and Controller custody. Extracting compiler DATA
//! does not make those effect-owning continuations independent.

#[cfg(target_os = "linux")]
pub(crate) mod host_resources;

mod binding_v2;
#[cfg(target_os = "linux")]
pub(crate) mod execution_no_apply_root;
mod cache_journal_readback;
mod cache_readback_pin;
mod cache_readback_session;
mod cache_root_settlement;
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
#[cfg(target_os = "linux")]
pub(crate) use aos_sandbox_broker::root_nonce::fresh_root_nonce;
mod controller_root_receipt_readback_v8;
mod controller_v8_readback_envelope;
mod controller_v8_settlement_readback;
mod deployment_head;

pub(crate) mod root_signed_sources;
#[cfg(target_os = "linux")]
mod git_coverage_enrollment;
#[cfg(target_os = "linux")]
pub use git_coverage_enrollment::{
    GIT_COVERAGE_ROOT_BOOTSTRAP_MAGIC_V1, GitCoverageRootClientV1,
    GitCoverageRootFlightErrorV1, GitCoverageAccountAttemptV1,
    RootGitCoverageEnrollmentOwnerV1,
};
#[cfg(target_os = "linux")]
mod nix_current_preflight;
#[cfg(target_os = "linux")]
pub use nix_current_preflight::{
    CurrentNixPreflightAttemptV1,
    CurrentNixPreflightOriginalsV1,
};
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
mod publication_error;
#[cfg(target_os = "linux")]
pub(crate) mod create_q04;
#[cfg(target_os = "linux")]
pub use create_q04::root::{
    OriginalRootCreateQ04AttemptV1, ROOT_CREATE_Q04_QUERY_MAGIC_V1,
    RootCreateQ04SourceObservationLoanV1,
};
#[cfg(target_os = "linux")]
pub(crate) mod create_storage_current;
#[cfg(target_os = "linux")]
pub use create_storage_current::{
    OriginalRootCreateStorageCurrentAttemptV1, RootCreateStorageCurrentErrorV1, RootCurrentFailureViewV1,
};
#[cfg(target_os = "linux")]
pub use create_storage_current::policy_inputs::RootCurrentPolicyInputDataV1;
mod protected_owner;
mod public_create_source;
pub(crate) use public_create_source::{
    HistoricalCreateProjectSourceHeadsV1, create_project_source_commitment_v1,
};
#[cfg(target_os = "linux")]
pub mod consumer_read_flight;
mod publisher_origin;
mod resource_read;
mod root_challenge_record;
mod root_project_admission_proof;
mod root_startup_journal;
#[cfg(target_os = "linux")]
mod startup_credential_error;
pub(crate) mod root_current_writers;
pub use root_startup_journal::{RootStartupCredentialWriterV1, RootPolicyStartupDeploymentV1, RootPolicyStartupJournalV1};
mod root_v8_released_proof;
use aos_sandbox_ledger_replay::source_signer_data::source_genesis_readback;
#[cfg(test)]
#[path = "source_genesis_readback.rs"]
mod source_genesis_readback_native_tests;
#[cfg(target_os = "linux")]
mod kernel_clock;
#[cfg(target_os = "linux")]
pub(crate) use kernel_clock::RetainedKernelPairedClockAttemptV1;
#[cfg(target_os = "linux")]
mod source_genesis_root;
#[cfg(target_os = "linux")]
pub(crate) use source_genesis_root::{
    root_flight_additional_control_bytes_v1,
    root_flight_detached_construction_bytes_v1,
};
mod source_phase_geometry;
pub(crate) use source_phase_geometry::first_source_successor_fixed_codec_peak_bytes_v1;
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
pub use source_genesis_root::{
    HeldControllerFirstSourceSuccessorV2,
    HeldRootFirstSourceSuccessorIntentV2,
    RootFirstSourceSuccessorFloorProofV2,
    FailedOriginalFirstSourceSuccessorV2,
    FirstSourceSuccessorConsumerPhaseV2,
    FirstSourceSuccessorSelectionV2,
    OriginalFirstSourceSuccessorInvocationV2,
    HeldControllerProjectSuccessorV3,
    HeldRootProjectSuccessorIntentV3,
    RootProjectSuccessorFloorProofV3,
    OriginalProjectSuccessorInvocationV3,
    FailedProjectSuccessorInvocationV3,
};
#[cfg(target_os = "linux")]
pub(crate) use source_genesis_root::{
    ControllerSuccessorOwnerViewV3,
    RootSuccessorIntentViewV3,
    RootSuccessorFloorViewV3,
};
#[cfg(target_os = "linux")]
pub(crate) use source_genesis_root::{
    unavailable_project_successor_v3,
    unavailable_predecessor_successor_v3,
};

#[cfg(target_os = "linux")]
pub(crate) use source_genesis_root::{
    unavailable_first_source_successor_v2,
};
mod source_hold_pin;
#[cfg(target_os = "linux")]
pub(crate) use public_create_source::{
    consume_completed_gen1_ancestry_v1,
    consume_completed_project_genesis_ancestry_v3,
};
#[cfg(target_os = "linux")]
pub(crate) use source_genesis_root::{
    CompletedRootSourceGenesisFloorV1,
};
mod source_hold_readback;
use aos_sandbox_ledger_replay::source_signer_data::source_hold_readback_v2;
#[cfg(target_os = "linux")]
pub use source_genesis_root::{
    OriginalConfiguredProjectGenesisInvocationV3,
    FailedConfiguredProjectGenesisInvocationV3,
    observe_root_first_source_successor_clock_v2,
    CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1,
    CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2,
    HeldRootSourceGenesisIntentV1,
    HeldRootSourceProjectGenesisIntentV3,
    RootSourceProjectGenesisFloorProofV3,
    FailedOriginalSourceSuccessorInvocationV2,
    OriginalSourceSuccessorInvocationV2,
    OriginalSourceProjectSuccessorInvocationV3,
    FailedSourceProjectSuccessorInvocationV3,
    SourceSuccessorIssuancePhaseV2,
    RootSourceGenesisFloorProofV1,
    coordinate_provisioned_source_genesis_v1,
    OriginalConfiguredGlobalGenesisInvocationV2,
    FailedConfiguredGlobalGenesisInvocationV2,
    sign_controller_source_genesis_completion_readback_v1,
    sign_controller_source_genesis_readback_v1,
};
#[cfg(target_os = "linux")]
pub(crate) use source_genesis_root::{
    unavailable_project_genesis_v3,
    unavailable_global_genesis_v2,
    SourceSuccessorSigningCutV2,
    SourceSuccessorSigningCutV3,
    CompletedRootSourceProjectGenesisFloorV3,
    unavailable_source_successor_issuer_v2,
    unavailable_project_issuer_v3,
};
mod source_project_admission_readback;

#[cfg(all(test, target_os = "linux"))]
mod source_signer_comparison_fixture;
#[cfg(target_os = "linux")]
pub use aos_sandbox_ledger_replay::source_signer_data::source_signer_wire;

#[cfg(target_os = "linux")]
mod v8_successor_clear;

pub use binding_v2::{
    CLOSED_POLICY_BINDING_BYTES_V2, CLOSED_SOURCE_TERMINAL_RECORD_BYTES_V1,
    CONTROLLER_V8_FINAL_RELEASE_BYTES_V1, ClosedPolicyBindingDecisionV2,
    ClosedPolicyEffectHandoffV2, ClosedPolicyRootCacheCutV2, ClosedPolicyRootCasBaseV2,
    ClosedPolicyRootCasObservationV2, ClosedPolicyRootSessionV2, ClosedPolicyRootSignerJoinV2,
    ClosedSourceTerminalClaimV1, ClosedSourceTerminalRecordV1, ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1,
    RootV8EffectAckErrorV1, RootV8EffectAckV1, RootV8HeldTerminalStepV1,
    RootV8SuccessorSettlementV1, RootV8TerminalCustodyV1, RootV8VerifiedTerminalV1,
    StagedClosedPolicyRootBaseV2, StagedClosedPolicySignerChallengeV2,
    acknowledge_and_verify_fixed_closed_root_v8_terminal_v1,
    acknowledge_fixed_closed_root_v8_effect_v1,
    acknowledge_verify_and_release_fixed_closed_root_v8_terminal_v1,
    closed_policy_binding_digest_v2, closed_policy_effect_handoff_v2,
    compare_closed_policy_binding_hold_claims_v2,
    compare_closed_policy_binding_released_cache_claims_v2,
    propose_closed_current_create_explicit_policy_binding_v2,
    read_fixed_inert_closed_policy_binding_hold_v1,
    recover_fixed_closed_policy_binding_decision_v2, recover_fixed_closed_root_v8_effect_ack_v1,
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
pub use controller_effect_ack_readback::{
    ControllerEffectAckChallengeV1, ControllerEffectAckReadbackErrorV1,
};
pub use controller_effect_ack_readback_v8::{
    CONTROLLER_V8_EFFECT_ACK_READBACK_BYTES_V1, sign_fixed_controller_v8_effect_ack_readback_v1,
    verify_controller_v8_effect_ack_readback_v1,
};
pub use controller_hold_pin::{ControllerHoldPinErrorV1, admit_fixed_controller_hold_pin_v1};
pub use controller_hold_readback::{
    ControllerHoldReadbackErrorV1, sign_fixed_controller_hold_readback_v1,
};
pub use controller_project_admission_readback::{
    ControllerProjectAdmissionReadbackErrorV1, sign_fixed_controller_project_admission_readback_v1,
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
    PolicyDeploymentHeadErrorV1, admit_fixed_policy_deployment_head_v1,
    admit_fixed_policy_deployment_profile_v2, admit_fixed_policy_signer_pins_v1,
    verify_current_policy_deployment_profile_v2,
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
    AdmittedSignedProjectPolicySourceV2, admit_fixed_signed_project_policy_source_v2,
};
pub use project_source_v3::{
    HeldCurrentCreatePolicyInputsV3, PROJECT_POLICY_ASSOCIATION_PACKET_BYTES_V3,
    ProjectPolicyAssociationV3, verify_held_project_policy_association_v3,
    with_current_parentless_create_policy_inputs_v3,
};
pub use publication_error::PolicyCompilerJournalErrorV1;
pub use aos_sandbox_policy::publication::PolicyPublicationPrerequisitesV1;
pub use aos_sandbox_policy::publication::{
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
pub use aos_sandbox_policy::normalized_policy_input_digest_v1;
pub use publisher_origin::{
    CompiledPublisherPolicyRevisionV2, compile_publisher_policy_revision_v2,
};
pub use aos_sandbox_policy::publication::{
    HeldResolvedRuntimePolicyV1, PolicyCompilerStateReadbackOwnerV1,
};
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
    verify_current_source_hold_readback_v1,
};
pub use source_hold_readback_v2::{
    SOURCE_HOLD_READBACK_BYTES_V2, verify_source_hold_readback_with_names_v2,
};
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
pub use v8_successor_clear::clear_current_create_v8_successor_fences_v1;

#[cfg(target_os = "linux")]
pub(crate) mod provisioning_current;

// Fresh Delete retains its distinct actual accepted flight and native debts.
pub(crate) mod delete_root;

mod root_subject_readiness;
pub(crate) use root_subject_readiness::RootSubjectReadinessV1;

// Same checked native BOOTTIME bookend for a paid Root peer leaf.

mod root_subject_chunk;

#[cfg(target_os = "linux")]
pub(crate) mod root_policy_prelude;
#[cfg(target_os = "linux")]
pub use root_policy_prelude::{RootPolicyPreludeOriginalV1, RootPolicyPreludeErrorV1, RootPolicyPurposeV1};

#[cfg(target_os = "linux")]
pub(crate) mod continuation_policy;


pub(crate) mod storage_apply_root;
pub(crate) mod host_launch_root;
pub(crate) mod start_assignment_inputs_root;
mod root_resource_opening;
pub use storage_apply_root::RootStorageApplyReceivingV1;
pub use host_launch_root::{RootStartResourceReceivingV2, RootMaintenanceStorageReceivingV3};
#[cfg(target_os = "linux")]
pub(crate) mod finality_recover_root;
#[cfg(target_os = "linux")]
pub use finality_recover_root::RootFinalityRecoverReceivingV1;
#[cfg(target_os = "linux")]
pub(crate) mod environment_root;

#[cfg(target_os = "linux")]
pub use environment_root::{RootEnvironmentPolicyAttemptV1, RootEnvironmentExchangeErrorV1};

mod assignment_manifest;
pub(crate) use assignment_manifest::{
    AssignmentManifestPlacementDataV2, assignment_manifest_policy_data_v2,
    assignment_manifest_construction_receiving_bytes_v2,
    materialize_assignment_manifest_v2,
};

#[cfg(target_os = "linux")]
mod public_start_source;
#[cfg(target_os = "linux")]
pub(crate) use public_start_source::{
    start_source_observation_control_bytes_v2,
    CurrentAcceptedStartProjectSourceV2, current_accepted_start_project_source_v2,
};

#[cfg(target_os = "linux")]
pub(crate) use provisioning_current::{
    StartAssignmentCompilationDataV2, StartAssignmentCompilationResultV2,
    compile_accepted_start_assignment_v2,
};

#[cfg(target_os = "linux")]
pub use start_assignment_inputs_root::RootStartAssignmentInputsReceivingV2;
#[cfg(target_os = "linux")]
pub(crate) mod stop_cleanup_root;
