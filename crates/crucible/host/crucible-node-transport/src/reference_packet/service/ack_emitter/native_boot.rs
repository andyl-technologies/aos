//! Retains the inherited source key and verifies one actual original Admit.
//!
//! A private boot authenticates preparation only. The MAC verifier binds the
//! same current native registrar, original Hello literals and assigned Admit
//! before the SDK can install its distinct protocol acknowledgement marker.

mod boot;
pub use boot::{
    PacketNativeRestoreCommitConstructionData, PacketNativeRestoreCommitConstructionInputs,
    original_native_restore_commit_construction_counter_scratch_data,
    original_native_restore_commit_construction_storage_data,
};
use boot::{
    measure_original_restore_controller_executable, measure_original_restore_current_executable,
};
pub(in crate::reference_packet::service) use boot::{
    original_native_startup_attempt_counter_scratch_data,
    original_native_startup_attempt_transient_data,
};
mod bootstrap;
mod owned_read;

#[path = "native_boot/bootstrap_import18.rs"]
mod bootstrap_import18;
pub(crate) use boot::ORIGINAL_ACK_CONTEXT_BANK_BYTES;
pub(crate) use boot::{
    NativeRestorationObservationAttempt, NativeRestorationUploadAttempt,
    OriginalRestorationActivationPermit, OriginalRestorationActivationRequirement,
    OriginalRestorationObservationPermit, OriginalRestorationObservationRead,
    OriginalRestorationReleaseState, OriginalRestorationReleased, OriginalRestorationUploadPermit,
    OriginalRestoredSuffixPostObservation,
    original_native_restoration_activation_attempt_backing_data,
    original_native_restoration_activation_counter_scratch_data,
    original_native_restoration_activation_ingress_row_data,
    original_native_restoration_activation_ingress_storage_data,
    original_native_restoration_observation_attempt_backing_data,
    original_native_restoration_observation_counter_scratch_data,
    original_native_restoration_observation_ingress_row_data,
    original_native_restoration_upload_attempt_backing_data,
    original_native_restoration_upload_counter_scratch_data,
    original_restored_suffix_post_observation_counter_scratch_data,
};
pub(in crate::reference_packet::service) use bootstrap_import18::controller_measurement_construction_data as original_import18_controller_measurement_construction_data;
pub(in crate::reference_packet::service) use bootstrap_import18::raw_storage_floor as original_import18_raw_bootstrap_storage_data;
pub(in crate::reference_packet::service) use bootstrap_import18::{
    bootstrap_codec_construction_data as original_import18_bootstrap_codec_construction_data,
    bootstrap_codec_counter_scratch_data as original_import18_bootstrap_codec_counter_scratch_data,
    bootstrap_correlation_construction_data as original_import18_bootstrap_correlation_construction_data,
    bootstrap_correlation_counter_scratch_data as original_import18_bootstrap_correlation_counter_scratch_data,
    bootstrap_kernel_construction_data as original_import18_bootstrap_kernel_construction_data,
    bootstrap_kernel_counter_scratch_data as original_import18_bootstrap_kernel_counter_scratch_data,
    bootstrap_literal_construction_data as original_import18_bootstrap_literal_construction_data,
    bootstrap_normalizations_construction_data as original_import18_bootstrap_normalizations_construction_data,
    bootstrap_normalizations_counter_scratch_data as original_import18_bootstrap_normalizations_counter_scratch_data,
    bootstrap_proof_construction_data as original_import18_bootstrap_proof_construction_data,
    bootstrap_proof_counter_scratch_data as original_import18_bootstrap_proof_counter_scratch_data,
    bootstrap_reply_construction_data as original_import18_bootstrap_reply_construction_data,
    bootstrap_reply_counter_scratch_data as original_import18_bootstrap_reply_counter_scratch_data,
    bootstrap_retained_schedule_data as original_import18_bootstrap_retained_schedule_data,
    bootstrap_schedule_counter_scratch_data as original_import18_bootstrap_schedule_counter_scratch_data,
    bootstrap_value_construction_data as original_import18_bootstrap_value_construction_data,
    bootstrap_value_counter_scratch_data as original_import18_bootstrap_value_counter_scratch_data,
    hello_admission_construction_data as original_import18_hello_initial_admission_construction_data,
    hello_admission_counter_scratch_data as original_import18_hello_initial_admission_counter_scratch_data,
    hello_envelope_construction_bound_data as original_import18_hello_envelope_construction_bound_data,
    hello_envelope_counter_scratch_data as original_import18_hello_envelope_counter_scratch_data,
    hello_exchange_construction_data as original_import18_hello_exchange_construction_data,
    hello_exchange_counter_scratch_data as original_import18_hello_exchange_counter_scratch_data,
    hello_frames_construction_data as original_import18_hello_frames_construction_data,
    hello_frames_counter_scratch_data as original_import18_hello_frames_counter_scratch_data,
    hello_initial_admission_backing_counter_scratch_data as original_import18_hello_initial_admission_backing_counter_scratch_data,
    hello_initial_admission_retained_backing_data as original_import18_hello_initial_admission_retained_backing_data,
    hello_literal_construction_data as original_import18_hello_literal_construction_data,
    hello_literal_counter_scratch_data as original_import18_hello_literal_counter_scratch_data,
    hello_publication_construction_data as original_import18_hello_publication_construction_data,
    hello_publication_counter_scratch_data as original_import18_hello_publication_counter_scratch_data,
    hello_registrar_construction_data as original_import18_hello_registrar_construction_data,
    hello_registrar_counter_scratch_data as original_import18_hello_registrar_counter_scratch_data,
    hello_request_construction_bound_data as original_import18_hello_request_construction_bound_data,
    hello_request_counter_scratch_data as original_import18_hello_request_counter_scratch_data,
    hello_response_construction_data as original_import18_hello_response_construction_data,
    hello_response_counter_scratch_data as original_import18_hello_response_counter_scratch_data,
    hello_result_construction_data as original_import18_hello_result_construction_data,
    hello_result_counter_scratch_data as original_import18_hello_result_counter_scratch_data,
    hello_sdk_request_construction_bound_data as original_import18_sdk_hello_request_construction_bound_data,
    hello_sdk_request_counter_scratch_data as original_import18_sdk_hello_request_counter_scratch_data,
    hello_selection_construction_data as original_import18_hello_selection_construction_data,
    hello_selection_counter_scratch_data as original_import18_hello_selection_counter_scratch_data,
    hello_value_construction_bound_data as original_import18_hello_value_construction_bound_data,
    hello_value_counter_scratch_data as original_import18_hello_value_counter_scratch_data,
    immutable_policy_construction_data as original_import18_immutable_policy_construction_data,
    immutable_policy_counter_scratch_data as original_import18_immutable_policy_counter_scratch_data,
    launch_validation_construction_data as original_import18_launch_validation_construction_data,
    launch_validation_counter_scratch_data as original_import18_launch_validation_counter_scratch_data,
    public_channel_construction_data as original_import18_public_channel_construction_data,
    public_channel_counter_scratch_data as original_import18_public_channel_counter_scratch_data,
    selection_construction_data as original_import18_selection_construction_data,
    selection_counter_scratch_data as original_import18_selection_counter_scratch_data,
};

pub(crate) use boot::{
    NativeAckBoot, NativeRestoredControlEvidence, OriginalCanonicalAckControlAdmit,
    OriginalCompleteRestoreCommit, OriginalNativeBirthReadScope,
    OriginalNativeReportStartupAllocation, VerifiedCanonicalAckAdmission,
    VerifiedCanonicalRestoreInputAdmission, VerifiedCompleteRestoration,
    VerifiedCompleteRestorationHeld, VerifiedCompleteRestorePrepare,
    original_native_ack_boot_layout, original_native_report_startup_scope_layout_data,
};
pub(crate) use bootstrap::{
    OriginalNativeBootstrapOwned11, original_native_private_bootstrap_layout,
};
pub(in crate::reference_packet::service) use bootstrap::{
    accept, accept_admitted, accept_invocation,
};

pub(crate) use boot::{
    OriginalNativePrepareStartupAllocation, measure_conformance_executable_data,
    measure_original_prepare_executable_data,
    original_conformance_executable_measurement_counter_scratch_data,
    original_prepare_executable_measurement_construction_data,
    original_prepare_executable_measurement_counter_scratch_data,
    original_prepare_executable_reference_retained_backing_data,
};
pub use boot::{
    PacketNativePrepareStartupStorageData, original_native_prepare_startup_counter_scratch_data,
    original_native_prepare_startup_storage_data,
};

#[path = "native_boot/bootstrap_suffix.rs"]
mod bootstrap_suffix;
pub(in crate::reference_packet::service) use bootstrap_suffix::accept as accept_restored_suffix;
pub(crate) use bootstrap_suffix::{
    original_restored_suffix_bootstrap_counter_scratch_data,
    original_restored_suffix_bootstrap_header_data,
};

pub(crate) use boot::{
    OriginalRestoredProducerRead, OriginalRestoredSuffixObserveRead,
    original_restored_suffix_native_counter_scratch_data,
    original_restored_suffix_native_header_data,
};

#[path = "native_boot/bootstrap_settled.rs"]
pub(super) mod bootstrap_settled;

pub(crate) use bootstrap_settled::{
    original_restored_settled_bootstrap_counter_scratch_data,
    original_restored_settled_bootstrap_header_data,
};

#[path = "native_boot/restored_settled.rs"]
mod restored_settled;

pub(crate) use restored_settled::original_restored_settled_native_owner_header_data;

pub(in crate::reference_packet::service) use bootstrap_settled::accept as accept_restored_settled;
pub(crate) use bootstrap_settled::original_restored_settled_bootstrap_accept_header_data;

pub(in crate::reference_packet::service) use bootstrap_settled::borrow_current_settled_bootstrap_data;

pub(crate) use boot::{HistoricalCommitToken17, HistoricalHeldToken17};

pub(crate) use boot::{HistoricalPrepareStartupAllocation17, HistoricalReportStartupAllocation17};

pub(in crate::reference_packet::service) use bootstrap_settled::SettledBootstrapHistory17;
pub(crate) use bootstrap_settled::{
    CurrentBootstrap17GroupIds, HistoricalCurrentBootstrap17,
    read_current_native17_bootstrap_fields_data,
};

pub(crate) use bootstrap_settled::{
    BorrowedBootstrap17LineageData, borrow_current_bootstrap17_lineage_data,
};

pub(crate) use boot::{
    NativeObservation17SpentAction, OriginalNativeObservation17Read,
    native_observation17_scope_counter_scratch_data,
};

pub(crate) use boot::{
    NativeObservation17OwningCheckpointData,
    original_observation17_checkpoint_owner_counter_scratch_data,
};

pub(crate) use boot::{
    NativeCapture17UploadSpentAction, OriginalNativeCapture17Read,
    native_capture17_receive_scope_counter_scratch_data,
    native_capture17_upload_scope_counter_scratch_data,
};
