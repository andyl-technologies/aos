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
mod bootstrap;
mod owned_read;
pub(crate) use boot::ORIGINAL_ACK_CONTEXT_BANK_BYTES;
pub(crate) use boot::{
    OriginalRestorationActivationPermit,
    NativeRestorationUploadAttempt, OriginalRestorationUploadPermit,
    OriginalRestorationActivationRequirement,
    original_native_restoration_upload_attempt_backing_data,
    original_native_restoration_upload_counter_scratch_data,
    original_native_restoration_activation_attempt_backing_data,
    original_native_restoration_activation_counter_scratch_data,
    original_native_restoration_activation_ingress_storage_data,
    original_native_restoration_activation_ingress_row_data,
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
    original_prepare_executable_measurement_counter_scratch_data,
};
pub use boot::{
    PacketNativePrepareStartupStorageData, original_native_prepare_startup_counter_scratch_data,
    original_native_prepare_startup_storage_data,
};
