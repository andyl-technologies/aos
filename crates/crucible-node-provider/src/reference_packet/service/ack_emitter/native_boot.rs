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
