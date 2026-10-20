//! Selects canonical SDK Blob acknowledgements without installing a peer limit.
//!
//! The closed source grammar requires the actual original SDK controller writer
//! and a separately authenticated native peer association. Portable selection or
//! a numeric bound cannot replace either owning source. An absent selection keeps
//! the ordinary raw frame ceiling and existing codec bytes.

use crucible_source_birth_data::profile::reference_packet::service::ack_emitter::NativeCanonicalBlobAckContractValue;

pub use crucible_source_birth_data::profile::reference_packet::service::ack_emitter::{
    PACKET_NATIVE_CANONICAL_ACK_FEATURE, native_canonical_ack_admission_contract,
    native_canonical_ack_admission_schema, native_canonical_blob_ack_contract,
    native_canonical_blob_ack_schema,
};

use crate::ProviderError;

mod admission;
pub use admission::{
    MAXIMUM_CANONICAL_ACK_ADMISSION_CONTEXT_BYTES, MAXIMUM_CANONICAL_ACK_ADMISSION_PROOF_BYTES,
    PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM, PACKET_CANONICAL_ACK_ADMISSION_FEATURE,
    PacketCanonicalAckAdmissionContext, PacketCanonicalAckAdmissionProof,
    canonical_ack_admission_proof_data, verify_canonical_ack_admission_proof_data,
};

mod admission_projection;
pub(crate) use admission_projection::validate_proof_value;

pub(in crate::reference_packet::service) mod native_boot;
pub(crate) use native_boot::ORIGINAL_ACK_CONTEXT_BANK_BYTES;
pub(crate) use native_boot::{
    NativeRestorationObservationAttempt, NativeRestorationUploadAttempt,
    OriginalRestorationActivationPermit, OriginalRestorationActivationRequirement,
    OriginalRestorationObservationPermit, OriginalRestorationObservationRead,
    OriginalRestorationReleaseState, OriginalRestorationReleased, OriginalRestorationUploadPermit,
    OriginalRestoredProducerRead, OriginalRestoredSuffixObserveRead,
    OriginalRestoredSuffixPostObservation,
    original_native_restoration_activation_attempt_backing_data,
    original_native_restoration_activation_counter_scratch_data,
    original_native_restoration_activation_ingress_row_data,
    original_native_restoration_observation_attempt_backing_data,
    original_native_restoration_observation_counter_scratch_data,
    original_native_restoration_observation_ingress_row_data,
    original_native_restoration_upload_attempt_backing_data,
    original_native_restoration_upload_counter_scratch_data,
    original_restored_suffix_post_observation_counter_scratch_data,
};
pub use native_boot::{
    PacketNativeRestoreCommitConstructionData, PacketNativeRestoreCommitConstructionInputs,
    original_native_restore_commit_construction_counter_scratch_data,
    original_native_restore_commit_construction_storage_data,
};

pub(crate) use native_boot::{
    NativeAckBoot, NativeRestoredControlEvidence, OriginalCanonicalAckControlAdmit,
    OriginalCompleteRestoreCommit, OriginalNativeBirthReadScope, OriginalNativeBootstrapOwned11,
    OriginalNativeReportStartupAllocation, VerifiedCanonicalAckAdmission,
    VerifiedCanonicalRestoreInputAdmission, VerifiedCompleteRestoration,
    VerifiedCompleteRestorationHeld, VerifiedCompleteRestorePrepare,
    original_native_ack_boot_layout, original_native_private_bootstrap_layout,
    original_native_report_startup_scope_layout_data,
};
pub(crate) use native_boot::{
    OriginalNativePrepareStartupAllocation, measure_conformance_executable_data,
    measure_original_prepare_executable_data,
    original_conformance_executable_measurement_counter_scratch_data,
    original_prepare_executable_measurement_counter_scratch_data,
};

// One borrowed compiled roster drives BOTH the existing canonical definition
// and its prospective DOM/canonical counter. No schema bytes or field values
// are regenerated independently in the admission calculation.

pub(crate) fn native_canonical_blob_ack_contract_storage_data(
    maximum: usize,
) -> Result<
    crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
    ProviderError,
> {
    // This unit struct and its borrowed literals own no heap/Bytes formatter.
    crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
        &NativeCanonicalBlobAckContractValue,
        crate::retained_metadata::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}

pub use native_boot::{
    PacketNativePrepareStartupStorageData, original_native_prepare_startup_counter_scratch_data,
    original_native_prepare_startup_storage_data,
};

pub(crate) use native_boot::{
    original_restored_suffix_bootstrap_counter_scratch_data,
    original_restored_suffix_bootstrap_header_data,
    original_restored_suffix_native_counter_scratch_data,
    original_restored_suffix_native_header_data,
};

pub(crate) use native_boot::{
    original_restored_settled_bootstrap_counter_scratch_data,
    original_restored_settled_bootstrap_header_data,
};

pub(crate) use native_boot::original_restored_settled_native_owner_header_data;

pub(crate) use native_boot::original_restored_settled_bootstrap_accept_header_data;

pub(in crate::reference_packet::service) use native_boot::borrow_current_settled_bootstrap_data;

pub(crate) use native_boot::{HistoricalCommitToken17, HistoricalHeldToken17};

pub(crate) use native_boot::{
    HistoricalPrepareStartupAllocation17, HistoricalReportStartupAllocation17,
};

pub(in crate::reference_packet::service) use native_boot::SettledBootstrapHistory17;
pub(crate) use native_boot::{
    CurrentBootstrap17GroupIds, HistoricalCurrentBootstrap17,
    read_current_native17_bootstrap_fields_data,
};

pub(crate) use native_boot::{
    BorrowedBootstrap17LineageData, borrow_current_bootstrap17_lineage_data,
};

pub(crate) use native_boot::{
    NativeObservation17SpentAction, OriginalNativeObservation17Read,
    native_observation17_scope_counter_scratch_data,
};

pub(crate) use native_boot::{
    NativeObservation17OwningCheckpointData,
    original_observation17_checkpoint_owner_counter_scratch_data,
};

pub(crate) use native_boot::{
    NativeCapture17UploadSpentAction, OriginalNativeCapture17Read,
    native_capture17_receive_scope_counter_scratch_data,
    native_capture17_upload_scope_counter_scratch_data,
};

pub use crucible_source_birth_data::profile::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection;
