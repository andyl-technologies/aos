//! Selects canonical SDK Blob acknowledgements without installing a peer limit.
//!
//! The closed source grammar requires the actual original SDK controller writer
//! and a separately authenticated native peer association. Portable selection or
//! a numeric bound cannot replace either owning source. An absent selection keeps
//! the ordinary raw frame ceiling and existing codec bytes.

use crate::ProviderError;
use crucible_node_contract::{Id, SchemaRef, canonical};
use serde::{Deserialize, Serialize};

/// Selects the independently installed acknowledgement emitter grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketNative5AckEmitterSelection {
    /// Selects the original SDK canonical success-or-no-send Blob reply path.
    CanonicalSdkBlob5,
}

/// Names the immutable canonical acknowledgement specification.
pub const PACKET_NATIVE_CANONICAL_ACK_FEATURE: &str = "source-owned.packet-canonical-blob-ack/5";

/// Encodes the closed canonical emitter and native receive obligations.
///
/// This definition is data. The installed source factory independently proves
/// the actual controller, native peer, registrar and codec association.
///
/// # Errors
/// Refuses canonical encoding failure or invalid static contract values.
pub fn native_canonical_blob_ack_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(
        &serde_json::to_value(NativeCanonicalBlobAckContractValue)
            .map_err(crucible_node_contract::ContractError::from)?,
    )?)
}

/// Binds the complete immutable canonical emitter specification.
///
/// # Errors
/// Refuses invalid static identifiers or canonical contract encoding.
pub fn native_canonical_blob_ack_schema() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(PACKET_NATIVE_CANONICAL_ACK_FEATURE)?,
        version: 5,
        definition: canonical::content_ref(
            &native_canonical_blob_ack_contract()?,
            "application/json",
        )?,
        extensions: Default::default(),
    })
}

mod admission;
pub use admission::{
    MAXIMUM_CANONICAL_ACK_ADMISSION_CONTEXT_BYTES, MAXIMUM_CANONICAL_ACK_ADMISSION_PROOF_BYTES,
    PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM, PACKET_CANONICAL_ACK_ADMISSION_FEATURE,
    PacketCanonicalAckAdmissionContext, PacketCanonicalAckAdmissionProof,
    canonical_ack_admission_proof_data, verify_canonical_ack_admission_proof_data,
};

/// Returns the complete fixed admission contract as registered canonical data.
///
/// # Errors
/// Refuses a changed or noncanonical embedded contract.
pub fn native_canonical_ack_admission_contract() -> Result<Vec<u8>, ProviderError> {
    let bytes = include_bytes!("ack_emitter/admission-contract.json");
    let value = canonical::parse_json(bytes, bytes.len())?;
    if canonical::canonical_json(&value)?.as_slice() != bytes {
        return Err(ProviderError::Correlation(
            "canonical ACK admission contract",
        ));
    }
    Ok(bytes.to_vec())
}

/// Binds the complete immutable assigned-Admit proof contract.
///
/// # Errors
/// Refuses an invalid static identifier or embedded contract.
pub fn native_canonical_ack_admission_schema() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(PACKET_CANONICAL_ACK_ADMISSION_FEATURE)?,
        version: 5,
        definition: canonical::content_ref(
            &native_canonical_ack_admission_contract()?,
            "application/json",
        )?,
        extensions: Default::default(),
    })
}

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
struct NativeCanonicalBlobAckContractValue;

impl serde::Serialize for NativeCanonicalBlobAckContractValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::reference_packet::service::native_startup::contract_value::ContractValue as V;
        static VALUE: V<'static> = V::Object(&[
            (
                "schema",
                V::Text("source-owned.packet-canonical-blob-ack-contract/5"),
            ),
            ("feature", V::Text(PACKET_NATIVE_CANONICAL_ACK_FEATURE)),
            ("selection", V::Text("canonical_sdk_blob5")),
            (
                "writer",
                V::Text(
                    "same original SDK ClientSession receive_transfer; BlobBegin, BlobChunk or BlobFinish completed success with empty body and envelope extensions, or no send on failure",
                ),
            ),
            (
                "scope",
                V::Text(
                    "same original source-owned controller, native peer executable and kernel identity, Hello registrar, immutable codec, Capture and confirmation; opaque host lease never crosses process as authority",
                ),
            ),
            (
                "extent",
                V::Text(
                    "complete canonical envelope plus four-byte header, bounded original ASCII IDs, all U64 digits and full ContentRef hash, length and escaped media type",
                ),
            ),
            (
                "native_receive",
                V::Text(
                    "selected original acknowledgement scope reserves bounded literal slot before its first header byte and refuses oversized header before body allocation or read; exact partial original remains owned and uncertain",
                ),
            ),
            (
                "settlement",
                V::Text(
                    "source retains complete original request, response and literal suffix; no lifetime credit refund, replay, metadata ticket or Ready permission",
                ),
            ),
            (
                "legacy",
                V::Text("absent selection keeps negotiated raw frame ceiling and old codec bytes"),
            ),
        ]);
        serde::Serialize::serialize(&VALUE, serializer)
    }
}

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
