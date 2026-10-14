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
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema": "source-owned.packet-canonical-blob-ack-contract/5",
        "feature": PACKET_NATIVE_CANONICAL_ACK_FEATURE,
        "selection": "canonical_sdk_blob5",
        "writer": "same original SDK ClientSession receive_transfer; BlobBegin, BlobChunk or BlobFinish completed success with empty body and envelope extensions, or no send on failure",
        "scope": "same original source-owned controller, native peer executable and kernel identity, Hello registrar, immutable codec, Capture and confirmation; opaque host lease never crosses process as authority",
        "extent": "complete canonical envelope plus four-byte header, bounded original ASCII IDs, all U64 digits and full ContentRef hash, length and escaped media type",
        "native_receive": "selected original acknowledgement scope reserves bounded literal slot before its first header byte and refuses oversized header before body allocation or read; exact partial original remains owned and uncertain",
        "settlement": "source retains complete original request, response and literal suffix; no lifetime credit refund, replay, metadata ticket or Ready permission",
        "legacy": "absent selection keeps negotiated raw frame ceiling and old codec bytes"
    }))?)
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
pub(crate) use native_boot::{
    NativeAckBoot, OriginalCanonicalAckControlAdmit, OriginalNativeBootstrapOwned11, VerifiedCanonicalAckAdmission, VerifiedCompleteRestoration, VerifiedCompleteRestorePrepare, original_native_ack_boot_layout, original_native_private_bootstrap_layout, VerifiedCanonicalRestoreInputAdmission, NativeRestoredControlEvidence, OriginalCompleteRestoreCommit, VerifiedCompleteRestorationHeld,
};
