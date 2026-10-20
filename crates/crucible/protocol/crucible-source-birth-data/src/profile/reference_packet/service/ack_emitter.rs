//! Defines the unchanged closed ack emitter selector data.

use serde::{Deserialize, Serialize};

/// Selects the independently installed acknowledgement emitter grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketNative5AckEmitterSelection {
    /// Selects the original SDK canonical success-or-no-send Blob reply path.
    CanonicalSdkBlob5,
}

use crate::profile::ProviderError;
use crucible_node_format::{Id, SchemaRef, canonical};

/// Names the immutable canonical acknowledgement specification.
pub const PACKET_NATIVE_CANONICAL_ACK_FEATURE: &str = "source-owned.packet-canonical-blob-ack/5";

/// Names the registered envelope extension and immutable proof specification.
pub const PACKET_CANONICAL_ACK_ADMISSION_FEATURE: &str =
    "source-owned.packet-canonical-ack-admission/5";

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
            .map_err(crucible_node_format::ContractError::from)?,
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

/// Returns the complete fixed admission contract as registered canonical data.
///
/// # Errors
/// Refuses a changed or noncanonical embedded contract.
pub fn native_canonical_ack_admission_contract() -> Result<Vec<u8>, ProviderError> {
    let bytes = NATIVE_CANONICAL_ACK_ADMISSION_CONTRACT_DATA;
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

/// Serializes the original borrowed canonical Blob ACK contract roster.
pub struct NativeCanonicalBlobAckContractValue;

impl serde::Serialize for NativeCanonicalBlobAckContractValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::profile::reference_packet::service::native_startup::contract_value::ContractValue as V;
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

/// Borrows the original canonical ACK admission contract literal without allocation.
pub const NATIVE_CANONICAL_ACK_ADMISSION_CONTRACT_DATA: &[u8] =
    include_bytes!("ack_emitter/admission-contract.json");
