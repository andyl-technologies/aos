//! Defines the original immutable schema DATA without live protocol owners.

use crate::profile::ProviderError;
use crucible_node_format::{Id, SchemaRef, canonical};

/// Names the separately negotiated canonical restoration-input writer feature.
pub const PACKET_CANONICAL_RESTORE_INPUTS_FEATURE: &str =
    "source-owned.packet-canonical-restore-inputs/12";

/// Returns the fixed full definition of the selected restoration-input writer.
///
/// # Errors
/// Reports fixed canonical definition encoding failure.
pub fn canonical_restore_inputs_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(
        &serde_json::to_value(CanonicalRestoreInputsContractValue)
            .map_err(crucible_node_format::ContractError::from)?,
    )?)
}

/// Returns the exact schema bound before provider/binding/template hashing.
///
/// # Errors
/// Reports invalid fixed identifier or definition encoding failure.
pub fn canonical_restore_inputs_schema() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(PACKET_CANONICAL_RESTORE_INPUTS_FEATURE)?,
        version: 12,
        definition: canonical::content_ref(
            &canonical_restore_inputs_contract()?,
            "application/json",
        )?,
        extensions: Default::default(),
    })
}

/// Serializes the original borrowed immutable contract roster without authority.
pub struct CanonicalRestoreInputsContractValue;

impl serde::Serialize for CanonicalRestoreInputsContractValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::profile::reference_packet::service::native_startup::contract_value::ContractValue as V;
        static VALUE: V<'static> = V::Object(&[
            (
                "schema",
                V::Text("source-owned.packet-canonical-restore-inputs-contract/12"),
            ),
            ("selection", V::Text("CanonicalSdkRestoreInputs12")),
            (
                "requires",
                V::Array(&[
                    V::Text("SourceSignedTransfer12"),
                    V::Text("OwnedProtocol11"),
                    V::Text("CanonicalSdkBlob5"),
                ]),
            ),
            (
                "writer",
                V::Text(
                    "same current original SDK controller/connection/registration/codec; source retains opaque nonclone writer lease and reauthenticates it before signing exact assigned Prepare",
                ),
            ),
            (
                "scope",
                V::Text(
                    "only exact full six-input roster in authenticated Prepare; canonical assigned BlobBegin/Chunk/Finish and exact completed success ACK or no-send; same prepared transaction, mapping and fresh native key",
                ),
            ),
            (
                "admission",
                V::Text(
                    "preflight entire exact upload/ACK/Commit request-and-response suffix and lifetime IDs before first frame; bound full Envelope headers and base64 escaped payload, not decoded observed ACK lengths",
                ),
            ),
            (
                "segment",
                V::Text(
                    "distinct append-only original literal/descriptor segment, privately selected and physically precharged before receipt; preserve prior bank Rc/bytes/counters/cuts verbatim; immutable selected ordering and both allocations retained at simultaneous peak",
                ),
            ),
            (
                "failure",
                V::Text(
                    "consume one-shot native prepare marker before accepting selected larger inputs; retain exact original slots, raw headers/partial bodies, IDs, progress and both segments on error/unwind; resume does not renew its original cut",
                ),
            ),
            (
                "capture",
                V::Text(
                    "complete owning view/metadata/aliases/reader and archive decoder must retain all segment bytes/capacities/counters/ordering and prepare-to-commit linkage; missing coverage refuses Capture",
                ),
            ),
            (
                "authority",
                V::Text(
                    "enum/schema/features/scalars are data only; whole512MiB, true kernel/Hello/source/archive/fresh Core context and post-Hello opaque writer association remain mandatory; no generic BlobReceiver or old bank limit increase",
                ),
            ),
        ]);
        serde::Serialize::serialize(&VALUE, serializer)
    }
}
