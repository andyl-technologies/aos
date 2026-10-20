//! Selects the actual canonical restoration upload writer and retained segment.
//!
//! ```text
//! selection: "CanonicalSdkRestoreInputs12"
//! schema/feature: source-owned.packet-canonical-restore-inputs/12
//! ```
//!
//! The enum is declaration data. A private native prepare marker and the same
//! current SDK writer lease authenticate publication; decoding this selection
//! cannot enlarge an existing byte/record bank or authorize input allocation.

use super::*;

/// Selects one closed original SDK restoration-input writer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketNative5RestoreInputEmitterSelection {
    /// Requires the source-bound canonical SDK writer and append-only segment.
    CanonicalSdkRestoreInputs12,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_input_selection_is_closed_and_definition_is_full() {
        let schema = canonical_restore_inputs_schema().unwrap();
        schema
            .definition
            .verify(&canonical_restore_inputs_contract().unwrap())
            .unwrap();
        let selected = PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12;
        assert_eq!(
            serde_json::to_string(&selected).unwrap(),
            "\"CanonicalSdkRestoreInputs12\""
        );
        assert!(
            serde_json::from_str::<PacketNative5RestoreInputEmitterSelection>("\"OtherWriter\"")
                .is_err()
        );
    }
}

// One borrowed compiled roster drives BOTH the existing canonical definition
// and its prospective DOM/canonical counter. No schema bytes or field values
// are regenerated independently in the admission calculation.
struct CanonicalRestoreInputsContractValue;

impl serde::Serialize for CanonicalRestoreInputsContractValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::reference_packet::service::native_startup::contract_value::ContractValue as V;
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

pub(crate) fn canonical_restore_inputs_contract_storage_data(
    maximum: usize,
) -> Result<
    crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
    ProviderError,
> {
    // This unit struct and its borrowed literals own no heap/Bytes formatter.
    crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
        &CanonicalRestoreInputsContractValue,
        crate::retained_metadata::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}
