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
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-canonical-restore-inputs-contract/12",
        "selection":"CanonicalSdkRestoreInputs12",
        "requires":["SourceSignedTransfer12","OwnedProtocol11","CanonicalSdkBlob5"],
        "writer":"same current original SDK controller/connection/registration/codec; source retains opaque nonclone writer lease and reauthenticates it before signing exact assigned Prepare",
        "scope":"only exact full six-input roster in authenticated Prepare; canonical assigned BlobBegin/Chunk/Finish and exact completed success ACK or no-send; same prepared transaction, mapping and fresh native key",
        "admission":"preflight entire exact upload/ACK/Commit request-and-response suffix and lifetime IDs before first frame; bound full Envelope headers and base64 escaped payload, not decoded observed ACK lengths",
        "segment":"distinct append-only original literal/descriptor segment, privately selected and physically precharged before receipt; preserve prior bank Rc/bytes/counters/cuts verbatim; immutable selected ordering and both allocations retained at simultaneous peak",
        "failure":"consume one-shot native prepare marker before accepting selected larger inputs; retain exact original slots, raw headers/partial bodies, IDs, progress and both segments on error/unwind; resume does not renew its original cut",
        "capture":"complete owning view/metadata/aliases/reader and archive decoder must retain all segment bytes/capacities/counters/ordering and prepare-to-commit linkage; missing coverage refuses Capture",
        "authority":"enum/schema/features/scalars are data only; whole512MiB, true kernel/Hello/source/archive/fresh Core context and post-Hello opaque writer association remain mandatory; no generic BlobReceiver or old bank limit increase"
    }))?)
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
