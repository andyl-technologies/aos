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

use crucible_source_birth_data::profile::reference_packet::service::complete_restore::CanonicalRestoreInputsContractValue;

pub use crucible_source_birth_data::profile::reference_packet::service::complete_restore::{
    PACKET_CANONICAL_RESTORE_INPUTS_FEATURE, canonical_restore_inputs_contract,
    canonical_restore_inputs_schema,
};

use super::*;

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

pub use crucible_source_birth_data::profile::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection;
