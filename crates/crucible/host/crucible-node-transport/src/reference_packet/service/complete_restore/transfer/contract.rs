//! Registers both transfer phases and their complete portable definition.

pub use crucible_source_birth_data::profile::reference_packet::service::complete_restore::transfer::{
    PacketCompleteRestoreTransferSchema,
};

use crucible_source_birth_data::profile::reference_packet::service::complete_restore::transfer::CompleteRestoreTransferContractValue;

pub use crucible_source_birth_data::profile::reference_packet::service::complete_restore::transfer::{
    complete_restore_transfer_contract,
    complete_restore_transfer_schema,
};

use super::*;

// One borrowed compiled roster drives BOTH the existing canonical definition
// and its prospective DOM/canonical counter. No schema bytes or field values
// are regenerated independently in the admission calculation.

pub(crate) fn complete_restore_transfer_contract_storage_data(
    maximum: usize,
) -> Result<
    crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
    ProviderError,
> {
    // This unit struct and its borrowed literals own no heap/Bytes formatter.
    crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
        &CompleteRestoreTransferContractValue,
        crate::retained_metadata::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}
