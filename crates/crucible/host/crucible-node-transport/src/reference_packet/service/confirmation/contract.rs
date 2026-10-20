//! Defines the closed confirmation specification independently of installation.

use crucible_source_birth_data::profile::reference_packet::service::confirmation::NativeAfterConfirmationContractValue;

pub use crucible_source_birth_data::profile::reference_packet::service::confirmation::{
    native_after_confirmation_contract, native_after_confirmation_schema,
};

use crate::ProviderError;

// One borrowed compiled roster drives BOTH the existing canonical definition
// and its prospective DOM/canonical counter. No schema bytes or field values
// are regenerated independently in the admission calculation.

pub(crate) fn native_after_confirmation_contract_storage_data(
    maximum: usize,
) -> Result<
    crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
    ProviderError,
> {
    // This unit struct and its borrowed literals own no heap/Bytes formatter.
    crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
        &NativeAfterConfirmationContractValue,
        crate::retained_metadata::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}
