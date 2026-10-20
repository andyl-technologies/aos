//! Counts the actual borrowed static contract rosters without constructing schemas.
//!
//! These are the original selected native schema producers. Upper declaration,
//! policy and native consumers retain their existing paths as direct aliases.

use crate::ProviderError;

/// Counts the unchanged borrowed compiled contract's serialization phase.
///
/// # Errors
/// Preserves the original serializer, layout arithmetic and maximum refusals.
pub fn complete_ingress_contract_storage_data(
    maximum: usize,
) -> Result<crate::profile::serialization_storage::OriginalSerializationStorageData, ProviderError>
{
    // This unit struct and its borrowed literals own no heap/Bytes formatter.
    crate::profile::serialization_storage::actual_serialization_storage_data(
        &crate::profile::reference_packet::continuation_contracts::CompleteIngressContractValue,
        crate::profile::serialization_storage::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}

/// Counts the unchanged borrowed compiled contract's serialization phase.
///
/// # Errors
/// Preserves the original serializer, layout arithmetic and maximum refusals.
pub fn native_after_confirmation_contract_storage_data(
    maximum: usize,
) -> Result<crate::profile::serialization_storage::OriginalSerializationStorageData, ProviderError>
{
    // This unit struct and its borrowed literals own no heap/Bytes formatter.
    crate::profile::serialization_storage::actual_serialization_storage_data(
        &crate::profile::reference_packet::service::confirmation::NativeAfterConfirmationContractValue,
        crate::profile::serialization_storage::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}

/// Counts the unchanged borrowed compiled contract's serialization phase.
///
/// # Errors
/// Preserves the original serializer, layout arithmetic and maximum refusals.
pub fn native_canonical_blob_ack_contract_storage_data(
    maximum: usize,
) -> Result<crate::profile::serialization_storage::OriginalSerializationStorageData, ProviderError>
{
    // This unit struct and its borrowed literals own no heap/Bytes formatter.
    crate::profile::serialization_storage::actual_serialization_storage_data(
        &crate::profile::reference_packet::service::ack_emitter::NativeCanonicalBlobAckContractValue,
        crate::profile::serialization_storage::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}

/// Counts the unchanged borrowed compiled contract's serialization phase.
///
/// # Errors
/// Preserves the original serializer, layout arithmetic and maximum refusals.
pub fn complete_restore_contract_storage_data(
    maximum: usize,
) -> Result<crate::profile::serialization_storage::OriginalSerializationStorageData, ProviderError>
{
    // This unit struct and its borrowed literals own no heap/Bytes formatter.
    crate::profile::serialization_storage::actual_serialization_storage_data(
        &crate::profile::reference_packet::service::complete_restore::CompleteRestoreContractValue,
        crate::profile::serialization_storage::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}

/// Counts the unchanged borrowed compiled contract's serialization phase.
///
/// # Errors
/// Preserves the original serializer, layout arithmetic and maximum refusals.
pub fn complete_restore_transfer_contract_storage_data(
    maximum: usize,
) -> Result<crate::profile::serialization_storage::OriginalSerializationStorageData, ProviderError>
{
    // This unit struct and its borrowed literals own no heap/Bytes formatter.
    crate::profile::serialization_storage::actual_serialization_storage_data(
        &crate::profile::reference_packet::service::complete_restore::transfer::CompleteRestoreTransferContractValue,
        crate::profile::serialization_storage::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}

/// Counts the unchanged borrowed compiled contract's serialization phase.
///
/// # Errors
/// Preserves the original serializer, layout arithmetic and maximum refusals.
pub fn native_restored_record_contract_storage_data(
    maximum: usize,
) -> Result<crate::profile::serialization_storage::OriginalSerializationStorageData, ProviderError>
{
    // This unit struct and its borrowed literals own no heap/Bytes formatter.
    crate::profile::serialization_storage::actual_serialization_storage_data(
        &crate::profile::reference_packet::service::complete_restore::NativeRestoredRecordContractValue,
        crate::profile::serialization_storage::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}

/// Counts the unchanged borrowed compiled contract's serialization phase.
///
/// # Errors
/// Preserves the original serializer, layout arithmetic and maximum refusals.
pub fn canonical_restore_inputs_contract_storage_data(
    maximum: usize,
) -> Result<crate::profile::serialization_storage::OriginalSerializationStorageData, ProviderError>
{
    // This unit struct and its borrowed literals own no heap/Bytes formatter.
    crate::profile::serialization_storage::actual_serialization_storage_data(
        &crate::profile::reference_packet::service::complete_restore::CanonicalRestoreInputsContractValue,
        crate::profile::serialization_storage::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}

/// Counts the unchanged borrowed compiled contract's serialization phase.
///
/// # Errors
/// Preserves the original serializer, layout arithmetic and maximum refusals.
pub fn capture_allocation_contract_storage_data(
    maximum: usize,
) -> Result<crate::profile::serialization_storage::OriginalSerializationStorageData, ProviderError>
{
    // This unit struct and its borrowed literals own no heap/Bytes formatter.
    crate::profile::serialization_storage::actual_serialization_storage_data(
        &crate::profile::reference_packet::service::capture_allocation::CaptureAllocationContractValue,
        crate::profile::serialization_storage::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}
