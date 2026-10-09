//! Storage-specific authenticated success-body correlation.

use aos_proto::aos::sandbox::local::v1::{PrepareStorageCatalogResponse, StorageResult};
use buffa::Message as _;

use crate::ProtocolValidationError;
use crate::semantics::{
    CanonicalStoragePreparationSemanticsV1, CanonicalStorageRepairSemanticsV1,
    CanonicalStorageSemanticsV1, StorageOperation,
};

pub(super) fn validate_storage_preparation_response(
    body: &[u8],
    request: &CanonicalStoragePreparationSemanticsV1,
) -> Result<(), ProtocolValidationError> {
    let response = PrepareStorageCatalogResponse::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty()
        || response.encode_to_vec() != body
        || response.operation_id.as_slice() != request.operation_id().as_slice()
        || response.catalog_generation == 0
        || response.preparation_expires_boottime_nanoseconds
            != request.expires_boottime_nanoseconds()
        || response.non_authorizing_receipt.is_empty()
        || response.non_authorizing_receipt.len() > 1_048_576
    {
        return Err(ProtocolValidationError::InvalidField(
            "storage preparation response",
        ));
    }
    crate::exact_nonzero::<32>(&response.catalog_digest, "catalog_digest")?;
    Ok(())
}

pub(super) fn validate_storage_repair_response(
    body: &[u8],
    request: &CanonicalStorageRepairSemanticsV1,
) -> Result<(), ProtocolValidationError> {
    let response = StorageResult::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty()
        || response.encode_to_vec() != body
        || response.error.as_option().is_some()
        || response.storage_handle.as_slice() != request.storage_handle().as_bytes()
        || !response.immutable_version_handle.is_empty()
        || response.portable_state.as_option().is_some()
        || !response.non_secret_receipt.is_empty()
    {
        return Err(ProtocolValidationError::InvalidField(
            "storage repair response",
        ));
    }
    Ok(())
}

pub(super) fn validate_storage_apply_response(
    body: &[u8],
    request: &CanonicalStorageSemanticsV1,
) -> Result<(), ProtocolValidationError> {
    let response = StorageResult::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty()
        || response.encode_to_vec() != body
        || response.error.as_option().is_some()
        || response.portable_state.as_option().is_some()
        || response.non_secret_receipt.len() != 32
        || response.non_secret_receipt.iter().all(|byte| *byte == 0)
        || !matches!(response.storage_handle.len(), 0 | 32)
        || !matches!(response.immutable_version_handle.len(), 0 | 32)
        || (response.storage_handle.iter().all(|byte| *byte == 0)
            && !response.storage_handle.is_empty())
        || (response
            .immutable_version_handle
            .iter()
            .all(|byte| *byte == 0)
            && !response.immutable_version_handle.is_empty())
    {
        return Err(ProtocolValidationError::InvalidField(
            "storage apply response",
        ));
    }
    let handles_match = match request.operation() {
        StorageOperation::CreateWorkspace { .. } => {
            response.storage_handle.len() == 32 && response.immutable_version_handle.is_empty()
        }
        StorageOperation::Clone { storage_handle, .. } => {
            response.storage_handle.len() == 32
                && response.storage_handle.as_slice() != storage_handle.as_slice()
                && response.immutable_version_handle.is_empty()
        }
        StorageOperation::Snapshot { storage_handle } => {
            response.storage_handle.as_slice() == storage_handle.as_slice()
                && response.immutable_version_handle.len() == 32
        }
        StorageOperation::HoldSnapshot {
            storage_handle,
            version_handle,
        }
        | StorageOperation::ReleaseHold {
            storage_handle,
            version_handle,
        } => {
            response.storage_handle.as_slice() == storage_handle.as_slice()
                && response.immutable_version_handle.as_slice() == version_handle.as_slice()
        }
        StorageOperation::SetQuota { storage_handle, .. } => {
            response.storage_handle.as_slice() == storage_handle.as_slice()
                && response.immutable_version_handle.is_empty()
        }
        StorageOperation::Destroy {
            storage_handle,
            version_handle,
        } => {
            response.storage_handle.as_slice() == storage_handle.as_slice()
                && match version_handle {
                    Some(version) => {
                        response.immutable_version_handle.as_slice() == version.as_slice()
                    }
                    None => response.immutable_version_handle.is_empty(),
                }
        }
    };
    if !handles_match {
        return Err(ProtocolValidationError::InvalidField(
            "storage apply response binding",
        ));
    }
    Ok(())
}
