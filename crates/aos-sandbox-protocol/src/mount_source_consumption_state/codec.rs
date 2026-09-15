//! Canonical key and JSON codecs for Mount source-consumption companions.

use super::{
    MAXIMUM_MOUNT_RESOURCE_VALUE_BYTES_V2, MAXIMUM_SOURCE_PIN_VALUE_BYTES_V1,
    MOUNT_RESOURCE_FORMAT_VERSION_V2, MOUNT_RESOURCE_KEY_PREFIX_V2, MountResourceV1,
    SOURCE_PIN_FORMAT_VERSION_V1, SOURCE_PIN_KEY_PREFIX_V1, SOURCE_PIN_SCHEMA_V1, SourcePinRowV1,
    StoredMountResourceV1, StoredSourcePinV1,
};

/// Reports malformed or noncanonical Mount source-consumption state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MountSourceConsumptionStateError {
    /// A key does not use the exact closed format.
    #[error("invalid Mount source-consumption record key")]
    InvalidKey,
    /// A value is empty or exceeds its pre-decode ceiling.
    #[error("invalid Mount source-consumption record size")]
    InvalidSize,
    /// A value is malformed, noncanonical, or from another schema version.
    #[error("invalid Mount source-consumption record value")]
    InvalidValue,
}

/// Encodes the exact SourcePin key from its binding and realization digests.
#[must_use]
pub fn source_pin_key_v1(binding_digest: [u8; 32], handle: [u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(SOURCE_PIN_KEY_PREFIX_V1.len() + 64);
    key.extend_from_slice(SOURCE_PIN_KEY_PREFIX_V1);
    key.extend_from_slice(&binding_digest);
    key.extend_from_slice(&handle);
    key
}

/// Decodes one exact SourcePin key.
///
/// # Errors
///
/// Returns [`MountSourceConsumptionStateError::InvalidKey`] for any other
/// prefix or length.
pub fn decode_source_pin_key_v1(
    key: &[u8],
) -> Result<([u8; 32], [u8; 32]), MountSourceConsumptionStateError> {
    if key.len() != SOURCE_PIN_KEY_PREFIX_V1.len() + 64
        || !key.starts_with(SOURCE_PIN_KEY_PREFIX_V1)
    {
        return Err(MountSourceConsumptionStateError::InvalidKey);
    }
    let binding = key[SOURCE_PIN_KEY_PREFIX_V1.len()..SOURCE_PIN_KEY_PREFIX_V1.len() + 32]
        .try_into()
        .map_err(|_| MountSourceConsumptionStateError::InvalidKey)?;
    let handle = key[SOURCE_PIN_KEY_PREFIX_V1.len() + 32..]
        .try_into()
        .map_err(|_| MountSourceConsumptionStateError::InvalidKey)?;
    Ok((binding, handle))
}

/// Encodes one canonical `AOSMSP01` value.
///
/// # Errors
///
/// Returns an error when JSON encoding fails or exceeds the fixed bound.
pub fn encode_source_pin_value_v1(
    row: &SourcePinRowV1,
) -> Result<Vec<u8>, MountSourceConsumptionStateError> {
    let value = serde_json::to_vec(&StoredSourcePinV1 {
        schema: SOURCE_PIN_SCHEMA_V1.to_owned(),
        version: SOURCE_PIN_FORMAT_VERSION_V1,
        row: row.clone(),
    })
    .map_err(|_| MountSourceConsumptionStateError::InvalidValue)?;
    if value.is_empty() || value.len() > MAXIMUM_SOURCE_PIN_VALUE_BYTES_V1 {
        return Err(MountSourceConsumptionStateError::InvalidSize);
    }
    Ok(value)
}

/// Decodes and canonical-reencodes one bounded `AOSMSP01` value.
///
/// # Errors
///
/// Returns an error for an unsupported, malformed, over-limit, or
/// noncanonical value.
pub fn decode_source_pin_value_v1(
    value: &[u8],
) -> Result<SourcePinRowV1, MountSourceConsumptionStateError> {
    if value.is_empty() || value.len() > MAXIMUM_SOURCE_PIN_VALUE_BYTES_V1 {
        return Err(MountSourceConsumptionStateError::InvalidSize);
    }
    let stored: StoredSourcePinV1 = serde_json::from_slice(value)
        .map_err(|_| MountSourceConsumptionStateError::InvalidValue)?;
    if stored.schema != SOURCE_PIN_SCHEMA_V1 || stored.version != SOURCE_PIN_FORMAT_VERSION_V1 {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    }
    if serde_json::to_vec(&stored).map_err(|_| MountSourceConsumptionStateError::InvalidValue)?
        != value
    {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    }
    Ok(stored.row)
}

/// Encodes the exact Mount-resource key.
#[must_use]
pub fn mount_resource_key_v2(handle: [u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(MOUNT_RESOURCE_KEY_PREFIX_V2.len() + 32);
    key.extend_from_slice(MOUNT_RESOURCE_KEY_PREFIX_V2);
    key.extend_from_slice(&handle);
    key
}

/// Decodes one exact Mount-resource key.
///
/// # Errors
///
/// Returns [`MountSourceConsumptionStateError::InvalidKey`] for any other
/// prefix or length.
pub fn decode_mount_resource_key_v2(
    key: &[u8],
) -> Result<[u8; 32], MountSourceConsumptionStateError> {
    if key.len() != MOUNT_RESOURCE_KEY_PREFIX_V2.len() + 32
        || !key.starts_with(MOUNT_RESOURCE_KEY_PREFIX_V2)
    {
        return Err(MountSourceConsumptionStateError::InvalidKey);
    }
    key[MOUNT_RESOURCE_KEY_PREFIX_V2.len()..]
        .try_into()
        .map_err(|_| MountSourceConsumptionStateError::InvalidKey)
}

/// Encodes one canonical Mount-resource value.
///
/// # Errors
///
/// Returns an error when JSON encoding fails or exceeds the fixed bound.
pub fn encode_mount_resource_value_v2(
    resource: &MountResourceV1,
) -> Result<Vec<u8>, MountSourceConsumptionStateError> {
    let value = serde_json::to_vec(&StoredMountResourceV1 {
        version: MOUNT_RESOURCE_FORMAT_VERSION_V2,
        resource: resource.clone(),
    })
    .map_err(|_| MountSourceConsumptionStateError::InvalidValue)?;
    if value.is_empty() || value.len() > MAXIMUM_MOUNT_RESOURCE_VALUE_BYTES_V2 {
        return Err(MountSourceConsumptionStateError::InvalidSize);
    }
    Ok(value)
}

/// Decodes and canonical-reencodes one bounded Mount-resource value.
///
/// # Errors
///
/// Returns an error for an unsupported, malformed, over-limit, or
/// noncanonical value.
pub fn decode_mount_resource_value_v2(
    value: &[u8],
) -> Result<MountResourceV1, MountSourceConsumptionStateError> {
    if value.is_empty() || value.len() > MAXIMUM_MOUNT_RESOURCE_VALUE_BYTES_V2 {
        return Err(MountSourceConsumptionStateError::InvalidSize);
    }
    let stored: StoredMountResourceV1 = serde_json::from_slice(value)
        .map_err(|_| MountSourceConsumptionStateError::InvalidValue)?;
    if stored.version != MOUNT_RESOURCE_FORMAT_VERSION_V2
        || serde_json::to_vec(&stored)
            .map_err(|_| MountSourceConsumptionStateError::InvalidValue)?
            != value
    {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    }
    Ok(stored.resource)
}
