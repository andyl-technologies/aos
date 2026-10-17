//! Maps authored storage-resource admission into the live driver error surface.

use super::*;

pub(super) fn reserve_storage_resource(
    field: &'static str,
    current: u64,
    requested: u64,
    limits: FaultResourceLimits,
) -> Result<(), DeviceRuntimeError> {
    limits
        .reserve(field, current, requested)
        .map_err(|error| storage_resource_error(error, limits))
}

pub(super) fn storage_resource_error(
    error: FaultResourceLimitError,
    limits: FaultResourceLimits,
) -> DeviceRuntimeError {
    let (field, current, requested, configured, hard) = match error {
        FaultResourceLimitError::Exceeded {
            field,
            current,
            requested,
            configured,
            hard,
        }
        | FaultResourceLimitError::UsageOverflow {
            field,
            current,
            requested,
            configured,
            hard,
        } => (field, current, requested, configured, hard),
        FaultResourceLimitError::Representation { field, value } => (
            field,
            0,
            value,
            limits.configured(field).unwrap_or(0),
            FaultResourceLimits::compiled_maximum()
                .configured(field)
                .unwrap_or(0),
        ),
        FaultResourceLimitError::Zero { field } => (
            field,
            0,
            1,
            0,
            FaultResourceLimits::compiled_maximum()
                .configured(field)
                .unwrap_or(0),
        ),
        FaultResourceLimitError::ConfiguredAboveHard {
            field,
            configured,
            hard,
        } => (field, 0, configured, configured, hard),
        FaultResourceLimitError::UnknownField { field } => (field, 0, 1, 0, 0),
    };
    DeviceRuntimeError::resource_limit(field, current, requested, configured, hard)
}
