//! Resource admission and error translation for production fault checkpoints.

use crucible::model::{FaultResourceLimitError, FaultResourceLimits, FaultRuntimeError};
use crucible::{BackendNetworkOutputCodecError, SchedulerNetworkCheckpointCodecError};

use super::{
    MAX_BYTES, MAX_EVENT_RECORDS, ProductionFaultRuntimeCheckpoint,
    ProductionFaultRuntimeCheckpointCodecError,
};
use crate::checkpoint::bounded_cbor::BoundedCborError;
use crate::production_fault_runtime::ProductionFaultRuntimeError;

pub(super) struct CheckpointConstructionBudget {
    configured: u64,
    current: u64,
}

impl CheckpointConstructionBudget {
    pub(super) fn new(maximum: u64) -> Self {
        Self {
            configured: maximum.min(MAX_BYTES),
            current: 0,
        }
    }

    pub(super) fn remaining(&self) -> u64 {
        self.configured.saturating_sub(self.current)
    }

    pub(super) fn admit(
        &mut self,
        requested: usize,
    ) -> Result<(), ProductionFaultRuntimeCheckpointCodecError> {
        let requested = u64::try_from(requested).map_err(|_| {
            resource_limit(
                "production fault checkpoint",
                self.current,
                u64::MAX,
                self.configured,
                MAX_BYTES,
            )
        })?;
        let total = self.current.checked_add(requested).ok_or_else(|| {
            resource_limit(
                "production fault checkpoint",
                self.current,
                requested,
                self.configured,
                MAX_BYTES,
            )
        })?;
        if total > self.configured {
            return Err(resource_limit(
                "production fault checkpoint",
                self.current,
                requested,
                self.configured,
                MAX_BYTES,
            ));
        }
        self.current = total;
        Ok(())
    }
}

pub(super) fn map_bounded_cbor_error(
    error: BoundedCborError,
) -> ProductionFaultRuntimeCheckpointCodecError {
    match error {
        BoundedCborError::Malformed => ProductionFaultRuntimeCheckpointCodecError::Malformed,
        BoundedCborError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => resource_limit(field, current, requested, configured, hard),
    }
}

pub(super) fn map_plan_resource_error(
    error: FaultResourceLimitError,
) -> ProductionFaultRuntimeCheckpointCodecError {
    match error {
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
        } => resource_limit(field, current, requested, configured, hard),
        FaultResourceLimitError::ConfiguredAboveHard {
            field,
            configured,
            hard,
        } => resource_limit(field, 0, configured, configured, hard),
        FaultResourceLimitError::Zero { field } => resource_limit(field, 0, 1, 0, 0),
        FaultResourceLimitError::UnknownField { field } => resource_limit(field, 0, 1, 0, 0),
        FaultResourceLimitError::Representation { field, value } => {
            resource_limit(field, 0, value, value, value)
        }
    }
}

pub(super) fn map_host_error(
    error: FaultRuntimeError,
) -> ProductionFaultRuntimeCheckpointCodecError {
    match error {
        FaultRuntimeError::ResourceLimit(error) => map_plan_resource_error(error),
        _ => ProductionFaultRuntimeCheckpointCodecError::Host,
    }
}

pub(super) fn map_runtime_error(
    error: FaultRuntimeError,
) -> ProductionFaultRuntimeCheckpointCodecError {
    match error {
        FaultRuntimeError::ResourceLimit(error) => map_plan_resource_error(error),
        _ => ProductionFaultRuntimeCheckpointCodecError::Runtime,
    }
}

pub(super) fn map_identity_error(
    error: ProductionFaultRuntimeError,
) -> ProductionFaultRuntimeCheckpointCodecError {
    match error {
        ProductionFaultRuntimeError::ResourceLimit(error) => map_plan_resource_error(error),
        _ => ProductionFaultRuntimeCheckpointCodecError::Invalid,
    }
}

pub(super) fn map_scheduler_network_error(
    error: SchedulerNetworkCheckpointCodecError,
) -> ProductionFaultRuntimeCheckpointCodecError {
    match error {
        SchedulerNetworkCheckpointCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => resource_limit(field, current, requested, configured, hard),
        _ => ProductionFaultRuntimeCheckpointCodecError::Network,
    }
}

pub(super) fn map_backend_network_output_error(
    error: BackendNetworkOutputCodecError,
) -> ProductionFaultRuntimeCheckpointCodecError {
    match error {
        BackendNetworkOutputCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => resource_limit(field, current, requested, configured, hard),
        _ => ProductionFaultRuntimeCheckpointCodecError::Network,
    }
}

pub(super) fn checkpoint_runtime_bytes(
    runtime: &crucible::model::FaultRuntimeCheckpoint,
    maximum: u64,
) -> Result<Vec<u8>, ProductionFaultRuntimeCheckpointCodecError> {
    runtime
        .canonical_bytes_with_limit(maximum)
        .map_err(map_runtime_error)
}

pub(super) fn host_resource_limits(
    checkpoint: &ProductionFaultRuntimeCheckpoint,
    maximum: u64,
) -> FaultResourceLimits {
    let mut limits = checkpoint
        .runtime
        .as_ref()
        .map_or_else(FaultResourceLimits::compiled_maximum, |runtime| {
            runtime.resource_limits
        });
    limits.fat_checkpoint_bytes = limits.fat_checkpoint_bytes.min(maximum);
    limits
}

pub(super) const fn resource_limit(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> ProductionFaultRuntimeCheckpointCodecError {
    ProductionFaultRuntimeCheckpointCodecError::ResourceLimit {
        field,
        current,
        requested,
        configured,
        hard,
    }
}

pub(super) fn admit_checkpoint_record_count(
    field: &'static str,
    count: usize,
) -> Result<(), ProductionFaultRuntimeCheckpointCodecError> {
    let requested = u64::try_from(count)
        .map_err(|_| resource_limit(field, 0, u64::MAX, MAX_EVENT_RECORDS, MAX_EVENT_RECORDS))?;
    if requested > MAX_EVENT_RECORDS {
        return Err(resource_limit(
            field,
            0,
            requested,
            MAX_EVENT_RECORDS,
            MAX_EVENT_RECORDS,
        ));
    }
    Ok(())
}

pub(super) fn admit_checkpoint_bytes(
    field: &'static str,
    count: usize,
) -> Result<(), ProductionFaultRuntimeCheckpointCodecError> {
    let requested = u64::try_from(count)
        .map_err(|_| resource_limit(field, 0, u64::MAX, MAX_BYTES, MAX_BYTES))?;
    if requested > MAX_BYTES {
        return Err(resource_limit(field, 0, requested, MAX_BYTES, MAX_BYTES));
    }
    Ok(())
}

pub(super) fn record_allocation_limit(
    field: &'static str,
    count: usize,
) -> ProductionFaultRuntimeCheckpointCodecError {
    let requested = u64::try_from(count).unwrap_or(u64::MAX);
    resource_limit(field, 0, requested, MAX_EVENT_RECORDS, MAX_EVENT_RECORDS)
}
