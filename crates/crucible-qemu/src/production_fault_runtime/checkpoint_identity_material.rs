//! Bounded aggregate material and nested error translation for checkpoint IDs.

use super::*;
use std::mem::size_of;

pub(super) struct BoundedCheckpointIdentityMaterial {
    bytes: Vec<u8>,
    resource_limits: FaultResourceLimits,
}

pub(super) struct BoundedObservationIdentityMaterial {
    bytes: Vec<u8>,
    resource_limits: FaultResourceLimits,
    checkpoint_offset: Option<u64>,
}

impl BoundedObservationIdentityMaterial {
    pub(super) fn new(resource_limits: FaultResourceLimits) -> Self {
        Self {
            bytes: Vec::new(),
            resource_limits,
            checkpoint_offset: None,
        }
    }

    pub(super) fn at_checkpoint_offset(
        resource_limits: FaultResourceLimits,
        checkpoint_offset: u64,
    ) -> Self {
        Self {
            bytes: Vec::new(),
            resource_limits,
            checkpoint_offset: Some(checkpoint_offset),
        }
    }

    pub(super) fn append(&mut self, value: &[u8]) -> Result<(), ProductionFaultRuntimeError> {
        self.reserve(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(super) fn push(&mut self, value: u8) -> Result<(), ProductionFaultRuntimeError> {
        self.reserve(1)?;
        self.bytes.push(value);
        Ok(())
    }

    pub(super) fn append_length_prefixed(
        &mut self,
        value: &[u8],
    ) -> Result<(), ProductionFaultRuntimeError> {
        let requested = value.len().checked_add(size_of::<u64>()).ok_or(
            FaultResourceLimitError::Representation {
                field: "event_log_bytes",
                value: u64::MAX,
            },
        )?;
        self.reserve(requested)?;
        let length =
            u64::try_from(value.len()).map_err(|_| FaultResourceLimitError::Representation {
                field: "event_log_bytes",
                value: u64::MAX,
            })?;
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(super) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    fn reserve(&mut self, requested: usize) -> Result<(), ProductionFaultRuntimeError> {
        let current = u64::try_from(self.bytes.len()).map_err(|_| {
            FaultResourceLimitError::Representation {
                field: "event_log_bytes",
                value: u64::MAX,
            }
        })?;
        let requested_u64 =
            u64::try_from(requested).map_err(|_| FaultResourceLimitError::Representation {
                field: "event_log_bytes",
                value: u64::MAX,
            })?;
        self.resource_limits
            .reserve("event_log_bytes", current, requested_u64)?;
        if let Some(checkpoint_offset) = self.checkpoint_offset {
            let aggregate_current = checkpoint_offset.checked_add(current).ok_or(
                FaultResourceLimitError::Representation {
                    field: "fat_checkpoint_bytes",
                    value: u64::MAX,
                },
            )?;
            self.resource_limits.reserve(
                "fat_checkpoint_bytes",
                aggregate_current,
                requested_u64,
            )?;
        }
        self.bytes.try_reserve_exact(requested).map_err(|_| {
            observation_allocation_error(
                current,
                requested_u64,
                self.resource_limits,
                self.checkpoint_offset,
            )
        })?;
        Ok(())
    }
}

fn observation_allocation_error(
    current: u64,
    requested: u64,
    limits: FaultResourceLimits,
    checkpoint_offset: Option<u64>,
) -> ProductionFaultRuntimeError {
    if let Some(checkpoint_offset) = checkpoint_offset
        && limits
            .fat_checkpoint_bytes
            .saturating_sub(checkpoint_offset.saturating_add(current))
            < limits.event_log_bytes.saturating_sub(current)
    {
        return FaultResourceLimitError::Exceeded {
            field: "fat_checkpoint_bytes",
            current: checkpoint_offset.saturating_add(current),
            requested,
            configured: limits.fat_checkpoint_bytes,
            hard: FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes,
        }
        .into();
    }
    FaultResourceLimitError::Exceeded {
        field: "event_log_bytes",
        current,
        requested,
        configured: limits.event_log_bytes,
        hard: FaultResourceLimits::compiled_maximum().event_log_bytes,
    }
    .into()
}

impl BoundedCheckpointIdentityMaterial {
    pub(super) fn new(resource_limits: FaultResourceLimits) -> Self {
        Self {
            bytes: Vec::new(),
            resource_limits,
        }
    }

    pub(super) fn append(&mut self, value: &[u8]) -> Result<(), ProductionFaultRuntimeError> {
        self.reserve(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(super) fn push(&mut self, value: u8) -> Result<(), ProductionFaultRuntimeError> {
        self.reserve(1)?;
        self.bytes.push(value);
        Ok(())
    }

    pub(super) fn append_length_prefixed(
        &mut self,
        value: &[u8],
    ) -> Result<(), ProductionFaultRuntimeError> {
        let requested = value.len().checked_add(size_of::<u64>()).ok_or(
            FaultResourceLimitError::Representation {
                field: "fat_checkpoint_bytes",
                value: u64::MAX,
            },
        )?;
        self.reserve(requested)?;
        let length =
            u64::try_from(value.len()).map_err(|_| FaultResourceLimitError::Representation {
                field: "fat_checkpoint_bytes",
                value: u64::MAX,
            })?;
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn remaining_after_length_prefix(&self) -> Result<u64, ProductionFaultRuntimeError> {
        let current = u64::try_from(self.bytes.len()).map_err(|_| {
            FaultResourceLimitError::Representation {
                field: "fat_checkpoint_bytes",
                value: u64::MAX,
            }
        })?;
        let prefix = u64::try_from(size_of::<u64>()).unwrap_or(u64::MAX);
        self.resource_limits
            .reserve("fat_checkpoint_bytes", current, prefix)?;
        Ok(self
            .resource_limits
            .fat_checkpoint_bytes
            .saturating_sub(current)
            .saturating_sub(prefix))
    }

    pub(super) fn offset_after_length_prefix(&self) -> Result<u64, ProductionFaultRuntimeError> {
        let current = u64::try_from(self.bytes.len()).map_err(|_| {
            FaultResourceLimitError::Representation {
                field: "fat_checkpoint_bytes",
                value: u64::MAX,
            }
        })?;
        let prefix = u64::try_from(size_of::<u64>()).unwrap_or(u64::MAX);
        self.resource_limits
            .reserve("fat_checkpoint_bytes", current, prefix)?;
        current.checked_add(prefix).ok_or(
            FaultResourceLimitError::Representation {
                field: "fat_checkpoint_bytes",
                value: u64::MAX,
            }
            .into(),
        )
    }

    fn reserve(&mut self, requested: usize) -> Result<(), ProductionFaultRuntimeError> {
        let current = u64::try_from(self.bytes.len()).map_err(|_| {
            FaultResourceLimitError::Representation {
                field: "fat_checkpoint_bytes",
                value: u64::MAX,
            }
        })?;
        let requested_u64 =
            u64::try_from(requested).map_err(|_| FaultResourceLimitError::Representation {
                field: "fat_checkpoint_bytes",
                value: u64::MAX,
            })?;
        self.resource_limits
            .reserve("fat_checkpoint_bytes", current, requested_u64)?;
        self.bytes
            .try_reserve_exact(requested)
            .map_err(|_| identity_allocation_error(current, requested_u64, self.resource_limits))?;
        Ok(())
    }
}

fn identity_allocation_error(
    current: u64,
    requested: u64,
    limits: FaultResourceLimits,
) -> ProductionFaultRuntimeError {
    FaultResourceLimitError::Exceeded {
        field: "fat_checkpoint_bytes",
        current,
        requested,
        configured: limits.fat_checkpoint_bytes,
        hard: FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes,
    }
    .into()
}

pub(super) fn map_identity_scheduler_error(
    error: crucible::SchedulerNetworkCheckpointCodecError,
) -> ProductionFaultRuntimeError {
    match error {
        crucible::SchedulerNetworkCheckpointCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => FaultResourceLimitError::Exceeded {
            field,
            current,
            requested,
            configured,
            hard,
        }
        .into(),
        _ => ProductionFaultRuntimeError::CheckpointEncoding {
            component: "scheduler network",
        },
    }
}

pub(super) fn map_identity_network_output_error(
    error: crucible::BackendNetworkOutputCodecError,
) -> ProductionFaultRuntimeError {
    match error {
        crucible::BackendNetworkOutputCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => FaultResourceLimitError::Exceeded {
            field,
            current,
            requested,
            configured,
            hard,
        }
        .into(),
        _ => ProductionFaultRuntimeError::CheckpointEncoding {
            component: "pending network output",
        },
    }
}
