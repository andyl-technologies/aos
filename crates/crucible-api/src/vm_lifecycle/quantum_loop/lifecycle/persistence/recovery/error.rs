//! Typed errors for bounded durable lifecycle-state recovery.

use super::*;

#[derive(Debug, thiserror::Error)]
pub(in crate::vm_lifecycle) enum DurableRunStateError {
    #[error("{message}")]
    Invalid { message: String },
    #[error(
        "durable run-state resource limit: field={field} current={current} requested={requested} configured={configured} hard={hard}"
    )]
    ResourceLimit {
        field: &'static str,
        current: u64,
        requested: u64,
        configured: u64,
        hard: u64,
    },
}

impl DurableRunStateError {
    #[cfg(test)]
    pub(in crate::vm_lifecycle) fn contains(&self, needle: &str) -> bool {
        self.to_string().contains(needle)
    }
}

impl From<String> for DurableRunStateError {
    fn from(message: String) -> Self {
        Self::Invalid { message }
    }
}

pub(super) fn map_limit(error: FaultResourceLimitError) -> DurableRunStateError {
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
        } => DurableRunStateError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        },
        error => format!("invalid durable run-state resource policy: {error}").into(),
    }
}

pub(super) fn decode_allocation_error(
    allocation: process_owners::DurableDecodeAllocation,
    limits: FaultResourceLimits,
    runtime_event_records: u64,
    runtime_event_log_bytes: u64,
) -> DurableRunStateError {
    let current = match allocation.field {
        "event_records" => runtime_event_records.saturating_add(allocation.current),
        "event_log_bytes" => runtime_event_log_bytes.saturating_add(allocation.current),
        _ => allocation.current,
    };
    DurableRunStateError::ResourceLimit {
        field: allocation.field,
        current,
        requested: allocation.requested,
        configured: limits.configured(allocation.field).unwrap_or(0),
        hard: FaultResourceLimits::compiled_maximum()
            .configured(allocation.field)
            .unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_allocation_error_adds_the_complete_runtime_base() {
        let limits = FaultResourceLimits {
            event_records: 32,
            ..FaultResourceLimits::default()
        };
        assert!(matches!(
            decode_allocation_error(
                process_owners::DurableDecodeAllocation {
                    field: "event_records",
                    current: 3,
                    requested: 5,
                },
                limits,
                7,
                0,
            ),
            DurableRunStateError::ResourceLimit {
                field: "event_records",
                current: 10,
                requested: 5,
                configured: 32,
                hard,
            } if hard == FaultResourceLimits::compiled_maximum().event_records
        ));
    }
}
