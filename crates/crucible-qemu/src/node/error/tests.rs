//! Tests scheduler propagation of node-local typed failures.

use super::*;
use crate::QemuAsyncDriverRuntimeError;
use crucible::SchedulerError;

#[test]
fn operational_failure_kind_survives_node_and_scheduler_conversion() {
    for (source, kind) in [
        (
            HostSupervisionError::DeadlineExpired {
                operation_id: 7,
                class: crucible_linux_resource::host_supervision::HostOperationClass::PageIn,
            },
            BackendOperationalFailureKind::Expired,
        ),
        (
            HostSupervisionError::Terminal {
                state: HostOperationState::Canceled,
            },
            BackendOperationalFailureKind::Canceled,
        ),
        (
            HostSupervisionError::Unavailable,
            BackendOperationalFailureKind::Unavailable,
        ),
    ] {
        let runtime = QemuAsyncDriverRuntimeError::operational_supervision("page in", source);
        let node = QemuNodeError::from_async_driver(QemuAsyncDriverError::Runtime(runtime));
        let scheduler = SchedulerError::from(BackendError::from(node));

        assert!(matches!(
            scheduler,
            SchedulerError::Backend(BackendError::OperationalFailure { kind: found, message })
                if found == kind && message.contains("page in")
                    && message.contains(&source.to_string())
        ));
    }
}

#[test]
fn resource_limit_coordinates_survive_node_and_scheduler_conversion() {
    let runtime = QemuAsyncDriverRuntimeError::resource_limit("storage_request_bytes", 3, 5, 7, 11);
    let node = QemuNodeError::from_async_driver(QemuAsyncDriverError::Runtime(runtime));
    let scheduler = SchedulerError::from(BackendError::from(node));

    assert!(matches!(
        scheduler,
        SchedulerError::ResourceLimit {
            field: "storage_request_bytes",
            current: 3,
            requested: 5,
            configured: 7,
            hard: 11,
        }
    ));
}
