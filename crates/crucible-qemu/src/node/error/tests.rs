//! Tests scheduler propagation of node-local typed failures.

use super::*;
use crate::QemuAsyncDriverRuntimeError;
use crucible::SchedulerError;
use std::error::Error;

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
            SchedulerError::Backend(BackendError::RetainedOperationalFailure { kind: found, ref source })
                if found == kind && source.to_string().contains("page in")
        ));
        let original = scheduler
            .source()
            .and_then(Error::source)
            .and_then(Error::source)
            .and_then(|source| source.downcast_ref::<QemuAsyncDriverRuntimeError>())
            .unwrap_or_else(|| panic!("original runtime cause must remain downcastable"));
        assert_eq!(original.operational_supervision_source(), Some(source));
        assert_eq!(
            original
                .source()
                .and_then(|source| source.downcast_ref::<HostSupervisionError>()),
            Some(&source),
            "standard error chaining retains the original supervision coordinates"
        );
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

#[test]
fn pending_source_failures_remain_typed_operational_scheduler_errors() {
    use crate::QemuAsyncDriverHealthError;
    use crate::ram_source::QemuRamSourceError;
    use crucible::SchedulerOperationalFailureClass;

    for (source, kind, class) in [
        (
            QemuRamSourceError::Canceled,
            BackendOperationalFailureKind::Canceled,
            SchedulerOperationalFailureClass::Canceled,
        ),
        (
            QemuRamSourceError::Io(std::io::Error::other("original transport")),
            BackendOperationalFailureKind::Unavailable,
            SchedulerOperationalFailureClass::Retryable,
        ),
        (
            QemuRamSourceError::Proof("original page authentication".into()),
            BackendOperationalFailureKind::Terminal,
            SchedulerOperationalFailureClass::Terminal,
        ),
    ] {
        let health = QemuAsyncDriverHealthError::ram_source(source);
        let observer = health.clone();
        let node =
            QemuNodeError::from_async_driver(QemuAsyncDriverError::OperationalHealth(health));
        let scheduler = SchedulerError::from(BackendError::from(node));

        assert_eq!(scheduler.operational_failure_class(), Some(class));
        assert!(matches!(scheduler, SchedulerError::Backend(ref backend)
            if backend.operational_kind() == Some(kind)));
        let original = scheduler
            .source()
            .and_then(Error::source)
            .and_then(Error::source)
            .and_then(|source| source.downcast_ref::<QemuAsyncDriverHealthError>())
            .unwrap_or_else(|| panic!("original source-health cause must remain downcastable"));
        assert_eq!(original, &observer);
    }
}
