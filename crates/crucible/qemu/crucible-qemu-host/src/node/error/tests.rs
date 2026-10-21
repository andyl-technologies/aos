//! Tests scheduler propagation of node-local typed failures.

use super::*;
use crate::QemuAsyncDriverRuntimeError;
use crucible_engine::SchedulerError;
use std::error::Error;

#[test]
fn operational_failure_kind_survives_node_and_scheduler_conversion() {
    for (source, kind) in [
        (
            HostSupervisionError::DeadlineExpired {
                operation_id: 7,
                class: crucible_host_resources::host_supervision::HostOperationClass::PageIn,
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
        (
            HostSupervisionError::BorrowedOperation,
            BackendOperationalFailureKind::Terminal,
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
fn runtime_original_post_survives_scheduler_conversion_without_erasing_first()
-> Result<(), Box<dyn std::error::Error>> {
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = supervisor.begin(HostOperationClass::Quantum)?;
    supervisor.cancel()?;
    let post = original
        .wait_slice()
        .expect_err("actual Original is canceled");

    for (first, kind) in [
        (
            QemuAsyncDriverRuntimeError::new("adapter", "initiating diagnostic"),
            BackendOperationalFailureKind::Canceled,
        ),
        (
            QemuAsyncDriverRuntimeError::operational_supervision(
                "adapter",
                HostSupervisionError::Unavailable,
            ),
            BackendOperationalFailureKind::Unavailable,
        ),
        (
            QemuAsyncDriverRuntimeError::resource_limit("storage_request_bytes", 3, 5, 7, 11),
            BackendOperationalFailureKind::CapacityExhausted,
        ),
    ] {
        let expected = first.clone().with_operational_supervision_post(post);

        let node = QemuNodeError::from_async_driver(QemuAsyncDriverError::Runtime(
            first.with_operational_supervision_post(post),
        ));
        let scheduler = SchedulerError::from(BackendError::from(node));

        assert!(matches!(scheduler, SchedulerError::Backend(ref backend)
            if backend.operational_kind() == Some(kind)));
        let retained = scheduler
            .source()
            .and_then(Error::source)
            .and_then(Error::source)
            .and_then(|source| source.downcast_ref::<QemuAsyncDriverRuntimeError>())
            .expect("complete first and post remain downcastable");
        assert_eq!(retained, &expected);
        assert_eq!(retained.operational_supervision_post(), Some(post));
    }
    Ok(())
}

#[test]
fn pending_source_failures_remain_typed_operational_scheduler_errors() {
    use crate::QemuAsyncDriverHealthError;
    use crate::ram_source::QemuRamSourceError;
    use crucible_engine::SchedulerOperationalFailureClass;

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

#[test]
#[cfg(target_os = "linux")]
fn cleanup_refusals_keep_operational_category_and_typed_cause() {
    use crate::ram_source::QemuRamSourceError;
    use crucible_engine::SchedulerOperationalFailureClass;

    for (source, kind, class) in [
        (
            QemuRamSourceError::Canceled,
            BackendOperationalFailureKind::Canceled,
            SchedulerOperationalFailureClass::Canceled,
        ),
        (
            QemuRamSourceError::Io(std::io::Error::other("original cleanup transport")),
            BackendOperationalFailureKind::Unavailable,
            SchedulerOperationalFailureClass::Retryable,
        ),
        (
            QemuRamSourceError::Supervision(HostSupervisionError::DeadlineExpired {
                operation_id: 41,
                class: crucible_host_resources::host_supervision::HostOperationClass::Cleanup,
            }),
            BackendOperationalFailureKind::Expired,
            SchedulerOperationalFailureClass::Terminal,
        ),
    ] {
        let node = QemuNodeError::from_ram_source_cleanup("join retained RAM source", source);
        let QemuNodeError::RamSourceCleanup {
            source: observer, ..
        } = &node
        else {
            panic!("cleanup must expose its typed cause");
        };
        let observer = observer.clone();
        let scheduler = SchedulerError::from(BackendError::from(node));

        assert_eq!(scheduler.operational_failure_class(), Some(class));
        assert!(matches!(scheduler, SchedulerError::Backend(ref backend)
            if backend.operational_kind() == Some(kind)));
        let retained = scheduler
            .source()
            .and_then(Error::source)
            .and_then(Error::source)
            .and_then(|source| source.downcast_ref::<crate::QemuAsyncDriverHealthError>())
            .unwrap_or_else(|| panic!("original cleanup cause must remain downcastable"));
        assert_eq!(retained, &observer);
    }
}
