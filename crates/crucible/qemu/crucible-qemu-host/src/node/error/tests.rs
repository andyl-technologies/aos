//! Tests scheduler propagation of node-local typed failures.

use super::*;
use crate::QemuAsyncDriverRuntimeError;
use crucible_engine::SchedulerError;
use std::error::Error;

#[test]
fn channel_diagnostics_borrow_static_text_and_move_owned_allocations() {
    use crucible_host_resources::test_support::TestAllocationObserver;

    let timeout = Duration::from_millis(17);
    let (errors, counts) = TestAllocationObserver::count(|| {
        let first = QemuNodeChannelError::new("channel", "fixed refusal");
        let alias = first.clone();
        [
            first,
            alias,
            QemuNodeChannelError::retryable("channel", "fixed pending"),
            QemuNodeChannelError::bounded_await_timeout("channel", "fixed timeout", timeout),
        ]
    });

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(
        errors
            .iter()
            .all(|error| matches!(error.message, Cow::Borrowed(_)))
    );
    assert_eq!(errors[0], errors[1]);
    assert!(!errors[0].is_retryable());
    assert!(errors[2].is_retryable());
    assert_eq!(errors[3].bounded_timeout(), Some(timeout));

    let constructors: [fn(String) -> QemuNodeChannelError; 3] = [
        |message| QemuNodeChannelError::new("owned channel", message),
        |message| QemuNodeChannelError::retryable("owned channel", message),
        |message| {
            QemuNodeChannelError::bounded_await_timeout(
                "owned channel",
                message,
                Duration::from_millis(17),
            )
        },
    ];
    for construct in constructors {
        let message = String::from("original owned channel diagnostic");
        let allocation = message.as_ptr();
        let (error, counts) = TestAllocationObserver::count(|| construct(message));

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert!(matches!(error.message, Cow::Owned(_)));
        assert_eq!(error.message.as_ptr(), allocation);
        assert_eq!(error.message, "original owned channel diagnostic");

        let (node, counts) = TestAllocationObserver::count(|| {
            QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, error)
        });

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        let QemuNodeError::Channel { message, .. } = node else {
            panic!("channel conversion preserves its original diagnostic");
        };
        assert!(matches!(message, Cow::Owned(_)));
        assert_eq!(message.as_ptr(), allocation);
    }
}

#[test]
fn channel_supervision_retains_actual_cause_through_shutdown_without_allocating()
-> Result<(), Box<dyn Error>> {
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    use crucible_host_resources::test_support::TestAllocationObserver;

    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    original.complete()?;
    let expected = original
        .wait_slice()
        .expect_err("the actual Cleanup has completed");

    let ((channel, shutdown), counts) = TestAllocationObserver::count(|| {
        let channel =
            QemuNodeChannelError::operational_supervision("send supervised plugin Quit", expected);
        let shutdown = super::super::channel_error_to_shutdown_error(channel.clone());
        (channel, shutdown)
    });

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!(channel.operational_supervision_source(), Some(expected));
    assert_eq!(
        channel
            .source()
            .and_then(|source| source.downcast_ref::<HostSupervisionError>()),
        Some(&expected)
    );
    assert!(!channel.is_retryable());
    assert_eq!(channel.bounded_timeout(), None);
    assert!(matches!(channel.message, Cow::Borrowed("")));
    assert_eq!(shutdown.operational_supervision_source(), Some(expected));
    assert_eq!(
        shutdown
            .source()
            .and_then(|source| source.downcast_ref::<HostSupervisionError>()),
        Some(&expected)
    );
    assert_eq!(channel.to_string(), shutdown.to_string());
    assert_eq!(
        channel.to_string(),
        format!("send supervised plugin Quit failed: {expected}")
    );
    Ok(())
}

#[test]
fn unsupported_supervised_quit_refuses_without_allocation_or_effect() -> Result<(), Box<dyn Error>>
{
    use crate::QemuPluginIpcControlChannel;
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    use crucible_host_resources::test_support::TestAllocationObserver;

    struct UnsupervisedChannel {
        sent: bool,
    }

    impl QemuPluginIpcControlChannel for UnsupervisedChannel {
        fn send_quit(&mut self) -> Result<(), QemuNodeChannelError> {
            self.sent = true;
            Ok(())
        }
    }

    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    let mut channel = UnsupervisedChannel { sent: false };

    let (result, counts) = TestAllocationObserver::count(|| {
        channel.send_quit_supervised(&original).map_err(|error| {
            QemuNodeError::from_channel(QemuNodeChannelPlane::PluginIpcControl, error)
        })
    });

    let error = result.expect_err("the actual default requires a bounded cleanup writer");
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(!channel.sent);
    let QemuNodeError::Channel {
        plane,
        operation,
        message,
    } = error
    else {
        panic!("the actual default retains the channel role and diagnostic");
    };
    assert_eq!(plane, QemuNodeChannelPlane::PluginIpcControl);
    assert_eq!(operation, "send supervised plugin Quit");
    assert_eq!(message, "transport has no bounded cleanup writer");
    assert!(matches!(message, Cow::Borrowed(_)));
    original.wait_slice()?;
    Ok(())
}

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

#[test]
fn channel_original_post_preserves_both_causes_through_scheduler_conversion()
-> Result<(), Box<dyn Error>> {
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = supervisor.begin(HostOperationClass::Quantum)?;
    supervisor.cancel()?;
    let post = original
        .wait_slice()
        .expect_err("actual Original is canceled");

    for (first, expected_kind) in [
        (
            QemuNodeChannelError::new("start quantum", "initiating transport refusal"),
            BackendOperationalFailureKind::Canceled,
        ),
        (
            QemuNodeChannelError::operational_supervision(
                "start quantum",
                HostSupervisionError::CapacityExhausted,
            ),
            BackendOperationalFailureKind::CapacityExhausted,
        ),
    ] {
        let expected = QemuAsyncDriverError::ChannelOriginalPost {
            source: first,
            original_after: post,
        };
        let node = QemuNodeError::from_async_driver(expected.clone());

        let scheduler = SchedulerError::from(BackendError::from(node));

        assert!(matches!(scheduler, SchedulerError::Backend(ref backend)
            if backend.operational_kind() == Some(expected_kind)));
        let retained = scheduler
            .source()
            .and_then(Error::source)
            .and_then(Error::source)
            .and_then(|source| source.downcast_ref::<QemuAsyncDriverError>())
            .expect("complete channel first and Original post remain downcastable");
        assert_eq!(retained, &expected);
    }
    Ok(())
}
