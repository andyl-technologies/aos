//! Checks same-Restore/native callback ordering without issuing a Main or World.

use super::*;

#[test]
fn replay_boundary_uses_the_same_restore_before_each_native_callback() {
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationState, HostOperationSupervisor,
        HostSupervisionError,
    };
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = supervisor.begin(HostOperationClass::Restore).unwrap();
    let mut native_calls = 0;

    assert!(
        check_replay_boundary(Some(&original), || {
            native_calls += 1;
            Ok(())
        })
        .is_ok()
    );
    original.complete().unwrap();
    let refused = check_replay_boundary(Some(&original), || {
        native_calls += 1;
        Ok(())
    });

    assert!(matches!(
        refused,
        Err(ReplayBoundaryRefusal::Original(
            HostSupervisionError::Terminal {
                state: HostOperationState::Completed
            }
        ))
    ));
    assert_eq!(native_calls, 1);
}

#[test]
fn replay_boundary_preserves_the_actual_native_error_after_the_restore_check() {
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = supervisor.begin(HostOperationClass::Restore).unwrap();
    let message = String::from("same actual native boundary refusal");
    let pointer = message.as_ptr();
    let first = QemuVmRealizationError::ExecutorUnavailable {
        operation: "component native replay boundary",
        message,
    };
    let mut calls = 0;

    let refused = check_replay_boundary(Some(&original), || {
        calls += 1;
        Err(first)
    });

    let Err(ReplayBoundaryRefusal::Native(QemuVmRealizationError::ExecutorUnavailable {
        operation,
        message,
    })) = refused
    else {
        panic!("the same native leaf must be returned");
    };
    assert_eq!(operation, "component native replay boundary");
    assert_eq!(message, "same actual native boundary refusal");
    assert_eq!(message.as_ptr(), pointer);
    assert_eq!(calls, 1);
}

#[test]
fn operation_only_replay_boundary_calls_its_actual_callback_once() {
    let mut calls = 0;

    let result = check_replay_boundary(None, || {
        calls += 1;
        Err(QemuVmRealizationError::Canceled {
            operation: "component replay boundary",
        })
    });

    assert!(matches!(
        result,
        Err(ReplayBoundaryRefusal::Native(
            QemuVmRealizationError::Canceled {
                operation: "component replay boundary"
            }
        ))
    ));
    assert_eq!(calls, 1);
}
