//! Checks pure recipient moves using actual component-owned child processes.
//!
//! Receivers are deliberately unissued and carry no Source funding or lender.
//! The production cleanup gate must refuse them. Only the explicit component
//! owner then permits ordinary test cleanup of its real process.

use super::*;
use crucible_host_resources::host_supervision::{HostOperationBudgets, HostOperationClass};
use crucible_host_resources::test_support::TestAllocationObserver;

fn component_owner(
    supervisor: &HostOperationSupervisor,
) -> Result<
    (
        IssuedLaunchOwner,
        crate::RetainedNativeFreshLaunchError,
        u32,
    ),
    Box<dyn std::error::Error>,
> {
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation)?);
    let receiver = crate::OriginalNativeFreshLaunchError::component_receiver(&original);
    let process = std::process::Command::new("sleep").arg("60").spawn()?;
    let process_id = process.id();
    let mut owner = IssuedLaunchOwner::component(QemuNodeChild::new(process), Some(supervisor));
    owner.receiver = Some(receiver.clone());
    Ok((owner, receiver, process_id))
}

fn close_component_child(
    receiver: &crate::RetainedNativeFreshLaunchError,
    process_id: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut owner = receiver
        .take_component_returned_owner()
        .ok_or("the same actual child must reach its preborn component recipient")?;
    assert_eq!(owner.process_id(), Some(process_id));
    assert!(!owner.child_reaped());
    assert!(matches!(
        owner.retry_cleanup(),
        Err(QemuNodeError::RamCleanupPending)
    ));
    assert!(!owner.child_reaped());

    // This explicit component owner, rather than an invented Source lender,
    // permits ordinary test containment only after checking production refusal.
    owner.source_cleanup = FailedSourceCleanup::Existing;
    owner.retry_cleanup()?;
    assert!(owner.child_reaped());
    Ok(())
}

#[test]
fn incomplete_node_handoff_keeps_the_actual_child_in_the_same_guard()
-> Result<(), Box<dyn std::error::Error>> {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let (mut owner, receiver, process_id) = component_owner(&supervisor)?;
    let before = supervisor.operation_statuses()?.len();

    let (node, allocations) = TestAllocationObserver::count(|| owner.take_assembled_node());

    assert!(node.is_none());
    assert_eq!(allocations.allocations, 0);
    assert_eq!(allocations.reallocations, 0);
    assert!(!allocations.overflow);
    assert_eq!(owner.process_id(), process_id);
    assert_eq!(owner.child_mut()?.process_id(), process_id);
    assert!(
        owner
            .retained_receiver()
            .is_some_and(|actual| actual.same_owner(&receiver))
    );
    assert!(receiver.take_component_returned_owner().is_none());
    assert_eq!(supervisor.operation_statuses()?.len(), before);

    // The caller still chooses when to return the child after its dependent
    // artifacts; failed extraction has not published it to the receiver early.
    let error = owner.retain_cleanup_failure(crate::QemuLiveNodeStepGateError::Step {
        operation: const { &crate::QemuNodeStepOperation::new("component incomplete Node handoff") },
        source: QemuNodeError::RamCleanupPending,
    });
    assert!(matches!(
        error,
        crate::QemuLiveNodeStepGateError::OriginalNativeLaunch { source }
            if source.same_owner(&receiver)
    ));
    close_component_child(&receiver, process_id)?;
    Ok(())
}

#[test]
fn cleanup_failure_returns_actual_body_before_publishing_the_same_receiver()
-> Result<(), Box<dyn std::error::Error>> {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let (owner, receiver, process_id) = component_owner(&supervisor)?;
    let before = supervisor.operation_statuses()?.len();
    let primary = crate::QemuLiveNodeStepGateError::Step {
        operation: const { &crate::QemuNodeStepOperation::new("component exact-resume refusal") },
        source: QemuNodeError::RamCleanupPending,
    };

    let error = owner.retain_cleanup_failure(primary);

    assert!(error.has_retained_owner());
    assert!(matches!(
        &error,
        crate::QemuLiveNodeStepGateError::OriginalNativeLaunch { source }
            if source.same_owner(&receiver)
    ));
    assert!(!receiver.retry_physical_cleanup());
    assert_eq!(supervisor.operation_statuses()?.len(), before);
    close_component_child(&receiver, process_id)?;
    assert!(
        receiver
            .to_string()
            .contains("component exact-resume refusal")
    );
    Ok(())
}

#[test]
fn unwind_returns_the_actual_body_without_starting_another_operation()
-> Result<(), Box<dyn std::error::Error>> {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let (owner, receiver, process_id) = component_owner(&supervisor)?;
    let before = supervisor.operation_statuses()?.len();

    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _retained = owner;
        panic!("abandon the same actual issued-owner component body");
    }));

    assert!(unwind.is_err());
    assert_eq!(supervisor.operation_statuses()?.len(), before);
    assert!(!receiver.retry_physical_cleanup());
    close_component_child(&receiver, process_id)?;
    Ok(())
}
