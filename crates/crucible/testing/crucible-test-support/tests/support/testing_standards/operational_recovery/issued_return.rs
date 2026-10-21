//! Binds real component child return controls without issuing Source authority.
//!
//! Complete bodies preserve the same PID, recipient, preexisting operation
//! count and explicit production refusal before independent component cleanup.

pub(super) const CHILD_CLEANUP: &str = r##"fn close_component_child(
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
}"##;

pub(super) const FAILURE_RETURN: &str = r##"fn cleanup_failure_returns_actual_body_before_publishing_the_same_receiver()
-> Result<(), Box<dyn std::error::Error>> {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let (owner, receiver, process_id) = component_owner(&supervisor)?;
    let before = supervisor.operation_statuses()?.len();
    let primary = crate::QemuLiveNodeStepGateError::Step {
        operation: "component exact-resume refusal",
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
}"##;

pub(super) const UNWIND_RETURN: &str = r##"fn unwind_returns_the_actual_body_without_starting_another_operation()
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
}"##;
