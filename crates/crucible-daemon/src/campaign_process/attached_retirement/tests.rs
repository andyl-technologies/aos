//! Exercises the actual inline diagnostic collector without admitting Main.

use super::*;
use crucible_linux_resource::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
};
use std::time::Duration;

#[test]
fn inline_history_keeps_initial_cause_and_later_cleanup_phases_independent()
-> Result<(), Box<dyn std::error::Error>> {
    let history = AttachedRetirementHistory::new();
    let directory = tempfile::tempdir()?;
    let failure = std::fs::File::open(directory.path().join("missing")).unwrap_err();
    let errno = failure.raw_os_error();
    history.record_first(PackagedQemuExecutorJoinError::OwnerSpawn(failure));
    let first = history.first.get().unwrap() as *const _;
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    original.complete()?;
    let refused = original.wait_slice().unwrap_err();
    history.record_cleanup(AttachedRetirementReport::from_admission(refused.into()));
    let cleanup = std::ptr::from_ref(history.cleanup.admission().unwrap());

    history.record_post(refused);
    history.record_first(PackagedQemuExecutorJoinError::OwnerUnavailable);
    history.record_cleanup(AttachedRetirementReport::from_post(refused));

    assert!(std::ptr::eq(history.first.get().unwrap(), first));
    assert!(std::ptr::eq(history.cleanup.admission().unwrap(), cleanup));
    assert!(
        matches!(history.first.get(), Some(PackagedQemuExecutorJoinError::OwnerSpawn(error)) if error.raw_os_error() == errno)
    );
    assert!(
        matches!(history.cleanup.admission(), Some(crucible_linux_resource::host_services::process_birth::ServiceBirthError::Supervision(error)) if *error == refused)
    );
    assert_eq!(history.cleanup.original_post(), Some(refused));
    assert_eq!(history.post.get().copied(), Some(refused));
    Ok(())
}

#[test]
fn post_only_history_retains_a_typed_cleanup_cause_without_a_service_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let history = AttachedRetirementHistory::new();
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    original.complete()?;
    let post = original.wait_slice().unwrap_err();

    history.record_post(post);

    assert!(history.first.get().is_none());
    assert_eq!(history.cleanup.original_post(), Some(post));
    assert_eq!(history.post.get().copied(), Some(post));
    Ok(())
}
