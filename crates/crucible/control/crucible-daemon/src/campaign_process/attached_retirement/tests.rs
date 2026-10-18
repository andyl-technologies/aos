//! Exercises the actual inline diagnostic collector without admitting Main.

use super::*;
use crucible_host_resources::host_supervision::{
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

    history.record_cleanup(AttachedRetirementReport::from_post(refused));
    history.record_first(PackagedQemuExecutorJoinError::OwnerUnavailable);
    history.record_cleanup(AttachedRetirementReport::from_post(refused));

    assert!(std::ptr::eq(history.first.get().unwrap(), first));
    assert!(std::ptr::eq(history.cleanup.admission().unwrap(), cleanup));
    assert!(
        matches!(history.first.get(), Some(PackagedQemuExecutorJoinError::OwnerSpawn(error)) if error.raw_os_error() == errno)
    );
    assert!(
        matches!(history.cleanup.admission(), Some(crucible_host_resources::host_services::process_birth::ServiceBirthError::Supervision(error)) if *error == refused)
    );
    assert_eq!(history.cleanup.original_post(), Some(refused));
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

    history.record_cleanup(AttachedRetirementReport::from_post(post));

    assert!(history.first.get().is_none());
    assert_eq!(history.cleanup.original_post(), Some(post));
    Ok(())
}

#[test]
fn first_body_post_is_shared_without_reordering_the_initiating_phase()
-> Result<(), Box<dyn std::error::Error>> {
    use crucible_host_resources::host_services::process_birth::ServiceBirthError;
    use crucible_host_resources::host_supervision::HostSupervisionError;

    let history = AttachedRetirementHistory::new();
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    original.complete()?;
    let first_post = original.wait_slice().unwrap_err();
    let report = AttachedRetirementReport::from_admission(first_post.into())
        .with_first_post(Some(first_post));

    history.record_cleanup(report);
    // This later injected diagnostic must not replace the actual body post.
    history.record_cleanup(AttachedRetirementReport::from_post(
        HostSupervisionError::Unavailable,
    ));

    assert_eq!(history.cleanup.original_post(), Some(first_post));
    let first = std::error::Error::source(&history.cleanup)
        .unwrap()
        .downcast_ref::<ServiceBirthError>()
        .unwrap();
    assert!(matches!(first, ServiceBirthError::Supervision(error) if *error == first_post));
    Ok(())
}
