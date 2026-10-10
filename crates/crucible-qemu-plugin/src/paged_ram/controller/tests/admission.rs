//! Checks original setup lifetime across synchronous native inventory work.

use super::*;
use std::sync::mpsc;

fn setup_controller() -> LivePagerController {
    let controller = controller();
    controller
        .state
        .lock()
        .unwrap_or_else(|error| panic!("setup state: {error}"))
        .budgets[0]
        .total_ms = Some(80);
    controller
}

#[test]
fn blocked_native_export_retains_one_original_setup_and_refuses_late_success() {
    let controller = Arc::new(setup_controller());
    let (entered, entering) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let retained = controller.clone();
    let worker = std::thread::spawn(move || {
        super::super::admission::export_owner_inventory(&retained, |inventory| {
            assert!(retained.state.try_lock().is_ok());
            entered
                .send(())
                .unwrap_or_else(|error| panic!("signal export: {error}"));
            released
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_else(|error| panic!("release export: {error}"));
            inventory.existing_tasks = 7;
            0
        })
    });

    entering
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("wait export: {error}"));
    assert_eq!(controller.operations.load(Ordering::Acquire), 1);
    std::thread::sleep(Duration::from_millis(120));
    assert!(!worker.is_finished());
    assert_eq!(controller.operations.load(Ordering::Acquire), 1);
    assert!(
        controller
            .state
            .lock()
            .unwrap_or_else(|error| panic!("inspect state: {error}"))
            .inventory
            .is_none()
    );

    release
        .send(())
        .unwrap_or_else(|error| panic!("release native wait: {error}"));
    let result = worker
        .join()
        .unwrap_or_else(|_| panic!("export worker panicked"));
    assert!(matches!(result, Err(RamError::Io(error)) if error.kind() == io::ErrorKind::TimedOut));
    assert!(
        controller
            .state
            .lock()
            .unwrap_or_else(|error| panic!("inspect refused state: {error}"))
            .inventory
            .is_none()
    );
    assert_eq!(controller.operations.load(Ordering::Acquire), 0);
}

#[test]
fn native_export_failure_keeps_original_status_after_setup_expiry() {
    let controller = setup_controller();
    let result = super::super::admission::export_owner_inventory(&controller, |_| {
        assert_eq!(controller.operations.load(Ordering::Acquire), 1);
        std::thread::sleep(Duration::from_millis(120));
        -libc::ENOTSUP
    });

    assert!(matches!(result, Err(RamError::Native {
        operation: "authenticate pre-CPU owner inventory",
        status,
    }) if status == -libc::ENOTSUP));
    assert_eq!(controller.operations.load(Ordering::Acquire), 0);
}

#[test]
fn successful_export_returns_same_setup_custody_without_completion_or_renewal() {
    let controller = controller();
    let (inventory, operation) =
        super::super::admission::export_owner_inventory(&controller, |inventory| {
            assert_eq!(controller.operations.load(Ordering::Acquire), 1);
            inventory.existing_tasks = 7;
            inventory.existing_file_descriptors = 9;
            inventory.registered_service_tasks = 1;
            0
        })
        .unwrap_or_else(|error| panic!("authenticate inventory: {error}"));

    assert_eq!(inventory.existing_tasks, 7);
    assert_eq!(inventory.existing_file_descriptors, 9);
    assert_eq!(inventory.registered_service_tasks, 1);
    assert_eq!(inventory.prospective_tasks, 1);
    assert_eq!(inventory.prospective_file_descriptors, 5);
    operation
        .wait_slice()
        .unwrap_or_else(|error| panic!("setup still live: {error}"));
    let retained = operation.clone();
    assert!(Arc::ptr_eq(&operation, &retained));
    drop(operation);
    assert_eq!(controller.operations.load(Ordering::Acquire), 1);
    retained
        .complete()
        .unwrap_or_else(|error| panic!("complete original setup: {error}"));
    assert_eq!(controller.operations.load(Ordering::Acquire), 1);
    drop(retained);
    assert_eq!(controller.operations.load(Ordering::Acquire), 0);
}
