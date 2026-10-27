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
        .total_ns = Some(80_000_000);
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
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 1);
    std::thread::sleep(Duration::from_millis(120));
    assert!(!worker.is_finished());
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 1);
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
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
}

#[test]
fn native_export_failure_keeps_original_status_after_setup_expiry() {
    let controller = setup_controller();
    let result = super::super::admission::export_owner_inventory(&controller, |_| {
        assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 1);
        std::thread::sleep(Duration::from_millis(120));
        -libc::ENOTSUP
    });

    assert!(matches!(result, Err(RamError::Native {
        operation: "authenticate pre-CPU owner inventory",
        status,
    }) if status == -libc::ENOTSUP));
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
}

#[test]
fn successful_export_returns_same_setup_custody_without_completion_or_renewal() {
    let controller = controller();
    let (inventory, operation) =
        super::super::admission::export_owner_inventory(&controller, |inventory| {
            assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 1);
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
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 1);
    retained
        .complete()
        .unwrap_or_else(|error| panic!("complete original setup: {error}"));
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 1);
    drop(retained);
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
}

#[test]
fn complete_metadata_grant_refuses_the_original_omission_before_owner_birth() {
    use crucible_ram::{Limits, RegionClass, RegionDescriptor, Topology};

    let controller = controller();
    let topology = Topology::new(
        vec![RegionDescriptor::new("main", RegionClass::MutableMain, 4096).unwrap()],
        Limits::default(),
    )
    .unwrap();
    let quota = 8192;
    let required = PausedPagingOwner::required_rust_metadata_bytes(&topology, quota).unwrap();
    let native = 4096;
    let initial = RamControlResources {
        resident_peak_bytes: 64 * 1024 * 1024,
        backing_peak_bytes: 64 * 1024 * 1024,
        metadata_bytes: native + required - 8192,
        staging_bytes: 4096,
        paging_io_slots: 1,
        cpu_slots: 1,
        task_slots: 1,
        file_descriptors: 3,
    };
    {
        let mut state = controller.state.lock().unwrap();
        state.resources = initial;
        state.inventory = Some(Inventory {
            report: RamControlInventoryReport {
                topology_generation: 1,
                logical_bytes: 4096,
                region_count: 1,
                native_metadata_bytes: native,
                native_scratch_bytes: 4096,
                rust_metadata_required_bytes: required,
                owner_resources: RamControlOwnerInventory {
                    existing_tasks: 1,
                    existing_file_descriptors: 3,
                    registered_service_tasks: 0,
                    prospective_tasks: 0,
                    prospective_file_descriptors: 0,
                },
                granted: false,
            },
            regions: vec![RamControlInventoryRegion::new(0, 4096, 1, "main").unwrap()],
            grant: None,
            operation: None,
        });
    }

    assert_eq!(
        controller.grant_inventory(1, initial, quota).disposition,
        RamControlDisposition::AdmissionRefused
    );
    let complete = RamControlResources {
        metadata_bytes: native + required,
        ..initial
    };
    assert_eq!(
        controller.grant_inventory(2, complete, quota).disposition,
        RamControlDisposition::AdmissionRefused
    );
    assert_eq!(
        controller
            .grant_inventory(1, complete, quota + 4096)
            .disposition,
        RamControlDisposition::AdmissionRefused
    );
    {
        let state = controller.state.lock().unwrap();
        assert_eq!(state.resources, initial);
        assert!(state.owner.is_none());
        let inventory = state.inventory.as_ref().unwrap();
        assert!(inventory.grant.is_none());
        assert!(!inventory.report.granted);
    }

    // Reclassification uses the same complete peaks and census. This records a
    // pending request only: no native grant or installed pager is fabricated.
    assert_eq!(
        controller.grant_inventory(1, complete, quota).disposition,
        RamControlDisposition::Accepted
    );
    let state = controller.state.lock().unwrap();
    assert_eq!(state.resources, initial);
    assert!(state.owner.is_none());
    let inventory = state.inventory.as_ref().unwrap();
    assert_eq!(inventory.grant, Some((complete, quota)));
    assert!(!inventory.report.granted);
}

#[test]
fn actual_native_residual_must_cover_the_complete_report_before_owner_birth() {
    use crucible_ram::{Limits, RegionClass, RegionDescriptor, Topology};

    extern "C" fn grant_one_byte_short(_: u64, metadata: u64, allowance: *mut u64) -> c_int {
        // SAFETY: the actual grant adapter supplies its live scalar output for
        // this synchronous callback. This fixture models native G minus N.
        unsafe { *allowance = metadata - 4096 - 1 };
        0
    }

    let mut controller = controller();
    controller.native_grant = grant_one_byte_short;
    let topology = Topology::new(
        vec![RegionDescriptor::new("main", RegionClass::MutableMain, 4096).unwrap()],
        Limits::default(),
    )
    .unwrap();
    let required = PausedPagingOwner::required_rust_metadata_bytes(&topology, 8192).unwrap();
    let operation = controller
        .begin(SourceOperationClass::ControlSetup)
        .unwrap();

    let result = super::super::admission::grant_native_rust_allowance(
        &controller,
        operation.as_ref(),
        1,
        4096 + required,
        required,
    );

    assert!(matches!(result, Err(RamError::MetadataAdmission {
        required: actual,
        admitted,
    }) if actual == required && admitted == required - 1));
    let state = controller.state.lock().unwrap();
    assert!(state.failed);
    assert!(state.owner.is_none());
    assert!(state.inventory.is_none());
    assert_eq!(state.resources, RamControlResources::default());
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 1);
    drop(state);
    assert!(operation.wait_slice().is_err());
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 1);
}

#[test]
fn pending_record_retries_without_reissuing_setup_or_publishing_partial_census() {
    let controller = controller();
    let mut attempts = 0;
    let (inventory, operation) =
        super::super::admission::export_owner_inventory(&controller, |inventory| {
            attempts += 1;
            assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 1);
            assert!(controller.state.try_lock().is_ok());
            assert_eq!(inventory.existing_tasks, 0);
            assert_eq!(inventory.existing_file_descriptors, 0);
            assert_eq!(inventory.registered_service_tasks, 0);
            assert!(controller.state.lock().unwrap().inventory.is_none());
            if attempts < 3 {
                return 1;
            }
            inventory.existing_tasks = 7;
            inventory.existing_file_descriptors = 9;
            inventory.registered_service_tasks = 1;
            0
        })
        .unwrap();

    assert_eq!(attempts, 3);
    assert_eq!(inventory.existing_tasks, 7);
    assert_eq!(inventory.existing_file_descriptors, 9);
    assert_eq!(inventory.prospective_tasks, 1);
    assert_eq!(inventory.prospective_file_descriptors, 5);
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 1);
    operation.wait_slice().unwrap();
    drop(operation);
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
}

#[test]
fn negative_or_unknown_inventory_status_never_retries_as_record_pending() {
    for status in [-libc::EAGAIN, -libc::EBUSY, -libc::EIO, 2] {
        let controller = controller();
        let mut attempts = 0;
        let result = super::super::admission::export_owner_inventory(&controller, |_| {
            attempts += 1;
            status
        });

        assert_eq!(attempts, 1);
        assert!(matches!(result, Err(RamError::Native { status: actual, .. }) if actual == status));
        assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
        assert!(controller.state.lock().unwrap().inventory.is_none());
    }
}

#[test]
fn pending_record_cannot_publish_census_or_renew_expired_setup() {
    let controller = setup_controller();
    let mut attempts = 0;
    let result = super::super::admission::export_owner_inventory(&controller, |_| {
        attempts += 1;
        std::thread::sleep(Duration::from_millis(120));
        1
    });

    assert_eq!(attempts, 1);
    assert!(matches!(result, Err(RamError::Io(error)) if error.kind() == io::ErrorKind::TimedOut));
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
    assert!(controller.state.lock().unwrap().inventory.is_none());
}

#[test]
fn pending_inventory_with_output_or_success_without_census_refuses_publication() {
    for status in [0, 1] {
        let controller = controller();
        let mut attempts = 0;
        let result = super::super::admission::export_owner_inventory(&controller, |inventory| {
            attempts += 1;
            inventory.existing_tasks = 7;
            status
        });

        assert_eq!(attempts, 1);
        assert!(matches!(result, Err(RamError::Invariant(_))));
        assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
        assert!(controller.state.lock().unwrap().inventory.is_none());
    }
}
