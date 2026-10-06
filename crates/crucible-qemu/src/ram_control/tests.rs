//! Host controller response authentication and finite total exchange deadlines.

// crucible-lint: allow panic-shortcut -- bounded protocol fixtures panic to localize invalid setup or responses.
#![allow(
    clippy::unwrap_used,
    reason = "Protocol fixtures panic on unexpected setup or response failures."
)]

use super::*;
use std::io::Write;
use std::thread;

fn target() -> HostRamTarget {
    HostRamTarget {
        daemon_epoch: [1; 32],
        owner_id: [2; 32],
        node_id: [3; 32],
        owner_generation: 1,
        arena_generation: 1,
        retained_template: false,
    }
}

fn state() -> RamControlReply {
    RamControlReply {
        placement_receipt: None,
        operation_failure: None,
        fault_actor: None,
        kernel_probe: None,
        activity: None,
        disposition: RamControlDisposition::Accepted,
        logical_ram_bytes: 8192,
        inventory: None,
        inventory_region: None,
        limitation_reasons: RAM_LIMIT_COMPULSORY_FLOOR,
        measurements_available: true,
        requested_policy_revision: 1,
        applied_policy_revision: 1,
        reservation_revision: 1,
        observation_sequence: 1,
        effective_resident_target_bytes: 4096,
        effective_floor_bytes: 8192,
        private_resident_bytes: 4096,
        shared_resident_bytes_observed: 0,
        preserved_backing_bytes: 4096,
        private_dirty_bytes: 0,
        writeback_pending_bytes: 0,
        convergence: RamControlConvergence::Stable,
    }
}

fn response(frame: RamControlFrame) -> RamControlFrame {
    RamControlFrame {
        message: RamControlMessage::Reply {
            request_digest: ram_control_request_digest(&frame).unwrap(),
            state: state(),
        },
        ..frame
    }
}

#[test]
fn pager_controller_authenticates_reply_and_poisoned_session_cannot_retry() {
    let (host, mut worker) = UnixStream::pair().unwrap();
    let pager = thread::spawn(move || {
        let hello = read_ram_control(&mut worker).unwrap().unwrap();
        write_ram_control(&mut worker, &response(hello)).unwrap();
        let status = read_ram_control(&mut worker).unwrap().unwrap();
        let mut wrong = response(status);
        wrong.target.arena_generation += 1;
        write_ram_control(&mut worker, &wrong).unwrap();
    });
    let mut client =
        RamControlClient::connect(host, [4; 32], target(), Duration::from_secs(1)).unwrap();
    assert!(matches!(
        client.status(),
        Err(RamControlError::AuthorityMismatch)
    ));
    assert!(matches!(
        client.status(),
        Err(RamControlError::AuthorityMismatch)
    ));
    pager.join().unwrap();
}

#[test]
fn pager_controller_total_deadline_cannot_be_extended_by_trickle_reads() {
    let (host, mut worker) = UnixStream::pair().unwrap();
    let pager = thread::spawn(move || {
        let hello = read_ram_control(&mut worker).unwrap().unwrap();
        let mut encoded = Vec::new();
        write_ram_control(&mut encoded, &response(hello)).unwrap();
        for byte in encoded {
            if worker.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(15));
        }
    });
    let started = supervision::TransportDeadline::after(Duration::from_secs(1)).unwrap();
    assert!(RamControlClient::connect(host, [4; 32], target(), Duration::from_millis(50)).is_err());
    assert!(started.remaining().is_ok());
    pager.join().unwrap();
}

#[test]
fn pager_controller_budget_conversion_is_exact_and_rejects_rounding() {
    let policy = HostRamPolicy {
        mode: HostRamMode::Managed,
        resident_target_bytes: 4096,
        eviction_preference: 80,
        writeback_bytes_per_second: 4096,
        maximum_paging_io_in_flight: 1,
        prefetch_on_increase: false,
        latency: HostOperationBudgets::default(),
    };
    assert_eq!(policy_from_wire(policy_to_wire(policy).unwrap()), policy);
    let mut fractional = policy;
    fractional.latency.classes[0].poll_interval = Duration::from_nanos(1_500_000);
    assert!(policy_to_wire(fractional).is_err());
}

#[test]
fn supervised_pager_controller_retains_partial_frame_across_poll_expiration() {
    let (host, mut worker) = UnixStream::pair().unwrap();
    let pager = thread::spawn(move || {
        let hello = read_ram_control(&mut worker).unwrap().unwrap();
        let mut encoded = Vec::new();
        write_ram_control(&mut encoded, &response(hello)).unwrap();

        // Both the prefix and body span multiple host polling slices.
        for chunk in encoded.chunks(2) {
            worker.write_all(chunk).unwrap();
            thread::sleep(Duration::from_millis(12));
        }
    });
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let client = RamControlClient::connect_supervised(host, [4; 32], target(), supervisor.clone());
    assert!(client.is_ok());
    pager.join().unwrap();
}

#[test]
fn supervised_pager_controller_applies_new_setup_budget_during_stalled_reply() {
    let (host, mut worker) = UnixStream::pair().unwrap();
    let (admitted, request_admitted) = std::sync::mpsc::channel();
    let (release, wait_release) = std::sync::mpsc::channel();
    let pager = thread::spawn(move || {
        let hello = read_ram_control(&mut worker).unwrap().unwrap();
        let mut encoded = Vec::new();
        write_ram_control(&mut encoded, &response(hello)).unwrap();
        worker.write_all(&encoded[..2]).unwrap();
        admitted.send(()).unwrap();
        wait_release.recv().unwrap();
    });
    let mut budgets = HostOperationBudgets::default();
    budgets.classes[HostOperationClass::Setup as usize].poll_interval = Duration::from_secs(10);
    let supervisor = HostOperationSupervisor::new(budgets, None).unwrap();
    let live = supervisor.clone();
    let controller =
        thread::spawn(move || RamControlClient::connect_supervised(host, [4; 32], target(), live));
    request_admitted.recv().unwrap();
    let operations = supervisor.operation_statuses().unwrap();
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0].class, HostOperationClass::Setup);
    assert_eq!(operations[0].started_policy_revision, 0);

    let amended = supervision::TransportDeadline::after(Duration::from_secs(1)).unwrap();
    budgets.classes[HostOperationClass::Setup as usize].total_timeout =
        Some(Duration::from_millis(50));
    supervisor.update_budgets(0, budgets).unwrap();
    assert!(controller.join().unwrap().is_err());
    assert!(amended.remaining().is_ok());
    assert_eq!(supervisor.budgets().unwrap().0, 1);
    release.send(()).unwrap();
    pager.join().unwrap();
}

#[test]
fn supervised_pager_controller_outer_cap_is_independent_of_unlimited_quantum() {
    let (host, mut worker) = UnixStream::pair().unwrap();
    let (release, wait_release) = std::sync::mpsc::channel();
    let pager = thread::spawn(move || {
        read_ram_control(&mut worker).unwrap().unwrap();
        wait_release.recv().unwrap();
    });
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_millis(50)),
    )
    .unwrap();
    let started = supervision::TransportDeadline::after(Duration::from_secs(1)).unwrap();
    assert!(RamControlClient::connect_supervised(host, [4; 32], target(), supervisor).is_err());
    assert!(started.remaining().is_ok());
    release.send(()).unwrap();
    pager.join().unwrap();
}

#[test]
fn native_inventory_grant_retains_the_original_setup_guard() {
    let (host, mut worker) = UnixStream::pair().unwrap();
    let (release, wait_release) = std::sync::mpsc::channel();
    let report = RamControlInventoryReport {
        topology_generation: 1,
        logical_bytes: 4096,
        region_count: 1,
        native_metadata_bytes: 4096,
        native_scratch_bytes: 4096,
        owner_resources: RamControlOwnerInventory {
            existing_tasks: 1,
            existing_file_descriptors: 1,
            registered_service_tasks: 1,
            prospective_tasks: 1,
            prospective_file_descriptors: 4,
        },
        granted: false,
    };
    let pager = thread::spawn(move || {
        for index in 0..3 {
            let request = read_ram_control(&mut worker).unwrap().unwrap();
            let mut reply = response(request);
            if let RamControlMessage::Reply { state, .. } = &mut reply.message {
                state.logical_ram_bytes = report.logical_bytes;
                if index > 0 {
                    state.inventory = Some(report);
                }
                if index == 2 {
                    state.inventory_region =
                        Some(RamControlInventoryRegion::new(0, 4096, 1, "ram").unwrap());
                }
            }
            write_ram_control(&mut worker, &reply).unwrap();
        }
        wait_release.recv().unwrap();
        worker
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        assert!(read_ram_control(&mut worker).is_err());
    });
    let mut budgets = HostOperationBudgets::default();
    let supervisor = HostOperationSupervisor::new(budgets, None).unwrap();
    let mut client =
        RamControlClient::connect_supervised(host, [4; 32], target(), supervisor.clone()).unwrap();
    let inventory = client.inventory().unwrap();
    let original = supervisor.operation_statuses().unwrap();
    assert_eq!(original.len(), 1);
    assert_eq!(original[0].class, HostOperationClass::Setup);

    // Shortening the live class below its original elapsed time must refuse
    // the grant before sending another frame, rather than begin a new clock.
    thread::sleep(Duration::from_millis(5));
    budgets.classes[HostOperationClass::Setup as usize].total_timeout =
        Some(Duration::from_millis(1));
    supervisor.update_budgets(0, budgets).unwrap();
    let resources = HostResourceVector {
        resident_peak_bytes: 64 * 1024 * 1024,
        backing_peak_bytes: 64 * 1024 * 1024,
        metadata_bytes: 1024 * 1024,
        staging_bytes: 1024 * 1024,
        paging_io_slots: 1,
        cpu_slots: 1,
        task_slots: 64,
        file_descriptors: 128,
    };
    assert!(client.grant_inventory(&inventory, resources, 8192).is_err());
    release.send(()).unwrap();
    pager.join().unwrap();
}

#[test]
fn independent_setup_keeps_control_admission_when_work_records_are_full() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)
        .unwrap_or_else(|error| panic!("construct live owner: {error}"));
    let mut work = Vec::new();
    for _ in 0..10 {
        work.push(
            supervisor
                .begin_work(HostOperationClass::PageIn, 1)
                .unwrap_or_else(|error| panic!("admit bounded work: {error}")),
        );
    }
    assert!(
        supervisor
            .begin_work(HostOperationClass::PageIn, 1)
            .is_err()
    );
    let (host, mut worker) =
        UnixStream::pair().unwrap_or_else(|error| panic!("create independent channel: {error}"));
    let pager = thread::spawn(move || {
        let hello = read_ram_control(&mut worker)
            .unwrap_or_else(|error| panic!("receive setup: {error}"))
            .unwrap_or_else(|| panic!("setup channel closed"));
        write_ram_control(&mut worker, &response(hello))
            .unwrap_or_else(|error| panic!("send setup receipt: {error}"));
    });
    assert!(RamControlClient::connect_supervised(host, [4; 32], target(), supervisor).is_ok());
    pager
        .join()
        .unwrap_or_else(|_| panic!("independent pager panicked"));
    drop(work);
}
