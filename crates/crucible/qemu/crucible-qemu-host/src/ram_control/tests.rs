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
        performance: None,
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
        resident_observation: None,
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

pub(crate) fn response(frame: RamControlFrame) -> RamControlFrame {
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
fn pager_controller_budget_conversion_preserves_exact_nanoseconds() {
    let mut policy = HostRamPolicy {
        mode: HostRamMode::Managed,
        resident_target_bytes: 4096,
        eviction_preference: 80,
        writeback_bytes_per_second: 4096,
        maximum_paging_io_in_flight: 1,
        prefetch_on_increase: false,
        latency: HostOperationBudgets::default(),
    };
    for duration in [Duration::from_nanos(1), Duration::from_micros(500)] {
        policy.latency.classes[0] = HostOperationBudget {
            poll_interval: duration,
            progress_timeout: Some(duration),
            total_timeout: Some(duration),
        };
        let wire = policy_to_wire(policy).unwrap();
        let encoded = encode_ram_control_budgets(&wire.budgets).unwrap();
        let observed = decode_ram_control_budgets(&encoded).unwrap();

        assert_eq!(budgets_from_wire(observed).unwrap(), policy.latency);
        assert_eq!(policy_from_wire(wire).unwrap(), policy);
        assert_eq!(wire.budgets[0].poll_ns, duration.as_nanos() as u64);
    }
}

#[test]
fn policy_conversion_refuses_invalid_scalars_in_both_directions() {
    let valid = HostRamPolicy {
        mode: HostRamMode::Managed,
        resident_target_bytes: 4096,
        eviction_preference: 100,
        writeback_bytes_per_second: 1,
        maximum_paging_io_in_flight: 1,
        prefetch_on_increase: false,
        latency: HostOperationBudgets::default(),
    };
    let wire = policy_to_wire(valid).unwrap();

    for (preference, rate, slots) in [(101, 1, 1), (255, 1, 1), (100, 0, 1), (100, 1, 0)] {
        let host = HostRamPolicy {
            eviction_preference: preference,
            writeback_bytes_per_second: rate,
            maximum_paging_io_in_flight: slots,
            ..valid
        };
        let direct_wire = RamControlPolicy {
            eviction_preference: preference,
            writeback_bytes_per_second: rate,
            maximum_paging_io_in_flight: slots,
            ..wire
        };

        assert!(matches!(
            policy_to_wire(host),
            Err(RamControlError::InvalidFrame)
        ));
        assert!(matches!(
            policy_from_wire(direct_wire),
            Err(RamControlError::InvalidFrame)
        ));
    }

    assert_eq!(policy_from_wire(wire).unwrap(), valid);
}

#[test]
fn budget_conversion_refuses_zero_and_unrepresentable_values_in_both_directions() {
    for duration in [
        Duration::ZERO,
        Duration::from_nanos(RAM_CONTROL_MAX_ALLOWANCE_NS + 1),
        Duration::MAX,
    ] {
        let mut budgets = HostOperationBudgets::default();
        budgets.classes[0].total_timeout = Some(duration);
        assert!(budgets_to_wire(budgets).is_err());
    }
    for value in [0, RAM_CONTROL_MAX_ALLOWANCE_NS + 1, u64::MAX] {
        let mut budgets = budgets_to_wire(HostOperationBudgets::default()).unwrap();
        budgets[0].total_ns = Some(value);
        assert!(budgets_from_wire(budgets).is_err());
    }
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
    use crucible_host_resources::host_supervision::{HostOperationState, HostSupervisionError};

    let (host, mut worker) = UnixStream::pair().unwrap();
    let (ready, wait_ready) = std::sync::mpsc::sync_channel(1);
    let (release, wait_release) = std::sync::mpsc::channel();
    let pager = thread::spawn(move || {
        ready.send(()).unwrap();
        let request = read_ram_control(&mut worker);
        // Keep the endpoint alive until the controller has actually refused.
        // An original cap may expire before Hello, or between its frame writes.
        wait_release.recv().unwrap();
        request
    });
    wait_ready.recv().unwrap();
    let budgets = HostOperationBudgets::default();
    assert!(
        budgets.classes[HostOperationClass::Quantum as usize]
            .total_timeout
            .is_none()
    );
    assert!(
        budgets.classes[HostOperationClass::Quantum as usize]
            .progress_timeout
            .is_none()
    );
    let supervisor =
        HostOperationSupervisor::new(budgets, Some(Duration::from_millis(50))).unwrap();
    let original = supervisor.outer_cap_binding().unwrap();
    let started = supervision::TransportDeadline::after(Duration::from_secs(1)).unwrap();

    let result = RamControlClient::connect_supervised(host, [4; 32], target(), supervisor.clone());
    let bounded = started.remaining();
    let terminal = supervisor.outer_cap_binding().unwrap();
    release.send(()).unwrap();
    let request = pager.join().unwrap();

    assert!(
        result.is_err(),
        "controller unexpectedly completed: {result:?}"
    );
    assert!(
        bounded.is_ok(),
        "controller exceeded the original one-second bound: {bounded:?}"
    );
    let RamControlError::Io(failure) = result.unwrap_err() else {
        panic!("outer expiry must preserve a typed supervision I/O cause");
    };
    assert_eq!(failure.kind(), std::io::ErrorKind::TimedOut);
    let original_failure = failure
        .get_ref()
        .and_then(|source| source.downcast_ref::<HostSupervisionError>());
    assert!(
        matches!(
            original_failure,
            Some(HostSupervisionError::DeadlineExpired {
                class: HostOperationClass::Setup,
                ..
            }) | Some(HostSupervisionError::Terminal {
                state: HostOperationState::Expired
            })
        ),
        "unexpected original refusal: {failure:?}"
    );
    assert_eq!(terminal.cap_id, original.cap_id);
    assert_eq!(
        terminal.original_monotonic_ns,
        original.original_monotonic_ns
    );
    assert_eq!(terminal.revision, original.revision);
    assert_eq!(terminal.allowance, Some(Duration::from_millis(50)));
    assert_eq!(terminal.state, HostOperationState::Expired);

    match request {
        Ok(Some(frame)) => assert!(matches!(
            frame.message,
            RamControlMessage::Request(RamControlRequest::Hello)
        )),
        // These closures are valid only beside the proven unchanged cap expiry
        // above. The peer never manufactures an admitted request or a reply.
        Ok(None) => {}
        Err(RamControlError::Io(first)) if first.kind() == std::io::ErrorKind::UnexpectedEof => {}
        unexpected => panic!("unexpected peer frame outcome: {unexpected:?}"),
    }
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
        rust_metadata_required_bytes: 8192,
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
    let exact_metadata = report.native_metadata_bytes + report.rust_metadata_required_bytes;
    let undersized = HostResourceVector {
        metadata_bytes: exact_metadata - 1,
        ..HostResourceVector::default()
    };
    assert!(matches!(
        client.grant_inventory(&inventory, undersized, 8192),
        Err(RamControlError::AuthorityMismatch)
    ));
    let exact = HostResourceVector {
        metadata_bytes: exact_metadata + 1,
        ..undersized
    };
    let mut changed = inventory.clone();
    changed.report.rust_metadata_required_bytes += 1;
    assert!(matches!(
        client.grant_inventory(&changed, exact, 8192),
        Err(RamControlError::AuthorityMismatch)
    ));
    changed = inventory.clone();
    changed.report.topology_generation += 1;
    assert!(matches!(
        client.grant_inventory(&changed, exact, 8192),
        Err(RamControlError::AuthorityMismatch)
    ));
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

#[test]
fn performance_exchange_borrows_original_guard_and_authenticates_report() {
    let (host, mut worker) = UnixStream::pair().unwrap();
    let pager = thread::spawn(move || {
        let hello = read_ram_control(&mut worker).unwrap().unwrap();
        write_ram_control(&mut worker, &response(hello)).unwrap();
        let request = read_ram_control(&mut worker).unwrap().unwrap();
        assert!(matches!(
            request.message,
            RamControlMessage::Request(RamControlRequest::Performance {
                action: RamControlPerformanceAction::Start
            })
        ));
        let mut reply = response(request);
        if let RamControlMessage::Reply { state, .. } = &mut reply.message {
            state.performance = Some(RamControlPerformance {
                generation: 1,
                active: true,
                complete: true,
                pending_operations: 0,
                io: [RamControlIoMeasurement::default(); RAM_PERFORMANCE_IO_CLASSES],
            });
        }
        write_ram_control(&mut worker, &reply).unwrap();
    });
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let mut client =
        RamControlClient::connect_supervised(host, [4; 32], target(), supervisor.clone()).unwrap();
    let guard = supervisor.begin_control(HostOperationClass::Setup).unwrap();
    let before = supervisor.operation_statuses().unwrap();
    let reply = client
        .performance_under(RamControlPerformanceAction::Start, &guard)
        .unwrap();
    assert!(reply.performance.unwrap().active);
    let after = supervisor.operation_statuses().unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].operation_id, before[0].operation_id);
    assert_eq!(
        after[0].started_policy_revision,
        before[0].started_policy_revision
    );
    guard.complete().unwrap();
    pager.join().unwrap();
}

#[test]
fn cancellation_borrows_one_same_original_cleanup_and_refuses_foreign_or_stale_inputs() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let foreign = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let (host, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let server = thread::spawn(move || {
        let hello = read_ram_control(&mut peer).unwrap().unwrap();
        write_ram_control(&mut peer, &response(hello)).unwrap();
        let frame = read_ram_control(&mut peer).unwrap().unwrap();
        assert!(matches!(
            frame.message,
            RamControlMessage::Request(RamControlRequest::Cancel {
                operation_generation: 1
            })
        ));
        assert_eq!(frame.sequence, 2);
        let mut reply = response(frame);
        let RamControlMessage::Reply { state, .. } = &mut reply.message else {
            panic!("reply");
        };
        state.disposition = RamControlDisposition::Canceled;
        write_ram_control(&mut peer, &reply).unwrap();
    });
    let mut client =
        RamControlClient::connect_supervised(host, [4; 32], target(), supervisor.clone()).unwrap();
    let foreign_cleanup = foreign.begin_control(HostOperationClass::Cleanup).unwrap();
    assert!(client.cancel_under(1, &foreign_cleanup).is_err());
    let cleanup = supervisor
        .begin_control(HostOperationClass::Cleanup)
        .unwrap();
    assert!(client.cancel_under(2, &cleanup).is_err());
    supervisor.cancel().unwrap();

    let receipt = client.cancel_under(1, &cleanup).unwrap();

    assert_eq!(receipt.disposition, RamControlDisposition::Canceled);
    cleanup.complete().unwrap();
    server.join().unwrap();
}
