//! Checks live operational allowances without constructing guest mapping authority.

use super::*;

mod admission;

extern "C" fn unused_worker(_: u32, _: u64, _: u64, _: u32) -> c_int {
    -libc::ENOSYS
}
extern "C" fn unused_grant(_: u64, _: u64, _: *mut u64) -> c_int {
    -libc::ENOSYS
}

extern "C" fn runtime_not_ready() -> c_int {
    0
}

fn controller() -> LivePagerController {
    LivePagerController {
        target: RamControlTarget {
            daemon_epoch: [1; 32],
            owner_id: [2; 32],
            node_id: [3; 32],
            owner_generation: 1,
            arena_generation: 1,
            retained_template: false,
        },
        session: [4; 32],
        fault_actor_test_entitlement: None,
        state: Arc::new(Mutex::new(State {
            resources: RamControlResources::default(),
            budgets: [RamControlBudget {
                poll_ms: 10,
                progress_ms: None,
                total_ms: Some(30_000),
            }; RAM_CONTROL_BUDGET_COUNT],
            outer: None,
            outer_expired: false,
            aliases: [None; 3],
            inventory: None,
            owner: None,
            requested_revision: 0,
            applied_revision: 0,
            reservation_revision: 0,
            observation_sequence: 0,
            policy: None,
            failed: false,
            fork_preparing: false,
            policy_applying: false,
            child_bootstrap: false,
        })),
        canceled: Arc::new(AtomicBool::new(false)),
        operations: Arc::new(AtomicUsize::new(0)),
        native_worker: unused_worker,
        native_grant: unused_grant,
        child_runtime_ready: runtime_not_ready,
        spill: Mutex::new(None),
        spill_quota: 0,
        worker: Mutex::new(None),
        paused: Mutex::new(None),
        joining: Mutex::new(None),
    }
}

// This component fixture records a completed Apply without creating guest
// mapping authority or advertising any backend qualification.
fn applied_controller() -> (LivePagerController, RamControlPolicy, RamControlResources) {
    let controller = controller();
    let resources = RamControlResources {
        resident_peak_bytes: 1024 * 1024,
        backing_peak_bytes: 1024 * 1024,
        metadata_bytes: 256 * 1024,
        staging_bytes: 256 * 1024,
        paging_io_slots: 1,
        cpu_slots: 1,
        task_slots: 2,
        file_descriptors: 4,
    };
    let mut state = controller
        .state
        .lock()
        .unwrap_or_else(|error| panic!("record applied component state: {error}"));
    let policy = RamControlPolicy {
        mode: RamControlMode::Managed,
        resident_target_bytes: 4096,
        eviction_preference: 80,
        writeback_bytes_per_second: 4096,
        maximum_paging_io_in_flight: 1,
        prefetch_on_increase: false,
        budgets: state.budgets,
    };
    state.resources = resources;
    state.policy = Some(policy);
    state.requested_revision = 1;
    state.applied_revision = 1;
    state.reservation_revision = 0;
    drop(state);
    (controller, policy, resources)
}

#[test]
fn exact_applied_retry_returns_portable_observation_without_new_work() {
    let (controller, policy, resources) = applied_controller();
    let cap = RamControlOuterCap {
        cap_id: [8; 32],
        revision: 0,
        original_monotonic_ns: super::super::supervision::monotonic_ns()
            .unwrap_or_else(|error| panic!("capture original cap: {error}")),
        allowance_ns: Some(30_000_000_000),
        state: RamControlOuterState::Running,
    };
    controller
        .state
        .lock()
        .unwrap_or_else(|error| panic!("install original cap: {error}"))
        .outer = Some(cap);
    let operation = controller
        .begin(SourceOperationClass::Quiescence)
        .unwrap_or_else(|error| panic!("begin existing work: {error}"));
    operation
        .progress(7)
        .unwrap_or_else(|error| panic!("record existing completed work: {error}"));

    let reply = controller.apply(0, 1, 0, policy, resources);
    assert_eq!(reply.disposition, RamControlDisposition::Accepted);
    assert_eq!(reply.requested_policy_revision, 1);
    assert_eq!(reply.applied_policy_revision, 1);
    assert_eq!(reply.reservation_revision, 0);
    assert_eq!(reply.observation_sequence, 1);
    assert_eq!(controller.operations.load(Ordering::Acquire), 1);
    assert_eq!(reply.kernel_probe, None);
    assert_eq!(reply.activity, None);
    assert_eq!(
        operation
            .progress(7)
            .err()
            .unwrap_or_else(|| panic!("retry reset completed work"))
            .kind(),
        io::ErrorKind::InvalidInput
    );
    let state = controller
        .state
        .lock()
        .unwrap_or_else(|error| panic!("observe replayed state: {error}"));
    assert_eq!(state.outer, Some(cap));
    assert_eq!(state.budgets, policy.budgets);
    assert_eq!(state.policy, Some(policy));
    assert!(!state.policy_applying);
    drop(state);

    let request = RamControlFrame {
        session: controller.session,
        sequence: 2,
        target: controller.target,
        message: RamControlMessage::Request(RamControlRequest::Apply {
            expected_revision: 0,
            policy_revision: 1,
            reservation_revision: 0,
            resources,
            policy,
        }),
    };
    let frame = RamControlFrame {
        message: RamControlMessage::Reply {
            request_digest: ram_control_request_digest(&request)
                .unwrap_or_else(|error| panic!("bind exact retry digest: {error}")),
            state: reply,
        },
        ..request
    };
    let encoded = encode_ram_control(&frame)
        .unwrap_or_else(|error| panic!("encode applied observation: {error}"));
    assert_eq!(
        decode_ram_control(&encoded)
            .unwrap_or_else(|error| panic!("decode applied observation: {error}")),
        frame
    );
    operation
        .complete()
        .unwrap_or_else(|error| panic!("complete original work: {error}"));
}

#[test]
fn applied_retry_refuses_changed_tuple_and_revision_relation() {
    let (controller, policy, resources) = applied_controller();
    for changed_policy in [
        RamControlPolicy {
            resident_target_bytes: 8192,
            ..policy
        },
        RamControlPolicy {
            mode: RamControlMode::DiskOriented,
            ..policy
        },
        RamControlPolicy {
            eviction_preference: 79,
            ..policy
        },
        RamControlPolicy {
            writeback_bytes_per_second: 8192,
            ..policy
        },
        RamControlPolicy {
            maximum_paging_io_in_flight: 2,
            ..policy
        },
        RamControlPolicy {
            prefetch_on_increase: true,
            ..policy
        },
        RamControlPolicy {
            budgets: [RamControlBudget {
                poll_ms: 20,
                ..policy.budgets[0]
            }; RAM_CONTROL_BUDGET_COUNT],
            ..policy
        },
    ] {
        assert_eq!(
            controller
                .apply(0, 1, 0, changed_policy, resources)
                .disposition,
            RamControlDisposition::RevisionConflict
        );
    }
    for changed_resources in [
        RamControlResources {
            resident_peak_bytes: resources.resident_peak_bytes + 1,
            ..resources
        },
        RamControlResources {
            backing_peak_bytes: resources.backing_peak_bytes + 1,
            ..resources
        },
        RamControlResources {
            metadata_bytes: resources.metadata_bytes + 1,
            ..resources
        },
        RamControlResources {
            staging_bytes: resources.staging_bytes + 1,
            ..resources
        },
        RamControlResources {
            paging_io_slots: 2,
            ..resources
        },
        RamControlResources {
            cpu_slots: 2,
            ..resources
        },
        RamControlResources {
            task_slots: 3,
            ..resources
        },
        RamControlResources {
            file_descriptors: 5,
            ..resources
        },
    ] {
        assert_eq!(
            controller
                .apply(0, 1, 0, policy, changed_resources)
                .disposition,
            RamControlDisposition::RevisionConflict
        );
    }
    for (expected, revision, reservation) in [(0, 1, 1), (1, 1, 0), (0, 2, 0), (u64::MAX, 1, 0)] {
        assert_eq!(
            controller
                .apply(expected, revision, reservation, policy, resources)
                .disposition,
            RamControlDisposition::RevisionConflict
        );
    }
    let state = controller
        .state
        .lock()
        .unwrap_or_else(|error| panic!("observe refused retry: {error}"));
    assert_eq!(
        (
            state.requested_revision,
            state.applied_revision,
            state.reservation_revision
        ),
        (1, 1, 0)
    );
    assert_eq!(state.resources, resources);
    assert_eq!(state.policy, Some(policy));
    assert_eq!(state.budgets, policy.budgets);
    assert!(!state.policy_applying);
    assert_eq!(controller.operations.load(Ordering::Acquire), 0);
}

#[test]
fn exact_retry_from_another_controller_lineage_never_dispatches() {
    let (controller, policy, resources) = applied_controller();
    let changed_target = RamControlTarget {
        owner_generation: controller.target.owner_generation + 1,
        ..controller.target
    };
    for (session, target) in [
        ([5; 32], controller.target),
        (controller.session, changed_target),
    ] {
        let request = RamControlFrame {
            session,
            sequence: 2,
            target,
            message: RamControlMessage::Request(RamControlRequest::Apply {
                expected_revision: 0,
                policy_revision: 1,
                reservation_revision: 0,
                resources,
                policy,
            }),
        };
        let body = encode_ram_control(&request)
            .unwrap_or_else(|error| panic!("encode foreign retry: {error}"));
        let length = u32::try_from(body.len())
            .unwrap_or_else(|error| panic!("bound foreign retry length: {error}"));
        let mut record = length.to_be_bytes().to_vec();
        record.extend_from_slice(&body);
        let mut stream = std::io::Cursor::new(record);
        let mut sequence = 1;
        let mut dispatched = false;
        let result = serve_ram_control_once(
            &mut stream,
            controller.session,
            controller.target,
            &mut sequence,
            &mut |_| {
                dispatched = true;
                controller.apply(0, 1, 0, policy, resources)
            },
        );
        assert!(matches!(result, Err(RamControlError::AuthorityMismatch)));
        assert!(!dispatched);
        assert_eq!(sequence, 1);
    }
    assert_eq!(controller.operations.load(Ordering::Acquire), 0);
}

#[test]
fn exact_retry_cannot_bypass_failed_canceled_or_closed_admission() {
    for guard in 0..5 {
        let (controller, policy, resources) = applied_controller();
        let mut state = controller
            .state
            .lock()
            .unwrap_or_else(|error| panic!("close retry admission: {error}"));
        match guard {
            0 => state.failed = true,
            1 => controller.canceled.store(true, Ordering::Release),
            2 => state.fork_preparing = true,
            3 => state.policy_applying = true,
            _ => {
                state.outer = Some(RamControlOuterCap {
                    cap_id: [8; 32],
                    revision: 0,
                    original_monotonic_ns: 1,
                    allowance_ns: Some(1),
                    state: RamControlOuterState::Running,
                })
            }
        }
        drop(state);
        let reply = controller.apply(0, 1, 0, policy, resources);
        assert_eq!(
            reply.disposition,
            if guard < 2 || guard == 4 {
                RamControlDisposition::AdmissionRefused
            } else {
                RamControlDisposition::Unavailable
            }
        );
        assert_eq!(controller.operations.load(Ordering::Acquire), 0);
    }
}

#[test]
fn failed_authority_keeps_finite_control_cleanup_without_reviving_guest_work() {
    let controller = controller();
    let work = controller
        .begin(SourceOperationClass::PageIn)
        .unwrap_or_else(|error| panic!("begin original guest work: {error}"));

    controller.mark_failed();
    assert!(work.wait_slice().is_err());
    assert!(controller.begin(SourceOperationClass::PageIn).is_err());

    let cleanup = controller
        .begin(SourceOperationClass::Cleanup)
        .unwrap_or_else(|error| panic!("begin bounded failure cleanup: {error}"));
    assert!(cleanup.wait_slice().is_ok());
    cleanup
        .complete()
        .unwrap_or_else(|error| panic!("complete bounded failure cleanup: {error}"));
    assert!(work.complete().is_err());
}

#[test]
fn live_budget_reduction_expires_original_start_and_later_extension_cannot_revive_it() {
    let controller = controller();
    let operation = controller.begin(SourceOperationClass::PageIn).unwrap();
    std::thread::sleep(Duration::from_millis(25));

    controller.state.lock().unwrap().budgets[2].total_ms = Some(1);
    assert_eq!(
        operation.wait_slice().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    controller.state.lock().unwrap().budgets[2].total_ms = Some(30_000);
    assert_eq!(
        operation.complete().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    drop(operation);
    assert_eq!(controller.operations.load(Ordering::Acquire), 0);
}

#[test]
fn meaningful_work_progress_is_monotonic_and_cannot_renew_total_authority() {
    let controller = controller();
    let operation = controller
        .begin(SourceOperationClass::Quiescence)
        .unwrap_or_else(|error| panic!("begin original work: {error}"));
    operation
        .progress(1)
        .unwrap_or_else(|error| panic!("record completed work: {error}"));
    for repeated in [0, 1] {
        assert_eq!(
            operation
                .progress(repeated)
                .err()
                .unwrap_or_else(|| panic!("nonmonotonic work accepted"))
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    std::thread::sleep(Duration::from_millis(5));
    controller
        .state
        .lock()
        .unwrap_or_else(|error| panic!("amend live budget: {error}"))
        .budgets[6]
        .total_ms = Some(1);
    assert_eq!(
        operation
            .progress(2)
            .err()
            .unwrap_or_else(|| panic!("expired original total renewed"))
            .kind(),
        io::ErrorKind::TimedOut
    );
    controller
        .state
        .lock()
        .unwrap_or_else(|error| panic!("extend live budget: {error}"))
        .budgets[6]
        .total_ms = Some(30_000);
    assert_eq!(
        operation
            .progress(3)
            .err()
            .unwrap_or_else(|| panic!("expired operation revived"))
            .kind(),
        io::ErrorKind::TimedOut
    );
}

#[test]
fn completed_work_renews_progress_without_moving_the_original_start() {
    let controller = controller();
    controller
        .state
        .lock()
        .unwrap_or_else(|error| panic!("configure progress budget: {error}"))
        .budgets[6]
        .progress_ms = Some(500);
    let operation = controller
        .begin(SourceOperationClass::Quiescence)
        .unwrap_or_else(|error| panic!("begin original work: {error}"));
    std::thread::sleep(Duration::from_millis(150));
    operation
        .progress(1)
        .unwrap_or_else(|error| panic!("record completed work: {error}"));
    std::thread::sleep(Duration::from_millis(375));
    assert!(operation.wait_slice().is_ok());
    operation
        .complete()
        .unwrap_or_else(|error| panic!("complete authenticated work: {error}"));
    assert!(operation.progress(2).is_err());
}

#[test]
fn cancellation_stops_page_tokens_and_keeps_independent_cleanup_available() {
    let controller = controller();
    let page = controller.begin(SourceOperationClass::PageIn).unwrap();
    let cleanup = controller.begin(SourceOperationClass::Cleanup).unwrap();
    assert_eq!(
        controller.cancel(2).disposition,
        RamControlDisposition::NotCurrent
    );
    assert!(page.wait_slice().is_ok());

    assert_eq!(
        controller.cancel(1).disposition,
        RamControlDisposition::Canceled
    );
    assert_eq!(
        page.complete().unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    cleanup.complete().unwrap();
    assert!(cleanup.complete().is_err());
}

#[test]
fn unlimited_class_uses_shared_original_outer_and_expiry_cannot_revive() {
    let controller = controller();
    let cap = RamControlOuterCap {
        cap_id: [8; 32],
        revision: 0,
        original_monotonic_ns: super::super::supervision::monotonic_ns().unwrap(),
        allowance_ns: Some(1_000_000_000),
        state: RamControlOuterState::Running,
    };
    {
        let mut state = controller.state.lock().unwrap();
        state.outer = Some(cap);
        state.budgets[2].total_ms = None;
    }
    let page = controller.begin(SourceOperationClass::PageIn).unwrap();
    std::thread::sleep(Duration::from_millis(10));

    let shortened = RamControlOuterCap {
        revision: 1,
        allowance_ns: Some(1),
        ..cap
    };
    assert_eq!(
        controller.sync_outer_cap(shortened).disposition,
        RamControlDisposition::Accepted
    );
    assert_eq!(page.complete().unwrap_err().kind(), io::ErrorKind::TimedOut);
    let extended = RamControlOuterCap {
        revision: 2,
        allowance_ns: Some(30_000_000_000),
        ..cap
    };
    assert_eq!(
        controller.sync_outer_cap(extended).disposition,
        RamControlDisposition::AdmissionRefused
    );
    controller
        .begin(SourceOperationClass::Cleanup)
        .unwrap()
        .complete()
        .unwrap();
}

#[test]
fn cap_amendment_preserves_identity_anchor_and_exact_revision() {
    let controller = controller();
    let cap = RamControlOuterCap {
        cap_id: [8; 32],
        revision: 0,
        original_monotonic_ns: super::super::supervision::monotonic_ns().unwrap(),
        allowance_ns: Some(30_000_000_000),
        state: RamControlOuterState::Running,
    };
    controller.state.lock().unwrap().outer = Some(cap);

    for changed in [
        RamControlOuterCap {
            cap_id: [9; 32],
            revision: 1,
            ..cap
        },
        RamControlOuterCap {
            original_monotonic_ns: cap.original_monotonic_ns + 1,
            revision: 1,
            ..cap
        },
        RamControlOuterCap { revision: 2, ..cap },
    ] {
        assert_eq!(
            controller.sync_outer_cap(changed).disposition,
            RamControlDisposition::NotCurrent
        );
    }
    assert_eq!(
        controller.sync_outer_cap(cap).disposition,
        RamControlDisposition::Accepted
    );
    let extended = RamControlOuterCap {
        revision: 1,
        allowance_ns: Some(60_000_000_000),
        ..cap
    };
    assert_eq!(
        controller.sync_outer_cap(extended).disposition,
        RamControlDisposition::Accepted
    );
    assert_eq!(controller.state.lock().unwrap().outer, Some(extended));
}

#[test]
fn cleanup_keeps_finite_allowance_even_when_outer_supplies_other_infrastructure() {
    let mut budgets = [RamControlBudget {
        poll_ms: 10,
        progress_ms: None,
        total_ms: None,
    }; RAM_CONTROL_BUDGET_COUNT];
    let cap = RamControlOuterCap {
        cap_id: [8; 32],
        revision: 0,
        original_monotonic_ns: 1,
        allowance_ns: Some(30_000_000_000),
        state: RamControlOuterState::Running,
    };
    assert!(validate_infrastructure(&budgets, Some(cap)).is_err());
    budgets[13].total_ms = Some(1000);
    assert!(validate_infrastructure(&budgets, Some(cap)).is_ok());
    assert!(
        validate_infrastructure(
            &budgets,
            Some(RamControlOuterCap {
                allowance_ns: None,
                ..cap
            })
        )
        .is_err()
    );
}

#[test]
fn fault_actor_exit_without_startup_entitlement_has_no_effect() {
    let controller = controller();
    let before = {
        let state = controller
            .state
            .lock()
            .unwrap_or_else(|_| panic!("controller state"));
        (
            state.requested_revision,
            state.applied_revision,
            state.reservation_revision,
            state.failed,
        )
    };
    let refusal = controller.test_fault_actor([7; 32], 1, RamControlFaultActorAction::RequestExit);
    assert_eq!(refusal.disposition, RamControlDisposition::Unsupported);
    assert!(refusal.fault_actor.is_none());
    let state = controller
        .state
        .lock()
        .unwrap_or_else(|_| panic!("controller state"));
    assert_eq!(
        (
            state.requested_revision,
            state.applied_revision,
            state.reservation_revision,
            state.failed
        ),
        before
    );
    assert!(!controller.canceled.load(Ordering::Acquire));
}

#[test]
fn early_child_accepts_only_recorded_initial_retry_before_native_runtime_ready() {
    let (controller, policy, resources) = applied_controller();
    controller
        .state
        .lock()
        .unwrap_or_else(|_| panic!("controller state"))
        .child_bootstrap = true;

    let retry = controller.apply(0, 1, 0, policy, resources);
    assert_eq!(retry.disposition, RamControlDisposition::Accepted);
    let update = controller.apply(1, 2, 0, policy, resources);
    assert_eq!(update.disposition, RamControlDisposition::Unavailable);

    let state = controller
        .state
        .lock()
        .unwrap_or_else(|_| panic!("controller state"));
    assert!(state.child_bootstrap);
    assert_eq!(state.requested_revision, 1);
    assert_eq!(state.applied_revision, 1);
    assert_eq!(state.policy, Some(policy));
    assert_eq!(state.resources, resources);
    assert_eq!(controller.operations.load(Ordering::Acquire), 0);
}
