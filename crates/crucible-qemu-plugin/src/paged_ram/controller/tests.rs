//! Checks live operational allowances without constructing guest mapping authority.

use super::*;

mod admission;
mod observation;

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

#[test]
fn fingerprint_loan_retains_live_slot_until_return_and_callback_unwind() {
    let controller = controller();
    let mut calls = 0;
    controller
        .with_fingerprint_operation(&mut |operation| {
            calls += 1;
            assert_eq!(controller.operations.load(Ordering::Acquire), 1);
            assert!(operation.wait_slice_for_observation().is_ok());
            assert!(operation.complete_observation().is_ok());
            assert!(operation.complete_observation().is_err());
            assert_eq!(controller.operations.load(Ordering::Acquire), 1);
        })
        .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(controller.operations.load(Ordering::Acquire), 0);

    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = controller.with_fingerprint_operation(&mut |_| {
            assert_eq!(controller.operations.load(Ordering::Acquire), 1);
            panic!("callback unwind control");
        });
    }));
    assert!(unwind.is_err());
    assert_eq!(controller.operations.load(Ordering::Acquire), 0);
}

#[test]
fn fingerprint_loan_refuses_before_callback_and_keeps_original_terminal_cause() {
    let controller = controller();
    controller.canceled.store(true, Ordering::Release);
    let mut calls = 0;
    let error = controller
        .with_fingerprint_operation(&mut |_| calls += 1)
        .unwrap_err();
    assert!(matches!(
        error,
        ObservationOperationError::Static {
            kind: io::ErrorKind::Interrupted,
            message: "RAM operation canceled",
        }
    ));
    assert_eq!(calls, 0);
    assert_eq!(controller.operations.load(Ordering::Acquire), 0);

    controller.canceled.store(false, Ordering::Release);
    controller
        .operations
        .store(MAX_OPERATIONS, Ordering::Release);
    assert!(matches!(
        controller.with_fingerprint_operation(&mut |_| calls += 1),
        Err(ObservationOperationError::Static {
            message: "RAM operation slots exhausted",
            ..
        })
    ));
    assert_eq!(calls, 0);
    assert_eq!(
        controller.operations.load(Ordering::Acquire),
        MAX_OPERATIONS
    );
    controller.operations.store(0, Ordering::Release);

    controller.state.lock().unwrap().budgets[5].poll_ms = 0;
    assert!(matches!(
        controller.with_fingerprint_operation(&mut |_| calls += 1),
        Err(ObservationOperationError::Static {
            kind: io::ErrorKind::TimedOut,
            ..
        })
    ));
    assert_eq!(calls, 0);
    assert_eq!(controller.operations.load(Ordering::Acquire), 0);

    controller.state.lock().unwrap().budgets[5].poll_ms = 10;
    controller
        .with_fingerprint_operation(&mut |operation| {
            controller.canceled.store(true, Ordering::Release);
            assert!(matches!(
                operation.wait_slice_for_observation(),
                Err(ObservationOperationError::Static {
                    message: "RAM operation canceled",
                    ..
                })
            ));
            controller.canceled.store(false, Ordering::Release);
            assert!(matches!(
                operation.complete_observation(),
                Err(ObservationOperationError::Static {
                    message: "RAM operation already canceled",
                    ..
                })
            ));
        })
        .unwrap();
    assert_eq!(controller.operations.load(Ordering::Acquire), 0);
}

#[test]
fn restore_page_exchange_forwards_the_live_loan_and_releases_source_custody() {
    use super::super::restore::{RestorePageSource, ValidatedRestoreSource};
    use super::super::source::{SourceDiagnostic, SourceFetchError};
    use crucible_protocol::ram_page::{
        RamPageBinding, RamPageResponse, RamPageStatus, read_ram_page_request,
        write_ram_page_response,
    };
    use crucible_ram::{
        Limits, MetadataBudget, PageDigest, RegionClass, RegionDescriptor, RegionTree, RootRecord,
        Scope, Topology,
    };
    use std::sync::Weak;

    struct AuditedLoan {
        controller: Arc<LivePagerController>,
        source: Mutex<Weak<RestorePageSource>>,
        mode: u8,
        callbacks: AtomicUsize,
    }

    impl SourceOperationFactory for AuditedLoan {
        fn begin(&self, _: SourceOperationClass) -> io::Result<Box<dyn SourceOperation>> {
            panic!("borrowed restore must not enter the owned operation factory");
        }

        fn with_fingerprint_operation(
            &self,
            exchange: &mut dyn FnMut(&dyn SourceOperation),
        ) -> Result<(), ObservationOperationError> {
            self.controller
                .with_fingerprint_operation(&mut |operation| {
                    self.callbacks.fetch_add(1, Ordering::AcqRel);
                    exchange(operation);
                    let source = self.source.lock().unwrap().upgrade().unwrap();
                    // This is still inside the actual LiveOperation loan. The
                    // page exchange must have returned the connection lock first.
                    assert!(source.endpoint_descriptors().is_ok());
                    assert_eq!(self.controller.operations.load(Ordering::Acquire), 1);
                    if self.mode == 2 {
                        exchange(operation);
                    }
                    if self.mode == 3 {
                        panic!("factory unwind after the production page exchange");
                    }
                })?;
            if self.mode == 1 {
                return Err(io::Error::from_raw_os_error(libc::EPIPE).into());
            }
            Ok(())
        }
    }

    // The source is authenticated through the real fork-source constructor;
    // this does not prepare mappings or claim native capture/restore authority.
    for (mode, corrupt, canceled) in [
        (0, false, false),
        (0, true, false),
        (1, true, false),
        (1, false, false),
        (2, false, false),
        (3, false, false),
        (0, false, true),
    ] {
        let controller = Arc::new(controller());
        let factory = Arc::new(AuditedLoan {
            controller: controller.clone(),
            source: Mutex::new(Weak::new()),
            mode,
            callbacks: AtomicUsize::new(0),
        });
        let owner = PausedPagingOwner::new(
            crate::args::PluginRamResources {
                resident_peak_bytes: 8192,
                backing_peak_bytes: 16384,
                metadata_bytes: 4096,
                staging_bytes: 4096,
                paging_io_slots: 1,
                cpu_slots: 1,
                task_slots: 1,
                file_descriptors: 3,
            },
            factory.clone(),
        )
        .unwrap();
        let budget = MetadataBudget::new(1024 * 1024);
        let digest = PageDigest::hash(b"content").unwrap();
        let tree = RegionTree::from_page_digests(7, &[digest], &budget).unwrap();
        let descriptor = RegionDescriptor::new("ram", RegionClass::MutableMain, 7).unwrap();
        let topology = Topology::new(vec![descriptor], Limits::default()).unwrap();
        let record = RootRecord::new(topology, Scope::Exact, vec![tree.digest()]).unwrap();
        let binding = RamPageBinding {
            session: [1; 16],
            owner_incarnation: [2; 16],
            source_generation: 3,
            root_digest: *record.digest().as_bytes(),
        };
        let (client, mut server) = UnixStream::pair().unwrap();
        let (cancel_read, _cancel_write) = UnixStream::pair().unwrap();
        let source = ValidatedRestoreSource::bind_fork_source(
            7,
            budget,
            client,
            cancel_read.into(),
            binding,
            &record.encode(),
            owner,
        )
        .unwrap()
        .into_page_source();
        *factory.source.lock().unwrap() = Arc::downgrade(&source);
        controller.canceled.store(canceled, Ordering::Release);
        let worker = if canceled {
            server.set_nonblocking(true).unwrap();
            None
        } else {
            let source = source.clone();
            let controller = controller.clone();
            Some(std::thread::spawn(move || {
                let request = read_ram_page_request(&mut server).unwrap();
                assert_eq!(request.region_ordinal, 0);
                assert_eq!(request.page_index, 0);
                assert_eq!(request.sequence, 1);
                assert!(source.endpoint_descriptors().is_err());
                assert_eq!(controller.operations.load(Ordering::Acquire), 1);
                let proof = tree.proof("ram", 0).unwrap().encode();
                write_ram_page_response(
                    &mut server,
                    RamPageResponse {
                        binding,
                        sequence: request.sequence,
                        status: RamPageStatus::Page,
                        page: if corrupt { b"corrupt" } else { b"content" },
                        proof: &proof,
                    },
                )
                .unwrap();
            }))
        };
        let mut output = [0xa5; super::super::PAGE_BYTES];
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            source.fetch_with_borrowed_hasher(0, 0, &mut output, None)
        }));
        if mode == 3 {
            assert!(outcome.is_err());
        } else {
            let result = outcome.unwrap();
            if canceled {
                assert!(matches!(
                    result,
                    Err(SourceFetchError::Diagnostic(SourceDiagnostic::Operation {
                        kind: io::ErrorKind::Interrupted,
                        message: "RAM operation canceled",
                    }))
                ));
                assert_eq!(factory.callbacks.load(Ordering::Acquire), 0);
                assert!(output.iter().all(|byte| *byte == 0xa5));
            } else if corrupt {
                // The exchange's initiating authentication error wins even
                // when the factory subsequently supplies a different error.
                assert!(matches!(
                    result,
                    Err(SourceFetchError::Core(
                        crucible_ram::RamError::DigestMismatch
                    ))
                ));
                assert!(output.iter().all(|byte| *byte == 0xa5));
            } else if mode == 1 {
                assert!(
                    matches!(result, Err(SourceFetchError::Io(error)) if error.raw_os_error() == Some(libc::EPIPE))
                );
            } else if mode == 2 {
                assert!(matches!(
                    result,
                    Err(SourceFetchError::Diagnostic(SourceDiagnostic::Operation {
                        message: "fingerprint operation exchange repeated",
                        ..
                    }))
                ));
            } else {
                assert!(matches!(result, Ok((7, actual)) if actual == digest));
                assert_eq!(&output[..7], b"content");
                assert!(output[7..].iter().all(|byte| *byte == 0));
            }
        }
        if let Some(worker) = worker {
            worker.join().unwrap();
        }
        assert!(source.endpoint_descriptors().is_ok());
        assert_eq!(controller.operations.load(Ordering::Acquire), 0);
        if !canceled {
            assert_eq!(factory.callbacks.load(Ordering::Acquire), 1);
        }
    }
}
