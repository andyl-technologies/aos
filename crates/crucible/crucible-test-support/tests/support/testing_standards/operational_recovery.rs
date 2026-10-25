//! Binds single-attempt recovery names to retained-custody controls.
//!
//! Exact identifier counts admit the reviewed observations only. Removing a
//! custody assertion or adding another attempt leaves the retry token visible.
//! These local controls establish no live native Source or lifecycle authority.

use super::{
    compact_code, expression_offsets, identifier_count, mask_expression, mask_identifier,
    source_pattern,
};

#[path = "operational_recovery/delivery.rs"]
mod delivery;

#[path = "operational_recovery/physical_cleanup.rs"]
mod physical_cleanup;

#[path = "operational_recovery/issued_return.rs"]
mod issued_return;

struct Contract {
    package: &'static str,
    target: &'static str,
    required: &'static [&'static str],
    identifiers: &'static [(&'static str, usize)],
    expressions: &'static [(&'static str, usize)],
}

// The startup transcript is part of the same dispatcher custody contract.
// These obligations retain typed work and independent Preparation outcomes;
// rendering or physical closure cannot replace either saved result.
const DISPATCHER_STARTUP_REQUIRED: &[&str] = &[
    r#"struct DispatcherStartupHistory {
    first: Option<DispatcherStartupFailure>,
    post: Option<DispatcherStartupFailure>,
}"#,
    r#"enum DispatcherStartupFailure {
    Original(ServiceBirthError),
    Allocation(std::collections::TryReserveError),
    Custody(&'static str),
}"#,
    r#"self.first = started.err(); self.post = post().err();"#,
    r#"let started = self.wait_for_worker_startup();
        let purpose = self.purpose.as_mut();
        self.startup_history.observe(started, || {
            purpose
                .as_ref()
                .ok_or(DispatcherStartupFailure::Custody(
                    "Target dispatcher payer is absent",
                ))?
                .startup_wait_slice()
                .map(|_| ())
                .map_err(DispatcherStartupFailure::Original)
        });
        if let Some(purpose) = purpose {
            purpose.release_startup_observation();
        }
        self.report_retirement_history()?;
        self.phase = WorkerPhase::Running;"#,
    r#".startup_wait_slice().map_err(DispatcherStartupFailure::Original)?;"#,
    r#"if worker_startup_ready(state)? { return Ok(()); }"#,
    r#"Some(Err(source)) => Err(DispatcherStartupFailure::Allocation(source.clone())),"#,
    r#"(Some(first), Some(post)) => {
        write!(formatter, "{first}; independent startup post: {post}")
    }"#,
    r#"if self.startup_history.has_failure() {
            return Err(if panicked {
                retirement_failure(
                    &self.path,
                    format_args!(
                        "{}; Target dispatcher physically joined after worker panic",
                        self.startup_history,
                    ),
                )
            } else {
                retirement_failure(&self.path, &self.startup_history)
            });
        }"#,
    r#".checked_add(u64::try_from(std::mem::size_of::<Self>()).ok()?)?"#,
];

fn dispatcher_startup_is_bound(code: &str) -> bool {
    let compact = compact_code(code);
    DISPATCHER_STARTUP_REQUIRED
        .iter()
        .all(|requirement| compact.contains(&source_pattern(requirement)))
}

pub(super) const DISPATCHER_FAILED_STARTUP: &str = r#"fn failed_worker_startup_keeps_independent_original_post_after_physical_close()
-> Result<(), Box<dyn std::error::Error>> {
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationState, HostOperationSupervisor,
        HostSupervisionError,
    };

    let directory = tempfile::tempdir()?;
    let state = mechanism_state(directory.path(), 1)?;
    let descriptor = state._namespace.as_raw_fd();
    let expected = fs::metadata(format!("/proc/self/fd/{descriptor}"))?;
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = supervisor.begin(HostOperationClass::Preparation)?;
    let initial = original.status()?;
    let (published, ready) = std::sync::mpsc::sync_channel(1);
    let worker_state = Arc::clone(&state);
    let worker = thread::spawn(move || {
        // The actual worker records a genuine Vec capacity refusal, not a
        // fabricated Main/Target admission or a selected error response.
        run(worker_state, usize::MAX);
        published.send(()).unwrap();
    });
    // A polling slice is not the Preparation's complete allowance. Observe
    // this same worker once per slice, retaining its unchanged Original.
    loop {
        match ready.recv_timeout(original.wait_slice()?) {
            Ok(()) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(first) => return Err(first.into()),
        }
    }
    let mut dispatcher = TargetDispatcher {
        purpose: None,
        capacity: 1,
        state: Some(state),
        worker: Some(NativeJoinOwner::from_worker(worker)),
        worker_born: true,
        failed: true,
        cleanup: None,
        phase: WorkerPhase::Reserved,
        worker_panic: Mutex::new(None),
        startup_history: DispatcherStartupHistory::default(),
        join_observations: [(None, None); 2],
        path: directory.path().to_owned(),
    };

    original.wait_slice()?;
    let started = worker_startup_ready(dispatcher.state.as_ref().unwrap()).map(|_| ());
    dispatcher.startup_history.observe(started, || {
        supervisor.cancel().unwrap();
        original
            .wait_slice()
            .map(|_| ())
            .map_err(ServiceBirthError::from)
            .map_err(DispatcherStartupFailure::Original)
    });
    assert!(matches!(
        dispatcher.startup_history.first,
        Some(DispatcherStartupFailure::Allocation(_))
    ));
    assert!(matches!(
        dispatcher.startup_history.post,
        Some(DispatcherStartupFailure::Original(
            ServiceBirthError::Supervision(HostSupervisionError::Terminal {
                state: HostOperationState::Canceled
            })
        ))
    ));
    let terminal = original.status()?;
    assert_eq!(terminal.operation_id, initial.operation_id);
    assert_eq!(terminal.class, initial.class);
    assert_eq!(
        terminal.started_policy_revision,
        initial.started_policy_revision
    );
    assert_eq!(terminal.completed_work_units, initial.completed_work_units);
    assert_eq!(terminal.state, HostOperationState::Canceled);
    let first_report = dispatcher
        .report_retirement_history()
        .unwrap_err()
        .to_string();
    let first = dispatcher
        .startup_history
        .first
        .as_ref()
        .unwrap()
        .to_string();
    let post = dispatcher
        .startup_history
        .post
        .as_ref()
        .unwrap()
        .to_string();
    assert!(first_report.contains(&format!("{first}; independent startup post: {post}")));

    // Historical failure does not prevent closing these actual component
    // resources. No authenticated Main purpose exists or is invented here.
    let mut worker = dispatcher.worker.take().unwrap();
    for _ in 0..5_000 {
        if worker.poll()? == NativeJoinObservation::Returned {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        worker.last_status(),
        Some(0),
        "component worker did not physically join"
    );
    drop(worker);
    drop(dispatcher.state.take());
    assert_descriptor_closed(descriptor, &expected);
    assert!(dispatcher.worker.is_none());
    assert!(dispatcher.state.is_none());
    assert!(!dispatcher.is_physically_retired());
    let final_report = dispatcher
        .report_retirement_history()
        .unwrap_err()
        .to_string();
    assert_eq!(final_report, first_report);
    assert!(matches!(
        dispatcher.startup_history.first,
        Some(DispatcherStartupFailure::Allocation(_))
    ));
    assert!(matches!(
        dispatcher.startup_history.post,
        Some(DispatcherStartupFailure::Original(
            ServiceBirthError::Supervision(HostSupervisionError::Terminal {
                state: HostOperationState::Canceled
            })
        ))
    ));
    Ok(())
}"#;

pub(super) const DISPATCHER_QUARANTINED_RETURN: &str = r#"    assert!(dispatcher.retry_abandoned_jobs().is_err());
    assert!(
        state
            .slots
            .lock()
            .unwrap()
            .iter()
            .all(|slot| slot.failure_reported)
    );
    assert!(dispatcher.retry_abandoned_jobs().is_err());
    {
        let slots = state.slots.lock().unwrap();
        assert_eq!(slots[0].phase, JobPhase::Quarantined);
        assert!(slots[0].control.is_some());
        assert!(slots[0].next_retry.is_scheduled());
        assert_eq!(slots[1].phase, JobPhase::Idle);
        assert!(slots[1].control.is_none());
    }
    // Wait out the actual retry cadence independently of the physical empty
    // observation; neither fact changes the retained Cleanup authority.
    fs::write(
        directory.path().join("abandoned-0/cgroup.events"),
        "populated 0\n",
    )?;
    std::thread::sleep(CGROUP_KILL_INTERVAL);
    dispatcher.retry_abandoned_jobs()?;
    assert!(
        state
            .slots
            .lock()
            .unwrap()
            .iter()
            .all(|slot| slot.phase == JobPhase::Idle)
    );"#;

const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-qemu-host",
        target: "src/linux_attempt_host/original_node/helper_receiver",
        required: &[
            r#"let Some(receiver) = slot.lender.clone() else { return false; };"#,
            r#"child.retain_source_original(original);"#,
            r#"drop(slot.child.take());"#,
        ],
        identifiers: &[],
        expressions: &[
            (physical_cleanup::HELPER_SETTLEMENT, 1),
            (physical_cleanup::HELPER_CONTINUATION, 1),
        ],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/linux_attempt_host/original_node",
        required: &[
            r#"if self.child_borrowed.load(std::sync::atomic::Ordering::Acquire) { return false; }"#,
            r#"retained.first_cleanup = Some(first);"#,
            r#"retained.latest_cleanup = Some(first);"#,
        ],
        identifiers: &[],
        expressions: &[(physical_cleanup::CONTROLLER_CONTINUATION, 1)],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/node/failed_launch/issued",
        required: &[
            r#".map(|lender| lender.clone().retained_original()).transpose()"#,
            r#"node.child_shutdown.retain_source_original(original);"#,
            r#"None => Err(QemuNodeError::RamCleanupPending),"#,
        ],
        identifiers: &[],
        expressions: &[(physical_cleanup::ISSUED_CONTINUATION, 1)],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/node/failed_launch",
        required: &[
            r#".map_err(|_| QemuNodeError::RamCleanupPending)?;"#,
            r#"self.retain_source_original(original)?;"#,
            r#"assert_eq!(owner.process_id(), Some(process_id));"#,
            r#"assert!(!owner.child_reaped());"#,
        ],
        identifiers: &[],
        expressions: &[
            (physical_cleanup::CHILD_CONTINUATION, 1),
            (physical_cleanup::FAILED_CONTINUATION, 1),
            (physical_cleanup::ABSENT_LENDER_CONTROL, 1),
        ],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/node_factory/restore_cleanup",
        required: &[r#"primary: Box::new(primary), cleanup,"#],
        identifiers: &[],
        expressions: &[(physical_cleanup::RESTORE_SETTLEMENT, 1)],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/supervision/node_step_gate",
        required: &[
            r#"child.retain_cleanup_failure(QemuLiveNodeStepGateError::FailedCleanup {"#,
            r#"return Err(reap_failed_live_node_child(owner, primary));"#,
        ],
        identifiers: &[],
        expressions: &[
            (physical_cleanup::ISSUED_FAILURE_SETTLEMENT, 1),
            (physical_cleanup::EXACT_RESUME_BOUNDARY, 1),
        ],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/node/failed_launch/issued/tests",
        required: &[
            "assert_eq!(owner.process_id(), Some(process_id));",
            "assert!(!owner.child_reaped());",
            "Err(QemuNodeError::RamCleanupPending)",
            "assert!(owner.child_reaped());",
            "if source.same_owner(&receiver)",
            "assert_eq!(supervisor.operation_statuses()?.len(), before);",
            "assert!(!receiver.retry_physical_cleanup());",
            "assert!(unwind.is_err());",
            "close_component_child(&receiver, process_id)?;",
        ],
        identifiers: &[],
        expressions: &[
            (issued_return::CHILD_CLEANUP, 1),
            (issued_return::FAILURE_RETURN, 1),
            (issued_return::UNWIND_RETURN, 1),
        ],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/runtime/command_receive/delivery/tests",
        required: &[delivery::READY_RETURN],
        identifiers: &[(
            "refused_ready_return_preserves_first_error_through_real_lifetime_retry",
            1,
        )],
        expressions: &[],
    },
    Contract {
        package: "crucible-store",
        target: "src/ram/tests/packed_volume/archive_sender",
        required: &[
            r#"let visits = sender.state_for_test().1;"#,
            r#"let RamStoreError::Store(StoreError::RamValidation { source: first }) = error else"#,
            r#"first.storage_failure(), RamStoreError::Limit("transfer requests")"#,
            r#"let retry = sender.respond(want, &mut || { panic!("a failed sender cannot poll or read again") }).err().unwrap();"#,
            r#"assert_eq!(first, retry);"#,
            r#"assert_eq!(sender.state_for_test().1, visits);"#,
            r#"PreparedRamFailure::<std::convert::Infallible>::allocation_bytes().unwrap()"#,
            r#"drop((first, retry)); assert_eq!(fixture.quota.0.usage().unwrap(), baseline);"#,
        ],
        identifiers: &[("retry", 5)],
        expressions: &[],
    },
    Contract {
        package: "crucible-store",
        target: "src/ram/tests/packed_volume/pending_publication",
        required: &[
            r#"crate::ram::codec_ownership::SharedEnvelope::get_mut(envelope).unwrap().body_mut()[36] ^= 1;"#,
            r#"matches!(error, RamStoreError::Store(StoreError::Corrupt { id: found }) if found == id)"#,
            r#"assert_eq!(pending.len(), 1);"#,
            r#"assert_eq!(pending.sorted_positions, positions);"#,
            r#"assert_eq!(pending.encoded_bytes, encoded);"#,
            r#"assert_eq!(fixture.quota.0.usage().unwrap(), held);"#,
            r#"assert_eq!(work.pending.as_ref().unwrap().len(), 1);"#,
        ],
        identifiers: &[(
            "pending_duplicate_still_compares_exact_envelope_and_preserves_retry_state",
            1,
        )],
        expressions: &[],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/node/exact_snapshot/capture_original/tests",
        required: &[
            r#"assert_eq!(owner.enter(&replacement).unwrap_err(), first);"#,
            r#"assert_eq!(body.native_transfer.as_ref().unwrap().cancellation.as_raw_fd(), alias);"#,
            r#"supervisor.cancel().unwrap(); let retry = owner.prepare_receiving(&registration(&account, Arc::new(UnavailableRegistrar))).unwrap_err();"#,
            r#"assert_eq!(retry.source, refusal.source); assert!(retry.original_after.is_some());"#,
            r#"assert_eq!(body.first_refusal, Some(refusal)); assert_eq!(body.basis.unwrap(), basis);"#,
            r#"assert_eq!(owner.receiver_custody, ReceiverCustody::Receiving);"#,
            r#"assert!(account.reserve_resources(0, 1, 1).is_err());"#,
            r#"assert_eq!(retry.source, first.source); assert!(retry.original_after.is_some());"#,
            r#"assert_eq!(owner.body.as_ref().unwrap().first_refusal, Some(first));"#,
            r#"assert_eq!(retry, first);"#,
            r#"assert!(owner.body.as_ref().unwrap().native_transfer.is_none());"#,
            r#"assert!(owner.body.as_ref().unwrap().basis.is_none());"#,
            r#"assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);"#,
        ],
        identifiers: &[
            ("retry", 8),
            (
                "receiving_retry_cannot_replace_basis_or_alias_after_refusal",
                1,
            ),
        ],
        expressions: &[],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/qmp/checkpoint_begin/tests",
        required: &[
            r#"client.bind_checkpoint_original(original).unwrap();"#,
            r#"Err(QmpError::MalformedTypedResponse { .. })"#,
            r#"assert!(client.poisoned);"#,
            r#"let before = client.stream.get_ref().output.len(); assert!(client.begin_checkpoint_receiving(arm).is_err()); assert_eq!(client.stream.get_ref().output.len(), before);"#,
        ],
        identifiers: &[(
            "begin_refuses_a_mismatched_or_absent_connection_receipt_and_poisoning_blocks_retry",
            1,
        )],
        expressions: &[],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/qmp/checkpoint_original_wait/tests",
        required: &[
            r#"let id = original.guard.status().unwrap().operation_id;"#,
            r#"budgets.classes[HostOperationClass::Quiescence as usize].total_timeout = Some(Duration::from_nanos(1));"#,
            r#"assert!(matches!(first.source, QmpError::CheckpointOriginal { .. })); assert!(first.original_after.is_some()); assert!(client.poisoned);"#,
            r#"assert!(matches!(retry.source, QmpError::ConnectionPoisoned));"#,
            r#"assert_eq!(retry.original_after, first.original_after);"#,
            r#"assert_eq!(client.stream.get_ref().written.len(), before);"#,
            r#"assert_eq!(original.guard.status().unwrap().operation_id, id);"#,
            r#"assert_eq!(original.supervisor.operation_statuses().unwrap().len(), 1);"#,
        ],
        identifiers: &[
            (
                "amended_original_expiration_prevents_retry_without_new_start_or_write",
                1,
            ),
            ("retry", 3),
        ],
        expressions: &[],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/spawn/source_supervision/parent_park_return/tests",
        required: &[
            r#"action.retain_park_return(verified, 0).unwrap(); action.park_members_returned_mask = 1; action.retain_park_return(verified, 1).unwrap();"#,
            r#"assert_eq!(action.park_members_returned_mask, 1);"#,
            r#"assert_eq!(action.observation.borrowed_mask, 3);"#,
            r#"assert_eq!(action.verified_park_return, Some(verified));"#,
            r#"assert_eq!(verified.journal.first, -5);"#,
            r#"assert_eq!(verified.journal.original_statuses, [-125, -110]);"#,
            r#"verified.completed_requests = 2; assert!(action.retain_park_return(verified, 0).is_err());"#,
            r#"verified.journal.post = -4; assert!(action.retain_park_return(verified, 0).is_err());"#,
            r#"assert_eq!(action.verified_park_return, Some(evidence()));"#,
        ],
        identifiers: &[
            ("retry_keeps_same_evidence_and_actual_host_unlink_state", 1),
            (
                "new_closure_requires_advancement_but_retry_cannot_change_it",
                1,
            ),
        ],
        expressions: &[],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/paged_ram/engine/scheduling/checkpoint/tests",
        required: &[
            r#".completion_errno.store(libc::ECANCELED, Ordering::SeqCst);"#,
            r#"queue.finish_receipt(9, || panic!("uncertain completion must not retry")).is_err()"#,
            r#"queue.release_checkpoint(1, || panic!("uncertain receipt must remain held")).is_err()"#,
            r#"assert!(Arc::ptr_eq(&operation.upgrade().unwrap(), &queue.receipt.as_ref().unwrap().operation));"#,
            r#"assert!(queue.capture.disposition_uncertain);"#,
            r#"assert!(queue.capture.completed_receipt.is_none());"#,
            r#"assert!(queue.capture.require_open().is_err());"#,
            r#"assert_eq!(counts.completed.load(Ordering::SeqCst), 1);"#,
            r#"assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);"#,
        ],
        identifiers: &[(
            "negative_completion_after_its_effect_retains_the_receipt_without_retry",
            1,
        )],
        expressions: &[],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/runtime/callback_child/publication/tests",
        required: &[
            r#"cuts.begin_status = -libc::EKEYEXPIRED; cuts.return_status = -libc::EBUSY;"#,
            r#"assert_eq!(first, Err(super::super::status_error(-libc::EKEYEXPIRED)));"#,
            r#"assert_eq!(owner.loan, token()); assert_eq!(owner.serial, 9);"#,
            r#"assert_eq!(retry, Err(super::super::status_error(-libc::EBUSY)));"#,
            r#"assert_eq!(cuts.begins, 1); assert_eq!(cuts.currents, 0);"#,
            r#"cuts.return_status = 0; cuts.consume = true;"#,
            r#"assert!(owner.identity_return().is_ok()); assert!(!owner.retained());"#,
        ],
        identifiers: &[("retry", 2)],
        expressions: &[],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/runtime/callback_child/tests",
        required: &[
            r#"CUTS.with_borrow_mut(|cuts| cuts.create_status = -libc::ENOMEM);"#,
            r#"assert_eq!(first, Err(status_error(-libc::ENOMEM)));"#,
            r#"assert_eq!(owner.projection, token()); assert!(owner.retains_storage());"#,
            r#"assert_eq!(retry, Err(status_error(-libc::EALREADY)));"#,
            r#"assert_eq!(cuts.creates, 1); assert_eq!(cuts.initializes, 0);"#,
        ],
        identifiers: &[
            (
                "born_negative_child_allocation_retains_projection_and_closes_retry",
                1,
            ),
            ("retry", 2),
        ],
        expressions: &[],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/runtime/live_callbacks/fingerprint_worker/tests",
        required: &[
            r#"unsafe { worker.hold_workspace_for_fork() }.unwrap();"#,
            r#"assert!(enqueue(worker.control.as_ref().unwrap(), 64).is_ok());"#,
            r#"assert!(unsafe { worker.hold_workspace_for_fork() }.is_err());"#,
            r#"assert_eq!(worker.fork_workspace.get_mut().as_ref().unwrap().descriptor_number(), retained);"#,
            r#"assert!(worker.control.as_ref().unwrap().workspace().is_none());"#,
            r#"assert_eq!(worker.control.as_ref().unwrap().lock().pending.as_ref().unwrap().capture_request, 64);"#,
        ],
        identifiers: &[(
            "already_held_workspace_cannot_bless_a_retry_with_retained_capture",
            1,
        )],
        expressions: &[],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/runtime/live_callbacks/park_return/tests",
        required: &[
            r#"let progress = writer.write(&slot, &bytes); slot.retain_action_frontier(2).unwrap(); let retry = writer.write(&slot, &bytes);"#,
            r#"assert_eq!(progress.first_status, -libc::EIO);"#,
            r#"assert_eq!(progress.publication_uncertain, 1);"#,
            r#"assert_eq!(retry.first_status, -libc::EALREADY);"#,
            r#"assert_eq!(retry.write_attempted, 0);"#,
            r#"assert_eq!(slot.observe_parent_park_return().unwrap(), None);"#,
            r#"assert_eq!(writer.journal.lock().unwrap().bytes, bytes);"#,
        ],
        identifiers: &[("retry", 3)],
        expressions: &[],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/runtime/workspace_mapping/tests",
        required: &[
            r#"creation_status: -libc::ENOKEY, empty_outputs: true,"#,
            r#"Err(DeviceDigestWorkspaceError::Admission { status }) if status == -libc::ENOKEY"#,
            r#"assert!(owner.returned); assert!(owner.attempted);"#,
            r#"assert_eq!(owner.creation_status, Some(-libc::ENOKEY));"#,
            r#"assert_eq!(owner.return_status, None);"#,
            r#"assert!(owner.create_using(7, runtime(), api()).is_err());"#,
            r#"assert!(owner.identity_return().is_ok());"#,
            r#"NATIVE.with(|fixture| assert_eq!(fixture.borrow().calls, ["create"]));"#,
        ],
        identifiers: &[(
            "empty_negative_creation_settles_only_local_custody_without_retry",
            1,
        )],
        expressions: &[],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/startup_source/control_purpose/tests",
        required: &[
            r#"CUTS.with_borrow_mut(|cuts| cuts.null_success = true);"#,
            r#"let expected = Err(StartupSourceError::Ownership { reason: "native fixed control reservation returned no retained holder", });"#,
            r#"assert_eq!(reserve_model(owner), expected); assert_eq!(owner.check_installer_control_purpose(), expected); assert_eq!(reserve_model(owner), expected);"#,
            r#"CUTS.with_borrow(|cuts| assert_eq!(cuts.calls, ["reserve"]));"#,
        ],
        identifiers: &[(
            "null_success_cannot_admit_birth_or_retry_the_same_attempt",
            1,
        )],
        expressions: &[],
    },
    Contract {
        package: "crucible-store",
        target: "src/content_store/packed/read_view/tests/shared_cache",
        required: &[
            r#"if admitted.get() { Err(StoreError::Unauthorized) } else { Ok(()) }"#,
            r#".retain_in(&fixture.quota.1, |bytes, check| { check()?; let credit = fixture.quota.0.reserve_with_control(bytes)?; admitted.set(true); Ok(credit) })"#,
            r#"assert!(matches!(error, StoreError::Unauthorized)); drop(request); assert_eq!(fixture.quota.0.usage().unwrap(), baseline);"#,
            r#"assert_eq!(fixture.quota.1.reclaim(u64::MAX).unwrap(), Some(0));"#,
            r#"fixture.quota.read_packed_manifest(&mut retry).unwrap(); assert!(retry.finish().unwrap().is_some());"#,
            r#"assert!(fixture.quota.1.reclaim(u64::MAX).unwrap().unwrap() > 0); assert_eq!(fixture.quota.0.usage().unwrap(), baseline);"#,
        ],
        identifiers: &[("retry", 3)],
        expressions: &[],
    },
    // Real file descriptors model physical controls. These bounded component
    // recovery attempts preserve the same cell/epoch and first cause; no Main
    // or Target Original is issued, and the production retry helper is unmasked.
    Contract {
        package: "crucible-qemu-host",
        target: "src/linux_cgroup/target_dispatcher/tests",
        required: &[
            r#"fn assert_descriptor_closed(descriptor: RawFd, expected: &fs::Metadata) {
    // Parallel tests may reuse the number, but cannot reopen this private file.
    assert!(
        fs::metadata(format!("/proc/self/fd/{descriptor}")).map_or(true, |observed| {
            (observed.dev(), observed.ino()) != (expected.dev(), expected.ino())
        }),
        "the exact retained file must close before its slot becomes reusable"
    );
}"#,
            r#"slots[0].epoch = 1;
        slots[0].phase = JobPhase::Quarantined;
        slots[0].control = Some(control);
        slots[0].failure = Some(JobFailure {
            panicked: true,
            ..JobFailure::default()
        });
    }
    let job = TargetWatchJob {
        state: Arc::clone(&state),
        epoch: 1,
        index: 0,
        released: false,
    };

    let (job, first) = match job.retire() {
        Err(retained) => retained,
        Ok(_) => panic!("first failed attempt must be reported before physical retry"),
    };
    assert!(first.to_string().contains("panic true"));
    assert!(fs::metadata(format!("/proc/self/fd/{descriptor}")).is_ok());
    assert_eq!(state.slots.lock().unwrap()[0].phase, JobPhase::Quarantined);"#,
            r#"let returned = job.retire().unwrap();
    assert_eq!(state.slots.lock().unwrap()[0].phase, JobPhase::Retiring);
    assert!(fs::metadata(format!("/proc/self/fd/{descriptor}")).is_ok());
    drop(returned);

    let slots = state.slots.lock().unwrap();
    assert_eq!(slots[0].phase, JobPhase::Idle);
    assert!(slots[0].failure.as_ref().unwrap().panicked);
    assert!(slots[0].failure_reported);
    assert_descriptor_closed(descriptor, &expected);"#,
            r#"slots[0].epoch = 1;
        slots[0].phase = JobPhase::Running;
        state.running.lock().unwrap()[0] = Some(RunningJob {
            epoch: 1,
            control,
            original: None,
            draining: true,
            failure: None,
            next_attempt: HostRetryCadence::default(),
        });
    }"#,
            r#"let poisoned = Arc::clone(&state);
    assert!(
        thread::spawn(move || {
            let _held = poisoned.running.lock().unwrap();
            panic!("component worker unwind while retaining actual controls");
        })
        .join()
        .is_err()
    );
    let job = TargetWatchJob {
        state: Arc::clone(&state),
        epoch: 1,
        index: 0,
        released: false,
    };

    assert!(job.is_finished());
    let (job, first) = match job.retire() {
        Err(retained) => retained,
        Ok(_) => panic!("first failed attempt must be reported before physical retry"),
    };
    assert!(first.to_string().contains("panic true"));
    assert!(state.running.is_poisoned());
    match state.running.lock() {
        Err(poison) => assert!(poison.get_ref()[0].is_none()),
        Ok(_) => panic!("job recovery must not erase containing worker poison"),
    }
    assert!(fs::metadata(format!("/proc/self/fd/{descriptor}")).is_ok());"#,
            r#"drop(job.retire().unwrap());
    let slots = state.slots.lock().unwrap();
    assert_eq!(slots[0].phase, JobPhase::Idle);
    assert!(slots[0].failure.as_ref().unwrap().panicked);
    assert!(state.running.is_poisoned());
    assert_descriptor_closed(descriptor, &expected);"#,
            r#"for slot in slots.iter_mut() {
            slot.epoch = 1;
            slot.facade_live = true;
        }
        slots[0].phase = JobPhase::Running;
        slots[1].phase = JobPhase::Queued;
        slots[1].control = Some(queued_control);
        state.running.lock().unwrap()[0] = Some(RunningJob {
            epoch: 1,
            control: running_control,
            original: None,
            draining: false,
            failure: None,
            next_attempt: HostRetryCadence::default(),
        });
    }"#,
            r#"let poisoned = Arc::clone(&state);
    assert!(
        thread::spawn(move || {
            let _held = poisoned.slots.lock().unwrap();
            panic!("component slot-only poison before worker dispatch");
        })
        .join()
        .is_err()
    );

    // This exits normally while holding an unpoisoned running array. Recovery
    // must depend on the actual exit witness, not running mutex poison.
    run(Arc::clone(&state), 3);
    assert!(state.worker_exited.load(Ordering::Acquire));
    assert!(!state.running.is_poisoned());"#,
            r#"for (index, (descriptor, expected)) in descriptors.into_iter().enumerate() {
        let job = TargetWatchJob {
            state: Arc::clone(&state),
            epoch: 1,
            index,
            released: false,
        };
        assert!(job.is_finished());
        let (job, first) = match job.retire() {
            Err(retained) => retained,
            Ok(_) => panic!("worker exit must be reported before physical retry"),
        };
        assert!(first.to_string().contains("Target worker exited"));
        assert!(fs::metadata(format!("/proc/self/fd/{descriptor}")).is_ok());
        drop(job.retire().unwrap());
        assert_descriptor_closed(descriptor, &expected);
    }
    assert!(state.running.lock().unwrap().iter().all(Option::is_none));
    let slots = match state.slots.lock() {
        Err(poison) => poison.into_inner(),
        Ok(_) => panic!("individual recovery must retain containing slot poison"),
    };
    assert!(slots.iter().all(|slot| slot.phase == JobPhase::Idle));
    assert!(slots.iter().all(|slot| slot.failure_reported));"#,
            r#"slots[0].epoch = 7;
        slots[0].phase = JobPhase::Quarantined;
        slots[0].facade_live = true;
        slots[0].control = Some(control);
        slots[0].failure = Some(JobFailure {
            panicked: true,
            ..JobFailure::default()
        });
    }
    drop(TargetWatchJob {
        state: Arc::clone(&state),
        epoch: 7,
        index: 0,
        released: false,
    });
    assert!(!state.slots.lock().unwrap()[0].facade_live);"#,
            r#"let first = dispatcher.retry_abandoned_jobs().unwrap_err();
    assert!(first.to_string().contains("panic true"));
    assert_eq!(state.slots.lock().unwrap()[0].epoch, 7);
    assert!(!state.slots.lock().unwrap()[0].facade_live);
    assert!(fs::metadata(format!("/proc/self/fd/{descriptor}")).is_ok());

    dispatcher.retry_abandoned_jobs()?;
    let slots = state.slots.lock().unwrap();
    assert_eq!(slots[0].epoch, 7);
    assert_eq!(slots[0].phase, JobPhase::Idle);
    assert!(slots[0].failure.as_ref().unwrap().panicked);
    assert_descriptor_closed(descriptor, &expected);
    drop(slots);"#,
            r#"for (index, populated) in [true, false].into_iter().enumerate() {"#,
            r#"super::super::tests::watcher_control_fixture(&path, populated)?;"#,
            r#"slots[index].epoch = 1;
        slots[index].phase = JobPhase::Quarantined;
        slots[index].control = Some(control);
        slots[index].failure = Some(JobFailure {
            panicked: true,
            ..JobFailure::default()
        });"#,
            DISPATCHER_QUARANTINED_RETURN,
            r#"assert!(
        !dispatcher.is_physically_retired(),
        "actual join alone is not a paid Main return"
    );
    drop(dispatcher);
    assert_descriptor_closed(descriptor, &expected);"#,
            DISPATCHER_FAILED_STARTUP,
        ],
        identifiers: &[
            (
                "quarantined_failure_is_reported_before_same_control_physical_retry",
                1,
            ),
            (
                "poisoned_running_cell_returns_its_same_owners_through_explicit_retry",
                1,
            ),
            (
                "slot_poison_exit_preserves_running_and_queued_controls_for_retry",
                1,
            ),
            ("next_retry", 2),
            ("retry_abandoned_jobs", 5),
        ],
        expressions: &[
            (
                "let first = dispatcher.retry_abandoned_jobs().unwrap_err();",
                1,
            ),
            ("dispatcher.retry_abandoned_jobs()?;", 2),
            ("assert!(dispatcher.retry_abandoned_jobs().is_err());", 2),
        ],
    },
];

pub(super) fn mask(package: &str, target: &str, code: &str) -> String {
    let Some(contract) = CONTRACTS
        .iter()
        .find(|contract| contract.package == package && contract.target == target)
    else {
        return code.to_owned();
    };
    mask_contract(contract, code)
}

fn mask_contract(contract: &Contract, code: &str) -> String {
    let compact = compact_code(code);
    if !contract
        .required
        .iter()
        .all(|part| compact.contains(&source_pattern(part)))
        || !contract
            .identifiers
            .iter()
            .all(|(name, count)| identifier_count(code, name) == *count)
        || !contract.expressions.iter().all(|(expression, count)| {
            expression_offsets(code, &source_pattern(expression)).len() == *count
        })
    {
        return code.to_owned();
    }

    let mut masked = code.to_owned();
    for (expression, count) in contract.expressions {
        mask_expression(&mut masked, &source_pattern(expression), *count);
    }
    for (name, _) in contract.identifiers {
        masked = mask_identifier(&masked, name);
    }
    masked
}

// Keep surrounding lexical boundaries when removing a multiline obligation.
// Compacting the whole source could merge `let` and a surviving local name.
fn remove_obligation(code: &str, obligation: &str) -> String {
    let offsets = code
        .char_indices()
        .filter(|(_, character)| !character.is_whitespace())
        .flat_map(|(offset, character)| std::iter::repeat_n(offset, character.len_utf8()))
        .collect::<Vec<_>>();
    let compact = compact_code(code);
    let occurrences = compact
        .match_indices(obligation)
        .map(|(offset, _)| offset)
        .collect::<Vec<_>>();
    let mut changed = code.to_owned();
    for offset in occurrences.into_iter().rev() {
        let start = offsets[offset];
        let end = offsets[offset + obligation.len() - 1] + 1;
        changed.replace_range(start..end, " removed_custody_obligation() ");
    }
    changed
}

#[test]
fn recovery_names_require_custody_and_reject_additional_attempts()
-> Result<(), Box<dyn std::error::Error>> {
    let root = super::super::super::workspace_root();
    let has_retry = |code: &str| {
        super::super::flaky_escape_failures("unreviewed", "unreviewed", code)
            .iter()
            .any(|finding| finding.contains("`retry`"))
    };
    for contract in CONTRACTS {
        let source = std::fs::read_to_string(
            crate::workspace::package_path(&root.join("crates"), contract.package)
                .join(format!("{}.rs", contract.target)),
        )?;
        let code = super::super::scrub_comments_and_strings(&source);
        let compact = compact_code(&code);
        assert!(
            has_retry(&code),
            "control has no retry token: {}",
            contract.target
        );
        assert!(
            !has_retry(&mask_contract(contract, &code)),
            "reviewed recovery control drifted: {}",
            contract.target
        );

        for requirement in contract.required {
            let obligation = source_pattern(requirement);
            assert!(compact.contains(&obligation));
            let changed = remove_obligation(&code, &obligation);
            assert!(
                has_retry(&mask_contract(contract, &changed)),
                "removed custody assertion was admitted: {} {requirement}",
                contract.target
            );
        }
        for (name, count) in contract.identifiers {
            assert_eq!(identifier_count(&code, name), *count);
            let extra = format!("{code}\nfn conceal_failure() {{ let {name} = (); }}");
            assert!(
                has_retry(&mask_contract(contract, &extra)),
                "additional reviewed identifier was admitted: {} {name}",
                contract.target
            );
            let called = format!("{code}\nfn conceal_failure() {{ {name}(); }}");
            assert!(
                has_retry(&mask_contract(contract, &called)),
                "invocation of a reviewed name was admitted: {} {name}",
                contract.target
            );
        }
        for (expression, count) in contract.expressions {
            let expression = source_pattern(expression);
            assert_eq!(expression_offsets(&code, &expression).len(), *count);
            let extra = format!("{code}\n{expression}");
            assert!(
                has_retry(&mask_contract(contract, &extra)),
                "additional recovery call was admitted: {} {expression}",
                contract.target
            );
        }
        for addition in [
            "fn conceal_failure() { retry(); }",
            "fn conceal_failure() { retry!(); }",
            "fn conceal_failure() { retry_failed_test(); }",
            "fn conceal_failure() { loop { retry_failed_test(); } }",
        ] {
            let changed = format!("{code}\n{addition}");
            assert!(
                has_retry(&mask_contract(contract, &changed)),
                "test rerun was admitted: {} {addition}",
                contract.target
            );
        }
    }
    Ok(())
}

#[test]
fn dispatcher_recovery_requires_each_actual_custody_observation()
-> Result<(), Box<dyn std::error::Error>> {
    let root = super::super::super::workspace_root();
    let implementation = std::fs::read_to_string(
        root.join("crates/crucible/crucible-qemu-host/src/linux_cgroup/target_dispatcher.rs"),
    )?;
    let implementation = super::super::scrub_comments_and_strings(&implementation);
    assert!(dispatcher_startup_is_bound(&implementation));
    for requirement in DISPATCHER_STARTUP_REQUIRED {
        let changed = remove_obligation(&implementation, &source_pattern(requirement));
        assert!(
            !dispatcher_startup_is_bound(&changed),
            "removed startup custody obligation was admitted: {requirement}"
        );
    }

    let source = std::fs::read_to_string(root.join(
        "crates/crucible/crucible-qemu-host/src/linux_cgroup/target_dispatcher/tests.rs",
    ))?;
    let code = super::super::scrub_comments_and_strings(&source);
    let contract = CONTRACTS
        .iter()
        .find(|contract| {
            contract.package == "crucible-qemu-host"
                && contract.target == "src/linux_cgroup/target_dispatcher/tests"
        })
        .expect("the exact dispatcher component contract is present");
    let has_retry = |code: &str| {
        super::super::flaky_escape_failures("unreviewed", "unreviewed", code)
            .iter()
            .any(|finding| finding.contains("`retry`"))
    };
    let compact = compact_code(&code);
    let missing = contract
        .required
        .iter()
        .enumerate()
        .filter(|(_, required)| !compact.contains(&source_pattern(required)))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let counts = contract
        .identifiers
        .iter()
        .map(|(name, count)| (*name, *count, identifier_count(&code, name)))
        .collect::<Vec<_>>();
    assert!(
        !has_retry(&mask_contract(contract, &code)),
        "missing obligations: {missing:?}; identifier counts: {counts:?}"
    );
    let offsets = code
        .char_indices()
        .filter(|(_, character)| !character.is_whitespace())
        .flat_map(|(offset, character)| std::iter::repeat_n(offset, character.len_utf8()))
        .collect::<Vec<_>>();
    for requirement in [
        "assert_descriptor_closed(descriptor, &expected);",
        "assert!(slots[0].failure.as_ref().unwrap().panicked);",
        "assert!(slots[0].failure_reported);",
        "assert!(state.running.is_poisoned());",
        "assert!(!state.running.is_poisoned());",
        "run(Arc::clone(&state), 3); assert!(state.worker_exited.load(Ordering::Acquire)); assert!(!state.running.is_poisoned());",
        "assert_eq!(slots[0].epoch, 7);",
        "assert!(slots[0].control.is_some());",
        "assert!(slots[1].control.is_none());",
        "assert!(slots[0].next_retry.is_scheduled());",
    ] {
        let expression = source_pattern(requirement);
        let occurrences = expression_offsets(&code, &expression);
        assert!(
            !occurrences.is_empty(),
            "missing original observation: {requirement}"
        );
        for occurrence in occurrences {
            let mut changed = code.clone();
            let start = offsets[occurrence];
            let end = offsets[occurrence + expression.len() - 1] + 1;
            changed.replace_range(start..end, " removed_custody_observation(); ");
            assert!(
                has_retry(&mask_contract(contract, &changed)),
                "one missing custody observation was admitted: {requirement}"
            );
        }
    }
    Ok(())
}

#[test]
fn dispatcher_startup_wait_requires_the_same_original_worker_and_independent_history()
-> Result<(), Box<dyn std::error::Error>> {
    let root = super::super::super::workspace_root();
    let source = std::fs::read_to_string(root.join(
        "crates/crucible/crucible-qemu-host/src/linux_cgroup/target_dispatcher/tests.rs",
    ))?;
    let code = super::super::scrub_comments_and_strings(&source);
    let contract = CONTRACTS
        .iter()
        .find(|contract| {
            contract.package == "crucible-qemu-host"
                && contract.target == "src/linux_cgroup/target_dispatcher/tests"
        })
        .expect("the original dispatcher control remains registered");
    let has = |source: &str, pattern: &str| {
        super::super::flaky_escape_failures("unreviewed", "unreviewed", source)
            .iter()
            .any(|finding| finding.contains(pattern))
    };
    assert!(!has(&mask_contract(contract, &code), "`retry`"));
    assert!(!has(
        &super::mask_dispatcher_test_waits(&code),
        "`thread::sleep`"
    ));
    let cases: &[(&str, &str)] = &[
        (
            r#"std::sync::mpsc::sync_channel(1)"#,
            r#"std::sync::mpsc::sync_channel(0)"#,
        ),
        (
            r#"ready.recv_timeout(original.wait_slice()?)"#,
            r#"ready.recv_timeout(renewed.wait_slice()?)"#,
        ),
        (
            r#"Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}"#,
            r#"Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break"#,
        ),
        (
            r#"Err(first) => return Err(first.into()),"#,
            r#"Err(_) => break,"#,
        ),
        (
            r#"loop { match ready.recv_timeout(original.wait_slice()?)"#,
            r#"loop { original.progress(1)?; match ready.recv_timeout(original.wait_slice()?)"#,
        ),
        (
            r#"loop { match ready.recv_timeout(original.wait_slice()?)"#,
            r#"loop { let original = supervisor.begin(HostOperationClass::Preparation)?; match ready.recv_timeout(original.wait_slice()?)"#,
        ),
        (
            r#"run(worker_state, usize::MAX); published.send(()).unwrap();"#,
            r#"published.send(()).unwrap(); run(worker_state, usize::MAX);"#,
        ),
        (
            r#"let initial = original.status()?;"#,
            r#"let initial = unrelated.status()?;"#,
        ),
        (
            r#"terminal.operation_id, initial.operation_id"#,
            r#"terminal.operation_id, terminal.operation_id"#,
        ),
        (
            r#"terminal.completed_work_units, initial.completed_work_units"#,
            r#"terminal.completed_work_units, terminal.completed_work_units"#,
        ),
        (
            r#"terminal.started_policy_revision, initial.started_policy_revision"#,
            r#"terminal.started_policy_revision, terminal.started_policy_revision"#,
        ),
        (
            r#"supervisor.cancel().unwrap();"#,
            r#"original.progress(1).unwrap();"#,
        ),
        (
            r#"dispatcher.startup_history.observe(started, || {"#,
            r#"dispatcher.startup_history.observe(Ok(()), || {"#,
        ),
        (
            r#"Some(DispatcherStartupFailure::Allocation(_))"#,
            r#"None"#,
        ),
        (
            r#"Some(DispatcherStartupFailure::Original( ServiceBirthError::Supervision(HostSupervisionError::Terminal { state: HostOperationState::Canceled }) ))"#,
            r#"None"#,
        ),
        (
            r#"let mut worker = dispatcher.worker.take().unwrap();"#,
            r#"drop(dispatcher.worker.take());"#,
        ),
        (
            r#"NativeJoinOwner::from_worker(worker)"#,
            r#"NativeJoinOwner::from_worker(thread::spawn(|| ()))"#,
        ),
        (r#"worker_born: true,"#, r#"worker_born: false,"#),
        (
            r#"join_observations: [(None, None); 2],"#,
            r#"join_observations: [(None, None); 1],"#,
        ),
        (
            r#"if worker.poll()? == NativeJoinObservation::Returned"#,
            r#"if worker.poll()? == NativeJoinObservation::Pending"#,
        ),
        (r#"for _ in 0..5_000"#, r#"loop"#),
        (
            r#"thread::sleep(Duration::from_millis(1));"#,
            r#"worker = NativeJoinOwner::from_worker(thread::spawn(|| ()));"#,
        ),
        (
            r#"worker.last_status(), Some(0),"#,
            r#"worker.last_status(), Some(libc::EBUSY),"#,
        ),
        (
            r#"drop(worker); drop(dispatcher.state.take());"#,
            r#"drop(dispatcher.state.take()); drop(worker);"#,
        ),
        (
            r#"drop(worker); drop(dispatcher.state.take());"#,
            r#"drop(dispatcher.state.take());"#,
        ),
        (
            r#"assert_descriptor_closed(descriptor, &expected);"#,
            r#"assert!(true);"#,
        ),
        (
            r#"assert!(!dispatcher.is_physically_retired());"#,
            r#"assert!(dispatcher.is_physically_retired());"#,
        ),
        (
            r#"assert_eq!(final_report, first_report);"#,
            r#"assert_eq!(final_report, final_report);"#,
        ),
    ];
    let offsets = code
        .char_indices()
        .filter(|(_, ch)| !ch.is_whitespace())
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let compact = compact_code(&code);
    let body = source_pattern(DISPATCHER_FAILED_STARTUP);
    let body_offset = compact
        .find(&body)
        .expect("the complete real startup test is present");
    for (before, after) in cases {
        let needle = source_pattern(before);
        let at = body_offset
            + body
                .find(&needle)
                .expect("the actual same-Original observation is present");
        let mut changed = code.clone();
        changed.replace_range(offsets[at]..offsets[at + needle.len() - 1] + 1, after);
        assert_ne!(changed, code);
        assert!(
            has(&mask_contract(contract, &changed), "`retry`"),
            "changed synchronization/retained history passed: {before}"
        );
        assert!(
            has(
                &super::mask_dispatcher_test_waits(&changed),
                "`thread::sleep`"
            ),
            "changed synchronization/retained history hid the bounded waits: {before}"
        );
    }
    Ok(())
}
