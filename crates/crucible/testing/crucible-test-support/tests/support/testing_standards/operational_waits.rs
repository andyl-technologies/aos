//! Distinguishes reviewed original-operation waits from test rerun escapes.
//!
//! Each contract binds an exact source, the wait expression, its occurrence
//! count, and the checks that make the wait bounded or an adversarial input.
//! Additional sleeps and changed expressions remain visible to the lint.

#[path = "operational_target_cleanup.rs"]
mod operational_target_cleanup;

#[path = "operational_inputs.rs"]
mod operational_inputs;

#[path = "operational_recovery.rs"]
mod operational_recovery;

#[path = "operational_operations.rs"]
mod operational_operations;

pub(super) fn mask_operational_waits(package: &str, target: &str, code: &str) -> String {
    // Whole-operation contracts observe the original source before input
    // contracts mask individual declarations or assertions.
    let continuations = operational_operations::mask(package, target, code);
    mask_after_operations(package, target, &continuations)
}

fn mask_after_operations(package: &str, target: &str, code: &str) -> String {
    let operational = operational_inputs::mask(package, target, code);
    let recovery = operational_recovery::mask(package, target, &operational);
    if package == "crucible-qemu-host" && target == "src/linux_cgroup/target_dispatcher/tests" {
        // Both contracts inspect the original transcript: masking retry names
        // first would erase evidence needed to authenticate the actual wait.
        // Each mask preserves byte offsets and only replaces text with spaces.
        let waits = mask_dispatcher_test_waits(&operational);
        return recovery
            .char_indices()
            .map(|(offset, character)| {
                if waits.as_bytes()[offset] == b' ' {
                    ' '
                } else {
                    character
                }
            })
            .collect();
    }
    let code = recovery.as_str();
    let (requirements, expressions): (&[&str], &[(&str, usize)]) = match (package, target) {
        ("crucible-daemon", "src/executor_pool/checkpoint") => (
            &[
                "prepared.queued().cancellation().is_canceled()",
                "staged.queued().cancellation().is_canceled()",
                "published.queued().cancellation().is_canceled()",
                "supervisor_error_is_retryable(&error.source)",
                "Err(_)=>retain_forever(shared,retirement)",
                "token=error.token;",
            ],
            &[("thread::sleep(WORKER_RETRY_INTERVAL);", 6)],
        ),
        ("crucible-daemon", "src/host_operational_registry/fault_actor") => (
            &[
                "letguard=owner.supervisor.begin_control(class).map_err(supervision)?;",
                "letslice=guard.wait_slice().map_err(supervision)?;",
                "Err(TryLockError::WouldBlock)",
                "guard.complete().map_err(supervision)?;",
            ],
            &[(
                "std::thread::sleep(slice.min(std::time::Duration::from_millis(1)));",
                1,
            )],
        ),
        ("crucible-daemon", "src/packaged_qemu_executor/tests/hot_fork_native") => (
            &[
                "fnwait_for_parent_locks(",
                "receipt.mode==HostRamMode::ResidentRequired",
                "receipt.policy_revision==status.policy_revision",
                "operation.complete().expect();",
            ],
            &[(
                "std::thread::sleep(operation.wait_slice().expect().min(Duration::from_millis(25)),);",
                1,
            )],
        ),
        ("crucible-daemon", "src/packaged_qemu_executor/tests/paging_native/faults") => (
            &[
                "fnawait_reclaim(",
                ".physical_discards>before",
                "operation.complete().expect();",
            ],
            &[(
                "std::thread::sleep(operation.wait_slice().expect().min(Duration::from_millis(10)),);",
                1,
            )],
        ),
        (
            "crucible-daemon",
            "src/packaged_qemu_executor/tests/paging_native/source_failures/actor_exit",
        ) => (
            &[
                "fnverify_actual_return(",
                "letremaining=guard.wait_slice().expect();",
                "assert_eq!(report.worker_generation,self.generation);",
                "ifreport.membership_released{breakreport;}",
                "guard.complete().expect();",
            ],
            &[(
                "std::thread::sleep(remaining.min(Duration::from_millis(1)));",
                1,
            )],
        ),
        ("crucible-qemu-host", "src/ram_source/pending_health_tests") => (
            &[
                "fnawait_child(",
                ".failure.snapshot().delivered",
                "letslice=boundary.wait_slice().map_err(|error|map(&error))?;",
                "boundary.complete().map_err(|error|map(&error))?;",
                "assert!(!target.finished);",
                "assert!(!target.reaped);",
                "letcleanup=supervisor.begin(HostOperationClass::Cleanup)?;",
                "service.stop(Some(crate::ram_control::RamCleanupOriginal::direct(&cleanup,&supervisor,)))",
                "assert!(joined);",
            ],
            &[("thread::sleep(slice.min(Duration::from_millis(1)));", 1)],
        ),
        ("crucible-daemon", "src/packaged_qemu_executor/tests/paging_native/blocked_control") => (
            &[
                "ifmatches!(action.case,Case::Expiry|Case::Cancellation)",
                "HostOperationState::Expired",
                "HostOperationState::Canceled",
                "letrefusal=boundary();",
                "evidence.late_completion_refused=refusal.is_err();",
                "assert!(evidence.late_completion_refused);",
            ],
            &[("std::thread::sleep(Duration::from_millis(20));", 1)],
        ),
        // Component mechanisms and deliberate expiry inputs do not establish
        // native pager lifecycle or Source authority.
        ("crucible-qemu-host", "src/node/exact_snapshot/capture_original/tests/external") => (
            &[
                "fnwait(&self,timeout:Duration)",
                "letbegan=Instant::now();",
                "ifself.observe()?.is_some(){returnOk(true);}",
                "ifbegan.elapsed()>=timeout{returnOk(false);}",
                "parent.terminal=parent.child.try_wait()",
                "assert!(!process.reaped());",
                "assert!(process.checkpoint_original().unwrap().body.is_some());",
                "assert!(account.reserve_resources(0,2,16384).is_err());",
                "process.reap(Duration::from_secs(3)).unwrap(),QemuReap::Reaped",
                "assert!(parent.lock().unwrap().terminal.is_some());",
                "assert!(process.checkpoint_original().unwrap().body.is_none());",
                "assert!(account.reserve_resources(0,2,16384).is_ok());",
            ],
            &[("std::thread::sleep(Duration::from_millis(1));", 1)],
        ),
        ("crucible-qemu-plugin", "src/paged_ram/controller/actor/tests") => (
            &[
                "fnexpanding_policy_cannot_renew_an_expired_inline_record()",
                ".begin_inline::<true>(SourceOperationClass::Cleanup)",
                ".budgets[13].total_ns=Some(1_000_000);assert!(operation.wait_slice_for_observation().is_err());",
                ".budgets[13].total_ns=Some(30_000_000_000);assert!(operation.wait_slice_for_observation().is_err());",
                "assert!(operation.wait_slice_for_observation().is_err());",
                "assert!(operation.complete_observation().is_err());",
                "assert_ne!(operation.terminal.load(Ordering::Acquire),1);",
            ],
            &[("std::thread::sleep(Duration::from_millis(5));", 1)],
        ),
        _ => (&[], &[]),
    };

    // Cleanup/publication retries retain the same transaction and native
    // reservation. The delay is production backoff, not another test attempt.
    let compact = compact_code(code);
    let mut masked = code.to_owned();
    if !requirements.is_empty() && requirements.iter().all(|part| compact.contains(part)) {
        for (expression, count) in expressions {
            mask_expression(&mut masked, expression, *count);
        }
        if package == "crucible-daemon" && target == "src/executor_pool/checkpoint" {
            masked = masked.replace("WORKER_RETRY_INTERVAL", "WORKER_BACKOFF_INTERVAL");
        }
    }

    // These identifiers describe single-shot protocol observations. Exact
    // binding assertions distinguish them from a loop rerunning a failed test.
    let identifiers: (&[&str], &[&str]) = match (package, target) {
        ("crucible-daemon", "src/supervision") => (
            &[
                "assert!(!restarted);",
                "assert_eq!(retry.supervisor().cap_id(),supervisor.cap_id());",
            ],
            &["retry"],
        ),
        ("crucible-daemon", "src/packaged_qemu_executor/tests/paging_native/host_parallel") => (
            &[
                "assert!(healthy_peer_advanced&&logical_state_uncommitted&&retry_poisoned);",
                ".expect_err()",
            ],
            &["retry_poisoned"],
        ),
        ("crucible-qemu-plugin", "src/paged_ram/controller/tests") => (
            &[
                "assert_eq!(retry.disposition,RamControlDisposition::Accepted);",
                "assert_eq!(update.disposition,RamControlDisposition::Unavailable);",
                "assert_eq!(state.applied_revision,1);",
            ],
            &[
                "exact_applied_retry_returns_portable_observation_without_new_work",
                "applied_retry_refuses_changed_tuple_and_revision_relation",
                "exact_retry_from_another_controller_lineage_never_dispatches",
                "exact_retry_cannot_bypass_failed_canceled_or_closed_admission",
                "early_child_accepts_only_recorded_initial_retry_before_native_runtime_ready",
                "retry",
            ],
        ),
        _ => (&[], &[]),
    };
    if !identifiers.0.is_empty() && identifiers.0.iter().all(|part| compact.contains(part)) {
        for name in identifiers.1 {
            masked = mask_identifier(&masked, name);
        }
    }
    masked
}

// Only the entered worker/slot transitions and physical observations are bound.
// These file-backed component mechanisms grant no native authority.
const DISPATCHER_TEST_REQUIREMENTS: &[&str] = &[
    r#"fn mechanism_worker(state: Arc<DispatcherState>, capacity: usize) -> JoinHandle<()> {
    let event_capacity = capacity + 1;
    thread::spawn(move || run(state, event_capacity))
}"#,
    r#"fn one_worker_returns_actual_controls_for_sequential_jobs()"#,
    r#"fn busy_node_cannot_block_another_nodes_physical_return()"#,
    r#"let state = mechanism_state(directory.path(), 1)?;
    let worker_state = Arc::clone(&state);
    let worker = mechanism_worker(worker_state, 1);
    let worker_id = worker.thread().id();
    let end = std::time::Instant::now() + Duration::from_secs(5);"#,
    r#"for epoch in 1..=4 {"#,
    r#"signal_terminal(&control.watcher_state, cancellation.as_raw_fd())?;
        {
            let mut slots = state.slots.lock().unwrap();
            let slot = &mut slots[0];
            assert_eq!(slot.phase, JobPhase::Idle);
            slot.epoch = epoch;
            slot.phase = JobPhase::Queued;
            slot.control = Some(control);
        }
        let job = TargetWatchJob {
            state: Arc::clone(&state),
            epoch,
            index: 0,
            released: false,
        };
        wake(&state.wake)?;"#,
    r#"assert!(
            job.is_finished(),
            "same worker did not return actual job controls"
        );
        assert_eq!(worker.thread().id(), worker_id);
        assert!(!worker.is_finished());
        drop(job.retire().unwrap());
        assert_eq!(state.slots.lock().unwrap()[0].phase, JobPhase::Idle);"#,
    r#"state.shutdown.store(true, Ordering::Release);
    wake(&state.wake)?;
    while !worker.is_finished() && std::time::Instant::now() < end {
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        worker.is_finished(),
        "fixed Main worker did not physically stop"
    );
    worker.join().unwrap();
    assert_eq!(Arc::strong_count(&state), 1);"#,
    r#"let state = mechanism_state(directory.path(), 2)?;
    let worker = mechanism_worker(Arc::clone(&state), 2);
    let end = std::time::Instant::now() + Duration::from_secs(5);"#,
    r#"signal_terminal(&first.watcher_state, first_cancel.as_raw_fd())?;
    signal_terminal(&second.watcher_state, second_cancel.as_raw_fd())?;
    {
        let mut slots = state.slots.lock().unwrap();
        for (slot, control) in slots.iter_mut().zip([first, second]) {
            slot.epoch = 1;
            slot.phase = JobPhase::Queued;
            slot.control = Some(control);
        }
    }
    let first = TargetWatchJob {
        state: Arc::clone(&state),
        epoch: 1,
        index: 0,
        released: false,
    };
    let second = TargetWatchJob {
        state: Arc::clone(&state),
        epoch: 1,
        index: 1,
        released: false,
    };
    wake(&state.wake)?;"#,
    r#"assert!(
        second.is_finished(),
        "empty node must return independently of populated node"
    );
    assert!(
        !first.is_finished(),
        "populated node must retain its own controls"
    );
    drop(second.retire().unwrap());
    assert_eq!(state.slots.lock().unwrap()[0].phase, JobPhase::Running);
    assert_eq!(state.slots.lock().unwrap()[1].phase, JobPhase::Idle);"#,
    r#"fs::write(first_path.join("cgroup.events"), "populated 0\n")?;
    while !first.is_finished() && std::time::Instant::now() < end {
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        first.is_finished(),
        "first node must retain and later return its exact controls"
    );
    drop(first.retire().unwrap());"#,
    r#"state.shutdown.store(true, Ordering::Release);
    wake(&state.wake)?;
    while !worker.is_finished() && std::time::Instant::now() < end {
        thread::sleep(Duration::from_millis(1));
    }
    assert!(worker.is_finished());
    worker.join().unwrap();
    assert_eq!(Arc::strong_count(&state), 1);"#,
    r#"let returned = job.retire().unwrap();
    assert_eq!(state.slots.lock().unwrap()[0].phase, JobPhase::Retiring);
    let observed = fs::metadata(format!("/proc/self/fd/{descriptor}"))?;
    assert_eq!(
        (observed.dev(), observed.ino()),
        (expected.dev(), expected.ino())
    );
    drop(returned);

    assert_eq!(state.slots.lock().unwrap()[0].phase, JobPhase::Idle);
    // Another parallel test may reuse the numeric descriptor. It cannot reopen
    // this private fixture's same inode between these two observations.
    assert!(
        fs::metadata(format!("/proc/self/fd/{descriptor}")).map_or(true, |observed| {
            (observed.dev(), observed.ino()) != (expected.dev(), expected.ino())
        })
    );
    assert_eq!(Arc::strong_count(&state), 1);"#,
    operational_recovery::DISPATCHER_FAILED_STARTUP,
    operational_recovery::DISPATCHER_QUARANTINED_RETURN,
    r#"fn abandoned_worker_keeps_its_actual_join_owner_in_preborn_state()
-> Result<(), Box<dyn std::error::Error>> {
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    let directory = tempfile::tempdir()?;
    let state = mechanism_state(directory.path(), 1)?;
    assert!(state.retained_worker.get().is_none());
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = supervisor.begin(HostOperationClass::Preparation)?;
    let (release, blocked) = std::sync::mpsc::sync_channel(1);
    let worker = thread::spawn(move || blocked.recv().unwrap());
    let identity = worker.thread().id();
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

    // Exercise Drop's exact transfer without leaking its retained Arc into the
    // test process. No Main issuer, join observation or new recipient is made.
    dispatcher.retain_abandoned_worker();
    dispatcher.retain_abandoned_worker();

    assert!(dispatcher.worker.is_none());
    let state = dispatcher.state.take().unwrap();
    let mut state = Arc::try_unwrap(state).ok().unwrap();
    let retained = state.retained_worker.get_mut().unwrap();
    assert_eq!(retained.thread_id(), identity);
    assert_eq!(retained.last_status(), None);
    assert!(retained.belongs_to_current_process());

    // The same unique native owner remains capable of observing real return.
    // This component cleanup does not assert authenticated Main retirement.
    release.send(())?;
    loop {
        let slice = original.wait_slice()?;
        let observed = retained.poll()?;
        original.wait_slice()?;
        if observed == NativeJoinObservation::Returned {
            break;
        }
        thread::sleep(slice.min(WATCHER_WAIT_POLL_INTERVAL));
    }
    assert_eq!(retained.last_status(), Some(0));
    Ok(())
}"#,
];

const DISPATCHER_TEST_LOOPS: &[(&str, usize)] = &[
    ("std::thread::sleep(CGROUP_KILL_INTERVAL);", 1),
    (
        r#"for _ in 0..5_000 {
        if worker.poll()? == NativeJoinObservation::Returned {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }"#,
        1,
    ),
    (
        r#"loop {
        let slice = original.wait_slice()?;
        let observed = retained.poll()?;
        original.wait_slice()?;
        if observed == NativeJoinObservation::Returned {
            break;
        }
        thread::sleep(slice.min(WATCHER_WAIT_POLL_INTERVAL));
    }"#,
        1,
    ),
    (
        r#"while !job.is_finished() && std::time::Instant::now() < end { thread::sleep(Duration::from_millis(1)); }"#,
        1,
    ),
    (
        r#"while !worker.is_finished() && std::time::Instant::now() < end { thread::sleep(Duration::from_millis(1)); }"#,
        2,
    ),
    (
        r#"while !first.is_finished() && std::time::Instant::now() < end { thread::sleep(Duration::from_millis(1)); }"#,
        1,
    ),
    (
        r#"while !second.is_finished() && std::time::Instant::now() < end { thread::sleep(Duration::from_millis(1)); }"#,
        1,
    ),
];

fn mask_dispatcher_test_waits(code: &str) -> String {
    let compact = compact_code(code);
    let deadline = source_pattern("let end = std::time::Instant::now() + Duration::from_secs(5);");
    // Live jobs retain fixed ends; native join has a finite poll allowance.
    if expression_offsets(code, &deadline).len() != 2
        || !DISPATCHER_TEST_REQUIREMENTS
            .iter()
            .all(|required| compact.contains(&source_pattern(required)))
        || !DISPATCHER_TEST_LOOPS.iter().all(|(expression, count)| {
            expression_offsets(code, &source_pattern(expression)).len() == *count
        })
    {
        return code.to_owned();
    }

    let mut masked = code.to_owned();
    for (expression, count) in DISPATCHER_TEST_LOOPS {
        mask_expression(&mut masked, &source_pattern(expression), *count);
    }
    masked
}

fn compact_code(code: &str) -> String {
    code.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn identifier_count(code: &str, name: &str) -> usize {
    let is_identifier = |character: char| character.is_ascii_alphanumeric() || character == '_';
    code.match_indices(name)
        .filter(|(start, _)| {
            let end = *start + name.len();
            code[..*start]
                .chars()
                .next_back()
                .is_none_or(|c| !is_identifier(c))
                && code[end..].chars().next().is_none_or(|c| !is_identifier(c))
        })
        .count()
}

fn source_pattern(source: &str) -> String {
    compact_code(&super::scrub_comments_and_strings(source))
}

fn mask_identifier(code: &str, name: &str) -> String {
    let mut result = code.to_owned();
    for (start, _) in code.match_indices(name) {
        let end = start + name.len();
        let trailing = code[end..].trim_start();
        let declaration = code[..start].trim_end().ends_with("fn");
        if trailing.starts_with('!')
            || (trailing.starts_with('(') && (name == "retry" || !declaration))
        {
            continue;
        }
        let is_identifier = |character: char| character.is_ascii_alphanumeric() || character == '_';
        if code[..start]
            .chars()
            .next_back()
            .is_none_or(|character| !is_identifier(character))
            && code[end..]
                .chars()
                .next()
                .is_none_or(|character| !is_identifier(character))
        {
            result.replace_range(start..end, &" ".repeat(name.len()));
        }
    }
    result
}

fn mask_expression(code: &mut String, expression: &str, expected_count: usize) {
    let offsets = code
        .char_indices()
        .filter(|(_, character)| !character.is_whitespace())
        .flat_map(|(offset, character)| std::iter::repeat_n(offset, character.len_utf8()))
        .collect::<Vec<_>>();
    let occurrences = expression_offsets(code, expression);
    if occurrences.len() != expected_count {
        return;
    }
    for offset in occurrences {
        let start = offsets[offset];
        let end = offsets[offset + expression.len() - 1] + 1;
        code.replace_range(start..end, &" ".repeat(end - start));
    }
}

// A reviewed helper cannot be a suffix of another identifier or qualified path.
fn expression_offsets(code: &str, expression: &str) -> Vec<usize> {
    let offsets = code
        .char_indices()
        .filter(|(_, character)| !character.is_whitespace())
        .flat_map(|(offset, character)| std::iter::repeat_n(offset, character.len_utf8()))
        .collect::<Vec<_>>();
    let compact = compact_code(code);
    compact
        .match_indices(expression)
        .filter(|(offset, _)| {
            let preceding = &code[..offsets[*offset]];
            let separate_token = preceding.chars().next_back().is_none_or(|before| {
                before.is_whitespace()
                    || (before.is_ascii() && !before.is_ascii_alphanumeric() && before != '_')
            });
            separate_token && !preceding.trim_end().ends_with(':')
        })
        .map(|(offset, _)| offset)
        .collect()
}

#[test]
fn reviewed_waits_keep_deadlines_and_reject_additional_delays()
-> Result<(), Box<dyn std::error::Error>> {
    let root = super::workspace_root();
    for (package, target, authority) in [
        (
            "crucible-daemon",
            "src/host_operational_registry/fault_actor",
            "guard.wait_slice()",
        ),
        (
            "crucible-daemon",
            "src/packaged_qemu_executor/tests/hot_fork_native",
            "operation.wait_slice()",
        ),
        (
            "crucible-daemon",
            "src/packaged_qemu_executor/tests/paging_native/faults",
            "operation.wait_slice()",
        ),
        (
            "crucible-daemon",
            "src/packaged_qemu_executor/tests/paging_native/source_failures/actor_exit",
            ".wait_slice()",
        ),
        (
            "crucible-qemu-host",
            "src/ram_source/pending_health_tests",
            "boundary.wait_slice()",
        ),
        (
            "crucible-daemon",
            "src/packaged_qemu_executor/tests/paging_native/blocked_control",
            "let refusal = boundary();",
        ),
        (
            "crucible-qemu-host",
            "src/linux_cgroup/target_dispatcher/tests",
            "let end = std::time::Instant::now() + Duration::from_secs(5);",
        ),
        (
            "crucible-qemu-host",
            "src/node/exact_snapshot/capture_original/tests/external",
            "if began.elapsed() >= timeout",
        ),
        (
            "crucible-qemu-plugin",
            "src/paged_ram/controller/actor/tests",
            ".budgets[13].total_ns = Some(1_000_000);",
        ),
    ] {
        let path = crate::workspace::package_path(&root.join("crates"), package)
            .join(format!("{target}.rs"));
        let source = std::fs::read_to_string(path)?;
        assert!(
            super::flaky_escape_failures(package, target, &source).is_empty(),
            "reviewed wait no longer matches: {target}"
        );

        let (broken, removed) = if source.contains(authority) {
            (source.replace(authority, "unbounded_wait()"), true)
        } else {
            // A multi-line guard call has identical tokens after whitespace removal.
            let compact = compact_code(&super::scrub_comments_and_strings(&source));
            (
                compact.replace(authority, "unbounded_wait()"),
                compact.contains(authority),
            )
        };
        assert!(removed, "regression did not remove {authority} in {target}");
        assert!(
            super::flaky_escape_failures(package, target, &broken)
                .iter()
                .any(|finding| finding.contains("`thread::sleep`")),
            "missing original boundary passed: {target}"
        );

        let extra_delay = format!("{source}\nfn conceal_failure() {{ thread::sleep(wait); }}");
        assert!(
            super::flaky_escape_failures(package, target, &extra_delay)
                .iter()
                .any(|finding| finding.contains("`thread::sleep`")),
            "additional sleep passed: {target}"
        );
        let test_retry = format!("{source}\nfn conceal_failure() {{ retry_failed_test(); }}");
        assert!(
            super::flaky_escape_failures(package, target, &test_retry)
                .iter()
                .any(|finding| finding.contains("`retry`")),
            "test retry passed: {target}"
        );
    }
    for (package, target) in [
        ("crucible-daemon", "src/supervision"),
        (
            "crucible-daemon",
            "src/packaged_qemu_executor/tests/paging_native/host_parallel",
        ),
        ("crucible-qemu-plugin", "src/paged_ram/controller/tests"),
    ] {
        let path = crate::workspace::package_path(&root.join("crates"), package)
            .join(format!("{target}.rs"));
        let source = std::fs::read_to_string(path)?;
        assert!(
            !super::flaky_escape_failures(package, target, &source)
                .iter()
                .any(|finding| finding.contains("`retry`")),
            "single-shot protocol observation drifted: {target}"
        );
        let test_retry = format!("{source}\nfn conceal_failure() {{ retry(); }}");
        let retry_macro = format!("{source}\nfn conceal_failure() {{ retry!(); }}");
        assert!(
            super::flaky_escape_failures(package, target, &retry_macro)
                .iter()
                .any(|finding| finding.contains("`retry`")),
            "retry macro passed: {target}"
        );
        assert!(
            super::flaky_escape_failures(package, target, &test_retry)
                .iter()
                .any(|finding| finding.contains("`retry`")),
            "callable retry helper passed: {target}"
        );
    }
    Ok(())
}

#[test]
fn dispatcher_waits_require_each_fixed_deadline_and_whole_loop()
-> Result<(), Box<dyn std::error::Error>> {
    let root = super::workspace_root();
    let source = std::fs::read_to_string(root.join(
        "crates/crucible/qemu/crucible-qemu-host/src/linux_cgroup/target_dispatcher/tests.rs",
    ))?;
    let has_wait = |source: &str| {
        let code = super::scrub_comments_and_strings(source);
        let masked = mask_dispatcher_test_waits(&code);
        super::flaky_escape_failures("unreviewed", "unreviewed", &masked)
            .iter()
            .any(|finding| finding.contains("`thread::sleep`"))
    };
    let code = super::scrub_comments_and_strings(&source);
    let compact = compact_code(&code);
    let missing = DISPATCHER_TEST_REQUIREMENTS
        .iter()
        .enumerate()
        .filter(|(_, required)| !compact.contains(&source_pattern(required)))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    assert!(
        !has_wait(&source),
        "missing dispatcher obligations: {missing:?}"
    );

    let deadline = "let end = std::time::Instant::now() + Duration::from_secs(5);";
    let deadlines = source
        .match_indices(deadline)
        .map(|(offset, _)| offset)
        .collect::<Vec<_>>();
    assert_eq!(deadlines.len(), 2);
    for offset in deadlines {
        let mut changed = source.clone();
        changed.replace_range(offset..offset + deadline.len(), "removed_deadline();");
        assert!(
            has_wait(&changed),
            "one missing fixed deadline was admitted"
        );
    }

    let condition = " && std::time::Instant::now() < end";
    let conditions = source
        .match_indices(condition)
        .map(|(offset, _)| offset)
        .collect::<Vec<_>>();
    assert_eq!(conditions.len(), 5);
    for offset in conditions {
        let mut changed = source.clone();
        changed.replace_range(offset..offset + condition.len(), "");
        assert!(has_wait(&changed), "one unbounded wait loop was admitted");
    }
    for (expression, _) in DISPATCHER_TEST_LOOPS {
        let changed = format!("{source}\nfn extra_wait() {{ {expression} }}");
        assert!(
            has_wait(&changed),
            "an additional reviewed loop was admitted"
        );
    }
    for requirement in DISPATCHER_TEST_REQUIREMENTS {
        assert!(source.contains(*requirement));
        let changed = source.replacen(*requirement, "removed_worker_or_custody_proof();", 1);
        assert!(
            has_wait(&changed),
            "missing worker/custody proof was admitted"
        );
    }
    Ok(())
}
