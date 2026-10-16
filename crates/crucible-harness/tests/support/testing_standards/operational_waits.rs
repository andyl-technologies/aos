//! Distinguishes reviewed original-operation waits from test rerun escapes.
//!
//! Each contract binds an exact source, the wait expression, its occurrence
//! count, and the checks that make the wait bounded or an adversarial input.
//! Additional sleeps and changed expressions remain visible to the lint.

#[path = "operational_inputs.rs"]
mod operational_inputs;

pub(super) fn mask_operational_waits(package: &str, target: &str, code: &str) -> String {
    let operational = operational_inputs::mask(package, target, code);
    let code = operational.as_str();
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
        ("crucible-qemu", "src/ram_source/pending_health_tests") => (
            &[
                "fnawait_child(",
                ".is_some_and(|worker|worker.is_finished())",
                "letslice=boundary.wait_slice().map_err(|error|map(&error))?;",
                "boundary.complete().map_err(|error|map(&error))?;",
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
        ("crucible-qemu", "src/linux_cgroup/target_dispatcher/tests") => (
            &[
                "letworker=thread::spawn(move||run(worker_state));",
                "letworker_id=worker.thread().id();",
                "letend=std::time::Instant::now()+Duration::from_secs(5);",
                "forepochin1..=4{",
                "while!job.is_finished()&&std::time::Instant::now()<end{",
                "while!worker.is_finished()&&std::time::Instant::now()<end{",
                "assert!(job.is_finished(),);",
                "assert_eq!(worker.thread().id(),worker_id);",
                "assert!(!worker.is_finished());",
                "drop(job.retire().unwrap());",
                "assert!(worker.is_finished(),);",
                "worker.join().unwrap();",
                "assert_eq!(Arc::strong_count(&state),1);",
            ],
            &[("thread::sleep(Duration::from_millis(1));", 2)],
        ),
        ("crucible-qemu", "src/node/exact_snapshot/capture_original/tests/external") => (
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

fn compact_code(code: &str) -> String {
    code.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
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
            "crucible-qemu",
            "src/ram_source/pending_health_tests",
            "boundary.wait_slice()",
        ),
        (
            "crucible-daemon",
            "src/packaged_qemu_executor/tests/paging_native/blocked_control",
            "let refusal = boundary();",
        ),
        (
            "crucible-qemu",
            "src/linux_cgroup/target_dispatcher/tests",
            "let end = std::time::Instant::now() + Duration::from_secs(5);",
        ),
        (
            "crucible-qemu",
            "src/node/exact_snapshot/capture_original/tests/external",
            "if began.elapsed() >= timeout",
        ),
        (
            "crucible-qemu-plugin",
            "src/paged_ram/controller/actor/tests",
            ".budgets[13].total_ns = Some(1_000_000);",
        ),
    ] {
        let path = root
            .join("crates")
            .join(package)
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
        let path = root
            .join("crates")
            .join(package)
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
