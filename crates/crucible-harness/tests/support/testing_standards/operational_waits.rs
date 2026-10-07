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
    let compact = compact_code(code);
    let occurrences = compact
        .match_indices(expression)
        .map(|(offset, _)| offset)
        .collect::<Vec<_>>();
    if occurrences.len() != expected_count {
        return;
    }
    for offset in occurrences {
        let start = offsets[offset];
        let end = offsets[offset + expression.len() - 1] + 1;
        code.replace_range(start..end, &" ".repeat(end - start));
    }
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
