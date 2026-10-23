//! Binds source-health polling to same-node RAM ownership and actual join.
//!
//! The saved caller Cleanup replaces the removed consuming/new-clock API.
//! Physical return precedes independent history, and neither worker failure
//! nor first delivery destroys the canonical service or its retained credit.

use super::{Companion, Contract};

#[path = "ram_source_cleanup/source_stop.rs"]
mod source_stop;
pub(super) const STOP_CONTRACT: Contract = source_stop::CONTRACT;

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-qemu-host",
    target: "src/node/host_policy",
    required: &[
        (
            r#"self.child_shutdown.finish_ram(|original, history| {
    let mut returned = true;
    #[cfg(target_os = "linux")]
    {
        if let Some(stage) = stage
            && let Err(first) = stage.finish_source()
        {
            history.retain_stage(first);
            returned = false;
        }
        if let QemuNodeProcessControl::Direct(child) = child {
            drop(child.ram_source_start.take());
            returned &= history.source(1, &mut child.ram_source, original);
        }
        if let Some(ram) = continuation {
            returned &= ram.finish(original, history);
        }
    }
    if returned {
        let (closed, status) = runtime.retire_host_ram_after_cleanup(original, &mut history.retirement[0]);
        history.controller(0, status);
        returned &= closed;
    }
    returned
})"#,
            1,
        ),
        (
            r#"let observation = self.supervisor.begin(HostOperationClass::Preparation)?;
let source = self.retained.as_ref().ok_or("fixture no longer owns its Source service")?;
loop { match source.check_health()"#,
            1,
        ),
        (
            r#"Err(QemuRamSourceError::WorkerFailed(_)) => break, Err(source) => return Err(source.into()),"#,
            1,
        ),
        ("observation.complete()?;", 1),
        ("assert!(fixture.task_is_retained());", 4),
        (
            r#"fn close(&mut self) -> bool {
    self.history.source(1, &mut self.retained,
        Some(crate::ram_control::RamCleanupOriginal::direct(&self.cleanup, &self.supervisor,)),
    )
}"#,
            1,
        ),
        (
            r#"fixture.refuse_an_authenticated_page()?;
assert!(!fixture.close());
let error = fixture.history.failure().ok_or("raw worker cause missing")?;
let observed = fixture.retained.as_ref().unwrap().check_health().unwrap_err();
let QemuRamSourceError::WorkerFailed(worker) = observed else {
    panic!("the retained service must expose its original worker failure");
};
assert!(matches!(worker.as_ref(), QemuRamSourceError::Proof(_)));
let QemuNodeError::RamCleanup { sources, .. } = &error else {
    panic!("cleanup must preserve the typed source failure");
};
assert_eq!(sources[1].as_ref().and_then(|history| history.worker.as_ref()), Some(&worker));
assert!(fixture.task_is_retained());
assert!(fixture.close());
assert!(fixture.retained.is_none());"#,
            1,
        ),
        (
            r#"drop(worker); assert!(fixture.task_is_retained());
drop(scheduler); drop(fixture.history);
assert!(fixture.services.reserve_resources(1, 0, 0).is_ok());"#,
            1,
        ),
        (
            r#"let original_id = fixture.cleanup.status()?.operation_id;
let mut guards = Vec::new();
loop {
    match fixture.supervisor.begin(HostOperationClass::Cleanup) {
        Ok(guard) => guards.push(guard),
        Err(HostSupervisionError::CapacityExhausted) => break,
        Err(source) => return Err(source.into()),
    }
}
assert!(fixture.task_is_retained());
assert!(matches!(fixture.supervisor.begin(HostOperationClass::Cleanup), Err(HostSupervisionError::CapacityExhausted)));
assert!(fixture.close());
assert_eq!(fixture.cleanup.status()?.operation_id, original_id);
assert!(fixture.retained.is_none());
assert!(fixture.services.reserve_resources(1, 0, 0).is_ok());
drop(guards);"#,
            1,
        ),
    ],
    expressions: &[(
        "std::thread::sleep(observation.wait_slice()?.min(Duration::from_millis(1)))",
        1,
    )],
    identifiers: &[],
    companions: &[
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/ram_source/stop.rs",
            required: &[
                (
                    r#"pub fn stop(
    &mut self,
    original: Option<crate::ram_control::RamCleanupOriginal<'_>>,
) -> (bool, Result<(), QemuRamSourceStopHistory>)"#,
                    1,
                ),
                (
                    r#"if !self.stop.cancel_entered {
    let before = self.stop_original_check(original).err();
    self.stop.observe(0, false, before);
    self.stop.cancel_entered = true;
    self.cancellation.store(true, Ordering::Release);
    if let Err(first) = self.wake.shutdown(Shutdown::Both) {
        self.stop.history.cancellation = Some(BackendOperationalCause::new(first));
        self.stop.version += 1;
    }
    self.stop.cancel_returned = true;
    let after = self.stop_original_check(original).err();
    self.stop.observe(0, true, after);
}"#,
                    1,
                ),
                (
                    r#"let before = self.stop_original_check(original).err();
self.stop.observe(2, false, before);
let observed = match self.worker.as_mut() {
    Some(worker) => {
        let observed = worker.native.poll();
        self.stop.history.native_status = worker.native.last_status();
        observed
    }
    None => Err(NativeJoinError::MissingOwner),
};
match observed {
    Ok(NativeJoinObservation::Returned) => {
        self.stop.join_returned = true;
        if let Some(join) = &mut self.launch_join { join.joined(); }
        self.capture_returned_outcome();
        drop(self.worker.take());
    }
    Ok(NativeJoinObservation::Pending) => {}
    Err(first) => {
        if self.stop.history.native.is_none() {
            self.stop.history.native = Some(first);
            self.stop.version += 1;
        }
    }
}
let after = self.stop_original_check(original).err();
self.stop.observe(2, true, after);"#,
                    1,
                ),
                (
                    r#"let before = self.stop_original_check(original);
self.stop.observe(1, false, before.as_ref().err().copied());
if let Ok(slice) = before { thread::sleep(slice.min(Duration::from_millis(20))); }
let after = self.stop_original_check(original);
self.stop.observe(1, true, after.as_ref().err().copied());
if before.is_err() || after.is_err() { return self.stop_observation(); }"#,
                    1,
                ),
                (
                    r#"fn stop_original_check(
    &self,
    original: Option<crate::ram_control::RamCleanupOriginal<'_>>,
) -> Result<Duration, HostSupervisionError> {
    let original = original.ok_or(HostSupervisionError::Unavailable)?;
    original.wait_slice()
}"#,
                    1,
                ),
                (
                    r#"fn stop_observation(&mut self) -> (bool, Result<(), QemuRamSourceStopHistory>) {
    let joined = self.stop.join_returned;
    let failure = self.stop.failed()
        && (!joined || !self.stop.outcome_captured || self.stop.reported != self.stop.version);
    if failure {
        self.stop.reported = self.stop.version;
        (joined, Err(self.stop.journal.snapshot(&self.stop.history)))
    } else { (joined, Ok(())) }
}"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/node/ram_cleanup.rs",
            required: &[(
                r#"pub(super) fn source(
    &mut self,
    index: usize,
    source: &mut Option<QemuRamSourceService>,
    original: Option<crate::ram_control::RamCleanupOriginal<'_>>,
) -> bool {
    self.entered = true;
    let Some(service) = source.as_mut() else { return true; };
    let (joined, status) = service.stop(original);
    if let Err(first) = status {
        if self.sources[index].as_ref() != Some(&first) {
            self.sources[index] = Some(first);
            self.unreported = true;
        }
        return false;
    }
    if joined { drop(source.take()); }
    joined
}"#,
                1,
            )],
        },
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/ram_control/cleanup_original.rs",
            required: &[
                (
                    r#"fn original(self) -> Result<&'a HostOperationGuard, HostSupervisionError> {
    match self.origin {
        CleanupOrigin::Direct(original, supervisor) => {
            if !original.belongs_to_supervisor(supervisor) {
                return Err(HostSupervisionError::InvalidBudget);
            }
            Ok(original)
        }
        #[cfg(target_os = "linux")]
        CleanupOrigin::Target(original) => original.checked_original(),
        #[cfg(target_os = "linux")]
        CleanupOrigin::Source(original) => original.checked_original(),
    }
}"#,
                    1,
                ),
                (
                    r#"pub(crate) fn wait_slice(self) -> Result<std::time::Duration, HostSupervisionError> {
    let original = self.original()?;
    original.verify_operation_class(HostOperationClass::Cleanup)?;
    original.wait_slice()
}"#,
                    1,
                ),
            ],
        },
        super::host_physical_custody::NATIVE_JOIN,
    ],
};

#[cfg(test)]
mod tests {
    use super::super::{mask_contract, read_companions, replace_one_obligation, source_pattern};
    use super::CONTRACT;

    #[test]
    fn same_node_ram_cleanup_requires_actual_join_saved_original_and_retained_history()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = crate::workspace::package_path(
            &crate::workspace_root().join("crates"),
            CONTRACT.package,
        )
        .join(format!("{}.rs", CONTRACT.target));
        let code = crate::scrub_comments_and_strings(&std::fs::read_to_string(path)?);
        let companions = read_companions(&CONTRACT)?;
        assert!(mask_contract(&CONTRACT, &code, &companions) != code);

        for (index, before, after) in [
            (
                0,
                "self.stop.journal.snapshot(&self.stop.history)",
                "self.stop.history.clone()",
            ),
            (
                0,
                "worker.native.poll()",
                "Ok(NativeJoinObservation::Returned)",
            ),
            (
                0,
                "self.stop.history.native_status = worker.native.last_status();",
                "discard_status();",
            ),
            (
                0,
                "self.stop.join_returned = true;",
                "self.stop.join_returned = false;",
            ),
            (
                0,
                "self.stop.observe(2, true, after);",
                "discard_post(after);",
            ),
            (
                0,
                "self.stop.reported = self.stop.version;",
                "discard_history_version();",
            ),
            (
                1,
                "if let Err(first) = status",
                "if let Err(first) = Ok::<(), QemuRamSourceStopHistory>(())",
            ),
            (
                1,
                "if joined { drop(source.take()); }",
                "drop(source.take());",
            ),
            (2, "!original.belongs_to_supervisor(supervisor)", "false"),
            (
                2,
                "CleanupOrigin::Target(original) => original.checked_original()",
                "CleanupOrigin::Target(original) => Ok(original.original())",
            ),
            (
                2,
                "original.verify_operation_class(HostOperationClass::Cleanup)?;",
                "accept_any_class();",
            ),
        ] {
            let clause = CONTRACT.companions[index]
                .required
                .iter()
                .find_map(|(clause, _)| {
                    source_pattern(clause)
                        .contains(&source_pattern(before))
                        .then_some(*clause)
                })
                .ok_or("the actual return obligation is absent")?;
            let original = crate::scrub_comments_and_strings(clause);
            let altered = replace_one_obligation(&original, &source_pattern(before), after);
            assert!(altered != original, "causal mutation missed {before}");
            let evidence = crate::scrub_comments_and_strings(&companions[index]);
            let changed = replace_one_obligation(&evidence, &source_pattern(clause), &altered);
            assert!(
                changed != evidence,
                "actual companion clause absent: {before}"
            );

            let mut mutated = companions.clone();
            mutated[index] = changed;
            let masked = mask_contract(&CONTRACT, &code, &mutated);
            assert!(
                masked == code,
                "changed physical return was classified: {before}"
            );
            assert!(!crate::flaky_escape_failures("unreviewed", "unreviewed", &masked).is_empty());
        }

        Ok(())
    }
}
