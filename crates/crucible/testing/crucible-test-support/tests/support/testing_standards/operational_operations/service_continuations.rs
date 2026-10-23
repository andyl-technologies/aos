//! Binds Service continuations to the same Main role and factual return cuts.
//!
//! No declaration grants a Source. Initial admission remains once-only; cleanup
//! advances existing owners and preserves raw first/post and terminal history.

use super::{Companion, Contract};

#[path = "service_continuations/clients.rs"]
mod clients;

pub(super) const CLIENT_CONTRACTS: &[Contract] = clients::CONTRACTS;

const DRIVER: &Contract = super::lifecycle_retirement::SERVICE_DRIVER;
const POST_BODY: &Contract = super::lifecycle_retirement::SERVICE_POST_BODY;
const RECEIPT: &Contract = super::lifecycle_retirement::SERVICE_RECEIPT;
const IMPORTED: &Contract = super::retained_continuations::IMPORTED_RETURN;
const _: () = assert!(DRIVER.companions.len() == 4 && IMPORTED.companions.len() == 2);

// These are references to existing exact facts, not copied protocol snapshots.
const SHARED: &[Companion] = &[
    Companion {
        path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/driver.rs",
        required: &[(
            r#"if !(body.has_source_return() || body.has_target_return()) || !returned {
 return Err(refusal("same native return or observer remains outstanding",));
 } let no_world = body.world_never_entered();
 if !transport_receiver::retry_transport_return(slot, &mut service, epoch)"#,
            1,
        )],
    },
    Companion {
        path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/driver.rs",
        required: DRIVER.required,
    },
    Companion {
        path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/post_body.rs",
        required: POST_BODY.required,
    },
    Companion {
        path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/prepared_retirement.rs",
        required: RECEIPT.required,
    },
    super::production_publication::ROLE_REPORTS,
    Companion {
        path: DRIVER.companions[2].path,
        required: DRIVER.companions[2].required,
    },
    Companion {
        path: IMPORTED.companions[0].path,
        required: IMPORTED.companions[0].required,
    },
    Companion {
        path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/prepared_service.rs",
        required: &[
            (
                r#"if service.epoch != self.key.epoch
 || slot.epoch.load(Ordering::Acquire) != self.key.epoch
 || slot.body_destroyed_epoch.load(Ordering::Acquire) < self.key.epoch
 || slot.controls_closed_epoch.load(Ordering::Acquire) < self.key.epoch
 || slot.worlds_returned_epoch.load(Ordering::Acquire) < self.key.epoch
 || slot.external_receivers.load(Ordering::Acquire) != 0 || slot.is(CleanupPhase::Free)"#,
                1,
            ),
            (r#".filter(|start| start.matches_main_role(&self.key))"#, 3),
        ],
    },
    Companion {
        path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/prepared_retirement.rs",
        required: &[
            (
                r#"let retirement = PreparedSourceRetirement::for_key(self.key.copy_selection());
retirement.abandon_export(); retirement.request_retirement(); PreparedSourceFailure {
access: None, receiver: None, retirement, phase, }"#,
                1,
            ),
            (
                r#"let report_reference = key.queue.upgrade().is_some_and(|queue| {
queue.slots.get(key.index).is_some_and(|slot| report_refs::register(slot, key.epoch)) });"#,
                1,
            ),
            (
                r#"if !self.report_reference { return Err(self); } match
terminal::take_terminal_body_with_reports(&self.key, &mut self.access, &mut
self.receiver,) { Ok(body) => { self.report_reference = false; Ok(body) } Err(_) =>
Err(self), }"#,
                1,
            ),
            (
                r#"drop(self.access.take()); drop(self.receiver.take());
 if !self.report_reference { return; }
 self.abandon_export(); terminal::return_report_reference(&self.key, false);"#,
                1,
            ),
        ],
    },
];

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-daemon",
        target: "src/packaged_qemu_executor/guarded/continuation",
        required: &[
            (r#"loop {"#, 0),
            (r#"while "#, 0),
            (r#"thread::sleep("#, 0),
            (r#"Instant::now("#, 0),
            (r#"HostOperationSupervisor::new("#, 1),
            (r#".begin("#, 2),
            (
                r#"let preparation = preparation_supervisor.begin(HostOperationClass::Preparation)"#,
                1,
            ),
            (r#"check_preparation(&preparation, &cancellation)?;"#, 9),
            (
                r#"preparation.complete().map_err(|error| { cancellation.cancel();"#,
                1,
            ),
            (r#"let mut retirement = prepared.into_retirement();"#, 1),
            (
                r#".map_err(|first| GuardedContinuationError::Retirement { first, custody:
source.failure("retry genesis retirement"), })?"#,
                1,
            ),
            (
                r#"return Err(GuardedContinuationError::Retirement { first:
crate::PreparedSourceRefusal::Pending, custody: source.failure("retain pending genesis
retirement"), });"#,
                1,
            ),
            (
                r#"let terminal = retirement.finish().map_err(|_retained| {
GuardedContinuationError::Retirement { first: crate::PreparedSourceRefusal::Pending,
custody: source.failure("retain genesis terminal extraction"), } })?;"#,
                1,
            ),
            (r#"check_genesis_retirement(terminal)?;"#, 1),
            (
                r#"if terminal.first_failure().is_some() { return Err(GuardedContinuationError::Terminal(Box::new(terminal))); }"#,
                1,
            ),
            (r#"drop(retirement)"#, 0),
            (r#"drop(_retained)"#, 0),
        ],
        expressions: &[(r#"retirement.retry()"#, 1)],
        identifiers: &[],
        companions: SHARED,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/packaged_qemu_executor/guarded/imported",
        required: &[
            (r#"loop {"#, 0),
            (r#"while "#, 0),
            (r#"thread::sleep("#, 0),
            (r#"Instant::now("#, 0),
            (r#"HostOperationSupervisor::new("#, 0),
            (r#".begin("#, 0),
            (
                r#"let (capsule, owner) = imported.into_start_custody();"#,
                1,
            ),
            (r#"prepare_imported_service_source(capsule)"#, 1),
            (r#"let receiver = service.retain_receiver_in_main()"#, 1),
            (
                r#"let receiver_return = receiver.return_after_alias_destruction().err()"#,
                1,
            ),
            (
                r#"let _physical_attempt = retirement.retry(); let capsule = match
service.with_start_after_world_return(|start| {
start.take_unlaunched_import_after_world_return() })"#,
                1,
            ),
            (
                r#"let closing = retirement.retry(); if !matches!(closing, Ok(true))"#,
                1,
            ),
            (r#"failure.retain_retirement_refusal(first);"#, 1),
            (
                r#"Ok(terminal) if terminal.first_failure().is_some() =>"#,
                1,
            ),
            (r#"failure.retain_terminal(terminal);"#, 1),
            (
                r#"catalog.begin_retained_imported_checkpoint(&self.inner.checkpoints, capsule, owner, cancellation,)"#,
                1,
            ),
            (r#"drop(retirement)"#, 0),
            (r#"drop(_retained)"#, 0),
        ],
        expressions: &[(r#"retirement.retry()"#, 2)],
        identifiers: &[],
        companions: SHARED,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/packaged_qemu_executor/guarded/receiving",
        required: &[
            (r#"loop {"#, 0),
            (r#"while "#, 0),
            (r#"thread::sleep("#, 0),
            (r#"Instant::now("#, 0),
            (r#"HostOperationSupervisor::new("#, 0),
            (r#".begin("#, 0),
            (
                r#"return_to.return_maintenance(basis, maintenance, semantic_shutdown); retirement.request_retirement();"#,
                1,
            ),
            (
                r#"drop(self.aliases.take()); drop(self.lifecycle.take());"#,
                1,
            ),
            (
                r#"if self.completed { return if self.terminal_failure_returned {
Err(ReceivingExecutionPreparationError::HistoryAlreadyReturned) } else { Ok(()) }; }"#,
                1,
            ),
            (
                r#"if !lifecycle.return_to_main() { return Err(ReceivingExecutionPreparationError::ReceiverPending); }"#,
                1,
            ),
            (
                r#"self.lifecycle = None; let result = finish_service_retirement(&mut self.source, &mut self.retirement);"#,
                1,
            ),
            (
                r#"let owner = retirement.take().ok_or(ReceivingExecutionPreparationError::Unavailable)?;"#,
                1,
            ),
            (
                r#"if history.first_failure().is_some() {
Err(ReceivingExecutionPreparationError::Terminal(history)) } else { drop(history); Ok(())
}"#,
                1,
            ),
            (
                r#"Err(owner) => { *retirement = Some(owner); Err(ReceivingExecutionPreparationError::ReceiverPending) }"#,
                1,
            ),
            (r#"drop(retirement)"#, 0),
            (r#"drop(_retained)"#, 0),
        ],
        expressions: &[(r#"owner.retry()"#, 1)],
        identifiers: &[],
        companions: SHARED,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/packaged_qemu_executor/hot_fork/retained_service/retirement_input",
        required: &[
            (r#"loop {"#, 0),
            (r#"while "#, 0),
            (r#"thread::sleep("#, 0),
            (r#"Instant::now("#, 0),
            (r#"HostOperationSupervisor::new("#, 0),
            (r#".begin("#, 0),
            (
                r#"pub(super) fn retry_after_world_cleanup(&mut self) -> bool {"#,
                1,
            ),
            (
                r#"if let Some(aliases) = self.aliases.take() { match aliases {
RetirementAliases::Basis(basis) => drop(basis), RetirementAliases::Maintenance(imported)
=> { self.returned = Some(imported.retire_unpublished()); } } self.aliases_destroyed =
true; }"#,
                1,
            ),
            (r#"if !self.aliases_destroyed { return false; }"#, 1),
            (
                r#"if let Some(returned) = &mut self.returned { if !returned.retry_parent_return() { return false; } }"#,
                1,
            ),
            (
                r#"if let Some(receiver) = self.receiver.take() { self.receiver_return_attempted = true; if
let Err(receiver) = receiver.return_after_alias_destruction() {
self.receiver_return_refused = true; self.receiver = Some(receiver); return false; } }"#,
                1,
            ),
            (
                r#"self.aliases_destroyed && self.aliases.is_none() && self.receiver.is_none() &&
self.returned.as_ref().is_none_or(|returned| returned.parent_returned())"#,
                1,
            ),
            (r#"drop(retirement)"#, 0),
            (r#"drop(_retained)"#, 0),
        ],
        expressions: &[(r#"returned.retry_parent_return()"#, 1)],
        identifiers: &[("retry_after_world_cleanup", 1)],
        companions: SHARED,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/packaged_qemu_executor/hot_fork/retained_service/startup",
        required: &[
            (r#"loop {"#, 0),
            (r#"while "#, 0),
            (r#"thread::sleep("#, 0),
            (r#"Instant::now("#, 0),
            (r#"HostOperationSupervisor::new("#, 0),
            (r#".begin("#, 1),
            (
                r#"if self.attempted || self.first.is_some() || !matches!(self.phase,
ServiceStartPhase::Empty) { return Err(RetainedServiceStartRefusal); }
self.verify_preclaim()?; self.run_admission(operation)"#,
                1,
            ),
            (
                r#"pub(crate) fn retry_before_world_cleanup(&mut self) -> bool {
self.retry_cleanup(ServiceCleanupBoundary::Main { world_returned: false, }) }"#,
                1,
            ),
            (
                r#"pub(crate) fn retry_after_world_cleanup(&mut self) -> bool {
self.retry_cleanup(ServiceCleanupBoundary::Main { world_returned: true, }) }"#,
                1,
            ),
            (
                r#"fn world_returned(&self) -> bool {
matches!(self, Self::Main { world_returned: true }) }"#,
                1,
            ),
            (
                r#"fn releases_actor(&self) -> bool { match self {
Self::Main { .. } => true, #[cfg(test)]
Self::ComponentNoNative { release_actor } => *release_actor, } }"#,
                1,
            ),
            (r#"let world_returned = boundary.world_returned();"#, 1),
            (
                r#"fn retry_cleanup(&mut self,
admission: &mut Option<crucible_host_resources::host_supervision::HostOperationGuard>,
imported: &mut Option<crate::imported_checkpoint::RetainedImportedCheckpoint>,
imported_return: &mut Option<crate::imported_checkpoint::ImportedCheckpointReturn>,
release_actor: bool,) -> Result<(), HostOperationalError> {"#,
                1,
            ),
            (
                r#"if self.released { return Ok(()); }
if let Some(watchdog) = self.watchdog.take() {
self.stop = Some(watchdog.stop_service_owned()); self.completion_attempted = true;
} else if !self.completion_attempted { self.completion_attempted = true;
if self.complete_outer && let Some(supervisor) = &self.supervisor {
self.completion = supervisor.complete().err(); } }"#,
                1,
            ),
            (
                r#"if let Some(imported) = imported.take() {
*imported_return = Some(imported.retire_unpublished()); }
drop(admission.take()); drop(self.supervisor.take()); drop(self.prepared.take());
if self.stop.as_ref().is_some_and(|stop| stop.join_failure.is_some()) {
return Err(HostOperationalError::Unavailable); }"#,
                1,
            ),
            (
                r#"if self.reserved && release_actor {
self.registry.release_service_after_cleanup(self.owner)?; }
self.released = !self.reserved || release_actor; Ok(())"#,
                1,
            ),
            (
                r#"match result { Ok(()) => self.retry_parent_returns(), Err(first) => {
if self.cleanup.is_none() { self.cleanup = Some(first); } false } }"#,
                1,
            ),
            (r#"partial.reserved = true;"#, 1),
            (r#"let supervisor = match &factory.outer_supervisor"#, 1),
            (
                r#"let result = operation(self); if let Some(admission) = self.admission.as_ref() {
self.admission_post = admission.wait_slice().err(); if
!self.admission_completion_attempted { self.admission_completion_attempted = true;
self.admission_completion = admission.complete().err(); } }"#,
                1,
            ),
            (
                r#"if self.adopted_retirement_input.as_ref().is_some_and(|input| !input.is_returned()) { return false; }"#,
                1,
            ),
            (
                r#"if world_returned && self.imported_export_pending { return false; }"#,
                1,
            ),
            (
                r#"ServiceStartPhase::Partial(partial) if !world_returned => partial.retry_cleanup("#,
                1,
            ),
            (
                r#"ServiceStartPhase::Closing(partial) => partial.retry_cleanup("#,
                1,
            ),
            (
                r#"if let Some(returned) = &mut self.imported_return && !returned.retry_parent_return() { return false; }"#,
                1,
            ),
            (
                r#"let Some(receiver) = self.parent_receiver.take() else { return true; };"#,
                1,
            ),
            (
                r#"Err(receiver) => { self.parent_return_refused = true; self.parent_receiver = Some(receiver); false }"#,
                1,
            ),
            (
                r#"if self.stop.as_ref().is_some_and(|stop| stop.join_failure.is_some()) { return
Err(HostOperationalError::Unavailable); }"#,
                1,
            ),
            (
                r#"self.registry.release_service_after_cleanup(self.owner)?;"#,
                1,
            ),
            (r#"self.released = !self.reserved || release_actor;"#, 1),
            (
                r#"aliases_returned && self.pending_selected_root.is_none() && match &self.phase"#,
                1,
            ),
            (r#"ServiceStartPhase::Ready(_) => false,"#, 1),
            (r#"ServiceStartPhase::Empty => false,"#, 1),
            (r#"drop(retirement)"#, 0),
            (r#"drop(_retained)"#, 0),
            (
                r#"registry.reserve_service_with_assignment_headroom(owner, service, assignment)?;
} ServiceHeadroom::AdmittedAssignment(existing_owner) => {
registry.reserve_service_with_admitted_assignment(owner, service, existing_owner,)?;
} }
let ServiceStartPhase::Partial(partial) = &mut *phase else {
return Err(HostOperationalError::Unavailable.into());
}; partial.reserved = true; let supervisor = match &factory.outer_supervisor"#,
                1,
            ),
        ],
        expressions: &[
            (
                r#"self.retry_cleanup(ServiceCleanupBoundary::Main { world_returned: false, })"#,
                1,
            ),
            (
                r#"self.retry_cleanup(ServiceCleanupBoundary::Main { world_returned: true, })"#,
                1,
            ),
            (
                r#"partial.retry_cleanup(&mut self.admission, &mut self.imported,
&mut self.imported_return, boundary.releases_actor(),)"#,
                2,
            ),
            (r#"input.retry_after_world_cleanup()"#, 2),
            (r#"self.retry_parent_returns()"#, 3),
            (r#"returned.retry_parent_return()"#, 1),
        ],
        identifiers: &[
            ("retry_adopted_aliases_after_world_cleanup", 1),
            ("retry_adopted_aliases_before_world_cleanup", 1),
            ("retry_before_world_cleanup", 1),
            ("retry_after_world_cleanup", 3),
            ("retry_cleanup", 6),
            ("retry_parent_returns", 4),
        ],
        companions: SHARED,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/packaged_qemu_executor/hot_fork/retained_service/startup/component",
        required: &[
            (r#"loop {"#, 0),
            (r#"while "#, 0),
            (r#"thread::sleep("#, 0),
            (r#"Instant::now("#, 0),
            (r#"HostOperationSupervisor::new("#, 0),
            (r#".begin("#, 0),
            (
                r#"startup: RetainedServiceStart::empty_unbound(), quarantine_actor: false,"#,
                1,
            ),
            (
                r#"let result = owner.startup.run_admission(|startup| { RetainedServiceStart::start_fields("#,
                1,
            ),
            (r#"ServiceContextBinding::ComponentNoNative,"#, 1),
            (
                r#"if self.startup.is_released() { Ok(()) } else { Err(ComponentServiceCleanupRefusal) }"#,
                1,
            ),
            (
                r#"pub(in crate::packaged_qemu_executor) fn retain_after_unknown_cleanup(mut self) { self.quarantine_actor = true; }"#,
                1,
            ),
            (r#"drop(retirement)"#, 0),
            (r#"drop(_retained)"#, 0),
        ],
        expressions: &[
            (
                r#"owner.startup.retry_cleanup(ServiceCleanupBoundary::ComponentNoNative { release_actor: true, })"#,
                1,
            ),
            (
                r#"self.startup.retry_cleanup(ServiceCleanupBoundary::ComponentNoNative { release_actor: !self.quarantine_actor, })"#,
                2,
            ),
        ],
        identifiers: &[],
        companions: SHARED,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/packaged_qemu_executor/hot_fork/source_service",
        required: &[
            (r#"loop {"#, 0),
            (r#"while "#, 0),
            (r#"thread::sleep("#, 0),
            (r#"Instant::now("#, 0),
            (r#"HostOperationSupervisor::new("#, 0),
            (r#".begin("#, 0),
            (r#"let receiver = service.retain_receiver_in_main()"#, 1),
            (
                r#"let mut projection = SourceContextProjection { service, context: None, receiver:
Some(receiver), destruction_started: false, };"#,
                1,
            ),
            (r#"projection.context = Some(ready.context().clone());"#, 1),
            (
                r#"self.destruction_started = true; drop(self.context.take());"#,
                2,
            ),
            (
                r#"if self.destruction_started { return; } self.service.prepared_selector().request_retirement();"#,
                1,
            ),
            (r#"match (result, projection.finish())"#, 1),
            (r#"Ok(output) => { drop(output); None }"#, 1),
            (r#"let mut retirement = service.into_retirement();"#, 1),
            (
                r#"Err(retirement) => { return Err(RetainedSourceCaptureFailure { first: None,
receiver_return: None, retirement: Some(retirement), retirement_refusal: refusal,
terminal: None, }); }"#,
                1,
            ),
            (
                r#"if terminal.first_failure().is_some() || refusal.is_some() { return
Err(RetainedSourceCaptureFailure { first: None, receiver_return: None, retirement: None,
retirement_refusal: refusal, terminal: Some(std::sync::Mutex::new(terminal)), }); }"#,
                1,
            ),
            (r#"drop(retirement)"#, 0),
            (r#"drop(_retained)"#, 0),
        ],
        expressions: &[(r#"retirement.retry()"#, 1)],
        identifiers: &[],
        companions: SHARED,
    },
];

// Only mutant construction is extended; production matching stays unchanged.
#[cfg(test)]
pub(super) fn altered_expression(expression: &str) -> String {
    if !CONTRACTS.iter().chain(CLIENT_CONTRACTS).any(|contract| {
        contract
            .expressions
            .iter()
            .any(|(reviewed, _)| *reviewed == expression)
    }) {
        return expression.to_owned();
    }
    let Some(offset) = expression.find('(') else {
        return expression.to_owned();
    };
    let mut changed = expression.to_owned();
    changed.insert_str(offset + 1, "foreign_role, ");
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_escape(_contract: &Contract, code: &str) -> bool {
        !super::super::super::super::flaky_escape_failures("unreviewed", "unreviewed", code)
            .is_empty()
    }

    fn rejects(contract: &Contract, code: &str, companions: &[String]) {
        let masked = super::super::mask_contract(contract, code, companions);
        assert!(
            has_escape(contract, &masked),
            "changed protocol lost its lexical witness"
        );
        let composed =
            super::super::super::mask_after_operations(contract.package, contract.target, &masked);
        assert!(
            has_escape(contract, &composed),
            "composed scanner hid the changed protocol"
        );
    }

    #[test]
    fn service_continuations_reject_repeated_work_and_foreign_owners()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = super::super::super::super::super::workspace_root();
        for contract in CONTRACTS {
            let source = std::fs::read_to_string(
                crate::workspace::package_path(&root.join("crates"), contract.package)
                    .join(format!("{}.rs", contract.target)),
            )?;
            let code = super::super::super::super::scrub_comments_and_strings(&source);
            let companions = super::super::read_companions(contract)?;
            assert!(has_escape(contract, &code));
            assert!(!has_escape(
                contract,
                &super::super::mask_contract(contract, &code, &companions)
            ));

            for (expression, _) in contract.expressions {
                for replacement in [
                    format!("loop {{ {expression}; }}"),
                    format!("while keep_running {{ {expression}; }}"),
                    altered_expression(expression),
                ] {
                    let changed = super::super::replace_one_obligation(
                        &code,
                        &super::super::source_pattern(expression),
                        &replacement,
                    );
                    assert_ne!(changed, code);
                    rejects(contract, &changed, &companions);
                }
            }
            for effect in [
                "thread::sleep(Duration::from_millis(1));",
                "supervisor.begin(HostOperationClass::Preparation);",
                "HostOperationSupervisor::new(budgets, None);",
                "retry_failed_test();",
                "retry!(operation);",
                "rerun_failed_test();",
            ] {
                let changed = format!("{code}\n{effect}");
                rejects(contract, &changed, &companions);
            }
        }
        Ok(())
    }

    #[test]
    fn genesis_retirement_requires_each_protected_report_before_pin_return()
    -> Result<(), Box<dyn std::error::Error>> {
        let contract = &CONTRACTS[0];
        let root = super::super::super::super::super::workspace_root();
        let source = std::fs::read_to_string(root.join(
            "crates/crucible/control/crucible-daemon/src/packaged_qemu_executor/guarded/continuation.rs",
        ))?;
        let code = super::super::super::super::scrub_comments_and_strings(&source);
        let companions = super::super::read_companions(contract)?;
        for phase in [
            "retry genesis retirement",
            "retain pending genesis retirement",
            "retain genesis terminal extraction",
        ] {
            let needle = format!("custody: source.failure(\"{phase}\"),");
            // The real scanner erases literal contents, so select the actual
            // raw occurrence before scrubbing; each branch is mutated once.
            let offset = source.find(&needle).ok_or("protected branch is absent")?;
            let mut changed = source.clone();
            changed.replace_range(offset..offset + needle.len(), "");
            let changed = super::super::super::super::scrub_comments_and_strings(&changed);
            rejects(contract, &changed, &companions);
        }
        let mut changed = companions.clone();
        let index = SHARED
            .iter()
            .position(|binding| binding.path.ends_with("/report_refs.rs"))
            .ok_or("actual report pin proof is absent")?;
        let required = SHARED[index]
            .required
            .iter()
            .find(|(clause, _)| clause.contains("actual_epoch != epoch"))
            .ok_or("actual report epoch check is absent")?;
        let original = super::super::super::super::scrub_comments_and_strings(&changed[index]);
        changed[index] = super::super::replace_one_obligation(
            &original,
            &super::super::source_pattern(required.0),
            "unproven_report_pin();",
        );
        rejects(contract, &code, &changed);
        Ok(())
    }

    #[test]
    fn service_startup_requires_same_cleanup_inputs_and_physical_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let contract = CONTRACTS
            .iter()
            .find(|contract| contract.target.ends_with("/retained_service/startup"))
            .ok_or("startup contract is absent")?;
        let root = super::super::super::super::super::workspace_root();
        let source = std::fs::read_to_string(
            crate::workspace::package_path(&root.join("crates"), contract.package)
                .join(format!("{}.rs", contract.target)),
        )?;
        let code = super::super::super::super::scrub_comments_and_strings(&source);
        let companions = super::super::read_companions(contract)?;
        assert!(!has_escape(
            contract,
            &super::super::mask_contract(contract, &code, &companions)
        ));

        let cases = [
            (
                "fn world_returned(&self) -> bool { matches!(self, Self::Main { world_returned: true }) }",
                "fn world_returned(&self) -> bool { true }",
            ),
            (
                "Self::ComponentNoNative { release_actor } => *release_actor,",
                "Self::ComponentNoNative { release_actor } => true,",
            ),
            (
                "self.retry_cleanup(ServiceCleanupBoundary::Main { world_returned: false, })",
                "self.retry_cleanup(ServiceCleanupBoundary::Main { world_returned: true, })",
            ),
            (
                "self.retry_cleanup(ServiceCleanupBoundary::Main { world_returned: true, })",
                "self.retry_cleanup(ServiceCleanupBoundary::Main { world_returned: false, })",
            ),
            (
                "partial.retry_cleanup(&mut self.admission, &mut self.imported, &mut self.imported_return, boundary.releases_actor(),)",
                "partial.retry_cleanup(&mut foreign_admission, &mut self.imported, &mut self.imported_return, boundary.releases_actor(),)",
            ),
            (
                "self.admission_post = admission.wait_slice().err();",
                "self.admission_post = None;",
            ),
            (
                "self.stop = Some(watchdog.stop_service_owned()); self.completion_attempted = true;",
                "discard_stop(watchdog.stop_service_owned()); self.completion_attempted = true;",
            ),
            (
                "if self.complete_outer && let Some(supervisor) = &self.supervisor { self.completion = supervisor.complete().err(); }",
                "if self.complete_outer && let Some(supervisor) = &self.supervisor { self.completion = None; }",
            ),
            ("if self.reserved && release_actor {", "if self.reserved {"),
            (
                "drop(admission.take()); drop(self.supervisor.take()); drop(self.prepared.take());",
                "drop(self.supervisor.take()); drop(self.prepared.take());",
            ),
        ];
        for (before, after) in cases {
            let needle = super::super::source_pattern(before);
            assert!(
                contract
                    .required
                    .iter()
                    .chain(contract.expressions)
                    .any(|(clause, _)| super::super::source_pattern(clause).contains(&needle))
            );
            let changed = super::super::replace_one_obligation(&code, &needle, after);
            assert_ne!(changed, code, "missing actual cleanup cut: {before}");
            assert_eq!(
                super::super::mask_contract(contract, &changed, &companions),
                changed,
                "changed cleanup custody still matched: {before}"
            );
            rejects(contract, &changed, &companions);
        }
        Ok(())
    }
}
