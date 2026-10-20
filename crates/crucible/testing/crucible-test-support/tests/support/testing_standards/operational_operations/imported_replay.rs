//! Binds imported replay to its actual return pair and terminal disposition.
//!
//! Terminal extraction is irreversible even when its history is negative. The
//! source contract does not issue Main authority or qualify a native replay.

use super::{Companion, Contract};

const FINISH: &str = r#"pub fn finish(&mut self) -> Result<(), ImportedProductionReplayError> {
    if self.closed { return Ok(()); }
    if let Some(source) = self.prepared.as_ref() {
        if self.unaccepted_input.is_some() {
            source.service_main_handle()
                .adopt_retirement_input(&mut self.unaccepted_input)
                .map_err(|first| {
                    ImportedProductionReplayError::Prepared(
                        source.failure_with_refusal("retry imported replay input return", first),
                    )
                })?;
        }
        if let Some(lifecycle) = self.lifecycle.as_mut() {
            lifecycle.return_to_main();
        }
    }
    if let Some(source) = self.prepared.take() {
        self.retirement = Some(source.into_retirement());
    }
    let retirement = self.retirement.as_mut()
        .ok_or(ImportedProductionReplayError::Unavailable)?;
    if !retirement.retry().map_err(ImportedProductionReplayError::Retirement)? {
        return Err(ImportedProductionReplayError::Retirement(
            crate::PreparedSourceRefusal::Pending,
        ));
    }
    let Some(retirement) = self.retirement.take() else {
        return Err(ImportedProductionReplayError::Unavailable);
    };
    match retirement.finish() {
        Ok(terminal) => {
            self.closed = true;
            if terminal.first_failure().is_some() {
                return Err(ImportedProductionReplayError::Terminal(terminal));
            }
            drop(terminal);
            Ok(())
        }
        Err(retirement) => {
            self.retirement = Some(retirement);
            Err(ImportedProductionReplayError::Retirement(
                crate::PreparedSourceRefusal::Pending,
            ))
        }
    }
}"#;

// Reuse complete actual saved-Original and independent-post obligations.
const SAVED_WORLD: Companion = Companion {
    path: super::host_physical_custody::NORMAL_WORLD.companions[1].path,
    required: super::host_physical_custody::NORMAL_WORLD.companions[1].required,
};
const SAVED_CLEANUP: Companion = Companion {
    path: super::retained_continuations::WORLD_COMPANIONS[5].path,
    required: super::retained_continuations::WORLD_COMPANIONS[5].required,
};

pub(super) const CONTRACTS: &[Contract] = &[Contract {
    package: "crucible-daemon",
    target: "src/qemu_baked_genesis/imported_replay",
    required: &[
        ("if self.closed { return Ok(()); }", 1),
        (
            r#"if let Some(source) = self.prepared.as_ref() {
    if self.unaccepted_input.is_some() {
        source.service_main_handle()
            .adopt_retirement_input(&mut self.unaccepted_input)
            .map_err(|first| {
                ImportedProductionReplayError::Prepared(
                    source.failure_with_refusal("retry imported replay input return", first),
                )
            })?;
    }
    if let Some(lifecycle) = self.lifecycle.as_mut() {
        lifecycle.return_to_main();
    }
}"#,
            1,
        ),
        (
            r#"if let Some(source) = self.prepared.take() {
    self.retirement = Some(source.into_retirement());
}
let retirement = self.retirement.as_mut()
    .ok_or(ImportedProductionReplayError::Unavailable)?;"#,
            1,
        ),
        (
            r#".map_err(ImportedProductionReplayError::Retirement)? {
    return Err(ImportedProductionReplayError::Retirement(
        crate::PreparedSourceRefusal::Pending,
    ));
}"#,
            1,
        ),
        (
            r#"let Some(retirement) = self.retirement.take() else {
    return Err(ImportedProductionReplayError::Unavailable);
};
match retirement.finish() {
    Ok(terminal) => {
        self.closed = true;
        if terminal.first_failure().is_some() {
            return Err(ImportedProductionReplayError::Terminal(terminal));
        }
        drop(terminal);
        Ok(())
    }
    Err(retirement) => {
        self.retirement = Some(retirement);
        Err(ImportedProductionReplayError::Retirement(
            crate::PreparedSourceRefusal::Pending,
        ))
    }
}"#,
            1,
        ),
        (
            r#"lifecycle: Option<MainSourceLifecycle>, prepared: Option<ReplaySource>,
retirement: Option<crate::PreparedSourceRetirement>,
unaccepted_input: Option<ServiceRetirementInput>,"#,
            1,
        ),
        (
            r#"Ok(lifecycle) => {
    match lifecycle.into_main_lifecycle() {
        Ok(lifecycle) => replay.lifecycle = Some(lifecycle),
        Err(first) => unissued = Some(first),
    }
    None
}"#,
            1,
        ),
        (
            r#"impl Drop for ImportedProductionCheckpointReplay {
    fn drop(&mut self) {
        if let Some(mut lifecycle) = self.lifecycle.take() {
            lifecycle.return_to_main();
        }
        if let Some(source) = self.prepared.take() {
            drop(source.into_retirement());
        }
    }
}"#,
            1,
        ),
        ("HostOperationSupervisor::new(", 0),
        ("Instant::now(", 0),
        ("thread::sleep(", 0),
    ],
    expressions: &[("retirement.retry()", 1)],
    identifiers: &[],
    companions: &[
        Companion {
            path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/returned.rs",
            required: &[
                (
                    r#"Live {
    lifecycle: ProductionVmLifecycleLoop,
    carrier: Box<ProductionVmConstructionCustody>,
    destination: SourceBodyReturn,
},"#,
                    1,
                ),
                (
                    r#"pub fn return_to_main(&mut self) {
    let MainLifecycleState::Live { lifecycle, carrier, destination, } =
        std::mem::replace(&mut self.state, MainLifecycleState::Returned)
    else { return; };
    let carrier = carrier.install_owned_return(lifecycle);
    let receipt = destination.deliver(carrier);
    drop(receipt);
}"#,
                    1,
                ),
                (
                    "impl Drop for MainSourceLifecycle { fn drop(&mut self) { self.return_to_main(); } }",
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/prepared_service.rs",
            required: &[(
                r#"if slot.epoch.load(Ordering::Acquire) != self.key.epoch
    || cell.epoch != self.key.epoch
    || !(slot.is(CleanupPhase::Reserved) || slot.is(CleanupPhase::RetryingPrepared)
        || slot.is(CleanupPhase::PostBodyPending) || slot.is(CleanupPhase::Returning) || quarantined)
    || (!quarantined && cell.owner.is_some())
    || (!quarantined && cell.handoff
        && (slot.body_destroyed_epoch.load(Ordering::Acquire) < self.key.epoch
            || slot.controls_closed_epoch.load(Ordering::Acquire) < self.key.epoch))
    || cell.retirement_input.is_some() || cell.retirement_input_reserved
    || !input.as_ref().is_some_and(|input| input.matches_main_role(&self.key))
{
    return Err(unavailable("same receiving input destination is foreign or occupied",));
}
cell.retirement_input = input.take();
if poisoned || quarantined { slot.publish(CleanupPhase::DestructionRefused); }
Ok(())"#,
                1,
            )],
        },
        Companion {
            path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/prepared_retirement.rs",
            required: &[
                (
                    r#"if slot.epoch.load(Ordering::Acquire) != self.key.epoch {
    return Err(PreparedSourceRefusal::RoleUnavailable);
}
self.request_retirement();
let attempted = retry_slot(slot, Some(self.key.epoch));
if slot.is(CleanupPhase::TerminalReady) { return Ok(true); }
if slot.is(CleanupPhase::DestructionRefused) {
    return Err(PreparedSourceRefusal::DestructionUncertain);
}
attempted.map_err(|_| PreparedSourceRefusal::Pending)?;
Ok(false)"#,
                    1,
                ),
                (
                    r#"pub fn finish(mut self) -> Result<ProductionVmConstructionPostBody, Self> {
    if !self.report_reference { return Err(self); }
    match terminal::take_terminal_body_with_reports(&self.key, &mut self.access, &mut self.receiver,) {
        Ok(body) => { self.report_reference = false; Ok(body) }
        Err(_) => Err(self),
    }
}"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/terminal.rs",
            required: &[
                (
                    r#"let queue = key.queue.upgrade().ok_or(PreparedSourceRefusal::RoleUnavailable)?;
let slot = queue.slots.get(key.index).ok_or(PreparedSourceRefusal::RoleUnavailable)?;
let mut prepared = slot.prepared.try_lock().map_err(|_| PreparedSourceRefusal::Borrowed)?;
let mut service = slot.service.try_lock().map_err(|_| PreparedSourceRefusal::Borrowed)?;
let mut cell = slot.cell.try_lock().map_err(|_| PreparedSourceRefusal::Borrowed)?;"#,
                    1,
                ),
                (
                    r#"if cell.epoch != key.epoch || prepared.epoch != key.epoch
    || service.epoch != key.epoch || slot.epoch.load(Ordering::Acquire) != key.epoch
    || !slot.is(CleanupPhase::TerminalReady)
{ return Err(PreparedSourceRefusal::Pending); }"#,
                    1,
                ),
                (
                    r#"if (access.is_some() && prepared.terminal_access.is_some())
    || (receiver.is_some() && prepared.terminal_receiver.is_some())
    || service.role.is_none() || cell.retirement_input.is_some()
    || cell.retirement_input_reserved || cell.panic_payload.is_some()
    || prepared.panic_payload.is_some() || service.panic_payload.is_some()
    || service.queued_owner.is_some() || service.queued_owner_borrowed
    || cell.owner.is_some() || cell.controls.is_some()
    || prepared.pending_post_body.is_some() || !prepared.body_closed || !prepared.post_body_taken
    || slot.external_receivers.load(Ordering::Acquire) != 0
    || service.transport_receiver.is_some()
    || service.completed_transport_sequence != service.transport_sequence
    || service.start.as_ref().is_some_and(|start| !start.is_released())
{ return Err(PreparedSourceRefusal::Pending); }"#,
                    1,
                ),
                (
                    r#"if cell.post_body.is_some() {
    return Err(PreparedSourceRefusal::Pending);
}
let Some(body) = service.return_body.as_ref() else {
    return Err(PreparedSourceRefusal::Pending);
};
if !body.native_returns_observed() || body.terminal.is_some() {
    return Err(PreparedSourceRefusal::Pending);
}
if !slot.claim(CleanupPhase::TerminalReady, CleanupPhase::TerminalOwned) {
    return Err(PreparedSourceRefusal::Pending);
}
if slot.report_references.load(Ordering::Acquire) != 1 {
    let _restored = slot.claim(CleanupPhase::TerminalOwned, CleanupPhase::TerminalReady);
    return Err(PreparedSourceRefusal::Pending);
}"#,
                    1,
                ),
                (
                    r#"let Some(mut body) = service.return_body.take() else {
    slot.publish(CleanupPhase::DestructionRefused);
    return Err(PreparedSourceRefusal::DestructionUncertain);
};
cell.handoff = false;
cell.controls_bound = false;
cell.owner_cleanup_complete = false;
cell.owner_post_body_taken = false;
let mut fields = TerminalFields::take(&mut prepared, &mut service, &mut cell);
if fields.access.is_none() { fields.access = access.take(); }
if fields.receiver.is_none() { fields.receiver = receiver.take(); }
body.terminal = Some(TerminalCustody {
    key: key.copy_selection(), queue: Arc::clone(&queue), fields,
});
Ok(body)"#,
                    1,
                ),
            ],
        },
        SAVED_WORLD,
        SAVED_CLEANUP,
        // Keep the complete same-file route mandatory without deleting its
        // sole real retry witness when a local omission control runs.
        Companion {
            path: "crates/crucible/control/crucible-daemon/src/qemu_baked_genesis/imported_replay.rs",
            required: &[(FINISH, 1)],
        },
    ],
}];

#[cfg(test)]
pub(super) fn altered_expression(expression: &str) -> String {
    match expression {
        "retirement.retry()" => "foreign_retirement.retry()".to_owned(),
        _ => expression.to_owned(),
    }
}

#[test]
fn imported_replay_requires_same_body_terminal_disposition_and_saved_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let contract = &CONTRACTS[0];
    let path =
        crate::workspace::package_path(&crate::workspace_root().join("crates"), contract.package)
            .join(format!("{}.rs", contract.target));
    let code = crate::scrub_comments_and_strings(&std::fs::read_to_string(path)?);
    let companions = super::read_companions(contract)?;
    let masked = super::mask_contract(contract, &code, &companions);
    assert!(
        masked != code,
        "the actual imported replay route must match"
    );
    assert!(crate::flaky_escape_failures("unreviewed", "unreviewed", &masked).is_empty());

    // Omitting any present local clause must keep the real retry visible.
    // The complete method is separately required from its same-file producer.
    for (clause, count) in contract.required.iter().filter(|(_, count)| *count != 0) {
        assert_eq!(*count, 1);
        let changed = super::replace_one_obligation(
            &code,
            &super::source_pattern(clause),
            "omitted_imported_replay_obligation();",
        );
        assert!(changed != code, "actual local clause must be present");
        assert!(super::mask_contract(contract, &changed, &companions) == changed);
        assert!(!crate::flaky_escape_failures("unreviewed", "unreviewed", &changed).is_empty());
    }

    let mut omitted_route = companions.clone();
    omitted_route[6] = super::replace_one_obligation(
        &crate::scrub_comments_and_strings(&companions[6]),
        &super::source_pattern(FINISH),
        "omitted_same_file_route();",
    );
    assert!(omitted_route[6] != crate::scrub_comments_and_strings(&companions[6]));
    assert!(super::mask_contract(contract, &code, &omitted_route) == code);
    assert!(!crate::flaky_escape_failures("unreviewed", "unreviewed", &code).is_empty());

    for (before, after) in [
        (
            "if self.closed { return Ok(()); }",
            "if false { return Ok(()); }",
        ),
        ("self.closed = true;", "retain_old_open_state();"),
        (
            "lifecycle.return_to_main();",
            "discard_without_main(lifecycle);",
        ),
        (
            ".adopt_retirement_input(&mut self.unaccepted_input)",
            ".adopt_retirement_input(&mut foreign.unaccepted_input)",
        ),
        ("self.retirement.as_mut()", "foreign.retirement.as_mut()"),
        (
            "match retirement.finish()",
            "self.closed = true; match retirement.finish()",
        ),
        (
            "ImportedProductionReplayError::Terminal(terminal)",
            "ImportedProductionReplayError::Unavailable",
        ),
        ("self.retirement = Some(retirement);", "drop(retirement);"),
    ] {
        let changed_body = super::replace_one_obligation(
            &crate::scrub_comments_and_strings(FINISH),
            &super::source_pattern(before),
            after,
        );
        assert!(
            changed_body != crate::scrub_comments_and_strings(FINISH),
            "missed {before}"
        );
        let changed =
            super::replace_one_obligation(&code, &super::source_pattern(FINISH), &changed_body);
        assert!(changed != code, "actual finish clause absent: {before}");
        assert!(
            super::mask_contract(contract, &changed, &companions) == changed,
            "changed disposition classified: {before}",
        );
        assert!(!crate::flaky_escape_failures("unreviewed", "unreviewed", &changed).is_empty());
    }

    let changed = format!("{code}\nretirement.retry();");
    assert!(super::mask_contract(contract, &changed, &companions) == changed);

    for (index, before, after) in [
        (
            0,
            "carrier.install_owned_return(lifecycle)",
            "carrier.install_owned_return(foreign_lifecycle)",
        ),
        (1, "input.matches_main_role(&self.key)", "true"),
        (
            2,
            "Err(_) => Err(self)",
            "Err(_) => Ok(ProductionVmConstructionPostBody::history_only())",
        ),
        (3, "!body.native_returns_observed()", "false"),
        (
            3,
            "if cell.post_body.is_some() { return Err(PreparedSourceRefusal::Pending); }",
            "",
        ),
        (
            3,
            "let Some(body) = service.return_body.as_ref()",
            "let Some(body) = foreign_service.return_body.as_ref()",
        ),
        (
            3,
            "slot.report_references.load(Ordering::Acquire) != 1",
            "false",
        ),
        (
            3,
            "key: key.copy_selection()",
            "key: foreign.copy_selection()",
        ),
        (
            3,
            "queue: Arc::clone(&queue)",
            "queue: Arc::clone(&foreign_queue)",
        ),
        (
            4,
            "world.cleanup.get_or_init(",
            "world.cleanup.get_or_try_init(",
        ),
        (
            5,
            "let post = cleanup.wait_slice().map(|_| ());",
            "let post = Ok(());",
        ),
    ] {
        let clause = contract.companions[index]
            .required
            .iter()
            .find_map(|(clause, _)| {
                super::source_pattern(clause)
                    .contains(&super::source_pattern(before))
                    .then_some(*clause)
            })
            .ok_or("actual companion obligation is absent")?;
        let altered = super::replace_one_obligation(
            &crate::scrub_comments_and_strings(clause),
            &super::source_pattern(before),
            after,
        );
        let evidence = crate::scrub_comments_and_strings(&companions[index]);
        let changed =
            super::replace_one_obligation(&evidence, &super::source_pattern(clause), &altered);
        assert!(
            changed != evidence,
            "missed actual companion mutation: {before}"
        );

        let mut mutated = companions.clone();
        mutated[index] = changed;
        assert!(
            super::mask_contract(contract, &code, &mutated) == code,
            "changed owner classified: {before}",
        );
        assert!(!crate::flaky_escape_failures("unreviewed", "unreviewed", &code).is_empty());
    }

    Ok(())
}
