//! Binds daemon continuations to their same retained World or import receiver.
//!
//! Rejecting defaults and complete tiny forwarders grant no cleanup authority.
//! Import acknowledgment runs only after owned aliases are actually disposed.

use super::{Companion, Contract};

const REJECTING_DEFAULT: &str = r#"fn retry_native_world_construction(
    &mut self,
    _loan: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
) -> Result<(), QemuVmRealizationError> {
    Err(QemuVmRealizationError::ExecutorUnavailable {
        operation: "retry actual pending World construction",
        message: String::from("factory has no exact pending World owner"),
    })
}"#;
const SHARED_FORWARDER: &str = r#"fn retry_native_world_construction(
    &mut self,
    loan: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
) -> Result<(), QemuVmRealizationError> {
    self.host
        .try_lock()
        .map_err(|_| QemuVmRealizationError::ExecutorUnavailable {
            operation: "retry actual pending World construction",
            message: String::from("actual factory custody is busy or poisoned"),
        })?
        .retry_native_world_construction(loan)
}"#;
const DIRECT_FORWARDER: &str = r#"fn retry_native_world_construction(
    &mut self,
    loan: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
) -> Result<(), QemuVmRealizationError> {
    self.host.retry_native_world_construction(loan)
}"#;
const IMPORT_ACK: &str = r#"pub fn retry_parent_return(&mut self) -> bool {
    let Some(receiver) = self.parent_receiver.take() else {
        return true;
    };
    self.receiver_return_attempted = true;
    match receiver.return_after_alias_destruction() {
        Ok(()) => true,
        Err(receiver) => {
            self.receiver_return_refused = true;
            self.parent_receiver = Some(receiver);
            false
        }
    }
}"#;

// Share the existing physical/Original proofs instead of copying their bodies.
const WORLD: &Contract = super::host_physical_custody::NORMAL_WORLD;
const _: () = assert!(WORLD.companions.len() == 4);
pub(super) const WORLD_COMPANIONS: &[Companion] = &[
    Companion {
        path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/normal_pool.rs",
        required: WORLD.required,
    },
    Companion {
        path: WORLD.companions[0].path,
        required: WORLD.companions[0].required,
    },
    Companion {
        path: WORLD.companions[1].path,
        required: WORLD.companions[1].required,
    },
    Companion {
        path: WORLD.companions[2].path,
        required: WORLD.companions[2].required,
    },
    Companion {
        path: WORLD.companions[3].path,
        required: WORLD.companions[3].required,
    },
    Companion {
        path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher/pending_construction/cleanup.rs",
        required: &[
            (
                r#"let (attempt, first, post) = observe_saved_world_cleanup(&cleanup, || self.finish_native_members());
 if let Some(first) = first { self.history.cleanup_first.get_or_insert(first.into()); }
 if let Err(post) = post { self.history.cleanup_post.get_or_insert(post); } attempt"#,
                1,
            ),
            (r#"factory.retry_native_world_construction(world)"#, 1),
            (
                r#"let (result, first) = match cleanup.wait_slice() {
 Ok(_) => (attempt(), None), Err(first) => (
 Err(CleanupError::Retained("same World Cleanup refused retirement effects",)), Some(first), ), };
 let post = cleanup.wait_slice().map(|_| ()); (result, first, post)"#,
                1,
            ),
        ],
    },
];

pub(super) const IMPORTED_RETURN: &Contract = &CONTRACTS[2];

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-daemon",
        target: "src/crucible_qemu_session",
        required: &[("pub(crate) trait QemuAttemptResourceGuardFactory {", 1)],
        expressions: &[(REJECTING_DEFAULT, 1)],
        identifiers: &[],
        companions: WORLD_COMPANIONS,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/qemu_resource_guard",
        required: &[
            (
                "pub struct SharedQemuAttemptHostResourceFactory<H> { host: Arc<Mutex<H>>,",
                1,
            ),
            (
                "pub struct LinuxQemuAttemptHostResourceFactory { host: LinuxQemuAttemptHostFactory, }",
                1,
            ),
            (
                "pub struct ComposedQemuAttemptResourceGuardFactory<H> { host: H, }",
                1,
            ),
        ],
        expressions: &[
            (REJECTING_DEFAULT, 1),
            (SHARED_FORWARDER, 1),
            (DIRECT_FORWARDER, 2),
        ],
        identifiers: &[],
        companions: WORLD_COMPANIONS,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/imported_checkpoint",
        required: &[
            (
                r#"let completion_attempted = !self.launch_attempted || self.maintenance;
 let completion = completion_attempted.then(|| self.operation.complete().err()).flatten();
 let post = self.operation.status().err();"#,
                1,
            ),
            (
                r#"drop(basis); drop(selected); drop(operation); drop(owner_custody);
 let mut returned = ImportedCheckpointReturn {
 first, launch_post, completion_attempted, completion, return_post: post, parent_receiver,
 receiver_return_attempted: false, receiver_return_refused: false,
 };
 returned.retry_parent_return(); returned"#,
                1,
            ),
            (
                r#"pub fn first_failure(&self,) -> Option<crucible_host_resources::host_supervision::HostSupervisionError> {
 self.first.or(self.launch_post).or(self.completion).or(self.return_post) }"#,
                1,
            ),
            (
                r#"pub fn parent_returned(&self) -> bool { self.parent_receiver.is_none() }"#,
                1,
            ),
            (
                r#"let parent_receiver = context.retain_service_receiver("authenticate imported checkpoint")
 .map_err(ImportedCheckpointErrorCause::ServiceReceiver)?;
 let mut parent_receiver = AuthenticatedImportReceiver(parent_receiver);"#,
                1,
            ),
            (
                r#"operation: self.authentication_operation, parent_receiver: self.parent_receiver.take(),"#,
                1,
            ),
            (r#"Instant::now("#, 0),
            (r#"std::mem::forget("#, 0),
        ],
        expressions: &[(IMPORT_ACK, 1), ("returned.retry_parent_return();", 1)],
        identifiers: &[],
        companions: &[
            Companion {
                path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/prepared_service.rs",
                required: &[
                    (
                        r#"pub fn return_after_alias_destruction(mut self) -> Result<(), Self> {
 self.aliases_destroyed = true; if self.try_return() { Ok(()) } else { Err(self) } }"#,
                        1,
                    ),
                    (
                        r#"pub(super) fn try_return(&mut self) -> bool {
 if self.returned { return true; } if !self.aliases_destroyed { return false; }
 let Some(queue) = self.key.queue.upgrade() else { return false; };
 let Some(slot) = queue.slots.get(self.key.index) else { return false; };
 if slot.epoch.load(Ordering::Acquire) != self.key.epoch { return false; }"#,
                        1,
                    ),
                    (
                        r#"if slot.external_receivers.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
 count.checked_sub(1) }).is_err() { slot.publish(CleanupPhase::DestructionRefused); return false; }
 self.returned = true; true"#,
                        1,
                    ),
                    (
                        r#"impl Drop for ServiceMainReceiver { fn drop(&mut self) {
 if self.aliases_destroyed { let _returned = self.try_return(); } } }"#,
                        1,
                    ),
                ],
            },
            Companion {
                path: "crates/crucible/control/crucible-daemon/src/packaged_qemu_executor/hot_fork/retained_service/retirement_input.rs",
                required: &[
                    (
                        r#"if let Some(aliases) = self.aliases.take() {
 match aliases { RetirementAliases::Basis(basis) => drop(basis),
 RetirementAliases::Maintenance(imported) => { self.returned = Some(imported.retire_unpublished()); } }
 self.aliases_destroyed = true; }
 if !self.aliases_destroyed { return false; }
 if let Some(returned) = &mut self.returned { if !returned.retry_parent_return() { return false; } }"#,
                        1,
                    ),
                    (
                        r#"self.aliases_destroyed && self.aliases.is_none() && self.receiver.is_none()
 && self.returned.as_ref().is_none_or(|returned| returned.parent_returned())"#,
                        1,
                    ),
                ],
            },
        ],
    },
];

// Extend only test-mutant construction for these new exact expressions. The
// production matcher and every existing rejection predicate stay unchanged.
#[cfg(test)]
pub(super) fn altered_expression(expression: &str) -> String {
    if !CONTRACTS.iter().any(|contract| {
        contract
            .expressions
            .iter()
            .any(|(actual, _)| *actual == expression)
    }) {
        return expression.to_owned();
    }
    let mut altered = expression.to_owned();
    if let Some(offset) = expression.find('{') {
        altered.insert_str(offset + 1, " unreviewed_cleanup_effect(); ");
    } else if let Some(offset) = expression.find('(') {
        altered.insert_str(offset + 1, "foreign_owner, ");
    }
    altered
}

#[cfg(test)]
fn assert_rejected(contract: &Contract, code: &str, companions: &[String]) {
    let masked = super::mask_contract(contract, code, companions);
    assert_eq!(masked, code, "changed retained continuation still matched");
    let composed = super::super::mask_after_operations(contract.package, contract.target, &masked);
    assert!(!crate::flaky_escape_failures("unreviewed", "unreviewed", &composed).is_empty());
}

#[test]
fn world_forwarders_refuse_foreign_loan_repetition_and_extra_effects()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::workspace_root();
    for contract in &CONTRACTS[..2] {
        let path = crate::workspace::package_path(&root.join("crates"), contract.package)
            .join(format!("{}.rs", contract.target));
        let source = std::fs::read_to_string(path)?;
        let code = crate::scrub_comments_and_strings(&source);
        let companions = super::read_companions(contract)?;
        assert!(
            crate::flaky_escape_failures(contract.package, contract.target, &source).is_empty()
        );
        let (prefix, _) = REJECTING_DEFAULT
            .split_once('{')
            .ok_or("default body absent")?;
        let changed = super::replace_one_obligation(
            &code,
            &super::source_pattern(REJECTING_DEFAULT),
            &format!("{prefix}{{ Ok(()) }}"),
        );
        assert_rejected(contract, &changed, &companions);
        if contract.target != "src/qemu_resource_guard" {
            continue;
        }
        for changed_forwarder in [
            SHARED_FORWARDER.replace(".try_lock()", ".lock()"),
            SHARED_FORWARDER.replace("(loan)", "(foreign_loan)"),
        ] {
            let changed = super::replace_one_obligation(
                &code,
                &super::source_pattern(SHARED_FORWARDER),
                &changed_forwarder,
            );
            assert_rejected(contract, &changed, &companions);
        }
        for replacement in [
            "loop { self.host.retry_native_world_construction(loan)?; }",
            "{ let result = self.host.retry_native_world_construction(loan); extra_effect(); result }",
        ] {
            let forwarder = DIRECT_FORWARDER.replace(
                "self.host.retry_native_world_construction(loan)",
                replacement,
            );
            let changed = super::replace_one_obligation(
                &code,
                &super::source_pattern(DIRECT_FORWARDER),
                &forwarder,
            );
            assert_rejected(contract, &changed, &companions);
        }
    }
    Ok(())
}

#[test]
fn imported_return_requires_disposal_exact_receiver_and_independent_history()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::workspace_root();
    let contract = &CONTRACTS[2];
    let source = std::fs::read_to_string(
        crate::workspace::package_path(&root.join("crates"), contract.package)
            .join(format!("{}.rs", contract.target)),
    )?;
    let code = crate::scrub_comments_and_strings(&source);
    let companions = super::read_companions(contract)?;
    assert!(crate::flaky_escape_failures(contract.package, contract.target, &source).is_empty());
    for (needle, replacement) in [
        (
            "drop(basis); drop(selected); drop(operation); drop(owner_custody);",
            "",
        ),
        ("self.parent_receiver = Some(receiver);", "drop(receiver);"),
        (
            "pub fn parent_returned(&self) -> bool { self.parent_receiver.is_none() }",
            "pub fn parent_returned(&self) -> bool { true }",
        ),
        (
            "self.first.or(self.launch_post).or(self.completion).or(self.return_post)",
            "self.first",
        ),
    ] {
        let changed =
            super::replace_one_obligation(&code, &super::source_pattern(needle), replacement);
        assert_ne!(changed, code);
        assert_rejected(contract, &changed, &companions);
    }
    for (index, needle, replacement) in [
        (
            0,
            "if slot.epoch.load(Ordering::Acquire) != self.key.epoch { return false; }",
            "if false { return false; }",
        ),
        (0, "count.checked_sub(1)", "Some(count)"),
        (0, "self.returned = true; true", "true"),
        (
            0,
            "if self.aliases_destroyed { let _returned = self.try_return(); }",
            "let _returned = self.try_return();",
        ),
        (1, "if !self.aliases_destroyed { return false; }", ""),
        (
            1,
            "if !returned.retry_parent_return() { return false; }",
            "let _ = returned.retry_parent_return();",
        ),
    ] {
        let mut changed = companions.clone();
        let before = crate::scrub_comments_and_strings(&changed[index]);
        let obligation = contract.companions[index]
            .required
            .iter()
            .find(|(required, _)| {
                super::source_pattern(required).contains(&super::source_pattern(needle))
            })
            .map(|(required, _)| *required)
            .ok_or("mutation is outside the reviewed receiver cut")?;
        let changed_obligation =
            super::replace_one_obligation(obligation, &super::source_pattern(needle), replacement);
        changed[index] = super::replace_one_obligation(
            &before,
            &super::source_pattern(obligation),
            &changed_obligation,
        );
        assert_ne!(changed[index], before);
        assert_rejected(contract, &code, &changed);
    }
    Ok(())
}
