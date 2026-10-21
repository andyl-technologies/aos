//! Requires actual installed Source identity for every late helper recipient.
//!
//! These companions bind the complete native roster lookup, current physical
//! incarnation and receiving route. They issue no action Original or process
//! permission from the copied generation used to select that retained owner.

use super::Companion;

pub(super) const SOURCE: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_roster/process_purpose/source_cleanup.rs",
    required: &[
        (
            r#"pub(crate) fn current_incarnation(&self) -> Result<Self, OriginalActorAccountError> {
        let controller = self.controller()?;
        let attempt = NativeAccountAttempt {
            roster: RosterWeak::clone(&self.roster),
            index: self.index,
            generation: self.generation,
        };
        attempt.bound_source_cleanup_lender(controller.as_ref())
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn controller(
        &self,
    ) -> Result<
        crate::linux_attempt_host::original_node::RetainedNativeFreshLaunchError,
        OriginalActorAccountError,
    > {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .try_lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let purpose = slot
            .installed_process
            .as_ref()
            .filter(|purpose| purpose.ready && purpose.sound)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if let Some(expected) = self.process_generation {
            let allocation = purpose.journal.incarnations[0]
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?;
            if allocation.process_generation != expected || allocation.physical_retired {
                return Err(OriginalActorAccountError::Unavailable);
            }
        }
        slot.source_controller
            .as_ref()
            .cloned()
            .ok_or(OriginalActorAccountError::Unavailable)
    }"#,
            1,
        ),
        (
            r#"pub(in crate::linux_attempt_host) fn bound_source_cleanup_lender(
        &self,
        expected: &crate::linux_attempt_host::original_node::OriginalNativeFreshLaunchError,
    ) -> Result<SourceCleanupLender, OriginalActorAccountError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .try_lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if !slot
            .source_controller
            .as_ref()
            .is_some_and(|controller| std::ptr::eq(controller.as_ref(), expected))
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let purpose = slot
            .installed_process
            .as_ref()
            .filter(|purpose| purpose.ready && purpose.sound)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let allocation = purpose.journal.incarnations[0]
            .as_ref()
            .filter(|allocation| !allocation.physical_retired)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        Ok(SourceCleanupLender {
            roster: RosterWeak::clone(&self.roster),
            index: self.index,
            generation: self.generation,
            process_generation: Some(allocation.process_generation),
        })
    }"#,
            1,
        ),
    ],
};

pub(super) const RECEIVER: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/spawn/helper_receiver.rs",
    required: &[
        (
            r#"pub(super) fn retained_source_helper_lender(
        &self,
    ) -> Result<crate::linux_attempt_host::SourceCleanupLender, QemuSpawnError> {
        self.attempt_binding
            .helper_receiver
            .get()
            .ok_or_else(helper_custody_refusal)?
            .current_incarnation()
            .map_err(|_| helper_custody_refusal())
    }"#,
            1,
        ),
        (
            r#"pub(super) fn with_spawned_retained_source_helper<T: HelperOutput>(
        &self,
        command: Command,
        operation: &'static str,
        body: impl FnOnce(
            &mut QemuNodeChild,
            &crucible_host_resources::host_supervision::HostOperationGuard,
            &mut Option<RetainedHelperOutput>,
        ) -> Result<T, QemuSpawnError>,
    ) -> Result<T::Received, QemuGuardedImagePreparationError> {
        let receiver = self
            .retained_source_helper_lender()
            .map_err(QemuGuardedImagePreparationError::local)?;
        let controller = receiver
            .controller()
            .map_err(|_| QemuGuardedImagePreparationError::local(helper_custody_refusal()))?;
        controller.with_spawned_helper(&receiver, command, operation, body)
    }"#,
            1,
        ),
    ],
};

pub(super) const CALLER: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/spawn.rs",
    required: &[(
        r#"fn run_guarded_image_tool_for_purpose(
    executable: &Path,
    args: &[std::ffi::OsString],
    operation: &'static str,
    run_directory: &QemuPreparedRunDirectory,
    process_contract: &QemuChildProcessContract,
    purpose: GuardedImageToolPurpose,
) -> Result<(), QemuGuardedImagePreparationError> {
    let admission = match purpose {
        GuardedImageToolPurpose::FreshLaunch => {
            run_directory.validate_helper_basis(process_contract)
        }
        GuardedImageToolPurpose::RetainedHotForkSource => {
            run_directory
                .validate_retained_source_helper_basis(process_contract)
                .and_then(|()| process_contract.retained_source_helper_lender().map(|_| ()))
        }
    };
    if let Err(source) = admission {
        return Err(QemuGuardedImagePreparationError::local(source));
    }
    let mut command = Command::new(executable);
    command
        .env_clear()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    install_guarded_helper_authority(&mut command, run_directory, process_contract);
    process_contract
        .attempt_binding
        .freeze_for_launch()
        .map_err(|source| QemuGuardedImagePreparationError::local(source))?;

    match purpose {
        GuardedImageToolPurpose::FreshLaunch => {
            process_contract.with_spawned_helper(command, operation, |child, original, _output| {
                helper_receiver::wait_image_tool(child, original, operation)
            })
        }
        GuardedImageToolPurpose::RetainedHotForkSource => {
            process_contract.with_spawned_retained_source_helper(
                command,
                operation,
                |child, original, _output| {
                    helper_receiver::wait_image_tool(child, original, operation)
                },
            )
        }
    }
}"#,
        1,
    )],
};
