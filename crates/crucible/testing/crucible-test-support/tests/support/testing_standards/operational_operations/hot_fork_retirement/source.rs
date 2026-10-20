//! Binds existing Source owners, saved Cleanup and physical last-use order.

use super::{Companion, Contract};

#[path = "preparation.rs"]
mod preparation;

pub(super) const PRE_VM_CUSTODY: Companion = preparation::CUSTODY;
pub(super) const PRE_VM_BIRTH: Companion = preparation::BIRTH;
pub(super) const PRE_VM_ABORT: Companion = preparation::ABORT;
pub(super) const PRE_VM_ALLOCATION: Companion = preparation::ALLOCATION;
pub(super) const PRE_VM_RECEIVER: Companion = preparation::RECEIVER;
pub(super) const PRE_VM_HELPER_RETURN: Companion = preparation::HELPER_RETURN;
pub(super) const PRE_VM_LENDER: Companion = preparation::LENDER;
pub(super) const PRE_VM_NATIVE_RETURN: Companion = preparation::NATIVE_RETURN;
pub(super) const PRE_VM_NATIVE_OWNER: Companion = preparation::NATIVE_OWNER;
pub(super) const PRE_VM_ISSUED_RETURN: Companion = preparation::ISSUED_RETURN;
pub(super) const PRE_VM_NATIVE_ISSUER: Companion = preparation::NATIVE_ISSUER;
pub(super) const PRE_VM_NATIVE_NODE: Companion = preparation::NATIVE_NODE;
pub(super) const PRE_VM_NATIVE_CONTAIN: Companion = preparation::NATIVE_CONTAIN;
pub(super) const PRE_VM_NATIVE_CONTROLS: Companion = preparation::NATIVE_CONTROLS;
pub(super) const PRE_VM_MONOTONE_FINISH: Companion = preparation::MONOTONE_FINISH;

pub(super) const REQUIRED: &[(&str, usize)] = &[
    (
        r#"pub fn retry(&mut self) -> Result<crucible_control_api::ProductionVmCleanupStage, LifecycleApiError> {
    self.handoff.retry()
}"#,
        1,
    ),
    (
        r#"pub fn finish(self) -> Result<PostBody, Self> {
    self.handoff
        .into_post_body()
        .map_err(|handoff| Self { handoff })
}"#,
        1,
    ),
    (
        r#"pub(in crate::vm_lifecycle) fn retry_source_retirement_body(
    &mut self,
) -> Result<(), CleanupError> {
    if self.retirement.is_none() {
        let selector = self
            .lifecycle
            .as_ref()
            .and_then(|lifecycle| lifecycle.node_launcher.prepared_source_selector())
            .ok_or(CleanupError::Retained(
                "same Source Main selection is absent",
            ))?;
        selector.request_retirement();
        self.retirement = Some(SourceRetirementState::new());
    }
    if self.fork_target_is_owned() || self.parent_park_drain_is_owned() {
        return Err(CleanupError::Retained(
            "same Source retains Target or Park custody",
        ));
    }
    let lifecycle = self
        .lifecycle
        .as_mut()
        .ok_or(CleanupError::Retained("same Source lifecycle is absent"))?;
    let state = self.retirement.as_mut().ok_or(CleanupError::Retained(
        "same Source retirement was not admitted",
    ))?;
    if state.body_closed {
        return Ok(());
    }
    let history = state.history.as_mut().ok_or(CleanupError::Retained(
        "same Source history was already moved",
    ))?;
    #[cfg(feature = "private-measurement-domain")]
    if self.managed_parent_park_history.is_some() {
        if history.managed_parent_park.is_some() {
            return Err(CleanupError::Retained(
                "same Source retains independent Park histories",
            ));
        }
        history.managed_parent_park = self.managed_parent_park_history.take();
    }
    if state.post_body.is_none() {
        let loan = lifecycle
            .node_launcher
            .take_source_world_cleanup_loan()
            .ok_or(CleanupError::Retained(
                "same Source World return loan is absent",
            ))?;
        state.post_body = Some(PostBody::world(loan, self.cleanup_observer.take()));
    }
    if state.cleanup.is_none() {
        match state
            .post_body
            .as_ref()
            .and_then(PostBody::retained_source_cleanup)
        {
            Some(Ok(cleanup)) => state.cleanup = Some(cleanup),
            Some(Err(first)) => {
                history.admission.get_or_insert(first);
                return Err(CleanupError::Retained(
                    "same Source Cleanup admission refused",
                ));
            }
            None => {
                return Err(CleanupError::Retained(
                    "same Source return does not own its World loan",
                ));
            }
        }
    }
    let cleanup = state.cleanup.as_ref().ok_or(CleanupError::Retained(
        "same saved Source Cleanup is absent",
    ))?;
    if let Err(first) = cleanup.wait_slice() {
        history.original.get_or_insert(first);
        return Err(CleanupError::Retained(
            "same Source Cleanup precheck refused",
        ));
    }
    if let Some(prepared) = self.prepared.last() {
        let acknowledged = lifecycle
            .inner
            .backend_mut()
            .abort_retained_hot_fork_template(
                prepared.node(),
                Some(prepared.template_generation()),
            );
        let ack = matches!(&acknowledged, Ok(true));
        if ack && let Some(prepared) = self.prepared.pop() {
            // ACK is the physical cut. A failed independent post cannot
            // justify reissuing rollback or retaining an already used token.
            self.disk_custody.remove(prepared.node());
        }
        let post = cleanup.wait_slice();
        if let Err(first) = acknowledged {
            history.rollback.get_or_insert(first);
        }
        if let Err(first) = post {
            history.rollback_post.get_or_insert(first);
            return Err(CleanupError::Retained(
                "same Source rollback postcheck refused",
            ));
        }
        if !ack || !self.prepared.is_empty() {
            return Err(CleanupError::Retained(
                "same Source rollback acknowledgement remains pending",
            ));
        }
    }
    if !state.shutdown_attempted {
        if let Err(first) = cleanup.wait_slice() {
            history.original.get_or_insert(first);
            return Err(CleanupError::Retained(
                "same Source shutdown precheck refused",
            ));
        }
        state.shutdown_attempted = true;
        if let Err(first) = lifecycle.shutdown() {
            history.shutdown.get_or_insert(first);
        }
        if let Err(first) = cleanup.wait_slice() {
            history.shutdown_post.get_or_insert(first);
            return Err(CleanupError::Retained(
                "same Source shutdown postcheck refused",
            ));
        }
    }
    if let Err(first) = cleanup.wait_slice() {
        history.original.get_or_insert(first);
        return Err(CleanupError::Retained("same Source body precheck refused"));
    }
    let body = ProductionVmConstructionCustody::retire_complete_body(lifecycle);
    let closed = body.is_ok();
    let post = cleanup.wait_slice();
    if let Err(first) = body {
        history.body.get_or_insert(first);
    }
    if let Err(first) = post {
        history.body_post.get_or_insert(first);
    }
    if closed {
        state.body_closed = true;
        self.continuation = None;
        self.disk_custody.clear();
        state.cleanup = None;
        Ok(())
    } else {
        Err(CleanupError::Retained(
            "same Source physical body remains retained",
        ))
    }
}"#,
        1,
    ),
    (
        r#"pub(in crate::vm_lifecycle) fn take_source_retirement_post_body(
    &mut self,
) -> Result<Option<PostBody>, CleanupError> {
    let state = self
        .retirement
        .as_mut()
        .ok_or(CleanupError::Retained("same Source retirement is absent"))?;
    if !state.body_closed {
        return Err(CleanupError::Retained(
            "same Source physical body is not closed",
        ));
    }
    let Some(body) = state.post_body.as_mut() else {
        return Ok(None);
    };
    if let Some(history) = state.history.take()
        && let Err(history) = body.retain_source_retirement_history(history)
    {
        state.history = Some(history);
        return Err(CleanupError::Retained(
            "same Source history destination is occupied",
        ));
    }
    Ok(state.post_body.take())
}"#,
        1,
    ),
    (
        r#"cleanup.wait_slice()"#,
        6,
    ),
    (
        r#"state.shutdown_attempted = true;"#,
        1,
    ),
    (
        r#"state.body_closed = true;"#,
        1,
    ),
    (
        r#"HostOperationSupervisor::new("#,
        0,
    ),
    (
        r#"begin_original_cleanup_control("#,
        0,
    ),
    (
        r#"Instant::now("#,
        0,
    ),
];

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/vm_lifecycle/hot_fork/source_retirement",
    required: REQUIRED,
    expressions: &[
        (
            r#"pub fn retry(&mut self) -> Result<crucible_control_api::ProductionVmCleanupStage, LifecycleApiError>"#,
            1,
        ),
        (
            r#"self.handoff.retry()"#,
            1,
        ),
    ],
    identifiers: &[
        (
            r#"retry"#,
            2,
        ),
        (
            r#"retry_source_retirement_body"#,
            1,
        ),
    ],
    companions: &[
        Companion {
            path: "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/post_body.rs",
            required: &[
                (
                    r#"pub(crate) fn retained_source_cleanup(
    &self,
) -> Option<
    Result<
        Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        ServiceBirthError,
    >,
> {
    if self.returns.iter().flatten().count() != 1 {
        return None;
    }
    match self.returns.iter().flatten().next()? {
        NativeReturn::World(world) => Some(world.loan.retained_cleanup()),
        NativeReturn::Target(_) => None,
    }
}"#,
                    1,
                ),
                (
                    r#"pub(crate) fn retain_source_retirement_history(
    &mut self,
    history: crate::vm_lifecycle::ProductionVmHotForkSourceRetirementHistory,
) -> Result<(), crate::vm_lifecycle::ProductionVmHotForkSourceRetirementHistory> {
    if self.source_retirement_history.is_some() {
        return Err(history);
    }
    self.source_retirement_history = Some(history);
    Ok(())
}"#,
                    1,
                ),
                (
                    r#"fn observe_return(&mut self) {
    if self.returned {
        return;
    }
    match self.loan.observe_physically_returned() {
        Ok(true) => self.returned = true,
        Ok(false) => {}
        Err(first) => {
            self.observation.get_or_insert(first);
        }
    }
}"#,
                    1,
                ),
                (
                    r#"fn retry(&mut self) -> bool {
    self.observe_return();
    if !self.returned {
        if let Err(first) = self.loan.try_finish_after_members_returned() {
            self.first.get_or_insert(first);
        }
        // Native return latches consumption before its independent post.
        // A negative post must never cause a second physical debt return.
        self.observe_return();
    }
    if !self.returned || self.observer_returned || self.observer_panic_payload.is_some() {
        return self.returned && self.observer_returned;
    }
    let Some(observer) = self.observer.as_ref() else {
        return false;
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        observer.after_world_cleanup()
    })) {
        Ok(Ok(())) => self.observer_returned = true,
        Ok(Err(first)) => {
            self.observer_first.get_or_insert(first);
        }
        Err(payload) => self.observer_panic_payload = Some(payload),
    }
    self.returned && self.observer_returned
}"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/host/crucible-host-resources/src/host_services/process_birth/executor_purpose/native_pool.rs",
            required: &[
                (
                    r#"pub fn retained_cleanup(&self) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
    self.held
        .ledger
        .lock()
        .map_err(|_| ServiceBirthError::policy("native World Cleanup ledger is uncertain"))?
        .retained_cleanup(self.epoch)
}"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/host/crucible-host-resources/src/host_services/process_birth/executor_purpose/native_pool/ledger.rs",
            required: &[
                (
                    r#"pub(super) fn enter_cleanup(
    &self,
    epoch: u64,
) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
    let world = self
        .worlds
        .iter()
        .flatten()
        .find(|world| world.epoch == epoch)
        .ok_or_else(|| ServiceBirthError::policy("native World Cleanup is stale"))?;
    let _ = world.cleanup.get_or_init(|| {
        world
            ._original
            .begin_original_cleanup_control()
            .map(Arc::new)
    });
    self.saved_cleanup(epoch)
}"#,
                    1,
                ),
                (
                    r#"pub(super) fn saved_cleanup(
    &self,
    epoch: u64,
) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
    let world = self
        .worlds
        .iter()
        .flatten()
        .find(|world| world.epoch == epoch)
        .ok_or_else(|| ServiceBirthError::policy("native World Cleanup is stale"))?;
    let entered = world.cleanup.get().ok_or_else(|| {
        ServiceBirthError::policy("native World Cleanup has not been entered")
    })?;
    entered
        .as_ref()
        .map(Arc::clone)
        .map_err(|source| ServiceBirthError::from(*source))
}"#,
                    1,
                ),
                (
                    r#"pub(super) fn retained_cleanup(
    &self,
    epoch: u64,
) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
    let cleanup = self.enter_cleanup(epoch)?;
    cleanup.verify_operation_class(crate::host_supervision::HostOperationClass::Cleanup)?;
    Ok(cleanup)
}"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/custody.rs",
            required: &[
                (
                    r#"pub(in crate::vm_lifecycle) fn retire_complete_body(
    lifecycle: &mut ProductionVmLifecycleLoop,
) -> Result<(), ProductionVmConstructionCleanupError> {
    retire_complete(lifecycle)
}"#,
                    1,
                ),
                (
                    r#"fn retire_complete(
    lifecycle: &mut ProductionVmLifecycleLoop,
) -> Result<(), ProductionVmConstructionCleanupError> {
    if let Some(first) = lifecycle.retained_cleanup_failure.take() {
        return Err(first);
    }
    lifecycle.retry_retained_debug_construction()?;
    if lifecycle.debug_gateway.is_some() || lifecycle.indeterminate_debug_candidate.is_some() {
        return Err(ProductionVmConstructionCleanupError::Retained(
            "construction contains a live external debugger owner",
        ));
    }
    lifecycle
        .retire_terminal_replacement_transaction()
        .map_err(ProductionVmConstructionCleanupError::Scheduler)?;
    lifecycle
        .inner
        .backend_mut()
        .shutdown()
        .map_err(ProductionVmConstructionCleanupError::Backend)?;
    clear_devices(&lifecycle.block_devices)?;
    finish_retained_node_leases(&lifecycle.node_generations, &mut lifecycle.node_leases)?;
    lifecycle.retained_hot_fork_disk_owners.clear();
    lifecycle.launch_configs.clear();
    lifecycle.exact_ram_parents.clear();
    // This private failed-construction route preserves the ordinary Loop's
    // sticky latch as history, while proving actual map retirement directly.
    lifecycle.node_launcher.finish()
}"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher.rs",
            required: &[
                (
                    r#"fn finish(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
    if self.cleanup_complete {
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    if self.parent_park_phase.is_some() {
        return Err((LifecycleApiError::ParentParkHeld).into());
    }
    if let Some(failed) = self.retained_launch.as_mut() {
        failed.finish()?;
    }
    self.retained_launch = None;
    // The exact observation registrar/configuration aliases remain until
    // its real node and generation lease have physically closed.
    #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
    {
        if self.native_observation_config.take().is_some() {
            self.park_drain_registration = None;
        }
    }
    self.transfer_image_helper_debt();
    self.owner.finish()?;
    self.fork_target_factory = None;
    self.cleanup_complete = true;
    Ok(())
}"#,
                    1,
                ),
                preparation::LAYOUT.required[0],
                preparation::LAYOUT.required[1],
                preparation::LAYOUT.required[2],
                preparation::LAYOUT.required[3],
                preparation::LAYOUT.required[4],
                preparation::LAYOUT.required[5],
                preparation::LAYOUT.required[6],
                preparation::LAYOUT.required[7],
                preparation::LAYOUT.required[8],
                preparation::LAYOUT.required[9],
                preparation::LAYOUT.required[10],
                preparation::LAYOUT.required[11],
            ],
        },
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_host.rs",
            required: &[
                (
                    r#"fn close_original_physical_owners(&mut self) -> Result<(), QemuVmRealizationError> {
    if self.fork_target_is_owned() {
        return Err(missing_authority(
            "close Source with retained QEMU fork target",
        ));
    }
    let cleanup = self
        .original_account
        .as_ref()
        .ok_or_else(|| missing_authority("retain original native cleanup"))?
        .cleanup()
        .map_err(original_roster::original_error)?;
    self.retire_native_resources();
    if let Some(process) = self.process.as_mut() {
        process.finish_under_original(&cleanup)?;
    }
    self.process = None;
    if let Some(state) = self.native_resources.as_ref() {
        NativeResourceState::drain(state);
    }
    self.native_resources = None;

    cleanup
        .wait_slice()
        .map_err(|source| original_roster::original_error(source.into()))?;
    let result = if let Some(storage) = self.storage.as_mut() {
        storage.cleanup_under_original(&cleanup)
    } else {
        Ok(())
    };
    if result.is_ok() {
        // Physical release is recorded before the separate original
        // postcut. Refusal leaves the actual owner in this same slot.
        self.storage = None;
    }
    // Physical success or the actual recoverable owner is recorded before
    // observing original expiry on either outcome. Retry keeps Cleanup.
    original_roster::after_cleanup(result, &cleanup)?;
    Ok(())
}"#,
                    1,
                ),
                (
                    r#"fn close_original_vector(&mut self) -> Result<(), QemuVmRealizationError> {
    if self.fork_target.is_some() {
        return self.close_fork_target_vector();
    }
    self.original_account
        .as_ref()
        .ok_or_else(|| missing_authority("close original native vector"))?
        .close_vector()
        .map_err(original_roster::original_error)?;
    self.terminal = true;
    self.original_account = None;
    Ok(())
}"#,
                    1,
                ),
            ],
        },
        preparation::CUSTODY,
        preparation::BIRTH,
        preparation::ABORT,
        preparation::ALLOCATION,
        preparation::RECEIVER,
        preparation::HELPER_RETURN,
        preparation::CONTROLS,
        preparation::LENDER,
        super::super::host_physical_custody::SOURCE_CLEANUP,
        super::super::host_physical_custody::SOURCE_ORIGINAL,
        preparation::NATIVE_RETURN,
        preparation::NATIVE_OWNER,
        preparation::ISSUED_RETURN,
        preparation::NATIVE_ISSUER,
        preparation::NATIVE_NODE,
        preparation::NATIVE_CONTAIN,
        preparation::NATIVE_CONTROLS,
        preparation::MONOTONE_FINISH,
        super::pre_vm::CHILD_OWNER,
        super::pre_vm::CHILD_ORIGINAL,
        super::pre_vm::CHILD_LADDER,
        super::pre_vm::CHILD_WAIT,
        super::pre_vm::ACTUAL_CHILD,
        super::pre_vm::SHUTDOWN_TARGET,
        super::pre_vm::PROCESS_CONTROL,
        super::pre_vm::OWNED_WAIT,
        super::pre_vm::RAM_BODY,
        super::pre_vm::RAM_STOP,
        super::pre_vm::RAM_HISTORY,
        super::pre_vm::RAM_ORIGINAL,
        super::pre_vm::RAM_JOIN,
    ],
};
