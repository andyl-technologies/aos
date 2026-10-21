//! Binds the same retained body, paid layout and saved Source cleanup.
//!
//! Local physical progress grants neither diagnostic funding nor World return.

use super::Companion;

#[path = "preparation/native.rs"]
mod native;

pub(super) const CUSTODY: Companion = native::CUSTODY;
pub(super) const BIRTH: Companion = native::BIRTH;
pub(super) const NATIVE_RETURN: Companion = native::NATIVE_RETURN;
pub(super) const NATIVE_OWNER: Companion = native::NATIVE_OWNER;
pub(super) const ISSUED_RETURN: Companion = native::ISSUED_RETURN;
pub(super) const NATIVE_ISSUER: Companion = native::NATIVE_ISSUER;
pub(super) const NATIVE_NODE: Companion = native::NATIVE_NODE;
pub(super) const NATIVE_CONTAIN: Companion = native::NATIVE_CONTAIN;
pub(super) const NATIVE_CONTROLS: Companion = native::NATIVE_CONTROLS;
pub(super) const MONOTONE_FINISH: Companion = native::MONOTONE_FINISH;

pub(super) const ABORT: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_resource_guard/generation_resource.rs",
    required: &[(
        r#"pub(crate) fn abort_without_process(&mut self) -> Result<(), LifecycleApiError> {
    if self.finished {
        return Err(generation_error("cannot abort an already-finished QEMU generation lease",));
    }
    let mut state = self.generations.try_lock()
        .map_err(|_| generation_error("QEMU attempt generation registry is unavailable"))?;
    let index = state.nodes.binary_search_by(|row| row.node.cmp(self.identity.node())).ok();
    let active = index.and_then(|index| {
        let row = &state.nodes[index];
        (row.latest == Some(self.identity.generation()))
            .then(|| {
                row.active.iter().position(|generation| *generation == Some(self.identity.generation()))
            }).flatten()
    });
    let (Some(index), Some(active)) = (index, active) else {
        return Err(generation_error(format!(
            "QEMU node `{}` generation {} is not the exact pending generation",
            self.identity.node().name, self.identity.generation(),
        )));
    };
    state.nodes[index].active[active] = None;
    state.nodes[index].latest = self.previous_generation;
    self.finished = true;
    Ok(())
}"#,
        1,
    )],
};

pub(super) const LAYOUT: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher.rs",
    required: &[
        ("retained_launch: Option<RetainedLaunch>,", 1),
        (
            r#"pub(crate) fn retained_control_bytes() -> Result<u64, LifecycleApiError> {
    u64::try_from(std::mem::size_of::<Self>())
        .map_err(|_| launcher_message("retained Source launcher extent overflows"))
}"#,
            1,
        ),
        (
            r#"let retained_source = Self::retained_control_bytes()?
    .checked_add(directories)
    .and_then(|bytes| bytes.checked_add(helpers))
    .and_then(|bytes| bytes.checked_add(source_loop))
    .and_then(|bytes| bytes.checked_add(terminal_rows))
    .and_then(|bytes| bytes.checked_add(shared_source))
    .ok_or_else(|| launcher_message("retained Source launcher extent overflow"))?;"#,
            1,
        ),
        (
            r#"fn require_preparation_return(&self) -> Result<(), LifecycleApiError> {
    if self.retained_launch.as_ref().is_some_and(RetainedLaunch::is_preparation) {
        Err(LifecycleApiError::CleanupRetained)
    } else { Ok(()) }
}"#,
            1,
        ),
        (
            r#"fn take_target_construction_storage(
    &mut self,
) -> Result<TargetConstructionStorage, LifecycleApiError> {
    self.require_preparation_return()?;
    self.target_storage.take().ok_or_else(|| {
        launcher_message("Source Target construction storage is already borrowed or absent")
    })
}"#,
            1,
        ),
        (
            r#"fn prepare_fork_target_for_node(
    &mut self,
    node: &crucible_engine::NodeId,
) -> Result<
    crucible_qemu_host::QemuForkTargetPreparation,
    crate::qemu_lifecycle_launcher::TargetPreparationFailure,
> {
    self.require_preparation_return()?;
    self.owner.prepare_fork_target_for_node(node)
}"#,
            1,
        ),
        (
            r#"fn prepare_fork_target(
    &mut self,
) -> Result<
    crucible_qemu_host::QemuForkTargetPreparation,
    crate::qemu_lifecycle_launcher::TargetPreparationFailure,
> {
    self.require_preparation_return()?;
    self.owner.prepare_fork_target()
}"#,
            1,
        ),
        (
            r#"fn prepare_fork_target_run_directory(
    &mut self,
    target_contract: &QemuChildProcessContract,
    requirements: crucible_qemu_host::QemuLaunchResourceRequirements,
) -> Result<QemuPreparedRunDirectory, LifecycleApiError> {
    self.require_preparation_return()?;
    self.owner.prepare_fork_target_run_directory(target_contract, requirements)
}"#,
            1,
        ),
        (
            r#"fn parent_park_drain(
    &mut self,
    source: &mut crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
    request: crate::ProductionVmParentParkDrainRequest<'_>,
) -> Result<crucible_qemu_host::QmpParentParkResult, crate::ProductionVmParentParkDrainRefusal>
{
    self.require_preparation_return().map_err(|_| {
        crate::ProductionVmParentParkDrainRefusal::Unavailable(
            "pre-VM preparation retains its original cleanup",
        )
    })?;
    self.invoke_parent_park_drain(source, request)
}"#,
            1,
        ),
        (
            r#"fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
    self.require_preparation_return()?;
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    if self.parent_park_phase.is_some() {
        return Err(LifecycleApiError::ParentParkHeld);
    }
    self.owner.charge_execution_quantum()
}"#,
            1,
        ),
        (
            r#"fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
    self.require_preparation_return()?;
    self.owner.check_operational_boundary()
}"#,
            1,
        ),
        (
            r#"fn prepare_terminal_exact_checkpoint(
    &mut self,
    closure: ProductionExactCheckpointClosure,
) -> Result<DecodedProductionExactCheckpoint, LifecycleApiError> {
    self.require_preparation_return()?;
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    if self.parent_park_phase.is_some() {
        return Err(LifecycleApiError::ParentParkHeld);
    }
    self.owner.check_operational_boundary()?;
    let terminal = self.terminal_checkpoint.as_mut().ok_or_else(|| {
        launcher_message("terminal exact checkpoint has no selected campaign store")
    })?;
    terminal.published_root = None;"#,
            1,
        ),
    ],
};

pub(super) const ALLOCATION: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher/pending_construction/prepared.rs",
    required: &[(
        r#"let expected = self.begin_world(context, source, config, || {
    crate::QemuAttemptProductionVmNodeLauncher::<F::Guard, F>::retained_source_launcher_control_bytes(
        source.world().vm_nodes().iter().map(|node| &node.id), workers,
    )
})?;
let (guard, storage, factory, reservation, custody, world, targets) = self
    .take_launcher_parts().map_err(|_| self.record_unavailable())?;
self.launcher = Some(Box::new(
    crate::QemuAttemptProductionVmNodeLauncher::new_registered(
        crate::QemuAttemptGenerationResourceOwner::new(guard, storage), registration, Some(factory),
    )
    .with_cleanup_reservation(reservation)
    .with_construction_custody(custody)
    .with_world_cleanup_loan(world)
    .with_target_construction_storage(targets),
));
self.transferred = false;
self.finish_launcher = Some(
    finish_retained_launcher::<crate::QemuAttemptProductionVmNodeLauncher<F::Guard, F>>,
);"#,
        1,
    )],
};

pub(super) const RECEIVER: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/spawn/helper_receiver.rs",
    required: &[
        (
            r#"pub fn issued_helper_receiver(&self) -> Option<QemuIssuedHelperReceiver> {
        let lender = self.attempt_binding.helper_receiver.get()?;
        lender.controller().ok()?;
        Some(QemuIssuedHelperReceiver::from_lender(lender.clone()))
    }"#,
            1,
        ),
        (
            r#"impl QemuIssuedHelperReceiver {
    pub(crate) fn from_lender(lender: crate::linux_attempt_host::SourceCleanupLender) -> Self {
        Self { lender }
    }

    /// Resolves the same recipient only while its original Source is current.
    ///
    /// Missing, contended or retired custody returns `None`; it never proves
    /// that the helper or its diagnostic allocations have returned.
    #[must_use]
    pub fn upgrade(&self) -> Option<crate::RetainedNativeFreshLaunchError> {
        self.lender.controller().ok()
    }

    /// Compares existing lender identities without issuing or resolving custody.
    #[must_use]
    pub fn same_identity(&self, other: &Self) -> bool {
        self.lender.same_identity(&other.lender)
    }

    /// Checks a controller against this same live Source lender.
    ///
    /// This identity observation grants no helper effect or cleanup permission.
    #[must_use]
    pub fn matches_controller(
        &self,
        controller: &crate::RetainedNativeFreshLaunchError,
    ) -> bool {
        self.upgrade()
            .is_some_and(|current| current.same_owner(controller))
    }
}"#,
            1,
        ),
    ],
};

pub(super) const HELPER_RETURN: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_node/helper_receiver.rs",
    required: &[
        (
            r#"fn settle_helper(
    &self,
    slot: &mut HelperDebt,
    receiver: &crate::linux_attempt_host::SourceCleanupLender,
) {
    let Some(child) = slot.child.as_mut() else { return; };
    if !child.child_reaped() {
        let original = match receiver.clone().retained_original() {
            Ok(original) => original,
            Err(first) => {
                slot.observe(crate::QemuNodeError::RamCleanupLender {
                    source: crucible_engine::BackendOperationalCause::new(first),
                });
                return;
            }
        };
        child.retain_source_original(original);
        if let Err(first) = child.retry_cleanup() { slot.observe(first); }
    }
    if slot.child.as_ref().is_some_and(crate::node::RetainedChild::child_reaped) {
        drop(slot.child.take());
    }
}"#,
            1,
        ),
        (
            r#"pub fn retry_retained_helper(&self) -> bool {
    let Ok(mut slot) = self.helper.try_lock() else { return false; };
    if slot.child.is_none() { return true; }
    let Some(receiver) = slot.lender.clone() else { return false; };
    self.settle_helper(&mut slot, &receiver);
    slot.child.is_none()
}"#,
            1,
        ),
    ],
};

pub(super) const CONTROLS: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_resource_guard/generation_resource/tests.rs",
    required: &[
        (
            r#"let locked = registry.lock().expect("hold actual registry");
assert!(pending.abort_without_process().is_err());
assert!(!pending.finished);
assert_eq!(pending.identity(), &identity);
assert!(!locked.abandoned);
assert_eq!(locked.nodes[0].active[0], Some(1));
drop(locked);
pending.abort_without_process().expect("same lease return after contention");
assert!(pending.abort_without_process().is_err(), "no second return");"#,
            1,
        ),
        (
            r#"assert!(first.abort_without_process().is_err());
assert!(!first.finished);
assert!(!next.finished);
assert!(!owner.generations.lock().expect("registry observation").abandoned);
next.abort_without_process().expect("restore actual previous fence");
first.abort_without_process().expect("return same first lease");
owner.finish().expect("both exact leases physically absent");"#,
            1,
        ),
    ],
};

pub(super) const LENDER: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_roster/process_purpose/source_cleanup.rs",
    required: &[
        (
            r#"pub(crate) struct SourceCleanupOriginal {
    lender: SourceCleanupLender,
    original: Arc<HostOperationGuard>,
}"#,
            1,
        ),
        (
            r#"pub(crate) fn same_identity(&self, other: &Self) -> bool {
    RosterWeak::ptr_eq(&self.roster, &other.roster)
        && self.index == other.index
        && self.generation == other.generation
        && self.process_generation == other.process_generation
}"#,
            1,
        ),
        (
            r#"pub(in crate::linux_attempt_host) fn bound_source_cleanup_lender(
    &self,
    expected: &crate::linux_attempt_host::original_node::OriginalNativeFreshLaunchError,
) -> Result<SourceCleanupLender, OriginalActorAccountError> {
    let roster = self.roster.upgrade().ok_or(OriginalActorAccountError::Unavailable)?;
    let state = roster.try_lock().map_err(|_| OriginalActorAccountError::Unavailable)?;
    let slot = state.slots.get(self.index)
        .filter(|slot| slot.active == Some(self.generation))
        .ok_or(OriginalActorAccountError::Unavailable)?;
    if !slot.source_controller.as_ref()
        .is_some_and(|controller| std::ptr::eq(controller.as_ref(), expected))
    { return Err(OriginalActorAccountError::Unavailable); }
    let purpose = slot.installed_process.as_ref()
        .filter(|purpose| purpose.ready && purpose.sound)
        .ok_or(OriginalActorAccountError::Unavailable)?;
    let allocation = purpose.journal.incarnations[0].as_ref()
        .filter(|allocation| !allocation.physical_retired)
        .ok_or(OriginalActorAccountError::Unavailable)?;
    Ok(SourceCleanupLender {
        roster: RosterWeak::clone(&self.roster), index: self.index, generation: self.generation,
        process_generation: Some(allocation.process_generation),
    })
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
    let roster = self.roster.upgrade().ok_or(OriginalActorAccountError::Unavailable)?;
    let state = roster.try_lock().map_err(|_| OriginalActorAccountError::Unavailable)?;
    let slot = state.slots.get(self.index)
        .filter(|slot| slot.active == Some(self.generation))
        .ok_or(OriginalActorAccountError::Unavailable)?;
    let purpose = slot.installed_process.as_ref()
        .filter(|purpose| purpose.ready && purpose.sound)
        .ok_or(OriginalActorAccountError::Unavailable)?;
    if let Some(expected) = self.process_generation {
        let allocation = purpose.journal.incarnations[0].as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if allocation.process_generation != expected || allocation.physical_retired {
            return Err(OriginalActorAccountError::Unavailable);
        }
    }
    slot.source_controller.as_ref().cloned()
        .ok_or(OriginalActorAccountError::Unavailable)
}"#,
            1,
        ),
        (
            r#"pub(crate) fn retained_original(
    self,
) -> Result<SourceCleanupOriginal, OriginalActorAccountError> {
    let controller = self.controller()?;
    let attempt = NativeAccountAttempt {
        roster: RosterWeak::clone(&self.roster), index: self.index, generation: self.generation,
    };
    let original = attempt.cleanup_entry()?;
    let current = self.controller()?;
    if !controller.same_owner(&current) || !controller.cleanup_matches(&original) {
        return Err(OriginalActorAccountError::Unavailable);
    }
    Ok(SourceCleanupOriginal {
        lender: self, original,
    })
}"#,
            1,
        ),
        (
            r#"pub(crate) fn checked_original(
    &self,
) -> Result<&HostOperationGuard, crucible_host_resources::host_supervision::HostSupervisionError>
{
    let unavailable =
        || crucible_host_resources::host_supervision::HostSupervisionError::Unavailable;
    let current = self.lender.controller().map_err(|_| unavailable())?;
    if current.cleanup_matches(&self.original) {
        Ok(&self.original)
    } else { Err(unavailable()) }
}"#,
            1,
        ),
    ],
};
