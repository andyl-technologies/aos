//! Binds exact saved-operation custody and physical return ordering.

use super::{Companion, Contract};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-qemu-host",
    target: "src/linux_attempt_host/normal_pool",
    required: &[
        (
            r#"pub fn retry_native_world_construction(
    &mut self,
    loan: &AuthenticatedNativeWorldCleanupLoan,
) -> Result<(), QemuVmRealizationError> {
    let pool = self
        .normal_pool
        .as_mut()
        .ok_or_else(|| missing_authority("retain pending native World"))?;
    let world = pool
        .worlds
        .iter()
        .position(|world| {
            world
                .as_ref()
                .is_some_and(|world| world.matches_cleanup_loan(loan))
        })
        .ok_or_else(|| missing_authority("match pending native World"))?;
    let cleanup = loan
        .retained_cleanup()
        .map_err(|source| original_roster::original_error(source.into()))?;
    let result = (|| {
        for node in pool
            .nodes
            .iter_mut()
            .flatten()
            .filter(|node| node.world == world)
        {
            cleanup
                .wait_slice()
                .map_err(|source| original_roster::original_error(source.into()))?;
            node.roster.retry_unsettled()?;
            node.roster
                .verify_quiescent()
                .map_err(original_roster::original_error)?;
        }
        Ok(())
    })();
    original_roster::after_cleanup(result, &cleanup)
}"#,
            1,
        ),
        (r#"loan.retained_cleanup()"#, 1),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"begin_original_cleanup_control("#, 0),
        (r#"Instant::now("#, 0),
    ],
    expressions: &[(r#"node.roster.retry_unsettled()"#, 1)],
    identifiers: &[
        (r#"retry_native_world_construction"#, 1),
        (r#"retry_unsettled"#, 1),
    ],
    companions: &[
        Companion {
            path: "crates/crucible/host/crucible-host-resources/src/host_services/process_birth/executor_purpose/native_pool.rs",
            required: &[
                (
                    r#"pub fn matches_cleanup_loan(&self, loan: &AuthenticatedNativeWorldCleanupLoan) -> bool {
    self.epoch == loan.epoch
        && self
            .held
            .as_ref()
            .is_some_and(|held| Arc::ptr_eq(held, &loan.held))
}"#,
                    1,
                ),
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
            path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_roster.rs",
            required: &[
                (
                    r#"pub fn retry_unsettled(&mut self) -> Result<(), QemuVmRealizationError> {
    let held = self
        .held
        .as_ref()
        .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?;
    let mut state = held
        .try_lock()
        .map_err(|_| original_error(OriginalActorAccountError::Unavailable))?;
    for slot in &mut state.slots {
        fork_target::retry_unsettled_target(slot)?;
        if slot.fork_target.is_owned() || slot.unsettled.is_none() {
            continue;
        }
        let cleanup = retain_cleanup(slot).map_err(original_error)?;
        slot.unsettled
            .as_mut()
            .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?
            .finish(&cleanup)?;
        close_slot(slot).map_err(original_error)?;
        slot.unsettled = None;
    }
    Ok(())
}"#,
                    1,
                ),
                (
                    r#"fn retain_cleanup(
    slot: &mut NativeSlot,
) -> Result<Arc<HostOperationGuard>, OriginalActorAccountError> {
    if slot.cleanup.is_none() {
        let credit = slot
            .credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        // The guard Arc is within the already admitted TOTAL metadata. The
        // finite supervisor BTree was charged once as initial actor structure.
        let extent = cleanup_control_extent()?;
        if let Some(purpose) = slot.installed_process.as_mut()
            && !purpose.consume_cleanup(extent)
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        slot.require_metadata_assignment(extent)?;
        // Returned guard aliases may outlive a closed generation. Keep each
        // assigned body charged until whole-roster retirement, rather than
        // treating completion or dropping this slot's alias as physical free.
        slot.cleanup_controls_bytes = slot
            .cleanup_controls_bytes
            .checked_add(extent)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        slot.cleanup = Some(Arc::new(credit.begin_cleanup()?));
    }
    let cleanup = slot
        .cleanup
        .as_ref()
        .ok_or(OriginalActorAccountError::Unavailable)?;
    cleanup.wait_slice()?;
    Ok(Arc::clone(cleanup))
}"#,
                    1,
                ),
                (
                    r#"fn finish(&mut self, cleanup: &HostOperationGuard) -> Result<(), QemuVmRealizationError> {
    cleanup
        .wait_slice()
        .map_err(|source| original_error(source.into()))?;
    if let Some(process) = self.process.as_mut() {
        process.finish_under_original(cleanup)?;
    }
    self.process = None;
    if let Some(group) = self.unconfigured.as_mut() {
        group.remove_under_original(cleanup)?;
    }
    self.unconfigured = None;
    if let Some(state) = self.native_resources.as_ref() {
        NativeResourceState::drain(state);
    }
    self.native_resources = None;
    cleanup
        .wait_slice()
        .map_err(|source| original_error(source.into()))?;
    let result = if let Some(storage) = self.storage.as_mut() {
        storage.cleanup_under_original(cleanup)
    } else {
        Ok(())
    };
    if result.is_ok() {
        // Physical release is recorded before the separate original
        // postcut. Refusal leaves the actual owner in this same slot.
        self.storage = None;
    }
    after_cleanup(result, cleanup)
}"#,
                    1,
                ),
                (
                    r#"pub(super) fn after_cleanup<T>(
    result: Result<T, QemuVmRealizationError>,
    cleanup: &HostOperationGuard,
) -> Result<T, QemuVmRealizationError> {
    after_boundary(result, cleanup.wait_slice().map(|_| ()).map_err(Into::into))
}"#,
                    1,
                ),
                (
                    r#"pub(in crate::linux_attempt_host) fn after_boundary<T>(
    result: Result<T, QemuVmRealizationError>,
    original: Result<(), OriginalActorAccountError>,
) -> Result<T, QemuVmRealizationError> {
    match (result, original) {
        (result, Ok(())) => result,
        (Ok(_), Err(original)) => Err(original_error(original)),
        (Err(primary), Err(original)) => Err(QemuVmRealizationError::ModelCopy {
            source: Box::new(NativeAccountBoundaryError {
                primary: Some(primary),
                original,
            }),
        }),
    }
}"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_roster/fork_target.rs",
            required: super::super::TARGET_CLEANUP_REQUIRED,
        },
    ],
};
