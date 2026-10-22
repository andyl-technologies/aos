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
            for entry in pool
                .nodes
                .iter_mut()
                .filter(|entry| entry.as_ref().is_some_and(|node| node.world == world))
            {
                let node = entry
                    .as_mut()
                    .ok_or_else(|| missing_authority("retain pending native node"))?;
                cleanup
                    .wait_slice()
                    .map_err(|source| original_roster::original_error(source.into()))?;
                let result = node.retry_cleanup();
                // Exact native return is already recorded inside the same
                // construction owner, independently of a late post refusal.
                if node.can_remove() {
                    *entry = None;
                }
                result?;
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
    expressions: &[(r#"node.retry_cleanup()"#, 1)],
    identifiers: &[
        (r#"retry_native_world_construction"#, 1),
        (r#"retry_cleanup"#, 1),
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
                (super::roster_retirement::RECONCILE_BODY, 1),
                super::roster_retirement::SOURCE_CLEANUP.required[0],
                super::roster_retirement::SOURCE_CLEANUP.required[1],
                super::roster_retirement::SOURCE_CLEANUP.required[2],
                super::roster_retirement::SOURCE_CLEANUP.required[3],
                super::roster_retirement::SOURCE_CLEANUP.required[4],
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
        super::node_construction::NODE_OWNER,
        super::node_construction::NODE_BIRTH,
        super::node_construction::NODE_ISSUE,
        super::node_construction::NODE_CONVERSION,
        super::node_construction::NODE_SUBDIVISION,
        super::node_construction::NODE_LEDGER,
        super::node_construction::NODE_RETURN_HISTORY,
        super::node_construction::NODE_CREDIT_BIRTH,
        super::node_construction::NODE_PUBLISHER,
        super::node_construction::NODE_LAYOUT,
        super::node_construction::NODE_ROSTER_RETURN,
        super::node_construction::NODE_CREDIT_RETURN,
        super::roster_retirement::SOURCE_ORIGINAL,
    ],
};
