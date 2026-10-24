//! Binds exact saved-operation custody and physical return ordering.

use super::{Companion, Contract};

const FORK_TARGET_LOCAL_REQUIRED: &[(&str, usize)] = &[
    (
        r#"pub fn try_finish(&mut self) -> Result<(), QemuForkTargetConstructionError> {
    if self.returned {
        return Ok(());
    }
    let (returned, result) = self
        .attempt
        .retry_target_construction(self.epoch, self.process_generation);
    // Record the irreversible slot return before propagating its report.
    self.returned |= returned;
    if self.returned {
        drop(self.failed_permit.take());
    }
    result
}"#,
        1,
    ),
    (
        r#"fn retry_target_construction(
    &self,
    epoch: u64,
    process_generation: u64,
) -> (bool, Result<(), QemuForkTargetConstructionError>) {
    let unavailable =
        || QemuForkTargetConstructionError::Original(OriginalActorAccountError::Unavailable);
    let Some(roster) = self.roster.upgrade() else {
        return (false, Err(unavailable()));
    };
    let Ok(mut state) = roster.lock() else {
        return (false, Err(unavailable()));
    };
    let Some(slot) = state
        .slots
        .get_mut(self.index)
        .filter(|slot| slot.active == Some(self.generation))
    else {
        return (false, Err(unavailable()));
    };
    if epoch == 0 || epoch > slot.fork_target.next_epoch {
        return (false, Err(unavailable()));
    }
    if slot.fork_target.returned_epoch >= epoch {
        return (true, Ok(()));
    }
    if slot.fork_target.occupied != Some(epoch)
        || slot.fork_target.reserved_process_generation != Some(process_generation)
    {
        return (false, Err(unavailable()));
    }
    let result = if slot.fork_target.unsettled.is_some() {
        retry_unsettled_target_raw(slot)
    } else if slot.fork_target.physical_closed {
        finish_target_control_return(slot)
    } else if !slot.fork_target.born {
        // begin_birth precedes the first dispatcher/cgroup effect. Every
        // canonical physical field must also be absent before this exact
        // logical role can close under its existing Cleanup.
        let target = &slot.fork_target;
        if target.envelope.is_some()
            || target.process_binding.is_some()
            || target.control.is_some()
            || target.process_generation.is_some()
            || target.ram_registration_generation.is_some()
        {
            Err(unavailable())
        } else {
            match target.cleanup() {
                Err(first) => Err(first.into()),
                Ok(cleanup) => {
                    let before = cleanup.wait_slice().map(|_| ()).map_err(|first| {
                        QemuForkTargetConstructionError::Original(first.into())
                    });
                    drop(cleanup);
                    match before {
                        Err(first) => Err(first),
                        Ok(()) => {
                            slot.fork_target.physical_closed = true;
                            close_target_slot(slot)
                                .map_err(QemuForkTargetConstructionError::Original)
                        }
                    }
                }
            }
        }
    } else {
        // A successfully returned host guard remains the physical owner;
        // the cleanup loan must never steal it or attest its destruction.
        Err(unavailable())
    };
    (slot.fork_target.returned_epoch >= epoch, result)
}"#,
        1,
    ),
    (r#"HostOperationClass::Preparation"#, 0),
    (r#"Instant::now("#, 0),
];

// Both scanners retain the same complete Target cleanup obligations.
const FORK_TARGET_REQUIRED: [(&str, usize);
    super::super::TARGET_CLEANUP_REQUIRED.len() + FORK_TARGET_LOCAL_REQUIRED.len()] = {
    let mut required =
        [("", 0); super::super::TARGET_CLEANUP_REQUIRED.len() + FORK_TARGET_LOCAL_REQUIRED.len()];
    let mut index = 0;
    while index < super::super::TARGET_CLEANUP_REQUIRED.len() {
        required[index] = super::super::TARGET_CLEANUP_REQUIRED[index];
        index += 1;
    }
    let mut local = 0;
    while local < FORK_TARGET_LOCAL_REQUIRED.len() {
        required[index + local] = FORK_TARGET_LOCAL_REQUIRED[local];
        local += 1;
    }
    required
};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-qemu-host",
    target: "src/linux_attempt_host/original_roster/fork_target",
    required: &FORK_TARGET_REQUIRED,
    expressions: &[
        (
            r#"self.attempt.retry_target_construction(self.epoch, self.process_generation)"#,
            1,
        ),
        (r#"retry_unsettled_target_raw(slot)"#, 2),
    ],
    identifiers: &[
        (r#"retry_target_construction"#, 2),
        (r#"retry_unsettled_target"#, 1),
        (r#"retry_unsettled_target_raw"#, 3),
    ],
    companions: &[Companion {
        path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/original_roster.rs",
        required: &[
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
    }],
};
