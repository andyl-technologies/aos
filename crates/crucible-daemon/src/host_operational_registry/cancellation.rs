//! Exact live pager cancellation under the registered original Cleanup operation.
//!
//! The existing watcher and explicit quarantine paths retain their original
//! resource owner. This fanout cannot release reservations or certify process
//! cleanup; physical containment remains a separate operation.

use super::*;
use crucible_linux_resource::host_supervision::HostOperationClass;
use crucible_protocol::ram_control::RamControlDisposition;

/// First native cancellation failure and its independent original postcut.
/// The existing Owner body is admitted in registry_resource_floor before any
/// controller exposure, so retaining this inline slot creates no late body.
pub(super) struct CancellationFailure {
    pub(super) _first: RamControlError,
    _original_post: Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
}

impl HostOperationalRegistry {
    /// Cancels pagers sharing the supplied registered original owner.
    ///
    /// # Errors
    /// Refuses unavailable registry ownership, elapsed Cleanup, poisoned or
    /// uncertain transport, and a native response that does not confirm Cancel.
    /// Already canceled targets keep their original reservations on every path.
    pub(crate) fn cancel_registered_pagers(
        &self,
        supervisor: &HostOperationSupervisor,
    ) -> Result<(), HostOperationalError> {
        let cleanup = supervisor
            .begin_control(HostOperationClass::Cleanup)
            .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
        let mut cursor = None;
        let mut first = None;
        let mut visited = 0;
        loop {
            if let Err(source) = cleanup.wait_slice() {
                return Err(first.unwrap_or(HostOperationalError::OriginalBoundary { source }));
            }
            // One charged owner alias fits the existing watcher stack. Release
            // the roster before any client wait; a strict cursor and the original
            // finite roster bound prevent concurrent insertion from renewing work.
            let next = {
                let state = match self.shared.state.try_lock() {
                    Ok(state) => state,
                    Err(_) => return Err(first.unwrap_or(HostOperationalError::Unavailable)),
                };
                state
                    .nodes
                    .iter()
                    .find(|(target, owner)| {
                        cursor.is_none_or(|previous| **target > previous)
                            && owner.supervisor.shares_outer_cap(supervisor)
                    })
                    .map(|(target, owner)| (*target, Arc::clone(owner)))
            };
            let Some((target, owner)) = next else {
                break;
            };
            if visited == MAX_OWNERS {
                return Err(first.unwrap_or(HostOperationalError::Unavailable));
            }
            visited += 1;
            cursor = Some(target);

            // Cancellation wins before attempting to acquire an in-flight client.
            // Its existing exchange sees the same canceled original and exits.
            if owner.supervisor.cancel().is_err() {
                return Err(first.unwrap_or(HostOperationalError::Unavailable));
            }
            let result = cancel_owner(target, &owner, &cleanup);
            let status = owner
                .state
                .try_lock()
                .map_err(unavailable)
                .map(|mut status| {
                    status.convergence = HostRamConvergence::Quarantined;
                });
            if first.is_none() {
                first = result.and(status).err();
            }
        }
        let after = cleanup
            .complete()
            .map_err(|source| HostOperationalError::OriginalBoundary { source });
        match (first, after) {
            (Some(first), _) => Err(first),
            (None, after) => after.map(|_| ()),
        }
    }
}

fn cancel_owner(
    target: HostRamTarget,
    owner: &Owner,
    cleanup: &crucible_linux_resource::host_supervision::HostOperationGuard,
) -> Result<(), HostOperationalError> {
    loop {
        cleanup
            .wait_slice()
            .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
        match owner.client.try_lock() {
            Ok(mut client) => {
                let Some(client) = client.as_mut() else {
                    return Ok(());
                };
                if client.target() != target {
                    return Err(HostOperationalError::Unavailable);
                }
                // Reserve the admitted error slot before the exchange. Refusal
                // or poison cannot replace an initiating transport error later.
                let mut failure = owner.cancellation_failure.try_lock().map_err(unavailable)?;
                let first = client.cancel_under(target.arena_generation, cleanup);
                let original_post = cleanup.wait_slice().err();
                let reply = match first {
                    Ok(reply) if original_post.is_none() => reply,
                    Ok(_) => {
                        return Err(HostOperationalError::OriginalBoundary {
                            source: original_post.ok_or(HostOperationalError::Unavailable)?,
                        });
                    }
                    Err(first) => {
                        if failure.is_none() {
                            *failure = Some(CancellationFailure {
                                _first: first,
                                _original_post: original_post,
                            });
                        }
                        return Err(HostOperationalError::Unavailable);
                    }
                };
                match reply.disposition {
                    RamControlDisposition::Canceled => return Ok(()),
                    RamControlDisposition::Unavailable => {}
                    _ => return Err(HostOperationalError::Unavailable),
                }
            }
            Err(std::sync::TryLockError::WouldBlock) => {}
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(HostOperationalError::Unavailable);
            }
        }
        // Client and failure-slot guards are gone before this same-original wait.
        cleanup
            .wait_for_change()
            .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
    }
}
