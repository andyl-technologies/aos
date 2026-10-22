//! Requests bounded physical eviction after input verification and before funding.
//!
//! Pending retirement is not released space. The original quota observation and
//! all future holds must fit after eviction, before reservation can begin.

use super::{
    super::{publication::eviction, retention::NativeOwnerExecutor},
    state,
};
use std::io;

/// Makes at most one physical eviction attempt for a verified incoming payload.
///
/// The exclusive worker retains the original registered input and dictionary
/// dependencies across this turn. No embedded custody or job mutex spans the
/// publisher exchange. Pending deletion keeps its real charge; a caller may
/// retry after actual cleanup without leaving a failed input's reservation.
///
/// # Errors
/// Refuses stale custody, excessive holds, unavailable native evidence, failed
/// eviction and capacity that remains above the selected low-watermark target.
pub(super) async fn prepare(executor: &mut NativeOwnerExecutor, payload: usize) -> io::Result<()> {
    let incoming = {
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| io::Error::other("admission pressure custody poisoned"))?;
        owner.check_current()?;
        state::incoming_hold(&owner, payload)?
    };
    prepare_hold(executor, incoming).await
}

/// Makes one host-pressure attempt for an already verified finite copy hold.
///
/// The caller retains its original verified input and chooses the actual
/// configured future hold; this helper creates no reservation or native job.
///
/// # Errors
/// Refuses stale custody, excess holds, failed eviction or unmet actual capacity.
pub(in crate::host_cache::owner) async fn prepare_hold(
    executor: &mut NativeOwnerExecutor,
    incoming: u64,
) -> io::Result<()> {
    {
        let mut owner = executor
            .custody()
            .lock()
            .map_err(|_| io::Error::other("admission pressure custody poisoned"))?;
        owner.check_current()?;
        owner.preparation.recheck()?;
        if incoming > owner.preparation.config.policy.capacity {
            return Err(capacity());
        }
        match state::check_incoming(&owner, incoming) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::StorageFull => {}
            Err(error) => return Err(error),
        }
    }

    // Repeated retirement while the same original FDs remain open would evict
    // more content without releasing quota. Let the owner's normal due-cut and
    // accepted-command ordering complete actual retirement before a later retry.
    if !eviction::run(executor, incoming).await?.target_met {
        return Err(capacity());
    }

    let mut owner = executor
        .custody()
        .lock()
        .map_err(|_| io::Error::other("admission pressure custody poisoned"))?;
    owner.check_current()?;
    owner.preparation.recheck()?;
    state::check_incoming(&owner, incoming)
}

fn capacity() -> io::Error {
    io::Error::new(
        io::ErrorKind::StorageFull,
        "verified admission cannot fit after bounded cache eviction",
    )
}
