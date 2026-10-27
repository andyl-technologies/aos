//! Retires cold derived indexes before reconciling their disposable copy holds.
//!
//! No cold filename, root tag, state row or verity measurement authorizes index
//! adoption. Recompilation from canonical nodes supplies future cache entries.
//! Existing kernel references survive unlink and remain in actual project charge.

use crate::{
    host_cache::owner::{
        recovery::check_charge, recovery_namespace::SharedNamespaceObservation,
        retention::NativeOwnerExecutor, snapshot,
    },
    publisher_local::client::PublisherRecoveryContext,
};
use std::io;
use terrane_sdk::host::cache::HostDomainLocation;

/// Performs a funded cold retirement and preserves every unrelated policy row.
///
/// # Errors
/// Refuses a foreign recovery turn, malformed reserved names or holds, unsafe
/// native custody, partial namespace effects, state durability or actual quota.
pub(in crate::host_cache::owner) async fn retire(
    executor: &NativeOwnerExecutor,
    shared: &mut SharedNamespaceObservation,
    bootstrap: &[u8; 16],
    context: &PublisherRecoveryContext<HostDomainLocation>,
) -> io::Result<Option<u64>> {
    executor.check_physical_worker()?;
    let custody = executor.custody();
    let (session, retired_policy) = {
        let owner = custody
            .lock()
            .map_err(|_| invalid("surface recovery custody poisoned"))?;
        owner.check_synchronized_bootstrap(bootstrap)?;
        if !owner.faulted
            || !owner.recovery_required
            || owner.recovery_id.is_some()
            || !owner.surface_indexes.is_empty()
        {
            return Err(invalid(
                "surface retirement lost original cold recovery phase",
            ));
        }
        let cold = owner
            .recovery_cold
            .as_ref()
            .ok_or_else(|| invalid("surface recovery lost cold candidates"))?;
        (
            owner.preparation.publisher_session(),
            cold.without_surface_reservations()?,
        )
    };
    session
        .check_recovery_context(context)
        .map_err(io::Error::other)?;
    if !shared.has_surface_indexes()? && retired_policy.is_none() {
        return Ok(None);
    }

    shared.discard_surface_indexes()?;
    // Replace the original O_PATH census only after all namespace effects finish.
    // Kernel references outside this owner remain charged even when this drops
    // the last local inspection descriptor for an unlinked index.
    {
        let owner = custody
            .lock()
            .map_err(|_| invalid("surface recovery custody poisoned"))?;
        owner.check_current()?;
        *shared = SharedNamespaceObservation::inspect(&owner.preparation)?;
    }
    if shared.has_surface_indexes()? {
        return Err(invalid("surface names survived cold retirement"));
    }
    session
        .check_recovery_context(context)
        .map_err(io::Error::other)?;
    let Some(retired_policy) = retired_policy else {
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("surface recovery custody poisoned"))?;
        owner.check_synchronized_bootstrap(bootstrap)?;
        owner.preparation.recheck()?;
        check_charge(&owner, 0)?;
        return Ok(Some(owner.generation));
    };
    let write = {
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("surface recovery custody poisoned"))?;
        owner.check_synchronized_bootstrap(bootstrap)?;
        shared.check_current()?;
        // Actual full-project charge includes retained descriptors and mappings.
        // Releasing a future copy allowance never credits those physical bytes.
        owner.preparation.recheck()?;
        check_charge(&owner, 0)?;
        let next = retired_policy.bootstrap(&owner.preparation.config, bootstrap)?;
        owner.begin_mutation()?;
        owner.state = next;
        owner.recovery_cold = Some(retired_policy);
        snapshot::prepare(executor, &mut owner)?
    };
    snapshot::persist(executor, write).await?;
    session
        .check_recovery_context(context)
        .map_err(io::Error::other)?;
    let mut owner = custody
        .lock()
        .map_err(|_| invalid("surface recovery custody poisoned"))?;
    owner.check_synchronized_bootstrap(bootstrap)?;
    owner.preparation.recheck()?;
    check_charge(&owner, 0)?;
    Ok(Some(owner.generation))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
