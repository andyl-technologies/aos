//! Synchronizes consumer policy mutations under actual Running owner custody.
//!
//! The retained bootstrap funds serialized metadata work. New consumer grants
//! additionally hold a distinct future budget until their actual final release.
//! Failed effects keep faulted custody and never manufacture an acknowledgment.

use super::{ConsumerJob, invalid};
use crate::publisher_local::client::PublisherRunningContext;
use crate::{
    host_cache::owner::{
        publication::residence::check_snapshot,
        recovery,
        retention::{Custody, NativeOwnerExecutor},
        snapshot,
    },
    host_quota::synchronized_allocated_bytes,
};
use std::{
    fs::File,
    io::{self, Read},
    os::unix::fs::MetadataExt,
    sync::Arc,
};
use terrane_sdk::host::cache::CacheState;

/// Separates full-owner quota usage from future policy holds after real IO.
pub(in crate::host_cache::owner) struct PolicyObservation {
    /// Fresh kernel charged-and-reserved usage for the complete project.
    pub(in crate::host_cache::owner) charged: u64,
    /// Sum of distinct future policy holds after synchronization.
    pub(in crate::host_cache::owner) future: u64,
}

/// Checks actual writable custody and its complete synchronized policy snapshot.
///
/// # Errors
/// Refuses another worker, cold/faulted state or changed snapshot provenance.
pub(in crate::host_cache::owner) fn check_ready(
    executor: &NativeOwnerExecutor,
    owner: &Custody,
) -> io::Result<()> {
    executor.check_physical_worker()?;
    check_snapshot(owner)?;
    if owner.faulted || owner.recovery_required {
        return Err(invalid(
            "consumer mutation requires writable Running custody",
        ));
    }
    Ok(())
}

/// Checks this actual acknowledged context and its original metadata budget.
///
/// This performs no RPC while embedded state is held. Context liveness is
/// checked separately before and after actual IO outside that state lock.
///
/// # Errors
/// Refuses a foreign session or changed original bootstrap hold.
pub(in crate::host_cache::owner) fn check_bootstrap(
    owner: &Custody,
    running: &Arc<PublisherRunningContext>,
) -> io::Result<()> {
    let id = hex(running.retained_bootstrap_id());
    if !Arc::ptr_eq(
        running.publisher_session(),
        &owner.preparation.publisher_session(),
    ) || !owner.state.reservations.iter().any(|row| {
        row.id == id
            && row.owner == owner.preparation.config.quota_owner
            && row.bytes == owner.preparation.config.metadata_sync_hold_bytes
    }) {
        return Err(invalid(
            "consumer mutation lost original Running bootstrap custody",
        ));
    }
    Ok(())
}

/// Generates a fresh native operation identifier without colliding with old policy.
///
/// # Errors
/// Refuses unavailable entropy or an occupied reservation/lease name.
pub(super) fn fresh_token(owner: &Custody) -> io::Result<String> {
    let mut bytes = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let token = hex(&bytes);
    if owner.state.reservations.iter().any(|row| row.id == token)
        || owner.state.leases.iter().any(|row| {
            row.owner == format!("consumer:{token}")
                || row.owner == format!("consumer-grace:{token}")
        })
    {
        return Err(invalid("consumer operation identifier collision"));
    }
    Ok(token)
}

/// Prepares the exact owned state transition before any snapshot write.
///
/// # Errors
/// Refuses stale custody, missing funding, overflowing limits or actual capacity.
pub(in crate::host_cache::owner) fn begin(
    executor: &NativeOwnerExecutor,
    owner: &mut Custody,
    running: &Arc<PublisherRunningContext>,
    next: CacheState,
    additional: u64,
    started: Option<&mut bool>,
) -> io::Result<snapshot::PreparedSnapshotWrite> {
    check_ready(executor, owner)?;
    check_bootstrap(owner, running)?;
    next.encoded_len(owner.preparation.config.state)
        .map_err(io::Error::other)?;
    owner.preparation.recheck()?;
    recovery::check_charge(owner, additional)?;
    if let Some(started) = started {
        *started = true;
    }
    owner.begin_mutation()?;
    owner.faulted = true;
    owner.state = next;
    snapshot::prepare(executor, owner)
}

/// Reconciles actual snapshot/directory blocks and fresh full-project usage.
///
/// # Errors
/// Refuses failed/foreign state, changed generation, native measurements or quota.
pub(in crate::host_cache::owner) fn finish(
    owner: &mut Custody,
    generation: u64,
) -> io::Result<PolicyObservation> {
    check_snapshot(owner)?;
    if !owner.faulted || owner.generation != generation {
        return Err(invalid(
            "consumer completion lost its physical mutation phase",
        ));
    }
    owner.snapshot_allocated_bytes = owner
        .snapshot
        .as_ref()
        .ok_or_else(|| invalid("consumer snapshot absent"))
        .and_then(|(file, _)| synchronized_allocated_bytes(file))?;
    owner.directory_allocated_bytes = synchronized_allocated_bytes(&owner.directory)?;
    owner.preparation.recheck()?;
    recovery::check_charge(owner, 0)?;
    let future = owner
        .state
        .reservations
        .iter()
        .try_fold(0_u64, |sum, hold| {
            sum.checked_add(hold.bytes)
                .ok_or_else(|| invalid("consumer future holds overflow"))
        })?;
    let charged = owner
        .preparation
        .quota()
        .observation()
        .charged_reserved_bytes;
    owner.faulted = false;
    Ok(PolicyObservation { charged, future })
}

/// Verifies this original consumer's exact live or grace records and future hold.
///
/// # Errors
/// Refuses changed source custody or any missing/changed lease, pin or reservation.
pub(super) fn check_job(
    owner: &Custody,
    job: &ConsumerJob,
    lease: &str,
    expiry: u64,
) -> io::Result<()> {
    job.source.check_consumer_backing(owner)?;
    check_bootstrap(owner, &job.running)?;
    let hash = hex(job.source.protected_object_digest());
    if !owner
        .state
        .leases
        .iter()
        .any(|row| row.owner == lease && row.expires == expiry)
        || !owner
            .state
            .pins
            .iter()
            .any(|row| row.owner == lease && row.hash == hash && row.expires == expiry)
        || !owner.state.reservations.iter().any(|row| {
            row.id == job.token
                && row.owner == owner.preparation.config.quota_owner
                && row.bytes == job.hold
        })
    {
        return Err(invalid(
            "consumer lost its original durable pin, lease or hold",
        ));
    }
    Ok(())
}

/// Synchronizes the exact native layout root without an embedded mutex held.
///
/// # Errors
/// Refuses stale layout bindings and native open or synchronization errors.
pub(in crate::host_cache::owner) fn synchronize_policy(
    executor: &NativeOwnerExecutor,
) -> io::Result<()> {
    let layout = {
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("consumer policy custody poisoned"))?;
        Arc::clone(owner.preparation.layout())
    };
    layout.recheck()?;
    let root = File::from(rustix::fs::openat(
        &layout.root,
        ".",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    let metadata = root.metadata()?;
    if (metadata.dev(), metadata.ino()) != layout.directory_binding("layout-root")? {
        return Err(invalid("consumer policy synchronization root changed"));
    }
    rustix::fs::syncfs(&root)?;
    layout.recheck()
}

/// Encodes policy identifiers without introducing a content identity.
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
