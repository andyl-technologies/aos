//! Observes acknowledged native policy and fresh authenticated project charges.
//!
//! The original physical queue selects the snapshot and queries its retained
//! quota helper. Reports contain counts rather than credentials, content hashes
//! or backing handles. Observing status grants no read, release or quota authority.

use super::{
    NativeMetadataOwner,
    consumer::state,
    retention::{Command, NativeOwnerExecutor},
};
use std::{io, sync::mpsc};
use terrane_sdk::host::cache::ExposurePhase;
use tokio::sync::oneshot;

/// Reports one acknowledged host policy with a fresh project quota observation.
///
/// Project charges include reserved and unlinked allocations retained by kernel
/// references. Future logical reservations are reported separately and must not
/// be mistaken for those charges or subtracted to infer free physical space.
/// Counts include retained grace and draining obligations, independently of
/// whether their owners currently accept work. This report is not a capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCacheStatus {
    /// Physical disclosure domain selected by the retained native owner.
    pub domain: String,
    /// Actual synchronized policy generation selected by this queue turn.
    pub generation: u64,
    /// Correlation ID of the fresh query on the retained native helper client.
    pub quota_request_id: u64,
    /// Kernel charged-and-reserved bytes for the complete project partition.
    pub charged_reserved_bytes: u64,
    /// Kernel charged inode count, including retained unlinked inodes.
    pub charged_inodes: u64,
    /// Enforced project hard byte limit from the authenticated helper.
    pub hard_limit_bytes: u64,
    /// Configured logical cache capacity, distinct from the project hard limit.
    pub capacity_bytes: u64,
    /// Sum of distinct durable future-capacity reservations.
    pub reservation_bytes: u64,
    /// Number of durable future-capacity reservation records.
    pub reservations: usize,
    /// Number of durable object pin records, including grace and draining pins.
    pub pins: usize,
    /// Number of durable owner lease records, including retained deadlines.
    pub leases: usize,
    /// Number of durable chunk-to-sealed-file residence records.
    pub residences: usize,
    /// Number of exposure records in the active phase, regardless of deadline.
    pub active_exposures: usize,
    /// Number of exposure records retaining draining obligations.
    pub draining_exposures: usize,
}

impl NativeMetadataOwner {
    /// Observes native policy counts and freshly authenticated kernel quota usage.
    ///
    /// The serialized physical owner checks its original Running custody,
    /// synchronized policy and bootstrap funding before and after the helper
    /// query. The query validates the actual retained project and root bindings;
    /// it cannot use caller-supplied counters or a cached quota observation.
    /// No policy is changed by this command. Normal due maintenance may run
    /// before its queue turn. Callers separately bound their queue wait, and
    /// cancellation leaves the observation with its original physical owner.
    ///
    /// This host-local operation exposes no repository or exposure credentials.
    /// A remote or user-facing status endpoint must independently authorize
    /// access to this domain and select the appropriate presentation scope.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn observe(owner: &terrane_linux::host_cache::NativeMetadataOwner)
    /// #     -> std::io::Result<()> {
    /// let status = owner.status().await?;
    /// println!("charged/reserved: {}", status.charged_reserved_bytes);
    /// println!("future policy holds: {}", status.reservation_bytes);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    /// Refuses a full or stopped queue, uncertain Resume, stale native roots or
    /// snapshot provenance, lost bootstrap funding, invalid accounting, failed
    /// helper authentication, changed project bindings and publisher fencing.
    pub async fn status(&self) -> io::Result<NativeCacheStatus> {
        let (response, receive) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(|| io::Error::other("native owner stopped"))?
            .try_send(Command::Status { response })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "native owner queue full")
                }
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "native owner stopped")
                }
            })?;
        receive
            .await
            .map_err(|_| io::Error::other("native owner stopped before status observation"))?
    }
}

/// Observes the original physical owner without granting maintenance authority.
///
/// # Errors
/// Preserves current custody, policy, helper and accounting failures.
pub(super) fn observe(executor: &NativeOwnerExecutor) -> io::Result<NativeCacheStatus> {
    let running = executor.admission_context()?;
    running.check_current().map_err(io::Error::other)?;
    let result = {
        let mut owner = executor
            .custody()
            .lock()
            .map_err(|_| io::Error::other("native status custody poisoned"))?;
        state::check_ready(executor, &owner)?;
        state::check_bootstrap(&owner, &running)?;
        owner.preparation.recheck()?;

        let reservation_bytes = owner
            .state
            .reservations
            .iter()
            .try_fold(0_u64, |sum, row| {
                sum.checked_add(row.bytes)
                    .ok_or_else(|| io::Error::other("native status future reservations overflow"))
            })?;
        let quota = owner.preparation.quota().observation();
        let active_exposures = owner
            .state
            .exposures
            .iter()
            .filter(|row| row.phase == ExposurePhase::Active)
            .count();
        let result = NativeCacheStatus {
            domain: owner.preparation.config.location.domain().to_owned(),
            generation: owner.generation,
            quota_request_id: quota.request_id,
            charged_reserved_bytes: quota.charged_reserved_bytes,
            charged_inodes: quota.charged_inodes,
            hard_limit_bytes: quota.hard_limit_bytes,
            capacity_bytes: owner.preparation.config.policy.capacity,
            reservation_bytes,
            reservations: owner.state.reservations.len(),
            pins: owner.state.pins.len(),
            leases: owner.state.leases.len(),
            residences: owner.state.residences.len(),
            active_exposures,
            draining_exposures: owner.state.exposures.len() - active_exposures,
        };

        // The helper query cannot replace the actual policy or Running checks.
        state::check_ready(executor, &owner)?;
        state::check_bootstrap(&owner, &running)?;
        result
    };
    running.check_current().map_err(io::Error::other)?;
    Ok(result)
}
