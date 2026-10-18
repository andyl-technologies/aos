//! Owns durable consumer grants, renewal, release grace and periodic expiry.
//!
//! Only the physical owner constructs a grant after synchronizing an actual pin
//! over original verified backing. Public handles contain no caller-selected
//! descriptor or authority token. Read views remain independent of embedded
//! state; mutation commands retain their actual resources after cancellation.

mod clock;
mod lifecycle;
mod state;
mod sweep;
mod view;

pub(in crate::host_cache::owner) use lifecycle::{acquire, release, renew};
pub(in crate::host_cache::owner) use sweep::{background as sweep_background, run as sweep};
pub(in crate::host_cache::owner) use view::{ReadBudget, ReadView};

use super::retention::{Command, Custody, NativeMetadataOwner};
use crate::{
    host_cache::NativeResidentChunkSource, publisher_local::client::PublisherRunningContext,
};
use clock::Deadline;
use std::{
    io,
    sync::{Arc, Mutex, mpsc},
};
use terrane_core::identity::Identity;
use tokio::sync::oneshot;

/// Reports independent measurements after an actual synchronized lease mutation.
#[derive(Clone, Copy, Debug)]
pub struct NativeLeaseAccounting {
    /// Synchronized allocated blocks of the original sealed inode alone.
    pub synchronized_sealed_inode_bytes: u64,
    /// Fresh charged-and-reserved kernel quota usage for the complete owner.
    pub charged_reserved_bytes: u64,
    /// Distinct future-capacity policy holds, never measured physical allocation.
    pub future_hold_bytes: u64,
}

/// Holds one genuinely acknowledged consumer pin over original native backing.
///
/// Cloning shares the same lease and does not add pins or allocation. Renewal
/// and release require the original physical owner. Dropping a handle leaves
/// its durable lease to periodic expiry; no metadata IO occurs in its Drop.
#[derive(Clone)]
pub struct NativeConsumerLease {
    view: Arc<ReadView>,
    initial_accounting: NativeLeaseAccounting,
}

/// Retains the exact state expected for this original physical lease operation.
enum Phase {
    /// Retains preflight or attempted effects without acknowledging a grant.
    Pending,
    /// Tracks synchronized live policy; reads still check revocation and both clocks.
    Live(Deadline),
    /// Retains already-revoked protection until its original durable deadline.
    Grace { owner: String, end: u64 },
    /// Records completed durable removal while actual reads finish dropping custody.
    Removed,
}

/// Owns actual backing, context and every attempted consumer pin effect.
pub(in crate::host_cache::owner) struct ConsumerJob {
    custody: Arc<Mutex<Custody>>,
    running: Arc<PublisherRunningContext>,
    source: Arc<NativeResidentChunkSource>,
    view: Arc<ReadView>,
    token: String,
    hold: u64,
    generation: u64,
    started: bool,
    phase: Phase,
    accounting: Option<NativeLeaseAccounting>,
}

impl ConsumerJob {
    /// Recognizes absence of attempted durable mutations for rejection cleanup only.
    pub(in crate::host_cache::owner) fn is_effect_free(&self) -> bool {
        !self.started
    }

    /// Compares actual original view and physical custody objects for routing only.
    pub(in crate::host_cache::owner) fn matches_view(
        &self,
        view: &Arc<ReadView>,
        custody: &Arc<Mutex<Custody>>,
    ) -> bool {
        Arc::ptr_eq(&self.view, view) && Arc::ptr_eq(&self.custody, custody)
    }

    /// Revokes the original view without claiming a durable decrement.
    pub(in crate::host_cache::owner) fn revoke_view(&self) {
        self.view.close();
    }

    /// Recognizes removed policy and actual closure of every started read reference.
    pub(in crate::host_cache::owner) fn can_reclaim(&self) -> bool {
        matches!(self.phase, Phase::Removed) && self.view.reads_quiescent()
    }
}

/// Transfers complete consumer command ownership to the native physical worker.
pub(in crate::host_cache::owner) enum ConsumerCommand {
    /// Synchronizes a new pin before returning its original opaque read view.
    Pin {
        identity: Identity,
        expires: u64,
        response: oneshot::Sender<io::Result<NativeConsumerLease>>,
    },
    /// Extends the original registered view after native synchronization.
    Renew {
        view: Arc<ReadView>,
        expires: u64,
        response: oneshot::Sender<io::Result<NativeLeaseAccounting>>,
    },
    /// Revokes a registered view and persists bounded grace protection.
    Release {
        view: Arc<ReadView>,
        response: oneshot::Sender<io::Result<NativeLeaseAccounting>>,
    },
    /// Runs periodic expiry through the same actual physical command path.
    Sweep {
        response: oneshot::Sender<io::Result<usize>>,
    },
}

/// Completes one owned consumer command before attempting its cancellable reply.
pub(in crate::host_cache::owner) async fn execute(
    executor: &mut super::retention::NativeOwnerExecutor,
    command: ConsumerCommand,
) {
    match command {
        ConsumerCommand::Pin {
            identity,
            expires,
            response,
        } => {
            let _ = response.send(acquire(executor, identity, expires).await);
        }
        ConsumerCommand::Renew {
            view,
            expires,
            response,
        } => {
            let _ = response.send(renew(executor, view, expires).await);
        }
        ConsumerCommand::Release { view, response } => {
            let _ = response.send(release(executor, view).await);
        }
        ConsumerCommand::Sweep { response } => {
            let _ = response.send(sweep(executor).await);
        }
    }
}

impl NativeMetadataOwner {
    /// Synchronizes a new consumer pin over this owner's verified resident chunk.
    ///
    /// The absolute Unix expiry must remain live through acknowledgment. Source
    /// lookup uses original native publication or completed recovery custody.
    /// A dropped waiter never cancels accepted physical pin work.
    ///
    /// # Errors
    /// Refuses an elapsed/unrepresentable expiry, a full/stopped queue, absent
    /// Resume or backing, exhausted resources, and native durability/quota failures.
    pub async fn pin_resident_chunk(
        &self,
        identity: Identity,
        expires: u64,
    ) -> io::Result<NativeConsumerLease> {
        Deadline::new(expires)?;
        let (response, receive) = oneshot::channel();
        self.send_consumer_command(ConsumerCommand::Pin {
            identity,
            expires,
            response,
        })?;
        receive.await.map_err(|_| stopped())?
    }

    /// Extends the exact original live lease after durable synchronization.
    ///
    /// Pending renewal leaves the old grant readable under its original deadline.
    /// The returned accounting describes this completed mutation, not current usage.
    ///
    /// # Errors
    /// Refuses foreign, released or expired handles, nonincreasing deadlines,
    /// queue exhaustion, changed native custody, and durability/quota failures.
    pub async fn renew_consumer_lease(
        &self,
        lease: &NativeConsumerLease,
        expires: u64,
    ) -> io::Result<NativeLeaseAccounting> {
        let (response, receive) = oneshot::channel();
        self.send_consumer_command(ConsumerCommand::Renew {
            view: Arc::clone(&lease.view),
            expires,
            response,
        })?;
        receive.await.map_err(|_| stopped())?
    }

    /// Revokes the original handle and durably preserves its release grace.
    ///
    /// Lease expiry starts grace at the original deadline, so a delayed sweep
    /// cannot add another full grace interval. Repeated release is idempotent.
    ///
    /// # Errors
    /// Refuses foreign handles, a full/stopped queue, changed native custody,
    /// unrepresentable grace, and native synchronization/quota failures.
    pub async fn release_consumer_lease(
        &self,
        lease: &NativeConsumerLease,
    ) -> io::Result<NativeLeaseAccounting> {
        if !lease.view.belongs_to(&self.consumer_reads) {
            return Err(invalid("consumer lease belongs to another physical owner"));
        }
        if let Some(accounting) = lease.view.released_accounting() {
            return Ok(accounting);
        }
        let (response, receive) = oneshot::channel();
        self.send_consumer_command(ConsumerCommand::Release {
            view: Arc::clone(&lease.view),
            response,
        })?;
        receive.await.map_err(|_| stopped())?
    }

    /// Runs the same expiry sweep used periodically by the physical worker.
    ///
    /// Returns the number of expired lease records removed after actual durable
    /// synchronization. Grace transitions alone do not count as removal.
    ///
    /// # Errors
    /// Refuses a full/stopped queue, absent writable Running custody, changed
    /// policy, and native synchronization or quota failures.
    pub async fn sweep_consumer_leases(&self) -> io::Result<usize> {
        let (response, receive) = oneshot::channel();
        self.send_consumer_command(ConsumerCommand::Sweep { response })?;
        receive.await.map_err(|_| stopped())?
    }

    fn send_consumer_command(&self, command: ConsumerCommand) -> io::Result<()> {
        self.commands
            .as_ref()
            .ok_or_else(stopped)?
            .try_send(Command::Consumer(command))
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "consumer queue full")
                }
                mpsc::TrySendError::Disconnected(_) => stopped(),
            })
    }
}

fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "consumer command owner stopped")
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
