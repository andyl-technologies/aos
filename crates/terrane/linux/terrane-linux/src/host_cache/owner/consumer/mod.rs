//! Owns durable consumer grants, renewal, release grace and periodic expiry.
//!
//! Only the physical owner constructs a grant after synchronizing an actual pin
//! over original verified backing. Public handles contain no caller-selected
//! descriptor or authority token. Read views remain independent of embedded
//! state; mutation commands retain their actual resources after cancellation.

pub(in crate::host_cache::owner) mod clock;
mod lifecycle;
mod scoped_file;
pub(in crate::host_cache::owner) mod source;
pub(in crate::host_cache::owner) mod state;
mod sweep;
mod view;

pub(in crate::host_cache::owner) use lifecycle::{acquire, acquire_object, release, renew};
pub use scoped_file::NativeFileBacking;
pub(crate) use scoped_file::NativeFilePreparation;
pub(in crate::host_cache::owner) use sweep::{background as sweep_background, run as sweep};
pub use view::NativeSealedBacking;
pub(in crate::host_cache::owner) use view::{ReadBudget, ReadView};

use super::retention::{Command, Custody, NativeMetadataOwner};
use crate::publisher_local::client::PublisherRunningContext;
use clock::Deadline;
use std::{
    io,
    sync::{Arc, Mutex, mpsc},
};
use terrane_format::identity::{Identity, IdentityKind};
use tokio::sync::oneshot;

/// Reports independent measurements after an actual synchronized lease mutation.
#[derive(Clone, Copy, Debug)]
pub struct NativeLeaseAccounting {
    /// Synchronized allocated blocks of the original sealed inode alone.
    pub synchronized_sealed_inode_bytes: u64,
    /// Synchronized allocation of distinct original backing inodes, including dictionaries.
    pub synchronized_backing_inode_bytes: u64,
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

/// Holds a durable consumer pin over one complete original sealed file.
///
/// This grant is separate from chunk and metadata reads. Clones share one lease
/// and at most one active backing registration. Dropping the grant leaves its
/// durable pin to ordinary expiry. The trusted descriptor transport must retain
/// its backing owner until the worker and kernel have released that backing.
#[derive(Clone)]
pub struct NativeSealedObjectLease {
    lease: NativeConsumerLease,
}

impl NativeSealedObjectLease {
    /// Retains the actual registered source context before exposure policy IO.
    ///
    /// # Errors
    /// Refuses foreign grants, unavailable original jobs or poisoned custody.
    #[cfg(feature = "surface-fuse")]
    pub(in crate::host_cache::owner) fn exposure_context(
        &self,
        executor: &super::retention::NativeOwnerExecutor,
    ) -> io::Result<Arc<PublisherRunningContext>> {
        let job = self
            .exposure_job(executor)?
            .lock()
            .map_err(|_| invalid("exposure consumer job poisoned"))?;
        Ok(Arc::clone(&job.running))
    }

    /// Checks actual whole-object custody and copies its complete protected hashes.
    ///
    /// # Errors
    /// Refuses foreign or revoked grants, expired phases, changed native backing
    /// and missing original durable pins or funding.
    #[cfg(feature = "surface-fuse")]
    pub(in crate::host_cache::owner) fn exposure_pins(
        &self,
        executor: &super::retention::NativeOwnerExecutor,
        owner: &Custody,
    ) -> io::Result<(
        Vec<String>,
        u64,
        terrane_sdk::host::cache::ExposureBackingRecord,
    )> {
        self.expires_at()?;
        let job = self
            .exposure_job(executor)?
            .lock()
            .map_err(|_| invalid("exposure consumer job poisoned"))?;
        let Phase::Live(deadline) = &job.phase else {
            return Err(invalid("exposure consumer is not live"));
        };
        deadline.check_live()?;
        state::check_job(owner, &job, self.owner(), deadline.expires)?;
        let kind = match self.identity().kind() {
            IdentityKind::Chunk => terrane_sdk::host::cache::ExposureBackingKind::Inline,
            IdentityKind::Manifest => terrane_sdk::host::cache::ExposureBackingKind::Manifest,
            _ => return Err(invalid("exposure source is not whole-file content")),
        };
        let file = std::fs::File::from(job.source.duplicate_object_backing()?);
        let digest = self
            .identity()
            .digest()
            .try_into()
            .map_err(|_| invalid("exposure source digest has an unsupported width"))?;
        let binding = super::surface_index::bindings::capture(owner, &file, kind, digest)?;
        Ok((
            job.source.protected_hashes().to_vec(),
            deadline.expires,
            binding,
        ))
    }

    #[cfg(feature = "surface-fuse")]
    fn exposure_job<'a>(
        &self,
        executor: &'a super::retention::NativeOwnerExecutor,
    ) -> io::Result<&'a Arc<Mutex<ConsumerJob>>> {
        for resource in executor.consumer_jobs() {
            let job = resource
                .lock()
                .map_err(|_| invalid("exposure consumer job poisoned"))?;
            if Arc::ptr_eq(&job.view, &self.lease.view) {
                return Ok(resource);
            }
        }
        Err(invalid("exposure consumer belongs to another native owner"))
    }

    /// Borrows the original whole-object identity, including its content kind.
    pub fn identity(&self) -> &Identity {
        self.lease.identity()
    }

    /// Borrows this exact durable consumer's owner name.
    pub fn owner(&self) -> &str {
        self.lease.owner()
    }

    /// Returns the currently acknowledged live expiry in Unix seconds.
    ///
    /// # Errors
    /// Refuses revoked, expired or concurrently changing grants.
    pub fn expires_at(&self) -> io::Result<u64> {
        self.lease.expires_at()
    }

    /// Borrows independent accounting at the original synchronized grant boundary.
    pub fn initial_accounting(&self) -> &NativeLeaseAccounting {
        self.lease.initial_accounting()
    }

    /// Retains one read-only whole-file descriptor through delegated backing use.
    ///
    /// The finite physical consumer registry bounds retained backing owners.
    /// A lease permits only one active backing owner, shared by all its clones;
    /// reopening is allowed after that owner closes. Descriptor preparation uses
    /// the temporary read budget but does not occupy it for the backing's life.
    ///
    /// # Errors
    /// Refuses revoked or expired grants, an existing backing owner, exhausted
    /// preparation capacity, changed native custody or seal, and descriptor IO.
    pub fn backing(&self) -> io::Result<NativeSealedBacking> {
        self.lease.view.begin_backing()
    }
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
    source: Arc<source::ConsumerSource>,
    view: Arc<ReadView>,
    token: String,
    hold: u64,
    generation: u64,
    started: bool,
    phase: Phase,
    accounting: Option<NativeLeaseAccounting>,
}

impl ConsumerJob {
    /// Keeps actual admitted body and dictionary jobs through final consumer quiescence.
    pub(in crate::host_cache::owner) fn retains_admission(
        &self,
        resource: &Arc<Mutex<super::admission::AdmissionJob>>,
    ) -> bool {
        self.source.retains(resource)
    }

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
    /// Pins only a complete sealed publication for whole-file descriptor access.
    PinObject {
        identity: Identity,
        domain: Option<String>,
        expires: u64,
        response: oneshot::Sender<io::Result<NativeSealedObjectLease>>,
    },
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
        ConsumerCommand::PinObject {
            identity,
            domain,
            expires,
            response,
        } => {
            let result = acquire_object(executor, identity, domain.as_deref(), expires)
                .await
                .map(|lease| NativeSealedObjectLease { lease });
            let _ = response.send(result);
        }
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
    /// Synchronizes a consumer pin over an actual complete sealed publication.
    ///
    /// The current physical owner must retain the original completed publication
    /// or its actual verified recovery source after acknowledged Resume. A
    /// chunk's range in another object, encoded admission, canonical Manifest
    /// bytes or an unverified cold record cannot substitute for the exact whole
    /// sealed file. Accepted work survives waiter cancellation. This grants
    /// neither exposure scope nor lasting caller Read.
    ///
    /// # Errors
    /// Refuses another identity kind or profile, an expired deadline, absent
    /// actual publication or Resume, exhausted bounds and native durability,
    /// integrity, custody or quota failures.
    pub async fn pin_sealed_object(
        &self,
        identity: Identity,
        expires: u64,
    ) -> io::Result<NativeSealedObjectLease> {
        self.pin_object(identity, None, expires).await
    }

    async fn pin_object(
        &self,
        identity: Identity,
        domain: Option<String>,
        expires: u64,
    ) -> io::Result<NativeSealedObjectLease> {
        if !matches!(
            identity.kind(),
            IdentityKind::Chunk | IdentityKind::Manifest
        ) {
            return Err(invalid("sealed object grant requires a content identity"));
        }
        Deadline::new(expires)?;
        let (response, receive) = oneshot::channel();
        self.send_consumer_command(ConsumerCommand::PinObject {
            identity,
            domain,
            expires,
            response,
        })?;
        receive.await.map_err(|_| stopped())?
    }

    /// Renews this exact sealed-file consumer after native durable synchronization.
    ///
    /// # Errors
    /// Refuses foreign, released or expired grants, a nonincreasing deadline,
    /// unavailable queues, changed native backing and durability or quota errors.
    pub async fn renew_sealed_object_lease(
        &self,
        lease: &NativeSealedObjectLease,
        expires: u64,
    ) -> io::Result<NativeLeaseAccounting> {
        self.renew_consumer_lease(&lease.lease, expires).await
    }

    /// Revokes new backing requests and synchronizes the original release grace.
    ///
    /// An existing backing owner retains its exact native source until it closes;
    /// dropping the lease or revoking its view cannot acknowledge descriptor
    /// quiescence early.
    ///
    /// # Errors
    /// Refuses foreign grants, unavailable queues, changed native custody and
    /// failed durable release or quota reconciliation.
    pub async fn release_sealed_object_lease(
        &self,
        lease: &NativeSealedObjectLease,
    ) -> io::Result<NativeLeaseAccounting> {
        self.release_consumer_lease(&lease.lease).await
    }

    /// Synchronizes a new consumer pin over this owner's verified resident chunk.
    ///
    /// The absolute Unix expiry must remain live through acknowledgment. Source
    /// lookup uses original publication, completed recovery or admitted cache
    /// custody, including the actual one-hop dictionary.
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
        if identity.kind() != IdentityKind::Chunk {
            return Err(invalid("resident chunk grant requires a chunk identity"));
        }
        self.pin_resident_content(identity, expires).await
    }

    /// Synchronizes an independent consumer pin over an original cached metadata pair.
    ///
    /// Both original pack and detached index remain protected through release grace.
    /// Dropping the waiter never cancels accepted physical pin work.
    ///
    /// # Errors
    /// Refuses non-metadata identities, absent actual cache custody, expired grants,
    /// changed native resources, exhausted limits or durability failures.
    pub async fn pin_resident_metadata(
        &self,
        identity: Identity,
        expires: u64,
    ) -> io::Result<NativeConsumerLease> {
        if matches!(identity.kind(), IdentityKind::Chunk | IdentityKind::Pack) {
            return Err(invalid(
                "resident metadata grant requires a metadata identity",
            ));
        }
        self.pin_resident_content(identity, expires).await
    }

    /// Selects cached metadata without masking failures of a selected original pair.
    ///
    /// # Errors
    /// Propagates every failure except a completed physical lookup finding no job.
    pub(in crate::host_cache) async fn pin_cached_metadata(
        &self,
        identity: Identity,
        expires: u64,
    ) -> io::Result<Option<NativeConsumerLease>> {
        match self.pin_resident_metadata(identity, expires).await {
            Ok(lease) => Ok(Some(lease)),
            Err(error) if super::admission::metadata_reads::cache_absent(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn pin_resident_content(
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
