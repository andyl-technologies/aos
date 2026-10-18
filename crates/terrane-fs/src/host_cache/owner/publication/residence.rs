//! Reads verified sealed ranges under original completed publication custody.
//!
//! Durable residence rows locate candidates. Only the physical worker's genuine
//! completed job, current synchronized pins and actual sealed descriptor permit
//! a read. Plaintext and kernel-seal reads run outside embedded policy locks.
//! This grants no consumer lease, Store readiness or caller-selected backing.

use super::{PublicationJob, invalid, state};
use crate::{
    host_cache::{NativeChunkSpan, NativeResidencePlan},
    host_quota::NativeProject,
    publisher_local::client::PeerPublishedObject,
};
use rustix::fs::{Mode, OFlags, openat};
use std::{
    fs::File,
    io,
    os::unix::fs::{FileExt, MetadataExt},
    sync::{Arc, Mutex, mpsc},
};
use terrane::host::cache::{HostDomainLocation, ResidenceRecord};
use terrane_core::identity::{Identity, IdentityKind, TERRANE_V1};
use tokio::sync::oneshot;

use super::super::{
    RETAINED_LEASE_DEADLINE,
    retention::{Command, Custody, NativeMetadataOwner, NativeOwnerExecutor},
};

/// Retains bounded verified plaintext and its original physical publication job.
///
/// The worker retains the actual publication pin and backing independently of
/// this value. These bytes grant no native handle, new consumer lease or writable
/// cache authority. Cold/recovered publications use their separate retained
/// recovery registry and are not accepted by this Running-publication path.
pub struct NativeResidentChunkRead {
    identity: Identity,
    span: NativeChunkSpan,
    plaintext: Vec<u8>,
    _job: Arc<Mutex<PublicationJob>>,
}

impl NativeResidentChunkRead {
    /// Borrows the registered chunk identity verified against the actual bytes.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Returns the independently derived first occurrence in its sealed object.
    pub fn span(&self) -> NativeChunkSpan {
        self.span
    }

    /// Borrows only the bounded plaintext read from that checked sealed range.
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

impl NativeMetadataOwner {
    /// Reads one chunk from this worker's genuinely completed Running publication.
    ///
    /// The owner resolves the exact durable residence through its original job
    /// registry. It checks current pins, canonical metadata, native inode and seal
    /// before and after a bounded positioned read, then revalidates the actual
    /// bytes in the containing manifest's chunk-boundary context. No path, raw
    /// descriptor, policy hold or caller assertion can substitute for custody.
    ///
    /// # Errors
    /// Refuses a full/stopped queue, absent Resume, missing current publication,
    /// stale policy/native custody, invalid chunk identity or boundary, and an
    /// operator allocation bound. An error returns no plaintext or native handle.
    pub async fn read_resident_chunk(
        &self,
        identity: Identity,
    ) -> io::Result<NativeResidentChunkRead> {
        let (response, receive) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(|| invalid("resident read owner stopped"))?
            .try_send(Command::ReadResidentChunk { identity, response })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "resident read queue full")
                }
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "resident read owner stopped")
                }
            })?;
        receive
            .await
            .map_err(|_| invalid("resident read worker terminated"))?
    }
}

struct Source {
    job: Arc<Mutex<PublicationJob>>,
    body: Arc<PeerPublishedObject<HostDomainLocation>>,
    span: NativeChunkSpan,
    row: ResidenceRecord,
    generation: u64,
    project: u32,
    publisher_uid: u32,
    allocation_limit: usize,
}

/// Reads only a registered physical publication on the retained worker thread.
///
/// # Errors
/// Refuses unverified/stale policy, missing physical resources or invalid bytes.
pub(in crate::host_cache::owner) fn read(
    executor: &NativeOwnerExecutor,
    identity: Identity,
) -> io::Result<NativeResidentChunkRead> {
    let context = executor.admission_context()?;
    context.check_current().map_err(io::Error::other)?;
    if identity.kind() != IdentityKind::Chunk || identity.profile() != TERRANE_V1.name() {
        return Err(invalid(
            "resident read requires a registered chunk identity",
        ));
    }
    let source = select(executor, &identity)?;
    check_native(&source)?;
    let mut plaintext = Vec::new();
    plaintext
        .try_reserve_exact(source.span.length)
        .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
    if plaintext.capacity() > source.allocation_limit {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "resident buffer exceeds operator bound",
        ));
    }
    plaintext.resize(source.span.length, 0);
    source
        .body
        .handle()
        .read_exact_at(&mut plaintext, source.span.offset)?;
    TERRANE_V1
        .verify(&identity, &plaintext)
        .map_err(io::Error::other)?;
    let profile = source.body.layout().layout().chunk_profile();
    if profile.first_boundary(&plaintext) != plaintext.len()
        || (!source.span.final_chunk && !profile.valid_nonfinal_chunk(&plaintext))
    {
        return Err(invalid(
            "resident plaintext has another object chunk boundary",
        ));
    }
    check_native(&source)?;
    context.check_current().map_err(io::Error::other)?;
    {
        let job = source
            .job
            .lock()
            .map_err(|_| invalid("resident publication poisoned"))?;
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("resident custody poisoned"))?;
        if owner.generation != source.generation
            || !owner
                .state
                .residences
                .iter()
                .any(|row| same_row(row, &source.row))
            || registration(&owner, &job, &identity, &source.row)? != source.span
        {
            return Err(invalid("resident read registration changed"));
        }
    }
    Ok(NativeResidentChunkRead {
        identity,
        span: source.span,
        plaintext,
        _job: source.job,
    })
}

fn select(executor: &NativeOwnerExecutor, identity: &Identity) -> io::Result<Source> {
    let row = {
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("resident custody poisoned"))?;
        owner.check_current()?;
        owner
            .state
            .residences
            .iter()
            .find(|row| row.chunk == state::hex(identity.digest()))
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "resident chunk absent"))?
    };
    for resource in executor.publication_jobs() {
        let job = resource
            .lock()
            .map_err(|_| invalid("resident publication poisoned"))?;
        if state::hex(job.claim.descriptor().digest()) != row.object {
            continue;
        }
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("resident custody poisoned"))?;
        if !Arc::ptr_eq(&job.custody, executor.custody()) {
            return Err(invalid("resident publication belongs to another owner"));
        }
        let span = registration(&owner, &job, identity, &row)?;
        let body = Arc::clone(
            job.body
                .as_ref()
                .ok_or_else(|| invalid("resident body absent"))?,
        );
        return Ok(Source {
            job: Arc::clone(resource),
            body,
            span,
            row,
            generation: owner.generation,
            project: owner.preparation.config.project_id,
            publisher_uid: owner.preparation.config.publisher.identities.publish_uid,
            allocation_limit: owner.preparation.config.reads.max_allocation_bytes,
        });
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "resident chunk lacks its original completed publication",
    ))
}

fn registration(
    owner: &Custody,
    job: &PublicationJob,
    identity: &Identity,
    row: &ResidenceRecord,
) -> io::Result<NativeChunkSpan> {
    owner.check_current()?;
    let written = owner
        .synchronized_state
        .as_ref()
        .ok_or_else(|| invalid("resident snapshot unverified"))?;
    let (_, snapshot) = owner
        .snapshot
        .as_ref()
        .ok_or_else(|| invalid("resident snapshot absent"))?;
    if (written.device, written.inode) != (snapshot.dev(), snapshot.ino()) {
        return Err(invalid("resident snapshot writer incarnation changed"));
    }
    if owner.faulted
        || owner.recovery_required
        || !job.started
        || !job.complete
        || owner.generation != written.generation
    {
        return Err(invalid("resident publication is not complete and current"));
    }
    super::super::recovery_manifest_state::require_same(&owner.state, &written.state)?;
    let hash = state::hex(job.claim.descriptor().digest());
    let pin_owner = format!("publication:{}", job.token);
    if !owner.state.reservations.iter().any(|hold| {
        hold.id == job.token
            && hold.bytes == job.hold
            && hold.owner == owner.preparation.config.quota_owner
    }) || !owner.state.pins.iter().any(|pin| {
        pin.owner == pin_owner && pin.hash == hash && pin.expires == RETAINED_LEASE_DEADLINE
    }) || !owner
        .state
        .leases
        .iter()
        .any(|lease| lease.owner == pin_owner && lease.expires == RETAINED_LEASE_DEADLINE)
    {
        return Err(invalid(
            "resident publication lost its original durable funding",
        ));
    }
    let body = job
        .body
        .as_ref()
        .ok_or_else(|| invalid("resident body absent"))?;
    if !Arc::ptr_eq(body.layout(), owner.preparation.layout())
        || body.claim().descriptor() != job.claim.descriptor()
        || body.claim().domain() != job.claim.domain()
        || body.claim().canonical_manifest() != job.claim.canonical_manifest()
    {
        return Err(invalid(
            "resident body differs from its original publication",
        ));
    }
    if let Some(manifest) = &job.manifest {
        manifest.retained.check_registration(owner)?;
    }
    let plan = NativeResidencePlan::new(
        owner.preparation.layout(),
        &job.claim,
        owner.preparation.config.inventory_entries,
    )?;
    let span = plan
        .span(identity)?
        .ok_or_else(|| invalid("resident chunk absent from verified claim"))?;
    if row.object != hash
        || row.chunk != state::hex(identity.digest())
        || row.offset != span.offset
        || row.length != span.length as u64
    {
        return Err(invalid(
            "resident row differs from independently verified metadata",
        ));
    }
    if span.length > owner.preparation.config.reads.max_allocation_bytes {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "resident read exceeds operator allocation budget",
        ));
    }
    Ok(span)
}

fn check_native(source: &Source) -> io::Result<()> {
    let layout = source.body.layout();
    layout.recheck()?;
    let body = source.body.handle();
    let metadata = body.metadata()?;
    let hash = state::hex(source.body.claim().descriptor().digest());
    let directory = layout
        .directories
        .get("sealed")
        .ok_or_else(|| invalid("sealed directory absent"))?;
    let shard = openat(
        directory,
        &hash[..2],
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let canonical = File::from(openat(
        &shard,
        hash.as_str(),
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let named = canonical.metadata()?;
    let flags = rustix::fs::fcntl_getfl(body)?;
    if !metadata.is_file()
        || metadata.uid() != source.publisher_uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o400
        || metadata.len() != source.body.claim().plaintext_size()
        || (metadata.dev(), metadata.ino()) != (named.dev(), named.ino())
        || flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::PATH)
        || NativeProject::inspect(body)?.project_id != source.project
        || crate::verity::measure(body)? != *source.body.binding()
    {
        return Err(invalid(
            "resident read changed canonical inode or kernel seal",
        ));
    }
    Ok(())
}

fn same_row(first: &ResidenceRecord, second: &ResidenceRecord) -> bool {
    first.chunk == second.chunk
        && first.object == second.object
        && first.offset == second.offset
        && first.length == second.length
}
