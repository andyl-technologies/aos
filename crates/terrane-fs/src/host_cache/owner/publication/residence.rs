//! Reads verified sealed ranges under original completed publication custody.
//!
//! Durable residence rows locate candidates. Only the physical worker's genuine
//! completed job or independently verified and resumed recovery, current
//! synchronized pins and actual sealed descriptor permit source preparation.
//! Subsequent plaintext and seal reads never lock embedded state.
//! This grants no consumer lease, Store readiness or caller-selected backing.

use super::{PublicationJob, invalid, state};
use crate::{
    host_cache::{NativeChunkSpan, NativeHostLayout, NativeResidencePlan},
    host_quota::NativeProject,
    publisher_local::client::PeerPublishedObject,
};
use rustix::fs::OFlags;
use std::{
    fs::File,
    io,
    os::unix::fs::{FileExt, MetadataExt},
    sync::{Arc, Mutex, mpsc},
};
use terrane::host::cache::{HostDomainLocation, ResidenceRecord};
use terrane_core::identity::{Identity, IdentityKind, TERRANE_V1};
use tokio::sync::oneshot;

mod recovered;
mod recovered_inline;
mod registry;
mod view;

pub(in crate::host_cache::owner) use recovered_inline::RecoveredInlineJob;
pub(super) use recovered_inline::prepare as prepare_recovered_inline;
pub use registry::NativeProducerReadClosure;
pub(in crate::host_cache::owner) use registry::{
    ProducerReadRegistry, storage_bytes as read_storage_bytes,
};

use super::super::{
    RETAINED_LEASE_DEADLINE,
    retention::{Command, Custody, NativeMetadataOwner, NativeOwnerExecutor},
};

/// Retains an original pinned sealed range for reads outside embedded state.
///
/// Physical custody keeps the actual durable funding and backing alive after
/// receipt or owner destruction, until this source is explicitly closed. This
/// source grants no native handle, new consumer lease or writable cache authority.
/// Its immutable read operations never consult the command queue or lock
/// embedded state.
pub struct NativeResidentChunkSource {
    identity: Identity,
    layout: Arc<NativeHostLayout<HostDomainLocation>>,
    span: NativeChunkSpan,
    object_digest: [u8; 32],
    view: Arc<view::ReadView<Source>>,
}

impl NativeResidentChunkSource {
    /// Borrows the registered chunk identity checked against its containing claim.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Returns the independently derived first occurrence in its sealed object.
    pub fn span(&self) -> NativeChunkSpan {
        self.span
    }

    /// Reads bounded verified plaintext without a queue or embedded-store lock.
    ///
    /// Each call checks the retained inode and kernel seal before and after a
    /// positioned read, then verifies the actual chunk identity and boundary.
    /// Original physical custody keeps its durable pin and descriptor
    /// alive throughout use. Concurrent readers never share a file cursor.
    ///
    /// # Errors
    /// Refuses changed native inode, project, root or seal, invalid chunk bytes
    /// or boundary, native I/O failure, unavailable bounded allocation, or a
    /// view closed before or during the operation.
    pub fn read_verified(&self) -> io::Result<Vec<u8>> {
        let read = self.view.begin()?;
        let source = &read.source;
        check_native(source)?;
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
            .verify(&self.identity, &plaintext)
            .map_err(io::Error::other)?;
        let profile = source.body.layout().layout().chunk_profile();
        if profile.first_boundary(&plaintext) != plaintext.len()
            || (!source.span.final_chunk && !profile.valid_nonfinal_chunk(&plaintext))
        {
            return Err(invalid(
                "resident plaintext has another object chunk boundary",
            ));
        }
        check_native(source)?;
        self.view.check_open()?;
        source.activity.record()?;
        Ok(plaintext)
    }

    /// Permanently closes this view and reports whether its operations have finished.
    ///
    /// New reads and protected reassembly operations are refused immediately. An
    /// already-started operation retains its actual backing until completion;
    /// a read that observes closure before returning withholds its plaintext.
    /// A `true` result means this view has dropped its sealed-body and original
    /// job references. Its immutable identity and configured layout remain
    /// available for metadata access.
    /// Repeating the call observes completion without reopening the view.
    ///
    /// This releases no durable pin, reservation or lease and claims no quota
    /// reclamation. Independently retained sources and consumer leases remain
    /// usable under their own protection. The call takes no embedded-store,
    /// publisher or worker-job mutex.
    pub fn close(&self) -> bool {
        self.view.close()
    }

    fn new(identity: Identity, source: Source) -> io::Result<Self> {
        let object_digest = source
            .body
            .claim()
            .descriptor()
            .digest()
            .try_into()
            .map_err(|_| invalid("resident object digest differs from the registered profile"))?;
        Ok(Self {
            identity,
            layout: Arc::clone(source.body.layout()),
            span: source.span,
            object_digest,
            view: Arc::new(view::ReadView::new(source)),
        })
    }
}

impl NativeMetadataOwner {
    /// Retains a pinned source from this worker's completed publication or recovery.
    ///
    /// Preparation resolves the exact durable residence through the original
    /// job registry and checks current synchronized funding and canonical
    /// metadata. Recovered manifests require independently inspected backing
    /// and the actual acknowledged Resume. Recovered inline bodies acquire a
    /// synchronized operation pin, lease and future hold before acknowledgment.
    /// Subsequent reads use only retained immutable resources and never enter
    /// the queue or embedded state.
    ///
    /// # Errors
    /// Refuses a full/stopped queue, absent Resume, missing current publication,
    /// stale policy/native custody, invalid chunk identity or operator bounds.
    pub async fn retain_resident_chunk(
        &self,
        identity: Identity,
    ) -> io::Result<NativeResidentChunkSource> {
        let (response, receive) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(|| invalid("resident read owner stopped"))?
            .try_send(Command::RetainResidentChunk { identity, response })
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
    origin: Origin,
    body: Arc<PeerPublishedObject<HostDomainLocation>>,
    activity: Arc<super::eviction::ReadActivity>,
    span: NativeChunkSpan,
    row: ResidenceRecord,
    generation: u64,
    project: u32,
    publisher_uid: u32,
    allocation_limit: usize,
}

enum Origin {
    Publication(Arc<Mutex<PublicationJob>>),
    Recovery(recovered::RecoveredSource),
    RecoveredInline(Arc<Mutex<RecoveredInlineJob>>),
}

/// Prepares only a registered physical publication on the retained worker thread.
///
/// # Errors
/// Refuses unverified/stale policy, missing physical resources or invalid bytes.
pub(in crate::host_cache::owner) async fn retain(
    executor: &mut NativeOwnerExecutor,
    identity: Identity,
) -> io::Result<NativeResidentChunkSource> {
    super::eviction::restore_for(executor, &identity).await?;
    let source = prepare(executor, identity).await?;
    executor.register_producer_read(&source)?;
    Ok(source)
}

/// Prepares genuine backing for an independently synchronized consumer grant.
///
/// # Errors
/// Refuses stale physical custody, absent publication/recovery, invalid spans,
/// changed native backing or unavailable allocation. This grants no lease.
pub(in crate::host_cache::owner) async fn prepare(
    executor: &mut NativeOwnerExecutor,
    identity: Identity,
) -> io::Result<NativeResidentChunkSource> {
    let context = executor.admission_context()?;
    context.check_current().map_err(io::Error::other)?;
    if identity.kind() != IdentityKind::Chunk || identity.profile() != TERRANE_V1.name() {
        return Err(invalid(
            "resident source requires a registered chunk identity",
        ));
    }
    recovered_inline::prepare(executor, &identity).await?;
    let source = select(executor, &identity)?;
    check_native(&source)?;
    context.check_current().map_err(io::Error::other)?;
    {
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("resident custody poisoned"))?;
        if owner.faulted
            || owner.generation != source.generation
            || !owner
                .state
                .residences
                .iter()
                .any(|row| same_row(row, &source.row))
        {
            return Err(invalid("resident source registration changed"));
        }
        check_origin(&owner, &source, &identity)?;
    }
    NativeResidentChunkSource::new(identity, source)
}

/// Retains an original source while the producer already holds genuine policy custody.
///
/// # Errors
/// Refuses another physical worker, faulted preparation, missing current pin or
/// native backing. This is preparation only; no plaintext is read under the lock.
pub(super) fn retain_registered(
    executor: &NativeOwnerExecutor,
    owner: &Custody,
    identity: Identity,
) -> io::Result<NativeResidentChunkSource> {
    let source = select_locked(executor, owner, &identity)?;
    check_native(&source)?;
    NativeResidentChunkSource::new(identity, source)
}

impl NativeResidentChunkSource {
    /// Borrows the actual retained source's domain binding.
    pub(in crate::host_cache) fn domain(&self) -> &str {
        self.layout.layout().domain()
    }

    /// Borrows the chunk profile checked against the original native root.
    pub(in crate::host_cache) fn profile(&self) -> &terrane_core::chunking::ChunkProfile {
        self.layout.layout().chunk_profile()
    }

    /// Rechecks original funding under a later serialized producer's exclusion.
    ///
    /// This creates no command or authority while that producer is faulted/busy.
    /// Its genuine source was retained before the later operation began.
    ///
    /// # Errors
    /// Refuses changed original job, pins, metadata, range or snapshot provenance.
    pub(in crate::host_cache::owner) fn check_protected(&self, owner: &Custody) -> io::Result<()> {
        let read = self.view.begin()?;
        if !owner
            .state
            .residences
            .iter()
            .any(|row| same_row(row, &read.source.row))
        {
            return Err(invalid("retained source lost original publication custody"));
        }
        check_origin(owner, &read.source, &self.identity)
    }

    /// Checks original immutable backing under a separately synchronized consumer pin.
    ///
    /// Producer funding can retire after handoff. The caller must independently
    /// check its original consumer job and current durable pin; this method
    /// supplies no replacement authority from a row or raw descriptor.
    ///
    /// # Errors
    /// Refuses foreign layouts, changed native backing or a changed verified span.
    pub(in crate::host_cache::owner) fn check_consumer_backing(
        &self,
        owner: &Custody,
    ) -> io::Result<()> {
        let read = self.view.begin()?;
        let source = &read.source;
        check_snapshot(owner)?;
        if !Arc::ptr_eq(source.body.layout(), owner.preparation.layout())
            || claim_span(owner, source.body.claim(), &self.identity, &source.row)? != source.span
        {
            return Err(invalid(
                "consumer source differs from its original verified backing",
            ));
        }
        check_native(source)
    }

    /// Borrows the containing verified object's digest for durable pin policy.
    pub(in crate::host_cache::owner) fn protected_object_digest(&self) -> &[u8] {
        &self.object_digest
    }

    /// Synchronizes the original sealed source outside embedded state.
    ///
    /// # Errors
    /// Refuses changed native backing, synchronization failure or changed layout.
    pub(in crate::host_cache::owner) fn synchronize_pin_backing(&self) -> io::Result<u64> {
        let read = self.view.begin()?;
        synchronize_body(
            &read.source.body,
            read.source.project,
            read.source.publisher_uid,
        )
    }

    /// Recognizes only the original checked residence, without choosing another body.
    pub(super) fn matches_record(&self, row: &ResidenceRecord) -> bool {
        self.view
            .begin()
            .is_ok_and(|read| same_row(row, &read.source.row))
    }
}

/// Counts retained native source and generated range-name storage per unique chunk.
pub(super) fn header_bytes() -> usize {
    // The backing and revocable view each have their own Arc in addition to
    // the shared source and producer ownership slots.
    std::mem::size_of::<NativeResidentChunkSource>()
        + std::mem::size_of::<view::ReadView<Source>>()
        + std::mem::size_of::<Source>()
        + 8 * std::mem::size_of::<usize>()
        + 128
        + TERRANE_V1.digest_len()
        + TERRANE_V1.name().len()
}

fn select(executor: &NativeOwnerExecutor, identity: &Identity) -> io::Result<Source> {
    let owner = executor
        .custody()
        .lock()
        .map_err(|_| invalid("resident custody poisoned"))?;
    select_locked(executor, &owner, identity)
}

fn select_locked(
    executor: &NativeOwnerExecutor,
    owner: &Custody,
    identity: &Identity,
) -> io::Result<Source> {
    executor.check_physical_worker()?;
    owner.check_current()?;
    if owner.faulted
        || owner.recovery_required
        || identity.kind() != IdentityKind::Chunk
        || identity.profile() != TERRANE_V1.name()
    {
        return Err(invalid(
            "resident source requires current Running preparation",
        ));
    }
    let row = owner
        .state
        .residences
        .iter()
        .find(|row| row.chunk == state::hex(identity.digest()))
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "resident chunk absent"))?;
    for resource in executor.publication_jobs() {
        let job = resource
            .lock()
            .map_err(|_| invalid("resident publication poisoned"))?;
        if state::hex(job.claim.descriptor().digest()) != row.object {
            continue;
        }
        if !Arc::ptr_eq(&job.custody, executor.custody()) {
            return Err(invalid("resident publication belongs to another owner"));
        }
        let span = registration(owner, &job, identity, &row)?;
        let body = Arc::clone(
            job.body
                .as_ref()
                .ok_or_else(|| invalid("resident body absent"))?,
        );
        return Ok(Source {
            activity: executor.body_read_activity(owner, &body)?,
            origin: Origin::Publication(Arc::clone(resource)),
            body,
            span,
            row,
            generation: owner.generation,
            project: owner.preparation.config.project_id,
            publisher_uid: owner.preparation.config.publisher.identities.publish_uid,
            allocation_limit: owner.preparation.config.reads.max_allocation_bytes,
        });
    }
    if let Some(source) = recovered_inline::select(executor, owner, identity, &row)? {
        return Ok(source);
    }
    recovered::select(executor, owner, identity, row)
}

fn check_origin(owner: &Custody, source: &Source, identity: &Identity) -> io::Result<()> {
    let span = match &source.origin {
        Origin::Publication(resource) => {
            let job = resource
                .lock()
                .map_err(|_| invalid("resident publication poisoned"))?;
            if !job
                .body
                .as_ref()
                .is_some_and(|body| Arc::ptr_eq(body, &source.body))
            {
                return Err(invalid("resident descriptor differs from original job"));
            }
            registration(owner, &job, identity, &source.row)?
        }
        Origin::Recovery(recovered) => recovered.check_registration(owner, source, identity)?,
        Origin::RecoveredInline(resource) => resource
            .lock()
            .map_err(|_| invalid("recovered inline source poisoned"))?
            .check_registration(owner, source, identity)?,
    };
    if span != source.span {
        return Err(invalid("resident source range changed"));
    }
    Ok(())
}

fn registration(
    owner: &Custody,
    job: &PublicationJob,
    identity: &Identity,
    row: &ResidenceRecord,
) -> io::Result<NativeChunkSpan> {
    registered_body(owner, job)?;
    claim_span(owner, &job.claim, identity, row)
}

/// Borrows the original completed body under its current durable funding.
///
/// # Errors
/// Refuses incomplete physical work, changed snapshot/pins or foreign backing.
pub(super) fn registered_body<'job>(
    owner: &Custody,
    job: &'job PublicationJob,
) -> io::Result<&'job Arc<PeerPublishedObject<HostDomainLocation>>> {
    check_snapshot(owner)?;
    if !job.started || !job.complete {
        return Err(invalid("resident publication is not complete"));
    }
    if let Some(cached) = &job.cached {
        let body = job
            .body
            .as_ref()
            .ok_or_else(|| invalid("cached body absent"))?;
        cached.check(owner, &job.custody, body)?;
        if body.claim().descriptor() != job.claim.descriptor()
            || body.claim().domain() != job.claim.domain()
            || body.claim().canonical_manifest() != job.claim.canonical_manifest()
        {
            return Err(invalid(
                "cached body differs from original publication claim",
            ));
        }
        return Ok(body);
    }
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
    Ok(body)
}

/// Checks actual snapshot provenance and the complete synchronized policy state.
///
/// # Errors
/// Refuses changed custody, writer incarnation, generation or persisted records.
pub(in crate::host_cache::owner) fn check_snapshot(owner: &Custody) -> io::Result<()> {
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
    if owner.recovery_required || owner.generation != written.generation {
        return Err(invalid("resident publication is not complete and current"));
    }
    super::super::recovery_manifest_state::require_same(&owner.state, &written.state)?;
    Ok(())
}

fn claim_span(
    owner: &Custody,
    claim: &terrane::host::publication::PublicationClaim,
    identity: &Identity,
    row: &ResidenceRecord,
) -> io::Result<NativeChunkSpan> {
    let plan = NativeResidencePlan::new(
        owner.preparation.layout(),
        claim,
        owner.preparation.config.inventory_entries,
    )?;
    let span = plan
        .span(identity)?
        .ok_or_else(|| invalid("resident chunk absent from verified claim"))?;
    if row.object != state::hex(claim.descriptor().digest())
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
    check_native_body(&source.body, source.project, source.publisher_uid)
}

/// Checks the original linked immutable inode and its native root/project seal.
///
/// # Errors
/// Refuses changed ownership, access, allocation namespace, project or verity.
pub(super) fn check_native_body(
    published: &PeerPublishedObject<HostDomainLocation>,
    project: u32,
    publisher_uid: u32,
) -> io::Result<()> {
    let layout = published.layout();
    layout.recheck()?;
    let body = published.handle();
    let metadata = body.metadata()?;
    let flags = rustix::fs::fcntl_getfl(body)?;
    if !metadata.is_file()
        || metadata.uid() != publisher_uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o400
        || metadata.len() != published.claim().plaintext_size()
        || metadata.dev() != layout.directory_binding("layout-root")?.0
        || flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::PATH)
        || NativeProject::inspect(body)?.project_id != project
        || crate::verity::measure(body)? != *published.binding()
    {
        return Err(invalid(
            "resident source changed retained inode or kernel seal",
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

/// Synchronizes actual immutable backing and its bound native filesystem.
///
/// # Errors
/// Refuses changed inode/project/seal or layout-root binding and native IO failures.
pub(super) fn synchronize_body(
    body: &PeerPublishedObject<HostDomainLocation>,
    project: u32,
    publisher_uid: u32,
) -> io::Result<u64> {
    check_native_body(body, project, publisher_uid)?;
    body.handle().sync_all()?;
    let root = File::from(rustix::fs::openat(
        &body.layout().root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    let observed = root.metadata()?;
    if (observed.dev(), observed.ino()) != body.layout().directory_binding("layout-root")? {
        return Err(invalid("pin synchronization root changed"));
    }
    rustix::fs::syncfs(&root)?;
    check_native_body(body, project, publisher_uid)?;
    crate::host_quota::synchronized_allocated_bytes(body.handle())
}
