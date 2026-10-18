//! Reads verified sealed ranges under original completed publication custody.
//!
//! Durable residence rows locate candidates. Only the physical worker's genuine
//! completed job or independently verified and resumed recovery, current
//! synchronized pins and actual sealed descriptor permit source preparation.
//! Subsequent plaintext and seal reads never lock embedded state.
//! This grants no consumer lease, Store readiness or caller-selected backing.

use super::{PublicationJob, invalid, state};
use crate::{
    host_cache::{NativeChunkSpan, NativeResidencePlan},
    host_quota::NativeProject,
    publisher_local::client::PeerPublishedObject,
};
use rustix::fs::OFlags;
use std::{
    io,
    os::unix::fs::{FileExt, MetadataExt},
    sync::{Arc, Mutex, mpsc},
};
use terrane::host::cache::{HostDomainLocation, ResidenceRecord};
use terrane_core::identity::{Identity, IdentityKind, TERRANE_V1};
use tokio::sync::oneshot;

mod recovered;
mod recovered_inline;

pub(in crate::host_cache::owner) use recovered_inline::RecoveredInlineJob;
pub(super) use recovered_inline::prepare as prepare_recovered_inline;

use super::super::{
    RETAINED_LEASE_DEADLINE,
    retention::{Command, Custody, NativeMetadataOwner, NativeOwnerExecutor},
};

/// Retains an original pinned sealed range for reads outside embedded state.
///
/// Physical custody keeps the actual durable funding and backing alive after
/// receipt or owner destruction. This source grants no native handle, new
/// consumer lease or writable cache authority. Its immutable read operations
/// never consult the command queue or lock embedded state.
pub struct NativeResidentChunkSource {
    identity: Identity,
    source: Source,
}

impl NativeResidentChunkSource {
    /// Borrows the registered chunk identity checked against its containing claim.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Returns the independently derived first occurrence in its sealed object.
    pub fn span(&self) -> NativeChunkSpan {
        self.source.span
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
    /// or boundary, native I/O failure, and unavailable bounded allocation.
    pub fn read_verified(&self) -> io::Result<Vec<u8>> {
        check_native(&self.source)?;
        let mut plaintext = Vec::new();
        plaintext
            .try_reserve_exact(self.source.span.length)
            .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
        if plaintext.capacity() > self.source.allocation_limit {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "resident buffer exceeds operator bound",
            ));
        }
        plaintext.resize(self.source.span.length, 0);
        self.source
            .body
            .handle()
            .read_exact_at(&mut plaintext, self.source.span.offset)?;
        TERRANE_V1
            .verify(&self.identity, &plaintext)
            .map_err(io::Error::other)?;
        let profile = self.source.body.layout().layout().chunk_profile();
        if profile.first_boundary(&plaintext) != plaintext.len()
            || (!self.source.span.final_chunk && !profile.valid_nonfinal_chunk(&plaintext))
        {
            return Err(invalid(
                "resident plaintext has another object chunk boundary",
            ));
        }
        check_native(&self.source)?;
        Ok(plaintext)
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
    Ok(NativeResidentChunkSource { identity, source })
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
    Ok(NativeResidentChunkSource { identity, source })
}

impl NativeResidentChunkSource {
    /// Borrows the actual retained source's domain binding.
    pub(in crate::host_cache) fn domain(&self) -> &str {
        self.source.body.claim().domain()
    }

    /// Borrows the chunk profile checked against the original native root.
    pub(in crate::host_cache) fn profile(&self) -> &terrane_core::chunking::ChunkProfile {
        self.source.body.layout().layout().chunk_profile()
    }

    /// Rechecks original funding under a later serialized producer's exclusion.
    ///
    /// This creates no command or authority while that producer is faulted/busy.
    /// Its genuine source was retained before the later operation began.
    ///
    /// # Errors
    /// Refuses changed original job, pins, metadata, range or snapshot provenance.
    pub(super) fn check_protected(&self, owner: &Custody) -> io::Result<()> {
        if !owner
            .state
            .residences
            .iter()
            .any(|row| self.matches_record(row))
        {
            return Err(invalid("retained source lost original publication custody"));
        }
        check_origin(owner, &self.source, &self.identity)
    }

    /// Recognizes only the original checked residence, without choosing another body.
    pub(super) fn matches_record(&self, row: &ResidenceRecord) -> bool {
        same_row(row, &self.source.row)
    }
}

/// Counts retained native source and generated range-name storage per unique chunk.
pub(super) fn header_bytes() -> usize {
    std::mem::size_of::<NativeResidentChunkSource>()
        + std::mem::size_of::<Source>()
        + 4 * std::mem::size_of::<usize>()
        + 128
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
    check_snapshot(owner)?;
    if !job.started || !job.complete {
        return Err(invalid("resident publication is not complete"));
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
    claim_span(owner, &job.claim, identity, row)
}

fn check_snapshot(owner: &Custody) -> io::Result<()> {
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

fn check_native_body(
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
