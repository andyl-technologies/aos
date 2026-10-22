//! Admits canonical surface projections through the existing physical owner.
//!
//! Derived indexes have a separate size cap and namespace, outside canonical
//! pack-index identities. A durable future hold precedes every native effect.
//! The physical registry retains partial copies and uncertain results after a
//! waiter disappears. Admission receipts grant no exposure lease or disclosure.
//!
//! ```text
//! objects/.terrane-surface:<version>:<canonical-root-hex>
//! objects/.terrane-surface-tmp:<random-operation-hex>
//! reservation id = surface-index:<random-operation-hex>
//! ```

pub(super) mod eviction;
pub(super) mod recovery;
mod scoped;

use super::{
    consumer::state,
    index_io::close_checked,
    retention::{Command, Custody, NativeMetadataOwner, NativeOwnerExecutor},
    snapshot,
};
use crate::{
    host_quota::{NativeProject, synchronized_allocated_bytes},
    structural_index::{CompiledIndex, IndexKey},
};
use rustix::fs::{Mode, OFlags, RenameFlags, fchmod, openat, renameat_with};
use std::{
    collections::BTreeMap,
    fs::{File, Metadata},
    io::{self, Read},
    os::unix::fs::{FileExt, MetadataExt},
    sync::{Arc, mpsc},
};
use terrane_format::identity::Digest;
use terrane_sdk::host::{cache::ReservationRecord, publication::VerityBinding};
use tokio::sync::oneshot;

/// Reports actual sealed cache admission without granting an exposure pin.
///
/// Only the serialized owner constructs this after synchronization and fresh
/// project accounting. This receipt exposes no descriptor; disclosure and
/// exposure-lease acquisition remain separate operations.
#[derive(Clone)]
pub struct NativeSurfaceIndex {
    backing: Arc<Backing>,
}

impl NativeSurfaceIndex {
    /// Returns the canonical root and derived format version actually compiled.
    pub fn key(&self) -> IndexKey {
        self.backing.key
    }

    /// Returns synchronized allocation of this index inode, including verity data.
    ///
    /// This excludes directory and snapshot allocation, kernel reservations and
    /// logical future holds; it is never the full project's charged usage.
    pub fn synchronized_inode_bytes(&self) -> u64 {
        self.backing.allocated
    }

    /// Rechecks the original immutable inode without consulting embedded policy.
    ///
    /// # Errors
    /// Refuses changed native identity, ownership, mode, project or kernel seal.
    /// Success grants no serving permission and says nothing about a lease.
    pub fn check_native_backing(&self) -> io::Result<()> {
        self.backing.check()
    }
}

struct Backing {
    key: IndexKey,
    file: File,
    metadata: Metadata,
    binding: VerityBinding,
    project: u32,
    allocated: u64,
}

impl Backing {
    fn check(&self) -> io::Result<()> {
        if !same_inode(&self.metadata, &self.file.metadata()?)
            || NativeProject::inspect(&self.file)?.project_id != self.project
            || crate::verity::measure(&self.file)? != self.binding
        {
            return Err(invalid("surface index lost original immutable custody"));
        }
        Ok(())
    }
}

/// Retains compilation and every attempted physical resource before effects.
pub(super) struct Job {
    compiled: CompiledIndex,
    reservation: String,
    hold: u64,
    temporary: String,
    canonical: String,
    writer: Option<File>,
    reader: Option<File>,
    backing: Option<Arc<Backing>>,
}

impl NativeMetadataOwner {
    /// Compiles and admits bounded canonical metadata through the physical queue.
    ///
    /// This fetches no object content. The caller separately authenticates the
    /// root; possession of input nodes is not disclosure authorization. After
    /// enqueue, cancellation cannot discard the job's physical progress or hold.
    /// Existing native names never substitute for actual canonical compilation.
    ///
    /// # Errors
    /// Refuses disabled admission, oversized input, queue exhaustion, absent
    /// actual Resume, malformed nodes, capacity, native IO, sealing or accounting.
    /// Late failures fault the owner and retain its original resources.
    pub async fn cache_surface_index(
        &self,
        root: Digest,
        nodes: BTreeMap<Digest, Vec<u8>>,
    ) -> io::Result<NativeSurfaceIndex> {
        self.submit_surface_index(root, nodes, None).await
    }

    async fn submit_surface_index(
        &self,
        root: Digest,
        nodes: BTreeMap<Digest, Vec<u8>>,
        domain: Option<String>,
    ) -> io::Result<NativeSurfaceIndex> {
        self.check_surface_input(&nodes)?;
        if let Some(domain) = &domain {
            self.admission_bounds.check(domain.len(), 0)?;
        }
        let (response, receive) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(|| invalid("native owner stopped"))?
            .try_send(Command::CacheSurfaceIndex {
                root,
                nodes,
                domain,
                response,
            })
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
            .map_err(|_| invalid("native owner stopped before surface completion"))?
    }

    fn check_surface_input(&self, nodes: &BTreeMap<Digest, Vec<u8>>) -> io::Result<()> {
        let policy = self.surface_policy.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "surface index admission disabled",
            )
        })?;
        let bytes = nodes.values().try_fold(0usize, |total, body| {
            total
                .checked_add(32)
                .and_then(|total| total.checked_add(body.len()))
                .ok_or_else(|| invalid("surface node input accounting overflows"))
        })?;
        if bytes > policy.max_node_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "surface node input exceeds configured bound",
            ));
        }
        Ok(())
    }
}

/// Owns actual admission through both durable snapshots and physical verification.
pub(super) async fn admit(
    executor: &NativeOwnerExecutor,
    root: Digest,
    nodes: BTreeMap<Digest, Vec<u8>>,
    domain: Option<&str>,
) -> io::Result<NativeSurfaceIndex> {
    let running = executor.admission_context()?;
    let custody = Arc::clone(executor.custody());
    let (key, generation, write) = {
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("surface custody poisoned"))?;
        state::check_ready(executor, &owner)?;
        if domain.is_some_and(|domain| domain != owner.preparation.config.location.domain()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "surface root belongs to another physical domain",
            ));
        }
        let policy = owner
            .preparation
            .config
            .surface_index
            .ok_or_else(|| invalid("surface admission disabled"))?;
        let minimum = u64::try_from(owner.preparation.config.location.chunk_profile().minimum())
            .map_err(|_| invalid("surface chunk geometry exceeds native bounds"))?;
        let compiled = CompiledIndex::from_nodes(
            root,
            &nodes,
            minimum,
            policy.max_entries,
            policy.max_index_bytes,
            policy.max_node_bytes,
        )
        .map_err(io::Error::other)?;
        let key = compiled.key();
        if let Some(job) = owner.surface_indexes.get(&key) {
            let reused = reuse(&owner, job, &compiled);
            if reused.is_err() {
                // A failed native check denies further writes while original
                // inode custody and funding remain available for reconciliation.
                owner.faulted = true;
            }
            return reused;
        }
        owner.preparation.recheck()?;
        let allocated = allocation_bound(&owner)?;
        if owner.surface_indexes.len() >= owner.preparation.config.state.records
            || allocated
                .checked_add(compiled.bytes().len() as u64)
                .is_none_or(|sum| sum > policy.capacity_bytes)
        {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "surface index cache cap exhausted",
            ));
        }
        let token = fresh_token(&owner)?;
        let mut next = owner.state.clone();
        next.reservations.push(ReservationRecord {
            id: format!("surface-index:{token}"),
            owner: owner.preparation.config.quota_owner.clone(),
            bytes: policy.future_hold_bytes,
        });
        next.encoded_len(owner.preparation.config.state)
            .map_err(io::Error::other)?;
        let write = state::begin(
            executor,
            &mut owner,
            &running,
            next,
            policy.future_hold_bytes,
            None,
        )?;
        // Retain the exact compilation and namespace intent before any state or
        // inode effect. Subsequent errors cannot turn a partial job into absence.
        owner.surface_indexes.insert(
            key,
            Job {
                compiled,
                reservation: format!("surface-index:{token}"),
                hold: policy.future_hold_bytes,
                temporary: format!(".terrane-surface-tmp:{token}"),
                canonical: format!(".terrane-surface:{}:{}", key.version(), hex(&key.root())),
                writer: None,
                reader: None,
                backing: None,
            },
        );
        (key, owner.generation, write)
    };
    snapshot::persist(executor, write).await?;
    running.check_current().map_err(io::Error::other)?;
    let completion = {
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("surface custody poisoned"))?;
        owner.check_current()?;
        state::check_bootstrap(&owner, &running)?;
        if !owner.faulted || owner.generation != generation {
            return Err(invalid("surface write lost funded physical turn"));
        }
        let layout = Arc::clone(owner.preparation.layout());
        let root = layout
            .directories
            .get("objects")
            .ok_or_else(|| invalid("surface objects root absent"))?;
        let uid = owner.preparation.config.content_uid;
        let gid = owner.preparation.config.content_gid;
        let project = owner.preparation.config.project_id;
        let job = owner
            .surface_indexes
            .get_mut(&key)
            .ok_or_else(|| invalid("surface job absent"))?;
        write_index(job, root, uid, gid, project)?;
        let policy = owner
            .preparation
            .config
            .surface_index
            .ok_or_else(|| invalid("surface policy absent"))?;
        owner.preparation.recheck()?;
        if allocation_bound(&owner)? > policy.capacity_bytes {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "actual surface allocation exceeds separate cap",
            ));
        }
        snapshot::prepare(executor, &mut owner)?
    };
    snapshot::persist(executor, completion).await?;
    running.check_current().map_err(io::Error::other)?;
    let mut owner = custody
        .lock()
        .map_err(|_| invalid("surface custody poisoned"))?;
    let job = owner
        .surface_indexes
        .get(&key)
        .ok_or_else(|| invalid("surface completion absent"))?;
    let backing = job
        .backing
        .as_ref()
        .ok_or_else(|| invalid("surface backing absent"))?;
    backing.check()?;
    let result = NativeSurfaceIndex {
        backing: Arc::clone(backing),
    };
    let observation = state::finish(&mut owner, generation)?;
    if observation.charged
        > owner
            .preparation
            .config
            .surface_index
            .ok_or_else(|| invalid("surface policy absent"))?
            .capacity_bytes
    {
        owner.faulted = true;
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "actual surface allocation bound exceeds separate cap after state synchronization",
        ));
    }
    Ok(result)
}

fn reuse(owner: &Custody, job: &Job, compiled: &CompiledIndex) -> io::Result<NativeSurfaceIndex> {
    if !owner.state.reservations.iter().any(|hold| {
        hold.id == job.reservation
            && hold.owner == owner.preparation.config.quota_owner
            && hold.bytes == job.hold
    }) {
        return Err(invalid("surface cache lost its durable funding"));
    }
    let backing = job
        .backing
        .as_ref()
        .ok_or_else(|| invalid("surface cache contains unresolved job"))?;
    backing.check()?;
    let parent = owner
        .preparation
        .layout()
        .directories
        .get("objects")
        .ok_or_else(|| invalid("surface objects root absent"))?;
    let named = File::from(openat(
        parent,
        &job.canonical,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    if !same_inode(&backing.metadata, &named.metadata()?) {
        return Err(invalid("surface cache name differs from original inode"));
    }
    compiled.verify_reader(&mut PositionedReader {
        file: &backing.file,
        offset: 0,
    })?;
    Ok(NativeSurfaceIndex {
        backing: Arc::clone(backing),
    })
}

fn allocation_bound(owner: &Custody) -> io::Result<u64> {
    let known = owner.surface_indexes.values().try_fold(0u64, |sum, job| {
        sum.checked_add(job.backing.as_ref().map_or(0, |backing| backing.allocated))
            .ok_or_else(|| invalid("surface cache allocation overflows"))
    })?;
    // A cold unlink cannot reveal whether another process or kernel mapping
    // still retains the inode. Counting the complete actual project prevents
    // that unknown allocation from being credited to the separate cap early.
    Ok(known.max(
        owner
            .preparation
            .quota()
            .observation()
            .charged_reserved_bytes,
    ))
}

fn write_index(
    job: &mut Job,
    parent: &impl std::os::fd::AsFd,
    uid: u32,
    gid: u32,
    project: u32,
) -> io::Result<()> {
    let directory = File::from(openat(
        parent,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = directory.metadata()?;
    let assigned = NativeProject::inspect(&directory)?;
    if metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != 0o2770
        || assigned.project_id != project
        || !assigned.inherit
        || assigned.device != metadata.dev()
        || assigned.inode != metadata.ino()
    {
        return Err(invalid(
            "surface parent differs from original charge custody",
        ));
    }
    job.writer = Some(File::from(openat(
        parent,
        &job.temporary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?));
    let writer = job
        .writer
        .as_mut()
        .ok_or_else(|| invalid("surface writer absent"))?;
    check_file(writer, uid, gid, project, 0o600)?;
    job.compiled.write_to(writer)?;
    writer.sync_all()?;
    let written = writer.metadata()?;
    close_checked(
        job.writer
            .take()
            .ok_or_else(|| invalid("surface writer disappeared"))?,
    )?;
    job.reader = Some(File::from(openat(
        parent,
        &job.temporary,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?));
    let reader = job
        .reader
        .as_ref()
        .ok_or_else(|| invalid("surface reader absent"))?;
    if !same_inode(&written, &reader.metadata()?) {
        return Err(invalid(
            "surface staging inode changed after writer closure",
        ));
    }
    job.compiled.verify_reader(&mut PositionedReader {
        file: reader,
        offset: 0,
    })?;
    let binding = crate::verity::enable(reader)?;
    if crate::verity::measure(reader)? != binding {
        return Err(invalid("surface seal measurement changed"));
    }
    fchmod(reader, Mode::from_raw_mode(0o400))?;
    reader.sync_all()?;
    job.compiled.verify_reader(&mut PositionedReader {
        file: reader,
        offset: 0,
    })?;
    check_file(reader, uid, gid, project, 0o400)?;
    renameat_with(
        parent,
        &job.temporary,
        parent,
        &job.canonical,
        RenameFlags::NOREPLACE,
    )?;
    directory.sync_all()?;
    let canonical = File::from(openat(
        parent,
        &job.canonical,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    if !same_inode(&reader.metadata()?, &canonical.metadata()?) {
        return Err(invalid("surface canonical name changed during publication"));
    }
    let allocated = synchronized_allocated_bytes(reader)?;
    job.backing = Some(Arc::new(Backing {
        key: job.compiled.key(),
        metadata: canonical.metadata()?,
        file: canonical,
        binding,
        project,
        allocated,
    }));
    Ok(())
}

fn check_file(file: &File, uid: u32, gid: u32, project: u32, mode: u32) -> io::Result<()> {
    let metadata = file.metadata()?;
    let actual = NativeProject::inspect(file)?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != mode
        || metadata.nlink() != 1
        || actual.project_id != project
        || actual.device != metadata.dev()
        || actual.inode != metadata.ino()
    {
        return Err(invalid(
            "surface inode differs from configured native custody",
        ));
    }
    Ok(())
}

struct PositionedReader<'file> {
    file: &'file File,
    offset: u64,
}

impl Read for PositionedReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.file.read_at(bytes, self.offset)?;
        self.offset = self
            .offset
            .checked_add(count as u64)
            .ok_or_else(|| invalid("surface read offset overflows"))?;
        Ok(count)
    }
}

fn same_inode(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.nlink() == right.nlink()
}

fn fresh_token(owner: &Custody) -> io::Result<String> {
    let mut random = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let token = hex(&random);
    if owner
        .state
        .reservations
        .iter()
        .any(|row| row.id == format!("surface-index:{token}"))
        || owner
            .surface_indexes
            .values()
            .any(|job| job.temporary == format!(".terrane-surface-tmp:{token}"))
    {
        return Err(invalid("surface operation identifier collision"));
    }
    Ok(token)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
