//! Serializes durable metadata pins and index repair in a physical native worker.
//!
//! A reservation snapshot precedes metadata synchronization. A second snapshot
//! records the actual manifest and whole-pack pins only after pack/index/parent
//! synchronization succeeds. Holds and source descriptors remain owned after a
//! cancelled request or late failure; recovery must reconcile them before reuse.

use super::{
    NativeCachePreparation,
    index_io::{IndexWriteCompletion, PendingIndexWrite, open_regular_at, write_missing_index},
};
use crate::{
    host_cache::{
        DerivedIndexRepair, DetachedIndexStatus, NativeHostLayout, NativeHostMetadataReader,
        NativeManifestSource,
    },
    host_quota::{NativeProject, synchronized_allocated_bytes},
    publisher_local::client::Client,
};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, openat};
use std::{
    collections::BTreeMap,
    fs::{File, Metadata},
    io::{self, Read},
    os::unix::fs::MetadataExt,
    sync::{Arc, Mutex, mpsc},
};
use terrane::{
    host::{
        cache::{CacheState, HostDomainLocation, LeaseRecord, PinRecord, ReservationRecord},
        publication::PublicationClaim,
    },
    store::{ByteRange, TokioLocalFs},
};
use terrane_core::identity::{Identity, IdentityKind};
use tokio::sync::oneshot;

mod executor;
use executor::NativeOwnerExecutor;
pub(crate) use executor::PublisherResumeTurn;

/// Retains a native queue for durable metadata pins and missing-index repair.
///
/// This owner enables no publication, eviction or native admission.
/// Cold records remain untrusted candidates until recovery reconciles
/// them. Dropping an awaiting request does not cancel physical execution.
pub struct NativeMetadataOwner {
    /// Bounded admission to physical work retained independently of reply waiters.
    pub(super) commands: Option<mpsc::SyncSender<Command>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

/// Transfers complete command ownership to the retained physical executor.
pub(super) enum Command {
    /// Transfers genuine completion through the sole physical Resume turn.
    Resume {
        completed: super::CompletedRecovery,
        response: oneshot::Sender<io::Result<()>>,
    },
    /// Runs actual recovery without enabling Resume or service readiness.
    Recover {
        response: oneshot::Sender<io::Result<super::CompletedRecovery>>,
    },
    /// Synchronizes and pins independently verified reconstruction metadata.
    Retain {
        identity: Identity,
        response: oneshot::Sender<io::Result<RetainedManifest>>,
    },
    /// Repairs one missing detached index under durable source custody.
    RepairIndex {
        source: DerivedIndexRepair,
        response: oneshot::Sender<io::Result<NativeIndexRepairReport>>,
    },
}

struct IndexRepairCustody {
    source: Arc<DerivedIndexRepair>,
    pending: Option<PendingIndexWrite>,
    completed: Option<IndexWriteCompletion>,
}

/// Retains native proofs, exclusive state ownership and physical command resources.
pub(super) struct Custody {
    pub(super) preparation: NativeCachePreparation,
    pub(super) directory: File,
    pub(super) state: CacheState,
    pub(super) snapshot: Option<(File, Metadata)>,
    sources: BTreeMap<[u8; 16], Arc<NativeManifestSource>>,
    index_repairs: BTreeMap<[u8; 16], IndexRepairCustody>,
    pub(super) faulted: bool,
    pub(super) recovery_required: bool,
    pub(super) generation: u64,
    pub(super) recovery_id: Option<[u8; 16]>,
    pub(super) snapshot_allocated_bytes: u64,
    pub(super) directory_allocated_bytes: u64,
}

/// Reports an actual index repair without granting serving or recovery authority.
///
/// The owner retains the source, durable pack pin and future hold independently
/// of this report. This describes one physical command, never complete inventory
/// reconciliation, writable readiness or permission to Resume.
pub struct NativeIndexRepairReport {
    pack_id: terrane::pack::PackId,
    synchronized_index_bytes: u64,
}

impl NativeIndexRepairReport {
    /// Returns the existing pack identifier whose detached index was repaired.
    pub fn pack_id(&self) -> terrane::pack::PackId {
        self.pack_id
    }

    /// Returns measured synchronized allocation for the canonical index alone.
    ///
    /// This excludes source, state and directory allocation, kernel reservations
    /// and logical future holds; it is not total tier charge.
    pub fn synchronized_index_bytes(&self) -> u64 {
        self.synchronized_index_bytes
    }
}

/// Proves actual synchronized metadata retention under one native owner.
///
/// Only the retained command worker constructs this receipt, after durable
/// reservation and pin snapshots, actual file/parent synchronization, fresh
/// authenticated quota reconciliation and source-incarnation checks. It is not
/// a serving handle or a completed startup-recovery receipt. No public file,
/// digest or boolean constructor exists. Its owner and source custody survive
/// destruction of the request waiter.
pub struct RetainedManifest {
    source: Arc<NativeManifestSource>,
    custody: Arc<Mutex<Custody>>,
    retention_id: [u8; 16],
    cache_incarnation: [u8; 16],
    session: Arc<Client<HostDomainLocation>>,
    synchronized_source_bytes: u64,
}

impl NativeMetadataOwner {
    /// Starts a bounded physical owner over already authenticated preparation.
    ///
    /// The dedicated thread retains all commands through actual completion. It
    /// takes exclusive custody of the configured existing `state/cache` inode;
    /// it never creates that operator-provisioned directory. Existing durable
    /// records load as candidates. Mutations require actual recovery first;
    /// unhandled records are never cleared merely to make startup succeed.
    ///
    /// # Errors
    /// Refuses unavailable thread/runtime resources, stale native preparation,
    /// unsafe/malformed state custody, another state writer and cold scratch.
    pub fn start(preparation: NativeCachePreparation) -> io::Result<Self> {
        let (commands, receive) = mpsc::sync_channel(preparation.config.queued_commands);
        let (ready, startup) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("terrane-metadata-owner".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                let custody = match runtime.block_on(Custody::open(preparation)) {
                    Ok(custody) => Arc::new(Mutex::new(custody)),
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                let mut executor = NativeOwnerExecutor::new(custody);
                if ready.send(Ok(())).is_err() {
                    return;
                }
                while let Ok(command) = receive.recv() {
                    match command {
                        Command::Resume {
                            completed,
                            response,
                        } => {
                            let result = executor.resume(completed);
                            // The executor retains the physical outcome before reply.
                            let _ = response.send(result);
                        }
                        Command::Recover { response } => {
                            let result = executor.check_recovery_phase().and_then(|()| {
                                runtime.block_on(super::recovery::run(executor.custody()))
                            });
                            let _ = response.send(result);
                        }
                        Command::Retain { identity, response } => {
                            let result = executor.check_recovery_phase().and_then(|()| {
                                runtime.block_on(retain(executor.custody(), identity))
                            });
                            // An abandoned reply never releases the registry's source,
                            // durable pins, future hold or exclusive state custody.
                            let _ = response.send(result);
                        }
                        Command::RepairIndex { source, response } => {
                            let result = executor.check_recovery_phase().and_then(|()| {
                                runtime.block_on(repair_index(executor.custody(), source))
                            });
                            // Actual source/temporary custody and durable holds
                            // belong to the worker, never to this reply waiter.
                            let _ = response.send(result);
                        }
                    }
                }
            })?;
        let initialized = startup
            .recv()
            .map_err(|_| io::Error::other("metadata owner startup terminated"))
            .and_then(|result| result);
        if let Err(error) = initialized {
            drop(commands);
            let _ = worker.join();
            return Err(error);
        }
        Ok(Self {
            commands: Some(commands),
            worker: Some(worker),
        })
    }

    /// Resumes the actual publisher through this owner's serialized physical queue.
    ///
    /// The consumed completion and acknowledged context remain with the worker
    /// even if this waiter disappears. Success grants no Store readiness or
    /// native admission; running mutations require a separate concrete turn.
    ///
    /// # Errors
    /// Refuses a full or stopped queue, foreign or stale completion, repeated
    /// handoff, or failed/uncertain transport. Failures retain recovery custody.
    pub async fn resume_recovered(&self, completed: super::CompletedRecovery) -> io::Result<()> {
        let (response, receive) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(|| io::Error::other("metadata owner stopped"))?
            .try_send(Command::Resume {
                completed,
                response,
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "metadata owner queue is full")
                }
                mpsc::TrySendError::Disconnected(_) => io::Error::other("metadata owner stopped"),
            })?;
        receive
            .await
            .map_err(|_| io::Error::other("metadata owner terminated before Resume completion"))?
    }

    /// Retains verified reconstruction metadata before any dependent publication.
    ///
    /// Requests use the actual configured domain and profile; callers supply no
    /// paths, source files, callback or validity assertion. A full queue returns
    /// immediately. Cancellation after enqueue leaves physical execution owned.
    ///
    /// # Errors
    /// Returns capacity, unavailable owner, metadata verification, synchronization,
    /// durable state or authenticated quota failures. No error grants a receipt.
    pub async fn retain_manifest(&self, identity: Identity) -> io::Result<RetainedManifest> {
        if identity.kind() != IdentityKind::Manifest {
            return Err(invalid("retention requires a manifest identity"));
        }
        let (response, receive) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(|| io::Error::other("metadata owner stopped"))?
            .try_send(Command::Retain { identity, response })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "metadata owner queue is full")
                }
                mpsc::TrySendError::Disconnected(_) => io::Error::other("metadata owner stopped"),
            })?;
        receive
            .await
            .map_err(|_| io::Error::other("metadata owner terminated before completion"))?
    }

    /// Repairs a missing index from genuine same-owner verified pack evidence.
    ///
    /// The bounded physical queue owns the source after enqueue. A cancelled
    /// waiter cannot release its durable pack pin, future hold or failed scratch.
    /// Existing mismatching indexes are never replaced. Successful repair does
    /// not clear any other recovery issue or authorize publication or Resume.
    ///
    /// # Errors
    /// Refuses disabled/unfunded repair, stale or foreign source custody, a full
    /// queue, failed durability and unreconciled actual charges. Late failures
    /// fault the owner while retaining physical resources and durable records.
    pub async fn repair_missing_index(
        &self,
        source: DerivedIndexRepair,
    ) -> io::Result<NativeIndexRepairReport> {
        let (response, receive) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(|| io::Error::other("metadata owner stopped"))?
            .try_send(Command::RepairIndex { source, response })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "metadata owner queue is full")
                }
                mpsc::TrySendError::Disconnected(_) => io::Error::other("metadata owner stopped"),
            })?;
        receive
            .await
            .map_err(|_| io::Error::other("metadata owner terminated before index completion"))?
    }
}

impl Drop for NativeMetadataOwner {
    fn drop(&mut self) {
        // Close admission before waiting for all already owned physical work.
        self.commands.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl RetainedManifest {
    /// Retains the actual producer's session without acquiring its state mutex.
    pub(crate) fn publisher_session(&self) -> Arc<Client<HostDomainLocation>> {
        Arc::clone(&self.session)
    }

    /// Checks native session object identity; it does not mint retention authority.
    pub(crate) fn matches_client(&self, client: &Client<HostDomainLocation>) -> bool {
        std::ptr::eq(self.session.as_ref(), client)
    }

    /// Borrows the exact canonical manifest claim bound to the durable pin.
    pub fn claim(&self) -> &PublicationClaim {
        self.source.claim()
    }

    /// Borrows the actual retained metadata-pack descriptor, without transferring custody.
    pub fn metadata_file(&self) -> &File {
        self.source.files().0
    }

    /// Returns the authoritative canonical manifest body range in that pack.
    pub fn manifest_range(&self) -> ByteRange {
        self.source.range()
    }

    /// Borrows the verified identity of the entire retained metadata pack.
    pub fn pack_identity(&self) -> &Identity {
        self.source.pack_identity()
    }

    /// Returns the existing random pack identifier selecting both canonical files.
    pub fn pack_id(&self) -> terrane::pack::PackId {
        self.source.pack_id()
    }

    /// Borrows the actual random pin and reservation identifier.
    pub fn retention_id(&self) -> &[u8; 16] {
        &self.retention_id
    }

    /// Borrows the real publisher client's stable cache incarnation.
    pub fn cache_incarnation(&self) -> &[u8; 16] {
        &self.cache_incarnation
    }

    /// Borrows actual domain-root and provisioning custody retained by the pin.
    pub fn layout(&self) -> &Arc<NativeHostLayout<HostDomainLocation>> {
        self.source.layout()
    }

    /// Returns synchronized pack/index allocation, counted once per native inode.
    ///
    /// This excludes state, directories, private publisher allocation and kernel
    /// reservations. It is not total tier usage or a future-capacity guarantee.
    pub fn synchronized_source_bytes(&self) -> u64 {
        self.synchronized_source_bytes
    }

    /// Returns the owner's latest synchronized snapshot and cache-directory allocation.
    ///
    /// This counts only those two native inodes. It excludes source packs,
    /// filesystem-wide metadata, publisher allocation and kernel reservations;
    /// shared policy allocation must not be counted again for each receipt.
    ///
    /// # Errors
    /// Refuses stale/faulted custody or an overflowing measured allocation sum.
    pub fn synchronized_policy_bytes(&self) -> io::Result<u64> {
        self.check_current()?;
        let custody = self
            .custody
            .lock()
            .map_err(|_| io::Error::other("metadata custody poisoned"))?;
        custody.check_current()?;
        if custody.faulted {
            return Err(invalid(
                "metadata allocation requires failed-operation recovery",
            ));
        }
        custody
            .snapshot_allocated_bytes
            .checked_add(custody.directory_allocated_bytes)
            .ok_or_else(|| invalid("policy allocation sum overflow"))
    }

    /// Checks current native source and the actual durable pin-owner custody.
    ///
    /// This checks pin state before publication, never on an already sealed read.
    ///
    /// # Errors
    /// Refuses a faulted owner, stale process/root/source/snapshot, absent actual
    /// pin registration or another cache incarnation.
    pub fn check_current(&self) -> io::Result<()> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| io::Error::other("metadata custody poisoned"))?;
        custody.check_current()?;
        if !Arc::ptr_eq(&self.session, &custody.preparation.publisher_session())
            || custody.faulted
            || custody.recovery_required
            || custody.snapshot.is_none()
            || !custody
                .sources
                .get(&self.retention_id)
                .is_some_and(|source| Arc::ptr_eq(source, &self.source))
            || custody.preparation.publisher().cache_incarnation() != &self.cache_incarnation
        {
            return Err(invalid("metadata retention custody is no longer current"));
        }
        let token = hex(&self.retention_id);
        let pin_owner = format!("metadata:{token}");
        if !custody.state.reservations.iter().any(|record| {
            record.id == token
                && record.owner == custody.preparation.config.quota_owner
                && record.bytes == custody.preparation.config.metadata_sync_hold_bytes
        }) || !custody
            .state
            .leases
            .iter()
            .any(|lease| lease.owner == pin_owner && lease.expires == u64::MAX)
            || [
                hex(self.claim().descriptor().digest()),
                hex(self.pack_identity().digest()),
            ]
            .iter()
            .any(|hash| {
                !custody.state.pins.iter().any(|pin| {
                    pin.owner == pin_owner && &pin.hash == hash && pin.expires == u64::MAX
                })
            })
        {
            return Err(invalid(
                "durable metadata pin, lease or reservation is absent",
            ));
        }
        self.source.recheck()
    }
}

impl Custody {
    async fn open(mut preparation: NativeCachePreparation) -> io::Result<Self> {
        preparation.recheck()?;
        let state = preparation
            .layout()
            .directories
            .get("state")
            .ok_or_else(|| invalid("retained state root is absent"))?;
        let directory = File::from(openat(
            state,
            "cache",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = directory.metadata()?;
        let project = NativeProject::inspect(&directory)?;
        if metadata.uid() != preparation.config.content_uid
            || metadata.gid() != preparation.config.state_gid
            || metadata.mode() & 0o7777 != 0o2770
            || project.project_id != preparation.config.project_id
            || !project.inherit
            || metadata.dev() != project.device
            || metadata.dev() != preparation.layout().directory_binding("state")?.0
        {
            return Err(invalid(
                "cache state directory differs from native role/project custody",
            ));
        }
        flock(&directory, FlockOperation::NonBlockingLockExclusive)?;
        for entry in rustix::fs::Dir::read_from(&directory)? {
            let entry = entry?;
            if !matches!(entry.file_name().to_bytes(), b"." | b".." | b"records.toml") {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "cold cache state scratch requires native recovery before metadata mutation",
                ));
            }
        }
        let mut custody = Self {
            preparation,
            directory,
            state: CacheState::default(),
            snapshot: None,
            sources: BTreeMap::new(),
            index_repairs: BTreeMap::new(),
            faulted: false,
            recovery_required: true,
            generation: 0,
            recovery_id: None,
            snapshot_allocated_bytes: 0,
            directory_allocated_bytes: 0,
        };
        custody.capture_snapshot()?;
        let path = custody
            .preparation
            .config
            .location
            .root()
            .join("state/cache");
        let state = CacheState::load(&TokioLocalFs, &path, custody.preparation.config.state)
            .await
            .map_err(io::Error::other)?
            .unwrap_or_default();
        custody.state = state;
        custody.check_current()?;
        Ok(custody)
    }

    /// Checks current confinement, retained state directory and snapshot incarnation.
    ///
    /// # Errors
    /// Refuses stale native roots, replaced directories/snapshots and snapshots
    /// created outside the physical owner.
    pub(super) fn check_current(&self) -> io::Result<()> {
        self.preparation.confinement.check_current()?;
        self.preparation.layout().recheck()?;
        let root = self
            .preparation
            .layout()
            .directories
            .get("state")
            .ok_or_else(|| invalid("state root absent"))?;
        let current = File::from(openat(
            root,
            "cache",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let expected = self.directory.metadata()?;
        let actual = current.metadata()?;
        if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
            return Err(invalid("cache state directory replaced"));
        }
        if let Some((retained, expected)) = &self.snapshot {
            let current = File::from(openat(
                &self.directory,
                "records.toml",
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            if !same_file(expected, &retained.metadata()?)
                || !same_file(expected, &current.metadata()?)
            {
                return Err(invalid("durable cache snapshot replaced or modified"));
            }
        } else {
            match openat(
                &self.directory,
                "records.toml",
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(invalid("cache snapshot appeared outside its owner")),
            }
        }
        Ok(())
    }

    fn capture_snapshot(&mut self) -> io::Result<()> {
        match open_regular_at(&self.directory, "records.toml") {
            Ok(file) => {
                let metadata = file.metadata()?;
                if !metadata.is_file()
                    || metadata.uid() != self.preparation.config.content_uid
                    || metadata.gid() != self.preparation.config.state_gid
                    || metadata.mode() & 0o002 != 0
                    || NativeProject::inspect(&file)?.project_id
                        != self.preparation.config.project_id
                {
                    return Err(invalid("cache snapshot has invalid native custody"));
                }
                self.snapshot = Some((file, metadata));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && self.snapshot.is_none() => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    /// Synchronizes the bounded snapshot and fixed ancestors before retaining it.
    ///
    /// # Errors
    /// Refuses failed snapshot/parent durability and missing or changed state.
    pub(super) async fn persist(&mut self) -> io::Result<()> {
        let path = self.preparation.config.location.root().join("state/cache");
        self.state
            .persist(&TokioLocalFs, &path, self.preparation.config.state)
            .await
            .map_err(io::Error::other)?;
        // The snapshot helper synchronizes state/cache itself. Retain and sync
        // its fixed layout ancestors too before treating the pin as durable.
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let state_root = self
            .preparation
            .layout()
            .directories
            .get("state")
            .ok_or_else(|| invalid("retained state root is absent"))?;
        File::from(openat(state_root, ".", flags, Mode::empty())?).sync_all()?;
        File::from(openat(
            &self.preparation.layout().root,
            ".",
            flags,
            Mode::empty(),
        )?)
        .sync_all()?;
        self.capture_snapshot()?;
        if self.snapshot.is_none() {
            return Err(invalid("synchronized metadata pin snapshot is absent"));
        }
        self.check_current()
    }

    /// Invalidates an older completion before any new durable command effects.
    ///
    /// # Errors
    /// Refuses exhaustion of the actual owner's monotonic command generation.
    pub(super) fn begin_mutation(&mut self) -> io::Result<()> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("native owner command generation overflow"))?;
        self.recovery_id = None;
        Ok(())
    }
}

async fn retain(custody: &Arc<Mutex<Custody>>, identity: Identity) -> io::Result<RetainedManifest> {
    let mut owner = custody
        .lock()
        .map_err(|_| io::Error::other("metadata custody poisoned"))?;
    if owner.faulted || owner.recovery_required {
        return Err(io::Error::other(
            "metadata owner requires failed-operation recovery",
        ));
    }
    owner.check_current()?;
    owner.preparation.recheck()?;
    let reader = NativeHostMetadataReader::open(
        Arc::clone(owner.preparation.layout()),
        owner.preparation.config.reads,
    )
    .await
    .map_err(io::Error::other)?;
    let source = Arc::new(
        NativeManifestSource::open(&reader, &identity, owner.preparation.config.reads).await?,
    );
    for file in [source.files().0, source.files().1] {
        if NativeProject::inspect(file)?.project_id != owner.preparation.config.project_id {
            return Err(invalid("retained metadata has another native project"));
        }
    }
    owner.preparation.recheck()?;
    let future = owner.state.reservations.iter().try_fold(
        owner.preparation.config.metadata_sync_hold_bytes,
        |total, reservation| {
            total
                .checked_add(reservation.bytes)
                .ok_or_else(|| invalid("future hold sum overflow"))
        },
    )?;
    let charged = owner
        .preparation
        .quota()
        .observation()
        .charged_reserved_bytes;
    if charged
        .checked_add(future)
        .is_none_or(|total| total > owner.preparation.config.policy.capacity)
    {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "native metadata future hold exceeds available charge budget",
        ));
    }
    let mut retention_id = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut retention_id)?;
    if owner.sources.contains_key(&retention_id) || owner.index_repairs.contains_key(&retention_id)
    {
        return Err(io::Error::other(
            "random metadata retention identifier collision",
        ));
    }
    let token = hex(&retention_id);
    let pin_owner = format!("metadata:{token}");
    let reservation = ReservationRecord {
        id: token,
        owner: owner.preparation.config.quota_owner.clone(),
        bytes: owner.preparation.config.metadata_sync_hold_bytes,
    };
    let mut next = owner.state.clone();
    next.reservations.push(reservation);
    let mut pinned = next.clone();
    pinned.leases.push(LeaseRecord {
        owner: pin_owner.clone(),
        expires: u64::MAX,
    });
    for hash in [hex(identity.digest()), hex(source.pack_identity().digest())] {
        pinned.pins.push(PinRecord {
            owner: pin_owner.clone(),
            hash,
            expires: u64::MAX,
        });
    }
    next.encoded_len(owner.preparation.config.state)
        .map_err(io::Error::other)?;
    pinned
        .encoded_len(owner.preparation.config.state)
        .map_err(io::Error::other)?;
    owner.begin_mutation()?;
    owner.sources.insert(retention_id, Arc::clone(&source));
    owner.state = next;
    // From the first attempted snapshot onward, all failure paths keep this
    // source and hold registered and refuse subsequent mutations. Once this
    // reservation snapshot is durable, later failures remain visible on disk.
    owner.faulted = true;
    owner.persist().await?;
    source.synchronize()?;
    owner.state = pinned;
    owner.persist().await?;
    let mut allocated = BTreeMap::new();
    for file in [source.files().0, source.files().1] {
        let bytes = synchronized_allocated_bytes(file)?;
        let metadata = file.metadata()?;
        allocated.insert((metadata.dev(), metadata.ino()), bytes);
    }
    let synchronized_source_bytes = allocated.values().try_fold(0_u64, |total, bytes| {
        total
            .checked_add(*bytes)
            .ok_or_else(|| invalid("source allocation overflow"))
    })?;
    let snapshot_bytes = owner
        .snapshot
        .as_ref()
        .ok_or_else(|| invalid("completed metadata pin snapshot is absent"))
        .and_then(|(file, _)| synchronized_allocated_bytes(file))?;
    owner.snapshot_allocated_bytes = snapshot_bytes;
    owner.directory_allocated_bytes = synchronized_allocated_bytes(&owner.directory)?;
    owner.preparation.recheck()?;
    if owner
        .preparation
        .quota()
        .observation()
        .charged_reserved_bytes
        .checked_add(future)
        .is_none_or(|total| total > owner.preparation.config.policy.capacity)
    {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "reconciled charge and retained holds exceed cache policy",
        ));
    }
    source.recheck()?;
    owner.check_current()?;
    // The policy hold remains durable for the dependent metadata's entire
    // lifetime. Only actual retirement/recovery can release it; waiter or receipt
    // destruction never does. Allocation and kernel charge remain separate.
    owner.faulted = false;
    let cache_incarnation = *owner.preparation.publisher().cache_incarnation();
    let session = owner.preparation.publisher_session();
    Ok(RetainedManifest {
        source,
        custody: Arc::clone(custody),
        retention_id,
        cache_incarnation,
        session,
        synchronized_source_bytes,
    })
}

async fn repair_index(
    custody: &Arc<Mutex<Custody>>,
    source: DerivedIndexRepair,
) -> io::Result<NativeIndexRepairReport> {
    let mut owner = custody
        .lock()
        .map_err(|_| io::Error::other("metadata custody poisoned"))?;
    if owner.faulted || owner.recovery_required {
        return Err(io::Error::other(
            "index repair requires failed-operation recovery",
        ));
    }
    owner.check_current()?;
    let hold = owner
        .preparation
        .config
        .index_repair_hold(source.index_bytes().len())?;
    if source.detached_index_status() != DetachedIndexStatus::Missing
        || !source.matches_client(owner.preparation.publisher())
        || !Arc::ptr_eq(source.layout(), owner.preparation.layout())
    {
        return Err(invalid(
            "index repair has foreign or ineligible source evidence",
        ));
    }
    source.check_pack_current()?;
    for file in [source.pack_file(), source.parent_file()] {
        if NativeProject::inspect(file)?.project_id != owner.preparation.config.project_id {
            return Err(invalid(
                "index repair source differs from the charged project",
            ));
        }
    }

    // InspectPending can itself reconcile publisher custody. Authenticate fresh
    // actual charges here, even if inspection performed no local cache writes.
    owner.preparation.recheck()?;
    let future = owner
        .state
        .reservations
        .iter()
        .try_fold(hold, |total, reservation| {
            total
                .checked_add(reservation.bytes)
                .ok_or_else(|| invalid("index repair future holds overflow"))
        })?;
    check_future_charge(&owner, future)?;
    let mut id = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut id)?;
    let token = hex(&id);
    if owner.sources.contains_key(&id)
        || owner.index_repairs.contains_key(&id)
        || owner
            .state
            .reservations
            .iter()
            .any(|record| record.id == token)
    {
        return Err(io::Error::other("random index repair identifier collision"));
    }
    let pin_owner = format!("index-repair:{token}");
    let mut next = owner.state.clone();
    next.reservations.push(ReservationRecord {
        id: token,
        owner: owner.preparation.config.quota_owner.clone(),
        bytes: hold,
    });
    next.leases.push(LeaseRecord {
        owner: pin_owner.clone(),
        expires: u64::MAX,
    });
    next.pins.push(PinRecord {
        owner: pin_owner,
        hash: hex(source.pack_identity().digest()),
        expires: u64::MAX,
    });
    next.encoded_len(owner.preparation.config.state)
        .map_err(io::Error::other)?;

    let source = Arc::new(source);
    owner.begin_mutation()?;
    owner.index_repairs.insert(
        id,
        IndexRepairCustody {
            source: Arc::clone(&source),
            pending: None,
            completed: None,
        },
    );
    owner.state = next;
    owner.faulted = true;
    // No index allocation begins before the actual source pin and future hold
    // survive state snapshot/parent synchronization. Every subsequent failure
    // leaves those records and the source in the physical owner's registry.
    owner.persist().await?;
    source.pack_file().sync_all()?;
    source.parent_file().sync_all()?;
    source.check_pack_current()?;
    let result = write_missing_index(&source);
    let entry = owner
        .index_repairs
        .get_mut(&id)
        .ok_or_else(|| invalid("registered index source custody is absent"))?;
    let allocated_bytes = match result {
        Ok(completion) => {
            let bytes = completion.allocated_bytes;
            entry.completed = Some(completion);
            bytes
        }
        Err(failure) => {
            entry.pending = Some(failure.pending);
            return Err(failure.error);
        }
    };

    // A second durable snapshot and fresh authenticated charge observation are
    // part of command completion, not tasks detached from the caller's waiter.
    owner.persist().await?;
    owner.snapshot_allocated_bytes = owner
        .snapshot
        .as_ref()
        .ok_or_else(|| invalid("index repair policy snapshot is absent"))
        .and_then(|(file, _)| synchronized_allocated_bytes(file))?;
    owner.directory_allocated_bytes = synchronized_allocated_bytes(&owner.directory)?;
    owner.preparation.recheck()?;
    check_future_charge(&owner, future)?;
    let retained = owner
        .index_repairs
        .get(&id)
        .ok_or_else(|| invalid("completed index source custody is absent"))?;
    retained.source.check_pack_current()?;
    let completed = retained
        .completed
        .as_ref()
        .ok_or_else(|| invalid("completed canonical index custody is absent"))?;
    completed.check_current(&retained.source)?;
    owner.check_current()?;
    owner.faulted = false;
    Ok(NativeIndexRepairReport {
        pack_id: source.pack_id(),
        synchronized_index_bytes: allocated_bytes,
    })
}

fn check_future_charge(owner: &Custody, future: u64) -> io::Result<()> {
    if owner
        .preparation
        .quota()
        .observation()
        .charged_reserved_bytes
        .checked_add(future)
        .is_none_or(|total| total > owner.preparation.config.policy.capacity)
    {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "actual charge and retained index repair holds exceed policy",
        ));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
