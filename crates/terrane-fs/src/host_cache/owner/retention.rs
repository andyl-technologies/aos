//! Serializes durable metadata pins in a retained physical native worker.
//!
//! A reservation snapshot precedes metadata synchronization. A second snapshot
//! records the actual manifest and whole-pack pins only after pack/index/parent
//! synchronization succeeds. Holds and source descriptors remain owned after a
//! cancelled request or late failure; recovery must reconcile them before reuse.

use super::NativeCachePreparation;
use crate::{
    host_cache::{NativeHostLayout, NativeHostMetadataReader, NativeManifestSource},
    host_quota::{NativeProject, synchronized_allocated_bytes},
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

/// Retains the native command queue for durable reconstruction-metadata pins.
///
/// This recovery-only owner enables no publication, eviction, admission or
/// Resume. Cold state containing records is refused until full native recovery
/// exists. Dropping an awaiting request does not cancel physical execution.
pub struct NativeMetadataOwner {
    commands: Option<mpsc::SyncSender<Command>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

enum Command {
    Retain {
        identity: Identity,
        response: oneshot::Sender<io::Result<RetainedManifest>>,
    },
}

struct Custody {
    preparation: NativeCachePreparation,
    directory: File,
    state: CacheState,
    snapshot: Option<(File, Metadata)>,
    sources: BTreeMap<[u8; 16], Arc<NativeManifestSource>>,
    faulted: bool,
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
    synchronized_source_bytes: u64,
}

impl NativeMetadataOwner {
    /// Starts a bounded physical owner over already authenticated preparation.
    ///
    /// The dedicated thread retains all commands through actual completion. It
    /// takes exclusive custody of the configured existing `state/cache` inode;
    /// it never creates that operator-provisioned directory. Existing durable
    /// records cause conservative startup refusal pending actual recovery.
    ///
    /// # Errors
    /// Refuses unavailable thread/runtime resources, stale native preparation,
    /// unsafe state custody, another state writer and unreconciled cold records.
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
                if ready.send(Ok(())).is_err() {
                    return;
                }
                while let Ok(command) = receive.recv() {
                    match command {
                        Command::Retain { identity, response } => {
                            let result = runtime.block_on(retain(&custody, identity));
                            // An abandoned reply never releases the registry's source,
                            // durable pins, future hold or exclusive state custody.
                            let _ = response.send(result);
                        }
                    }
                }
            })?;
        startup
            .recv()
            .map_err(|_| io::Error::other("metadata owner startup terminated"))??;
        Ok(Self {
            commands: Some(commands),
            worker: Some(worker),
        })
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
        if custody.faulted
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
            faulted: false,
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
        if !state.pins.is_empty()
            || !state.leases.is_empty()
            || !state.reservations.is_empty()
            || !state.residences.is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "cold cache policy records require native recovery before metadata mutation",
            ));
        }
        custody.state = state;
        custody.check_current()?;
        Ok(custody)
    }

    fn check_current(&self) -> io::Result<()> {
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
        match openat(
            &self.directory,
            "records.toml",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => {
                let file = File::from(file);
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
            Err(rustix::io::Errno::NOENT) if self.snapshot.is_none() => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    async fn persist(&mut self) -> io::Result<()> {
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
        self.check_current()
    }
}

async fn retain(custody: &Arc<Mutex<Custody>>, identity: Identity) -> io::Result<RetainedManifest> {
    let mut owner = custody
        .lock()
        .map_err(|_| io::Error::other("metadata custody poisoned"))?;
    if owner.faulted {
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
    if owner.sources.contains_key(&retention_id) {
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
    if let Some((file, _)) = &owner.snapshot {
        synchronized_allocated_bytes(file)?;
    }
    owner.directory.sync_all()?;
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
    // The conservative hold remains durable for the dependent metadata's entire
    // lifetime. Only actual retirement/recovery can release it; waiter or receipt
    // destruction never does. Allocation and kernel charge remain separate.
    owner.faulted = false;
    let cache_incarnation = *owner.preparation.publisher().cache_incarnation();
    Ok(RetainedManifest {
        source,
        custody: Arc::clone(custody),
        retention_id,
        cache_incarnation,
        synchronized_source_bytes,
    })
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
