//! Crash-safe immutable physical packs with a generation-bound logical index.
//!
//! A packed leaf stores canonical logical bytes in immutable pack files while
//! one checksummed, atomically replaced index maps each [`ContentId`] to a
//! pinned byte range. Logical identity never includes pack geometry. Ordinary
//! puts publish a valid one-object pack. [`PackedBlobBackend::plan_repack`]
//! captures one exact index generation, and [`PackedBlobBackend::apply_repack`]
//! rewrites that logical set into deterministic bounded multi-object packs,
//! switches the index generation, and only then removes superseded pack names.
//! Readers that opened the old generation retain their file inode until EOF.
//!
//! ```text
//! root/
//!   packs/<pack-id>.pack
//!   .packed-admin/index-v1
//!   .packed-admin/lifecycle.lock
//!   .packed-admin/state.lock
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{FlockOperation, flock};

mod format;

use format::{
    decode_index, decode_repack_plan, encode_index, encode_pack_manifest, encode_repack_plan,
    new_repack_plan, pack_fixed_header_length, pack_id, packed_index_digest, read_pack_header,
    write_pack_header,
};

use super::admin::{InventoryCounter, persistent_inventory_generation};
use super::directory::create_dir_all_durable;
use super::{
    BackendCapabilities, BlobHandle, BlobInventoryFence, BlobInventoryRecord, BlobInventorySummary,
    BlobSource, BlobStoreAdmin, ByteRange, ContentId, ImmutableBlobBackend, PlacementReceipt,
    PlannedDeleteDisposition, PutReceipt, StoreError, content_hasher, copy_source,
};

const PACK_MAGIC: &[u8] = b"crucible.content-store.pack.v1\0";
const INDEX_MAGIC: &[u8] = b"crucible.content-store.pack-index.v1\0";
const PACK_ID_DOMAIN: &[u8] = b"crucible.content-store.pack-id.v1";
const PACK_MANIFEST_DOMAIN: &[u8] = b"crucible.content-store.pack-manifest.v1";
const INDEX_CHECKSUM_DOMAIN: &[u8] = b"crucible.content-store.pack-index.v1";
const INDEX_DIGEST_DOMAIN: &[u8] = b"crucible.content-store.pack-index-digest.v1";
const REPACK_PLAN_MAGIC: &[u8] = b"crucible.content-store.pack-repack-plan.v1\0";
const REPACK_PLAN_CHECKSUM_DOMAIN: &[u8] = b"crucible.content-store.pack-repack-plan.v1";
const REPACK_PLAN_ID_DOMAIN: &[u8] = b"crucible.content-store.pack-repack-plan-id.v1";
const CONFIGURATION_DOMAIN: &[u8] = b"crucible.content-store.packed-configuration.v1";
const INSTANCE_DOMAIN: &[u8] = b"crucible.content-store.packed-instance.v1";
const ADMIN_DIRECTORY: &str = ".packed-admin";
const PACK_DIRECTORY: &str = "packs";
const INDEX_FILE: &str = "index-v1";
const LIFECYCLE_LOCK_FILE: &str = "lifecycle.lock";
const STATE_LOCK_FILE: &str = "state.lock";
const PACK_SUFFIX: &str = ".pack";
const MAX_INDEX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LOGICAL_OBJECTS: usize = 65_536;
const MAX_PACKS: usize = 65_536;
const MAX_PACK_ENTRIES: usize = 4_096;
const MAX_PACK_BYTES: u64 = 128 * 1024 * 1024;
const MIN_TARGET_PACK_BYTES: u64 = 64 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static INSTANCE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Checked logical and physical accounting for one packed leaf generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedStorageAccounting {
    generation: u64,
    logical_objects: u64,
    logical_bytes: u64,
    packs: u64,
    physical_bytes: u64,
}

impl PackedStorageAccounting {
    /// Returns the monotonic index generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the indexed logical-object count.
    #[must_use]
    pub const fn logical_objects(self) -> u64 {
        self.logical_objects
    }

    /// Returns the checked sum of indexed logical bytes.
    #[must_use]
    pub const fn logical_bytes(self) -> u64 {
        self.logical_bytes
    }

    /// Returns the number of physical packs referenced by the index.
    #[must_use]
    pub const fn packs(self) -> u64 {
        self.packs
    }

    /// Returns the checked sum of referenced physical pack bytes.
    #[must_use]
    pub const fn physical_bytes(self) -> u64 {
        self.physical_bytes
    }
}

/// Result of one deterministic replacement-pack publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedRepackReport {
    plan: PackedRepackPlanId,
    before: PackedStorageAccounting,
    after: PackedStorageAccounting,
    removed_packs: u64,
    replayed: bool,
}

impl PackedRepackReport {
    /// Returns the exact applied or replayed plan identity.
    #[must_use]
    pub const fn plan(self) -> PackedRepackPlanId {
        self.plan
    }

    /// Returns accounting before the index-generation switch.
    #[must_use]
    pub const fn before(self) -> PackedStorageAccounting {
        self.before
    }

    /// Returns accounting after replacement publication and cleanup.
    #[must_use]
    pub const fn after(self) -> PackedStorageAccounting {
        self.after
    }

    /// Returns the number of superseded pack names removed durably.
    #[must_use]
    pub const fn removed_packs(self) -> u64 {
        self.removed_packs
    }

    /// Returns whether the index switch had already committed before this call.
    #[must_use]
    pub const fn replayed(self) -> bool {
        self.replayed
    }
}

/// Content-derived identity of one exact packed-index repack plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackedRepackPlanId([u8; 32]);

impl PackedRepackPlanId {
    /// Returns the raw plan digest.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Canonical exact-generation plan for deterministic replacement packing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedRepackPlan {
    id: PackedRepackPlanId,
    configuration: [u8; 32],
    instance: [u8; 32],
    generation: u64,
    index_digest: [u8; 32],
    before: PackedStorageAccounting,
}

impl PackedRepackPlan {
    /// Returns the content-derived plan identity.
    #[must_use]
    pub const fn id(&self) -> PackedRepackPlanId {
        self.id
    }

    /// Returns the exact pre-apply storage accounting captured by the plan.
    #[must_use]
    pub const fn before(&self) -> PackedStorageAccounting {
        self.before
    }

    /// Returns canonical bytes suitable for an external maintenance journal.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_repack_plan(self)
    }

    /// Strictly decodes one canonical v1 plan.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Incompatible`] for truncation, trailing bytes,
    /// checksum failure, or invalid accounting.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        decode_repack_plan(bytes)
    }
}

/// Durable immutable-pack blob backend.
pub struct PackedBlobBackend {
    name: String,
    root: PathBuf,
    packs: PathBuf,
    admin: PathBuf,
    target_pack_bytes: u64,
    configuration: [u8; 32],
}

impl PackedBlobBackend {
    /// Opens or initializes one packed backend at `root`.
    ///
    /// `target_pack_bytes` controls deterministic repack grouping and must be
    /// between 64 KiB and 128 MiB inclusive. Existing roots are bound to the
    /// exact backend name, path bytes, and target size.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, incompatible or corrupt index
    /// state, or a filesystem durability failure.
    pub fn open(
        name: impl Into<String>,
        root: impl Into<PathBuf>,
        target_pack_bytes: u64,
    ) -> Result<Self, StoreError> {
        if !(MIN_TARGET_PACK_BYTES..=MAX_PACK_BYTES).contains(&target_pack_bytes) {
            return Err(StoreError::InvalidComposition {
                reason: "packed target size is outside the admitted bounds",
            });
        }
        let name = name.into();
        let root = root.into();
        let packs = root.join(PACK_DIRECTORY);
        let admin = root.join(ADMIN_DIRECTORY);
        create_dir_all_durable(&packs)?;
        create_dir_all_durable(&admin)?;
        let configuration = configuration_binding(&name, &root, target_pack_bytes);
        let backend = Self {
            name,
            root,
            packs,
            admin,
            target_pack_bytes,
            configuration,
        };
        backend.initialize()?;
        Ok(backend)
    }

    /// Returns generation-bound logical and referenced-physical accounting.
    ///
    /// # Errors
    ///
    /// Returns an error when the index or a referenced pack cannot be
    /// authenticated and measured completely.
    pub fn accounting(&self) -> Result<PackedStorageAccounting, StoreError> {
        let _lifecycle = self.lock_lifecycle(FlockOperation::LockShared)?;
        let _state = self.lock_state()?;
        let index = self.load_index()?;
        self.validate_index_packs(&index)?;
        self.accounting_for(&index)
    }

    /// Plans a deterministic replacement of the exact current index generation.
    ///
    /// Planning is read-only. Any intervening put, delete, or successful repack
    /// makes the returned plan stale and causes [`Self::apply_repack`] to fail
    /// closed.
    ///
    /// # Errors
    ///
    /// Returns an error when the current index or one of its packs cannot be
    /// authenticated and measured completely.
    pub fn plan_repack(&self) -> Result<PackedRepackPlan, StoreError> {
        let _lifecycle = self.lock_lifecycle(FlockOperation::LockShared)?;
        let _state = self.lock_state()?;
        let index = self.load_index()?;
        self.validate_index_packs(&index)?;
        let before = self.accounting_for(&index)?;
        let index_digest = packed_index_digest(&index, self.configuration)?;
        Ok(new_repack_plan(
            self.configuration,
            index.instance,
            index.generation,
            index_digest,
            before,
        ))
    }

    /// Applies one exact-generation replacement-pack plan.
    ///
    /// Existing readers keep pinned old pack inodes. New readers observe the
    /// replacement generation only after every replacement pack is durable.
    /// Superseded pack names are removed only after the index switch. Retrying
    /// the same plan after an indeterminate index publication or cleanup error
    /// is idempotent while no later logical mutation has committed.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan names another backend incarnation or a
    /// stale index generation, or for corrupt logical bytes, pack or index
    /// publication failure, generation overflow, or a resource bound.
    pub fn apply_repack(&self, plan: &PackedRepackPlan) -> Result<PackedRepackReport, StoreError> {
        let _lifecycle = self.lock_lifecycle(FlockOperation::LockExclusive)?;
        let _state = self.lock_state()?;
        let index = self.load_index()?;
        let removed_before = self.cleanup_unreferenced_packs(&index)?;
        self.validate_index_packs(&index)?;

        if plan.configuration != self.configuration || plan.instance != index.instance {
            return Err(StoreError::Incompatible);
        }
        if index.last_repack_plan == Some(plan.id) {
            let expected_generation = plan
                .generation
                .checked_add(1)
                .ok_or(StoreError::Incompatible)?;
            if index.generation != expected_generation {
                return Err(StoreError::Incompatible);
            }
            let after = self.accounting_for(&index)?;
            return Ok(PackedRepackReport {
                plan: plan.id,
                before: plan.before,
                after,
                removed_packs: removed_before,
                replayed: true,
            });
        }

        let before = self.accounting_for(&index)?;
        if index.generation != plan.generation
            || before != plan.before
            || packed_index_digest(&index, self.configuration)? != plan.index_digest
        {
            return Err(StoreError::Incompatible);
        }

        let groups = self.repack_groups(&index)?;
        let mut candidates = Vec::with_capacity(groups.len());
        for group in groups {
            let mut sources = Vec::with_capacity(group.len());
            for id in group {
                let entry = index.entries.get(&id).ok_or(StoreError::Incompatible)?;
                sources.push((id, self.open_entry(id, entry)?));
            }
            candidates.push(self.build_pack(&sources)?);
        }

        let mut next_entries = BTreeMap::new();
        for candidate in &candidates {
            self.publish_pack(candidate)?;
            for (id, entry) in candidate.entries_with_pack() {
                next_entries.insert(id, entry);
            }
        }
        let next = IndexState {
            instance: index.instance,
            generation: index.generation.checked_add(1).ok_or(StoreError::Quota)?,
            last_repack_plan: Some(plan.id),
            entries: next_entries,
        };
        self.publish_index_reconciled(&next)?;

        let retained = next.pack_ids();
        let mut removed_packs = removed_before;
        for pack in index.pack_ids().difference(&retained) {
            if self.remove_pack(*pack)? {
                removed_packs = removed_packs.checked_add(1).ok_or(StoreError::Quota)?;
            }
        }
        let after = self.accounting_for(&next)?;
        Ok(PackedRepackReport {
            plan: plan.id,
            before,
            after,
            removed_packs,
            replayed: false,
        })
    }

    fn initialize(&self) -> Result<(), StoreError> {
        let _lifecycle = self.lock_lifecycle(FlockOperation::LockExclusive)?;
        let _state = self.lock_state()?;
        let path = self.index_path();
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                let index = self.load_index()?;
                self.validate_index_packs(&index)?;
                self.cleanup_unreferenced_packs(&index)?;
            }
            Ok(_) => {
                return Err(StoreError::InvalidComposition {
                    reason: "packed index path is not a regular file",
                });
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                let initial = IndexState {
                    instance: new_instance(&self.root)?,
                    generation: 0,
                    last_repack_plan: None,
                    entries: BTreeMap::new(),
                };
                self.publish_index(&initial)?;
            }
            Err(source) => return Err(io_error("inspect packed index", &path, source)),
        }
        Ok(())
    }

    fn index_path(&self) -> PathBuf {
        self.admin.join(INDEX_FILE)
    }

    fn lock_lifecycle(&self, operation: FlockOperation) -> Result<File, StoreError> {
        self.lock_file(LIFECYCLE_LOCK_FILE, operation)
    }

    fn lock_state(&self) -> Result<File, StoreError> {
        self.lock_file(STATE_LOCK_FILE, FlockOperation::LockExclusive)
    }

    fn lock_file(&self, name: &str, operation: FlockOperation) -> Result<File, StoreError> {
        let path = self.admin.join(name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|source| io_error("open packed lock", &path, source))?;
        flock(&file, operation)
            .map_err(|source| io_error("lock packed backend", &path, source.into()))?;
        Ok(file)
    }

    fn load_index(&self) -> Result<IndexState, StoreError> {
        let path = self.index_path();
        let bytes = read_bounded_file(&path, MAX_INDEX_BYTES, "read packed index")?;
        let index = decode_index(&bytes, self.configuration)?;
        sync_directory(&self.admin)?;
        Ok(index)
    }

    fn publish_index(&self, index: &IndexState) -> Result<(), StoreError> {
        let bytes = encode_index(index, self.configuration)?;
        if bytes.len() as u64 > MAX_INDEX_BYTES {
            return Err(StoreError::Quota);
        }
        let (temporary, mut output) = self.create_temporary(&self.admin, "index")?;
        let result = (|| {
            output
                .write_all(&bytes)
                .and_then(|()| output.sync_all())
                .map_err(|source| io_error("write packed index", &temporary, source))?;
            let path = self.index_path();
            fs::rename(&temporary, &path)
                .map_err(|source| io_error("publish packed index", &path, source))?;
            sync_directory(&self.admin)
        })();
        remove_temporary(&temporary, result.is_ok())?;
        result
    }

    fn publish_index_reconciled(&self, index: &IndexState) -> Result<(), StoreError> {
        match self.publish_index(index) {
            Ok(()) => Ok(()),
            Err(error) => match self.load_index() {
                Ok(current) if current == *index => Ok(()),
                Ok(_) | Err(_) => Err(error),
            },
        }
    }

    fn create_temporary(
        &self,
        directory: &Path,
        label: &str,
    ) -> Result<(PathBuf, File), StoreError> {
        for _ in 0..1_024 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(".{label}.tmp-{}-{sequence}", std::process::id()));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => return Ok((path, file)),
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => return Err(io_error("create packed staging file", &path, source)),
            }
        }
        Err(StoreError::Quota)
    }

    fn pack_path(&self, pack: PackId) -> PathBuf {
        self.packs
            .join(format!("{}{}", encode_hex(pack.0), PACK_SUFFIX))
    }

    fn build_pack(&self, sources: &[(ContentId, BlobHandle)]) -> Result<PackCandidate, StoreError> {
        if sources.is_empty() || sources.len() > MAX_PACK_ENTRIES {
            return Err(StoreError::Quota);
        }
        let mut ordered = sources.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|(id, _source)| *id);
        if ordered.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(StoreError::InvalidComposition {
                reason: "packed batch contains duplicate logical IDs",
            });
        }

        let manifest_length = ordered.iter().try_fold(0_u64, |total, (id, _source)| {
            total
                .checked_add(2)
                .and_then(|value| value.checked_add(id.to_string().len() as u64))
                .and_then(|value| value.checked_add(16))
                .ok_or(StoreError::Quota)
        })?;
        let header_length = u64::try_from(PACK_MAGIC.len())
            .map_err(|_| StoreError::Quota)?
            .checked_add(32 + 4 + 4)
            .and_then(|value| value.checked_add(manifest_length))
            .and_then(|value| value.checked_add(32))
            .ok_or(StoreError::Quota)?;
        let mut offset = header_length;
        let mut entries = Vec::with_capacity(ordered.len());
        for (id, source) in &ordered {
            let length = source.logical_length();
            offset = offset.checked_add(length).ok_or(StoreError::Quota)?;
            entries.push(PackManifestEntry {
                id: *id,
                offset: offset - length,
                length,
            });
        }
        if offset > MAX_PACK_BYTES {
            return Err(StoreError::Quota);
        }

        let manifest = encode_pack_manifest(&entries)?;
        let pack = pack_id(self.configuration, &manifest);
        let (temporary, mut output) = self.create_temporary(&self.packs, "pack")?;
        let result = (|| {
            write_pack_header(&mut output, self.configuration, &entries, &manifest)?;
            for (id, source) in ordered {
                copy_source(*id, source, &mut output)?;
            }
            output
                .sync_all()
                .map_err(|source| io_error("sync packed candidate", &temporary, source))?;
            Ok(())
        })();
        if let Err(error) = result {
            remove_temporary(&temporary, true)?;
            return Err(error);
        }
        Ok(PackCandidate {
            id: pack,
            temporary,
            entries,
        })
    }

    fn publish_pack(&self, candidate: &PackCandidate) -> Result<(), StoreError> {
        let path = self.pack_path(candidate.id);
        match fs::hard_link(&candidate.temporary, &path) {
            Ok(()) => sync_directory(&self.packs),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                let manifest = self.load_pack_manifest(candidate.id)?;
                if manifest != candidate.entries
                    || !files_equal(&candidate.temporary, &path, MAX_PACK_BYTES)?
                {
                    return Err(StoreError::Incompatible);
                }
                sync_directory(&self.packs)
            }
            Err(source) => Err(io_error("publish immutable pack", &path, source)),
        }
    }

    fn load_pack_manifest(&self, pack: PackId) -> Result<Vec<PackManifestEntry>, StoreError> {
        let path = self.pack_path(pack);
        let mut file = open_regular_file(&path, "open immutable pack").map_err(|error| {
            if matches!(error, StoreError::Io { ref source, .. } if source.kind() == io::ErrorKind::NotFound)
            {
                StoreError::Incompatible
            } else {
                error
            }
        })?;
        let entries = read_pack_header(&mut file, self.configuration)?;
        let manifest = encode_pack_manifest(&entries)?;
        if pack_id(self.configuration, &manifest) != pack {
            return Err(StoreError::Incompatible);
        }
        let length = file
            .metadata()
            .map_err(|source| io_error("inspect immutable pack", &path, source))?
            .len();
        let header_end = file
            .stream_position()
            .map_err(|source| io_error("inspect immutable pack position", &path, source))?;
        let expected = entries
            .last()
            .map_or(header_end, |entry| entry.offset + entry.length);
        if length != expected || length > MAX_PACK_BYTES {
            return Err(StoreError::Incompatible);
        }
        Ok(entries)
    }

    fn open_entry(&self, id: ContentId, entry: &IndexEntry) -> Result<BlobHandle, StoreError> {
        let path = self.pack_path(entry.pack);
        let file = Arc::new(open_regular_file(&path, "open indexed pack").map_err(|error| {
            if matches!(error, StoreError::Io { ref source, .. } if source.kind() == io::ErrorKind::NotFound)
            {
                StoreError::Corrupt { id }
            } else {
                error
            }
        })?);
        let mut header = file
            .try_clone()
            .map_err(|source| io_error("clone indexed pack", &path, source))?;
        let manifest = read_pack_header(&mut header, self.configuration)?;
        let encoded = encode_pack_manifest(&manifest)?;
        if pack_id(self.configuration, &encoded) != entry.pack
            || !manifest.iter().any(|candidate| {
                candidate.id == id
                    && candidate.offset == entry.offset
                    && candidate.length == entry.length
            })
        {
            return Err(StoreError::Corrupt { id });
        }
        let file_length = file
            .metadata()
            .map_err(|source| io_error("inspect indexed pack", &path, source))?
            .len();
        let expected_length = manifest
            .last()
            .and_then(|entry| entry.offset.checked_add(entry.length))
            .ok_or(StoreError::Corrupt { id })?;
        if entry
            .offset
            .checked_add(entry.length)
            .is_none_or(|end| end > file_length)
            || file_length != expected_length
            || file_length > MAX_PACK_BYTES
        {
            return Err(StoreError::Corrupt { id });
        }
        Ok(BlobHandle::integrity_checked(
            id,
            Arc::new(PackedBlobSource {
                file,
                id,
                offset: entry.offset,
                logical_length: entry.length,
            }),
        ))
    }

    fn accounting_for(&self, index: &IndexState) -> Result<PackedStorageAccounting, StoreError> {
        let logical_objects = u64::try_from(index.entries.len()).map_err(|_| StoreError::Quota)?;
        let logical_bytes = index.entries.values().try_fold(0_u64, |total, entry| {
            total.checked_add(entry.length).ok_or(StoreError::Quota)
        })?;
        let packs = index.pack_ids();
        let physical_bytes = packs.iter().try_fold(0_u64, |total, pack| {
            let path = self.pack_path(*pack);
            let length = fs::metadata(&path)
                .map_err(|source| io_error("measure referenced pack", &path, source))?
                .len();
            total.checked_add(length).ok_or(StoreError::Quota)
        })?;
        Ok(PackedStorageAccounting {
            generation: index.generation,
            logical_objects,
            logical_bytes,
            packs: u64::try_from(packs.len()).map_err(|_| StoreError::Quota)?,
            physical_bytes,
        })
    }

    fn validate_index_packs(&self, index: &IndexState) -> Result<(), StoreError> {
        let mut manifests = BTreeMap::new();
        for pack in index.pack_ids() {
            let entries = self.load_pack_manifest(pack)?;
            manifests.insert(
                pack,
                entries
                    .into_iter()
                    .map(|entry| (entry.id, entry))
                    .collect::<BTreeMap<_, _>>(),
            );
        }
        for (id, entry) in &index.entries {
            let manifest = manifests
                .get(&entry.pack)
                .and_then(|manifest| manifest.get(id))
                .ok_or(StoreError::Incompatible)?;
            if manifest.offset != entry.offset || manifest.length != entry.length {
                return Err(StoreError::Incompatible);
            }
        }
        Ok(())
    }

    fn repack_groups(&self, index: &IndexState) -> Result<Vec<Vec<ContentId>>, StoreError> {
        let mut groups = Vec::new();
        let mut current = Vec::new();
        let mut current_bytes = pack_fixed_header_length();
        for (id, entry) in &index.entries {
            let entry_bytes = 2_u64
                .checked_add(id.to_string().len() as u64)
                .and_then(|value| value.checked_add(16))
                .and_then(|value| value.checked_add(entry.length))
                .ok_or(StoreError::Quota)?;
            let exceeds_target = !current.is_empty()
                && current_bytes
                    .checked_add(entry_bytes)
                    .is_none_or(|total| total > self.target_pack_bytes);
            if exceeds_target || current.len() == MAX_PACK_ENTRIES {
                groups.push(std::mem::take(&mut current));
                current_bytes = pack_fixed_header_length();
            }
            current.push(*id);
            current_bytes = current_bytes
                .checked_add(entry_bytes)
                .ok_or(StoreError::Quota)?;
        }
        if !current.is_empty() {
            groups.push(current);
        }
        Ok(groups)
    }

    fn remove_pack(&self, pack: PackId) -> Result<bool, StoreError> {
        let path = self.pack_path(pack);
        match fs::remove_file(&path) {
            Ok(()) => {
                sync_directory(&self.packs)?;
                Ok(true)
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(io_error("remove superseded pack", &path, source)),
        }
    }

    fn cleanup_unreferenced_packs(&self, index: &IndexState) -> Result<u64, StoreError> {
        let retained = index.pack_ids();
        let mut observed = 0_usize;
        let mut removed = 0_u64;
        for entry in fs::read_dir(&self.packs)
            .map_err(|source| io_error("list immutable packs", &self.packs, source))?
        {
            let entry = entry
                .map_err(|source| io_error("read immutable pack entry", &self.packs, source))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| StoreError::Incompatible)?;
            if name.starts_with('.') {
                continue;
            }
            observed = observed.checked_add(1).ok_or(StoreError::Quota)?;
            if observed > MAX_PACKS * 2 {
                return Err(StoreError::Quota);
            }
            let digest = name
                .strip_suffix(PACK_SUFFIX)
                .and_then(decode_hex)
                .ok_or(StoreError::Incompatible)?;
            let pack = PackId(digest);
            if !retained.contains(&pack) && self.remove_pack(pack)? {
                removed = removed.checked_add(1).ok_or(StoreError::Quota)?;
            }
        }
        Ok(removed)
    }
}

impl ImmutableBlobBackend for PackedBlobBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            durable: true,
            deferred_write: false,
            range_read: true,
            streaming_read: true,
            conditional_create: true,
            streaming_put: true,
            repair_inventory: true,
            planned_delete: true,
        }
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        let handle = match self.read(id, None) {
            Ok(handle) => handle,
            Err(StoreError::NotFound { .. }) => return Ok(false),
            Err(error) => return Err(error),
        };
        handle.copy_to(&mut io::sink())?;
        Ok(true)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        let _lifecycle = self.lock_lifecycle(FlockOperation::LockShared)?;
        let _state = self.lock_state()?;
        let index = self.load_index()?;
        let entry = index.entries.get(&id).ok_or(StoreError::NotFound { id })?;
        self.open_entry(id, entry)?.slice(range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        {
            let _lifecycle = self.lock_lifecycle(FlockOperation::LockShared)?;
            let _state = self.lock_state()?;
            let index = self.load_index()?;
            if let Some(entry) = index.entries.get(&id) {
                self.open_entry(id, entry)?.copy_to(&mut io::sink())?;
                source.verified_as(id)?;
                return Ok(packed_receipt(&self.name, id, source.logical_length()));
            }
            if index.entries.len() >= MAX_LOGICAL_OBJECTS {
                return Err(StoreError::Quota);
            }
        }

        let candidate = self.build_pack(&[(id, source.clone())])?;
        let result = (|| {
            let _lifecycle = self.lock_lifecycle(FlockOperation::LockShared)?;
            let _state = self.lock_state()?;
            let mut index = self.load_index()?;
            if let Some(existing) = index.entries.get(&id) {
                if existing.length != source.logical_length() {
                    return Err(StoreError::Incompatible);
                }
                self.open_entry(id, existing)?.copy_to(&mut io::sink())?;
                return Ok(packed_receipt(&self.name, id, source.logical_length()));
            }
            if index.entries.len() >= MAX_LOGICAL_OBJECTS || index.pack_ids().len() >= MAX_PACKS {
                return Err(StoreError::Quota);
            }
            self.publish_pack(&candidate)?;
            let entry = candidate
                .entries
                .first()
                .ok_or(StoreError::Incompatible)?
                .to_index_entry(candidate.id);
            index.entries.insert(id, entry);
            index.generation = index.generation.checked_add(1).ok_or(StoreError::Quota)?;
            index.last_repack_plan = None;
            self.publish_index_reconciled(&index)?;
            Ok(packed_receipt(&self.name, id, source.logical_length()))
        })();
        remove_temporary(&candidate.temporary, result.is_ok())?;
        result
    }
}

impl BlobStoreAdmin for PackedBlobBackend {
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        let lifecycle = self.lock_lifecycle(FlockOperation::LockExclusive)?;
        let state_lock = self.lock_state()?;
        let index = self.load_index()?;
        self.validate_index_packs(&index)?;
        self.cleanup_unreferenced_packs(&index)?;
        Ok(Box::new(PackedInventoryFence {
            backend: self,
            _lifecycle: lifecycle,
            _state_lock: state_lock,
            index,
        }))
    }
}

struct PackedInventoryFence<'a> {
    backend: &'a PackedBlobBackend,
    _lifecycle: File,
    _state_lock: File,
    index: IndexState,
}

impl BlobInventoryFence for PackedInventoryFence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        let generation = persistent_inventory_generation(
            &self.backend.name,
            self.index.instance,
            self.index.generation,
        )?;
        let mut inventory = InventoryCounter::new(generation);
        for (id, entry) in &self.index.entries {
            let record = BlobInventoryRecord::new(*id, entry.length);
            visitor(record)?;
            inventory.push(record)?;
        }
        Ok(inventory.finish(self.backend.name.clone()))
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        let Some(removed) = self.index.entries.get(&id).copied() else {
            self.backend.cleanup_unreferenced_packs(&self.index)?;
            return Ok(PlannedDeleteDisposition::AlreadyAbsent);
        };
        let mut next = self.index.clone();
        next.entries.remove(&id);
        next.generation = next.generation.checked_add(1).ok_or(StoreError::Quota)?;
        next.last_repack_plan = None;
        self.backend.publish_index_reconciled(&next)?;
        self.index = next;
        if !self
            .index
            .entries
            .values()
            .any(|entry| entry.pack == removed.pack)
        {
            self.backend.remove_pack(removed.pack)?;
        }
        Ok(PlannedDeleteDisposition::Deleted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PackId([u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IndexEntry {
    pack: PackId,
    offset: u64,
    length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PackManifestEntry {
    id: ContentId,
    offset: u64,
    length: u64,
}

impl PackManifestEntry {
    const fn to_index_entry(&self, pack: PackId) -> IndexEntry {
        IndexEntry {
            pack,
            offset: self.offset,
            length: self.length,
        }
    }
}

struct PackCandidate {
    id: PackId,
    temporary: PathBuf,
    entries: Vec<PackManifestEntry>,
}

impl PackCandidate {
    fn entries_with_pack(&self) -> impl Iterator<Item = (ContentId, IndexEntry)> + '_ {
        self.entries.iter().map(|entry| {
            (
                entry.id,
                IndexEntry {
                    pack: self.id,
                    offset: entry.offset,
                    length: entry.length,
                },
            )
        })
    }
}

impl Drop for PackCandidate {
    fn drop(&mut self) {
        let _ignored = fs::remove_file(&self.temporary);
    }
}

#[derive(Clone, PartialEq, Eq)]
struct IndexState {
    instance: [u8; 32],
    generation: u64,
    last_repack_plan: Option<PackedRepackPlanId>,
    entries: BTreeMap<ContentId, IndexEntry>,
}

impl IndexState {
    fn pack_ids(&self) -> BTreeSet<PackId> {
        self.entries.values().map(|entry| entry.pack).collect()
    }
}

struct PackedBlobSource {
    file: Arc<File>,
    id: ContentId,
    offset: u64,
    logical_length: u64,
}

impl BlobSource for PackedBlobSource {
    fn logical_length(&self) -> u64 {
        self.logical_length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(PackedAuthenticatingReader {
            file: Arc::clone(&self.file),
            id: self.id,
            offset: self.offset,
            logical_length: self.logical_length,
            position: 0,
            hasher: content_hasher(
                self.id.kind(),
                self.id.schema_version(),
                self.logical_length,
            ),
            finalized: false,
        }))
    }
}

struct PackedAuthenticatingReader {
    file: Arc<File>,
    id: ContentId,
    offset: u64,
    logical_length: u64,
    position: u64,
    hasher: blake3::Hasher,
    finalized: bool,
}

impl Read for PackedAuthenticatingReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.finalized {
            return Ok(0);
        }
        if self.position < self.logical_length {
            let remaining = self.logical_length - self.position;
            let limit = usize::try_from(remaining.min(output.len() as u64))
                .map_err(|_| invalid_pack_data())?;
            let read = read_at_retry(
                &self.file,
                &mut output[..limit],
                self.offset + self.position,
            )?;
            if read == 0 {
                return Err(invalid_pack_data());
            }
            self.hasher.update(&output[..read]);
            self.position += read as u64;
            return Ok(read);
        }
        if *self.hasher.finalize().as_bytes() != self.id.digest() {
            return Err(invalid_pack_data());
        }
        self.finalized = true;
        Ok(0)
    }
}

fn configuration_binding(name: &str, root: &Path, target_pack_bytes: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONFIGURATION_DOMAIN);
    hasher.update(&(name.len() as u64).to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update(&(root.as_os_str().as_bytes().len() as u64).to_be_bytes());
    hasher.update(root.as_os_str().as_bytes());
    hasher.update(&target_pack_bytes.to_be_bytes());
    *hasher.finalize().as_bytes()
}

fn new_instance(root: &Path) -> Result<[u8; 32], StoreError> {
    let random_path = Path::new("/dev/urandom");
    let mut random = [0_u8; 32];
    File::open(random_path)
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(|source| io_error("read packed instance randomness", random_path, source))?;
    let ordinal = INSTANCE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut hasher = blake3::Hasher::new();
    hasher.update(INSTANCE_DOMAIN);
    hasher.update(root.as_os_str().as_bytes());
    hasher.update(&std::process::id().to_be_bytes());
    hasher.update(&ordinal.to_be_bytes());
    hasher.update(&random);
    Ok(*hasher.finalize().as_bytes())
}

fn packed_receipt(name: &str, id: ContentId, logical_length: u64) -> PutReceipt {
    PutReceipt::one(
        id,
        PlacementReceipt {
            backend: name.to_owned(),
            durable: true,
            logical_length,
        },
    )
}

fn read_bounded_file(
    path: &Path,
    maximum: u64,
    operation: &'static str,
) -> Result<Vec<u8>, StoreError> {
    let file = open_regular_file(path, operation)?;
    let length = file
        .metadata()
        .map_err(|source| io_error(operation, path, source))?
        .len();
    if length > maximum {
        return Err(StoreError::Quota);
    }
    let capacity = usize::try_from(length).map_err(|_| StoreError::Quota)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| StoreError::Quota)?;
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(operation, path, source))?;
    if bytes.len() as u64 != length {
        return Err(StoreError::Incompatible);
    }
    Ok(bytes)
}

fn files_equal(left: &Path, right: &Path, maximum: u64) -> Result<bool, StoreError> {
    let mut left_file = open_regular_file(left, "open packed collision candidate")?;
    let mut right_file = open_regular_file(right, "open packed collision target")?;
    let left_length = left_file
        .metadata()
        .map_err(|source| io_error("inspect packed collision candidate", left, source))?
        .len();
    let right_length = right_file
        .metadata()
        .map_err(|source| io_error("inspect packed collision target", right, source))?
        .len();
    if left_length != right_length || left_length > maximum {
        return Ok(false);
    }
    let mut left_buffer = [0_u8; 64 * 1024];
    let mut right_buffer = [0_u8; 64 * 1024];
    loop {
        let left_read = read_retry(&mut left_file, &mut left_buffer)
            .map_err(|source| io_error("read packed collision candidate", left, source))?;
        let right_read = read_retry(&mut right_file, &mut right_buffer)
            .map_err(|source| io_error("read packed collision target", right, source))?;
        if left_read != right_read || left_buffer[..left_read] != right_buffer[..right_read] {
            return Ok(false);
        }
        if left_read == 0 {
            return Ok(true);
        }
    }
}

fn open_regular_file(path: &Path, operation: &'static str) -> Result<File, StoreError> {
    let file = File::open(path).map_err(|source| io_error(operation, path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error(operation, path, source))?;
    if !metadata.file_type().is_file() {
        return Err(StoreError::InvalidComposition {
            reason: "packed path is not a regular file",
        });
    }
    Ok(file)
}

fn remove_temporary(path: &Path, required: bool) -> Result<(), StoreError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) if !required => Ok(()),
        Err(source) => Err(io_error("remove packed staging file", path, source)),
    }
}

fn sync_directory(path: &Path) -> Result<(), StoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync packed directory", path, source))
}

fn read_at_retry(file: &File, output: &mut [u8], offset: u64) -> io::Result<usize> {
    loop {
        match file.read_at(output, offset) {
            Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn read_retry(reader: &mut dyn Read, output: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(output) {
            Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn invalid_pack_data() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "packed logical object is corrupt",
    )
}

fn encode_hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        digest[index] = (high << 4) | low;
    }
    Some(digest)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> StoreError {
    StoreError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
