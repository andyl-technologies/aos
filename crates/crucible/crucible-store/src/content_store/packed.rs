//! Crash-safe immutable physical packs with a generation-bound logical index.
//!
//! A packed leaf stores canonical logical bytes in immutable pack files and
//! maps each [`ContentId`] to a pinned byte range through an on-disk index.
//! Logical identity never includes pack geometry. Ordinary puts publish a
//! valid one-object pack and then commit one journal record.
//! [`PackedBlobBackend::plan_repack`] captures one exact index root, and
//! [`PackedBlobBackend::apply_repack`] rewrites that logical set into
//! deterministic bounded multi-object packs, switches the index root, and only
//! then removes superseded pack names. Readers that opened the old generation
//! retain their file inode until EOF.
//!
//! The index is a sorted immutable base, an append-only hash-chained journal,
//! and a sorted pack table, all committed by one small atomically replaced
//! root (see the `index` module). Every operation rereads only the root;
//! lookups binary-search the base with positioned reads, so per-operation cost
//! is logarithmic in the number of objects and resident memory is bounded by
//! the journal compaction threshold. No store-wide object or pack ceiling
//! remains; a logical quota wrapper and deployment storage bound growth.
//!
//! ```text
//! root/
//!   packs/<pack-id>.pack
//!   .packed-admin/index-v2
//!   .packed-admin/index-base-<digest>
//!   .packed-admin/pack-table-<digest>
//!   .packed-admin/index-journal-<base-digest>
//!   .packed-admin/lifecycle.lock
//!   .packed-admin/state.lock
//! ```
//!
//! Locking: every operation takes `lifecycle.lock` (shared for reads and
//! puts, exclusive for repack, cleanup, maintenance fences, and
//! initialization) and then `state.lock` exclusively. The in-process index
//! cache is only touched while `state.lock` is held.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};

mod external_sort;
mod format;
mod index;
mod index_records;
mod journal;
mod migration;
mod planning;
mod sorted_file;
#[cfg(test)]
mod tests;

use format::{
    decode_repack_plan, encode_pack_manifest, encode_repack_plan, new_repack_plan,
    pack_fixed_header_length, pack_id, read_pack_header, write_pack_header,
};
use index::{CompactionPolicy, IndexDirectory, PackIndex, PackOrder};
use index_records::{IndexTotals, PackState};
use journal::{JournalOperation, JournalRecord};
use migration::{legacy_index_path, remove_legacy_index};

use super::admin::{
    InventoryCounter, PhysicalRepairAuthority, persistent_inventory_generation,
    physical_storage_identity,
};
use super::directory::create_dir_all_durable;
use super::{
    BackendCapabilities, BlobHandle, BlobInventoryFence, BlobInventoryRecord, BlobInventorySummary,
    BlobSource, BlobStoreAdmin, ByteRange, ContentId, ImmutableBlobBackend, ObjectKind,
    PlacementReceipt, PlannedDeleteDisposition, PutReceipt, StoreError, content_hasher,
    copy_source,
};

const PACK_MAGIC: &[u8] = b"crucible.content-store.pack.v1\0";
const PACK_ID_DOMAIN: &[u8] = b"crucible.content-store.pack-id.v1";
const PACK_MANIFEST_DOMAIN: &[u8] = b"crucible.content-store.pack-manifest.v1";
const REPACK_PLAN_MAGIC: &[u8] = b"crucible.content-store.pack-repack-plan.v2\0";
const REPACK_PLAN_CHECKSUM_DOMAIN: &[u8] = b"crucible.content-store.pack-repack-plan.v2";
const REPACK_PLAN_ID_DOMAIN: &[u8] = b"crucible.content-store.pack-repack-plan-id.v2";
const CONFIGURATION_DOMAIN: &[u8] = b"crucible.content-store.packed-configuration.v1";
const INSTANCE_DOMAIN: &[u8] = b"crucible.content-store.packed-instance.v1";
const ADMIN_DIRECTORY: &str = ".packed-admin";
const PACK_DIRECTORY: &str = "packs";
const LIFECYCLE_LOCK_FILE: &str = "lifecycle.lock";
const STATE_LOCK_FILE: &str = "state.lock";
const PACK_SUFFIX: &str = ".pack";
const PACK_TEMPORARY_LABEL: &str = "pack";
const MAX_PACK_ENTRIES: usize = 4_096;
const MAX_PACK_BYTES: u64 = 128 * 1024 * 1024;
const MIN_TARGET_PACK_BYTES: u64 = 64 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static INSTANCE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "destructive-recovery-faults")]
const DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT: &str = "CRUCIBLE_DESTRUCTIVE_RECOVERY_TRIGGER";
/// Repack: replacement packs and index files are durable, root not switched.
#[cfg(feature = "destructive-recovery-faults")]
const PACK_INDEX_INTERRUPTION_TRIGGER: &str =
    "crucible.destructive-recovery.pack-index-interruption";
/// Mutation: journal record is durable, root not published.
#[cfg(feature = "destructive-recovery-faults")]
const JOURNAL_TAIL_INTERRUPTION_TRIGGER: &str =
    "crucible.destructive-recovery.pack-index-journal-tail";
/// Compaction: new base and pack table are durable, root not switched.
#[cfg(feature = "destructive-recovery-faults")]
const COMPACTION_INTERRUPTION_TRIGGER: &str = "crucible.destructive-recovery.pack-index-compaction";
/// Migration: v2 files are verified and durable, root not published.
#[cfg(feature = "destructive-recovery-faults")]
const MIGRATION_INTERRUPTION_TRIGGER: &str = "crucible.destructive-recovery.pack-index-migration";
#[cfg(feature = "destructive-recovery-faults")]
const PACK_INDEX_INTERRUPTION_EXIT_CODE: i32 = 91;

pub use planning::{
    PackedRepackPlan, PackedRepackPlanId, PackedRepackReport, PackedStorageAccounting,
};

/// Terminal report from reclaiming material outside an authenticated pack index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedIncompleteCleanupReport {
    index_generation: u64,
    removed_unreferenced_packs: u64,
    removed_staging_packs: u64,
}

impl PackedIncompleteCleanupReport {
    /// Returns the authenticated index generation that authorized cleanup.
    #[must_use]
    pub const fn index_generation(self) -> u64 {
        self.index_generation
    }

    /// Returns the number of complete pack files absent from that index.
    #[must_use]
    pub const fn removed_unreferenced_packs(self) -> u64 {
        self.removed_unreferenced_packs
    }

    /// Returns the number of abandoned staging pack files removed.
    #[must_use]
    pub const fn removed_staging_packs(self) -> u64 {
        self.removed_staging_packs
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
    compaction: CompactionPolicy,
    /// View of the last observed root; reused while the root is unchanged.
    index: Mutex<Option<PackIndex>>,
}

/// Proof that the caller holds the exclusive state lock.
struct StateLock {
    _file: File,
}

impl PackedBlobBackend {
    /// Opens or initializes one packed backend at `root`.
    ///
    /// `target_pack_bytes` controls deterministic repack grouping and must be
    /// between 64 KiB and 128 MiB inclusive. Existing roots are bound to the
    /// exact backend name, path bytes, and target size. A root written with
    /// the retired whole-file index is migrated in place.
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
        Self::open_with_compaction(name, root, target_pack_bytes, CompactionPolicy::DEFAULT)
    }

    /// Opens a backend whose journal compacts after exactly `records` records.
    #[cfg(test)]
    pub(in crate::content_store) fn open_with_journal_threshold(
        name: impl Into<String>,
        root: impl Into<PathBuf>,
        target_pack_bytes: u64,
        records: u64,
    ) -> Result<Self, StoreError> {
        Self::open_with_compaction(
            name,
            root,
            target_pack_bytes,
            CompactionPolicy::new(records, records),
        )
    }

    fn open_with_compaction(
        name: impl Into<String>,
        root: impl Into<PathBuf>,
        target_pack_bytes: u64,
        compaction: CompactionPolicy,
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
            compaction,
            index: Mutex::new(None),
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
        let state = self.lock_state()?;
        self.with_index(&state, |index| {
            self.validate_index_packs(index)?;
            Ok(accounting_for(index))
        })
    }

    /// Plans a deterministic replacement of the exact current index root.
    ///
    /// Planning is read-only. Any intervening put, delete, compaction, or
    /// successful repack makes the returned plan stale and causes
    /// [`Self::apply_repack`] to fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error when the current index or one of its packs cannot be
    /// authenticated and measured completely.
    pub fn plan_repack(&self) -> Result<PackedRepackPlan, StoreError> {
        let _lifecycle = self.lock_lifecycle(FlockOperation::LockShared)?;
        let state = self.lock_state()?;
        self.with_index(&state, |index| {
            self.validate_index_packs(index)?;
            let root = index.root();
            Ok(new_repack_plan(
                self.configuration,
                root.instance,
                root.generation,
                index.digest(),
                accounting_for(index),
            ))
        })
    }

    /// Applies one exact-generation replacement-pack plan.
    ///
    /// Existing readers keep pinned old pack inodes. New readers observe the
    /// replacement generation only after every replacement pack and index
    /// file is durable. Superseded pack names are removed only after the root
    /// switch. Retrying the same plan after an indeterminate root publication
    /// or cleanup error is idempotent while no later logical mutation has
    /// committed.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan names another backend incarnation or a
    /// stale index root, or for corrupt logical bytes, pack or index
    /// publication failure, generation overflow, or a resource bound.
    pub fn apply_repack(&self, plan: &PackedRepackPlan) -> Result<PackedRepackReport, StoreError> {
        let _lifecycle = self.lock_lifecycle(FlockOperation::LockExclusive)?;
        let state = self.lock_state()?;
        self.with_index(&state, |index| self.apply_repack_locked(index, plan))
    }

    /// Reclaims complete and staging packs absent from the authenticated index.
    ///
    /// The current index and every retained pack authenticate before deletion.
    /// An exclusive lifecycle lock excludes puts, deletes, and repacks for the
    /// whole operation. Each removed path is outside the retained generation,
    /// so interruption is idempotently recoverable by repeating this method.
    /// Index files that the current root no longer names are reclaimed too.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained index or one of its packs fails
    /// authentication, an unexpected pack-directory entry is present, or a
    /// removal cannot be made durable.
    pub fn cleanup_incomplete_packs(&self) -> Result<PackedIncompleteCleanupReport, StoreError> {
        let _lifecycle = self.lock_lifecycle(FlockOperation::LockExclusive)?;
        let state = self.lock_state()?;
        self.with_index(&state, |index| {
            self.validate_index_packs(index)?;

            let removed_unreferenced_packs = self.cleanup_unreferenced_packs(index)?;
            let removed_staging_packs = self.cleanup_staging_packs()?;
            self.index_directory().sweep_orphans(index)?;
            Ok(PackedIncompleteCleanupReport {
                index_generation: index.root().generation,
                removed_unreferenced_packs,
                removed_staging_packs,
            })
        })
    }

    fn initialize(&self) -> Result<(), StoreError> {
        let _lifecycle = self.lock_lifecycle(FlockOperation::LockExclusive)?;
        let _state = self.lock_state()?;
        let directory = self.index_directory();
        let root_path = directory.root_path();
        let index = match fs::symlink_metadata(&root_path) {
            Ok(metadata) if metadata.file_type().is_file() => directory.load(None)?,
            Ok(_) => {
                return Err(StoreError::InvalidComposition {
                    reason: "packed index path is not a regular file",
                });
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                let legacy = legacy_index_path(&self.admin);
                match fs::symlink_metadata(&legacy) {
                    Ok(_) => self.migrate_legacy_index()?,
                    Err(source) if source.kind() == io::ErrorKind::NotFound => {
                        self.create_empty_index()?
                    }
                    Err(source) => {
                        return Err(io_error("inspect legacy packed index", &legacy, source));
                    }
                }
            }
            Err(source) => return Err(io_error("inspect packed index", &root_path, source)),
        };

        // A mutation interrupted after its journal append but before its root
        // publication leaves bytes past the committed length.
        index.truncate_uncommitted_journal()?;
        self.validate_index_packs(&index)?;
        remove_legacy_index(&self.admin)?;
        directory.sweep_orphans(&index)?;
        *self.index.lock().unwrap_or_else(PoisonError::into_inner) = Some(index);
        Ok(())
    }

    fn create_empty_index(&self) -> Result<PackIndex, StoreError> {
        let directory = self.index_directory();
        let instance = new_instance(&self.root)?;
        let staged = directory.build(instance, 0, PackOrder::Sorted)?.finish()?;
        let index = directory.open_view(staged.root(0, None))?;
        directory.publish(&index)?;
        Ok(index)
    }

    fn index_directory(&self) -> IndexDirectory<'_> {
        IndexDirectory {
            admin: self.admin.as_path(),
            configuration: self.configuration,
            policy: self.compaction,
        }
    }

    /// Runs `operation` against the current committed index.
    ///
    /// The state lock is the only synchronization for the on-disk index; the
    /// mutex merely guards the cached view. The cache stays valid after an
    /// operation error because commits update it only after publication.
    fn with_index<T>(
        &self,
        _state: &StateLock,
        operation: impl FnOnce(&mut PackIndex) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut slot = self.index.lock().unwrap_or_else(PoisonError::into_inner);
        let mut index = self.index_directory().load(slot.take())?;
        let result = operation(&mut index);
        *slot = Some(index);
        result
    }

    fn lock_lifecycle(&self, operation: FlockOperation) -> Result<File, StoreError> {
        self.lock_file(LIFECYCLE_LOCK_FILE, operation)
    }

    fn lock_state(&self) -> Result<StateLock, StoreError> {
        Ok(StateLock {
            _file: self.lock_file(STATE_LOCK_FILE, FlockOperation::LockExclusive)?,
        })
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
        let (temporary, mut output) = create_temporary(&self.packs, PACK_TEMPORARY_LABEL)?;
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
            physical_bytes: offset,
        })
    }

    fn publish_pack(&self, candidate: &PackCandidate) -> Result<(), StoreError> {
        let path = self.pack_path(candidate.id);
        match fs::hard_link(&candidate.temporary, &path) {
            Ok(()) => sync_directory(&self.packs),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                let (manifest, _length) = self.load_pack_manifest(candidate.id)?;
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

    /// Authenticates one pack's manifest and returns it with the exact file length.
    fn load_pack_manifest(
        &self,
        pack: PackId,
    ) -> Result<(Vec<PackManifestEntry>, u64), StoreError> {
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
        Ok((entries, length))
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

    /// Authenticates every referenced pack against the complete index.
    ///
    /// For each referenced pack the manifest must exist, have the recorded
    /// exact length, and contain exactly the recorded number of entries that
    /// the index maps to the same range in that pack. Because the recorded
    /// live counts must also sum to the number of indexed objects, every index
    /// entry is matched against its pack without materializing either side.
    /// Both full iterations also authenticate the base and pack-table digests.
    fn validate_index_packs(&self, index: &PackIndex) -> Result<(), StoreError> {
        let mut observed = IndexTotals::default();
        let mut live_entries = 0_u64;
        for record in index.packs() {
            let record = record?;
            let (manifest, length) = self.load_pack_manifest(record.pack)?;
            if length != record.state.physical_bytes {
                return Err(StoreError::Incompatible);
            }
            let mut matched = 0_u64;
            for entry in &manifest {
                if index.get(entry.id)? == Some(entry.to_index_entry(record.pack)) {
                    matched += 1;
                }
            }
            if matched != record.state.live_entries {
                return Err(StoreError::Incompatible);
            }
            live_entries = checked_sum(live_entries, matched)?;
            observed.packs = checked_sum(observed.packs, 1)?;
            observed.physical_bytes = checked_sum(observed.physical_bytes, length)?;
        }
        for record in index.entries() {
            let record = record?;
            observed.logical_objects = checked_sum(observed.logical_objects, 1)?;
            observed.logical_bytes = checked_sum(observed.logical_bytes, record.entry.length)?;
        }
        if observed != index.root().totals || live_entries != observed.logical_objects {
            return Err(StoreError::Incompatible);
        }
        Ok(())
    }

    fn apply_repack_locked(
        &self,
        index: &mut PackIndex,
        plan: &PackedRepackPlan,
    ) -> Result<PackedRepackReport, StoreError> {
        self.validate_index_packs(index)?;
        let root = index.root().clone();
        if plan.configuration != self.configuration || plan.instance != root.instance {
            return Err(StoreError::Incompatible);
        }
        let directory = self.index_directory();
        if root.last_repack_plan == Some(plan.id) {
            let expected_generation = plan
                .generation
                .checked_add(1)
                .ok_or(StoreError::Incompatible)?;
            if root.generation != expected_generation {
                return Err(StoreError::Incompatible);
            }
            self.cleanup_staging_packs()?;
            let removed_before = self.cleanup_unreferenced_packs(index)?;
            directory.sweep_orphans(index)?;
            return Ok(PackedRepackReport {
                plan: plan.id,
                before: plan.before,
                after: accounting_for(index),
                removed_packs: removed_before,
                replayed: true,
            });
        }

        let before = accounting_for(index);
        if root.generation != plan.generation
            || before != plan.before
            || index.digest() != plan.root_digest
        {
            return Err(StoreError::Incompatible);
        }
        self.cleanup_staging_packs()?;
        let removed_before = self.cleanup_unreferenced_packs(index)?;
        directory.sweep_orphans(index)?;

        let generation = root.generation.checked_add(1).ok_or(StoreError::Quota)?;
        let staged = self.write_replacement_packs(index, generation)?;
        let next = directory.open_view(staged.root(generation, Some(plan.id)))?;
        if next.root().totals.logical_objects != before.logical_objects
            || next.root().totals.logical_bytes != before.logical_bytes
        {
            return Err(StoreError::Incompatible);
        }

        #[cfg(feature = "destructive-recovery-faults")]
        inject_fault(PACK_INDEX_INTERRUPTION_TRIGGER);

        directory.publish(&next)?;

        let mut removed_packs = removed_before;
        for record in index.packs() {
            let pack = record?.pack;
            if next.pack(pack)?.is_none() && self.remove_pack(pack)? {
                removed_packs = removed_packs.checked_add(1).ok_or(StoreError::Quota)?;
            }
        }
        directory.remove_superseded(&root, next.root())?;
        let after = accounting_for(&next);
        *index = next;
        Ok(PackedRepackReport {
            plan: plan.id,
            before,
            after,
            removed_packs,
            replayed: false,
        })
    }

    /// Streams the current entries into deterministic replacement packs.
    ///
    /// Groups are consecutive runs in content-ID order, so the new base is
    /// written in order while pack records are externally sorted. Each pack
    /// is durable and linked before its entries enter the staged base; packs
    /// remain unreferenced until the caller publishes the returned root.
    fn write_replacement_packs(
        &self,
        index: &PackIndex,
        generation: u64,
    ) -> Result<index::StagedIndex, StoreError> {
        let mut build =
            self.index_directory()
                .build(index.root().instance, generation, PackOrder::Unsorted)?;
        let mut group = Vec::new();
        let mut group_bytes = pack_fixed_header_length();
        for record in index.entries() {
            let record = record?;
            let entry_bytes = 2_u64
                .checked_add(record.id.to_string().len() as u64)
                .and_then(|value| value.checked_add(16))
                .and_then(|value| value.checked_add(record.entry.length))
                .ok_or(StoreError::Quota)?;
            let exceeds_target = !group.is_empty()
                && group_bytes
                    .checked_add(entry_bytes)
                    .is_none_or(|total| total > self.target_pack_bytes);
            if exceeds_target || group.len() == MAX_PACK_ENTRIES {
                self.publish_replacement_pack(&group, &mut build)?;
                group.clear();
                group_bytes = pack_fixed_header_length();
            }
            group.push((record.id, record.entry));
            group_bytes = group_bytes
                .checked_add(entry_bytes)
                .ok_or(StoreError::Quota)?;
        }
        if !group.is_empty() {
            self.publish_replacement_pack(&group, &mut build)?;
        }
        build.finish()
    }

    fn publish_replacement_pack(
        &self,
        group: &[(ContentId, IndexEntry)],
        build: &mut index::IndexBuild,
    ) -> Result<(), StoreError> {
        let mut sources = Vec::with_capacity(group.len());
        for (id, entry) in group {
            sources.push((*id, self.open_entry(*id, entry)?));
        }
        let candidate = self.build_pack(&sources)?;
        self.publish_pack(&candidate)?;
        for (id, entry) in candidate.entries_with_pack() {
            build.push_entry(id, entry)?;
        }
        build.push_pack(
            candidate.id,
            PackState {
                live_entries: candidate.entries.len() as u64,
                physical_bytes: candidate.physical_bytes,
            },
        )?;
        remove_temporary(&candidate.temporary, true)
    }

    /// Commits one put of `id` from an already staged one-object `candidate`.
    fn commit_put(
        &self,
        index: &mut PackIndex,
        id: ContentId,
        source: &BlobHandle,
        candidate: &PackCandidate,
    ) -> Result<PutReceipt, StoreError> {
        if let Some(existing) = index.get(id)? {
            if existing.length != source.logical_length() {
                return Err(StoreError::Incompatible);
            }
            self.open_entry(id, &existing)?.copy_to(&mut io::sink())?;
            return Ok(packed_receipt(&self.name, id, source.logical_length()));
        }

        // The pack must be durable before any journal record can name it.
        self.publish_pack(candidate)?;
        let entry = candidate
            .entries
            .first()
            .ok_or(StoreError::Incompatible)?
            .to_index_entry(candidate.id);
        let record = JournalRecord {
            operation: JournalOperation::Put,
            id,
            entry,
            pack_physical_bytes: candidate.physical_bytes,
        };
        self.index_directory().commit(index, record)?;
        Ok(packed_receipt(&self.name, id, source.logical_length()))
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

    fn cleanup_unreferenced_packs(&self, index: &PackIndex) -> Result<u64, StoreError> {
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
            let digest = name
                .strip_suffix(PACK_SUFFIX)
                .and_then(decode_hex)
                .ok_or(StoreError::Incompatible)?;
            let pack = PackId(digest);
            if index.pack(pack)?.is_none() && self.remove_pack(pack)? {
                removed = removed.checked_add(1).ok_or(StoreError::Quota)?;
            }
        }
        Ok(removed)
    }

    // The caller holds lifecycle exclusively after authenticating the retained generation.
    fn cleanup_staging_packs(&self) -> Result<u64, StoreError> {
        let mut removed = 0_u64;
        for entry in fs::read_dir(&self.packs)
            .map_err(|source| io_error("list packed staging files", &self.packs, source))?
        {
            let entry = entry
                .map_err(|source| io_error("read packed staging entry", &self.packs, source))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| StoreError::Incompatible)?;
            if !is_temporary_name(&name, PACK_TEMPORARY_LABEL) {
                continue;
            }
            let file_type = entry.file_type().map_err(|source| {
                io_error("inspect packed staging entry", &entry.path(), source)
            })?;
            if !file_type.is_file() {
                return Err(StoreError::InvalidComposition {
                    reason: "packed staging path is not a regular file",
                });
            }
            fs::remove_file(entry.path()).map_err(|source| {
                io_error(
                    "remove abandoned packed staging file",
                    &entry.path(),
                    source,
                )
            })?;
            removed = removed.checked_add(1).ok_or(StoreError::Quota)?;
        }
        if removed != 0 {
            sync_directory(&self.packs)?;
        }
        Ok(removed)
    }
}

#[cfg(feature = "destructive-recovery-faults")]
fn inject_fault(trigger: &str) {
    let requested = std::env::var_os(DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT);
    if requested.as_deref() == Some(std::ffi::OsStr::new(trigger)) {
        std::process::exit(PACK_INDEX_INTERRUPTION_EXIT_CODE);
    }
}

const fn accounting_for(index: &PackIndex) -> PackedStorageAccounting {
    let root = index.root();
    PackedStorageAccounting {
        generation: root.generation,
        logical_objects: root.totals.logical_objects,
        logical_bytes: root.totals.logical_bytes,
        packs: root.totals.packs,
        physical_bytes: root.totals.physical_bytes,
    }
}

fn checked_sum(total: u64, value: u64) -> Result<u64, StoreError> {
    total.checked_add(value).ok_or(StoreError::Quota)
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
        let state = self.lock_state()?;
        self.with_index(&state, |index| {
            let entry = index.get(id)?.ok_or(StoreError::NotFound { id })?;
            self.open_entry(id, &entry)?.slice(range)
        })
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        // Keep staging protected so exclusive cleanup cannot unlink an in-flight put.
        let _lifecycle = self.lock_lifecycle(FlockOperation::LockShared)?;
        {
            let state = self.lock_state()?;
            if let Some(entry) = self.with_index(&state, |index| index.get(id))? {
                self.open_entry(id, &entry)?.copy_to(&mut io::sink())?;
                source.verified_as(id)?;
                return Ok(packed_receipt(&self.name, id, source.logical_length()));
            }
        }

        let candidate = self.build_pack(&[(id, source.clone())])?;
        let result = self.lock_state().and_then(|state| {
            self.with_index(&state, |index| {
                self.commit_put(index, id, source, &candidate)
            })
        });
        remove_temporary(&candidate.temporary, result.is_ok())?;
        result
    }
}

impl BlobStoreAdmin for PackedBlobBackend {
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        let lifecycle = self.lock_lifecycle(FlockOperation::LockExclusive)?;
        let state = self.lock_state()?;
        self.with_index(&state, |index| {
            self.validate_index_packs(index)?;
            self.cleanup_unreferenced_packs(index)?;
            Ok(())
        })?;
        Ok(Box::new(PackedInventoryFence {
            backend: self,
            _lifecycle: lifecycle,
            state,
        }))
    }
}

struct PackedInventoryFence<'a> {
    backend: &'a PackedBlobBackend,
    _lifecycle: File,
    state: StateLock,
}

impl BlobInventoryFence for PackedInventoryFence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        let backend = self.backend;
        backend.with_index(&self.state, |index| {
            let root = index.root();
            let generation =
                persistent_inventory_generation(&backend.name, root.instance, root.generation)?;
            let mut inventory =
                InventoryCounter::new(physical_storage_identity(root.instance), generation);
            for record in index.entries() {
                let record = record?;
                let inventory_record = BlobInventoryRecord::new(record.id, record.entry.length);
                visitor(inventory_record)?;
                inventory.push(inventory_record)?;
            }
            Ok(inventory.finish(backend.name.clone()))
        })
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        let backend = self.backend;
        backend.with_index(&self.state, |index| {
            let Some(removed) = index.get(id)? else {
                backend.cleanup_unreferenced_packs(index)?;
                return Ok(PlannedDeleteDisposition::AlreadyAbsent);
            };
            let pack = index.pack(removed.pack)?.ok_or(StoreError::Incompatible)?;
            let record = JournalRecord {
                operation: JournalOperation::Delete,
                id,
                entry: removed,
                pack_physical_bytes: pack.physical_bytes,
            };
            backend.index_directory().commit(index, record)?;

            // Physical bytes are reclaimed only with the final live entry.
            if index.pack(removed.pack)?.is_none() {
                backend.remove_pack(removed.pack)?;
            }
            Ok(PlannedDeleteDisposition::Deleted)
        })
    }

    fn repair_put_if_absent(
        &mut self,
        _authority: &PhysicalRepairAuthority,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        let backend = self.backend;
        if let Some(existing) = backend.with_index(&self.state, |index| index.get(id))? {
            backend
                .open_entry(id, &existing)?
                .copy_to(&mut io::sink())?;
            source.verified_as(id)?;
            return Ok(packed_receipt(&backend.name, id, source.logical_length()));
        }

        let candidate = backend.build_pack(&[(id, source.clone())])?;
        let result = backend.with_index(&self.state, |index| {
            backend.commit_put(index, id, source, &candidate)
        });
        remove_temporary(&candidate.temporary, result.is_ok())?;
        result
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
    /// Exact length of the complete pack file.
    physical_bytes: u64,
}

impl PackCandidate {
    fn entries_with_pack(&self) -> impl Iterator<Item = (ContentId, IndexEntry)> + '_ {
        self.entries
            .iter()
            .map(|entry| (entry.id, entry.to_index_entry(self.id)))
    }
}

impl Drop for PackCandidate {
    fn drop(&mut self) {
        let _ignored = fs::remove_file(&self.temporary);
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

/// Creates a uniquely named staging file `.<label>.tmp-<pid>-<sequence>`.
fn create_temporary(directory: &Path, label: &str) -> Result<(PathBuf, File), StoreError> {
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
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| io_error(operation, path, source.into()))?;
    let file = File::from(descriptor);
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

/// Returns whether `name` is a staging name created by [`create_temporary`].
fn is_temporary_name(name: &str, label: &str) -> bool {
    let Some(suffix) = name
        .strip_prefix('.')
        .and_then(|name| name.strip_prefix(label))
        .and_then(|name| name.strip_prefix(".tmp-"))
    else {
        return false;
    };
    let Some((process, sequence)) = suffix.split_once('-') else {
        return false;
    };

    is_canonical_decimal(process)
        && process.parse::<u32>().is_ok()
        && is_canonical_decimal(sequence)
        && sequence.parse::<u64>().is_ok()
}

fn is_canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && (value.len() == 1 || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
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
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
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
