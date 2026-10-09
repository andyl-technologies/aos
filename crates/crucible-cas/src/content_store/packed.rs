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
//! Placement uses only the bounded version-two tree. The retained `index-v1`
//! filename is a namespace location, not a format promise: its root magic must
//! identify version two, and older roots are refused without an importer.
//! Pack-body framing remains version one; the configuration binding and graph
//! identity explicitly select the version-two placement semantics.
//!
//! ```text
//! root/
//!   packs/<pack-id>.pack
//!   .packed-admin/index-v1
//!   .packed-admin/arena-<id>
//!   .packed-admin/lifecycle.lock
//!   .packed-admin/state.lock
//! ```

use super::{ObjectKind, graph_object_count};

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};

pub(super) mod admitted;
mod checked;
mod checked_publication;

pub(in crate::content_store) use checked_publication::Accepted;
pub use checked_publication::{PackedPublicationOutcome, PackedScopeError};
mod checked_io;
mod format;
mod index_arena;
mod index_build;
mod index_format;
mod index_io;
mod index_update;
mod inventory;
mod maintenance;
mod placement_index;
pub(crate) mod read_view;
mod repack;
use placement_index as index_snapshot;
#[cfg(test)]
mod placement_tests;

use format::{
    decode_repack_plan, encode_pack_manifest, encode_repack_plan, new_repack_plan,
    pack_fixed_header_length, pack_id, read_pack_header, write_pack_header,
};

use super::admin::{
    InventoryCounter, PhysicalRepairAuthority, persistent_inventory_generation,
    physical_storage_identity,
};
use super::directory::create_dir_all_durable;
use super::{
    BackendCapabilities, BlobHandle, BlobInventoryFence, BlobInventoryRecord, BlobInventorySummary,
    BlobSource, BlobStoreAdmin, ByteRange, CheckedInventoryFence, ContentId, ImmutableBlobBackend,
    PlacementReceipt, PlannedDeleteDisposition, PutReceipt, StoreError, content_hasher,
    copy_source,
};

const PACK_MAGIC: &[u8] = b"crucible.content-store.pack.v1\0";
const PACK_ID_DOMAIN: &[u8] = b"crucible.content-store.pack-id.v1";
const PACK_MANIFEST_DOMAIN: &[u8] = b"crucible.content-store.pack-manifest.v1";
const REPACK_PLAN_MAGIC: &[u8] = b"crucible.content-store.pack-repack-plan.v2\0";
const REPACK_PLAN_CHECKSUM_DOMAIN: &[u8] = b"crucible.content-store.pack-repack-plan.v2";
const REPACK_PLAN_ID_DOMAIN: &[u8] = b"crucible.content-store.pack-repack-plan-id.v2";
const CONFIGURATION_DOMAIN: &[u8] = b"crucible.content-store.packed-configuration.v2";
pub(in crate::content_store) const INDEX_VERSION_MARKER: &[u8] = b"packed-index-v2\0";
const INSTANCE_DOMAIN: &[u8] = b"crucible.content-store.packed-instance.v1";
const ADMIN_DIRECTORY: &str = ".packed-admin";
const PACK_DIRECTORY: &str = "packs";
const INDEX_FILE: &str = "index-v1";
const LIFECYCLE_LOCK_FILE: &str = "lifecycle.lock";
const STATE_LOCK_FILE: &str = "state.lock";
const PACK_SUFFIX: &str = ".pack";
const MAX_PACK_MANIFEST_BYTES: u64 = 4096 * 111;
const MAX_PACK_ENTRIES: usize = 4_096;
const MAX_PACK_BYTES: u64 = 128 * 1024 * 1024;
const MIN_TARGET_PACK_BYTES: u64 = 64 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static INSTANCE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "destructive-recovery-faults")]
const DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT: &str = "CRUCIBLE_DESTRUCTIVE_RECOVERY_TRIGGER";
#[cfg(feature = "destructive-recovery-faults")]
const PACK_INDEX_INTERRUPTION_TRIGGER: &str =
    "crucible.destructive-recovery.pack-index-interruption";
#[cfg(feature = "destructive-recovery-faults")]
const PACK_INDEX_INTERRUPTION_EXIT_CODE: i32 = 91;

mod planning;

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
        repack::accounting(self)
    }

    /// Plans a replacement of the exact authenticated placement generation.
    ///
    /// # Errors
    /// Refuses corrupt metadata, incomplete physical accounting or generation overflow.
    pub fn plan_repack(&self) -> Result<PackedRepackPlan, StoreError> {
        repack::plan(self)
    }

    /// Rewrites one exact generation into bounded packs without retaining its closure.
    ///
    /// Existing readers retain their pinned inodes. Replacement names are
    /// durable before the root changes; superseded names close afterward.
    ///
    /// # Errors
    /// Refuses a stale plan, corrupt logical bytes, incomplete publication or cleanup.
    pub fn apply_repack(&self, plan: &PackedRepackPlan) -> Result<PackedRepackReport, StoreError> {
        repack::apply(self, plan)
    }

    /// Removes staging packs and complete packs outside the retained generation.
    ///
    /// # Errors
    /// Refuses malformed directory entries, corrupt retained metadata or incomplete cleanup.
    pub fn cleanup_incomplete_packs(&self) -> Result<PackedIncompleteCleanupReport, StoreError> {
        let _lifecycle = self.lock_lifecycle(FlockOperation::LockExclusive)?;
        let _state = self.lock_state()?;
        let index = self.load_index()?;
        self.validate_index_packs(&index)?;
        let (removed_unreferenced_packs, removed_staging_packs) = self.cleanup_material(&index)?;
        Ok(PackedIncompleteCleanupReport {
            index_generation: index.header.generation,
            removed_unreferenced_packs,
            removed_staging_packs,
        })
    }

    /// Authenticates accounting using the caller's unchanged original resources.
    ///
    /// # Errors
    /// Refuses original supervision, exhausted metadata or descriptors, and corrupt placements.
    pub fn accounting_with_boundary(
        &self,
        original: &crate::owned_decode::DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PackedStorageAccounting, StoreError> {
        repack::accounting_under(
            self,
            &mut index_io::Operation {
                original: Some(original),
                boundary,
            },
        )
    }

    /// Plans maintenance under the same supplied original operation.
    ///
    /// # Errors
    /// Refuses original supervision, incomplete physical authentication or counter overflow.
    pub fn plan_repack_with_boundary(
        &self,
        original: &crate::owned_decode::DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PackedRepackPlan, StoreError> {
        repack::plan_under(
            self,
            &mut index_io::Operation {
                original: Some(original),
                boundary,
            },
        )
    }

    /// Applies an exact plan under the caller's original allocation and I/O authority.
    ///
    /// # Errors
    /// Refuses stale plans, original supervision, corrupt sources, insufficient current
    /// disk headroom, and native publication or cleanup errors with their actual outcome.
    pub fn apply_repack_with_boundary(
        &self,
        original: &crate::owned_decode::DecodeBudget,
        plan: &PackedRepackPlan,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PackedRepackReport, StoreError> {
        repack::apply_under(
            self,
            plan,
            &mut index_io::Operation {
                original: Some(original),
                boundary,
            },
        )
    }

    fn initialize(&self) -> Result<(), StoreError> {
        let _lifecycle = self.lock_lifecycle(FlockOperation::LockExclusive)?;
        let _state = self.lock_state()?;
        let path = self.index_path();
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                let index = self.load_index()?;
                self.validate_index_packs(&index)?;
            }
            Ok(_) => {
                return Err(StoreError::InvalidComposition {
                    reason: "packed index path is not a regular file",
                });
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                let initial = index_snapshot::EncodedIndex::empty_under(
                    self,
                    new_instance(&self.root)?,
                    &mut index_io::Operation {
                        original: None,
                        boundary: &mut || Ok(()),
                    },
                )?;
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

    fn load_index(&self) -> Result<index_snapshot::IndexSnapshot, StoreError> {
        index_snapshot::IndexSnapshot::load_under(
            self,
            &mut index_io::Operation {
                original: None,
                boundary: &mut || Ok(()),
            },
        )
    }

    fn publish_index(&self, index: &index_snapshot::EncodedIndex) -> Result<(), StoreError> {
        let (temporary, mut output) = self.create_temporary(&self.admin, "index")?;
        let result = (|| {
            output
                .write_all(index.bytes())
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

    fn publish_index_reconciled(
        &self,
        index: &index_snapshot::EncodedIndex,
    ) -> Result<(), StoreError> {
        match self.publish_index(index) {
            Ok(()) => Ok(()),
            Err(error) => match self.load_index() {
                Ok(current)
                    if current.header == index.header
                        && current.encoded_bytes() == index.bytes() =>
                {
                    Ok(())
                }
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

    fn build_single_pack(
        &self,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<PackCandidate, StoreError> {
        let header_length = id.with_encoded_text(|text| {
            pack_fixed_header_length()
                .checked_add(text.len() as u64 + 18)
                .ok_or(StoreError::Quota)
        })?;
        let entry = PackManifestEntry {
            id,
            offset: header_length,
            length: source.logical_length(),
        };
        if header_length
            .checked_add(entry.length)
            .is_none_or(|length| length > MAX_PACK_BYTES)
        {
            return Err(StoreError::Quota);
        }
        let entries = [entry];
        let manifest = encode_pack_manifest(&entries)?;
        let pack = pack_id(self.configuration, &manifest);
        let (temporary, mut output) = self.create_temporary(&self.packs, "pack")?;
        let result = (|| {
            write_pack_header(&mut output, self.configuration, &entries, &manifest)?;
            copy_source(id, source, &mut output)?;
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
                if manifest.as_slice() != candidate.entries
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
            PackedBlobSource {
                file,
                id,
                offset: entry.offset,
                logical_length: entry.length,
            },
        ))
    }

    fn validate_index_packs(
        &self,
        index: &index_snapshot::IndexSnapshot,
    ) -> Result<(), StoreError> {
        maintenance::validate(
            self,
            index,
            &mut index_io::Operation {
                original: None,
                boundary: &mut || Ok(()),
            },
        )
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

    fn cleanup_material(
        &self,
        index: &index_snapshot::IndexSnapshot,
    ) -> Result<(u64, u64), StoreError> {
        maintenance::cleanup(
            self,
            index,
            &mut index_io::Operation {
                original: None,
                boundary: &mut || Ok(()),
            },
        )
    }
}

#[cfg(feature = "destructive-recovery-faults")]
fn inject_pack_index_interruption() {
    let requested = std::env::var_os(DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT);
    if requested.as_deref() == Some(std::ffi::OsStr::new(PACK_INDEX_INTERRUPTION_TRIGGER)) {
        std::process::exit(PACK_INDEX_INTERRUPTION_EXIT_CODE);
    }
}

impl ImmutableBlobBackend for PackedBlobBackend {
    fn read_bounded_with_boundary(
        &self,
        request: &mut crate::ram::BoundedReadRequest<'_, '_>,
    ) -> Result<(), StoreError> {
        request.execute_packed(self)
    }

    fn checked_publication_metadata(
        &self,
        _kind: ObjectKind,
    ) -> Result<super::CheckedPublicationMetadata, StoreError> {
        Ok(super::CheckedPublicationMetadata {
            maximum_placements: 1,
            maximum_backend_name_bytes: self.name.len(),
        })
    }

    fn put_many_if_absent_with_boundary(
        &self,
        original: &crate::owned_decode::DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<super::PutBatchReceipt, StoreError> {
        checked_publication::publish(self, original, objects, boundary)
    }

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

    fn admit_object_graph(&self, objects: &[(ObjectKind, u64)]) -> Result<(), StoreError> {
        let additional = graph_object_count(objects)?;
        let _state = self.lock_state()?;
        let index = self.load_index()?;
        index
            .header
            .count
            .checked_add(additional)
            .ok_or(StoreError::Quota)?;
        index
            .header
            .packs
            .checked_add(additional)
            .ok_or(StoreError::Quota)?;
        index
            .header
            .records
            .checked_add(additional.checked_mul(2).ok_or(StoreError::Quota)?)
            .ok_or(StoreError::Quota)?;
        Ok(())
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
        let mut operation = index_io::Operation {
            original: None,
            boundary: &mut || Ok(()),
        };
        let entry = index
            .reader(self, &mut operation)?
            .find(index_format::Key::object(id), &mut operation)?
            .map(index_format::Value::entry)
            .transpose()?
            .ok_or(StoreError::NotFound { id })?;
        self.open_entry(id, &entry)?.slice(range)
    }

    fn read_with_boundary(
        &self,
        original: &crate::owned_decode::DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        checked::lookup(self, original, id, range, boundary)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let _lifecycle = self.lock_lifecycle(FlockOperation::LockShared)?;
        let _state = self.lock_state()?;
        let index = self.load_index()?;
        let mut operation = index_io::Operation {
            original: None,
            boundary: &mut || Ok(()),
        };
        if let Some(existing) = index
            .reader(self, &mut operation)?
            .find(index_format::Key::object(id), &mut operation)?
        {
            self.open_entry(id, &existing.entry()?)?
                .copy_to(&mut io::sink())?;
            source.verified_as(id)?;
            sync_directory(&self.admin)?;
            return Ok(packed_receipt(&self.name, id, source.logical_length()));
        }
        let pack_bytes = id.with_encoded_text(|text| {
            pack_fixed_header_length()
                .checked_add(text.len() as u64 + 18)
                .and_then(|bytes| bytes.checked_add(source.logical_length()))
                .ok_or(StoreError::Quota)
        })?;
        maintenance::publication_headroom(self, &index, 1, pack_bytes, &mut operation)?;
        let candidate = self.build_single_pack(id, source)?;
        let mut progress = checked_publication::Progress::default();
        let result = (|| {
            let entry = candidate
                .entries
                .first()
                .ok_or(StoreError::Incompatible)?
                .to_index_entry(candidate.id);
            let physical_bytes = entry
                .offset
                .checked_add(entry.length)
                .ok_or(StoreError::Quota)?;
            let replacement = maintenance::replacement(
                self,
                &index,
                &[(id, entry)],
                physical_bytes,
                &mut operation,
                &mut progress,
            )?;
            self.publish_pack(&candidate)?;
            self.publish_index_reconciled(&replacement)?;
            Ok(packed_receipt(&self.name, id, source.logical_length()))
        })();
        let cleanup = remove_temporary(&candidate.temporary, result.is_ok());
        let result = match result {
            Ok(value) => {
                checked_publication::record_cleanup(Ok(()), cleanup, &mut progress).map(|()| value)
            }
            Err(error) => checked_publication::record_cleanup(Err(error), cleanup, &mut progress)
                .and(Err(StoreError::Unavailable)),
        };
        maintenance::ordinary_completion(self, result, &mut progress)
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
    entries: [PackManifestEntry; 1],
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

fn is_pack_temporary_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(".pack.tmp-") else {
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
