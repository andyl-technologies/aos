//! One-way in-place migration from the retired whole-file `PackIndexV1`.
//!
//! Earlier packed leaves kept every index entry in one checksummed file that
//! each operation reread and each mutation rewrote. Initialization converts
//! such a leaf under the exclusive lifecycle lock: it decodes the legacy
//! index, writes an equivalent base, pack table, and empty journal, verifies
//! that view against every referenced pack, publishes the v2 root, and only
//! then removes the legacy file. Instance, generation, and the last applied
//! repack plan carry over unchanged, so the logical inventory identity does
//! not change.
//!
//! An interruption before the root publication leaves the legacy index
//! authoritative and unreferenced staged files that the next sweep removes.
//! An interruption after it leaves a stale legacy file beside a valid root;
//! initialization removes that file once the root authenticates.
//!
//! ```text
//! PackIndexV1 =
//!   "crucible.content-store.pack-index.v1\0"
//!   configuration[32]
//!   backend_instance[32]
//!   generation_u64
//!   last_repack_tag_u8          # 0 None, 1 Some
//!   [last_repack_plan_id[32]]
//!   entry_count_u32
//!   repeated entry_count {
//!     content_id_length_u16
//!     content_id_ascii[content_id_length]
//!     pack_id[32]
//!     absolute_body_offset_u64
//!     logical_length_u64
//!   }
//!   index_checksum[32]          # BLAKE3("crucible.content-store.pack-index.v1" || preceding bytes)
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::format::{PackedCursor, validate_index_entry};
use super::index::{PackIndex, PackOrder};
use super::index_records::PackState;
use super::{
    ContentId, IndexEntry, PackId, PackedBlobBackend, PackedRepackPlanId, StoreError, io_error,
    read_bounded_file, sync_directory,
};

const LEGACY_INDEX_FILE: &str = "index-v1";
const LEGACY_INDEX_MAGIC: &[u8] = b"crucible.content-store.pack-index.v1\0";
const LEGACY_INDEX_CHECKSUM_DOMAIN: &[u8] = b"crucible.content-store.pack-index.v1";

/// Largest file the retired encoder could produce; it bounds migration input.
const LEGACY_MAX_INDEX_BYTES: u64 = 16 * 1024 * 1024;

/// Decoded legacy index.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct LegacyIndex {
    pub(super) instance: [u8; 32],
    pub(super) generation: u64,
    pub(super) last_repack_plan: Option<PackedRepackPlanId>,
    /// Strictly increasing by content ID.
    pub(super) entries: Vec<(ContentId, IndexEntry)>,
}

/// Returns the legacy index path inside `admin`.
pub(super) fn legacy_index_path(admin: &Path) -> PathBuf {
    admin.join(LEGACY_INDEX_FILE)
}

impl PackedBlobBackend {
    /// Converts the legacy index into an authoritative v2 root.
    ///
    /// The caller holds the lifecycle lock exclusively and the state lock,
    /// and has established that no v2 root exists.
    pub(super) fn migrate_legacy_index(&self) -> Result<PackIndex, StoreError> {
        let legacy_path = legacy_index_path(&self.admin);
        let bytes = read_bounded_file(
            &legacy_path,
            LEGACY_MAX_INDEX_BYTES,
            "read legacy packed index",
        )?;
        let legacy = decode_legacy_index(&bytes, self.configuration)?;
        let packs = self.measure_legacy_packs(&legacy)?;

        let directory = self.index_directory();
        let mut build = directory.build(legacy.instance, legacy.generation, PackOrder::Sorted)?;
        for (id, entry) in &legacy.entries {
            build.push_entry(*id, *entry)?;
        }
        for (pack, state) in &packs {
            build.push_pack(*pack, *state)?;
        }
        let staged = build.finish()?;
        let view = directory.open_view(staged.root(legacy.generation, legacy.last_repack_plan))?;
        self.validate_index_packs(&view)?;

        #[cfg(feature = "destructive-recovery-faults")]
        super::inject_fault(super::MIGRATION_INTERRUPTION_TRIGGER);

        directory.publish(&view)?;
        remove_legacy_index(&self.admin)?;
        Ok(view)
    }

    fn measure_legacy_packs(
        &self,
        legacy: &LegacyIndex,
    ) -> Result<BTreeMap<PackId, PackState>, StoreError> {
        let mut packs = BTreeMap::<PackId, PackState>::new();
        for (_id, entry) in &legacy.entries {
            let state = packs.entry(entry.pack).or_insert(PackState {
                live_entries: 0,
                physical_bytes: 0,
            });
            state.live_entries = state.live_entries.checked_add(1).ok_or(StoreError::Quota)?;
        }
        for (pack, state) in &mut packs {
            let path = self.pack_path(*pack);
            state.physical_bytes = match fs::metadata(&path) {
                Ok(metadata) => metadata.len(),
                Err(source) if source.kind() == io::ErrorKind::NotFound => {
                    return Err(StoreError::Incompatible);
                }
                Err(source) => return Err(io_error("measure legacy pack", &path, source)),
            };
        }
        Ok(packs)
    }
}

/// Removes a legacy index that a valid v2 root supersedes.
pub(super) fn remove_legacy_index(admin: &Path) -> Result<bool, StoreError> {
    let path = legacy_index_path(admin);
    match fs::remove_file(&path) {
        Ok(()) => {
            sync_directory(admin)?;
            Ok(true)
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error("remove legacy packed index", &path, source)),
    }
}

/// Strictly decodes one legacy index.
pub(super) fn decode_legacy_index(
    bytes: &[u8],
    configuration: [u8; 32],
) -> Result<LegacyIndex, StoreError> {
    let (payload, checksum) = bytes
        .split_at_checked(
            bytes
                .len()
                .checked_sub(32)
                .ok_or(StoreError::Incompatible)?,
        )
        .ok_or(StoreError::Incompatible)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEGACY_INDEX_CHECKSUM_DOMAIN);
    hasher.update(payload);
    if hasher.finalize().as_bytes() != checksum {
        return Err(StoreError::Incompatible);
    }

    let mut cursor = PackedCursor::new(payload);
    if cursor.fixed(LEGACY_INDEX_MAGIC.len())? != LEGACY_INDEX_MAGIC
        || cursor.array_32()? != configuration
    {
        return Err(StoreError::Incompatible);
    }
    let instance = cursor.array_32()?;
    let generation = cursor.u64()?;
    let last_repack_plan = match cursor.u8()? {
        0 => None,
        1 => Some(PackedRepackPlanId(cursor.array_32()?)),
        _ => return Err(StoreError::Incompatible),
    };

    // The count is not trusted for allocation; the bounded input bounds entries.
    let count = cursor.u32()?;
    let mut entries = Vec::new();
    for _ in 0..count {
        let id_length = usize::from(cursor.u16()?);
        let id = std::str::from_utf8(cursor.fixed(id_length)?)
            .map_err(|_| StoreError::Incompatible)
            .and_then(|id| ContentId::parse(id).map_err(|_| StoreError::Incompatible))?;
        let entry = IndexEntry {
            pack: PackId(cursor.array_32()?),
            offset: cursor.u64()?,
            length: cursor.u64()?,
        };
        validate_index_entry(entry)?;
        if entries
            .last()
            .is_some_and(|(prior, _entry): &(ContentId, IndexEntry)| id <= *prior)
        {
            return Err(StoreError::Incompatible);
        }
        entries.push((id, entry));
    }
    if !cursor.is_empty() {
        return Err(StoreError::Incompatible);
    }
    Ok(LegacyIndex {
        instance,
        generation,
        last_repack_plan,
        entries,
    })
}

/// Encodes a legacy index exactly as the retired writer did.
#[cfg(test)]
pub(super) fn encode_legacy_index(index: &LegacyIndex, configuration: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(LEGACY_INDEX_MAGIC);
    bytes.extend_from_slice(&configuration);
    bytes.extend_from_slice(&index.instance);
    bytes.extend_from_slice(&index.generation.to_be_bytes());
    match index.last_repack_plan {
        None => bytes.push(0),
        Some(plan) => {
            bytes.push(1);
            bytes.extend_from_slice(&plan.0);
        }
    }
    bytes.extend_from_slice(&(index.entries.len() as u32).to_be_bytes());
    for (id, entry) in &index.entries {
        let id = id.to_string();
        bytes.extend_from_slice(&(id.len() as u16).to_be_bytes());
        bytes.extend_from_slice(id.as_bytes());
        bytes.extend_from_slice(&entry.pack.0);
        bytes.extend_from_slice(&entry.offset.to_be_bytes());
        bytes.extend_from_slice(&entry.length.to_be_bytes());
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEGACY_INDEX_CHECKSUM_DOMAIN);
    hasher.update(&bytes);
    bytes.extend_from_slice(hasher.finalize().as_bytes());
    bytes
}
