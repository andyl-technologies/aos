//! Durable root-instantiation record store and load operations.
//!
//! These methods persist and re-hydrate the derivation closure of a fully warm
//! `instantiate(file, attr)` request so a later run can skip evaluation. Closure
//! `.drv` ATerm bytes are stored deduplicated in the `files/` blob pack; a small
//! record blob lists the closure by content hash alongside the transitive
//! impure-input trace; and the root cutoff key maps to that record blob through
//! the `roots/` sidecar index. Cross-writer serialization uses one advisory lock
//! file per cache root.

use super::*;
use ratchet_cache::file_lock::{AdvisoryFileLock, AdvisoryFileLockMode};
use std::ffi::OsStr;

/// A fully hydrated root-instantiation record ready to re-emit as a closure.
///
/// The closure map is keyed by absolute `.drv` path, mirroring the in-memory
/// closure the native evaluator produces, so callers can reconstruct their
/// closure type directly. The impure inputs remain available for auditing; the
/// caller is expected to have already revalidated them before trusting this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydratedRootInstantiation {
    root: PathBuf,
    closure: BTreeMap<PathBuf, Vec<u8>>,
    inputs: Vec<CacheableInputFingerprint>,
    run_id: u64,
}

impl HydratedRootInstantiation {
    /// Returns the selected top-level `.drv` path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the reconstructed closure keyed by absolute `.drv` path.
    pub fn closure(&self) -> &BTreeMap<PathBuf, Vec<u8>> {
        &self.closure
    }

    /// Returns the transitive impure-input trace pinned by this record.
    pub fn inputs(&self) -> &[CacheableInputFingerprint] {
        &self.inputs
    }

    /// Returns the bookkeeping run id recorded when this record was written.
    pub const fn run_id(&self) -> u64 {
        self.run_id
    }

    /// Consumes this record into its root path and closure `.drv` byte map.
    pub fn into_closure_parts(self) -> (PathBuf, BTreeMap<PathBuf, Vec<u8>>) {
        (self.root, self.closure)
    }
}

impl PersistCache {
    /// Stores a durable root-instantiation record for `key`.
    ///
    /// Each closure `.drv` payload is deduplicated into the `files/` pack, the
    /// encoded record is stored as its own `files/` blob, and the root cutoff
    /// key is mapped to that record blob in the `roots/` sidecar index. Repeated
    /// stores of an identical closure reuse the existing blobs.
    ///
    /// # Errors
    ///
    /// Returns [`PersistRootRecordError`] if the root directory cannot be
    /// created, a closure or record blob cannot be appended or indexed, the
    /// impure-input trace cannot be encoded, the advisory root-record lock
    /// cannot be acquired, or the sidecar index cannot be written.
    pub fn store_root_instantiation(
        &self,
        key: PersistRootRecordKey,
        root_drv: &[u8],
        closure: &BTreeMap<PathBuf, Vec<u8>>,
        inputs: &[CacheableInputFingerprint],
        run_id: u64,
    ) -> Result<(), PersistRootRecordError> {
        let roots_dir = self.layout().roots_dir();
        fs::create_dir_all(&roots_dir).map_err(|source| PersistRootRecordError::CreateDir {
            path: roots_dir,
            source,
        })?;

        let mut entries = Vec::with_capacity(closure.len());
        for (drv_path, bytes) in closure {
            let blob_hash = PersistFileBlobHash::for_payload(bytes);
            self.ensure_blob_indexed(PersistBlobKey::for_file(blob_hash), bytes)
                .map_err(|source| PersistRootRecordError::Blob { source })?;
            entries.push((drv_path.as_os_str().as_bytes().to_vec(), blob_hash));
        }

        let record = RootInstantiationRecord::new(root_drv, entries, inputs.to_vec(), run_id);
        let record_bytes = record
            .encode()
            .map_err(|source| PersistRootRecordError::Format { source })?;
        let record_hash = PersistFileBlobHash::for_payload(&record_bytes);
        let record_entry = self
            .ensure_blob_indexed(PersistBlobKey::for_file(record_hash), &record_bytes)
            .map_err(|source| PersistRootRecordError::Blob { source })?;

        let value = PersistRootRecordIndexValue::new(record_hash, record_entry.location());
        let lock_path = self.layout().root_record_lock_path();
        let _guard = AdvisoryFileLock::lock(lock_path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistRootRecordError::AdvisoryLock {
                path: lock_path,
                source,
            })?;
        let index = self.open_root_record_index()?;
        index
            .append_entry(PersistRootRecordIndexEntry::new(key, value))
            .map_err(|source| PersistRootRecordError::Index { source })
    }

    /// Loads and hydrates a durable root-instantiation record for `key`.
    ///
    /// Returns `Ok(None)` when no record is indexed for `key` or when any
    /// referenced closure blob is no longer present in the pack (for example
    /// after blob-pack maintenance), so callers treat a missing closure as a
    /// clean cache miss and fall through to normal evaluation.
    ///
    /// # Errors
    ///
    /// Returns [`PersistRootRecordError`] if the advisory root-record lock
    /// cannot be acquired, the sidecar index cannot be read, a blob location
    /// lookup fails, a present blob cannot be read, or the record payload is
    /// malformed.
    pub fn load_root_instantiation(
        &self,
        key: PersistRootRecordKey,
    ) -> Result<Option<HydratedRootInstantiation>, PersistRootRecordError> {
        let lock_path = self.layout().root_record_lock_path();
        let _guard = AdvisoryFileLock::lock(lock_path.clone(), AdvisoryFileLockMode::Shared)
            .map_err(|source| PersistRootRecordError::AdvisoryLock {
                path: lock_path,
                source,
            })?;
        let index = self.open_root_record_index()?;
        let Some(value) = index
            .lookup(key)
            .map_err(|source| PersistRootRecordError::Index { source })?
        else {
            return Ok(None);
        };

        let record_bytes = self
            .read_blob(value.blob_key(), value.location())
            .map_err(|source| PersistRootRecordError::BlobPack { source })?;
        let record = RootInstantiationRecord::decode(&record_bytes)
            .map_err(|source| PersistRootRecordError::Format { source })?;

        let mut closure = BTreeMap::new();
        for (drv_path, blob_hash) in record.entries() {
            let blob_key = PersistBlobKey::for_file(*blob_hash);
            let Some(location) = self
                .lookup_blob_location(blob_key)
                .map_err(|source| PersistRootRecordError::BlobIndex { source })?
            else {
                return Ok(None);
            };
            let bytes = self
                .read_blob(blob_key, location)
                .map_err(|source| PersistRootRecordError::BlobPack { source })?;
            closure.insert(PathBuf::from(OsStr::from_bytes(drv_path)), bytes);
        }

        Ok(Some(HydratedRootInstantiation {
            root: PathBuf::from(OsStr::from_bytes(record.root_drv())),
            closure,
            inputs: record.inputs().to_vec(),
            run_id: record.run_id(),
        }))
    }

    fn open_root_record_index(&self) -> Result<PersistRootRecordIndex, PersistRootRecordError> {
        PersistRootRecordIndex::open(self.layout().root_record_index_path())
            .map_err(|source| PersistRootRecordError::Index { source })
    }
}
