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

        // Hash every closure blob first (no I/O), keying the record entries and
        // the pack keys. The record references blobs by HASH, so closure-blob
        // locations are never consumed — only the record blob's is.
        let mut entries = Vec::with_capacity(closure.len());
        let closure_records: Vec<(PersistBlobKey, &[u8])> = closure
            .iter()
            .map(|(drv_path, bytes)| {
                let blob_hash = PersistFileBlobHash::for_payload(bytes);
                entries.push((drv_path.as_os_str().as_bytes().to_vec(), blob_hash));
                (PersistBlobKey::for_file(blob_hash), bytes.as_slice())
            })
            .collect();

        // Ensure the closure blobs durable: batched into one open/lock/flush when
        // write-behind is enabled (the cold storm this loop is otherwise), else
        // the per-blob path. Either way the blobs land before the record blob.
        if self.write_behind_values_enabled() {
            self.ensure_blobs_indexed_batch(PersistBlobStore::Files, &closure_records)
                .map_err(|source| PersistRootRecordError::Blob { source })?;
        } else {
            for (blob_key, bytes) in &closure_records {
                self.ensure_blob_indexed(*blob_key, bytes)
                    .map_err(|source| PersistRootRecordError::Blob { source })?;
            }
        }

        let record = RootInstantiationRecord::new(root_drv, entries, inputs.to_vec(), run_id);
        let record_bytes = record
            .encode()
            .map_err(|source| PersistRootRecordError::Format { source })?;
        let record_hash = PersistFileBlobHash::for_payload(&record_bytes);
        // The record blob is a single write whose location the root index needs,
        // so it stays a synchronous ensure (FILES store — never buffered).
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
        // The advisory guard is scoped to the index lookup alone: blob reads
        // below acquire the `files/` store lock, and holding the root-record
        // lock across them would invert the files-then-roots order used by
        // storage maintenance (an ABBA deadlock). The blob reads need no
        // root-record lock — they are content-addressed and self-verifying.
        let value = {
            let lock_path = self.layout().root_record_lock_path();
            let _guard = AdvisoryFileLock::lock(lock_path.clone(), AdvisoryFileLockMode::Shared)
                .map_err(|source| PersistRootRecordError::AdvisoryLock {
                    path: lock_path,
                    source,
                })?;
            let index = self.open_root_record_index()?;
            index
                .lookup(key)
                .map_err(|source| PersistRootRecordError::Index { source })?
        };
        let Some(value) = value else {
            return Ok(None);
        };

        let Some(record_bytes) = self.read_root_record_blob(value)? else {
            return Ok(None);
        };
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

    /// Reads a root-record payload blob, healing a stale indexed location.
    ///
    /// The `roots/` sidecar embeds the record blob's pack location at write
    /// time, but file-pack repack relocates records; a record written before a
    /// repack that predates root-record relocation support carries a stale
    /// offset. Because the blob is content-addressed, the current `files/`
    /// blob index remains the authority: when the embedded location no longer
    /// verifies, the read retries at the freshly indexed location.
    ///
    /// Returns `Ok(None)` when the blob is absent from both the embedded
    /// location and the current blob index (the record is dead; callers treat
    /// this as a clean miss).
    fn read_root_record_blob(
        &self,
        value: PersistRootRecordIndexValue,
    ) -> Result<Option<Vec<u8>>, PersistRootRecordError> {
        match self.read_blob(value.blob_key(), value.location()) {
            Ok(bytes) => return Ok(Some(bytes)),
            Err(error) => {
                tracing::debug!(
                    target: "aos_nix::cache",
                    error = %error,
                    "root-record blob unreadable at its indexed location; retrying via blob index"
                );
            }
        }
        let Some(location) = self
            .lookup_blob_location(value.blob_key())
            .map_err(|source| PersistRootRecordError::BlobIndex { source })?
        else {
            return Ok(None);
        };
        if location == value.location() {
            return Ok(None);
        }
        self.read_blob(value.blob_key(), location)
            .map(Some)
            .map_err(|source| PersistRootRecordError::BlobPack { source })
    }

    /// Enumerates the `files/` blobs kept live by durable root records.
    ///
    /// For every newest root-record index entry this resolves — through the
    /// current `files/` blob index, which stays authoritative across pack
    /// relocation — the encoded record blob plus every closure `.drv` blob the
    /// record references. Records whose blobs are unresolvable or whose
    /// payload no longer decodes are skipped (they are already dead and their
    /// bytes are legitimately reclaimable), so a single corrupt record never
    /// wedges storage maintenance.
    ///
    /// `files_advisory_guard` must be the caller's held `files/` store lock:
    /// maintenance callers already hold it exclusively, so record payloads are
    /// read through the mapped pack directly rather than through the
    /// self-locking [`Self::read_blob`] path (which would deadlock against the
    /// caller's own store lock). Callers must also hold the root-record
    /// advisory lock (shared suffices; the file-pack repack already holds it
    /// exclusively) so a concurrent record writer cannot tear the index
    /// snapshot — it is *not* acquired here because advisory file locks are
    /// not reentrant and the repack caller would self-deadlock.
    pub(super) fn root_record_blob_live_roots(
        &self,
        files_advisory_guard: &AdvisoryFileLock,
    ) -> Result<Vec<PersistBlobLiveRoot>, PersistBlobLiveRootError> {
        let index = PersistRootRecordIndex::open(self.layout().root_record_index_path())
            .map_err(|source| PersistBlobLiveRootError::RootRecordIndex { source })?;
        let mut roots = Vec::new();
        for entry in index
            .latest_entries()
            .map_err(|source| PersistBlobLiveRootError::RootRecordIndex { source })?
        {
            let value = entry.value();
            let Some(record_location) = self
                .lookup_blob_location(value.blob_key())
                .map_err(|source| PersistBlobLiveRootError::BlobIndex { source })?
            else {
                tracing::debug!(
                    target: "aos_nix::cache",
                    "root-record blob missing from the blob index; treating the record as dead"
                );
                continue;
            };
            let record_bytes = match self.file_pack().with_mapped_blob(
                files_advisory_guard,
                record_location,
                value.blob_key().hash(),
                <[u8]>::to_vec,
            ) {
                Ok(bytes) => bytes,
                Err(error) => {
                    tracing::debug!(
                        target: "aos_nix::cache",
                        error = %error,
                        "root-record blob unreadable; treating the record as dead"
                    );
                    continue;
                }
            };
            let Ok(record) = RootInstantiationRecord::decode(&record_bytes) else {
                tracing::debug!(
                    target: "aos_nix::cache",
                    "root-record payload undecodable; treating the record as dead"
                );
                continue;
            };
            roots.push(PersistBlobLiveRoot::new(
                PersistBlobLiveRootSource::RootRecordIndex,
                value.blob_key(),
                record_location,
            ));
            for (_, blob_hash) in record.entries() {
                let blob_key = PersistBlobKey::for_file(*blob_hash);
                let Some(location) = self
                    .lookup_blob_location(blob_key)
                    .map_err(|source| PersistBlobLiveRootError::BlobIndex { source })?
                else {
                    tracing::debug!(
                        target: "aos_nix::cache",
                        "root-record closure blob missing from the blob index"
                    );
                    continue;
                };
                roots.push(PersistBlobLiveRoot::new(
                    PersistBlobLiveRootSource::RootRecordIndex,
                    blob_key,
                    location,
                ));
            }
        }
        Ok(roots)
    }

    fn open_root_record_index(&self) -> Result<PersistRootRecordIndex, PersistRootRecordError> {
        PersistRootRecordIndex::open(self.layout().root_record_index_path())
            .map_err(|source| PersistRootRecordError::Index { source })
    }
}
