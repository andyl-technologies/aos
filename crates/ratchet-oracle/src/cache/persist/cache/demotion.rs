//! Size-pressure demotion planning for the primary persist-cache location.
//!
//! This is the primary-only, read-only half of the multi-location demotion
//! engine (RFC-0007 doc 29 §5.4/§5.6): it measures the primary's resident
//! footprint, enumerates its durable root-instantiation records, and selects
//! the cold victims to move down a latency class. The two-location executor
//! that copies victims to a secondary and unroots them from the primary lives
//! on [`PersistCacheLocations`](super::super::locations::PersistCacheLocations)
//! — demotion needs secondaries, which only the location stack owns.
//!
//! Demotion moves the **root-instantiation record** (`PersistRootRecordKey`),
//! never a blob-pack record: the location stack tiers only root records
//! (`load_root_instantiation`/`promote_root_instantiation`), and unrooted
//! blob-pack records are repack garbage, not demotion candidates. See the
//! executor brief §6 for the full resolution.

use super::*;
use ratchet_cache::file_lock::{AdvisoryFileLock, AdvisoryFileLockMode};
use std::collections::BTreeSet;

/// A read-only demotion plan for the primary location.
///
/// The plan pairs the primary's measured resident bytes and the policy's
/// derived `bytes_to_free` target with the selected victim prefix (largest and
/// coldest first). An empty `victims` list means demotion is disabled, the
/// primary is within its size-pressure bound, or no root records exist.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistDemotionPlan {
    primary_used_bytes: u64,
    bytes_to_free: u64,
    victims: Vec<PersistDemotionCandidate>,
}

impl PersistDemotionPlan {
    pub(super) fn new(
        primary_used_bytes: u64,
        bytes_to_free: u64,
        victims: Vec<PersistDemotionCandidate>,
    ) -> Self {
        Self {
            primary_used_bytes,
            bytes_to_free,
            victims,
        }
    }

    /// Returns the primary's measured resident bytes at planning time.
    pub const fn primary_used_bytes(&self) -> u64 {
        self.primary_used_bytes
    }

    /// Returns the bytes the policy asked demotion to free.
    pub const fn bytes_to_free(&self) -> u64 {
        self.bytes_to_free
    }

    /// Returns the selected demotion victims in move order (largest+coldest first).
    pub fn victims(&self) -> &[PersistDemotionCandidate] {
        &self.victims
    }
}

/// Why a demotion sweep moved no records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistDemotionSkip {
    /// Demotion is disabled or the primary is within its size-pressure bound.
    NoSizePressure,
    /// No opened secondary location exists to receive demoted records.
    NoSecondaryLocation,
    /// The primary holds no demotable root records.
    NoCandidates,
}

/// The outcome of a two-location demotion sweep.
///
/// Either records were moved down (`Demoted`) or the sweep was a no-op with a
/// reason (`Skipped`). Demotion is advisory: per-victim copy-down or verify
/// failures are logged and drop that victim from the moved set, never failing
/// the sweep.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersistDemotionOutcome {
    /// Nothing was demoted; the reason is attached.
    Skipped {
        /// Why the sweep moved no records.
        reason: PersistDemotionSkip,
    },
    /// Root records were moved to a slower latency class.
    Demoted {
        /// The keys unrooted from the primary and stored at the secondary.
        demoted_keys: Vec<PersistRootRecordKey>,
        /// The estimated primary bytes the demoted records made reclaimable.
        estimated_bytes_freed: u64,
        /// The class of the secondary that received the demoted records.
        target_class: PersistLatencyClass,
    },
}

impl PersistDemotionOutcome {
    /// Returns the number of root records moved down by this sweep.
    pub fn demoted_count(&self) -> usize {
        match self {
            Self::Skipped { .. } => 0,
            Self::Demoted { demoted_keys, .. } => demoted_keys.len(),
        }
    }

    /// Returns the estimated primary bytes this sweep made reclaimable.
    pub const fn estimated_bytes_freed(&self) -> u64 {
        match self {
            Self::Skipped { .. } => 0,
            Self::Demoted {
                estimated_bytes_freed,
                ..
            } => *estimated_bytes_freed,
        }
    }
}

/// A size-pressure demotion operation failed on the primary location.
#[derive(Debug, thiserror::Error)]
pub enum PersistDemotionError {
    /// The primary root-record advisory lock could not be acquired.
    #[error("root-record advisory lock at {path} could not be acquired")]
    AdvisoryLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying lock failure.
        #[source]
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The primary root-record index could not be opened, read, or rewritten.
    #[error("root-record index operation failed")]
    Index {
        /// The underlying index failure.
        #[source]
        source: PersistRootRecordIndexError,
    },
    /// A blob-index lookup failed while sizing a candidate.
    #[error("blob index lookup failed")]
    BlobIndex {
        /// The underlying blob-index failure.
        #[source]
        source: PersistBlobIndexError,
    },
    /// Measuring the primary's resident pack bytes failed.
    #[error("blob pack measurement failed")]
    BlobPack {
        /// The underlying blob-pack failure.
        #[source]
        source: PersistBlobPackError,
    },
    /// Swapping the rewritten primary root-record index into place failed.
    #[error("rewriting the primary root-record index at {path} failed")]
    RewriteIndex {
        /// The root-record index path being replaced.
        path: PathBuf,
        /// The underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
}

impl PersistCache {
    /// Returns the primary's resident bytes that root-record demotion can relieve.
    ///
    /// This measures the `files/` packfile, which holds every root-record blob
    /// and every closure `.drv` blob a demotion relocates; the `values/` pack is
    /// a distinct memo path and is not moved by root-record demotion. An empty
    /// or absent pack measures as its header length.
    ///
    /// # Errors
    ///
    /// Returns [`PersistDemotionError::BlobPack`] if the files packfile cannot be
    /// opened, mapped, or validated.
    pub fn primary_used_bytes(&self) -> Result<u64, PersistDemotionError> {
        self.file_pack()
            .len()
            .map_err(|source| PersistDemotionError::BlobPack { source })
    }

    /// Enumerates the primary's durable root records as demotion candidates.
    ///
    /// This is read-only on the primary. It snapshots the root-record index
    /// under a shared advisory lock and then releases it before reading any
    /// blob, preserving the campaign's files-then-roots lock order (holding the
    /// root-record lock across blob reads would invert it into an ABBA
    /// deadlock). Each candidate is sized by the cheap files-blob proxy — the
    /// record blob plus its closure blobs, which may over-count blobs shared by
    /// identical closures — and carries the record blob's files-pack append
    /// offset as a recency proxy (smaller is older/colder), because packed blobs
    /// have no independent filesystem mtime. Records whose blobs are
    /// unresolvable or whose payload no longer decodes are already dead and are
    /// skipped.
    ///
    /// # Errors
    ///
    /// Returns [`PersistDemotionError`] if the shared root-record lock cannot be
    /// acquired, the index cannot be read, or a blob-index lookup fails.
    pub fn enumerate_demotion_candidates(
        &self,
    ) -> Result<Vec<PersistDemotionCandidate>, PersistDemotionError> {
        let entries = {
            let lock_path = self.layout().root_record_lock_path();
            let _guard = AdvisoryFileLock::lock(lock_path.clone(), AdvisoryFileLockMode::Shared)
                .map_err(|source| PersistDemotionError::AdvisoryLock {
                    path: lock_path,
                    source,
                })?;
            let index = PersistRootRecordIndex::open(self.layout().root_record_index_path())
                .map_err(|source| PersistDemotionError::Index { source })?;
            index
                .latest_entries()
                .map_err(|source| PersistDemotionError::Index { source })?
        };

        let mut candidates = Vec::with_capacity(entries.len());
        for entry in entries {
            let record_key = entry.value().blob_key();
            // Resolve the record blob through the authoritative blob index so a
            // stale embedded location (from a pre-relocation repack) still sizes
            // correctly; a missing record blob means the record is dead.
            let Some(record_location) = self
                .lookup_blob_location(record_key)
                .map_err(|source| PersistDemotionError::BlobIndex { source })?
            else {
                continue;
            };
            let Ok(record_bytes) = self.read_blob(record_key, record_location) else {
                continue;
            };
            let Ok(record) = RootInstantiationRecord::decode(&record_bytes) else {
                continue;
            };
            let mut resident_bytes = record_location.payload_len();
            for (_, blob_hash) in record.entries() {
                if let Some(location) = self
                    .lookup_blob_location(PersistBlobKey::for_file(*blob_hash))
                    .map_err(|source| PersistDemotionError::BlobIndex { source })?
                {
                    resident_bytes = resident_bytes.saturating_add(location.payload_len());
                }
            }
            candidates.push(PersistDemotionCandidate::new(
                entry.key(),
                resident_bytes,
                record_location.record_offset(),
            ));
        }
        Ok(candidates)
    }

    /// Plans size-pressure demotion for the primary under `policy`.
    ///
    /// Measures the primary's resident bytes, derives the policy's
    /// `bytes_to_free`, and — when demotion is enabled and the primary exceeds
    /// its bound — enumerates and selects the victim prefix. Returns an empty
    /// victim list (with the measured bytes) when demotion is disabled or the
    /// primary is within its bound, so callers never enumerate needlessly.
    ///
    /// # Errors
    ///
    /// Returns [`PersistDemotionError`] if measuring or enumerating the primary
    /// fails.
    pub fn plan_demotion(
        &self,
        policy: PersistStorageMaintenancePolicy,
    ) -> Result<PersistDemotionPlan, PersistDemotionError> {
        let primary_used_bytes = self.primary_used_bytes()?;
        let bytes_to_free = policy.demotion_bytes_to_free(primary_used_bytes);
        if bytes_to_free == 0 {
            return Ok(PersistDemotionPlan::new(primary_used_bytes, 0, Vec::new()));
        }
        let mut candidates = self.enumerate_demotion_candidates()?;
        let victims = select_demotion_victims(&mut candidates, bytes_to_free).to_vec();
        Ok(PersistDemotionPlan::new(
            primary_used_bytes,
            bytes_to_free,
            victims,
        ))
    }

    /// Unroots `keys` from the primary root-record index.
    ///
    /// This is the "remove from primary" step of demotion (executor brief §5,
    /// step 3): once a record is durably stored at a secondary, its primary root
    /// is dropped so its exclusive closure blobs become reclaimable by the next
    /// repack — demotion reuses that existing reclamation rather than writing a
    /// second removal. The rewrite reads the newest index entries, drops the
    /// demoted keys, writes a replacement index to a temporary path, and
    /// atomically renames it over the live index, all under the exclusive
    /// root-record advisory lock so no concurrent append is lost. A crash before
    /// the rename leaves the record rooted in both locations (a benign
    /// duplicate: lookups probe primary-then-secondary and either answers).
    ///
    /// Returns the number of entries removed.
    ///
    /// # Errors
    ///
    /// Returns [`PersistDemotionError`] if the exclusive root-record lock cannot
    /// be acquired, the index cannot be read or staged, or the atomic swap fails.
    pub fn unroot_root_records(
        &self,
        keys: &BTreeSet<PersistRootRecordKey>,
    ) -> Result<usize, PersistDemotionError> {
        if keys.is_empty() {
            return Ok(0);
        }
        let index_path = self.layout().root_record_index_path();
        let lock_path = self.layout().root_record_lock_path();
        let _guard = AdvisoryFileLock::lock(lock_path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistDemotionError::AdvisoryLock {
                path: lock_path,
                source,
            })?;
        let index = PersistRootRecordIndex::open(&index_path)
            .map_err(|source| PersistDemotionError::Index { source })?;
        let before = index
            .latest_entries()
            .map_err(|source| PersistDemotionError::Index { source })?;
        let kept: Vec<PersistRootRecordIndexEntry> = before
            .iter()
            .copied()
            .filter(|entry| !keys.contains(&entry.key()))
            .collect();
        let removed = before.len().saturating_sub(kept.len());
        if removed == 0 {
            return Ok(0);
        }
        let staged = index_path.with_extension("demote-staged");
        PersistRootRecordIndex::write_entries_to(&staged, &kept)
            .map_err(|source| PersistDemotionError::Index { source })?;
        fs::rename(&staged, &index_path).map_err(|source| PersistDemotionError::RewriteIndex {
            path: index_path,
            source,
        })?;
        Ok(removed)
    }
}
